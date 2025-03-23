import Hyperswarm from "hyperswarm"
import Corestore from "corestore"
import Hyperbee from "hyperbee"
import axios from "axios"
import crypto from "crypto"
import express from "express"
import dotenv from "dotenv"
import {
    generateECDHKeys,
    generateSigningKeys,
    deriveSharedSecret,
    createSecureMessage,
    encryptForPeer,
    processSecureMessage,
    decryptMessage,
} from "./crypto-utils.js"

dotenv.config()

// Constants
const DISCOVERY_KEY = "forex-network-v1"
const PORT = 2003
const EXCHANGE_RATE_API = "https://api.exchangerate-api.com/v4/latest/USD"
const CACHE_EXPIRY = 5 * 60 * 1000 // 5 minutes

// Generate keys
const { publicKey, privateKey, ecdh } = generateECDHKeys()
const { publicKey: signPublicKey, privateKey: signPrivateKey } = generateSigningKeys()

console.log("Rate service ECDH public key:", publicKey)
console.log("Rate service Signing public key:", signPublicKey.substring(0, 64) + "...")

// Track peer keys and shared secrets
const peersPublicKeys = new Map()
const peersSignPublicKeys = new Map()
const sharedSecrets = new Map()

// Setup Corestore & Hyperbee
let rateDB
async function initializeStorage() {
    const store = new Corestore("./rate-service-store")
    await store.ready()
    const feed = store.get({ name: "exchange-rates" })
    await feed.ready()
    rateDB = new Hyperbee(feed, { keyEncoding: "utf-8", valueEncoding: "json" })
    await rateDB.ready()
    console.log("Rate database initialized")
}

// Setup Hyperswarm
const swarm = new Hyperswarm()
const topic = crypto.createHash("sha256").update(DISCOVERY_KEY).digest()
swarm.join(topic, { lookup: true, announce: true })

console.log("Rate service joining network with topic:", topic.toString("hex"))

// Track connected peers
const peers = new Map()

// Actively look for peers
swarm.on("peer", (peer) => {
    console.log("Rate service discovered new peer:", peer.topic.toString("hex"))
    // Attempt to connect to discovered peer
    swarm.connect(peer).catch((err) => {
        console.error("Failed to connect to peer:", err)
    })
})

    // Initialize and announce
    ; (async () => {
        await initializeStorage()
        await swarm.flush()
        console.log("Rate service has fully announced itself on the network")
    })()

// Periodically check connections
setInterval(() => {
    console.log(`Rate service connected peers: ${swarm.peers.size}`)
    if (swarm.peers.size === 0 && !swarm.flushing) {
        console.log("No peers connected, re-announcing...")
        swarm.flush().catch((err) => console.error("Error flushing announcements:", err))
    }
}, 5000)

swarm.on("connection", (socket) => {
    const peerId = socket.remotePublicKey ? socket.remotePublicKey.toString("hex").slice(0, 8) : "unknown"
    console.log(`New peer connected to rate service: ${peerId}`)

    socket.setKeepAlive(true, 10000) // Keep connection alive with 10s interval

    // Send identification with our public keys
    const identityMessage = {
        type: "identify",
        service: "rate-service",
        publicKey,
        signPublicKey,
        timestamp: Date.now(),
    }

    // Sign the identity message
    const signedIdentity = createSecureMessage(identityMessage, signPrivateKey)
    socket.write(JSON.stringify(signedIdentity))

    socket.on("data", async (data) => {
        try {
            const message = JSON.parse(data.toString())

            // Handle identification
            if (message.type === "identify") {
                try {
                    // Verify the message has required fields
                    if (!message.publicKey || !message.signPublicKey) {
                        console.error("Received identity message missing required keys")
                        return
                    }

                    // Verify the message signature
                    processSecureMessage(message, message.signPublicKey)

                    // Store peer's keys
                    peersPublicKeys.set(peerId, message.publicKey)
                    peersSignPublicKeys.set(peerId, message.signPublicKey)

                    // Derive and store shared secret
                    const secret = deriveSharedSecret(ecdh, message.publicKey)
                    if (secret) {
                        sharedSecrets.set(peerId, secret)

                        // Register the peer
                        peers.set(message.service, socket)
                        console.log(`Rate service registered ${message.service} peer with keys`)
                    } else {
                        console.error(`Failed to derive shared secret with ${message.service}`)
                    }
                } catch (error) {
                    console.error("Error processing identity message:", error.message)
                }
                return
            }

            // Handle encrypted messages
            if (message.type === "secure") {
                try {
                    // Validate message
                    if (!message.data || !message.from) {
                        console.error("Received invalid secure message format")
                        return
                    }

                    // Get shared secret for this peer
                    const secret = sharedSecrets.get(peerId)
                    if (!secret) {
                        console.error("No shared secret for peer", peerId)
                        return
                    }

                    // Decrypt the message
                    const decrypted = decryptMessage(message.data, secret)
                    if (!decrypted) {
                        console.error("Failed to decrypt message from", peerId)
                        return
                    }

                    // Verify the decrypted message
                    const peerSignPublicKey = peersSignPublicKeys.get(peerId)
                    if (!peerSignPublicKey) {
                        console.error("No signing public key for peer", peerId)
                        return
                    }

                    const verifiedMessage = processSecureMessage(decrypted, peerSignPublicKey)

                    console.log(`Rate service received secure message: ${verifiedMessage.type}`)

                    // Handle rate requests
                    if (verifiedMessage.type === "get-rate" && verifiedMessage.currency) {
                        handleRateRequest(verifiedMessage, message.from, socket, peerId)
                    }
                } catch (error) {
                    console.error("Error processing secure message:", error.message)
                }
                return
            }
        } catch (error) {
            console.error("Error processing message:", error)
        }
    })

    socket.on("error", (err) => {
        console.error(`Rate service connection error with ${peerId}:`, err.message)
    })

    socket.on("close", () => {
        console.log(`Peer ${peerId} disconnected from rate service`)

        // Clean up peer data
        peersPublicKeys.delete(peerId)
        peersSignPublicKeys.delete(peerId)
        sharedSecrets.delete(peerId)

        // Remove from service registry
        for (const [service, peerSocket] of peers.entries()) {
            if (peerSocket === socket) {
                peers.delete(service)
                console.log(`Removed ${service} peer from registry`)
                break
            }
        }
    })
})

// Send secure message to a service
function sendSecureMessage(serviceName, message) {
    const socket = peers.get(serviceName)
    if (!socket) {
        console.error(`No connection to ${serviceName}`)
        return false
    }

    try {
        // Get the peer ID from the socket
        const peerId = socket.remotePublicKey ? socket.remotePublicKey.toString("hex").slice(0, 8) : null
        if (!peerId) {
            console.error(`Cannot identify peer for ${serviceName}`)
            return false
        }

        // Get shared secret for this peer
        const secret = sharedSecrets.get(peerId)
        if (!secret) {
            console.error(`No shared secret for ${serviceName}`)
            return false
        }

        // Create signed message
        const signedMessage = createSecureMessage(message, signPrivateKey)

        // Encrypt the signed message
        const encryptedData = encryptForPeer(signedMessage, secret)

        if (!encryptedData) {
            console.error(`Failed to encrypt message for ${serviceName}`)
            return false
        }

        // Send the encrypted message
        socket.write(
            JSON.stringify({
                type: "secure",
                from: "rate-service",
                data: encryptedData,
            }),
        )

        return true
    } catch (err) {
        console.error(`Error sending secure message to ${serviceName}:`, err)
        return false
    }
}

// Handle rate request
async function handleRateRequest(message, fromService, socket, peerId) {
    try {
        console.log(`Processing rate request for ${message.currency}`)
        const rate = await getExchangeRate(message.currency)

        sendSecureMessage(fromService, {
            type: "rate-response",
            rate,
            requestId: message.requestId,
        })
    } catch (error) {
        console.error("Error handling rate request:", error)
        sendSecureMessage(fromService, {
            type: "rate-response",
            rate: null,
            error: error.message,
            requestId: message.requestId,
        })
    }
}

// Fetch exchange rate with caching
async function getExchangeRate(currency) {
    try {
        currency = currency.toUpperCase()

        // Check cache first
        const cachedRate = await rateDB.get(currency)
        if (cachedRate) {
            console.log(`Returning cached rate for ${currency}`)
            return cachedRate.value
        }

        // Fetch new rate if not cached
        console.log(`Fetching new rate for ${currency}`)
        const response = await axios.get(EXCHANGE_RATE_API)
        const rates = response.data.rates

        if (rates[currency]) {
            // Store in cache with expiration
            await rateDB.put(currency, rates[currency])
            setTimeout(() => {
                rateDB.del(currency).catch((err) => console.error(`Error deleting cached rate for ${currency}:`, err))
            }, CACHE_EXPIRY)

            console.log(`Cached new rate for ${currency}: ${rates[currency]}`)
            return rates[currency]
        }

        console.log(`Currency ${currency} not found in exchange rates`)
        return null
    } catch (err) {
        console.error("Error fetching exchange rate:", err.message)
        return null
    }
}

// Cleanup function
async function cleanup() {
    console.log("\nShutting down rate service...")
    await swarm.leave(topic)
    await swarm.destroy()
    console.log("Rate service disconnected from all peers")
    process.exit(0)
}

// Handle termination
process.on("SIGINT", cleanup)
process.on("SIGTERM", cleanup)

// Express API
const app = express()
app.use(express.json())

app.get("/rate/:currency", async (req, res) => {
    try {
        const currency = req.params.currency.toUpperCase()
        const rate = await getExchangeRate(currency)

        if (!rate) {
            return res.status(404).json({ error: "Currency not found" })
        }

        res.json({ currency, rate })
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch exchange rate" })
    }
})

// Test endpoints
app.get("/peers", (req, res) => {
    const connectedPeers = Array.from(peers.keys())
    res.json({
        peers: connectedPeers,
        count: connectedPeers.length,
        secure: connectedPeers.filter((peer) => {
            const peerId = peers.get(peer).remotePublicKey.toString("hex").slice(0, 8)
            return sharedSecrets.has(peerId)
        }),
    })
})

// Start server
app.listen(PORT, () => {
    console.log(`Rate service listening on port ${PORT}`)
})

