import Hyperswarm from "hyperswarm"
import Corestore from "corestore"
import Hyperbee from "hyperbee"
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
const PORT = 2002
const REQUEST_TIMEOUT = 10000 // 10 seconds

// Generate keys
const { publicKey, privateKey, ecdh } = generateECDHKeys()
const { publicKey: signPublicKey, privateKey: signPrivateKey } = generateSigningKeys()

console.log("Wallet service ECDH public key:", publicKey)
console.log("Wallet service Signing public key:", signPublicKey.substring(0, 64) + "...")

// Track peer keys and shared secrets
const peersPublicKeys = new Map()
const peersSignPublicKeys = new Map()
const sharedSecrets = new Map()

// Setup Corestore & Hyperbee
let walletDB
async function initializeStorage() {
    const store = new Corestore("./wallet-service-store")
    await store.ready()
    const feed = store.get({ name: "wallets" })
    await feed.ready()
    walletDB = new Hyperbee(feed, { keyEncoding: "utf-8", valueEncoding: "json" })
    await walletDB.ready()
    console.log("Wallet database initialized")
}

// Setup Hyperswarm
const swarm = new Hyperswarm()
const topic = crypto.createHash("sha256").update(DISCOVERY_KEY).digest()
swarm.join(topic, { lookup: true, announce: true })

console.log("Wallet service joining network with topic:", topic.toString("hex"))

// Track connected peers
const peers = new Map()

// Actively look for peers
swarm.on("peer", (peer) => {
    console.log("Wallet service discovered new peer:", peer.topic.toString("hex"))
    // Attempt to connect to discovered peer
    swarm.connect(peer).catch((err) => {
        console.error("Failed to connect to peer:", err)
    })
})

    // Initialize and announce
    ; (async () => {
        await initializeStorage()
        await swarm.flush()
        console.log("Wallet service has fully announced itself on the network")
    })()

// Periodically check connections
setInterval(() => {
    console.log(`Wallet service connected peers: ${swarm.peers.size}`)
    if (swarm.peers.size === 0 && !swarm.flushing) {
        console.log("No peers connected, re-announcing...")
        swarm.flush().catch((err) => console.error("Error flushing announcements:", err))
    }
}, 5000)

swarm.on("connection", (socket) => {
    const peerId = socket.remotePublicKey ? socket.remotePublicKey.toString("hex").slice(0, 8) : "unknown"
    console.log(`New peer connected to wallet service: ${peerId}`)

    socket.setKeepAlive(true, 10000) // Keep connection alive with 10s interval

    // Send identification with our public keys
    const identityMessage = {
        type: "identify",
        service: "wallet-service",
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
                        console.log(`Wallet service registered ${message.service} peer with keys`)
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

                    console.log(`Wallet service received secure message: ${verifiedMessage.type}`)

                    // Handle wallet creation requests
                    if (verifiedMessage.type === "create-wallet") {
                        handleCreateWallet(verifiedMessage, message.from, socket, peerId)
                    }

                    // Handle rate responses
                    if (verifiedMessage.type === "rate-response") {
                        // Find the handler for this request
                        const handler = pendingRequests.get(verifiedMessage.requestId)
                        if (handler) {
                            handler(verifiedMessage)
                            pendingRequests.delete(verifiedMessage.requestId)
                        }
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
        console.error(`Wallet service connection error with ${peerId}:`, err.message)
    })

    socket.on("close", () => {
        console.log(`Peer ${peerId} disconnected from wallet service`)

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

// Track pending requests
const pendingRequests = new Map()

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
                from: "wallet-service",
                data: encryptedData,
            }),
        )

        return true
    } catch (err) {
        console.error(`Error sending secure message to ${serviceName}:`, err)
        return false
    }
}

// Handle wallet creation request
async function handleCreateWallet(message, fromService, socket, peerId) {
    try {
        const { userId, currency = "USD", requestId } = message

        // Check if wallet already exists
        const existing = await walletDB.get(`wallet:${userId}`)
        if (existing) {
            sendSecureMessage(fromService, {
                type: "wallet-created",
                userId,
                success: true,
                message: "Wallet already exists",
                requestId,
            })
            return
        }

        // Create new wallet
        await walletDB.put(`wallet:${userId}`, {
            userId,
            balance: 0,
            currency,
            createdAt: Date.now(),
        })

        sendSecureMessage(fromService, {
            type: "wallet-created",
            userId,
            success: true,
            currency,
            requestId,
        })
    } catch (error) {
        console.error("Error creating wallet:", error)
        sendSecureMessage(fromService, {
            type: "wallet-created",
            userId: message.userId,
            success: false,
            error: error.message,
            requestId: message.requestId,
        })
    }
}

// Get exchange rate from rate service
async function getExchangeRate(currency) {
    return new Promise((resolve, reject) => {
        if (!peers.has("rate-service")) {
            return reject(new Error("No connection to rate service"))
        }

        const requestId = Date.now().toString()

        // Set up request handler
        pendingRequests.set(requestId, (response) => {
            if (response.rate !== null && response.rate !== undefined) {
                resolve(response.rate)
            } else {
                reject(new Error(response.error || "Currency not supported"))
            }
        })

        // Send the request
        sendSecureMessage("rate-service", {
            type: "get-rate",
            currency,
            requestId,
        })

        // Set timeout to prevent hanging
        setTimeout(() => {
            if (pendingRequests.has(requestId)) {
                pendingRequests.delete(requestId)
                reject(new Error("Request to rate service timed out"))
            }
        }, REQUEST_TIMEOUT)
    })
}

// Cleanup function
async function cleanup() {
    console.log("\nShutting down wallet service...")
    await swarm.leave(topic)
    await swarm.destroy()
    console.log("Wallet service disconnected from all peers")
    process.exit(0)
}

// Handle termination
process.on("SIGINT", cleanup)
process.on("SIGTERM", cleanup)

// Express API
const app = express()
app.use(express.json())

app.post("/wallet/create", async (req, res) => {
    try {
        const { userId, currency = "USD" } = req.body

        if (!userId) {
            return res.status(400).json({ error: "userId is required" })
        }

        // Check if wallet already exists
        const existing = await walletDB.get(`wallet:${userId}`)
        if (existing) {
            return res.status(409).json({ error: "Wallet already exists for this user" })
        }

        // Create new wallet
        await walletDB.put(`wallet:${userId}`, {
            userId,
            balance: 0,
            currency,
            createdAt: Date.now(),
        })

        res.status(201).json({
            message: "Wallet created successfully",
            userId,
            currency,
        })
    } catch (error) {
        console.error("Error creating wallet:", error)
        res.status(500).json({ error: "Failed to create wallet" })
    }
})

app.get("/wallet/:userId", async (req, res) => {
    try {
        const wallet = await walletDB.get(`wallet:${req.params.userId}`)

        if (!wallet) {
            return res.status(404).json({ error: "Wallet not found" })
        }

        res.json(wallet.value)
    } catch (error) {
        console.error("Error fetching wallet:", error)
        res.status(500).json({ error: "Failed to fetch wallet" })
    }
})

app.post("/wallet/transaction", async (req, res) => {
    try {
        const { userId, amount, type, currency } = req.body

        if (!userId || amount === undefined || !type) {
            return res.status(400).json({ error: "userId, amount, and type are required" })
        }

        if (type !== "credit" && type !== "debit") {
            return res.status(400).json({ error: "Type must be either credit or debit" })
        }

        const wallet = await walletDB.get(`wallet:${userId}`)
        if (!wallet) {
            return res.status(404).json({ error: "Wallet not found" })
        }

        let finalAmount = amount

        // Convert currency if needed
        if (currency && currency !== wallet.value.currency) {
            try {
                console.log(`Converting ${amount} ${currency} to ${wallet.value.currency}`)
                const rate = await getExchangeRate(currency)
                finalAmount = amount * rate
                console.log(`Converted amount: ${finalAmount} ${wallet.value.currency}`)
            } catch (error) {
                return res.status(500).json({
                    error: `Currency conversion failed: ${error.message}`,
                })
            }
        }

        // Process transaction
        let newBalance = wallet.value.balance

        if (type === "credit") {
            newBalance += finalAmount
        } else {
            // debit
            if (wallet.value.balance < finalAmount) {
                return res.status(400).json({ error: "Insufficient balance" })
            }
            newBalance -= finalAmount
        }

        // Update wallet
        await walletDB.put(`wallet:${userId}`, {
            ...wallet.value,
            balance: newBalance,
            updatedAt: Date.now(),
        })

        res.json({
            message: "Transaction successful",
            type,
            amount: finalAmount,
            currency: wallet.value.currency,
            balance: newBalance,
        })
    } catch (error) {
        console.error("Error processing transaction:", error)
        res.status(500).json({ error: "Failed to process transaction" })
    }
})

// Test endpoints
app.get("/test/rate/:currency", async (req, res) => {
    try {
        const rate = await getExchangeRate(req.params.currency)
        res.json({ currency: req.params.currency, rate })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

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
    console.log(`Wallet service listening on port ${PORT}`)
})

