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
const PORT = 2001

// Generate keys
const { publicKey, privateKey, ecdh } = generateECDHKeys()
const { publicKey: signPublicKey, privateKey: signPrivateKey } = generateSigningKeys()

console.log("User service ECDH public key:", publicKey)
console.log("User service Signing public key:", signPublicKey.substring(0, 64) + "...")

// Track peer keys and shared secrets
const peersPublicKeys = new Map()
const peersSignPublicKeys = new Map()
const sharedSecrets = new Map()

// Setup Corestore & Hyperbee
let userDB
async function initializeStorage() {
    const store = new Corestore("./user-service-store")
    await store.ready()
    const feed = store.get({ name: "users" })
    await feed.ready()
    userDB = new Hyperbee(feed, { keyEncoding: "utf-8", valueEncoding: "json" })
    await userDB.ready()
    console.log("User database initialized")
}

// Setup Hyperswarm
const swarm = new Hyperswarm()
const topic = crypto.createHash("sha256").update(DISCOVERY_KEY).digest()
swarm.join(topic, { lookup: true, announce: true })

console.log("User service joining network with topic:", topic.toString("hex"))

// Track connected peers
const peers = new Map()

// Actively look for peers
swarm.on("peer", (peer) => {
    console.log("User service discovered new peer:", peer.topic.toString("hex"))
    // Attempt to connect to discovered peer
    swarm.connect(peer).catch((err) => {
        console.error("Failed to connect to peer:", err)
    })
})

    // Initialize and announce
    ; (async () => {
        await initializeStorage()
        await swarm.flush()
        console.log("User service has fully announced itself on the network")
    })()

// Periodically check connections
setInterval(() => {
    console.log(`User service connected peers: ${swarm.peers.size}`)
    if (swarm.peers.size === 0 && !swarm.flushing) {
        console.log("No peers connected, re-announcing...")
        swarm.flush().catch((err) => console.error("Error flushing announcements:", err))
    }
}, 5000)

swarm.on("connection", (socket) => {
    const peerId = socket.remotePublicKey ? socket.remotePublicKey.toString("hex").slice(0, 8) : "unknown"
    console.log(`New peer connected to user service: ${peerId}`)

    socket.setKeepAlive(true, 10000) // Keep connection alive with 10s interval

    // Send identification with our public keys
    const identityMessage = {
        type: "identify",
        service: "user-service",
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
                        console.log(`User service registered ${message.service} peer with keys`)
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

                    console.log(`User service received secure message: ${verifiedMessage.type}`)

                    // Handle wallet creation responses
                    if (verifiedMessage.type === "wallet-created") {
                        console.log(`Wallet created for user ${verifiedMessage.userId}: ${verifiedMessage.success}`)

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
        console.error(`User service connection error with ${peerId}:`, err.message)
    })

    socket.on("close", () => {
        console.log(`Peer ${peerId} disconnected from user service`)

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
                from: "user-service",
                data: encryptedData,
            }),
        )

        return true
    } catch (err) {
        console.error(`Error sending secure message to ${serviceName}:`, err)
        return false
    }
}

// Create wallet for user via wallet service
async function createUserWallet(userId, currency = "USD") {
    return new Promise((resolve, reject) => {
        if (!peers.has("wallet-service")) {
            return reject(new Error("No connection to wallet service"))
        }

        const requestId = Date.now().toString()

        // Set up request handler
        pendingRequests.set(requestId, (response) => {
            clearTimeout(timeoutId)

            if (response.success) {
                resolve(response)
            } else {
                reject(new Error(response.error || "Failed to create wallet"))
            }
        })

        // Send the request
        sendSecureMessage("wallet-service", {
            type: "create-wallet",
            userId,
            currency,
            requestId,
        })

        // Set timeout to prevent hanging
        const timeoutId = setTimeout(() => {
            pendingRequests.delete(requestId)
            reject(new Error("Request to wallet service timed out"))
        }, 10000)
    })
}

// Cleanup function
async function cleanup() {
    console.log("\nShutting down user service...")
    await swarm.leave(topic)
    await swarm.destroy()
    console.log("User service disconnected from all peers")
    process.exit(0)
}

// Handle termination
process.on("SIGINT", cleanup)
process.on("SIGTERM", cleanup)

// Express API
const app = express()
app.use(express.json())

app.post("/register", async (req, res) => {
    try {
        const { userId, name, email } = req.body

        if (!userId || !name || !email) {
            return res.status(400).json({ error: "userId, name, and email are required" })
        }

        // Check if user already exists
        const existing = await userDB.get(`user:${userId}`)
        if (existing) {
            return res.status(409).json({ error: "User already exists" })
        }

        // Create user
        const userData = {
            userId,
            name,
            email,
            createdAt: Date.now(),
        }

        await userDB.put(`user:${userId}`, userData)

        // Try to create a wallet for the user
        try {
            if (peers.has("wallet-service")) {
                await createUserWallet(userId)
                userData.walletCreated = true
            } else {
                userData.walletCreated = false
                userData.walletMessage = "Wallet service not available"
            }
        } catch (error) {
            console.error("Failed to create wallet for user:", error.message)
            userData.walletCreated = false
            userData.walletMessage = error.message
        }

        res.status(201).json({
            message: "User registered successfully",
            user: userData,
        })
    } catch (error) {
        console.error("Error registering user:", error)
        res.status(500).json({ error: "Failed to register user" })
    }
})

app.get("/profile/:userId", async (req, res) => {
    try {
        const user = await userDB.get(`user:${req.params.userId}`)

        if (!user) {
            return res.status(404).json({ error: "User not found" })
        }

        res.json(user.value)
    } catch (error) {
        console.error("Error fetching user profile:", error)
        res.status(500).json({ error: "Failed to fetch user profile" })
    }
})

app.put("/profile/:userId", async (req, res) => {
    try {
        const userId = req.params.userId
        const existingUser = await userDB.get(`user:${userId}`)

        if (!existingUser) {
            return res.status(404).json({ error: "User not found" })
        }

        // Don't allow changing userId
        const { userId: _, ...updateData } = req.body

        const updatedUser = {
            ...existingUser.value,
            ...updateData,
            updatedAt: Date.now(),
        }

        await userDB.put(`user:${userId}`, updatedUser)

        res.json({
            message: "Profile updated successfully",
            user: updatedUser,
        })
    } catch (error) {
        console.error("Error updating user profile:", error)
        res.status(500).json({ error: "Failed to update user profile" })
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
    console.log(`User service listening on port ${PORT}`)
})

