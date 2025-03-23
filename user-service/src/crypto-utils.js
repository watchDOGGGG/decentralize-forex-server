import crypto from "crypto"

// Generate ECDH key pair for encryption
export function generateECDHKeys() {
    const ecdh = crypto.createECDH("secp256k1")
    ecdh.generateKeys("hex")
    return {
        publicKey: ecdh.getPublicKey("hex"),
        privateKey: ecdh.getPrivateKey("hex"),
        ecdh,
    }
}

// Generate ECDSA Key Pair for Signing
export function generateSigningKeys() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "secp256k1",
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
    })
    return { privateKey, publicKey }
}

// Derive shared secret using ECDH
export function deriveSharedSecret(ecdh, peerPublicKey) {
    try {
        if (!ecdh) {
            console.error("No ECDH instance provided for deriving shared secret")
            return null
        }

        if (!peerPublicKey) {
            console.error("No peer public key provided for deriving shared secret")
            return null
        }

        return ecdh.computeSecret(peerPublicKey, "hex", "hex")
    } catch (error) {
        console.error("Error deriving shared secret:", error)
        return null
    }
}

// Sign a message using ECDSA
export function signMessage(message, privateKey) {
    const sign = crypto.createSign("SHA256")
    sign.update(typeof message === "string" ? message : JSON.stringify(message))
    sign.end()
    return sign.sign(privateKey, "hex")
}

// Verify a message signature
export function verifySignature(message, signature, publicKey) {
    try {
        // Check if all required parameters are provided
        if (!message || !signature || !publicKey) {
            console.error("Missing required parameters for signature verification:", {
                hasMessage: !!message,
                hasSignature: !!signature,
                hasPublicKey: !!publicKey,
            })
            return false
        }

        const verify = crypto.createVerify("SHA256")
        verify.update(typeof message === "string" ? message : JSON.stringify(message))
        verify.end()
        return verify.verify(publicKey, signature, "hex")
    } catch (error) {
        console.error("Signature verification error:", error)
        return false
    }
}

// Encrypt a message using AES-256-GCM
export function encryptMessage(message, sharedSecret) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(sharedSecret, "hex"), iv)

    let encrypted = cipher.update(JSON.stringify(message), "utf8", "hex")
    encrypted += cipher.final("hex")

    const authTag = cipher.getAuthTag().toString("hex")

    return {
        iv: iv.toString("hex"),
        encrypted,
        authTag,
    }
}

// Decrypt a message
export function decryptMessage(encryptedData, sharedSecret) {
    try {
        // Validate inputs
        if (!encryptedData) {
            console.error("No encrypted data provided for decryption")
            return null
        }

        if (!sharedSecret) {
            console.error("No shared secret provided for decryption")
            return null
        }

        const { iv, encrypted, authTag } = encryptedData

        if (!iv || !encrypted || !authTag) {
            console.error("Encrypted data is missing required fields:", {
                hasIv: !!iv,
                hasEncrypted: !!encrypted,
                hasAuthTag: !!authTag,
            })
            return null
        }

        const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(sharedSecret, "hex"), Buffer.from(iv, "hex"))

        decipher.setAuthTag(Buffer.from(authTag, "hex"))

        let decrypted = decipher.update(encrypted, "hex", "utf8")
        decrypted += decipher.final("utf8")

        return JSON.parse(decrypted)
    } catch (error) {
        console.error("Decryption error:", error)
        return null
    }
}

// Create a secure message (signed and with timestamp)
export function createSecureMessage(message, signingPrivateKey) {
    // Add timestamp to prevent replay attacks
    const messageWithTimestamp = {
        ...message,
        timestamp: Date.now(),
    }

    // Create a copy without signature for signing
    const messageForSigning = { ...messageWithTimestamp }

    // Sign the message
    const signature = signMessage(messageForSigning, signingPrivateKey)

    // Return message with signature
    return {
        ...messageWithTimestamp,
        signature,
    }
}

// Encrypt a secure message for a specific peer
export function encryptForPeer(message, sharedSecret) {
    return encryptMessage(message, sharedSecret)
}

// Process a received secure message
export function processSecureMessage(message, signPublicKey, maxAgeMs = 5 * 60 * 1000) {
    try {
        // Check if message and public key are provided
        if (!message) {
            throw new Error("No message provided for processing")
        }

        if (!signPublicKey) {
            throw new Error("No signing public key provided for verification")
        }

        // Check if signature exists in the message
        if (!message.signature) {
            throw new Error("Message has no signature")
        }

        // Make a copy without signature for verification
        const { signature, ...messageWithoutSignature } = message

        // Verify signature
        if (!verifySignature(messageWithoutSignature, signature, signPublicKey)) {
            throw new Error("Invalid message signature")
        }

        // Check timestamp to prevent replay attacks
        const now = Date.now()
        const messageTime = message.timestamp

        if (!messageTime) {
            throw new Error("Message has no timestamp")
        }

        if (now - messageTime > maxAgeMs) {
            throw new Error("Message expired (too old)")
        }

        return message
    } catch (error) {
        console.error("Error processing secure message:", error.message)
        throw error
    }
}

// Send secure message to a service
export function sendSecureMessage(socket, message, fromService, signingPrivateKey, peerId, sharedSecret) {
    try {
        // Validate inputs
        if (!socket || !message || !fromService || !signingPrivateKey || !peerId || !sharedSecret) {
            console.error("Missing required parameters for sending secure message:", {
                hasSocket: !!socket,
                hasMessage: !!message,
                hasFromService: !!fromService,
                hasSigningPrivateKey: !!signingPrivateKey,
                hasPeerId: !!peerId,
                hasSharedSecret: !!sharedSecret,
            })
            return false
        }

        // Create signed message
        const signedMessage = createSecureMessage(message, signingPrivateKey)

        // Encrypt the signed message
        const encryptedData = encryptForPeer(signedMessage, sharedSecret)

        if (!encryptedData) {
            console.error("Failed to encrypt message")
            return false
        }

        // Send the encrypted message
        socket.write(
            JSON.stringify({
                type: "secure",
                from: fromService,
                data: encryptedData,
            }),
        )

        return true
    } catch (err) {
        console.error(`Error sending secure message:`, err)
        return false
    }
}

