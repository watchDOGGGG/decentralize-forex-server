# Hyperswarm Forex Network - Rate Service

## Overview

The Hyperswarm Forex Network - Rate Service is a decentralized service designed to securely communicate and exchange forex rates between peers using Hyperswarm, Corestore, Hyperbee, and cryptographic techniques for authentication and encryption.

## Features

- **Decentralized Peer-to-Peer Communication** via Hyperswarm.
- **Encrypted Communication** using AES-256-GCM with ECDH-derived shared secrets.
- **Digital Signing & Verification** using ECDSA (secp256k1) for message integrity.
- **Forex Rate Storage & Retrieval** using Hyperbee (built on Corestore).
- **Auto Peer Discovery & Secure Messaging** between network participants.

## Technologies Used

- [Hyperswarm](https://github.com/holepunchto/hyperswarm) - Peer-to-peer networking.
- [Corestore](https://github.com/holepunchto/corestore) - Data storage layer.
- [Hyperbee](https://github.com/holepunchto/hyperbee) - Key-value database.
- [Node.js Crypto Module](https://nodejs.org/api/crypto.html) - Encryption and signing.
- [Express.js](https://expressjs.com/) - REST API for local interactions.

---

## Security Implementation

### 1. Authentication via Digital Signatures

Each peer generates an **ECDSA (secp256k1) key pair** to sign and verify messages.

- A message is signed using the sender's **private key**.
- The recipient verifies the signature using the sender's **public key**.

```js
function signMessage(message) {
  const sign = crypto.createSign("SHA256");
  sign.update(message);
  sign.end();
  return sign.sign(signPrivateKey, "hex");
}

function verifySignature(message, signature, peerPublicKey) {
  const verify = crypto.createVerify("SHA256");
  verify.update(message);
  verify.end();
  return verify.verify(peerPublicKey, signature, "hex");
}
```

### 2. Secure Key Exchange with ECDH

- Each peer generates an **ECDH (secp256k1) key pair**.
- When peers connect, they **exchange public keys**.
- A **shared secret** is derived and used as the encryption key.

```js
function deriveSharedSecret(peerPublicKey) {
  const sharedSecret = ecdh.computeSecret(peerPublicKey, "hex", "hex");
  sharedSecrets.set(peerPublicKey, sharedSecret);
  return sharedSecret;
}
```

### 3. Encrypted Communication using AES-256-GCM

Once the shared secret is derived, messages are encrypted and decrypted using **AES-256-GCM**.

```js
function encryptMessage(message, peerPublicKey) {
  const sharedSecret = sharedSecrets.get(peerPublicKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(sharedSecret, "hex"),
    iv
  );
  let encrypted = cipher.update(JSON.stringify(message), "utf8", "hex");
  encrypted += cipher.final("hex");
  return JSON.stringify({
    iv: iv.toString("hex"),
    encrypted,
    authTag: cipher.getAuthTag().toString("hex"),
  });
}
```

```js
function decryptMessage(encryptedMessage, peerPublicKey) {
  const sharedSecret = sharedSecrets.get(peerPublicKey);
  const { iv, encrypted, authTag } = JSON.parse(encryptedMessage);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(sharedSecret, "hex"),
    Buffer.from(iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}
```

---

## Network Architecture

### Services & Communication Flow

1. **Rate Service** (this module) acts as a data provider.
2. **Peers** connect via Hyperswarm and establish secure communication.
3. **Rate Database (Hyperbee)** stores and retrieves forex rates.
4. **Messages are signed and encrypted** before transmission.

### Message Exchange Steps

1. **Identity Exchange**: Peers send their public keys upon connection.
2. **Signature Verification**: Every message is verified.
3. **Encryption**: Data is encrypted before sending.
4. **Decryption**: Receiver decrypts using the shared secret.

---

## Running the Rate Service

### Prerequisites

- Install [Node.js](https://nodejs.org/)
- Clone this repository.
- Install dependencies:
  ```sh
  npm install
  ```

### Start the Service

```sh
node src/server.js
```

### API Endpoints

- **GET /rates** - Fetches stored exchange rates.
- **POST /update** - Updates exchange rates in Hyperbee.

---

## Future Improvements

- Implement a **peer reputation system** to track reliable sources.
- Add **peer relay services** for better connectivity.
- Improve **rate validation** to prevent data poisoning attacks.

---

## License

MIT License. Open for contributions!

---

🚀 **Project By Prince Randy**
