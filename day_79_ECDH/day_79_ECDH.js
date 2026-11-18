"use strict";

/*
 * ECDH in Blockchain
 *
 * Node.js implementation using:
 * - Native secp256k1 ECDH
 * - SHA-256 and HKDF
 * - Event-driven blockchain processing
 * - Wallet identity registration
 * - Transaction validation
 * - Nonce-based replay prevention
 * - Block integrity verification
 * - Asynchronous transaction processing
 *
 * Run: node ecdh_blockchain.js
 *
 * Production systems should use authenticated encryption,
 * digital signatures, secure key storage and audited libraries.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

const CURVE = "secp256k1";

class ValidationError extends Error {}
class BlockchainError extends Error {}

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function canonicalJSON(value) {
    if (Array.isArray(value)) {
        return `[${value.map(canonicalJSON).join(",")}]`;
    }

    if (value !== null && typeof value === "object") {
        const keys = Object.keys(value).sort();

        return `{${keys.map(key =>
            `${JSON.stringify(key)}:${canonicalJSON(value[key])}`
        ).join(",")}}`;
    }

    return JSON.stringify(value);
}

function createWallet() {
    const ecdh = crypto.createECDH(CURVE);
    ecdh.generateKeys();

    const publicKey = ecdh.getPublicKey("hex", "compressed");
    const address = sha256(Buffer.from(publicKey, "hex")).slice(0, 40);

    return {
        address,
        publicKey,
        ecdh
    };
}

function validatePublicKey(publicKey) {
    if (
        typeof publicKey !== "string" ||
        !/^(02|03)[0-9a-f]{64}$/i.test(publicKey)
    ) {
        throw new ValidationError("Invalid compressed public key.");
    }

    const probe = crypto.createECDH(CURVE);

    try {
        probe.setPrivateKey(
            Buffer.from("01".padStart(64, "0"), "hex")
        );
        probe.computeSecret(Buffer.from(publicKey, "hex"));
    } catch {
        throw new ValidationError("Public key is not valid on secp256k1.");
    }
}

function deriveChannelKey(
    privateWallet,
    peerPublicKey,
    sessionId,
    participantA,
    participantB
) {
    validatePublicKey(peerPublicKey);

    if (!sessionId || typeof sessionId !== "string") {
        throw new ValidationError("A session identifier is required.");
    }

    const participants = [
        participantA,
        participantB
    ].sort();

    const context = Buffer.from(
        JSON.stringify({
            participants,
            sessionId,
            protocol: "blockchain-ecdh-v1"
        })
    );

    const sharedSecret = privateWallet.ecdh.computeSecret(
        Buffer.from(peerPublicKey, "hex")
    );

    const salt = crypto
        .createHash("sha256")
        .update("blockchain-ecdh-v1")
        .update(context)
        .digest();

    const info = Buffer.from("secp256k1-secure-channel");

    const key = Buffer.from(
        crypto.hkdfSync(
            "sha256",
            sharedSecret,
            salt,
            info,
            32
        )
    );

    sharedSecret.fill(0);

    return key;
}

class Blockchain extends EventEmitter {
    constructor() {
        super();

        this.blocks = [];
        this.pending = [];
        this.wallets = new Map();
        this.nonces = new Map();
        this.transactionIds = new Set();

        this.createGenesisBlock();
    }

    createGenesisBlock() {
        const block = {
            index: 0,
            previousHash: "0".repeat(64),
            timestamp: Date.now(),
            transactions: [],
            hash: ""
        };

        block.hash = this.calculateHash(block);
        this.blocks.push(block);
    }

    get latestBlock() {
        return this.blocks[this.blocks.length - 1];
    }

    calculateHash(block) {
        const data = {
            index: block.index,
            previousHash: block.previousHash,
            timestamp: block.timestamp,
            transactions: block.transactions
        };

        return sha256(Buffer.from(canonicalJSON(data)));
    }

    registerWallet(wallet) {
        if (this.wallets.has(wallet.address)) {
            throw new BlockchainError("Wallet already registered.");
        }

        validatePublicKey(wallet.publicKey);

        const expectedAddress = sha256(
            Buffer.from(wallet.publicKey, "hex")
        ).slice(0, 40);

        if (wallet.address !== expectedAddress) {
            throw new ValidationError("Wallet address mismatch.");
        }

        this.wallets.set(wallet.address, {
            publicKey: wallet.publicKey,
            registeredAt: Date.now()
        });

        this.nonces.set(wallet.address, 0);

        this.emit("walletRegistered", {
            address: wallet.address
        });
    }

    validateTransaction(transaction) {
        const {
            id,
            sender,
            recipient,
            amount,
            nonce,
            channelCommitment
        } = transaction;

        if (!id || typeof id !== "string") {
            throw new ValidationError("Invalid transaction ID.");
        }

        if (this.transactionIds.has(id)) {
            throw new BlockchainError("Duplicate transaction.");
        }

        if (!this.wallets.has(sender) || !this.wallets.has(recipient)) {
            throw new ValidationError("Unknown wallet.");
        }

        if (sender === recipient) {
            throw new ValidationError("Self-transfers are prohibited.");
        }

        if (!Number.isSafeInteger(amount) || amount <= 0) {
            throw new ValidationError("Invalid transfer amount.");
        }

        if (!Number.isSafeInteger(nonce) || nonce < 0) {
            throw new ValidationError("Invalid transaction nonce.");
        }

        if (nonce !== this.nonces.get(sender)) {
            throw new BlockchainError("Nonce mismatch.");
        }

        if (!/^[a-f0-9]{64}$/i.test(channelCommitment)) {
            throw new ValidationError("Invalid channel commitment.");
        }
    }

    async submitTransaction(transaction) {
        // Defer validation and processing to the event loop.
        await new Promise(resolve => setImmediate(resolve));

        this.validateTransaction(transaction);

        this.transactionIds.add(transaction.id);
        this.nonces.set(
            transaction.sender,
            transaction.nonce + 1
        );

        this.pending.push(Object.freeze({ ...transaction }));

        this.emit("transactionSubmitted", {
            id: transaction.id
        });

        return transaction.id;
    }

    mineBlock() {
        if (this.pending.length === 0) {
            throw new BlockchainError("No pending transactions.");
        }

        const block = {
            index: this.blocks.length,
            previousHash: this.latestBlock.hash,
            timestamp: Date.now(),
            transactions: this.pending.map(transaction => ({
                ...transaction
            })),
            hash: ""
        };

        block.hash = this.calculateHash(block);

        this.blocks.push(block);
        this.pending = [];

        this.emit("blockMined", {
            index: block.index,
            hash: block.hash
        });

        return block;
    }

    verifyChain() {
        for (let i = 0; i < this.blocks.length; i++) {
            const current = this.blocks[i];

            if (current.hash !== this.calculateHash(current)) {
                return false;
            }

            if (i === 0) {
                if (current.previousHash !== "0".repeat(64)) {
                    return false;
                }
                continue;
            }

            const previous = this.blocks[i - 1];

            if (current.previousHash !== previous.hash) {
                return false;
            }

            if (current.index !== previous.index + 1) {
                return false;
            }
        }

        return true;
    }
}

async function main() {
    console.log("ECDH BLOCKCHAIN DEMONSTRATION");
    console.log("=".repeat(55));

    const alice = createWallet();
    const bob = createWallet();

    const blockchain = new Blockchain();

    blockchain.on("walletRegistered", event => {
        console.log("Registered wallet:", event.address);
    });

    blockchain.on("transactionSubmitted", event => {
        console.log("Transaction accepted:", event.id);
    });

    blockchain.on("blockMined", event => {
        console.log("Block mined:", event.index);
    });

    blockchain.registerWallet(alice);
    blockchain.registerWallet(bob);

    const sessionId = crypto.randomBytes(16).toString("hex");

    const aliceKey = deriveChannelKey(
        alice,
        bob.publicKey,
        sessionId,
        alice.address,
        bob.address
    );

    const bobKey = deriveChannelKey(
        bob,
        alice.publicKey,
        sessionId,
        bob.address,
        alice.address
    );

    if (!crypto.timingSafeEqual(aliceKey, bobKey)) {
        throw new BlockchainError("ECDH key agreement failed.");
    }

    console.log("\nECDH key agreement successful.");

    const channelCommitment = sha256(
        Buffer.concat([
            Buffer.from("channel-commitment-v1"),
            aliceKey
        ])
    );

    const publicKeyCommitment = sha256(
        Buffer.concat([
            Buffer.from(alice.publicKey, "hex"),
            Buffer.from(bob.publicKey, "hex")
        ])
    );

    console.log("Channel fingerprint:", sha256(aliceKey).slice(0, 24));

    const transaction = {
        id: crypto.randomBytes(16).toString("hex"),
        sender: alice.address,
        recipient: bob.address,
        amount: 250,
        nonce: 0,
        channelCommitment,
        publicKeyCommitment,
        timestamp: Date.now()
    };

    await blockchain.submitTransaction(transaction);

    const block = blockchain.mineBlock();

    console.log("\nBlock details:");
    console.log("Index:", block.index);
    console.log("Hash:", block.hash);
    console.log("Transactions:", block.transactions.length);

    console.log("\nChain integrity:", blockchain.verifyChain());

    try {
        await blockchain.submitTransaction(transaction);
    } catch (error) {
        console.log("Replay rejected:", error.message);
    }

    block.transactions[0].amount = 9999;

    console.log(
        "Integrity after tampering:",
        blockchain.verifyChain()
    );

    // Restore demonstration state.
    block.transactions[0].amount = 250;

    console.log(
        "Integrity after restoration:",
        blockchain.verifyChain()
    );

    aliceKey.fill(0);
    bobKey.fill(0);

    console.log("\nECDH demonstration completed.");
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
