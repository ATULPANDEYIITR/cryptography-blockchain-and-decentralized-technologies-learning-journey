"use strict";

/**
 * MAC IN CRYPTOGRAPHY AND BLOCKCHAIN
 *
 * Node.js implementation using:
 * - crypto.createHmac()
 * - crypto.timingSafeEqual()
 * - asynchronous event-driven processing
 * - Maps and Sets
 * - transaction authentication
 * - replay protection
 * - block integrity validation
 * - configurable repository-style security policies
 *
 * Runtime: Node.js 18+
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

// ============================================================
// 1. DOMAIN ERRORS
// ============================================================

class MACError extends Error {
    constructor(message, code = "MAC_ERROR") {
        super(message);
        this.name = "MACError";
        this.code = code;
    }
}

class ValidationError extends MACError {
    constructor(message) {
        super(message, "VALIDATION_ERROR");
    }
}

class AuthenticationError extends MACError {
    constructor(message) {
        super(message, "AUTHENTICATION_ERROR");
    }
}

class ReplayError extends MACError {
    constructor(message) {
        super(message, "REPLAY_ERROR");
    }
}

// ============================================================
// 2. INPUT VALIDATION
// ============================================================

function requireString(value, field) {
    if (typeof value !== "string" || value.trim().length === 0) {
        throw new ValidationError(`${field} must be a non-empty string`);
    }

    return value;
}

function requirePositiveAmount(value) {
    if (
        typeof value !== "number" ||
        !Number.isFinite(value) ||
        value <= 0
    ) {
        throw new ValidationError("Amount must be a positive finite number");
    }

    return value;
}

// ============================================================
// 3. CRYPTOGRAPHIC KEY REGISTRY
// ============================================================

class KeyRegistry {
    #keys = new Map();

    create(keyId) {
        requireString(keyId, "keyId");

        if (this.#keys.has(keyId)) {
            throw new ValidationError("Key identifier already exists");
        }

        const secret = crypto.randomBytes(32);

        this.#keys.set(keyId, {
            secret,
            algorithm: "sha256",
            createdAt: Date.now()
        });

        return keyId;
    }

    register(keyId, secret) {
        requireString(keyId, "keyId");

        if (!Buffer.isBuffer(secret) || secret.length < 32) {
            throw new ValidationError("Key must contain at least 32 bytes");
        }

        if (this.#keys.has(keyId)) {
            throw new ValidationError("Duplicate key identifier");
        }

        this.#keys.set(keyId, {
            secret: Buffer.from(secret),
            algorithm: "sha256",
            createdAt: Date.now()
        });
    }

    get(keyId) {
        const entry = this.#keys.get(keyId);

        if (!entry) {
            throw new ValidationError("Unknown key identifier");
        }

        return entry.secret;
    }

    has(keyId) {
        return this.#keys.has(keyId);
    }
}

// ============================================================
// 4. CANONICAL MESSAGE SERIALIZATION
// ============================================================

function canonicalize(value) {
    if (value === null || typeof value !== "object") {
        throw new ValidationError("Expected a structured object");
    }

    // Recursively sort object keys to produce deterministic bytes.
    function normalize(input) {
        if (Array.isArray(input)) {
            return input.map(normalize);
        }

        if (input !== null && typeof input === "object") {
            const result = {};

            for (const key of Object.keys(input).sort()) {
                result[key] = normalize(input[key]);
            }

            return result;
        }

        if (typeof input === "number" && !Number.isFinite(input)) {
            throw new ValidationError("Non-finite numbers are prohibited");
        }

        if (typeof input === "bigint" || typeof input === "undefined") {
            throw new ValidationError("Unsupported serialization value");
        }

        return input;
    }

    return Buffer.from(
        JSON.stringify(normalize(value)),
        "utf8"
    );
}

// ============================================================
// 5. HMAC SERVICE
// ============================================================

class MACService {

    static generate(message, secret) {
        if (!Buffer.isBuffer(message)) {
            throw new ValidationError("Message must be a Buffer");
        }

        return crypto
            .createHmac("sha256", secret)
            .update(message)
            .digest();
    }

    static verify(message, suppliedMAC, secret) {
        if (
            !Buffer.isBuffer(message) ||
            !Buffer.isBuffer(suppliedMAC) ||
            suppliedMAC.length !== 32
        ) {
            return false;
        }

        const expected = MACService.generate(message, secret);

        // Node.js requires equal buffer lengths for timingSafeEqual.
        return crypto.timingSafeEqual(expected, suppliedMAC);
    }
}

// ============================================================
// 6. MESSAGE AUTHENTICATION
// ============================================================

class MessageService {

    constructor(keyRegistry) {
        this.keys = keyRegistry;
    }

    create(sender, receiver, payload, keyId) {
        requireString(sender, "sender");
        requireString(receiver, "receiver");
        requireString(payload, "payload");

        const message = {
            id: crypto.randomUUID(),
            sender,
            receiver,
            payload,
            timestamp: Date.now(),
            nonce: crypto.randomBytes(16).toString("hex"),
            keyId
        };

        const mac = MACService.generate(
            canonicalize(message),
            this.keys.get(keyId)
        );

        return Object.freeze({
            ...message,
            mac: mac.toString("hex")
        });
    }

    verify(message) {
        if (!message || typeof message !== "object") {
            return false;
        }

        try {
            const { mac, ...content } = message;

            if (
                typeof mac !== "string" ||
                !/^[0-9a-f]{64}$/i.test(mac)
            ) {
                return false;
            }

            return MACService.verify(
                canonicalize(content),
                Buffer.from(mac, "hex"),
                this.keys.get(content.keyId)
            );
        } catch {
            return false;
        }
    }
}

// ============================================================
// 7. REPLAY PROTECTION
// ============================================================

class ReplayGuard {

    #seen = new Map();

    constructor(maxAgeMs = 300000) {
        if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs <= 0) {
            throw new ValidationError("Invalid replay window");
        }

        this.maxAgeMs = maxAgeMs;
    }

    accept(message, now = Date.now()) {
        if (!Number.isSafeInteger(message.timestamp)) {
            throw new AuthenticationError("Invalid message timestamp");
        }

        const age = now - message.timestamp;

        if (age < -30000 || age > this.maxAgeMs) {
            throw new AuthenticationError("Message outside validity window");
        }

        const identity = `${message.sender}:${message.nonce}`;

        if (this.#seen.has(identity)) {
            throw new ReplayError("Previously processed nonce");
        }

        this.#seen.set(identity, now);

        // Remove expired entries to prevent unbounded memory growth.
        for (const [key, timestamp] of this.#seen) {
            if (now - timestamp > this.maxAgeMs) {
                this.#seen.delete(key);
            }
        }
    }
}

// ============================================================
// 8. BLOCKCHAIN TRANSACTION
// ============================================================

class Transaction {

    constructor({
        id,
        sender,
        receiver,
        amount,
        nonce,
        keyId
    }) {
        this.id = requireString(id, "id");
        this.sender = requireString(sender, "sender");
        this.receiver = requireString(receiver, "receiver");

        if (sender === receiver) {
            throw new ValidationError("Self-transfers are prohibited");
        }

        this.amount = requirePositiveAmount(amount);

        if (!Number.isSafeInteger(nonce) || nonce < 0) {
            throw new ValidationError("Invalid transaction nonce");
        }

        this.nonce = nonce;
        this.keyId = requireString(keyId, "keyId");
        this.mac = null;
    }

    content() {
        return {
            id: this.id,
            sender: this.sender,
            receiver: this.receiver,
            amount: this.amount,
            nonce: this.nonce,
            keyId: this.keyId
        };
    }
}

// ============================================================
// 9. TRANSACTION AUTHENTICATION SERVICE
// ============================================================

class TransactionAuthenticator {

    constructor(keyRegistry) {
        this.keys = keyRegistry;
    }

    authenticate(transaction) {
        const message = canonicalize(transaction.content());

        transaction.mac = MACService.generate(
            message,
            this.keys.get(transaction.keyId)
        ).toString("hex");

        return Object.freeze({
            ...transaction.content(),
            mac: transaction.mac
        });
    }

    verify(transaction) {
        if (
            !transaction ||
            typeof transaction.mac !== "string" ||
            !/^[0-9a-f]{64}$/i.test(transaction.mac)
        ) {
            return false;
        }

        try {
            return MACService.verify(
                canonicalize({
                    id: transaction.id,
                    sender: transaction.sender,
                    receiver: transaction.receiver,
                    amount: transaction.amount,
                    nonce: transaction.nonce,
                    keyId: transaction.keyId
                }),
                Buffer.from(transaction.mac, "hex"),
                this.keys.get(transaction.keyId)
            );
        } catch {
            return false;
        }
    }
}

// ============================================================
// 10. BLOCKCHAIN ENGINE
// ============================================================

class Blockchain extends EventEmitter {

    #blocks = [];
    #transactionIds = new Set();

    constructor(transactionAuthenticator) {
        super();

        this.authenticator = transactionAuthenticator;

        const genesis = {
            index: 0,
            timestamp: Date.now(),
            previousHash: "0".repeat(64),
            transactions: []
        };

        genesis.hash = this.hashBlock(genesis);
        this.#blocks.push(Object.freeze(genesis));
    }

    hashBlock(block) {
        return crypto
            .createHash("sha256")
            .update(canonicalize({
                index: block.index,
                timestamp: block.timestamp,
                previousHash: block.previousHash,
                transactions: block.transactions
            }))
            .digest("hex");
    }

    addBlock(transactions) {
        if (!Array.isArray(transactions) || transactions.length === 0) {
            throw new ValidationError("Block must contain transactions");
        }

        const localIds = new Set();

        for (const tx of transactions) {
            if (!this.authenticator.verify(tx)) {
                throw new AuthenticationError(
                    `Invalid transaction MAC: ${tx.id}`
                );
            }

            if (
                this.#transactionIds.has(tx.id) ||
                localIds.has(tx.id)
            ) {
                throw new ValidationError("Duplicate transaction identifier");
            }

            localIds.add(tx.id);
        }

        const previous = this.#blocks[this.#blocks.length - 1];

        const block = {
            index: this.#blocks.length,
            timestamp: Date.now(),
            previousHash: previous.hash,
            transactions: transactions.map(tx => ({ ...tx }))
        };

        block.hash = this.hashBlock(block);

        this.#blocks.push(Object.freeze(block));

        for (const id of localIds) {
            this.#transactionIds.add(id);
        }

        this.emit("blockAdded", {
            index: block.index,
            hash: block.hash
        });

        return block;
    }

    validate() {
        for (let i = 0; i < this.#blocks.length; i++) {
            const current = this.#blocks[i];

            if (current.hash !== this.hashBlock(current)) {
                return false;
            }

            if (i === 0) {
                if (current.previousHash !== "0".repeat(64)) {
                    return false;
                }
            } else if (
                current.previousHash !== this.#blocks[i - 1].hash
            ) {
                return false;
            }

            for (const tx of current.transactions) {
                if (!this.authenticator.verify(tx)) {
                    return false;
                }
            }
        }

        return true;
    }

    get blocks() {
        return this.#blocks.map(block => structuredClone(block));
    }
}

// ============================================================
// 11. EVENT-DRIVEN NODE
// ============================================================

class BlockchainNode extends EventEmitter {

    constructor(messageService, replayGuard) {
        super();

        this.messages = messageService;
        this.replayGuard = replayGuard;
    }

    async receive(message) {
        // Simulate an asynchronous network-processing boundary.
        await Promise.resolve();

        if (!this.messages.verify(message)) {
            this.emit("authenticationFailed", {
                sender: message?.sender ?? "unknown"
            });

            throw new AuthenticationError("Invalid message MAC");
        }

        this.replayGuard.accept(message);

        this.emit("messageAccepted", {
            sender: message.sender,
            messageId: message.id
        });

        return {
            accepted: true,
            sender: message.sender,
            payload: message.payload
        };
    }
}

// ============================================================
// 12. EXECUTION
// ============================================================

async function main() {

    console.log("MAC AND BLOCKCHAIN ENGINE");
    console.log("=".repeat(55));

    const keys = new KeyRegistry();
    keys.create("consensus-node-01");

    const secret = keys.get("consensus-node-01");

    // Basic HMAC.
    const original = Buffer.from("Blockchain transaction");

    const generated = MACService.generate(original, secret);

    console.log("\n1. HMAC-SHA256");

    console.log(
        "Valid:",
        MACService.verify(original, generated, secret)
    );

    console.log(
        "Tampered:",
        MACService.verify(
            Buffer.from("Modified transaction"),
            generated,
            secret
        )
    );

    // Message processing.
    const messageService = new MessageService(keys);
    const replayGuard = new ReplayGuard();

    const message = messageService.create(
        "node-A",
        "node-B",
        "Block proposal",
        "consensus-node-01"
    );

    const node = new BlockchainNode(messageService, replayGuard);

    node.on("messageAccepted", event => {
        console.log("\nMessage accepted:", event.messageId);
    });

    node.on("authenticationFailed", event => {
        console.log("\nAuthentication failed:", event.sender);
    });

    console.log("\n2. Asynchronous Message Processing");

    console.log(await node.receive(message));

    try {
        await node.receive(message);
    } catch (error) {
        console.log("Replay rejected:", error.code);
    }

    // Transaction.
    const transaction = new Transaction({
        id: "TX-001",
        sender: "wallet-A",
        receiver: "wallet-B",
        amount: 250.75,
        nonce: 1,
        keyId: "consensus-node-01"
    });

    const transactionService = new TransactionAuthenticator(keys);
    const authenticated = transactionService.authenticate(transaction);

    console.log("\n3. Transaction Authentication");
    console.log("Authenticated:", transactionService.verify(authenticated));

    // Blockchain.
    const blockchain = new Blockchain(transactionService);

    blockchain.on("blockAdded", event => {
        console.log("Block added:", event.index, event.hash);
    });

    blockchain.addBlock([authenticated]);

    console.log("\n4. Blockchain Integrity");
    console.log("Valid chain:", blockchain.validate());

    // Tampering.
    const tampered = {
        ...authenticated,
        amount: 999999
    };

    console.log("\n5. Tampering Detection");
    console.log("Modified transaction valid:",
        transactionService.verify(tampered));

    // Validation failures.
    console.log("\n6. Invalid Transaction Handling");

    try {
        new Transaction({
            id: "TX-002",
            sender: "wallet-A",
            receiver: "wallet-A",
            amount: 10,
            nonce: 1,
            keyId: "consensus-node-01"
        });
    } catch (error) {
        console.log("Rejected:", error.message);
    }

    // Assertions.
    if (!blockchain.validate()) {
        throw new Error("Blockchain integrity test failed");
    }

    if (transactionService.verify(tampered)) {
        throw new Error("Tampering test failed");
    }

    console.log("\nAll tests passed.");
}

main().catch(error => {
    console.error("Execution failure:", error.message);
    process.exitCode = 1;
});
