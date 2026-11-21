"use strict";

/*
 * ECDSA IN BLOCKCHAIN AND CRYPTOGRAPHY
 *
 * Node.js implementation using the built-in crypto module.
 *
 * Cryptographic operations use secp256k1 and SHA-256.
 * Private keys remain in KeyObject instances.
 * Signatures use ASN.1 DER encoding.
 *
 * Run:
 * node ecdsa_blockchain.js
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

// ============================================================
// 1. Configuration and domain errors
// ============================================================

const CURVE = "secp256k1";
const HASH_ALGORITHM = "sha256";

class CryptoError extends Error {
    constructor(message) {
        super(message);
        this.name = "CryptoError";
    }
}

class TransactionError extends Error {
    constructor(message) {
        super(message);
        this.name = "TransactionError";
    }
}

class GovernanceError extends Error {
    constructor(message) {
        super(message);
        this.name = "GovernanceError";
    }
}

// ============================================================
// 2. Canonical serialization
// ============================================================

function canonicalize(value) {
    if (value === null || typeof value !== "object") {
        if (typeof value === "number" && !Number.isSafeInteger(value)) {
            throw new TypeError("Only safe integers are accepted");
        }

        if (typeof value === "bigint") {
            throw new TypeError("Convert BigInt to a canonical string");
        }

        return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(",")}]`;
    }

    const keys = Object.keys(value).sort();

    return `{${keys.map(key =>
        `${JSON.stringify(key)}:${canonicalize(value[key])}`
    ).join(",")}}`;
}

function sha256(data) {
    return crypto.createHash(HASH_ALGORITHM)
        .update(data)
        .digest("hex");
}

function digestBuffer(data) {
    return crypto.createHash(HASH_ALGORITHM)
        .update(data)
        .digest();
}

// ============================================================
// 3. Key management
// ============================================================

class KeyPair {
    constructor(privateKey, publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        Object.freeze(this);
    }

    static generate() {
        const pair = crypto.generateKeyPairSync("ec", {
            namedCurve: CURVE,
            publicKeyEncoding: {
                type: "spki",
                format: "pem"
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem"
            }
        });

        return new KeyPair(
            crypto.createPrivateKey(pair.privateKey),
            crypto.createPublicKey(pair.publicKey)
        );
    }

    getAddress() {
        const publicDer = this.publicKey.export({
            type: "spki",
            format: "der"
        });

        return `bc_${sha256(publicDer).slice(0, 40)}`;
    }

    sign(data) {
        const signer = crypto.createSign(HASH_ALGORITHM);

        signer.update(data);
        signer.end();

        return signer.sign(this.privateKey).toString("hex");
    }

    static verify(publicKey, data, signatureHex) {
        try {
            if (
                typeof signatureHex !== "string" ||
                !/^(?:[0-9a-f]{2})+$/i.test(signatureHex)
            ) {
                return false;
            }

            const verifier = crypto.createVerify(HASH_ALGORITHM);

            verifier.update(data);
            verifier.end();

            return verifier.verify(
                publicKey,
                Buffer.from(signatureHex, "hex")
            );
        } catch {
            return false;
        }
    }
}

// ============================================================
// 4. Wallet registry
// ============================================================

class WalletRegistry {
    #wallets = new Map();

    register(keyPair) {
        if (!(keyPair instanceof KeyPair)) {
            throw new TypeError("Expected a KeyPair");
        }

        const address = keyPair.getAddress();

        if (this.#wallets.has(address)) {
            throw new CryptoError("Wallet already registered");
        }

        this.#wallets.set(address, keyPair.publicKey);

        return address;
    }

    getPublicKey(address) {
        const publicKey = this.#wallets.get(address);

        if (!publicKey) {
            throw new CryptoError("Unknown wallet address");
        }

        return publicKey;
    }

    verify(address, payload, signature) {
        return KeyPair.verify(
            this.getPublicKey(address),
            payload,
            signature
        );
    }
}

// ============================================================
// 5. Transaction state machine
// ============================================================

const TransactionState = Object.freeze({
    CREATED: "CREATED",
    SIGNED: "SIGNED",
    VERIFIED: "VERIFIED",
    INCLUDED: "INCLUDED",
    REJECTED: "REJECTED"
});

class BlockchainTransaction {
    constructor({
        sender,
        recipient,
        amount,
        nonce,
        timestamp = Date.now()
    }) {
        if (!sender || !recipient) {
            throw new TransactionError("Wallet addresses are required");
        }

        if (!Number.isSafeInteger(amount) || amount <= 0) {
            throw new TransactionError("Invalid transaction amount");
        }

        if (!Number.isSafeInteger(nonce) || nonce < 0) {
            throw new TransactionError("Invalid account nonce");
        }

        if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
            throw new TransactionError("Invalid timestamp");
        }

        this.sender = sender;
        this.recipient = recipient;
        this.amount = amount;
        this.nonce = nonce;
        this.timestamp = timestamp;

        this.signature = null;
        this.state = TransactionState.CREATED;

        this.transactionId = sha256(this.payload());
    }

    payload() {
        return canonicalize({
            amount: this.amount,
            nonce: this.nonce,
            recipient: this.recipient,
            sender: this.sender,
            timestamp: this.timestamp
        });
    }

    sign(keyPair) {
        if (this.state !== TransactionState.CREATED) {
            throw new TransactionError("Transaction cannot be signed now");
        }

        if (keyPair.getAddress() !== this.sender) {
            throw new CryptoError("Signer does not own sender address");
        }

        this.signature = keyPair.sign(this.payload());
        this.state = TransactionState.SIGNED;
    }

    verify(registry) {
        if (this.state !== TransactionState.SIGNED) {
            throw new TransactionError("Transaction must be signed first");
        }

        const valid = registry.verify(
            this.sender,
            this.payload(),
            this.signature
        );

        this.state = valid
            ? TransactionState.VERIFIED
            : TransactionState.REJECTED;

        return valid;
    }

    markIncluded() {
        if (this.state !== TransactionState.VERIFIED) {
            throw new TransactionError(
                "Only verified transactions can be included"
            );
        }

        this.state = TransactionState.INCLUDED;
    }
}

// ============================================================
// 6. Asynchronous transaction processing
// ============================================================

class TransactionProcessor extends EventEmitter {
    constructor(registry) {
        super();
        this.registry = registry;
        this.pending = new Map();
        this.processing = false;
    }

    submit(transaction) {
        if (!(transaction instanceof BlockchainTransaction)) {
            throw new TypeError("Invalid transaction object");
        }

        if (this.pending.has(transaction.transactionId)) {
            throw new TransactionError("Duplicate transaction");
        }

        this.pending.set(transaction.transactionId, transaction);

        this.emit("transaction:submitted", {
            transactionId: transaction.transactionId
        });
    }

    async process() {
        if (this.processing) {
            throw new TransactionError("Processor is already running");
        }

        this.processing = true;

        const results = [];

        try {
            for (const [id, transaction] of this.pending) {
                await new Promise(resolve => setImmediate(resolve));

                try {
                    const valid = transaction.verify(this.registry);

                    results.push({
                        transactionId: id,
                        accepted: valid,
                        state: transaction.state
                    });

                    this.emit(
                        valid ? "transaction:verified" : "transaction:rejected",
                        { transactionId: id }
                    );

                    if (!valid) {
                        this.pending.delete(id);
                    }
                } catch (error) {
                    transaction.state = TransactionState.REJECTED;

                    results.push({
                        transactionId: id,
                        accepted: false,
                        error: error.message
                    });

                    this.pending.delete(id);
                }
            }

            return results;
        } finally {
            this.processing = false;
        }
    }

    removeIncluded(transaction) {
        if (transaction.state !== TransactionState.INCLUDED) {
            throw new TransactionError("Transaction is not included");
        }

        this.pending.delete(transaction.transactionId);
    }
}

// ============================================================
// 7. Block and blockchain
// ============================================================

class Block {
    constructor(index, previousHash, transactions) {
        this.index = index;
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.timestamp = Date.now();
        this.blockHash = this.calculateHash();
    }

    calculateHash() {
        return sha256(canonicalize({
            index: this.index,
            previousHash: this.previousHash,
            timestamp: this.timestamp,
            transactions: this.transactions.map(tx => ({
                id: tx.transactionId,
                signature: tx.signature
            }))
        }));
    }
}

class Blockchain {
    constructor() {
        this.blocks = [];

        const genesis = new Block(0, "0".repeat(64), []);
        this.blocks.push(genesis);
    }

    addBlock(transactions) {
        if (!Array.isArray(transactions) || transactions.length === 0) {
            throw new TransactionError("Block cannot be empty");
        }

        const uniqueIds = new Set();

        for (const transaction of transactions) {
            if (transaction.state !== TransactionState.VERIFIED) {
                throw new TransactionError("Unverified transaction");
            }

            if (uniqueIds.has(transaction.transactionId)) {
                throw new TransactionError("Duplicate transaction in block");
            }

            uniqueIds.add(transaction.transactionId);
        }

        const previous = this.blocks[this.blocks.length - 1];

        const block = new Block(
            this.blocks.length,
            previous.blockHash,
            transactions
        );

        for (const transaction of transactions) {
            transaction.markIncluded();
        }

        this.blocks.push(block);

        return block;
    }

    validate() {
        for (let i = 0; i < this.blocks.length; i++) {
            const block = this.blocks[i];

            if (block.blockHash !== block.calculateHash()) {
                return false;
            }

            if (
                i > 0 &&
                block.previousHash !== this.blocks[i - 1].blockHash
            ) {
                return false;
            }

            if (block.index !== i) {
                return false;
            }
        }

        return true;
    }
}

// ============================================================
// 8. Signature policy
// ============================================================

class SignaturePolicy {
    constructor({ requiredAlgorithm, allowedCurve }) {
        this.requiredAlgorithm = requiredAlgorithm;
        this.allowedCurve = allowedCurve;
    }

    validate() {
        if (this.requiredAlgorithm !== "ECDSA-SHA256") {
            throw new GovernanceError("Unsupported signature algorithm");
        }

        if (this.allowedCurve !== CURVE) {
            throw new GovernanceError("Unapproved elliptic curve");
        }

        return true;
    }
}

// ============================================================
// 9. Demonstration and testing
// ============================================================

async function main() {
    console.log("ECDSA BLOCKCHAIN ENGINEERING");
    console.log("=".repeat(55));

    const policy = new SignaturePolicy({
        requiredAlgorithm: "ECDSA-SHA256",
        allowedCurve: "secp256k1"
    });

    policy.validate();

    const registry = new WalletRegistry();

    const sender = KeyPair.generate();
    const recipient = KeyPair.generate();

    const senderAddress = registry.register(sender);
    const recipientAddress = registry.register(recipient);

    console.log("\n1. WALLET GENERATION");
    console.log("Sender:", senderAddress);
    console.log("Recipient:", recipientAddress);
    console.log("Curve:", CURVE);

    const transaction = new BlockchainTransaction({
        sender: senderAddress,
        recipient: recipientAddress,
        amount: 500,
        nonce: 1
    });

    transaction.sign(sender);

    console.log("\n2. SIGNATURE");
    console.log("Transaction ID:", transaction.transactionId);
    console.log("Signature format: DER encoded hexadecimal");
    console.log("State:", transaction.state);

    const processor = new TransactionProcessor(registry);

    processor.on("transaction:submitted", event => {
        console.log("Submitted:", event.transactionId.slice(0, 16));
    });

    processor.on("transaction:verified", event => {
        console.log("Verified:", event.transactionId.slice(0, 16));
    });

    processor.on("transaction:rejected", event => {
        console.log("Rejected:", event.transactionId.slice(0, 16));
    });

    processor.submit(transaction);

    const results = await processor.process();

    console.log("\n3. VERIFICATION RESULTS");
    console.log(results);

    console.log("\n4. BLOCKCHAIN INCLUSION");

    const chain = new Blockchain();
    const block = chain.addBlock([transaction]);

    processor.removeIncluded(transaction);

    console.log("Block index:", block.index);
    console.log("Block hash:", block.blockHash);
    console.log("Transaction state:", transaction.state);
    console.log("Blockchain valid:", chain.validate());

    console.log("\n5. TAMPERING TEST");

    const tamperedPayload = canonicalize({
        amount: 501,
        nonce: transaction.nonce,
        recipient: transaction.recipient,
        sender: transaction.sender,
        timestamp: transaction.timestamp
    });

    const tamperedValid = registry.verify(
        senderAddress,
        tamperedPayload,
        transaction.signature
    );

    console.log("Modified amount accepted:", tamperedValid);

    if (tamperedValid) {
        throw new Error("Tampering test failed");
    }

    console.log("\n6. FAILURE HANDLING");

    try {
        new BlockchainTransaction({
            sender: senderAddress,
            recipient: recipientAddress,
            amount: -1,
            nonce: 0
        });
    } catch (error) {
        console.log("Negative amount rejected:", error.message);
    }

    try {
        const unauthorized = new BlockchainTransaction({
            sender: senderAddress,
            recipient: recipientAddress,
            amount: 100,
            nonce: 2
        });

        unauthorized.sign(recipient);
    } catch (error) {
        console.log("Unauthorized signing rejected:", error.message);
    }

    console.log("\nAll cryptographic workflow checks completed.");
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
