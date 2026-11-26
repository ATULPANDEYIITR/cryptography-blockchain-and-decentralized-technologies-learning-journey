"use strict";

/*
 * HMAC-SHA256 in Cryptography and Blockchain
 *
 * Node.js 18+
 * Uses:
 *   - crypto
 *   - events
 *   - structuredClone
 *   - Maps and Sets
 *   - asynchronous event-driven processing
 *
 * Demonstrates:
 *   - HMAC authentication
 *   - Canonical transaction serialization
 *   - Key lifecycle management
 *   - Transaction queues
 *   - Replay prevention
 *   - Blockchain hash linking
 *   - Event-driven audit processing
 *   - Tampering detection
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

// ============================================================
// 1. ERRORS AND CONSTANTS
// ============================================================

const ZERO_HASH = "0".repeat(64);

class AuthenticationError extends Error {}
class ValidationError extends Error {}
class ReplayError extends Error {}
class LedgerError extends Error {}

// ============================================================
// 2. CANONICAL SERIALIZATION
// ============================================================

function canonicalize(value) {
    if (value === null || typeof value !== "object") {
        if (typeof value === "number" && !Number.isFinite(value)) {
            throw new ValidationError("Non-finite numbers are forbidden.");
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

function serialize(value) {
    return Buffer.from(canonicalize(value), "utf8");
}

// ============================================================
// 3. CRYPTOGRAPHIC OPERATIONS
// ============================================================

class CryptoService {

    static generateKey() {
        return crypto.randomBytes(32);
    }

    static sha256(data) {
        return crypto
            .createHash("sha256")
            .update(data)
            .digest("hex");
    }

    static hmac(data, secret) {
        if (!Buffer.isBuffer(secret) || secret.length < 32) {
            throw new ValidationError(
                "HMAC key must contain at least 32 bytes."
            );
        }

        return crypto
            .createHmac("sha256", secret)
            .update(data)
            .digest("hex");
    }

    static verify(data, suppliedTag, secret) {
        if (
            typeof suppliedTag !== "string" ||
            !/^[a-f0-9]{64}$/i.test(suppliedTag)
        ) {
            return false;
        }

        try {
            const expected = Buffer.from(
                this.hmac(data, secret),
                "hex"
            );

            const supplied = Buffer.from(suppliedTag, "hex");

            return (
                expected.length === supplied.length &&
                crypto.timingSafeEqual(expected, supplied)
            );
        } catch {
            return false;
        }
    }
}

// ============================================================
// 4. KEY VAULT
// ============================================================

class KeyVault {

    #keys = new Map();

    create(keyId) {
        if (
            typeof keyId !== "string" ||
            keyId.trim() === "" ||
            this.#keys.has(keyId)
        ) {
            throw new ValidationError("Invalid or duplicate key ID.");
        }

        const record = {
            keyId,
            secret: CryptoService.generateKey(),
            status: "ACTIVE",
            createdAt: Date.now()
        };

        this.#keys.set(keyId, record);

        return keyId;
    }

    get(keyId) {
        const record = this.#keys.get(keyId);

        if (!record || record.status === "REVOKED") {
            throw new AuthenticationError(
                "Key is unknown or revoked."
            );
        }

        return record;
    }

    rotate(oldId, newId) {
        const oldRecord = this.get(oldId);

        if (oldRecord.status !== "ACTIVE") {
            throw new ValidationError("Old key is not active.");
        }

        this.create(newId);
        oldRecord.status = "RETIRED";

        return newId;
    }

    revoke(keyId) {
        this.get(keyId).status = "REVOKED";
    }

    sign(keyId, payload) {
        const record = this.get(keyId);

        if (record.status !== "ACTIVE") {
            throw new AuthenticationError(
                "Retired keys cannot sign new transactions."
            );
        }

        return CryptoService.hmac(
            serialize(payload),
            record.secret
        );
    }

    verify(keyId, payload, signature) {
        const record = this.get(keyId);

        return CryptoService.verify(
            serialize(payload),
            signature,
            record.secret
        );
    }
}

// ============================================================
// 5. TRANSACTION DOMAIN MODEL
// ============================================================

class Transaction {

    constructor({
        id,
        sender,
        receiver,
        amount,
        nonce,
        timestamp,
        keyId
    }) {
        if (
            !sender ||
            !receiver ||
            sender === receiver
        ) {
            throw new ValidationError("Invalid account addresses.");
        }

        if (
            !Number.isSafeInteger(amount) ||
            amount <= 0
        ) {
            throw new ValidationError(
                "Amount must be a positive safe integer."
            );
        }

        if (
            !Number.isSafeInteger(nonce) ||
            nonce < 0
        ) {
            throw new ValidationError("Invalid transaction nonce.");
        }

        this.id = id || crypto.randomUUID();
        this.sender = sender;
        this.receiver = receiver;
        this.amount = amount;
        this.nonce = nonce;
        this.timestamp = timestamp || Date.now();
        this.keyId = keyId;
        this.signature = null;
    }

    payload() {
        return {
            id: this.id,
            sender: this.sender,
            receiver: this.receiver,
            amount: this.amount,
            nonce: this.nonce,
            timestamp: this.timestamp,
            keyId: this.keyId
        };
    }

    sign(vault) {
        this.signature = vault.sign(
            this.keyId,
            this.payload()
        );
    }

    verify(vault) {
        return (
            typeof this.signature === "string" &&
            vault.verify(
                this.keyId,
                this.payload(),
                this.signature
            )
        );
    }

    export() {
        return {
            ...this.payload(),
            signature: this.signature
        };
    }
}

// ============================================================
// 6. BLOCK MODEL
// ============================================================

class Block {

    constructor(index, previousHash, transactions) {
        this.index = index;
        this.previousHash = previousHash;
        this.timestamp = Date.now();
        this.transactions = transactions.map(tx => tx.export());
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return CryptoService.sha256(
            serialize({
                index: this.index,
                previousHash: this.previousHash,
                timestamp: this.timestamp,
                transactions: this.transactions
            })
        );
    }
}

// ============================================================
// 7. EVENT-DRIVEN BLOCKCHAIN ENGINE
// ============================================================

class BlockchainEngine extends EventEmitter {

    #blocks = [];
    #pending = new Map();
    #nonces = new Map();
    #transactionIds = new Set();
    #processing = false;

    constructor(vault) {
        super();

        this.vault = vault;

        const genesis = new Block(
            0,
            ZERO_HASH,
            []
        );

        this.#blocks.push(genesis);
    }

    get blocks() {
        return structuredClone(this.#blocks);
    }

    get pendingCount() {
        return this.#pending.size;
    }

    async submit(transaction) {
        if (!(transaction instanceof Transaction)) {
            throw new ValidationError("Invalid transaction object.");
        }

        if (!transaction.verify(this.vault)) {
            throw new AuthenticationError("Invalid transaction HMAC.");
        }

        if (this.#transactionIds.has(transaction.id)) {
            throw new ValidationError("Duplicate transaction ID.");
        }

        const key = transaction.sender;
        const used = this.#nonces.get(key) || new Set();

        if (used.has(transaction.nonce)) {
            throw new ReplayError("Nonce already committed.");
        }

        const pendingNonces = [...this.#pending.values()]
            .filter(tx => tx.sender === key)
            .map(tx => tx.nonce);

        if (
            pendingNonces.includes(transaction.nonce)
        ) {
            throw new ReplayError("Nonce already pending.");
        }

        this.#pending.set(transaction.id, transaction);

        this.emit("transaction:accepted", {
            transactionId: transaction.id,
            sender: transaction.sender
        });

        return transaction.id;
    }

    async mine() {
        if (this.#processing) {
            throw new LedgerError("Block processing is already active.");
        }

        if (this.#pending.size === 0) {
            throw new LedgerError("No transactions available.");
        }

        this.#processing = true;

        try {
            // Snapshot prevents concurrent submissions from
            // changing the block currently being assembled.
            const batch = [...this.#pending.values()];

            for (const transaction of batch) {
                if (!transaction.verify(this.vault)) {
                    throw new AuthenticationError(
                        "Authentication failed during block processing."
                    );
                }

                const used = this.#nonces.get(
                    transaction.sender
                ) || new Set();

                if (used.has(transaction.nonce)) {
                    throw new ReplayError("Nonce conflict.");
                }
            }

            const previous = this.#blocks.at(-1);

            const block = new Block(
                this.#blocks.length,
                previous.hash,
                batch
            );

            this.#blocks.push(block);

            for (const transaction of batch) {
                this.#pending.delete(transaction.id);
                this.#transactionIds.add(transaction.id);

                if (!this.#nonces.has(transaction.sender)) {
                    this.#nonces.set(
                        transaction.sender,
                        new Set()
                    );
                }

                this.#nonces.get(transaction.sender)
                    .add(transaction.nonce);
            }

            this.emit("block:committed", {
                index: block.index,
                hash: block.hash,
                transactionCount: batch.length
            });

            return structuredClone(block);

        } finally {
            this.#processing = false;
        }
    }

    verifyChain() {
        for (let i = 0; i < this.#blocks.length; i++) {
            const block = this.#blocks[i];

            if (block.hash !== block.calculateHash()) {
                return false;
            }

            if (i === 0) {
                if (block.previousHash !== ZERO_HASH) {
                    return false;
                }
            } else {
                if (
                    block.previousHash !== this.#blocks[i - 1].hash
                ) {
                    return false;
                }
            }

            for (const item of block.transactions) {
                const { signature, ...payload } = item;

                try {
                    if (
                        !this.vault.verify(
                            item.keyId,
                            payload,
                            signature
                        )
                    ) {
                        return false;
                    }
                } catch {
                    return false;
                }
            }
        }

        return true;
    }

    balance(address) {
        let total = 0;

        for (const block of this.#blocks) {
            for (const transaction of block.transactions) {
                if (transaction.sender === address) {
                    total -= transaction.amount;
                }

                if (transaction.receiver === address) {
                    total += transaction.amount;
                }
            }
        }

        return total;
    }
}

// ============================================================
// 8. ASYNCHRONOUS DEMONSTRATION
// ============================================================

async function main() {
    const vault = new KeyVault();

    const keyId = vault.create("account-key-v1");

    const ledger = new BlockchainEngine(vault);

    // Event-driven audit listeners.
    ledger.on("transaction:accepted", event => {
        console.log(
            "Transaction accepted:",
            event.transactionId
        );
    });

    ledger.on("block:committed", event => {
        console.log(
            "Block committed:",
            event.index,
            event.hash.slice(0, 20)
        );
    });

    // Create transactions.
    const first = new Transaction({
        sender: "ALICE",
        receiver: "BOB",
        amount: 500,
        nonce: 1,
        keyId
    });

    first.sign(vault);

    const second = new Transaction({
        sender: "BOB",
        receiver: "CHARLIE",
        amount: 150,
        nonce: 1,
        keyId
    });

    second.sign(vault);

    console.log("\n1. HMAC VERIFICATION");
    console.log("First:", first.verify(vault));
    console.log("Second:", second.verify(vault));

    console.log("\n2. TRANSACTION QUEUE");

    await Promise.all([
        ledger.submit(first),
        ledger.submit(second)
    ]);

    console.log("Pending transactions:", ledger.pendingCount);

    console.log("\n3. BLOCK CREATION");

    await ledger.mine();

    console.log("Chain valid:", ledger.verifyChain());

    console.log("\n4. ACCOUNT BALANCES");

    console.log("Alice:", ledger.balance("ALICE"));
    console.log("Bob:", ledger.balance("BOB"));
    console.log("Charlie:", ledger.balance("CHARLIE"));

    console.log("\n5. REPLAY ATTACK");

    try {
        await ledger.submit(first);
    } catch (error) {
        console.log(error.name, error.message);
    }

    console.log("\n6. MESSAGE TAMPERING");

    const originalAmount = first.amount;
    first.amount = 9000;

    console.log("Tampered signature valid:", first.verify(vault));

    first.amount = originalAmount;

    console.log("Restored signature valid:", first.verify(vault));

    console.log("\n7. KEY ROTATION");

    const newKeyId = vault.rotate(
        "account-key-v1",
        "account-key-v2"
    );

    const third = new Transaction({
        sender: "CHARLIE",
        receiver: "DAVID",
        amount: 50,
        nonce: 1,
        keyId: newKeyId
    });

    third.sign(vault);

    console.log("New key authentication:", third.verify(vault));

    console.log("\n8. CHAIN AUDIT");

    for (const block of ledger.blocks) {
        console.log({
            index: block.index,
            transactions: block.transactions.length,
            hash: block.hash
        });
    }

    console.log("\nFinal integrity:", ledger.verifyChain());
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
