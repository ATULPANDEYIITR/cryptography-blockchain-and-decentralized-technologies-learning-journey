/*
 * Integrity in Cryptography and Blockchain
 * ========================================
 *
 * A self-contained JavaScript study implementation covering:
 * - Data integrity
 * - Cryptographic hashes
 * - Canonical serialization
 * - Hash chains
 * - HMAC
 * - Merkle trees
 * - Digital-signature concepts
 * - Blockchain blocks
 * - Proof of work
 * - Tamper detection
 * - Validation and testing
 *
 * Uses Node.js built-in "crypto" module only.
 */

"use strict";

const crypto = require("crypto");


// ============================================================================
// 1. BASIC CRYPTOGRAPHIC HASHING
// ============================================================================

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function canonicalJson(value) {
    /*
     * JSON.stringify preserves object insertion order rather than providing
     * universal canonical JSON semantics. Sorting keys recursively gives this
     * educational example deterministic object serialization.
     */
    if (Array.isArray(value)) {
        return `[${value.map(canonicalJson).join(",")}]`;
    }

    if (value !== null && typeof value === "object") {
        return `{${Object.keys(value)
            .sort()
            .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
            .join(",")}}`;
    }

    return JSON.stringify(value);
}

function hashObject(value) {
    return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function demonstrateHashes() {
    console.log("\n=== 1. HASH INTEGRITY ===");

    const original = "Transfer 100 coins to Alice";
    const modified = "Transfer 900 coins to Alice";

    const originalHash = sha256(original);
    const modifiedHash = sha256(modified);

    console.log("Original:", original);
    console.log("Original SHA-256:", originalHash);
    console.log("Modified:", modified);
    console.log("Modified SHA-256:", modifiedHash);
    console.log("Same digest:", originalHash === modifiedHash);
}


// ============================================================================
// 2. HASH-BASED FILE/DATA INTEGRITY MODEL
// ============================================================================

class IntegrityRecord {
    constructor(data) {
        this.data = data;
        this.digest = sha256(data);
    }

    verify() {
        return crypto.timingSafeEqual(
            Buffer.from(this.digest, "hex"),
            Buffer.from(sha256(this.data), "hex")
        );
    }
}

function demonstrateIntegrityRecord() {
    console.log("\n=== 2. TAMPER DETECTION ===");

    const record = new IntegrityRecord("employee=42;salary=50000");

    console.log("Before modification:", record.verify());

    record.data = "employee=42;salary=90000";

    console.log("After modification:", record.verify());
}


// ============================================================================
// 3. HMAC
// ============================================================================

function createHmac(message, secret) {
    return crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest("hex");
}

function verifyHmac(message, secret, expectedTag) {
    const actual = Buffer.from(createHmac(message, secret), "hex");
    const expected = Buffer.from(expectedTag, "hex");

    return actual.length === expected.length &&
        crypto.timingSafeEqual(actual, expected);
}

function demonstrateHmac() {
    console.log("\n=== 3. HMAC ===");

    const secret = crypto.randomBytes(32);
    const message = "temperature=25.4";

    const tag = createHmac(message, secret);

    console.log("Valid message:", verifyHmac(message, secret, tag));
    console.log(
        "Tampered message:",
        verifyHmac("temperature=99.9", secret, tag)
    );
}


// ============================================================================
// 4. HASH CHAIN
// ============================================================================

class HashChain {
    constructor() {
        this.entries = [];
    }

    calculateHash(index, data, previousHash) {
        return hashObject({
            index,
            data,
            previousHash
        });
    }

    append(data) {
        const index = this.entries.length;
        const previousHash = index === 0
            ? "0".repeat(64)
            : this.entries[index - 1].hash;

        const entry = {
            index,
            data,
            previousHash,
            hash: this.calculateHash(index, data, previousHash)
        };

        this.entries.push(entry);
        return entry;
    }

    verify() {
        for (let index = 0; index < this.entries.length; index++) {
            const entry = this.entries[index];

            const expectedPrevious = index === 0
                ? "0".repeat(64)
                : this.entries[index - 1].hash;

            if (entry.previousHash !== expectedPrevious) {
                return false;
            }

            const expectedHash = this.calculateHash(
                entry.index,
                entry.data,
                entry.previousHash
            );

            if (entry.hash !== expectedHash) {
                return false;
            }
        }

        return true;
    }
}

function demonstrateHashChain() {
    console.log("\n=== 4. HASH CHAIN ===");

    const chain = new HashChain();

    chain.append("Alice -> Bob: 10");
    chain.append("Bob -> Carol: 5");
    chain.append("Carol -> Dave: 2");

    console.log("Valid chain:", chain.verify());

    chain.entries[0].data = "Alice -> Bob: 100000";

    console.log("After tampering:", chain.verify());
}


// ============================================================================
// 5. MERKLE TREE
// ============================================================================

class MerkleTree {
    constructor(values) {
        if (!Array.isArray(values) || values.length === 0) {
            throw new Error("Merkle tree requires at least one value.");
        }

        this.leaves = values.map((value) => sha256(value));
        this.levels = [this.leaves];
        this.build();
    }

    static parentHash(left, right) {
        return sha256(
            Buffer.concat([
                Buffer.from(left, "hex"),
                Buffer.from(right, "hex")
            ])
        );
    }

    build() {
        let current = this.leaves;

        while (current.length > 1) {
            const next = [];

            for (let i = 0; i < current.length; i += 2) {
                const left = current[i];
                const right = i + 1 < current.length
                    ? current[i + 1]
                    : left;

                next.push(MerkleTree.parentHash(left, right));
            }

            this.levels.push(next);
            current = next;
        }
    }

    get root() {
        return this.levels[this.levels.length - 1][0];
    }

    inclusionProof(index) {
        if (!Number.isInteger(index) || index < 0 ||
            index >= this.leaves.length) {
            throw new RangeError("Invalid leaf index.");
        }

        const proof = [];
        let currentIndex = index;

        for (const level of this.levels.slice(0, -1)) {
            let siblingIndex = currentIndex % 2 === 0
                ? currentIndex + 1
                : currentIndex - 1;

            if (siblingIndex >= level.length) {
                siblingIndex = currentIndex;
            }

            proof.push({
                hash: level[siblingIndex],
                side: siblingIndex < currentIndex ? "left" : "right"
            });

            currentIndex = Math.floor(currentIndex / 2);
        }

        return proof;
    }

    static verifyProof(value, proof, expectedRoot) {
        let current = sha256(value);

        for (const item of proof) {
            current = item.side === "left"
                ? MerkleTree.parentHash(item.hash, current)
                : MerkleTree.parentHash(current, item.hash);
        }

        return current === expectedRoot;
    }
}

function demonstrateMerkleTree() {
    console.log("\n=== 5. MERKLE TREE ===");

    const transactions = [
        "TX1 Alice -> Bob 10",
        "TX2 Bob -> Carol 5",
        "TX3 Carol -> Dave 2",
        "TX4 Dave -> Erin 1"
    ];

    const tree = new MerkleTree(transactions);
    const proof = tree.inclusionProof(2);

    console.log("Merkle root:", tree.root);
    console.log(
        "Valid TX3:",
        MerkleTree.verifyProof(transactions[2], proof, tree.root)
    );
    console.log(
        "Tampered TX3:",
        MerkleTree.verifyProof(
            "TX3 Carol -> Dave 999999",
            proof,
            tree.root
        )
    );
}


// ============================================================================
// 6. BLOCKCHAIN BLOCK MODEL
// ============================================================================

class Block {
    constructor(index, transactions, previousHash, timestamp = Date.now()) {
        this.index = index;
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.merkleRoot = "";
        this.hash = "";
    }

    calculateMerkleRoot() {
        if (this.transactions.length === 0) {
            return sha256("");
        }

        return new MerkleTree(
            this.transactions.map((transaction) => canonicalJson(transaction))
        ).root;
    }

    calculateHash() {
        this.merkleRoot = this.calculateMerkleRoot();

        return hashObject({
            index: this.index,
            timestamp: this.timestamp,
            previousHash: this.previousHash,
            merkleRoot: this.merkleRoot,
            nonce: this.nonce
        });
    }

    mine(difficulty) {
        const target = "0".repeat(difficulty);

        do {
            this.hash = this.calculateHash();
            this.nonce++;
        } while (!this.hash.startsWith(target));

        return this;
    }
}


// ============================================================================
// 7. BLOCKCHAIN
// ============================================================================

class Blockchain {
    constructor(difficulty = 3) {
        if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 6) {
            throw new RangeError("Difficulty must be between 1 and 6.");
        }

        this.difficulty = difficulty;
        this.chain = [this.createGenesisBlock()];
    }

    createGenesisBlock() {
        const genesis = new Block(
            0,
            [{ type: "genesis" }],
            "0".repeat(64),
            1700000000000
        );

        genesis.mine(this.difficulty);
        return genesis;
    }

    latestBlock() {
        return this.chain[this.chain.length - 1];
    }

    addBlock(transactions) {
        if (!Array.isArray(transactions) || transactions.length === 0) {
            throw new TypeError("A block needs at least one transaction.");
        }

        const block = new Block(
            this.chain.length,
            structuredClone(transactions),
            this.latestBlock().hash
        );

        block.mine(this.difficulty);
        this.chain.push(block);

        return block;
    }

    verify() {
        const target = "0".repeat(this.difficulty);

        for (let i = 0; i < this.chain.length; i++) {
            const block = this.chain[i];

            if (block.calculateHash() !== block.hash) {
                return {
                    valid: false,
                    reason: `Block ${i}: hash mismatch`
                };
            }

            if (!block.hash.startsWith(target)) {
                return {
                    valid: false,
                    reason: `Block ${i}: invalid proof of work`
                };
            }

            if (i === 0) {
                if (block.previousHash !== "0".repeat(64)) {
                    return {
                        valid: false,
                        reason: "Invalid genesis previous hash"
                    };
                }
                continue;
            }

            if (block.previousHash !== this.chain[i - 1].hash) {
                return {
                    valid: false,
                    reason: `Block ${i}: broken chain link`
                };
            }
        }

        return {
            valid: true,
            reason: "Blockchain is valid"
        };
    }
}


// ============================================================================
// 8. REALISTIC TRANSACTION VALIDATION
// ============================================================================

function validateTransaction(transaction) {
    if (!transaction || typeof transaction !== "object") {
        return false;
    }

    if (typeof transaction.sender !== "string" ||
        typeof transaction.recipient !== "string") {
        return false;
    }

    if (transaction.sender.length === 0 ||
        transaction.recipient.length === 0) {
        return false;
    }

    if (!Number.isSafeInteger(transaction.amount) ||
        transaction.amount <= 0) {
        return false;
    }

    return true;
}

function validateTransactionBatch(transactions) {
    if (!Array.isArray(transactions) || transactions.length === 0) {
        throw new Error("Transaction batch cannot be empty.");
    }

    for (const transaction of transactions) {
        if (!validateTransaction(transaction)) {
            throw new Error(
                `Invalid transaction: ${canonicalJson(transaction)}`
            );
        }
    }

    return true;
}


// ============================================================================
// 9. BLOCKCHAIN CASE STUDY
// ============================================================================

function demonstrateBlockchainCaseStudy() {
    console.log("\n=== 6. BLOCKCHAIN CASE STUDY ===");

    const blockchain = new Blockchain(2);

    const firstBatch = [
        { sender: "Alice", recipient: "Bob", amount: 10 },
        { sender: "Bob", recipient: "Carol", amount: 3 }
    ];

    const secondBatch = [
        { sender: "Carol", recipient: "Dave", amount: 2 }
    ];

    validateTransactionBatch(firstBatch);
    validateTransactionBatch(secondBatch);

    blockchain.addBlock(firstBatch);
    blockchain.addBlock(secondBatch);

    console.log(blockchain.verify());

    // Tampering changes the transaction hash, Merkle root and block hash.
    blockchain.chain[1].transactions[0].amount = 999999;

    console.log("After tampering:", blockchain.verify());
}


// ============================================================================
// 10. REBUILDING AN OLD BLOCK
// ============================================================================

function demonstrateHistoryRewrite() {
    console.log("\n=== 7. HISTORY REWRITE ===");

    const blockchain = new Blockchain(2);

    blockchain.addBlock([
        { sender: "A", recipient: "B", amount: 10 }
    ]);

    blockchain.addBlock([
        { sender: "B", recipient: "C", amount: 5 }
    ]);

    const originalNextLink = blockchain.chain[2].previousHash;

    blockchain.chain[1].transactions[0].amount = 10000;

    // Re-mining this old block can produce a new valid hash, but the next
    // block still contains the original previous-hash commitment.
    blockchain.chain[1].mine(blockchain.difficulty);

    console.log(
        "Second block now has a different hash:",
        blockchain.chain[1].hash !== originalNextLink
    );

    console.log("Validation:", blockchain.verify());
}


// ============================================================================
// 11. DIGITAL SIGNATURE CONCEPT WITH NODE CRYPTO
// ============================================================================

function demonstrateDigitalSignature() {
    console.log("\n=== 8. DIGITAL SIGNATURE ===");

    /*
     * Ed25519 is used here because Node.js supports it natively.
     * The private key signs. The public key verifies.
     *
     * Unlike a plain hash, anyone possessing the public key can verify the
     * signature without knowing the private key.
     */
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

    const message = Buffer.from("Approved transaction: Alice -> Bob: 10");

    const signature = crypto.sign(null, message, privateKey);

    console.log(
        "Original signature valid:",
        crypto.verify(null, message, publicKey, signature)
    );

    console.log(
        "Tampered message valid:",
        crypto.verify(
            null,
            Buffer.from("Approved transaction: Alice -> Bob: 10000"),
            publicKey,
            signature
        )
    );
}


// ============================================================================
// 12. EDGE CASES
// ============================================================================

function demonstrateEdgeCases() {
    console.log("\n=== 9. EDGE CASES ===");

    console.log("Empty SHA-256:", sha256(""));

    try {
        new MerkleTree([]);
    } catch (error) {
        console.log("Empty Merkle tree:", error.message);
    }

    const single = new MerkleTree(["single transaction"]);
    console.log("Single-leaf root:", single.root);

    try {
        single.inclusionProof(4);
    } catch (error) {
        console.log("Invalid proof index:", error.message);
    }

    console.log(
        "Unicode representation hashes:",
        sha256("café") === sha256("cafe\u0301")
    );
}


// ============================================================================
// 13. PERFORMANCE DEMONSTRATION
// ============================================================================

function benchmarkHashing() {
    console.log("\n=== 10. PERFORMANCE ===");

    const oneMegabyte = Buffer.alloc(1024 * 1024, "A");

    const start = process.hrtime.bigint();
    sha256(oneMegabyte);
    const elapsedNanoseconds = process.hrtime.bigint() - start;

    console.log(
        "SHA-256 of 1 MiB took approximately:",
        Number(elapsedNanoseconds) / 1e6,
        "ms"
    );

    console.log("Hashing is approximately linear in input size.");
    console.log("Merkle inclusion proofs scale approximately with log2(n).");
    console.log("Proof of work deliberately consumes computational resources.");
}


// ============================================================================
// 14. SECURITY DISTINCTIONS
// ============================================================================

function printSecurityDistinctions() {
    console.log("\n=== 11. SECURITY DISTINCTIONS ===");

    const distinctions = [
        ["Hash", "Integrity fingerprint"],
        ["HMAC", "Integrity + shared-secret authentication"],
        ["Digital signature", "Integrity + public-key verification"],
        ["Merkle tree", "Efficient commitment to a data collection"],
        ["Hash chain", "Tamper-evident sequence"],
        ["Blockchain", "Linked data structure plus consensus/security rules"]
    ];

    for (const [mechanism, purpose] of distinctions) {
        console.log(`${mechanism}: ${purpose}`);
    }

    console.log(
        "\nA hash alone does not authenticate the source of the data."
    );
    console.log(
        "A blockchain does not automatically make incorrect input truthful."
    );
}


// ============================================================================
// 15. AUTOMATED TESTS
// ============================================================================

function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function runTests() {
    console.log("\n=== 12. SELF-TESTS ===");

    const chain = new HashChain();
    chain.append("A");
    chain.append("B");
    assert(chain.verify(), "Hash chain should initially be valid.");

    chain.entries[0].data = "Tampered";
    assert(!chain.verify(), "Tampered chain should fail.");

    const values = ["A", "B", "C", "D"];
    const tree = new MerkleTree(values);
    const proof = tree.inclusionProof(1);

    assert(
        MerkleTree.verifyProof("B", proof, tree.root),
        "Merkle proof should validate."
    );

    assert(
        !MerkleTree.verifyProof("X", proof, tree.root),
        "Tampered Merkle leaf should fail."
    );

    const blockchain = new Blockchain(1);
    blockchain.addBlock([
        { sender: "A", recipient: "B", amount: 1 }
    ]);

    assert(
        blockchain.verify().valid,
        "Blockchain should initially be valid."
    );

    blockchain.chain[1].transactions[0].amount = 2;

    assert(
        !blockchain.verify().valid,
        "Tampered blockchain should fail."
    );

    console.log("All tests passed.");
}


// ============================================================================
// 16. MAIN
// ============================================================================

function main() {
    console.log("=".repeat(78));
    console.log("INTEGRITY IN CRYPTOGRAPHY AND BLOCKCHAIN");
    console.log("=".repeat(78));

    demonstrateHashes();
    demonstrateIntegrityRecord();
    demonstrateHmac();
    demonstrateHashChain();
    demonstrateMerkleTree();
    demonstrateBlockchainCaseStudy();
    demonstrateHistoryRewrite();
    demonstrateDigitalSignature();
    demonstrateEdgeCases();
    benchmarkHashing();
    printSecurityDistinctions();
    runTests();

    console.log("\nStudy implementation completed successfully.");
}

main();
