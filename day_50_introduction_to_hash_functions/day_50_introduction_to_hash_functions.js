"use strict";

/*
 * Introduction to Hash Functions
 *
 * Node.js standard-library implementation covering:
 * - SHA-256 and SHA-3
 * - deterministic hashing
 * - avalanche behavior
 * - collision-aware hash-table design
 * - streaming file hashing
 * - HMAC authentication
 * - password key derivation
 * - Merkle-tree construction
 * - asynchronous/event-driven processing
 *
 * Run with:
 *     node hash-functions.js
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");

function requireNonEmptyString(value, name) {
    if (typeof value !== "string" || value.length === 0) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
}

function hashText(text, algorithm = "sha256") {
    requireNonEmptyString(text, "text");

    try {
        return crypto
            .createHash(algorithm)
            .update(text, "utf8")
            .digest("hex");
    } catch (error) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }
}

function hashBytes(buffer, algorithm = "sha256") {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError("buffer must be a Buffer");
    }

    return crypto
        .createHash(algorithm)
        .update(buffer)
        .digest("hex");
}

function avalancheDifference(left, right) {
    if (left.length !== right.length) {
        throw new Error("Hash values must have equal length");
    }

    let count = 0;

    for (let i = 0; i < left.length; i += 1) {
        if (left[i] !== right[i]) {
            count += 1;
        }
    }

    return count;
}

class RepositoryHashIndex {
    /*
     * This structure uses a cryptographic digest only as a stable identifier.
     * JavaScript's Map performs the actual key lookup and collision handling.
     */
    #records = new Map();

    set(identifier, metadata) {
        requireNonEmptyString(identifier, "identifier");

        if (metadata === null || typeof metadata !== "object") {
            throw new TypeError("metadata must be an object");
        }

        this.#records.set(identifier, Object.freeze({ ...metadata }));
    }

    get(identifier) {
        return this.#records.get(identifier) ?? null;
    }

    has(identifier) {
        return this.#records.has(identifier);
    }

    delete(identifier) {
        return this.#records.delete(identifier);
    }

    get size() {
        return this.#records.size;
    }
}

function hmacSha256(secret, message) {
    if (!Buffer.isBuffer(secret) || secret.length === 0) {
        throw new TypeError("secret must be a non-empty Buffer");
    }

    return crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest();
}

function secureEqual(left, right) {
    if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
        throw new TypeError("secureEqual expects Buffers");
    }

    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function derivePassword(password, salt, iterations = 600000) {
    requireNonEmptyString(password, "password");

    if (!Buffer.isBuffer(salt) || salt.length < 16) {
        throw new Error("Password salt must contain at least 16 bytes");
    }

    if (!Number.isInteger(iterations) || iterations <= 0) {
        throw new Error("Iterations must be a positive integer");
    }

    return new Promise((resolve, reject) => {
        /*
         * scrypt is designed for password derivation and is intentionally
         * more expensive than a general-purpose cryptographic hash.
         */
        crypto.scrypt(
            password,
            salt,
            32,
            {
                N: 16384,
                r: 8,
                p: 1,
                maxmem: 64 * 1024 * 1024
            },
            (error, derivedKey) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(derivedKey);
                }
            }
        );
    });
}

async function verifyPassword(password, salt, expectedKey) {
    const actualKey = await derivePassword(password, salt);

    return secureEqual(actualKey, expectedKey);
}

function hashFile(filePath) {
    return new Promise((resolve, reject) => {
        const digest = crypto.createHash("sha256");
        const stream = fs.createReadStream(filePath);

        stream.on("data", chunk => digest.update(chunk));
        stream.on("error", reject);
        stream.on("end", () => resolve(digest.digest("hex")));
    });
}

function merkleRoot(values) {
    if (!Array.isArray(values) || values.length === 0) {
        throw new Error("Merkle tree requires at least one value");
    }

    let level = values.map(value => {
        if (!Buffer.isBuffer(value)) {
            value = Buffer.from(String(value), "utf8");
        }

        return crypto.createHash("sha256").update(value).digest();
    });

    while (level.length > 1) {
        if (level.length % 2 !== 0) {
            level.push(level[level.length - 1]);
        }

        const next = [];

        for (let i = 0; i < level.length; i += 2) {
            next.push(
                crypto
                    .createHash("sha256")
                    .update(Buffer.concat([level[i], level[i + 1]]))
                    .digest()
            );
        }

        level = next;
    }

    return level[0].toString("hex");
}

class HashWorkflow extends EventEmitter {
    async processArtifact(filePath) {
        this.emit("started", filePath);

        try {
            const digest = await hashFile(filePath);

            this.emit("hashed", {
                filePath,
                digest
            });

            return digest;
        } catch (error) {
            this.emit("failed", {
                filePath,
                error
            });

            throw error;
        }
    }
}

async function main() {
    console.log("=== Deterministic Hashing ===");

    const first = hashText("repository artifact");
    const second = hashText("repository artifact");

    console.log(first);
    console.log("Deterministic:", first === second);

    console.log("\n=== Avalanche Behavior ===");

    const original = hashText("hash-function");
    const changed = hashText("hash-functions");

    console.log("Original:", original);
    console.log("Changed :", changed);
    console.log(
        "Different hexadecimal positions:",
        avalancheDifference(original, changed)
    );

    console.log("\n=== Hash Algorithms ===");
    console.log("SHA-256 :", hashText("secure data", "sha256"));
    console.log("SHA3-256:", hashText("secure data", "sha3-256"));

    console.log("\n=== Repository Hash Index ===");

    const index = new RepositoryHashIndex();
    const artifactId = hashText("commit-001");

    index.set(artifactId, {
        branch: "main",
        author: "developer@example.com",
        status: "verified"
    });

    console.log(index.get(artifactId));
    console.log("Exists:", index.has(artifactId));
    console.log("Records:", index.size);

    console.log("\n=== HMAC ===");

    const secret = crypto.randomBytes(32);
    const message = Buffer.from("amount=25000&account=ACCT-1042");

    const tag = hmacSha256(secret, message);

    console.log(
        "Valid message:",
        secureEqual(tag, hmacSha256(secret, message))
    );

    console.log(
        "Tampered message:",
        secureEqual(
            tag,
            hmacSha256(
                secret,
                Buffer.from("amount=99000&account=ACCT-1042")
            )
        )
    );

    console.log("\n=== Password Derivation ===");

    const salt = crypto.randomBytes(16);
    const derivedKey = await derivePassword("CorrectHorseBatteryStaple", salt);

    console.log(
        "Correct password:",
        await verifyPassword(
            "CorrectHorseBatteryStaple",
            salt,
            derivedKey
        )
    );

    console.log(
        "Wrong password:",
        await verifyPassword(
            "WrongPassword",
            salt,
            derivedKey
        )
    );

    console.log("\n=== Streaming File Hash ===");

    const temporaryPath = path.join(
        os.tmpdir(),
        `hash-demo-${process.pid}.txt`
    );

    fs.writeFileSync(temporaryPath, "release artifact v1", "utf8");

    const workflow = new HashWorkflow();

    workflow.on("started", file => {
        console.log("Started:", path.basename(file));
    });

    workflow.on("hashed", result => {
        console.log("Digest:", result.digest);
    });

    workflow.on("failed", result => {
        console.error("Hash failure:", result.error.message);
    });

    try {
        const expected = await workflow.processArtifact(temporaryPath);

        fs.writeFileSync(temporaryPath, "release artifact v2", "utf8");

        const changedDigest = await hashFile(temporaryPath);

        console.log(
            "Integrity preserved:",
            crypto.timingSafeEqual(
                Buffer.from(expected, "hex"),
                Buffer.from(changedDigest, "hex")
            )
        );
    } finally {
        fs.rmSync(temporaryPath, { force: true });
    }

    console.log("\n=== Merkle Tree ===");

    const transactions = [
        "TX-001 Alice -> Bob 10",
        "TX-002 Bob -> Carol 5",
        "TX-003 Carol -> Dave 2",
        "TX-004 Dave -> Erin 1"
    ];

    console.log("Merkle root:", merkleRoot(transactions));
}

main().catch(error => {
    console.error("Fatal error:", error.message);
    process.exitCode = 1;
});
