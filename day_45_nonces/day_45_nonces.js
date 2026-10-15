"use strict";

/*
 * Nonce Laboratory for JavaScript
 *
 * This Node.js program focuses on nonce lifecycle management rather than
 * implementing cryptographic primitives. Node's built-in crypto module is
 * used for secure random nonce generation and hashing.
 *
 * Run with:
 *   node nonce-laboratory.js
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { EventEmitter } = require("node:events");

const NONCE_BYTES = 12;

/* -------------------------------------------------------------------------
 * Secure random nonces
 * ---------------------------------------------------------------------- */

function randomNonce(bytes = NONCE_BYTES) {
    if (!Number.isInteger(bytes) || bytes <= 0) {
        throw new RangeError("Nonce size must be a positive integer.");
    }

    return crypto.randomBytes(bytes);
}

function nonceHex(nonce) {
    return nonce.toString("hex");
}

function counterNonce(counter, bytes = NONCE_BYTES) {
    if (!Number.isSafeInteger(counter) || counter < 0) {
        throw new RangeError("Counter must be a non-negative safe integer.");
    }

    if (!Number.isInteger(bytes) || bytes <= 0 || bytes > 6) {
        /*
         * Number can represent only integers up to Number.MAX_SAFE_INTEGER.
         * BigInt is preferable for counters that require wider values.
         */
        throw new RangeError(
            "This Number-based implementation supports nonce widths up to 6 bytes."
        );
    }

    const maximum = (2 ** (bytes * 8)) - 1;

    if (counter > maximum) {
        throw new RangeError("Counter does not fit into nonce.");
    }

    const nonce = Buffer.alloc(bytes);

    for (let index = bytes - 1; index >= 0; index -= 1) {
        nonce[index] = counter & 0xff;
        counter = Math.floor(counter / 256);
    }

    return nonce;
}

/* -------------------------------------------------------------------------
 * Collision experiment
 * ---------------------------------------------------------------------- */

function randomUniquenessExperiment(count) {
    if (!Number.isSafeInteger(count) || count < 0) {
        throw new RangeError("Count must be a non-negative safe integer.");
    }

    const seen = new Set();

    for (let index = 0; index < count; index += 1) {
        seen.add(nonceHex(randomNonce()));
    }

    return {
        generated: count,
        unique: seen.size,
        collisions: count - seen.size,
    };
}

/* -------------------------------------------------------------------------
 * Event-driven Pull-style nonce lifecycle
 * ---------------------------------------------------------------------- */

class NonceEventBus extends EventEmitter {
    publish(eventName, data) {
        this.emit(eventName, Object.freeze({
            timestamp: new Date().toISOString(),
            ...data,
        }));
    }
}

class NonceSession {
    constructor(sessionId, keyId, eventBus) {
        if (!sessionId || !keyId) {
            throw new Error("Session and key identifiers are required.");
        }

        this.sessionId = sessionId;
        this.keyId = keyId;
        this.eventBus = eventBus;
        this.counter = 0n;
        this.used = new Set();
        this.closed = false;
    }

    allocate() {
        if (this.closed) {
            throw new Error("Cannot allocate a nonce after session closure.");
        }

        /*
         * A session identifier plus a monotonically increasing counter gives
         * a deterministic nonce namespace. The exact encoding must be fixed
         * by the protocol and must remain unique under the same key.
         */
        const nonce = Buffer.alloc(12);

        nonce.writeUInt32BE(
            Number(this.sessionId),
            0
        );

        nonce.writeBigUInt64BE(this.counter, 4);
        this.counter += 1n;

        const encoded = nonceHex(nonce);

        if (this.used.has(encoded)) {
            throw new Error("Nonce reuse detected.");
        }

        this.used.add(encoded);

        this.eventBus.publish("nonceAllocated", {
            sessionId: this.sessionId,
            keyId: this.keyId,
            nonce: encoded,
        });

        return nonce;
    }

    close() {
        this.closed = true;

        this.eventBus.publish("sessionClosed", {
            sessionId: this.sessionId,
            keyId: this.keyId,
        });
    }
}

/* -------------------------------------------------------------------------
 * Replay detector
 * ---------------------------------------------------------------------- */

class ReplayDetector {
    constructor(maxEntries = 10_000) {
        if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
            throw new RangeError("maxEntries must be positive.");
        }

        this.maxEntries = maxEntries;
        this.entries = new Map();
    }

    accept(nonce) {
        if (!Buffer.isBuffer(nonce) || nonce.length === 0) {
            throw new TypeError("Nonce must be a non-empty Buffer.");
        }

        const key = nonceHex(nonce);

        if (this.entries.has(key)) {
            return false;
        }

        this.entries.set(key, Date.now());

        /*
         * Map preserves insertion order. Removing the oldest entry bounds
         * memory usage for a receiver that handles a large message stream.
         */
        while (this.entries.size > this.maxEntries) {
            const oldest = this.entries.keys().next().value;
            this.entries.delete(oldest);
        }

        return true;
    }
}

/* -------------------------------------------------------------------------
 * Sequence-number replay window
 * ---------------------------------------------------------------------- */

class SequenceWindow {
    constructor(size = 64) {
        if (!Number.isInteger(size) || size <= 0 || size > 32) {
            throw new RangeError(
                "This demonstration requires a window size between 1 and 32."
            );
        }

        this.size = size;
        this.highest = -1;
        this.bitmap = 0;
    }

    accept(sequence) {
        if (!Number.isSafeInteger(sequence) || sequence < 0) {
            throw new RangeError("Sequence number must be non-negative.");
        }

        if (this.highest === -1) {
            this.highest = sequence;
            this.bitmap = 1;
            return true;
        }

        if (sequence > this.highest) {
            const shift = sequence - this.highest;

            if (shift >= this.size) {
                this.bitmap = 1;
            } else {
                const mask = (2 ** this.size) - 1;
                this.bitmap = ((this.bitmap * (2 ** shift)) | 1) & mask;
            }

            this.highest = sequence;
            return true;
        }

        const distance = this.highest - sequence;

        if (distance >= this.size) {
            return false;
        }

        const bit = 2 ** distance;

        if ((this.bitmap & bit) !== 0) {
            return false;
        }

        this.bitmap |= bit;
        return true;
    }
}

/* -------------------------------------------------------------------------
 * Persistent counter
 * ---------------------------------------------------------------------- */

class PersistentCounter {
    constructor(filePath) {
        this.filePath = path.resolve(filePath);
        this.mutex = Promise.resolve();
    }

    async initialize(initialValue = 0n) {
        if (initialValue < 0n) {
            throw new RangeError("Initial counter cannot be negative.");
        }

        try {
            await fs.access(this.filePath);
        } catch {
            await fs.mkdir(path.dirname(this.filePath), {
                recursive: true,
            });

            await fs.writeFile(
                this.filePath,
                initialValue.toString(),
                "utf8"
            );
        }
    }

    async allocate() {
        /*
         * JavaScript is single-threaded within one event loop, but asynchronous
         * file operations can still interleave. Serializing operations through
         * a promise chain prevents this process from issuing duplicate values.
         *
         * This does not coordinate separate Node.js processes or machines.
         */
        const operation = this.mutex.then(async () => {
            const text = await fs.readFile(this.filePath, "utf8");
            const current = BigInt(text.trim());

            if (current < 0n) {
                throw new Error("Persistent counter is corrupt.");
            }

            const next = current + 1n;

            const temporary = `${this.filePath}.tmp`;
            await fs.writeFile(temporary, next.toString(), "utf8");
            await fs.rename(temporary, this.filePath);

            return next;
        });

        this.mutex = operation.catch(() => undefined);
        return operation;
    }
}

/* -------------------------------------------------------------------------
 * Key-scoped nonce registry
 * ---------------------------------------------------------------------- */

class KeyScopedNonceRegistry {
    constructor() {
        this.namespaces = new Map();
    }

    reserve(keyId, nonce) {
        if (!keyId) {
            throw new Error("keyId is required.");
        }

        if (!Buffer.isBuffer(nonce) || nonce.length === 0) {
            throw new TypeError("Nonce must be a non-empty Buffer.");
        }

        if (!this.namespaces.has(keyId)) {
            this.namespaces.set(keyId, new Set());
        }

        const namespace = this.namespaces.get(keyId);
        const encoded = nonceHex(nonce);

        if (namespace.has(encoded)) {
            return false;
        }

        namespace.add(encoded);
        return true;
    }
}

/* -------------------------------------------------------------------------
 * AEAD envelope validation
 * ---------------------------------------------------------------------- */

function validateEnvelope(envelope, expectedNonceBytes) {
    if (!envelope || typeof envelope !== "object") {
        throw new TypeError("Envelope must be an object.");
    }

    if (typeof envelope.keyId !== "string" || envelope.keyId.length === 0) {
        throw new Error("Missing key identifier.");
    }

    if (
        !Buffer.isBuffer(envelope.nonce) ||
        envelope.nonce.length !== expectedNonceBytes
    ) {
        throw new Error("Unexpected nonce length.");
    }

    if (
        !Buffer.isBuffer(envelope.ciphertext) ||
        envelope.ciphertext.length === 0
    ) {
        throw new Error("Ciphertext cannot be empty.");
    }

    if (
        !Buffer.isBuffer(envelope.tag) ||
        envelope.tag.length === 0
    ) {
        throw new Error("Authentication tag cannot be empty.");
    }
}

function envelopeFingerprint(envelope) {
    validateEnvelope(envelope, NONCE_BYTES);

    const hash = crypto.createHash("sha256");

    hash.update(envelope.keyId, "utf8");
    hash.update(envelope.nonce);
    hash.update(envelope.ciphertext);
    hash.update(envelope.tag);

    if (envelope.aad) {
        hash.update(envelope.aad);
    }

    return hash.digest("hex");
}

/* -------------------------------------------------------------------------
 * Practical AEAD demonstration
 * ---------------------------------------------------------------------- */

function encryptWithAesGcm(key, plaintext, aad = Buffer.alloc(0)) {
    /*
     * AES-GCM requires nonce uniqueness for a given key. The cryptographic
     * library provides encryption, while the caller remains responsible for
     * the nonce lifecycle.
     */
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new Error("This demonstration requires a 256-bit AES key.");
    }

    const nonce = randomNonce(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return {
        nonce,
        ciphertext,
        tag,
        aad,
    };
}

function decryptWithAesGcm(key, envelope) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new Error("This demonstration requires a 256-bit AES key.");
    }

    validateEnvelope(envelope, 12);

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        envelope.nonce
    );

    if (envelope.aad) {
        decipher.setAAD(envelope.aad);
    }

    decipher.setAuthTag(envelope.tag);

    return Buffer.concat([
        decipher.update(envelope.ciphertext),
        decipher.final(),
    ]);
}

/* -------------------------------------------------------------------------
 * Demonstrations
 * ---------------------------------------------------------------------- */

async function main() {
    console.log("NONCE LABORATORY");
    console.log("================");

    console.log("\n=== Random nonce generation ===");

    const random = randomNonce(12);
    console.log("Nonce:", nonceHex(random));
    console.log("Length:", random.length, "bytes");

    console.log("\n=== Counter nonce generation ===");

    for (let counter = 0; counter < 4; counter += 1) {
        console.log(
            counter,
            nonceHex(counterNonce(counter))
        );
    }

    console.log("\n=== Collision experiment ===");

    const experiment = randomUniquenessExperiment(10_000);
    console.log(experiment);

    console.log("\n=== Replay detection ===");

    const replay = new ReplayDetector(3);
    const replayNonce = randomNonce();

    console.log("First:", replay.accept(replayNonce));
    console.log("Replay:", replay.accept(replayNonce));

    console.log("\n=== Sequence window ===");

    const window = new SequenceWindow(4);

    for (const sequence of [10, 11, 9, 12, 11, 8, 13]) {
        console.log(
            sequence,
            "accepted:",
            window.accept(sequence)
        );
    }

    console.log("\n=== Event-driven session ===");

    const events = new NonceEventBus();

    events.on("nonceAllocated", event => {
        console.log(
            "allocated:",
            event.nonce,
            "session:",
            event.sessionId
        );
    });

    events.on("sessionClosed", event => {
        console.log("closed:", event.sessionId);
    });

    const session = new NonceSession(
        0x12345678,
        "key-2026",
        events
    );

    session.allocate();
    session.allocate();
    session.allocate();
    session.close();

    console.log("\n=== Key-scoped registry ===");

    const registry = new KeyScopedNonceRegistry();
    const sharedNonce = randomNonce();

    console.log("key-A:", registry.reserve("key-A", sharedNonce));
    console.log("key-A replay:", registry.reserve("key-A", sharedNonce));
    console.log("key-B:", registry.reserve("key-B", sharedNonce));

    console.log("\n=== AES-GCM envelope ===");

    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from(
        "Repository metadata protected by authenticated encryption.",
        "utf8"
    );
    const aad = Buffer.from("protocol=v1;record=nonce-demo", "utf8");

    const envelope = encryptWithAesGcm(key, plaintext, aad);

    console.log("Nonce:", nonceHex(envelope.nonce));
    console.log("Ciphertext:", envelope.ciphertext.toString("hex"));
    console.log("Tag:", envelope.tag.toString("hex"));

    const recovered = decryptWithAesGcm(key, envelope);

    if (!recovered.equals(plaintext)) {
        throw new Error("AEAD round trip failed.");
    }

    console.log("Decryption verified.");
    console.log("Fingerprint:", envelopeFingerprint({
        keyId: "key-2026",
        ...envelope,
    }));

    console.log("\n=== Persistent counter ===");

    const counterPath = path.join(
        process.cwd(),
        "nonce-counter-demo.state"
    );

    const persistent = new PersistentCounter(counterPath);
    await persistent.initialize(0n);

    console.log("Allocated:", (await persistent.allocate()).toString());
    console.log("Allocated:", (await persistent.allocate()).toString());

    await fs.rm(counterPath, { force: true });

    console.log("\nAll demonstrations completed successfully.");
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
