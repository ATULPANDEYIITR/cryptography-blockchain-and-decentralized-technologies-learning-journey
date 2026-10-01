"use strict";

/*
 * Introduction to Symmetric Encryption
 *
 * This Node.js program provides a practical model of symmetric encryption.
 *
 * It intentionally separates:
 *   - plaintext and ciphertext
 *   - secret keys
 *   - nonces
 *   - encryption and authentication
 *   - associated data
 *   - password-based key derivation
 *   - encrypted message envelopes
 *   - event-driven processing
 *   - tamper detection
 *   - key rotation
 *
 * Node's built-in `crypto` module is used for production-grade primitives
 * available in the runtime. The program also contains a small XOR example
 * to expose the underlying reversibility of XOR without presenting XOR as
 * secure encryption.
 *
 * Run with:
 *   node symmetric_encryption.js
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const EventEmitter = require("node:events");


// ---------------------------------------------------------------------------
// Basic byte and XOR demonstrations
// ---------------------------------------------------------------------------

function xorBytes(left, right) {
    if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
        throw new TypeError("xorBytes expects Buffer objects");
    }

    if (left.length !== right.length) {
        throw new RangeError("XOR operands must have equal length");
    }

    const result = Buffer.alloc(left.length);

    for (let index = 0; index < left.length; index += 1) {
        result[index] = left[index] ^ right[index];
    }

    return result;
}

function repeatingKey(key, length) {
    if (!Buffer.isBuffer(key) || key.length === 0) {
        throw new TypeError("A non-empty key is required");
    }

    const output = Buffer.alloc(length);

    for (let index = 0; index < length; index += 1) {
        output[index] = key[index % key.length];
    }

    return output;
}

function repeatingXor(data, key) {
    return xorBytes(data, repeatingKey(key, data.length));
}

function demonstrateXorMechanics() {
    console.log("\n=== XOR Mechanics ===");

    const plaintext = Buffer.from("symmetric encryption", "utf8");
    const key = Buffer.from("key", "utf8");

    const ciphertext = repeatingXor(plaintext, key);
    const recovered = repeatingXor(ciphertext, key);

    console.log(`Plaintext : ${plaintext.toString("utf8")}`);
    console.log(`Ciphertext: ${ciphertext.toString("hex")}`);
    console.log(`Recovered : ${recovered.toString("utf8")}`);

    if (!recovered.equals(plaintext)) {
        throw new Error("XOR demonstration failed");
    }

    /*
     * Repeating-key XOR is intentionally weak. Reusing the same keystream
     * allows ciphertext relationships to reveal relationships between
     * plaintexts.
     */
    const first = Buffer.from("database-password=alpha", "utf8");
    const second = Buffer.from("database-password=omega", "utf8");

    const firstCiphertext = repeatingXor(first, key);
    const secondCiphertext = repeatingXor(second, key);

    const commonLength = Math.min(
        firstCiphertext.length,
        secondCiphertext.length,
    );

    const cipherRelationship = xorBytes(
        firstCiphertext.subarray(0, commonLength),
        secondCiphertext.subarray(0, commonLength),
    );

    const plaintextRelationship = xorBytes(
        first.subarray(0, commonLength),
        second.subarray(0, commonLength),
    );

    console.log(
        `Repeated-key relationship exposed: ${cipherRelationship.equals(
            plaintextRelationship,
        )}`,
    );
}


// ---------------------------------------------------------------------------
// AES-256-GCM authenticated encryption
// ---------------------------------------------------------------------------

function requireKey(key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new TypeError("AES-256-GCM requires a 32-byte key");
    }
}

function requireNonce(nonce) {
    if (!Buffer.isBuffer(nonce) || nonce.length !== 12) {
        throw new TypeError("This implementation requires a 12-byte nonce");
    }
}

function encryptAesGcm(plaintext, key, associatedData = Buffer.alloc(0)) {
    requireKey(key);

    if (!Buffer.isBuffer(plaintext)) {
        throw new TypeError("Plaintext must be a Buffer");
    }

    if (!Buffer.isBuffer(associatedData)) {
        throw new TypeError("Associated data must be a Buffer");
    }

    /*
     * A fresh 96-bit nonce is generated for every message. AES-GCM depends
     * critically on nonce uniqueness for a given key.
     */
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);

    if (associatedData.length > 0) {
        cipher.setAAD(associatedData);
    }

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);

    const authenticationTag = cipher.getAuthTag();

    return {
        algorithm: "AES-256-GCM",
        nonce,
        ciphertext,
        authenticationTag,
    };
}

function decryptAesGcm(
    envelope,
    key,
    associatedData = Buffer.alloc(0),
) {
    requireKey(key);

    if (!envelope || envelope.algorithm !== "AES-256-GCM") {
        throw new TypeError("Unsupported encryption envelope");
    }

    requireNonce(envelope.nonce);

    if (
        !Buffer.isBuffer(envelope.ciphertext) ||
        !Buffer.isBuffer(envelope.authenticationTag)
    ) {
        throw new TypeError("Invalid ciphertext or authentication tag");
    }

    if (envelope.authenticationTag.length !== 16) {
        throw new TypeError("AES-GCM authentication tag must be 16 bytes");
    }

    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        envelope.nonce,
    );

    if (!Buffer.isBuffer(associatedData)) {
        throw new TypeError("Associated data must be a Buffer");
    }

    if (associatedData.length > 0) {
        decipher.setAAD(associatedData);
    }

    decipher.setAuthTag(envelope.authenticationTag);

    /*
     * `final()` performs authentication verification. If ciphertext,
     * associated data, nonce, or tag has been modified, it throws instead
     * of returning unauthenticated plaintext.
     */
    return Buffer.concat([
        decipher.update(envelope.ciphertext),
        decipher.final(),
    ]);
}

function demonstrateAesGcm() {
    console.log("\n=== AES-256-GCM ===");

    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from(
        "Production deployment configuration",
        "utf8",
    );
    const associatedData = Buffer.from(
        "tenant=finance;record-version=4",
        "utf8",
    );

    const encrypted = encryptAesGcm(
        plaintext,
        key,
        associatedData,
    );

    const recovered = decryptAesGcm(
        encrypted,
        key,
        associatedData,
    );

    console.log(`Algorithm: ${encrypted.algorithm}`);
    console.log(`Nonce: ${encrypted.nonce.toString("hex")}`);
    console.log(`Ciphertext: ${encrypted.ciphertext.toString("hex")}`);
    console.log(
        `Authentication tag: ${encrypted.authenticationTag.toString("hex")}`,
    );
    console.log(`Recovered: ${recovered.toString("utf8")}`);

    if (!recovered.equals(plaintext)) {
        throw new Error("AES-GCM recovery failed");
    }

    const tampered = {
        ...encrypted,
        ciphertext: Buffer.from(encrypted.ciphertext),
    };

    tampered.ciphertext[0] ^= 0x01;

    try {
        decryptAesGcm(tampered, key, associatedData);
    } catch (error) {
        console.log(`Tampering rejected: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// Envelope serialization
// ---------------------------------------------------------------------------

function serializeEnvelope(envelope) {
    if (!envelope || !Buffer.isBuffer(envelope.nonce)) {
        throw new TypeError("Invalid encryption envelope");
    }

    return JSON.stringify({
        algorithm: envelope.algorithm,
        nonce: envelope.nonce.toString("base64"),
        ciphertext: envelope.ciphertext.toString("base64"),
        authenticationTag: envelope.authenticationTag.toString("base64"),
    });
}

function deserializeEnvelope(serialized) {
    let parsed;

    try {
        parsed = JSON.parse(serialized);
    } catch (error) {
        throw new Error("Encrypted envelope is not valid JSON");
    }

    if (parsed.algorithm !== "AES-256-GCM") {
        throw new Error("Unsupported encryption algorithm");
    }

    const envelope = {
        algorithm: parsed.algorithm,
        nonce: Buffer.from(parsed.nonce, "base64"),
        ciphertext: Buffer.from(parsed.ciphertext, "base64"),
        authenticationTag: Buffer.from(
            parsed.authenticationTag,
            "base64",
        ),
    };

    requireNonce(envelope.nonce);

    if (envelope.authenticationTag.length !== 16) {
        throw new Error("Invalid authentication tag length");
    }

    return envelope;
}


// ---------------------------------------------------------------------------
// Password-based encryption
// ---------------------------------------------------------------------------

function deriveKeyFromPassword(
    password,
    salt,
    iterations = 310000,
) {
    if (typeof password !== "string" || password.length === 0) {
        throw new TypeError("Password must be a non-empty string");
    }

    if (!Buffer.isBuffer(salt) || salt.length < 16) {
        throw new TypeError("Salt must contain at least 128 bits");
    }

    if (!Number.isInteger(iterations) || iterations < 100000) {
        throw new RangeError("PBKDF2 iteration count is too low");
    }

    /*
     * The salt is not secret. Its role is to ensure that identical passwords
     * do not automatically generate identical derived keys across records.
     */
    return crypto.pbkdf2Sync(
        Buffer.from(password, "utf8"),
        salt,
        iterations,
        32,
        "sha256",
    );
}

function encryptWithPassword(
    plaintext,
    password,
    associatedData = Buffer.alloc(0),
) {
    const salt = crypto.randomBytes(16);
    const iterations = 310000;

    const key = deriveKeyFromPassword(
        password,
        salt,
        iterations,
    );

    const encrypted = encryptAesGcm(
        plaintext,
        key,
        associatedData,
    );

    return {
        version: 1,
        kdf: "PBKDF2-HMAC-SHA256",
        iterations,
        salt,
        message: encrypted,
    };
}

function decryptWithPassword(
    envelope,
    password,
    associatedData = Buffer.alloc(0),
) {
    if (!envelope || envelope.version !== 1) {
        throw new Error("Unsupported password envelope version");
    }

    if (envelope.kdf !== "PBKDF2-HMAC-SHA256") {
        throw new Error("Unsupported key derivation function");
    }

    const key = deriveKeyFromPassword(
        password,
        envelope.salt,
        envelope.iterations,
    );

    return decryptAesGcm(
        envelope.message,
        key,
        associatedData,
    );
}

function serializePasswordEnvelope(envelope) {
    return JSON.stringify({
        version: envelope.version,
        kdf: envelope.kdf,
        iterations: envelope.iterations,
        salt: envelope.salt.toString("base64"),
        message: JSON.parse(serializeEnvelope(envelope.message)),
    });
}

function deserializePasswordEnvelope(serialized) {
    let parsed;

    try {
        parsed = JSON.parse(serialized);
    } catch {
        throw new Error("Password envelope is not valid JSON");
    }

    if (
        parsed.version !== 1 ||
        parsed.kdf !== "PBKDF2-HMAC-SHA256"
    ) {
        throw new Error("Unsupported password envelope");
    }

    const salt = Buffer.from(parsed.salt, "base64");

    if (salt.length !== 16) {
        throw new Error("Invalid password-envelope salt");
    }

    const message = deserializeEnvelope(
        JSON.stringify(parsed.message),
    );

    return {
        version: parsed.version,
        kdf: parsed.kdf,
        iterations: parsed.iterations,
        salt,
        message,
    };
}

function demonstratePasswordProtection() {
    console.log("\n=== Password-Derived Key Protection ===");

    const plaintext = Buffer.from(
        "database backup metadata",
        "utf8",
    );
    const password = "repository-encryption-password";
    const associatedData = Buffer.from(
        "backup-format=v3",
        "utf8",
    );

    const envelope = encryptWithPassword(
        plaintext,
        password,
        associatedData,
    );

    const serialized = serializePasswordEnvelope(envelope);
    const restored = deserializePasswordEnvelope(serialized);

    const recovered = decryptWithPassword(
        restored,
        password,
        associatedData,
    );

    console.log(`Salt: ${restored.salt.toString("hex")}`);
    console.log(`PBKDF2 iterations: ${restored.iterations}`);
    console.log(`Recovered: ${recovered.toString("utf8")}`);

    try {
        decryptWithPassword(
            restored,
            "wrong-password",
            associatedData,
        );
    } catch (error) {
        console.log(`Wrong password rejected: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// Event-driven encryption workflow
// ---------------------------------------------------------------------------

class EncryptionJob extends EventEmitter {
    constructor(key) {
        super();
        requireKey(key);
        this.key = key;
        this.state = "created";
    }

    async process(plaintext, associatedData = Buffer.alloc(0)) {
        if (this.state !== "created") {
            throw new Error(
                `Cannot process job from state: ${this.state}`,
            );
        }

        this.state = "encrypting";
        this.emit("state", this.state);

        /*
         * The crypto operation itself is synchronous because AES-GCM over
         * small application records is inexpensive here. The surrounding
         * job remains asynchronous so it can fit an event-driven application
         * workflow.
         */
        await new Promise((resolve) => setImmediate(resolve));

        try {
            const envelope = encryptAesGcm(
                plaintext,
                this.key,
                associatedData,
            );

            this.state = "completed";
            this.emit("state", this.state);
            this.emit("encrypted", envelope);

            return envelope;
        } catch (error) {
            this.state = "failed";
            this.emit("state", this.state);
            this.emit("error", error);
            throw error;
        }
    }
}

async function demonstrateEventDrivenWorkflow() {
    console.log("\n=== Event-Driven Encryption Workflow ===");

    const key = crypto.randomBytes(32);
    const job = new EncryptionJob(key);

    job.on("state", (state) => {
        console.log(`Job state: ${state}`);
    });

    job.on("encrypted", (envelope) => {
        console.log(
            `Encrypted event emitted; ciphertext=${envelope.ciphertext.length} bytes`,
        );
    });

    job.on("error", (error) => {
        console.log(`Encryption error event: ${error.message}`);
    });

    const result = await job.process(
        Buffer.from("event-driven secret", "utf8"),
    );

    const recovered = decryptAesGcm(result, key);
    console.log(`Recovered: ${recovered.toString("utf8")}`);
}


// ---------------------------------------------------------------------------
// File encryption
// ---------------------------------------------------------------------------

async function encryptFile(
    sourcePath,
    destinationPath,
    password,
    associatedData,
) {
    const source = path.resolve(sourcePath);
    const destination = path.resolve(destinationPath);

    if (source === destination) {
        throw new Error(
            "Source and destination paths must be different",
        );
    }

    const plaintext = await fs.readFile(source);

    const envelope = encryptWithPassword(
        plaintext,
        password,
        associatedData,
    );

    const serialized = serializePasswordEnvelope(envelope);
    const fileContents = Buffer.concat([
        Buffer.from("SYMENC01", "ascii"),
        Buffer.from(serialized, "utf8"),
    ]);

    const temporary = `${destination}.tmp`;

    await fs.writeFile(temporary, fileContents);

    /*
     * Rename after a complete write avoids intentionally replacing the target
     * with a partially generated ciphertext file.
     */
    await fs.rename(temporary, destination);
}

async function decryptFile(
    sourcePath,
    destinationPath,
    password,
    associatedData,
) {
    const source = path.resolve(sourcePath);
    const destination = path.resolve(destinationPath);

    const fileContents = await fs.readFile(source);
    const magic = Buffer.from("SYMENC01", "ascii");

    if (
        fileContents.length <= magic.length ||
        !fileContents.subarray(0, magic.length).equals(magic)
    ) {
        throw new Error("Unrecognized encrypted file format");
    }

    const serialized = fileContents
        .subarray(magic.length)
        .toString("utf8");

    const envelope = deserializePasswordEnvelope(serialized);

    /*
     * Authentication occurs during decryption. The destination is not
     * written until the ciphertext and associated data have been verified.
     */
    const plaintext = decryptWithPassword(
        envelope,
        password,
        associatedData,
    );

    const temporary = `${destination}.tmp`;

    await fs.writeFile(temporary, plaintext);
    await fs.rename(temporary, destination);
}

async function demonstrateFileWorkflow() {
    console.log("\n=== File Encryption Workflow ===");

    const temporaryDirectory = await fs.mkdtemp(
        path.join(os.tmpdir(), "symmetric-encryption-"),
    );

    try {
        const source = path.join(
            temporaryDirectory,
            "configuration.txt",
        );
        const encrypted = path.join(
            temporaryDirectory,
            "configuration.sym",
        );
        const recovered = path.join(
            temporaryDirectory,
            "configuration.recovered.txt",
        );

        const content = [
            "service=payments-api",
            "environment=production",
            "audit=true",
            "rotation=enabled",
            "",
        ].join("\n");

        const associatedData = Buffer.from(
            "format=deployment-config;version=1",
            "utf8",
        );

        await fs.writeFile(source, content, "utf8");

        await encryptFile(
            source,
            encrypted,
            "file-protection-password",
            associatedData,
        );

        await decryptFile(
            encrypted,
            recovered,
            "file-protection-password",
            associatedData,
        );

        const recoveredContent = await fs.readFile(
            recovered,
            "utf8",
        );

        if (recoveredContent !== content) {
            throw new Error("Recovered file differs from source");
        }

        console.log("Source, encryption, and recovery succeeded.");

        /*
         * A wrong password must fail before an attacker-controlled plaintext
         * reaches the output file.
         */
        try {
            await decryptFile(
                encrypted,
                path.join(
                    temporaryDirectory,
                    "should-not-exist.txt",
                ),
                "wrong-password",
                associatedData,
            );
        } catch (error) {
            console.log(`Wrong password rejected: ${error.message}`);
        }
    } finally {
        await fs.rm(temporaryDirectory, {
            recursive: true,
            force: true,
        });
    }
}


// ---------------------------------------------------------------------------
// Key rotation model
// ---------------------------------------------------------------------------

class KeyRing {
    constructor() {
        this.keys = new Map();
        this.activeKeyId = null;
    }

    addKey(keyId, key, { activate = false } = {}) {
        if (typeof keyId !== "string" || keyId.trim() === "") {
            throw new TypeError("Key ID must be a non-empty string");
        }

        requireKey(key);

        if (this.keys.has(keyId)) {
            throw new Error(`Key already exists: ${keyId}`);
        }

        this.keys.set(keyId, {
            key: Buffer.from(key),
            active: activate,
        });

        if (activate) {
            this.activeKeyId = keyId;
        }
    }

    activate(keyId) {
        const record = this.keys.get(keyId);

        if (!record) {
            throw new Error(`Unknown key: ${keyId}`);
        }

        for (const value of this.keys.values()) {
            value.active = false;
        }

        record.active = true;
        this.activeKeyId = keyId;
    }

    deactivate(keyId) {
        const record = this.keys.get(keyId);

        if (!record) {
            throw new Error(`Unknown key: ${keyId}`);
        }

        record.active = false;

        if (this.activeKeyId === keyId) {
            this.activeKeyId = null;
        }
    }

    getActive() {
        if (!this.activeKeyId) {
            throw new Error("No active encryption key");
        }

        const record = this.keys.get(this.activeKeyId);

        if (!record || !record.active) {
            throw new Error("Active key is unavailable");
        }

        return {
            keyId: this.activeKeyId,
            key: Buffer.from(record.key),
        };
    }

    get(keyId) {
        const record = this.keys.get(keyId);

        if (!record) {
            throw new Error(`Unknown key: ${keyId}`);
        }

        return {
            keyId,
            key: Buffer.from(record.key),
        };
    }
}

function demonstrateKeyRotation() {
    console.log("\n=== Key Rotation ===");

    const keyRing = new KeyRing();

    keyRing.addKey(
        "key-2026-09",
        crypto.randomBytes(32),
        { activate: true },
    );

    const oldKey = keyRing.getActive();

    const oldMessage = encryptAesGcm(
        Buffer.from("data written under old key", "utf8"),
        oldKey.key,
    );

    keyRing.addKey(
        "key-2026-10",
        crypto.randomBytes(32),
    );
    keyRing.activate("key-2026-10");

    const newKey = keyRing.getActive();

    const newMessage = encryptAesGcm(
        Buffer.from("data written under new key", "utf8"),
        newKey.key,
    );

    const oldRecovered = decryptAesGcm(
        oldMessage,
        keyRing.get(oldKey.keyId).key,
    );

    const newRecovered = decryptAesGcm(
        newMessage,
        newKey.key,
    );

    console.log(`Old key ID: ${oldKey.keyId}`);
    console.log(`New active key ID: ${newKey.keyId}`);
    console.log(`Old data recovered: ${oldRecovered.toString("utf8")}`);
    console.log(`New data recovered: ${newRecovered.toString("utf8")}`);

    /*
     * Key rotation normally does not require all old ciphertext to become
     * unreadable immediately. Applications can retain old decryption keys
     * under controlled policy while using the new key for new writes.
     */
    keyRing.deactivate(oldKey.keyId);

    try {
        keyRing.get(oldKey.keyId);
        console.log(
            "Old key remains identifiable for controlled migration.",
        );
    } catch (error) {
        console.log(error.message);
    }
}


// ---------------------------------------------------------------------------
// Security and correctness tests
// ---------------------------------------------------------------------------

function runTests() {
    console.log("\n=== Self-Tests ===");

    const key = Buffer.alloc(32, 0x4b);
    const associatedData = Buffer.from("record=v1", "utf8");

    const plaintexts = [
        Buffer.alloc(0),
        Buffer.from("a", "utf8"),
        Buffer.from("short message", "utf8"),
        Buffer.alloc(1024, 0x00),
        Buffer.from([...Array(256).keys()]),
    ];

    for (const plaintext of plaintexts) {
        const envelope = encryptAesGcm(
            plaintext,
            key,
            associatedData,
        );

        const recovered = decryptAesGcm(
            envelope,
            key,
            associatedData,
        );

        if (!recovered.equals(plaintext)) {
            throw new Error("Round-trip encryption test failed");
        }
    }

    const original = encryptAesGcm(
        Buffer.from("authenticated data", "utf8"),
        key,
        associatedData,
    );

    const tamperedCiphertext = {
        ...original,
        ciphertext: Buffer.from(original.ciphertext),
    };

    tamperedCiphertext.ciphertext[0] ^= 0x01;

    let rejected = false;

    try {
        decryptAesGcm(
            tamperedCiphertext,
            key,
            associatedData,
        );
    } catch {
        rejected = true;
    }

    if (!rejected) {
        throw new Error("Ciphertext tampering was not rejected");
    }

    rejected = false;

    try {
        decryptAesGcm(
            original,
            key,
            Buffer.from("record=v2", "utf8"),
        );
    } catch {
        rejected = true;
    }

    if (!rejected) {
        throw new Error("Associated-data tampering was not rejected");
    }

    /*
     * Two encryptions of identical plaintext normally receive different
     * nonces and therefore different ciphertexts.
     */
    const first = encryptAesGcm(Buffer.from("same", "utf8"), key);
    const second = encryptAesGcm(Buffer.from("same", "utf8"), key);

    if (first.nonce.equals(second.nonce)) {
        throw new Error("Unexpected nonce collision in test");
    }

    if (first.ciphertext.equals(second.ciphertext)) {
        throw new Error("Ciphertexts unexpectedly identical");
    }

    console.log(
        `Passed ${plaintexts.length} AES-GCM round-trip tests.`,
    );
    console.log(
        "Passed ciphertext-tampering and associated-data integrity tests.",
    );
}


// ---------------------------------------------------------------------------
// Program entry point
// ---------------------------------------------------------------------------

async function main() {
    demonstrateXorMechanics();
    demonstrateAesGcm();
    demonstratePasswordProtection();
    await demonstrateEventDrivenWorkflow();
    await demonstrateFileWorkflow();
    demonstrateKeyRotation();
    runTests();

    console.log("\n=== Operational Rules ===");
    console.log(
        "Use authenticated encryption rather than encryption without integrity.",
    );
    console.log(
        "Generate a fresh nonce according to the selected algorithm's rules.",
    );
    console.log(
        "Protect encryption keys separately from encrypted application data.",
    );
    console.log(
        "Use password KDFs only when passwords are the required key source.",
    );
    console.log(
        "Never place plaintext secrets or encryption keys in source control.",
    );
}

main().catch((error) => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
