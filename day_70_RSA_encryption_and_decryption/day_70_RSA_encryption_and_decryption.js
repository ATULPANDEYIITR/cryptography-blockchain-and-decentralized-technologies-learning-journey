"use strict";

/*
 * RSA Encryption and Decryption
 *
 * Node.js 20+
 *
 * Implements an event-driven RSA encryption service using the
 * Node.js native crypto module.
 *
 * Algorithms:
 *   RSA-OAEP with SHA-256 for encryption.
 *   RSA-PSS with SHA-256 for digital signatures.
 *
 * Private keys are maintained separately from public keys.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const EventEmitter = require("node:events");
const assert = require("node:assert/strict");

// ============================================================
// Configuration
// ============================================================

const CONFIG = Object.freeze({
    modulusLength: 2048,
    publicExponent: 65537,
    hashAlgorithm: "sha256",
    oaepPadding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    pssPadding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
    maximumMessageBytes: 190
});

const KEY_STATES = Object.freeze({
    ACTIVE: "ACTIVE",
    REVOKED: "REVOKED"
});

const SERVICE_STATES = Object.freeze({
    READY: "READY",
    STOPPED: "STOPPED"
});

// ============================================================
// Domain exceptions
// ============================================================

class RSAServiceError extends Error {
    constructor(message, code = "RSA_ERROR") {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
    }
}

class InvalidKeyError extends RSAServiceError {}
class EncryptionError extends RSAServiceError {}
class DecryptionError extends RSAServiceError {}
class KeyRevokedError extends RSAServiceError {}

// ============================================================
// Validation
// ============================================================

function validateBuffer(value, fieldName) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError(`${fieldName} must be a Buffer.`);
    }
}

function validateIdentifier(identifier) {
    if (
        typeof identifier !== "string" ||
        !/^[a-zA-Z0-9_-]{3,64}$/.test(identifier)
    ) {
        throw new TypeError("Invalid key identifier.");
    }
}

function validateKeySize(bits) {
    if (
        !Number.isInteger(bits) ||
        bits < 2048 ||
        bits > 8192 ||
        bits % 256 !== 0
    ) {
        throw new RangeError(
            "RSA modulus must be between 2048 and 8192 bits."
        );
    }
}

// ============================================================
// Cryptographic utility functions
// ============================================================

function fingerprint(publicKey) {
    return crypto
        .createHash("sha256")
        .update(publicKey.export({
            type: "spki",
            format: "der"
        }))
        .digest("hex");
}

function generateKeyPair(bits = CONFIG.modulusLength) {
    validateKeySize(bits);

    return new Promise((resolve, reject) => {
        crypto.generateKeyPair(
            "rsa",
            {
                modulusLength: bits,
                publicExponent: CONFIG.publicExponent,
                publicKeyEncoding: {
                    type: "spki",
                    format: "pem"
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem"
                }
            },
            (error, publicKey, privateKey) => {
                if (error) {
                    reject(
                        new InvalidKeyError(
                            "RSA key generation failed."
                        )
                    );
                    return;
                }

                resolve({
                    publicKey,
                    privateKey
                });
            }
        );
    });
}

// ============================================================
// Key registry
// ============================================================

class KeyRegistry extends EventEmitter {
    #keys = new Map();

    register(identifier, keyPair) {
        validateIdentifier(identifier);

        if (this.#keys.has(identifier)) {
            throw new InvalidKeyError(
                "Key identifier already exists."
            );
        }

        const publicObject = crypto.createPublicKey(
            keyPair.publicKey
        );

        const privateObject = crypto.createPrivateKey(
            keyPair.privateKey
        );

        const publicFingerprint = fingerprint(publicObject);

        this.#keys.set(identifier, {
            publicKey: publicObject,
            privateKey: privateObject,
            fingerprint: publicFingerprint,
            state: KEY_STATES.ACTIVE,
            createdAt: new Date()
        });

        this.emit("key:registered", {
            identifier,
            fingerprint: publicFingerprint
        });

        return publicFingerprint;
    }

    get(identifier) {
        const record = this.#keys.get(identifier);

        if (!record) {
            throw new InvalidKeyError("Key not found.");
        }

        return record;
    }

    revoke(identifier) {
        const record = this.get(identifier);

        if (record.state === KEY_STATES.REVOKED) {
            return false;
        }

        record.state = KEY_STATES.REVOKED;

        this.emit("key:revoked", {
            identifier,
            fingerprint: record.fingerprint
        });

        return true;
    }

    getPublicKey(identifier) {
        return this.get(identifier).publicKey;
    }

    getActiveCount() {
        return [...this.#keys.values()].filter(
            key => key.state === KEY_STATES.ACTIVE
        ).length;
    }
}

// ============================================================
// RSA cryptographic service
// ============================================================

class RSAService extends EventEmitter {
    constructor(registry) {
        super();

        this.registry = registry;
        this.state = SERVICE_STATES.READY;
        this.operationCount = 0;
        this.failureCount = 0;
    }

    #ensureReady() {
        if (this.state !== SERVICE_STATES.READY) {
            throw new RSAServiceError(
                "RSA service is not available.",
                "SERVICE_STOPPED"
            );
        }
    }

    #getActiveRecord(identifier) {
        const record = this.registry.get(identifier);

        if (record.state !== KEY_STATES.ACTIVE) {
            throw new KeyRevokedError(
                "The requested key has been revoked.",
                "KEY_REVOKED"
            );
        }

        return record;
    }

    encrypt(identifier, plaintext, label = Buffer.alloc(0)) {
        this.#ensureReady();

        validateBuffer(plaintext, "plaintext");
        validateBuffer(label, "label");

        const record = this.#getActiveRecord(identifier);

        const maximum = Math.ceil(
            CONFIG.modulusLength / 8
        ) - 2 * 32 - 2;

        if (plaintext.length > maximum) {
            throw new EncryptionError(
                `Plaintext exceeds ${maximum} bytes.`
            );
        }

        try {
            const ciphertext = crypto.publicEncrypt(
                {
                    key: record.publicKey,
                    padding: CONFIG.oaepPadding,
                    oaepHash: CONFIG.hashAlgorithm,
                    oaepLabel: label
                },
                plaintext
            );

            this.operationCount++;

            const result = {
                keyId: identifier,
                fingerprint: record.fingerprint,
                algorithm: "RSA-OAEP-SHA256",
                ciphertext,
                createdAt: new Date()
            };

            this.emit("encryption:completed", {
                keyId: identifier,
                ciphertextLength: ciphertext.length
            });

            return result;

        } catch (error) {
            this.failureCount++;

            throw new EncryptionError(
                "Encryption operation failed."
            );
        }
    }

    decrypt(identifier, ciphertext, label = Buffer.alloc(0)) {
        this.#ensureReady();

        validateBuffer(ciphertext, "ciphertext");
        validateBuffer(label, "label");

        const record = this.#getActiveRecord(identifier);

        if (ciphertext.length !== 256) {
            throw new DecryptionError(
                "Invalid ciphertext length."
            );
        }

        try {
            const plaintext = crypto.privateDecrypt(
                {
                    key: record.privateKey,
                    padding: CONFIG.oaepPadding,
                    oaepHash: CONFIG.hashAlgorithm,
                    oaepLabel: label
                },
                ciphertext
            );

            this.operationCount++;

            this.emit("decryption:completed", {
                keyId: identifier,
                plaintextLength: plaintext.length
            });

            return plaintext;

        } catch (error) {
            this.failureCount++;

            throw new DecryptionError(
                "Decryption failed. Verify the key, ciphertext, and label."
            );
        }
    }

    sign(identifier, message) {
        this.#ensureReady();

        validateBuffer(message, "message");

        const record = this.#getActiveRecord(identifier);

        const signature = crypto.sign(
            "sha256",
            message,
            {
                key: record.privateKey,
                padding: CONFIG.pssPadding,
                saltLength: CONFIG.saltLength
            }
        );

        this.operationCount++;

        this.emit("signature:created", {
            keyId: identifier
        });

        return signature;
    }

    verify(identifier, message, signature) {
        this.#ensureReady();

        validateBuffer(message, "message");
        validateBuffer(signature, "signature");

        const record = this.registry.get(identifier);

        const valid = crypto.verify(
            "sha256",
            message,
            {
                key: record.publicKey,
                padding: CONFIG.pssPadding,
                saltLength: CONFIG.saltLength
            },
            signature
        );

        this.operationCount++;

        this.emit("signature:verified", {
            keyId: identifier,
            valid
        });

        return valid;
    }

    stop() {
        this.state = SERVICE_STATES.STOPPED;
        this.emit("service:stopped");
    }

    metrics() {
        return Object.freeze({
            operations: this.operationCount,
            failures: this.failureCount,
            activeKeys: this.registry.getActiveCount(),
            state: this.state
        });
    }
}

// ============================================================
// File operations
// ============================================================

async function savePublicKey(directory, identifier, publicKey) {
    validateIdentifier(identifier);

    const safeDirectory = path.resolve(directory);

    await fs.mkdir(safeDirectory, {
        recursive: true,
        mode: 0o700
    });

    const destination = path.join(
        safeDirectory,
        `${identifier}.public.pem`
    );

    await fs.writeFile(destination, publicKey, {
        encoding: "utf8",
        mode: 0o644,
        flag: "wx"
    });

    return destination;
}

// ============================================================
// Event monitoring
// ============================================================

function attachMonitoring(registry, service) {
    registry.on("key:registered", event => {
        console.log("[AUDIT] Key registered:", event.identifier);
    });

    registry.on("key:revoked", event => {
        console.log("[AUDIT] Key revoked:", event.identifier);
    });

    service.on("encryption:completed", event => {
        console.log(
            "[AUDIT] Encryption completed:",
            event.keyId
        );
    });

    service.on("decryption:completed", event => {
        console.log(
            "[AUDIT] Decryption completed:",
            event.keyId
        );
    });

    service.on("signature:verified", event => {
        console.log(
            "[AUDIT] Signature verification:",
            event.valid
        );
    });
}

// ============================================================
// Application workflow
// ============================================================

async function main() {
    console.log("RSA ENCRYPTION AND DECRYPTION");
    console.log("================================");

    const registry = new KeyRegistry();

    const service = new RSAService(registry);

    attachMonitoring(registry, service);

    const generated = await generateKeyPair();

    const keyId = "enterprise-key-001";

    const keyFingerprint = registry.register(
        keyId,
        generated
    );

    console.log("Key fingerprint:", keyFingerprint);

    const message = Buffer.from(
        "Confidential enterprise transaction information.",
        "utf8"
    );

    const label = Buffer.from(
        "enterprise-rsa-v1",
        "utf8"
    );

    const encrypted = service.encrypt(
        keyId,
        message,
        label
    );

    console.log(
        "Ciphertext length:",
        encrypted.ciphertext.length
    );

    const decrypted = service.decrypt(
        keyId,
        encrypted.ciphertext,
        label
    );

    assert.deepEqual(decrypted, message);

    console.log("Decrypted:", decrypted.toString("utf8"));

    const signature = service.sign(keyId, message);

    const valid = service.verify(
        keyId,
        message,
        signature
    );

    assert.equal(valid, true);

    const tampered = Buffer.from(
        message.toString("utf8") + " altered"
    );

    assert.equal(
        service.verify(keyId, tampered, signature),
        false
    );

    console.log("Signature verification: PASSED");
    console.log("Tamper detection: PASSED");

    // Encryption is randomized by OAEP.
    const second = service.encrypt(keyId, message, label);

    assert.notDeepEqual(
        encrypted.ciphertext,
        second.ciphertext
    );

    console.log("Randomized encryption: PASSED");

    // Incorrect labels must fail authentication during OAEP decoding.
    assert.throws(
        () => service.decrypt(
            keyId,
            encrypted.ciphertext,
            Buffer.from("wrong-label")
        ),
        DecryptionError
    );

    console.log("Wrong-label rejection: PASSED");

    // Revocation blocks further private-key operations.
    registry.revoke(keyId);

    assert.throws(
        () => service.decrypt(
            keyId,
            encrypted.ciphertext,
            label
        ),
        KeyRevokedError
    );

    console.log("Revocation enforcement: PASSED");

    console.log("\nService metrics:");
    console.log(service.metrics());

    service.stop();
}

// ============================================================
// Entry point
// ============================================================

if (require.main === module) {
    main().catch(error => {
        console.error(
            "Application failure:",
            error.message
        );

        process.exitCode = 1;
    });
}

module.exports = {
    RSAService,
    KeyRegistry,
    generateKeyPair,
    fingerprint,
    CONFIG
};
