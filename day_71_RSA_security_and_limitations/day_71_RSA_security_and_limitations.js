"use strict";

/*
 * RSA Security and Limitations
 *
 * Node.js implementation using the built-in crypto module.
 * Demonstrates actual RSA-OAEP encryption, RSA-PSS signatures,
 * asynchronous policy assessment, lifecycle events, and audit records.
 *
 * RSA private keys must be protected in production.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class RSAError extends Error {
    constructor(message, code) {
        super(message);
        this.name = "RSAError";
        this.code = code;
    }
}

const KeyState = Object.freeze({
    ACTIVE: "ACTIVE",
    ROTATED: "ROTATED",
    REVOKED: "REVOKED",
    COMPROMISED: "COMPROMISED"
});

const Operation = Object.freeze({
    ENCRYPT: "ENCRYPT",
    DECRYPT: "DECRYPT",
    SIGN: "SIGN",
    VERIFY: "VERIFY"
});

const Padding = Object.freeze({
    OAEP: "RSA-OAEP-SHA256",
    PSS: "RSA-PSS-SHA256",
    RAW: "RAW-RSA",
    PKCS1: "PKCS1-V1.5"
});

class RSAKeyRecord {
    constructor({
        id,
        modulusBits,
        exponent = 65537,
        state = KeyState.ACTIVE,
        privateExportable = false,
        owner
    }) {
        if (!id || typeof id !== "string") {
            throw new TypeError("A valid key identifier is required");
        }

        if (!Number.isInteger(modulusBits) || modulusBits < 512) {
            throw new RangeError("Invalid modulus size");
        }

        if (!Number.isInteger(exponent) || exponent < 3 ||
            exponent % 2 === 0) {
            throw new RangeError("Invalid RSA public exponent");
        }

        this.id = id;
        this.modulusBits = modulusBits;
        this.exponent = exponent;
        this.state = state;
        this.privateExportable = privateExportable;
        this.owner = owner || "cryptographic-service";
        this.createdAt = new Date().toISOString();
    }
}

class RSAPolicy {
    constructor({
        minimumBits = 2048,
        requiredExponent = 65537,
        allowLegacy = false
    } = {}) {
        if (!Number.isInteger(minimumBits) || minimumBits < 2048) {
            throw new RangeError("Production RSA minimum is 2048 bits");
        }

        this.minimumBits = minimumBits;
        this.requiredExponent = requiredExponent;
        this.allowLegacy = allowLegacy;
    }

    async evaluate(record, operation, padding) {
        // Yield to the event loop so independent assessments can run concurrently.
        await Promise.resolve();

        const findings = [];

        const add = (severity, code, message) => {
            findings.push({ severity, code, message });
        };

        if (record.state !== KeyState.ACTIVE) {
            add("CRITICAL", "INACTIVE_KEY", "Key is not active");
        }

        if (record.modulusBits < this.minimumBits) {
            add("CRITICAL", "WEAK_MODULUS", "RSA modulus is too small");
        }

        if (record.exponent !== this.requiredExponent) {
            add("HIGH", "INVALID_EXPONENT",
                "Public exponent violates policy");
        }

        if (record.privateExportable) {
            add("HIGH", "PRIVATE_KEY_EXPOSURE",
                "Private key is exportable");
        }

        if (padding === Padding.RAW) {
            add("CRITICAL", "TEXTBOOK_RSA",
                "Unpadded RSA is prohibited");
        }

        if (operation === Operation.ENCRYPT ||
            operation === Operation.DECRYPT) {
            if (padding !== Padding.OAEP) {
                add("HIGH", "ENCRYPTION_PADDING",
                    "RSA-OAEP with SHA-256 is required");
            }
        }

        if (operation === Operation.SIGN ||
            operation === Operation.VERIFY) {
            if (padding !== Padding.PSS) {
                add("HIGH", "SIGNATURE_PADDING",
                    "RSA-PSS with SHA-256 is required");
            }
        }

        if (padding === Padding.PKCS1 && !this.allowLegacy) {
            add("HIGH", "LEGACY_PADDING",
                "Legacy padding is disabled");
        }

        return Object.freeze({
            keyId: record.id,
            approved: findings.length === 0,
            findings: Object.freeze(findings)
        });
    }
}

class RSAService extends EventEmitter {
    constructor(policy) {
        super();

        this.policy = policy;
        this.records = new Map();
        this.material = new Map();
        this.audit = [];
    }

    log(event, data) {
        const entry = Object.freeze({
            timestamp: new Date().toISOString(),
            event,
            ...data
        });

        this.audit.push(entry);
        this.emit("audit", entry);
    }

    generateKeyPair(id, modulusBits = 3072) {
        if (this.records.has(id)) {
            throw new RSAError("Duplicate key identifier", "DUPLICATE_KEY");
        }

        if (![2048, 3072, 4096].includes(modulusBits)) {
            throw new RangeError("Supported modulus sizes: 2048, 3072, 4096");
        }

        const { publicKey, privateKey } = crypto.generateKeyPairSync(
            "rsa",
            {
                modulusLength: modulusBits,
                publicExponent: 65537,
                publicKeyEncoding: {
                    type: "spki",
                    format: "pem"
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem"
                }
            }
        );

        const record = new RSAKeyRecord({
            id,
            modulusBits,
            exponent: 65537,
            privateExportable: true
        });

        this.records.set(id, record);
        this.material.set(id, { publicKey, privateKey });

        this.log("KEY_GENERATED", {
            keyId: id,
            modulusBits
        });

        return record;
    }

    async authorize(id, operation, padding) {
        const record = this.records.get(id);

        if (!record) {
            throw new RSAError("Unknown key", "UNKNOWN_KEY");
        }

        const result = await this.policy.evaluate(
            record,
            operation,
            padding
        );

        this.log("POLICY_EVALUATED", {
            keyId: id,
            operation,
            padding,
            approved: result.approved
        });

        if (!result.approved) {
            throw new RSAError(
                JSON.stringify(result.findings),
                "POLICY_DENIED"
            );
        }

        return result;
    }

    async encrypt(id, plaintext) {
        await this.authorize(id, Operation.ENCRYPT, Padding.OAEP);

        if (typeof plaintext !== "string" || plaintext.length === 0) {
            throw new TypeError("Plaintext must be a nonempty string");
        }

        const material = this.material.get(id);

        // RSA-OAEP has a strict input-size limit.
        // SHA-256 permits k - 2*hLen - 2 bytes.
        const maxBytes = Math.ceil(
            this.records.get(id).modulusBits / 8
        ) - 66;

        const input = Buffer.from(plaintext, "utf8");

        if (input.length > maxBytes) {
            throw new RangeError(
                "Message exceeds RSA-OAEP capacity; use hybrid encryption"
            );
        }

        const ciphertext = crypto.publicEncrypt(
            {
                key: material.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            input
        );

        this.log("ENCRYPTION_COMPLETED", { keyId: id });

        return ciphertext.toString("base64");
    }

    async decrypt(id, ciphertextBase64) {
        await this.authorize(id, Operation.DECRYPT, Padding.OAEP);

        if (typeof ciphertextBase64 !== "string" ||
            !/^[A-Za-z0-9+/]+={0,2}$/.test(ciphertextBase64)) {
            throw new TypeError("Invalid Base64 ciphertext");
        }

        const material = this.material.get(id);
        const ciphertext = Buffer.from(ciphertextBase64, "base64");

        const expectedLength = Math.ceil(
            this.records.get(id).modulusBits / 8
        );

        if (ciphertext.length !== expectedLength) {
            throw new RSAError("Invalid ciphertext length", "INVALID_CIPHERTEXT");
        }

        try {
            const plaintext = crypto.privateDecrypt(
                {
                    key: material.privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256"
                },
                ciphertext
            );

            this.log("DECRYPTION_COMPLETED", { keyId: id });

            return plaintext.toString("utf8");
        } catch {
            // Do not disclose padding or decryption details to remote callers.
            this.log("DECRYPTION_FAILED", { keyId: id });
            throw new RSAError("Decryption failed", "DECRYPTION_FAILED");
        }
    }

    async sign(id, message) {
        await this.authorize(id, Operation.SIGN, Padding.PSS);

        if (typeof message !== "string") {
            throw new TypeError("Message must be a string");
        }

        const material = this.material.get(id);

        const signature = crypto.sign(
            "sha256",
            Buffer.from(message, "utf8"),
            {
                key: material.privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
            }
        );

        this.log("SIGNATURE_CREATED", { keyId: id });

        return signature.toString("base64");
    }

    async verify(id, message, signatureBase64) {
        await this.authorize(id, Operation.VERIFY, Padding.PSS);

        const material = this.material.get(id);

        try {
            const signature = Buffer.from(signatureBase64, "base64");

            return crypto.verify(
                "sha256",
                Buffer.from(message, "utf8"),
                {
                    key: material.publicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 32
                },
                signature
            );
        } catch {
            return false;
        }
    }

    revoke(id) {
        const record = this.records.get(id);

        if (!record) {
            throw new RSAError("Unknown key", "UNKNOWN_KEY");
        }

        record.state = KeyState.REVOKED;

        // Remove locally retained private material.
        this.material.delete(id);

        this.log("KEY_REVOKED", { keyId: id });
    }
}

async function runTests() {
    const policy = new RSAPolicy();

    const weak = new RSAKeyRecord({
        id: "weak-key",
        modulusBits: 1024,
        exponent: 3
    });

    const result = await policy.evaluate(
        weak,
        Operation.ENCRYPT,
        Padding.RAW
    );

    console.assert(!result.approved);
    console.assert(result.findings.length >= 3);

    const secure = new RSAKeyRecord({
        id: "secure-key",
        modulusBits: 3072,
        exponent: 65537
    });

    const secureResult = await policy.evaluate(
        secure,
        Operation.SIGN,
        Padding.PSS
    );

    console.assert(secureResult.approved);
}

async function main() {
    await runTests();

    const service = new RSAService(new RSAPolicy());

    service.on("audit", entry => {
        console.log(`[AUDIT] ${entry.event}: ${entry.keyId || ""}`);
    });

    const record = service.generateKeyPair("enterprise-rsa-001", 2048);

    const original = "RSA-OAEP and RSA-PSS security demonstration";

    const ciphertext = await service.encrypt(record.id, original);
    const decrypted = await service.decrypt(record.id, ciphertext);

    if (decrypted !== original) {
        throw new Error("Encryption/decryption verification failed");
    }

    const signature = await service.sign(record.id, original);

    const valid = await service.verify(
        record.id,
        original,
        signature
    );

    const invalid = await service.verify(
        record.id,
        original + " modified",
        signature
    );

    console.log("\nEncryption/decryption:", decrypted === original);
    console.log("Valid signature:", valid);
    console.log("Modified message accepted:", invalid);

    service.revoke(record.id);

    try {
        await service.sign(record.id, original);
    } catch (error) {
        console.log("Revoked-key operation rejected:", error.code);
    }

    console.log("\nAudit events:", service.audit.length);
    console.log("\nTests completed.");
}

main().catch(error => {
    console.error("Application failure:", error.message);
    process.exitCode = 1;
});
