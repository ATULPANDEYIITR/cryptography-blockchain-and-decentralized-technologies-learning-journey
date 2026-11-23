"use strict";

/*
 * Public-Key Cryptography Practice Project
 *
 * Uses Node.js built-in cryptographic facilities.
 *
 * Demonstrates:
 * - RSA key generation
 * - RSA-OAEP encryption and decryption
 * - RSA-PSS digital signatures
 * - SHA-256 hashing
 * - Public-key fingerprints
 * - Key rotation and revocation
 * - Asynchronous cryptographic workflows
 * - Validation and failure handling
 *
 * Unlike textbook RSA, OAEP and PSS use secure padding.
 * This is a practice implementation, not a complete
 * production key-management infrastructure.
 */

const crypto = require("node:crypto");
const { promisify } = require("node:util");

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

const CONFIG = Object.freeze({
    modulusLength: 3072,
    publicExponent: 65537,
    oaepHash: "sha256",
    pssSaltLength: 32
});

class CryptoOperationError extends Error {
    constructor(message) {
        super(message);
        this.name = "CryptoOperationError";
    }
}

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

function validateBuffer(value, fieldName) {
    if (!Buffer.isBuffer(value)) {
        throw new ValidationError(`${fieldName} must be a Buffer.`);
    }

    if (value.length === 0) {
        throw new ValidationError(`${fieldName} cannot be empty.`);
    }
}

function fingerprint(publicKey) {
    if (!(publicKey instanceof crypto.KeyObject)) {
        throw new ValidationError("Invalid public key object.");
    }

    const der = publicKey.export({
        type: "spki",
        format: "der"
    });

    return crypto
        .createHash("sha256")
        .update(der)
        .digest("hex");
}

class RSAIdentity {
    constructor(id, publicKey, privateKey) {
        if (!id || typeof id !== "string") {
            throw new ValidationError("Identity ID is required.");
        }

        this.id = id;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.fingerprint = fingerprint(publicKey);
        this.status = "ACTIVE";
        this.createdAt = new Date().toISOString();
    }

    encrypt(plaintext) {
        validateBuffer(plaintext, "Plaintext");

        const modulusBytes = Math.ceil(
            this.publicKey.asymmetricKeyDetails.modulusLength / 8
        );

        const maximumLength = modulusBytes - 2 * 32 - 2;

        if (plaintext.length > maximumLength) {
            throw new ValidationError(
                `Message exceeds OAEP limit of ${maximumLength} bytes.`
            );
        }

        return crypto.publicEncrypt(
            {
                key: this.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: CONFIG.oaepHash
            },
            plaintext
        );
    }

    decrypt(ciphertext) {
        this.ensureActive();
        validateBuffer(ciphertext, "Ciphertext");

        if (!this.privateKey) {
            throw new CryptoOperationError(
                "Private key is unavailable."
            );
        }

        try {
            return crypto.privateDecrypt(
                {
                    key: this.privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: CONFIG.oaepHash
                },
                ciphertext
            );
        } catch {
            throw new CryptoOperationError(
                "Decryption failed. Check the key and ciphertext."
            );
        }
    }

    sign(message) {
        this.ensureActive();
        validateBuffer(message, "Message");

        return crypto.sign("sha256", message, {
            key: this.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: CONFIG.pssSaltLength
        });
    }

    verify(message, signature) {
        validateBuffer(message, "Message");
        validateBuffer(signature, "Signature");

        try {
            return crypto.verify(
                "sha256",
                message,
                {
                    key: this.publicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: CONFIG.pssSaltLength
                },
                signature
            );
        } catch {
            return false;
        }
    }

    ensureActive() {
        if (this.status !== "ACTIVE") {
            throw new CryptoOperationError(
                `Identity ${this.id} is ${this.status}.`
            );
        }
    }

    revoke() {
        if (this.status === "REVOKED") {
            throw new CryptoOperationError(
                "Identity is already revoked."
            );
        }

        this.status = "REVOKED";
    }
}

class IdentityRegistry {
    #identities = new Map();

    register(identity) {
        if (!(identity instanceof RSAIdentity)) {
            throw new ValidationError("Invalid identity.");
        }

        if (this.#identities.has(identity.id)) {
            throw new ValidationError("Duplicate identity ID.");
        }

        this.#identities.set(identity.id, identity);
    }

    get(id) {
        const identity = this.#identities.get(id);

        if (!identity) {
            throw new ValidationError("Identity not found.");
        }

        return identity;
    }

    rotate(oldId, newIdentity) {
        const previous = this.get(oldId);

        if (newIdentity.id === oldId ||
            this.#identities.has(newIdentity.id)) {
            throw new ValidationError(
                "New identity must have a unique identifier."
            );
        }

        // Register the replacement before revoking the old identity.
        this.register(newIdentity);
        previous.revoke();

        return newIdentity;
    }

    publicDirectory() {
        return Array.from(this.#identities.values(), identity => ({
            id: identity.id,
            fingerprint: identity.fingerprint,
            publicKey: identity.publicKey.export({
                type: "spki",
                format: "pem"
            }),
            status: identity.status
        }));
    }
}

async function createIdentity(id) {
    const { publicKey, privateKey } = await generateKeyPairAsync(
        "rsa",
        {
            modulusLength: CONFIG.modulusLength,
            publicExponent: CONFIG.publicExponent,
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

    return new RSAIdentity(
        id,
        crypto.createPublicKey(publicKey),
        crypto.createPrivateKey(privateKey)
    );
}

async function main() {
    console.log("PUBLIC-KEY CRYPTOGRAPHY PRACTICE");
    console.log("================================");

    const registry = new IdentityRegistry();

    const alice = await createIdentity("alice-key-001");
    registry.register(alice);

    const plaintext = Buffer.from(
        "Confidential repository deployment configuration",
        "utf8"
    );

    console.log("\n1. PUBLIC-KEY ENCRYPTION");

    const encrypted = alice.encrypt(plaintext);
    const decrypted = alice.decrypt(encrypted);

    console.log("Ciphertext length:", encrypted.length);
    console.log("Recovered:", decrypted.toString("utf8"));

    if (!plaintext.equals(decrypted)) {
        throw new CryptoOperationError("Decryption integrity test failed.");
    }

    console.log("\n2. DIGITAL SIGNATURE");

    const artifact = Buffer.from(
        "Release artifact: build-2026-001",
        "utf8"
    );

    const signature = alice.sign(artifact);

    console.log("Signature verified:", alice.verify(
        artifact,
        signature
    ));

    const modified = Buffer.from(
        "Release artifact: build-2026-002",
        "utf8"
    );

    console.log("Modified artifact verified:", alice.verify(
        modified,
        signature
    ));

    console.log("\n3. PUBLIC KEY FINGERPRINT");

    console.log(alice.fingerprint);

    console.log("\n4. KEY ROTATION");

    const replacement = await createIdentity("alice-key-002");

    registry.rotate("alice-key-001", replacement);

    console.log("Old identity:", alice.status);
    console.log("Replacement identity:", replacement.status);

    try {
        alice.decrypt(encrypted);
    } catch (error) {
        console.log("Old identity rejected:", error.message);
    }

    console.log("\n5. FAILURE HANDLING");

    try {
        alice.encrypt(Buffer.alloc(0));
    } catch (error) {
        console.log("Empty message rejected:", error.message);
    }

    const invalidSignature = Buffer.from(signature);
    invalidSignature[0] ^= 0xff;

    console.log(
        "Tampered signature verified:",
        replacement.verify(artifact, invalidSignature)
    );

    console.log("\n6. PUBLIC DIRECTORY");

    for (const entry of registry.publicDirectory()) {
        console.log({
            id: entry.id,
            fingerprint: entry.fingerprint,
            status: entry.status
        });
    }

    console.log("\nAll cryptographic workflow tests completed.");
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
