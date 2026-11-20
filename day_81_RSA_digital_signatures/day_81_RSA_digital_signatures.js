"use strict";

/*
 * RSA Digital Signatures
 * Node.js implementation using the built-in crypto module.
 *
 * Run:
 *   node rsa_signatures.js
 *
 * Uses:
 *   RSA-PSS
 *   SHA-256
 *   MGF1-SHA256
 *   Explicit signature verification
 *   Key fingerprints
 *   Canonical JSON
 *   Asynchronous file operations
 *   Tamper detection
 *   Signature envelopes
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { promisify } = require("node:util");

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

const ALGORITHM = "RSA-PSS-SHA256";
const HASH = "sha256";
const SALT_LENGTH = 32;

class SignatureError extends Error {
    constructor(message) {
        super(message);
        this.name = "SignatureError";
    }
}

class SignatureService {
    constructor(privateKey = null, publicKey = null) {
        this.privateKey = privateKey;
        this.publicKey =
            publicKey ||
            (privateKey ? crypto.createPublicKey(privateKey) : null);

        this.validateKeys();
    }

    static async generate(modulusLength = 3072) {
        if (![2048, 3072, 4096].includes(modulusLength)) {
            throw new RangeError("Unsupported RSA key size.");
        }

        const pair = await generateKeyPairAsync("rsa", {
            modulusLength,
            publicExponent: 0x10001,
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        });

        return new SignatureService(
            pair.privateKey,
            pair.publicKey
        );
    }

    validateKeys() {
        for (const key of [this.privateKey, this.publicKey]) {
            if (!key) continue;

            let details;

            try {
                details = crypto.createPublicKey(key).asymmetricKeyDetails;
            } catch {
                details = key.asymmetricKeyDetails;
            }

            if (
                !details ||
                !details.modulusLength ||
                details.modulusLength < 2048
            ) {
                throw new SignatureError(
                    "RSA keys must contain at least 2048 bits."
                );
            }
        }

        if (this.privateKey && this.publicKey) {
            const derived = crypto.createPublicKey(this.privateKey)
                .export({ type: "spki", format: "der" });

            const supplied = crypto.createPublicKey(this.publicKey)
                .export({ type: "spki", format: "der" });

            if (!derived.equals(supplied)) {
                throw new SignatureError(
                    "Private and public keys do not match."
                );
            }
        }
    }

    static canonicalJSON(value) {
        function normalize(item) {
            if (item === null || typeof item !== "object") {
                if (typeof item === "number" && !Number.isFinite(item)) {
                    throw new TypeError("Non-finite numbers are forbidden.");
                }

                if (typeof item === "bigint" ||
                    typeof item === "undefined") {
                    throw new TypeError("Unsupported JSON value.");
                }

                return item;
            }

            if (Array.isArray(item)) {
                return item.map(normalize);
            }

            const result = Object.create(null);

            for (const key of Object.keys(item).sort()) {
                if (item[key] === undefined) {
                    throw new TypeError("Undefined object values are forbidden.");
                }

                result[key] = normalize(item[key]);
            }

            return result;
        }

        return Buffer.from(
            JSON.stringify(normalize(value)),
            "utf8"
        );
    }

    static digest(message) {
        return crypto.createHash(HASH).update(message).digest("hex");
    }

    fingerprint() {
        if (!this.publicKey) {
            throw new SignatureError("Public key is unavailable.");
        }

        return crypto.createHash(HASH)
            .update(
                crypto.createPublicKey(this.publicKey).export({
                    type: "spki",
                    format: "der",
                })
            )
            .digest("hex");
    }

    sign(message) {
        if (!this.privateKey) {
            throw new SignatureError("Private key required.");
        }

        const data = Buffer.isBuffer(message)
            ? message
            : Buffer.from(message);

        const signature = crypto.sign(HASH, data, {
            key: this.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: SALT_LENGTH,
        });

        return Object.freeze({
            algorithm: ALGORITHM,
            hash: HASH,
            keyFingerprint: this.fingerprint(),
            messageDigest: SignatureService.digest(data),
            signature: signature.toString("base64"),
            createdAt: new Date().toISOString(),
        });
    }

    verify(message, signature) {
        if (!this.publicKey) {
            throw new SignatureError("Public key required.");
        }

        try {
            const data = Buffer.isBuffer(message)
                ? message
                : Buffer.from(message);

            const bytes = Buffer.isBuffer(signature)
                ? signature
                : Buffer.from(signature, "base64");

            return crypto.verify(HASH, data, {
                key: this.publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: SALT_LENGTH,
            }, bytes);
        } catch {
            return false;
        }
    }

    verifyEnvelope(message, envelope) {
        if (
            !envelope ||
            envelope.algorithm !== ALGORITHM ||
            envelope.hash !== HASH ||
            envelope.keyFingerprint !== this.fingerprint()
        ) {
            return false;
        }

        const data = Buffer.isBuffer(message)
            ? message
            : Buffer.from(message);

        if (
            SignatureService.digest(data) !== envelope.messageDigest
        ) {
            return false;
        }

        if (
            typeof envelope.signature !== "string" ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
                .test(envelope.signature)
        ) {
            return false;
        }

        const signature = Buffer.from(envelope.signature, "base64");

        if (signature.length !==
            crypto.createPublicKey(this.publicKey)
                .asymmetricKeyDetails.modulusLength / 8) {
            return false;
        }

        return this.verify(data, signature);
    }

    exportPublicKey() {
        if (!this.publicKey) {
            throw new SignatureError("Public key unavailable.");
        }

        return crypto.createPublicKey(this.publicKey).export({
            type: "spki",
            format: "pem",
        });
    }

    exportEncryptedPrivateKey(password) {
        if (!this.privateKey) {
            throw new SignatureError("Private key unavailable.");
        }

        if (!password || password.length < 16) {
            throw new RangeError("Use a password of at least 16 characters.");
        }

        return crypto.createPrivateKey(this.privateKey).export({
            type: "pkcs8",
            format: "pem",
            cipher: "aes-256-cbc",
            passphrase: password,
        });
    }

    static loadPublicKey(pem) {
        return new SignatureService(
            null,
            crypto.createPublicKey(pem)
        );
    }

    static loadEncryptedPrivateKey(pem, password) {
        const key = crypto.createPrivateKey({
            key: pem,
            format: "pem",
            passphrase: password,
        });

        return new SignatureService(key);
    }

    async signFile(filePath) {
        const absolutePath = path.resolve(filePath);
        const stat = await fs.lstat(absolutePath);

        if (!stat.isFile() || stat.isSymbolicLink()) {
            throw new SignatureError("Expected a regular file.");
        }

        const data = await fs.readFile(absolutePath);
        return this.sign(data);
    }

    async verifyFile(filePath, envelope) {
        const absolutePath = path.resolve(filePath);
        const stat = await fs.lstat(absolutePath);

        if (!stat.isFile() || stat.isSymbolicLink()) {
            throw new SignatureError("Expected a regular file.");
        }

        const data = await fs.readFile(absolutePath);
        return this.verifyEnvelope(data, envelope);
    }
}

async function main() {
    console.log("\nRSA DIGITAL SIGNATURE ENGINE");
    console.log("=".repeat(45));

    const service = await SignatureService.generate(3072);

    const document = {
        id: "RELEASE-2026-001",
        repository: "secure-payment-platform",
        version: 4,
        authorization: {
            approved: true,
            reviewer: "security-reviewer",
        },
    };

    const message = SignatureService.canonicalJSON(document);

    const envelope = service.sign(message);

    console.log("Algorithm:", envelope.algorithm);
    console.log("Fingerprint:", envelope.keyFingerprint);
    console.log("Message digest:", envelope.messageDigest);
    console.log("Signature length:",
        Buffer.from(envelope.signature, "base64").length);

    console.log(
        "Original document:",
        service.verifyEnvelope(message, envelope)
    );

    const modified = SignatureService.canonicalJSON({
        ...document,
        version: 5,
    });

    console.log(
        "Modified document:",
        service.verifyEnvelope(modified, envelope)
    );

    const publicOnly = SignatureService.loadPublicKey(
        service.exportPublicKey()
    );

    console.log(
        "Public-key-only verification:",
        publicOnly.verifyEnvelope(message, envelope)
    );

    try {
        publicOnly.sign(message);
    } catch (error) {
        console.log("Expected failure:", error.message);
    }

    const tamperedEnvelope = {
        ...envelope,
        signature: Buffer.from(
            Buffer.from(envelope.signature, "base64")
        ).map((byte, index) => index === 0 ? byte ^ 1 : byte)
            .toString("base64"),
    };

    console.log(
        "Tampered signature:",
        service.verifyEnvelope(message, tamperedEnvelope)
    );

    const encryptedKey = service.exportEncryptedPrivateKey(
        "Secure-Example-Password-2026!"
    );

    const restored = SignatureService.loadEncryptedPrivateKey(
        encryptedKey,
        "Secure-Example-Password-2026!"
    );

    console.log(
        "Restored private key:",
        restored.verifyEnvelope(message, envelope)
    );

    if (!service.verifyEnvelope(message, envelope)) {
        throw new Error("Signature verification failed.");
    }

    if (service.verifyEnvelope(modified, envelope)) {
        throw new Error("Tampered document was accepted.");
    }

    if (service.verifyEnvelope(message, tamperedEnvelope)) {
        throw new Error("Tampered signature was accepted.");
    }

    console.log("\nAll validation tests passed.");
}

main().catch((error) => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
