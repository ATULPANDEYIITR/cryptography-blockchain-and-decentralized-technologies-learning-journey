"use strict";

/*
 * Public-Key Cryptography with Node.js.
 *
 * Runtime: Node.js 20+
 * Dependency: Node.js built-in crypto module.
 *
 * Demonstrates:
 * - RSA public/private key generation
 * - RSA-OAEP encryption
 * - RSA-PSS digital signatures
 * - SHA-256 fingerprints
 * - AES-256-GCM hybrid encryption
 * - Key lifecycle management
 * - Certificate-like issuer verification
 * - Asynchronous cryptographic workflows
 * - Tampering detection
 * - Event-driven audit records
 *
 * Educational certificate representation is not X.509.
 */

const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { EventEmitter } = require("node:events");

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

class CryptoError extends Error {
    constructor(message) {
        super(message);
        this.name = "CryptoError";
    }
}

class ValidationError extends CryptoError {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

class KeyPair {
    constructor(publicKey, privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.createdAt = new Date();

        this.status = "ACTIVE";

        this.fingerprint = crypto
            .createHash("sha256")
            .update(publicKey.export({
                type: "spki",
                format: "der"
            }))
            .digest("hex");
    }

    static async generate(modulusLength = 3072) {
        if (![2048, 3072, 4096].includes(modulusLength)) {
            throw new ValidationError("Unsupported RSA key size.");
        }

        const { publicKey, privateKey } =
            await generateKeyPairAsync("rsa", {
                modulusLength,
                publicExponent: 0x10001,
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
            crypto.createPublicKey(publicKey),
            crypto.createPrivateKey(privateKey)
        );
    }

    exportPublic() {
        return this.publicKey.export({
            type: "spki",
            format: "pem"
        });
    }

    revoke() {
        if (this.status === "REVOKED") {
            throw new ValidationError("Key is already revoked.");
        }

        this.status = "REVOKED";
    }

    rotate() {
        if (this.status !== "ACTIVE") {
            throw new ValidationError("Only active keys can rotate.");
        }

        this.status = "ROTATED";
    }
}

class KeyRegistry extends EventEmitter {
    #keys = new Map();

    register(keyPair) {
        if (!(keyPair instanceof KeyPair)) {
            throw new ValidationError("Invalid key-pair object.");
        }

        if (this.#keys.has(keyPair.fingerprint)) {
            throw new ValidationError("Duplicate key registration.");
        }

        this.#keys.set(keyPair.fingerprint, keyPair);

        this.emit("key.registered", {
            fingerprint: keyPair.fingerprint,
            timestamp: new Date().toISOString()
        });
    }

    find(fingerprint) {
        const key = this.#keys.get(fingerprint);

        if (!key) {
            throw new ValidationError("Unknown key fingerprint.");
        }

        return key;
    }

    requireActive(fingerprint) {
        const key = this.find(fingerprint);

        if (key.status !== "ACTIVE") {
            throw new ValidationError("Key is not active.");
        }

        return key;
    }

    revoke(fingerprint) {
        const key = this.find(fingerprint);

        key.revoke();

        this.emit("key.revoked", {
            fingerprint,
            timestamp: new Date().toISOString()
        });
    }

    list() {
        return [...this.#keys.values()].map(key => ({
            fingerprint: key.fingerprint,
            status: key.status,
            createdAt: key.createdAt.toISOString()
        }));
    }
}

class PublicKeyService {
    static encrypt(publicKey, plaintext) {
        if (!Buffer.isBuffer(plaintext)) {
            throw new ValidationError("Plaintext must be a Buffer.");
        }

        return crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        }, plaintext);
    }

    static decrypt(privateKey, ciphertext) {
        try {
            return crypto.privateDecrypt({
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            }, ciphertext);
        } catch {
            throw new CryptoError("RSA decryption failed.");
        }
    }

    static sign(privateKey, data) {
        const signer = crypto.createSign("SHA256");

        signer.update(data);
        signer.end();

        return signer.sign({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
        });
    }

    static verify(publicKey, data, signature) {
        const verifier = crypto.createVerify("SHA256");

        verifier.update(data);
        verifier.end();

        return verifier.verify({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
        }, signature);
    }
}

class HybridCipher {
    static encrypt(recipient, plaintext) {
        if (recipient.status !== "ACTIVE") {
            throw new ValidationError("Recipient key is not active.");
        }

        if (!Buffer.isBuffer(plaintext)) {
            throw new ValidationError("Plaintext must be a Buffer.");
        }

        const sessionKey = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(12);

        const aad = Buffer.from(recipient.fingerprint, "utf8");

        const cipher = crypto.createCipheriv(
            "aes-256-gcm",
            sessionKey,
            nonce
        );

        cipher.setAAD(aad);

        const encrypted = Buffer.concat([
            cipher.update(plaintext),
            cipher.final()
        ]);

        const tag = cipher.getAuthTag();

        const encryptedSessionKey = PublicKeyService.encrypt(
            recipient.publicKey,
            sessionKey
        );

        return Object.freeze({
            version: 1,
            algorithm: "RSA-OAEP-SHA256+A256GCM",
            recipientFingerprint: recipient.fingerprint,
            encryptedSessionKey: encryptedSessionKey.toString("base64"),
            nonce: nonce.toString("base64"),
            ciphertext: encrypted.toString("base64"),
            tag: tag.toString("base64")
        });
    }

    static decrypt(recipient, envelope) {
        if (recipient.status === "REVOKED") {
            throw new ValidationError("Recipient key is revoked.");
        }

        if (envelope.version !== 1 ||
            envelope.algorithm !== "RSA-OAEP-SHA256+A256GCM") {
            throw new ValidationError("Unsupported envelope format.");
        }

        if (envelope.recipientFingerprint !== recipient.fingerprint) {
            throw new ValidationError("Recipient fingerprint mismatch.");
        }

        try {
            const sessionKey = PublicKeyService.decrypt(
                recipient.privateKey,
                Buffer.from(envelope.encryptedSessionKey, "base64")
            );

            const nonce = Buffer.from(envelope.nonce, "base64");
            const ciphertext = Buffer.from(envelope.ciphertext, "base64");
            const tag = Buffer.from(envelope.tag, "base64");

            if (sessionKey.length !== 32 ||
                nonce.length !== 12 ||
                tag.length !== 16) {
                throw new CryptoError("Invalid envelope parameters.");
            }

            const decipher = crypto.createDecipheriv(
                "aes-256-gcm",
                sessionKey,
                nonce
            );

            decipher.setAAD(
                Buffer.from(recipient.fingerprint, "utf8")
            );

            decipher.setAuthTag(tag);

            return Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);
        } catch {
            throw new CryptoError(
                "Envelope decryption or authentication failed."
            );
        }
    }

    static serialize(envelope) {
        return JSON.stringify(envelope);
    }

    static parse(serialized) {
        let envelope;

        try {
            envelope = JSON.parse(serialized);
        } catch {
            throw new ValidationError("Malformed JSON envelope.");
        }

        const fields = [
            "version",
            "algorithm",
            "recipientFingerprint",
            "encryptedSessionKey",
            "nonce",
            "ciphertext",
            "tag"
        ];

        for (const field of fields) {
            if (!(field in envelope) ||
                typeof envelope[field] !== "string" &&
                typeof envelope[field] !== "number") {
                throw new ValidationError(`Invalid field: ${field}`);
            }
        }

        if (typeof envelope.recipientFingerprint !== "string" ||
            typeof envelope.encryptedSessionKey !== "string" ||
            typeof envelope.nonce !== "string" ||
            typeof envelope.ciphertext !== "string" ||
            typeof envelope.tag !== "string") {
            throw new ValidationError("Invalid envelope field types.");
        }

        return envelope;
    }
}

class CertificateAuthority {
    static issue(subject, subjectKey, issuerKey, validityDays = 365) {
        if (!subject || typeof subject !== "string") {
            throw new ValidationError("Certificate subject is required.");
        }

        if (issuerKey.status !== "ACTIVE") {
            throw new ValidationError("Issuer key is not active.");
        }

        if (!Number.isInteger(validityDays) ||
            validityDays < 1 ||
            validityDays > 825) {
            throw new ValidationError("Invalid certificate validity period.");
        }

        const content = {
            subject,
            publicKey: subjectKey.exportPublic(),
            issuerFingerprint: issuerKey.fingerprint,
            expiresAt: new Date(
                Date.now() + validityDays * 86400000
            ).toISOString()
        };

        const canonical = JSON.stringify(content);

        return Object.freeze({
            ...content,
            signature: PublicKeyService.sign(
                issuerKey.privateKey,
                Buffer.from(canonical)
            ).toString("base64")
        });
    }

    static verify(certificate, issuerKey) {
        if (issuerKey.status !== "ACTIVE") {
            return false;
        }

        if (certificate.issuerFingerprint !== issuerKey.fingerprint) {
            return false;
        }

        if (Date.now() >= Date.parse(certificate.expiresAt)) {
            return false;
        }

        const content = {
            subject: certificate.subject,
            publicKey: certificate.publicKey,
            issuerFingerprint: certificate.issuerFingerprint,
            expiresAt: certificate.expiresAt
        };

        return PublicKeyService.verify(
            issuerKey.publicKey,
            Buffer.from(JSON.stringify(content)),
            Buffer.from(certificate.signature, "base64")
        );
    }
}

class AuditService extends EventEmitter {
    #events = [];

    record(type, details) {
        const event = Object.freeze({
            type,
            details,
            timestamp: new Date().toISOString()
        });

        this.#events.push(event);
        this.emit("audit", event);
    }

    getEvents() {
        return [...this.#events];
    }
}

async function main() {
    console.log("PUBLIC-KEY CRYPTOGRAPHY DEMONSTRATION");
    console.log("=".repeat(55));

    const registry = new KeyRegistry();
    const audit = new AuditService();

    registry.on("key.registered", event => {
        audit.record("KEY_REGISTERED", event);
    });

    registry.on("key.revoked", event => {
        audit.record("KEY_REVOKED", event);
    });

    audit.on("audit", event => {
        console.log(`[AUDIT] ${event.type}`);
    });

    console.log("\n1. GENERATING KEY PAIRS");

    const alice = await KeyPair.generate(2048);
    const bob = await KeyPair.generate(2048);
    const authority = await KeyPair.generate(2048);

    registry.register(alice);
    registry.register(bob);
    registry.register(authority);

    console.log("Alice fingerprint:", alice.fingerprint.slice(0, 32));
    console.log("Bob fingerprint:", bob.fingerprint.slice(0, 32));

    console.log("\n2. RSA ENCRYPTION");

    const confidential = Buffer.from(
        "Confidential enterprise communication"
    );

    const ciphertext = PublicKeyService.encrypt(
        bob.publicKey,
        confidential
    );

    const recovered = PublicKeyService.decrypt(
        bob.privateKey,
        ciphertext
    );

    console.log("Original:", confidential.toString());
    console.log("Recovered:", recovered.toString());

    console.log("\n3. DIGITAL SIGNATURE");

    const transaction = Buffer.from(
        "Transaction ID: TX-2026-001; Amount: 50000"
    );

    const signature = PublicKeyService.sign(
        alice.privateKey,
        transaction
    );

    console.log(
        "Valid signature:",
        PublicKeyService.verify(
            alice.publicKey,
            transaction,
            signature
        )
    );

    console.log(
        "Modified transaction:",
        PublicKeyService.verify(
            alice.publicKey,
            Buffer.from(transaction.toString() + "; Amount: 1"),
            signature
        )
    );

    console.log("\n4. HYBRID ENCRYPTION");

    const largeDocument = Buffer.from(
        "Confidential corporate document. ".repeat(5000)
    );

    const envelope = HybridCipher.encrypt(
        bob,
        largeDocument
    );

    const serialized = HybridCipher.serialize(envelope);
    const restoredEnvelope = HybridCipher.parse(serialized);

    const decryptedDocument = HybridCipher.decrypt(
        bob,
        restoredEnvelope
    );

    console.log("Original bytes:", largeDocument.length);
    console.log("Envelope bytes:", Buffer.byteLength(serialized));
    console.log(
        "Recovered correctly:",
        largeDocument.equals(decryptedDocument)
    );

    console.log("\n5. CERTIFICATE ISSUANCE");

    const certificate = CertificateAuthority.issue(
        "Bob Enterprise Account",
        bob,
        authority,
        365
    );

    console.log("Subject:", certificate.subject);

    console.log(
        "Certificate valid:",
        CertificateAuthority.verify(certificate, authority)
    );

    console.log("\n6. TAMPERING DETECTION");

    const damaged = {
        ...envelope,
        ciphertext: Buffer.alloc(largeDocument.length, 0).toString("base64")
    };

    try {
        HybridCipher.decrypt(bob, damaged);
        throw new Error("Tampering was not detected.");
    } catch (error) {
        console.log("Tampering rejected:", error.message);
    }

    console.log("\n7. KEY LIFECYCLE");

    registry.revoke(bob.fingerprint);

    try {
        registry.requireActive(bob.fingerprint);
    } catch (error) {
        console.log("Expected rejection:", error.message);
    }

    console.log("\n8. KEY INVENTORY");

    console.table(registry.list());

    console.log("\n9. AUDIT HISTORY");

    console.log("Recorded events:", audit.getEvents().length);

    console.log("\nAll demonstrations completed.");
}

main().catch(error => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
