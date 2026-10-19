"use strict";

/*
 * Symmetric Encryption Practice Project
 *
 * Node.js implementation using the platform's maintained crypto subsystem.
 * The focus is authenticated symmetric encryption, key derivation, nonce
 * management, encrypted envelopes, file handling, and key rotation.
 *
 * This implementation deliberately differs from the Python implementation:
 * Node.js crypto APIs expose AES-GCM directly and make the authenticated
 * encryption workflow explicit through cipher.setAAD(), getAuthTag(), and
 * setAuthTag().
 */

const crypto = require("crypto");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 600_000;

/*
 * AES-GCM does not encrypt the AAD. It authenticates it alongside the
 * ciphertext. This makes it useful for protecting metadata such as record
 * identifiers or message types.
 */
function encryptBuffer(key, plaintext, aad = Buffer.alloc(0)) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
        throw new TypeError("AES-256-GCM requires a 32-byte key");
    }

    if (!Buffer.isBuffer(plaintext)) {
        throw new TypeError("Plaintext must be a Buffer");
    }

    if (!Buffer.isBuffer(aad)) {
        throw new TypeError("AAD must be a Buffer");
    }

    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, {
        authTagLength: TAG_LENGTH
    });

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return {
        nonce,
        ciphertext,
        tag,
        aad
    };
}

function decryptBuffer(key, envelope) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
        throw new TypeError("AES-256-GCM requires a 32-byte key");
    }

    if (!envelope || !Buffer.isBuffer(envelope.nonce)) {
        throw new TypeError("Invalid encryption envelope");
    }

    if (envelope.nonce.length !== NONCE_LENGTH) {
        throw new Error("Invalid GCM nonce length");
    }

    if (!Buffer.isBuffer(envelope.tag) || envelope.tag.length !== TAG_LENGTH) {
        throw new Error("Invalid GCM authentication tag");
    }

    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        key,
        envelope.nonce,
        { authTagLength: TAG_LENGTH }
    );

    decipher.setAAD(envelope.aad);
    decipher.setAuthTag(envelope.tag);

    /*
     * The final() call verifies the authentication tag. Plaintext must not
     * be treated as trusted until final() succeeds.
     */
    return Buffer.concat([
        decipher.update(envelope.ciphertext),
        decipher.final()
    ]);
}

function deriveKey(password, salt) {
    if (typeof password !== "string" || password.length < 12) {
        throw new Error("Password must contain at least 12 characters");
    }

    if (!Buffer.isBuffer(salt) || salt.length < 16) {
        throw new Error("PBKDF2 salt must contain at least 16 bytes");
    }

    return crypto.pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        "sha256"
    );
}

class KeyRing {
    constructor() {
        this.keys = new Map();
    }

    create(keyId) {
        if (!keyId || this.keys.has(keyId)) {
            throw new Error(`Key identifier already exists: ${keyId}`);
        }

        const key = crypto.randomBytes(KEY_LENGTH);
        this.keys.set(keyId, key);
        return key;
    }

    get(keyId) {
        const key = this.keys.get(keyId);

        if (!key) {
            throw new Error(`Unknown key identifier: ${keyId}`);
        }

        return key;
    }

    rotate(newKeyId) {
        return this.create(newKeyId);
    }
}

class EncryptedMessageService {
    constructor(keyRing) {
        this.keyRing = keyRing;
    }

    encryptText(text, keyId, metadata = {}) {
        if (typeof text !== "string") {
            throw new TypeError("Message must be text");
        }

        const aadObject = {
            schema: "symmetric-message-v1",
            metadata
        };

        const aad = Buffer.from(
            JSON.stringify(aadObject),
            "utf8"
        );

        const envelope = encryptBuffer(
            this.keyRing.get(keyId),
            Buffer.from(text, "utf8"),
            aad
        );

        return {
            version: 1,
            algorithm: ALGORITHM,
            keyId,
            nonce: envelope.nonce.toString("base64"),
            ciphertext: envelope.ciphertext.toString("base64"),
            tag: envelope.tag.toString("base64"),
            aad: envelope.aad.toString("base64")
        };
    }

    decryptText(document) {
        if (document.version !== 1) {
            throw new Error("Unsupported envelope version");
        }

        if (document.algorithm !== ALGORITHM) {
            throw new Error("Unsupported encryption algorithm");
        }

        const envelope = {
            nonce: Buffer.from(document.nonce, "base64"),
            ciphertext: Buffer.from(document.ciphertext, "base64"),
            tag: Buffer.from(document.tag, "base64"),
            aad: Buffer.from(document.aad, "base64")
        };

        return decryptBuffer(
            this.keyRing.get(document.keyId),
            envelope
        ).toString("utf8");
    }
}

async function encryptFile(sourcePath, destinationPath, service, keyId) {
    const plaintext = await fs.readFile(sourcePath);

    const document = service.encryptText(
        plaintext.toString("utf8"),
        keyId,
        {
            source: path.basename(sourcePath),
            type: "training-file"
        }
    );

    await fs.writeFile(
        destinationPath,
        JSON.stringify(document, null, 2),
        "utf8"
    );
}

async function decryptFile(sourcePath, destinationPath, service) {
    const document = JSON.parse(
        await fs.readFile(sourcePath, "utf8")
    );

    const plaintext = service.decryptText(document);

    await fs.writeFile(
        destinationPath,
        plaintext,
        "utf8"
    );
}

function demonstrateAuthenticatedEncryption() {
    const ring = new KeyRing();
    ring.create("2026-primary");

    const service = new EncryptedMessageService(ring);

    const encrypted = service.encryptText(
        "Confidential payment authorization",
        "2026-primary",
        {
            transactionId: "TX-2048",
            classification: "confidential"
        }
    );

    const recovered = service.decryptText(encrypted);

    console.log("\n=== AES-256-GCM ===");
    console.log("Algorithm:", encrypted.algorithm);
    console.log("Recovered:", recovered);

    return { ring, service, encrypted };
}

function demonstrateTampering(service, encrypted) {
    const modified = structuredClone(encrypted);

    const ciphertext = Buffer.from(
        modified.ciphertext,
        "base64"
    );

    ciphertext[0] ^= 0x01;
    modified.ciphertext = ciphertext.toString("base64");

    try {
        service.decryptText(modified);
        throw new Error("Tampering was incorrectly accepted");
    } catch (error) {
        if (error.message === "Tampering was incorrectly accepted") {
            throw error;
        }

        console.log("\n=== Tamper Detection ===");
        console.log("Modified ciphertext rejected by GCM authentication.");
    }
}

function demonstratePasswordDerivation() {
    const password = "correct horse battery staple 2026";
    const salt = crypto.randomBytes(16);

    const key = deriveKey(password, salt);
    const repeatedKey = deriveKey(password, salt);

    if (!crypto.timingSafeEqual(key, repeatedKey)) {
        throw new Error("PBKDF2 reproducibility test failed");
    }

    const otherSalt = crypto.randomBytes(16);
    const otherKey = deriveKey(password, otherSalt);

    console.log("\n=== PBKDF2 ===");
    console.log("Derived key length:", key.length);
    console.log("Same password and salt:", true);
    console.log(
        "Different salt produces different key:",
        !crypto.timingSafeEqual(key, otherKey)
    );
}

function demonstrateKeyRotation() {
    const ring = new KeyRing();
    ring.create("key-v1");
    ring.create("key-v2");

    const service = new EncryptedMessageService(ring);

    const oldEnvelope = service.encryptText(
        "Data originally encrypted under key-v1",
        "key-v1"
    );

    const plaintext = service.decryptText(oldEnvelope);

    const newEnvelope = service.encryptText(
        plaintext,
        "key-v2"
    );

    console.log("\n=== Key Rotation ===");
    console.log("Old key ID:", oldEnvelope.keyId);
    console.log("New key ID:", newEnvelope.keyId);
    console.log("Recovered after rotation:", service.decryptText(newEnvelope));
}

function demonstrateNonceRequirement() {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const key = crypto.randomBytes(KEY_LENGTH);

    const first = encryptBuffer(
        key,
        Buffer.from("first"),
        Buffer.from("record=1")
    );

    /*
     * The public API generates a fresh nonce. The application should also
     * maintain a nonce registry if deterministic nonce construction is used.
     * Reusing a nonce under the same GCM key can expose relationships between
     * plaintexts and can undermine authentication security.
     */
    console.log("\n=== Nonce Handling ===");
    console.log("Required nonce size:", NONCE_LENGTH);
    console.log("Generated nonce size:", first.nonce.length);
    console.log("Example separately generated nonce:", nonce.length);
}

async function demonstrateFileWorkflow(service) {
    const directory = await fs.mkdtemp(
        path.join(os.tmpdir(), "symmetric-encryption-")
    );

    const source = path.join(directory, "record.txt");
    const encrypted = path.join(directory, "record.enc.json");
    const restored = path.join(directory, "record.restored.txt");

    const content =
        "Confidential operational record\n" +
        "Classification: restricted\n" +
        "Encryption: AES-256-GCM\n";

    await fs.writeFile(source, content, "utf8");
    await encryptFile(source, encrypted, service, "2026-primary");
    await decryptFile(encrypted, restored, service);

    const recovered = await fs.readFile(restored, "utf8");

    if (recovered !== content) {
        throw new Error("File round-trip failed");
    }

    console.log("\n=== File Workflow ===");
    console.log("Encrypted file:", encrypted);
    console.log("Recovered content matches original:", true);
}

function runValidationTests() {
    const key = crypto.randomBytes(KEY_LENGTH);

    const encrypted = encryptBuffer(
        key,
        Buffer.from("edge case"),
        Buffer.from("type=test")
    );

    const recovered = decryptBuffer(key, encrypted);

    if (!recovered.equals(Buffer.from("edge case"))) {
        throw new Error("Basic round-trip failed");
    }

    try {
        decryptBuffer(
            crypto.randomBytes(KEY_LENGTH),
            encrypted
        );
        throw new Error("Wrong-key decryption unexpectedly succeeded");
    } catch (error) {
        if (error.message === "Wrong-key decryption unexpectedly succeeded") {
            throw error;
        }
    }

    console.log("\n=== Validation Tests ===");
    console.log("Correct-key round trip: PASS");
    console.log("Wrong-key rejection: PASS");
}

async function main() {
    console.log("SYMMETRIC ENCRYPTION PRACTICE PROJECT");

    const { ring, service, encrypted } =
        demonstrateAuthenticatedEncryption();

    demonstrateTampering(service, encrypted);
    demonstratePasswordDerivation();
    demonstrateKeyRotation();
    demonstrateNonceRequirement();
    runValidationTests();

    /*
     * Re-create the primary key after the rotation demonstration because
     * each KeyRing is independent in this practice application.
     */
    if (!ring.keys.has("2026-primary")) {
        ring.create("2026-primary");
    }

    await demonstrateFileWorkflow(service);

    console.log("\n=== Security Properties ===");
    console.log("Confidentiality: AES-256 encryption");
    console.log("Integrity/authenticity: GCM authentication tag");
    console.log("Metadata authentication: GCM AAD");
    console.log("Password hardening: PBKDF2-HMAC-SHA256");
    console.log("Key generation: cryptographically secure random bytes");
    console.log("Production rule: use maintained cryptographic libraries");
}

main().catch((error) => {
    console.error("\nFatal error:", error.message);
    process.exitCode = 1;
});
