/*
 * Modern Cryptography in JavaScript
 * =================================
 *
 * This file demonstrates modern cryptographic concepts using Node.js'
 * built-in `crypto` module.
 *
 * The examples intentionally distinguish:
 *   - encoding from encryption
 *   - hashing from password hashing
 *   - authentication from confidentiality
 *   - symmetric cryptography from public-key cryptography
 *   - key exchange from encryption
 *   - digital signatures from MACs
 *
 * Production cryptography should use standardized algorithms and mature,
 * audited implementations. Do not replace Node.js cryptographic primitives
 * with hand-written implementations in production.
 *
 * Tested conceptually against modern Node.js APIs:
 *   - crypto.randomBytes
 *   - crypto.createHash
 *   - crypto.createHmac
 *   - crypto.scryptSync
 *   - crypto.createCipheriv
 *   - crypto.createDecipheriv
 *   - crypto.generateKeyPairSync
 *   - crypto.sign
 *   - crypto.verify
 *   - crypto.diffieHellman
 *   - crypto.timingSafeEqual
 */

"use strict";

const crypto = require("crypto");

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

// ---------------------------------------------------------------------------
// 1. Encoding versus encryption
// ---------------------------------------------------------------------------

function demonstrateEncoding() {
    section("1. Encoding versus encryption");

    const plaintext = Buffer.from("Confidential message", "utf8");
    const encoded = plaintext.toString("base64");
    const decoded = Buffer.from(encoded, "base64").toString("utf8");

    console.log("Plaintext:", plaintext.toString());
    console.log("Base64:", encoded);
    console.log("Decoded:", decoded);

    console.log(
        "Base64 is encoding. Anyone who can decode it can recover the data."
    );
}

// ---------------------------------------------------------------------------
// 2. Hashing
// ---------------------------------------------------------------------------

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function demonstrateHashing() {
    section("2. Cryptographic hashing");

    const firstMessage = Buffer.from("modern cryptography");
    const secondMessage = Buffer.from("modern cryptographY");

    const firstDigest = sha256(firstMessage);
    const secondDigest = sha256(secondMessage);

    console.log("SHA-256 A:", firstDigest);
    console.log("SHA-256 B:", secondDigest);
    console.log("Digests differ:", firstDigest !== secondDigest);

    const streamingHash = crypto.createHash("sha256");
    streamingHash.update("modern ");
    streamingHash.update("cryptography");
    console.log("Incremental hash:", streamingHash.digest("hex"));
}

// ---------------------------------------------------------------------------
// 3. Password-derived keys
// ---------------------------------------------------------------------------

function derivePasswordKey(password, salt, keyLength = 32) {
    if (!Buffer.isBuffer(salt) || salt.length < 16) {
        throw new Error("A password salt should contain sufficient random data.");
    }

    return crypto.scryptSync(
        password,
        salt,
        keyLength,
        {
            N: 16384,
            r: 8,
            p: 1,
        }
    );
}

function demonstratePasswordKdf() {
    section("3. Password hashing and key derivation");

    const password = "correct horse battery staple";
    const salt = crypto.randomBytes(16);

    const key = derivePasswordKey(password, salt);

    console.log("Salt:", salt.toString("hex"));
    console.log("Derived key:", key.toString("hex"));

    const sameKey = derivePasswordKey(password, salt);
    const differentKey = derivePasswordKey(
        password,
        crypto.randomBytes(16)
    );

    console.log(
        "Same password and salt:",
        crypto.timingSafeEqual(key, sameKey)
    );

    console.log(
        "Different random salt produces different key:",
        !crypto.timingSafeEqual(key, differentKey)
    );
}

// ---------------------------------------------------------------------------
// 4. HMAC
// ---------------------------------------------------------------------------

function calculateHmac(key, message) {
    return crypto
        .createHmac("sha256", key)
        .update(message)
        .digest();
}

function demonstrateHmac() {
    section("4. HMAC");

    const secret = crypto.randomBytes(32);
    const message = Buffer.from("transfer=5000&currency=INR");

    const tag = calculateHmac(secret, message);

    console.log("HMAC:", tag.toString("hex"));

    const validTag = calculateHmac(secret, message);

    console.log(
        "Valid tag:",
        crypto.timingSafeEqual(tag, validTag)
    );

    const tampered = Buffer.from("transfer=9000&currency=INR");
    const tamperedTag = calculateHmac(secret, tampered);

    console.log(
        "Tampered message accepted:",
        crypto.timingSafeEqual(tag, tamperedTag)
    );
}

// ---------------------------------------------------------------------------
// 5. Secure randomness
// ---------------------------------------------------------------------------

function demonstrateRandomness() {
    section("5. Cryptographically secure randomness");

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const randomInteger = crypto.randomInt(0, 1_000_000);

    console.log("256-bit key:", key.toString("hex"));
    console.log("96-bit nonce:", nonce.toString("hex"));
    console.log("Random integer:", randomInteger);

    console.log(
        "Do not use Math.random() to generate cryptographic keys or tokens."
    );
}

// ---------------------------------------------------------------------------
// 6. AES-256-GCM authenticated encryption
// ---------------------------------------------------------------------------

function encryptAesGcm(key, plaintext, associatedData = Buffer.alloc(0)) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new Error("AES-256-GCM requires a 32-byte key.");
    }

    const nonce = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        key,
        nonce
    );

    cipher.setAAD(associatedData);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);

    const authenticationTag = cipher.getAuthTag();

    return {
        nonce,
        ciphertext,
        authenticationTag,
    };
}

function decryptAesGcm(
    key,
    encrypted,
    associatedData = Buffer.alloc(0)
) {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        encrypted.nonce
    );

    decipher.setAAD(associatedData);
    decipher.setAuthTag(encrypted.authenticationTag);

    return Buffer.concat([
        decipher.update(encrypted.ciphertext),
        decipher.final(),
    ]);
}

function demonstrateAead() {
    section("6. AES-256-GCM authenticated encryption");

    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from("Confidential payment instruction");
    const associatedData = Buffer.from("account-id=42");

    const encrypted = encryptAesGcm(
        key,
        plaintext,
        associatedData
    );

    console.log("Nonce:", encrypted.nonce.toString("hex"));
    console.log("Ciphertext:", encrypted.ciphertext.toString("hex"));
    console.log(
        "Authentication tag:",
        encrypted.authenticationTag.toString("hex")
    );

    const recovered = decryptAesGcm(
        key,
        encrypted,
        associatedData
    );

    console.log("Recovered:", recovered.toString());

    // Altering ciphertext should cause authentication failure.
    const tamperedCiphertext = Buffer.from(encrypted.ciphertext);
    tamperedCiphertext[0] ^= 1;

    try {
        decryptAesGcm(
            key,
            {
                nonce: encrypted.nonce,
                ciphertext: tamperedCiphertext,
                authenticationTag: encrypted.authenticationTag,
            },
            associatedData
        );
        console.log("Unexpected success.");
    } catch (error) {
        console.log("Tampering detected:", error.message);
    }
}

// ---------------------------------------------------------------------------
// 7. RSA key generation and OAEP encryption
// ---------------------------------------------------------------------------

function demonstrateRsa() {
    section("7. RSA public-key encryption");

    const { publicKey, privateKey } = crypto.generateKeyPairSync(
        "rsa",
        {
            modulusLength: 3072,
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        }
    );

    const plaintext = Buffer.from("Secret session key");

    const encrypted = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        plaintext
    );

    const recovered = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encrypted
    );

    console.log("Encrypted length:", encrypted.length);
    console.log("Recovered:", recovered.toString());
}

// ---------------------------------------------------------------------------
// 8. Digital signatures
// ---------------------------------------------------------------------------

function demonstrateDigitalSignature() {
    section("8. Digital signatures");

    const { publicKey, privateKey } = crypto.generateKeyPairSync(
        "ed25519",
        {
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        }
    );

    const document = Buffer.from(
        "Approved purchase order #1042"
    );

    const signature = crypto.sign(
        null,
        document,
        privateKey
    );

    const valid = crypto.verify(
        null,
        document,
        publicKey,
        signature
    );

    console.log("Signature:", signature.toString("hex"));
    console.log("Valid signature:", valid);

    const modifiedDocument = Buffer.from(
        "Approved purchase order #1043"
    );

    console.log(
        "Modified document accepted:",
        crypto.verify(
            null,
            modifiedDocument,
            publicKey,
            signature
        )
    );
}

// ---------------------------------------------------------------------------
// 9. Diffie-Hellman / X25519 key agreement
// ---------------------------------------------------------------------------

function demonstrateKeyAgreement() {
    section("9. X25519 key agreement");

    const alice = crypto.generateKeyPairSync("x25519");
    const bob = crypto.generateKeyPairSync("x25519");

    const aliceSharedSecret = crypto.diffieHellman({
        privateKey: alice.privateKey,
        publicKey: bob.publicKey,
    });

    const bobSharedSecret = crypto.diffieHellman({
        privateKey: bob.privateKey,
        publicKey: alice.publicKey,
    });

    console.log(
        "Alice shared secret:",
        aliceSharedSecret.toString("hex")
    );

    console.log(
        "Bob shared secret:",
        bobSharedSecret.toString("hex")
    );

    console.log(
        "Shared secrets match:",
        crypto.timingSafeEqual(
            aliceSharedSecret,
            bobSharedSecret
        )
    );

    /*
     * Key agreement establishes shared secret material.
     * It does not automatically authenticate the peer.
     *
     * A complete protocol normally combines key agreement with:
     *   - authentication
     *   - transcript binding
     *   - key derivation
     *   - nonce management
     *   - replay protection
     */
}

// ---------------------------------------------------------------------------
// 10. Hybrid encryption
// ---------------------------------------------------------------------------

function demonstrateHybridEncryption() {
    section("10. Hybrid encryption");

    const {
        publicKey,
        privateKey,
    } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 3072,
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
    });

    const sessionKey = crypto.randomBytes(32);

    const payload = Buffer.from(
        "Large application payload"
    );

    const encryptedPayload = encryptAesGcm(
        sessionKey,
        payload,
        Buffer.from("protocol-version=1")
    );

    const wrappedSessionKey = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        sessionKey
    );

    const recoveredSessionKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        wrappedSessionKey
    );

    const recoveredPayload = decryptAesGcm(
        recoveredSessionKey,
        encryptedPayload,
        Buffer.from("protocol-version=1")
    );

    console.log("Wrapped session key length:", wrappedSessionKey.length);
    console.log("Recovered payload:", recoveredPayload.toString());
}

// ---------------------------------------------------------------------------
// 11. Password storage record
// ---------------------------------------------------------------------------

function createPasswordRecord(password) {
    const salt = crypto.randomBytes(16);
    const derivedKey = derivePasswordKey(password, salt);

    return {
        algorithm: "scrypt",
        salt: salt.toString("base64"),
        derivedKey: derivedKey.toString("base64"),
    };
}

function verifyPassword(password, record) {
    const salt = Buffer.from(record.salt, "base64");
    const expected = Buffer.from(record.derivedKey, "base64");
    const actual = derivePasswordKey(password, salt);

    return (
        expected.length === actual.length &&
        crypto.timingSafeEqual(expected, actual)
    );
}

function demonstratePasswordStorage() {
    section("11. Password storage");

    const record = createPasswordRecord(
        "correct horse battery staple"
    );

    console.log("Stored record:", record);

    console.log(
        "Correct password:",
        verifyPassword(
            "correct horse battery staple",
            record
        )
    );

    console.log(
        "Wrong password:",
        verifyPassword(
            "incorrect password",
            record
        )
    );
}

// ---------------------------------------------------------------------------
// 12. Replay protection
// ---------------------------------------------------------------------------

class ReplayProtector {
    constructor(maximumAgeSeconds = 300) {
        this.maximumAgeSeconds = maximumAgeSeconds;
        this.seenIds = new Set();
    }

    accept(message, secret) {
        const currentTime = Math.floor(Date.now() / 1000);

        if (
            Math.abs(currentTime - message.timestamp) >
            this.maximumAgeSeconds
        ) {
            return false;
        }

        if (this.seenIds.has(message.id)) {
            return false;
        }

        const authenticatedData = Buffer.from(
            `${message.id}|${message.timestamp}|${message.body}`,
            "utf8"
        );

        const expectedTag = calculateHmac(
            secret,
            authenticatedData
        );

        const suppliedTag = Buffer.from(
            message.tag,
            "base64"
        );

        if (
            expectedTag.length !== suppliedTag.length ||
            !crypto.timingSafeEqual(
                expectedTag,
                suppliedTag
            )
        ) {
            return false;
        }

        this.seenIds.add(message.id);
        return true;
    }
}

function demonstrateReplayProtection() {
    section("12. Replay protection");

    const secret = crypto.randomBytes(32);

    const message = {
        id: crypto.randomBytes(16).toString("hex"),
        timestamp: Math.floor(Date.now() / 1000),
        body: "withdraw=1000",
    };

    const authenticatedData = Buffer.from(
        `${message.id}|${message.timestamp}|${message.body}`,
        "utf8"
    );

    message.tag = calculateHmac(
        secret,
        authenticatedData
    ).toString("base64");

    const protector = new ReplayProtector();

    console.log(
        "First request:",
        protector.accept(message, secret)
    );

    console.log(
        "Replayed request:",
        protector.accept(message, secret)
    );
}

// ---------------------------------------------------------------------------
// 13. Cryptographic agility
// ---------------------------------------------------------------------------

function demonstrateCryptoAgility() {
    section("13. Cryptographic agility");

    const policies = [
        {
            version: 1,
            encryption: "AES-256-GCM",
            hash: "SHA-256",
            signature: "Ed25519",
        },
        {
            version: 2,
            encryption: "ChaCha20-Poly1305",
            hash: "SHA-384",
            signature: "Post-quantum signature selected by policy",
        },
    ];

    for (const policy of policies) {
        console.log(policy);
    }

    console.log(
        "Protocols should identify algorithm suites explicitly so that "
        + "migration does not require rewriting every application component."
    );
}

// ---------------------------------------------------------------------------
// 14. Security checklist
// ---------------------------------------------------------------------------

function printSecurityChecklist() {
    section("14. Production security checklist");

    const checklist = [
        "Use standardized cryptographic primitives.",
        "Prefer AEAD for authenticated encryption.",
        "Never reuse nonces where an algorithm forbids reuse.",
        "Use CSPRNG-generated keys and tokens.",
        "Use password-specific KDFs for passwords.",
        "Never hard-code production secrets.",
        "Separate key IDs from key material.",
        "Plan key rotation and revocation.",
        "Authenticate protocol metadata.",
        "Implement replay protection for state-changing requests.",
        "Use timing-safe comparison for authentication material.",
        "Avoid logging secrets and plaintext sensitive data.",
        "Design for algorithm migration.",
        "Test authentication failures and malformed input.",
        "Consider post-quantum migration requirements.",
    ];

    checklist.forEach((item, index) => {
        console.log(`${String(index + 1).padStart(2, "0")}. ${item}`);
    });
}

// ---------------------------------------------------------------------------
// 15. Integrated secure messaging service
// ---------------------------------------------------------------------------

class SecureMessageService {
    constructor() {
        this.masterKey = crypto.randomBytes(32);
        this.usedMessageIds = new Set();
    }

    encrypt(sender, plaintext) {
        if (!Buffer.isBuffer(plaintext) || plaintext.length === 0) {
            throw new Error("Plaintext must be a non-empty Buffer.");
        }

        const messageId = crypto.randomBytes(16).toString("hex");

        const associatedData = Buffer.from(
            `sender=${sender}|message-id=${messageId}`,
            "utf8"
        );

        const encrypted = encryptAesGcm(
            this.masterKey,
            plaintext,
            associatedData
        );

        return {
            sender,
            messageId,
            associatedData,
            encrypted,
        };
    }

    decrypt(packageData) {
        if (this.usedMessageIds.has(packageData.messageId)) {
            throw new Error("Replay detected.");
        }

        const plaintext = decryptAesGcm(
            this.masterKey,
            packageData.encrypted,
            packageData.associatedData
        );

        this.usedMessageIds.add(packageData.messageId);

        return plaintext;
    }
}

function demonstrateIntegratedService() {
    section("15. Integrated secure messaging service");

    const service = new SecureMessageService();

    const messagePackage = service.encrypt(
        "alice@example.test",
        Buffer.from("Confidential payment instruction")
    );

    console.log(
        "Message ID:",
        messagePackage.messageId
    );

    const recovered = service.decrypt(messagePackage);

    console.log("Recovered:", recovered.toString());

    try {
        service.decrypt(messagePackage);
    } catch (error) {
        console.log("Replay blocked:", error.message);
    }
}

// ---------------------------------------------------------------------------
// 16. Main
// ---------------------------------------------------------------------------

function main() {
    console.log("MODERN CRYPTOGRAPHY - JAVASCRIPT STUDY PROGRAM");

    demonstrateEncoding();
    demonstrateHashing();
    demonstratePasswordKdf();
    demonstrateHmac();
    demonstrateRandomness();
    demonstrateAead();
    demonstrateRsa();
    demonstrateDigitalSignature();
    demonstrateKeyAgreement();
    demonstrateHybridEncryption();
    demonstratePasswordStorage();
    demonstrateReplayProtection();
    demonstrateCryptoAgility();
    printSecurityChecklist();
    demonstrateIntegratedService();

    section("Program completed");
    console.log(
        "Use audited cryptographic libraries and explicit security reviews "
        + "for production systems."
    );
}

main();
