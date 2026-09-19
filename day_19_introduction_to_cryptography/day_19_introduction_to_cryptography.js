"use strict";

/*
 * Introduction to Cryptography
 * =============================
 *
 * A self-contained JavaScript study file covering fundamental and advanced
 * cryptographic concepts through executable examples.
 *
 * Node.js provides cryptographic primitives through the built-in `crypto`
 * module. Production systems should use standardized protocols and trusted
 * libraries rather than custom cryptographic constructions.
 */

const crypto = require("crypto");

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}


// ---------------------------------------------------------------------------
// 1. ENCODING IS NOT ENCRYPTION
// ---------------------------------------------------------------------------

function demonstrateEncoding() {
    section("1. Encoding is not encryption");

    const message = "Confidential data";
    const encoded = Buffer.from(message, "utf8").toString("base64");
    const decoded = Buffer.from(encoded, "base64").toString("utf8");

    console.log("Original:", message);
    console.log("Base64  :", encoded);
    console.log("Decoded :", decoded);

    console.log("\nBase64 provides representation, not confidentiality.");
}


// ---------------------------------------------------------------------------
// 2. HASH FUNCTIONS
// ---------------------------------------------------------------------------

function hashWithAlgorithm(algorithm, message) {
    return crypto
        .createHash(algorithm)
        .update(message)
        .digest("hex");
}

function demonstrateHashes() {
    section("2. Cryptographic hashes");

    const message = "Cryptography";

    for (const algorithm of ["sha256", "sha512", "sha3-256"]) {
        console.log(
            `${algorithm}: ${hashWithAlgorithm(algorithm, message)}`
        );
    }

    console.log("\nA hash is deterministic and one-way under the intended security model.");
    console.log("A one-character change should produce a substantially different digest.");

    console.log("\nAvalanche example:");
    console.log("Hello:", hashWithAlgorithm("sha256", "Hello"));
    console.log("hello:", hashWithAlgorithm("sha256", "hello"));
}


// ---------------------------------------------------------------------------
// 3. HMAC
// ---------------------------------------------------------------------------

function createHmac(secret, message) {
    return crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest("hex");
}

function demonstrateHmac() {
    section("3. HMAC");

    const secret = crypto.randomBytes(32);
    const message = Buffer.from("Transfer amount=500");

    const tag = createHmac(secret, message);

    console.log("Message:", message.toString());
    console.log("HMAC   :", tag);

    const correct = createHmac(secret, message);
    const modified = createHmac(secret, Buffer.from("Transfer amount=900"));

    console.log("Expected tag matches:", crypto.timingSafeEqual(
        Buffer.from(tag, "hex"),
        Buffer.from(correct, "hex")
    ));

    console.log("Modified message tag differs:", tag !== modified);

    console.log(
        "\nHMAC provides integrity and authentication when both parties possess the shared secret."
    );
}


// ---------------------------------------------------------------------------
// 4. SECURE RANDOMNESS
// ---------------------------------------------------------------------------

function demonstrateRandomness() {
    section("4. Cryptographically secure randomness");

    const randomBytes = crypto.randomBytes(32);
    const randomToken = crypto.randomBytes(24).toString("base64url");

    console.log("Random key material:", randomBytes.toString("hex"));
    console.log("Random token       :", randomToken);

    console.log(
        "\nCryptographic randomness is required for unpredictable keys, nonces, salts, and tokens."
    );
}


// ---------------------------------------------------------------------------
// 5. SYMMETRIC ENCRYPTION WITH AES-GCM
// ---------------------------------------------------------------------------

function encryptAesGcm(plaintext, key, associatedData = "") {
    // AES-GCM is authenticated encryption. The authentication tag detects
    // modification of ciphertext and associated data.
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    if (associatedData) {
        cipher.setAAD(Buffer.from(associatedData, "utf8"));
    }

    const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(plaintext, "utf8")),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return {
        iv,
        ciphertext,
        tag,
        associatedData
    };
}

function decryptAesGcm(record, key) {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        record.iv
    );

    if (record.associatedData) {
        decipher.setAAD(Buffer.from(record.associatedData, "utf8"));
    }

    decipher.setAuthTag(record.tag);

    return Buffer.concat([
        decipher.update(record.ciphertext),
        decipher.final()
    ]).toString("utf8");
}

function demonstrateAesGcm() {
    section("5. Authenticated symmetric encryption: AES-GCM");

    const key = crypto.randomBytes(32);

    const encrypted = encryptAesGcm(
        "Sensitive application data",
        key,
        "record-type=user"
    );

    console.log("IV        :", encrypted.iv.toString("hex"));
    console.log("Ciphertext:", encrypted.ciphertext.toString("hex"));
    console.log("Tag       :", encrypted.tag.toString("hex"));

    const recovered = decryptAesGcm(encrypted, key);

    console.log("Recovered :", recovered);

    // Tampering with one ciphertext byte should make authentication fail.
    const tampered = {
        ...encrypted,
        ciphertext: Buffer.from(encrypted.ciphertext)
    };

    tampered.ciphertext[0] ^= 1;

    try {
        decryptAesGcm(tampered, key);
        console.log("Unexpected result: tampered ciphertext accepted.");
    } catch (error) {
        console.log("Tampering rejected:", error.message);
    }

    console.log(
        "\nNonce/IV uniqueness is critical for GCM. Do not randomly or deliberately"
        + "\nreuse a nonce with the same key."
    );
}


// ---------------------------------------------------------------------------
// 6. PASSWORD HASHING WITH SCRYPT
// ---------------------------------------------------------------------------

function derivePasswordKey(password, salt) {
    // scrypt is deliberately expensive and memory-intensive compared with
    // ordinary SHA-256, making password guessing more costly.
    return new Promise((resolve, reject) => {
        crypto.scrypt(
            password,
            salt,
            32,
            {
                N: 16384,
                r: 8,
                p: 1
            },
            (error, derivedKey) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(derivedKey);
            }
        );
    });
}

async function demonstratePasswordHashing() {
    section("6. Password hashing with scrypt");

    const password = "correct horse battery staple";
    const salt = crypto.randomBytes(16);

    const storedKey = await derivePasswordKey(password, salt);
    const candidateKey = await derivePasswordKey(password, salt);
    const wrongKey = await derivePasswordKey("incorrect password", salt);

    console.log("Salt:", salt.toString("hex"));
    console.log(
        "Correct password:",
        crypto.timingSafeEqual(storedKey, candidateKey)
    );
    console.log(
        "Wrong password:",
        crypto.timingSafeEqual(storedKey, wrongKey)
    );

    console.log(
        "\nA password KDF should use a unique salt and intentionally expensive parameters."
    );
}


// ---------------------------------------------------------------------------
// 7. PBKDF2
// ---------------------------------------------------------------------------

function demonstratePbkdf2() {
    section("7. PBKDF2");

    const password = "example password";
    const salt = crypto.randomBytes(16);

    const derived = crypto.pbkdf2Sync(
        password,
        salt,
        200000,
        32,
        "sha256"
    );

    console.log("Salt   :", salt.toString("hex"));
    console.log("Derived:", derived.toString("hex"));

    console.log(
        "\nPBKDF2 is standardized and widely supported. Password-specific KDF choices"
        + "\nshould account for current security requirements and deployment constraints."
    );
}


// ---------------------------------------------------------------------------
// 8. ECDH KEY AGREEMENT
// ---------------------------------------------------------------------------

function demonstrateEcdh() {
    section("8. Elliptic-curve Diffie-Hellman");

    const alice = crypto.createECDH("prime256v1");
    const bob = crypto.createECDH("prime256v1");

    alice.generateKeys();
    bob.generateKeys();

    const aliceShared = alice.computeSecret(bob.getPublicKey());
    const bobShared = bob.computeSecret(alice.getPublicKey());

    console.log("Shared secrets equal:", aliceShared.equals(bobShared));
    console.log("Shared secret:", aliceShared.toString("hex"));

    console.log(
        "\nECDH establishes shared secret material without directly transmitting the secret."
    );
    console.log(
        "Authentication is still required to prevent man-in-the-middle attacks."
    );
}


// ---------------------------------------------------------------------------
// 9. RSA
// ---------------------------------------------------------------------------

function demonstrateRsa() {
    section("9. RSA public-key cryptography");

    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
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

    const message = Buffer.from("RSA encryption demonstration");

    const ciphertext = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        },
        message
    );

    const recovered = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        },
        ciphertext
    );

    console.log("Ciphertext:", ciphertext.toString("base64"));
    console.log("Recovered :", recovered.toString());

    console.log(
        "\nOAEP is required for secure RSA encryption; textbook RSA is not suitable."
    );
}


// ---------------------------------------------------------------------------
// 10. DIGITAL SIGNATURES
// ---------------------------------------------------------------------------

function demonstrateDigitalSignature() {
    section("10. Digital signatures");

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        publicKeyEncoding: {
            type: "spki",
            format: "pem"
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem"
        }
    });

    const message = Buffer.from("Approved transaction: 1000");

    const signer = crypto.createSign("SHA256");
    signer.update(message);
    signer.end();

    const signature = signer.sign(privateKey);

    const verifier = crypto.createVerify("SHA256");
    verifier.update(message);
    verifier.end();

    const valid = verifier.verify(publicKey, signature);

    console.log("Signature:", signature.toString("base64"));
    console.log("Valid:", valid);

    const tamperedMessage = Buffer.from("Approved transaction: 900");

    const tamperedVerifier = crypto.createVerify("SHA256");
    tamperedVerifier.update(tamperedMessage);
    tamperedVerifier.end();

    console.log(
        "Tampered message accepted:",
        tamperedVerifier.verify(publicKey, signature)
    );

    console.log(
        "\nA signature proves possession of the signing private key under the scheme's"
        + "\nsecurity assumptions and allows recipients to detect message modification."
    );
}


// ---------------------------------------------------------------------------
// 11. HASH CHAIN
// ---------------------------------------------------------------------------

function demonstrateHashChain() {
    section("11. Hash chains");

    let current = Buffer.from("GENESIS");

    for (let index = 1; index <= 5; index += 1) {
        current = crypto
            .createHash("sha256")
            .update(current)
            .digest();

        console.log(`Block ${index}: ${current.toString("hex")}`);
    }

    console.log(
        "\nHash chains make later values depend on earlier values."
    );
}


// ---------------------------------------------------------------------------
// 12. MERKLE TREE
// ---------------------------------------------------------------------------

function sha256Buffer(data) {
    return crypto
        .createHash("sha256")
        .update(data)
        .digest();
}

function merkleRoot(items) {
    if (items.length === 0) {
        throw new Error("A Merkle tree requires at least one item.");
    }

    let nodes = items.map(item => sha256Buffer(Buffer.from(item)));

    while (nodes.length > 1) {
        if (nodes.length % 2 === 1) {
            nodes.push(nodes[nodes.length - 1]);
        }

        const next = [];

        for (let index = 0; index < nodes.length; index += 2) {
            next.push(
                sha256Buffer(Buffer.concat([
                    nodes[index],
                    nodes[index + 1]
                ]))
            );
        }

        nodes = next;
    }

    return nodes[0];
}

function demonstrateMerkleTree() {
    section("12. Merkle trees");

    const transactions = [
        "Alice pays Bob 10",
        "Bob pays Carol 5",
        "Carol pays Dave 2",
        "Dave pays Erin 1",
        "Erin pays Frank 3"
    ];

    const root = merkleRoot(transactions);

    console.log("Merkle root:", root.toString("hex"));
    console.log(
        "A root hash commits to the collection of transactions beneath it."
    );
}


// ---------------------------------------------------------------------------
// 13. HASH-BASED TOKEN
// ---------------------------------------------------------------------------

class AuthenticatedTokenService {
    constructor(secret) {
        if (!Buffer.isBuffer(secret) || secret.length < 32) {
            throw new Error("A 32-byte or larger secret is required.");
        }

        this.secret = secret;
    }

    issue(userId, expiration) {
        if (!userId || !Number.isSafeInteger(expiration)) {
            throw new Error("Invalid token parameters.");
        }

        const payload = Buffer.from(
            JSON.stringify({
                userId,
                expiration
            }),
            "utf8"
        ).toString("base64url");

        const signingInput = `v1.${payload}`;

        const signature = crypto
            .createHmac("sha256", this.secret)
            .update(signingInput)
            .digest("base64url");

        return `${signingInput}.${signature}`;
    }

    verify(token, currentTime) {
        if (typeof token !== "string") {
            throw new Error("Token must be a string.");
        }

        const parts = token.split(".");

        if (parts.length !== 3 || parts[0] !== "v1") {
            throw new Error("Malformed token.");
        }

        const signingInput = `${parts[0]}.${parts[1]}`;

        const expected = crypto
            .createHmac("sha256", this.secret)
            .update(signingInput)
            .digest();

        let supplied;

        try {
            supplied = Buffer.from(parts[2], "base64url");
        } catch {
            throw new Error("Malformed signature.");
        }

        if (
            supplied.length !== expected.length ||
            !crypto.timingSafeEqual(expected, supplied)
        ) {
            throw new Error("Invalid token signature.");
        }

        let payload;

        try {
            payload = JSON.parse(
                Buffer.from(parts[1], "base64url").toString("utf8")
            );
        } catch {
            throw new Error("Malformed token payload.");
        }

        if (!Number.isSafeInteger(payload.expiration)) {
            throw new Error("Invalid expiration.");
        }

        if (payload.expiration < currentTime) {
            throw new Error("Token expired.");
        }

        return payload.userId;
    }
}

function demonstrateTokenService() {
    section("13. Mini case study: authenticated application tokens");

    const service = new AuthenticatedTokenService(
        crypto.randomBytes(32)
    );

    const token = service.issue("alice", 2_000_000_000);

    console.log("Token:", token);
    console.log(
        "Verified user:",
        service.verify(token, 1_900_000_000)
    );

    const tampered = token.slice(0, -1)
        + (token.endsWith("A") ? "B" : "A");

    try {
        service.verify(tampered, 1_900_000_000);
        console.log("Unexpected: tampered token accepted.");
    } catch (error) {
        console.log("Tampering rejected:", error.message);
    }

    try {
        service.verify(token, 2_100_000_000);
        console.log("Unexpected: expired token accepted.");
    } catch (error) {
        console.log("Expiration rejected:", error.message);
    }
}


// ---------------------------------------------------------------------------
// 14. NONCE AND IV DESIGN
// ---------------------------------------------------------------------------

function demonstrateNonceRules() {
    section("14. Nonces and IVs");

    const first = crypto.randomBytes(12);
    const second = crypto.randomBytes(12);

    console.log("First nonce :", first.toString("hex"));
    console.log("Second nonce:", second.toString("hex"));
    console.log("Equal:", first.equals(second));

    console.log(
        "\nNonce requirements depend on the cryptographic construction."
    );
    console.log(
        "For AES-GCM, reusing a nonce with the same key can seriously compromise security."
    );
}


// ---------------------------------------------------------------------------
// 15. KEY DERIVATION
// ---------------------------------------------------------------------------

function deriveApplicationKey(masterKey, label) {
    return crypto
        .createHmac("sha256", masterKey)
        .update(label)
        .digest();
}

function demonstrateKeySeparation() {
    section("15. Key separation and derivation");

    const masterKey = crypto.randomBytes(32);

    const encryptionKey = deriveApplicationKey(
        masterKey,
        "application encryption"
    );

    const authenticationKey = deriveApplicationKey(
        masterKey,
        "application authentication"
    );

    console.log("Encryption key     :", encryptionKey.toString("hex"));
    console.log("Authentication key :", authenticationKey.toString("hex"));
    console.log(
        "Same:",
        encryptionKey.equals(authenticationKey)
    );
}


// ---------------------------------------------------------------------------
// 16. CERTIFICATE INSPECTION MODEL
// ---------------------------------------------------------------------------

function demonstrateCertificateConcept() {
    section("16. Certificates and trust");

    const certificateConcept = {
        subject: "api.example",
        issuer: "Example Root CA",
        publicKey: "server public key",
        validity: "defined validity period",
        signature: "issuer's signature"
    };

    for (const [field, value] of Object.entries(certificateConcept)) {
        console.log(`${field}: ${value}`);
    }

    console.log(
        "\nCertificates bind identities to public keys through signatures."
    );
    console.log(
        "TLS certificate validation must check the relevant trust chain, name,"
        + "\nvalidity, key usage, and other protocol requirements."
    );
}


// ---------------------------------------------------------------------------
// 17. ASYNCHRONOUS APPLICATION BEHAVIOR
// ---------------------------------------------------------------------------

async function demonstrateAsyncCrypto() {
    section("17. Asynchronous cryptographic operations");

    const password = "application password";
    const salt = crypto.randomBytes(16);

    const derivedKey = await new Promise((resolve, reject) => {
        crypto.scrypt(
            password,
            salt,
            32,
            {
                N: 16384,
                r: 8,
                p: 1
            },
            (error, key) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(key);
            }
        );
    });

    console.log("Derived key:", derivedKey.toString("hex"));
    console.log(
        "\nAsynchronous APIs can prevent expensive password-derivation work"
        + "\nfrom unnecessarily blocking application logic."
    );
}


// ---------------------------------------------------------------------------
// 18. ERROR HANDLING
// ---------------------------------------------------------------------------

function demonstrateFailureHandling() {
    section("18. Failure handling");

    const key = crypto.randomBytes(32);

    const encrypted = encryptAesGcm(
        "Protected information",
        key
    );

    encrypted.tag[0] ^= 1;

    try {
        decryptAesGcm(encrypted, key);
        console.log("Unexpected: invalid authentication tag accepted.");
    } catch (error) {
        console.log(
            "Authentication failure correctly raised:",
            error.message
        );
    }

    console.log(
        "\nCryptographic verification failures should cause protected operations"
        + "\nto fail closed rather than silently continuing with untrusted data."
    );
}


// ---------------------------------------------------------------------------
// 19. PERFORMANCE
// ---------------------------------------------------------------------------

function demonstratePerformance() {
    section("19. Performance considerations");

    const data = Buffer.alloc(1024 * 1024, "A");

    const start = process.hrtime.bigint();

    const digest = crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");

    const end = process.hrtime.bigint();

    const milliseconds =
        Number(end - start) / 1_000_000;

    console.log("Bytes processed:", data.length);
    console.log("Digest:", digest);
    console.log("Time:", milliseconds.toFixed(3), "ms");

    console.log(
        "\nSymmetric cryptography is normally much faster than public-key operations."
    );
    console.log(
        "Password KDFs are deliberately slower to increase the cost of guessing attacks."
    );
}


// ---------------------------------------------------------------------------
// 20. COMMON MISTAKES
// ---------------------------------------------------------------------------

function demonstrateCommonMistakes() {
    section("20. Common cryptographic mistakes");

    const mistakes = [
        "Using Base64 as though it were encryption.",
        "Hashing passwords with plain SHA-256.",
        "Reusing an AES-GCM nonce with the same key.",
        "Hard-coding production secrets in source code.",
        "Using predictable random numbers for security tokens.",
        "Ignoring certificate validation.",
        "Using ordinary equality checks for authentication tags.",
        "Creating a custom encryption algorithm.",
        "Encrypting data without integrity protection.",
        "Failing to rotate or revoke compromised keys.",
        "Using one key for unrelated security purposes."
    ];

    mistakes.forEach((mistake, index) => {
        console.log(`${index + 1}. ${mistake}`);
    });
}


// ---------------------------------------------------------------------------
// 21. TESTS
// ---------------------------------------------------------------------------

function runTests() {
    section("21. Assertions");

    const key = crypto.randomBytes(32);

    const encrypted = encryptAesGcm(
        "test",
        key
    );

    if (decryptAesGcm(encrypted, key) !== "test") {
        throw new Error("AES-GCM test failed.");
    }

    const message = Buffer.from("message");
    const tag = Buffer.from(createHmac(key, message), "hex");

    const expected = Buffer.from(createHmac(key, message), "hex");

    if (!crypto.timingSafeEqual(tag, expected)) {
        throw new Error("HMAC test failed.");
    }

    const root1 = merkleRoot(["a", "b"]);
    const root2 = merkleRoot(["a", "c"]);

    if (root1.equals(root2)) {
        throw new Error("Merkle tree test failed.");
    }

    const service = new AuthenticatedTokenService(key);
    const token = service.issue("user-1", 2000000000);

    if (service.verify(token, 1900000000) !== "user-1") {
        throw new Error("Token test failed.");
    }

    console.log("All tests passed.");
}


// ---------------------------------------------------------------------------
// 22. MAIN
// ---------------------------------------------------------------------------

async function main() {
    demonstrateEncoding();
    demonstrateHashes();
    demonstrateHmac();
    demonstrateRandomness();
    demonstrateAesGcm();
    await demonstratePasswordHashing();
    demonstratePbkdf2();
    demonstrateEcdh();
    demonstrateRsa();
    demonstrateDigitalSignature();
    demonstrateHashChain();
    demonstrateMerkleTree();
    demonstrateTokenService();
    demonstrateNonceRules();
    demonstrateKeySeparation();
    demonstrateCertificateConcept();
    await demonstrateAsyncCrypto();
    demonstrateFailureHandling();
    demonstratePerformance();
    demonstrateCommonMistakes();
    runTests();

    section("Cryptography study program complete");

    console.log(
        "Covered encoding, hashing, HMAC, randomness, authenticated encryption,"
        + "\npassword KDFs, ECDH, RSA, digital signatures, Merkle trees,"
        + "\nkey separation, certificates, error handling, testing, and performance."
    );
}

main().catch(error => {
    console.error("Fatal error:", error.message);
    process.exitCode = 1;
});
