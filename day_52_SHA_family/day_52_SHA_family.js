"use strict";

/*
 * SHA family case study using the Node.js standard library.
 *
 * Covers:
 * - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
 * - SHA-3 and SHAKE where supported by the installed Node.js/OpenSSL build
 * - Incremental hashing
 * - Streaming file hashing
 * - HMAC
 * - PBKDF2-HMAC password verification
 * - Event-driven processing
 * - Constant-time digest comparison
 * - Algorithm validation and failure handling
 *
 * Run with:
 *   node sha-family.js
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SUPPORTED_ALGORITHMS = [
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512"
];

function assertAlgorithm(algorithm) {
    if (!crypto.getHashes().includes(algorithm)) {
        throw new Error(`Hash algorithm is unavailable: ${algorithm}`);
    }
}

function hashText(text, algorithm = "sha256") {
    assertAlgorithm(algorithm);

    return crypto
        .createHash(algorithm)
        .update(text, "utf8")
        .digest("hex");
}

function hashBuffer(buffer, algorithm = "sha256") {
    assertAlgorithm(algorithm);

    return crypto
        .createHash(algorithm)
        .update(buffer)
        .digest("hex");
}

async function hashFile(filePath, algorithm = "sha256") {
    assertAlgorithm(algorithm);

    return new Promise((resolve, reject) => {
        const hash = crypto.createHash(algorithm);
        const stream = fs.createReadStream(filePath, {
            highWaterMark: 1024 * 1024
        });

        stream.on("data", chunk => {
            hash.update(chunk);
        });

        stream.once("error", reject);

        stream.once("end", () => {
            resolve(hash.digest("hex"));
        });
    });
}

function safeHexEqual(expectedHex, actualHex) {
    if (!/^[0-9a-f]+$/i.test(expectedHex)) {
        return false;
    }

    if (!/^[0-9a-f]+$/i.test(actualHex)) {
        return false;
    }

    const expected = Buffer.from(expectedHex, "hex");
    const actual = Buffer.from(actualHex, "hex");

    if (expected.length !== actual.length) {
        return false;
    }

    return crypto.timingSafeEqual(expected, actual);
}

function createHmac(key, message, algorithm = "sha256") {
    assertAlgorithm(algorithm);

    return crypto
        .createHmac(algorithm, key)
        .update(message)
        .digest("hex");
}

function verifyHmac(key, message, expectedHex, algorithm = "sha256") {
    const actualHex = createHmac(key, message, algorithm);
    return safeHexEqual(expectedHex, actualHex);
}

function derivePassword(password, salt, iterations = 600000) {
    if (typeof password !== "string" || password.length === 0) {
        throw new TypeError("Password must be a non-empty string.");
    }

    if (!Number.isSafeInteger(iterations) || iterations < 100000) {
        throw new RangeError("Iteration count is below the accepted security policy.");
    }

    return new Promise((resolve, reject) => {
        crypto.pbkdf2(
            password,
            salt,
            iterations,
            32,
            "sha256",
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

async function verifyPassword(password, record) {
    const candidate = await derivePassword(
        password,
        record.salt,
        record.iterations
    );

    if (candidate.length !== record.digest.length) {
        return false;
    }

    return crypto.timingSafeEqual(candidate, record.digest);
}

async function createTemporaryArtifact() {
    const directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "sha-family-")
    );

    const filePath = path.join(directory, "artifact.bin");

    const content = crypto.randomBytes(2 * 1024 * 1024);
    fs.writeFileSync(filePath, content);

    return { directory, filePath };
}

function demonstrateIncrementalHashing() {
    const chunks = [
        Buffer.from("commit: 8e1a7d\n"),
        Buffer.from("artifact: release.tar\n"),
        Buffer.from("status: verified\n")
    ];

    const incremental = crypto.createHash("sha256");

    for (const chunk of chunks) {
        incremental.update(chunk);
    }

    const expected = hashBuffer(Buffer.concat(chunks));

    if (!safeHexEqual(expected, incremental.digest("hex"))) {
        throw new Error("Incremental SHA-256 verification failed.");
    }

    console.log("\nIncremental SHA-256");
    console.log("===================");
    console.log(expected);
}

function demonstrateHashFamily() {
    const message = "SHA family integrity example";

    console.log("SHA-family digests");
    console.log("===================");

    for (const algorithm of SUPPORTED_ALGORITHMS) {
        console.log(
            `${algorithm.padEnd(10)} ${hashText(message, algorithm)}`
        );
    }
}

async function demonstrateFileHashing() {
    const { directory, filePath } = await createTemporaryArtifact();

    try {
        const digest = await hashFile(filePath);

        console.log("\nStreaming file hashing");
        console.log("======================");
        console.log(`Path:   ${filePath}`);
        console.log(`SHA256: ${digest}`);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

async function demonstrateHmac() {
    const key = crypto.randomBytes(32);
    const message = Buffer.from("release-artifact:v4");

    const tag = createHmac(key, message);

    const valid = verifyHmac(key, message, tag);
    const invalid = verifyHmac(
        key,
        Buffer.from("release-artifact:v4-tampered"),
        tag
    );

    if (!valid || invalid) {
        throw new Error("HMAC verification test failed.");
    }

    console.log("\nHMAC authentication");
    console.log("===================");
    console.log(`Tag:      ${tag}`);
    console.log(`Valid:    ${valid}`);
    console.log(`Tampered: ${invalid}`);
}

async function demonstratePasswordKdf() {
    const salt = crypto.randomBytes(16);
    const iterations = 600000;

    const digest = await derivePassword(
        "correct horse battery staple",
        salt,
        iterations
    );

    const record = {
        salt,
        iterations,
        digest
    };

    const accepted = await verifyPassword(
        "correct horse battery staple",
        record
    );

    const rejected = await verifyPassword(
        "incorrect password",
        record
    );

    if (!accepted || rejected) {
        throw new Error("PBKDF2 password verification failed.");
    }

    console.log("\nPBKDF2-HMAC password verification");
    console.log("=================================");
    console.log(`Salt:       ${salt.toString("hex")}`);
    console.log(`Iterations: ${iterations}`);
    console.log(`Digest:     ${digest.toString("hex")}`);
    console.log(`Correct:    ${accepted}`);
    console.log(`Incorrect:  ${rejected}`);
}

function demonstrateFailureHandling() {
    console.log("\nValidation and failure handling");
    console.log("===============================");

    try {
        hashText("data", "not-a-real-sha");
    } catch (error) {
        console.log(`Rejected algorithm: ${error.message}`);
    }

    try {
        safeHexEqual("zzzz", "1234");
    } catch (error) {
        console.log(`Unexpected comparison failure: ${error.message}`);
    }

    console.log("Malformed digest comparison returns false rather than authenticating data.");
}

async function main() {
    demonstrateHashFamily();
    demonstrateIncrementalHashing();
    await demonstrateFileHashing();
    await demonstrateHmac();
    await demonstratePasswordKdf();
    demonstrateFailureHandling();

    console.log("\nSecurity considerations");
    console.log("=======================");
    console.log("SHA-1 remains available for compatibility but is not suitable for new collision-resistant designs.");
    console.log("Raw SHA digests do not prove who produced a message.");
    console.log("HMAC provides authentication when both parties share a secret key.");
    console.log("PBKDF2 deliberately increases password-guessing cost.");
    console.log("Streaming prevents large files from being loaded entirely into memory.");
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
