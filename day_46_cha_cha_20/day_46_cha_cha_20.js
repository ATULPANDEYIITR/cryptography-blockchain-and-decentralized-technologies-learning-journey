"use strict";

/*
 * ChaCha20 implementation and protocol-oriented demonstration.
 *
 * The implementation follows RFC 8439:
 *   - 256-bit key
 *   - 96-bit nonce
 *   - 32-bit block counter
 *   - 20 rounds
 *   - little-endian 32-bit words
 *
 * Node.js is used only for secure random bytes, hashing, and the filesystem
 * example. The ChaCha20 primitive itself is implemented here so its mechanics
 * remain visible.
 *
 * Raw ChaCha20 provides confidentiality but no authentication. Node.js also
 * exposes "chacha20-poly1305", which is preferable for application data
 * because Poly1305 authenticates the ciphertext and associated data.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const KEY_SIZE = 32;
const NONCE_SIZE = 12;
const BLOCK_SIZE = 64;
const MAX_COUNTER = 0xffffffff;
const MASK32 = 0xffffffff;

function rotl32(value, amount) {
    value >>>= 0;
    return ((value << amount) | (value >>> (32 - amount))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = (state[d] ^ state[a]) >>> 0;
    state[d] = rotl32(state[d], 16);

    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = (state[b] ^ state[c]) >>> 0;
    state[b] = rotl32(state[b], 12);

    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = (state[d] ^ state[a]) >>> 0;
    state[d] = rotl32(state[d], 8);

    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = (state[b] ^ state[c]) >>> 0;
    state[b] = rotl32(state[b], 7);
}

function readUInt32LE(buffer, offset) {
    return buffer.readUInt32LE(offset);
}

function writeUInt32LE(value, buffer, offset) {
    buffer.writeUInt32LE(value >>> 0, offset);
}

function validateInputs(key, nonce, counter) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_SIZE) {
        throw new TypeError("ChaCha20 requires a 32-byte key.");
    }

    if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_SIZE) {
        throw new TypeError("RFC 8439 ChaCha20 requires a 12-byte nonce.");
    }

    if (!Number.isInteger(counter) || counter < 0 || counter > MAX_COUNTER) {
        throw new RangeError("Counter must be an unsigned 32-bit integer.");
    }
}

function initialState(key, counter, nonce) {
    validateInputs(key, nonce, counter);

    const constants = Buffer.from("expand 32-byte k", "ascii");

    return Uint32Array.from([
        readUInt32LE(constants, 0),
        readUInt32LE(constants, 4),
        readUInt32LE(constants, 8),
        readUInt32LE(constants, 12),
        readUInt32LE(key, 0),
        readUInt32LE(key, 4),
        readUInt32LE(key, 8),
        readUInt32LE(key, 12),
        readUInt32LE(key, 16),
        readUInt32LE(key, 20),
        readUInt32LE(key, 24),
        readUInt32LE(key, 28),
        counter >>> 0,
        readUInt32LE(nonce, 0),
        readUInt32LE(nonce, 4),
        readUInt32LE(nonce, 8),
    ]);
}

function chacha20Block(key, counter, nonce) {
    const original = initialState(key, counter, nonce);
    const state = Uint32Array.from(original);

    for (let round = 0; round < 10; round++) {
        quarterRound(state, 0, 4, 8, 12);
        quarterRound(state, 1, 5, 9, 13);
        quarterRound(state, 2, 6, 10, 14);
        quarterRound(state, 3, 7, 11, 15);

        quarterRound(state, 0, 5, 10, 15);
        quarterRound(state, 1, 6, 11, 12);
        quarterRound(state, 2, 7, 8, 13);
        quarterRound(state, 3, 4, 9, 14);
    }

    const output = Buffer.alloc(BLOCK_SIZE);

    for (let index = 0; index < 16; index++) {
        writeUInt32LE(
            (state[index] + original[index]) >>> 0,
            output,
            index * 4,
        );
    }

    return output;
}

function xorBuffers(left, right) {
    if (left.length !== right.length) {
        throw new RangeError("XOR buffers must have equal lengths.");
    }

    const output = Buffer.alloc(left.length);

    for (let index = 0; index < left.length; index++) {
        output[index] = left[index] ^ right[index];
    }

    return output;
}

function chacha20(key, nonce, input, initialCounter = 1) {
    validateInputs(key, nonce, initialCounter);

    if (!Buffer.isBuffer(input)) {
        throw new TypeError("Input must be a Buffer.");
    }

    if (input.length === 0) {
        return Buffer.alloc(0);
    }

    const blockCount = Math.ceil(input.length / BLOCK_SIZE);

    if (initialCounter + blockCount - 1 > MAX_COUNTER) {
        throw new RangeError("Message exceeds the 32-bit block counter space.");
    }

    const output = Buffer.alloc(input.length);

    for (let block = 0; block < blockCount; block++) {
        const offset = block * BLOCK_SIZE;
        const length = Math.min(BLOCK_SIZE, input.length - offset);

        const keystream = chacha20Block(
            key,
            initialCounter + block,
            nonce,
        );

        for (let index = 0; index < length; index++) {
            output[offset + index] = input[offset + index] ^ keystream[index];
        }
    }

    return output;
}

function assertEqual(actual, expected, label) {
    if (!actual.equals(expected)) {
        throw new Error(`${label}: verification failed`);
    }
    console.log(`${label}: PASS`);
}

function runQuarterRoundTest() {
    const state = new Uint32Array([
        0x11111111,
        0x01020304,
        0x9b8d6f43,
        0x01234567,
    ]);

    quarterRound(state, 0, 1, 2, 3);

    const expected = [
        0xea2a92f4,
        0xcb1cf8ce,
        0x4581472e,
        0x5881c4bb,
    ];

    assertEqual(
        Buffer.from(new Uint32Array(state).buffer),
        Buffer.from(new Uint32Array(expected).buffer),
        "Quarter round",
    );
}

function runRfcVector() {
    const key = Buffer.from(
        "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f",
        "hex",
    );

    const nonce = Buffer.from("000000090000004a00000000", "hex");

    const plaintext = Buffer.from(
        "Ladies and Gentlemen of the class of '99: " +
        "If I could offer you only one tip for the future, sunscreen would be it.",
        "ascii",
    );

    const expected = Buffer.from(
        "6e2e359a2568f98041ba0728dd0d6981" +
        "e97e7aec1d4360c20a27afccfd9fae0b" +
        "f91b65c5524733ab8f593dabcd62b357" +
        "1639d624e65152ab8f530c359f0861d8" +
        "07ca0dbf500d6a6156a38e088a22b65e" +
        "52bc514d16ccf806818ce91ab7793736" +
        "5af90bbf74a35be6b40b8eedf2785a30" +
        "7b5d6e5e6a0b",
        "hex",
    );

    const ciphertext = chacha20(key, nonce, plaintext, 1);

    assertEqual(ciphertext, expected, "RFC 8439 ChaCha20 vector");

    const recovered = chacha20(key, nonce, ciphertext, 1);
    assertEqual(recovered, plaintext, "Encryption/decryption symmetry");
}

function createSecureMessage(key, plaintext) {
    if (!Buffer.isBuffer(plaintext)) {
        throw new TypeError("Plaintext must be a Buffer.");
    }

    // The nonce is public metadata, but it must be unique for the key.
    const nonce = crypto.randomBytes(NONCE_SIZE);
    const counter = 1;
    const ciphertext = chacha20(key, nonce, plaintext, counter);

    return {
        version: 1,
        algorithm: "ChaCha20",
        nonce: nonce.toString("base64url"),
        counter,
        ciphertext: ciphertext.toString("base64url"),
    };
}

function openSecureMessage(key, message) {
    if (!message || message.algorithm !== "ChaCha20") {
        throw new Error("Unsupported or malformed message.");
    }

    if (!Number.isInteger(message.counter)) {
        throw new Error("Invalid message counter.");
    }

    const nonce = Buffer.from(message.nonce, "base64url");
    const ciphertext = Buffer.from(message.ciphertext, "base64url");

    return chacha20(key, nonce, ciphertext, message.counter);
}

function demonstrateAuthenticatedAlternative() {
    /*
     * Node's chacha20-poly1305 mode is an authenticated construction.
     * The authentication tag detects ciphertext or associated-data changes.
     *
     * This is not the raw ChaCha20 primitive implemented above. The distinction
     * matters: confidentiality and integrity are separate security properties.
     */
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const associatedData = Buffer.from("repository=secure-artifacts", "utf8");
    const plaintext = Buffer.from("signed release metadata", "utf8");

    const cipher = crypto.createCipheriv(
        "chacha20-poly1305",
        key,
        nonce,
        { authTagLength: 16 },
    );

    cipher.setAAD(associatedData);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv(
        "chacha20-poly1305",
        key,
        nonce,
        { authTagLength: 16 },
    );

    decipher.setAAD(associatedData);
    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);

    assertEqual(
        recovered,
        plaintext,
        "ChaCha20-Poly1305 authenticated round trip",
    );
}

async function demonstrateFileWorkflow() {
    const key = crypto.randomBytes(KEY_SIZE);
    const plaintext = Buffer.from(
        "ChaCha20 file processing example\n" +
        "The nonce is stored with ciphertext because it is not secret.\n",
        "utf8",
    );

    const nonce = crypto.randomBytes(NONCE_SIZE);
    const ciphertext = chacha20(key, nonce, plaintext, 1);

    const encryptedFile = Buffer.concat([
        nonce,
        Buffer.from([1, 0, 0, 0]),
        ciphertext,
    ]);

    const recoveredNonce = encryptedFile.subarray(0, 12);
    const recoveredCounter = encryptedFile.readUInt32LE(12);
    const recoveredCiphertext = encryptedFile.subarray(16);

    const recovered = chacha20(
        key,
        recoveredNonce,
        recoveredCiphertext,
        recoveredCounter,
    );

    assertEqual(recovered, plaintext, "File metadata round trip");

    // Temporary filesystem behavior is included only to demonstrate that
    // nonce metadata and ciphertext can be persisted separately from the key.
    const fileName = "chacha20-demo.bin";
    await fs.writeFile(fileName, encryptedFile);

    const stored = await fs.readFile(fileName);
    await fs.unlink(fileName);

    if (!stored.equals(encryptedFile)) {
        throw new Error("Filesystem persistence test failed.");
    }

    console.log("Filesystem persistence: PASS");
}

function demonstrateNonceReuse() {
    const key = crypto.randomBytes(KEY_SIZE);
    const nonce = crypto.randomBytes(NONCE_SIZE);

    const plaintextA = Buffer.from("salary=1000;team=alpha", "utf8");
    const plaintextB = Buffer.from("salary=9000;team=omega", "utf8");

    const ciphertextA = chacha20(key, nonce, plaintextA);
    const ciphertextB = chacha20(key, nonce, plaintextB);

    const length = Math.min(ciphertextA.length, ciphertextB.length);
    const ciphertextXor = xorBuffers(
        ciphertextA.subarray(0, length),
        ciphertextB.subarray(0, length),
    );
    const plaintextXor = xorBuffers(
        plaintextA.subarray(0, length),
        plaintextB.subarray(0, length),
    );

    assertEqual(
        ciphertextXor,
        plaintextXor,
        "Nonce reuse exposes XOR relationship",
    );
}

async function main() {
    console.log("ChaCha20 JavaScript implementation");
    console.log("==================================");

    runQuarterRoundTest();
    runRfcVector();

    const key = crypto.randomBytes(KEY_SIZE);
    const message = createSecureMessage(
        key,
        Buffer.from("Confidential repository artifact", "utf8"),
    );

    const opened = openSecureMessage(key, message);
    assertEqual(
        opened,
        Buffer.from("Confidential repository artifact", "utf8"),
        "Structured message API",
    );

    demonstrateNonceReuse();
    demonstrateAuthenticatedAlternative();
    await demonstrateFileWorkflow();

    console.log("\nOperational constraints");
    console.log("- Never reuse a nonce with the same ChaCha20 key.");
    console.log("- Raw ChaCha20 does not detect ciphertext modification.");
    console.log("- Prefer ChaCha20-Poly1305 for application protocols.");
    console.log("- Protect keys separately from ciphertext and nonce metadata.");
}

main().catch((error) => {
    console.error("Failure:", error.message);
    process.exitCode = 1;
});
