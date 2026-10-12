"use strict";

/*
 * ECB and CBC using Node.js's built-in crypto module.
 *
 * This implementation uses real AES-256 so that the JavaScript file can
 * demonstrate actual block-cipher behavior rather than a toy cipher.
 *
 * Security note:
 * - ECB is deterministic and leaks repeated-block structure.
 * - CBC requires a fresh, unpredictable IV for encryption.
 * - Neither ECB nor CBC provides authentication.
 * - CBC ciphertext must be authenticated before being trusted.
 * - For new application protocols, authenticated encryption such as AES-GCM
 *   is normally preferable.
 */

const crypto = require("node:crypto");

const ALGORITHM = "aes-256";
const BLOCK_SIZE = 16;

function requireKey(key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new TypeError("AES-256 requires a 32-byte key");
    }
}

function requireIv(iv) {
    if (!Buffer.isBuffer(iv) || iv.length !== BLOCK_SIZE) {
        throw new TypeError("AES-CBC requires a 16-byte IV");
    }
}

function encryptEcb(plaintext, key) {
    requireKey(key);

    // Node's ECB cipher has no IV. PKCS#7 padding is supplied by OpenSSL.
    const cipher = crypto.createCipheriv(`${ALGORITHM}-ecb`, key, null);
    cipher.setAutoPadding(true);

    return Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);
}

function decryptEcb(ciphertext, key) {
    requireKey(key);

    if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) {
        throw new Error("ECB ciphertext must contain complete AES blocks");
    }

    const decipher = crypto.createDecipheriv(`${ALGORITHM}-ecb`, key, null);
    decipher.setAutoPadding(true);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
}

function encryptCbc(plaintext, key, iv) {
    requireKey(key);
    requireIv(iv);

    const cipher = crypto.createCipheriv(`${ALGORITHM}-cbc`, key, iv);
    cipher.setAutoPadding(true);

    return Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);
}

function decryptCbc(ciphertext, key, iv) {
    requireKey(key);
    requireIv(iv);

    if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) {
        throw new Error("CBC ciphertext must contain complete AES blocks");
    }

    const decipher = crypto.createDecipheriv(`${ALGORITHM}-cbc`, key, iv);
    decipher.setAutoPadding(true);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
}

function blocks(buffer) {
    if (buffer.length % BLOCK_SIZE !== 0) {
        throw new Error("Buffer is not block aligned");
    }

    const result = [];

    for (let offset = 0; offset < buffer.length; offset += BLOCK_SIZE) {
        result.push(buffer.subarray(offset, offset + BLOCK_SIZE));
    }

    return result;
}

function blockHex(buffer) {
    return blocks(buffer).map((block) => block.toString("hex"));
}

function countDistinctBlocks(buffer) {
    return new Set(blockHex(buffer)).size;
}

function demonstrateBasicAES(key) {
    const message = Buffer.from(
        "Pull requests should not be merged until repository policy permits it."
    );

    const iv = crypto.randomBytes(BLOCK_SIZE);

    const ecb = encryptEcb(message, key);
    const cbc = encryptCbc(message, key, iv);

    const ecbRecovered = decryptEcb(ecb, key);
    const cbcRecovered = decryptCbc(cbc, key, iv);

    console.log("=== AES ECB and CBC round trip ===");
    console.log("Plaintext:", message.toString());
    console.log("ECB:", ecb.toString("hex"));
    console.log("CBC IV:", iv.toString("hex"));
    console.log("CBC:", cbc.toString("hex"));
    console.log("ECB recovered:", ecbRecovered.toString());
    console.log("CBC recovered:", cbcRecovered.toString());
    console.log();
}

function demonstrateECBLeakage(key) {
    /*
     * The repeated plaintext blocks are intentionally exact AES blocks.
     * ECB encrypts each block independently, so identical blocks have
     * identical ciphertext.
     */
    const repeated = Buffer.from("0123456789ABCDEF".repeat(8));
    const ciphertext = encryptEcb(repeated, key);

    console.log("=== ECB repeated-block behavior ===");
    console.log("Plaintext block count:", blocks(repeated).length);
    console.log("Ciphertext blocks:", blockHex(ciphertext).join(" | "));
    console.log("Distinct ciphertext blocks:", countDistinctBlocks(ciphertext));
    console.log();
}

function demonstrateCBCChaining(key) {
    const repeated = Buffer.from("0123456789ABCDEF".repeat(8));
    const iv = crypto.randomBytes(BLOCK_SIZE);
    const ciphertext = encryptCbc(repeated, key, iv);

    console.log("=== CBC chaining behavior ===");
    console.log("IV:", iv.toString("hex"));
    console.log("Ciphertext blocks:", blockHex(ciphertext).join(" | "));
    console.log("Distinct ciphertext blocks:", countDistinctBlocks(ciphertext));
    console.log();
}

function demonstrateIVChange(key) {
    const message = Buffer.from(
        "Same plaintext, different IV, different CBC ciphertext."
    );

    const iv1 = crypto.randomBytes(BLOCK_SIZE);
    const iv2 = crypto.randomBytes(BLOCK_SIZE);

    const ciphertext1 = encryptCbc(message, key, iv1);
    const ciphertext2 = encryptCbc(message, key, iv2);

    console.log("=== CBC IV change ===");
    console.log("IV 1:", iv1.toString("hex"));
    console.log("IV 2:", iv2.toString("hex"));
    console.log("Ciphertexts equal:", ciphertext1.equals(ciphertext2));
    console.log();
}

function demonstrateErrorPropagation(key) {
    /*
     * CBC has a characteristic corruption pattern:
     * changing a bit in C_i corrupts P_i substantially, but the same bit
     * position is flipped in P_(i+1). Later blocks can recover because
     * chaining resumes from the unmodified subsequent ciphertext block.
     */
    const message = Buffer.from(
        "BLOCK-ONE-123456BLOCK-TWO-123456BLOCK-THREE-123"
    );

    const iv = crypto.randomBytes(BLOCK_SIZE);
    const ciphertext = encryptCbc(message, key, iv);
    const modified = Buffer.from(ciphertext);

    modified[BLOCK_SIZE] ^= 0x01;

    console.log("=== CBC tampering and error propagation ===");

    try {
        const recovered = decryptCbc(modified, key, iv);
        console.log("Modified plaintext:", recovered.toString());
    } catch (error) {
        console.log("Decryption rejected:", error.message);
    }

    console.log(
        "CBC decryption alone does not establish authenticity."
    );
    console.log();
}

function demonstrateAuthenticatedAlternative(key) {
    /*
     * This section is deliberately AES-GCM rather than CBC. It shows why a
     * modern protocol should normally pair confidentiality with integrity.
     */
    const plaintext = Buffer.from(
        "A protected branch requires successful policy validation."
    );

    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);

    const recovered = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    console.log("=== Authenticated-encryption comparison ===");
    console.log("AES-GCM recovered:", recovered.toString());
    console.log(
        "GCM supplies authentication through its authentication tag; "
        + "plain ECB/CBC do not."
    );
    console.log();
}

function demonstrateValidation(key) {
    console.log("=== Input validation ===");

    try {
        encryptCbc(Buffer.from("test"), key, Buffer.alloc(8));
    } catch (error) {
        console.log("Invalid IV rejected:", error.message);
    }

    try {
        decryptEcb(Buffer.alloc(15), key);
    } catch (error) {
        console.log("Invalid ECB ciphertext rejected:", error.message);
    }

    console.log();
}

function main() {
    const key = crypto
        .createHash("sha256")
        .update("educational-key-for-ecb-cbc")
        .digest();

    demonstrateBasicAES(key);
    demonstrateECBLeakage(key);
    demonstrateCBCChaining(key);
    demonstrateIVChange(key);
    demonstrateErrorPropagation(key);
    demonstrateAuthenticatedAlternative(key);
    demonstrateValidation(key);

    console.log("ECB/CBC demonstration completed.");
}

main();
