"use strict";

/*
 * AES-GCM demonstration using the Web Crypto API available in modern
 * browsers and Node.js 18+.
 *
 * AES-GCM provides confidentiality and authentication in one construction.
 * The authentication tag is produced and verified by the cryptographic API.
 *
 * Run with:
 *   node aes_demo.js
 */

const crypto = globalThis.crypto ?? require("node:crypto").webcrypto;
const subtle = crypto.subtle;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
    return Buffer.from(bytes).toString("base64url");
}

function base64ToBytes(value) {
    return new Uint8Array(Buffer.from(value, "base64url"));
}

function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}

async function generateKey() {
    return subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    return new Uint8Array(await subtle.exportKey("raw", key));
}

async function importKey(rawKey) {
    if (![16, 24, 32].includes(rawKey.length)) {
        throw new Error("AES raw keys must contain 16, 24, or 32 bytes.");
    }

    return subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encrypt(plaintext, key, associatedData = "") {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    if (iv.length !== 12) {
        throw new Error("AES-GCM should use a unique 96-bit IV in this design.");
    }

    const ciphertextAndTag = new Uint8Array(
        await subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode(associatedData),
                tagLength: 128
            },
            key,
            encoder.encode(plaintext)
        )
    );

    return {
        algorithm: "AES-256-GCM",
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(ciphertextAndTag),
        associatedData
    };
}

async function decrypt(record, key) {
    if (record.algorithm !== "AES-256-GCM") {
        throw new Error("Unsupported encryption algorithm.");
    }

    const iv = base64ToBytes(record.iv);
    const ciphertextAndTag = base64ToBytes(record.ciphertext);

    if (iv.length !== 12) {
        throw new Error("Invalid AES-GCM IV length.");
    }

    try {
        const plaintext = await subtle.decrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode(record.associatedData ?? ""),
                tagLength: 128
            },
            key,
            ciphertextAndTag
        );

        return decoder.decode(plaintext);
    } catch {
        throw new Error(
            "AES-GCM authentication failed. The key, ciphertext, IV, or associated data is invalid."
        );
    }
}

async function demonstrateAdditionalAuthenticatedData(key) {
    const record = await encrypt(
        "Pull request metadata",
        key,
        "repository=security-platform;branch=main"
    );

    const plaintext = await decrypt(record, key);

    console.log("\nAuthenticated encryption");
    console.log("-----------------------");
    console.log("Ciphertext:", record.ciphertext);
    console.log("Recovered :", plaintext);
    console.log("AAD       :", record.associatedData);

    const alteredAAD = {
        ...record,
        associatedData: "repository=untrusted-repository;branch=main"
    };

    try {
        await decrypt(alteredAAD, key);
    } catch (error) {
        console.log("AAD tampering rejected:", error.message);
    }
}

async function demonstrateTampering(record, key) {
    const corrupted = base64ToBytes(record.ciphertext);
    corrupted[0] ^= 0x01;

    const tamperedRecord = {
        ...record,
        ciphertext: bytesToBase64(corrupted)
    };

    try {
        await decrypt(tamperedRecord, key);
        console.error("Unexpected result: tampered ciphertext was accepted.");
    } catch (error) {
        console.log("Ciphertext tampering rejected:", error.message);
    }
}

async function main() {
    console.log("AES-GCM encryption and decryption");
    console.log("=================================");

    const key = await generateKey();
    const rawKey = await exportKey(key);

    console.log("Generated key length:", rawKey.length * 8, "bits");

    const message = await encrypt(
        "A protected repository policy requires two independent approvals.",
        key,
        "policy=protected-main;version=7"
    );

    console.log("Encoded IV       :", message.iv);
    console.log("Encoded ciphertext:", message.ciphertext);

    const recovered = await decrypt(message, key);

    console.log("Recovered plaintext:", recovered);

    await demonstrateTampering(message, key);
    await demonstrateAdditionalAuthenticatedData(key);

    console.log("\nImported-key round trip");
    console.log("-----------------------");

    const importedKey = await importKey(rawKey);
    const importedRecord = await encrypt(
        "The same raw key can be imported into a separate cryptographic context.",
        importedKey
    );

    console.log(await decrypt(importedRecord, importedKey));
}

main().catch(error => {
    console.error("Encryption demonstration failed:", error);
    process.exitCode = 1;
});
