/*
 * Authenticated Encryption with Web Crypto API.
 *
 * Runtime:
 *   Modern browser
 *   Node.js 20+ with globalThis.crypto.subtle
 *
 * The Web Crypto API supplies AES-GCM as a standardized authenticated
 * encryption primitive. No npm dependency is required.
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const NONCE_LENGTH = 12;
const TAG_LENGTH = 128;

function toBase64(bytes) {
    return Buffer.from(bytes).toString("base64");
}

function fromBase64(value) {
    return new Uint8Array(Buffer.from(value, "base64"));
}

function utf8(value) {
    return TEXT_ENCODER.encode(value);
}

function text(bytes) {
    return TEXT_DECODER.decode(bytes);
}

function concatenate(first, second) {
    const result = new Uint8Array(first.length + second.length);
    result.set(first, 0);
    result.set(second, first.length);
    return result;
}

function randomNonce() {
    const nonce = new Uint8Array(NONCE_LENGTH);
    crypto.getRandomValues(nonce);
    return nonce;
}

async function createAesKey() {
    return crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(raw);
}

async function importAesKey(rawKey) {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM"
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptMessage(key, plaintext, associatedData) {
    const nonce = randomNonce();

    /*
     * Web Crypto returns ciphertext followed by the GCM authentication tag.
     * The associatedData participates in authentication but is not encrypted.
     */
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: nonce,
            additionalData: utf8(associatedData),
            tagLength: TAG_LENGTH
        },
        key,
        utf8(plaintext)
    );

    const ciphertextAndTag = new Uint8Array(encrypted);

    return {
        algorithm: "AES-256-GCM",
        nonce: toBase64(nonce),
        ciphertextAndTag: toBase64(ciphertextAndTag),
        associatedData
    };
}

async function decryptMessage(key, envelope) {
    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: fromBase64(envelope.nonce),
                additionalData: utf8(envelope.associatedData),
                tagLength: TAG_LENGTH
            },
            key,
            fromBase64(envelope.ciphertextAndTag)
        );

        return text(new Uint8Array(plaintext));
    } catch {
        /*
         * Do not expose whether the nonce, ciphertext, tag, or AAD caused
         * authentication to fail. The caller receives one generic error.
         */
        throw new Error("Authenticated decryption failed");
    }
}

function mutateBase64(value) {
    const bytes = fromBase64(value);

    if (bytes.length === 0) {
        throw new Error("Cannot modify empty binary data");
    }

    bytes[0] ^= 0x01;
    return toBase64(bytes);
}

async function demonstrateAesGcm() {
    console.log("\n=== AES-GCM encryption ===");

    const key = await createAesKey();

    const envelope = await encryptMessage(
        key,
        "Protected repository governance data",
        "repository=platform-security;record=branch-policy"
    );

    console.log("Algorithm:", envelope.algorithm);
    console.log("Nonce:", envelope.nonce);
    console.log("AAD:", envelope.associatedData);

    const plaintext = await decryptMessage(key, envelope);
    console.log("Recovered:", plaintext);

    return { key, envelope };
}

async function demonstrateTamperDetection(key, originalEnvelope) {
    console.log("\n=== Ciphertext tamper detection ===");

    const tampered = {
        ...originalEnvelope,
        ciphertextAndTag: mutateBase64(originalEnvelope.ciphertextAndTag)
    };

    try {
        await decryptMessage(key, tampered);
    } catch (error) {
        console.log(error.message);
    }
}

async function demonstrateAadProtection(key, originalEnvelope) {
    console.log("\n=== AAD tamper detection ===");

    const tampered = {
        ...originalEnvelope,
        associatedData: "repository=platform-security;record=other-policy"
    };

    try {
        await decryptMessage(key, tampered);
    } catch (error) {
        console.log(error.message);
    }
}

async function demonstrateWrongKey(originalEnvelope) {
    console.log("\n=== Wrong-key rejection ===");

    const unrelatedKey = await createAesKey();

    try {
        await decryptMessage(unrelatedKey, originalEnvelope);
    } catch (error) {
        console.log(error.message);
    }
}

async function demonstrateNonceGeneration() {
    console.log("\n=== Nonce generation ===");

    const key = await createAesKey();
    const nonces = new Set();

    for (let index = 0; index < 1000; index += 1) {
        const envelope = await encryptMessage(
            key,
            "same logical payload",
            "record-type=demo"
        );

        nonces.add(envelope.nonce);
    }

    console.log("Unique nonces:", nonces.size);
}

async function demonstrateSerialization(key) {
    console.log("\n=== JSON transport envelope ===");

    const envelope = await encryptMessage(
        key,
        "Review approval metadata",
        "pull-request=482;field=approval-state"
    );

    const serialized = JSON.stringify(envelope, null, 2);
    const parsed = JSON.parse(serialized);

    console.log(serialized);
    console.log("Recovered:", await decryptMessage(key, parsed));
}

class RepositoryArtifactStore {
    constructor(key) {
        this.key = key;
        this.records = new Map();
    }

    async save(repository, artifactName, contents) {
        /*
         * The identity of the artifact is AAD. It remains readable by
         * infrastructure but cannot be changed without invalidating the tag.
         */
        const associatedData =
            `repository=${repository};artifact=${artifactName}`;

        const envelope = await encryptMessage(
            this.key,
            contents,
            associatedData
        );

        this.records.set(`${repository}/${artifactName}`, envelope);
    }

    async load(repository, artifactName) {
        const identifier = `${repository}/${artifactName}`;
        const envelope = this.records.get(identifier);

        if (!envelope) {
            throw new Error("Encrypted artifact does not exist");
        }

        return decryptMessage(this.key, envelope);
    }
}

async function demonstrateApplicationWorkflow(key) {
    console.log("\n=== Repository artifact workflow ===");

    const store = new RepositoryArtifactStore(key);

    await store.save(
        "platform-security",
        "branch-protection.json",
        JSON.stringify({
            requiredReviews: 2,
            requiredChecks: ["tests", "security-scan"],
            allowForcePush: false
        })
    );

    console.log(
        await store.load("platform-security", "branch-protection.json")
    );
}

async function main() {
    if (typeof Buffer === "undefined") {
        throw new Error(
            "This demonstration expects a Node.js runtime because it uses Buffer for Base64."
        );
    }

    console.log("Authenticated Encryption with Web Crypto AES-GCM");

    const { key, envelope } = await demonstrateAesGcm();

    await demonstrateTamperDetection(key, envelope);
    await demonstrateAadProtection(key, envelope);
    await demonstrateWrongKey(envelope);
    await demonstrateNonceGeneration();
    await demonstrateSerialization(key);
    await demonstrateApplicationWorkflow(key);

    /*
     * Exporting a raw key is included only to demonstrate interoperability.
     * Production applications should not casually export encryption keys.
     */
    const rawKey = await exportKey(key);
    const importedKey = await importAesKey(rawKey);

    const interoperabilityEnvelope = await encryptMessage(
        importedKey,
        "Imported-key round trip",
        "format=aead-v1"
    );

    console.log(
        "\nImported-key recovery:",
        await decryptMessage(importedKey, interoperabilityEnvelope)
    );
}

main().catch((error) => {
    console.error("Execution failed:", error.message);
    process.exitCode = 1;
});
