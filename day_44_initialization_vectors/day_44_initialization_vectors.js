"use strict";

/*
 * Initialization vectors and nonces using Node.js built-in cryptography.
 *
 * Run with:
 *   node initialization_vectors.js
 *
 * The example uses AES-256-GCM, authenticated decryption, key-scoped
 * nonce tracking, and asynchronous event-driven processing.
 */

const crypto = require("node:crypto");

class IVPolicyError extends Error {}
class NonceReuseError extends Error {}

function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0 || length > 1024) {
    throw new IVPolicyError("Random byte length must be a positive integer.");
  }
  return crypto.randomBytes(length);
}

function createKey() {
  return crypto.randomBytes(32);
}

function validateGcmNonce(nonce) {
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) {
    throw new IVPolicyError("AES-GCM requires a 12-byte nonce in this model.");
  }
}

class NonceRegistry {
  constructor(keyIdentifier) {
    if (typeof keyIdentifier !== "string" || !keyIdentifier.trim()) {
      throw new IVPolicyError("A key identifier is required.");
    }
    this.keyIdentifier = keyIdentifier;
    this.seen = new Set();
  }

  register(nonce) {
    validateGcmNonce(nonce);
    const encoded = nonce.toString("hex");

    if (this.seen.has(encoded)) {
      throw new NonceReuseError(
        `Nonce reuse detected for key ${this.keyIdentifier}.`
      );
    }

    this.seen.add(encoded);
  }
}

function encryptGcm(key, nonce, plaintext, associatedData = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new IVPolicyError("AES-256-GCM requires a 32-byte key.");
  }
  validateGcmNonce(nonce);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });

  // Associated data is authenticated but is not encrypted.
  cipher.setAAD(associatedData);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  return {
    algorithm: "aes-256-gcm",
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    associatedData: associatedData.toString("base64"),
  };
}

function decryptGcm(key, record) {
  const nonce = Buffer.from(record.nonce, "base64");
  const ciphertext = Buffer.from(record.ciphertext, "base64");
  const tag = Buffer.from(record.tag, "base64");
  const associatedData = Buffer.from(record.associatedData, "base64");

  validateGcmNonce(nonce);

  if (tag.length !== 16) {
    throw new IVPolicyError("Expected a 16-byte authentication tag.");
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });

  decipher.setAAD(associatedData);
  decipher.setAuthTag(tag);

  // final() throws if the ciphertext, tag, nonce, key, or AAD is invalid.
  // Do not release plaintext until authentication succeeds.
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
}

async function processEncryptionQueue(items, key, registry) {
  const records = [];

  // Sequential allocation makes the policy explicit. A registry in a
  // multi-process system must use atomic, durable coordination.
  for (const item of items) {
    const nonce = randomBytes(12);
    registry.register(nonce);

    const record = encryptGcm(
      key,
      nonce,
      Buffer.from(item.message, "utf8"),
      Buffer.from(item.context, "utf8")
    );

    records.push({ id: item.id, record });
    await new Promise((resolve) => setImmediate(resolve));
  }

  return records;
}

async function main() {
  const key = createKey();
  const registry = new NonceRegistry("document-encryption-key-v7");

  console.log("--- Random initialization material ---");
  console.log("CBC IV sample:", randomBytes(16).toString("hex"));
  console.log("GCM nonce sample:", randomBytes(12).toString("hex"));

  console.log("\n--- Event-driven encryption workflow ---");
  const jobs = [
    {
      id: "deployment-104",
      message: "Rotate the application signing secret.",
      context: "tenant=operations;record=104",
    },
    {
      id: "deployment-105",
      message: "Restrict access to the production database.",
      context: "tenant=operations;record=105",
    },
  ];

  const encrypted = await processEncryptionQueue(jobs, key, registry);

  for (const item of encrypted) {
    const recovered = decryptGcm(key, item.record);
    console.log({
      id: item.id,
      nonce: item.record.nonce,
      ciphertextBytes: Buffer.from(item.record.ciphertext, "base64").length,
      recovered: recovered.toString("utf8"),
    });
  }

  console.log("\n--- Authentication failure ---");
  const tampered = { ...encrypted[0].record };
  const ciphertext = Buffer.from(tampered.ciphertext, "base64");

  if (ciphertext.length > 0) {
    ciphertext[0] ^= 1;
  }
  tampered.ciphertext = ciphertext.toString("base64");

  try {
    decryptGcm(key, tampered);
    throw new Error("Unexpected success: tampering was not detected.");
  } catch (error) {
    if (error.message.startsWith("Unexpected success")) throw error;
    console.log("Modified ciphertext rejected:", error.message);
  }

  console.log("\n--- Nonce reuse policy ---");
  const repeatedNonce = randomBytes(12);
  const testRegistry = new NonceRegistry("test-key");

  testRegistry.register(repeatedNonce);

  try {
    testRegistry.register(repeatedNonce);
  } catch (error) {
    if (!(error instanceof NonceReuseError)) throw error;
    console.log("Repeated nonce rejected:", error.message);
  }

  console.log("\n--- Security properties ---");
  console.log("AES-GCM authenticates ciphertext and associated data.");
  console.log("A nonce is not a password and normally need not be secret.");
  console.log("Nonce uniqueness is scoped to each encryption key.");
  console.log("The in-memory registry is a demonstration, not durable storage.");
}

main().catch((error) => {
  console.error("Cryptographic workflow failed:", error.message);
  process.exitCode = 1;
});
