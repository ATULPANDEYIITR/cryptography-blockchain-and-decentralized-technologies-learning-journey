"use strict";

/*
 * CTR Mode: event-driven counter stream processing.
 *
 * This implementation uses Node.js crypto to perform AES-CTR operations.
 * It complements the Python implementation by modeling asynchronous
 * message handling, stream lifecycle, chunk boundaries, and application
 * metadata.
 *
 * Run with: node ctr_mode.js
 *
 * Security: AES-CTR does not authenticate ciphertext. The application
 * must guarantee nonce uniqueness for each key and should normally use
 * AES-GCM when authenticated encryption is required.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const assert = require("node:assert/strict");

const ALLOWED_KEY_LENGTHS = new Set([16, 24, 32]);
const BLOCK_BYTES = 16;

function validateKey(key) {
  if (!Buffer.isBuffer(key) || !ALLOWED_KEY_LENGTHS.has(key.length)) {
    throw new TypeError("AES key must be a Buffer of 16, 24, or 32 bytes.");
  }
}

function validateCounterBlock(counterBlock) {
  if (!Buffer.isBuffer(counterBlock) || counterBlock.length !== BLOCK_BYTES) {
    throw new TypeError("CTR initial counter must be exactly 16 bytes.");
  }
}

function incrementCounter(counterBlock, blocks) {
  if (!Number.isSafeInteger(blocks) || blocks < 0) {
    throw new RangeError("Block increment must be a nonnegative safe integer.");
  }

  const result = Buffer.from(counterBlock);
  let carry = BigInt(blocks);

  for (let index = result.length - 1; index >= 0 && carry > 0n; index--) {
    const total = BigInt(result[index]) + (carry & 0xffn);
    result[index] = Number(total & 0xffn);
    carry = (carry >> 8n) + (total >> 8n);
  }

  if (carry > 0n) {
    throw new RangeError("Counter would overflow its 128-bit representation.");
  }

  return result;
}

function aesCtrTransform(key, initialCounter, input) {
  validateKey(key);
  validateCounterBlock(initialCounter);

  if (!Buffer.isBuffer(input)) {
    throw new TypeError("Input must be a Buffer.");
  }

  const cipher = crypto.createCipheriv(
    `aes-${key.length * 8}-ctr`,
    key,
    initialCounter
  );

  // Node's CTR cipher consumes the counter internally and requires no
  // PKCS padding. Finalizing returns any buffered output.
  return Buffer.concat([cipher.update(input), cipher.final()]);
}

function aesGcmEncrypt(key, nonce, plaintext, associatedData = Buffer.alloc(0)) {
  validateKey(key);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) {
    throw new TypeError("AES-GCM requires a 12-byte nonce in this example.");
  }

  const cipher = crypto.createCipheriv(
    `aes-${key.length * 8}-gcm`,
    key,
    nonce
  );
  cipher.setAAD(associatedData);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  return {
    ciphertext,
    tag: cipher.getAuthTag()
  };
}

function aesGcmDecrypt(key, nonce, ciphertext, tag, associatedData = Buffer.alloc(0)) {
  validateKey(key);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) {
    throw new TypeError("AES-GCM requires a 12-byte nonce in this example.");
  }
  if (!Buffer.isBuffer(tag) || tag.length !== 16) {
    throw new TypeError("Expected a 16-byte authentication tag.");
  }

  const decipher = crypto.createDecipheriv(
    `aes-${key.length * 8}-gcm`,
    key,
    nonce
  );
  decipher.setAAD(associatedData);
  decipher.setAuthTag(tag);

  // Plaintext must not be trusted unless final() succeeds and the tag
  // has been verified.
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}

class NonceLedger {
  constructor() {
    this.used = new Map();
  }

  reserve(key, nonce) {
    validateKey(key);
    if (!Buffer.isBuffer(nonce) || nonce.length === 0) {
      throw new TypeError("Nonce must be a nonempty Buffer.");
    }

    const fingerprint = crypto
      .createHash("sha256")
      .update(key)
      .digest("hex");

    const nonceText = nonce.toString("hex");
    if (!this.used.has(fingerprint)) {
      this.used.set(fingerprint, new Set());
    }

    const keyNonces = this.used.get(fingerprint);
    if (keyNonces.has(nonceText)) {
      throw new Error("Nonce reuse detected for this key.");
    }

    keyNonces.add(nonceText);
  }
}

class CTRJob extends EventEmitter {
  constructor({ id, key, counter, payload }) {
    super();

    if (typeof id !== "string" || id.trim() === "") {
      throw new TypeError("Job ID must be a nonempty string.");
    }
    if (!Buffer.isBuffer(payload)) {
      throw new TypeError("Payload must be a Buffer.");
    }

    validateKey(key);
    validateCounterBlock(counter);

    this.id = id;
    this.key = Buffer.from(key);
    this.counter = Buffer.from(counter);
    this.payload = Buffer.from(payload);
    this.state = "created";
    this.result = null;
  }

  async execute() {
    if (this.state !== "created") {
      throw new Error(`Cannot execute a job in state ${this.state}.`);
    }

    this.state = "running";
    this.emit("started", { id: this.id, byteLength: this.payload.length });

    try {
      // A Promise boundary models an asynchronous service operation.
      await Promise.resolve();
      this.result = aesCtrTransform(this.key, this.counter, this.payload);
      this.state = "completed";
      this.emit("completed", {
        id: this.id,
        byteLength: this.result.length
      });
      return this.result;
    } catch (error) {
      this.state = "failed";
      this.emit("failed", { id: this.id, message: error.message });
      throw error;
    }
  }
}

function splitBuffer(buffer, sizes) {
  const chunks = [];
  let offset = 0;

  for (const size of sizes) {
    if (!Number.isInteger(size) || size <= 0) {
      throw new RangeError("Chunk sizes must be positive integers.");
    }
    if (offset >= buffer.length) break;

    chunks.push(buffer.subarray(offset, Math.min(offset + size, buffer.length)));
    offset += size;
  }

  if (offset < buffer.length) {
    chunks.push(buffer.subarray(offset));
  }

  return chunks;
}

async function runDemonstration() {
  const key = crypto.randomBytes(32);
  const counter = Buffer.alloc(BLOCK_BYTES);
  counter.writeBigUInt64BE(77n, 8);

  const source = Buffer.from(
    "Inspection record: asset=HVAC-42; finding=filter obstruction",
    "utf8"
  );

  const encrypted = aesCtrTransform(key, counter, source);
  const recovered = aesCtrTransform(key, counter, encrypted);
  assert.deepEqual(recovered, source);

  console.log("CTR round trip:", recovered.toString("utf8"));
  console.log("Ciphertext hex:", encrypted.toString("hex"));

  // CTR is a continuous stream. Independent cipher instances reset their
  // counters, so independently encrypting each chunk would be incorrect.
  const chunks = splitBuffer(source, [3, 8, 1, 17]);
  const job = new CTRJob({
    id: "inspection-2026-104",
    key,
    counter,
    payload: source
  });

  job.on("started", event => {
    console.log(`Started ${event.id}: ${event.byteLength} bytes`);
  });
  job.on("completed", event => {
    console.log(`Completed ${event.id}: ${event.byteLength} bytes`);
  });
  job.on("failed", event => {
    console.error(`Failed ${event.id}: ${event.message}`);
  });

  const jobCiphertext = await job.execute();
  assert.deepEqual(jobCiphertext, encrypted);
  assert.equal(chunks.reduce((sum, chunk) => sum + chunk.length, 0), source.length);

  const nextCounter = incrementCounter(counter, 4);
  console.log("Next counter block:", nextCounter.toString("hex"));

  const ledger = new NonceLedger();
  const nonce = crypto.randomBytes(12);
  ledger.reserve(key, nonce);

  assert.throws(() => ledger.reserve(key, nonce), /Nonce reuse/);

  const aad = Buffer.from("record=104;format=v1", "utf8");
  const protectedRecord = aesGcmEncrypt(key, nonce, source, aad);
  const authenticatedPlaintext = aesGcmDecrypt(
    key,
    nonce,
    protectedRecord.ciphertext,
    protectedRecord.tag,
    aad
  );
  assert.deepEqual(authenticatedPlaintext, source);

  assert.throws(
    () => aesGcmDecrypt(
      key,
      nonce,
      protectedRecord.ciphertext,
      protectedRecord.tag,
      Buffer.from("record=105;format=v1")
    )
  );

  console.log("Authenticated record verification passed.");
  console.log("Tampered associated data was rejected.");
  console.log("Job state:", job.state);
}

runDemonstration().catch(error => {
  console.error("CTR demonstration failed:", error.message);
  process.exitCode = 1;
});
