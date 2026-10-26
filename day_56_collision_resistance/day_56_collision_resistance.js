"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const SUPPORTED_ALGORITHMS = Object.freeze({
  SHA256: "sha256",
  SHA3_256: "sha3-256",
  BLAKE2B: "blake2b512",
});

class HashingError extends Error {}

function createHash(algorithm, data) {
  if (!Object.values(SUPPORTED_ALGORITHMS).includes(algorithm)) {
    throw new HashingError(`Unsupported hash algorithm: ${algorithm}`);
  }

  const hash = crypto.createHash(algorithm);
  hash.update(data);
  return hash.digest("hex");
}

function hashText(text, algorithm = SUPPORTED_ALGORITHMS.SHA256) {
  if (typeof text !== "string") {
    throw new HashingError("text must be a string");
  }

  return {
    algorithm,
    inputLength: Buffer.byteLength(text, "utf8"),
    digest: createHash(algorithm, Buffer.from(text, "utf8")),
  };
}

async function hashFile(filePath, algorithm = SUPPORTED_ALGORITHMS.SHA256) {
  const contents = await fs.readFile(filePath);

  return {
    algorithm,
    inputLength: contents.length,
    digest: createHash(algorithm, contents),
  };
}

function constantTimeHexEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const a = Buffer.from(left.toLowerCase(), "utf8");
  const b = Buffer.from(right.toLowerCase(), "utf8");

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

function verifyDigest(data, expectedDigest, algorithm) {
  const actualDigest = createHash(algorithm, data);
  return constantTimeHexEqual(actualDigest, expectedDigest);
}

function truncatedSha256(data, bits) {
  if (!Number.isInteger(bits) || bits < 1 || bits > 24) {
    throw new RangeError("bits must be an integer from 1 through 24");
  }

  const digest = crypto.createHash("sha256").update(data).digest();
  let value = 0;

  for (let i = 0; i < 8; i++) {
    value = value * 256 + digest[i];
  }

  return Math.floor(value / 2 ** (64 - bits));
}

function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError("length must be positive");
  }

  return crypto.randomBytes(length);
}

function findCollision(bits, maxAttempts = 100000) {
  const seen = new Map();

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const candidate = randomBytes(16);
    const digest = truncatedSha256(candidate, bits);

    if (seen.has(digest)) {
      const previous = seen.get(digest);

      if (!previous.equals(candidate)) {
        return {
          attempts: attempt + 1,
          first: previous,
          second: candidate,
          digest,
        };
      }
    }

    seen.set(digest, candidate);
  }

  throw new Error(`No collision found after ${maxAttempts} attempts`);
}

class ContentRegistry {
  constructor(algorithm = SUPPORTED_ALGORITHMS.SHA256) {
    this.algorithm = algorithm;
    this.documents = new Map();
  }

  add(id, content) {
    if (typeof id !== "string" || id.trim() === "") {
      throw new TypeError("id must be a non-empty string");
    }

    if (!Buffer.isBuffer(content)) {
      throw new TypeError("content must be a Buffer");
    }

    const digest = createHash(this.algorithm, content);
    const existing = this.documents.get(digest);

    if (existing && !existing.content.equals(content)) {
      throw new Error("Detected identical digest for different content");
    }

    const record = Object.freeze({
      id,
      digest,
      content: Buffer.from(content),
    });

    this.documents.set(digest, record);
    return record;
  }

  verify(id, content) {
    const digest = createHash(this.algorithm, content);
    const record = this.documents.get(digest);

    return Boolean(record && record.id === id && record.content.equals(content));
  }
}

async function main() {
  console.log("=== Collision Resistance ===");

  const message = "repository commit content";
  const result = hashText(message);

  console.log(result);
  console.log(
    "Valid digest:",
    verifyDigest(Buffer.from(message), result.digest, result.algorithm)
  );
  console.log(
    "Modified digest:",
    verifyDigest(
      Buffer.from("repository commit contents"),
      result.digest,
      result.algorithm
    )
  );

  const registry = new ContentRegistry();
  registry.add("commit-001", Buffer.from("source tree state"));
  console.log(
    "Registry valid:",
    registry.verify("commit-001", Buffer.from("source tree state"))
  );
  console.log(
    "Registry modified:",
    registry.verify("commit-001", Buffer.from("modified source tree state"))
  );

  console.log("\n=== Birthday-Bound Demonstration ===");

  for (const bits of [8, 12, 16]) {
    const collision = findCollision(bits);
    console.log({
      bits,
      attempts: collision.attempts,
      first: collision.first.toString("hex"),
      second: collision.second.toString("hex"),
      digest: collision.digest,
    });
  }

  console.log("\nSecurity properties:");
  console.log("- Collision resistance concerns finding x != y where H(x) = H(y).");
  console.log("- Generic attacks against an n-bit ideal hash require about 2^(n/2) work.");
  console.log("- SHA-256 therefore provides approximately 128-bit generic collision security.");
  console.log("- Short digests are useful for experiments, not security-sensitive identifiers.");
}

main().catch((error) => {
  console.error(`Failure: ${error.message}`);
  process.exitCode = 1;
});
