"use strict";

/*
 * SHA-3 and Keccak using Node.js cryptographic primitives.
 * Run with: node sha3_keccak.js
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const { Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");

const ALGORITHMS = Object.freeze({
  SHA3_224: "sha3-224",
  SHA3_256: "sha3-256",
  SHA3_384: "sha3-384",
  SHA3_512: "sha3-512",
  SHAKE_128: "shake128",
  SHAKE_256: "shake256",
});

function asBuffer(message) {
  if (typeof message === "string") {
    return Buffer.from(message, "utf8");
  }
  if (Buffer.isBuffer(message) || message instanceof Uint8Array) {
    return Buffer.from(message);
  }
  throw new TypeError("Message must be a string, Buffer, or Uint8Array.");
}

function validateSize(message, maximum = 16 * 1024 * 1024) {
  if (message.length > maximum) {
    throw new RangeError(`Message exceeds ${maximum} bytes.`);
  }
}

function hashMessage(message, algorithm = ALGORITHMS.SHA3_256) {
  const data = asBuffer(message);
  validateSize(data);

  const allowed = Object.values(ALGORITHMS);
  if (!allowed.includes(algorithm)) {
    throw new RangeError("Unsupported digest algorithm.");
  }

  const digest = crypto.createHash(algorithm).update(data).digest();

  return Object.freeze({
    algorithm,
    messageBytes: data.length,
    digestBytes: digest.length,
    digestHex: digest.toString("hex"),
  });
}

function shakeMessage(message, outputBytes = 32, strength = 256) {
  const data = asBuffer(message);
  validateSize(data);

  if (!Number.isSafeInteger(outputBytes) || outputBytes < 1 || outputBytes > 4096) {
    throw new RangeError("Output length must be between 1 and 4096 bytes.");
  }

  if (strength !== 128 && strength !== 256) {
    throw new RangeError("SHAKE strength must be 128 or 256.");
  }

  const algorithm = strength === 128 ? "shake128" : "shake256";
  const digest = crypto.createHash(algorithm, {
    outputLength: outputBytes,
  }).update(data).digest();

  return digest.toString("hex");
}

function verifySha3(message, expectedHex) {
  const data = asBuffer(message);
  validateSize(data);

  if (typeof expectedHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(expectedHex)) {
    return false;
  }

  const expected = Buffer.from(expectedHex, "hex");
  const actual = crypto.createHash("sha3-256").update(data).digest();

  return crypto.timingSafeEqual(actual, expected);
}

async function hashFile(path, algorithm = "sha3-256") {
  if (!["sha3-224", "sha3-256", "sha3-384", "sha3-512"].includes(algorithm)) {
    throw new RangeError("File hashing requires a fixed-output SHA-3 algorithm.");
  }

  const hasher = crypto.createHash(algorithm);
  let totalBytes = 0;

  const counter = new Transform({
    transform(chunk, encoding, callback) {
      totalBytes += chunk.length;
      hasher.update(chunk);
      callback(null, chunk);
    },
  });

  // Hash incrementally. The transform discards its output through a sink.
  const sink = new Transform({
    transform(chunk, encoding, callback) {
      callback();
    },
  });

  await pipeline(fs.createReadStream(path), counter, sink);

  return {
    algorithm,
    messageBytes: totalBytes,
    digestHex: hasher.digest("hex"),
  };
}

function merkleRoot(leaves) {
  if (!Array.isArray(leaves)) {
    throw new TypeError("Leaves must be an array.");
  }

  let level = leaves.map((leaf) => {
    const data = asBuffer(leaf);
    return crypto.createHash("sha3-256")
      .update(Buffer.concat([Buffer.from([0x00]), data]))
      .digest();
  });

  if (level.length === 0) {
    return crypto.createHash("sha3-256")
      .update(Buffer.from([0x02]))
      .digest("hex");
  }

  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]);
    }

    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        crypto.createHash("sha3-256")
          .update(Buffer.concat([
            Buffer.from([0x01]),
            level[i],
            level[i + 1],
          ]))
          .digest()
      );
    }
    level = next;
  }

  return level[0].toString("hex");
}

class DigestJobQueue {
  constructor(concurrency = 2, maximumQueue = 100) {
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new RangeError("Concurrency must be a positive integer.");
    }
    if (!Number.isInteger(maximumQueue) || maximumQueue < 1) {
      throw new RangeError("Queue capacity must be positive.");
    }

    this.concurrency = concurrency;
    this.maximumQueue = maximumQueue;
    this.pending = [];
    this.active = 0;
    this.closed = false;
  }

  submit(message, algorithm = ALGORITHMS.SHA3_256) {
    if (this.closed) {
      return Promise.reject(new Error("Queue is closed."));
    }
    if (this.pending.length + this.active >= this.maximumQueue) {
      return Promise.reject(new Error("Queue capacity exceeded."));
    }

    const data = asBuffer(message);
    validateSize(data);

    return new Promise((resolve, reject) => {
      this.pending.push({ data, algorithm, resolve, reject });
      this.drain();
    });
  }

  drain() {
    while (!this.closed && this.active < this.concurrency && this.pending.length) {
      const job = this.pending.shift();
      this.active++;

      // Promise scheduling allows independent requests to be managed uniformly.
      Promise.resolve()
        .then(() => hashMessage(job.data, job.algorithm))
        .then(job.resolve, job.reject)
        .finally(() => {
          this.active--;
          this.drain();
        });
    }
  }

  close() {
    this.closed = true;
    const error = new Error("Queue closed before job execution.");
    for (const job of this.pending.splice(0)) {
      job.reject(error);
    }
  }
}

async function main() {
  const known = hashMessage("abc");
  if (known.digestHex !==
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") {
    throw new Error("SHA3-256 known-answer test failed.");
  }

  const queue = new DigestJobQueue(2, 10);
  const messages = [
    "release manifest",
    "source archive",
    "compiled package",
  ];

  try {
    const results = await Promise.all(
      messages.map((message) => queue.submit(message))
    );

    console.log(JSON.stringify({
      knownAnswerTest: "passed",
      results,
      shake256_64Bytes: shakeMessage("release manifest", 64, 256),
      verification: verifySha3(
        "release manifest",
        hashMessage("release manifest").digestHex
      ),
      merkleRoot: merkleRoot(messages),
    }, null, 2));
  } finally {
    queue.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`SHA-3 processing failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  ALGORITHMS,
  hashMessage,
  shakeMessage,
  verifySha3,
  hashFile,
  merkleRoot,
  DigestJobQueue,
};
