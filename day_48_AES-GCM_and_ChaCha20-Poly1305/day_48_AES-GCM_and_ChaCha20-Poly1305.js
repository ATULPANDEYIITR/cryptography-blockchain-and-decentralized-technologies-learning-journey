"use strict";

/*
 * AES-GCM and ChaCha20-Poly1305
 *
 * This Node.js implementation uses the platform's built-in crypto provider.
 * AES-GCM is exposed through createCipheriv/createDecipheriv.
 * ChaCha20-Poly1305 is exposed through the same API with the
 * "chacha20-poly1305" cipher name.
 *
 * The implementation concentrates on application-level AEAD behavior:
 * nonce generation, AAD, authentication tags, tamper detection, key
 * validation, key rotation metadata, and event-driven processing.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

const ALGORITHMS = Object.freeze({
  AES_GCM: {
    name: "AES-256-GCM",
    cipher: "aes-256-gcm",
    keyBytes: 32,
    nonceBytes: 12,
  },
  CHACHA20_POLY1305: {
    name: "ChaCha20-Poly1305",
    cipher: "chacha20-poly1305",
    keyBytes: 32,
    nonceBytes: 12,
  },
});

function requireBuffer(name, value) {
  if (!Buffer.isBuffer(value)) {
    throw new TypeError(`${name} must be a Buffer`);
  }
}

function validateKey(key, algorithm) {
  requireBuffer("key", key);

  if (key.length !== algorithm.keyBytes) {
    throw new RangeError(
      `${algorithm.name} requires a ${algorithm.keyBytes}-byte key`
    );
  }
}

function validateNonce(nonce, algorithm) {
  requireBuffer("nonce", nonce);

  if (nonce.length !== algorithm.nonceBytes) {
    throw new RangeError(
      `${algorithm.name} requires a ${algorithm.nonceBytes}-byte nonce`
    );
  }
}

function encryptAead(algorithm, key, plaintext, aad = Buffer.alloc(0), nonce) {
  validateKey(key, algorithm);
  requireBuffer("plaintext", plaintext);
  requireBuffer("aad", aad);

  const actualNonce =
    nonce === undefined
      ? crypto.randomBytes(algorithm.nonceBytes)
      : nonce;

  validateNonce(actualNonce, algorithm);

  const cipher = crypto.createCipheriv(
    algorithm.cipher,
    key,
    actualNonce,
    { authTagLength: 16 }
  );

  cipher.setAAD(aad, { plaintextLength: plaintext.length });

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  return Object.freeze({
    algorithm: algorithm.name,
    nonce: actualNonce,
    ciphertext,
    tag: cipher.getAuthTag(),
    aad,
  });
}

function decryptAead(algorithm, key, record) {
  validateKey(key, algorithm);

  if (!record || record.algorithm !== algorithm.name) {
    throw new Error("AEAD record algorithm does not match the key context");
  }

  validateNonce(record.nonce, algorithm);
  requireBuffer("ciphertext", record.ciphertext);
  requireBuffer("tag", record.tag);
  requireBuffer("aad", record.aad);

  if (record.tag.length !== 16) {
    throw new RangeError("The application requires a 16-byte authentication tag");
  }

  const decipher = crypto.createDecipheriv(
    algorithm.cipher,
    key,
    record.nonce,
    { authTagLength: 16 }
  );

  decipher.setAAD(record.aad, {
    plaintextLength: record.ciphertext.length,
  });

  decipher.setAuthTag(record.tag);

  try {
    return Buffer.concat([
      decipher.update(record.ciphertext),
      decipher.final(),
    ]);
  } catch {
    throw new Error(`${algorithm.name} authentication failed`);
  }
}

class KeyRing {
  constructor() {
    this.keys = new Map();
    this.activeVersion = null;
  }

  addKey(version, algorithm, key, active = false) {
    if (!Number.isInteger(version) || version <= 0) {
      throw new RangeError("Key version must be a positive integer");
    }

    validateKey(key, algorithm);

    this.keys.set(version, {
      version,
      algorithm,
      key: Buffer.from(key),
    });

    if (active) {
      this.activeVersion = version;
    }
  }

  getActive() {
    if (this.activeVersion === null) {
      throw new Error("No active encryption key is configured");
    }

    return this.keys.get(this.activeVersion);
  }

  get(version) {
    const entry = this.keys.get(version);

    if (!entry) {
      throw new Error(`Unknown key version: ${version}`);
    }

    return entry;
  }
}

class SecureEnvelopeService extends EventEmitter {
  constructor(keyRing) {
    super();
    this.keyRing = keyRing;
  }

  seal(plaintext, aadObject) {
    requireBuffer("plaintext", plaintext);

    const keyEntry = this.keyRing.getActive();

    /*
     * AAD is intentionally serialized separately from ciphertext.
     * The recipient does not need to hide metadata such as tenant ID or
     * schema version, but modification of that metadata must be detected.
     */
    const aad = Buffer.from(JSON.stringify(aadObject), "utf8");

    const record = encryptAead(
      keyEntry.algorithm,
      keyEntry.key,
      plaintext,
      aad
    );

    const envelope = Object.freeze({
      keyVersion: keyEntry.version,
      algorithm: record.algorithm,
      nonce: record.nonce.toString("base64"),
      ciphertext: record.ciphertext.toString("base64"),
      tag: record.tag.toString("base64"),
      aad: record.aad.toString("base64"),
    });

    this.emit("encrypted", envelope);
    return envelope;
  }

  open(envelope) {
    if (!envelope || !Number.isInteger(envelope.keyVersion)) {
      throw new Error("Envelope is missing a valid key version");
    }

    const keyEntry = this.keyRing.get(envelope.keyVersion);

    const record = {
      algorithm: envelope.algorithm,
      nonce: Buffer.from(envelope.nonce, "base64"),
      ciphertext: Buffer.from(envelope.ciphertext, "base64"),
      tag: Buffer.from(envelope.tag, "base64"),
      aad: Buffer.from(envelope.aad, "base64"),
    };

    const plaintext = decryptAead(
      keyEntry.algorithm,
      keyEntry.key,
      record
    );

    this.emit("decrypted", {
      keyVersion: envelope.keyVersion,
      algorithm: envelope.algorithm,
    });

    return plaintext;
  }
}

function demonstrateBasicAEAD() {
  const plaintext = Buffer.from(
    "The deployment manifest contains confidential configuration."
  );

  const aad = Buffer.from(
    "tenant=payments;object=deployment-manifest;schema=3"
  );

  for (const algorithm of Object.values(ALGORITHMS)) {
    const key = crypto.randomBytes(algorithm.keyBytes);
    const record = encryptAead(algorithm, key, plaintext, aad);

    const recovered = decryptAead(algorithm, key, record);

    console.log(`\n${algorithm.name}`);
    console.log("Nonce:", record.nonce.toString("hex"));
    console.log("Ciphertext:", record.ciphertext.toString("hex"));
    console.log("Tag:", record.tag.toString("hex"));
    console.log("Recovered:", recovered.toString("utf8"));
  }
}

function demonstrateTampering() {
  const algorithm = ALGORITHMS.AES_GCM;
  const key = crypto.randomBytes(algorithm.keyBytes);
  const record = encryptAead(
    algorithm,
    key,
    Buffer.from("approved configuration"),
    Buffer.from("environment=production")
  );

  const modifiedCiphertext = Buffer.from(record.ciphertext);
  modifiedCiphertext[0] ^= 0x01;

  try {
    decryptAead(algorithm, key, {
      ...record,
      ciphertext: modifiedCiphertext,
    });
  } catch (error) {
    console.log("\nCiphertext tampering rejected:", error.message);
  }

  try {
    decryptAead(algorithm, key, {
      ...record,
      aad: Buffer.from("environment=development"),
    });
  } catch (error) {
    console.log("AAD tampering rejected:", error.message);
  }

  try {
    decryptAead(algorithm, crypto.randomBytes(32), record);
  } catch (error) {
    console.log("Wrong-key decryption rejected:", error.message);
  }
}

function demonstrateKeyRotation() {
  const keyRing = new KeyRing();

  keyRing.addKey(
    7,
    ALGORITHMS.AES_GCM,
    crypto.randomBytes(32),
    false
  );

  keyRing.addKey(
    8,
    ALGORITHMS.CHACHA20_POLY1305,
    crypto.randomBytes(32),
    true
  );

  const service = new SecureEnvelopeService(keyRing);

  service.on("encrypted", (event) => {
    console.log(
      `\nEncrypted with key version ${event.keyVersion} using ${event.algorithm}`
    );
  });

  service.on("decrypted", (event) => {
    console.log(
      `Decrypted with key version ${event.keyVersion} using ${event.algorithm}`
    );
  });

  const envelope = service.seal(
    Buffer.from("rotation-safe application secret"),
    {
      tenant: "acme",
      recordType: "configuration",
      schemaVersion: 4,
    }
  );

  console.log("Envelope:", envelope);
  console.log("Plaintext:", service.open(envelope).toString("utf8"));

  /*
   * The old key remains available for decrypting old records while the
   * active key handles new records. This separates key rotation from
   * immediate re-encryption of every stored object.
   */
}

function demonstrateNonceRule() {
  const algorithm = ALGORITHMS.AES_GCM;
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from("same message");

  const first = encryptAead(algorithm, key, plaintext);
  const second = encryptAead(algorithm, key, plaintext);

  console.log("\nNonce uniqueness:");
  console.log(
    "Different random nonces:",
    !first.nonce.equals(second.nonce)
  );

  /*
   * AES-GCM and ChaCha20-Poly1305 both require nonce uniqueness for a
   * particular key. Random 96-bit nonces are convenient, but systems with
   * extremely large encryption volumes may use a coordinated counter or
   * another carefully designed nonce-allocation mechanism.
   */
}

function demonstrateFailureBoundary() {
  const algorithm = ALGORITHMS.CHACHA20_POLY1305;

  try {
    encryptAead(
      algorithm,
      crypto.randomBytes(16),
      Buffer.from("invalid key length")
    );
  } catch (error) {
    console.log("\nValidation failure:", error.message);
  }

  try {
    encryptAead(
      algorithm,
      crypto.randomBytes(32),
      Buffer.from("invalid nonce"),
      Buffer.alloc(0),
      crypto.randomBytes(8)
    );
  } catch (error) {
    console.log("Nonce validation failure:", error.message);
  }
}

function main() {
  console.log("AES-GCM and ChaCha20-Poly1305");
  console.log("================================");

  demonstrateBasicAEAD();
  demonstrateTampering();
  demonstrateKeyRotation();
  demonstrateNonceRule();
  demonstrateFailureBoundary();
}

main();
