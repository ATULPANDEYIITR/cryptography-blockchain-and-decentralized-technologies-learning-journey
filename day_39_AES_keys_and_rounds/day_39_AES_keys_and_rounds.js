"use strict";

/*
 * AES keys and rounds: event-driven key-schedule and round-state explorer.
 *
 * Run with Node.js 18 or later:
 *   node aes_keys_rounds.js
 *
 * The built-in node:crypto implementation is used for actual AES
 * encryption. The finite-field and key-schedule components are educational.
 * Production encryption should use authenticated encryption such as GCM.
 */

const crypto = require("node:crypto");
const assert = require("node:assert/strict");

const AES_VARIANTS = new Map([
  [16, { name: "AES-128", keyBytes: 16, rounds: 10 }],
  [24, { name: "AES-192", keyBytes: 24, rounds: 12 }],
  [32, { name: "AES-256", keyBytes: 32, rounds: 14 }],
]);

function parametersForKey(key) {
  if (!Buffer.isBuffer(key)) {
    throw new TypeError("AES keys must be Node.js Buffer objects.");
  }

  const parameters = AES_VARIANTS.get(key.length);
  if (!parameters) {
    throw new RangeError("AES keys must contain 16, 24, or 32 bytes.");
  }

  return parameters;
}

function xtime(value) {
  const byte = value & 0xff;
  return ((byte << 1) ^ ((byte & 0x80) ? 0x11b : 0)) & 0xff;
}

function multiplyInField(left, right) {
  let a = left & 0xff;
  let b = right & 0xff;
  let result = 0;

  while (b !== 0) {
    if (b & 1) result ^= a;
    a = xtime(a);
    b >>>= 1;
  }

  return result;
}

function powerInField(value, exponent) {
  let result = 1;
  let base = value & 0xff;

  while (exponent > 0) {
    if (exponent & 1) result = multiplyInField(result, base);
    base = multiplyInField(base, base);
    exponent = Math.floor(exponent / 2);
  }

  return result;
}

function rotateByteLeft(value, count) {
  const byte = value & 0xff;
  return ((byte << count) | (byte >>> (8 - count))) & 0xff;
}

function createSBox() {
  return Array.from({ length: 256 }, (_, value) => {
    const inverse = value === 0 ? 0 : powerInField(value, 254);
    return (
      inverse ^
      rotateByteLeft(inverse, 1) ^
      rotateByteLeft(inverse, 2) ^
      rotateByteLeft(inverse, 3) ^
      rotateByteLeft(inverse, 4) ^
      0x63
    );
  });
}

const SBOX = createSBox();

function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}

function subWord(word) {
  return word.map((byte) => SBOX[byte]);
}

function xorWords(left, right) {
  return left.map((byte, index) => byte ^ right[index]);
}

function expandKey(key) {
  const parameters = parametersForKey(key);
  const nk = key.length / 4;
  const wordCount = 4 * (parameters.rounds + 1);
  const words = [];

  for (let offset = 0; offset < key.length; offset += 4) {
    words.push([...key.subarray(offset, offset + 4)]);
  }

  let rcon = 1;

  for (let index = nk; index < wordCount; index++) {
    let temporary = [...words[index - 1]];

    if (index % nk === 0) {
      temporary = subWord(rotWord(temporary));
      temporary[0] ^= rcon;
      rcon = xtime(rcon);
    } else if (nk > 6 && index % nk === 4) {
      temporary = subWord(temporary);
    }

    words.push(xorWords(words[index - nk], temporary));
  }

  const roundKeys = [];

  for (let index = 0; index < wordCount; index += 4) {
    roundKeys.push(
      Buffer.from(words.slice(index, index + 4).flat())
    );
  }

  return roundKeys;
}

class RoundSchedule {
  #key;
  #roundKeys;

  constructor(key) {
    parametersForKey(key);
    this.#key = Buffer.from(key);
    this.#roundKeys = expandKey(this.#key);
    Object.freeze(this);
  }

  get parameters() {
    return { ...parametersForKey(this.#key) };
  }

  getRoundKey(round) {
    if (!Number.isInteger(round) || round < 0 || round >= this.#roundKeys.length) {
      throw new RangeError("Requested round key does not exist.");
    }

    // Return a copy so callers cannot mutate the internal key schedule.
    return Buffer.from(this.#roundKeys[round]);
  }

  describe() {
    return this.#roundKeys.map((key, round) => ({
      round,
      keyHex: key.toString("hex"),
    }));
  }
}

class AESWorkflow extends require("node:events").EventEmitter {
  #key;
  #schedule;

  constructor(key) {
    super();
    this.#schedule = new RoundSchedule(key);
    this.#key = Buffer.from(key);
  }

  encryptBlock(block) {
    if (!Buffer.isBuffer(block) || block.length !== 16) {
      throw new RangeError("AES block encryption requires 16 bytes.");
    }

    const algorithm = `aes-${this.#key.length * 8}-ecb`;
    const cipher = crypto.createCipheriv(algorithm, this.#key, null);

    // Disable automatic padding because this method accepts exactly one block.
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(block), cipher.final()]);

    this.emit("blockEncrypted", {
      algorithm,
      inputBytes: block.length,
      outputBytes: encrypted.length,
      roundCount: this.#schedule.parameters.rounds,
    });

    return encrypted;
  }

  encryptMessageGcm(message, associatedData = Buffer.alloc(0)) {
    if (!Buffer.isBuffer(message) || !Buffer.isBuffer(associatedData)) {
      throw new TypeError("Message and associated data must be Buffers.");
    }

    // A fresh 96-bit nonce is standard for AES-GCM. Nonce reuse with the
    // same key can catastrophically compromise confidentiality and integrity.
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      `aes-${this.#key.length * 8}-gcm`,
      this.#key,
      nonce
    );

    cipher.setAAD(associatedData);
    const ciphertext = Buffer.concat([
      cipher.update(message),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    this.emit("messageEncrypted", {
      nonceBytes: nonce.length,
      tagBytes: tag.length,
      ciphertextBytes: ciphertext.length,
    });

    return { nonce, ciphertext, tag };
  }

  decryptMessageGcm(envelope, associatedData = Buffer.alloc(0)) {
    if (
      !envelope ||
      !Buffer.isBuffer(envelope.nonce) ||
      envelope.nonce.length !== 12 ||
      !Buffer.isBuffer(envelope.ciphertext) ||
      !Buffer.isBuffer(envelope.tag) ||
      envelope.tag.length !== 16 ||
      !Buffer.isBuffer(associatedData)
    ) {
      throw new TypeError("Malformed AES-GCM envelope.");
    }

    const decipher = crypto.createDecipheriv(
      `aes-${this.#key.length * 8}-gcm`,
      this.#key,
      envelope.nonce
    );

    decipher.setAAD(associatedData);
    decipher.setAuthTag(envelope.tag);

    // Authentication is verified when final() executes. Do not release
    // decrypted data to application logic until that verification succeeds.
    return Buffer.concat([
      decipher.update(envelope.ciphertext),
      decipher.final(),
    ]);
  }

  get schedule() {
    return this.#schedule.describe();
  }
}

function runTests() {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const plaintext = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const expected = "69c4e0d86a7b0430d8cdb78070b4c55a";

  const workflow = new AESWorkflow(key);
  const events = [];

  workflow.on("blockEncrypted", (event) => events.push(event));

  const ciphertext = workflow.encryptBlock(plaintext);
  assert.equal(ciphertext.toString("hex"), expected);
  assert.equal(events[0].roundCount, 10);

  for (const [length, expectedRounds] of [[16, 10], [24, 12], [32, 14]]) {
    const candidate = new RoundSchedule(crypto.randomBytes(length));
    assert.equal(candidate.parameters.rounds, expectedRounds);
    assert.equal(candidate.describe().length, expectedRounds + 1);
  }

  assert.throws(() => new RoundSchedule(Buffer.alloc(15)), RangeError);
  assert.throws(() => workflow.encryptBlock(Buffer.alloc(15)), RangeError);
  assert.equal(multiplyInField(0x57, 0x13), 0xfe);

  const message = Buffer.from("Protected release manifest");
  const aad = Buffer.from("release:2026-10");
  const envelope = workflow.encryptMessageGcm(message, aad);

  assert.deepEqual(workflow.decryptMessageGcm(envelope, aad), message);

  const damaged = {
    ...envelope,
    ciphertext: Buffer.from(envelope.ciphertext),
  };
  damaged.ciphertext[0] ^= 1;

  assert.throws(() => workflow.decryptMessageGcm(damaged, aad));

  assert.throws(
    () => workflow.decryptMessageGcm(envelope, Buffer.from("wrong-record")),
  );

  console.log("All AES tests passed.");
}

function main() {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const workflow = new AESWorkflow(key);
  const plaintext = Buffer.from("00112233445566778899aabbccddeeff", "hex");

  console.log("AES key schedule");
  console.log(`Variant: ${workflow.schedule.length - 1} rounds`);

  for (const entry of workflow.schedule) {
    console.log(`Round ${String(entry.round).padStart(2, "0")}: ${entry.keyHex}`);
  }

  console.log(`\nPlaintext : ${plaintext.toString("hex")}`);
  console.log(`Ciphertext: ${workflow.encryptBlock(plaintext).toString("hex")}`);

  workflow.on("messageEncrypted", (event) => {
    console.log("\nAuthenticated encryption event:", event);
  });

  const envelope = workflow.encryptMessageGcm(
    Buffer.from("Build artifact metadata"),
    Buffer.from("artifact-id:release-842")
  );

  console.log("AES-GCM nonce:", envelope.nonce.toString("hex"));
  console.log("AES-GCM tag:", envelope.tag.toString("hex"));

  runTests();
}

if (require.main === module) {
  main();
}

module.exports = {
  AESWorkflow,
  RoundSchedule,
  expandKey,
  multiplyInField,
  parametersForKey,
};
