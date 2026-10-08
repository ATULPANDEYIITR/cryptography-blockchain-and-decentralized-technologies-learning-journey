"use strict";

/*
 * AES Structure and Working
 *
 * This Node.js program provides a complementary AES-128 implementation.
 * It focuses on the byte-oriented representation of the AES state, key
 * expansion, transformation pipeline, round tracing, and authenticated
 * application-level encryption with Node's crypto module.
 *
 * The pure implementation makes the AES structure visible.
 * Node's built-in crypto API is then used to demonstrate how production
 * software should normally consume AES through a vetted implementation.
 */

const crypto = require("crypto");

const SBOX = Uint8Array.from([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

const RCON = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

function assertBlock(block) {
  if (!Buffer.isBuffer(block) || block.length !== 16) {
    throw new Error("AES-128 requires a 16-byte block.");
  }
}

function assertKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 16) {
    throw new Error("This implementation requires a 16-byte AES-128 key.");
  }
}

function toState(block) {
  assertBlock(block);
  const state = Array.from({ length: 4 }, () => new Uint8Array(4));
  for (let column = 0; column < 4; column++) {
    for (let row = 0; row < 4; row++) {
      state[row][column] = block[column * 4 + row];
    }
  }
  return state;
}

function fromState(state) {
  const result = Buffer.alloc(16);
  for (let column = 0; column < 4; column++) {
    for (let row = 0; row < 4; row++) {
      result[column * 4 + row] = state[row][column];
    }
  }
  return result;
}

function cloneState(state) {
  return state.map(row => Uint8Array.from(row));
}

function xorStates(left, right) {
  const result = Array.from({ length: 4 }, () => new Uint8Array(4));
  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      result[row][column] = left[row][column] ^ right[row][column];
    }
  }
  return result;
}

function subBytes(state) {
  return state.map(row => Uint8Array.from(row, value => SBOX[value]));
}

function shiftRows(state) {
  return state.map((row, index) => {
    const result = new Uint8Array(4);
    for (let column = 0; column < 4; column++) {
      result[column] = row[(column + index) % 4];
    }
    return result;
  });
}

function xtime(value) {
  value <<= 1;
  if (value & 0x100) value ^= 0x11b;
  return value & 0xff;
}

function gmul(a, b) {
  let result = 0;
  while (b !== 0) {
    if (b & 1) result ^= a;
    a = xtime(a);
    b >>>= 1;
  }
  return result;
}

function mixColumns(state) {
  const result = cloneState(state);

  for (let column = 0; column < 4; column++) {
    const a0 = state[0][column];
    const a1 = state[1][column];
    const a2 = state[2][column];
    const a3 = state[3][column];

    result[0][column] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    result[1][column] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    result[2][column] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    result[3][column] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }

  return result;
}

function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}

function expandKey(key) {
  assertKey(key);

  const words = [];
  for (let i = 0; i < 4; i++) {
    words.push(Array.from(key.subarray(i * 4, i * 4 + 4)));
  }

  while (words.length < 44) {
    let temp = words[words.length - 1].slice();

    if (words.length % 4 === 0) {
      temp = rotWord(temp).map(value => SBOX[value]);
      temp[0] ^= RCON[words.length / 4];
    }

    const previous = words[words.length - 4];
    words.push(temp.map((value, index) => value ^ previous[index]));
  }

  return Array.from({ length: 11 }, (_, round) => {
    const roundKey = Buffer.alloc(16);
    for (let word = 0; word < 4; word++) {
      for (let byte = 0; byte < 4; byte++) {
        roundKey[word * 4 + byte] = words[round * 4 + word][byte];
      }
    }
    return roundKey;
  });
}

function aes128Trace(plaintext, key) {
  assertBlock(plaintext);
  assertKey(key);

  const roundKeys = expandKey(key);
  let state = toState(plaintext);
  const trace = [];

  const record = (round, operation) => {
    trace.push({
      round,
      operation,
      state: fromState(state).toString("hex")
    });
  };

  state = xorStates(state, toState(roundKeys[0]));
  record(0, "AddRoundKey");

  for (let round = 1; round <= 10; round++) {
    state = subBytes(state);
    record(round, "SubBytes");

    state = shiftRows(state);
    record(round, "ShiftRows");

    if (round !== 10) {
      state = mixColumns(state);
      record(round, "MixColumns");
    }

    state = xorStates(state, toState(roundKeys[round]));
    record(round, "AddRoundKey");
  }

  return {
    ciphertext: fromState(state),
    roundKeys,
    trace
  };
}

function encryptGcm(plaintext, key, additionalData = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(plaintext)) throw new TypeError("Plaintext must be a Buffer.");
  assertKey(key);

  // GCM uses a nonce, commonly 12 bytes. Never reuse a nonce with the same key.
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
  cipher.setAAD(additionalData);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { iv, ciphertext, tag };
}

function decryptGcm(record, key, additionalData = Buffer.alloc(0)) {
  assertKey(key);

  const decipher = crypto.createDecipheriv("aes-128-gcm", key, record.iv);
  decipher.setAAD(additionalData);
  decipher.setAuthTag(record.tag);

  return Buffer.concat([
    decipher.update(record.ciphertext),
    decipher.final()
  ]);
}

function printTrace(trace) {
  let currentRound = -1;

  for (const item of trace) {
    if (item.round !== currentRound) {
      currentRound = item.round;
      console.log(`\nRound ${currentRound}`);
    }
    console.log(`${item.operation.padEnd(14)} ${item.state}`);
  }
}

function demonstratePureStructure() {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const plaintext = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const expected = "69c4e0d86a7b0430d8cdb78070b4c55a";

  const result = aes128Trace(plaintext, key);

  console.log("AES-128 internal structure");
  console.log("==========================");
  console.log("Plaintext :", plaintext.toString("hex"));
  console.log("Key       :", key.toString("hex"));
  console.log("Ciphertext:", result.ciphertext.toString("hex"));

  if (result.ciphertext.toString("hex") !== expected) {
    throw new Error("FIPS-197 AES-128 known-answer test failed.");
  }

  console.log("Known-answer test: PASS");
  console.log("\nExpanded round keys:");

  result.roundKeys.forEach((roundKey, round) => {
    console.log(`Round ${String(round).padStart(2, " ")}: ${roundKey.toString("hex")}`);
  });

  printTrace(result.trace);
}

function demonstrateAuthenticatedApplication() {
  const key = crypto.randomBytes(16);
  const plaintext = Buffer.from(
    JSON.stringify({
      recordId: "OPS-2026-0017",
      classification: "internal",
      amount: 48250
    }),
    "utf8"
  );

  const aad = Buffer.from("repository=secure-operations;version=1", "utf8");
  const encrypted = encryptGcm(plaintext, key, aad);
  const recovered = decryptGcm(encrypted, key, aad);

  console.log("\nProduction-oriented AES usage");
  console.log("=============================");
  console.log("Cipher     : AES-128-GCM");
  console.log("Nonce      :", encrypted.iv.toString("hex"));
  console.log("Ciphertext :", encrypted.ciphertext.toString("hex"));
  console.log("Auth tag   :", encrypted.tag.toString("hex"));
  console.log("Recovered  :", recovered.toString("utf8"));

  // GCM authenticates the ciphertext and AAD. A changed tag must cause failure.
  const tampered = { ...encrypted, tag: Buffer.from(encrypted.tag) };
  tampered.tag[0] ^= 0x01;

  try {
    decryptGcm(tampered, key, aad);
    throw new Error("Tampered ciphertext was incorrectly accepted.");
  } catch (error) {
    console.log("Tamper detection: PASS");
  }
}

function demonstrateStateRepresentation() {
  const block = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const state = toState(block);

  console.log("\nAES state matrix");
  console.log("================");

  for (const row of state) {
    console.log(Array.from(row, value => value.toString(16).padStart(2, "0")).join(" "));
  }

  console.log(
    "\nThe matrix is filled column-first, so the displayed matrix is not the same "
    + "as simply splitting the hexadecimal string into four visual rows."
  );
}

function main() {
  demonstrateStateRepresentation();
  demonstratePureStructure();
  demonstrateAuthenticatedApplication();

  console.log("\nOperational boundary");
  console.log("====================");
  console.log(
    "The AES primitive provides confidentiality transformations. AES-GCM additionally "
    + "provides authenticated encryption. Applications should use vetted platform "
    + "cryptography instead of replacing it with educational implementations."
  );
}

main();
