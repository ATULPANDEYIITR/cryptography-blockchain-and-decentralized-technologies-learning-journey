"use strict";

/*
 * AES Introduction
 *
 * This Node.js program implements AES-128 directly so that the fundamental
 * AES transformations can be inspected without an external dependency.
 *
 * It also demonstrates:
 *   - AES blocks and keys
 *   - key expansion
 *   - SubBytes, ShiftRows, MixColumns, AddRoundKey
 *   - CBC mode with PKCS#7 padding
 *   - CTR mode
 *   - Node.js crypto for production-oriented authenticated encryption
 *     with AES-256-GCM
 *
 * The hand-written AES implementation is educational. Production software
 * should use Node's reviewed crypto implementation rather than this code.
 */

const crypto = require("node:crypto");

const BLOCK_SIZE = 16;

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

const INV_SBOX = Uint8Array.from([
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
]);

const RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function assertLength(buffer, expected, name) {
  if (buffer.length !== expected) {
    throw new Error(`${name} must contain ${expected} bytes`);
  }
}

function xtime(value) {
  value <<= 1;
  if (value & 0x100) value ^= 0x11b;
  return value & 0xff;
}

function gfMultiply(a, b) {
  let result = 0;
  while (b !== 0) {
    if (b & 1) result ^= a;
    a = xtime(a);
    b >>>= 1;
  }
  return result;
}

function expandKey128(key) {
  assertLength(key, 16, "AES-128 key");

  const words = [];
  for (let i = 0; i < 16; i += 4) {
    words.push(Array.from(key.subarray(i, i + 4)));
  }

  while (words.length < 44) {
    let temp = words[words.length - 1].slice();

    if (words.length % 4 === 0) {
      temp = [
        SBOX[temp[1]],
        SBOX[temp[2]],
        SBOX[temp[3]],
        SBOX[temp[0]]
      ];
      temp[0] ^= RCON[words.length / 4];
    }

    const previous = words[words.length - 4];
    words.push(previous.map((value, index) => value ^ temp[index]));
  }

  const roundKeys = [];
  for (let round = 0; round < 11; round++) {
    const keyBytes = [];
    for (let word = 0; word < 4; word++) {
      keyBytes.push(...words[round * 4 + word]);
    }
    roundKeys.push(Uint8Array.from(keyBytes));
  }
  return roundKeys;
}

function xorBlocks(a, b) {
  assertLength(a, 16, "first block");
  assertLength(b, 16, "second block");

  const output = new Uint8Array(16);
  for (let i = 0; i < 16; i++) output[i] = a[i] ^ b[i];
  return output;
}

function subBytes(state) {
  return Uint8Array.from(state, byte => SBOX[byte]);
}

function inverseSubBytes(state) {
  return Uint8Array.from(state, byte => INV_SBOX[byte]);
}

function shiftRows(state) {
  const output = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      output[4 * column + row] =
        state[4 * ((column + row) % 4) + row];
    }
  }
  return output;
}

function inverseShiftRows(state) {
  const output = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      output[4 * column + row] =
        state[4 * ((column - row + 4) % 4) + row];
    }
  }
  return output;
}

function mixColumns(state) {
  const output = new Uint8Array(state);

  for (let column = 0; column < 4; column++) {
    const i = column * 4;
    const a0 = state[i];
    const a1 = state[i + 1];
    const a2 = state[i + 2];
    const a3 = state[i + 3];

    output[i] =
      gfMultiply(a0, 2) ^ gfMultiply(a1, 3) ^ a2 ^ a3;
    output[i + 1] =
      a0 ^ gfMultiply(a1, 2) ^ gfMultiply(a2, 3) ^ a3;
    output[i + 2] =
      a0 ^ a1 ^ gfMultiply(a2, 2) ^ gfMultiply(a3, 3);
    output[i + 3] =
      gfMultiply(a0, 3) ^ a1 ^ a2 ^ gfMultiply(a3, 2);
  }

  return output;
}

function inverseMixColumns(state) {
  const output = new Uint8Array(state);

  for (let column = 0; column < 4; column++) {
    const i = column * 4;
    const a0 = state[i];
    const a1 = state[i + 1];
    const a2 = state[i + 2];
    const a3 = state[i + 3];

    output[i] =
      gfMultiply(a0, 14) ^ gfMultiply(a1, 11) ^
      gfMultiply(a2, 13) ^ gfMultiply(a3, 9);
    output[i + 1] =
      gfMultiply(a0, 9) ^ gfMultiply(a1, 14) ^
      gfMultiply(a2, 11) ^ gfMultiply(a3, 13);
    output[i + 2] =
      gfMultiply(a0, 13) ^ gfMultiply(a1, 9) ^
      gfMultiply(a2, 14) ^ gfMultiply(a3, 11);
    output[i + 3] =
      gfMultiply(a0, 11) ^ gfMultiply(a1, 13) ^
      gfMultiply(a2, 9) ^ gfMultiply(a3, 14);
  }

  return output;
}

function aesEncryptBlock(block, key) {
  assertLength(block, 16, "AES block");
  const roundKeys = expandKey128(key);

  let state = xorBlocks(block, roundKeys[0]);

  for (let round = 1; round < 10; round++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = xorBlocks(state, roundKeys[round]);
  }

  state = subBytes(state);
  state = shiftRows(state);
  state = xorBlocks(state, roundKeys[10]);

  return state;
}

function aesDecryptBlock(block, key) {
  assertLength(block, 16, "AES block");
  const roundKeys = expandKey128(key);

  let state = xorBlocks(block, roundKeys[10]);

  for (let round = 9; round > 0; round--) {
    state = inverseShiftRows(state);
    state = inverseSubBytes(state);
    state = xorBlocks(state, roundKeys[round]);
    state = inverseMixColumns(state);
  }

  state = inverseShiftRows(state);
  state = inverseSubBytes(state);
  state = xorBlocks(state, roundKeys[0]);

  return state;
}

function pkcs7Pad(data) {
  const padding = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  return Buffer.concat([
    data,
    Buffer.alloc(padding, padding)
  ]);
}

function pkcs7Unpad(data) {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error("Invalid padded data");
  }

  const padding = data[data.length - 1];

  if (padding < 1 || padding > BLOCK_SIZE) {
    throw new Error("Invalid padding length");
  }

  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new Error("Invalid padding bytes");
    }
  }

  return data.subarray(0, data.length - padding);
}

function aesCbcEncrypt(plaintext, key, iv) {
  assertLength(key, 16, "AES-128 key");
  assertLength(iv, 16, "CBC IV");

  const padded = pkcs7Pad(plaintext);
  const output = Buffer.alloc(padded.length);
  let previous = Uint8Array.from(iv);

  for (let offset = 0; offset < padded.length; offset += 16) {
    const block = padded.subarray(offset, offset + 16);
    const encrypted = aesEncryptBlock(
      xorBlocks(block, previous),
      key
    );
    output.set(encrypted, offset);
    previous = encrypted;
  }

  return output;
}

function aesCbcDecrypt(ciphertext, key, iv) {
  assertLength(key, 16, "AES-128 key");
  assertLength(iv, 16, "CBC IV");

  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error("CBC ciphertext must contain complete blocks");
  }

  const output = Buffer.alloc(ciphertext.length);
  let previous = Uint8Array.from(iv);

  for (let offset = 0; offset < ciphertext.length; offset += 16) {
    const block = ciphertext.subarray(offset, offset + 16);
    const decrypted = aesDecryptBlock(block, key);
    output.set(xorBlocks(decrypted, previous), offset);
    previous = Uint8Array.from(block);
  }

  return pkcs7Unpad(output);
}

function incrementCounter(counter) {
  for (let i = counter.length - 1; i >= 0; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) return;
  }
}

function aesCtrCrypt(data, key, nonce) {
  assertLength(key, 16, "AES-128 key");
  assertLength(nonce, 16, "CTR nonce");

  const output = Buffer.alloc(data.length);
  const counter = Uint8Array.from(nonce);

  for (let offset = 0; offset < data.length; offset += 16) {
    const keystream = aesEncryptBlock(counter, key);
    const length = Math.min(16, data.length - offset);

    for (let i = 0; i < length; i++) {
      output[offset + i] = data[offset + i] ^ keystream[i];
    }

    incrementCounter(counter);
  }

  return output;
}

function productionAes256Gcm(plaintext, associatedData = Buffer.alloc(0)) {
  /*
   * Node's crypto module provides the production-oriented primitive.
   * AES-GCM combines confidentiality and authentication. The authentication
   * tag makes accidental or malicious ciphertext modification detectable.
   */
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);

  if (associatedData.length > 0) {
    cipher.setAAD(associatedData);
  }

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  return {
    key,
    nonce,
    ciphertext,
    tag: cipher.getAuthTag(),
    associatedData
  };
}

function decryptAes256Gcm(message) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    message.key,
    message.nonce
  );

  if (message.associatedData.length > 0) {
    decipher.setAAD(message.associatedData);
  }

  decipher.setAuthTag(message.tag);

  return Buffer.concat([
    decipher.update(message.ciphertext),
    decipher.final()
  ]);
}

function knownAnswerTest() {
  const key = Buffer.from(
    "000102030405060708090a0b0c0d0e0f",
    "hex"
  );

  const plaintext = Buffer.from(
    "00112233445566778899aabbccddeeff",
    "hex"
  );

  const expected =
    "69c4e0d86a7b0430d8cdb78070b4c55a";

  const ciphertext = aesEncryptBlock(plaintext, key);

  if (ciphertext.toString("hex") !== expected) {
    throw new Error("AES known-answer test failed");
  }

  if (!aesDecryptBlock(ciphertext, key).equals(plaintext)) {
    throw new Error("AES decryption test failed");
  }

  console.log("AES-128 known-answer test: PASS");
}

function demonstrateModes() {
  const key = crypto.randomBytes(16);
  const plaintext = Buffer.from(
    "Sensitive inventory data requiring confidentiality."
  );

  const iv = crypto.randomBytes(16);
  const cbcCiphertext = aesCbcEncrypt(plaintext, key, iv);
  const cbcRecovered = aesCbcDecrypt(
    cbcCiphertext,
    key,
    iv
  );

  console.log("\nCBC mode");
  console.log("Key        :", key.toString("hex"));
  console.log("IV         :", iv.toString("hex"));
  console.log("Ciphertext :", cbcCiphertext.toString("hex"));
  console.log("Recovered  :", cbcRecovered.toString());

  const nonce = crypto.randomBytes(16);
  const ctrCiphertext = aesCtrCrypt(plaintext, key, nonce);
  const ctrRecovered = aesCtrCrypt(
    ctrCiphertext,
    key,
    nonce
  );

  console.log("\nCTR mode");
  console.log("Nonce      :", nonce.toString("hex"));
  console.log("Ciphertext :", ctrCiphertext.toString("hex"));
  console.log("Recovered  :", ctrRecovered.toString());

  if (!cbcRecovered.equals(plaintext)) {
    throw new Error("CBC recovery failed");
  }

  if (!ctrRecovered.equals(plaintext)) {
    throw new Error("CTR recovery failed");
  }
}

function demonstrateGcm() {
  const plaintext = Buffer.from(
    "Production services should prefer authenticated encryption."
  );

  const associatedData = Buffer.from(
    "record-type=financial-transfer"
  );

  const protectedMessage = productionAes256Gcm(
    plaintext,
    associatedData
  );

  const recovered = decryptAes256Gcm(protectedMessage);

  console.log("\nAES-256-GCM using Node crypto");
  console.log("Nonce      :", protectedMessage.nonce.toString("hex"));
  console.log("Ciphertext :", protectedMessage.ciphertext.toString("hex"));
  console.log("Auth tag   :", protectedMessage.tag.toString("hex"));
  console.log("Recovered  :", recovered.toString());

  if (!recovered.equals(plaintext)) {
    throw new Error("GCM recovery failed");
  }

  const tampered = {
    ...protectedMessage,
    ciphertext: Buffer.from(protectedMessage.ciphertext)
  };

  tampered.ciphertext[0] ^= 1;

  try {
    decryptAes256Gcm(tampered);
  } catch (error) {
    console.log("Tampering detected: authentication failed as expected.");
  }
}

function demonstrateSecurityRules() {
  console.log("\nAES security rules");
  console.log("------------------");
  console.log("AES has a fixed 128-bit block size.");
  console.log("AES-128, AES-192 and AES-256 refer to key size.");
  console.log("CBC needs padding and an unpredictable IV.");
  console.log("CTR needs a never-reused counter/nonce under the same key.");
  console.log("GCM provides confidentiality and integrity together.");
  console.log("Never use ECB for ordinary structured application data.");
  console.log("Never treat an AES key as a password.");
  console.log("Use cryptographically secure random generation for keys and nonces.");
}

function main() {
  console.log("AES INTRODUCTION");
  console.log("=================");

  knownAnswerTest();
  demonstrateModes();
  demonstrateGcm();
  demonstrateSecurityRules();

  console.log("\nExecution completed successfully.");
}

main();
