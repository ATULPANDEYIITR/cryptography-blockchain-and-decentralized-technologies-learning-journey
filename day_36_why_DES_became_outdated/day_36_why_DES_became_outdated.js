'use strict';

/*
 * Why DES became outdated
 *
 * This Node.js program focuses on DES from a JavaScript perspective.
 * It implements a compact DES engine, an event-driven migration assessment,
 * reduced-key brute-force demonstration, and policy evaluation.
 *
 * Run with:
 *   node des_obsolescence.js
 */

const crypto = require('crypto');

const IP = [
  58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
];

const FP = [
  40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
];

const E = [
  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
  12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,
  24,25,24,25,26,27,28,29,28,29,30,31,32,1
];

const P = [
  16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
];

const PC1 = [
  57,49,41,33,25,17,9,1,58,50,42,34,26,18,
  10,2,59,51,43,35,27,19,11,3,60,52,44,36,
  63,55,47,39,31,23,15,7,62,54,46,38,30,22,
  14,6,61,53,45,37,29,21,13,5,28,20,12,4
];

const PC2 = [
  14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
  26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
  51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
];

const ROTATIONS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

const S = [
  [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
  ],
  [
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
  ],
  [
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
  ],
  [
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
  ],
  [
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
  ],
  [
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
  ],
  [
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
  ],
  [
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
  ]
];

function permutation(value, table, inputBits) {
  let result = 0n;
  for (const position of table) {
    result = (result << 1n) | ((value >> BigInt(inputBits - position)) & 1n);
  }
  return result;
}

function rotate28(value, amount) {
  const mask = (1n << 28n) - 1n;
  return ((value << BigInt(amount)) | (value >> BigInt(28 - amount))) & mask;
}

function generateRoundKeys(key) {
  let transformed = permutation(key, PC1, 64);
  let c = transformed >> 28n;
  let d = transformed & ((1n << 28n) - 1n);

  return ROTATIONS.map(rotation => {
    c = rotate28(c, rotation);
    d = rotate28(d, rotation);
    return permutation((c << 28n) | d, PC2, 56);
  });
}

function feistel(right, roundKey) {
  const expanded = permutation(right, E, 32);
  const mixed = expanded ^ roundKey;
  let substituted = 0n;

  for (let box = 0; box < 8; box++) {
    const six = Number((mixed >> BigInt(42 - 6 * box)) & 0x3Fn);
    const row = ((six & 0x20) >> 4) | (six & 1);
    const column = (six >> 1) & 15;
    substituted = (substituted << 4n) | BigInt(S[box][row][column]);
  }

  return permutation(substituted, P, 32);
}

function desBlock(block, key, decrypt = false) {
  let keys = generateRoundKeys(key);
  if (decrypt) keys = [...keys].reverse();

  const state = permutation(block, IP, 64);
  let left = state >> 32n;
  let right = state & 0xffffffffn;

  for (const roundKey of keys) {
    [left, right] = [right, left ^ feistel(right, roundKey)];
  }

  return permutation((right << 32n) | left, FP, 64);
}

function hexToBigInt(hex) {
  if (!/^[0-9a-fA-F]{16}$/.test(hex)) {
    throw new Error('A DES block/key must contain exactly 16 hexadecimal characters.');
  }
  return BigInt(`0x${hex}`);
}

function bigintToHex(value) {
  return value.toString(16).padStart(16, '0').toUpperCase();
}

function encryptHexBlock(plaintextHex, keyHex) {
  return bigintToHex(desBlock(hexToBigInt(plaintextHex), hexToBigInt(keyHex)));
}

function decryptHexBlock(ciphertextHex, keyHex) {
  return bigintToHex(
    desBlock(hexToBigInt(ciphertextHex), hexToBigInt(keyHex), true)
  );
}

class MigrationAssessment extends require('events') {
  constructor() {
    super();
    this.records = [];
  }

  evaluate(algorithm) {
    const rules = {
      DES: {
        keyBits: 56,
        blockBits: 64,
        status: 'REJECT',
        reason: '56-bit effective key space is vulnerable to exhaustive search.'
      },
      '3DES': {
        keyBits: 112,
        blockBits: 64,
        status: 'LEGACY',
        reason: 'Improves key strength but retains the 64-bit block size and high computational cost.'
      },
      'AES-128': {
        keyBits: 128,
        blockBits: 128,
        status: 'ACCEPT',
        reason: 'Modern key and block dimensions with broad implementation support.'
      },
      'AES-256': {
        keyBits: 256,
        blockBits: 128,
        status: 'ACCEPT',
        reason: 'Larger key space with a 128-bit block size.'
      }
    };

    const result = rules[algorithm];
    if (!result) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    const assessment = { algorithm, ...result };
    this.records.push(assessment);
    this.emit('assessment', assessment);
    return assessment;
  }
}

function demonstrateKnownVector() {
  const plaintext = '0123456789ABCDEF';
  const key = '133457799BBCDFF1';
  const expected = '85E813540F0AB405';

  const ciphertext = encryptHexBlock(plaintext, key);
  const recovered = decryptHexBlock(ciphertext, key);

  console.log('Classic DES known vector');
  console.log(`  Ciphertext: ${ciphertext}`);
  console.log(`  Expected  : ${expected}`);
  console.log(`  Valid     : ${ciphertext === expected}`);
  console.log(`  Recovered : ${recovered}`);
  console.log();
}

function demonstrateReducedBruteForce() {
  const plaintext = '44455344454D4F21'; // "DESDEMO!"
  const prefix = 0x133457799BBC0000n;
  const secretSuffix = 0x0A5Bn;
  const secretKey = bigintToHex(prefix | secretSuffix);
  const ciphertext = encryptHexBlock(plaintext, secretKey);

  const start = process.hrtime.bigint();
  let found = null;

  for (let candidate = 0n; candidate < 65536n; candidate++) {
    const candidateKey = bigintToHex(prefix | candidate);
    if (encryptHexBlock(plaintext, candidateKey) === ciphertext) {
      found = candidate;
      break;
    }
  }

  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

  console.log('Reduced key-space brute-force demonstration');
  console.log('  Demonstration space: 2^16 candidates');
  console.log(`  Found suffix       : ${found === null ? 'not found' : '0x' + found.toString(16)}`);
  console.log(`  Time               : ${elapsedMs.toFixed(2)} ms`);
  console.log('  Real DES space     : 2^56 candidates');
  console.log();
}

function demonstrateAvalanche() {
  const key = '133457799BBCDFF1';
  const a = encryptHexBlock('0123456789ABCDEF', key);
  const b = encryptHexBlock('0123456789ABCDEE', key);

  const x = BigInt(`0x${a}`) ^ BigInt(`0x${b}`);
  let changed = 0;

  for (let value = x; value !== 0n; value &= value - 1n) {
    changed++;
  }

  console.log('Avalanche behavior');
  console.log(`  Cipher A: ${a}`);
  console.log(`  Cipher B: ${b}`);
  console.log(`  Changed bits: ${changed}/64`);
  console.log('  Interpretation: DES can have strong diffusion while still being obsolete.');
  console.log();
}

function demonstrateBlockSize() {
  const birthdayBlocks = 2 ** 32;
  const bytes = birthdayBlocks * 8;
  const gib = bytes / (1024 ** 3);

  console.log('64-bit block-size limitation');
  console.log(`  Birthday-bound scale: approximately 2^32 blocks`);
  console.log(`  Eight-byte blocks at that scale: approximately ${gib.toFixed(1)} GiB`);
  console.log('  Modern AES uses a 128-bit block, substantially increasing this scale.');
  console.log();
}

function demonstrateHashDistinction() {
  const message = Buffer.from('DES migration record', 'utf8');
  const digest = crypto.createHash('sha256').update(message).digest('hex');

  console.log('Primitive selection');
  console.log(`  SHA-256 digest: ${digest}`);
  console.log('  A digest is not a replacement for reversible encryption.');
  console.log();
}

function main() {
  console.log('='.repeat(78));
  console.log('WHY DES BECAME OUTDATED');
  console.log('='.repeat(78));
  console.log();

  demonstrateKnownVector();
  demonstrateReducedBruteForce();
  demonstrateAvalanche();
  demonstrateBlockSize();

  const assessment = new MigrationAssessment();

  assessment.on('assessment', result => {
    console.log(
      `[event] ${result.algorithm}: ${result.status} - ${result.reason}`
    );
  });

  for (const algorithm of ['DES', '3DES', 'AES-128', 'AES-256']) {
    assessment.evaluate(algorithm);
  }

  console.log();
  demonstrateHashDistinction();

  console.log('Engineering interpretation');
  console.log('  DES was designed for an earlier threat and hardware environment.');
  console.log('  Its 56-bit effective key size became too small as computation improved.');
  console.log('  Its 64-bit block size also limits modern high-volume use.');
  console.log('  3DES extended compatibility but retained important DES-era constraints.');
  console.log('  AES became the modern general-purpose symmetric encryption standard.');
}

main();
