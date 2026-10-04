/**
 * DES in Cryptography and Blockchain
 *
 * This Node.js-compatible file implements DES at the block level and uses
 * JavaScript's event-driven model to demonstrate a blockchain governance-style
 * workflow for encrypted records.
 *
 * Run:
 *   node des-blockchain.js
 *
 * DES is obsolete for new security systems because its effective key size is
 * only 56 bits. The implementation is educational and intentionally exposes
 * the internal DES mechanism.
 */

"use strict";

const crypto = require("crypto");

// -----------------------------------------------------------------------------
// DES tables
// -----------------------------------------------------------------------------

const IP = [
  58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
];

const FP = [
  40,8,48,16,56,24,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
];

const E = [
  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
  12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,
  23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
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

const SBOXES = [
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

function getBit(value, position, width) {
  return Number((value >> BigInt(width - position)) & 1n);
}

function permute(value, table, width) {
  let result = 0n;
  for (const position of table) {
    result = (result << 1n) | BigInt(getBit(value, position, width));
  }
  return result;
}

function rotate28(value, amount) {
  const mask = (1n << 28n) - 1n;
  return ((value << BigInt(amount)) | (value >> BigInt(28 - amount))) & mask;
}

function bufferToBigInt(buffer) {
  return BigInt("0x" + buffer.toString("hex"));
}

function bigIntToBuffer(value, size = 8) {
  return Buffer.from(value.toString(16).padStart(size * 2, "0"), "hex");
}

function setOddParity(key) {
  if (key.length !== 8) throw new Error("DES requires an 8-byte key.");
  const result = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    const data = key[i] & 0xfe;
    let ones = 0;
    for (let bit = 0; bit < 8; bit++) ones += (data >> bit) & 1;
    result[i] = data | (ones % 2 === 0 ? 1 : 0);
  }
  return result;
}

function generateRoundKeys(key) {
  key = setOddParity(key);
  const permuted = permute(bufferToBigInt(key), PC1, 64);
  let c = permuted >> 28n;
  let d = permuted & ((1n << 28n) - 1n);

  return ROTATIONS.map(rotation => {
    c = rotate28(c, rotation);
    d = rotate28(d, rotation);
    return permute((c << 28n) | d, PC2, 56);
  });
}

function feistel(right, roundKey) {
  const expanded = permute(right, E, 32);
  const mixed = expanded ^ roundKey;

  let output = 0n;

  for (let i = 0; i < 8; i++) {
    const six = Number((mixed >> BigInt(42 - i * 6)) & 0x3fn);
    const row = ((six >> 5) << 1) | (six & 1);
    const column = (six >> 1) & 15;
    output = (output << 4n) | BigInt(SBOXES[i][row][column]);
  }

  return permute(output, P, 32);
}

function desBlock(block, key, decrypt = false) {
  if (block.length !== 8) throw new Error("DES block size is 8 bytes.");

  let state = permute(bufferToBigInt(block), IP, 64);
  let left = state >> 32n;
  let right = state & 0xffffffffn;
  let keys = generateRoundKeys(key);

  if (decrypt) keys = keys.reverse();

  for (const roundKey of keys) {
    const nextLeft = right;
    const nextRight = left ^ feistel(right, roundKey);
    left = nextLeft;
    right = nextRight;
  }

  const preoutput = (right << 32n) | left;
  return bigIntToBuffer(permute(preoutput, FP, 64));
}

function pad(data) {
  const padding = 8 - (data.length % 8);
  return Buffer.concat([data, Buffer.alloc(padding, padding)]);
}

function unpad(data) {
  if (!data.length || data.length % 8 !== 0) {
    throw new Error("Invalid padded data length.");
  }

  const padding = data[data.length - 1];
  if (padding < 1 || padding > 8) {
    throw new Error("Invalid padding length.");
  }

  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) throw new Error("Invalid padding.");
  }

  return data.subarray(0, data.length - padding);
}

function desCbcEncrypt(data, key, iv) {
  if (iv.length !== 8) throw new Error("DES-CBC IV must be 8 bytes.");

  const padded = pad(data);
  const output = [];
  let previous = iv;

  for (let offset = 0; offset < padded.length; offset += 8) {
    const block = padded.subarray(offset, offset + 8);
    const mixed = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) mixed[i] = block[i] ^ previous[i];

    const encrypted = desBlock(mixed, key);
    output.push(encrypted);
    previous = encrypted;
  }

  return Buffer.concat(output);
}

function desCbcDecrypt(ciphertext, key, iv) {
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error("Invalid DES-CBC ciphertext.");
  }

  const output = [];
  let previous = iv;

  for (let offset = 0; offset < ciphertext.length; offset += 8) {
    const block = ciphertext.subarray(offset, offset + 8);
    const decrypted = desBlock(block, key, true);
    const plain = Buffer.alloc(8);

    for (let i = 0; i < 8; i++) plain[i] = decrypted[i] ^ previous[i];

    output.push(plain);
    previous = block;
  }

  return unpad(Buffer.concat(output));
}

// -----------------------------------------------------------------------------
// Event-driven encrypted ledger
// -----------------------------------------------------------------------------

class EncryptedLedger extends require("events") {
  constructor(desKey, macKey) {
    super();
    this.desKey = setOddParity(desKey);
    this.macKey = macKey;
    this.blocks = [];
  }

  append(payload) {
    if (typeof payload !== "string" || payload.trim().length === 0) {
      throw new Error("Ledger payload must be a non-empty string.");
    }

    const iv = crypto.randomBytes(8);
    const ciphertext = desCbcEncrypt(
      Buffer.from(payload, "utf8"),
      this.desKey,
      iv
    );

    const mac = crypto
      .createHmac("sha256", this.macKey)
      .update(Buffer.concat([iv, ciphertext]))
      .digest("hex");

    const previousHash = this.blocks.length
      ? this.blocks[this.blocks.length - 1].hash
      : "0".repeat(64);

    const block = {
      index: this.blocks.length,
      previousHash,
      timestamp: Date.now(),
      payload,
      iv: iv.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
      mac,
      nonce: crypto.randomInt(0, 2 ** 31)
    };

    block.hash = this.hashBlock(block);
    this.blocks.push(block);

    // Node.js EventEmitter provides a useful model for asynchronous systems:
    // listeners can audit, persist, or monitor the append operation.
    this.emit("blockAppended", {
      index: block.index,
      hash: block.hash
    });

    return block;
  }

  hashBlock(block) {
    const canonical = [
      block.index,
      block.previousHash,
      block.timestamp,
      block.payload,
      block.iv,
      block.ciphertext,
      block.mac,
      block.nonce
    ].join("|");

    return crypto.createHash("sha256").update(canonical).digest("hex");
  }

  decrypt(block) {
    const iv = Buffer.from(block.iv, "hex");
    const ciphertext = Buffer.from(block.ciphertext, "hex");

    const expectedMac = crypto
      .createHmac("sha256", this.macKey)
      .update(Buffer.concat([iv, ciphertext]))
      .digest("hex");

    if (
      expectedMac.length !== block.mac.length ||
      !crypto.timingSafeEqual(
        Buffer.from(expectedMac, "hex"),
        Buffer.from(block.mac, "hex")
      )
    ) {
      throw new Error("Encrypted payload failed HMAC authentication.");
    }

    return desCbcDecrypt(ciphertext, this.desKey, iv).toString("utf8");
  }

  validate() {
    const errors = [];

    for (let i = 0; i < this.blocks.length; i++) {
      const block = this.blocks[i];

      const expectedPrevious = i === 0
        ? "0".repeat(64)
        : this.blocks[i - 1].hash;

      if (block.previousHash !== expectedPrevious) {
        errors.push(`Broken chain link at block ${block.index}`);
      }

      if (this.hashBlock(block) !== block.hash) {
        errors.push(`Block hash mismatch at block ${block.index}`);
      }

      try {
        this.decrypt(block);
      } catch (error) {
        errors.push(`Payload authentication failed at block ${block.index}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

function classicDesTestVector() {
  const key = Buffer.from("133457799BBCDFF1", "hex");
  const plaintext = Buffer.from("0123456789ABCDEF", "hex");
  const expected = Buffer.from("85E813540F0AB405", "hex");

  const encrypted = desBlock(plaintext, key);

  if (!encrypted.equals(expected)) {
    throw new Error(
      `DES test vector failed: ${encrypted.toString("hex").toUpperCase()}`
    );
  }

  if (!desBlock(encrypted, key, true).equals(plaintext)) {
    throw new Error("DES decryption test failed.");
  }
}

function main() {
  classicDesTestVector();

  console.log("=== DES block operation ===");

  const key = setOddParity(Buffer.from("Crypto!!"));
  const block = Buffer.from("12345678");

  const encrypted = desBlock(block, key);
  const recovered = desBlock(encrypted, key, true);

  console.log("Key:", key.toString("hex").toUpperCase());
  console.log("Ciphertext:", encrypted.toString("hex").toUpperCase());
  console.log("Recovered:", recovered.toString());
  console.log("Round-trip:", recovered.equals(block));

  console.log("\n=== Event-driven blockchain payload model ===");

  const ledger = new EncryptedLedger(
    crypto.randomBytes(8),
    crypto.randomBytes(32)
  );

  ledger.on("blockAppended", event => {
    console.log(
      `Audit event: block ${event.index} appended, hash=${event.hash.slice(0, 18)}...`
    );
  });

  ledger.append("Token transfer from wallet-A to wallet-B: 125 units");
  ledger.append("Validator quorum accepted transaction batch");
  ledger.append("Smart-contract escrow state changed to RELEASED");

  for (const block of ledger.blocks) {
    console.log(
      `Block ${block.index}:`,
      ledger.decrypt(block)
    );
  }

  console.log("Ledger valid:", ledger.validate().valid);

  // Modifying authenticated ciphertext without recomputing the HMAC should
  // cause decryption to fail. This demonstrates why confidentiality and
  // integrity are separate requirements.
  const tampered = ledger.blocks[1];
  const firstCipherByte = parseInt(tampered.ciphertext.slice(0, 2), 16) ^ 1;
  tampered.ciphertext =
    firstCipherByte.toString(16).padStart(2, "0") +
    tampered.ciphertext.slice(2);

  try {
    ledger.decrypt(tampered);
  } catch (error) {
    console.log("Tampering detected:", error.message);
  }

  console.log("\n=== Security distinction ===");
  console.log("DES -> legacy confidentiality mechanism");
  console.log("HMAC-SHA-256 -> payload authenticity/integrity");
  console.log("SHA-256 -> block and chain-link digest");
  console.log("Consensus/signatures -> blockchain-level trust mechanisms");
  console.log(
    "Modern systems should use AES-GCM or ChaCha20-Poly1305 instead of DES."
  );
}

main();
