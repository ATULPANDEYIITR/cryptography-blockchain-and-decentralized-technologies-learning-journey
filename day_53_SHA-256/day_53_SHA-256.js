'use strict';

/*
 * SHA-256 implementation and integrity workflow.
 *
 * Node.js Buffer is used for binary data, while the compression function
 * operates on unsigned 32-bit JavaScript integers through >>> and | 0.
 * The built-in crypto module is used as an independent verification oracle.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const INITIAL_HASH = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbc4, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
}

function ch(x, y, z) {
    return (x & y) ^ (~x & z);
}

function maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

function bigSigma0(x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

function bigSigma1(x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

function smallSigma0(x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
}

function smallSigma1(x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
}

function padMessage(input) {
    const length = input.length;
    const zeroCount = (56 - ((length + 1) % 64) + 64) % 64;
    const result = Buffer.alloc(length + 1 + zeroCount + 8);

    input.copy(result, 0);
    result[length] = 0x80;

    const bitLength = BigInt(length) * 8n;
    result.writeBigUInt64BE(bitLength, result.length - 8);

    return result;
}

function compressBlock(block, state) {
    if (block.length !== 64) {
        throw new RangeError('SHA-256 blocks must contain 64 bytes.');
    }

    const words = new Uint32Array(64);

    for (let i = 0; i < 16; i++) {
        words[i] = block.readUInt32BE(i * 4);
    }

    for (let i = 16; i < 64; i++) {
        words[i] = (
            smallSigma1(words[i - 2]) +
            words[i - 7] +
            smallSigma0(words[i - 15]) +
            words[i - 16]
        ) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = state;

    for (let i = 0; i < 64; i++) {
        const temp1 = (
            h +
            bigSigma1(e) +
            ch(e, f, g) +
            K[i] +
            words[i]
        ) >>> 0;

        const temp2 = (
            bigSigma0(a) +
            maj(a, b, c)
        ) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
    }

    return new Uint32Array([
        (state[0] + a) >>> 0,
        (state[1] + b) >>> 0,
        (state[2] + c) >>> 0,
        (state[3] + d) >>> 0,
        (state[4] + e) >>> 0,
        (state[5] + f) >>> 0,
        (state[6] + g) >>> 0,
        (state[7] + h) >>> 0
    ]);
}

function sha256(input) {
    const message = Buffer.isBuffer(input) ? input : Buffer.from(input);
    const padded = padMessage(message);

    let state = new Uint32Array(INITIAL_HASH);

    for (let offset = 0; offset < padded.length; offset += 64) {
        state = compressBlock(padded.subarray(offset, offset + 64), state);
    }

    const output = Buffer.alloc(32);

    for (let i = 0; i < 8; i++) {
        output.writeUInt32BE(state[i], i * 4);
    }

    return output;
}

function sha256Hex(input) {
    return sha256(input).toString('hex');
}

function builtinSha256(input) {
    return crypto.createHash('sha256').update(input).digest();
}

function constantTimeEqual(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) {
        return false;
    }

    return crypto.timingSafeEqual(a, b);
}

function verifyDigest(input, expectedHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(expectedHex)) {
        return false;
    }

    return constantTimeEqual(
        sha256(input),
        Buffer.from(expectedHex, 'hex')
    );
}

function hashFile(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);

        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

async function runKnownVectors() {
    const vectors = [
        ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        ['hello world', 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9']
    ];

    for (const [message, expected] of vectors) {
        const actual = sha256Hex(message);

        if (actual !== expected) {
            throw new Error(`Known vector failed: ${message}`);
        }

        if (!constantTimeEqual(sha256(message), builtinSha256(message))) {
            throw new Error(`Built-in verification failed: ${message}`);
        }
    }

    console.log('Known SHA-256 vectors: PASS');
}

async function runFileDemo() {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sha256-'));
    const filePath = path.join(directory, 'artifact.bin');

    try {
        const payload = Buffer.alloc(256 * 4096);

        for (let i = 0; i < payload.length; i++) {
            payload[i] = i % 256;
        }

        fs.writeFileSync(filePath, payload);

        const expected = builtinSha256(payload).toString('hex');
        const actual = await hashFile(filePath);

        console.log(`File SHA-256: ${actual}`);
        console.log(`File verification: ${actual === expected ? 'PASS' : 'FAIL'}`);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

async function main() {
    await runKnownVectors();

    const messages = [
        'repository artifact',
        'SHA-256 is deterministic',
        Buffer.from([...Array(32).keys()])
    ];

    for (const message of messages) {
        const actual = sha256Hex(message);
        const reference = builtinSha256(message).toString('hex');

        console.log(`\nMessage: ${Buffer.from(message).toString('hex')}`);
        console.log(`SHA-256: ${actual}`);
        console.log(`Matches crypto module: ${constantTimeEqual(sha256(message), builtinSha256(message))}`);
        console.log(`Verification: ${verifyDigest(message, actual)}`);
        console.log(`Reference match: ${actual === reference}`);
    }

    await runFileDemo();
}

main().catch(error => {
    console.error(`SHA-256 workflow failed: ${error.message}`);
    process.exitCode = 1;
});
