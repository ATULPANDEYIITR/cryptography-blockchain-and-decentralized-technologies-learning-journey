'use strict';

/*
 * SHA-256 from first principles.
 *
 * This implementation demonstrates:
 * - UTF-8 message encoding
 * - SHA-256 padding
 * - 512-bit block processing
 * - 64-word message schedules
 * - 64 compression rounds
 * - 32-bit unsigned arithmetic
 * - avalanche-effect measurement
 * - comparison with Node.js crypto
 *
 * Run with:
 * node sha256.js
 */

const crypto = require('crypto');

const MASK32 = 0xffffffff;

const INITIAL_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xa2bfe8a1, 0xc24b8b70,
    0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
    0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c,
    0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
    0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
];

function rotr32(x, n) {
    x >>>= 0;
    return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function ch(x, y, z) {
    return ((x & y) ^ (~x & z)) >>> 0;
}

function maj(x, y, z) {
    return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

function bigSigma0(x) {
    return (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)) >>> 0;
}

function bigSigma1(x) {
    return (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)) >>> 0;
}

function smallSigma0(x) {
    return (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)) >>> 0;
}

function smallSigma1(x) {
    return (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10)) >>> 0;
}

function add32(...values) {
    let result = 0;
    for (const value of values) {
        result = (result + value) >>> 0;
    }
    return result;
}

function padMessage(message) {
    if (!Buffer.isBuffer(message)) {
        throw new TypeError('message must be a Buffer');
    }

    // Buffer lengths are safely below SHA-256's 2^64-bit theoretical limit.
    const bitLength = BigInt(message.length) * 8n;

    let paddingLength = 1;
    while ((message.length + paddingLength + 8) % 64 !== 0) {
        paddingLength++;
    }

    const padded = Buffer.alloc(message.length + paddingLength + 8);
    message.copy(padded);
    padded[message.length] = 0x80;

    // SHA-256 stores the original length as a 64-bit big-endian integer.
    padded.writeBigUInt64BE(bitLength, padded.length - 8);

    return padded;
}

function buildSchedule(block) {
    if (block.length !== 64) {
        throw new Error('A SHA-256 block must contain exactly 64 bytes');
    }

    const w = new Uint32Array(64);

    for (let i = 0; i < 16; i++) {
        w[i] = block.readUInt32BE(i * 4);
    }

    for (let i = 16; i < 64; i++) {
        w[i] = add32(
            smallSigma1(w[i - 2]),
            w[i - 7],
            smallSigma0(w[i - 15]),
            w[i - 16]
        );
    }

    return w;
}

function compress(state, block) {
    const w = buildSchedule(block);

    let [a, b, c, d, e, f, g, h] = state;

    for (let i = 0; i < 64; i++) {
        const temp1 = add32(
            h,
            bigSigma1(e),
            ch(e, f, g),
            K[i],
            w[i]
        );

        const temp2 = add32(
            bigSigma0(a),
            maj(a, b, c)
        );

        h = g;
        g = f;
        f = e;
        e = add32(d, temp1);
        d = c;
        c = b;
        b = a;
        a = add32(temp1, temp2);
    }

    return state.map((oldValue, index) => {
        const newValue = [a, b, c, d, e, f, g, h][index];
        return add32(oldValue, newValue);
    });
}

function sha256Buffer(message) {
    const padded = padMessage(message);
    let state = [...INITIAL_HASH];

    for (let offset = 0; offset < padded.length; offset += 64) {
        state = compress(state, padded.subarray(offset, offset + 64));
    }

    const output = Buffer.alloc(32);

    state.forEach((word, index) => {
        output.writeUInt32BE(word >>> 0, index * 4);
    });

    return output;
}

function sha256(text) {
    if (typeof text !== 'string') {
        throw new TypeError('text must be a string');
    }

    return sha256Buffer(Buffer.from(text, 'utf8')).toString('hex');
}

function referenceSha256(text) {
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function hammingDistance(a, b) {
    if (a.length !== b.length) {
        throw new Error('Buffers must have equal length');
    }

    let count = 0;

    for (let i = 0; i < a.length; i++) {
        let value = a[i] ^ b[i];

        while (value !== 0) {
            value &= value - 1;
            count++;
        }
    }

    return count;
}

function avalancheExperiment(text) {
    const original = Buffer.from(text, 'utf8');

    if (original.length === 0) {
        throw new Error('Input must not be empty');
    }

    const modified = Buffer.from(original);
    modified[0] ^= 0x01;

    const first = sha256Buffer(original);
    const second = sha256Buffer(modified);

    return {
        original: text,
        modified: modified.toString('utf8'),
        originalDigest: first.toString('hex'),
        modifiedDigest: second.toString('hex'),
        differingBits: hammingDistance(first, second)
    };
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message}: expected ${expected}, received ${actual}`);
    }
}

function runKnownAnswerTests() {
    const vectors = [
        [
            '',
            'e3b0c44298fc1c149afbf4c8996fb924' +
            '27ae41e4649b934ca495991b7852b855'
        ],
        [
            'abc',
            'ba7816bf8f01cfea414140de5dae2223' +
            'b00361a396177a9cb410ff61f20015ad'
        ],
        [
            'The quick brown fox jumps over the lazy dog',
            'd7a8fbb307d7809469ca9abcb0082e4f' +
            '8d5651e46d3cdb762d02d0bf37c9e592'
        ]
    ];

    for (const [input, expected] of vectors) {
        assertEqual(sha256(input), expected, `Known vector failed for ${JSON.stringify(input)}`);
        assertEqual(sha256(input), referenceSha256(input), 'Node crypto comparison failed');
    }

    console.log('Known-answer tests: PASS');
}

function runRandomizedTests(count = 100) {
    if (!Number.isInteger(count) || count <= 0) {
        throw new RangeError('count must be a positive integer');
    }

    for (let i = 0; i < count; i++) {
        const length = crypto.randomInt(0, 4097);
        const input = crypto.randomBytes(length);

        const custom = sha256Buffer(input).toString('hex');
        const reference = crypto.createHash('sha256').update(input).digest('hex');

        assertEqual(custom, reference, `Random test failed at iteration ${i}`);
    }

    console.log(`Randomized tests: PASS (${count} cases)`);
}

function demonstratePadding() {
    const padded = padMessage(Buffer.from('abc'));

    console.log('\nPadding demonstration');
    console.log(`Original bytes: ${Buffer.byteLength('abc')}`);
    console.log(`Padded bytes:   ${padded.length}`);
    console.log(`Block count:    ${padded.length / 64}`);
    console.log(`Last 8 bytes:   ${padded.subarray(-8).toString('hex')}`);
}

function main() {
    runKnownAnswerTests();
    runRandomizedTests();
    demonstratePadding();

    const input = 'Hello, SHA-256!';

    console.log('\nDigest demonstration');
    console.log(`Input:   ${input}`);
    console.log(`SHA-256: ${sha256(input)}`);

    const experiment = avalancheExperiment('security');

    console.log('\nAvalanche experiment');
    console.log(`Original:        ${JSON.stringify(experiment.original)}`);
    console.log(`Modified:        ${JSON.stringify(experiment.modified)}`);
    console.log(`Original digest: ${experiment.originalDigest}`);
    console.log(`Modified digest: ${experiment.modifiedDigest}`);
    console.log(`Differing bits:  ${experiment.differingBits} / 256`);

    console.log('\nSecurity notes');
    console.log('- SHA-256 is hashing, not encryption.');
    console.log('- A digest does not provide a reversible representation of the input.');
    console.log('- Password storage requires a password-hashing algorithm, not raw SHA-256.');
    console.log('- SHA-256 processes data in 512-bit blocks and produces a 256-bit digest.');
}

main();
