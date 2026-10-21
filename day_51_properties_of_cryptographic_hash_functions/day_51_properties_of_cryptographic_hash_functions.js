'use strict';

/*
 * Cryptographic hash function properties using Node.js built-in crypto.
 *
 * The program models:
 * - deterministic hashing
 * - digest size
 * - avalanche behavior
 * - integrity verification
 * - domain separation
 * - hash chaining
 * - Merkle-style aggregation
 * - truncated-digest collision behavior
 * - asynchronous file hashing
 *
 * Run with:
 *   node hash-properties.js
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const ALGORITHMS = new Set(['sha256', 'sha3-256', 'blake2s256']);

function hash(data, algorithm = 'sha256') {
    if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data);
    }

    if (!ALGORITHMS.has(algorithm)) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }

    return crypto.createHash(algorithm).update(data).digest();
}

function hexHash(data, algorithm = 'sha256') {
    return hash(data, algorithm).toString('hex');
}

function bitDifference(a, b) {
    if (a.length !== b.length) {
        throw new Error('Digest lengths must match');
    }

    let changed = 0;

    for (let i = 0; i < a.length; i++) {
        let value = a[i] ^ b[i];

        while (value !== 0) {
            changed += value & 1;
            value >>>= 1;
        }
    }

    return changed;
}

function demonstrateDeterminism() {
    const input = Buffer.from('commit=8f42');
    const first = hexHash(input);
    const second = hexHash(input);

    if (first !== second) {
        throw new Error('Determinism property failed');
    }

    console.log('Determinism');
    console.log(`  ${first}`);
}

function demonstrateAvalanche() {
    const original = Buffer.from('amount=1000;account=42');
    const modified = Buffer.from('amount=1001;account=42');

    const first = hash(original);
    const second = hash(modified);
    const changed = bitDifference(first, second);
    const total = first.length * 8;

    console.log('\nAvalanche effect');
    console.log(`  changed bits: ${changed}/${total}`);
    console.log(`  percentage: ${(changed / total * 100).toFixed(2)}%`);
}

function demonstrateDomainSeparation() {
    const message = Buffer.from('user=42');

    const registration = hexHash(
        Buffer.concat([Buffer.from('registration:'), message])
    );

    const audit = hexHash(
        Buffer.concat([Buffer.from('audit:'), message])
    );

    console.log('\nDomain separation');
    console.log(`  registration: ${registration}`);
    console.log(`  audit:        ${audit}`);

    if (registration === audit) {
        throw new Error('Domain separation failed');
    }
}

function demonstrateIntegrity() {
    const expected = hash('release=2026.10.21;artifact=build-1842');

    const received = Buffer.from('release=2026.10.21;artifact=build-1842');
    const tampered = Buffer.from('release=2026.10.21;artifact=build-1843');

    const receivedDigest = hash(received);
    const tamperedDigest = hash(tampered);

    console.log('\nIntegrity verification');
    console.log(`  valid artifact:   ${crypto.timingSafeEqual(expected, receivedDigest)}`);
    console.log(`  tampered artifact:${crypto.timingSafeEqual(expected, tamperedDigest)}`);
}

function demonstrateTruncatedCollision() {
    const seen = new Map();
    const digestBytes = 2;

    for (let number = 0; number < 1_000_000; number++) {
        const message = Buffer.from(`record-${number}`);
        const prefix = hash(message).subarray(0, digestBytes).toString('hex');

        if (seen.has(prefix) && seen.get(prefix) !== message.toString()) {
            console.log('\nTruncated collision experiment');
            console.log(`  digest prefix: ${prefix}`);
            console.log(`  first: ${seen.get(prefix)}`);
            console.log(`  second: ${message.toString()}`);
            console.log('  A 16-bit digest is intentionally weak for this experiment.');
            return;
        }

        seen.set(prefix, message.toString());
    }

    console.log('\nNo collision found within the experiment limit.');
}

function blockHash(index, previousHash, payload) {
    const indexBuffer = Buffer.alloc(4);
    indexBuffer.writeUInt32BE(index);

    return hexHash(
        Buffer.concat([
            indexBuffer,
            Buffer.from(previousHash, 'hex'),
            Buffer.from(payload)
        ])
    );
}

function validateChain(chain) {
    for (let i = 0; i < chain.length; i++) {
        const expectedPrevious = i === 0
            ? '0'.repeat(64)
            : chain[i - 1].hash;

        if (chain[i].previousHash !== expectedPrevious) {
            return false;
        }

        const rebuilt = blockHash(
            chain[i].index,
            chain[i].previousHash,
            chain[i].payload
        );

        if (rebuilt !== chain[i].hash) {
            return false;
        }
    }

    return chain.length > 0;
}

function demonstrateHashChain() {
    const chain = [];
    let previous = '0'.repeat(64);

    for (const [index, payload] of [
        [0, 'commit:8f42'],
        [1, 'review:approved'],
        [2, 'merge:main']
    ]) {
        const currentHash = blockHash(index, previous, payload);

        chain.push({
            index,
            previousHash: previous,
            payload,
            hash: currentHash
        });

        previous = currentHash;
    }

    console.log('\nHash chain');
    console.log(`  before modification: ${validateChain(chain)}`);

    const modified = structuredClone(chain);
    modified[1].payload = 'review:rejected';

    console.log(`  after modification:  ${validateChain(modified)}`);
}

function merkleRoot(values) {
    if (values.length === 0) {
        throw new Error('Cannot construct a Merkle root from an empty set');
    }

    let level = values.map(value => hash(value));

    while (level.length > 1) {
        const next = [];

        for (let i = 0; i < level.length; i += 2) {
            const right = level[i + 1] ?? level[i];

            next.push(
                hash(Buffer.concat([level[i], right]))
            );
        }

        level = next;
    }

    return level[0].toString('hex');
}

function demonstrateMerkleAggregation() {
    const records = [
        'commit:8f42',
        'commit:19bc',
        'commit:a71e',
        'commit:f004'
    ];

    console.log('\nMerkle-style aggregation');
    console.log(`  root: ${merkleRoot(records)}`);
}

async function hashFile(filePath, algorithm = 'sha256') {
    if (!ALGORITHMS.has(algorithm)) {
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    return new Promise((resolve, reject) => {
        const stream = fs.createReadStream(filePath);
        const hasher = crypto.createHash(algorithm);

        stream.on('data', chunk => hasher.update(chunk));
        stream.on('error', reject);
        stream.on('end', () => resolve(hasher.digest('hex')));
    });
}

async function demonstrateFileHashing() {
    const directory = await fsp.mkdtemp(
        path.join(os.tmpdir(), 'hash-properties-')
    );

    const file = path.join(directory, 'artifact.bin');

    try {
        await fsp.writeFile(file, crypto.randomBytes(4096));

        const original = await hashFile(file);

        await fsp.appendFile(file, Buffer.from([0]));

        const modified = await hashFile(file);

        console.log('\nStreaming file hashing');
        console.log(`  original: ${original}`);
        console.log(`  modified: ${modified}`);
        console.log(`  identical: ${original === modified}`);
    } finally {
        await fsp.rm(directory, { recursive: true, force: true });
    }
}

function demonstrateAlgorithmSizes() {
    const message = Buffer.from('cryptographic hash properties');

    console.log('\nDigest sizes');

    for (const algorithm of ALGORITHMS) {
        const digest = hash(message, algorithm);
        console.log(`  ${algorithm}: ${digest.length * 8} bits`);
    }
}

async function main() {
    demonstrateDeterminism();
    demonstrateAvalanche();
    demonstrateDomainSeparation();
    demonstrateIntegrity();
    demonstrateTruncatedCollision();
    demonstrateHashChain();
    demonstrateMerkleAggregation();
    demonstrateAlgorithmSizes();
    await demonstrateFileHashing();

    console.log('\nSecurity boundaries');
    console.log('  Hashing provides integrity fingerprints, not confidentiality.');
    console.log('  Plain SHA-256 is not suitable for password storage.');
    console.log('  Authentication requires HMAC or a digital signature when an attacker can modify data.');
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
