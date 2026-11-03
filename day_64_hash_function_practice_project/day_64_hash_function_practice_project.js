'use strict';

/*
 * Hash Functions Practice Project
 *
 * Node.js implementation featuring:
 * - SHA-256, SHA-512, SHA3-256 and SHA3-512
 * - Asynchronous streaming file hashing
 * - HMAC-SHA256 authentication
 * - PBKDF2-HMAC-SHA256 password derivation
 * - Concurrent file manifest creation
 * - File integrity verification
 *
 * Run:
 *   node hash_functions.js
 *   node hash_functions.js hash sha256 ./artifact.bin
 *   node hash_functions.js manifest ./releases ./manifest.json sha256
 *   node hash_functions.js verify ./releases ./manifest.json
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { promisify } = require('node:util');

const pbkdf2Async = promisify(crypto.pbkdf2);

const ALGORITHMS = new Set([
    'sha256',
    'sha512',
    'sha3-256',
    'sha3-512',
]);

const PBKDF2_ITERATIONS = 310000;
const MIN_PBKDF2_ITERATIONS = 100000;
const MAX_PBKDF2_ITERATIONS = 2000000;
const SALT_LENGTH = 16;
const DERIVED_KEY_LENGTH = 32;

class HashLabError extends Error {
    constructor(message) {
        super(message);
        this.name = 'HashLabError';
    }
}

function validateAlgorithm(algorithm) {
    if (typeof algorithm !== 'string') {
        throw new TypeError('Algorithm must be a string');
    }

    const normalized = algorithm.toLowerCase();

    if (!ALGORITHMS.has(normalized)) {
        throw new HashLabError(
            `Unsupported algorithm: ${algorithm}. ` +
            `Allowed algorithms: ${[...ALGORITHMS].join(', ')}`
        );
    }

    return normalized;
}

function hashBuffer(data, algorithm = 'sha256') {
    if (!Buffer.isBuffer(data)) {
        throw new TypeError('Hash input must be a Buffer');
    }

    const normalized = validateAlgorithm(algorithm);
    const hash = crypto.createHash(normalized);

    hash.update(data);

    return {
        algorithm: normalized,
        digest: hash.digest('hex'),
        bytesProcessed: data.length,
    };
}

async function hashFile(filePath, algorithm = 'sha256') {
    const normalized = validateAlgorithm(algorithm);
    const absolutePath = path.resolve(filePath);

    const fileInfo = await fs.promises.lstat(absolutePath);

    if (fileInfo.isSymbolicLink()) {
        throw new HashLabError('Symbolic links are not accepted');
    }

    if (!fileInfo.isFile()) {
        throw new HashLabError('Input must be a regular file');
    }

    const hash = crypto.createHash(normalized);
    let bytesProcessed = 0;

    const stream = fs.createReadStream(absolutePath, {
        highWaterMark: 1024 * 1024,
    });

    try {
        for await (const chunk of stream) {
            hash.update(chunk);
            bytesProcessed += chunk.length;
        }
    } catch (error) {
        stream.destroy();
        throw new HashLabError(
            `Unable to read ${absolutePath}: ${error.message}`
        );
    }

    return {
        algorithm: normalized,
        digest: hash.digest('hex'),
        bytesProcessed,
    };
}

function hmacSha256(data, secretKey) {
    if (!Buffer.isBuffer(data) || !Buffer.isBuffer(secretKey)) {
        throw new TypeError('HMAC data and key must be Buffers');
    }

    if (secretKey.length === 0) {
        throw new HashLabError('HMAC key cannot be empty');
    }

    return crypto
        .createHmac('sha256', secretKey)
        .update(data)
        .digest('hex');
}

function verifyHmacSha256(data, secretKey, suppliedHex) {
    if (typeof suppliedHex !== 'string') {
        return false;
    }

    if (!/^[0-9a-f]{64}$/i.test(suppliedHex)) {
        return false;
    }

    const expected = Buffer.from(
        hmacSha256(data, secretKey),
        'hex'
    );

    const supplied = Buffer.from(suppliedHex, 'hex');

    if (expected.length !== supplied.length) {
        return false;
    }

    return crypto.timingSafeEqual(expected, supplied);
}

async function hashPassword(password, iterations = PBKDF2_ITERATIONS) {
    if (typeof password !== 'string' || password.length === 0) {
        throw new HashLabError('Password must be a non-empty string');
    }

    if (
        !Number.isSafeInteger(iterations) ||
        iterations < MIN_PBKDF2_ITERATIONS ||
        iterations > MAX_PBKDF2_ITERATIONS
    ) {
        throw new HashLabError('PBKDF2 iteration count is outside the allowed range');
    }

    const salt = crypto.randomBytes(SALT_LENGTH);

    const derivedKey = await pbkdf2Async(
        password,
        salt,
        iterations,
        DERIVED_KEY_LENGTH,
        'sha256'
    );

    return [
        'pbkdf2_sha256',
        iterations,
        salt.toString('hex'),
        derivedKey.toString('hex'),
    ].join('$');
}

async function verifyPassword(password, encodedRecord) {
    if (typeof password !== 'string' || typeof encodedRecord !== 'string') {
        return false;
    }

    try {
        const parts = encodedRecord.split('$');

        if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') {
            return false;
        }

        const iterations = Number(parts[1]);

        if (
            !Number.isSafeInteger(iterations) ||
            iterations < MIN_PBKDF2_ITERATIONS ||
            iterations > MAX_PBKDF2_ITERATIONS
        ) {
            return false;
        }

        if (!/^[0-9a-f]{32}$/i.test(parts[2])) {
            return false;
        }

        if (!/^[0-9a-f]{64}$/i.test(parts[3])) {
            return false;
        }

        const salt = Buffer.from(parts[2], 'hex');
        const expected = Buffer.from(parts[3], 'hex');

        const actual = await pbkdf2Async(
            password,
            salt,
            iterations,
            DERIVED_KEY_LENGTH,
            'sha256'
        );

        return crypto.timingSafeEqual(expected, actual);

    } catch {
        return false;
    }
}

async function walkFiles(root, excludedPaths = new Set()) {
    const rootReal = await fs.promises.realpath(root);
    const files = [];

    async function visit(directory) {
        const entries = await fs.promises.readdir(directory, {
            withFileTypes: true,
        });

        entries.sort((a, b) => a.name.localeCompare(b.name));

        for (const entry of entries) {
            const absolutePath = path.join(directory, entry.name);

            if (excludedPaths.has(path.resolve(absolutePath))) {
                continue;
            }

            if (entry.isSymbolicLink()) {
                continue;
            }

            if (entry.isDirectory()) {
                await visit(absolutePath);
                continue;
            }

            if (!entry.isFile()) {
                continue;
            }

            const relativePath = path
                .relative(rootReal, absolutePath)
                .split(path.sep)
                .join('/');

            files.push({
                absolutePath,
                relativePath,
            });
        }
    }

    await visit(rootReal);

    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));

    return files;
}

async function mapWithConcurrency(items, concurrency, task) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
        throw new RangeError('Concurrency must be a positive integer');
    }

    const results = new Array(items.length);
    let nextIndex = 0;

    async function worker() {
        while (true) {
            const index = nextIndex++;

            if (index >= items.length) {
                return;
            }

            results[index] = await task(items[index], index);
        }
    }

    const workerCount = Math.min(concurrency, items.length);

    await Promise.all(
        Array.from({ length: workerCount }, () => worker())
    );

    return results;
}

async function createManifest(
    rootDirectory,
    algorithm = 'sha256',
    excludedPaths = new Set()
) {
    const normalized = validateAlgorithm(algorithm);
    const root = await fs.promises.realpath(rootDirectory);

    const rootInfo = await fs.promises.stat(root);

    if (!rootInfo.isDirectory()) {
        throw new HashLabError('Manifest root must be a directory');
    }

    const files = await walkFiles(root, excludedPaths);

    const entries = await mapWithConcurrency(
        files,
        4,
        async (file) => {
            const result = await hashFile(file.absolutePath, normalized);

            return {
                path: file.relativePath,
                size: result.bytesProcessed,
                digest: result.digest,
            };
        }
    );

    return {
        formatVersion: 1,
        algorithm: normalized,
        files: entries,
    };
}

async function writeManifest(rootDirectory, outputFile, algorithm = 'sha256') {
    const output = path.resolve(outputFile);
    const parent = path.dirname(output);

    await fs.promises.mkdir(parent, { recursive: true });

    const manifest = await createManifest(
        rootDirectory,
        algorithm,
        new Set([output])
    );

    const temporary = path.join(
        parent,
        `.${path.basename(output)}.${process.pid}.` +
        `${crypto.randomBytes(6).toString('hex')}.tmp`
    );

    try {
        await fs.promises.writeFile(
            temporary,
            JSON.stringify(manifest, null, 2) + '\n',
            {
                encoding: 'utf8',
                flag: 'wx',
                mode: 0o600,
            }
        );

        await fs.promises.rename(temporary, output);
        return manifest.files.length;

    } catch (error) {
        await fs.promises.rm(temporary, { force: true }).catch(() => {});
        throw error;
    }
}

function resolveManifestPath(root, relativePath) {
    if (
        typeof relativePath !== 'string' ||
        relativePath.length === 0 ||
        relativePath.includes('\\') ||
        path.posix.isAbsolute(relativePath) ||
        path.win32.isAbsolute(relativePath)
    ) {
        throw new HashLabError(`Invalid manifest path: ${relativePath}`);
    }

    const parts = relativePath.split('/');

    if (parts.some(part => part === '' || part === '.' || part === '..')) {
        throw new HashLabError(`Unsafe manifest path: ${relativePath}`);
    }

    const candidate = path.resolve(root, ...parts);
    const relative = path.relative(root, candidate);

    if (
        relative === '..' ||
        relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relative)
    ) {
        throw new HashLabError(`Path escapes root: ${relativePath}`);
    }

    return candidate;
}

async function verifyManifest(rootDirectory, manifestFile) {
    const root = await fs.promises.realpath(rootDirectory);
    const parsed = JSON.parse(
        await fs.promises.readFile(manifestFile, 'utf8')
    );

    if (
        !parsed ||
        parsed.formatVersion !== 1 ||
        !Array.isArray(parsed.files)
    ) {
        throw new HashLabError('Invalid or unsupported manifest');
    }

    const algorithm = validateAlgorithm(parsed.algorithm);
    const seenPaths = new Set();
    const results = [];

    for (const entry of parsed.files) {
        if (!entry || typeof entry !== 'object') {
            throw new HashLabError('Invalid manifest entry');
        }

        const relativePath = entry.path;

        if (seenPaths.has(relativePath)) {
            throw new HashLabError(`Duplicate manifest path: ${relativePath}`);
        }

        seenPaths.add(relativePath);

        if (
            typeof entry.digest !== 'string' ||
            !/^[0-9a-f]+$/i.test(entry.digest)
        ) {
            throw new HashLabError(`Invalid digest: ${relativePath}`);
        }

        const expectedDigestLength = crypto
            .createHash(algorithm)
            .digest()
            .length;

        if (Buffer.from(entry.digest, 'hex').length !== expectedDigestLength) {
            throw new HashLabError(`Wrong digest length: ${relativePath}`);
        }

        if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
            throw new HashLabError(`Invalid file size: ${relativePath}`);
        }

        try {
            const candidate = resolveManifestPath(root, relativePath);
            const info = await fs.promises.lstat(candidate);

            if (info.isSymbolicLink() || !info.isFile()) {
                throw new HashLabError('Manifest entry is not a regular file');
            }

            const realFile = await fs.promises.realpath(candidate);
            const realRelative = path.relative(root, realFile);

            if (
                realRelative === '..' ||
                realRelative.startsWith(`..${path.sep}`) ||
                path.isAbsolute(realRelative)
            ) {
                throw new HashLabError('File resolves outside the manifest root');
            }

            const actual = await hashFile(candidate, algorithm);
            const sizeMatches = actual.bytesProcessed === entry.size;
            const digestMatches = actual.digest === entry.digest.toLowerCase();

            results.push({
                path: relativePath,
                passed: sizeMatches && digestMatches,
                error: sizeMatches && digestMatches
                    ? null
                    : 'Size or digest mismatch',
                actualDigest: actual.digest,
            });

        } catch (error) {
            results.push({
                path: relativePath,
                passed: false,
                error: error.message,
                actualDigest: null,
            });
        }
    }

    return results;
}

async function runSelfTests() {
    assert.equal(
        hashBuffer(Buffer.from('abc'), 'sha256').digest,
        'ba7816bf8f01cfea414140de5dae2223' +
        'b00361a396177a9cb410ff61f20015ad'
    );

    assert.equal(
        hashBuffer(Buffer.from('abc'), 'sha3-256').digest,
        '3a985da74fe225b2045c172d6bd390bd' +
        '855f086e3e9d525b46bfe24511431532'
    );

    const key = Buffer.alloc(20, 0x0b);
    const message = Buffer.from('Hi There');

    const expectedHmac =
        'b0344c61d8db38535ca8afceaf0bf12b' +
        '881dc200c9833da726e9376c2e32cff7';

    const signature = hmacSha256(message, key);

    assert.equal(signature, expectedHmac);
    assert.equal(verifyHmacSha256(message, key, signature), true);
    assert.equal(
        verifyHmacSha256(Buffer.from('Changed'), key, signature),
        false
    );

    const passwordRecord = await hashPassword('Practice-Password-2026');

    assert.equal(
        await verifyPassword('Practice-Password-2026', passwordRecord),
        true
    );

    assert.equal(
        await verifyPassword('Incorrect-Password', passwordRecord),
        false
    );

    assert.equal(hashBuffer(Buffer.alloc(0)).bytesProcessed, 0);
}

async function runDemo() {
    await runSelfTests();

    console.log('Hash Functions Practice Project');
    console.log('================================');

    const sample = Buffer.from(
        'release=2.4.0;component=payment-service',
        'utf8'
    );

    console.log('\nDigest examples:');

    for (const algorithm of ALGORITHMS) {
        const result = hashBuffer(sample, algorithm);
        console.log(`${algorithm.padEnd(9)} ${result.digest}`);
    }

    console.log('\nHMAC demonstration:');

    const key = crypto.randomBytes(32);
    const signature = hmacSha256(sample, key);

    console.log(`Signature: ${signature}`);
    console.log(
        'Original message:',
        verifyHmacSha256(sample, key, signature)
    );
    console.log(
        'Modified message:',
        verifyHmacSha256(
            Buffer.concat([sample, Buffer.from(';changed=true')]),
            key,
            signature
        )
    );

    console.log('\nPassword derivation demonstration:');

    const passwordRecord = await hashPassword('Practice-Password-2026');

    console.log(`Stored representation: ${passwordRecord}`);
    console.log(
        'Correct password:',
        await verifyPassword('Practice-Password-2026', passwordRecord)
    );
    console.log(
        'Incorrect password:',
        await verifyPassword('Wrong-Password', passwordRecord)
    );

    console.log('\nAll known-answer tests passed.');
}

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    try {
        if (!command || command === 'demo') {
            await runDemo();
            return 0;
        }

        if (command === 'hash') {
            if (args.length !== 3) {
                throw new HashLabError(
                    'Usage: hash <algorithm> <file>'
                );
            }

            const result = await hashFile(args[2], args[1]);

            console.log(`Algorithm: ${result.algorithm}`);
            console.log(`File: ${path.resolve(args[2])}`);
            console.log(`Bytes: ${result.bytesProcessed}`);
            console.log(`Digest: ${result.digest}`);

            return 0;
        }

        if (command === 'manifest') {
            if (args.length < 3 || args.length > 4) {
                throw new HashLabError(
                    'Usage: manifest <root> <output> [algorithm]'
                );
            }

            const algorithm = args[3] || 'sha256';

            const count = await writeManifest(
                args[1],
                args[2],
                algorithm
            );

            console.log(`Manifest created: ${args[2]}`);
            console.log(`Algorithm: ${algorithm}`);
            console.log(`Files processed: ${count}`);

            return 0;
        }

        if (command === 'verify') {
            if (args.length !== 3) {
                throw new HashLabError(
                    'Usage: verify <root> <manifest>'
                );
            }

            const results = await verifyManifest(args[1], args[2]);

            let passed = 0;
            let failed = 0;

            for (const result of results) {
                if (result.passed) {
                    passed++;
                    console.log(`[PASS] ${result.path}`);
                } else {
                    failed++;
                    console.log(`[FAIL] ${result.path}: ${result.error}`);
                }
            }

            console.log(`\nVerified: ${passed}`);
            console.log(`Failed: ${failed}`);

            return failed === 0 ? 0 : 1;
        }

        throw new HashLabError(
            'Unknown command. Use demo, hash, manifest or verify.'
        );

    } catch (error) {
        console.error(`Error: ${error.message}`);
        return 2;
    }
}

main().then(
    code => {
        process.exitCode = code;
    },
    error => {
        console.error(`Unexpected failure: ${error.message}`);
        process.exitCode = 2;
    }
);
