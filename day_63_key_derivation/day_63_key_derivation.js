'use strict';

/*
 * Key derivation in blockchain and cryptography.
 *
 * Node.js standard library only:
 * - PBKDF2-HMAC-SHA256
 * - scrypt
 * - HKDF-SHA256
 * - HMAC domain separation
 * - hierarchical deterministic-style key derivation
 * - asynchronous processing and event-driven workflow
 *
 * This is an educational HD-style construction, not a BIP-32 implementation.
 */

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const EventEmitter = require('node:events');

const MAX_DEPTH = 32;
const MIN_SALT_LENGTH = 16;

class KDFError extends Error {
    constructor(message) {
        super(message);
        this.name = 'KDFError';
    }
}

function assertBuffer(value, name) {
    if (!Buffer.isBuffer(value)) {
        throw new KDFError(`${name} must be a Buffer`);
    }
}

function validateSalt(salt) {
    assertBuffer(salt, 'salt');

    if (salt.length < MIN_SALT_LENGTH) {
        throw new KDFError('salt must contain at least 16 bytes');
    }
}

function pbkdf2Sha256(password, salt, iterations = 310000, length = 32) {
    assertBuffer(password, 'password');
    validateSalt(salt);

    if (password.length === 0) {
        throw new KDFError('password must not be empty');
    }

    if (iterations < 100000) {
        throw new KDFError('PBKDF2 iteration count is below the security floor');
    }

    if (length < 16 || length > 64) {
        throw new KDFError('derived key length must be between 16 and 64 bytes');
    }

    return crypto.pbkdf2Sync(password, salt, iterations, length, 'sha256');
}

function pbkdf2Sha256Async(password, salt, iterations = 310000, length = 32) {
    assertBuffer(password, 'password');
    validateSalt(salt);

    if (password.length === 0) {
        throw new KDFError('password must not be empty');
    }

    if (iterations < 100000) {
        throw new KDFError('PBKDF2 iteration count is below the security floor');
    }

    return new Promise((resolve, reject) => {
        crypto.pbkdf2(
            password,
            salt,
            iterations,
            length,
            'sha256',
            (error, derivedKey) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(derivedKey);
                }
            }
        );
    });
}

function scryptSha256(
    password,
    salt,
    options = {}
) {
    assertBuffer(password, 'password');
    validateSalt(salt);

    if (password.length === 0) {
        throw new KDFError('password must not be empty');
    }

    const N = options.N ?? 16384;
    const r = options.r ?? 8;
    const p = options.p ?? 1;
    const length = options.length ?? 32;

    if (N < 16384 || (N & (N - 1)) !== 0) {
        throw new KDFError('scrypt N must be a power of two and at least 16384');
    }

    if (r <= 0 || p <= 0) {
        throw new KDFError('scrypt r and p must be positive');
    }

    return crypto.scryptSync(password, salt, length, {
        N,
        r,
        p,
        maxmem: 64 * 1024 * 1024
    });
}

function hmacSha256(key, data) {
    assertBuffer(key, 'key');
    assertBuffer(data, 'data');

    return crypto
        .createHmac('sha256', key)
        .update(data)
        .digest();
}

function hkdfSha256(ikm, salt, info, length = 32) {
    assertBuffer(ikm, 'ikm');
    validateSalt(salt);
    assertBuffer(info, 'info');

    if (ikm.length === 0) {
        throw new KDFError('HKDF input key material must not be empty');
    }

    if (length <= 0 || length > 255 * 32) {
        throw new KDFError('invalid HKDF output length');
    }

    const prk = hmacSha256(salt, ikm);
    const output = [];
    let previous = Buffer.alloc(0);

    for (let counter = 1; Buffer.concat(output).length < length; counter++) {
        previous = hmacSha256(
            prk,
            Buffer.concat([
                previous,
                info,
                Buffer.from([counter])
            ])
        );
        output.push(previous);
    }

    return Buffer.concat(output).subarray(0, length);
}

function encodePathComponent(index, hardened) {
    if (!Number.isInteger(index) || index < 0 || index >= 2 ** 31) {
        throw new KDFError('invalid derivation index');
    }

    const value = hardened ? index + 2 ** 31 : index;
    const result = Buffer.alloc(4);
    result.writeUInt32BE(value, 0);
    return result;
}

class HDNode {
    constructor(depth, index, key, chainCode, path) {
        this.depth = depth;
        this.index = index;
        this.key = Buffer.from(key);
        this.chainCode = Buffer.from(chainCode);
        this.path = path;
    }
}

class HDKeyTree {
    constructor(seed) {
        assertBuffer(seed, 'seed');

        if (seed.length < 16) {
            throw new KDFError('seed must contain at least 16 bytes');
        }

        const key = hmacSha256(
            Buffer.from('Blockchain HD Root', 'utf8'),
            seed
        );

        const chainCode = hmacSha256(
            Buffer.from('Blockchain Chain Code', 'utf8'),
            seed
        );

        this.root = new HDNode(0, 0, key, chainCode, 'm');
    }

    derive(parent, index, hardened = false) {
        if (parent.depth >= MAX_DEPTH) {
            throw new KDFError('maximum derivation depth exceeded');
        }

        const encoded = encodePathComponent(index, hardened);

        const context = Buffer.concat([
            Buffer.from('HD-NODE', 'ascii'),
            Buffer.from([parent.depth + 1]),
            encoded,
            parent.key
        ]);

        const childKey = hmacSha256(parent.chainCode, context);

        const childChainCode = hmacSha256(
            parent.key,
            Buffer.concat([
                Buffer.from('CHAIN', 'ascii'),
                context
            ])
        );

        const suffix = `${index}${hardened ? "'" : ""}`;

        return new HDNode(
            parent.depth + 1,
            index,
            childKey,
            childChainCode,
            `${parent.path}/${suffix}`
        );
    }

    derivePath(path) {
        if (path === 'm') {
            return this.root;
        }

        if (!path.startsWith('m/')) {
            throw new KDFError('path must begin with m/');
        }

        let node = this.root;

        for (const component of path.slice(2).split('/')) {
            if (!component) {
                throw new KDFError('empty path component');
            }

            const hardened = component.endsWith("'");
            const numeric = hardened
                ? component.slice(0, -1)
                : component;

            if (!/^\d+$/.test(numeric)) {
                throw new KDFError(`invalid path component: ${component}`);
            }

            node = this.derive(
                node,
                Number(numeric),
                hardened
            );
        }

        return node;
    }
}

function fingerprint(buffer) {
    return crypto
        .createHash('sha256')
        .update(buffer)
        .digest('hex')
        .slice(0, 16);
}

async function deriveWallet(passwordPhrase, network) {
    if (typeof passwordPhrase !== 'string' || passwordPhrase.trim() === '') {
        throw new KDFError('wallet phrase must not be empty');
    }

    if (!['mainnet', 'testnet'].includes(network)) {
        throw new KDFError('unsupported network');
    }

    const salt = crypto
        .createHash('sha256')
        .update(`wallet:${network}`)
        .digest();

    const seed = await pbkdf2Sha256Async(
        Buffer.from(passwordPhrase, 'utf8'),
        salt,
        310000,
        64
    );

    const tree = new HDKeyTree(seed);

    const account = tree.derivePath("m/44'/0'/0'");
    const external = tree.derive(account, 0);
    const address = tree.derive(external, 0);

    const signingKey = hkdfSha256(
        address.key,
        address.chainCode,
        Buffer.from('blockchain/signing-key/v1')
    );

    const encryptionKey = hkdfSha256(
        address.key,
        address.chainCode,
        Buffer.from('blockchain/storage-key/v1')
    );

    return {
        network,
        path: address.path,
        addressKeyFingerprint: fingerprint(address.key),
        signingKeyFingerprint: fingerprint(signingKey),
        encryptionKeyFingerprint: fingerprint(encryptionKey)
    };
}

class DerivationWorkflow extends EventEmitter {
    constructor() {
        super();
        this.completed = 0;
        this.failed = 0;
    }

    async run(name, operation) {
        this.emit('started', { name });

        try {
            const result = await operation();
            this.completed += 1;
            this.emit('completed', { name });
            return result;
        } catch (error) {
            this.failed += 1;
            this.emit('failed', {
                name,
                message: error.message
            });
            throw error;
        }
    }
}

async function writeAuditRecord() {
    const auditFile = 'kdf_audit.txt';

    await fs.writeFile(
        auditFile,
        [
            'operation=wallet-derivation',
            'secret_material_persisted=false',
            'raw_keys_logged=false',
            ''
        ].join('\n'),
        { encoding: 'utf8', mode: 0o600 }
    );

    const content = await fs.readFile(auditFile, 'utf8');

    if (!content.includes('secret_material_persisted=false')) {
        throw new KDFError('audit validation failed');
    }

    await fs.unlink(auditFile);
}

async function main() {
    const workflow = new DerivationWorkflow();

    workflow.on('started', ({ name }) => {
        console.log(`started: ${name}`);
    });

    workflow.on('completed', ({ name }) => {
        console.log(`completed: ${name}`);
    });

    workflow.on('failed', ({ name, message }) => {
        console.error(`failed: ${name}: ${message}`);
    });

    const salt = Buffer.from(
        '00112233445566778899aabbccddeeff',
        'hex'
    );

    const password = Buffer.from(
        'correct horse battery staple',
        'utf8'
    );

    const pbkdf = await workflow.run(
        'PBKDF2',
        () => pbkdf2Sha256Async(password, salt)
    );

    const scrypt = await workflow.run(
        'scrypt',
        () => Promise.resolve(scryptSha256(password, salt))
    );

    const hkdf = await workflow.run(
        'HKDF',
        () => Promise.resolve(
            hkdfSha256(
                pbkdf,
                salt,
                Buffer.from('blockchain/demo')
            )
        )
    );

    console.log('\nKDF results');
    console.log('PBKDF2:', pbkdf.toString('hex'));
    console.log('scrypt:', scrypt.toString('hex'));
    console.log('HKDF  :', hkdf.toString('hex'));

    const wallet = await workflow.run(
        'HD wallet derivation',
        () => deriveWallet(
            'legal winner thank year wave sausage worth useful legal winner thank yellow',
            'testnet'
        )
    );

    console.log('\nWallet derivation');
    console.table(wallet);

    await workflow.run(
        'non-secret audit',
        writeAuditRecord
    );

    console.log('\nWorkflow state');
    console.log({
        completed: workflow.completed,
        failed: workflow.failed
    });

    try {
        pbkdf2Sha256(Buffer.alloc(0), salt);
    } catch (error) {
        if (!(error instanceof KDFError)) {
            throw error;
        }
        console.log('\nRejected invalid empty password:', error.message);
    }

    console.log('\nSecurity controls');
    console.log('Unique salts prevent identical passwords from producing identical password-derived keys.');
    console.log('HKDF info strings separate signing and encryption key purposes.');
    console.log('Secret material is kept in memory and never written to the audit file.');
    console.log('This HD-style construction is not a substitute for a standardized wallet specification.');
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
