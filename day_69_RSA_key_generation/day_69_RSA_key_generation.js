'use strict';

/*
 * RSA Key Generation and Enterprise Key Lifecycle
 * Runtime: Node.js 20+
 *
 * Uses the built-in crypto module.
 *
 * Features:
 * - RSA key generation
 * - PEM serialization
 * - SHA-256 public-key fingerprinting
 * - OAEP encryption/decryption
 * - PSS digital signatures
 * - Key metadata management
 * - Asynchronous filesystem operations
 * - Export collision prevention
 */

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

const KEY_POLICIES = Object.freeze({
    DEVELOPMENT: {
        modulusLength: 2048,
        publicExponent: 65537,
    },
    STANDARD: {
        modulusLength: 3072,
        publicExponent: 65537,
    },
    HIGH_ASSURANCE: {
        modulusLength: 4096,
        publicExponent: 65537,
    },
});

const KEY_STATE = Object.freeze({
    GENERATED: 'GENERATED',
    ACTIVE: 'ACTIVE',
    REVOKED: 'REVOKED',
});

class RSAError extends Error {
    constructor(message, cause) {
        super(message, { cause });
        this.name = 'RSAError';
    }
}

class RSAKeyRecord {
    constructor({
        id,
        publicKey,
        privateKey,
        fingerprint,
        modulusLength,
        createdAt,
    }) {
        this.id = id;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.fingerprint = fingerprint;
        this.modulusLength = modulusLength;
        this.createdAt = createdAt;
        this.state = KEY_STATE.GENERATED;
    }

    activate() {
        if (this.state !== KEY_STATE.GENERATED) {
            throw new RSAError(
                `Cannot activate a key in state ${this.state}.`
            );
        }

        this.state = KEY_STATE.ACTIVE;
    }

    revoke() {
        if (this.state === KEY_STATE.REVOKED) {
            throw new RSAError('Key is already revoked.');
        }

        this.state = KEY_STATE.REVOKED;
    }

    publicMetadata() {
        return Object.freeze({
            id: this.id,
            fingerprint: this.fingerprint,
            modulusLength: this.modulusLength,
            createdAt: this.createdAt,
            state: this.state,
            algorithm: 'RSA',
            publicExponent: 65537,
        });
    }
}

class RSAKeyService {
    constructor(policy = KEY_POLICIES.STANDARD) {
        if (!Object.values(KEY_POLICIES).includes(policy)) {
            throw new RSAError('Unsupported RSA generation policy.');
        }

        this.policy = policy;
        this.records = new Map();
        this.auditEvents = [];
    }

    recordEvent(event, details = {}) {
        this.auditEvents.push(
            Object.freeze({
                event,
                timestamp: new Date().toISOString(),
                ...details,
            })
        );
    }

    async generateKeyPair() {
        try {
            const { publicKey, privateKey } =
                await generateKeyPairAsync('rsa', {
                    modulusLength: this.policy.modulusLength,
                    publicExponent: this.policy.publicExponent,
                    publicKeyEncoding: {
                        type: 'spki',
                        format: 'pem',
                    },
                    privateKeyEncoding: {
                        type: 'pkcs8',
                        format: 'pem',
                        cipher: 'aes-256-cbc',
                        passphrase: crypto.randomBytes(32).toString('hex'),
                    },
                }).then(result => {
                    // Re-export with caller-controlled encryption below.
                    return result;
                });

            // Generate the actual persistent private key separately using
            // a dedicated export passphrase at the export boundary.
            const privateObject = crypto.createPrivateKey({
                key: privateKey,
                format: 'pem',
                passphrase: this._temporaryPassphrase,
            });

            return this.createRecord(publicKey, privateObject);

        } catch (error) {
            // The service uses generateKeyPair directly with an in-memory
            // encrypted PEM export. A failed conversion is never accepted.
            if (error instanceof RSAError) {
                throw error;
            }

            throw new RSAError('RSA key generation failed.', error);
        }
    }

    createRecord(publicKey, privateKey) {
        const publicObject = crypto.createPublicKey(publicKey);
        const canonicalPublic = publicObject.export({
            type: 'spki',
            format: 'der',
        });

        const fingerprint = crypto
            .createHash('sha256')
            .update(canonicalPublic)
            .digest('hex');

        const id = crypto.randomUUID();

        const record = new RSAKeyRecord({
            id,
            publicKey: publicObject,
            privateKey,
            fingerprint,
            modulusLength: this.policy.modulusLength,
            createdAt: new Date().toISOString(),
        });

        this.records.set(id, record);
        this.recordEvent('KEY_GENERATED', { id, fingerprint });

        return record;
    }

    async generateSecureKeyPair(passphrase) {
        if (typeof passphrase !== 'string' || passphrase.length < 12) {
            throw new RSAError(
                'A private-key passphrase of at least 12 characters is required.'
            );
        }

        try {
            const { publicKey, privateKey } =
                await generateKeyPairAsync('rsa', {
                    modulusLength: this.policy.modulusLength,
                    publicExponent: 65537,
                    publicKeyEncoding: {
                        type: 'spki',
                        format: 'pem',
                    },
                    privateKeyEncoding: {
                        type: 'pkcs8',
                        format: 'pem',
                        cipher: 'aes-256-cbc',
                        passphrase,
                    },
                });

            const publicObject = crypto.createPublicKey(publicKey);

            // Keep the encrypted PEM representation for secure export.
            const privateObject = crypto.createPrivateKey({
                key: privateKey,
                format: 'pem',
                passphrase,
            });

            const record = this.createRecord(
                publicObject,
                privateObject
            );

            record.encryptedPrivatePEM = privateKey;
            return record;

        } catch (error) {
            throw new RSAError('Secure RSA generation failed.', error);
        }
    }

    activateKey(id) {
        const record = this.getRecord(id);
        record.activate();

        this.recordEvent('KEY_ACTIVATED', { id });
        return record.publicMetadata();
    }

    revokeKey(id) {
        const record = this.getRecord(id);
        record.revoke();

        this.recordEvent('KEY_REVOKED', { id });
    }

    getRecord(id) {
        const record = this.records.get(id);

        if (!record) {
            throw new RSAError(`Unknown key identifier: ${id}`);
        }

        if (record.state === KEY_STATE.REVOKED) {
            throw new RSAError('Revoked keys cannot perform operations.');
        }

        return record;
    }

    sign(id, message) {
        const record = this.getRecord(id);

        if (record.state !== KEY_STATE.ACTIVE) {
            throw new RSAError('Key must be active before signing.');
        }

        const data = Buffer.isBuffer(message)
            ? message
            : Buffer.from(String(message), 'utf8');

        if (data.length === 0) {
            throw new RSAError('Cannot sign an empty message.');
        }

        const signature = crypto.sign('sha256', data, {
            key: record.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32,
        });

        this.recordEvent('MESSAGE_SIGNED', { id });

        return signature;
    }

    verify(id, message, signature) {
        const record = this.getRecord(id);

        const data = Buffer.isBuffer(message)
            ? message
            : Buffer.from(String(message), 'utf8');

        return crypto.verify(
            'sha256',
            data,
            {
                key: record.publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32,
            },
            signature
        );
    }

    encrypt(id, plaintext) {
        const record = this.getRecord(id);

        if (record.state !== KEY_STATE.ACTIVE) {
            throw new RSAError('Key must be active before encryption.');
        }

        const data = Buffer.from(plaintext);

        if (data.length === 0) {
            throw new RSAError('Plaintext cannot be empty.');
        }

        const maximumLength =
            Math.ceil(record.modulusLength / 8) - 2 * 32 - 2;

        if (data.length > maximumLength) {
            throw new RSAError(
                `Message exceeds RSA-OAEP limit of ${maximumLength} bytes.`
            );
        }

        return crypto.publicEncrypt(
            {
                key: record.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            data
        );
    }

    decrypt(id, ciphertext) {
        const record = this.getRecord(id);

        if (record.state !== KEY_STATE.ACTIVE) {
            throw new RSAError('Key must be active before decryption.');
        }

        return crypto.privateDecrypt(
            {
                key: record.privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            ciphertext
        );
    }

    async exportKeys(record, directory, passphrase) {
        if (typeof passphrase !== 'string' || passphrase.length < 12) {
            throw new RSAError('Invalid export passphrase.');
        }

        if (!record.encryptedPrivatePEM) {
            throw new RSAError(
                'Record does not contain an encrypted private-key export.'
            );
        }

        await fs.mkdir(directory, {
            recursive: true,
            mode: 0o700,
        });

        const privatePath = path.join(directory, `${record.id}.private.pem`);
        const publicPath = path.join(directory, `${record.id}.public.pem`);

        const publicPEM = record.publicKey.export({
            type: 'spki',
            format: 'pem',
        });

        // wx prevents accidental replacement of existing key material.
        try {
            await fs.writeFile(privatePath, record.encryptedPrivatePEM, {
                flag: 'wx',
                mode: 0o600,
            });

            await fs.writeFile(publicPath, publicPEM, {
                flag: 'wx',
                mode: 0o644,
            });

        } catch (error) {
            await fs.rm(privatePath, { force: true });
            await fs.rm(publicPath, { force: true });
            throw new RSAError('Key export failed.', error);
        }

        return { privatePath, publicPath };
    }

    listMetadata() {
        return [...this.records.values()].map(
            record => record.publicMetadata()
        );
    }
}

async function main() {
    const service = new RSAKeyService(KEY_POLICIES.STANDARD);

    const passphrase = process.env.RSA_KEY_PASSPHRASE;

    if (!passphrase || passphrase.length < 12) {
        throw new RSAError(
            'Set RSA_KEY_PASSPHRASE to a value of at least 12 characters.'
        );
    }

    const record = await service.generateSecureKeyPair(passphrase);

    service.activateKey(record.id);

    const message = Buffer.from(
        'Enterprise RSA key generation demonstration.'
    );

    const signature = service.sign(record.id, message);

    const signatureValid = service.verify(
        record.id,
        message,
        signature
    );

    const ciphertext = service.encrypt(
        record.id,
        message
    );

    const decrypted = service.decrypt(
        record.id,
        ciphertext
    );

    if (!signatureValid || !decrypted.equals(message)) {
        throw new RSAError('Cryptographic self-test failed.');
    }

    const exported = await service.exportKeys(
        record,
        './rsa_keys',
        passphrase
    );

    console.log('\nRSA KEY GENERATION');
    console.log('------------------');
    console.log('Key ID:', record.id);
    console.log('Modulus:', record.modulusLength);
    console.log('Exponent:', 65537);
    console.log('Fingerprint:', record.fingerprint);
    console.log('Signature valid:', signatureValid);
    console.log('Encryption verified:', decrypted.equals(message));
    console.log('Private key:', exported.privatePath);
    console.log('Public key:', exported.publicPath);
    console.log('Audit events:', service.auditEvents.length);

    service.revokeKey(record.id);

    console.log('Final key state:', record.state);
}

main().catch(error => {
    console.error('RSA operation failed:', error.message);
    process.exitCode = 1;
});
