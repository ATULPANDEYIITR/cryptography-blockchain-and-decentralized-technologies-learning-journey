'use strict';

/**
 * Public Keys and Private Keys
 *
 * Node.js implementation using the built-in crypto module.
 *
 * Demonstrates:
 * - RSA-OAEP encryption and decryption
 * - RSA-PSS digital signatures
 * - Ed25519 signatures
 * - X25519 key agreement
 * - SHA-256 key fingerprints
 * - Public-key import and export
 * - Event-driven key lifecycle management
 * - Policy enforcement and validation
 *
 * Run: node public-keys.js
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const assert = require('node:assert/strict');


class CryptoError extends Error {
    constructor(message, code = 'CRYPTO_ERROR') {
        super(message);
        this.name = 'CryptoError';
        this.code = code;
    }
}


const KeyStatus = Object.freeze({
    ACTIVE: 'ACTIVE',
    ROTATED: 'ROTATED',
    REVOKED: 'REVOKED',
    EXPIRED: 'EXPIRED'
});


const KeyPurpose = Object.freeze({
    ENCRYPTION: 'ENCRYPTION',
    SIGNING: 'SIGNING',
    KEY_AGREEMENT: 'KEY_AGREEMENT'
});


function validateNonEmptyString(value, field) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new TypeError(`${field} must be a non-empty string.`);
    }
}


function fingerprint(publicKey) {
    if (!publicKey || publicKey.type !== 'public') {
        throw new CryptoError('A public key is required.');
    }

    const der = publicKey.export({
        type: 'spki',
        format: 'der'
    });

    return crypto
        .createHash('sha256')
        .update(der)
        .digest('hex');
}


// ============================================================
// RSA encryption service
// ============================================================

class RSAEncryptionService {

    constructor(modulusLength = 2048) {
        if (!Number.isInteger(modulusLength) || modulusLength < 2048) {
            throw new RangeError(
                'RSA modulus must be at least 2048 bits.'
            );
        }

        this.modulusLength = modulusLength;
    }

    generateKeyPair() {
        const pair = crypto.generateKeyPairSync('rsa', {
            modulusLength: this.modulusLength,
            publicExponent: 65537,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        return Object.freeze({
            publicKey: crypto.createPublicKey(pair.publicKey),
            privateKey: crypto.createPrivateKey(pair.privateKey),
            algorithm: 'RSA-OAEP-SHA256'
        });
    }

    encrypt(message, publicKey) {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError('Message must be a Buffer.');
        }

        if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'rsa') {
            throw new CryptoError('Invalid RSA public key.');
        }

        const details = publicKey.asymmetricKeyDetails;

        if (!details || details.modulusLength < 2048) {
            throw new CryptoError('RSA key is below the security policy.');
        }

        const hashLength = 32;
        const maximumLength =
            Math.ceil(details.modulusLength / 8) - 2 * hashLength - 2;

        if (message.length > maximumLength) {
            throw new CryptoError(
                `Message exceeds OAEP limit of ${maximumLength} bytes.`
            );
        }

        return crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            message
        );
    }

    decrypt(ciphertext, privateKey) {
        if (!Buffer.isBuffer(ciphertext)) {
            throw new TypeError('Ciphertext must be a Buffer.');
        }

        if (
            privateKey.type !== 'private' ||
            privateKey.asymmetricKeyType !== 'rsa'
        ) {
            throw new CryptoError('Invalid RSA private key.');
        }

        return crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            ciphertext
        );
    }
}


// ============================================================
// RSA-PSS signature service
// ============================================================

class RSASignatureService {

    sign(message, privateKey) {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError('Message must be a Buffer.');
        }

        if (
            privateKey.type !== 'private' ||
            privateKey.asymmetricKeyType !== 'rsa'
        ) {
            throw new CryptoError('Invalid signing private key.');
        }

        return crypto.sign('sha256', message, {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        });
    }

    verify(message, signature, publicKey) {
        if (!Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) {
            throw new TypeError('Message and signature must be Buffers.');
        }

        if (
            publicKey.type !== 'public' ||
            publicKey.asymmetricKeyType !== 'rsa'
        ) {
            throw new CryptoError('Invalid verification public key.');
        }

        return crypto.verify('sha256', message, {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }, signature);
    }
}


// ============================================================
// Ed25519 signature service
// ============================================================

class Ed25519Service {

    generateKeyPair() {
        const pair = crypto.generateKeyPairSync('ed25519');

        return Object.freeze({
            publicKey: pair.publicKey,
            privateKey: pair.privateKey
        });
    }

    sign(message, privateKey) {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError('Message must be a Buffer.');
        }

        return crypto.sign(null, message, privateKey);
    }

    verify(message, signature, publicKey) {
        if (!Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) {
            throw new TypeError('Invalid signature input.');
        }

        return crypto.verify(
            null,
            message,
            publicKey,
            signature
        );
    }
}


// ============================================================
// X25519 key agreement
// ============================================================

class X25519Service {

    generateKeyPair() {
        const pair = crypto.generateKeyPairSync('x25519');

        return Object.freeze({
            publicKey: pair.publicKey,
            privateKey: pair.privateKey
        });
    }

    deriveSharedSecret(privateKey, peerPublicKey) {
        if (
            privateKey.asymmetricKeyType !== 'x25519' ||
            peerPublicKey.asymmetricKeyType !== 'x25519'
        ) {
            throw new CryptoError('Both keys must use X25519.');
        }

        const sharedSecret = crypto.diffieHellman({
            privateKey,
            publicKey: peerPublicKey
        });

        // Reject the all-zero result, which can indicate a low-order input.
        if (sharedSecret.every(byte => byte === 0)) {
            throw new CryptoError('Invalid X25519 shared secret.');
        }

        return sharedSecret;
    }

    deriveApplicationKey(sharedSecret, context) {
        validateNonEmptyString(context, 'Context');

        // HKDF derives an application-specific symmetric key.
        return Buffer.from(
            crypto.hkdfSync(
                'sha256',
                sharedSecret,
                Buffer.alloc(32, 0),
                Buffer.from(context, 'utf8'),
                32
            )
        );
    }
}


// ============================================================
// AES-256-GCM symmetric encryption
// ============================================================

class AuthenticatedEncryptionService {

    encrypt(plaintext, key) {
        if (!Buffer.isBuffer(plaintext) || key.length !== 32) {
            throw new TypeError('AES-256-GCM requires a 32-byte key.');
        }

        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        const ciphertext = Buffer.concat([
            cipher.update(plaintext),
            cipher.final()
        ]);

        return Object.freeze({
            iv,
            ciphertext,
            tag: cipher.getAuthTag()
        });
    }

    decrypt(envelope, key) {
        if (
            !Buffer.isBuffer(key) ||
            key.length !== 32 ||
            !Buffer.isBuffer(envelope.iv) ||
            envelope.iv.length !== 12 ||
            !Buffer.isBuffer(envelope.tag) ||
            envelope.tag.length !== 16 ||
            !Buffer.isBuffer(envelope.ciphertext)
        ) {
            throw new CryptoError('Invalid encrypted envelope.');
        }

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            envelope.iv
        );

        decipher.setAuthTag(envelope.tag);

        return Buffer.concat([
            decipher.update(envelope.ciphertext),
            decipher.final()
        ]);
    }
}


// ============================================================
// Key lifecycle registry
// ============================================================

class KeyRegistry extends EventEmitter {

    #records = new Map();

    register({
        owner,
        purpose,
        publicKey,
        validityDays = 365
    }) {
        validateNonEmptyString(owner, 'Owner');

        if (!Object.values(KeyPurpose).includes(purpose)) {
            throw new CryptoError('Unsupported key purpose.');
        }

        if (
            !Number.isInteger(validityDays) ||
            validityDays < 1 ||
            validityDays > 3650
        ) {
            throw new RangeError('Invalid key validity period.');
        }

        const id = crypto.randomUUID();
        const keyFingerprint = fingerprint(publicKey);

        for (const existing of this.#records.values()) {
            if (
                existing.fingerprint === keyFingerprint &&
                existing.status !== KeyStatus.REVOKED
            ) {
                throw new CryptoError('Public key is already registered.');
            }
        }

        const now = new Date();

        const record = {
            id,
            owner,
            purpose,
            fingerprint: keyFingerprint,
            algorithm: publicKey.asymmetricKeyType,
            createdAt: now,
            expiresAt: new Date(
                now.getTime() + validityDays * 86400000
            ),
            status: KeyStatus.ACTIVE
        };

        this.#records.set(id, record);

        this.emit('key:registered', this.publicRecord(record));

        return this.publicRecord(record);
    }

    publicRecord(record) {
        // Private key material is never stored in registry records.
        return Object.freeze({
            id: record.id,
            owner: record.owner,
            purpose: record.purpose,
            fingerprint: record.fingerprint,
            algorithm: record.algorithm,
            createdAt: record.createdAt.toISOString(),
            expiresAt: record.expiresAt.toISOString(),
            status: record.status
        });
    }

    get(id) {
        const record = this.#records.get(id);

        if (!record) {
            throw new CryptoError('Key record not found.', 'NOT_FOUND');
        }

        return this.publicRecord(record);
    }

    assertUsable(id, expectedPurpose) {
        const record = this.#records.get(id);

        if (!record) {
            throw new CryptoError('Unknown key.', 'NOT_FOUND');
        }

        if (record.status !== KeyStatus.ACTIVE) {
            throw new CryptoError(
                `Key is not active: ${record.status}`
            );
        }

        if (Date.now() >= record.expiresAt.getTime()) {
            record.status = KeyStatus.EXPIRED;

            this.emit('key:expired', this.publicRecord(record));

            throw new CryptoError('Key has expired.');
        }

        if (record.purpose !== expectedPurpose) {
            throw new CryptoError('Key purpose mismatch.');
        }

        return true;
    }

    rotate(id) {
        const record = this.#records.get(id);

        if (!record || record.status !== KeyStatus.ACTIVE) {
            throw new CryptoError('Only active keys can be rotated.');
        }

        record.status = KeyStatus.ROTATED;

        this.emit('key:rotated', this.publicRecord(record));

        return this.publicRecord(record);
    }

    revoke(id, reason) {
        const record = this.#records.get(id);

        if (!record || record.status === KeyStatus.REVOKED) {
            throw new CryptoError('Key cannot be revoked.');
        }

        validateNonEmptyString(reason, 'Revocation reason');

        record.status = KeyStatus.REVOKED;

        this.emit('key:revoked', {
            ...this.publicRecord(record),
            reason
        });
    }

    listByOwner(owner) {
        return [...this.#records.values()]
            .filter(record => record.owner === owner)
            .map(record => this.publicRecord(record));
    }
}


// ============================================================
// Public-key serialization
// ============================================================

function exportPublicKey(publicKey) {
    if (publicKey.type !== 'public') {
        throw new CryptoError('Only public keys may be exported.');
    }

    return publicKey.export({
        type: 'spki',
        format: 'pem'
    });
}


function importPublicKey(pem) {
    validateNonEmptyString(pem, 'PEM key');

    const key = crypto.createPublicKey(pem);

    if (key.type !== 'public') {
        throw new CryptoError('Imported object is not a public key.');
    }

    return key;
}


// ============================================================
// Demonstration and tests
// ============================================================

async function main() {

    console.log('PUBLIC KEYS AND PRIVATE KEYS');
    console.log('='.repeat(60));

    const rsa = new RSAEncryptionService(2048);
    const signatures = new RSASignatureService();
    const ed25519 = new Ed25519Service();
    const x25519 = new X25519Service();
    const aes = new AuthenticatedEncryptionService();

    // 1. RSA encryption.
    const rsaKeys = rsa.generateKeyPair();

    const message = Buffer.from(
        'Confidential financial transaction',
        'utf8'
    );

    const ciphertext = rsa.encrypt(
        message,
        rsaKeys.publicKey
    );

    const decrypted = rsa.decrypt(
        ciphertext,
        rsaKeys.privateKey
    );

    assert.deepEqual(decrypted, message);

    console.log('\nRSA-OAEP');
    console.log('Ciphertext length:', ciphertext.length);
    console.log('Decryption successful:', decrypted.equals(message));

    // 2. RSA digital signatures.
    const signature = signatures.sign(
        message,
        rsaKeys.privateKey
    );

    assert.equal(
        signatures.verify(message, signature, rsaKeys.publicKey),
        true
    );

    assert.equal(
        signatures.verify(
            Buffer.from('Modified transaction'),
            signature,
            rsaKeys.publicKey
        ),
        false
    );

    console.log('\nRSA-PSS');
    console.log('Original message valid:', true);
    console.log(
        'Modified message valid:',
        signatures.verify(
            Buffer.from('Modified transaction'),
            signature,
            rsaKeys.publicKey
        )
    );

    // 3. Ed25519 signatures.
    const edKeys = ed25519.generateKeyPair();

    const edSignature = ed25519.sign(
        message,
        edKeys.privateKey
    );

    assert.equal(
        ed25519.verify(message, edSignature, edKeys.publicKey),
        true
    );

    console.log('\nED25519');
    console.log('Signature verified:', true);

    // 4. X25519 key agreement.
    const alice = x25519.generateKeyPair();
    const bob = x25519.generateKeyPair();

    const aliceSecret = x25519.deriveSharedSecret(
        alice.privateKey,
        bob.publicKey
    );

    const bobSecret = x25519.deriveSharedSecret(
        bob.privateKey,
        alice.publicKey
    );

    assert.deepEqual(aliceSecret, bobSecret);

    const aliceApplicationKey = x25519.deriveApplicationKey(
        aliceSecret,
        'transaction-session-v1'
    );

    const bobApplicationKey = x25519.deriveApplicationKey(
        bobSecret,
        'transaction-session-v1'
    );

    assert.deepEqual(aliceApplicationKey, bobApplicationKey);

    console.log('\nX25519 AND HKDF');
    console.log('Shared secret matches:', true);

    // 5. Hybrid encryption.
    const envelope = aes.encrypt(message, aliceApplicationKey);

    const recovered = aes.decrypt(envelope, bobApplicationKey);

    assert.deepEqual(recovered, message);

    console.log('\nHYBRID ENCRYPTION');
    console.log('AES-256-GCM authentication successful:', true);

    // 6. Key registry.
    const registry = new KeyRegistry();

    registry.on('key:registered', record => {
        console.log('\nEvent: key registered');
        console.log('Fingerprint:', record.fingerprint);
    });

    registry.on('key:rotated', record => {
        console.log('Event: key rotated:', record.id);
    });

    registry.on('key:revoked', record => {
        console.log('Event: key revoked:', record.reason);
    });

    const registered = registry.register({
        owner: 'payment-service',
        purpose: KeyPurpose.SIGNING,
        publicKey: rsaKeys.publicKey,
        validityDays: 365
    });

    registry.assertUsable(
        registered.id,
        KeyPurpose.SIGNING
    );

    registry.rotate(registered.id);

    assert.throws(
        () => registry.assertUsable(
            registered.id,
            KeyPurpose.SIGNING
        ),
        CryptoError
    );

    // 7. Public-key import and export.
    const exported = exportPublicKey(rsaKeys.publicKey);
    const imported = importPublicKey(exported);

    assert.equal(
        fingerprint(imported),
        fingerprint(rsaKeys.publicKey)
    );

    console.log('\nPUBLIC KEY FINGERPRINT');
    console.log(fingerprint(imported));

    // 8. Revocation.
    const encryptionRecord = registry.register({
        owner: 'document-service',
        purpose: KeyPurpose.ENCRYPTION,
        publicKey: edKeys.publicKey
    });

    registry.revoke(
        encryptionRecord.id,
        'Compromised demonstration credential'
    );

    console.log('\nREGISTERED KEYS');
    console.log(registry.listByOwner('payment-service'));

    // 9. Tamper detection.
    const corrupted = {
        ...envelope,
        ciphertext: Buffer.from(envelope.ciphertext)
    };

    corrupted.ciphertext[0] ^= 1;

    assert.throws(
        () => aes.decrypt(corrupted, bobApplicationKey)
    );

    console.log('\nTampered ciphertext rejected.');

    // 10. Invalid inputs.
    assert.throws(
        () => rsa.encrypt(Buffer.alloc(500), rsaKeys.publicKey),
        CryptoError
    );

    assert.throws(
        () => importPublicKey('invalid-key'),
        Error
    );

    console.log('\nAll cryptographic demonstrations passed.');
}


main().catch(error => {
    console.error('Execution failed:', error.message);
    process.exitCode = 1;
});
