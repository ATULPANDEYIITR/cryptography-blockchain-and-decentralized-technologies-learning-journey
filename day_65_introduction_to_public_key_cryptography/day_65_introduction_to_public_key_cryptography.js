'use strict';

/*
 * Introduction to Public-Key Cryptography
 *
 * Node.js implementation using the built-in crypto module.
 *
 * Demonstrates:
 * - RSA-OAEP encryption and decryption
 * - RSA-PSS digital signatures
 * - ECDH key agreement
 * - HKDF key derivation
 * - SHA-256 fingerprints
 * - Public-key identity registration and revocation
 *
 * Run: node public_key_cryptography.js
 */

const crypto = require('node:crypto');

class CryptoOperationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CryptoOperationError';
    }
}

function generateRSAKeyPair() {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair(
            'rsa',
            {
                modulusLength: 3072,
                publicExponent: 65537,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            },
            (error, publicKey, privateKey) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve({ publicKey, privateKey });
            }
        );
    });
}

function encryptRSA(message, publicKey) {
    if (!Buffer.isBuffer(message)) {
        throw new TypeError('Message must be a Buffer.');
    }

    const key = crypto.createPublicKey(publicKey);

    if (key.asymmetricKeyType !== 'rsa') {
        throw new CryptoOperationError('RSA public key required.');
    }

    const modulusBytes =
        key.asymmetricKeyDetails.modulusLength / 8;

    const maximumMessageLength = modulusBytes - 2 * 32 - 2;

    if (message.length > maximumMessageLength) {
        throw new CryptoOperationError(
            'Message exceeds RSA-OAEP payload limit. Encrypt a data key instead.'
        );
    }

    return crypto.publicEncrypt(
        {
            key,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        message
    );
}

function decryptRSA(ciphertext, privateKey) {
    if (!Buffer.isBuffer(ciphertext)) {
        throw new TypeError('Ciphertext must be a Buffer.');
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

function signMessage(message, privateKey) {
    const signer = crypto.createSign('SHA256');

    signer.update(message);
    signer.end();

    return signer.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32
    });
}

function verifySignature(message, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256');

    verifier.update(message);
    verifier.end();

    return verifier.verify(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32
        },
        signature
    );
}

function generateECDHParticipant() {
    const exchange = crypto.createECDH('prime256v1');
    exchange.generateKeys();

    return exchange;
}

function deriveSessionKey(sharedSecret, salt, context) {
    return Buffer.from(
        crypto.hkdfSync(
            'sha256',
            sharedSecret,
            salt,
            Buffer.from(context),
            32
        )
    );
}

function fingerprint(publicKey) {
    const key = crypto.createPublicKey(publicKey);

    return crypto
        .createHash('sha256')
        .update(key.export({
            type: 'spki',
            format: 'der'
        }))
        .digest('hex');
}

class PublicKeyDirectory {
    #identities = new Map();

    register(identity, publicKey) {
        if (typeof identity !== 'string' || !identity.trim()) {
            throw new TypeError('Identity must be a nonempty string.');
        }

        if (this.#identities.has(identity)) {
            throw new CryptoOperationError('Identity already exists.');
        }

        const key = crypto.createPublicKey(publicKey);

        if (key.asymmetricKeyType !== 'rsa') {
            throw new CryptoOperationError('RSA key required.');
        }

        if (key.asymmetricKeyDetails.modulusLength < 2048) {
            throw new CryptoOperationError('RSA key is too small.');
        }

        this.#identities.set(identity, {
            publicKey: key,
            fingerprint: fingerprint(key),
            status: 'ACTIVE',
            registeredAt: new Date()
        });
    }

    lookup(identity) {
        const entry = this.#identities.get(identity);

        if (!entry || entry.status !== 'ACTIVE') {
            throw new CryptoOperationError(
                'Public key does not exist or is revoked.'
            );
        }

        return entry;
    }

    revoke(identity) {
        const entry = this.#identities.get(identity);

        if (!entry) {
            throw new CryptoOperationError('Unknown identity.');
        }

        entry.status = 'REVOKED';
    }

    list() {
        return Array.from(this.#identities.entries()).map(
            ([identity, entry]) => ({
                identity,
                fingerprint: entry.fingerprint,
                status: entry.status
            })
        );
    }
}

async function demonstrateRSA() {
    console.log('\n--- RSA-OAEP Encryption ---');

    const alice = await generateRSAKeyPair();

    const message = Buffer.from(
        'Confidential information for Alice'
    );

    const ciphertext = encryptRSA(message, alice.publicKey);
    const plaintext = decryptRSA(ciphertext, alice.privateKey);

    console.log('Original:', message.toString());
    console.log('Ciphertext length:', ciphertext.length);
    console.log('Recovered:', plaintext.toString());

    if (!plaintext.equals(message)) {
        throw new CryptoOperationError('RSA decryption failed.');
    }

    console.log('\n--- RSA-PSS Digital Signature ---');

    const signature = signMessage(message, alice.privateKey);

    console.log(
        'Signature valid:',
        verifySignature(message, signature, alice.publicKey)
    );

    console.log(
        'Modified message valid:',
        verifySignature(
            Buffer.from('Modified information'),
            signature,
            alice.publicKey
        )
    );

    if (!verifySignature(message, signature, alice.publicKey)) {
        throw new CryptoOperationError('Signature verification failed.');
    }

    return alice;
}

function demonstrateECDH() {
    console.log('\n--- Elliptic-Curve Diffie-Hellman ---');

    const alice = generateECDHParticipant();
    const bob = generateECDHParticipant();

    const alicePublic = alice.getPublicKey();
    const bobPublic = bob.getPublicKey();

    const aliceSecret = alice.computeSecret(bobPublic);
    const bobSecret = bob.computeSecret(alicePublic);

    if (!aliceSecret.equals(bobSecret)) {
        throw new CryptoOperationError('ECDH agreement failed.');
    }

    const salt = crypto.randomBytes(32);
    const context = 'public-key-cryptography-session-v1';

    const aliceSessionKey = deriveSessionKey(
        aliceSecret,
        salt,
        context
    );

    const bobSessionKey = deriveSessionKey(
        bobSecret,
        salt,
        context
    );

    console.log('Alice public key bytes:', alicePublic.length);
    console.log('Bob public key bytes:', bobPublic.length);
    console.log('Shared secret matches:', aliceSecret.equals(bobSecret));
    console.log(
        'Derived session keys match:',
        aliceSessionKey.equals(bobSessionKey)
    );

    return {
        aliceSessionKey,
        bobSessionKey
    };
}

async function demonstrateDirectory(alice) {
    console.log('\n--- Public-Key Directory ---');

    const directory = new PublicKeyDirectory();

    directory.register('alice@example.com', alice.publicKey);

    const registered = directory.lookup('alice@example.com');

    console.log('Fingerprint:', registered.fingerprint);
    console.log('Directory:', directory.list());

    directory.revoke('alice@example.com');

    try {
        directory.lookup('alice@example.com');
    } catch (error) {
        console.log('Revocation enforced:', error.message);
    }
}

async function runTests() {
    const alice = await generateRSAKeyPair();
    const message = Buffer.from('Cryptographic test');

    const ciphertext = encryptRSA(message, alice.publicKey);

    if (!decryptRSA(ciphertext, alice.privateKey).equals(message)) {
        throw new Error('RSA round-trip test failed.');
    }

    const signature = signMessage(message, alice.privateKey);

    if (!verifySignature(message, signature, alice.publicKey)) {
        throw new Error('Signature test failed.');
    }

    if (
        verifySignature(
            Buffer.from('Tampered'),
            signature,
            alice.publicKey
        )
    ) {
        throw new Error('Tampering was not detected.');
    }

    console.log('All cryptographic tests passed.');
}

async function main() {
    console.log('INTRODUCTION TO PUBLIC-KEY CRYPTOGRAPHY');

    await runTests();

    const alice = await demonstrateRSA();

    demonstrateECDH();

    await demonstrateDirectory(alice);

    console.log('\nSecurity considerations:');
    console.log('- Protect private keys from unauthorized access.');
    console.log('- Authenticate public keys before trusting them.');
    console.log('- Use authenticated protocols to prevent MITM attacks.');
    console.log('- Use hybrid encryption for large messages.');
    console.log('- Rotate and revoke compromised keys.');
}

main().catch(error => {
    console.error('Cryptographic operation failed:', error.message);
    process.exitCode = 1;
});
