'use strict';

/**
 * Comparing RSA, Diffie-Hellman and ECC.
 *
 * Node.js implementation using:
 * - Built-in crypto module
 * - RSA-3072 key generation and RSA-PSS signatures
 * - Finite-field Diffie-Hellman using a standardized group
 * - ECDH using prime256v1
 * - HKDF key derivation
 * - AES-256-GCM authenticated encryption
 * - Event-driven cryptographic policy evaluation
 *
 * Requires Node.js 18 or later.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');


// ============================================================
// 1. CRYPTOGRAPHIC DOMAIN
// ============================================================

const Algorithm = Object.freeze({
    RSA: 'RSA',
    DH: 'DIFFIE_HELLMAN',
    ECC: 'ECC'
});

const Purpose = Object.freeze({
    ENCRYPTION: 'ENCRYPTION',
    KEY_AGREEMENT: 'KEY_AGREEMENT',
    SIGNATURE: 'DIGITAL_SIGNATURE'
});

const ALGORITHM_PROFILES = Object.freeze([
    {
        name: 'RSA',
        foundation: 'Integer factorization',
        capabilities: ['Encryption', 'Digital signatures'],
        security: 'RSA-3072: approximately 128-bit classical security',
        parameters: '3072-bit or larger modulus'
    },
    {
        name: 'Diffie-Hellman',
        foundation: 'Finite-field discrete logarithm',
        capabilities: ['Key agreement'],
        security: 'Approximately 128-bit with suitable 3072-bit parameters',
        parameters: '3072-bit or larger finite-field group'
    },
    {
        name: 'ECC',
        foundation: 'Elliptic curve discrete logarithm',
        capabilities: ['ECDH', 'ECDSA'],
        security: 'P-256: approximately 128-bit classical security',
        parameters: 'P-256 or stronger standardized curve'
    }
]);


// ============================================================
// 2. INPUT VALIDATION
// ============================================================

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

class CryptographicError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CryptographicError';
    }
}

function validateBuffer(value, name) {
    if (!Buffer.isBuffer(value) || value.length === 0) {
        throw new ValidationError(`${name} must be a nonempty Buffer.`);
    }
}

function validateString(value, name) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new ValidationError(`${name} must be a nonempty string.`);
    }
}


// ============================================================
// 3. RSA IMPLEMENTATION
// ============================================================

class RSAService {

    constructor() {
        this.keyPair = null;
    }

    generateKeys() {

        try {
            this.keyPair = crypto.generateKeyPairSync('rsa', {
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
            });

            return {
                publicKey: this.keyPair.publicKey,
                privateKey: this.keyPair.privateKey
            };

        } catch (error) {
            throw new CryptographicError(
                `RSA key generation failed: ${error.message}`
            );
        }
    }

    sign(message) {

        if (!this.keyPair) {
            throw new CryptographicError('RSA keys are unavailable.');
        }

        validateString(message, 'Message');

        return crypto.sign(
            'sha256',
            Buffer.from(message, 'utf8'),
            {
                key: this.keyPair.privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
            }
        );
    }

    verify(message, signature) {

        if (!this.keyPair) {
            throw new CryptographicError('RSA keys are unavailable.');
        }

        validateString(message, 'Message');
        validateBuffer(signature, 'Signature');

        return crypto.verify(
            'sha256',
            Buffer.from(message, 'utf8'),
            {
                key: this.keyPair.publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
            },
            signature
        );
    }

    encryptSmallSecret(secret) {

        if (!this.keyPair) {
            throw new CryptographicError('RSA keys are unavailable.');
        }

        validateBuffer(secret, 'Secret');

        return crypto.publicEncrypt(
            {
                key: this.keyPair.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            secret
        );
    }

    decryptSmallSecret(ciphertext) {

        if (!this.keyPair) {
            throw new CryptographicError('RSA keys are unavailable.');
        }

        validateBuffer(ciphertext, 'Ciphertext');

        return crypto.privateDecrypt(
            {
                key: this.keyPair.privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            ciphertext
        );
    }
}


// ============================================================
// 4. FINITE-FIELD DIFFIE-HELLMAN
// ============================================================

class DHService {

    constructor(groupName = 'modp15') {

        // modp15 is a standardized 3072-bit finite-field group.
        try {
            this.group = crypto.getDiffieHellman(groupName);
            this.group.generateKeys();
        } catch (error) {
            throw new CryptographicError(
                `DH initialization failed: ${error.message}`
            );
        }
    }

    getPublicKey() {
        return this.group.getPublicKey();
    }

    computeSecret(peerPublicKey) {

        validateBuffer(peerPublicKey, 'Peer public key');

        try {
            const secret = this.group.computeSecret(peerPublicKey);

            if (secret.every(byte => byte === 0)) {
                throw new CryptographicError('Invalid DH shared secret.');
            }

            return secret;

        } catch (error) {
            throw new CryptographicError(
                `DH agreement failed: ${error.message}`
            );
        }
    }
}


// ============================================================
// 5. ELLIPTIC CURVE DIFFIE-HELLMAN
// ============================================================

class ECDHService {

    constructor(curveName = 'prime256v1') {

        this.curveName = curveName;

        try {
            this.ecdh = crypto.createECDH(curveName);
            this.ecdh.generateKeys();
        } catch (error) {
            throw new CryptographicError(
                `ECDH initialization failed: ${error.message}`
            );
        }
    }

    getPublicKey() {
        return this.ecdh.getPublicKey();
    }

    computeSecret(peerPublicKey) {

        validateBuffer(peerPublicKey, 'Peer public key');

        try {
            return this.ecdh.computeSecret(peerPublicKey);
        } catch (error) {
            throw new CryptographicError(
                `ECDH agreement failed: ${error.message}`
            );
        }
    }
}


// ============================================================
// 6. KEY DERIVATION
// ============================================================

function deriveSessionKey(sharedSecret, context) {

    validateBuffer(sharedSecret, 'Shared secret');
    validateString(context, 'Context');

    return Buffer.from(
        crypto.hkdfSync(
            'sha256',
            sharedSecret,
            Buffer.from('repository-security-system-v1'),
            Buffer.from(context),
            32
        )
    );
}


// ============================================================
// 7. AUTHENTICATED ENCRYPTION
// ============================================================

class AEADService {

    static encrypt(plaintext, sessionKey, associatedData) {

        validateBuffer(plaintext, 'Plaintext');
        validateBuffer(sessionKey, 'Session key');

        if (sessionKey.length !== 32) {
            throw new ValidationError('AES-256 requires a 32-byte key.');
        }

        validateBuffer(associatedData, 'Associated data');

        const nonce = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            sessionKey,
            nonce,
            { authTagLength: 16 }
        );

        cipher.setAAD(associatedData);

        const ciphertext = Buffer.concat([
            cipher.update(plaintext),
            cipher.final()
        ]);

        return {
            algorithm: 'AES-256-GCM',
            nonce,
            ciphertext,
            authenticationTag: cipher.getAuthTag()
        };
    }

    static decrypt(packet, sessionKey, associatedData) {

        validateBuffer(sessionKey, 'Session key');
        validateBuffer(associatedData, 'Associated data');

        if (sessionKey.length !== 32) {
            throw new ValidationError('AES-256 requires a 32-byte key.');
        }

        if (
            !packet ||
            packet.algorithm !== 'AES-256-GCM' ||
            !Buffer.isBuffer(packet.nonce) ||
            packet.nonce.length !== 12 ||
            !Buffer.isBuffer(packet.ciphertext) ||
            !Buffer.isBuffer(packet.authenticationTag) ||
            packet.authenticationTag.length !== 16
        ) {
            throw new ValidationError('Malformed encrypted packet.');
        }

        try {
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                sessionKey,
                packet.nonce,
                { authTagLength: 16 }
            );

            decipher.setAAD(associatedData);
            decipher.setAuthTag(packet.authenticationTag);

            return Buffer.concat([
                decipher.update(packet.ciphertext),
                decipher.final()
            ]);

        } catch {
            throw new CryptographicError(
                'Authentication failed. Ciphertext or metadata was modified.'
            );
        }
    }
}


// ============================================================
// 8. EVENT-DRIVEN CRYPTOGRAPHIC GOVERNANCE
// ============================================================

class CryptographicPolicy extends EventEmitter {

    constructor() {
        super();

        this.minimumStrength = Object.freeze({
            [Algorithm.RSA]: 3072,
            [Algorithm.DH]: 3072,
            [Algorithm.ECC]: 256
        });
    }

    evaluate(configuration) {

        const findings = [];

        if (!Object.values(Algorithm).includes(configuration.algorithm)) {
            throw new ValidationError('Unsupported cryptographic algorithm.');
        }

        if (!Object.values(Purpose).includes(configuration.purpose)) {
            throw new ValidationError('Unsupported cryptographic purpose.');
        }

        if (
            !Number.isInteger(configuration.parameterSize) ||
            configuration.parameterSize <= 0
        ) {
            throw new ValidationError('Invalid parameter size.');
        }

        const minimum = this.minimumStrength[configuration.algorithm];

        if (configuration.parameterSize < minimum) {
            findings.push(`Minimum parameter size is ${minimum}.`);
        }

        if (!configuration.approvedParameters) {
            findings.push('Parameters are not approved.');
        }

        if (!configuration.authenticated) {
            findings.push('Peer authentication is required.');
        }

        if (
            configuration.algorithm === Algorithm.DH &&
            configuration.purpose !== Purpose.KEY_AGREEMENT
        ) {
            findings.push('DH supports key agreement, not direct encryption.');
        }

        if (
            configuration.algorithm === Algorithm.ECC &&
            configuration.purpose === Purpose.ENCRYPTION
        ) {
            findings.push('Use a standardized hybrid encryption construction.');
        }

        if (
            configuration.algorithm === Algorithm.RSA &&
            configuration.purpose === Purpose.KEY_AGREEMENT
        ) {
            findings.push('RSA is not a DH-style key-agreement algorithm.');
        }

        const result = Object.freeze({
            approved: findings.length === 0,
            algorithm: configuration.algorithm,
            findings
        });

        this.emit('policyEvaluated', result);

        return result;
    }
}


// ============================================================
// 9. ASYNCHRONOUS KEY EXCHANGE WORKFLOW
// ============================================================

async function performKeyAgreement(serviceFactory, context) {

    const alice = serviceFactory();
    const bob = serviceFactory();

    const alicePublic = alice.getPublicKey();
    const bobPublic = bob.getPublicKey();

    const aliceSecret = alice.computeSecret(bobPublic);
    const bobSecret = bob.computeSecret(alicePublic);

    if (!crypto.timingSafeEqual(aliceSecret, bobSecret)) {
        throw new CryptographicError('Key agreement mismatch.');
    }

    const aliceKey = deriveSessionKey(aliceSecret, context);
    const bobKey = deriveSessionKey(bobSecret, context);

    if (!crypto.timingSafeEqual(aliceKey, bobKey)) {
        throw new CryptographicError('Derived session keys do not match.');
    }

    return {
        aliceKey,
        bobKey
    };
}


// ============================================================
// 10. COMPLETE DEMONSTRATIONS
// ============================================================

async function demonstrateRSA() {

    console.log('\nRSA DEMONSTRATION');

    const rsa = new RSAService();
    rsa.generateKeys();

    const message = 'Repository release authorization';

    const signature = rsa.sign(message);

    console.log('RSA signature valid:', rsa.verify(message, signature));

    console.log(
        'Modified message valid:',
        rsa.verify(message + ' changed', signature)
    );

    const secret = crypto.randomBytes(32);

    const encrypted = rsa.encryptSmallSecret(secret);
    const decrypted = rsa.decryptSmallSecret(encrypted);

    console.log(
        'RSA-OAEP secret recovery:',
        crypto.timingSafeEqual(secret, decrypted)
    );

    console.log('RSA signature length:', signature.length);
    console.log('RSA ciphertext length:', encrypted.length);
}

async function demonstrateDH() {

    console.log('\nDIFFIE-HELLMAN DEMONSTRATION');

    const { aliceKey, bobKey } = await performKeyAgreement(
        () => new DHService('modp15'),
        'repository-session-dh-v1'
    );

    console.log('DH shared key matches:',
        crypto.timingSafeEqual(aliceKey, bobKey));

    const metadata = Buffer.from('repository=production;version=1');
    const message = Buffer.from('Confidential repository configuration');

    const packet = AEADService.encrypt(message, aliceKey, metadata);

    const recovered = AEADService.decrypt(
        packet,
        bobKey,
        metadata
    );

    console.log('Authenticated recovery:', recovered.equals(message));

    try {
        const modified = Buffer.from(metadata);
        modified[0] ^= 1;

        AEADService.decrypt(packet, bobKey, modified);

    } catch (error) {
        console.log('Metadata modification rejected:', error.message);
    }
}

async function demonstrateECC() {

    console.log('\nELLIPTIC CURVE DEMONSTRATION');

    const { aliceKey, bobKey } = await performKeyAgreement(
        () => new ECDHService('prime256v1'),
        'repository-session-ecdh-v1'
    );

    console.log('ECDH shared key matches:',
        crypto.timingSafeEqual(aliceKey, bobKey));

    console.log('Derived key length:', aliceKey.length);
}

function demonstratePolicy() {

    console.log('\nPOLICY EVALUATION');

    const policy = new CryptographicPolicy();

    policy.on('policyEvaluated', result => {
        console.log(
            `Policy event: ${result.algorithm}, approved=${result.approved}`
        );
    });

    const cases = [
        {
            algorithm: Algorithm.RSA,
            purpose: Purpose.SIGNATURE,
            parameterSize: 3072,
            authenticated: true,
            approvedParameters: true
        },
        {
            algorithm: Algorithm.DH,
            purpose: Purpose.KEY_AGREEMENT,
            parameterSize: 2048,
            authenticated: false,
            approvedParameters: true
        },
        {
            algorithm: Algorithm.ECC,
            purpose: Purpose.KEY_AGREEMENT,
            parameterSize: 256,
            authenticated: true,
            approvedParameters: true
        }
    ];

    for (const configuration of cases) {

        const result = policy.evaluate(configuration);

        console.log(JSON.stringify(result, null, 2));
    }
}

function displayComparison() {

    console.log('\nALGORITHM COMPARISON');

    for (const profile of ALGORITHM_PROFILES) {

        console.log(`\n${profile.name}`);
        console.log('Foundation:', profile.foundation);
        console.log('Capabilities:', profile.capabilities.join(', '));
        console.log('Security:', profile.security);
        console.log('Parameters:', profile.parameters);
    }
}


// ============================================================
// 11. TESTING AND APPLICATION ENTRY POINT
// ============================================================

async function runTests() {

    const rsa = new RSAService();
    rsa.generateKeys();

    const signature = rsa.sign('test');

    if (!rsa.verify('test', signature)) {
        throw new Error('RSA signature test failed.');
    }

    if (rsa.verify('modified', signature)) {
        throw new Error('RSA tampering test failed.');
    }

    const { aliceKey, bobKey } = await performKeyAgreement(
        () => new ECDHService(),
        'test-context'
    );

    if (!crypto.timingSafeEqual(aliceKey, bobKey)) {
        throw new Error('ECDH test failed.');
    }

    const key = crypto.randomBytes(32);
    const aad = Buffer.from('test metadata');
    const plaintext = Buffer.from('confidential data');

    const packet = AEADService.encrypt(plaintext, key, aad);
    const recovered = AEADService.decrypt(packet, key, aad);

    if (!recovered.equals(plaintext)) {
        throw new Error('AES-GCM test failed.');
    }

    console.log('\nAll JavaScript validation tests passed.');
}

async function main() {

    console.log('RSA vs DIFFIE-HELLMAN vs ECC');
    console.log('='.repeat(65));

    displayComparison();

    await demonstrateRSA();
    await demonstrateDH();
    await demonstrateECC();

    demonstratePolicy();

    await runTests();

    console.log('\nSECURITY CONSIDERATIONS');
    console.log('- RSA encryption uses OAEP, not textbook RSA.');
    console.log('- RSA signatures use PSS.');
    console.log('- DH and ECDH require authenticated peer identities.');
    console.log('- HKDF derives application-specific session keys.');
    console.log('- AES-GCM provides authenticated encryption.');
    console.log('- Never reuse an AES-GCM nonce with the same key.');
    console.log('- Classical RSA, DH and ECC are vulnerable to sufficiently');
    console.log('  capable cryptographically relevant quantum computers.');
}

main().catch(error => {
    console.error('Application failure:', error.message);
    process.exitCode = 1;
});
