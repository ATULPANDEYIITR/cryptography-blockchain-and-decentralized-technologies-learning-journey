'use strict';

/*
 * Digital Certificates: Event-Driven PKI Management
 *
 * Implements:
 * - RSA public/private key generation
 * - SHA-256 certificate signatures
 * - Certificate authority hierarchy
 * - Certificate issuance
 * - Cryptographic signature verification
 * - Certificate chain validation
 * - Expiration and revocation
 * - Hostname and key usage policies
 * - Event-driven certificate lifecycle monitoring
 *
 * This is a compact educational certificate model, not a DER-encoded
 * X.509 implementation. Production X.509 processing requires a
 * standards-compliant certificate library.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const fs = require('node:fs/promises');

class CertificateError extends Error {}

class ValidationError extends CertificateError {}

const CertificateStatus = Object.freeze({
    ACTIVE: 'ACTIVE',
    REVOKED: 'REVOKED',
    SUSPENDED: 'SUSPENDED'
});

const CertificateType = Object.freeze({
    ROOT: 'ROOT',
    INTERMEDIATE: 'INTERMEDIATE',
    SERVER: 'SERVER',
    CLIENT: 'CLIENT',
    CODE_SIGNING: 'CODE_SIGNING'
});

const KeyUsage = Object.freeze({
    DIGITAL_SIGNATURE: 'digitalSignature',
    KEY_CERT_SIGN: 'keyCertSign',
    CRL_SIGN: 'cRLSign',
    KEY_ENCIPHERMENT: 'keyEncipherment'
});

function canonicalJSON(value) {
    if (Array.isArray(value)) {
        return `[${value.map(canonicalJSON).join(',')}]`;
    }

    if (value && typeof value === 'object') {
        return `{${Object.keys(value).sort().map(
            key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`
        ).join(',')}}`;
    }

    return JSON.stringify(value);
}

function validateFingerprint(fingerprint) {
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
        throw new CertificateError('Invalid SHA-256 fingerprint.');
    }
}

function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 3072,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

function publicKeyFingerprint(publicKey) {
    return crypto.createHash('sha256')
        .update(publicKey)
        .digest('hex');
}

function signPayload(payload, privateKey) {
    const signer = crypto.createSign('SHA256');
    signer.update(canonicalJSON(payload));
    signer.end();

    return signer.sign(privateKey, 'base64');
}

function verifyPayload(payload, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(canonicalJSON(payload));
    verifier.end();

    return verifier.verify(publicKey, signature, 'base64');
}

class Certificate {
    constructor({
        serialNumber,
        subject,
        issuer,
        publicKey,
        type,
        notBefore,
        notAfter,
        usages,
        isCA = false,
        pathLength = null,
        subjectAltNames = [],
        status = CertificateStatus.ACTIVE,
        signature = null
    }) {
        if (!serialNumber || !subject || !issuer) {
            throw new CertificateError(
                'Serial number, subject and issuer are required.'
            );
        }

        if (!Object.values(CertificateType).includes(type)) {
            throw new CertificateError('Unsupported certificate type.');
        }

        const start = new Date(notBefore);
        const end = new Date(notAfter);

        if (
            Number.isNaN(start.getTime()) ||
            Number.isNaN(end.getTime()) ||
            end <= start
        ) {
            throw new CertificateError('Invalid certificate validity.');
        }

        if (!Array.isArray(usages) || usages.length === 0) {
            throw new CertificateError('At least one key usage is required.');
        }

        for (const usage of usages) {
            if (!Object.values(KeyUsage).includes(usage)) {
                throw new CertificateError(`Invalid key usage: ${usage}`);
            }
        }

        if (isCA && !usages.includes(KeyUsage.KEY_CERT_SIGN)) {
            throw new CertificateError('CA requires keyCertSign usage.');
        }

        if (pathLength !== null && (
            !isCA ||
            !Number.isInteger(pathLength) ||
            pathLength < 0
        )) {
            throw new CertificateError('Invalid CA path length.');
        }

        this.serialNumber = String(serialNumber);
        this.subject = subject;
        this.issuer = issuer;
        this.publicKey = publicKey;
        this.publicKeyFingerprint = publicKeyFingerprint(publicKey);
        this.type = type;
        this.notBefore = start.toISOString();
        this.notAfter = end.toISOString();
        this.usages = Object.freeze([...new Set(usages)]);
        this.isCA = isCA;
        this.pathLength = pathLength;
        this.subjectAltNames = Object.freeze([...subjectAltNames]);
        this.status = status;
        this.signature = signature;
    }

    payload() {
        return {
            serialNumber: this.serialNumber,
            subject: this.subject,
            issuer: this.issuer,
            publicKey: this.publicKey,
            type: this.type,
            notBefore: this.notBefore,
            notAfter: this.notAfter,
            usages: this.usages,
            isCA: this.isCA,
            pathLength: this.pathLength,
            subjectAltNames: this.subjectAltNames
        };
    }

    isValidAt(moment = new Date()) {
        return (
            this.status === CertificateStatus.ACTIVE &&
            moment >= new Date(this.notBefore) &&
            moment <= new Date(this.notAfter)
        );
    }

    toJSON() {
        return {
            ...this.payload(),
            publicKeyFingerprint: this.publicKeyFingerprint,
            status: this.status,
            signature: this.signature
        };
    }
}

class CertificateAuthority {
    constructor(name, certificate, privateKey, trusted = false) {
        if (!certificate.isCA) {
            throw new CertificateError('Authority must have a CA certificate.');
        }

        if (certificate.subject !== name) {
            throw new CertificateError('CA subject mismatch.');
        }

        this.name = name;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.trusted = trusted;
    }

    issue({
        serialNumber,
        subject,
        publicKey,
        type,
        days = 90,
        usages = [KeyUsage.DIGITAL_SIGNATURE],
        subjectAltNames = [],
        isCA = false,
        pathLength = null
    }) {
        if (!this.certificate.isValidAt()) {
            throw new CertificateError('Issuing CA is not valid.');
        }

        if (!Number.isInteger(days) || days < 1 || days > 825) {
            throw new CertificateError('Validity must be 1 to 825 days.');
        }

        if (isCA && !this.certificate.isCA) {
            throw new CertificateError('Issuer cannot issue CA certificates.');
        }

        if (isCA && this.certificate.pathLength === 0) {
            throw new CertificateError('Issuer path length exhausted.');
        }

        if (!isCA && usages.includes(KeyUsage.KEY_CERT_SIGN)) {
            throw new CertificateError(
                'End-entity certificate cannot have keyCertSign.'
            );
        }

        const now = new Date();

        const certificate = new Certificate({
            serialNumber,
            subject,
            issuer: this.name,
            publicKey,
            type,
            notBefore: now.toISOString(),
            notAfter: new Date(
                now.getTime() + days * 86400000
            ).toISOString(),
            usages,
            isCA,
            pathLength,
            subjectAltNames
        });

        certificate.signature = signPayload(
            certificate.payload(),
            this.privateKey
        );

        return certificate;
    }
}

class CertificateStore extends EventEmitter {
    #certificates = new Map();
    #authorities = new Map();
    #revocations = new Map();

    addAuthority(authority) {
        if (this.#authorities.has(authority.name)) {
            throw new CertificateError('Duplicate authority.');
        }

        if (!authority.certificate.isValidAt()) {
            throw new CertificateError('Invalid authority certificate.');
        }

        if (
            authority.certificate.issuer === authority.name &&
            !verifyPayload(
                authority.certificate.payload(),
                authority.certificate.signature,
                authority.certificate.publicKey
            )
        ) {
            throw new CertificateError('Invalid root self-signature.');
        }

        this.#authorities.set(authority.name, authority);
        this.addCertificate(authority.certificate);
    }

    addCertificate(certificate) {
        if (this.#certificates.has(certificate.serialNumber)) {
            throw new CertificateError('Duplicate certificate serial.');
        }

        this.#certificates.set(certificate.serialNumber, certificate);

        this.emit('certificate:issued', {
            serialNumber: certificate.serialNumber,
            subject: certificate.subject
        });
    }

    get(serialNumber) {
        const certificate = this.#certificates.get(String(serialNumber));

        if (!certificate) {
            throw new CertificateError('Certificate not found.');
        }

        return certificate;
    }

    authority(name) {
        return this.#authorities.get(name);
    }

    revoke(serialNumber, reason) {
        const certificate = this.get(serialNumber);

        if (!reason || !reason.trim()) {
            throw new CertificateError('Revocation reason is required.');
        }

        if (certificate.status === CertificateStatus.REVOKED) {
            throw new CertificateError('Already revoked.');
        }

        certificate.status = CertificateStatus.REVOKED;

        this.#revocations.set(serialNumber, {
            reason,
            revokedAt: new Date().toISOString()
        });

        this.emit('certificate:revoked', {
            serialNumber,
            reason
        });
    }

    isRevoked(serialNumber) {
        return this.#revocations.has(serialNumber);
    }

    inventory() {
        return [...this.#certificates.values()].map(certificate => ({
            serialNumber: certificate.serialNumber,
            subject: certificate.subject,
            issuer: certificate.issuer,
            type: certificate.type,
            status: certificate.status,
            expired: new Date() > new Date(certificate.notAfter),
            fingerprint: certificate.publicKeyFingerprint
        }));
    }
}

class CertificateValidator {
    constructor(store) {
        this.store = store;
    }

    validate(serialNumber, {
        hostname = null,
        requiredUsage = null,
        moment = new Date()
    } = {}) {
        const errors = [];
        const chain = [];
        const visited = new Set();

        let certificate;

        try {
            certificate = this.store.get(serialNumber);
        } catch (error) {
            return { valid: false, errors: [error.message], chain };
        }

        const leaf = certificate;

        while (certificate) {
            if (visited.has(certificate.serialNumber)) {
                errors.push('Certificate chain cycle detected.');
                break;
            }

            visited.add(certificate.serialNumber);
            chain.push(certificate.subject);

            if (!certificate.isValidAt(moment)) {
                errors.push(`Invalid validity or status: ${certificate.subject}`);
            }

            const issuer = this.store.authority(certificate.issuer);

            if (!issuer) {
                errors.push(`Unknown issuer: ${certificate.issuer}`);
                break;
            }

            if (!issuer.certificate.isValidAt(moment)) {
                errors.push(`Issuer expired: ${issuer.name}`);
            }

            if (
                !verifyPayload(
                    certificate.payload(),
                    certificate.signature,
                    issuer.certificate.publicKey
                )
            ) {
                errors.push(`Invalid signature: ${certificate.subject}`);
            }

            if (issuer.certificate.issuer === issuer.name) {
                if (!issuer.trusted) {
                    errors.push('Root is not a configured trust anchor.');
                }

                if (
                    !verifyPayload(
                        issuer.certificate.payload(),
                        issuer.certificate.signature,
                        issuer.certificate.publicKey
                    )
                ) {
                    errors.push('Root self-signature verification failed.');
                }

                break;
            }

            certificate = issuer.certificate;
        }

        if (hostname) {
            if (leaf.type !== CertificateType.SERVER) {
                errors.push('Certificate is not a server certificate.');
            } else if (!leaf.subjectAltNames.includes(hostname)) {
                errors.push(`Hostname mismatch: ${hostname}`);
            }
        }

        if (requiredUsage && !leaf.usages.includes(requiredUsage)) {
            errors.push(`Missing key usage: ${requiredUsage}`);
        }

        return {
            valid: errors.length === 0,
            errors,
            chain
        };
    }
}

async function saveInventory(store, filename) {
    const temporary = `${filename}.tmp`;

    try {
        await fs.writeFile(
            temporary,
            JSON.stringify(store.inventory(), null, 2),
            { mode: 0o600 }
        );

        await fs.rename(temporary, filename);
    } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
    }
}

async function main() {
    const rootKeys = generateKeyPair();
    const intermediateKeys = generateKeyPair();
    const serverKeys = generateKeyPair();

    const now = Date.now();

    const root = new Certificate({
        serialNumber: '1000',
        subject: 'Example Root CA',
        issuer: 'Example Root CA',
        publicKey: rootKeys.publicKey,
        type: CertificateType.ROOT,
        notBefore: new Date(now - 86400000),
        notAfter: new Date(now + 3650 * 86400000),
        usages: [KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN],
        isCA: true,
        pathLength: 1
    });

    root.signature = signPayload(root.payload(), rootKeys.privateKey);

    const rootAuthority = new CertificateAuthority(
        'Example Root CA',
        root,
        rootKeys.privateKey,
        true
    );

    const store = new CertificateStore();

    store.on('certificate:issued', event => {
        console.log(`[ISSUED] ${event.serialNumber}: ${event.subject}`);
    });

    store.on('certificate:revoked', event => {
        console.log(`[REVOKED] ${event.serialNumber}: ${event.reason}`);
    });

    store.addAuthority(rootAuthority);

    const intermediate = rootAuthority.issue({
        serialNumber: '2000',
        subject: 'Example Intermediate CA',
        publicKey: intermediateKeys.publicKey,
        type: CertificateType.INTERMEDIATE,
        days: 730,
        usages: [KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN],
        isCA: true,
        pathLength: 0
    });

    const intermediateAuthority = new CertificateAuthority(
        'Example Intermediate CA',
        intermediate,
        intermediateKeys.privateKey
    );

    store.addAuthority(intermediateAuthority);

    const server = intermediateAuthority.issue({
        serialNumber: '3000',
        subject: 'www.example.com',
        publicKey: serverKeys.publicKey,
        type: CertificateType.SERVER,
        days: 90,
        usages: [
            KeyUsage.DIGITAL_SIGNATURE,
            KeyUsage.KEY_ENCIPHERMENT
        ],
        subjectAltNames: ['www.example.com', 'api.example.com']
    });

    store.addCertificate(server);

    const validator = new CertificateValidator(store);

    const validResult = validator.validate('3000', {
        hostname: 'www.example.com',
        requiredUsage: KeyUsage.DIGITAL_SIGNATURE
    });

    console.log('\nValid certificate:');
    console.log(validResult);

    if (!validResult.valid) {
        throw new ValidationError(validResult.errors.join('; '));
    }

    const invalidResult = validator.validate('3000', {
        hostname: 'malicious.example.net'
    });

    console.log('\nInvalid hostname:');
    console.log(invalidResult);

    if (invalidResult.valid) {
        throw new Error('Hostname validation test failed.');
    }

    const tampered = {
        ...server.payload(),
        subject: 'attacker.example.com'
    };

    if (verifyPayload(
        tampered,
        server.signature,
        intermediate.publicKey
    )) {
        throw new Error('Tampered certificate was accepted.');
    }

    console.log('\nTampering detection: passed');

    store.revoke('3000', 'Private key compromise');

    const revokedResult = validator.validate('3000');

    if (revokedResult.valid) {
        throw new Error('Revoked certificate was accepted.');
    }

    console.log('\nRevocation validation: passed');

    await saveInventory(store, 'certificate_inventory.json');

    console.log('\nCertificate inventory:');
    console.table(store.inventory());
}

main().catch(error => {
    console.error('PKI operation failed:', error.message);
    process.exitCode = 1;
});
