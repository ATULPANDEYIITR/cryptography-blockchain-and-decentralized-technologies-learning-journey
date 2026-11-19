'use strict';

/*
 * Digital Signature Governance Engine
 *
 * Runtime: Node.js 20+
 * Dependencies: Node.js built-in crypto, fs, path
 *
 * Algorithms:
 * - Ed25519 digital signatures
 * - SHA-256 document fingerprints
 * - Public/private key separation
 * - Detached signature verification
 * - Key lifecycle and revocation
 * - Event-driven verification and audit
 */

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const assert = require('node:assert/strict');


class SignatureError extends Error {}
class KeyError extends SignatureError {}
class DocumentError extends SignatureError {}
class VerificationError extends SignatureError {}


const KeyStatus = Object.freeze({
    ACTIVE: 'ACTIVE',
    REVOKED: 'REVOKED',
    EXPIRED: 'EXPIRED'
});

const VerificationStatus = Object.freeze({
    VALID: 'VALID',
    INVALID: 'INVALID',
    REVOKED: 'REVOKED',
    EXPIRED: 'EXPIRED',
    UNKNOWN_KEY: 'UNKNOWN_KEY'
});


class Document {
    constructor(id, name, content) {
        if (typeof id !== 'string' || !id.trim()) {
            throw new DocumentError('Document ID is required.');
        }

        if (typeof name !== 'string' || !name.trim()) {
            throw new DocumentError('Document name is required.');
        }

        if (!Buffer.isBuffer(content) || content.length === 0) {
            throw new DocumentError(
                'Document must contain non-empty binary content.'
            );
        }

        if (content.length > 10 * 1024 * 1024) {
            throw new DocumentError('Document exceeds 10 MB.');
        }

        this.id = id;
        this.name = name;
        this.content = Buffer.from(content);
        this.hash = crypto
            .createHash('sha256')
            .update(this.content)
            .digest('hex');

        Object.freeze(this);
    }
}


class KeyRegistry {
    #keys = new Map();

    generate(owner, validityDays = 365) {
        if (typeof owner !== 'string' || !owner.trim()) {
            throw new KeyError('Valid key owner is required.');
        }

        if (
            validityDays !== null &&
            (!Number.isInteger(validityDays) || validityDays <= 0)
        ) {
            throw new KeyError('Invalid key validity period.');
        }

        const pair = crypto.generateKeyPairSync('ed25519');
        const keyId = crypto.randomUUID();

        const now = Date.now();

        const expiresAt = validityDays === null
            ? null
            : now + validityDays * 86400000;

        this.#keys.set(keyId, {
            keyId,
            owner: owner.trim(),
            privateKey: pair.privateKey,
            publicKey: pair.publicKey,
            createdAt: now,
            expiresAt,
            revokedAt: null,
            status: KeyStatus.ACTIVE
        });

        return keyId;
    }

    get(keyId) {
        const record = this.#keys.get(keyId);

        if (!record) {
            throw new KeyError('Unknown key identifier.');
        }

        return record;
    }

    getSigningKey(keyId) {
        const record = this.get(keyId);

        if (record.status !== KeyStatus.ACTIVE) {
            throw new KeyError('Key is not active.');
        }

        if (
            record.expiresAt !== null &&
            Date.now() >= record.expiresAt
        ) {
            record.status = KeyStatus.EXPIRED;
            throw new KeyError('Key has expired.');
        }

        return record.privateKey;
    }

    revoke(keyId) {
        const record = this.get(keyId);

        if (record.status === KeyStatus.REVOKED) {
            throw new KeyError('Key is already revoked.');
        }

        record.status = KeyStatus.REVOKED;
        record.revokedAt = Date.now();

        // Discard signing capability while retaining verification material.
        record.privateKey = null;
    }

    exportPublicKey(keyId) {
        return this.get(keyId).publicKey.export({
            type: 'spki',
            format: 'pem'
        });
    }

    importPublicKey(owner, pem) {
        let publicKey;

        try {
            publicKey = crypto.createPublicKey(pem);
        } catch (error) {
            throw new KeyError('Invalid public key encoding.');
        }

        if (publicKey.asymmetricKeyType !== 'ed25519') {
            throw new KeyError('Only Ed25519 keys are accepted.');
        }

        const keyId = crypto.randomUUID();

        this.#keys.set(keyId, {
            keyId,
            owner,
            privateKey: null,
            publicKey,
            createdAt: Date.now(),
            expiresAt: null,
            revokedAt: null,
            status: KeyStatus.ACTIVE
        });

        return keyId;
    }
}


class AuditLog extends EventEmitter {
    #events = [];

    record(eventType, data) {
        const event = Object.freeze({
            eventId: crypto.randomUUID(),
            eventType,
            timestamp: new Date().toISOString(),
            data: structuredClone(data)
        });

        this.#events.push(event);
        this.emit(eventType, event);

        return event;
    }

    getEvents() {
        return this.#events.map(event => ({ ...event }));
    }

    count(eventType) {
        return this.#events.filter(
            event => event.eventType === eventType
        ).length;
    }
}


class SignatureEngine {
    constructor(registry, audit) {
        this.registry = registry;
        this.audit = audit;
        this.signatures = new Map();
    }

    sign(keyId, document) {
        if (!(document instanceof Document)) {
            throw new DocumentError('Invalid document object.');
        }

        const key = this.registry.get(keyId);
        const privateKey = this.registry.getSigningKey(keyId);

        const signatureBytes = crypto.sign(
            null,
            document.content,
            privateKey
        );

        const signature = Object.freeze({
            signatureId: crypto.randomUUID(),
            documentId: document.id,
            documentName: document.name,
            documentHash: document.hash,
            keyId,
            owner: key.owner,
            algorithm: 'Ed25519',
            signature: signatureBytes.toString('base64'),
            signedAt: new Date().toISOString()
        });

        this.signatures.set(
            signature.signatureId,
            signature
        );

        this.audit.record('SIGNED', {
            signatureId: signature.signatureId,
            documentId: document.id,
            keyId
        });

        return signature;
    }

    verify(signature, document, options = {}) {
        if (!(document instanceof Document)) {
            throw new DocumentError('Invalid document.');
        }

        if (!signature || signature.algorithm !== 'Ed25519') {
            throw new VerificationError(
                'Unsupported or missing signature.'
            );
        }

        const fail = (status, reason) => {
            const result = {
                status,
                reason,
                signatureId: signature.signatureId,
                verifiedAt: new Date().toISOString()
            };

            this.audit.record('VERIFICATION_FAILED', result);

            return result;
        };

        let key;

        try {
            key = this.registry.get(signature.keyId);
        } catch (error) {
            return fail(
                VerificationStatus.UNKNOWN_KEY,
                error.message
            );
        }

        if (document.id !== signature.documentId) {
            return fail(
                VerificationStatus.INVALID,
                'Document identifier mismatch.'
            );
        }

        if (document.hash !== signature.documentHash) {
            return fail(
                VerificationStatus.INVALID,
                'Document content has changed.'
            );
        }

        if (key.status === KeyStatus.REVOKED) {
            return fail(
                VerificationStatus.REVOKED,
                'Signing key is revoked.'
            );
        }

        const verificationTime = options.verificationTime ?? Date.now();

        if (
            key.expiresAt !== null &&
            verificationTime >= key.expiresAt
        ) {
            return fail(
                VerificationStatus.EXPIRED,
                'Signing key is expired at verification time.'
            );
        }

        let valid = false;

        try {
            valid = crypto.verify(
                null,
                document.content,
                key.publicKey,
                Buffer.from(signature.signature, 'base64')
            );
        } catch (error) {
            valid = false;
        }

        if (!valid) {
            return fail(
                VerificationStatus.INVALID,
                'Cryptographic verification failed.'
            );
        }

        const result = {
            status: VerificationStatus.VALID,
            reason: 'Document integrity and signature verified.',
            signatureId: signature.signatureId,
            signer: key.owner,
            verifiedAt: new Date().toISOString()
        };

        this.audit.record('VERIFIED', result);

        return result;
    }

    verifyDetached(publicKey, signatureBytes, content) {
        if (!Buffer.isBuffer(content) || content.length === 0) {
            throw new DocumentError('Invalid verification content.');
        }

        return crypto.verify(
            null,
            content,
            publicKey,
            Buffer.from(signatureBytes, 'base64')
        );
    }
}


class SignatureArchive {
    static async save(signature, directory) {
        await fs.mkdir(directory, { recursive: true });

        const filename = `${signature.signatureId}.json`;
        const destination = path.join(directory, filename);

        // Exclusive creation prevents accidental overwrite.
        const handle = await fs.open(destination, 'wx', 0o600);

        try {
            await handle.writeFile(
                JSON.stringify(signature, null, 2),
                'utf8'
            );
        } finally {
            await handle.close();
        }

        return destination;
    }

    static async load(filename) {
        let data;

        try {
            data = JSON.parse(
                await fs.readFile(filename, 'utf8')
            );
        } catch (error) {
            throw new SignatureError(
                `Archive cannot be read: ${error.message}`
            );
        }

        if (
            data.algorithm !== 'Ed25519' ||
            typeof data.signature !== 'string' ||
            !/^[A-Za-z0-9+/]+={0,2}$/.test(data.signature)
        ) {
            throw new SignatureError('Invalid signature archive.');
        }

        return Object.freeze(data);
    }
}


async function runTests() {
    const registry = new KeyRegistry();
    const audit = new AuditLog();
    const engine = new SignatureEngine(registry, audit);

    const keyId = registry.generate(
        'Enterprise Legal Department'
    );

    const document = new Document(
        'DOC-2026-001',
        'Service Agreement',
        Buffer.from('Approved contract version 1', 'utf8')
    );

    const signature = engine.sign(keyId, document);

    assert.equal(
        engine.verify(signature, document).status,
        VerificationStatus.VALID
    );

    const altered = new Document(
        'DOC-2026-001',
        'Service Agreement',
        Buffer.from('Modified contract version 1', 'utf8')
    );

    assert.equal(
        engine.verify(signature, altered).status,
        VerificationStatus.INVALID
    );

    const publicPem = registry.exportPublicKey(keyId);

    const importedId = registry.importPublicKey(
        'Independent Auditor',
        publicPem
    );

    assert.equal(
        engine.verifyDetached(
            registry.get(importedId).publicKey,
            signature.signature,
            document.content
        ),
        true
    );

    const wrongPair = crypto.generateKeyPairSync('ed25519');

    assert.equal(
        engine.verifyDetached(
            wrongPair.publicKey,
            signature.signature,
            document.content
        ),
        false
    );

    registry.revoke(keyId);

    assert.equal(
        engine.verify(signature, document).status,
        VerificationStatus.REVOKED
    );

    assert.throws(
        () => engine.sign(keyId, document),
        KeyError
    );

    assert.throws(
        () => new Document('EMPTY', 'Empty', Buffer.alloc(0)),
        DocumentError
    );

    assert.ok(audit.count('SIGNED') >= 1);
    assert.ok(audit.count('VERIFIED') >= 1);

    console.log('All digital signature tests passed.');
}


async function demonstration() {
    const registry = new KeyRegistry();
    const audit = new AuditLog();
    const engine = new SignatureEngine(registry, audit);

    audit.on('SIGNED', event => {
        console.log('Audit event:', event.eventType);
    });

    const keyId = registry.generate(
        'Digital Records Authority',
        365
    );

    const document = new Document(
        'CONTRACT-2026-100',
        'Procurement Contract',
        Buffer.from(
            'Procurement contract approved on 19 November 2026.',
            'utf8'
        )
    );

    const signature = engine.sign(keyId, document);

    console.log('\nDIGITAL SIGNATURE REPORT');
    console.log('Algorithm:', signature.algorithm);
    console.log('Document hash:', signature.documentHash);
    console.log('Signature ID:', signature.signatureId);

    console.log(
        '\nOriginal:',
        engine.verify(signature, document)
    );

    const tampered = new Document(
        document.id,
        document.name,
        Buffer.from('Unauthorized modification', 'utf8')
    );

    console.log(
        '\nTampered:',
        engine.verify(signature, tampered)
    );

    console.log('\nAudit events:', audit.getEvents().length);
}


(async () => {
    try {
        await demonstration();
        await runTests();
    } catch (error) {
        console.error('Execution failed:', error.message);
        process.exitCode = 1;
    }
})();
