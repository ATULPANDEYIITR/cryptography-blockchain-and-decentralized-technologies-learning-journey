'use strict';

/*
 * Security Threats and Basic Security Principles
 *
 * This Node.js program models security as a collection of independent
 * controls rather than as a single defensive mechanism.
 *
 * Demonstrated areas:
 * - CIA security properties
 * - Threat modeling
 * - Validation and canonicalization
 * - Password-derived key verification
 * - Authentication and authorization
 * - Session lifecycle
 * - Event-driven rate limiting
 * - HMAC integrity
 * - Replay prevention
 * - Audit events
 * - Secure file boundary checks
 * - Layered policy evaluation
 *
 * Runtime: Node.js 18+
 */

const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');


/* -------------------------------------------------------------------------
 * CIA security properties
 * ------------------------------------------------------------------------- */

const SECURITY_PROPERTIES = Object.freeze({
    confidentiality: [
        'Authentication',
        'Authorization',
        'Encryption',
        'Secret management'
    ],
    integrity: [
        'Input validation',
        'HMAC authentication',
        'Audit trails',
        'Controlled changes'
    ],
    availability: [
        'Rate limiting',
        'Resource limits',
        'Backups',
        'Failure isolation'
    ]
});

function showSecurityProperties() {
    console.log('\n=== CIA Security Properties ===');

    for (const [property, controls] of Object.entries(SECURITY_PROPERTIES)) {
        console.log(`${property}:`);
        for (const control of controls) {
            console.log(`  ${control}`);
        }
    }
}


/* -------------------------------------------------------------------------
 * Threat modeling
 * ------------------------------------------------------------------------- */

class Threat {
    constructor({ name, asset, surface, impact, likelihood, controls }) {
        this.name = name;
        this.asset = asset;
        this.surface = surface;
        this.impact = impact;
        this.likelihood = likelihood;
        this.controls = controls;
    }

    priority() {
        if (this.impact === 'high' && this.likelihood === 'high') {
            return 'critical';
        }

        if (this.impact === 'high' || this.likelihood === 'high') {
            return 'high';
        }

        return 'moderate';
    }
}

function createThreatModel() {
    return [
        new Threat({
            name: 'Credential stuffing',
            asset: 'User accounts',
            surface: 'Authentication endpoint',
            impact: 'high',
            likelihood: 'high',
            controls: [
                'Password KDF',
                'Rate limiting',
                'Multi-factor authentication'
            ]
        }),
        new Threat({
            name: 'Path traversal',
            asset: 'Private files',
            surface: 'File retrieval endpoint',
            impact: 'high',
            likelihood: 'medium',
            controls: [
                'Canonicalization',
                'Storage boundary validation',
                'Filename allowlisting'
            ]
        }),
        new Threat({
            name: 'Message tampering',
            asset: 'Financial request',
            surface: 'API message boundary',
            impact: 'high',
            likelihood: 'medium',
            controls: [
                'HMAC',
                'Nonce',
                'Timestamp validation'
            ]
        })
    ];
}

function showThreatModel() {
    console.log('\n=== Threat Model ===');

    for (const threat of createThreatModel()) {
        console.log(
            `${threat.name}: ${threat.priority()} risk priority`
        );
        console.log(`  Asset: ${threat.asset}`);
        console.log(`  Surface: ${threat.surface}`);
        console.log(`  Controls: ${threat.controls.join(', ')}`);
    }
}


/* -------------------------------------------------------------------------
 * Input validation
 * ------------------------------------------------------------------------- */

function validateUsername(username) {
    if (typeof username !== 'string') {
        throw new TypeError('Username must be a string');
    }

    const normalized = username.trim();

    if (normalized.length < 3 || normalized.length > 32) {
        throw new Error('Username length is outside the permitted range');
    }

    if (!/^[A-Za-z0-9._-]+$/.test(normalized)) {
        throw new Error('Username contains unsupported characters');
    }

    return normalized;
}

function validateAmount(amount) {
    if (!Number.isInteger(amount)) {
        throw new TypeError('Amount must be an integer');
    }

    if (amount < 1 || amount > 1_000_000) {
        throw new RangeError('Amount is outside the permitted range');
    }

    return amount;
}


/* -------------------------------------------------------------------------
 * Path traversal defense
 * ------------------------------------------------------------------------- */

function safeFilePath(baseDirectory, requestedName) {
    if (
        typeof requestedName !== 'string' ||
        requestedName.length === 0 ||
        requestedName.includes('\0')
    ) {
        throw new Error('Invalid file name');
    }

    const base = path.resolve(baseDirectory);
    const candidate = path.resolve(base, requestedName);

    const relative = path.relative(base, candidate);

    /*
     * path.relative() gives the path relationship after normalization.
     * A path beginning with ".." escapes the intended storage boundary.
     */
    if (
        relative === '..' ||
        relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relative)
    ) {
        throw new Error('Path escapes storage boundary');
    }

    return candidate;
}

async function demonstrateFileSecurity() {
    console.log('\n=== Path Traversal Defense ===');

    const temporaryDirectory = await fs.mkdtemp(
        path.join(os.tmpdir(), 'security-demo-')
    );

    try {
        await fs.writeFile(
            path.join(temporaryDirectory, 'report.txt'),
            'confidential report',
            'utf8'
        );

        for (const requestedName of [
            'report.txt',
            '../report.txt',
            '../../etc/passwd'
        ]) {
            try {
                const safePath = safeFilePath(
                    temporaryDirectory,
                    requestedName
                );
                console.log(`Allowed: ${path.basename(safePath)}`);
            } catch (error) {
                console.log(`Blocked ${requestedName}: ${error.message}`);
            }
        }
    } finally {
        await fs.rm(temporaryDirectory, {
            recursive: true,
            force: true
        });
    }
}


/* -------------------------------------------------------------------------
 * Password hashing
 * ------------------------------------------------------------------------- */

function derivePassword(password, salt, iterations = 600_000) {
    if (typeof password !== 'string' || password.length < 12) {
        throw new Error('Password must contain at least 12 characters');
    }

    return crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        32,
        'sha256'
    );
}

function createPasswordRecord(username, password) {
    const salt = crypto.randomBytes(16);
    const iterations = 600_000;
    const derivedKey = derivePassword(password, salt, iterations);

    return Object.freeze({
        username,
        salt,
        iterations,
        derivedKey
    });
}

function verifyPassword(password, record) {
    const candidate = derivePassword(
        password,
        record.salt,
        record.iterations
    );

    /*
     * timingSafeEqual avoids a simple early-exit comparison of secret
     * derived values. Both buffers must have identical length.
     */
    return crypto.timingSafeEqual(candidate, record.derivedKey);
}

function demonstratePasswordSecurity() {
    console.log('\n=== Password Security ===');

    const record = createPasswordRecord(
        'security-user',
        'Correct-Horse-Battery-7'
    );

    console.log(
        `Correct password: ${verifyPassword(
            'Correct-Horse-Battery-7',
            record
        )}`
    );

    console.log(
        `Wrong password: ${verifyPassword(
            'incorrect-password',
            record
        )}`
    );
}


/* -------------------------------------------------------------------------
 * Authentication and authorization
 * ------------------------------------------------------------------------- */

const ROLE_PERMISSIONS = Object.freeze({
    viewer: new Set(['read:reports']),
    analyst: new Set(['read:reports', 'create:reports']),
    administrator: new Set([
        'read:reports',
        'create:reports',
        'delete:reports',
        'manage:users'
    ])
});

class AuthorizationService {
    isAllowed(user, permission) {
        if (!user.active) {
            return false;
        }

        for (const role of user.roles) {
            const permissions = ROLE_PERMISSIONS[role];

            if (permissions && permissions.has(permission)) {
                return true;
            }
        }

        return false;
    }
}

function demonstrateAuthorization() {
    console.log('\n=== Authorization and Least Privilege ===');

    const authorization = new AuthorizationService();

    const users = [
        {
            username: 'reader',
            roles: ['viewer'],
            active: true
        },
        {
            username: 'analyst',
            roles: ['analyst'],
            active: true
        },
        {
            username: 'administrator',
            roles: ['administrator'],
            active: true
        }
    ];

    for (const user of users) {
        console.log(
            `${user.username}: read=${authorization.isAllowed(
                user,
                'read:reports'
            )}, delete=${authorization.isAllowed(
                user,
                'delete:reports'
            )}`
        );
    }
}


/* -------------------------------------------------------------------------
 * Session lifecycle
 * ------------------------------------------------------------------------- */

class SessionManager {
    constructor(lifetimeMilliseconds = 15 * 60 * 1000) {
        this.lifetimeMilliseconds = lifetimeMilliseconds;
        this.sessions = new Map();
    }

    create(username, now = Date.now()) {
        const sessionId = crypto.randomBytes(32).toString('base64url');

        const session = {
            sessionId,
            username,
            createdAt: now,
            expiresAt: now + this.lifetimeMilliseconds
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    get(sessionId, now = Date.now()) {
        const session = this.sessions.get(sessionId);

        if (!session) {
            throw new Error('Unknown session');
        }

        if (now >= session.expiresAt) {
            this.sessions.delete(sessionId);
            throw new Error('Session expired');
        }

        return session;
    }

    revoke(sessionId) {
        this.sessions.delete(sessionId);
    }
}

function demonstrateSessions() {
    console.log('\n=== Session Security ===');

    const manager = new SessionManager(60_000);
    const session = manager.create('security-user', 1000);

    console.log(
        `Authenticated user: ${manager.get(session.sessionId, 2000).username}`
    );

    manager.revoke(session.sessionId);

    try {
        manager.get(session.sessionId, 3000);
    } catch (error) {
        console.log(`Revoked session rejected: ${error.message}`);
    }
}


/* -------------------------------------------------------------------------
 * Event-driven rate limiter
 * ------------------------------------------------------------------------- */

class SlidingWindowRateLimiter {
    constructor(maximumRequests, windowMilliseconds) {
        if (
            !Number.isInteger(maximumRequests) ||
            maximumRequests <= 0
        ) {
            throw new Error('Invalid request limit');
        }

        this.maximumRequests = maximumRequests;
        this.windowMilliseconds = windowMilliseconds;
        this.events = new Map();
    }

    allow(identity, now = Date.now()) {
        const timestamps = this.events.get(identity) ?? [];
        const cutoff = now - this.windowMilliseconds;

        while (timestamps.length > 0 && timestamps[0] <= cutoff) {
            timestamps.shift();
        }

        if (timestamps.length >= this.maximumRequests) {
            this.events.set(identity, timestamps);
            return false;
        }

        timestamps.push(now);
        this.events.set(identity, timestamps);
        return true;
    }
}

async function demonstrateRateLimiting() {
    console.log('\n=== Rate Limiting ===');

    const limiter = new SlidingWindowRateLimiter(3, 10_000);

    for (let attempt = 1; attempt <= 5; attempt++) {
        console.log(
            `Request ${attempt}: ${limiter.allow('client-1', 1000) ? 'allowed' : 'blocked'}`
        );

        /*
         * Promise.resolve().then() queues the next continuation as a
         * microtask. This illustrates asynchronous JavaScript flow without
         * requiring an external dependency.
         */
        await Promise.resolve();
    }
}


/* -------------------------------------------------------------------------
 * HMAC integrity and replay protection
 * ------------------------------------------------------------------------- */

function createHmac(key, payload) {
    return crypto
        .createHmac('sha256', key)
        .update(payload)
        .digest();
}

function constantTimeBufferEqual(left, right) {
    if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
        return false;
    }

    if (left.length !== right.length) {
        return false;
    }

    return crypto.timingSafeEqual(left, right);
}

class ReplayGuard {
    constructor(maximumAgeMilliseconds = 5 * 60 * 1000) {
        this.maximumAgeMilliseconds = maximumAgeMilliseconds;
        this.seenNonces = new Map();
    }

    accept(nonce, timestamp, now) {
        if (
            Math.abs(now - timestamp) >
            this.maximumAgeMilliseconds
        ) {
            return false;
        }

        if (this.seenNonces.has(nonce)) {
            return false;
        }

        this.seenNonces.set(nonce, now);
        return true;
    }
}

function demonstrateIntegrityAndReplay() {
    console.log('\n=== Integrity and Replay Protection ===');

    const key = crypto.randomBytes(32);
    const payload = Buffer.from(
        JSON.stringify({
            operation: 'transfer',
            amount: 500
        })
    );

    const signature = createHmac(key, payload);

    console.log(
        `Original message accepted: ${constantTimeBufferEqual(
            signature,
            createHmac(key, payload)
        )}`
    );

    const modifiedPayload = Buffer.from(
        JSON.stringify({
            operation: 'transfer',
            amount: 500000
        })
    );

    console.log(
        `Modified message accepted: ${constantTimeBufferEqual(
            signature,
            createHmac(key, modifiedPayload)
        )}`
    );

    const replayGuard = new ReplayGuard();
    const nonce = crypto.randomBytes(16).toString('base64url');

    console.log(
        `First request accepted: ${replayGuard.accept(
            nonce,
            100_000,
            100_001
        )}`
    );

    console.log(
        `Replay accepted: ${replayGuard.accept(
            nonce,
            100_000,
            100_002
        )}`
    );
}


/* -------------------------------------------------------------------------
 * Audit events
 * ------------------------------------------------------------------------- */

class AuditLog {
    constructor() {
        this.events = [];
    }

    record(event) {
        if (!event.type || !event.actor || !event.outcome) {
            throw new Error('Security event is missing required fields');
        }

        this.events.push(Object.freeze({
            timestamp: new Date().toISOString(),
            ...event
        }));
    }

    toJSON() {
        return JSON.stringify(this.events, null, 2);
    }
}

function demonstrateAuditLogging() {
    console.log('\n=== Audit Logging ===');

    const audit = new AuditLog();

    audit.record({
        type: 'authentication',
        actor: 'security-user',
        outcome: 'success',
        resource: 'account',
        method: 'password'
    });

    audit.record({
        type: 'authorization',
        actor: 'reader',
        outcome: 'denied',
        resource: 'reports/delete',
        requiredPermission: 'delete:reports'
    });

    console.log(audit.toJSON());
}


/* -------------------------------------------------------------------------
 * Layered security policy
 * ------------------------------------------------------------------------- */

class SecureOperationService {
    constructor(hmacKey) {
        this.authorization = new AuthorizationService();
        this.replayGuard = new ReplayGuard();
        this.hmacKey = hmacKey;
    }

    process(request, now) {
        if (!request.user.active) {
            return 'rejected: inactive account';
        }

        if (
            !this.authorization.isAllowed(
                request.user,
                'create:reports'
            )
        ) {
            return 'rejected: insufficient privilege';
        }

        try {
            validateUsername(request.destination);
            validateAmount(request.amount);
        } catch (error) {
            return `rejected: invalid input (${error.message})`;
        }

        if (
            !this.replayGuard.accept(
                request.nonce,
                request.timestamp,
                now
            )
        ) {
            return 'rejected: stale or replayed request';
        }

        const expected = createHmac(
            this.hmacKey,
            request.payload
        );

        const supplied = Buffer.from(request.signature, 'base64url');

        if (!constantTimeBufferEqual(supplied, expected)) {
            return 'rejected: invalid integrity signature';
        }

        return 'accepted';
    }
}

function demonstrateLayeredSecurity() {
    console.log('\n=== Layered Security Policy ===');

    const key = crypto.randomBytes(32);
    const service = new SecureOperationService(key);

    const payload = Buffer.from(
        JSON.stringify({
            destination: 'secure_account',
            amount: 500
        })
    );

    const request = {
        user: {
            username: 'analyst',
            roles: ['analyst'],
            active: true
        },
        destination: 'secure_account',
        amount: 500,
        nonce: crypto.randomBytes(16).toString('base64url'),
        timestamp: 1000,
        payload,
        signature: createHmac(key, payload).toString('base64url')
    };

    console.log(service.process(request, 1001));
    console.log(`Replay: ${service.process(request, 1002)}`);
}


/* -------------------------------------------------------------------------
 * Assertions
 * ------------------------------------------------------------------------- */

function runSecurityAssertions() {
    console.log('\n=== Security Assertions ===');

    console.assert(
        validateUsername('secure_user') === 'secure_user',
        'Username should be accepted'
    );

    try {
        validateUsername('../admin');
        throw new Error('Unsafe username was accepted');
    } catch (error) {
        if (error.message === 'Unsafe username was accepted') {
            throw error;
        }
    }

    console.assert(validateAmount(250) === 250);

    const record = createPasswordRecord(
        'tester',
        'Strong-password-123'
    );

    console.assert(
        verifyPassword('Strong-password-123', record),
        'Correct password should verify'
    );

    console.assert(
        !verifyPassword('wrong-password', record),
        'Wrong password should fail'
    );

    const key = crypto.randomBytes(32);
    const message = Buffer.from('security message');
    const signature = createHmac(key, message);

    console.assert(
        constantTimeBufferEqual(
            signature,
            createHmac(key, message)
        ),
        'Valid HMAC should verify'
    );

    console.assert(
        !constantTimeBufferEqual(
            signature,
            createHmac(key, Buffer.from('tampered message'))
        ),
        'Tampered HMAC should fail'
    );

    const limiter = new SlidingWindowRateLimiter(2, 10_000);

    console.assert(limiter.allow('test', 1000));
    console.assert(limiter.allow('test', 1001));
    console.assert(!limiter.allow('test', 1002));

    console.log('All assertions passed.');
}


/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

async function main() {
    console.log('SECURITY THREATS AND BASIC SECURITY PRINCIPLES');
    console.log('='.repeat(52));

    showSecurityProperties();
    showThreatModel();

    console.log('\n=== Validation ===');

    for (const username of [
        'secure_user',
        'user name',
        '../admin',
        'x'
    ]) {
        try {
            console.log(`Accepted: ${validateUsername(username)}`);
        } catch (error) {
            console.log(`Rejected ${JSON.stringify(username)}: ${error.message}`);
        }
    }

    await demonstrateFileSecurity();
    demonstratePasswordSecurity();
    demonstrateAuthorization();
    demonstrateSessions();
    await demonstrateRateLimiting();
    demonstrateIntegrityAndReplay();
    demonstrateAuditLogging();
    demonstrateLayeredSecurity();
    runSecurityAssertions();
}

main().catch((error) => {
    console.error(`Security demonstration failed: ${error.message}`);
    process.exitCode = 1;
});
