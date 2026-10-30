'use strict';

/*
 * Secure Password Hashing and Authentication
 *
 * Runtime: Node.js 18+
 *
 * Uses:
 * - crypto.pbkdf2
 * - crypto.randomBytes
 * - crypto.timingSafeEqual
 * - Unicode NFC normalization
 * - Promise-based asynchronous derivation
 * - EventEmitter-based security auditing
 * - Per-account asynchronous serialization
 * - Adaptive credential upgrades
 *
 * PBKDF2-HMAC-SHA256 is used for standard-library portability.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { promisify } = require('node:util');

const pbkdf2Async = promisify(crypto.pbkdf2);

const CONFIG = Object.freeze({
    algorithm: 'pbkdf2-sha256',
    currentIterations: 600000,
    minimumIterations: 100000,
    maximumIterations: 2000000,
    saltLength: 16,
    keyLength: 32,
    minimumPasswordLength: 15,
    maximumPasswordLength: 256,
    maximumPasswordBytes: 1024,
    maximumFailures: 5,
    lockDurationMs: 60000
});


class PasswordPolicyError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PasswordPolicyError';
    }
}


class PasswordPolicy {
    constructor() {
        this.blockedPasswords = new Set([
            'password',
            'password123',
            '123456789012345',
            'qwerty123456789',
            'letmein123456'
        ]);
    }

    validate(password, username = '') {
        if (typeof password !== 'string') {
            throw new PasswordPolicyError('Password must be a string.');
        }

        const normalized = password.normalize('NFC');

        const length = Array.from(normalized).length;
        const byteLength = Buffer.byteLength(normalized, 'utf8');

        if (normalized.includes('\0')) {
            throw new PasswordPolicyError(
                'Null characters are not permitted.'
            );
        }

        if (
            length < CONFIG.minimumPasswordLength ||
            length > CONFIG.maximumPasswordLength
        ) {
            throw new PasswordPolicyError(
                'Password length is outside permitted limits.'
            );
        }

        if (byteLength > CONFIG.maximumPasswordBytes) {
            throw new PasswordPolicyError(
                'Password exceeds the byte limit.'
            );
        }

        const folded = normalized.toLowerCase();

        if (this.blockedPasswords.has(folded)) {
            throw new PasswordPolicyError(
                'Password appears on the blocked-password list.'
            );
        }

        if (username && folded === username.toLowerCase()) {
            throw new PasswordPolicyError(
                'Password cannot equal the account identifier.'
            );
        }

        return normalized;
    }
}


class PasswordHasher {
    constructor(iterations = CONFIG.currentIterations) {
        if (
            !Number.isInteger(iterations) ||
            iterations < CONFIG.minimumIterations ||
            iterations > CONFIG.maximumIterations
        ) {
            throw new RangeError('Unsupported PBKDF2 iteration count.');
        }

        this.iterations = iterations;
    }

    async derive(password, salt, iterations) {
        return pbkdf2Async(
            Buffer.from(password, 'utf8'),
            salt,
            iterations,
            CONFIG.keyLength,
            'sha256'
        );
    }

    async hash(password) {
        if (typeof password !== 'string') {
            throw new TypeError('Password must be a string.');
        }

        const normalized = password.normalize('NFC');
        const salt = crypto.randomBytes(CONFIG.saltLength);

        const derived = await this.derive(
            normalized,
            salt,
            this.iterations
        );

        return [
            CONFIG.algorithm,
            this.iterations,
            salt.toString('base64url'),
            derived.toString('base64url')
        ].join('$');
    }

    parse(encodedHash) {
        if (typeof encodedHash !== 'string') {
            throw new Error('Invalid password credential.');
        }

        const parts = encodedHash.split('$');

        if (parts.length !== 4 || parts[0] !== CONFIG.algorithm) {
            throw new Error('Unsupported password hash format.');
        }

        const iterations = Number(parts[1]);

        if (
            !Number.isInteger(iterations) ||
            iterations < CONFIG.minimumIterations ||
            iterations > CONFIG.maximumIterations
        ) {
            throw new Error('Invalid PBKDF2 iteration count.');
        }

        if (
            !/^[A-Za-z0-9_-]+$/.test(parts[2]) ||
            !/^[A-Za-z0-9_-]+$/.test(parts[3])
        ) {
            throw new Error('Invalid Base64URL encoding.');
        }

        const salt = Buffer.from(parts[2], 'base64url');
        const expected = Buffer.from(parts[3], 'base64url');

        if (salt.length < CONFIG.saltLength || salt.length > 64) {
            throw new Error('Invalid salt length.');
        }

        if (expected.length !== CONFIG.keyLength) {
            throw new Error('Invalid derived-key length.');
        }

        return { iterations, salt, expected };
    }

    async verify(password, encodedHash) {
        try {
            if (
                typeof password !== 'string' ||
                Buffer.byteLength(password, 'utf8') >
                    CONFIG.maximumPasswordBytes
            ) {
                return false;
            }

            const normalized = password.normalize('NFC');
            const parsed = this.parse(encodedHash);

            const actual = await this.derive(
                normalized,
                parsed.salt,
                parsed.iterations
            );

            // timingSafeEqual requires identical input lengths.
            if (actual.length !== parsed.expected.length) {
                return false;
            }

            return crypto.timingSafeEqual(
                actual,
                parsed.expected
            );

        } catch {
            return false;
        }
    }

    needsRehash(encodedHash) {
        try {
            const parsed = this.parse(encodedHash);

            return parsed.iterations < this.iterations;
        } catch {
            return true;
        }
    }
}


/*
 * Serializes operations affecting one account.
 *
 * Different accounts can continue hashing concurrently, while operations
 * on the same account execute in a predictable order.
 */
class KeyedMutex {
    constructor() {
        this.tails = new Map();
    }

    async run(key, operation) {
        const previous = this.tails.get(key) || Promise.resolve();

        let release;

        const gate = new Promise(resolve => {
            release = resolve;
        });

        const tail = previous.then(() => gate);

        this.tails.set(key, tail);

        await previous;

        try {
            return await operation();
        } finally {
            release();

            if (this.tails.get(key) === tail) {
                this.tails.delete(key);
            }
        }
    }
}


class AuthenticationService extends EventEmitter {
    constructor() {
        super();

        this.policy = new PasswordPolicy();
        this.hasher = new PasswordHasher();

        this.accounts = new Map();
        this.accountMutex = new KeyedMutex();

        this.dummyHash = null;
    }

    async initialize() {
        // Used to perform comparable work for nonexistent account names.
        this.dummyHash = await this.hasher.hash(
            'internal dummy credential not for authentication'
        );
    }

    normalizeUsername(username) {
        if (typeof username !== 'string') {
            throw new TypeError('Username must be a string.');
        }

        const key = username.trim().toLowerCase();

        if (!/^[a-z0-9._-]{3,64}$/.test(key)) {
            throw new Error('Invalid account identifier.');
        }

        return key;
    }

    async register(username, password) {
        const key = this.normalizeUsername(username);

        const normalizedPassword = this.policy.validate(
            password,
            key
        );

        if (this.accounts.has(key)) {
            throw new Error('Account already exists.');
        }

        const passwordHash = await this.hasher.hash(
            normalizedPassword
        );

        // Recheck after asynchronous derivation to handle concurrent
        // account-creation requests.
        if (this.accounts.has(key)) {
            throw new Error('Account already exists.');
        }

        this.accounts.set(key, {
            username: key,
            passwordHash,
            enabled: true,
            failedAttempts: 0,
            lockedUntil: 0
        });

        this.emit('credential:created', {
            username: key,
            timestamp: new Date().toISOString()
        });
    }

    async authenticate(username, password) {
        if (!this.dummyHash) {
            throw new Error('Authentication service is not initialized.');
        }

        let key;

        try {
            key = this.normalizeUsername(username);
        } catch {
            await this.hasher.verify(password, this.dummyHash);
            return false;
        }

        const account = this.accounts.get(key);

        if (!account) {
            await this.hasher.verify(password, this.dummyHash);

            this.emit('authentication:failure', {
                username: key,
                reason: 'invalid_credentials'
            });

            return false;
        }

        return this.accountMutex.run(key, async () => {
            if (!account.enabled) {
                return false;
            }

            const now = Date.now();

            if (now < account.lockedUntil) {
                this.emit('authentication:throttled', {
                    username: key
                });

                return false;
            }

            const valid = await this.hasher.verify(
                password,
                account.passwordHash
            );

            if (!valid) {
                account.failedAttempts += 1;

                if (
                    account.failedAttempts >=
                    CONFIG.maximumFailures
                ) {
                    account.lockedUntil =
                        Date.now() + CONFIG.lockDurationMs;
                }

                this.emit('authentication:failure', {
                    username: key,
                    reason: 'invalid_credentials',
                    failures: account.failedAttempts
                });

                return false;
            }

            account.failedAttempts = 0;
            account.lockedUntil = 0;

            // Successful legacy authentication permits a credential upgrade.
            if (this.hasher.needsRehash(account.passwordHash)) {
                account.passwordHash = await this.hasher.hash(password);

                this.emit('credential:upgraded', {
                    username: key,
                    iterations: this.hasher.iterations
                });
            }

            this.emit('authentication:success', {
                username: key,
                timestamp: new Date().toISOString()
            });

            return true;
        });
    }

    disableAccount(username) {
        const key = this.normalizeUsername(username);
        const account = this.accounts.get(key);

        if (!account) {
            throw new Error('Account does not exist.');
        }

        account.enabled = false;

        this.emit('account:disabled', {
            username: key
        });
    }

    async seedLegacyCredential(username, password) {
        // This operation exists only to exercise migration behavior.
        const key = this.normalizeUsername(username);
        const account = this.accounts.get(key);

        if (!account) {
            throw new Error('Account does not exist.');
        }

        const legacyHasher = new PasswordHasher(120000);
        account.passwordHash = await legacyHasher.hash(password);
    }
}


async function demonstratePasswordHashing() {
    const service = new AuthenticationService();

    service.on('credential:created', event => {
        console.log('Credential created:', event.username);
    });

    service.on('credential:upgraded', event => {
        console.log(
            'Credential upgraded:',
            event.username,
            event.iterations
        );
    });

    service.on('authentication:failure', event => {
        console.log('Authentication failure:', event.username);
    });

    service.on('authentication:success', event => {
        console.log('Authentication successful:', event.username);
    });

    await service.initialize();

    const username = 'alex.developer';
    const password = 'Correct-Horse-Battery-Staple-2026!';

    await service.register(username, password);

    // Exercise backward-compatible credential migration.
    await service.seedLegacyCredential(username, password);

    const incorrect = await service.authenticate(
        username,
        'incorrect-authentication-secret'
    );

    console.log('Incorrect password accepted:', incorrect);

    const correct = await service.authenticate(
        username,
        password
    );

    console.log('Correct password accepted:', correct);

    console.log(
        'Upgraded iteration count:',
        service.hasher.parse(
            service.accounts.get(username).passwordHash
        ).iterations
    );

    // Unique salts must produce unique encoded credentials.
    const first = await service.hasher.hash(password);
    const second = await service.hasher.hash(password);

    if (first === second) {
        throw new Error('Salt uniqueness assertion failed.');
    }

    if (!(await service.hasher.verify(password, first))) {
        throw new Error('Valid password verification failed.');
    }

    if (await service.hasher.verify('incorrect-secret', first)) {
        throw new Error('Incorrect password was accepted.');
    }

    try {
        await service.register(
            'weak.account',
            'password123456789'
        );

        throw new Error('Weak password was incorrectly accepted.');

    } catch (error) {
        if (!(error instanceof PasswordPolicyError)) {
            throw error;
        }

        console.log('Weak password rejected successfully.');
    }

    // Exercise account-level throttling.
    const throttlePassword =
        'A-Long-Unique-Authentication-Secret-2026!';

    await service.register('throttle.user', throttlePassword);

    for (let i = 0; i < CONFIG.maximumFailures; i++) {
        await service.authenticate(
            'throttle.user',
            'incorrect-authentication-secret'
        );
    }

    const lockedLogin = await service.authenticate(
        'throttle.user',
        throttlePassword
    );

    if (lockedLogin) {
        throw new Error('Locked account incorrectly authenticated.');
    }

    console.log('Account throttling assertion passed.');
    console.log('All JavaScript security checks passed.');
}


demonstratePasswordHashing().catch(error => {
    console.error('Authentication demonstration failed:', error.message);
    process.exitCode = 1;
});
