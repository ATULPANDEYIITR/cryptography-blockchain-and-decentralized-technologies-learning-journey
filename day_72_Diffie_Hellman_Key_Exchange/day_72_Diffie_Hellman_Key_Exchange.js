'use strict';

/**
 * Diffie-Hellman Key Exchange
 *
 * Node.js 20+ implementation.
 *
 * Demonstrates:
 * - Safe-prime subgroup parameters
 * - BigInt modular exponentiation
 * - Cryptographically secure randomness
 * - Public-key validation
 * - Asynchronous key derivation
 * - HKDF-SHA256
 * - Event-driven exchange lifecycle
 * - Failure handling
 *
 * The demonstration parameters are deliberately small.
 * They must never be used for production cryptography.
 */

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const assert = require('node:assert/strict');

class DHError extends Error {
    constructor(message) {
        super(message);
        this.name = 'DHError';
    }
}

class ParameterError extends DHError {
    constructor(message) {
        super(message);
        this.name = 'ParameterError';
    }
}

class ExchangeError extends DHError {
    constructor(message) {
        super(message);
        this.name = 'ExchangeError';
    }
}

function modPow(base, exponent, modulus) {
    if (modulus <= 1n || exponent < 0n) {
        throw new RangeError('Invalid modular exponentiation arguments.');
    }

    let result = 1n;
    base = ((base % modulus) + modulus) % modulus;

    while (exponent > 0n) {
        if ((exponent & 1n) === 1n) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1n;
    }

    return result;
}

function isProbablePrime(n) {
    if (n < 2n) return false;

    const smallPrimes = [
        2n, 3n, 5n, 7n, 11n, 13n, 17n,
        19n, 23n, 29n, 31n, 37n
    ];

    for (const prime of smallPrimes) {
        if (n === prime) return true;
        if (n % prime === 0n) return false;
    }

    let d = n - 1n;
    let s = 0;

    while (d % 2n === 0n) {
        d /= 2n;
        s++;
    }

    for (const base of [2n, 3n, 5n, 7n, 11n, 13n, 17n]) {
        if (base >= n - 1n) continue;

        let x = modPow(base, d, n);

        if (x === 1n || x === n - 1n) continue;

        let passed = false;

        for (let i = 1; i < s; i++) {
            x = modPow(x, 2n, n);

            if (x === n - 1n) {
                passed = true;
                break;
            }
        }

        if (!passed) return false;
    }

    return true;
}

class DHGroup {
    constructor(p, q, g) {
        this.p = p;
        this.q = q;
        this.g = g;
        Object.freeze(this);
    }

    validate() {
        if (
            this.p <= 5n ||
            !isProbablePrime(this.p) ||
            !isProbablePrime(this.q)
        ) {
            throw new ParameterError('Invalid prime parameters.');
        }

        if (this.p !== 2n * this.q + 1n) {
            throw new ParameterError('Expected safe-prime group.');
        }

        if (
            this.g <= 1n ||
            this.g >= this.p ||
            modPow(this.g, this.q, this.p) !== 1n
        ) {
            throw new ParameterError('Invalid subgroup generator.');
        }
    }
}

const GROUP = new DHGroup(23n, 11n, 2n);

function randomPrivateKey(group) {
    group.validate();

    // Rejection sampling avoids modulo bias.
    const range = group.q - 1n;
    const bits = range.toString(2).length;
    const byteLength = Math.ceil(bits / 8);
    const mask = (1n << BigInt(bits)) - 1n;

    while (true) {
        const bytes = crypto.randomBytes(byteLength);
        const candidate =
            BigInt('0x' + bytes.toString('hex')) & mask;

        if (candidate < range) {
            return candidate + 1n;
        }
    }
}

function publicKey(privateKey, group) {
    group.validate();

    if (privateKey < 1n || privateKey >= group.q) {
        throw new ExchangeError('Invalid private key.');
    }

    return modPow(group.g, privateKey, group.p);
}

function validatePublicKey(value, group) {
    if (value <= 1n || value >= group.p - 1n) {
        throw new ExchangeError('Public key outside valid range.');
    }

    if (modPow(value, group.q, group.p) !== 1n) {
        throw new ExchangeError('Public key outside subgroup.');
    }
}

function sharedSecret(privateKey, peerPublic, group) {
    validatePublicKey(peerPublic, group);

    if (privateKey < 1n || privateKey >= group.q) {
        throw new ExchangeError('Invalid private key.');
    }

    const secret = modPow(peerPublic, privateKey, group.p);

    if (secret === 1n) {
        throw new ExchangeError('Trivial shared secret rejected.');
    }

    return secret;
}

function encodeInteger(value, width) {
    let hex = value.toString(16);

    if (hex.length % 2 !== 0) {
        hex = '0' + hex;
    }

    const result = Buffer.from(hex, 'hex');

    if (result.length > width) {
        throw new ExchangeError('Integer exceeds encoding width.');
    }

    return Buffer.concat([
        Buffer.alloc(width - result.length),
        result
    ]);
}

function hkdf(secret, salt, info, length = 32) {
    if (length < 1 || length > 8160) {
        throw new RangeError('Invalid HKDF output length.');
    }

    return new Promise((resolve, reject) => {
        crypto.hkdf(
            'sha256',
            secret,
            salt,
            info,
            length,
            (error, derivedKey) => {
                if (error) reject(error);
                else resolve(Buffer.from(derivedKey));
            }
        );
    });
}

const ExchangeState = Object.freeze({
    CREATED: 'CREATED',
    KEYS_EXCHANGED: 'KEYS_EXCHANGED',
    VERIFIED: 'VERIFIED',
    DERIVED: 'DERIVED',
    FAILED: 'FAILED'
});

class Participant {
    constructor(name, group) {
        if (!name.trim()) {
            throw new TypeError('Participant name is required.');
        }

        this.name = name;
        this.privateKey = randomPrivateKey(group);
        this.publicKey = publicKey(this.privateKey, group);
    }

    compute(peerPublic, group) {
        return sharedSecret(this.privateKey, peerPublic, group);
    }
}

class ExchangeManager extends EventEmitter {
    constructor(group) {
        super();

        this.group = group;
        this.state = ExchangeState.CREATED;
        this.audit = [];
    }

    transition(nextState, details = {}) {
        this.state = nextState;

        const event = Object.freeze({
            state: nextState,
            timestamp: new Date().toISOString(),
            ...details
        });

        this.audit.push(event);
        this.emit('stateChange', event);
    }

    async execute() {
        try {
            this.group.validate();

            const alice = new Participant('Alice', this.group);
            const bob = new Participant('Bob', this.group);

            const aliceSecret = alice.compute(
                bob.publicKey,
                this.group
            );

            const bobSecret = bob.compute(
                alice.publicKey,
                this.group
            );

            this.transition(ExchangeState.KEYS_EXCHANGED);

            if (aliceSecret !== bobSecret) {
                throw new ExchangeError('Key agreement mismatch.');
            }

            this.transition(ExchangeState.VERIFIED);

            const transcript = Buffer.from([
                'DH-v1',
                this.group.p.toString(),
                this.group.q.toString(),
                this.group.g.toString(),
                alice.publicKey.toString(),
                bob.publicKey.toString()
            ].join('|'));

            const transcriptHash = crypto
                .createHash('sha256')
                .update(transcript)
                .digest();

            const width = Math.ceil(
                this.group.p.toString(2).length / 8
            );

            const key = await hkdf(
                encodeInteger(aliceSecret, width),
                transcriptHash,
                Buffer.from('educational-dh-session-key'),
                32
            );

            this.transition(ExchangeState.DERIVED);

            return {
                alicePublic: alice.publicKey,
                bobPublic: bob.publicKey,
                sharedSecret: aliceSecret,
                sessionKey: key.toString('hex'),
                transcriptHash: transcriptHash.toString('hex'),
                state: this.state
            };

        } catch (error) {
            this.transition(ExchangeState.FAILED, {
                error: error.message
            });

            throw error;
        }
    }
}

async function runTests() {
    GROUP.validate();

    const alice = new Participant('Alice', GROUP);
    const bob = new Participant('Bob', GROUP);

    assert.equal(
        alice.compute(bob.publicKey, GROUP),
        bob.compute(alice.publicKey, GROUP)
    );

    assert.throws(
        () => validatePublicKey(1n, GROUP),
        ExchangeError
    );

    assert.throws(
        () => validatePublicKey(5n, GROUP),
        ExchangeError
    );

    assert.throws(
        () => publicKey(0n, GROUP),
        ExchangeError
    );

    const key = await hkdf(
        Buffer.from('test-secret'),
        Buffer.from('test-salt'),
        Buffer.from('test-context'),
        32
    );

    assert.equal(key.length, 32);

    const manager = new ExchangeManager(GROUP);
    const transitions = [];

    manager.on('stateChange', event => {
        transitions.push(event.state);
    });

    const result = await manager.execute();

    assert.equal(result.state, ExchangeState.DERIVED);

    assert.deepEqual(transitions, [
        ExchangeState.KEYS_EXCHANGED,
        ExchangeState.VERIFIED,
        ExchangeState.DERIVED
    ]);

    console.log('All tests passed.');
}

async function main() {
    console.log('DIFFIE-HELLMAN KEY EXCHANGE');
    console.log('===========================');

    console.log('p:', GROUP.p.toString());
    console.log('q:', GROUP.q.toString());
    console.log('g:', GROUP.g.toString());

    const manager = new ExchangeManager(GROUP);

    manager.on('stateChange', event => {
        console.log('EVENT:', event.state);
    });

    const result = await manager.execute();

    console.log('\nAlice public key:', result.alicePublic.toString());
    console.log('Bob public key:', result.bobPublic.toString());
    console.log('Shared secret:', result.sharedSecret.toString());
    console.log('Session key:', result.sessionKey);
    console.log('Transcript hash:', result.transcriptHash);

    console.log('\nSecurity: EDUCATIONAL ONLY');

    await runTests();
}

main().catch(error => {
    console.error('Exchange failed:', error.message);
    process.exitCode = 1;
});
