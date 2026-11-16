'use strict';

/**
 * Elliptic Curve Calculations using JavaScript BigInt.
 *
 * Features:
 * - Finite-field arithmetic
 * - Extended Euclidean algorithm
 * - Point validation
 * - Point addition and doubling
 * - Point negation
 * - Scalar multiplication
 * - Point enumeration
 * - ECDH demonstration
 * - Event-driven calculation reporting
 *
 * Educational implementation, not production cryptography.
 */

const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');

class ECCError extends Error {}

class CurveValidationError extends ECCError {}

class PointValidationError extends ECCError {}

class ArithmeticError extends ECCError {}

function mod(value, modulus) {
    const result = value % modulus;
    return result < 0n ? result + modulus : result;
}

function gcd(a, b) {
    while (b !== 0n) {
        [a, b] = [b, a % b];
    }

    return a < 0n ? -a : a;
}

function extendedGCD(a, b) {
    let oldR = a;
    let r = b;

    let oldS = 1n;
    let s = 0n;

    let oldT = 0n;
    let t = 1n;

    while (r !== 0n) {
        const quotient = oldR / r;

        [oldR, r] = [r, oldR - quotient * r];
        [oldS, s] = [s, oldS - quotient * s];
        [oldT, t] = [t, oldT - quotient * t];
    }

    return {
        gcd: oldR,
        x: oldS,
        y: oldT
    };
}

function modInverse(value, modulus) {
    value = mod(value, modulus);

    const result = extendedGCD(value, modulus);

    if (result.gcd !== 1n) {
        throw new ArithmeticError(
            'Modular inverse does not exist.'
        );
    }

    return mod(result.x, modulus);
}

function modPow(base, exponent, modulus) {
    let result = 1n;

    base = mod(base, modulus);

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = mod(result * base, modulus);
        }

        base = mod(base * base, modulus);
        exponent >>= 1n;
    }

    return result;
}

function isPrime(n) {
    if (n < 2n) return false;

    if (n === 2n || n === 3n) return true;

    if (n % 2n === 0n) return false;

    for (let divisor = 3n; divisor * divisor <= n; divisor += 2n) {
        if (n % divisor === 0n) return false;
    }

    return true;
}

class ECPoint {
    constructor(x = null, y = null) {
        if ((x === null) !== (y === null)) {
            throw new PointValidationError(
                'Both coordinates must be null for infinity.'
            );
        }

        this.x = x;
        this.y = y;

        Object.freeze(this);
    }

    get isInfinity() {
        return this.x === null;
    }

    toString() {
        return this.isInfinity
            ? 'O'
            : `(${this.x}, ${this.y})`;
    }

    toJSON() {
        return this.isInfinity
            ? { infinity: true }
            : {
                x: this.x.toString(),
                y: this.y.toString()
            };
    }
}

const INFINITY = new ECPoint();

class EllipticCurve extends EventEmitter {
    constructor(a, b, p) {
        super();

        if (
            typeof a !== 'bigint' ||
            typeof b !== 'bigint' ||
            typeof p !== 'bigint'
        ) {
            throw new CurveValidationError(
                'Curve parameters must be BigInt values.'
            );
        }

        if (!isPrime(p) || p < 3n) {
            throw new CurveValidationError(
                'The modulus must be a prime >= 3.'
            );
        }

        this.p = p;
        this.a = mod(a, p);
        this.b = mod(b, p);

        const discriminant = mod(
            4n * modPow(this.a, 3n, p) +
            27n * modPow(this.b, 2n, p),
            p
        );

        if (discriminant === 0n) {
            throw new CurveValidationError(
                'Singular elliptic curves are invalid.'
            );
        }
    }

    contains(point) {
        if (!(point instanceof ECPoint)) return false;

        if (point.isInfinity) return true;

        if (
            point.x < 0n ||
            point.x >= this.p ||
            point.y < 0n ||
            point.y >= this.p
        ) {
            return false;
        }

        const lhs = modPow(point.y, 2n, this.p);

        const rhs = mod(
            modPow(point.x, 3n, this.p) +
            this.a * point.x +
            this.b,
            this.p
        );

        return lhs === rhs;
    }

    validate(point) {
        if (!this.contains(point)) {
            throw new PointValidationError(
                `Invalid curve point: ${point}`
            );
        }
    }

    negate(point) {
        this.validate(point);

        if (point.isInfinity) return INFINITY;

        return new ECPoint(
            point.x,
            mod(-point.y, this.p)
        );
    }

    add(p1, p2) {
        this.validate(p1);
        this.validate(p2);

        if (p1.isInfinity) return p2;
        if (p2.isInfinity) return p1;

        const { x: x1, y: y1 } = p1;
        const { x: x2, y: y2 } = p2;

        if (
            x1 === x2 &&
            mod(y1 + y2, this.p) === 0n
        ) {
            return INFINITY;
        }

        let numerator;
        let denominator;

        if (x1 === x2 && y1 === y2) {
            if (y1 === 0n) return INFINITY;

            numerator = mod(
                3n * x1 * x1 + this.a,
                this.p
            );

            denominator = mod(2n * y1, this.p);
        } else {
            numerator = mod(y2 - y1, this.p);
            denominator = mod(x2 - x1, this.p);
        }

        const slope = mod(
            numerator * modInverse(denominator, this.p),
            this.p
        );

        const x3 = mod(
            slope * slope - x1 - x2,
            this.p
        );

        const y3 = mod(
            slope * (x1 - x3) - y1,
            this.p
        );

        const result = new ECPoint(x3, y3);

        this.validate(result);

        return result;
    }

    subtract(p1, p2) {
        return this.add(p1, this.negate(p2));
    }

    multiply(scalar, point) {
        if (typeof scalar !== 'bigint') {
            throw new ECCError('Scalar must be BigInt.');
        }

        this.validate(point);

        if (scalar < 0n) {
            return this.multiply(-scalar, this.negate(point));
        }

        let result = INFINITY;
        let addend = point;

        while (scalar > 0n) {
            if (scalar & 1n) {
                result = this.add(result, addend);
            }

            addend = this.add(addend, addend);
            scalar >>= 1n;
        }

        return result;
    }

    enumeratePoints() {
        const points = [INFINITY];

        for (let x = 0n; x < this.p; x++) {
            const rhs = mod(
                x * x * x + this.a * x + this.b,
                this.p
            );

            for (let y = 0n; y < this.p; y++) {
                if (mod(y * y, this.p) === rhs) {
                    points.push(new ECPoint(x, y));
                }
            }
        }

        return points;
    }

    pointOrder(point) {
        this.validate(point);

        if (point.isInfinity) return 1n;

        let current = INFINITY;

        // Hasse's bound gives a finite upper bound.
        const bound = this.p + 1n + 2n * BigInt(
            Math.floor(Math.sqrt(Number(this.p)))
        );

        for (let i = 1n; i <= bound; i++) {
            current = this.add(current, point);

            if (current.isInfinity) return i;
        }

        throw new ECCError('Point order could not be determined.');
    }

    describe() {
        return {
            a: this.a.toString(),
            b: this.b.toString(),
            p: this.p.toString(),
            equation: `y² = x³ + ${this.a}x + ${this.b} mod ${this.p}`
        };
    }
}

class ECDHProtocol {
    constructor(curve, generator) {
        curve.validate(generator);

        if (generator.isInfinity) {
            throw new PointValidationError(
                'Generator cannot be infinity.'
            );
        }

        this.curve = curve;
        this.generator = generator;
    }

    publicKey(privateKey) {
        if (privateKey <= 0n) {
            throw new ECCError(
                'Private key must be positive.'
            );
        }

        return this.curve.multiply(
            privateKey,
            this.generator
        );
    }

    sharedSecret(privateKey, publicKey) {
        if (privateKey <= 0n) {
            throw new ECCError('Invalid private key.');
        }

        this.curve.validate(publicKey);

        if (publicKey.isInfinity) {
            throw new PointValidationError(
                'Public key cannot be infinity.'
            );
        }

        const secret = this.curve.multiply(
            privateKey,
            publicKey
        );

        if (secret.isInfinity) {
            throw new ECCError('Degenerate shared secret.');
        }

        return secret;
    }
}

class CalculationEngine extends EventEmitter {
    constructor(curve) {
        super();

        this.curve = curve;
        this.history = [];
    }

    async execute(operation, ...args) {
        // Event-driven processing allows separate observers
        // to monitor calculation success and failure.
        await Promise.resolve();

        try {
            if (typeof this.curve[operation] !== 'function') {
                throw new ECCError(
                    `Unsupported operation: ${operation}`
                );
            }

            const result = this.curve[operation](...args);

            const entry = {
                operation,
                result: result.toString()
            };

            this.history.push(entry);

            this.emit('calculation', entry);

            return result;
        } catch (error) {
            this.emit('calculationError', {
                operation,
                message: error.message
            });

            throw error;
        }
    }
}

async function main() {
    const curve = new EllipticCurve(2n, 2n, 17n);
    const generator = new ECPoint(5n, 1n);

    curve.validate(generator);

    const engine = new CalculationEngine(curve);

    engine.on('calculation', event => {
        console.log(
            `[EVENT] ${event.operation}: ${event.result}`
        );
    });

    engine.on('calculationError', event => {
        console.error(
            `[ERROR] ${event.operation}: ${event.message}`
        );
    });

    console.log('\nCURVE');
    console.log(curve.describe());

    console.log('\nPOINT OPERATIONS');

    const doubled = await engine.execute(
        'add',
        generator,
        generator
    );

    console.log('Generator:', generator.toString());
    console.log('2G:', doubled.toString());

    const tripled = await engine.execute(
        'multiply',
        3n,
        generator
    );

    console.log('3G:', tripled.toString());

    const points = curve.enumeratePoints();

    console.log('\nPOINT ENUMERATION');
    console.log('Total points:', points.length);

    for (const point of points) {
        console.log(point.toString());
    }

    const order = curve.pointOrder(generator);

    console.log('\nPOINT ORDER');
    console.log(order.toString());

    console.log('\nECDH');

    const protocol = new ECDHProtocol(curve, generator);

    const alicePrivate = 5n;
    const bobPrivate = 7n;

    const alicePublic = protocol.publicKey(alicePrivate);
    const bobPublic = protocol.publicKey(bobPrivate);

    const aliceSecret = protocol.sharedSecret(
        alicePrivate,
        bobPublic
    );

    const bobSecret = protocol.sharedSecret(
        bobPrivate,
        alicePublic
    );

    if (aliceSecret.toString() !== bobSecret.toString()) {
        throw new ECCError('ECDH verification failed.');
    }

    console.log('Alice public:', alicePublic.toString());
    console.log('Bob public:', bobPublic.toString());
    console.log('Shared secret:', aliceSecret.toString());

    const report = {
        curve: curve.describe(),
        generator: generator.toJSON(),
        order: order.toString(),
        totalPoints: points.length,
        alicePublic: alicePublic.toJSON(),
        bobPublic: bobPublic.toJSON(),
        sharedSecret: aliceSecret.toJSON(),
        operations: engine.history
    };

    await fs.writeFile(
        'ecc_report.json',
        JSON.stringify(report, null, 2),
        { encoding: 'utf8', mode: 0o600 }
    );

    console.log('\nReport written to ecc_report.json');

    // Arithmetic invariants.
    if (!curve.add(generator, INFINITY).equals) {
        // Point equality is checked through coordinates below.
        if (curve.add(generator, INFINITY).toString() !== generator.toString()) {
            throw new ECCError('Identity invariant failed.');
        }
    }

    if (
        curve.add(generator, curve.negate(generator)).isInfinity !== true
    ) {
        throw new ECCError('Inverse-point invariant failed.');
    }

    if (
        curve.multiply(0n, generator).isInfinity !== true
    ) {
        throw new ECCError('Zero-scalar invariant failed.');
    }

    console.log('All validation checks passed.');
}

main().catch(error => {
    console.error('Execution failed:', error.message);
    process.exitCode = 1;
});
