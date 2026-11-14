'use strict';

/*
 * Introduction to Elliptic Curves
 * Event-driven finite-field elliptic curve laboratory.
 *
 * Runtime: Node.js 18+
 * No external dependencies.
 *
 * Educational implementation, not production cryptography.
 */

const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');

class CurveError extends Error {}
class InvalidCurveError extends CurveError {}
class InvalidPointError extends CurveError {}
class InverseError extends CurveError {}
class PolicyError extends CurveError {}

class FiniteField {
    constructor(prime) {
        if (!Number.isSafeInteger(prime) || prime < 5) {
            throw new InvalidCurveError(
                'Prime modulus must be a safe integer >= 5.'
            );
        }

        if (!FiniteField.isPrime(prime)) {
            throw new InvalidCurveError(
                'Modulus must be prime.'
            );
        }

        this.p = prime;
    }

    static isPrime(n) {
        if (n < 2) return false;
        if (n % 2 === 0) return n === 2;

        for (let d = 3; d * d <= n; d += 2) {
            if (n % d === 0) return false;
        }

        return true;
    }

    normalize(value) {
        return ((value % this.p) + this.p) % this.p;
    }

    add(a, b) {
        return this.normalize(a + b);
    }

    subtract(a, b) {
        return this.normalize(a - b);
    }

    multiply(a, b) {
        return this.normalize(a * b);
    }

    power(base, exponent) {
        if (!Number.isSafeInteger(exponent) || exponent < 0) {
            throw new RangeError('Exponent must be nonnegative.');
        }

        let result = 1n;
        let value = BigInt(this.normalize(base));
        let exp = BigInt(exponent);
        const modulus = BigInt(this.p);

        while (exp > 0n) {
            if (exp & 1n) {
                result = (result * value) % modulus;
            }

            value = (value * value) % modulus;
            exp >>= 1n;
        }

        return Number(result);
    }

    inverse(value) {
        let a = BigInt(this.normalize(value));
        const modulus = BigInt(this.p);

        if (a === 0n) {
            throw new InverseError('Zero has no modular inverse.');
        }

        // Extended Euclidean algorithm.
        let oldR = a;
        let r = modulus;
        let oldS = 1n;
        let s = 0n;

        while (r !== 0n) {
            const quotient = oldR / r;

            [oldR, r] = [r, oldR - quotient * r];
            [oldS, s] = [s, oldS - quotient * s];
        }

        if (oldR !== 1n) {
            throw new InverseError('Element is not invertible.');
        }

        return Number((oldS % modulus + modulus) % modulus);
    }
}

class ECPoint {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        Object.freeze(this);
    }

    static infinity() {
        return new ECPoint(null, null);
    }

    get isInfinity() {
        return this.x === null && this.y === null;
    }

    toJSON() {
        return this.isInfinity
            ? { infinity: true }
            : { x: this.x, y: this.y };
    }

    toString() {
        return this.isInfinity
            ? 'O'
            : `(${this.x}, ${this.y})`;
    }
}

class EllipticCurve {
    constructor(a, b, prime) {
        this.field = new FiniteField(prime);
        this.p = prime;

        if (!Number.isSafeInteger(a) ||
            !Number.isSafeInteger(b)) {
            throw new InvalidCurveError(
                'Curve coefficients must be safe integers.'
            );
        }

        this.a = this.field.normalize(a);
        this.b = this.field.normalize(b);

        const discriminant = this.field.add(
            this.field.multiply(
                4,
                this.field.power(this.a, 3)
            ),
            this.field.multiply(
                27,
                this.field.power(this.b, 2)
            )
        );

        if (discriminant === 0) {
            throw new InvalidCurveError(
                'Singular curves are not allowed.'
            );
        }
    }

    normalize(point) {
        if (point.isInfinity) return ECPoint.infinity();

        return new ECPoint(
            this.field.normalize(point.x),
            this.field.normalize(point.y)
        );
    }

    contains(point) {
        if (!(point instanceof ECPoint)) return false;

        if (point.isInfinity) return true;

        if (!Number.isSafeInteger(point.x) ||
            !Number.isSafeInteger(point.y)) {
            return false;
        }

        const x = this.field.normalize(point.x);
        const y = this.field.normalize(point.y);

        const left = this.field.power(y, 2);

        const right = this.field.add(
            this.field.add(
                this.field.power(x, 3),
                this.field.multiply(this.a, x)
            ),
            this.b
        );

        return left === right;
    }

    validate(point) {
        if (!this.contains(point)) {
            throw new InvalidPointError(
                `Point ${point} is not on the curve.`
            );
        }
    }

    negate(point) {
        this.validate(point);

        if (point.isInfinity) return point;

        return new ECPoint(
            this.field.normalize(point.x),
            this.field.normalize(-point.y)
        );
    }

    add(first, second) {
        this.validate(first);
        this.validate(second);

        first = this.normalize(first);
        second = this.normalize(second);

        if (first.isInfinity) return second;
        if (second.isInfinity) return first;

        const f = this.field;
        const x1 = first.x;
        const y1 = first.y;
        const x2 = second.x;
        const y2 = second.y;

        if (x1 === x2 && f.add(y1, y2) === 0) {
            return ECPoint.infinity();
        }

        let numerator;
        let denominator;

        if (x1 === x2 && y1 === y2) {
            numerator = f.add(
                f.multiply(3, f.power(x1, 2)),
                this.a
            );

            denominator = f.multiply(2, y1);
        } else {
            numerator = f.subtract(y2, y1);
            denominator = f.subtract(x2, x1);
        }

        const slope = f.multiply(
            numerator,
            f.inverse(denominator)
        );

        const x3 = f.subtract(
            f.subtract(f.power(slope, 2), x1),
            x2
        );

        const y3 = f.subtract(
            f.multiply(slope, f.subtract(x1, x3)),
            y1
        );

        const result = new ECPoint(x3, y3);
        this.validate(result);

        return result;
    }

    multiply(scalar, point) {
        if (typeof scalar !== 'bigint') {
            throw new TypeError('Scalar must be a BigInt.');
        }

        this.validate(point);

        if (scalar < 0n) {
            return this.multiply(-scalar, this.negate(point));
        }

        let result = ECPoint.infinity();
        let current = this.normalize(point);

        // Binary double-and-add multiplication.
        while (scalar > 0n) {
            if ((scalar & 1n) === 1n) {
                result = this.add(result, current);
            }

            current = this.add(current, current);
            scalar >>= 1n;
        }

        return result;
    }

    enumeratePoints() {
        const points = [];

        for (let x = 0; x < this.p; x++) {
            for (let y = 0; y < this.p; y++) {
                const point = new ECPoint(x, y);

                if (this.contains(point)) {
                    points.push(point);
                }
            }
        }

        return points;
    }

    groupOrder() {
        return this.enumeratePoints().length + 1;
    }

    pointOrder(point) {
        this.validate(point);

        let current = ECPoint.infinity();
        const limit = this.groupOrder();

        for (let order = 1; order <= limit; order++) {
            current = this.add(current, point);

            if (current.isInfinity) return order;
        }

        throw new CurveError('Point order not found.');
    }
}

class CurveRegistry extends EventEmitter {
    constructor() {
        super();
        this.curves = new Map();
        this.operations = [];
    }

    register(name, curve, generator) {
        if (typeof name !== 'string' ||
            !/^[a-zA-Z0-9_-]{1,40}$/.test(name)) {
            throw new TypeError('Invalid curve identifier.');
        }

        if (this.curves.has(name)) {
            throw new PolicyError('Curve already registered.');
        }

        if (!(curve instanceof EllipticCurve)) {
            throw new TypeError('Invalid curve instance.');
        }

        curve.validate(generator);

        const entry = Object.freeze({
            curve,
            generator: curve.normalize(generator)
        });

        this.curves.set(name, entry);

        this.emit('curve:registered', {
            name,
            modulus: curve.p
        });

        return entry;
    }

    get(name) {
        const entry = this.curves.get(name);

        if (!entry) {
            throw new PolicyError(`Unknown curve: ${name}`);
        }

        return entry;
    }

    async execute(operation) {
        if (!operation || typeof operation !== 'object') {
            throw new TypeError('Operation must be an object.');
        }

        const { curveName, type, scalar } = operation;
        const entry = this.get(curveName);

        let result;

        switch (type) {
            case 'ADD': {
                const first = new ECPoint(
                    operation.first.x,
                    operation.first.y
                );

                const second = new ECPoint(
                    operation.second.x,
                    operation.second.y
                );

                result = entry.curve.add(first, second);
                break;
            }

            case 'MULTIPLY': {
                if (typeof scalar !== 'string' ||
                    !/^-?\d+$/.test(scalar)) {
                    throw new TypeError(
                        'Scalar must be a decimal integer string.'
                    );
                }

                result = entry.curve.multiply(
                    BigInt(scalar),
                    entry.generator
                );
                break;
            }

            case 'NEGATE': {
                const point = new ECPoint(
                    operation.point.x,
                    operation.point.y
                );

                result = entry.curve.negate(point);
                break;
            }

            default:
                throw new PolicyError(
                    `Unsupported operation: ${type}`
                );
        }

        const event = Object.freeze({
            id: crypto.randomUUID(),
            curveName,
            type,
            result: result.toJSON(),
            timestamp: new Date().toISOString()
        });

        this.operations.push(event);

        this.emit('operation:completed', event);

        return event;
    }

    getAuditLog() {
        return this.operations.map(
            event => ({ ...event })
        );
    }
}

async function main() {
    const registry = new CurveRegistry();

    registry.on('curve:registered', event => {
        console.log('Registered:', event);
    });

    registry.on('operation:completed', event => {
        console.log(
            `Completed ${event.type}:`,
            event.result
        );
    });

    const curve = new EllipticCurve(2, 2, 17);
    const generator = new ECPoint(5, 1);

    registry.register('educational-17', curve, generator);

    console.log('\nCurve group order:', curve.groupOrder());
    console.log('Generator order:', curve.pointOrder(generator));

    const operations = [
        {
            curveName: 'educational-17',
            type: 'MULTIPLY',
            scalar: '2'
        },
        {
            curveName: 'educational-17',
            type: 'MULTIPLY',
            scalar: '7'
        },
        {
            curveName: 'educational-17',
            type: 'ADD',
            first: { x: 5, y: 1 },
            second: { x: 5, y: 1 }
        },
        {
            curveName: 'educational-17',
            type: 'NEGATE',
            point: { x: 5, y: 1 }
        }
    ];

    // Promise-based processing preserves operation order.
    for (const operation of operations) {
        await registry.execute(operation);
    }

    console.log('\nDiffie-Hellman demonstration');

    const alicePrivate = 5n;
    const bobPrivate = 7n;

    const alicePublic = curve.multiply(
        alicePrivate,
        generator
    );

    const bobPublic = curve.multiply(
        bobPrivate,
        generator
    );

    const aliceShared = curve.multiply(
        alicePrivate,
        bobPublic
    );

    const bobShared = curve.multiply(
        bobPrivate,
        alicePublic
    );

    console.log('Alice public:', alicePublic.toString());
    console.log('Bob public:', bobPublic.toString());
    console.log('Shared secret:', aliceShared.toString());

    if (aliceShared.toString() !== bobShared.toString()) {
        throw new CurveError('Shared-secret mismatch.');
    }

    console.log('\nAudit log:');
    console.log(
        JSON.stringify(registry.getAuditLog(), null, 2)
    );

    // Validation of expected mathematical properties.
    const infinity = ECPoint.infinity();

    if (!curve.add(generator, infinity).equals?.(generator)) {
        // Equality is checked explicitly below.
        const identityResult = curve.add(generator, infinity);
        if (identityResult.x !== generator.x ||
            identityResult.y !== generator.y) {
            throw new CurveError('Identity property failed.');
        }
    }

    const inverseResult = curve.add(
        generator,
        curve.negate(generator)
    );

    if (!inverseResult.isInfinity) {
        throw new CurveError('Inverse property failed.');
    }

    try {
        curve.validate(new ECPoint(1, 1));
    } catch (error) {
        console.log('\nExpected invalid-point rejection:', error.message);
    }

    try {
        new EllipticCurve(0, 0, 17);
    } catch (error) {
        console.log('Expected singular-curve rejection:', error.message);
    }

    // Demonstrate durable audit output using atomic file replacement.
    const auditPath = 'elliptic_curve_audit.json';
    const temporaryPath = `${auditPath}.tmp`;

    await fs.writeFile(
        temporaryPath,
        JSON.stringify(registry.getAuditLog(), null, 2),
        { encoding: 'utf8', mode: 0o600 }
    );

    await fs.rename(temporaryPath, auditPath);

    console.log('\nAudit exported to:', auditPath);
}

main().catch(error => {
    console.error('Execution failed:', error.message);
    process.exitCode = 1;
});
