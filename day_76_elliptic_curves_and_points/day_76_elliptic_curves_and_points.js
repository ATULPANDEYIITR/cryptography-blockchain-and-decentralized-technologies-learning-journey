"use strict";

/*
 * Elliptic Curves and Points
 *
 * Event-driven finite-field elliptic curve laboratory.
 *
 * Features:
 * - BigInt finite-field arithmetic
 * - Short Weierstrass curves
 * - Immutable point objects
 * - Point addition and doubling
 * - Double-and-add scalar multiplication
 * - Point enumeration and order calculation
 * - Event-driven operation tracking
 * - Asynchronous operation execution
 * - Validation and structured error handling
 *
 * Educational implementation only.
 */

const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");

class CurveError extends Error {
    constructor(message) {
        super(message);
        this.name = "CurveError";
    }
}

class InvalidCurveError extends CurveError {
    constructor(message) {
        super(message);
        this.name = "InvalidCurveError";
    }
}

class InvalidPointError extends CurveError {
    constructor(message) {
        super(message);
        this.name = "InvalidPointError";
    }
}

class Point {
    constructor(x = null, y = null) {
        if ((x === null) !== (y === null)) {
            throw new InvalidPointError(
                "Both coordinates must be null for infinity."
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
            ? "O (point at infinity)"
            : `(${this.x}, ${this.y})`;
    }
}

const INFINITY = new Point();

function mod(value, modulus) {
    return ((value % modulus) + modulus) % modulus;
}

function modPow(base, exponent, modulus) {
    let result = 1n;
    base = mod(base, modulus);

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = result * base % modulus;
        }

        base = base * base % modulus;
        exponent >>= 1n;
    }

    return result;
}

function modInverse(value, modulus) {
    let a = mod(value, modulus);
    let b = modulus;

    let x0 = 1n;
    let x1 = 0n;

    if (a === 0n) {
        throw new CurveError("Zero has no modular inverse.");
    }

    // Extended Euclidean algorithm.
    while (b !== 0n) {
        const quotient = a / b;

        [a, b] = [b, a - quotient * b];
        [x0, x1] = [x1, x0 - quotient * x1];
    }

    if (a !== 1n) {
        throw new CurveError("Element is not invertible.");
    }

    return mod(x0, modulus);
}

function isPrime(n) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;

    // Deterministic trial division, suitable for educational fields.
    for (let divisor = 3n; divisor * divisor <= n; divisor += 2n) {
        if (n % divisor === 0n) return false;
    }

    return true;
}

class EllipticCurve extends EventEmitter {
    constructor(p, a, b) {
        super();

        this.p = BigInt(p);
        this.a = BigInt(a);
        this.b = BigInt(b);

        if (!isPrime(this.p)) {
            throw new InvalidCurveError(
                "The field modulus must be prime."
            );
        }

        this.a = mod(this.a, this.p);
        this.b = mod(this.b, this.p);

        const discriminant = mod(
            4n * modPow(this.a, 3n, this.p) +
            27n * modPow(this.b, 2n, this.p),
            this.p
        );

        if (discriminant === 0n) {
            throw new InvalidCurveError(
                "The curve is singular."
            );
        }

        this.infinity = INFINITY;
        this.operationCount = 0;
    }

    contains(point) {
        if (!(point instanceof Point)) return false;
        if (point.isInfinity) return true;

        if (
            point.x < 0n || point.x >= this.p ||
            point.y < 0n || point.y >= this.p
        ) {
            return false;
        }

        const left = mod(point.y * point.y, this.p);

        const right = mod(
            point.x * point.x * point.x +
            this.a * point.x +
            this.b,
            this.p
        );

        return left === right;
    }

    validate(point) {
        if (!this.contains(point)) {
            throw new InvalidPointError(
                `Invalid curve point: ${point}`
            );
        }
    }

    point(x, y) {
        const point = new Point(
            mod(BigInt(x), this.p),
            mod(BigInt(y), this.p)
        );

        this.validate(point);
        return point;
    }

    negate(point) {
        this.validate(point);

        if (point.isInfinity) return this.infinity;

        return new Point(
            point.x,
            mod(-point.y, this.p)
        );
    }

    add(p1, p2) {
        this.validate(p1);
        this.validate(p2);

        this.operationCount++;

        if (p1.isInfinity) return p2;
        if (p2.isInfinity) return p1;

        const { x: x1, y: y1 } = p1;
        const { x: x2, y: y2 } = p2;

        if (
            x1 === x2 &&
            mod(y1 + y2, this.p) === 0n
        ) {
            this.emit("point:add", {
                left: p1.toString(),
                right: p2.toString(),
                result: "O"
            });

            return this.infinity;
        }

        let numerator;
        let denominator;

        if (x1 === x2 && y1 === y2) {
            if (y1 === 0n) return this.infinity;

            numerator = 3n * x1 * x1 + this.a;
            denominator = 2n * y1;
        } else {
            numerator = y2 - y1;
            denominator = x2 - x1;
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

        const result = new Point(x3, y3);
        this.validate(result);

        this.emit("point:add", {
            left: p1.toString(),
            right: p2.toString(),
            result: result.toString()
        });

        return result;
    }

    subtract(p1, p2) {
        return this.add(p1, this.negate(p2));
    }

    multiply(scalar, point) {
        this.validate(point);

        let k = BigInt(scalar);

        if (k < 0n) {
            return this.multiply(-k, this.negate(point));
        }

        let result = this.infinity;
        let addend = point;

        while (k > 0n) {
            if (k & 1n) {
                result = this.add(result, addend);
            }

            addend = this.add(addend, addend);
            k >>= 1n;
        }

        this.emit("scalar:multiply", {
            scalar: String(scalar),
            point: point.toString(),
            result: result.toString()
        });

        return result;
    }

    enumeratePoints(maxFieldSize = 100000n) {
        if (this.p > maxFieldSize) {
            throw new CurveError(
                "Enumeration limit exceeded."
            );
        }

        const points = [this.infinity];

        for (let x = 0n; x < this.p; x++) {
            const rhs = mod(
                x * x * x + this.a * x + this.b,
                this.p
            );

            for (let y = 0n; y < this.p; y++) {
                if (mod(y * y, this.p) === rhs) {
                    points.push(new Point(x, y));
                }
            }
        }

        return points;
    }

    pointOrder(point) {
        this.validate(point);

        if (point.isInfinity) return 1n;

        let current = this.infinity;

        // Hasse's bound gives a finite search limit.
        const bound = this.p + 1n +
            2n * BigInt(Math.ceil(Math.sqrt(Number(this.p))));

        for (let order = 1n; order <= bound; order++) {
            current = this.add(current, point);

            if (current.isInfinity) {
                return order;
            }
        }

        throw new CurveError("Point order search failed.");
    }

    encode(point) {
        this.validate(point);

        if (point.isInfinity) return Buffer.from([0]);

        const width = Math.ceil(
            this.p.toString(2).length / 8
        );

        const x = Buffer.from(
            point.x.toString(16).padStart(width * 2, "0"),
            "hex"
        );

        const y = Buffer.from(
            point.y.toString(16).padStart(width * 2, "0"),
            "hex"
        );

        return Buffer.concat([
            Buffer.from([4]),
            x,
            y
        ]);
    }

    decode(buffer) {
        if (!Buffer.isBuffer(buffer)) {
            throw new CurveError("Expected a Buffer.");
        }

        if (buffer.length === 1 && buffer[0] === 0) {
            return this.infinity;
        }

        const width = Math.ceil(
            this.p.toString(2).length / 8
        );

        if (
            buffer.length !== 1 + 2 * width ||
            buffer[0] !== 4
        ) {
            throw new CurveError(
                "Invalid uncompressed point encoding."
            );
        }

        const x = BigInt("0x" + buffer.subarray(
            1, 1 + width
        ).toString("hex"));

        const y = BigInt("0x" + buffer.subarray(
            1 + width
        ).toString("hex"));

        if (x >= this.p || y >= this.p) {
            throw new CurveError(
                "Coordinates exceed the field modulus."
            );
        }

        return this.point(x, y);
    }

    async multiplyAsync(scalar, point) {
        // Yield between operations to avoid monopolizing the event loop.
        return new Promise((resolve, reject) => {
            setImmediate(() => {
                try {
                    resolve(this.multiply(scalar, point));
                } catch (error) {
                    reject(error);
                }
            });
        });
    }
}

class CurveAudit {
    constructor(curve) {
        this.curve = curve;
        this.events = [];

        curve.on("point:add", event => {
            this.events.push({
                type: "addition",
                ...event
            });
        });

        curve.on("scalar:multiply", event => {
            this.events.push({
                type: "scalar-multiplication",
                ...event
            });
        });
    }

    report() {
        return {
            eventCount: this.events.length,
            operations: this.events
        };
    }
}

async function main() {
    const curve = new EllipticCurve(97n, 2n, 3n);
    const audit = new CurveAudit(curve);

    const G = curve.point(3n, 6n);

    console.log("ELLIPTIC CURVE");
    console.log("Equation: y² = x³ + 2x + 3 mod 97");
    console.log("Generator:", G.toString());

    console.log("\nPOINT OPERATIONS");

    for (let k = 0n; k <= 7n; k++) {
        const result = curve.multiply(k, G);
        console.log(`${k}G = ${result}`);
    }

    console.log("\nGROUP PROPERTIES");
    console.log("Negative G:", curve.negate(G).toString());
    console.log("G + (-G):", curve.add(G, curve.negate(G)).toString());
    console.log("Order:", String(curve.pointOrder(G)));
    console.log("Group size:", curve.enumeratePoints().length);

    console.log("\nASYNC OPERATION");
    const asyncResult = await curve.multiplyAsync(3n, G);
    console.log("Asynchronous 3G:", asyncResult.toString());

    console.log("\nPOINT ENCODING");
    const encoded = curve.encode(G);
    console.log("Encoded:", encoded.toString("hex"));
    console.log("Decoded:", curve.decode(encoded).toString());

    console.log("\nEVENT AUDIT");
    console.log(JSON.stringify(audit.report(), null, 2));

    console.log("\nVALIDATION TESTS");

    const tests = [
        {
            name: "Point membership",
            run: () => curve.contains(G)
        },
        {
            name: "Identity",
            run: () => curve.add(G, INFINITY).toString() === G.toString()
        },
        {
            name: "Inverse",
            run: () => curve.add(G, curve.negate(G)).isInfinity
        },
        {
            name: "Scalar zero",
            run: () => curve.multiply(0n, G).isInfinity
        },
        {
            name: "Negative scalar",
            run: () => curve.multiply(-2n, G).toString() ===
                curve.negate(curve.multiply(2n, G)).toString()
        },
        {
            name: "Encoding round trip",
            run: () => curve.decode(curve.encode(G)).toString() === G.toString()
        }
    ];

    for (const test of tests) {
        if (!test.run()) {
            throw new Error(`Failed: ${test.name}`);
        }

        console.log(`PASS: ${test.name}`);
    }

    try {
        curve.point(10n, 10n);
    } catch (error) {
        console.log("Expected invalid-point rejection:", error.message);
    }

    console.log("\nAll validations completed.");
}

main().catch(error => {
    console.error("Execution failure:", error.message);
    process.exitCode = 1;
});
