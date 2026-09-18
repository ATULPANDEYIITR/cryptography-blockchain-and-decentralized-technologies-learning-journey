/*
 * Mathematical Concepts Used in Cryptography
 * ===========================================
 *
 * A self-contained JavaScript study file demonstrating mathematical
 * foundations that appear in cryptographic systems.
 *
 * Topics:
 * - Integer arithmetic
 * - Divisibility and primality
 * - GCD and extended GCD
 * - Modular arithmetic
 * - Modular inverses
 * - Fast modular exponentiation
 * - Euler's totient
 * - Fermat's and Euler's theorems
 * - Chinese Remainder Theorem
 * - Discrete logarithms
 * - Diffie-Hellman
 * - RSA
 * - Finite fields
 * - Elliptic-curve arithmetic
 * - Hash functions
 * - Entropy
 * - Security and implementation considerations
 *
 * Run with a modern Node.js runtime:
 *     node cryptography_math.js
 *
 * The numerical parameters are intentionally tiny and are NOT secure.
 */

"use strict";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function subsection(title) {
    console.log("\n" + "-".repeat(78));
    console.log(title);
    console.log("-".repeat(78));
}

// ---------------------------------------------------------------------------
// Integer mathematics
// ---------------------------------------------------------------------------

function isPrime(n) {
    if (!Number.isSafeInteger(n) || n < 2) {
        return false;
    }

    if (n === 2) {
        return true;
    }

    if (n % 2 === 0) {
        return false;
    }

    for (let divisor = 3; divisor * divisor <= n; divisor += 2) {
        if (n % divisor === 0) {
            return false;
        }
    }

    return true;
}

function primeFactors(n) {
    if (!Number.isSafeInteger(n) || n < 2) {
        return [];
    }

    const factors = [];
    let remaining = n;

    for (let divisor = 2; divisor * divisor <= remaining; divisor += 1) {
        while (remaining % divisor === 0) {
            factors.push(divisor);
            remaining /= divisor;
        }
    }

    if (remaining > 1) {
        factors.push(remaining);
    }

    return factors;
}

function demonstrateIntegerMath() {
    subsection("Integers, primes, and factorization");

    for (const value of [1, 2, 17, 25, 97, 100]) {
        console.log(
            `${value}: prime=${isPrime(value)}, factors=[${primeFactors(value)}]`
        );
    }
}

// ---------------------------------------------------------------------------
// GCD and extended GCD
// ---------------------------------------------------------------------------

function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);

    while (b !== 0) {
        [a, b] = [b, a % b];
    }

    return a;
}

function extendedGcd(a, b) {
    let oldR = a;
    let r = b;
    let oldX = 1;
    let x = 0;
    let oldY = 0;
    let y = 1;

    while (r !== 0) {
        const quotient = Math.trunc(oldR / r);

        [oldR, r] = [r, oldR - quotient * r];
        [oldX, x] = [x, oldX - quotient * x];
        [oldY, y] = [y, oldY - quotient * y];
    }

    if (oldR < 0) {
        return [-oldR, -oldX, -oldY];
    }

    return [oldR, oldX, oldY];
}

function modInverse(a, modulus) {
    if (modulus <= 1) {
        throw new Error("Modulus must be greater than 1.");
    }

    const [g, x] = extendedGcd(a, modulus);

    if (g !== 1) {
        throw new Error(
            `${a} has no inverse modulo ${modulus}; gcd=${g}.`
        );
    }

    return ((x % modulus) + modulus) % modulus;
}

function demonstrateGcd() {
    subsection("GCD, Bézout coefficients, and modular inverses");

    const [g, x, y] = extendedGcd(240, 46);

    console.log(`gcd(240, 46) = ${g}`);
    console.log(`240(${x}) + 46(${y}) = ${g}`);

    const inverse = modInverse(17, 3120);
    console.log(`17^(-1) mod 3120 = ${inverse}`);
    console.log(`Verification = ${(17 * inverse) % 3120}`);

    try {
        modInverse(12, 18);
    } catch (error) {
        console.log("Expected failure:", error.message);
    }
}

// ---------------------------------------------------------------------------
// BigInt modular arithmetic
// ---------------------------------------------------------------------------

function modNormalize(value, modulus) {
    return ((value % modulus) + modulus) % modulus;
}

/*
 * JavaScript Number is a floating-point type. Cryptographic integers often
 * exceed Number.MAX_SAFE_INTEGER, so BigInt is required for exact arithmetic.
 */
function modPow(base, exponent, modulus) {
    base = BigInt(base);
    exponent = BigInt(exponent);
    modulus = BigInt(modulus);

    if (modulus <= 0n) {
        throw new Error("Modulus must be positive.");
    }

    if (exponent < 0n) {
        throw new Error(
            "This function expects a nonnegative exponent."
        );
    }

    let result = 1n % modulus;
    base %= modulus;

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1n;
    }

    return result;
}

function demonstrateModularArithmetic() {
    subsection("Modular arithmetic and BigInt");

    console.log("17 mod 5 =", 17 % 5);
    console.log("-17 normalized mod 5 =", modNormalize(-17, 5));

    console.log("3^100 mod 13 =", modPow(3n, 100n, 13n).toString());

    const huge = modPow(
        12345678901234567890n,
        987654321n,
        1000000007n
    );

    console.log("Large BigInt modular exponentiation =", huge.toString());
}

// ---------------------------------------------------------------------------
// Euler's totient
// ---------------------------------------------------------------------------

function eulerTotient(n) {
    if (!Number.isInteger(n) || n <= 0) {
        throw new Error("n must be positive.");
    }

    let result = n;

    for (const prime of new Set(primeFactors(n))) {
        result -= Math.floor(result / prime);
    }

    return result;
}

function demonstrateEuler() {
    subsection("Euler's totient and exponentiation theorems");

    for (let n = 1; n <= 15; n += 1) {
        console.log(`phi(${n}) = ${eulerTotient(n)}`);
    }

    console.log(
        "Fermat example:",
        modPow(5n, 12n, 13n).toString()
    );

    console.log(
        "Euler example:",
        modPow(2n, BigInt(eulerTotient(35)), 35n).toString()
    );
}

// ---------------------------------------------------------------------------
// Chinese Remainder Theorem
// ---------------------------------------------------------------------------

function chineseRemainder(residues, moduli) {
    if (residues.length === 0 || residues.length !== moduli.length) {
        throw new Error("Residues and moduli must have equal nonzero lengths.");
    }

    for (let i = 0; i < moduli.length; i += 1) {
        for (let j = i + 1; j < moduli.length; j += 1) {
            if (gcd(moduli[i], moduli[j]) !== 1) {
                throw new Error("Moduli must be pairwise coprime.");
            }
        }
    }

    const product = moduli.reduce((a, b) => a * b, 1);
    let solution = 0;

    for (let i = 0; i < residues.length; i += 1) {
        const partial = product / moduli[i];
        const inverse = modInverse(partial, moduli[i]);

        solution += residues[i] * partial * inverse;
    }

    return ((solution % product) + product) % product;
}

function demonstrateCRT() {
    subsection("Chinese Remainder Theorem");

    const residues = [2, 3, 2];
    const moduli = [3, 5, 7];
    const solution = chineseRemainder(residues, moduli);

    console.log("x ≡ 2 mod 3");
    console.log("x ≡ 3 mod 5");
    console.log("x ≡ 2 mod 7");
    console.log("Solution =", solution);
}

// ---------------------------------------------------------------------------
// Discrete logarithm
// ---------------------------------------------------------------------------

function bruteForceDiscreteLog(base, target, modulus) {
    let current = 1;

    for (let exponent = 0; exponent < modulus; exponent += 1) {
        if (current === target) {
            return exponent;
        }

        current = Number(
            modPow(BigInt(current) * BigInt(base), 1n, BigInt(modulus))
        );
    }

    return null;
}

function demonstrateDiscreteLog() {
    subsection("Discrete logarithms");

    const base = 5;
    const modulus = 23;
    const secret = 7;

    const target = Number(modPow(
        BigInt(base),
        BigInt(secret),
        BigInt(modulus)
    ));

    const recovered = bruteForceDiscreteLog(base, target, modulus);

    console.log(`${base}^${secret} mod ${modulus} = ${target}`);
    console.log("Recovered exponent =", recovered);

    console.log(
        "The forward operation is efficient; the reverse operation is "
        + "intentionally difficult for suitable cryptographic groups."
    );
}

// ---------------------------------------------------------------------------
// Diffie-Hellman
// ---------------------------------------------------------------------------

function demonstrateDiffieHellman() {
    subsection("Diffie-Hellman key exchange");

    const p = 23n;
    const g = 5n;

    const alicePrivate = 6n;
    const bobPrivate = 15n;

    const alicePublic = modPow(g, alicePrivate, p);
    const bobPublic = modPow(g, bobPrivate, p);

    const aliceShared = modPow(bobPublic, alicePrivate, p);
    const bobShared = modPow(alicePublic, bobPrivate, p);

    console.log("p =", p.toString());
    console.log("g =", g.toString());
    console.log("Alice public =", alicePublic.toString());
    console.log("Bob public =", bobPublic.toString());
    console.log("Alice shared =", aliceShared.toString());
    console.log("Bob shared =", bobShared.toString());
    console.log("Equal =", aliceShared === bobShared);

    console.log(
        "Unauthenticated Diffie-Hellman does not by itself prevent "
        + "man-in-the-middle attacks."
    );
}

// ---------------------------------------------------------------------------
// RSA using BigInt
// ---------------------------------------------------------------------------

function rsaGenerate(p, q, e) {
    p = BigInt(p);
    q = BigInt(q);
    e = BigInt(e);

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    if (modInverse(e, Number(phi)) === undefined) {
        throw new Error("Invalid public exponent.");
    }

    const d = BigInt(modInverse(Number(e), Number(phi)));

    return { p, q, n, phi, e, d };
}

function rsaEncrypt(message, e, n) {
    message = BigInt(message);

    if (message < 0n || message >= n) {
        throw new Error("Message must satisfy 0 <= message < n.");
    }

    return modPow(message, e, n);
}

function rsaDecrypt(ciphertext, d, n) {
    return modPow(ciphertext, d, n);
}

function demonstrateRSA() {
    subsection("RSA");

    const rsa = rsaGenerate(61, 53, 17);

    console.log("n =", rsa.n.toString());
    console.log("phi(n) =", rsa.phi.toString());
    console.log("e =", rsa.e.toString());
    console.log("d =", rsa.d.toString());

    const message = 65n;
    const ciphertext = rsaEncrypt(message, rsa.e, rsa.n);
    const plaintext = rsaDecrypt(ciphertext, rsa.d, rsa.n);

    console.log("Message =", message.toString());
    console.log("Ciphertext =", ciphertext.toString());
    console.log("Recovered =", plaintext.toString());

    console.log(
        "Production RSA requires large parameters and standardized "
        + "padding constructions. Textbook RSA is not secure."
    );
}

// ---------------------------------------------------------------------------
// Finite-field arithmetic GF(2^8)
// ---------------------------------------------------------------------------

function gf256Multiply(a, b) {
    if (a < 0 || a > 255 || b < 0 || b > 255) {
        throw new Error("Inputs must be bytes.");
    }

    let result = 0;
    let multiplicand = a;
    let multiplier = b;

    for (let i = 0; i < 8; i += 1) {
        if (multiplier & 1) {
            result ^= multiplicand;
        }

        const highBit = multiplicand & 0x80;
        multiplicand = (multiplicand << 1) & 0xFF;

        if (highBit) {
            multiplicand ^= 0x1B;
        }

        multiplier >>= 1;
    }

    return result;
}

function gf256Power(value, exponent) {
    let result = 1;

    while (exponent > 0) {
        if (exponent & 1) {
            result = gf256Multiply(result, value);
        }

        value = gf256Multiply(value, value);
        exponent >>= 1;
    }

    return result;
}

function gf256Inverse(value) {
    if (value === 0) {
        throw new Error("Zero has no inverse.");
    }

    return gf256Power(value, 254);
}

function demonstrateGF256() {
    subsection("Finite-field arithmetic in GF(2^8)");

    const a = 0x57;
    const b = 0x83;
    const product = gf256Multiply(a, b);
    const inverse = gf256Inverse(a);

    console.log(
        `0x${a.toString(16).toUpperCase()} * `
        + `0x${b.toString(16).toUpperCase()} = `
        + `0x${product.toString(16).toUpperCase()}`
    );

    console.log(
        `inverse(0x${a.toString(16).toUpperCase()}) = `
        + `0x${inverse.toString(16).toUpperCase()}`
    );

    console.log(
        "Verification =",
        `0x${gf256Multiply(a, inverse).toString(16).toUpperCase()}`
    );
}

// ---------------------------------------------------------------------------
// Elliptic curves over prime fields
// ---------------------------------------------------------------------------

class EllipticCurve {
    constructor(a, b, p) {
        this.a = BigInt(a);
        this.b = BigInt(b);
        this.p = BigInt(p);

        if (this.p <= 2n) {
            throw new Error("Use an odd prime field.");
        }

        const discriminant = (
            4n * this.a ** 3n + 27n * this.b ** 2n
        ) % this.p;

        if (discriminant === 0n) {
            throw new Error("Singular elliptic curve.");
        }
    }

    infinity() {
        return { infinity: true };
    }

    contains(point) {
        if (point.infinity) {
            return true;
        }

        const x = point.x;
        const y = point.y;

        const left = (y * y) % this.p;
        const right = (
            x ** 3n + this.a * x + this.b
        ) % this.p;

        return modNormalize(left - right, this.p) === 0n;
    }

    negate(point) {
        if (point.infinity) {
            return point;
        }

        return {
            x: point.x,
            y: modNormalize(-point.y, this.p)
        };
    }

    add(P, Q) {
        if (!this.contains(P) || !this.contains(Q)) {
            throw new Error("Both points must be on the curve.");
        }

        if (P.infinity) {
            return Q;
        }

        if (Q.infinity) {
            return P;
        }

        const x1 = P.x;
        const y1 = P.y;
        const x2 = Q.x;
        const y2 = Q.y;

        if (x1 === x2 && modNormalize(y1 + y2, this.p) === 0n) {
            return this.infinity();
        }

        let slope;

        if (x1 === x2 && y1 === y2) {
            if (y1 % this.p === 0n) {
                return this.infinity();
            }

            const numerator = (
                3n * x1 * x1 + this.a
            ) % this.p;

            const denominator = modNormalize(2n * y1, this.p);
            const inverse = this.modInverseBigInt(denominator);

            slope = (numerator * inverse) % this.p;
        } else {
            const numerator = modNormalize(y2 - y1, this.p);
            const denominator = modNormalize(x2 - x1, this.p);
            const inverse = this.modInverseBigInt(denominator);

            slope = (numerator * inverse) % this.p;
        }

        const x3 = modNormalize(
            slope * slope - x1 - x2,
            this.p
        );

        const y3 = modNormalize(
            slope * (x1 - x3) - y1,
            this.p
        );

        return { x: x3, y: y3 };
    }

    modInverseBigInt(value) {
        let oldR = value;
        let r = this.p;
        let oldS = 1n;
        let s = 0n;

        while (r !== 0n) {
            const quotient = oldR / r;
            [oldR, r] = [r, oldR - quotient * r];
            [oldS, s] = [s, oldS - quotient * s];
        }

        if (oldR !== 1n) {
            throw new Error("No modular inverse exists.");
        }

        return modNormalize(oldS, this.p);
    }

    multiply(scalar, point) {
        scalar = BigInt(scalar);

        if (scalar < 0n) {
            return this.multiply(-scalar, this.negate(point));
        }

        let result = this.infinity();
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
}

function formatPoint(point) {
    if (point.infinity) {
        return "O";
    }

    return `(${point.x.toString()}, ${point.y.toString()})`;
}

function demonstrateEllipticCurves() {
    subsection("Elliptic-curve arithmetic");

    const curve = new EllipticCurve(2, 2, 17);
    const generator = { x: 5n, y: 1n };

    console.log("Generator valid =", curve.contains(generator));

    for (let scalar = 1n; scalar <= 7n; scalar += 1n) {
        console.log(
            `${scalar}P = ${formatPoint(curve.multiply(scalar, generator))}`
        );
    }

    const opposite = curve.negate(generator);
    console.log("P + (-P) =", formatPoint(curve.add(generator, opposite)));
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

async function demonstrateHashes() {
    subsection("Cryptographic hashes");

    const crypto = await import("node:crypto");

    for (const message of [
        "cryptography",
        "Cryptography",
        "cryptography!"
    ]) {
        const digest = crypto
            .createHash("sha256")
            .update(message)
            .digest("hex");

        console.log(`${message} -> ${digest}`);
    }

    console.log(
        "SHA-256 produces a 256-bit digest and is designed so that "
        + "small input changes cause substantial digest changes."
    );
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

function shannonEntropy(text) {
    if (text.length === 0) {
        return 0;
    }

    const counts = new Map();

    for (const symbol of text) {
        counts.set(symbol, (counts.get(symbol) || 0) + 1);
    }

    let entropy = 0;

    for (const count of counts.values()) {
        const probability = count / text.length;
        entropy -= probability * Math.log2(probability);
    }

    return entropy;
}

function demonstrateEntropy() {
    subsection("Entropy and randomness");

    for (const value of [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ABABABABABABABABABABABABABABABAB",
        "Q7m!2xL9#pR4$zT8@kN1%wC6"
    ]) {
        console.log(
            `${value}: entropy ≈ ${shannonEntropy(value).toFixed(4)} bits/symbol`
        );
    }

    console.log(
        "Use cryptographically secure random generators for secrets, "
        + "not Math.random()."
    );
}

// ---------------------------------------------------------------------------
// Security-scale reasoning
// ---------------------------------------------------------------------------

function demonstrateSearchSpace() {
    subsection("Search spaces and brute-force reasoning");

    for (const bits of [8, 16, 32, 64, 128, 256]) {
        const probability = 2 ** (-bits);
        console.log(
            `${bits} bits: one uniform guess ≈ ${probability.toExponential(3)}`
        );
    }

    console.log(
        "Key length is only one part of cryptographic security. "
        + "Algorithms, parameters, protocols, implementation, randomness, "
        + "and authentication all matter."
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

function demonstrateEdgeCases() {
    subsection("Edge cases");

    const operations = [
        ["gcd(0, 15)", () => gcd(0, 15)],
        ["gcd(0, 0)", () => gcd(0, 0)],
        ["inverse(1, 17)", () => modInverse(1, 17)],
        ["inverse(0, 17)", () => modInverse(0, 17)],
        ["inverse(6, 15)", () => modInverse(6, 15)],
    ];

    for (const [description, operation] of operations) {
        try {
            console.log(`${description} = ${operation()}`);
        } catch (error) {
            console.log(
                `${description} -> ${error.constructor.name}: ${error.message}`
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Correctness checks
// ---------------------------------------------------------------------------

function runTests() {
    subsection("Correctness checks");

    console.assert(gcd(240, 46) === 2);

    const [g, x, y] = extendedGcd(240, 46);
    console.assert(g === 2);
    console.assert(240 * x + 46 * y === 2);

    console.assert(modInverse(3, 11) === 4);
    console.assert((3 * modInverse(3, 11)) % 11 === 1);

    console.assert(modPow(2n, 10n, 1000n) === 24n);
    console.assert(eulerTotient(35) === 24);
    console.assert(chineseRemainder([2, 3, 2], [3, 5, 7]) === 23);
    console.assert(gf256Multiply(0x57, 0x83) === 0xC1);

    const curve = new EllipticCurve(2, 2, 17);
    const point = { x: 5n, y: 1n };
    console.assert(curve.contains(point));

    const infinity = curve.add(point, curve.negate(point));
    console.assert(infinity.infinity === true);

    console.log("All assertions passed.");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    console.log("MATHEMATICAL CONCEPTS USED IN CRYPTOGRAPHY");
    console.log("Educational JavaScript implementation laboratory");
    console.log("Small parameters are used deliberately and are not secure.");

    demonstrateIntegerMath();
    demonstrateGcd();
    demonstrateModularArithmetic();
    demonstrateEuler();
    demonstrateCRT();
    demonstrateDiscreteLog();
    demonstrateDiffieHellman();
    demonstrateRSA();
    demonstrateGF256();
    demonstrateEllipticCurves();
    await demonstrateHashes();
    demonstrateEntropy();
    demonstrateSearchSpace();
    demonstrateEdgeCases();
    runTests();

    section("Implementation principles");

    const principles = [
        "Use BigInt for exact large integer arithmetic in JavaScript.",
        "Never use Math.random() to generate cryptographic secrets.",
        "Do not implement production cryptographic primitives without specialist review.",
        "Use authenticated protocols rather than relying on confidentiality alone.",
        "Validate public inputs and reject malformed parameters.",
        "Protect private keys and sensitive intermediate values.",
        "Consider timing and other side-channel leakage.",
        "Use standardized algorithms and parameter sets in production.",
        "Treat educational small-number examples as mathematical demonstrations only."
    ];

    for (const principle of principles) {
        console.log("*", principle);
    }
}

main().catch(error => {
    console.error("Program failed:", error);
    process.exitCode = 1;
});
