"use strict";

/*
 * Discrete Logarithms in JavaScript
 *
 * This file complements the mathematical Python implementation by focusing
 * on JavaScript's BigInt arithmetic, browser/application-friendly structure,
 * validation, algorithm implementation, and practical demonstrations.
 *
 * Important:
 * The numerical parameters below are intentionally small. JavaScript BigInt
 * can represent large integers exactly, but implementing production
 * cryptography from scratch is inappropriate. Production cryptographic
 * systems should use audited cryptographic libraries and standardized groups.
 */

// -----------------------------------------------------------------------------
// 1. Basic BigInt modular arithmetic
// -----------------------------------------------------------------------------

function gcd(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;

    while (b !== 0n) {
        const remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}

function extendedGcd(a, b) {
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

function modNormalize(value, modulus) {
    const result = value % modulus;
    return result < 0n ? result + modulus : result;
}

function modInverse(value, modulus) {
    const normalized = modNormalize(value, modulus);
    const result = extendedGcd(normalized, modulus);

    if (result.gcd !== 1n) {
        throw new Error(`No modular inverse exists for ${value} modulo ${modulus}`);
    }

    return modNormalize(result.x, modulus);
}

function modPow(base, exponent, modulus) {
    if (modulus <= 0n) {
        throw new Error("Modulus must be positive");
    }

    if (exponent < 0n) {
        return modPow(
            modInverse(base, modulus),
            -exponent,
            modulus
        );
    }

    let result = 1n % modulus;
    base = modNormalize(base, modulus);

    while (exponent > 0n) {
        if (exponent & 1n) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1n;
    }

    return result;
}

// -----------------------------------------------------------------------------
// 2. Group utilities
// -----------------------------------------------------------------------------

function multiplicativeOrder(base, modulus) {
    if (gcd(base, modulus) !== 1n) {
        throw new Error("Base must be invertible modulo modulus");
    }

    let value = 1n;

    for (let order = 1n; order <= modulus; order++) {
        value = (value * base) % modulus;

        if (value === 1n) {
            return order;
        }
    }

    throw new Error("Multiplicative order was not found");
}

function factorInteger(value) {
    const factors = new Map();

    let remaining = value;
    let divisor = 2n;

    while (divisor * divisor <= remaining) {
        while (remaining % divisor === 0n) {
            factors.set(
                divisor,
                (factors.get(divisor) || 0n) + 1n
            );
            remaining /= divisor;
        }

        divisor = divisor === 2n ? 3n : divisor + 2n;
    }

    if (remaining > 1n) {
        factors.set(
            remaining,
            (factors.get(remaining) || 0n) + 1n
        );
    }

    return factors;
}

// -----------------------------------------------------------------------------
// 3. Brute-force discrete logarithm
// -----------------------------------------------------------------------------

function bruteForceDiscreteLog(base, target, modulus, order = null) {
    if (order === null) {
        order = multiplicativeOrder(base, modulus);
    }

    let value = 1n;

    for (let exponent = 0n; exponent < order; exponent++) {
        if (value === modNormalize(target, modulus)) {
            return exponent;
        }

        value = (value * base) % modulus;
    }

    return null;
}

// -----------------------------------------------------------------------------
// 4. Baby-step giant-step
// -----------------------------------------------------------------------------

function babyStepGiantStep(base, target, modulus, order = null) {
    if (order === null) {
        order = multiplicativeOrder(base, modulus);
    }

    if (gcd(base, modulus) !== 1n) {
        throw new Error("Base must be invertible modulo modulus");
    }

    // JavaScript's Number is sufficient for array/map sizing in this
    // educational example, while BigInt preserves the mathematical values.
    const mNumber = Math.ceil(Math.sqrt(Number(order)));
    const m = BigInt(mNumber);

    const babySteps = new Map();

    let value = 1n;

    for (let j = 0; j < m; j++) {
        if (!babySteps.has(value.toString())) {
            babySteps.set(value.toString(), BigInt(j));
        }

        value = (value * base) % modulus;
    }

    const factor = modInverse(
        modPow(base, m, modulus),
        modulus
    );

    let gamma = modNormalize(target, modulus);

    for (let i = 0; i <= mNumber; i++) {
        const key = gamma.toString();

        if (babySteps.has(key)) {
            const j = babySteps.get(key);
            const candidate = BigInt(i) * m + j;

            if (
                candidate < order &&
                modPow(base, candidate, modulus) ===
                modNormalize(target, modulus)
            ) {
                return candidate;
            }
        }

        gamma = (gamma * factor) % modulus;
    }

    return null;
}

// -----------------------------------------------------------------------------
// 5. Pollard-rho discrete logarithm
// -----------------------------------------------------------------------------

function pollardRhoDiscreteLog(
    base,
    target,
    modulus,
    order = null,
    maxIterations = 100000
) {
    if (order === null) {
        order = multiplicativeOrder(base, modulus);
    }

    function step(state) {
        const bucket = Number(state.value % 3n);

        if (bucket === 0) {
            return {
                value: (state.value * base) % modulus,
                alpha: (state.alpha + 1n) % order,
                beta: state.beta
            };
        }

        if (bucket === 1) {
            return {
                value: (state.value * target) % modulus,
                alpha: state.alpha,
                beta: (state.beta + 1n) % order
            };
        }

        return {
            value: (state.value * state.value) % modulus,
            alpha: (2n * state.alpha) % order,
            beta: (2n * state.beta) % order
        };
    }

    for (let seed = 1n; seed <= 15n; seed++) {
        const initialValue = modPow(base, seed, modulus);

        let tortoise = {
            value: initialValue,
            alpha: seed % order,
            beta: 0n
        };

        let hare = { ...tortoise };

        for (let iteration = 0; iteration < maxIterations; iteration++) {
            tortoise = step(tortoise);
            hare = step(step(hare));

            if (tortoise.value !== hare.value) {
                continue;
            }

            const numerator =
                modNormalize(
                    tortoise.alpha - hare.alpha,
                    order
                );

            const denominator =
                modNormalize(
                    hare.beta - tortoise.beta,
                    order
                );

            const divisor = gcd(denominator, order);

            if (divisor === 0n || numerator % divisor !== 0n) {
                break;
            }

            const reducedOrder = order / divisor;
            const reducedDenominator = denominator / divisor;
            const reducedNumerator = numerator / divisor;

            let inverse;

            try {
                inverse = modInverse(
                    reducedDenominator,
                    reducedOrder
                );
            } catch {
                break;
            }

            const baseSolution =
                (reducedNumerator * inverse) % reducedOrder;

            for (let offset = 0n; offset < divisor; offset++) {
                const candidate =
                    (baseSolution + offset * reducedOrder) % order;

                if (
                    modPow(base, candidate, modulus) ===
                    modNormalize(target, modulus)
                ) {
                    return candidate;
                }
            }

            break;
        }
    }

    return null;
}

// -----------------------------------------------------------------------------
// 6. Chinese remainder theorem
// -----------------------------------------------------------------------------

function chineseRemainder(congruences) {
    let result = 0n;
    let product = 1n;

    for (const [residue, modulus] of congruences) {
        if (gcd(product, modulus) !== 1n) {
            throw new Error("CRT moduli must be pairwise coprime");
        }

        const inverse = modInverse(product, modulus);

        const adjustment =
            modNormalize(
                (residue - result) * inverse,
                modulus
            );

        result += product * adjustment;
        product *= modulus;
        result = modNormalize(result, product);
    }

    return {
        value: result,
        modulus: product
    };
}

// -----------------------------------------------------------------------------
// 7. Pohlig-Hellman
// -----------------------------------------------------------------------------

function primeOrderDiscreteLog(base, target, modulus, primeOrder) {
    let value = 1n;

    for (let exponent = 0n; exponent < primeOrder; exponent++) {
        if (value === modNormalize(target, modulus)) {
            return exponent;
        }

        value = (value * base) % modulus;
    }

    return null;
}

function pohligHellman(base, target, modulus) {
    const order = multiplicativeOrder(base, modulus);
    const factors = factorInteger(order);
    const congruences = [];

    for (const [prime, exponent] of factors.entries()) {
        let recovered = 0n;

        for (let digitPosition = 0n; digitPosition < exponent; digitPosition++) {
            const primePower = prime ** digitPosition;

            const inverseCurrent =
                modInverse(
                    modPow(base, recovered, modulus),
                    modulus
                );

            const residual =
                (target * inverseCurrent) % modulus;

            const reducedTarget =
                modPow(
                    residual,
                    order / (prime ** (digitPosition + 1n)),
                    modulus
                );

            const reducedBase =
                modPow(
                    base,
                    order / (prime ** (digitPosition + 1n)),
                    modulus
                );

            const digit = primeOrderDiscreteLog(
                reducedBase,
                reducedTarget,
                modulus,
                prime
            );

            if (digit === null) {
                return null;
            }

            recovered += digit * primePower;
        }

        congruences.push([
            recovered,
            prime ** exponent
        ]);
    }

    const reconstructed = chineseRemainder(congruences);

    if (reconstructed.modulus !== order) {
        throw new Error("CRT reconstruction did not cover the full order");
    }

    if (
        modPow(base, reconstructed.value, modulus) !==
        modNormalize(target, modulus)
    ) {
        return null;
    }

    return reconstructed.value;
}

// -----------------------------------------------------------------------------
// 8. Diffie-Hellman demonstration
// -----------------------------------------------------------------------------

function demonstrateDiffieHellman() {
    const p = 23n;
    const g = 5n;

    const alicePrivate = 6n;
    const bobPrivate = 15n;

    const alicePublic = modPow(g, alicePrivate, p);
    const bobPublic = modPow(g, bobPrivate, p);

    const aliceShared = modPow(
        bobPublic,
        alicePrivate,
        p
    );

    const bobShared = modPow(
        alicePublic,
        bobPrivate,
        p
    );

    console.log("Diffie-Hellman");
    console.log({
        p: p.toString(),
        g: g.toString(),
        alicePublic: alicePublic.toString(),
        bobPublic: bobPublic.toString(),
        aliceShared: aliceShared.toString(),
        bobShared: bobShared.toString(),
        match: aliceShared === bobShared
    });

    // Because the group is intentionally tiny, brute force can recover
    // Alice's private exponent. Real systems choose parameters where this
    // attack is computationally infeasible.
    const recovered =
        bruteForceDiscreteLog(
            g,
            alicePublic,
            p
        );

    console.log(
        "Toy discrete-log recovery:",
        recovered === null ? null : recovered.toString()
    );

    console.log();
}

// -----------------------------------------------------------------------------
// 9. ElGamal demonstration
// -----------------------------------------------------------------------------

function demonstrateElGamal() {
    const p = 467n;
    const g = 2n;

    const privateKey = 127n;
    const message = 123n;
    const ephemeralKey = 83n;

    const publicKey = modPow(
        g,
        privateKey,
        p
    );

    const c1 = modPow(
        g,
        ephemeralKey,
        p
    );

    const shared = modPow(
        publicKey,
        ephemeralKey,
        p
    );

    const c2 =
        (message * shared) % p;

    const recoveredShared =
        modPow(
            c1,
            privateKey,
            p
        );

    const recoveredMessage =
        (c2 * modInverse(recoveredShared, p)) % p;

    console.log("ElGamal");
    console.log({
        publicKey: publicKey.toString(),
        ciphertext: [
            c1.toString(),
            c2.toString()
        ],
        recoveredMessage: recoveredMessage.toString(),
        correct: recoveredMessage === message
    });

    console.log();
}

// -----------------------------------------------------------------------------
// 10. JavaScript-specific BigInt behavior
// -----------------------------------------------------------------------------

function demonstrateBigIntRules() {
    console.log("JavaScript BigInt rules");

    const a = 9007199254740993n;
    const b = 7n;

    console.log("Exact BigInt arithmetic:", (a * b).toString());

    // BigInt and Number should not be mixed directly in arithmetic.
    try {
        // This intentionally demonstrates an error.
        console.log(a + 1);
    } catch (error) {
        console.log(
            "Expected BigInt/Number type error:",
            error.message
        );
    }

    console.log();
}

// -----------------------------------------------------------------------------
// 11. Validation and edge cases
// -----------------------------------------------------------------------------

function validateDiscreteLog(
    base,
    target,
    modulus,
    candidate
) {
    if (candidate === null) {
        return false;
    }

    if (gcd(base, modulus) !== 1n) {
        return false;
    }

    const order = multiplicativeOrder(base, modulus);

    return (
        candidate >= 0n &&
        candidate < order &&
        modPow(base, candidate, modulus) ===
        modNormalize(target, modulus)
    );
}

function demonstrateEdgeCases() {
    console.log("Edge cases");

    console.log(
        "3^0 mod 17 =",
        modPow(3n, 0n, 17n).toString()
    );

    console.log(
        "3^-1 mod 17 =",
        modPow(3n, -1n, 17n).toString()
    );

    try {
        modInverse(6n, 15n);
    } catch (error) {
        console.log(
            "Expected inverse failure:",
            error.message
        );
    }

    const base = 4n;
    const modulus = 29n;
    const target = 2n;

    const order =
        multiplicativeOrder(
            base,
            modulus
        );

    const result =
        babyStepGiantStep(
            base,
            target,
            modulus,
            order
        );

    console.log(
        `log_${base}(${target}) mod ${modulus} =`,
        result === null ? null : result.toString()
    );

    console.log();
}

// -----------------------------------------------------------------------------
// 12. Algorithm comparison
// -----------------------------------------------------------------------------

function compareAlgorithms() {
    const modulus = 10007n;
    const base = 5n;
    const secret = 4321n;

    const order =
        multiplicativeOrder(
            base,
            modulus
        );

    const target =
        modPow(
            base,
            secret,
            modulus
        );

    console.log("Algorithm comparison");
    console.log({
        modulus: modulus.toString(),
        base: base.toString(),
        order: order.toString(),
        target: target.toString()
    });

    const startBrute = performance.now();
    const brute =
        bruteForceDiscreteLog(
            base,
            target,
            modulus,
            order
        );
    const bruteTime = performance.now() - startBrute;

    const startBsgs = performance.now();
    const bsgs =
        babyStepGiantStep(
            base,
            target,
            modulus,
            order
        );
    const bsgsTime = performance.now() - startBsgs;

    const startRho = performance.now();
    const rho =
        pollardRhoDiscreteLog(
            base,
            target,
            modulus,
            order
        );
    const rhoTime = performance.now() - startRho;

    console.table([
        {
            algorithm: "Brute force",
            result: brute?.toString() ?? null,
            milliseconds: bruteTime.toFixed(4)
        },
        {
            algorithm: "Baby-step giant-step",
            result: bsgs?.toString() ?? null,
            milliseconds: bsgsTime.toFixed(4)
        },
        {
            algorithm: "Pollard rho",
            result: rho?.toString() ?? null,
            milliseconds: rhoTime.toFixed(4)
        }
    ]);

    console.log();
}

// -----------------------------------------------------------------------------
// 13. Self-tests
// -----------------------------------------------------------------------------

function runSelfTests() {
    const cases = [
        {
            base: 5n,
            exponent: 12n,
            modulus: 23n
        },
        {
            base: 2n,
            exponent: 11n,
            modulus: 29n
        },
        {
            base: 11n,
            exponent: 731n,
            modulus: 1009n
        }
    ];

    for (const testCase of cases) {
        const target =
            modPow(
                testCase.base,
                testCase.exponent,
                testCase.modulus
            );

        const order =
            multiplicativeOrder(
                testCase.base,
                testCase.modulus
            );

        const result =
            babyStepGiantStep(
                testCase.base,
                target,
                testCase.modulus,
                order
            );

        if (result !== testCase.exponent % order) {
            throw new Error(
                `BSGS test failed for modulus ${testCase.modulus}`
            );
        }

        if (
            !validateDiscreteLog(
                testCase.base,
                target,
                testCase.modulus,
                result
            )
        ) {
            throw new Error("Discrete-log validation failed");
        }
    }

    const crtResult =
        chineseRemainder([
            [2n, 3n],
            [3n, 5n],
            [2n, 7n]
        ]);

    if (
        crtResult.value !== 23n ||
        crtResult.modulus !== 105n
    ) {
        throw new Error("CRT test failed");
    }

    console.log("All JavaScript self-tests passed.");
    console.log();
}

// -----------------------------------------------------------------------------
// 14. Browser and Node.js compatibility
// -----------------------------------------------------------------------------

function main() {
    console.log("=".repeat(72));
    console.log("DISCRETE LOGARITHMS IN JAVASCRIPT");
    console.log("=".repeat(72));
    console.log();

    const modulus = 29n;
    const base = 2n;
    const exponent = 11n;

    const target =
        modPow(
            base,
            exponent,
            modulus
        );

    const order =
        multiplicativeOrder(
            base,
            modulus
        );

    console.log("Basic discrete logarithm");
    console.log({
        equation: `${base}^x ≡ ${target} (mod ${modulus})`,
        order: order.toString()
    });

    const brute =
        bruteForceDiscreteLog(
            base,
            target,
            modulus,
            order
        );

    const bsgs =
        babyStepGiantStep(
            base,
            target,
            modulus,
            order
        );

    console.log(
        "Brute-force result:",
        brute?.toString() ?? null
    );

    console.log(
        "BSGS result:",
        bsgs?.toString() ?? null
    );

    console.log();

    demonstrateBigIntRules();
    demonstrateDiffieHellman();
    demonstrateElGamal();
    demonstrateEdgeCases();
    compareAlgorithms();
    runSelfTests();

    console.log("Core algorithm properties");
    console.log("Brute force: O(n) time, O(1) memory");
    console.log("BSGS: O(sqrt(n)) time, O(sqrt(n)) memory");
    console.log("Pollard rho: O(sqrt(n)) expected time, O(1) memory");
    console.log("Pohlig-Hellman: efficient when the group order has small factors");
}

main();
