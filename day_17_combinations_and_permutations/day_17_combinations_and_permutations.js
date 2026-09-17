/*
 * Combinations and Permutations
 * ==============================
 *
 * A self-contained JavaScript study file covering:
 *   - factorials
 *   - permutations
 *   - combinations
 *   - repetition
 *   - enumeration
 *   - generators
 *   - duplicate values
 *   - circular permutations
 *   - probability
 *   - constrained selection
 *   - ranking and unranking
 *   - validation
 *   - performance considerations
 *
 * Run with:
 *   node combinations-permutations.js
 *
 * BigInt is used for exact large combinatorial counts.
 */

"use strict";

// -----------------------------------------------------------------------------
// 1. Utility functions
// -----------------------------------------------------------------------------

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function toNumberIfSafe(value) {
    return value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(value)
        : value;
}

// -----------------------------------------------------------------------------
// 2. Factorial
// -----------------------------------------------------------------------------

function factorial(n) {
    if (!Number.isInteger(n)) {
        throw new TypeError("n must be an integer");
    }
    if (n < 0) {
        throw new RangeError("n must be non-negative");
    }

    let result = 1n;

    for (let value = 2; value <= n; value += 1) {
        result *= BigInt(value);
    }

    return result;
}

function showFactorials() {
    section("1. Factorials");

    for (let n = 0; n <= 7; n += 1) {
        console.log(`${n}! = ${factorial(n)}`);
    }

    console.log(
        "JavaScript Number is unsafe for many large integer counts, so " +
        "the implementations use BigInt."
    );
}

// -----------------------------------------------------------------------------
// 3. Permutations
// -----------------------------------------------------------------------------

function validateNR(n, r) {
    if (!Number.isInteger(n) || !Number.isInteger(r)) {
        throw new TypeError("n and r must be integers");
    }

    if (n < 0 || r < 0 || r > n) {
        throw new RangeError("require n >= 0 and 0 <= r <= n");
    }
}

function permutationCount(n, r) {
    validateNR(n, r);

    let result = 1n;

    for (let value = n - r + 1; value <= n; value += 1) {
        result *= BigInt(value);
    }

    return result;
}

function permutationWithRepetition(n, r) {
    if (!Number.isInteger(n) || !Number.isInteger(r)) {
        throw new TypeError("n and r must be integers");
    }

    if (n < 0 || r < 0) {
        throw new RangeError("n and r must be non-negative");
    }

    return BigInt(n) ** BigInt(r);
}

function showPermutationCounts() {
    section("2. Permutations");

    console.log("P(5,2) =", permutationCount(5, 2));
    console.log("P(5,3) =", permutationCount(5, 3));
    console.log("P(10,3) =", permutationCount(10, 3));

    console.log(
        "4-digit code using 10 symbols with repetition =",
        permutationWithRepetition(10, 4)
    );
}

// -----------------------------------------------------------------------------
// 4. Combinations
// -----------------------------------------------------------------------------

function combinationCount(n, r) {
    validateNR(n, r);

    // C(n,r) = C(n,n-r), so use the smaller r.
    r = Math.min(r, n - r);

    let result = 1n;

    for (let i = 1; i <= r; i += 1) {
        result = (result * BigInt(n - r + i)) / BigInt(i);
    }

    return result;
}

function showCombinationCounts() {
    section("3. Combinations");

    console.log("C(5,2) =", combinationCount(5, 2));
    console.log("C(10,4) =", combinationCount(10, 4));
    console.log("C(52,5) =", combinationCount(52, 5));

    console.log(
        "A committee is a combination because changing the order of " +
        "committee members does not create a different committee."
    );
}

// -----------------------------------------------------------------------------
// 5. Recursive permutation generator
// -----------------------------------------------------------------------------

function* permutations(items, r = items.length) {
    if (!Number.isInteger(r) || r < 0 || r > items.length) {
        throw new RangeError("r must satisfy 0 <= r <= items.length");
    }

    const used = new Array(items.length).fill(false);
    const current = [];

    function* backtrack() {
        if (current.length === r) {
            yield [...current];
            return;
        }

        for (let index = 0; index < items.length; index += 1) {
            if (used[index]) {
                continue;
            }

            used[index] = true;
            current.push(items[index]);

            yield* backtrack();

            current.pop();
            used[index] = false;
        }
    }

    yield* backtrack();
}

// -----------------------------------------------------------------------------
// 6. Recursive combination generator
// -----------------------------------------------------------------------------

function* combinations(items, r) {
    if (!Number.isInteger(r) || r < 0 || r > items.length) {
        throw new RangeError("r must satisfy 0 <= r <= items.length");
    }

    const current = [];

    function* backtrack(start) {
        if (current.length === r) {
            yield [...current];
            return;
        }

        const required = r - current.length;

        for (
            let index = start;
            index <= items.length - required;
            index += 1
        ) {
            current.push(items[index]);
            yield* backtrack(index + 1);
            current.pop();
        }
    }

    yield* backtrack(0);
}

function showEnumeration() {
    section("4. Enumeration");

    const items = ["A", "B", "C"];

    console.log("Permutations of length 2:");
    for (const value of permutations(items, 2)) {
        console.log(" ", value.join(""));
    }

    console.log("Combinations of size 2:");
    for (const value of combinations(items, 2)) {
        console.log(" ", value.join(""));
    }

    console.log(
        "Generator functions are lazy. They produce one result at a time " +
        "instead of requiring the entire result set in memory."
    );
}

// -----------------------------------------------------------------------------
// 7. Unique permutations for duplicate values
// -----------------------------------------------------------------------------

function* uniquePermutations(items) {
    const counts = new Map();

    for (const item of items) {
        counts.set(item, (counts.get(item) || 0) + 1);
    }

    const keys = [...counts.keys()].sort();
    const current = [];

    function* backtrack() {
        if (current.length === items.length) {
            yield [...current];
            return;
        }

        for (const key of keys) {
            const remaining = counts.get(key);

            if (remaining === 0) {
                continue;
            }

            counts.set(key, remaining - 1);
            current.push(key);

            yield* backtrack();

            current.pop();
            counts.set(key, remaining);
        }
    }

    yield* backtrack();
}

function multisetPermutationCount(items) {
    const counts = new Map();

    for (const item of items) {
        counts.set(item, (counts.get(item) || 0) + 1);
    }

    let total = factorial(items.length);

    for (const frequency of counts.values()) {
        total /= factorial(frequency);
    }

    return total;
}

function showDuplicateHandling() {
    section("5. Duplicate values");

    const word = [..."LEVEL"];

    console.log(
        "Distinct permutations of LEVEL =",
        multisetPermutationCount(word)
    );

    const generated = [...uniquePermutations(word)];
    console.log("Generated unique permutations =", generated.length);
    console.log("First five =", generated.slice(0, 5).map(value => value.join("")));
}

// -----------------------------------------------------------------------------
// 8. Circular permutations
// -----------------------------------------------------------------------------

function circularPermutationCount(n) {
    if (!Number.isInteger(n) || n < 0) {
        throw new RangeError("n must be a non-negative integer");
    }

    return n === 0 ? 1n : factorial(n - 1);
}

function showCircularPermutations() {
    section("6. Circular permutations");

    for (let n = 1; n <= 6; n += 1) {
        console.log(
            `${n} distinct objects around a circle =`,
            circularPermutationCount(n)
        );
    }

    console.log(
        "Rotations are equivalent, so one object can be fixed and the " +
        "remaining n-1 objects arranged: (n-1)!."
    );
}

// -----------------------------------------------------------------------------
// 9. Hypergeometric probability
// -----------------------------------------------------------------------------

function hypergeometricProbability(N, K, n, k) {
    if (
        !Number.isInteger(N) ||
        !Number.isInteger(K) ||
        !Number.isInteger(n) ||
        !Number.isInteger(k)
    ) {
        throw new TypeError("all arguments must be integers");
    }

    if (N < 0 || K < 0 || K > N || n < 0 || n > N) {
        throw new RangeError("invalid population or sample parameters");
    }

    if (k < 0 || k > K || n - k < 0 || n - k > N - K) {
        return { numerator: 0n, denominator: 1n };
    }

    const favorable =
        combinationCount(K, k) *
        combinationCount(N - K, n - k);

    const total = combinationCount(N, n);

    return reduceFraction(favorable, total);
}

function reduceFraction(numerator, denominator) {
    function gcdBigInt(a, b) {
        while (b !== 0n) {
            [a, b] = [b, a % b];
        }
        return a < 0n ? -a : a;
    }

    const divisor = gcdBigInt(numerator, denominator);

    return {
        numerator: numerator / divisor,
        denominator: denominator / divisor
    };
}

function showProbability() {
    section("7. Probability");

    const probability = hypergeometricProbability(52, 13, 5, 2);

    console.log(
        "P(exactly two hearts in five cards) =",
        `${probability.numerator}/${probability.denominator}`
    );

    console.log(
        "The numerator counts favorable unordered hands and the " +
        "denominator counts all unordered five-card hands."
    );
}

// -----------------------------------------------------------------------------
// 10. Dynamic programming for constrained selection
// -----------------------------------------------------------------------------

function subsetSumSelectionCount(values, target) {
    if (!Number.isInteger(target) || target < 0) {
        throw new RangeError("target must be a non-negative integer");
    }

    const dp = new Array(target + 1).fill(0n);
    dp[0] = 1n;

    for (const value of values) {
        if (!Number.isInteger(value) || value < 0) {
            throw new RangeError(
                "this implementation requires non-negative integer values"
            );
        }

        // Descending order ensures each input value is used at most once.
        for (let sum = target; sum >= value; sum -= 1) {
            dp[sum] += dp[sum - value];
        }
    }

    return dp[target];
}

function showDynamicProgramming() {
    section("8. Constrained combinations");

    const values = [2, 3, 5, 7, 11];
    const target = 10;

    console.log(
        "Number of subsets of [2,3,5,7,11] whose sum is 10 =",
        subsetSumSelectionCount(values, target)
    );

    console.log(
        "Dynamic programming is useful when a simple C(n,r) count is " +
        "insufficient because a numerical constraint has been added."
    );
}

// -----------------------------------------------------------------------------
// 11. Lexicographic ranking of permutations
// -----------------------------------------------------------------------------

function permutationRank(items, permutation) {
    if (items.length !== permutation.length) {
        throw new RangeError("lengths must match");
    }

    if (new Set(items).size !== items.length) {
        throw new Error("items must be distinct");
    }

    if (new Set(permutation).size !== permutation.length) {
        throw new Error("permutation must be distinct");
    }

    const expected = [...items].sort();
    const actual = [...permutation].sort();

    if (expected.some((value, index) => value !== actual[index])) {
        throw new Error("permutation must contain the same items");
    }

    let available = [...items].sort();
    let rank = 0n;

    for (let index = 0; index < permutation.length; index += 1) {
        const position = available.indexOf(permutation[index]);
        const remaining = permutation.length - index - 1;

        rank += BigInt(position) * factorial(remaining);
        available.splice(position, 1);
    }

    return rank;
}

// -----------------------------------------------------------------------------
// 12. Lexicographic unranking
// -----------------------------------------------------------------------------

function permutationUnrank(items, rank) {
    if (new Set(items).size !== items.length) {
        throw new Error("items must be distinct");
    }

    if (typeof rank !== "bigint" || rank < 0n || rank >= factorial(items.length)) {
        throw new RangeError("rank is outside the valid range");
    }

    const available = [...items].sort();
    const result = [];

    let remainingRank = rank;

    for (let remaining = items.length; remaining >= 1; remaining -= 1) {
        const blockSize = factorial(remaining - 1);
        const index = remainingRank / blockSize;

        remainingRank %= blockSize;

        result.push(available[Number(index)]);
        available.splice(Number(index), 1);
    }

    return result;
}

function showRanking() {
    section("9. Ranking and unranking");

    const items = ["A", "B", "C", "D"];

    for (const permutation of [
        ["A", "B", "C", "D"],
        ["B", "A", "D", "C"],
        ["D", "C", "B", "A"]
    ]) {
        const rank = permutationRank(items, permutation);
        const recovered = permutationUnrank(items, rank);

        console.log(
            permutation.join(""),
            "-> rank",
            rank.toString(),
            "->",
            recovered.join("")
        );

        assert(
            recovered.join("") === permutation.join(""),
            "ranking/unranking round trip"
        );
    }
}

// -----------------------------------------------------------------------------
// 13. Practical event-code system
// -----------------------------------------------------------------------------

class EventCodeSystem {
    constructor(letterAlphabet, digitAlphabet) {
        if (letterAlphabet.length === 0 || digitAlphabet.length === 0) {
            throw new Error("both alphabets must be non-empty");
        }

        this.letters = [...letterAlphabet];
        this.digits = [...digitAlphabet];
    }

    countCodes(letterPositions, digitPositions, repetitionAllowed) {
        if (letterPositions < 0 || digitPositions < 0) {
            throw new RangeError("position counts cannot be negative");
        }

        if (repetitionAllowed) {
            return (
                BigInt(this.letters.length) ** BigInt(letterPositions) *
                BigInt(this.digits.length) ** BigInt(digitPositions)
            );
        }

        if (
            letterPositions > this.letters.length ||
            digitPositions > this.digits.length
        ) {
            return 0n;
        }

        return (
            permutationCount(this.letters.length, letterPositions) *
            permutationCount(this.digits.length, digitPositions)
        );
    }

    *generateCodes(letterPositions, digitPositions) {
        if (
            letterPositions > this.letters.length ||
            digitPositions > this.digits.length
        ) {
            return;
        }

        for (const letters of permutations(this.letters, letterPositions)) {
            for (const digits of permutations(this.digits, digitPositions)) {
                yield letters.join("") + digits.join("");
            }
        }
    }
}

function showPracticalSystem() {
    section("10. Practical event-code system");

    const system = new EventCodeSystem(
        ["A", "B", "C", "D"],
        ["1", "2", "3", "4", "5"]
    );

    const count = system.countCodes(2, 3, false);

    console.log("Number of unique 2-letter + 3-digit codes =", count);

    let shown = 0;

    for (const code of system.generateCodes(2, 3)) {
        console.log(code);
        shown += 1;

        if (shown === 10) {
            break;
        }
    }

    console.log(
        "The generator can produce codes lazily, so the application does " +
        "not have to construct all possibilities at once."
    );
}

// -----------------------------------------------------------------------------
// 14. Edge cases and mistakes
// -----------------------------------------------------------------------------

function showEdgeCases() {
    section("11. Edge cases");

    console.log("0! =", factorial(0));
    console.log("C(5,0) =", combinationCount(5, 0));
    console.log("C(5,5) =", combinationCount(5, 5));
    console.log("P(5,0) =", permutationCount(5, 0));

    const invalidOperations = [
        () => combinationCount(3, 5),
        () => permutationCount(3, 5),
        () => factorial(-1)
    ];

    for (const operation of invalidOperations) {
        try {
            operation();
        } catch (error) {
            console.log(error.name + ":", error.message);
        }
    }

    console.log(
        [
            "Common mistakes:",
            "1. Treating a committee as an ordered arrangement.",
            "2. Forgetting whether repetition is permitted.",
            "3. Counting duplicate arrangements separately.",
            "4. Enumerating huge result sets unnecessarily.",
            "5. Using Number for integer values beyond the safe integer range.",
            "6. Ignoring restrictions such as adjacency or fixed positions."
        ].join("\n")
    );
}

// -----------------------------------------------------------------------------
// 15. Complexity and exact arithmetic
// -----------------------------------------------------------------------------

function showPerformanceNotes() {
    section("12. Performance considerations");

    console.log(
        [
            "Closed-form counting is normally much cheaper than enumeration.",
            "Permutation enumeration grows as n!.",
            "r-permutation enumeration grows as P(n,r).",
            "Combination enumeration grows as C(n,r).",
            "Generators reduce memory usage because results are produced lazily.",
            "BigInt preserves exact integer results but is slower than Number.",
            "Dynamic programming can replace exponential subset enumeration when",
            "the target constraint is relatively small."
        ].join("\n")
    );

    console.log(
        "C(100,50) =",
        combinationCount(100, 50).toString()
    );
}

// -----------------------------------------------------------------------------
// 16. Tests
// -----------------------------------------------------------------------------

function runTests() {
    section("13. Self-tests");

    for (let n = 0; n <= 10; n += 1) {
        assert(factorial(n) > 0n, "factorial is positive");
    }

    for (let n = 0; n <= 10; n += 1) {
        for (let r = 0; r <= n; r += 1) {
            const p = permutationCount(n, r);
            const c = combinationCount(n, r);

            assert(
                p === c * factorial(r),
                `P(${n},${r}) = C(${n},${r}) * ${r}!`
            );

            assert(
                c === combinationCount(n, n - r),
                `symmetry of C(${n},${r})`
            );
        }
    }

    assert(
        multisetPermutationCount([..."AAB"]) === 3n,
        "multiset count"
    );

    assert(
        [...uniquePermutations([..."AAB"])].length === 3,
        "unique permutation enumeration"
    );

    assert(
        circularPermutationCount(5) === 24n,
        "circular permutation count"
    );

    assert(
        subsetSumSelectionCount([2, 3, 5, 7, 11], 10) === 2n,
        "subset sum count"
    );

    const items = ["A", "B", "C", "D"];

    for (let rank = 0n; rank < factorial(items.length); rank += 1n) {
        const permutation = permutationUnrank(items, rank);
        const recoveredRank = permutationRank(items, permutation);

        assert(
            recoveredRank === rank,
            `rank/unrank round trip ${rank}`
        );
    }

    console.log("All tests passed.");
}

// -----------------------------------------------------------------------------
// 17. Main
// -----------------------------------------------------------------------------

function main() {
    console.log("COMBINATIONS AND PERMUTATIONS");

    showFactorials();
    showPermutationCounts();
    showCombinationCounts();
    showEnumeration();
    showDuplicateHandling();
    showCircularPermutations();
    showProbability();
    showDynamicProgramming();
    showRanking();
    showPracticalSystem();
    showEdgeCases();
    showPerformanceNotes();
    runTests();

    console.log("\nAll demonstrations completed successfully.");
}

main();
