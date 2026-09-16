/*
 * Probability Basics: JavaScript Practical Demonstration
 *
 * This file complements the Python study program with JavaScript-specific
 * examples involving:
 * - Arrays, Sets, Maps, functions, and classes
 * - Random simulation
 * - Functional data processing
 * - Validation and error handling
 * - Asynchronous probability experiments
 * - Monte Carlo estimation
 * - Discrete and continuous probability models
 * - Reliability analysis
 * - A browser-compatible UI example when executed in a browser
 *
 * The file uses only standard JavaScript APIs and requires no npm packages.
 */

"use strict";

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------

const EPSILON = 1e-12;

function assertProbability(value, name = "probability") {
    if (!Number.isFinite(value) || value < -EPSILON || value > 1 + EPSILON) {
        throw new RangeError(`${name} must be between 0 and 1.`);
    }
    return Math.min(1, Math.max(0, value));
}

function approximatelyEqual(a, b, tolerance = 1e-9) {
    return Math.abs(a - b) <= tolerance;
}

function factorial(n) {
    if (!Number.isInteger(n) || n < 0) {
        throw new RangeError("n must be a non-negative integer.");
    }

    let result = 1n;

    for (let i = 2n; i <= BigInt(n); i += 1n) {
        result *= i;
    }

    return result;
}

function combination(n, r) {
    if (!Number.isInteger(n) || !Number.isInteger(r)) {
        throw new TypeError("n and r must be integers.");
    }

    if (n < 0 || r < 0 || r > n) {
        throw new RangeError("Require n >= r >= 0.");
    }

    const effectiveR = Math.min(r, n - r);
    let result = 1n;

    for (let i = 1; i <= effectiveR; i += 1) {
        result = (result * BigInt(n - effectiveR + i)) / BigInt(i);
    }

    return result;
}

// -----------------------------------------------------------------------------
// Fundamental probability
// -----------------------------------------------------------------------------

function classicalProbability(favorable, total) {
    if (!Number.isInteger(favorable) || !Number.isInteger(total)) {
        throw new TypeError("Outcome counts must be integers.");
    }

    if (total <= 0 || favorable < 0 || favorable > total) {
        throw new RangeError("Invalid outcome counts.");
    }

    return favorable / total;
}

function complement(probability) {
    return 1 - assertProbability(probability);
}

function unionProbability(probabilityA, probabilityB, intersection) {
    assertProbability(probabilityA, "P(A)");
    assertProbability(probabilityB, "P(B)");
    assertProbability(intersection, "P(A and B)");

    return probabilityA + probabilityB - intersection;
}

function conditionalProbability(intersection, condition) {
    assertProbability(intersection, "P(A and B)");
    assertProbability(condition, "P(B)");

    if (condition === 0) {
        throw new RangeError("Conditional probability is undefined when P(B)=0.");
    }

    return intersection / condition;
}

function independent(probabilityA, probabilityB, intersection) {
    return approximatelyEqual(
        intersection,
        probabilityA * probabilityB
    );
}

// -----------------------------------------------------------------------------
// Bayes and total probability
// -----------------------------------------------------------------------------

function bayesTheorem(pBGivenA, pA, pBGivenNotA) {
    assertProbability(pBGivenA, "P(B|A)");
    assertProbability(pA, "P(A)");
    assertProbability(pBGivenNotA, "P(B|not A)");

    const pNotA = 1 - pA;
    const denominator =
        pBGivenA * pA +
        pBGivenNotA * pNotA;

    if (denominator === 0) {
        throw new RangeError("Posterior is undefined because P(B)=0.");
    }

    return (pBGivenA * pA) / denominator;
}

function lawOfTotalProbability(conditionalProbabilities, priorProbabilities) {
    if (
        conditionalProbabilities.length !== priorProbabilities.length ||
        conditionalProbabilities.length === 0
    ) {
        throw new RangeError("Probability arrays must have equal non-zero length.");
    }

    const priorTotal = priorProbabilities.reduce((sum, p) => sum + p, 0);

    if (!approximatelyEqual(priorTotal, 1)) {
        throw new RangeError("Prior probabilities must sum to 1.");
    }

    return conditionalProbabilities.reduce(
        (sum, conditional, index) =>
            sum + conditional * priorProbabilities[index],
        0
    );
}

// -----------------------------------------------------------------------------
// Discrete distributions
// -----------------------------------------------------------------------------

function bernoulliPMF(x, p) {
    assertProbability(p, "p");

    if (x === 1) return p;
    if (x === 0) return 1 - p;

    return 0;
}

function binomialPMF(k, n, p) {
    assertProbability(p, "p");

    if (!Number.isInteger(n) || n < 0) {
        throw new RangeError("n must be a non-negative integer.");
    }

    if (!Number.isInteger(k) || k < 0 || k > n) {
        return 0;
    }

    const coefficient = Number(combination(n, k));

    return coefficient *
        Math.pow(p, k) *
        Math.pow(1 - p, n - k);
}

function binomialCDF(k, n, p) {
    if (k < 0) return 0;
    if (k >= n) return 1;

    let total = 0;

    for (let i = 0; i <= k; i += 1) {
        total += binomialPMF(i, n, p);
    }

    return total;
}

function poissonPMF(k, lambda) {
    if (!Number.isInteger(k) || k < 0) return 0;

    if (!Number.isFinite(lambda) || lambda < 0) {
        throw new RangeError("lambda must be non-negative and finite.");
    }

    return Math.exp(-lambda) *
        Math.pow(lambda, k) /
        Number(factorial(k));
}

function geometricPMF(k, p) {
    assertProbability(p, "p");

    if (p <= 0) {
        throw new RangeError("p must be positive.");
    }

    if (!Number.isInteger(k) || k < 1) return 0;

    return Math.pow(1 - p, k - 1) * p;
}

function hypergeometricPMF(k, N, K, n) {
    if (![k, N, K, n].every(Number.isInteger)) {
        throw new TypeError("Parameters must be integers.");
    }

    if (N < 0 || K < 0 || n < 0 || K > N || n > N) {
        throw new RangeError("Invalid hypergeometric parameters.");
    }

    if (k < Math.max(0, n - (N - K)) || k > Math.min(n, K)) {
        return 0;
    }

    const numerator =
        combination(K, k) *
        combination(N - K, n - k);

    const denominator = combination(N, n);

    return Number(numerator) / Number(denominator);
}

// -----------------------------------------------------------------------------
// Continuous distributions
// -----------------------------------------------------------------------------

function normalPDF(x, mean = 0, standardDeviation = 1) {
    if (standardDeviation <= 0) {
        throw new RangeError("standardDeviation must be positive.");
    }

    const coefficient =
        1 / (standardDeviation * Math.sqrt(2 * Math.PI));

    const exponent =
        -0.5 * Math.pow((x - mean) / standardDeviation, 2);

    return coefficient * Math.exp(exponent);
}

function standardNormalCDF(z) {
    /*
     * Abramowitz-Stegun-style approximation.
     * This is sufficient for educational numerical work.
     */
    const sign = z < 0 ? -1 : 1;
    const absoluteZ = Math.abs(z);

    const t = 1 / (1 + 0.2316419 * absoluteZ);

    const d = 0.3989423 * Math.exp(-absoluteZ * absoluteZ / 2);

    const probability =
        1 -
        d *
        (
            0.3193815 * t -
            0.3565638 * t ** 2 +
            1.781478 * t ** 3 -
            1.821256 * t ** 4 +
            1.330274 * t ** 5
        );

    return sign === 1 ? probability : 1 - probability;
}

function normalCDF(x, mean = 0, standardDeviation = 1) {
    if (standardDeviation <= 0) {
        throw new RangeError("standardDeviation must be positive.");
    }

    return standardNormalCDF(
        (x - mean) / standardDeviation
    );
}

function exponentialCDF(x, rate) {
    if (rate <= 0) {
        throw new RangeError("rate must be positive.");
    }

    return x < 0 ? 0 : 1 - Math.exp(-rate * x);
}

// -----------------------------------------------------------------------------
// Random sampling
// -----------------------------------------------------------------------------

function randomDieRoll() {
    // Math.random() is suitable for simulation, not cryptographic security.
    return Math.floor(Math.random() * 6) + 1;
}

function simulateDieRolls(numberOfRolls) {
    if (!Number.isInteger(numberOfRolls) || numberOfRolls <= 0) {
        throw new RangeError("numberOfRolls must be positive.");
    }

    const counts = new Map();

    for (let face = 1; face <= 6; face += 1) {
        counts.set(face, 0);
    }

    for (let i = 0; i < numberOfRolls; i += 1) {
        const face = randomDieRoll();
        counts.set(face, counts.get(face) + 1);
    }

    return counts;
}

function weightedChoice(values, weights) {
    if (values.length !== weights.length || values.length === 0) {
        throw new RangeError("Values and weights must have equal non-zero length.");
    }

    const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);

    if (totalWeight <= 0) {
        throw new RangeError("Total weight must be positive.");
    }

    let target = Math.random() * totalWeight;

    for (let i = 0; i < values.length; i += 1) {
        target -= weights[i];

        if (target < 0) {
            return values[i];
        }
    }

    return values[values.length - 1];
}

// -----------------------------------------------------------------------------
// Random variable class
// -----------------------------------------------------------------------------

class DiscreteDistribution {
    constructor(probabilities) {
        this.probabilities = new Map(probabilities);

        if (this.probabilities.size === 0) {
            throw new RangeError("Distribution cannot be empty.");
        }

        const total = [...this.probabilities.values()]
            .reduce((sum, probability) => sum + probability, 0);

        if (!approximatelyEqual(total, 1)) {
            throw new RangeError("Probabilities must sum to 1.");
        }

        for (const probability of this.probabilities.values()) {
            assertProbability(probability);
        }
    }

    probability(outcome) {
        return this.probabilities.get(outcome) ?? 0;
    }

    expectedValue() {
        let total = 0;

        for (const [outcome, probability] of this.probabilities) {
            total += outcome * probability;
        }

        return total;
    }

    variance() {
        const mean = this.expectedValue();

        let total = 0;

        for (const [outcome, probability] of this.probabilities) {
            total += Math.pow(outcome - mean, 2) * probability;
        }

        return total;
    }

    sample() {
        return weightedChoice(
            [...this.probabilities.keys()],
            [...this.probabilities.values()]
        );
    }
}

// -----------------------------------------------------------------------------
// Functional data processing
// -----------------------------------------------------------------------------

function expectedValue(values, probabilities) {
    if (
        values.length !== probabilities.length ||
        values.length === 0
    ) {
        throw new RangeError("Values and probabilities must have equal length.");
    }

    const probabilityTotal = probabilities.reduce(
        (sum, probability) => sum + probability,
        0
    );

    if (!approximatelyEqual(probabilityTotal, 1)) {
        throw new RangeError("Probabilities must sum to 1.");
    }

    return values.reduce(
        (sum, value, index) =>
            sum + value * probabilities[index],
        0
    );
}

function variance(values, probabilities) {
    const mean = expectedValue(values, probabilities);

    return values.reduce(
        (sum, value, index) =>
            sum +
            probabilities[index] *
            Math.pow(value - mean, 2),
        0
    );
}

// -----------------------------------------------------------------------------
// Monte Carlo
// -----------------------------------------------------------------------------

function estimatePi(samples) {
    if (!Number.isInteger(samples) || samples <= 0) {
        throw new RangeError("samples must be positive.");
    }

    let inside = 0;

    for (let i = 0; i < samples; i += 1) {
        const x = Math.random();
        const y = Math.random();

        if (x * x + y * y <= 1) {
            inside += 1;
        }
    }

    return 4 * inside / samples;
}

// -----------------------------------------------------------------------------
// Reliability
// -----------------------------------------------------------------------------

function seriesReliability(reliabilities) {
    if (reliabilities.length === 0) {
        throw new RangeError("At least one component is required.");
    }

    return reliabilities.reduce(
        (product, reliability) =>
            product * assertProbability(reliability),
        1
    );
}

function parallelReliability(reliabilities) {
    if (reliabilities.length === 0) {
        throw new RangeError("At least one component is required.");
    }

    const allFail = reliabilities.reduce(
        (product, reliability) =>
            product * (1 - assertProbability(reliability)),
        1
    );

    return 1 - allFail;
}

// -----------------------------------------------------------------------------
// Asynchronous simulation
// -----------------------------------------------------------------------------

function delay(milliseconds) {
    return new Promise(resolve => {
        setTimeout(resolve, milliseconds);
    });
}

async function asynchronousExperiment(numberOfTrials) {
    /*
     * Async functions return Promises. This example demonstrates how a
     * probability experiment can coexist with event-driven JavaScript.
     */
    if (!Number.isInteger(numberOfTrials) || numberOfTrials <= 0) {
        throw new RangeError("numberOfTrials must be positive.");
    }

    let successes = 0;

    for (let i = 0; i < numberOfTrials; i += 1) {
        await delay(0);

        if (Math.random() < 0.5) {
            successes += 1;
        }
    }

    return successes / numberOfTrials;
}

// -----------------------------------------------------------------------------
// Practical case study: quality-control inspection
// -----------------------------------------------------------------------------

class QualityControlModel {
    constructor() {
        this.machines = [
            {
                name: "Machine A",
                probability: 0.70,
                defectRate: 0.02
            },
            {
                name: "Machine B",
                probability: 0.30,
                defectRate: 0.08
            }
        ];
    }

    theoreticalDefectProbability() {
        return lawOfTotalProbability(
            this.machines.map(machine => machine.defectRate),
            this.machines.map(machine => machine.probability)
        );
    }

    probabilityMachineBGivenDefect() {
        const machineB = this.machines[1];

        return bayesTheorem(
            machineB.defectRate,
            machineB.probability,
            this.machines[0].defectRate
        );
    }

    simulate(trials) {
        if (!Number.isInteger(trials) || trials <= 0) {
            throw new RangeError("trials must be positive.");
        }

        let defects = 0;
        let machineBDefects = 0;

        for (let i = 0; i < trials; i += 1) {
            const machineB = Math.random() < 0.30;
            const defectRate = machineB ? 0.08 : 0.02;
            const defect = Math.random() < defectRate;

            if (defect) {
                defects += 1;

                if (machineB) {
                    machineBDefects += 1;
                }
            }
        }

        return {
            defectProbability: defects / trials,
            machineBGivenDefect:
                defects === 0 ? NaN : machineBDefects / defects
        };
    }
}

// -----------------------------------------------------------------------------
// Browser-specific demonstration
// -----------------------------------------------------------------------------

function createBrowserProbabilityDemo() {
    /*
     * The same JavaScript file can run in Node.js. DOM code is therefore
     * guarded so it does not execute when document is unavailable.
     */
    if (typeof document === "undefined") {
        return;
    }

    const container = document.createElement("section");
    container.style.fontFamily = "system-ui, sans-serif";
    container.style.padding = "20px";

    const title = document.createElement("h2");
    title.textContent = "Probability Simulation";

    const button = document.createElement("button");
    button.textContent = "Simulate 10,000 Coin Flips";

    const output = document.createElement("pre");

    button.addEventListener("click", () => {
        let heads = 0;
        const trials = 10_000;

        for (let i = 0; i < trials; i += 1) {
            if (Math.random() < 0.5) {
                heads += 1;
            }
        }

        const estimated = heads / trials;

        output.textContent =
            `Heads: ${heads}\n` +
            `Trials: ${trials}\n` +
            `Estimated P(heads): ${estimated.toFixed(4)}\n` +
            `Theoretical P(heads): 0.5000`;
    });

    container.append(title, button, output);
    document.body.appendChild(container);
}

// -----------------------------------------------------------------------------
// Demonstrations
// -----------------------------------------------------------------------------

function runDemonstrations() {
    console.log("=".repeat(78));
    console.log("Probability Basics: JavaScript Demonstration");
    console.log("=".repeat(78));

    console.log("\nSample space");
    const die = new Set([1, 2, 3, 4, 5, 6]);
    const even = new Set([...die].filter(value => value % 2 === 0));

    console.log("Die outcomes:", [...die]);
    console.log("Even outcomes:", [...even]);
    console.log("P(even):", classicalProbability(even.size, die.size));

    console.log("\nCounting");
    console.log("5! =", factorial(5).toString());
    console.log("C(5,2) =", combination(5, 2).toString());

    console.log("\nEvent rules");
    console.log("P(not A), P(A)=0.3:", complement(0.3));
    console.log(
        "P(A union B):",
        unionProbability(0.5, 0.4, 0.2)
    );
    console.log(
        "P(A|B):",
        conditionalProbability(0.2, 0.4)
    );
    console.log(
        "Independent:",
        independent(0.5, 0.4, 0.2)
    );

    console.log("\nBayes theorem");
    const posterior = bayesTheorem(0.99, 0.01, 0.05);
    console.log("P(disease | positive):", posterior);

    console.log("\nDiscrete distributions");
    console.log("Bernoulli P(X=1), p=0.7:", bernoulliPMF(1, 0.7));
    console.log("Binomial P(X=6), n=10, p=0.6:", binomialPMF(6, 10, 0.6));
    console.log("Binomial P(X<=6):", binomialCDF(6, 10, 0.6));
    console.log("Geometric P(X=4), p=0.25:", geometricPMF(4, 0.25));
    console.log("Poisson P(X=3), lambda=2:", poissonPMF(3, 2));
    console.log(
        "Hypergeometric P(X=1):",
        hypergeometricPMF(1, 20, 5, 4)
    );

    console.log("\nContinuous distributions");
    console.log("Normal PDF at 0:", normalPDF(0));
    console.log("Normal P(X<=1.96):", normalCDF(1.96));
    console.log("Exponential P(X<=2), rate=0.5:", exponentialCDF(2, 0.5));

    console.log("\nRandom variable");
    const fairDie = new DiscreteDistribution(
        [[1, 1 / 6], [2, 1 / 6], [3, 1 / 6],
         [4, 1 / 6], [5, 1 / 6], [6, 1 / 6]]
    );

    console.log("Mean:", fairDie.expectedValue());
    console.log("Variance:", fairDie.variance());
    console.log("Random sample:", fairDie.sample());

    console.log("\nFunctional expected value");
    const values = [0, 1, 2];
    const probabilities = [0.2, 0.5, 0.3];

    console.log("E[X]:", expectedValue(values, probabilities));
    console.log("Var(X):", variance(values, probabilities));

    console.log("\nMonte Carlo");
    for (const samples of [1_000, 10_000, 100_000]) {
        const estimate = estimatePi(samples);
        console.log(
            `samples=${samples}: pi≈${estimate.toFixed(6)}, ` +
            `error=${Math.abs(estimate - Math.PI).toFixed(6)}`
        );
    }

    console.log("\nReliability");
    const components = [0.99, 0.98, 0.995];

    console.log("Series:", seriesReliability(components));
    console.log("Parallel:", parallelReliability(components));

    console.log("\nQuality-control case study");
    const qualityControl = new QualityControlModel();

    console.log(
        "Theoretical defect probability:",
        qualityControl.theoreticalDefectProbability()
    );

    console.log(
        "P(Machine B | defect):",
        qualityControl.probabilityMachineBGivenDefect()
    );

    console.log(
        "Simulation:",
        qualityControl.simulate(100_000)
    );

    console.log("\nError handling");
    try {
        binomialPMF(20, 10, 0.5);
        console.log("Invalid input was unexpectedly accepted.");
    } catch (error) {
        console.log("Handled invalid input:", error.message);
    }

    console.log("\nPerformance note");
    console.log(
        "Combinatorial counts use BigInt internally to avoid integer precision " +
        "loss for large exact counts."
    );
}

// -----------------------------------------------------------------------------
// Self-tests
// -----------------------------------------------------------------------------

function runTests() {
    console.log("\n" + "-".repeat(78));
    console.log("Self-tests");
    console.log("-".repeat(78));

    console.assert(
        approximatelyEqual(classicalProbability(1, 6), 1 / 6),
        "Classical probability failed."
    );

    console.assert(
        combination(5, 2) === 10n,
        "Combination failed."
    );

    console.assert(
        approximatelyEqual(
            binomialPMF(0, 10, 0.5),
            1 / 1024
        ),
        "Binomial failed."
    );

    console.assert(
        approximatelyEqual(normalCDF(0), 0.5, 1e-5),
        "Normal CDF failed."
    );

    console.assert(
        approximatelyEqual(
            seriesReliability([1, 1]),
            1
        ),
        "Series reliability failed."
    );

    try {
        assertProbability(2);
        console.assert(false, "Invalid probability was accepted.");
    } catch {
        console.log("Invalid probability correctly rejected.");
    }

    console.log("Self-tests completed.");
}

// -----------------------------------------------------------------------------
// Program entry
// -----------------------------------------------------------------------------

async function main() {
    runDemonstrations();
    runTests();

    console.log("\nAsynchronous experiment");

    const estimatedHeads = await asynchronousExperiment(1000);

    console.log(
        "Estimated probability of heads:",
        estimatedHeads
    );

    createBrowserProbabilityDemo();
}

if (typeof module !== "undefined" && require.main === module) {
    main().catch(error => {
        console.error("Program failed:", error);
        process.exitCode = 1;
    });
} else if (typeof window !== "undefined") {
    main().catch(error => {
        console.error("Browser execution failed:", error);
    });
}
