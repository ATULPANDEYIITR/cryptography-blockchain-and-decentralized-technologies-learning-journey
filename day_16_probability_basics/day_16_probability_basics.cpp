/*
 * Probability Basics: C++17 Technical Case Study
 *
 * Case study:
 * A manufacturing quality-control system receives products from multiple
 * production machines. The system must estimate defect risk, calculate
 * conditional probabilities, simulate inspections, model reliability,
 * calculate exact discrete distributions for small independent risk
 * portfolios, and report statistical quantities.
 *
 * The program demonstrates:
 * - Sample spaces and events
 * - Counting
 * - Conditional probability
 * - Bayes' theorem
 * - Total probability
 * - Discrete distributions
 * - Simulation
 * - Expected value and variance
 * - Reliability
 * - Input validation
 * - Classes and structures
 * - STL containers and algorithms
 * - Random number generation
 * - Complexity considerations
 *
 * Compile:
 *     g++ -std=c++17 -O2 probability_basics.cpp -o probability_basics
 */

#include <algorithm>
#include <cassert>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;

constexpr double EPSILON = 1e-10;

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------

bool approximatelyEqual(double a, double b, double tolerance = EPSILON) {
    return fabs(a - b) <= tolerance;
}

double validateProbability(double probability, const string& name) {
    if (!isfinite(probability) ||
        probability < -EPSILON ||
        probability > 1.0 + EPSILON) {
        throw invalid_argument(name + " must be between 0 and 1.");
    }

    return min(1.0, max(0.0, probability));
}

double safeDivide(double numerator, double denominator) {
    if (fabs(denominator) <= EPSILON) {
        throw domain_error("Division by zero in probability calculation.");
    }

    return numerator / denominator;
}

// -----------------------------------------------------------------------------
// Counting
// -----------------------------------------------------------------------------

unsigned long long factorial(unsigned int n) {
    unsigned long long result = 1;

    for (unsigned int i = 2; i <= n; ++i) {
        if (result > numeric_limits<unsigned long long>::max() / i) {
            throw overflow_error("Factorial exceeds unsigned long long.");
        }

        result *= i;
    }

    return result;
}

unsigned long long combination(unsigned int n, unsigned int r) {
    if (r > n) {
        throw invalid_argument("r cannot exceed n.");
    }

    r = min(r, n - r);

    unsigned long long result = 1;

    for (unsigned int i = 1; i <= r; ++i) {
        /*
         * For large n, even mathematically valid combinations can exceed
         * machine integer capacity. Production systems should use arbitrary
         * precision integers when exact large counts are required.
         */
        if (result > numeric_limits<unsigned long long>::max() / (n - r + i)) {
            throw overflow_error("Combination exceeds unsigned long long.");
        }

        result *= (n - r + i);
        result /= i;
    }

    return result;
}

// -----------------------------------------------------------------------------
// Probability rules
// -----------------------------------------------------------------------------

double classicalProbability(unsigned int favorable, unsigned int total) {
    if (total == 0 || favorable > total) {
        throw invalid_argument("Invalid outcome counts.");
    }

    return static_cast<double>(favorable) / total;
}

double conditionalProbability(double intersection, double condition) {
    validateProbability(intersection, "P(A and B)");
    validateProbability(condition, "P(B)");

    return safeDivide(intersection, condition);
}

double bayesTheorem(
    double pBGivenA,
    double pA,
    double pBGivenNotA
) {
    validateProbability(pBGivenA, "P(B|A)");
    validateProbability(pA, "P(A)");
    validateProbability(pBGivenNotA, "P(B|not A)");

    double pNotA = 1.0 - pA;

    double denominator =
        pBGivenA * pA +
        pBGivenNotA * pNotA;

    return safeDivide(
        pBGivenA * pA,
        denominator
    );
}

double totalProbability(
    const vector<double>& conditionals,
    const vector<double>& priors
) {
    if (conditionals.empty() ||
        conditionals.size() != priors.size()) {
        throw invalid_argument(
            "Conditional and prior probability vectors must match."
        );
    }

    double priorSum =
        accumulate(priors.begin(), priors.end(), 0.0);

    if (!approximatelyEqual(priorSum, 1.0)) {
        throw invalid_argument("Prior probabilities must sum to 1.");
    }

    double result = 0.0;

    for (size_t i = 0; i < conditionals.size(); ++i) {
        validateProbability(conditionals[i], "Conditional probability");
        validateProbability(priors[i], "Prior probability");

        result += conditionals[i] * priors[i];
    }

    return result;
}

// -----------------------------------------------------------------------------
// Discrete distribution
// -----------------------------------------------------------------------------

class DiscreteDistribution {
private:
    map<int, double> probabilities;

public:
    explicit DiscreteDistribution(map<int, double> probabilities)
        : probabilities(move(probabilities)) {

        if (this->probabilities.empty()) {
            throw invalid_argument("Distribution cannot be empty.");
        }

        double total = 0.0;

        for (const auto& [outcome, probability] : this->probabilities) {
            (void)outcome;
            validateProbability(probability, "Distribution probability");
            total += probability;
        }

        if (!approximatelyEqual(total, 1.0)) {
            throw invalid_argument(
                "Distribution probabilities must sum to 1."
            );
        }
    }

    double probability(int outcome) const {
        auto iterator = probabilities.find(outcome);

        if (iterator == probabilities.end()) {
            return 0.0;
        }

        return iterator->second;
    }

    double expectedValue() const {
        double result = 0.0;

        for (const auto& [outcome, probability] : probabilities) {
            result += static_cast<double>(outcome) * probability;
        }

        return result;
    }

    double variance() const {
        const double mean = expectedValue();
        double result = 0.0;

        for (const auto& [outcome, probability] : probabilities) {
            double difference =
                static_cast<double>(outcome) - mean;

            result += difference * difference * probability;
        }

        return result;
    }

    double standardDeviation() const {
        return sqrt(variance());
    }

    int sample(mt19937& generator) const {
        vector<int> outcomes;
        vector<double> weights;

        for (const auto& [outcome, probability] : probabilities) {
            outcomes.push_back(outcome);
            weights.push_back(probability);
        }

        discrete_distribution<int> distribution(
            weights.begin(),
            weights.end()
        );

        return outcomes[distribution(generator)];
    }
};

// -----------------------------------------------------------------------------
// Statistical functions
// -----------------------------------------------------------------------------

double mean(const vector<double>& values) {
    if (values.empty()) {
        throw invalid_argument("Cannot calculate mean of empty data.");
    }

    return accumulate(
        values.begin(),
        values.end(),
        0.0
    ) / values.size();
}

double populationVariance(const vector<double>& values) {
    if (values.empty()) {
        throw invalid_argument("Cannot calculate variance of empty data.");
    }

    double average = mean(values);
    double squaredDifference = 0.0;

    for (double value : values) {
        squaredDifference +=
            (value - average) * (value - average);
    }

    return squaredDifference / values.size();
}

double covariance(
    const vector<double>& x,
    const vector<double>& y
) {
    if (x.empty() || x.size() != y.size()) {
        throw invalid_argument(
            "Covariance requires equal non-empty vectors."
        );
    }

    double meanX = mean(x);
    double meanY = mean(y);
    double total = 0.0;

    for (size_t i = 0; i < x.size(); ++i) {
        total +=
            (x[i] - meanX) *
            (y[i] - meanY);
    }

    return total / x.size();
}

// -----------------------------------------------------------------------------
// Distributions
// -----------------------------------------------------------------------------

double binomialPMF(
    unsigned int k,
    unsigned int n,
    double p
) {
    validateProbability(p, "p");

    if (k > n) {
        return 0.0;
    }

    /*
     * The direct combination formula is suitable for moderate n.
     * For very large n, production implementations often work in logarithmic
     * space to avoid overflow and underflow.
     */
    double coefficient =
        static_cast<double>(combination(n, k));

    return coefficient *
           pow(p, static_cast<double>(k)) *
           pow(
               1.0 - p,
               static_cast<double>(n - k)
           );
}

double poissonPMF(
    unsigned int k,
    double lambda
) {
    if (!isfinite(lambda) || lambda < 0.0) {
        throw invalid_argument("lambda must be non-negative.");
    }

    return exp(-lambda) *
           pow(lambda, static_cast<double>(k)) /
           static_cast<double>(factorial(k));
}

double normalPDF(
    double x,
    double meanValue = 0.0,
    double standardDeviation = 1.0
) {
    if (standardDeviation <= 0.0) {
        throw invalid_argument(
            "Standard deviation must be positive."
        );
    }

    const double pi = acos(-1.0);

    double coefficient =
        1.0 /
        (standardDeviation * sqrt(2.0 * pi));

    double z =
        (x - meanValue) /
        standardDeviation;

    return coefficient * exp(-0.5 * z * z);
}

// -----------------------------------------------------------------------------
// Reliability
// -----------------------------------------------------------------------------

double seriesReliability(
    const vector<double>& reliabilities
) {
    if (reliabilities.empty()) {
        throw invalid_argument(
            "Series system requires components."
        );
    }

    double result = 1.0;

    for (double reliability : reliabilities) {
        result *=
            validateProbability(
                reliability,
                "Component reliability"
            );
    }

    return result;
}

double parallelReliability(
    const vector<double>& reliabilities
) {
    if (reliabilities.empty()) {
        throw invalid_argument(
            "Parallel system requires components."
        );
    }

    double allFail = 1.0;

    for (double reliability : reliabilities) {
        allFail *=
            1.0 -
            validateProbability(
                reliability,
                "Component reliability"
            );
    }

    return 1.0 - allFail;
}

// -----------------------------------------------------------------------------
// Manufacturing domain model
// -----------------------------------------------------------------------------

struct Machine {
    string name;
    double selectionProbability;
    double defectRate;
};

class QualityControlSystem {
private:
    vector<Machine> machines;
    mt19937 generator;

public:
    QualityControlSystem(
        vector<Machine> machines,
        unsigned int seed = 42
    )
        : machines(move(machines)),
          generator(seed) {

        if (this->machines.empty()) {
            throw invalid_argument(
                "At least one machine is required."
            );
        }

        double totalSelectionProbability = 0.0;

        for (const auto& machine : this->machines) {
            validateProbability(
                machine.selectionProbability,
                "Machine selection probability"
            );

            validateProbability(
                machine.defectRate,
                "Machine defect rate"
            );

            totalSelectionProbability +=
                machine.selectionProbability;
        }

        if (!approximatelyEqual(
                totalSelectionProbability,
                1.0
            )) {
            throw invalid_argument(
                "Machine selection probabilities must sum to 1."
            );
        }
    }

    double theoreticalDefectProbability() const {
        double result = 0.0;

        for (const auto& machine : machines) {
            result +=
                machine.selectionProbability *
                machine.defectRate;
        }

        return result;
    }

    double probabilityMachineBGivenDefect(
        size_t machineIndex
    ) const {
        if (machineIndex >= machines.size()) {
            throw out_of_range("Machine index out of range.");
        }

        const Machine& selected = machines[machineIndex];

        double denominator =
            theoreticalDefectProbability();

        return safeDivide(
            selected.selectionProbability *
            selected.defectRate,
            denominator
        );
    }

    struct SimulationResult {
        unsigned long long totalInspections = 0;
        unsigned long long defects = 0;
        vector<unsigned long long> defectsByMachine;
    };

    SimulationResult simulate(
        unsigned long long inspections
    ) {
        if (inspections == 0) {
            throw invalid_argument(
                "Inspection count must be positive."
            );
        }

        vector<double> selectionWeights;

        for (const auto& machine : machines) {
            selectionWeights.push_back(
                machine.selectionProbability
            );
        }

        discrete_distribution<size_t> machineDistribution(
            selectionWeights.begin(),
            selectionWeights.end()
        );

        SimulationResult result;
        result.totalInspections = inspections;
        result.defectsByMachine.assign(
            machines.size(),
            0
        );

        uniform_real_distribution<double> uniform(0.0, 1.0);

        for (unsigned long long i = 0;
             i < inspections;
             ++i) {

            size_t machineIndex =
                machineDistribution(generator);

            bool defect =
                uniform(generator) <
                machines[machineIndex].defectRate;

            if (defect) {
                ++result.defects;
                ++result.defectsByMachine[machineIndex];
            }
        }

        return result;
    }

    const vector<Machine>& getMachines() const {
        return machines;
    }
};

// -----------------------------------------------------------------------------
// Exact independent portfolio-loss distribution
// -----------------------------------------------------------------------------

struct RiskPosition {
    string name;
    double probabilityOfLoss;
    double lossAmount;
};

map<double, double> portfolioLossDistribution(
    const vector<RiskPosition>& positions
) {
    if (positions.empty()) {
        throw invalid_argument(
            "Portfolio requires at least one position."
        );
    }

    map<double, double> distribution;
    distribution[0.0] = 1.0;

    for (const auto& position : positions) {
        validateProbability(
            position.probabilityOfLoss,
            "Loss probability"
        );

        if (position.lossAmount < 0.0) {
            throw invalid_argument(
                "Loss amount cannot be negative."
            );
        }

        map<double, double> nextDistribution;

        for (const auto& [currentLoss, currentProbability]
             : distribution) {

            double noLoss =
                currentProbability *
                (1.0 - position.probabilityOfLoss);

            double loss =
                currentProbability *
                position.probabilityOfLoss;

            nextDistribution[currentLoss] += noLoss;

            nextDistribution[
                currentLoss + position.lossAmount
            ] += loss;
        }

        distribution = move(nextDistribution);
    }

    return distribution;
}

// -----------------------------------------------------------------------------
// Monte Carlo
// -----------------------------------------------------------------------------

double estimatePi(
    unsigned long long samples,
    unsigned int seed = 42
) {
    if (samples == 0) {
        throw invalid_argument(
            "Number of samples must be positive."
        );
    }

    mt19937 generator(seed);
    uniform_real_distribution<double> uniform(0.0, 1.0);

    unsigned long long inside = 0;

    for (unsigned long long i = 0;
         i < samples;
         ++i) {

        double x = uniform(generator);
        double y = uniform(generator);

        if (x * x + y * y <= 1.0) {
            ++inside;
        }
    }

    return 4.0 *
           static_cast<double>(inside) /
           static_cast<double>(samples);
}

// -----------------------------------------------------------------------------
// Quality-control report
// -----------------------------------------------------------------------------

void printQualityControlReport(
    const QualityControlSystem& system,
    const QualityControlSystem::SimulationResult& result
) {
    cout << "\nQUALITY-CONTROL REPORT\n";
    cout << "----------------------\n";

    double theoretical =
        system.theoreticalDefectProbability();

    double empirical =
        static_cast<double>(result.defects) /
        result.totalInspections;

    cout << fixed << setprecision(6);

    cout << "Theoretical defect probability: "
         << theoretical << '\n';

    cout << "Empirical defect probability:   "
         << empirical << '\n';

    cout << "Absolute simulation error:      "
         << fabs(empirical - theoretical)
         << '\n';

    cout << "\nDefects by machine:\n";

    const auto& machines =
        system.getMachines();

    for (size_t i = 0;
         i < machines.size();
         ++i) {

        cout << "  "
             << machines[i].name
             << ": "
             << result.defectsByMachine[i]
             << '\n';
    }
}

// -----------------------------------------------------------------------------
// Demonstrations
// -----------------------------------------------------------------------------

void demonstrateFundamentals() {
    cout << "\n";
    cout << string(78, '=') << '\n';
    cout << "FUNDAMENTALS\n";
    cout << string(78, '=') << '\n';

    cout << "P(even on a fair die) = "
         << classicalProbability(3, 6)
         << '\n';

    double pA = 0.4;
    double pB = 0.3;
    double pIntersection = 0.12;

    cout << "P(A union B) = "
         << pA + pB - pIntersection
         << '\n';

    cout << "P(not A) = "
         << 1.0 - pA
         << '\n';

    cout << "P(A|B) = "
         << conditionalProbability(
                pIntersection,
                pB
            )
         << '\n';

    cout << "P(A and B) under independence = "
         << pA * pB
         << '\n';
}

void demonstrateDistributions() {
    cout << "\n";
    cout << string(78, '=') << '\n';
    cout << "DISTRIBUTIONS\n";
    cout << string(78, '=') << '\n';

    cout << "Binomial P(X=6), n=10, p=0.6 = "
         << binomialPMF(6, 10, 0.6)
         << '\n';

    cout << "Poisson P(X=3), lambda=2 = "
         << poissonPMF(3, 2.0)
         << '\n';

    cout << "Standard normal PDF at 0 = "
         << normalPDF(0.0)
         << '\n';

    DiscreteDistribution die({
        {1, 1.0 / 6.0},
        {2, 1.0 / 6.0},
        {3, 1.0 / 6.0},
        {4, 1.0 / 6.0},
        {5, 1.0 / 6.0},
        {6, 1.0 / 6.0}
    });

    cout << "Fair-die expected value = "
         << die.expectedValue()
         << '\n';

    cout << "Fair-die variance = "
         << die.variance()
         << '\n';

    mt19937 generator(42);

    cout << "Random die samples: ";

    for (int i = 0; i < 10; ++i) {
        cout << die.sample(generator) << ' ';
    }

    cout << '\n';
}

void demonstratePortfolio() {
    cout << "\n";
    cout << string(78, '=') << '\n';
    cout << "INDEPENDENT PORTFOLIO RISK MODEL\n";
    cout << string(78, '=') << '\n';

    vector<RiskPosition> positions = {
        {"A", 0.10, 1000.0},
        {"B", 0.20, 2000.0},
        {"C", 0.05, 5000.0}
    };

    auto distribution =
        portfolioLossDistribution(positions);

    double expectedLoss = 0.0;

    for (const auto& [loss, probability] : distribution) {
        expectedLoss += loss * probability;
    }

    double variance = 0.0;

    for (const auto& [loss, probability] : distribution) {
        variance +=
            (loss - expectedLoss) *
            (loss - expectedLoss) *
            probability;
    }

    double probabilityAtLeast3000 = 0.0;

    for (const auto& [loss, probability] : distribution) {
        if (loss >= 3000.0) {
            probabilityAtLeast3000 += probability;
        }
    }

    cout << fixed << setprecision(6);

    cout << "Exact loss distribution:\n";

    for (const auto& [loss, probability] : distribution) {
        cout << "  Loss = "
             << setw(7) << loss
             << ", P = "
             << probability
             << '\n';
    }

    cout << "Expected loss = "
         << expectedLoss
         << '\n';

    cout << "Loss variance = "
         << variance
         << '\n';

    cout << "P(loss >= 3000) = "
         << probabilityAtLeast3000
         << '\n';

    cout << "\nAssumption: positions are independent.\n";
    cout << "Correlated losses require a dependence model.\n";
}

void demonstratePerformance() {
    cout << "\n";
    cout << string(78, '=') << '\n';
    cout << "PERFORMANCE AND COMPLEXITY\n";
    cout << string(78, '=') << '\n';

    cout << "C(100,50) has "
         << combination(100, 50)
         << " possible subsets within this integer range.\n";

    cout << "Direct counting avoids enumerating every subset.\n";
    cout << "Enumerating subsets has exponential growth.\n";
}

void runTests() {
    cout << "\n";
    cout << string(78, '=') << '\n';
    cout << "SELF-TESTS\n";
    cout << string(78, '=') << '\n';

    assert(approximatelyEqual(
        classicalProbability(1, 6),
        1.0 / 6.0
    ));

    assert(combination(5, 2) == 10);

    assert(approximatelyEqual(
        binomialPMF(0, 10, 0.5),
        1.0 / 1024.0
    ));

    assert(approximatelyEqual(
        normalPDF(0.0),
        1.0 / sqrt(2.0 * acos(-1.0))
    ));

    assert(approximatelyEqual(
        seriesReliability({1.0, 1.0}),
        1.0
    ));

    assert(approximatelyEqual(
        parallelReliability({0.0, 0.0}),
        0.0
    ));

    try {
        validateProbability(2.0, "invalid");
        assert(false);
    } catch (const invalid_argument&) {
        cout << "Invalid probability correctly rejected.\n";
    }

    try {
        conditionalProbability(0.1, 0.0);
        assert(false);
    } catch (const domain_error&) {
        cout << "Zero conditional denominator correctly rejected.\n";
    }

    cout << "All tests passed.\n";
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

int main() {
    try {
        cout << string(78, '=') << '\n';
        cout << "PROBABILITY BASICS: C++17 TECHNICAL CASE STUDY\n";
        cout << string(78, '=') << '\n';

        demonstrateFundamentals();
        demonstrateDistributions();

        cout << "\n";
        cout << string(78, '=') << '\n';
        cout << "BAYES AND TOTAL PROBABILITY\n";
        cout << string(78, '=') << '\n';

        double defectProbability =
            totalProbability(
                {0.02, 0.08},
                {0.70, 0.30}
            );

        double machineBGivenDefect =
            bayesTheorem(
                0.08,
                0.30,
                0.02
            );

        cout << "P(defect) = "
             << defectProbability
             << '\n';

        cout << "P(Machine B | defect) = "
             << machineBGivenDefect
             << '\n';

        QualityControlSystem qualityControl({
            {"Machine A", 0.70, 0.02},
            {"Machine B", 0.30, 0.08}
        });

        auto simulation =
            qualityControl.simulate(100000);

        printQualityControlReport(
            qualityControl,
            simulation
        );

        demonstratePortfolio();

        cout << "\n";
        cout << string(78, '=') << '\n';
        cout << "MONTE CARLO\n";
        cout << string(78, '=') << '\n';

        for (unsigned long long samples
             : {1000ULL, 10000ULL, 100000ULL}) {

            double estimate =
                estimatePi(samples);

            cout << "Samples: "
                 << setw(7) << samples
                 << ", pi estimate: "
                 << fixed
                 << setprecision(6)
                 << estimate
                 << ", absolute error: "
                 << fabs(estimate - acos(-1.0))
                 << '\n';
        }

        demonstratePerformance();
        runTests();

        cout << "\n";
        cout << string(78, '=') << '\n';
        cout << "PROGRAM COMPLETE\n";
        cout << string(78, '=') << '\n';

        return 0;
    }
    catch (const exception& error) {
        cerr << "Fatal error: "
             << error.what()
             << '\n';

        return 1;
    }
}
