"""
Probability Basics: From Fundamentals to Advanced Concepts

A self-contained study and demonstration program covering:
- Experiments, outcomes, sample spaces, and events
- Classical, empirical, and subjective probability
- Counting principles and combinatorics
- Complement, union, intersection, and conditional probability
- Independence and dependence
- Bayes' theorem and diagnostic testing
- Random variables and probability distributions
- Expected value, variance, covariance, and correlation
- Bernoulli, Binomial, Geometric, Negative Binomial, Hypergeometric,
  Poisson, Uniform, Exponential, and Normal distributions
- Law of total probability
- Law of large numbers and simulation
- Central limit theorem demonstration
- Monte Carlo estimation
- Reliability and risk calculations
- Markov-chain-style finite-state simulation
- Numerical stability and validation
- Common probability mistakes
- Basic testing and performance considerations

Run with:
    python probability_basics.py

The program intentionally uses only the Python standard library.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from dataclasses import dataclass
from itertools import combinations, permutations, product
from typing import Callable, Iterable, Sequence


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

EPSILON = 1e-12


def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def subsection(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78)


def approximately_equal(a: float, b: float, tolerance: float = 1e-9) -> bool:
    return math.isclose(a, b, rel_tol=tolerance, abs_tol=tolerance)


def validate_probability(value: float, name: str = "probability") -> float:
    """Probability must lie in the closed interval [0, 1]."""
    if not math.isfinite(value) or value < -EPSILON or value > 1 + EPSILON:
        raise ValueError(f"{name} must be between 0 and 1.")
    return min(1.0, max(0.0, value))


def safe_divide(numerator: float, denominator: float) -> float:
    """Explicitly handle the undefined case of division by zero."""
    if math.isclose(denominator, 0.0, abs_tol=EPSILON):
        raise ZeroDivisionError("Probability division is undefined for denominator 0.")
    return numerator / denominator


# ---------------------------------------------------------------------------
# 1. Fundamental probability concepts
# ---------------------------------------------------------------------------

def classical_probability(
    favorable_outcomes: int,
    total_outcomes: int,
) -> float:
    """
    Classical probability applies when elementary outcomes are equally likely.

    P(A) = number of favorable outcomes / number of possible outcomes
    """
    if total_outcomes <= 0:
        raise ValueError("total_outcomes must be positive.")
    if favorable_outcomes < 0 or favorable_outcomes > total_outcomes:
        raise ValueError("favorable_outcomes must be between 0 and total_outcomes.")
    return favorable_outcomes / total_outcomes


def empirical_probability(successes: int, trials: int) -> float:
    """Estimate probability from observed data."""
    if trials <= 0:
        raise ValueError("trials must be positive.")
    if successes < 0 or successes > trials:
        raise ValueError("successes must be between 0 and trials.")
    return successes / trials


def demonstrate_sample_spaces() -> None:
    subsection("Sample spaces and events")

    die = tuple(range(1, 7))
    even_event = {x for x in die if x % 2 == 0}
    greater_than_four = {x for x in die if x > 4}

    print("Die sample space:", die)
    print("Event E = even:", even_event)
    print("Event F = greater than 4:", greater_than_four)
    print("P(E):", classical_probability(len(even_event), len(die)))
    print("P(F):", classical_probability(len(greater_than_four), len(die)))

    # Set operations correspond directly to event operations.
    union = even_event | greater_than_four
    intersection = even_event & greater_than_four
    complement = set(die) - even_event

    print("E union F:", union)
    print("E intersection F:", intersection)
    print("Complement of E:", complement)

    # Addition rule:
    # P(E ∪ F) = P(E) + P(F) - P(E ∩ F)
    p_e = len(even_event) / len(die)
    p_f = len(greater_than_four) / len(die)
    p_intersection = len(intersection) / len(die)
    p_union = p_e + p_f - p_intersection

    print("Addition-rule result:", p_union)
    print("Direct enumeration:", len(union) / len(die))


# ---------------------------------------------------------------------------
# 2. Counting principles
# ---------------------------------------------------------------------------

def factorial(n: int) -> int:
    """n! counts permutations of n distinct objects."""
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative integer.")
    return math.factorial(n)


def permutations_count(n: int, r: int) -> int:
    """P(n, r) = n! / (n-r)!"""
    if not (isinstance(n, int) and isinstance(r, int)):
        raise TypeError("n and r must be integers.")
    if n < 0 or r < 0 or r > n:
        raise ValueError("Require n >= r >= 0.")
    return math.perm(n, r)


def combinations_count(n: int, r: int) -> int:
    """C(n, r) = n! / (r!(n-r)!)."""
    if not (isinstance(n, int) and isinstance(r, int)):
        raise TypeError("n and r must be integers.")
    if n < 0 or r < 0 or r > n:
        raise ValueError("Require n >= r >= 0.")
    return math.comb(n, r)


def demonstrate_counting() -> None:
    subsection("Counting principles")

    print("5! =", factorial(5))
    print("P(5, 2) =", permutations_count(5, 2))
    print("C(5, 2) =", combinations_count(5, 2))

    # Multiplication principle:
    # Three shirts and two trousers create 3 * 2 combinations.
    outfits = list(product(["shirt A", "shirt B", "shirt C"], ["trouser 1", "trouser 2"]))
    print("Number of outfits:", len(outfits))
    print("Outfits:", outfits)

    # Enumerating a small sample space is useful for verification.
    binary_sequences = list(product([0, 1], repeat=3))
    at_least_two_ones = [x for x in binary_sequences if sum(x) >= 2]

    print("Three binary trials:", binary_sequences)
    print("Sequences with at least two successes:", at_least_two_ones)
    print("Probability:", len(at_least_two_ones) / len(binary_sequences))


# ---------------------------------------------------------------------------
# 3. Conditional probability, independence, and Bayes' theorem
# ---------------------------------------------------------------------------

def conditional_probability(
    probability_of_a_and_b: float,
    probability_of_b: float,
) -> float:
    """
    P(A | B) = P(A ∩ B) / P(B).

    The condition B changes the reference population from the whole sample
    space to B.
    """
    validate_probability(probability_of_a_and_b, "P(A and B)")
    validate_probability(probability_of_b, "P(B)")
    return validate_probability(
        safe_divide(probability_of_a_and_b, probability_of_b),
        "P(A|B)",
    )


def are_independent(
    probability_a: float,
    probability_b: float,
    probability_a_and_b: float,
    tolerance: float = 1e-9,
) -> bool:
    """
    A and B are independent when:
        P(A ∩ B) = P(A)P(B)
    """
    validate_probability(probability_a, "P(A)")
    validate_probability(probability_b, "P(B)")
    validate_probability(probability_a_and_b, "P(A and B)")
    return approximately_equal(
        probability_a_and_b,
        probability_a * probability_b,
        tolerance,
    )


def bayes_theorem(
    p_b_given_a: float,
    p_a: float,
    p_b_given_not_a: float,
) -> float:
    """
    P(A|B) = P(B|A)P(A) /
             [P(B|A)P(A) + P(B|not A)P(not A)]
    """
    for value, name in (
        (p_b_given_a, "P(B|A)"),
        (p_a, "P(A)"),
        (p_b_given_not_a, "P(B|not A)"),
    ):
        validate_probability(value, name)

    p_not_a = 1 - p_a
    denominator = p_b_given_a * p_a + p_b_given_not_a * p_not_a
    return safe_divide(p_b_given_a * p_a, denominator)


def demonstrate_conditional_probability() -> None:
    subsection("Conditional probability and independence")

    # Two cards are drawn without replacement.
    # P(second card is an ace | first card is an ace) = 3/51.
    p_second_ace_given_first_ace = 3 / 51
    print(
        "P(second card is ace | first card is ace):",
        p_second_ace_given_first_ace,
    )

    p_ace_first = 4 / 52
    p_ace_second_and_first = (4 / 52) * (3 / 51)
    print("P(first and second are aces):", p_ace_second_and_first)

    # With replacement, the draws are independent.
    print(
        "With replacement, P(two aces):",
        (4 / 52) * (4 / 52),
    )

    p_a = 0.4
    p_b = 0.3
    p_a_and_b = p_a * p_b

    print(
        "Independence check:",
        are_independent(p_a, p_b, p_a_and_b),
    )

    # Diagnostic-test example:
    # Disease prevalence = 1%.
    # Sensitivity = P(positive | disease) = 99%.
    # False-positive rate = P(positive | no disease) = 5%.
    posterior = bayes_theorem(0.99, 0.01, 0.05)
    print("P(disease | positive test):", posterior)

    # Base-rate effects are often counterintuitive.
    print("Posterior percentage:", posterior * 100)


# ---------------------------------------------------------------------------
# 4. Total probability
# ---------------------------------------------------------------------------

def total_probability(
    conditional_probabilities: Sequence[float],
    prior_probabilities: Sequence[float],
) -> float:
    """P(B) = sum_i P(B|A_i)P(A_i)."""
    if len(conditional_probabilities) != len(prior_probabilities):
        raise ValueError("Both sequences must have equal length.")
    if not conditional_probabilities:
        raise ValueError("At least one partition element is required.")

    priors = [validate_probability(p, "prior") for p in prior_probabilities]
    conditionals = [
        validate_probability(p, "conditional probability")
        for p in conditional_probabilities
    ]

    if not approximately_equal(sum(priors), 1.0):
        raise ValueError("Prior probabilities must sum to 1.")

    return sum(p * q for p, q in zip(conditionals, priors))


# ---------------------------------------------------------------------------
# 5. Random variables and discrete distributions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiscreteDistribution:
    """A finite discrete probability distribution."""

    probabilities: dict[float, float]

    def __post_init__(self) -> None:
        if not self.probabilities:
            raise ValueError("Distribution cannot be empty.")

        total = 0.0
        for outcome, probability in self.probabilities.items():
            if not math.isfinite(float(outcome)):
                raise ValueError("Outcomes must be finite numbers.")
            validate_probability(probability, "probability")
            total += probability

        if not math.isclose(total, 1.0, abs_tol=1e-9):
            raise ValueError(f"Probabilities must sum to 1, got {total}.")

    def probability(self, outcome: float) -> float:
        return self.probabilities.get(outcome, 0.0)

    def expected_value(self) -> float:
        return sum(x * p for x, p in self.probabilities.items())

    def variance(self) -> float:
        mean = self.expected_value()
        return sum(((x - mean) ** 2) * p for x, p in self.probabilities.items())

    def standard_deviation(self) -> float:
        return math.sqrt(self.variance())

    def cdf(self, x: float) -> float:
        return sum(p for outcome, p in self.probabilities.items() if outcome <= x)

    def sample(self, rng: random.Random | None = None) -> float:
        generator = rng or random
        outcomes = list(self.probabilities)
        weights = list(self.probabilities.values())
        return generator.choices(outcomes, weights=weights, k=1)[0]


def bernoulli_pmf(x: int, p: float) -> float:
    validate_probability(p, "p")
    if x not in (0, 1):
        return 0.0
    return p if x == 1 else 1 - p


def binomial_pmf(k: int, n: int, p: float) -> float:
    validate_probability(p, "p")
    if n < 0 or not isinstance(n, int):
        raise ValueError("n must be a non-negative integer.")
    if k < 0 or k > n:
        return 0.0
    return math.comb(n, k) * p**k * (1 - p) ** (n - k)


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return sum(binomial_pmf(i, n, p) for i in range(k + 1))


def geometric_pmf(k: int, p: float) -> float:
    """
    Geometric convention used here:
    X = trial number of the first success, so X ∈ {1,2,...}.
    """
    validate_probability(p, "p")
    if p <= 0:
        raise ValueError("p must be positive for a geometric distribution.")
    if k < 1 or not isinstance(k, int):
        return 0.0
    return (1 - p) ** (k - 1) * p


def poisson_pmf(k: int, rate: float) -> float:
    """P(X=k) = e^-lambda lambda^k / k!."""
    if rate < 0 or not math.isfinite(rate):
        raise ValueError("rate must be a non-negative finite number.")
    if k < 0 or not isinstance(k, int):
        return 0.0
    return math.exp(-rate) * rate**k / math.factorial(k)


def hypergeometric_pmf(
    k: int,
    population_size: int,
    successes: int,
    draws: int,
) -> float:
    """
    Sampling without replacement.

    P(X=k) =
        C(K,k) C(N-K,n-k) / C(N,n)
    """
    if min(population_size, successes, draws) < 0:
        raise ValueError("Parameters cannot be negative.")
    if successes > population_size or draws > population_size:
        raise ValueError("Successes and draws cannot exceed population.")
    if k < max(0, draws - (population_size - successes)):
        return 0.0
    if k > min(draws, successes):
        return 0.0

    numerator = (
        combinations_count(successes, k)
        * combinations_count(population_size - successes, draws - k)
    )
    denominator = combinations_count(population_size, draws)
    return numerator / denominator


def demonstrate_discrete_distributions() -> None:
    subsection("Discrete distributions")

    fair_die = DiscreteDistribution({x: 1 / 6 for x in range(1, 7)})
    print("Fair die mean:", fair_die.expected_value())
    print("Fair die variance:", fair_die.variance())
    print("P(die <= 4):", fair_die.cdf(4))

    p = 0.6
    n = 10
    probability_exactly_six = binomial_pmf(6, n, p)
    probability_at_most_six = binomial_cdf(6, n, p)

    print("Binomial P(X=6):", probability_exactly_six)
    print("Binomial P(X<=6):", probability_at_most_six)

    print("Geometric P(first success on trial 4):", geometric_pmf(4, 0.25))
    print("Poisson P(X=3), lambda=2:", poisson_pmf(3, 2.0))

    # Finite population example:
    # 20 components contain 5 defective units.
    # Select 4 without replacement.
    print(
        "Hypergeometric P(exactly 1 defective):",
        hypergeometric_pmf(1, 20, 5, 4),
    )


# ---------------------------------------------------------------------------
# 6. Continuous distributions
# ---------------------------------------------------------------------------

def uniform_pdf(x: float, lower: float, upper: float) -> float:
    if upper <= lower:
        raise ValueError("upper must be greater than lower.")
    return 1 / (upper - lower) if lower <= x <= upper else 0.0


def uniform_cdf(x: float, lower: float, upper: float) -> float:
    if upper <= lower:
        raise ValueError("upper must be greater than lower.")
    if x < lower:
        return 0.0
    if x >= upper:
        return 1.0
    return (x - lower) / (upper - lower)


def exponential_pdf(x: float, rate: float) -> float:
    if rate <= 0:
        raise ValueError("rate must be positive.")
    return rate * math.exp(-rate * x) if x >= 0 else 0.0


def exponential_cdf(x: float, rate: float) -> float:
    if rate <= 0:
        raise ValueError("rate must be positive.")
    return 1 - math.exp(-rate * x) if x >= 0 else 0.0


def normal_pdf(x: float, mean: float = 0.0, standard_deviation: float = 1.0) -> float:
    if standard_deviation <= 0:
        raise ValueError("standard_deviation must be positive.")
    coefficient = 1 / (standard_deviation * math.sqrt(2 * math.pi))
    exponent = -0.5 * ((x - mean) / standard_deviation) ** 2
    return coefficient * math.exp(exponent)


def standard_normal_cdf(z: float) -> float:
    """CDF of N(0,1), using the error function available in the standard library."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def normal_cdf(
    x: float,
    mean: float = 0.0,
    standard_deviation: float = 1.0,
) -> float:
    if standard_deviation <= 0:
        raise ValueError("standard_deviation must be positive.")
    z = (x - mean) / standard_deviation
    return standard_normal_cdf(z)


def demonstrate_continuous_distributions() -> None:
    subsection("Continuous distributions")

    # A continuous variable has probability 0 at an exact point under an
    # ordinary continuous distribution. Probabilities are assigned to intervals.
    print("Uniform PDF at 0.5 on [0,1]:", uniform_pdf(0.5, 0, 1))
    print("Uniform P(X <= 0.25):", uniform_cdf(0.25, 0, 1))

    print("Exponential P(X <= 2), rate=0.5:", exponential_cdf(2, 0.5))
    print("Exponential PDF at x=2:", exponential_pdf(2, 0.5))

    print("Standard normal PDF at 0:", normal_pdf(0))
    print("P(Z <= 1.96):", standard_normal_cdf(1.96))

    # The familiar approximately 68-95-99.7 pattern follows from normal CDFs.
    for z in (1, 2, 3):
        central_probability = standard_normal_cdf(z) - standard_normal_cdf(-z)
        print(f"P(-{z} <= Z <= {z}): {central_probability:.6f}")


# ---------------------------------------------------------------------------
# 7. Moments: mean, variance, covariance, correlation
# ---------------------------------------------------------------------------

def weighted_mean(values: Sequence[float], probabilities: Sequence[float]) -> float:
    if len(values) != len(probabilities) or not values:
        raise ValueError("Values and probabilities must have equal non-zero length.")
    probabilities = [validate_probability(p) for p in probabilities]
    if not approximately_equal(sum(probabilities), 1.0):
        raise ValueError("Probabilities must sum to 1.")
    return sum(x * p for x, p in zip(values, probabilities))


def weighted_variance(
    values: Sequence[float],
    probabilities: Sequence[float],
) -> float:
    mean = weighted_mean(values, probabilities)
    return sum(p * (x - mean) ** 2 for x, p in zip(values, probabilities))


def covariance(
    x_values: Sequence[float],
    y_values: Sequence[float],
) -> float:
    if len(x_values) != len(y_values) or not x_values:
        raise ValueError("Sequences must have equal non-zero length.")
    mean_x = statistics.fmean(x_values)
    mean_y = statistics.fmean(y_values)
    return statistics.fmean(
        (x - mean_x) * (y - mean_y)
        for x, y in zip(x_values, y_values)
    )


def correlation(
    x_values: Sequence[float],
    y_values: Sequence[float],
) -> float:
    cov = covariance(x_values, y_values)
    std_x = statistics.pstdev(x_values)
    std_y = statistics.pstdev(y_values)

    if math.isclose(std_x * std_y, 0.0):
        raise ZeroDivisionError("Correlation is undefined for zero variance.")
    return cov / (std_x * std_y)


def demonstrate_moments() -> None:
    subsection("Expected value, variance, covariance, and correlation")

    values = [1, 2, 3, 4, 5, 6]
    probabilities = [1 / 6] * 6

    mean = weighted_mean(values, probabilities)
    variance = weighted_variance(values, probabilities)

    print("Die expected value:", mean)
    print("Die variance:", variance)
    print("Die standard deviation:", math.sqrt(variance))

    study_hours = [1, 2, 3, 4, 5]
    scores = [52, 59, 65, 73, 82]

    print("Population covariance:", covariance(study_hours, scores))
    print("Population correlation:", correlation(study_hours, scores))

    # Correlation measures linear association, not causation.
    print("Correlation is descriptive, not proof of causation.")


# ---------------------------------------------------------------------------
# 8. Simulation and Monte Carlo methods
# ---------------------------------------------------------------------------

def simulate_die_rolls(
    number_of_rolls: int,
    seed: int = 42,
) -> Counter[int]:
    if number_of_rolls <= 0:
        raise ValueError("number_of_rolls must be positive.")

    rng = random.Random(seed)
    counts: Counter[int] = Counter()

    for _ in range(number_of_rolls):
        counts[rng.randint(1, 6)] += 1

    return counts


def demonstrate_empirical_probability() -> None:
    subsection("Simulation and empirical probability")

    counts = simulate_die_rolls(100_000)
    total = sum(counts.values())

    for face in range(1, 7):
        estimate = counts[face] / total
        print(
            f"Face {face}: observed={counts[face]:6d}, "
            f"estimated P={estimate:.5f}, theoretical={1/6:.5f}"
        )


def monte_carlo_pi(
    samples: int,
    seed: int = 42,
) -> float:
    """
    Estimate pi by sampling points in the unit square.

    A quarter-circle of radius 1 occupies pi/4 of the square,
    so pi ≈ 4 * fraction_inside.
    """
    if samples <= 0:
        raise ValueError("samples must be positive.")

    rng = random.Random(seed)
    inside = 0

    for _ in range(samples):
        x = rng.random()
        y = rng.random()

        if x * x + y * y <= 1:
            inside += 1

    return 4 * inside / samples


# ---------------------------------------------------------------------------
# 9. Law of large numbers
# ---------------------------------------------------------------------------

def law_of_large_numbers_demo(
    sample_sizes: Sequence[int],
    seed: int = 42,
) -> list[tuple[int, float]]:
    rng = random.Random(seed)
    running_total = 0
    results: list[tuple[int, float]] = []
    target = 1 / 6

    max_size = max(sample_sizes)

    requested = set(sample_sizes)

    for i in range(1, max_size + 1):
        running_total += rng.randint(1, 6)
        if i in requested:
            sample_mean = running_total / i
            results.append((i, sample_mean - 3.5))

    # Difference from the theoretical mean tends to become smaller in a
    # broad long-run sense, but individual paths can fluctuate.
    return results


# ---------------------------------------------------------------------------
# 10. Central Limit Theorem
# ---------------------------------------------------------------------------

def central_limit_demo(
    population: Sequence[float],
    sample_size: int,
    number_of_samples: int,
    seed: int = 42,
) -> dict[str, float]:
    """
    Draw many independent samples and inspect their sample means.

    For sufficiently large sample sizes, the distribution of sample means
    approaches a normal shape under broad conditions.
    """
    if not population:
        raise ValueError("population cannot be empty.")
    if sample_size <= 0 or number_of_samples <= 0:
        raise ValueError("sample_size and number_of_samples must be positive.")

    rng = random.Random(seed)
    means = [
        statistics.fmean(rng.choices(population, k=sample_size))
        for _ in range(number_of_samples)
    ]

    return {
        "mean_of_sample_means": statistics.fmean(means),
        "standard_deviation_of_sample_means": statistics.pstdev(means),
        "population_mean": statistics.fmean(population),
        "population_standard_deviation": statistics.pstdev(population),
        "theoretical_standard_error":
            statistics.pstdev(population) / math.sqrt(sample_size),
    }


# ---------------------------------------------------------------------------
# 11. Conditional simulation
# ---------------------------------------------------------------------------

def simulate_two_stage_process(
    trials: int,
    seed: int = 42,
) -> dict[str, float]:
    """
    Example of conditional probability:

    Stage 1 chooses a machine:
        Machine A with probability 0.7
        Machine B with probability 0.3

    Defect probabilities:
        A: 2%
        B: 8%

    The simulation estimates P(defect), while Bayes gives
    P(machine B | defect).
    """
    if trials <= 0:
        raise ValueError("trials must be positive.")

    rng = random.Random(seed)
    defects = 0
    defects_from_b = 0

    for _ in range(trials):
        machine_b = rng.random() < 0.30
        defect = rng.random() < (0.08 if machine_b else 0.02)

        if defect:
            defects += 1
            if machine_b:
                defects_from_b += 1

    estimated_defect_probability = defects / trials
    estimated_b_given_defect = (
        defects_from_b / defects if defects else float("nan")
    )

    theoretical_defect_probability = total_probability(
        [0.02, 0.08],
        [0.70, 0.30],
    )

    theoretical_b_given_defect = bayes_theorem(
        p_b_given_a=0.08,
        p_a=0.30,
        p_b_given_not_a=0.02,
    )

    return {
        "estimated_defect_probability": estimated_defect_probability,
        "theoretical_defect_probability": theoretical_defect_probability,
        "estimated_machine_b_given_defect": estimated_b_given_defect,
        "theoretical_machine_b_given_defect": theoretical_b_given_defect,
    }


# ---------------------------------------------------------------------------
# 12. Reliability and risk
# ---------------------------------------------------------------------------

def series_system_reliability(component_reliabilities: Sequence[float]) -> float:
    """
    In a series system, every component must work.

    Under independence:
        P(system works) = product(P(component works))
    """
    if not component_reliabilities:
        raise ValueError("At least one component is required.")

    result = 1.0
    for reliability in component_reliabilities:
        result *= validate_probability(reliability, "reliability")

    return result


def parallel_system_reliability(component_reliabilities: Sequence[float]) -> float:
    """
    In a parallel system, at least one component must work.

    Under independence:
        P(system works) = 1 - product(P(component fails))
    """
    if not component_reliabilities:
        raise ValueError("At least one component is required.")

    probability_all_fail = 1.0

    for reliability in component_reliabilities:
        probability_all_fail *= 1 - validate_probability(
            reliability,
            "reliability",
        )

    return 1 - probability_all_fail


def demonstrate_reliability() -> None:
    subsection("Reliability and risk")

    components = [0.99, 0.98, 0.995]

    print("Series reliability:", series_system_reliability(components))
    print("Parallel reliability:", parallel_system_reliability(components))

    # Independence is an assumption. Shared power, software, environment,
    # manufacturing defects, and common-cause failures can violate it.
    print("Series systems amplify component failure risk.")
    print("Parallel systems can provide redundancy under independence assumptions.")


# ---------------------------------------------------------------------------
# 13. Markov process demonstration
# ---------------------------------------------------------------------------

@dataclass
class MarkovChain:
    states: tuple[str, ...]
    transition_matrix: tuple[tuple[float, ...], ...]

    def __post_init__(self) -> None:
        n = len(self.states)

        if n == 0:
            raise ValueError("At least one state is required.")

        if len(self.transition_matrix) != n:
            raise ValueError("Transition matrix must have one row per state.")

        for row in self.transition_matrix:
            if len(row) != n:
                raise ValueError("Transition matrix must be square.")
            for probability in row:
                validate_probability(probability)

            if not approximately_equal(sum(row), 1.0):
                raise ValueError("Each transition row must sum to 1.")

    def next_state(
        self,
        current_state: str,
        rng: random.Random,
    ) -> str:
        if current_state not in self.states:
            raise ValueError(f"Unknown state: {current_state}")

        index = self.states.index(current_state)
        next_value = rng.choices(
            self.states,
            weights=self.transition_matrix[index],
            k=1,
        )[0]

        return next_value

    def simulate(
        self,
        initial_state: str,
        steps: int,
        seed: int = 42,
    ) -> list[str]:
        if steps < 0:
            raise ValueError("steps cannot be negative.")

        rng = random.Random(seed)
        current = initial_state
        path = [current]

        for _ in range(steps):
            current = self.next_state(current, rng)
            path.append(current)

        return path


def demonstrate_markov_chain() -> None:
    subsection("A finite-state Markov process")

    chain = MarkovChain(
        states=("Low", "Medium", "High"),
        transition_matrix=(
            (0.70, 0.25, 0.05),
            (0.20, 0.60, 0.20),
            (0.05, 0.25, 0.70),
        ),
    )

    path = chain.simulate("Medium", 15)
    print("Simulated state path:")
    print(" -> ".join(path))

    # The Markov property says that the next state depends on the current
    # state according to the transition mechanism, rather than requiring the
    # complete historical path.
    print("Number of simulated states:", len(path))


# ---------------------------------------------------------------------------
# 14. Sampling without replacement
# ---------------------------------------------------------------------------

def compare_sampling_models() -> None:
    subsection("With replacement versus without replacement")

    population = ["A", "B", "C", "D"]

    # With replacement: each draw restores the same population.
    with_replacement = list(product(population, repeat=2))
    same_with_replacement = [
        pair for pair in with_replacement if pair[0] == pair[1]
    ]

    # Without replacement: repeated outcomes are impossible.
    without_replacement = list(permutations(population, 2))
    same_without_replacement = [
        pair for pair in without_replacement if pair[0] == pair[1]
    ]

    print("With replacement outcomes:", len(with_replacement))
    print("Same item twice:", len(same_with_replacement))
    print("Without replacement outcomes:", len(without_replacement))
    print("Same item twice:", len(same_without_replacement))


# ---------------------------------------------------------------------------
# 15. Probability inequalities and bounds
# ---------------------------------------------------------------------------

def markov_bound_nonnegative(expected_value: float, threshold: float) -> float:
    """
    Markov's inequality:
        P(X >= a) <= E[X] / a
    for X >= 0 and a > 0.
    """
    if expected_value < 0:
        raise ValueError("Expected value must be non-negative.")
    if threshold <= 0:
        raise ValueError("threshold must be positive.")
    return min(1.0, expected_value / threshold)


def chebyshev_bound(
    variance: float,
    distance: float,
) -> float:
    """
    Chebyshev:
        P(|X-mu| >= k) <= variance / k^2
    """
    if variance < 0:
        raise ValueError("variance cannot be negative.")
    if distance <= 0:
        raise ValueError("distance must be positive.")
    return min(1.0, variance / (distance**2))


def demonstrate_bounds() -> None:
    subsection("Probability bounds")

    print("Markov bound:", markov_bound_nonnegative(10, 25))
    print("Chebyshev bound:", chebyshev_bound(16, 8))

    # Bounds can be loose. Their value is that they do not require the full
    # probability distribution.
    print("Bounds can remain valid even when the exact distribution is unknown.")


# ---------------------------------------------------------------------------
# 16. Numerical and conceptual edge cases
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    subsection("Edge cases and common mistakes")

    # Certain events and impossible events.
    print("Certain-event probability:", classical_probability(6, 6))
    print("Impossible-event probability:", classical_probability(0, 6))

    # Complement rule:
    p_event = 0.27
    print("P(not A) when P(A)=0.27:", 1 - p_event)

    # The probability of A or B is NOT always P(A)+P(B).
    p_a = 0.5
    p_b = 0.5
    p_overlap = 0.25
    print("Correct P(A union B):", p_a + p_b - p_overlap)

    # Floating-point arithmetic can introduce tiny errors.
    probability_sum = 0.1 + 0.2 + 0.7
    print("Floating-point probability sum:", probability_sum)
    print("Validated approximately:", approximately_equal(probability_sum, 1.0))

    # Continuous distributions:
    # P(X = exact_point) is 0 for ordinary continuous distributions.
    print("Normal PDF at x=0:", normal_pdf(0))
    print("Normal interval probability is obtained using CDF differences.")


# ---------------------------------------------------------------------------
# 17. Testing probability functions
# ---------------------------------------------------------------------------

def run_tests() -> None:
    subsection("Self-tests")

    assert approximately_equal(classical_probability(1, 6), 1 / 6)
    assert combinations_count(5, 2) == 10
    assert permutations_count(5, 2) == 20
    assert approximately_equal(
        binomial_pmf(0, 10, 0.5),
        1 / 1024,
    )
    assert approximately_equal(
        sum(binomial_pmf(k, 10, 0.5) for k in range(11)),
        1.0,
    )
    assert approximately_equal(
        sum(poisson_pmf(k, 3) for k in range(30)),
        1.0,
        tolerance=1e-8,
    )
    assert approximately_equal(
        normal_cdf(0),
        0.5,
    )
    assert approximately_equal(
        standard_normal_cdf(1.96),
        0.9750021048517795,
        tolerance=1e-10,
    )
    assert approximately_equal(
        series_system_reliability([1, 1, 1]),
        1,
    )
    assert approximately_equal(
        parallel_system_reliability([0, 0]),
        0,
    )

    try:
        validate_probability(1.5)
        raise AssertionError("Invalid probability was accepted.")
    except ValueError:
        pass

    try:
        conditional_probability(0.2, 0)
        raise AssertionError("Zero denominator was accepted.")
    except ZeroDivisionError:
        pass

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# 18. Advanced worked example: portfolio loss probability
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RiskPosition:
    name: str
    probability_of_loss: float
    loss_amount: float

    def __post_init__(self) -> None:
        validate_probability(self.probability_of_loss, "probability_of_loss")
        if self.loss_amount < 0:
            raise ValueError("loss_amount cannot be negative.")


def portfolio_loss_distribution(
    positions: Sequence[RiskPosition],
) -> dict[float, float]:
    """
    Exact distribution for independent binary loss positions.

    Each position either loses its stated amount or loses zero.
    The number of positions is kept small so exact enumeration remains
    understandable.
    """
    if not positions:
        raise ValueError("At least one position is required.")

    distribution: dict[float, float] = {0.0: 1.0}

    for position in positions:
        next_distribution: dict[float, float] = {}

        for current_loss, current_probability in distribution.items():
            no_loss_probability = current_probability * (
                1 - position.probability_of_loss
            )
            loss_probability = current_probability * position.probability_of_loss

            next_distribution[current_loss] = (
                next_distribution.get(current_loss, 0.0)
                + no_loss_probability
            )

            new_loss = current_loss + position.loss_amount
            next_distribution[new_loss] = (
                next_distribution.get(new_loss, 0.0)
                + loss_probability
            )

        distribution = next_distribution

    return distribution


def demonstrate_portfolio_risk() -> None:
    subsection("Advanced worked example: independent loss positions")

    positions = [
        RiskPosition("A", 0.10, 1000),
        RiskPosition("B", 0.20, 2000),
        RiskPosition("C", 0.05, 5000),
    ]

    distribution = portfolio_loss_distribution(positions)

    expected_loss = sum(loss * probability for loss, probability in distribution.items())
    variance = sum(
        ((loss - expected_loss) ** 2) * probability
        for loss, probability in distribution.items()
    )

    probability_loss_at_least_3000 = sum(
        probability
        for loss, probability in distribution.items()
        if loss >= 3000
    )

    print("Exact loss distribution:")
    for loss, probability in sorted(distribution.items()):
        print(f"  Loss={loss:7.0f}: P={probability:.6f}")

    print("Expected loss:", expected_loss)
    print("Loss variance:", variance)
    print("P(loss >= 3000):", probability_loss_at_least_3000)

    # The calculation assumes independence. Correlated risks require a model
    # that represents dependence rather than multiplying independent terms.


# ---------------------------------------------------------------------------
# 19. Performance considerations
# ---------------------------------------------------------------------------

def benchmark_counting_methods() -> None:
    subsection("Performance considerations")

    # Direct combinations use optimized arithmetic rather than constructing
    # every subset. Enumerating all subsets is exponential and becomes
    # infeasible rapidly.
    n = 100
    r = 50
    count = combinations_count(n, r)

    print(f"C({n}, {r}) has {len(str(count))} decimal digits.")
    print(
        "Direct combinatorial calculation avoids enumerating "
        f"{count:,} individual subsets."
    )

    print("Rule of thumb: avoid sample-space enumeration when its size explodes.")


# ---------------------------------------------------------------------------
# 20. Main study program
# ---------------------------------------------------------------------------

def main() -> None:
    section("Probability Basics: Complete Python Study Program")

    print(
        "Probability quantifies uncertainty using numbers between 0 and 1.\n"
        "A probability of 0 represents impossibility, while 1 represents\n"
        "certainty. Real probability models depend on assumptions about\n"
        "outcomes, dependence, sampling, and the mechanism generating data."
    )

    demonstrate_sample_spaces()
    demonstrate_counting()
    demonstrate_conditional_probability()

    subsection("Law of total probability")
    result = total_probability(
        conditional_probabilities=[0.02, 0.08],
        prior_probabilities=[0.70, 0.30],
    )
    print("P(defect) from total probability:", result)

    demonstrate_discrete_distributions()
    demonstrate_continuous_distributions()
    demonstrate_moments()
    demonstrate_empirical_probability()

    subsection("Monte Carlo estimation")
    for samples in (1_000, 10_000, 100_000):
        estimate = monte_carlo_pi(samples)
        print(
            f"samples={samples:>7}: pi≈{estimate:.6f}, "
            f"absolute error={abs(estimate - math.pi):.6f}"
        )

    subsection("Law of large numbers")
    for sample_size, error in law_of_large_numbers_demo(
        [10, 100, 1_000, 10_000, 100_000]
    ):
        print(
            f"n={sample_size:>6}: sample-mean error from die mean = {error:+.6f}"
        )

    subsection("Central limit theorem")
    clt = central_limit_demo(
        population=[1, 2, 3, 4, 5, 6],
        sample_size=30,
        number_of_samples=10_000,
    )
    for key, value in clt.items():
        print(f"{key}: {value:.8f}")

    subsection("Conditional simulation")
    simulation = simulate_two_stage_process(100_000)
    for key, value in simulation.items():
        print(f"{key}: {value:.8f}")

    demonstrate_reliability()
    demonstrate_markov_chain()
    compare_sampling_models()
    demonstrate_bounds()
    demonstrate_edge_cases()
    demonstrate_portfolio_risk()
    benchmark_counting_methods()
    run_tests()

    section("Key formulas demonstrated")

    formulas = {
        "Complement": "P(Aᶜ) = 1 - P(A)",
        "Union": "P(A ∪ B) = P(A) + P(B) - P(A ∩ B)",
        "Conditional": "P(A|B) = P(A ∩ B) / P(B)",
        "Independence": "P(A ∩ B) = P(A)P(B)",
        "Bayes": "P(A|B) = P(B|A)P(A) / P(B)",
        "Expectation": "E[X] = Σ x p(x)",
        "Variance": "Var(X) = E[(X - μ)²]",
        "Covariance": "Cov(X,Y) = E[(X-μX)(Y-μY)]",
        "Standard error": "SE(mean) = σ / √n",
        "Markov": "P(X ≥ a) ≤ E[X]/a for X ≥ 0",
        "Chebyshev": "P(|X-μ| ≥ k) ≤ σ²/k²",
    }

    for name, formula in formulas.items():
        print(f"{name:>15}: {formula}")

    section("End of program")
    print(
        "The examples use exact formulas where practical and simulation where\n"
        "simulation helps connect theoretical probability with observed data."
    )


if __name__ == "__main__":
    main()
