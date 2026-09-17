"""
Combinations and Permutations
==============================

A self-contained study and executable demonstration of permutations,
combinations, counting principles, probability, algorithms, edge cases,
and practical applications.

The script progresses from elementary counting to exact arithmetic,
generators, constrained arrangements, multiset permutations, dynamic
programming, ranking/unranking, and performance considerations.

No external packages are required.
"""

from __future__ import annotations

from collections import Counter
from fractions import Fraction
from itertools import combinations as itertools_combinations
from itertools import permutations as itertools_permutations
from math import comb, factorial, gcd
from typing import Iterable, Iterator, Sequence, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# 1. Basic vocabulary
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_fundamentals() -> None:
    print_section("1. Fundamentals")

    print(
        """
Permutation:
    An arrangement in which order matters.

Combination:
    A selection in which order does not matter.

Factorial:
    n! = n × (n-1) × ... × 2 × 1.
    By convention, 0! = 1.

Multiplication principle:
    If one choice can be made in a ways and a second independent choice
    can be made in b ways, there are a × b combined possibilities.

Addition principle:
    If mutually exclusive alternatives contain a and b possibilities,
    there are a + b possibilities.

Examples:
    PIN of 3 distinct digits: 10 × 10 × 10 = 1000 if repetition is allowed.
    Arrange 3 distinct objects: 3! = 6.
    Select 2 objects from 5: C(5, 2) = 10.
"""
    )


# ---------------------------------------------------------------------------
# 2. Factorials and exact arithmetic
# ---------------------------------------------------------------------------

def factorial_manual(n: int) -> int:
    """Compute n! without using math.factorial."""
    if not isinstance(n, int):
        raise TypeError("n must be an integer")
    if n < 0:
        raise ValueError("factorial is defined only for n >= 0")

    result = 1
    for value in range(2, n + 1):
        result *= value
    return result


def demonstrate_factorials() -> None:
    print_section("2. Factorials")

    for n in range(0, 8):
        print(f"{n}! = {factorial_manual(n)}")

    assert factorial_manual(0) == 1
    assert factorial_manual(5) == factorial(5)

    print("0! =", factorial_manual(0))
    print("10! =", factorial_manual(10))


# ---------------------------------------------------------------------------
# 3. Permutation formulas
# ---------------------------------------------------------------------------

def permutation_count(n: int, r: int) -> int:
    """
    Number of ordered selections of r distinct objects from n objects.

    P(n, r) = n! / (n-r)!
    """
    validate_n_r(n, r)

    result = 1
    for value in range(n - r + 1, n + 1):
        result *= value
    return result


def permutation_count_factorial(n: int, r: int) -> int:
    validate_n_r(n, r)
    return factorial(n) // factorial(n - r)


def validate_n_r(n: int, r: int) -> None:
    if not isinstance(n, int) or not isinstance(r, int):
        raise TypeError("n and r must be integers")
    if n < 0:
        raise ValueError("n must be non-negative")
    if r < 0 or r > n:
        raise ValueError("r must satisfy 0 <= r <= n")


def demonstrate_permutations() -> None:
    print_section("3. Permutations")

    examples = [(5, 2), (5, 3), (5, 5), (10, 3)]
    for n, r in examples:
        print(f"P({n}, {r}) = {permutation_count(n, r)}")

    print(
        """
Why does order matter?

For 5 people choosing a president and a vice-president:
    5 choices for president
    4 remaining choices for vice-president
    total = 5 × 4 = 20

The pair (Alice, Bob) is different from (Bob, Alice).
"""
    )

    assert permutation_count(5, 2) == 20
    assert permutation_count(5, 5) == factorial(5)


# ---------------------------------------------------------------------------
# 4. Permutations with repetition
# ---------------------------------------------------------------------------

def permutation_with_repetition(n: int, r: int) -> int:
    """
    Ordered selection of length r from n types when repetition is allowed.

    Number = n^r.
    """
    if not isinstance(n, int) or not isinstance(r, int):
        raise TypeError("n and r must be integers")
    if n < 0 or r < 0:
        raise ValueError("n and r must be non-negative")
    return n ** r


def demonstrate_repetition() -> None:
    print_section("4. Permutations with repetition")

    print("4-digit PIN using digits 0-9:", permutation_with_repetition(10, 4))
    print("3-character code using 26 letters:", permutation_with_repetition(26, 3))

    print(
        """
Repeated values change the counting rule.

If repetition is permitted:
    n choices are available at each of r positions.
    Count = n^r.

If repetition is forbidden:
    available choices decrease after each selection.
    Count = P(n, r).
"""
    )


# ---------------------------------------------------------------------------
# 5. Combination formulas
# ---------------------------------------------------------------------------

def combination_count(n: int, r: int) -> int:
    """
    Number of unordered selections of r objects from n objects.

    C(n, r) = n! / (r! (n-r)!).

    The multiplicative form avoids constructing three large factorials.
    """
    validate_n_r(n, r)

    # C(n, r) = C(n, n-r), so use the smaller side.
    r = min(r, n - r)

    result = 1
    for i in range(1, r + 1):
        result = result * (n - r + i) // i

    return result


def demonstrate_combinations() -> None:
    print_section("5. Combinations")

    examples = [(5, 2), (5, 3), (10, 4), (52, 5)]
    for n, r in examples:
        print(f"C({n}, {r}) = {combination_count(n, r)}")

    print(
        """
Why does order not matter?

Selecting Alice and Bob as a committee is the same committee as
selecting Bob and Alice.

The permutation count P(n,r) counts every group r! times because the
same selected objects can be arranged in r! orders.

Therefore:
    C(n,r) = P(n,r) / r!
           = n! / (r!(n-r)!).
"""
    )

    assert combination_count(5, 2) == 10
    assert combination_count(10, 4) == comb(10, 4)
    assert combination_count(5, 2) == combination_count(5, 3)


# ---------------------------------------------------------------------------
# 6. Relationship between combinations and permutations
# ---------------------------------------------------------------------------

def demonstrate_relationship() -> None:
    print_section("6. Relationship between permutations and combinations")

    n, r = 8, 3
    permutations = permutation_count(n, r)
    combinations = combination_count(n, r)

    print("n =", n, "r =", r)
    print("P(n,r) =", permutations)
    print("C(n,r) =", combinations)
    print("P(n,r) / r! =", permutations // factorial(r))

    assert permutations == combinations * factorial(r)


# ---------------------------------------------------------------------------
# 7. Enumerating actual permutations and combinations
# ---------------------------------------------------------------------------

def generate_permutations(items: Sequence[T], r: int | None = None) -> Iterator[tuple[T, ...]]:
    """
    Generate ordered selections without replacement.

    This recursive implementation is intentionally explicit so that the
    counting formula can be connected to the actual enumeration algorithm.
    """
    if r is None:
        r = len(items)

    if r < 0 or r > len(items):
        raise ValueError("r must satisfy 0 <= r <= len(items)")

    used = [False] * len(items)
    current: list[T] = []

    def backtrack() -> Iterator[tuple[T, ...]]:
        if len(current) == r:
            yield tuple(current)
            return

        for index, item in enumerate(items):
            if used[index]:
                continue

            used[index] = True
            current.append(item)

            yield from backtrack()

            current.pop()
            used[index] = False

    yield from backtrack()


def generate_combinations(items: Sequence[T], r: int) -> Iterator[tuple[T, ...]]:
    """Generate unordered selections without replacement."""
    if r < 0 or r > len(items):
        raise ValueError("r must satisfy 0 <= r <= len(items)")

    current: list[T] = []

    def backtrack(start: int) -> Iterator[tuple[T, ...]]:
        if len(current) == r:
            yield tuple(current)
            return

        remaining_needed = r - len(current)

        for index in range(start, len(items) - remaining_needed + 1):
            current.append(items[index])
            yield from backtrack(index + 1)
            current.pop()

    yield from backtrack(0)


def demonstrate_enumeration() -> None:
    print_section("7. Enumerating arrangements and selections")

    items = ["A", "B", "C"]

    print("Permutations:")
    for arrangement in generate_permutations(items):
        print(" ", arrangement)

    print("Combinations of size 2:")
    for selection in generate_combinations(items, 2):
        print(" ", selection)

    assert sum(1 for _ in generate_permutations(items)) == factorial(3)
    assert sum(1 for _ in generate_combinations(items, 2)) == 3


# ---------------------------------------------------------------------------
# 8. Built-in itertools comparison
# ---------------------------------------------------------------------------

def demonstrate_itertools() -> None:
    print_section("8. Python itertools")

    items = ["A", "B", "C"]

    print("itertools.permutations:")
    print(list(itertools_permutations(items, 2)))

    print("itertools.combinations:")
    print(list(itertools_combinations(items, 2)))

    print(
        """
itertools is usually preferable in production when you need enumeration.
It provides efficient iterators and avoids storing the entire result set.

A major distinction is:
    list(permutations(...)) -> materializes every result.
    permutations(...)       -> produces results lazily.
"""
    )


# ---------------------------------------------------------------------------
# 9. Repeated objects and multiset permutations
# ---------------------------------------------------------------------------

def multiset_permutation_count(items: Iterable[T]) -> int:
    """
    Number of distinct permutations of a multiset.

    If n objects contain frequencies n1, n2, ..., nk:
        n! / (n1! n2! ... nk!)
    """
    counts = Counter(items)
    total = sum(counts.values())

    result = factorial(total)
    for frequency in counts.values():
        result //= factorial(frequency)

    return result


def generate_unique_permutations(items: Sequence[T]) -> Iterator[tuple[T, ...]]:
    """Generate each distinct permutation once, even when values repeat."""
    counts = Counter(items)
    current: list[T] = []
    total = len(items)

    def backtrack() -> Iterator[tuple[T, ...]]:
        if len(current) == total:
            yield tuple(current)
            return

        for item in sorted(counts, key=repr):
            if counts[item] == 0:
                continue

            counts[item] -= 1
            current.append(item)

            yield from backtrack()

            current.pop()
            counts[item] += 1

    yield from backtrack()


def demonstrate_multisets() -> None:
    print_section("9. Repeated objects and multiset permutations")

    word = "LEVEL"
    print(f"Distinct permutations of {word}:",
          multiset_permutation_count(word))

    unique = list(generate_unique_permutations(word))
    print("Enumerated count:", len(unique))
    print("First five:", unique[:5])

    print(
        """
For LEVEL:
    total characters = 5
    L appears twice
    E appears twice
    V appears once

Distinct arrangements:
    5! / (2! × 2! × 1!) = 30

Dividing by duplicate factorials removes arrangements that differ only
because identical objects were swapped.
"""
    )


# ---------------------------------------------------------------------------
# 10. Circular permutations
# ---------------------------------------------------------------------------

def circular_permutation_count(n: int) -> int:
    """
    Arrangements of n distinct objects around a circle when rotations
    are considered equivalent.

    Count = (n-1)!.
    """
    if not isinstance(n, int):
        raise TypeError("n must be an integer")
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 1
    return factorial(n - 1)


def demonstrate_circular_permutations() -> None:
    print_section("10. Circular permutations")

    for n in range(1, 6):
        print(f"{n} distinct people around a circle: {circular_permutation_count(n)}")

    print(
        """
For a line, n distinct people have n! arrangements.

For a circle, rotations do not create a new arrangement. Fix one person
as an anchor and arrange the remaining n-1 people:
    (n-1)!
"""
    )


# ---------------------------------------------------------------------------
# 11. Permutations with restrictions
# ---------------------------------------------------------------------------

def count_binary_strings(length: int, ones: int) -> int:
    """
    Binary strings with exactly `ones` occurrences of 1.

    Choose which positions contain 1:
        C(length, ones)
    """
    if length < 0 or ones < 0 or ones > length:
        raise ValueError("invalid length or number of ones")
    return combination_count(length, ones)


def count_strings_without_adjacent_ones(length: int, ones: int) -> int:
    """
    Binary strings of given length containing exactly `ones` ones,
    with no two ones adjacent.

    Place the ones into the gaps around zeros:
        C(length - ones + 1, ones)
    """
    if length < 0 or ones < 0:
        raise ValueError("invalid arguments")
    if ones > length - ones + 1:
        return 0
    return combination_count(length - ones + 1, ones)


def demonstrate_restricted_counting() -> None:
    print_section("11. Restricted arrangements")

    print("Binary strings of length 6 with exactly 3 ones:",
          count_binary_strings(6, 3))

    print("Binary strings of length 6 with exactly 3 non-adjacent ones:",
          count_strings_without_adjacent_ones(6, 3))

    print(
        """
Restrictions often require changing the model rather than blindly
applying n! or C(n,r).

For non-adjacent ones, first place the zeros. The available gaps around
the zeros become positions where ones can be inserted.
"""
    )


# ---------------------------------------------------------------------------
# 12. Inclusion-exclusion example
# ---------------------------------------------------------------------------

def count_permutations_with_fixed_points(n: int) -> int:
    """
    Number of derangements, where no element remains in its original
    position.

    D(n) = n! * sum((-1)^k / k!, k=0..n)
    computed exactly using integer inclusion-exclusion.
    """
    if n < 0:
        raise ValueError("n must be non-negative")

    total = 0
    for k in range(n + 1):
        term = combination_count(n, k) * factorial(n - k)
        total += term if k % 2 == 0 else -term

    return total


def demonstrate_derangements() -> None:
    print_section("12. Derangements and inclusion-exclusion")

    for n in range(1, 8):
        print(f"D({n}) =", count_permutations_with_fixed_points(n))

    print(
        """
A derangement is a permutation in which no item occupies its original
position.

For each position, define an event that the corresponding item stays
fixed. Inclusion-exclusion alternately adds and subtracts arrangements
having specified fixed positions.

D(n) = n! - C(n,1)(n-1)! + C(n,2)(n-2)! - ...

The exact integer implementation avoids floating-point rounding.
"""
    )


# ---------------------------------------------------------------------------
# 13. Pascal's triangle
# ---------------------------------------------------------------------------

def pascal_triangle(rows: int) -> list[list[int]]:
    if rows < 0:
        raise ValueError("rows must be non-negative")

    triangle: list[list[int]] = []

    for row_index in range(rows):
        row = [combination_count(row_index, k) for k in range(row_index + 1)]
        triangle.append(row)

    return triangle


def demonstrate_pascal() -> None:
    print_section("13. Pascal's triangle")

    for row in pascal_triangle(7):
        print(row)

    print(
        """
Each entry satisfies Pascal's identity:

    C(n,r) = C(n-1,r-1) + C(n-1,r)

Interpretation:
A selection either contains a particular final object or it does not.
"""
    )


# ---------------------------------------------------------------------------
# 14. Binomial theorem
# ---------------------------------------------------------------------------

def binomial_coefficients(n: int) -> list[int]:
    return [combination_count(n, r) for r in range(n + 1)]


def demonstrate_binomial_theorem() -> None:
    print_section("14. Binomial theorem")

    n = 5
    coefficients = binomial_coefficients(n)
    print(f"Coefficients of (x + y)^{n}:", coefficients)

    print(
        """
The binomial theorem states:

    (x + y)^n = sum(C(n,r) x^(n-r) y^r)

The coefficients are exactly the combinations C(n,r).
"""
    )


# ---------------------------------------------------------------------------
# 15. Probability using combinations
# ---------------------------------------------------------------------------

def hypergeometric_probability(
    population_size: int,
    success_population: int,
    sample_size: int,
    required_successes: int,
) -> Fraction:
    """
    Probability of exactly k successes when sampling without replacement.

    P(X=k) =
        C(K,k) C(N-K,n-k) / C(N,n)
    """
    N = population_size
    K = success_population
    n = sample_size
    k = required_successes

    if not all(isinstance(value, int) for value in (N, K, n, k)):
        raise TypeError("all arguments must be integers")

    if N < 0 or K < 0 or K > N:
        raise ValueError("invalid population parameters")

    if n < 0 or n > N:
        raise ValueError("invalid sample size")

    if k < 0 or k > K or n - k < 0 or n - k > N - K:
        return Fraction(0, 1)

    favorable = combination_count(K, k) * combination_count(N - K, n - k)
    total = combination_count(N, n)

    return Fraction(favorable, total)


def demonstrate_probability() -> None:
    print_section("15. Probability and combinations")

    probability = hypergeometric_probability(
        population_size=52,
        success_population=13,
        sample_size=5,
        required_successes=2,
    )

    print("Probability of exactly two hearts in a five-card hand:")
    print(probability)
    print(float(probability))

    print(
        """
Combinations are central to probability when the sample space consists
of unordered selections.

For a five-card hand:
    total hands = C(52,5)

For exactly two hearts:
    favorable hands = C(13,2) × C(39,3)

The probability is favorable / total.
"""
    )


# ---------------------------------------------------------------------------
# 16. Dynamic programming for constrained selection
# ---------------------------------------------------------------------------

def subset_sum_selection_count(values: Sequence[int], target: int) -> int:
    """
    Count how many subsets have sum exactly equal to target.

    Each value may be used at most once.

    dp[s] stores the number of ways to obtain sum s after processing
    the values seen so far.
    """
    if target < 0:
        return 0

    dp = [0] * (target + 1)
    dp[0] = 1

    for value in values:
        if value < 0:
            raise ValueError("this implementation expects non-negative values")

        for current_sum in range(target, value - 1, -1):
            dp[current_sum] += dp[current_sum - value]

    return dp[target]


def demonstrate_dynamic_programming() -> None:
    print_section("16. Dynamic programming for constrained combinations")

    values = [2, 3, 5, 7, 11]
    target = 10

    print("Values:", values)
    print("Target:", target)
    print("Subsets with sum 10:", subset_sum_selection_count(values, target))

    print(
        """
Simple C(n,r) handles unconstrained selection.

Real applications often add constraints such as:
    - total weight must equal a limit
    - budget must not exceed a limit
    - selected items must satisfy capacity rules

Dynamic programming can count constrained selections efficiently when the
constraint has a manageable state space.
"""
    )


# ---------------------------------------------------------------------------
# 17. Ranking and unranking permutations
# ---------------------------------------------------------------------------

def permutation_rank(items: Sequence[T], permutation: Sequence[T]) -> int:
    """
    Lexicographic zero-based rank of a permutation of distinct items.

    Example:
        sorted items [A,B,C]
        ABC -> 0
        ACB -> 1
        BAC -> 2
        BCA -> 3
        CAB -> 4
        CBA -> 5
    """
    if len(items) != len(permutation):
        raise ValueError("items and permutation must have equal length")

    if len(set(items)) != len(items) or len(set(permutation)) != len(permutation):
        raise ValueError("ranking requires distinct values")

    if set(items) != set(permutation):
        raise ValueError("permutation must contain exactly the original values")

    ordered = sorted(items)
    rank = 0

    for index, value in enumerate(permutation):
        position = ordered.index(value)
        remaining = len(permutation) - index - 1
        rank += position * factorial(remaining)
        ordered.pop(position)

    return rank


def permutation_unrank(items: Sequence[T], rank: int) -> tuple[T, ...]:
    """Recover the permutation at a specified zero-based lexicographic rank."""
    if len(set(items)) != len(items):
        raise ValueError("unranking requires distinct values")

    total = factorial(len(items))
    if rank < 0 or rank >= total:
        raise ValueError("rank is outside the valid range")

    available = sorted(items)
    result: list[T] = []

    for remaining_size in range(len(items), 0, -1):
        block_size = factorial(remaining_size - 1)
        index, rank = divmod(rank, block_size)
        result.append(available.pop(index))

    return tuple(result)


def demonstrate_rank_unrank() -> None:
    print_section("17. Ranking and unranking permutations")

    items = ["A", "B", "C", "D"]

    for permutation in [
        ("A", "B", "C", "D"),
        ("B", "A", "D", "C"),
        ("D", "C", "B", "A"),
    ]:
        rank = permutation_rank(items, permutation)
        recovered = permutation_unrank(items, rank)
        print(permutation, "-> rank", rank, "->", recovered)
        assert recovered == permutation


# ---------------------------------------------------------------------------
# 18. Sampling without enumerating every possibility
# ---------------------------------------------------------------------------

def sample_combinations_without_replacement(
    items: Sequence[T],
    r: int,
    seed: int | None = None,
) -> tuple[T, ...]:
    """
    Select r distinct items using a local pseudo-random generator.

    This demonstrates the difference between counting all possibilities
    and selecting one possibility.
    """
    import random

    if r < 0 or r > len(items):
        raise ValueError("invalid sample size")

    generator = random.Random(seed)
    return tuple(generator.sample(list(items), r))


def demonstrate_sampling() -> None:
    print_section("18. Sampling versus enumeration")

    people = ["A", "B", "C", "D", "E", "F"]

    print("One reproducible random committee:",
          sample_combinations_without_replacement(people, 3, seed=42))

    print(
        """
Counting asks:
    How many possible committees exist?

Enumeration asks:
    What are all of them?

Sampling asks:
    Give me one or more selected possibilities without constructing all
    possible possibilities.

For large n, sampling is usually far more practical than enumeration.
"""
    )


# ---------------------------------------------------------------------------
# 19. Edge cases
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    print_section("19. Edge cases")

    print("C(5,0) =", combination_count(5, 0))
    print("C(5,5) =", combination_count(5, 5))
    print("P(5,0) =", permutation_count(5, 0))
    print("P(5,5) =", permutation_count(5, 5))
    print("0! =", factorial_manual(0))

    print(
        """
Important identities:
    C(n,0) = 1
    C(n,n) = 1
    P(n,0) = 1
    0! = 1

These values represent the empty selection or empty arrangement and make
many recursive and algebraic identities work cleanly.
"""
    )

    invalid_cases = [
        ("C(3,5)", lambda: combination_count(3, 5)),
        ("P(3,5)", lambda: permutation_count(3, 5)),
        ("factorial(-1)", lambda: factorial_manual(-1)),
    ]

    for description, operation in invalid_cases:
        try:
            operation()
        except (TypeError, ValueError) as error:
            print(description, "->", type(error).__name__, ":", error)


# ---------------------------------------------------------------------------
# 20. Common mistakes
# ---------------------------------------------------------------------------

def demonstrate_common_mistakes() -> None:
    print_section("20. Common mistakes")

    print(
        """
Mistake 1:
    Using permutations when order does not matter.

Mistake 2:
    Forgetting that repeated selections may change the formula.

Mistake 3:
    Dividing by r! when the selected objects are not all distinct.

Mistake 4:
    Enumerating every result when only the count is required.

Mistake 5:
    Using floating-point arithmetic for exact combinatorial counts.

Mistake 6:
    Ignoring constraints such as adjacency, fixed positions, capacity,
    or duplicate objects.

Mistake 7:
    Assuming combinations and permutations describe probability in the
    same way. The sample-space model determines the appropriate method.
"""
    )


# ---------------------------------------------------------------------------
# 21. Performance comparison
# ---------------------------------------------------------------------------

def performance_notes() -> None:
    print_section("21. Performance considerations")

    print(
        """
Counting:
    factorial(n) grows extremely quickly.
    P(n,r) and C(n,r) can be calculated without explicitly constructing
    every arrangement.

Enumeration:
    Number of permutations of n distinct objects is n!.
    Number of r-permutations is P(n,r).
    Number of r-combinations is C(n,r).

Memory:
    A generator is generally preferable to list(...) when the result set
    is large.

Exact arithmetic:
    Python integers have arbitrary precision, so large counts remain exact,
    limited mainly by memory and execution time.

Algorithm selection:
    Use a closed-form formula when only a count is required.
    Use lazy enumeration when actual arrangements are needed.
    Use dynamic programming when constraints introduce a useful finite
    state representation.
    Use sampling when only representative possibilities are needed.
"""
    )


# ---------------------------------------------------------------------------
# 22. Integrated practical example: event code system
# ---------------------------------------------------------------------------

class EventCodeSystem:
    """
    A small industry-style model for generating and analyzing codes.

    A code contains:
        - a fixed number of letters
        - a fixed number of digits
        - optional uniqueness requirements
    """

    def __init__(
        self,
        letters: Sequence[str],
        digits: Sequence[str],
    ) -> None:
        if not letters or not digits:
            raise ValueError("both alphabets must be non-empty")

        self.letters = tuple(letters)
        self.digits = tuple(digits)

    def count_codes(
        self,
        letter_positions: int,
        digit_positions: int,
        allow_repetition: bool,
    ) -> int:
        if letter_positions < 0 or digit_positions < 0:
            raise ValueError("position counts cannot be negative")

        if allow_repetition:
            return (
                len(self.letters) ** letter_positions
                * len(self.digits) ** digit_positions
            )

        if letter_positions > len(self.letters):
            return 0

        if digit_positions > len(self.digits):
            return 0

        return (
            permutation_count(len(self.letters), letter_positions)
            * permutation_count(len(self.digits), digit_positions)
        )

    def generate_codes(
        self,
        letter_positions: int,
        digit_positions: int,
    ) -> Iterator[str]:
        """
        Generate codes with distinct letters and distinct digits.

        The code format is:
            all letters first, followed by all digits.
        """
        if letter_positions > len(self.letters):
            return
        if digit_positions > len(self.digits):
            return

        for letters in generate_permutations(self.letters, letter_positions):
            for digits in generate_permutations(self.digits, digit_positions):
                yield "".join(letters + digits)


def demonstrate_integrated_example() -> None:
    print_section("22. Integrated practical example")

    system = EventCodeSystem(
        letters=["A", "B", "C", "D"],
        digits=["1", "2", "3", "4", "5"],
    )

    count = system.count_codes(
        letter_positions=2,
        digit_positions=3,
        allow_repetition=False,
    )

    print("Number of 2-letter + 3-digit unique codes:", count)

    first_codes = []
    for code in system.generate_codes(2, 3):
        first_codes.append(code)
        if len(first_codes) == 10:
            break

    print("First 10 generated codes:")
    for code in first_codes:
        print(" ", code)

    print(
        """
The total follows the multiplication principle:

    P(4,2) × P(5,3)

The letter arrangement and digit arrangement are separate choices, so
their counts are multiplied.
"""
    )


# ---------------------------------------------------------------------------
# 23. Validation and tests
# ---------------------------------------------------------------------------

def run_self_tests() -> None:
    print_section("23. Self-tests")

    for n in range(0, 10):
        assert factorial_manual(n) == factorial(n)

    for n in range(0, 10):
        for r in range(0, n + 1):
            assert combination_count(n, r) == comb(n, r)
            assert combination_count(n, r) == combination_count(n, n - r)
            assert permutation_count(n, r) == factorial(n) // factorial(n - r)
            assert permutation_count(n, r) == combination_count(n, r) * factorial(r)

    assert multiset_permutation_count("AAB") == 3
    assert multiset_permutation_count("AAAA") == 1
    assert circular_permutation_count(5) == 24
    assert count_strings_without_adjacent_ones(5, 3) == 1

    for n in range(1, 8):
        derangement = count_permutations_with_fixed_points(n)
        assert derangement >= 0
        assert derangement != 0 or n == 1

    items = ["A", "B", "C", "D"]
    for rank in range(factorial(len(items))):
        permutation = permutation_unrank(items, rank)
        assert permutation_rank(items, permutation) == rank

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# 24. Main execution
# ---------------------------------------------------------------------------

def main() -> None:
    print_section("COMBINATIONS AND PERMUTATIONS")
    print(
        "This executable study moves from basic counting to constrained "
        "combinatorial algorithms."
    )

    explain_fundamentals()
    demonstrate_factorials()
    demonstrate_permutations()
    demonstrate_repetition()
    demonstrate_combinations()
    demonstrate_relationship()
    demonstrate_enumeration()
    demonstrate_itertools()
    demonstrate_multisets()
    demonstrate_circular_permutations()
    demonstrate_restricted_counting()
    demonstrate_derangements()
    demonstrate_pascal()
    demonstrate_binomial_theorem()
    demonstrate_probability()
    demonstrate_dynamic_programming()
    demonstrate_rank_unrank()
    demonstrate_sampling()
    demonstrate_edge_cases()
    demonstrate_common_mistakes()
    performance_notes()
    demonstrate_integrated_example()
    run_self_tests()

    print_section("End of executable study")
    print("All demonstrations completed successfully.")


if __name__ == "__main__":
    main()
