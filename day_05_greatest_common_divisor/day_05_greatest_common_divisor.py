"""
Greatest Common Divisor (GCD)
============================

A comprehensive study script covering GCD from beginner to advanced level.

Topics covered:
1. Definition and terminology
2. Divisors and common divisors
3. Mathematical properties
4. Brute-force GCD
5. Euclidean algorithm
6. Recursive Euclidean algorithm
7. Binary GCD (Stein's algorithm)
8. Extended Euclidean algorithm
9. Bézout's identity
10. Least Common Multiple (LCM) and its relationship with GCD
11. GCD of multiple numbers
12. Fractions and simplification
13. Modular arithmetic applications
14. Modular multiplicative inverses
15. Linear Diophantine equations
16. Chinese remainder theorem foundations
17. Prime factorization comparison
18. Edge cases and exceptions
19. Performance considerations
20. Testing and validation
21. Real-world applications
"""

from __future__ import annotations

import math
import random
import time
from functools import reduce
from typing import Iterable


# =============================================================================
# 1. FUNDAMENTAL DEFINITIONS
# =============================================================================

def divisors(number: int) -> list[int]:
    """
    Return all positive divisors of a non-zero integer.

    A divisor d of n satisfies:

        n % d == 0

    Example:
        divisors(12) -> [1, 2, 3, 4, 6, 12]

    Negative numbers have the same positive divisors as their absolute values.

    The algorithm checks divisors only up to sqrt(n), making it more efficient
    than checking every number from 1 through n.
    """
    if number == 0:
        raise ValueError("Zero has infinitely many divisors.")

    number = abs(number)
    result = []

    for candidate in range(1, math.isqrt(number) + 1):
        if number % candidate == 0:
            result.append(candidate)

            paired_divisor = number // candidate

            if paired_divisor != candidate:
                result.append(paired_divisor)

    return sorted(result)


def common_divisors(a: int, b: int) -> list[int]:
    """
    Return positive integers that divide both a and b.

    The case gcd(0, 0) is mathematically special because every non-zero integer
    divides zero. For this educational helper, that case raises ValueError.
    """
    if a == 0 and b == 0:
        raise ValueError("0 and 0 have infinitely many common divisors.")

    if a == 0:
        return divisors(b)

    if b == 0:
        return divisors(a)

    return sorted(set(divisors(a)).intersection(divisors(b)))


# =============================================================================
# 2. GCD DEFINITION
# =============================================================================

def gcd_definition(a: int, b: int) -> int:
    """
    Compute GCD directly from the definition.

    The Greatest Common Divisor of two integers is the largest positive integer
    that divides both numbers.

    This implementation is useful for understanding the concept but is not the
    fastest algorithm for large numbers.
    """
    a = abs(a)
    b = abs(b)

    if a == 0 and b == 0:
        return 0

    if a == 0:
        return b

    if b == 0:
        return a

    return max(common_divisors(a, b))


# =============================================================================
# 3. BRUTE-FORCE GCD
# =============================================================================

def gcd_brute_force(a: int, b: int) -> int:
    """
    Compute GCD by checking possible divisors from min(a, b) downward.

    Time complexity:
        O(min(|a|, |b|))

    This is simple but inefficient for large values.
    """
    a = abs(a)
    b = abs(b)

    if a == 0:
        return b

    if b == 0:
        return a

    for candidate in range(min(a, b), 0, -1):
        if a % candidate == 0 and b % candidate == 0:
            return candidate

    # Every pair of positive integers has 1 as a common divisor.
    return 1


# =============================================================================
# 4. EUCLIDEAN ALGORITHM
# =============================================================================

def gcd_euclidean(a: int, b: int) -> int:
    """
    Compute GCD using the iterative Euclidean algorithm.

    Core mathematical principle:

        gcd(a, b) = gcd(b, a mod b)

    If:

        a = bq + r

    then every common divisor of a and b also divides r, and every common
    divisor of b and r also divides a.

    Therefore:

        gcd(a, b) = gcd(b, r)

    Repeating this transformation eventually produces remainder zero.

    Time complexity:
        O(log(min(|a|, |b|))) in the usual asymptotic analysis.

    This is the standard practical algorithm for ordinary integer GCD.
    """
    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a


def show_euclidean_steps(a: int, b: int) -> None:
    """
    Print the divisions performed by the Euclidean algorithm.

    Example for gcd(252, 105):

        252 = 105 * 2 + 42
        105 = 42 * 2 + 21
        42 = 21 * 2 + 0

    Therefore, GCD = 21.
    """
    original_a = a
    original_b = b

    a = abs(a)
    b = abs(b)

    print(f"\nEuclidean steps for gcd({original_a}, {original_b}):")

    if a == 0 and b == 0:
        print("gcd(0, 0) is conventionally defined as 0 in programming.")
        return

    while b != 0:
        quotient, remainder = divmod(a, b)
        print(f"{a} = {b} * {quotient} + {remainder}")
        a, b = b, remainder

    print(f"GCD = {a}")


# =============================================================================
# 5. RECURSIVE EUCLIDEAN ALGORITHM
# =============================================================================

def gcd_recursive(a: int, b: int) -> int:
    """
    Compute GCD recursively.

    Base case:
        gcd(a, 0) = |a|

    Recursive case:
        gcd(a, b) = gcd(b, a mod b)

    Recursion is mathematically elegant but iterative implementations avoid
    recursion overhead and recursion-depth limitations.
    """
    a = abs(a)
    b = abs(b)

    if b == 0:
        return a

    return gcd_recursive(b, a % b)


# =============================================================================
# 6. SUBTRACTION-BASED EUCLIDEAN ALGORITHM
# =============================================================================

def gcd_subtraction(a: int, b: int) -> int:
    """
    Compute GCD using repeated subtraction.

    Mathematical identity:

        gcd(a, b) = gcd(a - b, b), when a >= b

    This demonstrates an important idea behind the Euclidean algorithm.

    It is usually much slower than using modulo. For example, numbers such as
    gcd(1_000_000, 1) require many subtraction steps.
    """
    a = abs(a)
    b = abs(b)

    if a == 0:
        return b

    if b == 0:
        return a

    while a != b:
        if a > b:
            a -= b
        else:
            b -= a

    return a


# =============================================================================
# 7. BINARY GCD (STEIN'S ALGORITHM)
# =============================================================================

def gcd_binary(a: int, b: int) -> int:
    """
    Compute GCD using Stein's algorithm, also called Binary GCD.

    The algorithm uses:
    - comparisons
    - subtraction
    - bit shifting

    Important rules:

    1. gcd(0, b) = |b|

    2. If both a and b are even:
           gcd(a, b) = 2 * gcd(a / 2, b / 2)

    3. If only one number is even:
           gcd(a, b) = gcd(a / 2, b)

    4. If both numbers are odd:
           gcd(a, b) = gcd(|a - b| / 2, min(a, b))

    Binary GCD can be useful in environments where division or modulo is
    relatively expensive.
    """
    a = abs(a)
    b = abs(b)

    if a == 0:
        return b

    if b == 0:
        return a

    # Count the common factors of 2.
    common_power_of_two = 0

    while ((a | b) & 1) == 0:
        a >>= 1
        b >>= 1
        common_power_of_two += 1

    # Make a odd.
    while (a & 1) == 0:
        a >>= 1

    while b != 0:
        # Make b odd.
        while (b & 1) == 0:
            b >>= 1

        # Ensure a <= b.
        if a > b:
            a, b = b, a

        b -= a

    return a << common_power_of_two


# =============================================================================
# 8. EXTENDED EUCLIDEAN ALGORITHM
# =============================================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return (g, x, y) such that:

        a*x + b*y = g

    where:

        g = gcd(a, b)

    This is the Extended Euclidean Algorithm.

    The equation:

        a*x + b*y = gcd(a, b)

    is known as Bézout's identity.

    The coefficients x and y are called Bézout coefficients.

    Example:

        extended_gcd(30, 18)

    may produce:

        gcd = 6
        x = -1
        y = 2

    because:

        30*(-1) + 18*(2) = 6

    These coefficients are essential in modular arithmetic, cryptography,
    Diophantine equations, and number theory.
    """
    if b == 0:
        # Ensure the returned GCD is non-negative.
        return abs(a), 1 if a > 0 else -1 if a < 0 else 0, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


def extended_gcd_iterative(a: int, b: int) -> tuple[int, int, int]:
    """
    Iterative implementation of the Extended Euclidean Algorithm.

    Maintains the invariant:

        old_r = a*old_x + b*old_y
        r     = a*x + b*y

    When r becomes zero, old_r is the GCD.
    """
    original_a = a
    original_b = b

    old_r, r = abs(a), abs(b)
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    # Restore coefficient signs for the original signed inputs.
    if original_a < 0:
        old_x = -old_x

    if original_b < 0:
        old_y = -old_y

    return old_r, old_x, old_y


# =============================================================================
# 9. BÉZOUT IDENTITY VALIDATION
# =============================================================================

def verify_bezout_identity(a: int, b: int) -> None:
    """Compute and display Bézout coefficients."""
    g, x, y = extended_gcd(a, b)
    left_side = a * x + b * y

    print(f"\nBézout identity for a={a}, b={b}")
    print(f"gcd({a}, {b}) = {g}")
    print(f"x = {x}, y = {y}")
    print(f"{a} * ({x}) + {b} * ({y}) = {left_side}")


# =============================================================================
# 10. GCD OF MULTIPLE NUMBERS
# =============================================================================

def gcd_many(numbers: Iterable[int]) -> int:
    """
    Compute the GCD of multiple integers.

    Mathematical associativity:

        gcd(a, b, c) = gcd(gcd(a, b), c)

    Empty input is rejected because no ordinary GCD exists for an empty
    collection in this implementation.
    """
    numbers = list(numbers)

    if not numbers:
        raise ValueError("At least one integer is required.")

    result = 0

    for number in numbers:
        result = gcd_euclidean(result, number)

    return result


def gcd_many_reduce(numbers: Iterable[int]) -> int:
    """
    Compute GCD using functools.reduce.

    This is concise but does not provide special educational advantages over an
    explicit loop.
    """
    numbers = list(numbers)

    if not numbers:
        raise ValueError("At least one integer is required.")

    return reduce(gcd_euclidean, numbers)


# =============================================================================
# 11. LEAST COMMON MULTIPLE (LCM)
# =============================================================================

def lcm(a: int, b: int) -> int:
    """
    Compute the Least Common Multiple.

    For non-zero integers:

        gcd(a, b) * lcm(a, b) = |a * b|

    Therefore:

        lcm(a, b) = |a * b| / gcd(a, b)

    To reduce unnecessary large intermediate products, calculate:

        (a // gcd(a, b)) * b

    before taking the absolute value.
    """
    a = int(a)
    b = int(b)

    if a == 0 or b == 0:
        return 0

    return abs((a // gcd_euclidean(a, b)) * b)


def lcm_many(numbers: Iterable[int]) -> int:
    """Compute LCM for multiple integers."""
    numbers = list(numbers)

    if not numbers:
        raise ValueError("At least one integer is required.")

    return reduce(lcm, numbers)


# =============================================================================
# 12. PRIME FACTORIZATION APPROACH
# =============================================================================

def prime_factorization(number: int) -> dict[int, int]:
    """
    Return prime factorization as:

        prime -> exponent

    Example:

        360 = 2^3 * 3^2 * 5

    returns:

        {2: 3, 3: 2, 5: 1}

    This approach is useful for understanding GCD theoretically.

    GCD can be constructed by taking each common prime factor with the minimum
    exponent.

    For very large integers, factorization is generally far more expensive than
    the Euclidean algorithm.
    """
    number = abs(number)

    if number == 0:
        raise ValueError("Prime factorization of zero is not finite.")

    if number == 1:
        return {}

    factors = {}

    while number % 2 == 0:
        factors[2] = factors.get(2, 0) + 1
        number //= 2

    candidate = 3

    while candidate * candidate <= number:
        while number % candidate == 0:
            factors[candidate] = factors.get(candidate, 0) + 1
            number //= candidate

        candidate += 2

    if number > 1:
        factors[number] = factors.get(number, 0) + 1

    return factors


def gcd_prime_factorization(a: int, b: int) -> int:
    """
    Compute GCD using prime factorization.

    This is educational and should generally not replace Euclid's algorithm.
    """
    if a == 0 and b == 0:
        return 0

    if a == 0:
        return abs(b)

    if b == 0:
        return abs(a)

    factors_a = prime_factorization(a)
    factors_b = prime_factorization(b)

    result = 1

    for prime in factors_a.keys() & factors_b.keys():
        exponent = min(factors_a[prime], factors_b[prime])
        result *= prime ** exponent

    return result


# =============================================================================
# 13. GCD AND FRACTION SIMPLIFICATION
# =============================================================================

def simplify_fraction(numerator: int, denominator: int) -> tuple[int, int]:
    """
    Reduce a fraction to lowest terms.

    Example:

        42 / 56

    gcd(42, 56) = 14

    Therefore:

        42 / 56 = 3 / 4

    The denominator is normalized to be positive.
    """
    if denominator == 0:
        raise ZeroDivisionError("A fraction denominator cannot be zero.")

    if numerator == 0:
        return 0, 1

    divisor = gcd_euclidean(numerator, denominator)

    numerator //= divisor
    denominator //= divisor

    if denominator < 0:
        numerator = -numerator
        denominator = -denominator

    return numerator, denominator


class Rational:
    """
    Minimal immutable-style rational number representation.

    GCD ensures that every stored fraction remains normalized.
    """

    def __init__(self, numerator: int, denominator: int = 1):
        numerator, denominator = simplify_fraction(numerator, denominator)
        self.numerator = numerator
        self.denominator = denominator

    def __repr__(self) -> str:
        if self.denominator == 1:
            return f"Rational({self.numerator})"

        return f"Rational({self.numerator}, {self.denominator})"

    def __str__(self) -> str:
        if self.denominator == 1:
            return str(self.numerator)

        return f"{self.numerator}/{self.denominator}"

    def __add__(self, other: Rational) -> Rational:
        if not isinstance(other, Rational):
            return NotImplemented

        numerator = (
            self.numerator * other.denominator
            + other.numerator * self.denominator
        )

        denominator = self.denominator * other.denominator

        return Rational(numerator, denominator)

    def __mul__(self, other: Rational) -> Rational:
        if not isinstance(other, Rational):
            return NotImplemented

        # Cross-cancellation reduces intermediate multiplication sizes.
        gcd_left = gcd_euclidean(
            self.numerator,
            other.denominator
        )

        gcd_right = gcd_euclidean(
            other.numerator,
            self.denominator
        )

        numerator = (
            (self.numerator // gcd_left)
            * (other.numerator // gcd_right)
        )

        denominator = (
            (self.denominator // gcd_right)
            * (other.denominator // gcd_left)
        )

        return Rational(numerator, denominator)


# =============================================================================
# 14. COPRIME NUMBERS
# =============================================================================

def are_coprime(a: int, b: int) -> bool:
    """
    Return True when two integers are relatively prime.

    Two numbers are coprime when:

        gcd(a, b) = 1

    Coprime numbers do not need to be prime.

    Example:
        8 and 15 are coprime.

    Both are composite, but their GCD is 1.
    """
    return gcd_euclidean(a, b) == 1


# =============================================================================
# 15. MODULAR MULTIPLICATIVE INVERSE
# =============================================================================

def modular_inverse(a: int, modulus: int) -> int:
    """
    Compute the multiplicative inverse of a modulo modulus.

    An inverse x satisfies:

        a*x ≡ 1 (mod modulus)

    Such an inverse exists if and only if:

        gcd(a, modulus) = 1

    The Extended Euclidean Algorithm gives:

        a*x + modulus*y = 1

    Taking both sides modulo modulus gives:

        a*x ≡ 1 (mod modulus)
    """
    if modulus <= 1:
        raise ValueError("Modulus must be greater than 1.")

    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise ValueError(
            f"{a} has no modular inverse modulo {modulus} because "
            f"gcd({a}, {modulus}) = {g}."
        )

    return x % modulus


# =============================================================================
# 16. LINEAR DIOPHANTINE EQUATIONS
# =============================================================================

def solve_linear_diophantine(
    a: int,
    b: int,
    c: int,
) -> tuple[int, int] | None:
    """
    Solve:

        a*x + b*y = c

    for one integer solution.

    A solution exists if and only if:

        gcd(a, b) divides c

    If:

        a*x0 + b*y0 = gcd(a, b)

    then multiplying both sides by:

        c / gcd(a, b)

    gives a solution to:

        a*x + b*y = c

    Returns:
        (x, y) for one solution

    Returns:
        None when no integer solution exists.
    """
    g, x0, y0 = extended_gcd(a, b)

    if g == 0:
        if c == 0:
            return 0, 0
        return None

    if c % g != 0:
        return None

    multiplier = c // g

    return x0 * multiplier, y0 * multiplier


def diophantine_solution_family(
    a: int,
    b: int,
    c: int,
) -> tuple[int, int, int, int] | None:
    """
    Return parameters describing all integer solutions to:

        a*x + b*y = c

    If (x0, y0) is one solution and g = gcd(a, b), then:

        x = x0 + (b / g) * t
        y = y0 - (a / g) * t

    for every integer t.

    Returns:

        (x0, y0, step_x, step_y)

    where:

        x = x0 + step_x*t
        y = y0 + step_y*t
    """
    solution = solve_linear_diophantine(a, b, c)

    if solution is None:
        return None

    x0, y0 = solution
    g = gcd_euclidean(a, b)

    if g == 0:
        return x0, y0, 0, 0

    step_x = b // g
    step_y = -(a // g)

    return x0, y0, step_x, step_y


# =============================================================================
# 17. MODULAR LINEAR EQUATIONS
# =============================================================================

def solve_modular_linear_equation(
    a: int,
    b: int,
    modulus: int,
) -> list[int]:
    """
    Solve:

        a*x ≡ b (mod modulus)

    A solution exists exactly when:

        gcd(a, modulus) divides b

    If g = gcd(a, modulus), there are g distinct solutions modulo modulus when
    a solution exists.

    This function returns all solutions in the canonical range:

        0 <= x < modulus
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    g = gcd_euclidean(a, modulus)

    if b % g != 0:
        return []

    reduced_a = a // g
    reduced_b = b // g
    reduced_modulus = modulus // g

    inverse = modular_inverse(reduced_a, reduced_modulus)

    first_solution = (inverse * reduced_b) % reduced_modulus

    return sorted(
        {
            (first_solution + k * reduced_modulus) % modulus
            for k in range(g)
        }
    )


# =============================================================================
# 18. CHINESE REMAINDER THEOREM FOR TWO CONGRUENCES
# =============================================================================

def chinese_remainder_two(
    remainder1: int,
    modulus1: int,
    remainder2: int,
    modulus2: int,
) -> tuple[int, int]:
    """
    Solve two congruences:

        x ≡ remainder1 (mod modulus1)
        x ≡ remainder2 (mod modulus2)

    This generalized implementation works when moduli are not necessarily
    coprime, provided the system is consistent.

    Consistency condition:

        remainder2 - remainder1

    must be divisible by:

        gcd(modulus1, modulus2)

    Returns:

        (x, lcm(modulus1, modulus2))

    where x is the smallest non-negative solution.
    """
    if modulus1 <= 0 or modulus2 <= 0:
        raise ValueError("Moduli must be positive.")

    g, coefficient1, _ = extended_gcd(modulus1, modulus2)

    difference = remainder2 - remainder1

    if difference % g != 0:
        raise ValueError("The congruences are inconsistent.")

    reduced_modulus2 = modulus2 // g

    multiplier = (
        (difference // g) * coefficient1
    ) % reduced_modulus2

    solution = remainder1 + modulus1 * multiplier
    combined_modulus = lcm(modulus1, modulus2)

    return solution % combined_modulus, combined_modulus


# =============================================================================
# 19. GCD PROPERTIES
# =============================================================================

def demonstrate_gcd_properties(a: int, b: int) -> None:
    """
    Display important GCD properties for two integers.

    Important properties:

    1. Non-negativity:
           gcd(a, b) >= 0

    2. Symmetry:
           gcd(a, b) = gcd(b, a)

    3. Identity:
           gcd(a, 0) = |a|

    4. Divisibility:
           gcd(a, b) divides a
           gcd(a, b) divides b

    5. Euclidean invariance:
           gcd(a, b) = gcd(b, a mod b)

    6. Scaling:
           gcd(k*a, k*b) = |k| * gcd(a, b)

    7. Relationship with LCM for non-zero numbers:
           gcd(a, b) * lcm(a, b) = |a*b|
    """
    g = gcd_euclidean(a, b)

    print(f"\nProperties for a={a}, b={b}")
    print(f"gcd(a, b) = {g}")
    print(f"gcd(b, a) = {gcd_euclidean(b, a)}")
    print(f"gcd(a, b) divides a: {a % g == 0 if g != 0 else a == 0}")
    print(f"gcd(a, b) divides b: {b % g == 0 if g != 0 else b == 0}")

    if b != 0:
        print(
            "Euclidean identity holds:",
            g == gcd_euclidean(b, a % b),
        )

    scale = 7
    print(
        f"Scaling identity for k={scale}:",
        gcd_euclidean(scale * a, scale * b)
        == abs(scale) * g,
    )

    if a != 0 and b != 0:
        print(
            "GCD * LCM = |a*b|:",
            g * lcm(a, b) == abs(a * b),
        )


# =============================================================================
# 20. PRACTICAL APPLICATION: GROUPING OBJECTS
# =============================================================================

def largest_equal_group_size(a: int, b: int) -> int:
    """
    Return the largest number of equal groups into which quantities a and b
    can both be divided without remainder.

    Example:
        24 red items and 36 blue items can be arranged into at most:

            gcd(24, 36) = 12

        equal groups.

    Each group then contains:
        24 / 12 = 2 red items
        36 / 12 = 3 blue items.
    """
    return gcd_euclidean(a, b)


# =============================================================================
# 21. PRACTICAL APPLICATION: REDUCING RATIOS
# =============================================================================

def simplify_ratio(a: int, b: int) -> tuple[int, int]:
    """
    Reduce an integer ratio using GCD.

    Example:

        150 : 100

    gcd = 50

    Reduced ratio:

        3 : 2
    """
    if a == 0 and b == 0:
        raise ValueError("The ratio 0:0 is undefined.")

    divisor = gcd_euclidean(a, b)

    if divisor == 0:
        return 0, 0

    return a // divisor, b // divisor


# =============================================================================
# 22. PRACTICAL APPLICATION: PERIODIC EVENTS
# =============================================================================

def next_simultaneous_event(
    period_a: int,
    period_b: int,
) -> int:
    """
    Return the smallest positive time at which two periodic events coincide.

    This is the LCM:

        lcm(period_a, period_b)

    GCD is used internally because:

        lcm(a, b) = |a*b| / gcd(a, b)
    """
    if period_a <= 0 or period_b <= 0:
        raise ValueError("Periods must be positive.")

    return lcm(period_a, period_b)


# =============================================================================
# 23. PYTHON STANDARD LIBRARY IMPLEMENTATION
# =============================================================================

def demonstrate_math_gcd() -> None:
    """
    Demonstrate Python's built-in math.gcd.

    math.gcd is the preferred choice for production code unless an educational
    or specialized implementation is required.
    """
    values = [84, 126, 210]

    result = math.gcd(*values)

    print("\nPython standard library:")
    print(f"math.gcd{tuple(values)} = {result}")
    print(f"math.lcm{tuple(values)} = {math.lcm(*values)}")


# =============================================================================
# 24. EDGE CASES
# =============================================================================

def demonstrate_edge_cases() -> None:
    """
    Demonstrate important GCD edge cases.

    Mathematically and computationally important cases include:

        gcd(a, 0) = |a|
        gcd(0, b) = |b|
        gcd(0, 0) = 0 in common programming conventions
        gcd(-a, b) = gcd(a, b)
        gcd(a, -b) = gcd(a, b)
        gcd(-a, -b) = gcd(a, b)
    """
    cases = [
        (0, 0),
        (10, 0),
        (0, 15),
        (-12, 18),
        (12, -18),
        (-12, -18),
        (1, 1),
        (1, 999_983),
        (999_983, 1),
    ]

    print("\nEdge cases:")

    for a, b in cases:
        print(
            f"gcd({a}, {b}) = {gcd_euclidean(a, b)} "
            f"(math.gcd = {math.gcd(a, b)})"
        )


# =============================================================================
# 25. COMMON IMPLEMENTATION MISTAKES
# =============================================================================

def explain_common_mistakes() -> None:
    """
    Print common conceptual and implementation mistakes.

    These are intentionally described rather than implemented incorrectly as
    reusable functions.
    """
    mistakes = [
        "Assuming GCD is negative when both inputs are negative.",
        "Dividing by gcd(a, b) without handling gcd(0, 0).",
        "Using prime factorization when the Euclidean algorithm is sufficient.",
        "Using repeated subtraction for very large unequal numbers.",
        "Confusing GCD with LCM.",
        "Assuming coprime numbers must both be prime.",
        "Assuming a modular inverse always exists.",
        "Ignoring denominator zero while simplifying fractions.",
        "Using floating-point arithmetic for integer divisibility problems.",
    ]

    print("\nCommon mistakes:")

    for index, mistake in enumerate(mistakes, start=1):
        print(f"{index}. {mistake}")


# =============================================================================
# 26. PERFORMANCE COMPARISON
# =============================================================================

def benchmark_algorithms() -> None:
    """
    Compare selected algorithms on moderately sized inputs.

    Timing results vary by hardware and Python implementation.

    Prime factorization and brute force are intentionally tested only on values
    where the demonstration remains practical.
    """
    test_cases = [
        (48, 180),
        (12345, 67890),
        (987654, 123456),
    ]

    algorithms = [
        ("Brute Force", gcd_brute_force),
        ("Euclidean", gcd_euclidean),
        ("Recursive Euclidean", gcd_recursive),
        ("Binary GCD", gcd_binary),
        ("math.gcd", math.gcd),
    ]

    print("\nPerformance comparison:")

    for a, b in test_cases:
        print(f"\nInputs: {a}, {b}")

        expected = math.gcd(a, b)

        for name, algorithm in algorithms:
            start = time.perf_counter()
            result = algorithm(a, b)
            elapsed = time.perf_counter() - start

            correct = result == expected

            print(
                f"{name:<22} "
                f"Result={result:<8} "
                f"Correct={str(correct):<5} "
                f"Time={elapsed:.10f}s"
            )


# =============================================================================
# 27. TESTING
# =============================================================================

def test_known_cases() -> None:
    """Test algorithms against known GCD values."""
    test_cases = [
        (48, 18, 6),
        (54, 24, 6),
        (17, 13, 1),
        (100, 10, 10),
        (0, 5, 5),
        (5, 0, 5),
        (0, 0, 0),
        (-48, 18, 6),
        (-48, -18, 6),
        (270, 192, 6),
        (999_983, 999_983, 999_983),
    ]

    algorithms = [
        gcd_definition,
        gcd_brute_force,
        gcd_euclidean,
        gcd_recursive,
        gcd_subtraction,
        gcd_binary,
        gcd_prime_factorization,
    ]

    for a, b, expected in test_cases:
        for algorithm in algorithms:
            actual = algorithm(a, b)

            assert actual == expected, (
                f"{algorithm.__name__} failed for "
                f"({a}, {b}): expected {expected}, got {actual}"
            )


def test_random_cases(number_of_tests: int = 1_000) -> None:
    """
    Randomized testing against math.gcd.

    Property-based testing is valuable because GCD algorithms must handle many
    possible integer combinations.
    """
    algorithms = [
        gcd_euclidean,
        gcd_recursive,
        gcd_binary,
    ]

    for _ in range(number_of_tests):
        a = random.randint(-1_000_000, 1_000_000)
        b = random.randint(-1_000_000, 1_000_000)

        expected = math.gcd(a, b)

        for algorithm in algorithms:
            actual = algorithm(a, b)

            assert actual == expected, (
                f"{algorithm.__name__} failed for "
                f"({a}, {b}): expected {expected}, got {actual}"
            )


def test_extended_gcd() -> None:
    """Verify Bézout identity for several integer pairs."""
    test_cases = [
        (30, 18),
        (240, 46),
        (-30, 18),
        (30, -18),
        (17, 31),
    ]

    for a, b in test_cases:
        g, x, y = extended_gcd(a, b)

        assert g == math.gcd(a, b)
        assert a * x + b * y == g


def test_modular_inverse() -> None:
    """Verify modular inverse behavior."""
    cases = [
        (3, 11),
        (7, 26),
        (17, 31),
    ]

    for a, modulus in cases:
        inverse = modular_inverse(a, modulus)
        assert (a * inverse) % modulus == 1

    try:
        modular_inverse(6, 15)
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected modular_inverse(6, 15) to fail."
        )


def run_tests() -> None:
    """Run the complete test suite."""
    test_known_cases()
    test_random_cases()
    test_extended_gcd()
    test_modular_inverse()

    print("\nAll tests passed successfully.")


# =============================================================================
# 28. COMPARISON OF GCD IMPLEMENTATIONS
# =============================================================================

def compare_implementations(a: int, b: int) -> None:
    """Compare several GCD implementations for one input pair."""
    implementations = {
        "Definition": gcd_definition,
        "Brute Force": gcd_brute_force,
        "Euclidean": gcd_euclidean,
        "Recursive Euclidean": gcd_recursive,
        "Subtraction": gcd_subtraction,
        "Binary GCD": gcd_binary,
        "Prime Factorization": gcd_prime_factorization,
        "math.gcd": math.gcd,
    }

    print(f"\nComparing GCD implementations for ({a}, {b}):")

    expected = math.gcd(a, b)

    for name, algorithm in implementations.items():
        result = algorithm(a, b)
        print(
            f"{name:<24} = {result} "
            f"{'OK' if result == expected else 'ERROR'}"
        )


# =============================================================================
# 29. ADVANCED NUMBER-THEORETIC EXAMPLES
# =============================================================================

def advanced_examples() -> None:
    """Run advanced applications built on GCD."""

    print("\n" + "=" * 72)
    print("ADVANCED EXAMPLES")
    print("=" * 72)

    # -------------------------------------------------------------------------
    # Modular inverse
    # -------------------------------------------------------------------------

    a = 17
    modulus = 43
    inverse = modular_inverse(a, modulus)

    print("\nModular inverse:")
    print(
        f"Inverse of {a} modulo {modulus} = {inverse}"
    )
    print(
        f"Verification: ({a} * {inverse}) % {modulus} "
        f"= {(a * inverse) % modulus}"
    )

    # -------------------------------------------------------------------------
    # Linear Diophantine equation
    # -------------------------------------------------------------------------

    coefficient_a = 15
    coefficient_b = 25
    target = 5

    solution = solve_linear_diophantine(
        coefficient_a,
        coefficient_b,
        target,
    )

    print("\nLinear Diophantine equation:")
    print(
        f"{coefficient_a}x + {coefficient_b}y = {target}"
    )
    print(f"One solution: {solution}")

    if solution is not None:
        x, y = solution
        print(
            "Verification:",
            coefficient_a * x + coefficient_b * y,
        )

    family = diophantine_solution_family(
        coefficient_a,
        coefficient_b,
        target,
    )

    print(f"Solution family parameters: {family}")

    # -------------------------------------------------------------------------
    # Modular linear equation
    # -------------------------------------------------------------------------

    print("\nModular linear equation:")
    print("Solve 6x ≡ 8 (mod 14)")

    solutions = solve_modular_linear_equation(
        6,
        8,
        14,
    )

    print(f"Solutions: {solutions}")

    for x in solutions:
        print(
            f"x={x}: (6*{x}) % 14 = {(6 * x) % 14}"
        )

    # -------------------------------------------------------------------------
    # Chinese Remainder Theorem
    # -------------------------------------------------------------------------

    print("\nChinese Remainder Theorem:")
    print("x ≡ 2 (mod 3)")
    print("x ≡ 3 (mod 5)")

    solution, combined_modulus = chinese_remainder_two(
        2,
        3,
        3,
        5,
    )

    print(
        f"x = {solution} (mod {combined_modulus})"
    )
    print(
        f"Verification: {solution} % 3 = {solution % 3}"
    )
    print(
        f"Verification: {solution} % 5 = {solution % 5}"
    )


# =============================================================================
# 30. MAIN EDUCATIONAL DEMONSTRATION
# =============================================================================

def main() -> None:
    """Execute the complete GCD study demonstration."""

    print("=" * 72)
    print("GREATEST COMMON DIVISOR (GCD) - COMPREHENSIVE STUDY")
    print("=" * 72)

    # -------------------------------------------------------------------------
    # Fundamentals
    # -------------------------------------------------------------------------

    a = 48
    b = 180

    print("\n1. FUNDAMENTALS")
    print("-" * 72)

    print(f"Divisors of {a}: {divisors(a)}")
    print(f"Divisors of {b}: {divisors(b)}")
    print(f"Common divisors: {common_divisors(a, b)}")
    print(f"GCD by definition: {gcd_definition(a, b)}")

    # -------------------------------------------------------------------------
    # Compare algorithms
    # -------------------------------------------------------------------------

    print("\n2. GCD ALGORITHMS")
    print("-" * 72)

    compare_implementations(a, b)

    # -------------------------------------------------------------------------
    # Euclidean algorithm steps
    # -------------------------------------------------------------------------

    print("\n3. EUCLIDEAN ALGORITHM")
    print("-" * 72)

    show_euclidean_steps(252, 105)

    # -------------------------------------------------------------------------
    # Extended Euclidean algorithm
    # -------------------------------------------------------------------------

    print("\n4. EXTENDED EUCLIDEAN ALGORITHM")
    print("-" * 72)

    verify_bezout_identity(240, 46)

    # -------------------------------------------------------------------------
    # Multiple numbers
    # -------------------------------------------------------------------------

    print("\n5. GCD OF MULTIPLE NUMBERS")
    print("-" * 72)

    numbers = [84, 126, 210]

    print(f"Numbers: {numbers}")
    print(f"GCD: {gcd_many(numbers)}")
    print(f"GCD using reduce: {gcd_many_reduce(numbers)}")

    # -------------------------------------------------------------------------
    # LCM
    # -------------------------------------------------------------------------

    print("\n6. RELATIONSHIP BETWEEN GCD AND LCM")
    print("-" * 72)

    lcm_a = 12
    lcm_b = 18

    print(f"gcd({lcm_a}, {lcm_b}) = {gcd_euclidean(lcm_a, lcm_b)}")
    print(f"lcm({lcm_a}, {lcm_b}) = {lcm(lcm_a, lcm_b)}")

    print(
        "Identity:",
        gcd_euclidean(lcm_a, lcm_b)
        * lcm(lcm_a, lcm_b)
        == abs(lcm_a * lcm_b),
    )

    # -------------------------------------------------------------------------
    # Prime factorization
    # -------------------------------------------------------------------------

    print("\n7. PRIME FACTORIZATION")
    print("-" * 72)

    factor_a = 360
    factor_b = 840

    print(
        f"Prime factorization of {factor_a}: "
        f"{prime_factorization(factor_a)}"
    )
    print(
        f"Prime factorization of {factor_b}: "
        f"{prime_factorization(factor_b)}"
    )
    print(
        f"GCD using factorization: "
        f"{gcd_prime_factorization(factor_a, factor_b)}"
    )
    print(
        f"GCD using Euclid: "
        f"{gcd_euclidean(factor_a, factor_b)}"
    )

    # -------------------------------------------------------------------------
    # Fractions
    # -------------------------------------------------------------------------

    print("\n8. FRACTION SIMPLIFICATION")
    print("-" * 72)

    numerator = 42
    denominator = 56

    print(
        f"{numerator}/{denominator} simplifies to "
        f"{simplify_fraction(numerator, denominator)}"
    )

    fraction_1 = Rational(42, 56)
    fraction_2 = Rational(9, 12)

    print(f"Fraction 1: {fraction_1}")
    print(f"Fraction 2: {fraction_2}")
    print(f"Addition: {fraction_1} + {fraction_2} = {fraction_1 + fraction_2}")
    print(
        f"Multiplication: {fraction_1} * {fraction_2} "
        f"= {fraction_1 * fraction_2}"
    )

    # -------------------------------------------------------------------------
    # Coprimality
    # -------------------------------------------------------------------------

    print("\n9. COPRIME NUMBERS")
    print("-" * 72)

    pairs = [
        (8, 15),
        (12, 18),
        (17, 31),
    ]

    for first, second in pairs:
        print(
            f"{first} and {second}: "
            f"GCD={gcd_euclidean(first, second)}, "
            f"coprime={are_coprime(first, second)}"
        )

    # -------------------------------------------------------------------------
    # Ratios and grouping
    # -------------------------------------------------------------------------

    print("\n10. PRACTICAL APPLICATIONS")
    print("-" * 72)

    red_items = 24
    blue_items = 36

    groups = largest_equal_group_size(
        red_items,
        blue_items,
    )

    print(
        f"{red_items} and {blue_items} items can form "
        f"{groups} maximum equal groups."
    )
    print(
        f"Each group contains "
        f"{red_items // groups} and "
        f"{blue_items // groups} items."
    )

    ratio = (150, 100)

    print(
        f"Ratio {ratio[0]}:{ratio[1]} simplifies to "
        f"{simplify_ratio(*ratio)}"
    )

    period_a = 12
    period_b = 18

    print(
        f"Events repeating every {period_a} and {period_b} units "
        f"coincide every "
        f"{next_simultaneous_event(period_a, period_b)} units."
    )

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    print("\n11. MATHEMATICAL PROPERTIES")
    print("-" * 72)

    demonstrate_gcd_properties(84, 126)

    # -------------------------------------------------------------------------
    # Edge cases
    # -------------------------------------------------------------------------

    print("\n12. EDGE CASES")
    print("-" * 72)

    demonstrate_edge_cases()

    # -------------------------------------------------------------------------
    # Python library
    # -------------------------------------------------------------------------

    print("\n13. STANDARD LIBRARY")
    print("-" * 72)

    demonstrate_math_gcd()

    # -------------------------------------------------------------------------
    # Advanced concepts
    # -------------------------------------------------------------------------

    advanced_examples()

    # -------------------------------------------------------------------------
    # Common mistakes
    # -------------------------------------------------------------------------

    print("\n14. COMMON MISTAKES")
    print("-" * 72)

    explain_common_mistakes()

    # -------------------------------------------------------------------------
    # Performance
    # -------------------------------------------------------------------------

    print("\n15. PERFORMANCE")
    print("-" * 72)

    benchmark_algorithms()

    # -------------------------------------------------------------------------
    # Testing
    # -------------------------------------------------------------------------

    print("\n16. TESTING AND VALIDATION")
    print("-" * 72)

    run_tests()


if __name__ == "__main__":
    main()
