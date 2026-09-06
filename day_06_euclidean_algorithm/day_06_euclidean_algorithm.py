"""
Euclidean Algorithm: Complete Study Script
===========================================

This self-contained script teaches the Euclidean algorithm from beginner to
advanced level using executable Python examples.

Topics covered:
- Divisibility and remainders
- Greatest common divisor (GCD)
- Classical Euclidean algorithm
- Iterative and recursive implementations
- Correctness and termination
- Extended Euclidean algorithm
- Bézout's identity
- Modular multiplicative inverses
- Linear Diophantine equations
- GCD of multiple integers
- Least common multiple (LCM)
- Coprimality
- GCD normalization and negative/zero inputs
- Euclidean algorithm on very large integers
- Continued-fraction connection
- Modular arithmetic applications
- RSA-related mathematical foundations
- Complexity analysis
- Common mistakes
- Testing and verification
- Performance comparison
- Practical implementation considerations

The script uses only the Python standard library.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd as math_gcd
from random import randint
from time import perf_counter
from typing import Iterable


# ============================================================================
# 1. FUNDAMENTAL IDEAS
# ============================================================================

def demonstrate_division_algorithm() -> None:
    """
    Demonstrate the division algorithm:

        a = bq + r

    where:
        a = dividend
        b = divisor, b != 0
        q = quotient
        r = remainder
        0 <= r < |b|
    """
    dividend = 107
    divisor = 23

    quotient, remainder = divmod(dividend, divisor)

    print("\n=== Division Algorithm ===")
    print(f"{dividend} = {divisor} * {quotient} + {remainder}")
    print(f"Remainder satisfies 0 <= {remainder} < {abs(divisor)}")


def demonstrate_remainder_properties() -> None:
    """
    Show the key remainder transformation behind the Euclidean algorithm.

    If:
        a = bq + r

    then:
        gcd(a, b) = gcd(b, r)

    because the common divisors of (a, b) are exactly the common divisors
    of (b, r).
    """
    a = 252
    b = 105

    q, r = divmod(a, b)

    print("\n=== GCD-Preserving Remainder Transformation ===")
    print(f"{a} = {b} * {q} + {r}")
    print(f"gcd({a}, {b}) = gcd({b}, {r})")


# ============================================================================
# 2. BASIC GCD CONCEPT
# ============================================================================

def gcd_by_definition(a: int, b: int) -> int:
    """
    Compute the GCD by checking every possible positive common divisor.

    This implementation is intentionally educational rather than efficient.
    It illustrates the definition:

        gcd(a, b) = largest positive integer dividing both a and b.
    """
    a = abs(a)
    b = abs(b)

    if a == 0 and b == 0:
        raise ValueError("gcd(0, 0) is conventionally undefined.")

    limit = min(a, b)

    if limit == 0:
        return max(a, b)

    greatest = 1

    for candidate in range(1, limit + 1):
        if a % candidate == 0 and b % candidate == 0:
            greatest = candidate

    return greatest


def gcd_euclidean_iterative(a: int, b: int) -> int:
    """
    Compute gcd(a, b) using the iterative Euclidean algorithm.

    The algorithm repeatedly replaces:

        (a, b)

    with:

        (b, a mod b)

    until b becomes zero.

    The remaining value of a is the GCD.
    """
    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a


def gcd_euclidean_recursive(a: int, b: int) -> int:
    """
    Recursive Euclidean algorithm.

    Base case:
        gcd(a, 0) = |a|

    Recursive case:
        gcd(a, b) = gcd(b, a mod b)
    """
    a = abs(a)
    b = abs(b)

    if b == 0:
        return a

    return gcd_euclidean_recursive(b, a % b)


def demonstrate_basic_gcd() -> None:
    print("\n=== Basic GCD ===")

    a = 252
    b = 105

    print(f"Definition-based GCD: gcd({a}, {b}) = {gcd_by_definition(a, b)}")
    print(f"Iterative GCD:         gcd({a}, {b}) = {gcd_euclidean_iterative(a, b)}")
    print(f"Recursive GCD:         gcd({a}, {b}) = {gcd_euclidean_recursive(a, b)}")
    print(f"Python math.gcd:       gcd({a}, {b}) = {math_gcd(a, b)}")


# ============================================================================
# 3. SHOW EVERY EUCLIDEAN STEP
# ============================================================================

@dataclass(frozen=True)
class EuclideanStep:
    dividend: int
    divisor: int
    quotient: int
    remainder: int


def euclidean_steps(a: int, b: int) -> list[EuclideanStep]:
    """
    Return all division steps performed by the Euclidean algorithm.
    """
    a = abs(a)
    b = abs(b)

    if a < b:
        a, b = b, a

    steps: list[EuclideanStep] = []

    while b != 0:
        quotient, remainder = divmod(a, b)
        steps.append(EuclideanStep(a, b, quotient, remainder))
        a, b = b, remainder

    return steps


def print_euclidean_steps(a: int, b: int) -> None:
    print(f"\n=== Euclidean Algorithm Steps for gcd({a}, {b}) ===")

    steps = euclidean_steps(a, b)

    for step in steps:
        print(
            f"{step.dividend} = "
            f"{step.divisor} * "
            f"{step.quotient} + "
            f"{step.remainder}"
        )

    print(f"GCD = {steps[-1].divisor if steps[-1].remainder == 0 else 'undefined'}")


# ============================================================================
# 4. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print("\n=== Edge Cases ===")

    cases = [
        (0, 15),
        (15, 0),
        (0, -15),
        (-15, 0),
        (-48, 18),
        (48, -18),
        (-48, -18),
        (1, 1),
        (17, 13),
        (13, 17),
    ]

    for a, b in cases:
        result = gcd_euclidean_iterative(a, b)
        print(f"gcd({a:>4}, {b:>4}) = {result}")


# ============================================================================
# 5. MULTIPLE-INTEGER GCD
# ============================================================================

def gcd_many(numbers: Iterable[int]) -> int:
    """
    Compute the GCD of an arbitrary iterable.

    The associative property gives:

        gcd(a, b, c) = gcd(gcd(a, b), c)

    so numbers can be processed one at a time.
    """
    iterator = iter(numbers)

    try:
        result = abs(next(iterator))
    except StopIteration:
        raise ValueError("At least one integer is required.")

    for number in iterator:
        result = gcd_euclidean_iterative(result, number)

        if result == 1:
            break

    return result


def demonstrate_gcd_many() -> None:
    print("\n=== GCD of Multiple Integers ===")

    numbers = [84, 126, 210, 294]

    print(f"Numbers: {numbers}")
    print(f"GCD: {gcd_many(numbers)}")


# ============================================================================
# 6. COPRIME NUMBERS
# ============================================================================

def are_coprime(a: int, b: int) -> bool:
    """
    Two integers are coprime if their GCD is 1.
    """
    return gcd_euclidean_iterative(a, b) == 1


def demonstrate_coprimality() -> None:
    print("\n=== Coprimality ===")

    pairs = [
        (8, 15),
        (14, 21),
        (35, 64),
        (17, 34),
    ]

    for a, b in pairs:
        print(f"{a} and {b} are coprime: {are_coprime(a, b)}")


# ============================================================================
# 7. LCM USING GCD
# ============================================================================

def lcm(a: int, b: int) -> int:
    """
    Compute the least common multiple.

    For nonzero integers:

        lcm(a, b) = |a*b| / gcd(a, b)

    Division is performed before multiplication to reduce intermediate
    integer growth.
    """
    if a == 0 or b == 0:
        return 0

    return abs(a // gcd_euclidean_iterative(a, b) * b)


def lcm_many(numbers: Iterable[int]) -> int:
    """
    Compute the LCM of multiple integers.
    """
    iterator = iter(numbers)

    try:
        result = next(iterator)
    except StopIteration:
        raise ValueError("At least one integer is required.")

    for number in iterator:
        result = lcm(result, number)

    return abs(result)


def demonstrate_lcm() -> None:
    print("\n=== LCM ===")

    a, b = 84, 30

    print(f"gcd({a}, {b}) = {gcd_euclidean_iterative(a, b)}")
    print(f"lcm({a}, {b}) = {lcm(a, b)}")
    print(f"lcm(4, 6, 10) = {lcm_many([4, 6, 10])}")


# ============================================================================
# 8. WHY THE EUCLIDEAN ALGORITHM IS CORRECT
# ============================================================================

def demonstrate_correctness_invariant() -> None:
    """
    Demonstrate the invariant:

        gcd(a, b) = gcd(b, a mod b)

    at every stage.

    This is the central mathematical justification for the algorithm.
    """
    a = 1071
    b = 462

    print("\n=== Correctness Invariant ===")

    while b != 0:
        old_gcd = gcd_euclidean_iterative(a, b)
        remainder = a % b
        new_gcd = gcd_euclidean_iterative(b, remainder)

        print(
            f"gcd({a}, {b}) = {old_gcd}; "
            f"gcd({b}, {remainder}) = {new_gcd}"
        )

        a, b = b, remainder


# ============================================================================
# 9. TERMINATION
# ============================================================================

def explain_termination_with_code(a: int, b: int) -> None:
    """
    The remainder is always strictly smaller than the divisor.

    Therefore, the sequence of nonnegative remainders strictly decreases:

        r0 > r1 > r2 > ...

    A strictly decreasing sequence of nonnegative integers cannot continue
    forever, so the algorithm must terminate.
    """
    a = abs(a)
    b = abs(b)

    print("\n=== Termination Demonstration ===")

    while b:
        remainder = a % b
        print(f"Current pair: ({a}, {b}), next remainder: {remainder}")
        a, b = b, remainder

    print("The divisor reached zero, so the algorithm terminated.")


# ============================================================================
# 10. EXTENDED EUCLIDEAN ALGORITHM
# ============================================================================

@dataclass(frozen=True)
class ExtendedGCDResult:
    gcd: int
    x: int
    y: int


def extended_gcd(a: int, b: int) -> ExtendedGCDResult:
    """
    Extended Euclidean algorithm.

    Returns g, x, y satisfying:

        g = gcd(a, b)
        ax + by = g

    This equation is Bézout's identity.

    The implementation supports negative integers.
    """
    original_a = a
    original_b = b

    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    x = old_s if original_a >= 0 else -old_s
    y = old_t if original_b >= 0 else -old_t

    return ExtendedGCDResult(old_r, x, y)


def demonstrate_extended_gcd() -> None:
    print("\n=== Extended Euclidean Algorithm ===")

    a, b = 240, 46
    result = extended_gcd(a, b)

    print(f"gcd({a}, {b}) = {result.gcd}")
    print(f"x = {result.x}")
    print(f"y = {result.y}")
    print(f"{a}*{result.x} + {b}*{result.y} = "
          f"{a * result.x + b * result.y}")


# ============================================================================
# 11. MODULAR MULTIPLICATIVE INVERSE
# ============================================================================

def modular_inverse(a: int, modulus: int) -> int:
    """
    Find x such that:

        ax ≡ 1 (mod modulus)

    Such an inverse exists exactly when:

        gcd(a, modulus) = 1

    The extended Euclidean algorithm provides the required coefficient.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    result = extended_gcd(a, modulus)

    if result.gcd != 1:
        raise ValueError(
            f"No modular inverse exists because gcd({a}, {modulus}) "
            f"= {result.gcd}, not 1."
        )

    return result.x % modulus


def demonstrate_modular_inverse() -> None:
    print("\n=== Modular Multiplicative Inverse ===")

    a = 17
    modulus = 3120

    inverse = modular_inverse(a, modulus)

    print(f"Inverse of {a} modulo {modulus}: {inverse}")
    print(f"({a} * {inverse}) % {modulus} = "
          f"{(a * inverse) % modulus}")

    try:
        modular_inverse(6, 15)
    except ValueError as error:
        print(f"Expected failure: {error}")


# ============================================================================
# 12. LINEAR DIOPHANTINE EQUATIONS
# ============================================================================

def solve_linear_diophantine(a: int, b: int, c: int) -> tuple[int, int]:
    """
    Find one integer solution to:

        ax + by = c

    A solution exists if and only if:

        gcd(a, b) divides c

    If g = gcd(a, b), the extended algorithm gives:

        ax0 + by0 = g

    Multiplying by c/g gives a solution for c.
    """
    if a == 0 and b == 0:
        if c == 0:
            return 0, 0
        raise ValueError("No solution exists.")

    result = extended_gcd(a, b)

    if c % result.gcd != 0:
        raise ValueError(
            f"No integer solution because gcd({a}, {b}) = {result.gcd} "
            f"does not divide {c}."
        )

    multiplier = c // result.gcd

    x = result.x * multiplier
    y = result.y * multiplier

    return x, y


def demonstrate_diophantine_equation() -> None:
    print("\n=== Linear Diophantine Equation ===")

    a, b, c = 15, 25, 5
    x, y = solve_linear_diophantine(a, b, c)

    print(f"Equation: {a}x + {b}y = {c}")
    print(f"One solution: x = {x}, y = {y}")
    print(f"Verification: {a}*{x} + {b}*{y} = {a*x + b*y}")


# ============================================================================
# 13. ALL SOLUTIONS TO A LINEAR DIOPHANTINE EQUATION
# ============================================================================

def diophantine_solution_family(
    a: int,
    b: int,
    c: int,
) -> tuple[int, int, int, int]:
    """
    Return one solution and the step sizes for all integer solutions.

    If:

        ax + by = c

    and (x0, y0) is one solution, then all solutions are:

        x = x0 + k(b/g)
        y = y0 - k(a/g)

    where:

        g = gcd(a, b)
        k is any integer.
    """
    x0, y0 = solve_linear_diophantine(a, b, c)
    g = gcd_euclidean_iterative(a, b)

    return x0, y0, b // g, -a // g


def demonstrate_solution_family() -> None:
    print("\n=== Diophantine Solution Family ===")

    a, b, c = 15, 25, 5
    x0, y0, dx, dy = diophantine_solution_family(a, b, c)

    print(f"Base solution: ({x0}, {y0})")
    print(f"General form: x = {x0} + k*({dx})")
    print(f"General form: y = {y0} + k*({dy})")

    for k in range(-2, 3):
        x = x0 + k * dx
        y = y0 + k * dy
        print(f"k={k:>2}: x={x:>4}, y={y:>4}, "
              f"equation value={a*x + b*y}")


# ============================================================================
# 14. REDUCING FRACTIONS
# ============================================================================

def reduce_fraction(numerator: int, denominator: int) -> tuple[int, int]:
    """
    Reduce a fraction using the GCD.

    The denominator cannot be zero.
    The denominator is normalized to positive form.
    """
    if denominator == 0:
        raise ZeroDivisionError("A fraction cannot have denominator zero.")

    divisor = gcd_euclidean_iterative(numerator, denominator)

    numerator //= divisor
    denominator //= divisor

    if denominator < 0:
        numerator = -numerator
        denominator = -denominator

    return numerator, denominator


def demonstrate_fraction_reduction() -> None:
    print("\n=== Fraction Reduction ===")

    numerator, denominator = 150, 210
    reduced = reduce_fraction(numerator, denominator)

    print(f"{numerator}/{denominator} = {reduced[0]}/{reduced[1]}")


# ============================================================================
# 15. GCD OF POLYNOMIAL COEFFICIENTS
# ============================================================================

def gcd_of_coefficients(coefficients: Iterable[int]) -> int:
    """
    Compute the integer GCD of polynomial coefficients.

    For example:

        12x^3 + 18x^2 + 30x

    has coefficient GCD 6.
    """
    return gcd_many(coefficients)


def demonstrate_polynomial_content() -> None:
    print("\n=== Polynomial Coefficient GCD ===")

    coefficients = [12, 18, 30]
    print(f"Coefficients: {coefficients}")
    print(f"Content: {gcd_of_coefficients(coefficients)}")


# ============================================================================
# 16. CONTINUED-FRACTION CONNECTION
# ============================================================================

def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """
    Produce the simple continued fraction coefficients of a rational number.

    The quotient sequence is exactly the quotient sequence generated by
    the Euclidean algorithm.
    """
    if denominator == 0:
        raise ZeroDivisionError("Denominator cannot be zero.")

    coefficients: list[int] = []

    numerator, denominator = (
        numerator if denominator > 0 else -numerator,
        abs(denominator),
    )

    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        coefficients.append(quotient)
        numerator, denominator = denominator, remainder

    return coefficients


def demonstrate_continued_fraction_connection() -> None:
    print("\n=== Continued Fraction Connection ===")

    numerator, denominator = 415, 93
    coefficients = continued_fraction(numerator, denominator)

    print(f"{numerator}/{denominator}")
    print(f"Continued-fraction coefficients: {coefficients}")
    print("These quotients are the quotients produced by Euclid's algorithm.")


# ============================================================================
# 17. GCD-BASED VALIDATION OF A CONGRUENCE
# ============================================================================

def linear_congruence_has_solution(a: int, b: int, modulus: int) -> bool:
    """
    Determine whether:

        ax ≡ b (mod modulus)

    has an integer solution.

    A solution exists exactly when:

        gcd(a, modulus) divides b.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    return b % gcd_euclidean_iterative(a, modulus) == 0


def demonstrate_linear_congruence() -> None:
    print("\n=== Linear Congruence Solvability ===")

    examples = [
        (6, 8, 14),
        (6, 7, 14),
        (5, 3, 11),
    ]

    for a, b, modulus in examples:
        possible = linear_congruence_has_solution(a, b, modulus)
        print(f"{a}x ≡ {b} (mod {modulus}) -> solution exists: {possible}")


# ============================================================================
# 18. A SMALL RSA MATHEMATICAL DEMONSTRATION
# ============================================================================

def rsa_toy_key_generation(
    p: int,
    q: int,
    e: int,
) -> tuple[int, int, int, int, int]:
    """
    Demonstrate the mathematical role of GCD in a simplified RSA setup.

    This is educational only and is NOT a production cryptographic
    implementation.

    Requirements:
        p and q are distinct primes.
        n = p*q
        phi(n) = (p-1)(q-1)
        gcd(e, phi(n)) = 1
        d = e^(-1) mod phi(n)
    """
    if p <= 1 or q <= 1 or p == q:
        raise ValueError("p and q must be distinct integers greater than 1.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd_euclidean_iterative(e, phi) != 1:
        raise ValueError("e must be coprime with phi(n).")

    d = modular_inverse(e, phi)

    return p, q, n, phi, d


def demonstrate_rsa_math() -> None:
    print("\n=== RSA Mathematical Connection ===")

    p, q, e = 61, 53, 17

    result = rsa_toy_key_generation(p, q, e)
    _, _, n, phi, d = result

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = {n}")
    print(f"phi(n) = {phi}")
    print(f"e = {e}")
    print(f"gcd(e, phi(n)) = {gcd_euclidean_iterative(e, phi)}")
    print(f"d = {d}")
    print(f"(e*d) % phi(n) = {(e*d) % phi}")


# ============================================================================
# 19. FAST MODULAR EXPONENTIATION
# ============================================================================

def modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Compute:

        base^exponent mod modulus

    using repeated squaring.

    Although this is not itself the Euclidean algorithm, it frequently
    appears beside GCD and modular-inverse operations in number theory.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    if exponent < 0:
        raise ValueError("Exponent must be nonnegative.")

    result = 1 % modulus
    base %= modulus

    while exponent:
        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent >>= 1

    return result


def demonstrate_modular_power() -> None:
    print("\n=== Repeated-Squaring Modular Exponentiation ===")

    base = 7
    exponent = 128
    modulus = 13

    result = modular_power(base, exponent, modulus)

    print(f"{base}^{exponent} mod {modulus} = {result}")
    print(f"Python verification: {pow(base, exponent, modulus)}")


# ============================================================================
# 20. FIBONACCI NUMBERS AND EUCLIDEAN COMPLEXITY
# ============================================================================

def fibonacci(n: int) -> int:
    """
    Compute the nth Fibonacci number iteratively.
    """
    if n < 0:
        raise ValueError("n must be nonnegative.")

    a, b = 0, 1

    for _ in range(n):
        a, b = b, a + b

    return a


def demonstrate_fibonacci_connection() -> None:
    """
    Consecutive Fibonacci numbers form worst-case-style inputs for the
    number of Euclidean divisions.

    This connection is central to understanding why the number of iterations
    grows only logarithmically with the magnitude of the inputs.
    """
    print("\n=== Fibonacci and Euclidean Algorithm ===")

    for n in range(5, 16):
        a = fibonacci(n + 1)
        b = fibonacci(n)
        steps = len(euclidean_steps(a, b))

        print(
            f"F({n+1})={a:<6}, "
            f"F({n})={b:<5}, "
            f"Euclidean divisions={steps}"
        )


# ============================================================================
# 21. BRUTE FORCE VS EUCLIDEAN ALGORITHM
# ============================================================================

def compare_gcd_methods(a: int, b: int) -> None:
    """
    Compare the educational brute-force method with Euclid's algorithm.

    The exact timing depends on hardware and Python version, so the numbers
    are illustrative rather than universal benchmarks.
    """
    print("\n=== Brute Force vs Euclidean Algorithm ===")

    start = perf_counter()
    brute_result = gcd_by_definition(a, b)
    brute_time = perf_counter() - start

    start = perf_counter()
    euclid_result = gcd_euclidean_iterative(a, b)
    euclid_time = perf_counter() - start

    print(f"Brute-force result: {brute_result}")
    print(f"Euclidean result:   {euclid_result}")
    print(f"Brute-force time:   {brute_time:.8f} seconds")
    print(f"Euclidean time:     {euclid_time:.8f} seconds")


# ============================================================================
# 22. RANDOMIZED PROPERTY TESTING
# ============================================================================

def property_test_gcd(number_of_tests: int = 1000) -> None:
    """
    Test important GCD identities on randomly generated integer pairs.

    Identities tested:
        gcd(a, b) == gcd(b, a)
        gcd(a, 0) == |a|
        gcd(a, b) == gcd(a, b + ka)
        gcd(a, b) divides both a and b
    """
    print("\n=== Randomized GCD Property Testing ===")

    for _ in range(number_of_tests):
        a = randint(-100_000, 100_000)
        b = randint(-100_000, 100_000)

        if a == 0 and b == 0:
            continue

        g = gcd_euclidean_iterative(a, b)

        assert g == gcd_euclidean_iterative(b, a)
        assert g == gcd_euclidean_iterative(a, 0 if b == 0 else b)
        assert g >= 0

        if a != 0:
            assert a % g == 0

        if b != 0:
            assert b % g == 0

        k = randint(-100, 100)
        assert g == gcd_euclidean_iterative(a, b + k * a)

        assert g == math_gcd(a, b)

    print(f"All {number_of_tests} randomized property tests passed.")


# ============================================================================
# 23. IMPORTANT GCD IDENTITIES
# ============================================================================

def demonstrate_gcd_identities() -> None:
    print("\n=== Important GCD Identities ===")

    a, b = 84, 30
    k = 7

    print(f"gcd(a, b) = gcd(b, a): "
          f"{gcd_euclidean_iterative(a, b) == gcd_euclidean_iterative(b, a)}")

    print(
        f"gcd(a, b) = gcd(a, b + k*a): "
        f"{gcd_euclidean_iterative(a, b) == gcd_euclidean_iterative(a, b + k*a)}"
    )

    print(
        f"gcd(ka, kb) = |k|*gcd(a,b): "
        f"{gcd_euclidean_iterative(k*a, k*b) == "
        f"abs(k)*gcd_euclidean_iterative(a,b)}"
    )

    print(
        f"gcd(a, lcm(a,b)) = |a|: "
        f"{gcd_euclidean_iterative(a, lcm(a,b)) == abs(a)}"
    )


# ============================================================================
# 24. COMMON IMPLEMENTATION MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n=== Common Implementation Mistakes ===")

    print("Mistake 1: Forgetting absolute values for negative inputs.")
    print("Correct result for gcd(-48, 18):",
          gcd_euclidean_iterative(-48, 18))

    print("\nMistake 2: Dividing by zero before checking the base case.")
    print("Correct base case: gcd(a, 0) = |a|.")

    print("\nMistake 3: Using multiplication before division in LCM.")
    print("Safer expression: abs((a // gcd(a,b)) * b).")

    print("\nMistake 4: Assuming every number has a modular inverse.")
    print("An inverse exists only when gcd(a, modulus) = 1.")

    print("\nMistake 5: Treating gcd(0, 0) as an ordinary positive GCD.")
    print("This pair has no uniquely defined greatest positive common divisor.")


# ============================================================================
# 25. EXPLICIT INPUT VALIDATION
# ============================================================================

def validate_integer(value: object, name: str = "value") -> int:
    """
    Validate that a value is an integer.

    bool is rejected because bool is a subclass of int in Python and can
    otherwise accidentally enter mathematical functions as 0 or 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer.")

    return value


def safe_gcd(a: object, b: object) -> int:
    """
    Type-checked public-facing GCD wrapper.
    """
    a = validate_integer(a, "a")
    b = validate_integer(b, "b")

    return gcd_euclidean_iterative(a, b)


def demonstrate_validation() -> None:
    print("\n=== Input Validation ===")

    print("safe_gcd(84, 30) =", safe_gcd(84, 30))

    for invalid_pair in [(84.0, 30), (True, 30), ("84", 30)]:
        try:
            safe_gcd(*invalid_pair)
        except TypeError as error:
            print(f"Rejected {invalid_pair!r}: {error}")


# ============================================================================
# 26. UNIT TESTS
# ============================================================================

def run_unit_tests() -> None:
    """
    Deterministic tests for important cases.
    """
    print("\n=== Unit Tests ===")

    known_cases = {
        (48, 18): 6,
        (18, 48): 6,
        (-48, 18): 6,
        (-48, -18): 6,
        (0, 18): 18,
        (18, 0): 18,
        (1, 999): 1,
        (17, 13): 1,
        (270, 192): 6,
        (1071, 462): 21,
    }

    for (a, b), expected in known_cases.items():
        actual = gcd_euclidean_iterative(a, b)
        assert actual == expected, (a, b, actual, expected)

    assert lcm(21, 6) == 42
    assert lcm(0, 10) == 0
    assert are_coprime(35, 64)
    assert not are_coprime(12, 18)

    extended = extended_gcd(240, 46)
    assert extended.gcd == 2
    assert 240 * extended.x + 46 * extended.y == extended.gcd

    inverse = modular_inverse(3, 11)
    assert inverse == 4
    assert (3 * inverse) % 11 == 1

    x, y = solve_linear_diophantine(15, 25, 5)
    assert 15 * x + 25 * y == 5

    print(f"Passed {len(known_cases)} deterministic GCD cases and related tests.")


# ============================================================================
# 27. LARGE-INTEGER EXAMPLE
# ============================================================================

def demonstrate_large_integers() -> None:
    """
    Python integers have arbitrary precision, so the Euclidean algorithm can
    operate directly on very large integers.

    Runtime is determined by the size of the operands and the sequence of
    quotient/remainder operations, not by a fixed machine integer width.
    """
    print("\n=== Large Integer Example ===")

    a = 10**100 + 123456789
    b = 10**80 + 987654321

    result = gcd_euclidean_iterative(a, b)

    print(f"Number of digits in a: {len(str(a))}")
    print(f"Number of digits in b: {len(str(b))}")
    print(f"Number of digits in GCD: {len(str(result))}")
    print(f"GCD: {result}")


# ============================================================================
# 28. GCD IN ARRAY NORMALIZATION
# ============================================================================

def normalize_integer_list(numbers: Iterable[int]) -> list[int]:
    """
    Divide every number by the common GCD.

    This is useful when an integer vector or coefficient list contains a
    common scaling factor.
    """
    values = list(numbers)

    if not values:
        raise ValueError("At least one integer is required.")

    common = gcd_many(values)

    if common == 0:
        return values

    return [value // common for value in values]


def demonstrate_normalization() -> None:
    print("\n=== Integer List Normalization ===")

    values = [84, 126, 210]
    print(f"Original:   {values}")
    print(f"Normalized: {normalize_integer_list(values)}")


# ============================================================================
# 29. PERFORMANCE CHARACTERISTICS
# ============================================================================

def count_euclidean_divisions(a: int, b: int) -> int:
    """
    Count the number of division steps in Euclid's algorithm.
    """
    return len(euclidean_steps(a, b))


def demonstrate_step_counts() -> None:
    print("\n=== Euclidean Step Counts ===")

    examples = [
        (100, 40),
        (1000, 37),
        (fibonacci(20), fibonacci(19)),
        (fibonacci(40), fibonacci(39)),
    ]

    for a, b in examples:
        print(
            f"gcd({a}, {b}) = {gcd_euclidean_iterative(a,b)}, "
            f"divisions = {count_euclidean_divisions(a,b)}"
        )


# ============================================================================
# 30. RELATIONSHIP WITH PYTHON'S BUILT-IN IMPLEMENTATION
# ============================================================================

def compare_with_standard_library() -> None:
    print("\n=== Comparison with Python Standard Library ===")

    test_cases = [
        (0, 0),
        (0, 12),
        (-42, 18),
        (123456, 7890),
    ]

    for a, b in test_cases:
        custom = gcd_euclidean_iterative(a, b)
        standard = math_gcd(a, b)

        print(
            f"gcd({a}, {b}): "
            f"custom={custom}, "
            f"math.gcd={standard}, "
            f"equal={custom == standard}"
        )


# ============================================================================
# 31. PRACTICAL NUMBER-THEORY WORKFLOW
# ============================================================================

def number_theory_workflow(a: int, b: int) -> None:
    """
    Combine several Euclidean-algorithm-based operations for two integers.
    """
    print("\n=== Practical Number-Theory Workflow ===")

    g = gcd_euclidean_iterative(a, b)

    print(f"a = {a}")
    print(f"b = {b}")
    print(f"GCD = {g}")
    print(f"Coprime = {g == 1}")
    print(f"LCM = {lcm(a, b)}")

    extended = extended_gcd(a, b)
    print(
        f"Bézout coefficients: x={extended.x}, y={extended.y}"
    )
    print(
        f"Verification: {a}*{extended.x} + "
        f"{b}*{extended.y} = {extended.gcd}"
    )

    if g == 1 and b > 1:
        inverse = modular_inverse(a, b)
        print(f"Inverse of {a} modulo {b} = {inverse}")
    else:
        print(
            "A modular inverse of a modulo b does not necessarily exist "
            "because gcd(a, b) is not 1."
        )


# ============================================================================
# 32. ADVANCED PROPERTY: GCD OF PRODUCTS
# ============================================================================

def demonstrate_product_identity() -> None:
    """
    For positive integers:

        gcd(a,b) * lcm(a,b) = |ab|

    This follows directly from the GCD/LCM relationship.
    """
    print("\n=== GCD-LCM Product Identity ===")

    a, b = 84, 30
    left = gcd_euclidean_iterative(a, b) * lcm(a, b)
    right = abs(a * b)

    print(f"gcd(a,b) * lcm(a,b) = {left}")
    print(f"|a*b| = {right}")
    print(f"Identity holds: {left == right}")


# ============================================================================
# 33. ADVANCED PROPERTY: EUCLID'S LEMMA CONTEXT
# ============================================================================

def demonstrate_euclids_lemma_context() -> None:
    """
    Euclid's lemma states:

        If gcd(a, b) = 1 and a divides bc,
        then a divides c.

    The implementation below verifies the divisibility condition for a
    concrete example.
    """
    print("\n=== Euclid's Lemma Context ===")

    a = 5
    b = 6
    c = 10

    product = b * c

    print(f"gcd({a}, {b}) = {gcd_euclidean_iterative(a, b)}")
    print(f"{a} divides {product}: {product % a == 0}")
    print(f"{a} divides {c}: {c % a == 0}")


# ============================================================================
# 34. GCD OF RATIONAL-LIKE PAIRS
# ============================================================================

def gcd_ratio(
    numerator_a: int,
    denominator_a: int,
    numerator_b: int,
    denominator_b: int,
) -> tuple[int, int]:
    """
    Find the greatest rational scaling represented by two rational values.

    This educational helper first normalizes both fractions, then uses
    integer GCD operations where appropriate.

    It demonstrates that GCD techniques extend naturally to structured
    integer representations.
    """
    a_num, a_den = reduce_fraction(numerator_a, denominator_a)
    b_num, b_den = reduce_fraction(numerator_b, denominator_b)

    common_numerator = gcd_euclidean_iterative(a_num, b_num)
    common_denominator = lcm(a_den, b_den)

    return reduce_fraction(common_numerator, common_denominator)


def demonstrate_structured_values() -> None:
    print("\n=== GCD-Based Structured Integer Operations ===")

    result = gcd_ratio(12, 5, 18, 7)

    print(f"Resulting reduced ratio: {result[0]}/{result[1]}")


# ============================================================================
# 35. MAIN DEMONSTRATION
# ============================================================================

def main() -> None:
    """
    Run the complete educational demonstration in a logical progression.
    """
    print("=" * 78)
    print("EUCLIDEAN ALGORITHM: COMPLETE PYTHON STUDY SCRIPT")
    print("=" * 78)

    demonstrate_division_algorithm()
    demonstrate_remainder_properties()
    demonstrate_basic_gcd()
    print_euclidean_steps(1071, 462)
    demonstrate_edge_cases()
    demonstrate_gcd_many()
    demonstrate_coprimality()
    demonstrate_lcm()
    demonstrate_correctness_invariant()
    explain_termination_with_code(1071, 462)
    demonstrate_extended_gcd()
    demonstrate_modular_inverse()
    demonstrate_diophantine_equation()
    demonstrate_solution_family()
    demonstrate_fraction_reduction()
    demonstrate_polynomial_content()
    demonstrate_continued_fraction_connection()
    demonstrate_linear_congruence()
    demonstrate_rsa_math()
    demonstrate_modular_power()
    demonstrate_fibonacci_connection()
    compare_gcd_methods(1_000_003, 1_000_033)
    property_test_gcd()
    demonstrate_gcd_identities()
    demonstrate_common_mistakes()
    demonstrate_validation()
    run_unit_tests()
    demonstrate_large_integers()
    demonstrate_normalization()
    demonstrate_step_counts()
    compare_with_standard_library()
    number_theory_workflow(240, 46)
    demonstrate_product_identity()
    demonstrate_euclids_lemma_context()
    demonstrate_structured_values()

    print("\n" + "=" * 78)
    print("ALL DEMONSTRATIONS COMPLETED")
    print("=" * 78)


if __name__ == "__main__":
    main()
