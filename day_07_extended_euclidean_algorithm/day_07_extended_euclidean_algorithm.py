"""
Extended Euclidean Algorithm
============================

A comprehensive, executable study file covering the Extended Euclidean Algorithm
from absolute beginner concepts through advanced applications.

Topics demonstrated:
    1. Greatest Common Divisor (GCD)
    2. Euclidean Algorithm
    3. Bézout's Identity
    4. Extended Euclidean Algorithm
    5. Iterative and recursive implementations
    6. Verification and invariants
    7. Modular inverses
    8. Linear Diophantine equations
    9. Solving systems of congruences
    10. Chinese Remainder Theorem
    11. RSA-related modular arithmetic
    12. Fraction reduction and rational arithmetic
    13. Edge cases and failure conditions
    14. Complexity and performance
    15. Testing and property-based style verification
    16. Generalizations and implementation considerations

The script uses only Python's standard library.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd
from random import Random
from typing import Iterable, List, Optional, Sequence, Tuple


# =============================================================================
# 1. BASIC TERMINOLOGY AND INTUITION
# =============================================================================

def explain_gcd(a: int, b: int) -> int:
    """
    Return the greatest common divisor of a and b.

    The GCD is the largest positive integer that divides both numbers.

    Important mathematical properties:
        gcd(a, b) = gcd(b, a)
        gcd(a, b) = gcd(|a|, |b|)
        gcd(a, 0) = |a|
        gcd(0, 0) = 0 by Python's math.gcd convention

    The function below deliberately uses the built-in gcd for a simple
    reference implementation. The Euclidean algorithm itself is implemented
    separately later.
    """
    return gcd(a, b)


def divisors(n: int) -> List[int]:
    """Return the positive divisors of a nonzero integer."""
    n = abs(n)

    if n == 0:
        raise ValueError("Zero has infinitely many integer divisors.")

    return [d for d in range(1, n + 1) if n % d == 0]


def demonstrate_gcd() -> None:
    """Show the meaning of a greatest common divisor."""
    a, b = 48, 18

    print("\n=== GCD Fundamentals ===")
    print(f"Divisors of {a}: {divisors(a)}")
    print(f"Divisors of {b}: {divisors(b)}")
    print(f"gcd({a}, {b}) = {explain_gcd(a, b)}")

    print("\nCommon divisors:", sorted(set(divisors(a)) & set(divisors(b))))
    print("The greatest common divisor is 6.")


# =============================================================================
# 2. THE EUCLIDEAN ALGORITHM
# =============================================================================

def euclidean_gcd_recursive(a: int, b: int) -> int:
    """
    Compute gcd(a, b) recursively using the Euclidean algorithm.

    Core rule:
        gcd(a, b) = gcd(b, a mod b)

    The process terminates when the second argument becomes zero.

    Example:
        gcd(48, 18)
        = gcd(18, 12)
        = gcd(12, 6)
        = gcd(6, 0)
        = 6
    """
    a = abs(a)
    b = abs(b)

    if b == 0:
        return a

    return euclidean_gcd_recursive(b, a % b)


def euclidean_gcd_iterative(a: int, b: int) -> int:
    """
    Compute gcd(a, b) iteratively.

    Iteration avoids recursion depth concerns and is generally preferred for
    production code when only the GCD is needed.
    """
    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a


def euclidean_trace(a: int, b: int) -> List[Tuple[int, int, int, int]]:
    """
    Return the division steps of the Euclidean algorithm.

    Each tuple is:
        (dividend, divisor, quotient, remainder)

    For example, gcd(48, 18) produces:
        48 = 18 * 2 + 12
        18 = 12 * 1 + 6
        12 = 6  * 2 + 0
    """
    a = abs(a)
    b = abs(b)

    if a < b:
        a, b = b, a

    steps = []

    while b != 0:
        quotient, remainder = divmod(a, b)
        steps.append((a, b, quotient, remainder))
        a, b = b, remainder

    return steps


def print_euclidean_trace(a: int, b: int) -> None:
    """Print the Euclidean division sequence."""
    print(f"\n=== Euclidean Algorithm Trace for gcd({a}, {b}) ===")

    steps = euclidean_trace(a, b)

    if not steps:
        print(f"gcd({a}, {b}) = 0")
        return

    for dividend, divisor, quotient, remainder in steps:
        print(
            f"{dividend} = {divisor} * {quotient} + {remainder}"
        )

    print(f"GCD = {steps[-1][1]}")


# =============================================================================
# 3. BÉZOUT'S IDENTITY
# =============================================================================

def demonstrate_bezout_identity() -> None:
    """
    Demonstrate Bézout's Identity.

    For integers a and b, there exist integers x and y such that:

        ax + by = gcd(a, b)

    The Extended Euclidean Algorithm finds such x and y.
    """
    a, b = 48, 18

    # One valid Bézout representation is:
    #     48 * (-1) + 18 * 3 = 6
    x, y = -1, 3

    print("\n=== Bézout's Identity ===")
    print(f"{a} * ({x}) + {b} * ({y}) = {a * x + b * y}")
    print(f"gcd({a}, {b}) = {gcd(a, b)}")

    assert a * x + b * y == gcd(a, b)


# =============================================================================
# 4. BASIC EXTENDED EUCLIDEAN ALGORITHM
# =============================================================================

@dataclass(frozen=True)
class ExtendedGCDResult:
    """
    Result of the Extended Euclidean Algorithm.

    Attributes:
        gcd:
            The greatest common divisor.
        x:
            Coefficient of the first input.
        y:
            Coefficient of the second input.

    The defining invariant is:

        a * x + b * y = gcd

    """
    gcd: int
    x: int
    y: int

    def verify(self, a: int, b: int) -> bool:
        """Verify Bézout's identity for the stored coefficients."""
        return a * self.x + b * self.y == self.gcd


def extended_gcd_recursive(a: int, b: int) -> ExtendedGCDResult:
    """
    Recursive Extended Euclidean Algorithm.

    Returns (g, x, y) such that:

        ax + by = g
        g = gcd(a, b)

    Derivation:

        Suppose:
            b * x1 + (a mod b) * y1 = g

        Since:
            a mod b = a - floor(a/b) * b

        Substitute:

            b*x1 + (a - q*b)*y1 = g

        Rearranging:

            a*y1 + b*(x1 - q*y1) = g

        Therefore:

            x = y1
            y = x1 - q*y1

    Python's divmod handles the quotient/remainder relationship consistently
    with Python's modulo semantics.
    """
    if b == 0:
        g = abs(a)

        # If a is negative, x = -1 makes:
        #     a * (-1) = |a|
        # If a is positive, x = 1 is sufficient.
        x = 1 if a >= 0 else -1

        return ExtendedGCDResult(g, x, 0)

    quotient, remainder = divmod(a, b)

    result = extended_gcd_recursive(b, remainder)

    x = result.y
    y = result.x - quotient * result.y

    return ExtendedGCDResult(result.gcd, x, y)


def extended_gcd_iterative(a: int, b: int) -> ExtendedGCDResult:
    """
    Iterative Extended Euclidean Algorithm.

    This implementation tracks two coefficient pairs.

    Initially:
        old_r = a
        r     = b

        old_s = 1
        s     = 0

        old_t = 0
        t     = 1

    At every iteration:

        old_r = old_q * r + new_r

    and the same quotient is applied to the coefficient sequences.

    At termination:
        old_r = gcd(a, b)
        old_s = x
        old_t = y

    such that:
        a*x + b*y = gcd(a, b)
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # Normalize the GCD to be nonnegative.
    if old_r < 0:
        old_r = -old_r
        old_s = -old_s
        old_t = -old_t

    return ExtendedGCDResult(old_r, old_s, old_t)


def demonstrate_extended_gcd() -> None:
    """Demonstrate recursive and iterative Extended GCD."""
    print("\n=== Extended Euclidean Algorithm ===")

    a, b = 48, 18

    recursive_result = extended_gcd_recursive(a, b)
    iterative_result = extended_gcd_iterative(a, b)

    print(
        f"Recursive: gcd={recursive_result.gcd}, "
        f"x={recursive_result.x}, y={recursive_result.y}"
    )

    print(
        f"Iterative: gcd={iterative_result.gcd}, "
        f"x={iterative_result.x}, y={iterative_result.y}"
    )

    print(
        f"Verification: "
        f"{a}*({iterative_result.x}) + "
        f"{b}*({iterative_result.y}) = "
        f"{a * iterative_result.x + b * iterative_result.y}"
    )

    assert recursive_result.verify(a, b)
    assert iterative_result.verify(a, b)


# =============================================================================
# 5. STEP-BY-STEP COEFFICIENT TABLE
# =============================================================================

def extended_gcd_trace(
    a: int,
    b: int
) -> List[Tuple[int, int, int, int, int, int]]:
    """
    Produce a detailed Extended Euclidean Algorithm trace.

    Each row contains:

        quotient
        remainder
        x coefficient
        y coefficient
        current relation
        verification value

    The coefficient tracking makes it possible to see how Bézout coefficients
    emerge from the Euclidean divisions.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    trace = []

    while r != 0:
        quotient = old_r // r
        new_r = old_r - quotient * r
        new_s = old_s - quotient * s
        new_t = old_t - quotient * t

        trace.append(
            (
                quotient,
                new_r,
                new_s,
                new_t,
                a * new_s + b * new_t,
                old_r,
            )
        )

        old_r, r = r, new_r
        old_s, s = s, new_s
        old_t, t = t, new_t

    return trace


def print_extended_trace(a: int, b: int) -> None:
    """Print a human-readable coefficient trace."""
    print(f"\n=== Extended GCD Trace for ({a}, {b}) ===")
    print(
        f"{'q':>5} {'remainder':>12} "
        f"{'x':>12} {'y':>12} {'ax+by':>12}"
    )
    print("-" * 59)

    for quotient, remainder, x, y, combination, _ in extended_gcd_trace(a, b):
        print(
            f"{quotient:>5} {remainder:>12} "
            f"{x:>12} {y:>12} {combination:>12}"
        )

    result = extended_gcd_iterative(a, b)
    print(
        f"\nFinal: {a}*({result.x}) + "
        f"{b}*({result.y}) = {result.gcd}"
    )


# =============================================================================
# 6. WHY THE ALGORITHM WORKS
# =============================================================================

def explain_invariant_with_code() -> None:
    """
    Demonstrate the central invariant:

        old_r = a*old_s + b*old_t
        r     = a*s     + b*t

    Every transformation preserves these linear combinations.

    This is the key reason the Extended Euclidean Algorithm produces Bézout
    coefficients rather than merely producing the GCD.
    """
    print("\n=== Extended GCD Invariant ===")

    a, b = 99, 78

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    iteration = 0

    while r != 0:
        assert old_r == a * old_s + b * old_t
        assert r == a * s + b * t

        print(
            f"Iteration {iteration}: "
            f"old_r={old_r}, r={r}, "
            f"old_s={old_s}, s={s}, "
            f"old_t={old_t}, t={t}"
        )

        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

        iteration += 1

    assert old_r == a * old_s + b * old_t

    print(
        f"Final invariant: {a}*{old_s} + "
        f"{b}*{old_t} = {old_r}"
    )


# =============================================================================
# 7. MODULAR ARITHMETIC FUNDAMENTALS
# =============================================================================

def normalize_mod(value: int, modulus: int) -> int:
    """
    Return the canonical nonnegative residue modulo modulus.

    Example:
        normalize_mod(-3, 7) == 4

    A positive modulus is required.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")

    return value % modulus


def demonstrate_modular_arithmetic() -> None:
    """Demonstrate basic congruence behavior."""
    print("\n=== Modular Arithmetic ===")

    a = 29
    modulus = 7

    print(f"{a} mod {modulus} = {a % modulus}")
    print(f"-3 mod 7 = {-3 % 7}")

    print(
        "29 and 1 are congruent modulo 7:",
        (29 - 1) % 7 == 0
    )

    print(
        "Multiplication preserves congruence:",
        (29 * 5) % 7 == (1 * 5) % 7
    )


# =============================================================================
# 8. MODULAR MULTIPLICATIVE INVERSE
# =============================================================================

def modular_inverse(a: int, modulus: int) -> int:
    """
    Return the multiplicative inverse of a modulo modulus.

    An inverse x exists exactly when:

        gcd(a, modulus) = 1

    because the Extended Euclidean Algorithm gives:

        ax + modulus*y = 1

    Reducing modulo modulus:

        ax ≡ 1 (mod modulus)

    Therefore x is an inverse of a modulo modulus.

    Raises:
        ValueError: if modulus is not positive or inverse does not exist.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")

    result = extended_gcd_iterative(a, modulus)

    if result.gcd != 1:
        raise ValueError(
            f"{a} has no multiplicative inverse modulo {modulus}; "
            f"gcd({a}, {modulus}) = {result.gcd}."
        )

    return result.x % modulus


def demonstrate_modular_inverse() -> None:
    """Demonstrate modular inverses and non-invertible values."""
    print("\n=== Modular Multiplicative Inverse ===")

    a, modulus = 3, 11
    inverse = modular_inverse(a, modulus)

    print(f"Inverse of {a} modulo {modulus}: {inverse}")
    print(f"{a} * {inverse} mod {modulus} = {(a * inverse) % modulus}")

    try:
        modular_inverse(6, 15)
    except ValueError as error:
        print("Expected failure:", error)

    # gcd(6, 15) = 3, so no integer x can satisfy:
    #     6x ≡ 1 (mod 15)
    assert gcd(6, 15) != 1


# =============================================================================
# 9. ALL MODULAR INVERSES FOR A SMALL MODULUS
# =============================================================================

def invertible_residues(modulus: int) -> List[int]:
    """
    Return all residues in {1, ..., modulus-1} that have inverses.

    These are exactly the integers relatively prime to modulus.
    """
    if modulus <= 1:
        return []

    return [
        value
        for value in range(1, modulus)
        if gcd(value, modulus) == 1
    ]


def demonstrate_units_modulo_n() -> None:
    """Show the relationship between inverses and coprimality."""
    modulus = 12
    residues = invertible_residues(modulus)

    print(f"\n=== Invertible Residues Modulo {modulus} ===")
    print(residues)

    for value in residues:
        inverse = modular_inverse(value, modulus)
        assert (value * inverse) % modulus == 1
        print(f"{value} -> inverse {inverse}")


# =============================================================================
# 10. LINEAR DIOPHANTINE EQUATIONS
# =============================================================================

def solve_linear_diophantine(
    a: int,
    b: int,
    c: int
) -> Optional[Tuple[int, int]]:
    """
    Find one integer solution to:

        ax + by = c

    A solution exists exactly when:

        gcd(a, b) divides c

    If:
        ax0 + by0 = g
        g = gcd(a, b)

    then multiplying by c/g gives:

        a(x0*c/g) + b(y0*c/g) = c

    Returns:
        (x, y) for one solution, or None if no solution exists.
    """
    if a == 0 and b == 0:
        if c == 0:
            return (0, 0)
        return None

    result = extended_gcd_iterative(a, b)
    g = result.gcd

    if c % g != 0:
        return None

    scale = c // g

    return result.x * scale, result.y * scale


def general_diophantine_solution(
    a: int,
    b: int,
    c: int
) -> Optional[Tuple[int, int, int, int]]:
    """
    Return a particular solution plus the parameter increments.

    If (x0, y0) is one solution to:

        ax + by = c

    and g = gcd(a, b), then every solution is:

        x = x0 + k*(b/g)
        y = y0 - k*(a/g)

    for any integer k.

    Returns:
        (x0, y0, dx, dy), where:
            x = x0 + k*dx
            y = y0 + k*dy
    """
    solution = solve_linear_diophantine(a, b, c)

    if solution is None:
        return None

    x0, y0 = solution
    g = gcd(a, b)

    return x0, y0, b // g, -a // g


def demonstrate_diophantine_equations() -> None:
    """Demonstrate solvable and unsolvable linear Diophantine equations."""
    print("\n=== Linear Diophantine Equations ===")

    a, b, c = 15, 21, 6
    solution = solve_linear_diophantine(a, b, c)

    print(f"Equation: {a}x + {b}y = {c}")
    print("One solution:", solution)

    assert solution is not None
    x, y = solution
    assert a * x + b * y == c

    general = general_diophantine_solution(a, b, c)

    assert general is not None

    x0, y0, dx, dy = general

    print(
        f"General form: x = {x0} + k*({dx}), "
        f"y = {y0} + k*({dy})"
    )

    for k in range(-2, 3):
        x_k = x0 + k * dx
        y_k = y0 + k * dy

        print(
            f"k={k:>2}: x={x_k:>4}, y={y_k:>4}, "
            f"left side={a * x_k + b * y_k}"
        )

    impossible = solve_linear_diophantine(6, 15, 7)
    print("6x + 15y = 7:", impossible)
    assert impossible is None


# =============================================================================
# 11. LINEAR CONGRUENCES
# =============================================================================

def solve_linear_congruence(
    a: int,
    b: int,
    modulus: int
) -> List[int]:
    """
    Solve:

        ax ≡ b (mod modulus)

    Let:
        g = gcd(a, modulus)

    A solution exists iff:
        g divides b

    When this holds, divide the entire congruence by g:

        (a/g)x ≡ b/g (mod modulus/g)

    Now a/g is coprime to modulus/g, so an inverse exists.

    There are exactly g distinct solutions modulo the original modulus.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")

    if a == 0:
        if b % modulus == 0:
            return list(range(modulus))
        return []

    g = gcd(a, modulus)

    if b % g != 0:
        return []

    reduced_a = a // g
    reduced_b = b // g
    reduced_modulus = modulus // g

    inverse = modular_inverse(reduced_a, reduced_modulus)
    base_solution = (inverse * reduced_b) % reduced_modulus

    return sorted(
        (base_solution + k * reduced_modulus) % modulus
        for k in range(g)
    )


def demonstrate_linear_congruence() -> None:
    """Demonstrate equations involving modular multiplication."""
    print("\n=== Linear Congruences ===")

    a, b, modulus = 14, 8, 30

    solutions = solve_linear_congruence(a, b, modulus)

    print(f"{a}x ≡ {b} (mod {modulus})")
    print("Solutions:", solutions)

    for x in solutions:
        assert (a * x - b) % modulus == 0

    no_solution = solve_linear_congruence(6, 5, 15)

    print(f"6x ≡ 5 (mod 15) -> {no_solution}")
    assert no_solution == []


# =============================================================================
# 12. CHINESE REMAINDER THEOREM
# =============================================================================

def extended_crt(
    congruences: Sequence[Tuple[int, int]]
) -> Tuple[int, int]:
    """
    Solve a system of pairwise-compatible linear congruences.

    Each equation has the form:

        x ≡ remainder (mod modulus)

    Unlike the simplest form of CRT, the moduli do not need to be pairwise
    coprime. The system is solvable when each newly combined congruence is
    compatible with the existing one.

    Returns:
        (x, modulus)

    meaning:
        x is the smallest nonnegative representative and all solutions satisfy:

            x ≡ result (mod modulus)
    """
    if not congruences:
        raise ValueError("At least one congruence is required.")

    x, current_modulus = congruences[0]

    if current_modulus <= 0:
        raise ValueError("Moduli must be positive.")

    x %= current_modulus

    for remainder, modulus in congruences[1:]:
        if modulus <= 0:
            raise ValueError("Moduli must be positive.")

        remainder %= modulus

        # We need:
        #
        #     x + current_modulus * k ≡ remainder (mod modulus)
        #
        # so:
        #
        #     current_modulus*k ≡ remainder - x (mod modulus)
        #
        difference = remainder - x
        g = gcd(current_modulus, modulus)

        if difference % g != 0:
            raise ValueError("The congruence system is incompatible.")

        reduced_current = current_modulus // g
        reduced_modulus = modulus // g
        reduced_difference = difference // g

        if reduced_modulus == 1:
            k = 0
        else:
            inverse = modular_inverse(
                reduced_current,
                reduced_modulus
            )
            k = (reduced_difference * inverse) % reduced_modulus

        combined_modulus = current_modulus * reduced_modulus

        x = (x + current_modulus * k) % combined_modulus
        current_modulus = combined_modulus

    return x, current_modulus


def demonstrate_chinese_remainder_theorem() -> None:
    """Demonstrate pairwise-coprime and non-coprime CRT cases."""
    print("\n=== Chinese Remainder Theorem ===")

    system = [
        (2, 3),
        (3, 5),
        (2, 7),
    ]

    solution, modulus = extended_crt(system)

    print("System:")
    for remainder, mod in system:
        print(f"    x ≡ {remainder} (mod {mod})")

    print(f"Solution: x ≡ {solution} (mod {modulus})")

    for remainder, mod in system:
        assert solution % mod == remainder

    compatible_non_coprime = [
        (2, 6),
        (5, 9),
    ]

    solution, modulus = extended_crt(compatible_non_coprime)

    print("\nCompatible non-coprime system:")
    print("    x ≡ 2 (mod 6)")
    print("    x ≡ 5 (mod 9)")
    print(f"Solution: x ≡ {solution} (mod {modulus})")

    assert solution % 6 == 2
    assert solution % 9 == 5

    incompatible = [
        (1, 4),
        (2, 6),
    ]

    try:
        extended_crt(incompatible)
    except ValueError as error:
        print("\nExpected incompatible-system failure:", error)


# =============================================================================
# 13. RSA-STYLE MODULAR INVERSE
# =============================================================================

def rsa_private_exponent(
    p: int,
    q: int,
    public_exponent: int
) -> Tuple[int, int, int]:
    """
    Compute RSA-style values for educational purposes.

    Given primes p and q:

        n   = p*q
        phi = (p-1)*(q-1)

    The private exponent d satisfies:

        e*d ≡ 1 (mod phi)

    Therefore d is found using the Extended Euclidean Algorithm.

    This function is educational. Real cryptographic implementations should
    use established cryptographic libraries and carefully designed key
    generation rather than hand-rolled arithmetic.
    """
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be greater than 1.")

    n = p * q
    phi = (p - 1) * (q - 1)

    d = modular_inverse(public_exponent, phi)

    return n, phi, d


def rsa_encrypt(message: int, public_exponent: int, n: int) -> int:
    """
    Demonstrate the mathematical RSA encryption operation:

        c = m^e mod n
    """
    if not 0 <= message < n:
        raise ValueError("Message must satisfy 0 <= message < n.")

    return pow(message, public_exponent, n)


def rsa_decrypt(ciphertext: int, private_exponent: int, n: int) -> int:
    """
    Demonstrate the mathematical RSA decryption operation:

        m = c^d mod n
    """
    if not 0 <= ciphertext < n:
        raise ValueError("Ciphertext must satisfy 0 <= ciphertext < n.")

    return pow(ciphertext, private_exponent, n)


def demonstrate_rsa_connection() -> None:
    """Show exactly where Extended GCD enters RSA key mathematics."""
    print("\n=== RSA Mathematical Connection ===")

    # Small educational primes only.
    p = 61
    q = 53
    e = 17

    n, phi, d = rsa_private_exponent(p, q, e)

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p*q = {n}")
    print(f"phi(n) = {phi}")
    print(f"e = {e}")
    print(f"d = {d}")

    print(f"e*d mod phi(n) = {(e * d) % phi}")

    message = 65
    ciphertext = rsa_encrypt(message, e, n)
    recovered = rsa_decrypt(ciphertext, d, n)

    print(f"Message: {message}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Recovered: {recovered}")

    assert recovered == message


# =============================================================================
# 14. FRACTION REDUCTION USING GCD
# =============================================================================

@dataclass(frozen=True)
class Fraction:
    """
    Minimal immutable rational-number implementation.

    This class demonstrates a practical use of GCD rather than Extended GCD
    itself. The numerator and denominator are reduced to lowest terms.

    The denominator is always kept positive.
    """
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if self.denominator == 0:
            raise ZeroDivisionError("Denominator cannot be zero.")

        numerator = self.numerator
        denominator = self.denominator

        if denominator < 0:
            numerator = -numerator
            denominator = -denominator

        common = gcd(abs(numerator), denominator)

        object.__setattr__(
            self,
            "numerator",
            numerator // common
        )
        object.__setattr__(
            self,
            "denominator",
            denominator // common
        )

    def __add__(self, other: "Fraction") -> "Fraction":
        if not isinstance(other, Fraction):
            return NotImplemented

        return Fraction(
            self.numerator * other.denominator
            + other.numerator * self.denominator,
            self.denominator * other.denominator
        )

    def __sub__(self, other: "Fraction") -> "Fraction":
        if not isinstance(other, Fraction):
            return NotImplemented

        return Fraction(
            self.numerator * other.denominator
            - other.numerator * self.denominator,
            self.denominator * other.denominator
        )

    def __mul__(self, other: "Fraction") -> "Fraction":
        if not isinstance(other, Fraction):
            return NotImplemented

        return Fraction(
            self.numerator * other.numerator,
            self.denominator * other.denominator
        )

    def __truediv__(self, other: "Fraction") -> "Fraction":
        if not isinstance(other, Fraction):
            return NotImplemented

        if other.numerator == 0:
            raise ZeroDivisionError("Cannot divide by zero.")

        return Fraction(
            self.numerator * other.denominator,
            self.denominator * other.numerator
        )

    def __str__(self) -> str:
        if self.denominator == 1:
            return str(self.numerator)

        return f"{self.numerator}/{self.denominator}"


def demonstrate_gcd_in_fraction_arithmetic() -> None:
    """Show how GCD reduces rational values."""
    print("\n=== GCD in Fraction Arithmetic ===")

    first = Fraction(12, 18)
    second = Fraction(5, 15)

    print(f"12/18 -> {first}")
    print(f"5/15 -> {second}")
    print(f"{first} + {second} = {first + second}")
    print(f"{first} * {second} = {first * second}")

    assert str(first) == "2/3"
    assert str(second) == "1/3"


# =============================================================================
# 15. EDGE CASES
# =============================================================================

def demonstrate_edge_cases() -> None:
    """Exercise zero, negative, equal, and coprime inputs."""
    print("\n=== Edge Cases ===")

    cases = [
        (0, 0),
        (0, 7),
        (7, 0),
        (48, 18),
        (-48, 18),
        (48, -18),
        (-48, -18),
        (13, 13),
        (17, 31),
        (1, 999),
    ]

    for a, b in cases:
        result = extended_gcd_iterative(a, b)

        print(
            f"a={a:>5}, b={b:>5} -> "
            f"gcd={result.gcd:>5}, "
            f"x={result.x:>5}, y={result.y:>5}"
        )

        assert result.gcd >= 0
        assert a * result.x + b * result.y == result.gcd
        assert result.gcd == gcd(a, b)

    print("\nSpecial observations:")
    print("gcd(0, 0) = 0 under this implementation.")
    print("The Bézout coefficients for (0, 0) are not unique.")
    print("Negative inputs are normalized to a nonnegative GCD.")


# =============================================================================
# 16. COMPARING EXTENDED GCD WITH PYTHON'S BUILT-IN GCD
# =============================================================================

def compare_with_builtin_gcd() -> None:
    """
    Verify the custom implementation against math.gcd.

    The built-in gcd is highly optimized. The custom implementation exists
    here to expose the algorithmic mechanics.
    """
    print("\n=== Comparison with math.gcd ===")

    test_cases = [
        (48, 18),
        (270, 192),
        (1071, 462),
        (0, 25),
        (-81, 153),
        (99991, 17),
        (123456789, 987654321),
    ]

    for a, b in test_cases:
        custom = euclidean_gcd_iterative(a, b)
        builtin = gcd(a, b)

        print(
            f"gcd({a}, {b}) -> custom={custom}, "
            f"builtin={builtin}"
        )

        assert custom == builtin


# =============================================================================
# 17. PERFORMANCE CHARACTERISTICS
# =============================================================================

def fibonacci_numbers(count: int) -> List[int]:
    """Generate Fibonacci numbers for worst-case Euclidean behavior."""
    if count <= 0:
        return []

    values = [0, 1]

    while len(values) < count:
        values.append(values[-1] + values[-2])

    return values[:count]


def count_euclidean_steps(a: int, b: int) -> int:
    """Count Euclidean division steps."""
    a = abs(a)
    b = abs(b)

    steps = 0

    while b != 0:
        a, b = b, a % b
        steps += 1

    return steps


def demonstrate_performance_behavior() -> None:
    """
    Demonstrate why Fibonacci pairs are associated with slow Euclidean traces.

    Consecutive Fibonacci numbers produce relatively small quotients and thus
    approach the worst-case number of Euclidean iterations for a given input
    magnitude.
    """
    print("\n=== Euclidean Algorithm Performance ===")

    fib = fibonacci_numbers(15)

    for i in range(2, len(fib)):
        a = fib[i]
        b = fib[i - 1]

        if b == 0:
            continue

        steps = count_euclidean_steps(a, b)

        print(
            f"gcd(F_{i}, F_{i - 1}) = {gcd(a, b):>2}; "
            f"steps = {steps}"
        )


# =============================================================================
# 18. VERIFYING IMPORTANT MATHEMATICAL PROPERTIES
# =============================================================================

def verify_gcd_properties(
    a: int,
    b: int
) -> None:
    """Verify standard GCD properties for a pair of integers."""
    g = gcd(a, b)

    assert g >= 0
    assert g == gcd(b, a)
    assert g == gcd(abs(a), abs(b))

    if a != 0:
        assert a % g == 0

    if b != 0:
        assert b % g == 0


def verify_extended_gcd_properties(
    a: int,
    b: int
) -> None:
    """Verify all central properties of Extended GCD."""
    result = extended_gcd_iterative(a, b)

    assert result.gcd == gcd(a, b)
    assert result.gcd >= 0
    assert a * result.x + b * result.y == result.gcd

    if result.gcd == 1:
        assert (a * result.x) % abs(b) == 1 % abs(b) if b != 0 else True


def demonstrate_properties() -> None:
    """Run deterministic property checks."""
    print("\n=== Mathematical Property Verification ===")

    values = [
        -100,
        -37,
        -1,
        0,
        1,
        2,
        17,
        48,
        123,
        1000,
    ]

    checked = 0

    for a in values:
        for b in values:
            verify_gcd_properties(a, b)
            verify_extended_gcd_properties(a, b)
            checked += 1

    print(f"Verified {checked} pairs successfully.")


# =============================================================================
# 19. RANDOMIZED TESTING
# =============================================================================

def randomized_tests(
    seed: int = 20260907,
    number_of_tests: int = 1000,
    magnitude: int = 10**12
) -> None:
    """
    Perform randomized consistency testing.

    Each generated pair is checked against:
        - math.gcd
        - Bézout's identity
        - nonnegative GCD requirement
    """
    rng = Random(seed)

    for _ in range(number_of_tests):
        a = rng.randint(-magnitude, magnitude)
        b = rng.randint(-magnitude, magnitude)

        result = extended_gcd_iterative(a, b)

        assert result.gcd == gcd(a, b)
        assert result.gcd >= 0
        assert a * result.x + b * result.y == result.gcd

    print(
        f"Randomized testing passed for {number_of_tests} "
        f"integer pairs."
    )


# =============================================================================
# 20. MODULAR INVERSE TABLE
# =============================================================================

def inverse_table(modulus: int) -> List[Tuple[int, int]]:
    """
    Return pairs (a, a_inverse) for every invertible residue modulo modulus.
    """
    table = []

    for a in range(1, modulus):
        if gcd(a, modulus) == 1:
            table.append((a, modular_inverse(a, modulus)))

    return table


def demonstrate_inverse_table() -> None:
    """Display a complete inverse table for a small modulus."""
    modulus = 11

    print(f"\n=== Inverse Table Modulo {modulus} ===")

    for value, inverse in inverse_table(modulus):
        print(
            f"{value:>2} * {inverse:>2} "
            f"≡ {(value * inverse) % modulus:>2} (mod {modulus})"
        )


# =============================================================================
# 21. MULTIPLE BÉZOUT REPRESENTATIONS
# =============================================================================

def bezout_solutions(
    a: int,
    b: int,
    number_of_solutions: int = 5
) -> List[Tuple[int, int]]:
    """
    Generate several Bézout coefficient pairs.

    If:

        ax0 + by0 = g

    then every pair:

        x = x0 + k*(b/g)
        y = y0 - k*(a/g)

    also satisfies:

        ax + by = g
    """
    if number_of_solutions <= 0:
        return []

    result = extended_gcd_iterative(a, b)

    if result.gcd == 0:
        return [(result.x, result.y)] * number_of_solutions

    dx = b // result.gcd
    dy = -a // result.gcd

    start = -(number_of_solutions // 2)

    return [
        (
            result.x + k * dx,
            result.y + k * dy
        )
        for k in range(start, start + number_of_solutions)
    ]


def demonstrate_multiple_bezout_pairs() -> None:
    """Show that Bézout coefficients are generally not unique."""
    print("\n=== Multiple Bézout Representations ===")

    a, b = 48, 18
    g = gcd(a, b)

    for x, y in bezout_solutions(a, b):
        print(
            f"x={x:>4}, y={y:>4}: "
            f"{a}x + {b}y = {a * x + b * y}"
        )
        assert a * x + b * y == g


# =============================================================================
# 22. USING EXTENDED GCD TO COMPUTE A MODULAR DIVISION
# =============================================================================

def modular_division(
    numerator: int,
    denominator: int,
    modulus: int
) -> int:
    """
    Compute:

        numerator / denominator (mod modulus)

    which means:

        numerator * denominator^(-1) (mod modulus)

    This operation is defined only when denominator is invertible modulo
    modulus.
    """
    inverse = modular_inverse(denominator, modulus)

    return (numerator * inverse) % modulus


def demonstrate_modular_division() -> None:
    """Demonstrate modular division."""
    print("\n=== Modular Division ===")

    numerator = 7
    denominator = 3
    modulus = 11

    result = modular_division(numerator, denominator, modulus)

    print(
        f"{numerator}/{denominator} mod {modulus} = {result}"
    )

    # Verify:
    # 3 * result ≡ 7 mod 11
    assert (denominator * result) % modulus == numerator % modulus


# =============================================================================
# 23. EXTENDED GCD FOR POLYNOMIAL-LIKE INTEGER LINEAR COMBINATIONS
# =============================================================================

def integer_linear_combination(
    coefficients: Sequence[int]
) -> Tuple[int, List[int]]:
    """
    Find coefficients expressing the GCD of a list of integers.

    For:

        a1, a2, ..., an

    find:

        c1*a1 + c2*a2 + ... + cn*an = gcd(a1, ..., an)

    This repeatedly applies the two-number Extended Euclidean Algorithm.

    Returns:
        (g, coefficients)
    """
    if not coefficients:
        return 0, []

    current_gcd = coefficients[0]
    combination = [1]

    for value in coefficients[1:]:
        result = extended_gcd_iterative(current_gcd, value)

        # If:
        #
        # current_gcd*x + value*y = new_gcd
        #
        # and current_gcd itself is:
        #
        # sum(ci*ai)
        #
        # then every existing coefficient is multiplied by x and the new
        # coefficient becomes y.
        combination = [coefficient * result.x for coefficient in combination]
        combination.append(result.y)

        current_gcd = result.gcd

    return current_gcd, combination


def demonstrate_multi_integer_gcd() -> None:
    """Demonstrate a Bézout identity involving more than two integers."""
    print("\n=== Multi-Integer Bézout Combination ===")

    values = [84, 30, 18]
    g, coefficients = integer_linear_combination(values)

    expression = " + ".join(
        f"({coefficient})*{value}"
        for coefficient, value in zip(coefficients, values)
    )

    value = sum(
        coefficient * number
        for coefficient, number in zip(coefficients, values)
    )

    print(f"Values: {values}")
    print(f"GCD: {g}")
    print(f"Expression: {expression}")
    print(f"Value: {value}")

    assert value == g
    assert g == gcd(gcd(values[0], values[1]), values[2])


# =============================================================================
# 24. COMMON IMPLEMENTATION MISTAKES
# =============================================================================

def demonstrate_common_mistakes() -> None:
    """
    Illustrate incorrect assumptions without intentionally implementing unsafe
    or misleading algorithms.

    Mistake 1:
        Assuming every number has a modular inverse.

    Mistake 2:
        Forgetting to normalize the inverse into the chosen residue range.

    Mistake 3:
        Confusing an integer equation ax + by = c with a congruence.

    Mistake 4:
        Assuming CRT always works for non-coprime moduli.

    Mistake 5:
        Forgetting that gcd(a, b) may be greater than one.
    """
    print("\n=== Common Mistakes ===")

    # Mistake 1: assuming an inverse always exists.
    a, modulus = 8, 12
    print(
        f"gcd({a}, {modulus}) = {gcd(a, modulus)}; "
        "therefore 8 has no inverse modulo 12."
    )

    # Mistake 2: Bézout's coefficient may be negative, but an equivalent
    # modular inverse is represented by a nonnegative residue.
    a, modulus = 3, 11
    result = extended_gcd_iterative(a, modulus)

    print(
        f"Raw Bézout coefficient for {a}: {result.x}; "
        f"normalized inverse: {result.x % modulus}"
    )

    # Mistake 3: a congruence can have several solutions.
    solutions = solve_linear_congruence(14, 8, 30)
    print("14x ≡ 8 (mod 30) has:", solutions)

    # Mistake 4: non-coprime CRT moduli require compatibility.
    print(
        "For x ≡ 1 (mod 4) and x ≡ 2 (mod 6), "
        "the system is incompatible."
    )


# =============================================================================
# 25. LARGE INTEGER EXAMPLE
# =============================================================================

def demonstrate_large_integers() -> None:
    """
    Demonstrate that Python's arbitrary-precision integers allow the algorithm
    to operate on values much larger than fixed-width machine integers.
    """
    print("\n=== Large Integer Example ===")

    a = 1234567890123456789012345678901234567890
    b = 987654321098765432109876543210

    result = extended_gcd_iterative(a, b)

    print(f"a = {a}")
    print(f"b = {b}")
    print(f"gcd = {result.gcd}")

    # Python integers do not overflow in the usual fixed-width sense.
    # The actual cost is determined by the size of the integers.
    assert a * result.x + b * result.y == result.gcd
    assert result.gcd == gcd(a, b)


# =============================================================================
# 26. ALGORITHM COMPARISON
# =============================================================================

def compare_algorithm_purposes() -> None:
    """
    Print a conceptual comparison of related operations.

    This section uses executable data structures to make the distinction
    explicit rather than relying only on prose.
    """
    print("\n=== Algorithm Comparison ===")

    comparison = [
        (
            "Trial division",
            "Find divisors",
            "Simple but inefficient for large integers"
        ),
        (
            "Euclidean algorithm",
            "Compute gcd(a, b)",
            "Fast and logarithmic in input magnitude"
        ),
        (
            "Extended Euclidean algorithm",
            "Compute gcd and Bézout coefficients",
            "Also enables modular inverses and linear congruences"
        ),
        (
            "Built-in math.gcd",
            "Compute GCD",
            "Highly optimized library implementation"
        ),
        (
            "Built-in pow(a, -1, m)",
            "Compute modular inverse",
            "Convenient when supported by the Python version"
        ),
    ]

    for algorithm, purpose, characteristic in comparison:
        print(f"{algorithm:>30} | {purpose:<32} | {characteristic}")


# =============================================================================
# 27. PRACTICAL VALIDATION HELPERS
# =============================================================================

def validate_extended_gcd_result(
    a: int,
    b: int,
    result: ExtendedGCDResult
) -> None:
    """
    Raise AssertionError if an Extended GCD result is mathematically invalid.
    """
    if result.gcd != gcd(a, b):
        raise AssertionError("Incorrect GCD.")

    if result.gcd < 0:
        raise AssertionError("GCD must be nonnegative.")

    if a * result.x + b * result.y != result.gcd:
        raise AssertionError("Bézout identity does not hold.")


def demonstrate_validation() -> None:
    """Show explicit validation of algorithm output."""
    print("\n=== Result Validation ===")

    a, b = 391, 299
    result = extended_gcd_iterative(a, b)

    validate_extended_gcd_result(a, b, result)

    print("Result passed:")
    print(f"gcd = {result.gcd}")
    print(f"x = {result.x}")
    print(f"y = {result.y}")
    print(f"391x + 299y = {a * result.x + b * result.y}")


# =============================================================================
# 28. PRACTICAL EXAMPLE: COPRIME KEY PARAMETERS
# =============================================================================

def choose_valid_public_exponent(
    phi: int,
    candidates: Iterable[int]
) -> Optional[int]:
    """
    Select the first candidate relatively prime to phi.

    In RSA, the public exponent e must satisfy:

        gcd(e, phi(n)) = 1

    This helper demonstrates how GCD determines whether an exponent can have
    a modular inverse.
    """
    for candidate in candidates:
        if candidate > 1 and gcd(candidate, phi) == 1:
            return candidate

    return None


def demonstrate_key_parameter_selection() -> None:
    """Demonstrate coprimality checks for an RSA-style exponent."""
    print("\n=== Coprimality in Key Parameter Selection ===")

    phi = 3120
    candidates = [2, 4, 6, 8, 10, 17]

    selected = choose_valid_public_exponent(phi, candidates)

    print(f"phi = {phi}")
    print(f"Candidates = {candidates}")
    print(f"First valid candidate = {selected}")

    assert selected == 17
    assert gcd(selected, phi) == 1


# =============================================================================
# 29. ALGORITHM PSEUDOCODE AS EXECUTABLE DATA
# =============================================================================

def print_pseudocode() -> None:
    """
    Print pseudocode for study purposes.

    The actual implementations above are the executable versions.
    """
    pseudocode = [
        "extended_gcd(a, b):",
        "    if b == 0:",
        "        return (abs(a), sign-adjusted 1, 0)",
        "    q, r = divmod(a, b)",
        "    (g, x1, y1) = extended_gcd(b, r)",
        "    x = y1",
        "    y = x1 - q*y1",
        "    return (g, x, y)",
    ]

    print("\n=== Extended Euclidean Algorithm Pseudocode ===")

    for line in pseudocode:
        print(line)


# =============================================================================
# 30. END-TO-END NUMBER THEORY WORKFLOW
# =============================================================================

def end_to_end_workflow() -> None:
    """
    Solve a practical modular-arithmetic problem from first principles.

    Problem:
        Find x satisfying:

            37x ≡ 12 (mod 101)

    Steps:
        1. Compute gcd(37, 101).
        2. Since the GCD is 1, an inverse exists.
        3. Find the inverse using Extended GCD.
        4. Multiply by 12.
        5. Verify the result.
    """
    print("\n=== End-to-End Modular Equation ===")

    a, b, modulus = 37, 12, 101

    g = gcd(a, modulus)
    print(f"gcd({a}, {modulus}) = {g}")

    assert g == 1

    inverse = modular_inverse(a, modulus)
    solution = (b * inverse) % modulus

    print(f"Inverse of {a} modulo {modulus}: {inverse}")
    print(f"Solution x = {solution}")
    print(
        f"Verification: "
        f"{a}*{solution} mod {modulus} = "
        f"{(a * solution) % modulus}"
    )

    assert (a * solution) % modulus == b % modulus


# =============================================================================
# 31. STUDY CHECKS
# =============================================================================

def study_checks() -> None:
    """
    Compact collection of expected results that can be used as regression
    tests while modifying the implementation.
    """
    expected_gcds = {
        (48, 18): 6,
        (270, 192): 6,
        (1071, 462): 21,
        (0, 9): 9,
        (-25, 15): 5,
        (17, 31): 1,
    }

    for (a, b), expected in expected_gcds.items():
        assert euclidean_gcd_iterative(a, b) == expected
        assert extended_gcd_iterative(a, b).gcd == expected

    expected_inverses = {
        (3, 11): 4,
        (7, 11): 8,
        (10, 17): 12,
        (17, 43): 38,
    }

    for (a, modulus), expected in expected_inverses.items():
        actual = modular_inverse(a, modulus)

        assert actual == expected
        assert (a * actual) % modulus == 1

    print("\n=== Study Regression Checks ===")
    print("All expected GCD and modular-inverse values passed.")


# =============================================================================
# 32. MAIN DEMONSTRATION
# =============================================================================

def main() -> None:
    """
    Execute the complete Extended Euclidean Algorithm study program.

    Each section is intentionally independent enough to be read and modified
    as a learning exercise.
    """
    print("=" * 79)
    print("EXTENDED EUCLIDEAN ALGORITHM")
    print("From Fundamental GCD Computation to Modular Arithmetic Applications")
    print("=" * 79)

    demonstrate_gcd()
    print_euclidean_trace(48, 18)
    demonstrate_bezout_identity()
    demonstrate_extended_gcd()
    print_extended_trace(240, 46)
    explain_invariant_with_code()

    demonstrate_modular_arithmetic()
    demonstrate_modular_inverse()
    demonstrate_units_modulo_n()

    demonstrate_diophantine_equations()
    demonstrate_linear_congruence()
    demonstrate_chinese_remainder_theorem()

    demonstrate_rsa_connection()
    demonstrate_gcd_in_fraction_arithmetic()

    demonstrate_edge_cases()
    compare_with_builtin_gcd()
    demonstrate_performance_behavior()

    demonstrate_properties()
    randomized_tests()

    demonstrate_inverse_table()
    demonstrate_multiple_bezout_pairs()
    demonstrate_modular_division()
    demonstrate_multi_integer_gcd()

    demonstrate_common_mistakes()
    demonstrate_large_integers()
    compare_algorithm_purposes()
    demonstrate_validation()
    demonstrate_key_parameter_selection()

    print_pseudocode()
    end_to_end_workflow()
    study_checks()

    print("\n" + "=" * 79)
    print("All demonstrations and mathematical checks completed successfully.")
    print("=" * 79)


if __name__ == "__main__":
    main()
