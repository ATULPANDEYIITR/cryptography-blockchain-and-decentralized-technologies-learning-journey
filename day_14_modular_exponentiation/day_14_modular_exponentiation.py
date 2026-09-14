"""
MODULAR EXPONENTIATION
=======================

A self-contained study file covering modular exponentiation from absolute
beginner concepts through advanced algorithms and practical applications.

Core notation:
    a^b mod m

means:
    compute a raised to the power b, then take the remainder modulo m.

The central efficient algorithm is binary exponentiation (repeated squaring),
which reduces the number of multiplications from O(b) to O(log b).

This script contains:
    1. Modular arithmetic fundamentals
    2. Naive modular exponentiation
    3. Binary exponentiation
    4. Recursive exponentiation
    5. Operation counting and complexity comparison
    6. Edge cases and validation
    7. Negative exponents and modular inverses
    8. Euler's theorem
    9. Fermat's little theorem
    10. Exponent reduction
    11. Chinese Remainder Theorem applications
    12. Matrix exponentiation
    13. Modular multiplication for very large integers
    14. Montgomery-style concepts and implementation discussion
    15. Sliding-window exponentiation
    16. Constant-time considerations
    17. Cryptographic examples
    18. Discrete logarithm context
    19. RSA-style modular exponentiation
    20. Diffie-Hellman-style calculations
    21. Testing and correctness checks
    22. Performance experiments
    23. Common mistakes and implementation guidance

The file uses only Python's standard library.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


# ============================================================================
# 1. FUNDAMENTAL MODULAR ARITHMETIC
# ============================================================================

def remainder(a: int, modulus: int) -> int:
    """
    Return a modulo modulus.

    For positive modulus m, Python guarantees:
        0 <= a % m < m

    Examples:
        17 mod 5  = 2
        20 mod 5  = 0
        -3 mod 5  = 2

    A modulus of zero is invalid because division by zero is undefined.
    """
    if modulus <= 0:
        raise ValueError("modulus must be a positive integer")
    return a % modulus


def demonstrate_basic_modular_arithmetic() -> None:
    print("\n" + "=" * 78)
    print("1. BASIC MODULAR ARITHMETIC")
    print("=" * 78)

    examples = [
        (17, 5),
        (20, 5),
        (-3, 5),
        (123456789, 97),
    ]

    for a, m in examples:
        print(f"{a} mod {m} = {a % m}")

    # Modular arithmetic allows reduction after every operation:
    #
    # (a + b) mod m = ((a mod m) + (b mod m)) mod m
    # (a * b) mod m = ((a mod m) * (b mod m)) mod m
    #
    # This property is the key reason modular exponentiation can keep
    # intermediate values small.

    a = 123456
    b = 789012
    m = 1009

    direct_addition = (a + b) % m
    reduced_addition = ((a % m) + (b % m)) % m

    direct_multiplication = (a * b) % m
    reduced_multiplication = ((a % m) * (b % m)) % m

    print("\nReduction compatibility:")
    print("Addition:", direct_addition == reduced_addition)
    print("Multiplication:", direct_multiplication == reduced_multiplication)


# ============================================================================
# 2. WHAT MODULAR EXPONENTIATION COMPUTES
# ============================================================================

def modular_power_definition(base: int, exponent: int, modulus: int) -> int:
    """
    Direct mathematical definition for a non-negative exponent.

    This is intentionally naive. It is useful for teaching and for testing
    optimized implementations.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus

    for _ in range(exponent):
        result = (result * base) % modulus

    return result


def demonstrate_definition() -> None:
    print("\n" + "=" * 78)
    print("2. DEFINITION OF MODULAR EXPONENTIATION")
    print("=" * 78)

    base = 3
    exponent = 13
    modulus = 7

    ordinary_power = base ** exponent
    modular_result = ordinary_power % modulus
    direct_modular_result = modular_power_definition(base, exponent, modulus)

    print(f"{base}^{exponent} = {ordinary_power}")
    print(f"{base}^{exponent} mod {modulus} = {modular_result}")
    print(
        "Repeated modular multiplication gives:",
        direct_modular_result,
    )

    # The expression can be reduced at every multiplication:
    #
    # 3^13 mod 7
    # = (((((... 3) * 3) mod 7) * 3) mod 7) ...)
    #
    # This prevents the complete value 3^13 from needing to be retained.


# ============================================================================
# 3. NAIVE MODULAR EXPONENTIATION
# ============================================================================

def naive_modular_pow(
    base: int,
    exponent: int,
    modulus: int,
    *,
    count_operations: bool = False,
) -> int | Tuple[int, int]:
    """
    Compute base^exponent mod modulus using one multiplication per exponent.

    Time complexity:
        O(exponent)

    Space complexity:
        O(1)

    This is easy to understand but becomes impractical when the exponent is
    extremely large.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    normalized_base = base % modulus
    multiplications = 0

    for _ in range(exponent):
        result = (result * normalized_base) % modulus
        multiplications += 1

    if count_operations:
        return result, multiplications

    return result


# ============================================================================
# 4. BINARY EXPONENTIATION / REPEATED SQUARING
# ============================================================================

def binary_modular_pow(
    base: int,
    exponent: int,
    modulus: int,
    *,
    count_operations: bool = False,
) -> int | Tuple[int, int]:
    """
    Compute base^exponent mod modulus using binary exponentiation.

    Binary representation of the exponent determines which powers of the
    base are needed.

    Example:
        13 = binary 1101
           = 8 + 4 + 1

    Therefore:
        a^13 = a^8 * a^4 * a^1

    Repeated squaring generates:
        a^1
        a^2
        a^4
        a^8
        ...

    Time complexity:
        O(log exponent)

    Space complexity:
        O(1)
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    current = base % modulus
    power = exponent
    multiplications = 0

    while power > 0:
        # If the least significant binary bit is 1, this power contributes
        # to the final result.
        if power & 1:
            result = (result * current) % modulus
            multiplications += 1

        # Squaring produces the next power:
        # current = base^(1), base^(2), base^(4), base^(8), ...
        current = (current * current) % modulus
        multiplications += 1

        # Shift right by one binary position, equivalent to floor(power / 2).
        power >>= 1

    if count_operations:
        return result, multiplications

    return result


def binary_modular_pow_verbose(base: int, exponent: int, modulus: int) -> int:
    """
    Educational version that prints every repeated-squaring step.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    current = base % modulus
    power = exponent
    step = 0

    print(f"\nComputing {base}^{exponent} mod {modulus}")
    print(f"Binary exponent: {exponent:b}")
    print()

    while power > 0:
        bit = power & 1

        print(
            f"Step {step}: exponent={power}, "
            f"bit={bit}, current={current}, result={result}"
        )

        if bit:
            result = (result * current) % modulus
            print(f"        multiply -> result={result}")

        current = (current * current) % modulus
        print(f"        square   -> current={current}")

        power >>= 1
        step += 1

    print(f"Final result: {result}")
    return result


# ============================================================================
# 5. RECURSIVE BINARY EXPONENTIATION
# ============================================================================

def recursive_modular_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Recursive repeated squaring.

    Mathematical recurrence:

        a^0 = 1

        a^n = (a^(n/2))^2                 if n is even

        a^n = a * (a^((n-1)/2))^2         if n is odd

    Time complexity:
        O(log exponent)

    Space complexity:
        O(log exponent) due to recursion depth.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    if exponent == 0:
        return 1 % modulus

    half = recursive_modular_pow(base, exponent // 2, modulus)
    squared = (half * half) % modulus

    if exponent % 2 == 0:
        return squared

    return (squared * (base % modulus)) % modulus


# ============================================================================
# 6. WHY BINARY EXPONENTIATION IS FAST
# ============================================================================

def binary_digits(number: int) -> List[int]:
    """Return binary digits from least significant to most significant."""
    if number < 0:
        raise ValueError("number must be non-negative")

    if number == 0:
        return [0]

    digits = []

    while number:
        digits.append(number & 1)
        number >>= 1

    return digits


def theoretical_binary_steps(exponent: int) -> Tuple[int, int]:
    """
    Return:
        number_of_bits,
        number_of_set_bits

    For the standard left-to-right or right-to-left binary method, the number
    of squarings is approximately the number of exponent bits, while the
    number of extra multiplications depends on the number of 1 bits.
    """
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    if exponent == 0:
        return 0, 0

    return exponent.bit_length(), exponent.bit_count()


def demonstrate_binary_structure() -> None:
    print("\n" + "=" * 78)
    print("3. BINARY REPRESENTATION AND REPEATED SQUARING")
    print("=" * 78)

    exponent = 13
    digits = binary_digits(exponent)

    print(f"Exponent: {exponent}")
    print(f"Binary:   {exponent:b}")
    print(f"Bits from least significant to most significant: {digits}")

    bits, ones = theoretical_binary_steps(exponent)

    print(f"Number of bits: {bits}")
    print(f"Number of set bits: {ones}")
    print(f"Mathematical decomposition: {exponent} = 8 + 4 + 1")


# ============================================================================
# 7. COMPARING NAIVE AND BINARY METHODS
# ============================================================================

def compare_operation_counts() -> None:
    print("\n" + "=" * 78)
    print("4. NAIVE VERSUS BINARY EXPONENTIATION")
    print("=" * 78)

    modulus = 1_000_000_007

    exponents = [
        10,
        100,
        1_000,
        10_000,
        1_000_000,
    ]

    print(
        f"{'Exponent':>12} | {'Naive multiplications':>24} | "
        f"{'Binary multiplications':>24}"
    )
    print("-" * 68)

    for exponent in exponents:
        _, naive_count = naive_modular_pow(
            7,
            exponent,
            modulus,
            count_operations=True,
        )

        _, binary_count = binary_modular_pow(
            7,
            exponent,
            modulus,
            count_operations=True,
        )

        print(
            f"{exponent:>12} | {naive_count:>24} | {binary_count:>24}"
        )

    # Note:
    # The operation count above counts the modular multiplication used for
    # every square as well as result multiplications. Exact low-level runtime
    # also depends on integer size, CPU architecture, interpreter behavior,
    # and the implementation of big-integer multiplication.


# ============================================================================
# 8. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print("\n" + "=" * 78)
    print("5. EDGE CASES")
    print("=" * 78)

    cases = [
        (0, 0, 7),
        (0, 5, 7),
        (5, 0, 7),
        (10, 3, 1),
        (-2, 5, 7),
        (123456789, 2, 13),
    ]

    for base, exponent, modulus in cases:
        result = binary_modular_pow(base, exponent, modulus)
        print(f"{base}^{exponent} mod {modulus} = {result}")

    # Important:
    #
    # a^0 = 1 for every non-zero base in ordinary exponentiation.
    # In modular arithmetic this becomes 1 mod m.
    #
    # If m = 1, every integer is congruent to 0 modulo 1, so the result is 0.
    #
    # 0^0 is convention-dependent in mathematics, but algorithmic contexts
    # commonly define exponentiation with exponent zero as 1. The implementation
    # follows that convention.
    #
    # Negative bases are naturally supported because Python's % operation
    # returns a canonical non-negative remainder for positive moduli.


# ============================================================================
# 9. PYTHON'S BUILT-IN POW
# ============================================================================

def demonstrate_builtin_pow() -> None:
    print("\n" + "=" * 78)
    print("6. PYTHON'S THREE-ARGUMENT pow")
    print("=" * 78)

    base = 7
    exponent = 10**18
    modulus = 1_000_000_007

    result = pow(base, exponent, modulus)

    print(f"pow({base}, {exponent}, {modulus}) = {result}")

    # The three-argument form:
    #
    #     pow(base, exponent, modulus)
    #
    # computes modular exponentiation efficiently without first constructing
    # base**exponent as a giant integer.
    #
    # For production Python code, this built-in implementation is generally
    # preferable to a hand-written implementation when the goal is simply
    # to calculate a modular power.


# ============================================================================
# 10. CORRECTNESS INVARIANT
# ============================================================================

def binary_modular_pow_with_invariant(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Binary exponentiation written to make its mathematical invariant explicit.

    Invariant:
        result * current^power ≡ base^original_exponent (mod modulus)

    Each iteration either transfers the current power into result when the
    lowest bit is 1 or skips it. Squaring current corresponds to doubling
    its exponent, and shifting power corresponds to dividing the remaining
    exponent by two.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    original_exponent = exponent
    result = 1 % modulus
    current = base % modulus
    power = exponent

    while power:
        # Before the operations:
        # result * current^power ≡ base^original_exponent (mod modulus)

        if power & 1:
            result = (result * current) % modulus

        current = (current * current) % modulus
        power >>= 1

        # The invariant remains true after each iteration.

    assert result == pow(base, original_exponent, modulus)
    return result


# ============================================================================
# 11. MODULAR INVERSE
# ============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.

    Returns:
        (g, x, y)

    such that:
        ax + by = g
        g = gcd(a, b)

    This is used to calculate modular inverses.
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return old_r, old_x, old_y


def modular_inverse(a: int, modulus: int) -> int:
    """
    Return the multiplicative inverse of a modulo modulus.

    The inverse x satisfies:

        a*x ≡ 1 (mod modulus)

    It exists exactly when:

        gcd(a, modulus) = 1
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    gcd_value, coefficient, _ = extended_gcd(a, modulus)

    if gcd_value != 1:
        raise ValueError(
            f"{a} has no modular inverse modulo {modulus}; "
            f"gcd={gcd_value}"
        )

    return coefficient % modulus


def demonstrate_modular_inverse() -> None:
    print("\n" + "=" * 78)
    print("7. MODULAR INVERSES")
    print("=" * 78)

    a = 3
    modulus = 11

    inverse = modular_inverse(a, modulus)

    print(f"Inverse of {a} modulo {modulus}: {inverse}")
    print(f"Verification: ({a} * {inverse}) mod {modulus} = {(a * inverse) % modulus}")

    # Fermat's theorem can provide another inverse formula when the modulus
    # p is prime and p does not divide a:
    #
    #     a^(-1) ≡ a^(p-2) mod p
    #
    # That relationship is demonstrated later.


def modular_pow_signed(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Modular exponentiation supporting negative exponents.

    For exponent < 0:
        base^exponent = (base^(-1))^(-exponent)

    This requires base to have an inverse modulo modulus.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if exponent >= 0:
        return binary_modular_pow(base, exponent, modulus)

    inverse = modular_inverse(base, modulus)
    return binary_modular_pow(inverse, -exponent, modulus)


# ============================================================================
# 12. EULER'S TOTIENT FUNCTION
# ============================================================================

def euler_totient(n: int) -> int:
    """
    Compute Euler's totient phi(n), the number of integers in [1, n]
    that are coprime to n.

    Uses prime factorization:
        phi(n) = n * product(1 - 1/p)
    over distinct prime factors p of n.
    """
    if n <= 0:
        raise ValueError("n must be positive")

    result = n
    remaining = n
    factor = 2

    while factor * factor <= remaining:
        if remaining % factor == 0:
            result -= result // factor

            while remaining % factor == 0:
                remaining //= factor

        factor += 1 if factor == 2 else 2

    if remaining > 1:
        result -= result // remaining

    return result


def demonstrate_totient() -> None:
    print("\n" + "=" * 78)
    print("8. EULER'S TOTIENT FUNCTION")
    print("=" * 78)

    for n in range(1, 13):
        print(f"phi({n}) = {euler_totient(n)}")


# ============================================================================
# 13. EULER'S THEOREM
# ============================================================================

def euler_theorem_reduction(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Apply Euler's theorem when gcd(base, modulus) = 1.

    Euler's theorem:
        a^phi(m) ≡ 1 (mod m)

    Therefore:
        a^k mod m
        = a^(k mod phi(m)) mod m

    only under the required coprimality condition.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if math.gcd(base, modulus) != 1:
        raise ValueError(
            "Euler exponent reduction requires gcd(base, modulus) = 1"
        )

    phi = euler_totient(modulus)
    reduced_exponent = exponent % phi

    return binary_modular_pow(base, reduced_exponent, modulus)


def demonstrate_euler_theorem() -> None:
    print("\n" + "=" * 78)
    print("9. EULER'S THEOREM AND EXPONENT REDUCTION")
    print("=" * 78)

    base = 3
    exponent = 12345678901234567890
    modulus = 100

    direct = binary_modular_pow(base, exponent, modulus)
    reduced = euler_theorem_reduction(base, exponent, modulus)

    print(f"phi({modulus}) = {euler_totient(modulus)}")
    print("Direct result:", direct)
    print("Euler-reduced result:", reduced)
    print("Equal:", direct == reduced)

    # Critical restriction:
    #
    # It is incorrect to reduce the exponent modulo phi(m) when gcd(a, m)
    # is not 1. The theorem does not apply in that situation.


# ============================================================================
# 14. FERMAT'S LITTLE THEOREM
# ============================================================================

def fermat_inverse(a: int, prime_modulus: int) -> int:
    """
    Compute a modular inverse modulo a prime p using Fermat's theorem.

    If p is prime and p does not divide a:
        a^(p-1) ≡ 1 mod p

    Hence:
        a^(p-2) ≡ a^(-1) mod p
    """
    if prime_modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if not is_prime(prime_modulus):
        raise ValueError("modulus must be prime")

    if a % prime_modulus == 0:
        raise ValueError("a is not invertible modulo p")

    return binary_modular_pow(a, prime_modulus - 2, prime_modulus)


# ============================================================================
# 15. PRIME TESTING
# ============================================================================

def is_prime(n: int) -> bool:
    """
    Deterministic primality test suitable for the educational examples here.

    This trial-division implementation is not intended for very large
    cryptographic primes.
    """
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2

    return True


def demonstrate_fermat() -> None:
    print("\n" + "=" * 78)
    print("10. FERMAT'S LITTLE THEOREM")
    print("=" * 78)

    p = 17
    a = 5

    print(f"{a}^({p - 1}) mod {p} = {binary_modular_pow(a, p - 1, p)}")

    inverse_1 = modular_inverse(a, p)
    inverse_2 = fermat_inverse(a, p)

    print("Extended Euclidean inverse:", inverse_1)
    print("Fermat inverse:", inverse_2)
    print("Equal:", inverse_1 == inverse_2)


# ============================================================================
# 16. GENERALIZED EXPONENT REDUCTION AND PRIME POWERS
# ============================================================================

def prime_power(modulus: int) -> Tuple[int, int]:
    """
    If modulus is a power of one prime, return (prime, exponent).

    For example:
        8 -> (2, 3)
        27 -> (3, 3)

    Otherwise raise ValueError.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    remaining = modulus

    for p in range(2, int(math.isqrt(modulus)) + 1):
        if remaining % p == 0:
            exponent = 0

            while remaining % p == 0:
                remaining //= p
                exponent += 1

            if remaining == 1:
                return p, exponent

            raise ValueError("modulus is not a prime power")

    return modulus, 1


def demonstrate_exponent_reduction_warning() -> None:
    print("\n" + "=" * 78)
    print("11. WHY COPRIMALITY MATTERS")
    print("=" * 78)

    base = 2
    modulus = 8
    exponent = 10

    direct = binary_modular_pow(base, exponent, modulus)

    print(f"Direct: {base}^{exponent} mod {modulus} = {direct}")
    print(
        "gcd(base, modulus) =",
        math.gcd(base, modulus),
        "so Euler's theorem cannot be applied directly."
    )

    # Incorrect reasoning would be:
    #   phi(8) = 4
    #   10 mod 4 = 2
    #   2^2 mod 8 = 4
    #
    # In this particular case the result happens to be the same.
    #
    # That accidental equality must not be mistaken for a theorem.
    #
    # For exponent reduction, conditions must be established rather than
    # inferred from a few successful examples.


# ============================================================================
# 17. CHINESE REMAINDER THEOREM
# ============================================================================

def chinese_remainder_theorem(
    congruences: Sequence[Tuple[int, int]],
) -> int:
    """
    Solve a system of pairwise-coprime congruences.

    Input:
        [(remainder_1, modulus_1), ...]

    Returns the smallest non-negative solution x.

    The moduli must be pairwise coprime.

    Construction:
        M = m1*m2*...*mk

        Mi = M/mi

        yi = inverse(Mi mod mi)

        x = sum(ai*Mi*yi) mod M
    """
    if not congruences:
        raise ValueError("at least one congruence is required")

    moduli = [modulus for _, modulus in congruences]

    for modulus in moduli:
        if modulus <= 0:
            raise ValueError("moduli must be positive")

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if math.gcd(moduli[i], moduli[j]) != 1:
                raise ValueError("moduli must be pairwise coprime")

    total_modulus = math.prod(moduli)
    result = 0

    for remainder_value, modulus in congruences:
        partial = total_modulus // modulus
        inverse = modular_inverse(partial, modulus)
        result += remainder_value * partial * inverse

    return result % total_modulus


def demonstrate_crt() -> None:
    print("\n" + "=" * 78)
    print("12. CHINESE REMAINDER THEOREM")
    print("=" * 78)

    system = [
        (2, 3),
        (3, 5),
        (2, 7),
    ]

    solution = chinese_remainder_theorem(system)

    print("System:")
    for remainder_value, modulus in system:
        print(f"x ≡ {remainder_value} (mod {modulus})")

    print("Smallest non-negative solution:", solution)

    for remainder_value, modulus in system:
        assert solution % modulus == remainder_value


def modular_pow_via_crt(
    base: int,
    exponent: int,
    modulus: int,
    prime_power_moduli: Sequence[int],
) -> int:
    """
    Calculate a modular power separately under coprime component moduli,
    then reconstruct the result with CRT.

    The product of prime_power_moduli must equal modulus.
    """
    if math.prod(prime_power_moduli) != modulus:
        raise ValueError("component moduli must multiply to modulus")

    if any(
        math.gcd(prime_power_moduli[i], prime_power_moduli[j]) != 1
        for i in range(len(prime_power_moduli))
        for j in range(i + 1, len(prime_power_moduli))
    ):
        raise ValueError("component moduli must be pairwise coprime")

    congruences = [
        (
            binary_modular_pow(base, exponent, component),
            component,
        )
        for component in prime_power_moduli
    ]

    return chinese_remainder_theorem(congruences)


# ============================================================================
# 18. MATRIX MULTIPLICATION MODULO m
# ============================================================================

Matrix = List[List[int]]


def validate_square_matrix(matrix: Matrix) -> int:
    """Validate a square matrix and return its dimension."""
    if not matrix:
        raise ValueError("matrix must not be empty")

    size = len(matrix)

    if any(len(row) != size for row in matrix):
        raise ValueError("matrix must be square")

    return size


def matrix_multiply_mod(
    left: Matrix,
    right: Matrix,
    modulus: int,
) -> Matrix:
    """
    Multiply two square matrices modulo modulus.

    The modular reduction is applied during accumulation so values remain
    controlled.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    n = validate_square_matrix(left)
    if validate_square_matrix(right) != n:
        raise ValueError("matrix dimensions must match")

    result = [[0] * n for _ in range(n)]

    for i in range(n):
        for k in range(n):
            left_value = left[i][k] % modulus

            if left_value == 0:
                continue

            for j in range(n):
                result[i][j] = (
                    result[i][j] + left_value * right[k][j]
                ) % modulus

    return result


def identity_matrix(size: int) -> Matrix:
    """Return an identity matrix."""
    return [
        [1 if row == column else 0 for column in range(size)]
        for row in range(size)
    ]


def matrix_power_mod(
    matrix: Matrix,
    exponent: int,
    modulus: int,
) -> Matrix:
    """
    Raise a square matrix to a non-negative power using binary exponentiation.

    This is exactly the same algorithmic idea as scalar modular
    exponentiation, except multiplication is matrix multiplication.
    """
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    size = validate_square_matrix(matrix)

    result = identity_matrix(size)
    current = [[value % modulus for value in row] for row in matrix]
    power = exponent

    while power:
        if power & 1:
            result = matrix_multiply_mod(result, current, modulus)

        current = matrix_multiply_mod(current, current, modulus)
        power >>= 1

    return result


def fibonacci_mod_matrix(n: int, modulus: int) -> int:
    """
    Compute the nth Fibonacci number modulo modulus using matrix exponentiation.

    Matrix identity:

        [1 1]^n = [F(n+1) F(n)]
        [1 0]    [F(n)   F(n-1)]
    """
    if n < 0:
        raise ValueError("n must be non-negative")

    matrix = [
        [1, 1],
        [1, 0],
    ]

    powered = matrix_power_mod(matrix, n, modulus)
    return powered[0][1] % modulus


def demonstrate_matrix_exponentiation() -> None:
    print("\n" + "=" * 78)
    print("13. MATRIX EXPONENTIATION")
    print("=" * 78)

    modulus = 1_000_000_007

    for n in [0, 1, 2, 10, 100, 1_000_000]:
        value = fibonacci_mod_matrix(n, modulus)
        print(f"F({n}) mod {modulus} = {value}")


# ============================================================================
# 19. SAFE MODULAR MULTIPLICATION
# ============================================================================

def modular_multiply_by_doubling(
    a: int,
    b: int,
    modulus: int,
) -> int:
    """
    Compute (a*b) mod modulus using repeated doubling.

    This is useful conceptually when direct multiplication is undesirable or
    when working in environments where overflow is a concern.

    Python integers do not overflow like fixed-width C/C++ integers, so this
    implementation is primarily educational in Python.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    a %= modulus
    b %= modulus
    result = 0

    while b > 0:
        if b & 1:
            result = (result + a) % modulus

        a = (a + a) % modulus
        b >>= 1

    return result


def modular_pow_using_safe_multiplication(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Modular exponentiation using multiplication-by-doubling instead of
    direct multiplication.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    current = base % modulus
    power = exponent

    while power:
        if power & 1:
            result = modular_multiply_by_doubling(
                result,
                current,
                modulus,
            )

        current = modular_multiply_by_doubling(
            current,
            current,
            modulus,
        )

        power >>= 1

    return result


def demonstrate_safe_multiplication() -> None:
    print("\n" + "=" * 78)
    print("14. MODULAR MULTIPLICATION BY DOUBLING")
    print("=" * 78)

    a = 987654321987654321
    b = 123456789123456789
    modulus = 1_000_000_007

    direct = (a * b) % modulus
    safe = modular_multiply_by_doubling(a, b, modulus)

    print("Direct multiplication:", direct)
    print("Doubling multiplication:", safe)
    print("Equal:", direct == safe)


# ============================================================================
# 20. SLIDING-WINDOW EXPONENTIATION
# ============================================================================

def sliding_window_modular_pow(
    base: int,
    exponent: int,
    modulus: int,
    window_size: int = 4,
) -> int:
    """
    Left-to-right fixed-window modular exponentiation.

    The implementation precomputes odd powers:

        base^1, base^3, base^5, ...

    and processes chunks of exponent bits.

    This can reduce the number of multiplications compared with plain binary
    exponentiation at the cost of precomputation and memory.

    It is presented for algorithmic understanding. Cryptographic software
    requires careful constant-time engineering and should use audited
    cryptographic implementations.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    if window_size < 1:
        raise ValueError("window_size must be positive")

    if exponent == 0:
        return 1 % modulus

    base %= modulus

    # Number of odd powers needed:
    # 1, 3, 5, ..., 2^w - 1
    table_size = 1 << (window_size - 1)

    odd_powers = [0] * table_size
    odd_powers[0] = base

    base_squared = (base * base) % modulus

    for index in range(1, table_size):
        odd_powers[index] = (
            odd_powers[index - 1] * base_squared
        ) % modulus

    bits = f"{exponent:b}"
    result = 1 % modulus
    position = 0

    while position < len(bits):
        if bits[position] == "0":
            result = (result * result) % modulus
            position += 1
            continue

        remaining = len(bits) - position
        take = min(window_size, remaining)

        # Ensure the selected window ends in 1, so it represents an odd value.
        while take > 1 and bits[position + take - 1] == "0":
            take -= 1

        window_value = int(bits[position:position + take], 2)

        for _ in range(take):
            result = (result * result) % modulus

        index = (window_value - 1) // 2
        result = (result * odd_powers[index]) % modulus

        position += take

    return result


def demonstrate_sliding_window() -> None:
    print("\n" + "=" * 78)
    print("15. SLIDING-WINDOW EXPONENTIATION")
    print("=" * 78)

    base = 7
    exponent = 1234567
    modulus = 1_000_000_007

    binary_result = binary_modular_pow(base, exponent, modulus)
    window_result = sliding_window_modular_pow(
        base,
        exponent,
        modulus,
        window_size=4,
    )

    print("Binary result:", binary_result)
    print("Sliding-window result:", window_result)
    print("Equal:", binary_result == window_result)


# ============================================================================
# 21. RSA-STYLE MODULAR EXPONENTIATION
# ============================================================================

@dataclass(frozen=True)
class RSAExampleKeyPair:
    """
    Small educational RSA key pair.

    These values are intentionally tiny and insecure. They exist only to
    demonstrate modular exponentiation mechanics.
    """

    n: int
    public_exponent: int
    private_exponent: int


def create_tiny_rsa_example() -> RSAExampleKeyPair:
    """
    Construct a tiny RSA example using two small primes.

    p = 61
    q = 53
    n = p*q
    phi(n) = (p-1)(q-1)
    e = 17
    d = e^(-1) mod phi(n)
    """
    p = 61
    q = 53

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = modular_inverse(e, phi)

    return RSAExampleKeyPair(
        n=n,
        public_exponent=e,
        private_exponent=d,
    )


def rsa_encrypt_small(message: int, key: RSAExampleKeyPair) -> int:
    """Educational RSA encryption: c = m^e mod n."""
    if not 0 <= message < key.n:
        raise ValueError("message must be in the range [0, n)")
    return binary_modular_pow(
        message,
        key.public_exponent,
        key.n,
    )


def rsa_decrypt_small(ciphertext: int, key: RSAExampleKeyPair) -> int:
    """Educational RSA decryption: m = c^d mod n."""
    if not 0 <= ciphertext < key.n:
        raise ValueError("ciphertext must be in the range [0, n)")
    return binary_modular_pow(
        ciphertext,
        key.private_exponent,
        key.n,
    )


def demonstrate_rsa() -> None:
    print("\n" + "=" * 78)
    print("16. RSA-STYLE APPLICATION")
    print("=" * 78)

    key = create_tiny_rsa_example()

    message = 65
    ciphertext = rsa_encrypt_small(message, key)
    recovered = rsa_decrypt_small(ciphertext, key)

    print("n =", key.n)
    print("public exponent =", key.public_exponent)
    print("private exponent =", key.private_exponent)
    print("message =", message)
    print("ciphertext =", ciphertext)
    print("decrypted =", recovered)

    # Real RSA uses very large primes and carefully specified padding schemes.
    # Textbook RSA as demonstrated here is not secure for real communication.


# ============================================================================
# 22. DIFFIE-HELLMAN-STYLE KEY EXCHANGE
# ============================================================================

@dataclass(frozen=True)
class DiffieHellmanParameters:
    prime: int
    generator: int


def demonstrate_diffie_hellman() -> None:
    print("\n" + "=" * 78)
    print("17. DIFFIE-HELLMAN-STYLE APPLICATION")
    print("=" * 78)

    parameters = DiffieHellmanParameters(
        prime=23,
        generator=5,
    )

    alice_private = 6
    bob_private = 15

    alice_public = binary_modular_pow(
        parameters.generator,
        alice_private,
        parameters.prime,
    )

    bob_public = binary_modular_pow(
        parameters.generator,
        bob_private,
        parameters.prime,
    )

    alice_shared = binary_modular_pow(
        bob_public,
        alice_private,
        parameters.prime,
    )

    bob_shared = binary_modular_pow(
        alice_public,
        bob_private,
        parameters.prime,
    )

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared value:", alice_shared)
    print("Bob shared value:", bob_shared)
    print("Shared values equal:", alice_shared == bob_shared)

    # The security of real Diffie-Hellman depends on carefully chosen groups,
    # large parameters, protocol design, authentication, and implementation
    # details. Tiny classroom parameters are not secure.


# ============================================================================
# 23. MODULAR EXPONENTIATION AS A BUILDING BLOCK FOR COMBINATORICS
# ============================================================================

def factorial_mod(n: int, modulus: int) -> int:
    """Compute n! modulo modulus."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1 % modulus

    for value in range(2, n + 1):
        result = (result * value) % modulus

    return result


def binomial_mod_prime(
    n: int,
    k: int,
    prime_modulus: int,
) -> int:
    """
    Compute C(n,k) modulo a prime using factorials and Fermat inverses.

    This simple implementation assumes:
        0 <= k <= n
        prime_modulus is prime
        n < prime_modulus

    For much larger n, techniques such as Lucas's theorem are needed.
    """
    if n < 0 or k < 0 or k > n:
        raise ValueError("require 0 <= k <= n")

    if not is_prime(prime_modulus):
        raise ValueError("modulus must be prime")

    if n >= prime_modulus:
        raise ValueError("this implementation requires n < prime modulus")

    numerator = factorial_mod(n, prime_modulus)
    denominator = (
        factorial_mod(k, prime_modulus)
        * factorial_mod(n - k, prime_modulus)
    ) % prime_modulus

    inverse_denominator = fermat_inverse(
        denominator,
        prime_modulus,
    )

    return (numerator * inverse_denominator) % prime_modulus


def demonstrate_combinatorics() -> None:
    print("\n" + "=" * 78)
    print("18. MODULAR EXPONENTIATION IN COMBINATORICS")
    print("=" * 78)

    n = 10
    k = 3
    prime = 1_000_000_007

    result = binomial_mod_prime(n, k, prime)

    print(f"C({n}, {k}) mod {prime} = {result}")
    print("Ordinary C(10, 3) =", math.comb(n, k))


# ============================================================================
# 24. DISCRETE LOGARITHM CONTEXT
# ============================================================================

def baby_step_giant_step(
    base: int,
    target: int,
    modulus: int,
) -> Optional[int]:
    """
    Solve:

        base^x ≡ target (mod modulus)

    using the baby-step giant-step algorithm.

    This implementation is educational and assumes:
        gcd(base, modulus) = 1

    It returns one x if found, otherwise None.

    Complexity:
        Time  O(sqrt(modulus))
        Space O(sqrt(modulus))

    Modular exponentiation and modular inverses are essential components.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if math.gcd(base, modulus) != 1:
        raise ValueError("base and modulus must be coprime")

    base %= modulus
    target %= modulus

    step = math.isqrt(modulus) + 1

    # Baby steps:
    # target * base^(-j)
    #
    # Another common formulation stores base^j and matches against target
    # multiplied by inverse(base)^step.
    table = {}

    current = 1

    for j in range(step):
        table.setdefault(current, j)
        current = (current * base) % modulus

    factor = modular_inverse(
        binary_modular_pow(base, step, modulus),
        modulus,
    )

    gamma = target

    for i in range(step + 1):
        if gamma in table:
            candidate = i * step + table[gamma]

            if binary_modular_pow(base, candidate, modulus) == target:
                return candidate

        gamma = (gamma * factor) % modulus

    return None


def demonstrate_discrete_logarithm() -> None:
    print("\n" + "=" * 78)
    print("19. DISCRETE LOGARITHM CONTEXT")
    print("=" * 78)

    base = 5
    modulus = 23
    exponent = 6

    target = binary_modular_pow(base, exponent, modulus)
    recovered = baby_step_giant_step(base, target, modulus)

    print(f"{base}^{exponent} mod {modulus} = {target}")
    print("Recovered exponent:", recovered)


# ============================================================================
# 25. MODULAR EXPONENTIATION WITH EXPONENT GIVEN AS A STRING
# ============================================================================

def modular_pow_with_decimal_exponent(
    base: int,
    exponent_string: str,
    modulus: int,
) -> int:
    """
    Compute base^E mod modulus when E is supplied as a decimal string.

    This is useful when E is too large or is received as textual input.

    The exponent is processed digit by digit using:

        a^(10q + d)
        = (a^q)^10 * a^d

    Therefore:
        result <- result^10 * base^digit mod modulus
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    exponent_string = exponent_string.strip()

    if not exponent_string:
        raise ValueError("exponent string must not be empty")

    if not exponent_string.isdigit():
        raise ValueError("exponent string must contain decimal digits only")

    result = 1 % modulus
    base %= modulus

    for character in exponent_string:
        digit = ord(character) - ord("0")

        # result represents base^(digits processed so far).
        result = binary_modular_pow(result, 10, modulus)

        if digit:
            result = (
                result * binary_modular_pow(base, digit, modulus)
            ) % modulus

    return result


def demonstrate_string_exponent() -> None:
    print("\n" + "=" * 78)
    print("20. EXPONENT GIVEN AS A DECIMAL STRING")
    print("=" * 78)

    base = 7
    huge_exponent = "1234567890123456789012345678901234567890"
    modulus = 1_000_000_007

    result = modular_pow_with_decimal_exponent(
        base,
        huge_exponent,
        modulus,
    )

    print(f"{base}^{huge_exponent} mod {modulus} = {result}")


# ============================================================================
# 26. MODULAR EXPONENTIATION WITH BINARY STRING EXPONENT
# ============================================================================

def modular_pow_with_binary_exponent(
    base: int,
    binary_exponent: str,
    modulus: int,
) -> int:
    """
    Compute a^E mod m when E is provided as a binary string.

    Each bit causes a square, and a bit of 1 causes a multiplication.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    bits = binary_exponent.strip()

    if not bits or any(bit not in "01" for bit in bits):
        raise ValueError("binary exponent must contain only 0 and 1")

    result = 1 % modulus
    base %= modulus

    for bit in bits:
        result = (result * result) % modulus

        if bit == "1":
            result = (result * base) % modulus

    return result


# ============================================================================
# 27. BATCH MODULAR EXPONENTIATION
# ============================================================================

def batch_modular_powers(
    base: int,
    exponents: Iterable[int],
    modulus: int,
) -> List[int]:
    """
    Compute several powers independently.

    This simple function is useful when clarity matters more than advanced
    multi-exponentiation techniques.
    """
    return [
        binary_modular_pow(base, exponent, modulus)
        for exponent in exponents
    ]


def multi_exponentiation(
    bases: Sequence[int],
    exponents: Sequence[int],
    modulus: int,
) -> int:
    """
    Compute:

        product(base_i ^ exponent_i) mod modulus

    using a straightforward implementation.

    This pattern appears in cryptographic protocols and algebraic algorithms.
    """
    if len(bases) != len(exponents):
        raise ValueError("bases and exponents must have equal length")

    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1 % modulus

    for base, exponent in zip(bases, exponents):
        if exponent < 0:
            base = modular_inverse(base, modulus)
            exponent = -exponent

        result = (
            result * binary_modular_pow(base, exponent, modulus)
        ) % modulus

    return result


# ============================================================================
# 28. CONSTANT-TIME CONSIDERATIONS
# ============================================================================

def constant_pattern_modular_pow(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Demonstrate a fixed-operation-pattern exponentiation strategy.

    This is an educational illustration, not a cryptographic primitive.

    A classic concern with ordinary square-and-multiply is that the branch:

        if exponent_bit == 1

    causes different operation patterns for different secret exponents.

    Real cryptographic implementations can use techniques such as:
        - Montgomery ladder
        - fixed-window methods with constant-time table access
        - carefully implemented big-integer arithmetic

    Python itself is generally unsuitable for implementing production-grade
    constant-time cryptography because interpreter behavior and arbitrary
    precision integer operations can expose timing variability.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    power = base % modulus

    if exponent == 0:
        return result

    for bit_position in range(exponent.bit_length() - 1, -1, -1):
        squared = (result * result) % modulus
        multiplied = (squared * power) % modulus

        # Selecting between already-computed values is intended to illustrate
        # the idea of avoiding a secret-dependent multiplication branch.
        bit = (exponent >> bit_position) & 1

        if bit:
            result = multiplied
        else:
            result = squared

    return result


# ============================================================================
# 29. MONTGOMERY LADDER
# ============================================================================

def montgomery_ladder_pow(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Educational Montgomery-ladder-style modular exponentiation.

    It maintains two related powers:
        r0
        r1

    For each exponent bit, one multiplication and one squaring are performed
    in a regular pattern.

    This helps explain why ladder methods are valuable in cryptographic
    implementations, although true constant-time security requires more than
    this Python-level structure.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    r0 = 1 % modulus
    r1 = base % modulus

    for bit_position in range(exponent.bit_length() - 1, -1, -1):
        bit = (exponent >> bit_position) & 1

        product = (r0 * r1) % modulus

        if bit == 0:
            r1 = product
            r0 = (r0 * r0) % modulus
        else:
            r0 = product
            r1 = (r1 * r1) % modulus

    return r0


def demonstrate_montgomery_ladder() -> None:
    print("\n" + "=" * 78)
    print("21. MONTGOMERY LADDER CONCEPT")
    print("=" * 78)

    base = 17
    exponent = 12345
    modulus = 1_000_000_007

    ordinary = binary_modular_pow(base, exponent, modulus)
    ladder = montgomery_ladder_pow(base, exponent, modulus)

    print("Binary exponentiation:", ordinary)
    print("Montgomery ladder:", ladder)
    print("Equal:", ordinary == ladder)


# ============================================================================
# 30. PROPERTY-BASED STYLE TESTING
# ============================================================================

def verify_modular_power_identity(
    base: int,
    x: int,
    y: int,
    modulus: int,
) -> bool:
    """
    Verify:

        a^(x+y) mod m
        =
        (a^x mod m)(a^y mod m) mod m
    """
    left = binary_modular_pow(base, x + y, modulus)
    right = (
        binary_modular_pow(base, x, modulus)
        * binary_modular_pow(base, y, modulus)
    ) % modulus

    return left == right


def verify_power_of_power_identity(
    base: int,
    x: int,
    y: int,
    modulus: int,
) -> bool:
    """
    Verify:

        (a^x)^y mod m = a^(xy) mod m
    """
    left = binary_modular_pow(
        binary_modular_pow(base, x, modulus),
        y,
        modulus,
    )

    right = binary_modular_pow(
        base,
        x * y,
        modulus,
    )

    return left == right


def run_randomized_correctness_tests(
    test_count: int = 500,
    seed: int = 42,
) -> None:
    """
    Compare custom implementations against Python's pow.
    """
    print("\n" + "=" * 78)
    print("22. RANDOMIZED CORRECTNESS TESTING")
    print("=" * 78)

    generator = random.Random(seed)

    for _ in range(test_count):
        base = generator.randint(-10**12, 10**12)
        exponent = generator.randint(0, 10**5)
        modulus = generator.randint(2, 10**6)

        expected = pow(base, exponent, modulus)

        assert binary_modular_pow(
            base,
            exponent,
            modulus,
        ) == expected

        assert recursive_modular_pow(
            base,
            exponent,
            modulus,
        ) == expected

        assert modular_pow_using_safe_multiplication(
            base,
            exponent,
            modulus,
        ) == expected

        assert montgomery_ladder_pow(
            base,
            exponent,
            modulus,
        ) == expected

        assert sliding_window_modular_pow(
            base,
            exponent,
            modulus,
            window_size=4,
        ) == expected

    print(f"{test_count} randomized tests passed.")


def run_algebraic_identity_tests(
    test_count: int = 500,
    seed: int = 123,
) -> None:
    """Test fundamental modular exponentiation identities."""
    generator = random.Random(seed)

    for _ in range(test_count):
        base = generator.randint(-10_000, 10_000)
        x = generator.randint(0, 500)
        y = generator.randint(0, 500)
        modulus = generator.randint(2, 10_000)

        assert verify_modular_power_identity(
            base,
            x,
            y,
            modulus,
        )

        assert verify_power_of_power_identity(
            base,
            x,
            y,
            modulus,
        )

    print(f"{test_count} algebraic identity tests passed.")


# ============================================================================
# 31. ERROR-HANDLING TESTS
# ============================================================================

def demonstrate_validation() -> None:
    print("\n" + "=" * 78)
    print("23. VALIDATION AND ERROR HANDLING")
    print("=" * 78)

    invalid_calls: List[Tuple[str, Callable[[], object]]] = [
        (
            "zero modulus",
            lambda: binary_modular_pow(2, 10, 0),
        ),
        (
            "negative exponent",
            lambda: binary_modular_pow(2, -1, 7),
        ),
        (
            "non-invertible modular inverse",
            lambda: modular_inverse(6, 15),
        ),
        (
            "non-prime Fermat modulus",
            lambda: fermat_inverse(3, 15),
        ),
        (
            "negative factorial",
            lambda: factorial_mod(-1, 100),
        ),
    ]

    for description, operation in invalid_calls:
        try:
            operation()
        except ValueError as error:
            print(f"{description}: correctly rejected -> {error}")
        else:
            raise AssertionError(
                f"Expected ValueError for {description}"
            )


# ============================================================================
# 32. PERFORMANCE BENCHMARK
# ============================================================================

def benchmark_modular_exponentiation() -> None:
    print("\n" + "=" * 78)
    print("24. PERFORMANCE CONSIDERATIONS")
    print("=" * 78)

    base = 123456789
    modulus = 1_000_000_007

    exponents = [
        10_000,
        100_000,
        1_000_000,
        10_000_000,
    ]

    print(
        f"{'Exponent':>12} | {'Binary (seconds)':>20} | "
        f"{'Built-in pow (seconds)':>24}"
    )
    print("-" * 64)

    for exponent in exponents:
        start = time.perf_counter()
        binary_result = binary_modular_pow(
            base,
            exponent,
            modulus,
        )
        binary_time = time.perf_counter() - start

        start = time.perf_counter()
        builtin_result = pow(
            base,
            exponent,
            modulus,
        )
        builtin_time = time.perf_counter() - start

        assert binary_result == builtin_result

        print(
            f"{exponent:>12} | "
            f"{binary_time:>20.8f} | "
            f"{builtin_time:>24.8f}"
        )

    # The built-in pow is implemented in optimized native code and can be
    # substantially faster than Python-level loops. The benchmark is not a
    # universal performance guarantee because results depend on hardware,
    # Python version, workload, and integer sizes.


# ============================================================================
# 33. LARGE EXPONENT EXAMPLE
# ============================================================================

def demonstrate_huge_exponent() -> None:
    print("\n" + "=" * 78)
    print("25. EXTREMELY LARGE EXPONENT")
    print("=" * 78)

    base = 123456789
    exponent = 10**100
    modulus = 1_000_000_007

    # The exponent has 101 decimal digits, but only about 333 binary bits.
    # Binary exponentiation therefore needs only a few hundred iterations.
    result = binary_modular_pow(base, exponent, modulus)

    print("Exponent decimal digits:", len(str(exponent)))
    print("Exponent binary bits:", exponent.bit_length())
    print("Result:", result)


# ============================================================================
# 34. MODULAR POWER TABLE
# ============================================================================

def print_power_table(
    base: int,
    modulus: int,
    maximum_exponent: int,
) -> None:
    """Print powers of base modulo modulus for small educational examples."""
    print(
        f"\nPowers of {base} modulo {modulus}:"
    )

    for exponent in range(maximum_exponent + 1):
        value = binary_modular_pow(
            base,
            exponent,
            modulus,
        )
        print(f"{base}^{exponent:>2} mod {modulus} = {value}")


# ============================================================================
# 35. MODULAR EXPONENTIATION AND CONGRUENCES
# ============================================================================

def demonstrate_congruence_properties() -> None:
    print("\n" + "=" * 78)
    print("26. CONGRUENCES AND EXPONENTIATION")
    print("=" * 78)

    modulus = 13
    a = 10
    b = 23

    print(f"a = {a}, b = {b}, modulus = {modulus}")
    print("a mod m =", a % modulus)
    print("b mod m =", b % modulus)
    print("a and b congruent:", a % modulus == b % modulus)

    for exponent in [1, 2, 3, 5, 10]:
        left = binary_modular_pow(a, exponent, modulus)
        right = binary_modular_pow(b, exponent, modulus)

        print(
            f"Exponent {exponent:>2}: "
            f"a^k mod m={left}, "
            f"b^k mod m={right}, "
            f"equal={left == right}"
        )

    # If:
    #     a ≡ b (mod m)
    #
    # then:
    #     a^k ≡ b^k (mod m)
    #
    # for every non-negative integer k.


# ============================================================================
# 36. PERIODICITY OF POWERS
# ============================================================================

def multiplicative_order(
    base: int,
    modulus: int,
) -> int:
    """
    Find the smallest positive k such that:

        base^k ≡ 1 (mod modulus)

    This requires gcd(base, modulus) = 1.

    The simple implementation checks successive powers and is intended for
    small educational moduli.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if math.gcd(base, modulus) != 1:
        raise ValueError("base and modulus must be coprime")

    current = base % modulus

    for exponent in range(1, modulus + 1):
        if current == 1:
            return exponent

        current = (current * base) % modulus

    raise RuntimeError("multiplicative order not found")


def demonstrate_periodicity() -> None:
    print("\n" + "=" * 78)
    print("27. PERIODICITY AND MULTIPLICATIVE ORDER")
    print("=" * 78)

    base = 2
    modulus = 7

    order = multiplicative_order(base, modulus)

    print(
        f"Multiplicative order of {base} modulo {modulus}:",
        order,
    )

    print("Powers:")
    for exponent in range(1, order + 1):
        print(
            f"{base}^{exponent} mod {modulus} =",
            binary_modular_pow(base, exponent, modulus),
        )


# ============================================================================
# 37. EXPONENT REDUCTION USING MULTIPLICATIVE ORDER
# ============================================================================

def reduce_exponent_by_order(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Reduce exponent using the multiplicative order of the base.

    If ord_m(base) = r, then:

        base^r ≡ 1 (mod m)

    and therefore exponents may be reduced modulo r.
    """
    order = multiplicative_order(base, modulus)
    return binary_modular_pow(
        base,
        exponent % order,
        modulus,
    )


# ============================================================================
# 38. FAST EXPONENTIATION FOR POLYNOMIAL-LIKE EXPRESSIONS
# ============================================================================

def polynomial_power_mod(
    x: int,
    coefficients: Sequence[int],
    exponent: int,
    modulus: int,
) -> int:
    """
    Demonstrate a modular power applied to a polynomial value.

    First evaluate:

        P(x) = c0 + c1*x + c2*x^2 + ...

    using Horner's rule, then calculate P(x)^exponent modulo modulus.

    This combines modular reduction, polynomial evaluation, and exponentiation.
    """
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    polynomial_value = 0

    for coefficient in reversed(coefficients):
        polynomial_value = (
            polynomial_value * x + coefficient
        ) % modulus

    return binary_modular_pow(
        polynomial_value,
        exponent,
        modulus,
    )


# ============================================================================
# 39. RSA CRT OPTIMIZATION
# ============================================================================

def rsa_decrypt_using_crt(
    ciphertext: int,
    p: int,
    q: int,
    private_exponent: int,
) -> int:
    """
    Demonstrate the Chinese Remainder Theorem optimization used in RSA-style
    private operations.

    Instead of calculating modulo n = p*q directly:

        m = c^d mod n

    calculate:

        m_p = c^d mod p
        m_q = c^d mod q

    and reconstruct m modulo p*q.

    Real RSA implementations use carefully engineered CRT recombination and
    protections against fault attacks.
    """
    n = p * q

    if not (0 <= ciphertext < n):
        raise ValueError("ciphertext must be in [0, n)")

    m_p = binary_modular_pow(
        ciphertext,
        private_exponent,
        p,
    )

    m_q = binary_modular_pow(
        ciphertext,
        private_exponent,
        q,
    )

    return chinese_remainder_theorem(
        [
            (m_p, p),
            (m_q, q),
        ]
    )


def demonstrate_rsa_crt() -> None:
    print("\n" + "=" * 78)
    print("28. RSA CRT OPTIMIZATION")
    print("=" * 78)

    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = modular_inverse(e, phi)

    message = 65
    ciphertext = binary_modular_pow(message, e, n)

    direct = binary_modular_pow(ciphertext, d, n)
    crt = rsa_decrypt_using_crt(
        ciphertext,
        p,
        q,
        d,
    )

    print("Direct RSA-style decryption:", direct)
    print("CRT decryption:", crt)
    print("Equal:", direct == crt)


# ============================================================================
# 40. MODULAR EXPONENTIATION WITH A COMPOSITE MODULUS
# ============================================================================

def demonstrate_composite_modulus() -> None:
    print("\n" + "=" * 78)
    print("29. COMPOSITE MODULI")
    print("=" * 78)

    base = 7
    exponent = 12345
    modulus = 1000

    result = binary_modular_pow(
        base,
        exponent,
        modulus,
    )

    print(
        f"{base}^{exponent} mod {modulus} =",
        result,
    )

    print(
        "gcd(base, modulus) =",
        math.gcd(base, modulus),
    )

    print(
        "phi(modulus) =",
        euler_totient(modulus),
    )


# ============================================================================
# 41. COMMON IMPLEMENTATION MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n" + "=" * 78)
    print("30. COMMON IMPLEMENTATION MISTAKES")
    print("=" * 78)

    print(
        "Mistake 1: computing base ** exponent before applying % modulus."
    )
    print(
        "Correct approach: reduce modulo during repeated squaring."
    )

    print(
        "Mistake 2: using exponentiation reduction without checking gcd."
    )
    print(
        "Correct approach: verify the theorem's conditions first."
    )

    print(
        "Mistake 3: treating modular division like ordinary division."
    )
    print(
        "Correct approach: use a modular inverse when it exists."
    )

    print(
        "Mistake 4: assuming every number has an inverse modulo m."
    )
    print(
        "Correct condition: gcd(a, m) must equal 1."
    )

    print(
        "Mistake 5: using textbook RSA directly in production."
    )
    print(
        "Correct approach: use standardized, audited cryptographic schemes."
    )

    print(
        "Mistake 6: assuming Python-level branches automatically provide "
        "constant-time cryptography."
    )
    print(
        "Correct approach: use dedicated cryptographic libraries."
    )


# ============================================================================
# 42. LIMITATIONS AND TRADE-OFFS
# ============================================================================

def print_tradeoffs() -> None:
    print("\n" + "=" * 78)
    print("31. ALGORITHM TRADE-OFFS")
    print("=" * 78)

    tradeoffs = [
        (
            "Naive repeated multiplication",
            "O(e)",
            "Very simple",
            "Terrible for huge exponents",
        ),
        (
            "Binary exponentiation",
            "O(log e)",
            "Simple and efficient",
            "Variable multiplication pattern",
        ),
        (
            "Sliding window",
            "O(log e)",
            "Fewer multiplications",
            "Precomputation and memory",
        ),
        (
            "Montgomery ladder",
            "O(log e)",
            "Regular operation structure",
            "Still requires careful implementation",
        ),
        (
            "CRT decomposition",
            "Depends on factors",
            "Can accelerate RSA-style operations",
            "Requires factorization and careful recombination",
        ),
    ]

    print(
        f"{'Method':<30} | {'Time':<12} | "
        f"{'Strength':<30} | Limitation"
    )
    print("-" * 115)

    for name, complexity, strength, limitation in tradeoffs:
        print(
            f"{name:<30} | {complexity:<12} | "
            f"{strength:<30} | {limitation}"
        )


# ============================================================================
# 43. PRACTICAL API
# ============================================================================

def mod_pow(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Small production-style API around Python's optimized implementation.

    For ordinary Python applications, this is generally the preferred form.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    if exponent < 0:
        return modular_pow_signed(base, exponent, modulus)

    return pow(base, exponent, modulus)


def demonstrate_practical_api() -> None:
    print("\n" + "=" * 78)
    print("32. PRACTICAL API")
    print("=" * 78)

    examples = [
        (2, 100, 1_000_000_007),
        (123456789, 10**20, 998244353),
        (-5, 17, 97),
    ]

    for base, exponent, modulus in examples:
        print(
            f"mod_pow({base}, {exponent}, {modulus}) =",
            mod_pow(base, exponent, modulus),
        )

    print(
        "Negative exponent example:",
        mod_pow(3, -2, 11),
    )


# ============================================================================
# 44. MAIN DEMONSTRATION
# ============================================================================

def run_all_demos() -> None:
    """Run the educational demonstrations in a logical order."""
    demonstrate_basic_modular_arithmetic()
    demonstrate_definition()

    print("\n" + "=" * 78)
    print("BINARY EXPONENTIATION WALKTHROUGH")
    print("=" * 78)
    binary_modular_pow_verbose(3, 13, 7)

    demonstrate_binary_structure()
    compare_operation_counts()
    demonstrate_edge_cases()
    demonstrate_builtin_pow()

    print("\nCorrectness invariant example:")
    print(
        binary_modular_pow_with_invariant(
            123,
            456,
            1009,
        )
    )

    demonstrate_modular_inverse()
    demonstrate_totient()
    demonstrate_euler_theorem()
    demonstrate_fermat()
    demonstrate_exponent_reduction_warning()

    demonstrate_crt()

    print("\nCRT-based modular exponentiation:")
    crt_result = modular_pow_via_crt(
        base=7,
        exponent=123456,
        modulus=15 * 16,
        prime_power_moduli=[15, 16],
    )
    direct_result = binary_modular_pow(
        7,
        123456,
        240,
    )
    print("CRT result:", crt_result)
    print("Direct result:", direct_result)
    print("Equal:", crt_result == direct_result)

    demonstrate_matrix_exponentiation()
    demonstrate_safe_multiplication()
    demonstrate_sliding_window()
    demonstrate_rsa()
    demonstrate_diffie_hellman()
    demonstrate_combinatorics()
    demonstrate_discrete_logarithm()
    demonstrate_string_exponent()

    print_power_table(
        base=3,
        modulus=10,
        maximum_exponent=12,
    )

    demonstrate_congruence_properties()
    demonstrate_periodicity()
    demonstrate_montgomery_ladder()

    print("\nPolynomial modular power example:")
    polynomial_result = polynomial_power_mod(
        x=7,
        coefficients=[2, 3, 5],
        exponent=100,
        modulus=1_000_000_007,
    )
    print("Result:", polynomial_result)

    demonstrate_rsa_crt()
    demonstrate_composite_modulus()
    demonstrate_common_mistakes()
    print_tradeoffs()
    demonstrate_practical_api()

    demonstrate_validation()
    run_randomized_correctness_tests()
    run_algebraic_identity_tests()

    demonstrate_huge_exponent()

    print("\n" + "=" * 78)
    print("EDUCATIONAL DEMONSTRATIONS COMPLETE")
    print("=" * 78)


# ============================================================================
# 45. PROGRAM ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    run_all_demos()
