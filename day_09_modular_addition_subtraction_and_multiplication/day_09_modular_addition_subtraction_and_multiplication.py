"""
Modular Addition, Subtraction and Multiplication
================================================

A self-contained study script covering modular arithmetic from absolute
beginner concepts through advanced implementation details.

The script demonstrates:

1. What modular arithmetic means
2. Remainders and congruence
3. Modulus and residue classes
4. Modular addition
5. Modular subtraction
6. Modular multiplication
7. Negative numbers
8. Python's modulo behavior
9. Closure and well-defined operations
10. Properties of modular arithmetic
11. Overflow-safe multiplication concepts
12. Fast modular exponentiation
13. Modular inverses
14. Extended Euclidean Algorithm
15. Solving simple modular equations
16. Chinese Remainder Theorem
17. Common mistakes and edge cases
18. Performance comparisons
19. Validation and testing
20. Practical applications
21. An interactive demonstration

No external packages are required.

Run with:

    python modular_arithmetic.py
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd
from time import perf_counter
from typing import Iterable, List, Optional, Sequence, Tuple


# ============================================================================
# SECTION 1: FUNDAMENTAL DEFINITIONS
# ============================================================================

def remainder(a: int, m: int) -> int:
    """
    Return the canonical remainder of a modulo m.

    For positive m, the result is always in:

        0 <= result < m

    Examples:
        17 mod 5  = 2
        20 mod 5  = 0
        23 mod 7  = 2
        -3 mod 5  = 2

    A modulus of zero is invalid.
    """
    if m <= 0:
        raise ValueError("The modulus must be a positive integer.")
    return a % m


def are_congruent(a: int, b: int, m: int) -> bool:
    """
    Test whether:

        a ≡ b (mod m)

    This is true exactly when m divides (a - b).
    """
    if m <= 0:
        raise ValueError("The modulus must be a positive integer.")
    return (a - b) % m == 0


def residue_class(a: int, m: int) -> int:
    """
    Return the canonical representative of the residue class of a modulo m.

    For example, all of:

        ..., -13, -8, -3, 2, 7, 12, 17, ...

    belong to the same residue class modulo 5.

    The canonical representative is 2.
    """
    return remainder(a, m)


def demonstrate_remainders() -> None:
    """Demonstrate the basic remainder operation."""
    print("\n" + "=" * 78)
    print("1. REMAINDERS AND CONGRUENCE")
    print("=" * 78)

    examples = [
        (17, 5),
        (20, 5),
        (23, 7),
        (-3, 5),
        (100, 9),
    ]

    for a, m in examples:
        print(f"{a} mod {m} = {remainder(a, m)}")

    print("\nCongruence examples:")
    pairs = [
        (17, 2, 5),
        (22, 7, 5),
        (14, 4, 5),
        (29, 5, 8),
    ]

    for a, b, m in pairs:
        symbol = "≡" if are_congruent(a, b, m) else "≢"
        print(f"{a} {symbol} {b} (mod {m})")


# ============================================================================
# SECTION 2: MODULAR ADDITION
# ============================================================================

def modular_add(a: int, b: int, m: int) -> int:
    """
    Compute modular addition:

        (a + b) mod m

    The reduction may be performed after ordinary addition because:

        (a + b) mod m
        =
        ((a mod m) + (b mod m)) mod m
    """
    validate_modulus(m)
    return (a + b) % m


def modular_add_reduced(a: int, b: int, m: int) -> int:
    """
    Modular addition using reduced operands.

    This makes the reduction property explicit.
    """
    validate_modulus(m)
    return ((a % m) + (b % m)) % m


def demonstrate_modular_addition() -> None:
    """Demonstrate modular addition."""
    print("\n" + "=" * 78)
    print("2. MODULAR ADDITION")
    print("=" * 78)

    examples = [
        (7, 8, 10),
        (17, 25, 12),
        (100, 250, 7),
        (-3, 8, 5),
        (-12, -9, 7),
    ]

    for a, b, m in examples:
        direct = modular_add(a, b, m)
        reduced = modular_add_reduced(a, b, m)

        print(
            f"({a} + {b}) mod {m} = {direct}; "
            f"reduced operands -> {reduced}"
        )

    print("\nExample:")
    print("(17 + 25) mod 12")
    print("= 42 mod 12")
    print("= 6")


# ============================================================================
# SECTION 3: MODULAR SUBTRACTION
# ============================================================================

def modular_subtract(a: int, b: int, m: int) -> int:
    """
    Compute modular subtraction:

        (a - b) mod m

    A negative ordinary result is perfectly valid before reduction.

    Example:

        (3 - 8) mod 5
        = -5 mod 5
        = 0
    """
    validate_modulus(m)
    return (a - b) % m


def demonstrate_modular_subtraction() -> None:
    """Demonstrate modular subtraction."""
    print("\n" + "=" * 78)
    print("3. MODULAR SUBTRACTION")
    print("=" * 78)

    examples = [
        (15, 8, 7),
        (3, 8, 5),
        (10, 17, 6),
        (-3, 8, 5),
        (4, -9, 7),
    ]

    for a, b, m in examples:
        print(f"({a} - {b}) mod {m} = {modular_subtract(a, b, m)}")

    print("\nImportant:")
    print("A modular result is represented by a residue in 0, 1, ..., m-1.")
    print("Therefore a negative intermediate value is reduced to its residue.")


# ============================================================================
# SECTION 4: MODULAR MULTIPLICATION
# ============================================================================

def modular_multiply(a: int, b: int, m: int) -> int:
    """
    Compute modular multiplication:

        (a * b) mod m

    Reduction can be performed before multiplication:

        (a * b) mod m
        =
        ((a mod m) * (b mod m)) mod m
    """
    validate_modulus(m)
    return (a * b) % m


def modular_multiply_reduced(a: int, b: int, m: int) -> int:
    """
    Explicitly reduce operands before multiplying.
    """
    validate_modulus(m)
    return ((a % m) * (b % m)) % m


def demonstrate_modular_multiplication() -> None:
    """Demonstrate modular multiplication."""
    print("\n" + "=" * 78)
    print("4. MODULAR MULTIPLICATION")
    print("=" * 78)

    examples = [
        (7, 8, 10),
        (17, 25, 12),
        (100, 250, 7),
        (-3, 8, 5),
        (-12, -9, 7),
    ]

    for a, b, m in examples:
        direct = modular_multiply(a, b, m)
        reduced = modular_multiply_reduced(a, b, m)

        print(
            f"({a} * {b}) mod {m} = {direct}; "
            f"reduced operands -> {reduced}"
        )

    print("\nLarge-value example:")
    a = 123456789
    b = 987654321
    m = 1000003

    print(f"({a} * {b}) mod {m} = {modular_multiply(a, b, m)}")


# ============================================================================
# SECTION 5: MODULUS VALIDATION
# ============================================================================

def validate_modulus(m: int) -> None:
    """
    Validate the modulus.

    This tutorial defines modulus as a positive integer.

    A modulus of zero is not valid because division/remainder modulo zero
    is undefined.

    Negative moduli are mathematically definable under some conventions,
    but using a positive modulus provides a unique canonical residue set
    {0, 1, ..., m-1} and avoids unnecessary ambiguity.
    """
    if not isinstance(m, int):
        raise TypeError("The modulus must be an integer.")
    if m <= 0:
        raise ValueError("The modulus must be positive.")


# ============================================================================
# SECTION 6: PYTHON'S MODULO BEHAVIOR
# ============================================================================

def demonstrate_negative_modulo() -> None:
    """
    Explain Python's modulo behavior for negative operands.

    Python satisfies:

        a == (a // m) * m + (a % m)

    for nonzero m.

    With a positive m, a % m is therefore nonnegative.
    """
    print("\n" + "=" * 78)
    print("5. NEGATIVE NUMBERS AND PYTHON'S % OPERATOR")
    print("=" * 78)

    examples = [
        (-1, 5),
        (-2, 5),
        (-3, 5),
        (-7, 5),
        (-10, 6),
    ]

    for a, m in examples:
        q = a // m
        r = a % m
        print(
            f"{a} = ({q}) * {m} + {r}; "
            f"{a} % {m} = {r}"
        )

    print("\nFor positive m, Python gives:")
    print("0 <= a % m < m")


# ============================================================================
# SECTION 7: CORE ALGEBRAIC PROPERTIES
# ============================================================================

def demonstrate_properties() -> None:
    """Demonstrate important algebraic properties."""
    print("\n" + "=" * 78)
    print("6. ALGEBRAIC PROPERTIES")
    print("=" * 78)

    a, b, c, m = 17, 25, 31, 12

    print(f"Modulus m = {m}")
    print(f"a = {a}, b = {b}, c = {c}")

    # Closure:
    add_result = (a + b) % m
    sub_result = (a - b) % m
    mul_result = (a * b) % m

    print("\nClosure:")
    print(f"(a + b) mod m = {add_result}")
    print(f"(a - b) mod m = {sub_result}")
    print(f"(a * b) mod m = {mul_result}")

    # Commutativity:
    print("\nCommutativity:")
    print("(a + b) mod m == (b + a) mod m:",
          (a + b) % m == (b + a) % m)
    print("(a * b) mod m == (b * a) mod m:",
          (a * b) % m == (b * a) % m)

    # Associativity:
    print("\nAssociativity:")
    print(
        "((a + b) + c) mod m == (a + (b + c)) mod m:",
        ((a + b) + c) % m == (a + (b + c)) % m,
    )
    print(
        "((a * b) * c) mod m == (a * (b * c)) mod m:",
        ((a * b) * c) % m == (a * (b * c)) % m,
    )

    # Distributivity:
    print("\nDistributivity:")
    left = (a * (b + c)) % m
    right = ((a * b) + (a * c)) % m

    print(f"a * (b + c) mod m = {left}")
    print(f"(a*b + a*c) mod m = {right}")
    print("Equal:", left == right)


# ============================================================================
# SECTION 8: REDUCTION BEFORE OR AFTER OPERATIONS
# ============================================================================

def demonstrate_reduction_rules() -> None:
    """
    Show why operands can be reduced before addition, subtraction, and
    multiplication.

    If:

        a ≡ a' (mod m)
        b ≡ b' (mod m)

    then:

        a + b ≡ a' + b' (mod m)
        a - b ≡ a' - b' (mod m)
        ab  ≡ a'b' (mod m)
    """
    print("\n" + "=" * 78)
    print("7. REDUCING OPERANDS BEFORE CALCULATION")
    print("=" * 78)

    a = 123456789
    b = 987654321
    m = 97

    print("Original operands:")
    print("a =", a)
    print("b =", b)
    print("m =", m)

    print("\nReduced operands:")
    print("a mod m =", a % m)
    print("b mod m =", b % m)

    print("\nAddition:")
    print("Direct:", (a + b) % m)
    print("Reduced:", ((a % m) + (b % m)) % m)

    print("\nSubtraction:")
    print("Direct:", (a - b) % m)
    print("Reduced:", ((a % m) - (b % m)) % m)

    print("\nMultiplication:")
    print("Direct:", (a * b) % m)
    print("Reduced:", ((a % m) * (b % m)) % m)


# ============================================================================
# SECTION 9: MODULAR ARITHMETIC AS CLOCK ARITHMETIC
# ============================================================================

def clock_addition(hour: int, hours_to_add: int) -> int:
    """
    Add hours on a 12-hour clock.

    We represent 12 o'clock as 12 rather than 0 for user-facing output.
    Internally, residues modulo 12 are convenient.
    """
    validate_modulus(12)

    internal_hour = hour % 12
    result = (internal_hour + hours_to_add) % 12

    return 12 if result == 0 else result


def demonstrate_clock_arithmetic() -> None:
    """Demonstrate modular arithmetic with a clock."""
    print("\n" + "=" * 78)
    print("8. CLOCK ARITHMETIC")
    print("=" * 78)

    examples = [
        (10, 5),
        (11, 7),
        (12, 8),
        (3, -7),
        (1, 25),
    ]

    for hour, change in examples:
        result = clock_addition(hour, change)
        print(f"{hour}:00 + {change} hours -> {result}:00")


# ============================================================================
# SECTION 10: A SMALL MODULAR ARITHMETIC CLASS
# ============================================================================

@dataclass(frozen=True)
class ModularInteger:
    """
    Represent an integer in Z/mZ.

    Two integers that differ by a multiple of m represent the same
    modular value.

    Example:

        ModularInteger(17, 5)

    represents the same residue as:

        ModularInteger(2, 5)
        ModularInteger(-3, 5)
    """

    value: int
    modulus: int

    def __post_init__(self) -> None:
        validate_modulus(self.modulus)

        if not isinstance(self.value, int):
            raise TypeError("The value must be an integer.")

    @property
    def residue(self) -> int:
        """Return the canonical representative."""
        return self.value % self.modulus

    def __add__(self, other: ModularInteger) -> ModularInteger:
        self._check_compatible(other)
        return ModularInteger(
            (self.residue + other.residue) % self.modulus,
            self.modulus,
        )

    def __sub__(self, other: ModularInteger) -> ModularInteger:
        self._check_compatible(other)
        return ModularInteger(
            (self.residue - other.residue) % self.modulus,
            self.modulus,
        )

    def __mul__(self, other: ModularInteger) -> ModularInteger:
        self._check_compatible(other)
        return ModularInteger(
            (self.residue * other.residue) % self.modulus,
            self.modulus,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModularInteger):
            return NotImplemented

        if self.modulus != other.modulus:
            return False

        return self.residue == other.residue

    def _check_compatible(self, other: ModularInteger) -> None:
        if not isinstance(other, ModularInteger):
            raise TypeError(
                "Operations require another ModularInteger."
            )

        if self.modulus != other.modulus:
            raise ValueError(
                "Modular integers must use the same modulus."
            )

    def __repr__(self) -> str:
        return f"{self.residue} (mod {self.modulus})"


def demonstrate_modular_integer_class() -> None:
    """Demonstrate a reusable modular integer abstraction."""
    print("\n" + "=" * 78)
    print("9. MODULAR INTEGER CLASS")
    print("=" * 78)

    a = ModularInteger(17, 5)
    b = ModularInteger(13, 5)
    c = ModularInteger(-3, 5)

    print("a =", a)
    print("b =", b)
    print("c =", c)

    print("\na + b =", a + b)
    print("a - b =", a - b)
    print("a * b =", a * b)

    print("\nEquivalent residue:")
    print("a == c:", a == c)

    try:
        incompatible = ModularInteger(3, 7)
        print(a + incompatible)
    except ValueError as error:
        print("Different modulus rejected:", error)


# ============================================================================
# SECTION 11: MODULAR EXPONENTIATION
# ============================================================================

def modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Compute:

        base^exponent mod modulus

    using binary exponentiation.

    Naively computing base ** exponent first can require enormous
    intermediate integers.

    Binary exponentiation reduces the number of multiplications from
    O(exponent) to O(log exponent).

    The algorithm repeatedly squares the base and processes the binary
    representation of the exponent.
    """
    validate_modulus(modulus)

    if exponent < 0:
        raise ValueError(
            "This implementation requires a nonnegative exponent."
        )

    result = 1 % modulus
    base %= modulus

    while exponent > 0:
        # If the current exponent bit is 1, include this power.
        if exponent & 1:
            result = (result * base) % modulus

        # Square the current power.
        base = (base * base) % modulus

        # Move to the next binary bit.
        exponent >>= 1

    return result


def demonstrate_modular_exponentiation() -> None:
    """Demonstrate efficient modular exponentiation."""
    print("\n" + "=" * 78)
    print("10. MODULAR EXPONENTIATION")
    print("=" * 78)

    examples = [
        (2, 10, 1000),
        (3, 20, 17),
        (12345, 67890, 1000003),
    ]

    for base, exponent, modulus in examples:
        result = modular_power(base, exponent, modulus)

        # Python's built-in pow(base, exponent, modulus) is also optimized.
        builtin_result = pow(base, exponent, modulus)

        print(
            f"{base}^{exponent} mod {modulus} = {result}; "
            f"built-in verification = {builtin_result}"
        )


# ============================================================================
# SECTION 12: EXTENDED EUCLIDEAN ALGORITHM
# ============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Return (g, x, y) satisfying:

        ax + by = g

    where:

        g = gcd(a, b)

    This is the Extended Euclidean Algorithm.

    It is fundamental for finding modular inverses.
    """
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r

        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    x = old_s if a >= 0 else -old_s
    y = old_t if b >= 0 else -old_t

    return old_r, x, y


def demonstrate_extended_gcd() -> None:
    """Demonstrate the Extended Euclidean Algorithm."""
    print("\n" + "=" * 78)
    print("11. EXTENDED EUCLIDEAN ALGORITHM")
    print("=" * 78)

    examples = [
        (30, 12),
        (35, 64),
        (101, 23),
    ]

    for a, b in examples:
        g, x, y = extended_gcd(a, b)

        print(f"\na = {a}, b = {b}")
        print(f"gcd(a, b) = {g}")
        print(f"x = {x}, y = {y}")
        print(f"{a}*{x} + {b}*{y} = {a*x + b*y}")


# ============================================================================
# SECTION 13: MODULAR INVERSE
# ============================================================================

def modular_inverse(a: int, modulus: int) -> int:
    """
    Compute the modular multiplicative inverse of a modulo modulus.

    An inverse x satisfies:

        ax ≡ 1 (mod m)

    Such an inverse exists if and only if:

        gcd(a, m) = 1

    Example:

        3^-1 mod 7 = 5

    because:

        3 * 5 = 15 ≡ 1 (mod 7)
    """
    validate_modulus(modulus)

    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise ValueError(
            f"{a} has no modular inverse modulo {modulus}; "
            f"gcd({a}, {modulus}) = {g}."
        )

    return x % modulus


def demonstrate_modular_inverses() -> None:
    """Demonstrate modular inverses and non-invertible values."""
    print("\n" + "=" * 78)
    print("12. MODULAR MULTIPLICATIVE INVERSE")
    print("=" * 78)

    examples = [
        (3, 7),
        (5, 11),
        (10, 17),
        (-3, 11),
    ]

    for a, m in examples:
        inverse = modular_inverse(a, m)
        verification = (a * inverse) % m

        print(
            f"Inverse of {a} mod {m} = {inverse}; "
            f"verification: {a} * {inverse} mod {m} = {verification}"
        )

    print("\nNon-invertible example:")

    try:
        modular_inverse(6, 15)
    except ValueError as error:
        print(error)


# ============================================================================
# SECTION 14: MODULAR DIVISION
# ============================================================================

def modular_divide(a: int, b: int, modulus: int) -> int:
    """
    Solve:

        a / b (mod m)

    by multiplying a by the modular inverse of b:

        a * b^-1 mod m

    This is only valid when gcd(b, m) = 1.

    Modular division is not ordinary division.
    """
    inverse = modular_inverse(b, modulus)
    return (a * inverse) % modulus


def demonstrate_modular_division() -> None:
    """Demonstrate valid and invalid modular division."""
    print("\n" + "=" * 78)
    print("13. MODULAR DIVISION")
    print("=" * 78)

    a, b, m = 10, 3, 7

    result = modular_divide(a, b, m)

    print(f"{a} / {b} mod {m} = {result}")
    print(
        f"Verification: ({b} * {result}) mod {m} = "
        f"{(b * result) % m}"
    )

    print("\nDivision by a non-invertible value:")

    try:
        modular_divide(10, 6, 15)
    except ValueError as error:
        print("Rejected:", error)


# ============================================================================
# SECTION 15: SOLVING LINEAR CONGRUENCES
# ============================================================================

def solve_linear_congruence(
    a: int,
    b: int,
    modulus: int,
) -> List[int]:
    """
    Solve:

        ax ≡ b (mod m)

    General rule:

        d = gcd(a, m)

    A solution exists iff:

        d divides b

    If it exists, there are d distinct solutions modulo m.

    The method reduces the equation to:

        (a/d)x ≡ (b/d) (mod m/d)

    where gcd(a/d, m/d) = 1.
    """
    validate_modulus(modulus)

    d = gcd(a, modulus)

    if b % d != 0:
        return []

    reduced_a = a // d
    reduced_b = b // d
    reduced_modulus = modulus // d

    inverse = modular_inverse(reduced_a, reduced_modulus)
    base_solution = (inverse * reduced_b) % reduced_modulus

    solutions = []

    for k in range(d):
        solution = base_solution + k * reduced_modulus
        solutions.append(solution % modulus)

    return sorted(set(solutions))


def demonstrate_linear_congruences() -> None:
    """Demonstrate linear congruence solving."""
    print("\n" + "=" * 78)
    print("14. LINEAR CONGRUENCES")
    print("=" * 78)

    examples = [
        (3, 5, 7),
        (6, 9, 15),
        (6, 8, 15),
        (10, 4, 14),
    ]

    for a, b, m in examples:
        solutions = solve_linear_congruence(a, b, m)

        print(
            f"{a}x ≡ {b} (mod {m}) -> "
            f"solutions: {solutions}"
        )

        for x in solutions:
            assert (a * x - b) % m == 0


# ============================================================================
# SECTION 16: CHINESE REMAINDER THEOREM
# ============================================================================

def chinese_remainder_theorem(
    congruences: Sequence[Tuple[int, int]],
) -> int:
    """
    Solve a system of pairwise-coprime congruences.

    Input:

        [(a1, m1), (a2, m2), ...]

    representing:

        x ≡ a1 (mod m1)
        x ≡ a2 (mod m2)
        ...

    The moduli must be pairwise coprime.

    The result is the smallest nonnegative solution modulo:

        M = m1 * m2 * ...

    This implementation uses:

        x = sum(ai * Mi * inverse(Mi, mi))

    where:

        Mi = M / mi
    """
    if not congruences:
        raise ValueError("At least one congruence is required.")

    normalized = []

    for remainder_value, modulus in congruences:
        validate_modulus(modulus)
        normalized.append((remainder_value % modulus, modulus))

    for i in range(len(normalized)):
        for j in range(i + 1, len(normalized)):
            mi = normalized[i][1]
            mj = normalized[j][1]

            if gcd(mi, mj) != 1:
                raise ValueError(
                    "This implementation requires pairwise-coprime moduli."
                )

    total_modulus = 1

    for _, modulus in normalized:
        total_modulus *= modulus

    result = 0

    for residue_value, modulus in normalized:
        partial_modulus = total_modulus // modulus
        inverse = modular_inverse(partial_modulus, modulus)

        result += (
            residue_value
            * partial_modulus
            * inverse
        )

    return result % total_modulus


def demonstrate_chinese_remainder_theorem() -> None:
    """Demonstrate the Chinese Remainder Theorem."""
    print("\n" + "=" * 78)
    print("15. CHINESE REMAINDER THEOREM")
    print("=" * 78)

    system = [
        (2, 3),
        (3, 5),
        (2, 7),
    ]

    solution = chinese_remainder_theorem(system)

    print("System:")
    for residue_value, modulus in system:
        print(f"x ≡ {residue_value} (mod {modulus})")

    print(f"\nSmallest nonnegative solution: x = {solution}")

    for residue_value, modulus in system:
        print(
            f"{solution} mod {modulus} = "
            f"{solution % modulus}"
        )


# ============================================================================
# SECTION 17: FAST MODULAR MULTIPLICATION
# ============================================================================

def add_mod(a: int, b: int, modulus: int) -> int:
    """
    Add modulo modulus.

    Python integers do not overflow, so this function is mostly useful
    pedagogically. In fixed-width languages, careful implementation can
    matter when a + b itself might overflow.
    """
    validate_modulus(modulus)
    return (a + b) % modulus


def multiply_mod_by_repeated_doubling(
    a: int,
    b: int,
    modulus: int,
) -> int:
    """
    Compute a*b mod modulus using repeated doubling.

    This avoids directly forming a*b.

    Complexity:
        O(log b)

    This technique is useful in environments with fixed-width integer
    limitations or when multiplication itself needs special handling.

    Python's arbitrary-precision integers generally make direct modular
    multiplication preferable for ordinary applications.
    """
    validate_modulus(modulus)

    if b < 0:
        return (
            -multiply_mod_by_repeated_doubling(a, -b, modulus)
        ) % modulus

    result = 0
    a %= modulus

    while b > 0:
        if b & 1:
            result = (result + a) % modulus

        a = (a + a) % modulus
        b >>= 1

    return result


def demonstrate_fast_modular_multiplication() -> None:
    """Compare direct multiplication with repeated doubling."""
    print("\n" + "=" * 78)
    print("16. REPEATED-DOUBLING MODULAR MULTIPLICATION")
    print("=" * 78)

    examples = [
        (123, 456, 97),
        (987654321, 123456789, 1000003),
        (-12345, 67890, 1009),
    ]

    for a, b, m in examples:
        direct = (a * b) % m
        repeated_doubling = multiply_mod_by_repeated_doubling(a, b, m)

        print(
            f"a={a}, b={b}, m={m}\n"
            f"direct multiplication = {direct}\n"
            f"repeated doubling    = {repeated_doubling}\n"
            f"equal                = {direct == repeated_doubling}\n"
        )


# ============================================================================
# SECTION 18: MODULAR OPERATION TABLES
# ============================================================================

def create_addition_table(modulus: int) -> List[List[int]]:
    """Create an addition table for residues modulo modulus."""
    validate_modulus(modulus)

    return [
        [
            (row + column) % modulus
            for column in range(modulus)
        ]
        for row in range(modulus)
    ]


def create_subtraction_table(modulus: int) -> List[List[int]]:
    """Create a subtraction table for residues modulo modulus."""
    validate_modulus(modulus)

    return [
        [
            (row - column) % modulus
            for column in range(modulus)
        ]
        for row in range(modulus)
    ]


def create_multiplication_table(modulus: int) -> List[List[int]]:
    """Create a multiplication table for residues modulo modulus."""
    validate_modulus(modulus)

    return [
        [
            (row * column) % modulus
            for column in range(modulus)
        ]
        for row in range(modulus)
    ]


def print_table(table: Sequence[Sequence[int]], title: str) -> None:
    """Print a small modular arithmetic table."""
    print(f"\n{title}")

    if not table:
        return

    width = max(len(str(value)) for row in table for value in row)

    header = " " * (width + 2)
    header += " ".join(
        f"{i:>{width}}"
        for i in range(len(table))
    )

    print(header)

    for index, row in enumerate(table):
        values = " ".join(
            f"{value:>{width}}"
            for value in row
        )
        print(f"{index:>{width}} | {values}")


def demonstrate_operation_tables() -> None:
    """Display operation tables for a small modulus."""
    print("\n" + "=" * 78)
    print("17. MODULAR OPERATION TABLES")
    print("=" * 78)

    modulus = 5

    print_table(
        create_addition_table(modulus),
        f"Addition modulo {modulus}",
    )

    print_table(
        create_subtraction_table(modulus),
        f"Subtraction modulo {modulus}",
    )

    print_table(
        create_multiplication_table(modulus),
        f"Multiplication modulo {modulus}",
    )


# ============================================================================
# SECTION 19: UNIT ELEMENTS AND INVERSES
# ============================================================================

def units_modulo(modulus: int) -> List[int]:
    """
    Return all residues having a multiplicative inverse modulo modulus.

    A residue a is a unit iff:

        gcd(a, modulus) = 1
    """
    validate_modulus(modulus)

    return [
        a
        for a in range(modulus)
        if gcd(a, modulus) == 1
    ]


def demonstrate_units() -> None:
    """Demonstrate invertible and non-invertible residues."""
    print("\n" + "=" * 78)
    print("18. MULTIPLICATIVE UNITS")
    print("=" * 78)

    for modulus in [5, 8, 10, 12, 15]:
        units = units_modulo(modulus)
        print(f"Units modulo {modulus}: {units}")

        for unit in units:
            inverse = modular_inverse(unit, modulus)
            assert (unit * inverse) % modulus == 1


# ============================================================================
# SECTION 20: FERMAT'S LITTLE THEOREM
# ============================================================================

def demonstrate_fermat_little_theorem() -> None:
    """
    Demonstrate Fermat's Little Theorem.

    If p is prime and p does not divide a, then:

        a^(p-1) ≡ 1 (mod p)

    Consequently:

        a^(-1) ≡ a^(p-2) (mod p)

    for nonzero a modulo prime p.
    """
    print("\n" + "=" * 78)
    print("19. FERMAT'S LITTLE THEOREM")
    print("=" * 78)

    primes_and_values = [
        (7, 3),
        (11, 2),
        (13, 5),
        (17, 9),
    ]

    for p, a in primes_and_values:
        result = modular_power(a, p - 1, p)
        inverse_by_fermat = modular_power(a, p - 2, p)
        inverse_by_euclid = modular_inverse(a, p)

        print(
            f"p={p}, a={a}: "
            f"a^(p-1) mod p = {result}; "
            f"Fermat inverse = {inverse_by_fermat}; "
            f"Euclid inverse = {inverse_by_euclid}"
        )


# ============================================================================
# SECTION 21: EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    """Demonstrate important edge cases."""
    print("\n" + "=" * 78)
    print("20. EDGE CASES")
    print("=" * 78)

    print("0 mod 7 =", 0 % 7)
    print("7 mod 7 =", 7 % 7)
    print("14 mod 7 =", 14 % 7)
    print("-1 mod 7 =", -1 % 7)
    print("1 mod 1 =", 1 % 1)
    print("0 mod 1 =", 0 % 1)

    print("\nModulus 1:")
    print("Every integer is congruent to 0 modulo 1.")

    print("\nInvalid modulus examples:")

    for invalid_modulus in [0, -1, -10]:
        try:
            modular_add(5, 3, invalid_modulus)
        except (ValueError, TypeError) as error:
            print(f"modulus={invalid_modulus}: rejected -> {error}")


# ============================================================================
# SECTION 22: COMMON MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    """
    Demonstrate mistakes that commonly occur when working with
    modular arithmetic.
    """
    print("\n" + "=" * 78)
    print("21. COMMON MISTAKES")
    print("=" * 78)

    print("\nMistake 1: Assuming a/b mod m equals (a mod m)/(b mod m).")
    print("Correct approach: multiply by the modular inverse of b.")
    print("Example: 10 / 3 mod 7 =", modular_divide(10, 3, 7))

    print("\nMistake 2: Assuming every number has an inverse.")
    print("6 has no inverse modulo 15 because gcd(6, 15) = 3.")

    print("\nMistake 3: Forgetting to reduce negative results.")
    print("(3 - 8) = -5")
    print("(3 - 8) mod 7 =", (3 - 8) % 7)

    print("\nMistake 4: Dividing a congruence without checking invertibility.")
    print("Cancellation by b is safe only when b is invertible modulo m.")

    print("\nMistake 5: Treating modulo as ordinary real-number arithmetic.")
    print("Modular arithmetic operates on equivalence classes of integers.")


# ============================================================================
# SECTION 23: CANCELLATION AND ITS CONDITIONS
# ============================================================================

def demonstrate_cancellation() -> None:
    """
    Demonstrate why cancellation needs conditions.

    If:

        ac ≡ bc (mod m)

    cancellation of c is guaranteed when:

        gcd(c, m) = 1

    Without that condition, cancellation can fail.
    """
    print("\n" + "=" * 78)
    print("22. CANCELLATION")
    print("=" * 78)

    print("Valid cancellation example:")
    print("3*4 ≡ 3*9 (mod 5)")
    print("12 ≡ 27 (mod 5)")
    print("4 ≡ 9 (mod 5)")
    print("Cancellation is valid because gcd(3, 5) = 1.")

    print("\nInvalid cancellation example:")
    print("2*1 ≡ 2*4 (mod 6)")
    print("2 ≡ 8 (mod 6) is true.")
    print("But 1 ≡ 4 (mod 6) is false.")
    print("Cancellation fails because gcd(2, 6) != 1.")


# ============================================================================
# SECTION 24: TESTING
# ============================================================================

def test_basic_operations() -> None:
    """Test basic modular addition, subtraction, and multiplication."""
    for modulus in range(1, 20):
        for a in range(-30, 31):
            for b in range(-30, 31):
                expected_add = (a + b) % modulus
                expected_sub = (a - b) % modulus
                expected_mul = (a * b) % modulus

                assert modular_add(a, b, modulus) == expected_add
                assert modular_subtract(a, b, modulus) == expected_sub
                assert modular_multiply(a, b, modulus) == expected_mul


def test_congruence_properties() -> None:
    """Test the main congruence preservation rules."""
    for modulus in range(1, 15):
        for a in range(-15, 16):
            for b in range(-15, 16):
                if are_congruent(a, b, modulus):
                    for c in range(-10, 11):
                        assert are_congruent(
                            a + c,
                            b + c,
                            modulus,
                        )

                        assert are_congruent(
                            a - c,
                            b - c,
                            modulus,
                        )

                        assert are_congruent(
                            a * c,
                            b * c,
                            modulus,
                        )


def test_modular_power() -> None:
    """Verify binary modular exponentiation."""
    for modulus in range(1, 30):
        for base in range(-10, 11):
            for exponent in range(0, 20):
                expected = pow(base, exponent, modulus)
                actual = modular_power(base, exponent, modulus)
                assert actual == expected


def test_modular_inverses() -> None:
    """Verify every computed inverse."""
    for modulus in range(2, 30):
        for value in range(modulus):
            if gcd(value, modulus) == 1:
                inverse = modular_inverse(value, modulus)

                assert (
                    value * inverse
                ) % modulus == 1


def test_repeated_doubling() -> None:
    """Verify overflow-aware multiplication against direct multiplication."""
    for modulus in range(1, 50):
        for a in range(-50, 51):
            for b in range(-50, 51):
                expected = (a * b) % modulus
                actual = multiply_mod_by_repeated_doubling(
                    a,
                    b,
                    modulus,
                )

                assert actual == expected


def run_tests() -> None:
    """Run all educational correctness tests."""
    print("\n" + "=" * 78)
    print("23. AUTOMATED TESTS")
    print("=" * 78)

    tests = [
        test_basic_operations,
        test_congruence_properties,
        test_modular_power,
        test_modular_inverses,
        test_repeated_doubling,
    ]

    for test in tests:
        start = perf_counter()
        test()
        elapsed = perf_counter() - start
        print(f"{test.__name__}: PASS ({elapsed:.6f} seconds)")

    print("\nAll tests passed.")


# ============================================================================
# SECTION 25: PERFORMANCE COMPARISON
# ============================================================================

def benchmark_modular_power() -> None:
    """
    Compare direct exponentiation followed by modulo with modular
    exponentiation.

    The direct approach constructs the potentially enormous integer
    base ** exponent before reducing it.

    Binary modular exponentiation reduces intermediate values at every step.
    """
    print("\n" + "=" * 78)
    print("24. PERFORMANCE CONSIDERATIONS")
    print("=" * 78)

    base = 1234567
    exponent = 5000
    modulus = 1000000007

    start = perf_counter()
    direct_result = (base ** exponent) % modulus
    direct_time = perf_counter() - start

    start = perf_counter()
    fast_result = modular_power(base, exponent, modulus)
    fast_time = perf_counter() - start

    print("Results equal:", direct_result == fast_result)
    print(f"Direct exponentiation time: {direct_time:.6f} seconds")
    print(f"Binary modular power time:  {fast_time:.6f} seconds")

    print("\nPython also provides optimized modular exponentiation:")
    start = perf_counter()
    builtin_result = pow(base, exponent, modulus)
    builtin_time = perf_counter() - start

    print("Built-in result correct:", builtin_result == fast_result)
    print(f"Built-in pow time:        {builtin_time:.6f} seconds")


# ============================================================================
# SECTION 26: REAL-WORLD STYLE EXAMPLES
# ============================================================================

def rolling_hash_step(
    current_hash: int,
    character_code: int,
    base: int,
    modulus: int,
) -> int:
    """
    One step of a simple polynomial rolling hash:

        H_new = (H_old * base + character_code) mod modulus

    This is an illustrative hashing technique rather than a complete
    cryptographic hash function.
    """
    validate_modulus(modulus)

    return (
        current_hash * base + character_code
    ) % modulus


def demonstrate_rolling_hash() -> None:
    """Demonstrate modular arithmetic in rolling hashes."""
    print("\n" + "=" * 78)
    print("25. APPLICATION: ROLLING HASH")
    print("=" * 78)

    text = "MODULAR"
    base = 31
    modulus = 1_000_000_007

    current_hash = 0

    for character in text:
        current_hash = rolling_hash_step(
            current_hash,
            ord(character),
            base,
            modulus,
        )

        print(
            f"Character {character!r}: "
            f"hash = {current_hash}"
        )


def demonstrate_checksum() -> None:
    """
    Demonstrate a simple checksum.

    Real integrity systems can use much stronger constructions, but
    modular sums illustrate the underlying arithmetic.
    """
    print("\n" + "=" * 78)
    print("26. APPLICATION: SIMPLE CHECKSUM")
    print("=" * 78)

    data = [10, 20, 30, 40, 50]
    modulus = 97

    checksum = sum(data) % modulus

    print("Data:", data)
    print("Modulus:", modulus)
    print("Checksum:", checksum)

    altered_data = data.copy()
    altered_data[2] += 1

    altered_checksum = sum(altered_data) % modulus

    print("Altered data:", altered_data)
    print("Altered checksum:", altered_checksum)
    print("Detected:", checksum != altered_checksum)


def demonstrate_cyclic_indexing() -> None:
    """Demonstrate modular indexing for circular data structures."""
    print("\n" + "=" * 78)
    print("27. APPLICATION: CYCLIC INDEXING")
    print("=" * 78)

    items = ["A", "B", "C", "D", "E"]
    start_index = 3

    print("Items:", items)

    for offset in range(-3, 8):
        index = (start_index + offset) % len(items)
        print(
            f"offset {offset:>2}: "
            f"index {index}: "
            f"{items[index]}"
        )


# ============================================================================
# SECTION 27: NEGATIVE INPUT NORMALIZATION
# ============================================================================

def normalize_residues(
    values: Iterable[int],
    modulus: int,
) -> List[int]:
    """Normalize every value to the canonical residue range."""
    validate_modulus(modulus)
    return [value % modulus for value in values]


def demonstrate_normalization() -> None:
    """Demonstrate normalization of arbitrary integers."""
    print("\n" + "=" * 78)
    print("28. NORMALIZING RESIDUES")
    print("=" * 78)

    values = [
        -100,
        -7,
        -1,
        0,
        1,
        7,
        100,
    ]

    modulus = 7

    print("Original:", values)
    print("Normalized modulo 7:", normalize_residues(values, modulus))


# ============================================================================
# SECTION 28: ASSOCIATED CONCEPTS
# ============================================================================

def demonstrate_related_concepts() -> None:
    """Show relationships among division, divisibility, and congruence."""
    print("\n" + "=" * 78)
    print("29. RELATED CONCEPTS")
    print("=" * 78)

    a = 29
    b = 5

    quotient = a // b
    rem = a % b

    print(f"Division identity:")
    print(f"{a} = {quotient} * {b} + {rem}")

    print("\nDivisibility:")
    print("5 divides 30:", 30 % 5 == 0)
    print("5 divides 31:", 31 % 5 == 0)

    print("\nCongruence:")
    print("29 ≡ 4 (mod 5):", are_congruent(29, 4, 5))
    print("29 ≡ 3 (mod 5):", are_congruent(29, 3, 5))


# ============================================================================
# SECTION 29: COMPARISON OF OPERATIONS
# ============================================================================

def compare_operations() -> None:
    """
    Present the essential formulas and conditions in executable form.
    """
    print("\n" + "=" * 78)
    print("30. OPERATION COMPARISON")
    print("=" * 78)

    a, b, m = 17, 8, 5

    operations = {
        "addition": (a + b) % m,
        "subtraction": (a - b) % m,
        "multiplication": (a * b) % m,
    }

    for operation, result in operations.items():
        print(
            f"{operation.capitalize():<15}: "
            f"{result}"
        )

    print("\nDivision requires an extra condition:")
    print(
        f"gcd({b}, {m}) = {gcd(b, m)}; "
        "therefore b is invertible."
    )
    print(
        f"{a} / {b} mod {m} = "
        f"{modular_divide(a, b, m)}"
    )


# ============================================================================
# SECTION 30: INTERACTIVE CALCULATOR
# ============================================================================

def interactive_calculator() -> None:
    """
    Provide a small interactive modular arithmetic calculator.

    The function is optional and is not automatically executed so that the
    main educational script remains non-blocking.
    """
    print("\n" + "=" * 78)
    print("INTERACTIVE MODULAR CALCULATOR")
    print("=" * 78)

    print("Enter integers for a, b, and a positive modulus m.")

    try:
        a = int(input("a = "))
        b = int(input("b = "))
        m = int(input("m = "))

        validate_modulus(m)

        print(f"\nAddition:       ({a} + {b}) mod {m} = {(a + b) % m}")
        print(f"Subtraction:    ({a} - {b}) mod {m} = {(a - b) % m}")
        print(f"Multiplication: ({a} * {b}) mod {m} = {(a * b) % m}")

        if gcd(b, m) == 1:
            print(
                f"Division:       ({a} / {b}) mod {m} = "
                f"{modular_divide(a, b, m)}"
            )
        else:
            print(
                "Division: unavailable because b has no "
                "multiplicative inverse modulo m."
            )

    except ValueError as error:
        print("Input error:", error)


# ============================================================================
# SECTION 31: MAIN EDUCATIONAL DEMONSTRATION
# ============================================================================

def main() -> None:
    """Run the complete modular arithmetic tutorial."""
    print("=" * 78)
    print("MODULAR ADDITION, SUBTRACTION AND MULTIPLICATION")
    print("=" * 78)
    print(
        "\nCore idea:\n"
        "Modular arithmetic works with integers after reducing them by a "
        "positive modulus.\n"
    )

    demonstrate_remainders()
    demonstrate_modular_addition()
    demonstrate_modular_subtraction()
    demonstrate_modular_multiplication()
    demonstrate_negative_modulo()
    demonstrate_properties()
    demonstrate_reduction_rules()
    demonstrate_clock_arithmetic()
    demonstrate_modular_integer_class()
    demonstrate_modular_exponentiation()
    demonstrate_extended_gcd()
    demonstrate_modular_inverses()
    demonstrate_modular_division()
    demonstrate_linear_congruences()
    demonstrate_chinese_remainder_theorem()
    demonstrate_fast_modular_multiplication()
    demonstrate_operation_tables()
    demonstrate_units()
    demonstrate_fermat_little_theorem()
    demonstrate_edge_cases()
    demonstrate_common_mistakes()
    demonstrate_cancellation()
    run_tests()
    benchmark_modular_power()
    demonstrate_rolling_hash()
    demonstrate_checksum()
    demonstrate_cyclic_indexing()
    demonstrate_normalization()
    demonstrate_related_concepts()
    compare_operations()

    print("\n" + "=" * 78)
    print("TUTORIAL COMPLETE")
    print("=" * 78)
    print(
        "\nThe interactive calculator is available through "
        "interactive_calculator()."
    )


if __name__ == "__main__":
    main()
