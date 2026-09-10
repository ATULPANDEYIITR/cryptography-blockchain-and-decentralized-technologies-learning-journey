"""
MODULAR INVERSE
===============

A self-contained study and demonstration script covering modular inverses
from absolute beginner level through advanced applications.

A modular inverse of a number a modulo m is an integer x such that:

    a * x ≡ 1 (mod m)

A modular inverse exists if and only if:

    gcd(a, m) = 1

This script demonstrates:
- Modular arithmetic fundamentals
- Congruence
- Greatest common divisor
- Brute-force modular inverse
- Extended Euclidean algorithm
- Modular inverse using Bézout coefficients
- Python's built-in modular inverse support
- Negative values and normalization
- Non-invertible values
- Prime-modulus special cases
- Fermat's little theorem
- Euler's theorem
- Extended Euclidean algorithm implementation details
- Verification
- Linear congruences
- Modular division
- Chinese Remainder Theorem
- RSA-style arithmetic
- Affine ciphers
- Modular inverse tables
- Batch inverse computation
- Performance comparisons
- Edge cases and error handling
- Testing
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd
from random import Random
from time import perf_counter
from typing import Iterable, Optional


# ============================================================================
# SECTION 1: BASIC MODULAR ARITHMETIC
# ============================================================================

def mod(value: int, modulus: int) -> int:
    """
    Return the canonical representative of value modulo modulus.

    Python's % operator already provides a non-negative result when modulus
    is positive.

    Examples:
        17 mod 5  -> 2
        -3 mod 5  -> 2
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    return value % modulus


def demonstrate_basic_modular_arithmetic() -> None:
    print("\n=== BASIC MODULAR ARITHMETIC ===")

    examples = [
        (17, 5),
        (42, 7),
        (-3, 5),
        (-17, 6),
        (100, 13),
    ]

    for value, modulus in examples:
        print(f"{value} mod {modulus} = {mod(value, modulus)}")

    print("\nCongruence examples:")
    print("17 ≡ 2 (mod 5):", 17 % 5 == 2 % 5)
    print("23 ≡ 5 (mod 9):", 23 % 9 == 5 % 9)
    print("14 ≡ 3 (mod 11):", 14 % 11 == 3 % 11)


# ============================================================================
# SECTION 2: GREATEST COMMON DIVISOR
# ============================================================================

def euclidean_gcd(a: int, b: int) -> int:
    """
    Compute gcd(a, b) using the Euclidean algorithm.

    The key identity is:

        gcd(a, b) = gcd(b, a mod b)

    Repeatedly replacing the pair eventually reaches zero.
    """
    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a


def demonstrate_gcd() -> None:
    print("\n=== GREATEST COMMON DIVISOR ===")

    pairs = [
        (48, 18),
        (17, 5),
        (21, 14),
        (35, 64),
        (100, 25),
    ]

    for a, b in pairs:
        print(f"gcd({a}, {b}) = {euclidean_gcd(a, b)}")


# ============================================================================
# SECTION 3: WHY THE GCD MATTERS
# ============================================================================

def inverse_exists(a: int, modulus: int) -> bool:
    """
    Determine whether a modular inverse exists.

    The fundamental theorem is:

        a has an inverse modulo m
        if and only if
        gcd(a, m) = 1
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    return euclidean_gcd(a, modulus) == 1


def demonstrate_inverse_existence() -> None:
    print("\n=== WHEN DOES A MODULAR INVERSE EXIST? ===")

    examples = [
        (3, 7),
        (5, 12),
        (6, 15),
        (10, 17),
        (8, 20),
        (7, 13),
    ]

    for a, m in examples:
        g = euclidean_gcd(a, m)
        print(
            f"a={a}, m={m}, gcd={g}, "
            f"inverse exists={g == 1}"
        )


# ============================================================================
# SECTION 4: BRUTE-FORCE MODULAR INVERSE
# ============================================================================

def modular_inverse_bruteforce(a: int, modulus: int) -> int:
    """
    Find a modular inverse by testing every possible residue.

    This is conceptually simple but inefficient for large moduli.

    If x is the inverse:

        (a * x) % modulus == 1

    The search only needs x in [0, modulus - 1].
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    a %= modulus

    for x in range(modulus):
        if (a * x) % modulus == 1:
            return x

    raise ValueError(
        f"{a} has no modular inverse modulo {modulus}"
    )


def demonstrate_bruteforce() -> None:
    print("\n=== BRUTE-FORCE MODULAR INVERSE ===")

    examples = [
        (3, 7),
        (5, 12),
        (7, 26),
        (10, 17),
    ]

    for a, m in examples:
        try:
            inverse = modular_inverse_bruteforce(a, m)
            print(
                f"{a}^(-1) mod {m} = {inverse}; "
                f"verification={(a * inverse) % m}"
            )
        except ValueError as error:
            print(error)


# ============================================================================
# SECTION 5: EXTENDED EUCLIDEAN ALGORITHM
# ============================================================================

@dataclass
class ExtendedGCDResult:
    gcd: int
    coefficient_a: int
    coefficient_b: int


def extended_gcd(a: int, b: int) -> ExtendedGCDResult:
    """
    Compute:

        gcd(a, b) = g

    together with integers x and y satisfying:

        ax + by = g

    These x and y are Bézout coefficients.

    Recursive mathematical structure:

        gcd(a, b) = gcd(b, a mod b)

    If:

        b = 0

    then:

        gcd(a, 0) = |a|

    The iterative implementation below avoids recursion depth concerns.
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

    coefficient_a = old_s if a >= 0 else -old_s
    coefficient_b = old_t if b >= 0 else -old_t

    return ExtendedGCDResult(
        gcd=old_r,
        coefficient_a=coefficient_a,
        coefficient_b=coefficient_b,
    )


def demonstrate_extended_gcd() -> None:
    print("\n=== EXTENDED EUCLIDEAN ALGORITHM ===")

    examples = [
        (30, 18),
        (17, 5),
        (240, 46),
        (99, 78),
    ]

    for a, b in examples:
        result = extended_gcd(a, b)

        lhs = (
            a * result.coefficient_a
            + b * result.coefficient_b
        )

        print(
            f"a={a}, b={b}, gcd={result.gcd}, "
            f"x={result.coefficient_a}, "
            f"y={result.coefficient_b}, "
            f"ax+by={lhs}"
        )


# ============================================================================
# SECTION 6: MODULAR INVERSE USING EXTENDED GCD
# ============================================================================

def modular_inverse(a: int, modulus: int) -> int:
    """
    Compute the modular inverse using the Extended Euclidean Algorithm.

    If:

        ax + my = 1

    then reducing modulo m gives:

        ax ≡ 1 (mod m)

    Therefore x is the modular inverse of a modulo m.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    result = extended_gcd(a, modulus)

    if result.gcd != 1:
        raise ValueError(
            f"{a} has no modular inverse modulo {modulus}; "
            f"gcd={result.gcd}"
        )

    return result.coefficient_a % modulus


def demonstrate_extended_inverse() -> None:
    print("\n=== MODULAR INVERSE USING EXTENDED GCD ===")

    examples = [
        (3, 7),
        (5, 12),
        (7, 26),
        (10, 17),
        (-3, 11),
        (22, 29),
    ]

    for a, m in examples:
        try:
            inverse = modular_inverse(a, m)
            print(
                f"Inverse of {a} modulo {m}: {inverse}; "
                f"check={(a * inverse) % m}"
            )
        except ValueError as error:
            print(error)


# ============================================================================
# SECTION 7: PYTHON'S BUILT-IN MODULAR INVERSE
# ============================================================================

def modular_inverse_builtin(a: int, modulus: int) -> int:
    """
    Python supports modular inversion directly with:

        pow(a, -1, modulus)

    This requires a version of Python supporting the negative exponent
    modular form of pow().
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    return pow(a, -1, modulus)


def demonstrate_builtin_inverse() -> None:
    print("\n=== PYTHON BUILT-IN MODULAR INVERSE ===")

    examples = [
        (3, 7),
        (10, 17),
        (23, 101),
        (-7, 19),
    ]

    for a, m in examples:
        inverse = modular_inverse_builtin(a, m)
        print(
            f"pow({a}, -1, {m}) = {inverse}; "
            f"verification={(a * inverse) % m}"
        )


# ============================================================================
# SECTION 8: NEGATIVE VALUES
# ============================================================================

def demonstrate_negative_values() -> None:
    print("\n=== NEGATIVE VALUES ===")

    examples = [
        (-3, 11),
        (-7, 13),
        (-10, 17),
        (25, 7),
    ]

    for a, m in examples:
        inverse = modular_inverse(a, m)

        print(
            f"a={a}, normalized={a % m}, "
            f"inverse={inverse}, "
            f"a*inverse mod m={(a * inverse) % m}"
        )


# ============================================================================
# SECTION 9: NON-INVERTIBLE VALUES
# ============================================================================

def demonstrate_noninvertible_values() -> None:
    print("\n=== NON-INVERTIBLE VALUES ===")

    examples = [
        (2, 4),
        (6, 15),
        (10, 20),
        (12, 18),
        (14, 21),
    ]

    for a, m in examples:
        try:
            inverse = modular_inverse(a, m)
            print(f"{a} inverse modulo {m} = {inverse}")
        except ValueError as error:
            print(
                f"a={a}, m={m}: {error}"
            )


# ============================================================================
# SECTION 10: VERIFYING AN INVERSE
# ============================================================================

def verify_inverse(a: int, inverse: int, modulus: int) -> bool:
    """
    Verify that inverse really is an inverse of a modulo modulus.
    """
    return (
        modulus > 1
        and (a * inverse) % modulus == 1
    )


def demonstrate_verification() -> None:
    print("\n=== VERIFYING MODULAR INVERSES ===")

    a = 17
    m = 43
    inverse = modular_inverse(a, m)

    print("a =", a)
    print("m =", m)
    print("inverse =", inverse)
    print("valid =", verify_inverse(a, inverse, m))


# ============================================================================
# SECTION 11: PRIME MODULUS AND FERMAT'S LITTLE THEOREM
# ============================================================================

def is_prime(n: int) -> bool:
    """
    Simple deterministic primality test suitable for educational examples.
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


def modular_inverse_prime_fermat(a: int, prime: int) -> int:
    """
    For prime p and a not divisible by p:

        a^(p-1) ≡ 1 (mod p)

    Therefore:

        a^(p-2) ≡ a^(-1) (mod p)

    This is based on Fermat's little theorem.
    """
    if not is_prime(prime):
        raise ValueError("modulus must be prime")

    if a % prime == 0:
        raise ValueError(
            "a is divisible by the prime modulus"
        )

    return pow(a, prime - 2, prime)


def demonstrate_fermat_inverse() -> None:
    print("\n=== FERMAT'S LITTLE THEOREM ===")

    examples = [
        (3, 7),
        (5, 13),
        (17, 43),
        (19, 101),
    ]

    for a, p in examples:
        inverse = modular_inverse_prime_fermat(a, p)
        direct = modular_inverse(a, p)

        print(
            f"a={a}, p={p}, "
            f"Fermat inverse={inverse}, "
            f"Extended-GCD inverse={direct}"
        )


# ============================================================================
# SECTION 12: EULER'S THEOREM
# ============================================================================

def euler_totient(n: int) -> int:
    """
    Compute Euler's totient phi(n), the number of integers in
    {1, ..., n} that are relatively prime to n.
    """
    if n <= 0:
        raise ValueError("n must be positive")

    result = n
    value = n
    prime_factor = 2

    while prime_factor * prime_factor <= value:
        if value % prime_factor == 0:
            while value % prime_factor == 0:
                value //= prime_factor
            result -= result // prime_factor

        prime_factor += (
            1 if prime_factor == 2 else 2
        )

    if value > 1:
        result -= result // value

    return result


def modular_inverse_euler(a: int, modulus: int) -> int:
    """
    Euler's theorem states that when gcd(a, m) = 1:

        a^phi(m) ≡ 1 (mod m)

    Therefore:

        a^(phi(m)-1) ≡ a^(-1) (mod m)
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if euclidean_gcd(a, modulus) != 1:
        raise ValueError(
            "Euler's theorem cannot be used because "
            "a and modulus are not coprime"
        )

    phi = euler_totient(modulus)
    return pow(a, phi - 1, modulus)


def demonstrate_euler_theorem() -> None:
    print("\n=== EULER'S THEOREM ===")

    examples = [
        (3, 10),
        (7, 20),
        (11, 30),
        (17, 40),
    ]

    for a, m in examples:
        phi = euler_totient(m)
        inverse = modular_inverse_euler(a, m)

        print(
            f"a={a}, m={m}, phi(m)={phi}, "
            f"inverse={inverse}, "
            f"verification={(a * inverse) % m}"
        )


# ============================================================================
# SECTION 13: MODULAR EXPONENTIATION
# ============================================================================

def modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Compute base^exponent modulo modulus efficiently.

    Python's three-argument pow() uses an efficient modular exponentiation
    algorithm rather than constructing the potentially enormous integer
    base^exponent first.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    if exponent < 0:
        inverse = modular_inverse(base, modulus)
        return pow(inverse, -exponent, modulus)

    return pow(base, exponent, modulus)


def demonstrate_modular_power() -> None:
    print("\n=== MODULAR EXPONENTIATION ===")

    examples = [
        (2, 100, 13),
        (7, 222, 19),
        (123456789, 12345, 1000003),
        (3, -1, 7),
    ]

    for base, exponent, modulus in examples:
        result = modular_power(base, exponent, modulus)
        print(
            f"{base}^{exponent} mod {modulus} = {result}"
        )


# ============================================================================
# SECTION 14: MODULAR DIVISION
# ============================================================================

def modular_division(
    numerator: int,
    denominator: int,
    modulus: int,
) -> int:
    """
    Compute:

        numerator / denominator (mod modulus)

    Division modulo m means multiplying by the modular inverse:

        numerator * denominator^(-1) (mod m)

    This is possible only when denominator and modulus are coprime.
    """
    inverse = modular_inverse(denominator, modulus)
    return (numerator * inverse) % modulus


def demonstrate_modular_division() -> None:
    print("\n=== MODULAR DIVISION ===")

    examples = [
        (10, 3, 7),
        (8, 5, 13),
        (17, 4, 19),
        (22, 7, 29),
    ]

    for numerator, denominator, modulus in examples:
        result = modular_division(
            numerator,
            denominator,
            modulus,
        )

        print(
            f"{numerator} / {denominator} mod {modulus} = {result}"
        )


# ============================================================================
# SECTION 15: LINEAR CONGRUENCES
# ============================================================================

def solve_linear_congruence(
    a: int,
    b: int,
    modulus: int,
) -> list[int]:
    """
    Solve:

        ax ≡ b (mod m)

    Let:

        d = gcd(a, m)

    A solution exists exactly when:

        d divides b

    After dividing by d:

        (a/d)x ≡ b/d (mod m/d)

    The reduced coefficient is now invertible modulo m/d.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    d = euclidean_gcd(a, modulus)

    if b % d != 0:
        return []

    reduced_a = a // d
    reduced_b = b // d
    reduced_modulus = modulus // d

    inverse = modular_inverse(
        reduced_a,
        reduced_modulus,
    )

    first_solution = (
        reduced_b * inverse
    ) % reduced_modulus

    return [
        (first_solution + k * reduced_modulus) % modulus
        for k in range(d)
    ]


def demonstrate_linear_congruences() -> None:
    print("\n=== LINEAR CONGRUENCES ===")

    examples = [
        (3, 6, 7),
        (4, 8, 12),
        (6, 9, 15),
        (6, 5, 15),
        (10, 20, 30),
    ]

    for a, b, m in examples:
        solutions = solve_linear_congruence(a, b, m)

        print(
            f"{a}x ≡ {b} (mod {m}) -> "
            f"solutions={solutions}"
        )

        for x in solutions:
            assert (a * x - b) % m == 0


# ============================================================================
# SECTION 16: INVERSE TABLE
# ============================================================================

def inverse_table(modulus: int) -> dict[int, int]:
    """
    Return all invertible residues modulo modulus and their inverses.
    """
    table: dict[int, int] = {}

    for value in range(1, modulus):
        if euclidean_gcd(value, modulus) == 1:
            table[value] = modular_inverse(value, modulus)

    return table


def demonstrate_inverse_table() -> None:
    print("\n=== MODULAR INVERSE TABLE ===")

    modulus = 11
    table = inverse_table(modulus)

    for value, inverse in table.items():
        print(
            f"{value:2d} -> {inverse:2d}"
        )


# ============================================================================
# SECTION 17: AFFINE CIPHER
# ============================================================================

def affine_encrypt(
    text: str,
    multiplicative_key: int,
    additive_key: int,
) -> str:
    """
    Encrypt letters using:

        E(x) = (a*x + b) mod 26

    The multiplicative key a must have an inverse modulo 26 for
    decryption to be possible.
    """
    if euclidean_gcd(multiplicative_key, 26) != 1:
        raise ValueError(
            "multiplicative_key must be coprime with 26"
        )

    result = []

    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            value = ord(character) - base

            encrypted = (
                multiplicative_key * value
                + additive_key
            ) % 26

            result.append(chr(base + encrypted))
        else:
            result.append(character)

    return "".join(result)


def affine_decrypt(
    text: str,
    multiplicative_key: int,
    additive_key: int,
) -> str:
    """
    Decrypt the affine cipher using:

        D(y) = a^(-1) * (y - b) mod 26
    """
    inverse = modular_inverse(
        multiplicative_key,
        26,
    )

    result = []

    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            value = ord(character) - base

            decrypted = (
                inverse
                * (value - additive_key)
            ) % 26

            result.append(chr(base + decrypted))
        else:
            result.append(character)

    return "".join(result)


def demonstrate_affine_cipher() -> None:
    print("\n=== AFFINE CIPHER ===")

    plaintext = "Modular Inverse"
    a = 5
    b = 8

    encrypted = affine_encrypt(
        plaintext,
        a,
        b,
    )

    decrypted = affine_decrypt(
        encrypted,
        a,
        b,
    )

    print("Plaintext :", plaintext)
    print("Encrypted :", encrypted)
    print("Decrypted :", decrypted)


# ============================================================================
# SECTION 18: RSA-STYLE KEY GENERATION
# ============================================================================

@dataclass
class RSAKeyPair:
    public_exponent: int
    private_exponent: int
    modulus: int


def generate_demo_rsa_keypair(
    p: int,
    q: int,
    public_exponent: int = 65537,
) -> RSAKeyPair:
    """
    Construct a small educational RSA key pair.

    Real RSA uses very large primes and carefully engineered key-generation
    procedures. This implementation is deliberately small and is NOT suitable
    for real cryptography.

    RSA requires:

        e*d ≡ 1 (mod phi(n))

    Thus d is the modular inverse of e modulo phi(n).
    """
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must be prime")

    if p == q:
        raise ValueError("p and q must be different")

    n = p * q
    phi = (p - 1) * (q - 1)

    if euclidean_gcd(public_exponent, phi) != 1:
        raise ValueError(
            "public exponent must be coprime with phi(n)"
        )

    private_exponent = modular_inverse(
        public_exponent,
        phi,
    )

    return RSAKeyPair(
        public_exponent=public_exponent,
        private_exponent=private_exponent,
        modulus=n,
    )


def rsa_encrypt(message: int, key: RSAKeyPair) -> int:
    """Educational RSA encryption."""
    if not 0 <= message < key.modulus:
        raise ValueError(
            "message must be in the range [0, modulus)"
        )

    return pow(
        message,
        key.public_exponent,
        key.modulus,
    )


def rsa_decrypt(ciphertext: int, key: RSAKeyPair) -> int:
    """Educational RSA decryption."""
    return pow(
        ciphertext,
        key.private_exponent,
        key.modulus,
    )


def demonstrate_rsa() -> None:
    print("\n=== RSA-STYLE MODULAR INVERSE ===")

    key = generate_demo_rsa_keypair(
        p=61,
        q=53,
        public_exponent=17,
    )

    message = 65
    ciphertext = rsa_encrypt(message, key)
    recovered = rsa_decrypt(ciphertext, key)

    phi = (61 - 1) * (53 - 1)

    print("Public exponent :", key.public_exponent)
    print("Private exponent:", key.private_exponent)
    print("Modulus         :", key.modulus)
    print("phi(n)          :", phi)
    print(
        "e*d mod phi(n)  :",
        (
            key.public_exponent
            * key.private_exponent
        ) % phi,
    )
    print("Message         :", message)
    print("Ciphertext      :", ciphertext)
    print("Recovered       :", recovered)

    # This demonstrates the exact role of the modular inverse:
    # d is the inverse of e modulo phi(n).


# ============================================================================
# SECTION 19: CHINESE REMAINDER THEOREM
# ============================================================================

def chinese_remainder_theorem(
    remainders: Iterable[int],
    moduli: Iterable[int],
) -> int:
    """
    Solve a system of pairwise-coprime congruences:

        x ≡ r1 (mod m1)
        x ≡ r2 (mod m2)
        ...
        x ≡ rk (mod mk)

    The result is returned in the interval [0, product(moduli)).

    For each modulus mi:

        Mi = M / mi

    Since gcd(Mi, mi) = 1, Mi has a modular inverse yi modulo mi.

    Then:

        x = sum(ri * Mi * yi) mod M
    """
    remainder_list = list(remainders)
    modulus_list = list(moduli)

    if not remainder_list or len(remainder_list) != len(modulus_list):
        raise ValueError(
            "remainders and moduli must be non-empty and equal in length"
        )

    for i in range(len(modulus_list)):
        if modulus_list[i] <= 1:
            raise ValueError(
                "each modulus must be greater than 1"
            )

        for j in range(i + 1, len(modulus_list)):
            if euclidean_gcd(
                modulus_list[i],
                modulus_list[j],
            ) != 1:
                raise ValueError(
                    "moduli must be pairwise coprime"
                )

    total_modulus = 1

    for modulus in modulus_list:
        total_modulus *= modulus

    result = 0

    for remainder, modulus in zip(
        remainder_list,
        modulus_list,
    ):
        partial_modulus = total_modulus // modulus

        inverse = modular_inverse(
            partial_modulus,
            modulus,
        )

        result += (
            remainder
            * partial_modulus
            * inverse
        )

    return result % total_modulus


def demonstrate_crt() -> None:
    print("\n=== CHINESE REMAINDER THEOREM ===")

    remainders = [2, 3, 2]
    moduli = [3, 5, 7]

    result = chinese_remainder_theorem(
        remainders,
        moduli,
    )

    print(
        "System: x ≡ 2 (mod 3), "
        "x ≡ 3 (mod 5), "
        "x ≡ 2 (mod 7)"
    )

    print("Solution:", result)

    for remainder, modulus in zip(
        remainders,
        moduli,
    ):
        print(
            f"x mod {modulus} = "
            f"{result % modulus}; "
            f"required={remainder}"
        )


# ============================================================================
# SECTION 20: BATCH MODULAR INVERSES
# ============================================================================

def batch_inverses_prime_modulus(
    values: list[int],
    prime_modulus: int,
) -> list[int]:
    """
    Compute inverses of many values modulo a prime in linear time after
    preparing prefix products.

    For nonzero values a1, a2, ..., an modulo a prime p:

        prefix[i] = a1*a2*...*ai

    The inverse of the total product is computed once.

    The method then recovers every individual inverse using suffix products.

    This is useful when many inverses are required modulo the same prime.
    """
    if not is_prime(prime_modulus):
        raise ValueError("modulus must be prime")

    if any(
        value % prime_modulus == 0
        for value in values
    ):
        raise ValueError(
            "all values must be nonzero modulo the prime"
        )

    if not values:
        return []

    normalized = [
        value % prime_modulus
        for value in values
    ]

    prefix_products = [1] * len(values)

    product = 1

    for index, value in enumerate(normalized):
        product = (
            product * value
        ) % prime_modulus

        prefix_products[index] = product

    inverse_product = modular_inverse(
        product,
        prime_modulus,
    )

    inverses = [0] * len(values)

    suffix_inverse = inverse_product

    for index in range(len(values) - 1, -1, -1):
        previous_product = (
            prefix_products[index - 1]
            if index > 0
            else 1
        )

        inverses[index] = (
            suffix_inverse
            * previous_product
        ) % prime_modulus

        suffix_inverse = (
            suffix_inverse
            * normalized[index]
        ) % prime_modulus

    return inverses


def demonstrate_batch_inverses() -> None:
    print("\n=== BATCH MODULAR INVERSES ===")

    values = [3, 5, 7, 11, 13]
    modulus = 101

    inverses = batch_inverses_prime_modulus(
        values,
        modulus,
    )

    for value, inverse in zip(
        values,
        inverses,
    ):
        print(
            f"{value} -> {inverse}; "
            f"check={(value * inverse) % modulus}"
        )


# ============================================================================
# SECTION 21: COMBINATORICS MODULO A PRIME
# ============================================================================

def factorial_mod(n: int, modulus: int) -> int:
    """
    Compute n! modulo modulus.
    """
    if n < 0:
        raise ValueError("n must be non-negative")

    result = 1

    for value in range(2, n + 1):
        result = (
            result * value
        ) % modulus

    return result


def combination_mod_prime(
    n: int,
    k: int,
    prime_modulus: int,
) -> int:
    """
    Compute C(n, k) modulo a prime p using:

        C(n,k) = n! / (k!(n-k)!)

    Modular division is implemented using modular inverses.

    This simple implementation assumes the denominator is invertible modulo p,
    which is guaranteed when n < p.
    """
    if n < 0 or k < 0 or k > n:
        return 0

    if not is_prime(prime_modulus):
        raise ValueError("modulus must be prime")

    if n >= prime_modulus:
        raise ValueError(
            "this simple implementation requires n < prime modulus"
        )

    numerator = factorial_mod(
        n,
        prime_modulus,
    )

    denominator = (
        factorial_mod(k, prime_modulus)
        * factorial_mod(n - k, prime_modulus)
    ) % prime_modulus

    denominator_inverse = modular_inverse(
        denominator,
        prime_modulus,
    )

    return (
        numerator
        * denominator_inverse
    ) % prime_modulus


def demonstrate_combinatorics() -> None:
    print("\n=== COMBINATORICS MODULO A PRIME ===")

    examples = [
        (5, 2, 13),
        (10, 3, 17),
        (12, 5, 19),
    ]

    for n, k, p in examples:
        result = combination_mod_prime(
            n,
            k,
            p,
        )

        print(
            f"C({n},{k}) mod {p} = {result}"
        )


# ============================================================================
# SECTION 22: MODULAR INVERSE TABLE THROUGH EXTENDED GCD
# ============================================================================

def all_inverses_by_gcd(modulus: int) -> dict[int, Optional[int]]:
    """
    Return every residue's inverse when it exists.

    Values that are not coprime with the modulus receive None.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    result: dict[int, Optional[int]] = {}

    for value in range(modulus):
        if euclidean_gcd(value, modulus) == 1:
            result[value] = modular_inverse(
                value,
                modulus,
            )
        else:
            result[value] = None

    return result


def demonstrate_all_inverses() -> None:
    print("\n=== ALL RESIDUE INVERSES ===")

    modulus = 15
    table = all_inverses_by_gcd(modulus)

    for value, inverse in table.items():
        print(
            f"{value:2d} -> "
            f"{inverse if inverse is not None else 'not invertible'}"
        )


# ============================================================================
# SECTION 23: INVERSE PAIRS
# ============================================================================

def inverse_pairs(modulus: int) -> list[tuple[int, int]]:
    """
    Return pairs (a, a^-1) modulo modulus.
    """
    table = inverse_table(modulus)

    return list(table.items())


def demonstrate_inverse_pairs() -> None:
    print("\n=== INVERSE PAIRS ===")

    modulus = 10

    for value, inverse in inverse_pairs(modulus):
        print(
            f"{value} and {inverse} "
            f"are multiplicative inverses modulo {modulus}"
        )


# ============================================================================
# SECTION 24: EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print("\n=== EDGE CASES ===")

    test_cases = [
        (0, 7),
        (1, 7),
        (6, 7),
        (7, 7),
        (-1, 7),
        (100, 101),
    ]

    for a, m in test_cases:
        try:
            inverse = modular_inverse(a, m)
            print(
                f"a={a}, m={m}, inverse={inverse}"
            )
        except ValueError as error:
            print(
                f"a={a}, m={m}, error={error}"
            )

    print("\nImportant observations:")
    print("0 has no modular inverse modulo m.")
    print("1 is its own inverse modulo every valid modulus.")
    print("a divisible by m is congruent to 0 and is not invertible.")
    print("-1 is its own inverse modulo every valid modulus.")


# ============================================================================
# SECTION 25: PERFORMANCE COMPARISON
# ============================================================================

def benchmark_inverse_methods(
    a: int,
    modulus: int,
) -> None:
    """
    Compare brute force, Extended Euclid, and Python's built-in pow.

    Brute force is intentionally used only with a small modulus.
    """
    if not inverse_exists(a, modulus):
        print(
            "Benchmark skipped because inverse does not exist."
        )
        return

    start = perf_counter()
    brute_force_result = modular_inverse_bruteforce(
        a,
        modulus,
    )
    brute_force_time = perf_counter() - start

    start = perf_counter()
    euclid_result = modular_inverse(
        a,
        modulus,
    )
    euclid_time = perf_counter() - start

    start = perf_counter()
    builtin_result = modular_inverse_builtin(
        a,
        modulus,
    )
    builtin_time = perf_counter() - start

    print("\n=== PERFORMANCE COMPARISON ===")
    print("Input:", a)
    print("Modulus:", modulus)
    print("Brute-force result:", brute_force_result)
    print("Extended-GCD result:", euclid_result)
    print("Built-in pow result:", builtin_result)
    print(f"Brute-force time: {brute_force_time:.8f}s")
    print(f"Extended-GCD time: {euclid_time:.8f}s")
    print(f"Built-in pow time: {builtin_time:.8f}s")


# ============================================================================
# SECTION 26: RANDOMIZED CORRECTNESS TESTING
# ============================================================================

def randomized_inverse_test(
    trials: int = 500,
    seed: int = 2026,
) -> None:
    """
    Test many random invertible pairs and verify:

        a * inverse ≡ 1 (mod m)

    The fixed seed makes the demonstration reproducible.
    """
    random_generator = Random(seed)

    tested = 0

    for _ in range(trials):
        modulus = random_generator.randint(2, 500)
        value = random_generator.randint(
            -1000,
            1000,
        )

        if euclidean_gcd(value, modulus) != 1:
            continue

        inverse = modular_inverse(
            value,
            modulus,
        )

        assert verify_inverse(
            value,
            inverse,
            modulus,
        )

        assert inverse == pow(
            value,
            -1,
            modulus,
        )

        tested += 1

    print("\n=== RANDOMIZED CORRECTNESS TEST ===")
    print("Requested trials:", trials)
    print("Invertible cases tested:", tested)
    print("All tests passed.")


# ============================================================================
# SECTION 27: COMMON IMPLEMENTATION MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n=== COMMON IMPLEMENTATION MISTAKES ===")

    print("\nMistake 1: Assuming every number has an inverse.")
    try:
        modular_inverse(6, 15)
    except ValueError as error:
        print("Correct behavior:", error)

    print("\nMistake 2: Forgetting to normalize negative coefficients.")
    inverse = modular_inverse(-3, 11)
    print(
        "Normalized inverse:",
        inverse,
        "verification:",
        (-3 * inverse) % 11,
    )

    print("\nMistake 3: Using ordinary division.")
    ordinary_division = 10 / 3
    modular_result = modular_division(
        10,
        3,
        7,
    )

    print("Ordinary real-number division:", ordinary_division)
    print("Modular division modulo 7:", modular_result)

    print("\nMistake 4: Using Fermat's theorem with a composite modulus.")
    try:
        modular_inverse_prime_fermat(3, 10)
    except ValueError as error:
        print("Correctly rejected:", error)

    print("\nMistake 5: Treating modular equality as ordinary equality.")
    print(
        "17 and 2 are different integers:",
        17 != 2,
    )
    print(
        "17 and 2 are congruent modulo 5:",
        17 % 5 == 2 % 5,
    )


# ============================================================================
# SECTION 28: ADVANCED RELATIONSHIP BETWEEN INVERSES
# ============================================================================

def demonstrate_inverse_properties() -> None:
    print("\n=== PROPERTIES OF MODULAR INVERSES ===")

    a = 7
    m = 20
    inverse = modular_inverse(a, m)

    print("a:", a)
    print("a inverse:", inverse)

    # If a^-1 exists, then:
    # (a^-1)^-1 ≡ a (mod m)
    inverse_of_inverse = modular_inverse(
        inverse,
        m,
    )

    print(
        "Inverse of inverse:",
        inverse_of_inverse,
    )

    # If a and b are invertible:
    # (ab)^-1 ≡ a^-1 b^-1 (mod m)
    b = 3
    inverse_a = modular_inverse(a, m)
    inverse_b = modular_inverse(b, m)
    inverse_ab = modular_inverse(
        a * b,
        m,
    )

    print(
        "(ab)^-1:",
        inverse_ab,
    )

    print(
        "a^-1*b^-1 mod m:",
        (inverse_a * inverse_b) % m,
    )

    # If a ≡ b (mod m) and both are invertible,
    # their inverses are also congruent modulo m.
    equivalent_a = 27
    equivalent_b = 7

    print(
        "27 ≡ 7 mod 20:",
        equivalent_a % m == equivalent_b % m,
    )

    print(
        "Their inverses:",
        modular_inverse(equivalent_a, m),
        modular_inverse(equivalent_b, m),
    )


# ============================================================================
# SECTION 29: SOLVING A MODULAR EQUATION BY INVERSION
# ============================================================================

def solve_using_inverse(
    coefficient: int,
    target: int,
    modulus: int,
) -> int:
    """
    Solve:

        coefficient * x ≡ target (mod modulus)

    when coefficient is invertible.
    """
    inverse = modular_inverse(
        coefficient,
        modulus,
    )

    return (
        target * inverse
    ) % modulus


def demonstrate_equation_solution() -> None:
    print("\n=== SOLVING MODULAR EQUATIONS ===")

    coefficient = 7
    target = 5
    modulus = 19

    x = solve_using_inverse(
        coefficient,
        target,
        modulus,
    )

    print(
        f"{coefficient}x ≡ {target} (mod {modulus})"
    )
    print("x =", x)
    print(
        "Verification:",
        (coefficient * x) % modulus,
    )


# ============================================================================
# SECTION 30: MODULAR INVERSE AS A FUNCTION OBJECT
# ============================================================================

def make_modular_inverse_function(
    modulus: int,
):
    """
    Create a reusable inverse function for one fixed modulus.

    The modulus is captured by the closure.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    def inverse(value: int) -> int:
        return modular_inverse(
            value,
            modulus,
        )

    return inverse


def demonstrate_closure() -> None:
    print("\n=== REUSABLE INVERSE FUNCTION ===")

    inverse_mod_17 = make_modular_inverse_function(17)

    for value in [2, 3, 5, 7, 11]:
        inverse = inverse_mod_17(value)

        print(
            f"{value}^-1 mod 17 = {inverse}"
        )


# ============================================================================
# SECTION 31: EDUCATIONAL UNIT TESTS
# ============================================================================

def run_unit_tests() -> None:
    """
    Basic assertions covering normal cases, edge cases, and relationships.
    """
    assert euclidean_gcd(48, 18) == 6
    assert euclidean_gcd(-48, 18) == 6

    result = extended_gcd(30, 18)

    assert result.gcd == 6
    assert (
        30 * result.coefficient_a
        + 18 * result.coefficient_b
        == 6
    )

    known_inverses = [
        (3, 7, 5),
        (5, 12, 5),
        (10, 17, 12),
        (7, 26, 15),
        (-3, 11, 7),
    ]

    for a, m, expected in known_inverses:
        assert modular_inverse(a, m) == expected

    noninvertible_cases = [
        (2, 4),
        (6, 15),
        (10, 20),
        (0, 7),
    ]

    for a, m in noninvertible_cases:
        try:
            modular_inverse(a, m)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "Expected modular inverse failure"
            )

    assert modular_inverse(1, 17) == 1
    assert modular_inverse(-1, 17) == 16

    for a in range(1, 50):
        for m in range(2, 30):
            if euclidean_gcd(a, m) == 1:
                inverse = modular_inverse(a, m)

                assert (
                    a * inverse
                ) % m == 1

                assert inverse == pow(
                    a,
                    -1,
                    m,
                )

    assert modular_inverse_prime_fermat(
        3,
        7,
    ) == modular_inverse(3, 7)

    assert modular_inverse_euler(
        3,
        10,
    ) == modular_inverse(3, 10)

    assert solve_linear_congruence(
        3,
        6,
        7,
    ) == [2]

    crt_result = chinese_remainder_theorem(
        [2, 3, 2],
        [3, 5, 7],
    )

    assert crt_result == 23

    values = [3, 5, 7, 11]
    inverses = batch_inverses_prime_modulus(
        values,
        101,
    )

    for value, inverse in zip(
        values,
        inverses,
    ):
        assert (
            value * inverse
        ) % 101 == 1

    plaintext = "Hello Modular World!"
    encrypted = affine_encrypt(
        plaintext,
        5,
        8,
    )

    decrypted = affine_decrypt(
        encrypted,
        5,
        8,
    )

    assert decrypted == plaintext

    key = generate_demo_rsa_keypair(
        61,
        53,
        17,
    )

    message = 65
    encrypted_message = rsa_encrypt(
        message,
        key,
    )

    assert rsa_decrypt(
        encrypted_message,
        key,
    ) == message


# ============================================================================
# SECTION 32: EDUCATIONAL INTERACTIVE CALCULATOR
# ============================================================================

def interactive_inverse_calculator() -> None:
    """
    Optional interactive demonstration.

    It is disabled by default so the complete script remains automatically
    executable without waiting for input.
    """
    print("\n=== INTERACTIVE MODULAR INVERSE CALCULATOR ===")
    print("Enter integers to calculate a modular inverse.")
    print("Press Ctrl+C or enter a blank value to stop.")

    while True:
        try:
            raw_a = input("a: ").strip()

            if not raw_a:
                break

            raw_m = input("modulus: ").strip()

            if not raw_m:
                break

            a = int(raw_a)
            modulus = int(raw_m)

            inverse = modular_inverse(
                a,
                modulus,
            )

            print(
                f"Inverse = {inverse}"
            )
            print(
                f"Verification = {(a * inverse) % modulus}"
            )

        except ValueError as error:
            print("Error:", error)

        except KeyboardInterrupt:
            print("\nInteractive mode stopped.")
            break


# ============================================================================
# SECTION 33: MAIN DEMONSTRATION
# ============================================================================

def main() -> None:
    """
    Run the complete modular inverse study program.
    """
    print("=" * 72)
    print("MODULAR INVERSE: COMPLETE PYTHON STUDY SCRIPT")
    print("=" * 72)

    demonstrate_basic_modular_arithmetic()
    demonstrate_gcd()
    demonstrate_inverse_existence()
    demonstrate_bruteforce()
    demonstrate_extended_gcd()
    demonstrate_extended_inverse()
    demonstrate_builtin_inverse()
    demonstrate_negative_values()
    demonstrate_noninvertible_values()
    demonstrate_verification()
    demonstrate_fermat_inverse()
    demonstrate_euler_theorem()
    demonstrate_modular_power()
    demonstrate_modular_division()
    demonstrate_linear_congruences()
    demonstrate_inverse_table()
    demonstrate_affine_cipher()
    demonstrate_rsa()
    demonstrate_crt()
    demonstrate_batch_inverses()
    demonstrate_combinatorics()
    demonstrate_all_inverses()
    demonstrate_inverse_pairs()
    demonstrate_edge_cases()
    benchmark_inverse_methods(
        a=997,
        modulus=1009,
    )
    randomized_inverse_test()
    demonstrate_common_mistakes()
    demonstrate_inverse_properties()
    demonstrate_equation_solution()
    demonstrate_closure()

    print("\n=== RUNNING UNIT TESTS ===")
    run_unit_tests()
    print("All unit tests passed.")

    print("\nThe interactive calculator is available through:")
    print("interactive_inverse_calculator()")
    print("It is intentionally not started automatically.")


if __name__ == "__main__":
    main()
