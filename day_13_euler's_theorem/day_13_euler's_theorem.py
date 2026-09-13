"""
Euler's Theorem in Number Theory
================================

A comprehensive, executable study file covering Euler's theorem for modular
arithmetic, including:

1. Divisibility and modular arithmetic foundations
2. Greatest common divisor and coprimality
3. Euler's totient function phi(n)
4. Computing phi(n) by several methods
5. Statement and interpretation of Euler's theorem
6. Direct verification
7. Modular exponentiation
8. Efficient computation for large exponents
9. Fermat's little theorem as a special case
10. Euler's theorem and multiplicative inverses
11. Solving congruences using Euler's theorem
12. Handling large exponents
13. Chinese remainder theorem connections
14. RSA-style modular arithmetic
15. Edge cases and common mistakes
16. Performance comparisons
17. Tests and validation
18. Advanced implementation details

The main theorem covered here is:

    If gcd(a, n) = 1, then

        a^phi(n) ≡ 1 (mod n)

where phi(n) is Euler's totient function.
"""

from __future__ import annotations

from math import gcd
from time import perf_counter
import random


# ============================================================================
# 1. BASIC MODULAR ARITHMETIC
# ============================================================================

def explain_modular_arithmetic() -> None:
    """
    Demonstrate the meaning of congruence modulo n.

    a ≡ b (mod n) means that n divides (a - b).
    Equivalently, a and b have the same remainder after division by n.
    """
    print("\n" + "=" * 78)
    print("1. MODULAR ARITHMETIC FOUNDATIONS")
    print("=" * 78)

    examples = [
        (17, 5),
        (29, 7),
        (100, 12),
        (-3, 5),
    ]

    for value, modulus in examples:
        print(
            f"{value} mod {modulus} = {value % modulus}"
        )

    a = 17
    b = 5
    modulus = 6

    print(f"\nChecking whether {a} ≡ {b} (mod {modulus}):")
    print(f"Difference = {a - b}")
    print(f"(a - b) mod modulus = {(a - b) % modulus}")
    print((a - b) % modulus == 0)

    # Addition and multiplication preserve congruence.
    x = 23
    y = 8
    n = 5

    print(f"\n{x} ≡ {y} (mod {n}): {(x - y) % n == 0}")
    print(
        f"Adding 11 gives "
        f"{x + 11} ≡ {y + 11} (mod {n}): "
        f"{((x + 11) - (y + 11)) % n == 0}"
    )
    print(
        f"Multiplying by 7 gives "
        f"{x * 7} ≡ {y * 7} (mod {n}): "
        f"{((x * 7) - (y * 7)) % n == 0}"
    )


# ============================================================================
# 2. GREATEST COMMON DIVISOR AND COPRIMALITY
# ============================================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return (g, x, y) satisfying:

        ax + by = g

    where g = gcd(a, b).

    This is the extended Euclidean algorithm.
    """
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def demonstrate_coprimality() -> None:
    print("\n" + "=" * 78)
    print("2. GCD AND COPRIMALITY")
    print("=" * 78)

    pairs = [
        (8, 15),
        (14, 21),
        (35, 64),
        (17, 100),
    ]

    for a, b in pairs:
        common_divisor = gcd(a, b)
        print(
            f"gcd({a}, {b}) = {common_divisor}; "
            f"coprime = {common_divisor == 1}"
        )

    a = 35
    b = 64
    g, x, y = extended_gcd(a, b)

    print("\nExtended Euclidean algorithm:")
    print(f"{a} * {x} + {b} * {y} = {g}")
    print(f"Verification: {a * x + b * y} = {g}")


# ============================================================================
# 3. EULER'S TOTIENT FUNCTION
# ============================================================================

def is_coprime(a: int, b: int) -> bool:
    """Return True when a and b have greatest common divisor 1."""
    return gcd(a, b) == 1


def totient_brute_force(n: int) -> int:
    """
    Compute phi(n) directly.

    phi(n) is the number of integers k in [1, n] for which gcd(k, n) = 1.

    The value 0 is not included in the usual counting range.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer.")

    return sum(1 for k in range(1, n + 1) if is_coprime(k, n))


def prime_factorization(n: int) -> dict[int, int]:
    """
    Return the prime factorization of n as {prime: exponent}.

    Example:
        360 = 2^3 * 3^2 * 5
    becomes:
        {2: 3, 3: 2, 5: 1}

    Trial division is intentionally used here because it is transparent
    for learning. It is not the preferred algorithm for extremely large
    integers.
    """
    if n < 1:
        raise ValueError("n must be a positive integer.")

    factors: dict[int, int] = {}
    remaining = n

    divisor = 2
    while divisor * divisor <= remaining:
        while remaining % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            remaining //= divisor

        divisor = 3 if divisor == 2 else divisor + 2

    if remaining > 1:
        factors[remaining] = factors.get(remaining, 0) + 1

    return factors


def totient_from_prime_factorization(n: int) -> int:
    """
    Compute phi(n) using the formula

        phi(n) = n * product((p - 1) / p)

    over the distinct prime divisors p of n.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer.")

    result = n

    for prime in prime_factorization(n):
        result -= result // prime

    return result


def demonstrate_totient_function() -> None:
    print("\n" + "=" * 78)
    print("3. EULER'S TOTIENT FUNCTION phi(n)")
    print("=" * 78)

    print(
        "phi(n) counts the positive integers up to n that are coprime to n."
    )

    for n in range(1, 21):
        brute = totient_brute_force(n)
        factor_based = totient_from_prime_factorization(n)
        print(
            f"phi({n:2}) = {brute:2} "
            f"(factorization method: {factor_based:2})"
        )

    print("\nSelected factorizations:")
    for n in [1, 2, 6, 8, 12, 36, 60, 100, 360]:
        print(f"{n:3} = {prime_factorization(n)}")


# ============================================================================
# 4. IMPORTANT TOTIENT FORMULAS
# ============================================================================

def demonstrate_totient_formulas() -> None:
    print("\n" + "=" * 78)
    print("4. IMPORTANT TOTIENT FORMULAS")
    print("=" * 78)

    print("For a prime p:")
    print("    phi(p) = p - 1")

    for p in [2, 3, 5, 7, 11, 13]:
        print(f"phi({p}) = {totient_from_prime_factorization(p)}")

    print("\nFor a prime power p^k:")
    print("    phi(p^k) = p^k - p^(k-1)")
    print("             = p^(k-1)(p - 1)")

    for p, k in [(2, 5), (3, 3), (5, 2)]:
        n = p ** k
        formula = p ** k - p ** (k - 1)
        print(f"phi({p}^{k}) = phi({n}) = {formula}")

    print("\nMultiplicativity for coprime m and n:")
    print("    gcd(m, n) = 1  =>  phi(mn) = phi(m)phi(n)")

    examples = [(3, 4), (5, 7), (8, 9), (7, 10)]

    for m, n in examples:
        if gcd(m, n) == 1:
            left = totient_from_prime_factorization(m * n)
            right = (
                totient_from_prime_factorization(m)
                * totient_from_prime_factorization(n)
            )
            print(f"phi({m}*{n}) = {left}; "
                  f"phi({m})phi({n}) = {right}")


# ============================================================================
# 5. EULER'S THEOREM
# ============================================================================

def euler_theorem_holds(a: int, n: int) -> bool:
    """
    Verify Euler's theorem:

        a^phi(n) ≡ 1 (mod n)

    provided gcd(a, n) = 1.

    Python's pow(a, exponent, modulus) performs modular exponentiation
    efficiently without constructing the enormous integer a^exponent.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer.")

    if gcd(a, n) != 1:
        return False

    phi_n = totient_from_prime_factorization(n)
    return pow(a, phi_n, n) == 1 % n


def demonstrate_euler_theorem() -> None:
    print("\n" + "=" * 78)
    print("5. EULER'S THEOREM")
    print("=" * 78)

    print(
        "Euler's theorem states that if gcd(a, n) = 1, then\n"
        "\n"
        "    a^phi(n) ≡ 1 (mod n).\n"
    )

    examples = [
        (2, 5),
        (3, 10),
        (7, 15),
        (11, 20),
        (7, 40),
        (13, 100),
    ]

    for a, n in examples:
        phi_n = totient_from_prime_factorization(n)
        result = pow(a, phi_n, n)

        print(
            f"a={a:2}, n={n:3}, gcd={gcd(a, n)}, "
            f"phi(n)={phi_n:3}, "
            f"a^phi(n) mod n={result}"
        )


# ============================================================================
# 6. WHY THE COPRIME CONDITION MATTERS
# ============================================================================

def demonstrate_coprime_condition() -> None:
    print("\n" + "=" * 78)
    print("6. WHY COPRIMALITY IS REQUIRED")
    print("=" * 78)

    a = 2
    n = 4

    phi_n = totient_from_prime_factorization(n)

    print(f"a = {a}, n = {n}")
    print(f"gcd(a, n) = {gcd(a, n)}")
    print(f"phi(n) = {phi_n}")
    print(f"a^phi(n) mod n = {pow(a, phi_n, n)}")

    print(
        "\nEuler's theorem cannot be applied because gcd(a, n) != 1."
    )

    print("\nAnother example:")
    a = 6
    n = 9
    phi_n = totient_from_prime_factorization(n)

    print(f"a = {a}, n = {n}")
    print(f"gcd(a, n) = {gcd(a, n)}")
    print(f"phi(n) = {phi_n}")
    print(f"a^phi(n) mod n = {pow(a, phi_n, n)}")


# ============================================================================
# 7. REDUCING LARGE EXPONENTS
# ============================================================================

def reduce_exponent_using_euler(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Compute base^exponent mod modulus by reducing the exponent modulo phi(modulus).

    This reduction is valid when gcd(base, modulus) = 1.

    If exponent is large:

        exponent = q*phi(n) + r

    then:

        base^exponent
        = base^(q*phi(n)+r)
        = (base^phi(n))^q * base^r
        ≡ base^r (mod n)
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive.")

    if exponent < 0:
        raise ValueError("This function expects a non-negative exponent.")

    if gcd(base, modulus) != 1:
        raise ValueError(
            "Euler exponent reduction requires gcd(base, modulus) = 1."
        )

    phi_n = totient_from_prime_factorization(modulus)
    reduced_exponent = exponent % phi_n

    return pow(base, reduced_exponent, modulus)


def demonstrate_large_exponents() -> None:
    print("\n" + "=" * 78)
    print("7. REDUCING LARGE EXPONENTS")
    print("=" * 78)

    base = 7
    exponent = 123456789
    modulus = 40

    phi_n = totient_from_prime_factorization(modulus)
    reduced_exponent = exponent % phi_n

    direct_result = pow(base, exponent, modulus)
    reduced_result = reduce_exponent_using_euler(
        base,
        exponent,
        modulus,
    )

    print(f"Expression: {base}^{exponent} mod {modulus}")
    print(f"phi({modulus}) = {phi_n}")
    print(f"Reduced exponent = {exponent} mod {phi_n} = {reduced_exponent}")
    print(f"Direct modular result = {direct_result}")
    print(f"Euler-reduced result = {reduced_result}")


# ============================================================================
# 8. MODULAR EXPONENTIATION FROM FIRST PRINCIPLES
# ============================================================================

def modular_power_naive(base: int, exponent: int, modulus: int) -> int:
    """
    Naive modular exponentiation.

    This computes multiplication repeatedly and is useful for understanding
    the basic operation, but it is inefficient for very large exponents.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive.")
    if exponent < 0:
        raise ValueError("exponent must be non-negative.")

    result = 1 % modulus

    for _ in range(exponent):
        result = (result * base) % modulus

    return result


def modular_power_fast(base: int, exponent: int, modulus: int) -> int:
    """
    Binary exponentiation, also called exponentiation by squaring.

    Instead of performing O(exponent) multiplications, this method uses
    O(log exponent) modular multiplications.

    Example:

        a^13
        = a^8 * a^4 * a

    Powers are repeatedly squared.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive.")
    if exponent < 0:
        raise ValueError("exponent must be non-negative.")

    result = 1 % modulus
    base %= modulus

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent >>= 1

    return result


def demonstrate_modular_exponentiation() -> None:
    print("\n" + "=" * 78)
    print("8. EFFICIENT MODULAR EXPONENTIATION")
    print("=" * 78)

    base = 7
    exponent = 13
    modulus = 40

    naive = modular_power_naive(base, exponent, modulus)
    fast = modular_power_fast(base, exponent, modulus)
    builtin = pow(base, exponent, modulus)

    print(f"{base}^{exponent} mod {modulus}")
    print(f"Naive method  = {naive}")
    print(f"Fast method   = {fast}")
    print(f"Python pow()  = {builtin}")

    print(
        "\nComplexity comparison:"
        "\nNaive exponentiation: O(exponent)"
        "\nBinary exponentiation: O(log exponent)"
    )


# ============================================================================
# 9. FERMAT'S LITTLE THEOREM
# ============================================================================

def demonstrate_fermat_as_special_case() -> None:
    print("\n" + "=" * 78)
    print("9. FERMAT'S LITTLE THEOREM AS A SPECIAL CASE")
    print("=" * 78)

    print(
        "For a prime p and gcd(a, p) = 1:\n"
        "\n"
        "    a^(p-1) ≡ 1 (mod p)\n"
        "\n"
        "Euler's theorem gives this immediately because:\n"
        "\n"
        "    phi(p) = p - 1."
    )

    primes = [2, 3, 5, 7, 11, 13, 17, 19]

    for p in primes:
        a = 2 if p != 2 else 1
        print(
            f"{a}^{p - 1} mod {p} = {pow(a, p - 1, p)}"
        )


# ============================================================================
# 10. MULTIPLICATIVE INVERSES
# ============================================================================

def modular_inverse_extended_gcd(a: int, modulus: int) -> int:
    """
    Compute the multiplicative inverse of a modulo modulus.

    An inverse exists exactly when gcd(a, modulus) = 1.

    If:

        ax + modulus*y = 1

    then:

        ax ≡ 1 (mod modulus)

    so x is the inverse of a modulo modulus.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1.")

    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise ValueError(
            f"{a} has no multiplicative inverse modulo {modulus}."
        )

    return x % modulus


def modular_inverse_euler(a: int, modulus: int) -> int:
    """
    Compute the inverse using Euler's theorem.

    Since:

        a^phi(n) ≡ 1 (mod n)

    dividing by a conceptually gives:

        a^(phi(n)-1) ≡ a^(-1) (mod n)

    Therefore:

        inverse(a) ≡ a^(phi(n)-1) (mod n)

    This requires gcd(a, n) = 1.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1.")

    if gcd(a, modulus) != 1:
        raise ValueError(
            "Euler-based inverse requires gcd(a, modulus) = 1."
        )

    phi_n = totient_from_prime_factorization(modulus)
    return pow(a, phi_n - 1, modulus)


def demonstrate_modular_inverses() -> None:
    print("\n" + "=" * 78)
    print("10. MODULAR MULTIPLICATIVE INVERSES")
    print("=" * 78)

    a = 7
    modulus = 40

    inverse_by_euclid = modular_inverse_extended_gcd(a, modulus)
    inverse_by_euler = modular_inverse_euler(a, modulus)

    print(f"Inverse of {a} modulo {modulus}:")
    print(f"Extended Euclidean method = {inverse_by_euclid}")
    print(f"Euler theorem method       = {inverse_by_euler}")

    print(
        f"Verification: "
        f"{a} * {inverse_by_euclid} mod {modulus} = "
        f"{(a * inverse_by_euclid) % modulus}"
    )

    print("\nWhy coprimality matters:")
    try:
        modular_inverse_euler(6, 15)
    except ValueError as error:
        print(f"Expected error: {error}")


# ============================================================================
# 11. SOLVING SIMPLE MODULAR EQUATIONS
# ============================================================================

def solve_linear_congruence(
    a: int,
    b: int,
    modulus: int,
) -> int:
    """
    Solve:

        a*x ≡ b (mod modulus)

    when gcd(a, modulus) = 1.

    Multiplying by the modular inverse of a gives:

        x ≡ b*a^(-1) (mod modulus)
    """
    inverse = modular_inverse_extended_gcd(a, modulus)
    return (b * inverse) % modulus


def demonstrate_linear_congruence() -> None:
    print("\n" + "=" * 78)
    print("11. SOLVING LINEAR CONGRUENCES")
    print("=" * 78)

    a = 7
    b = 11
    modulus = 40

    x = solve_linear_congruence(a, b, modulus)

    print(f"Solve {a}x ≡ {b} (mod {modulus})")
    print(f"x ≡ {x} (mod {modulus})")
    print(f"Verification: {a}*{x} mod {modulus} = {(a * x) % modulus}")


# ============================================================================
# 12. EULER'S THEOREM AND RSA-STYLE ARITHMETIC
# ============================================================================

def rsa_totient_from_primes(p: int, q: int) -> int:
    """
    For distinct primes p and q:

        n = pq
        phi(n) = (p - 1)(q - 1)
    """
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be greater than 1.")

    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must be prime.")

    if p == q:
        raise ValueError("p and q must be distinct.")

    return (p - 1) * (q - 1)


def is_prime(n: int) -> bool:
    """Return True if n is prime using trial division."""
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2

    return True


def demonstrate_rsa_style_arithmetic() -> None:
    print("\n" + "=" * 78)
    print("12. RSA-STYLE MODULAR ARITHMETIC")
    print("=" * 78)

    p = 61
    q = 53
    n = p * q
    phi_n = rsa_totient_from_primes(p, q)

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p*q = {n}")
    print(f"phi(n) = (p-1)(q-1) = {phi_n}")

    # Choose a public exponent e coprime to phi(n).
    e = 17

    if gcd(e, phi_n) != 1:
        raise RuntimeError("Chosen public exponent is invalid.")

    d = modular_inverse_extended_gcd(e, phi_n)

    print(f"Public exponent e = {e}")
    print(f"Private exponent d = {d}")
    print(f"e*d mod phi(n) = {(e * d) % phi_n}")

    message = 65

    encrypted = pow(message, e, n)
    decrypted = pow(encrypted, d, n)

    print(f"Message    = {message}")
    print(f"Encrypted  = {encrypted}")
    print(f"Decrypted  = {decrypted}")

    print(
        "\nThe example illustrates the modular-exponentiation structure used "
        "in RSA. Real cryptographic systems require much larger parameters "
        "and carefully designed padding and implementation techniques."
    )


# ============================================================================
# 13. CHINESE REMAINDER THEOREM CONNECTION
# ============================================================================

def chinese_remainder_two(
    a1: int,
    n1: int,
    a2: int,
    n2: int,
) -> int:
    """
    Solve:

        x ≡ a1 (mod n1)
        x ≡ a2 (mod n2)

    for coprime n1 and n2.

    This implementation is intentionally limited to two congruences so that
    the connection between modular inverses and CRT remains explicit.
    """
    if n1 <= 0 or n2 <= 0:
        raise ValueError("Moduli must be positive.")

    if gcd(n1, n2) != 1:
        raise ValueError("The moduli must be coprime.")

    inverse = modular_inverse_extended_gcd(n1, n2)

    # x = a1 + n1*k
    # a1 + n1*k ≡ a2 (mod n2)
    # n1*k ≡ a2-a1 (mod n2)
    k = ((a2 - a1) * inverse) % n2

    return (a1 + n1 * k) % (n1 * n2)


def demonstrate_crt_connection() -> None:
    print("\n" + "=" * 78)
    print("13. CONNECTION WITH THE CHINESE REMAINDER THEOREM")
    print("=" * 78)

    a1, n1 = 2, 3
    a2, n2 = 3, 5

    x = chinese_remainder_two(a1, n1, a2, n2)

    print(f"x ≡ {a1} (mod {n1})")
    print(f"x ≡ {a2} (mod {n2})")
    print(f"Solution modulo {n1 * n2}: x = {x}")
    print(f"Check first congruence: {x % n1}")
    print(f"Check second congruence: {x % n2}")

    print(
        "\nEuler's theorem is useful in modular arithmetic because it gives "
        "information about powers and inverses. CRT can then combine "
        "congruences over coprime moduli."
    )


# ============================================================================
# 14. CARMICHAEL FUNCTION: A SHARPER EXPONENT REDUCTION
# ============================================================================

def lcm(a: int, b: int) -> int:
    """Return the least common multiple of two positive integers."""
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // gcd(a, b)


def carmichael_prime_power(prime: int, exponent: int) -> int:
    """
    Compute the Carmichael function lambda(p^k).

    For odd prime p:

        lambda(p^k) = phi(p^k)

    For powers of 2:

        lambda(2) = 1
        lambda(4) = 2
        lambda(2^k) = 2^(k-2), k >= 3
    """
    if prime == 2:
        if exponent == 1:
            return 1
        if exponent == 2:
            return 2
        return 2 ** (exponent - 2)

    return (prime - 1) * prime ** (exponent - 1)


def carmichael_function(n: int) -> int:
    """
    Compute Carmichael's lambda(n) using prime factorization.

    lambda(n) is the exponent of the multiplicative group modulo n.
    For every a coprime to n:

        a^lambda(n) ≡ 1 (mod n)

    lambda(n) always divides phi(n).
    """
    if n <= 0:
        raise ValueError("n must be positive.")

    if n == 1:
        return 1

    prime_powers = [
        carmichael_prime_power(p, k)
        for p, k in prime_factorization(n).items()
    ]

    result = 1
    for value in prime_powers:
        result = lcm(result, value)

    return result


def demonstrate_carmichael_comparison() -> None:
    print("\n" + "=" * 78)
    print("14. CARMICHAEL FUNCTION AND SHARPER EXPONENT REDUCTION")
    print("=" * 78)

    print(
        "Euler gives an exponent phi(n). Carmichael's function lambda(n) "
        "can sometimes give a smaller universal exponent."
    )

    for n in [5, 8, 10, 12, 15, 16, 20, 21, 24, 40]:
        phi_n = totient_from_prime_factorization(n)
        lambda_n = carmichael_function(n)

        print(
            f"n={n:2}: phi(n)={phi_n:2}, "
            f"lambda(n)={lambda_n:2}, "
            f"lambda <= phi: {lambda_n <= phi_n}"
        )

    a = 7
    n = 40

    phi_n = totient_from_prime_factorization(n)
    lambda_n = carmichael_function(n)

    print(
        f"\nFor a={a}, n={n}: "
        f"a^phi(n) mod n = {pow(a, phi_n, n)}"
    )
    print(
        f"For a={a}, n={n}: "
        f"a^lambda(n) mod n = {pow(a, lambda_n, n)}"
    )


# ============================================================================
# 15. MULTIPLICATIVE GROUP INTERPRETATION
# ============================================================================

def reduced_residue_system(n: int) -> list[int]:
    """
    Return the integers from 1 through n that are coprime to n.

    These form the reduced residue system modulo n.
    """
    if n <= 0:
        raise ValueError("n must be positive.")

    return [a for a in range(1, n + 1) if gcd(a, n) == 1]


def demonstrate_group_interpretation() -> None:
    print("\n" + "=" * 78)
    print("15. MULTIPLICATIVE GROUP INTERPRETATION")
    print("=" * 78)

    n = 10
    residues = reduced_residue_system(n)

    print(f"Reduced residue system modulo {n}: {residues}")
    print(f"Number of elements = {len(residues)}")
    print(f"phi({n}) = {totient_from_prime_factorization(n)}")

    print(
        "\nThe invertible residue classes modulo n form the multiplicative "
        "group usually denoted U(n) or (Z/nZ)^*."
    )

    print(
        "\nEuler's theorem can be interpreted as follows:"
        "\nEach element a in this group satisfies"
        "\n    a^|U(n)| = a^phi(n) = 1"
        "\nwhen interpreted modulo n."
    )


# ============================================================================
# 16. EULER'S THEOREM BY PERMUTING COPRIME RESIDUES
# ============================================================================

def demonstrate_conceptual_proof() -> None:
    print("\n" + "=" * 78)
    print("16. CONCEPTUAL PROOF OF EULER'S THEOREM")
    print("=" * 78)

    n = 10
    a = 3

    residues = reduced_residue_system(n)
    multiplied = [(a * r) % n for r in residues]

    print(f"n = {n}")
    print(f"a = {a}")
    print(f"Reduced residue system: {residues}")
    print(f"Multiply every residue by {a} modulo {n}:")
    print(f"{multiplied}")

    print(
        "\nBecause gcd(a,n)=1, multiplication by a is a permutation of "
        "the reduced residue system."
    )

    print(
        "\nTherefore the product of the transformed residues is congruent "
        "to the product of the original residues."
    )

    print(
        "\nThe product contains a common factor a^phi(n). "
        "After cancellation in the modular group, this yields:"
        "\n"
        "\n    a^phi(n) ≡ 1 (mod n)."
    )


# ============================================================================
# 17. EDGE CASE: n = 1
# ============================================================================

def demonstrate_edge_case_n_equals_one() -> None:
    print("\n" + "=" * 78)
    print("17. EDGE CASE: n = 1")
    print("=" * 78)

    print(f"phi(1) = {totient_from_prime_factorization(1)}")
    print(
        "Modulo 1 every integer is congruent to 0, so the modular system "
        "is degenerate."
    )

    print(
        f"pow(7, phi(1), 1) = "
        f"{pow(7, totient_from_prime_factorization(1), 1)}"
    )


# ============================================================================
# 18. EDGE CASES FOR NEGATIVE BASES
# ============================================================================

def demonstrate_negative_bases() -> None:
    print("\n" + "=" * 78)
    print("18. NEGATIVE BASES")
    print("=" * 78)

    examples = [
        (-3, 4),
        (-5, 7),
        (-7, 10),
        (-11, 20),
    ]

    for base, modulus in examples:
        if gcd(base, modulus) == 1:
            phi_n = totient_from_prime_factorization(modulus)
            result = pow(base, phi_n, modulus)

            print(
                f"base={base:3}, modulus={modulus:2}, "
                f"gcd={gcd(base, modulus)}, "
                f"phi={phi_n:2}, result={result}"
            )


# ============================================================================
# 19. EDGE CASES FOR ZERO AND NON-COPRIME BASES
# ============================================================================

def demonstrate_zero_and_non_coprime_cases() -> None:
    print("\n" + "=" * 78)
    print("19. ZERO AND NON-COPRIME BASES")
    print("=" * 78)

    cases = [
        (0, 7),
        (2, 8),
        (4, 12),
        (9, 15),
    ]

    for base, modulus in cases:
        phi_n = totient_from_prime_factorization(modulus)
        result = pow(base, phi_n, modulus)

        print(
            f"a={base}, n={modulus}, gcd={gcd(base, modulus)}, "
            f"phi(n)={phi_n}, "
            f"a^phi(n) mod n={result}"
        )

    print(
        "\nThe theorem is not a universal identity for arbitrary a and n. "
        "The coprimality condition is part of the theorem."
    )


# ============================================================================
# 20. PERIODICITY AND MULTIPLICATIVE ORDER
# ============================================================================

def multiplicative_order(a: int, modulus: int) -> int:
    """
    Find the smallest positive k such that:

        a^k ≡ 1 (mod modulus)

    This is called the multiplicative order of a modulo modulus.

    Euler's theorem guarantees that such a k exists when gcd(a, modulus)=1
    and that k divides phi(modulus).
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1.")

    if gcd(a, modulus) != 1:
        raise ValueError(
            "Multiplicative order requires gcd(a, modulus) = 1."
        )

    phi_n = totient_from_prime_factorization(modulus)

    for k in range(1, phi_n + 1):
        if pow(a, k, modulus) == 1:
            return k

    raise RuntimeError("Order should exist by Euler's theorem.")


def demonstrate_multiplicative_order() -> None:
    print("\n" + "=" * 78)
    print("20. MULTIPLICATIVE ORDER")
    print("=" * 78)

    examples = [
        (2, 7),
        (3, 7),
        (2, 9),
        (3, 10),
        (7, 20),
    ]

    for a, n in examples:
        order = multiplicative_order(a, n)
        phi_n = totient_from_prime_factorization(n)

        print(
            f"ord_{n}({a}) = {order}; "
            f"phi({n}) = {phi_n}; "
            f"phi divisible by order = {phi_n % order == 0}"
        )

    print(
        "\nThe order is often much smaller than phi(n). "
        "Euler's theorem guarantees only that the order divides phi(n)."
    )


# ============================================================================
# 21. FINDING A SMALLER VALID EXPONENT
# ============================================================================

def divisors(n: int) -> list[int]:
    """Return all positive divisors of n in sorted order."""
    if n <= 0:
        raise ValueError("n must be positive.")

    result: list[int] = []

    for candidate in range(1, int(n ** 0.5) + 1):
        if n % candidate == 0:
            result.append(candidate)

            other = n // candidate
            if other != candidate:
                result.append(other)

    return sorted(result)


def find_smallest_exponent_for_base(
    base: int,
    modulus: int,
) -> int:
    """
    Find the multiplicative order by testing divisors of phi(n).

    This illustrates a useful optimization: instead of testing every
    exponent up to phi(n), only divisors of phi(n) need to be checked.
    """
    if gcd(base, modulus) != 1:
        raise ValueError("base and modulus must be coprime.")

    phi_n = totient_from_prime_factorization(modulus)

    for candidate in divisors(phi_n):
        if pow(base, candidate, modulus) == 1:
            return candidate

    raise RuntimeError("No valid order found.")


def demonstrate_order_optimization() -> None:
    print("\n" + "=" * 78)
    print("21. ORDER-BASED EXPONENT REDUCTION")
    print("=" * 78)

    base = 7
    modulus = 40

    phi_n = totient_from_prime_factorization(modulus)
    order = find_smallest_exponent_for_base(base, modulus)

    print(f"base = {base}")
    print(f"modulus = {modulus}")
    print(f"phi(modulus) = {phi_n}")
    print(f"multiplicative order = {order}")

    exponent = 987654321
    result_using_order = pow(base, exponent % order, modulus)
    direct_result = pow(base, exponent, modulus)

    print(f"\nExponent = {exponent}")
    print(f"Exponent mod order = {exponent % order}")
    print(f"Direct result = {direct_result}")
    print(f"Order-reduced result = {result_using_order}")


# ============================================================================
# 22. A GENERAL POWER REDUCTION FUNCTION
# ============================================================================

def euler_power_reduction(
    base: int,
    exponent: int,
    modulus: int,
) -> tuple[int, int, int, int]:
    """
    Return:

        (phi(n), reduced_exponent, result, direct_result)

    for a coprime base.
    """
    if exponent < 0:
        raise ValueError("Exponent must be non-negative.")

    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    if gcd(base, modulus) != 1:
        raise ValueError("Euler reduction requires a coprime base.")

    phi_n = totient_from_prime_factorization(modulus)
    reduced_exponent = exponent % phi_n
    result = pow(base, reduced_exponent, modulus)
    direct_result = pow(base, exponent, modulus)

    return phi_n, reduced_exponent, result, direct_result


def demonstrate_general_power_reduction() -> None:
    print("\n" + "=" * 78)
    print("22. GENERAL EULER POWER REDUCTION")
    print("=" * 78)

    examples = [
        (3, 10**6 + 123, 20),
        (11, 10**9 + 7, 100),
        (17, 987654321, 120),
        (19, 1234567890123, 200),
    ]

    for base, exponent, modulus in examples:
        phi_n, reduced, result, direct = euler_power_reduction(
            base,
            exponent,
            modulus,
        )

        print(
            f"a={base}, exponent={exponent}, n={modulus}"
        )
        print(
            f"phi(n)={phi_n}, exponent mod phi(n)={reduced}, "
            f"result={result}, matches={result == direct}"
        )
        print()


# ============================================================================
# 23. PERFORMANCE COMPARISON
# ============================================================================

def benchmark_modular_exponentiation() -> None:
    print("\n" + "=" * 78)
    print("23. PERFORMANCE CONSIDERATIONS")
    print("=" * 78)

    base = 1234567
    modulus = 1000000007
    exponent = 1_000_000

    start = perf_counter()
    naive_result = modular_power_naive(base, exponent, modulus)
    naive_time = perf_counter() - start

    start = perf_counter()
    fast_result = modular_power_fast(base, exponent, modulus)
    fast_time = perf_counter() - start

    start = perf_counter()
    builtin_result = pow(base, exponent, modulus)
    builtin_time = perf_counter() - start

    print(f"Results equal: {naive_result == fast_result == builtin_result}")
    print(f"Naive method time: {naive_time:.6f} seconds")
    print(f"Fast method time:  {fast_time:.6f} seconds")
    print(f"pow() time:       {builtin_time:.6f} seconds")

    print(
        "\nThe exact timings depend on the computer and Python version. "
        "The algorithmic difference is the important point."
    )


# ============================================================================
# 24. RANDOMIZED THEOREM VERIFICATION
# ============================================================================

def randomized_euler_verification(
    trials: int = 1000,
    maximum_modulus: int = 200,
) -> None:
    """
    Randomly test Euler's theorem for many small values.

    Only coprime pairs are tested because the theorem explicitly requires
    gcd(a,n)=1.
    """
    successful = 0

    for _ in range(trials):
        modulus = random.randint(2, maximum_modulus)
        base = random.randint(1, maximum_modulus)

        if gcd(base, modulus) != 1:
            continue

        phi_n = totient_from_prime_factorization(modulus)

        if pow(base, phi_n, modulus) != 1:
            raise AssertionError(
                f"Euler's theorem failed for a={base}, n={modulus}"
            )

        successful += 1

    print("\n" + "=" * 78)
    print("24. RANDOMIZED VERIFICATION")
    print("=" * 78)
    print(f"Random trials requested: {trials}")
    print(f"Coprime cases verified: {successful}")
    print("All tested coprime cases satisfied Euler's theorem.")


# ============================================================================
# 25. COMMON MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n" + "=" * 78)
    print("25. COMMON MISTAKES")
    print("=" * 78)

    print("Mistake 1: Forgetting the gcd condition.")
    print(
        "Wrong generalization: a^phi(n) ≡ 1 (mod n) for every a."
    )
    print(
        "Correct: the theorem requires gcd(a,n)=1."
    )

    print("\nMistake 2: Confusing phi(n) with n-1.")
    print("phi(n) = n-1 only when n is prime.")

    for n in [5, 7, 8, 9, 10]:
        print(
            f"n={n}: phi(n)={totient_from_prime_factorization(n)}, "
            f"n-1={n - 1}"
        )

    print("\nMistake 3: Computing huge powers directly.")
    print(
        "Use pow(base, exponent, modulus) or binary modular exponentiation."
    )

    print("\nMistake 4: Treating Euler reduction as valid for non-coprime bases.")
    print(
        "For example, reducing the exponent modulo phi(8) for 2^k mod 8 "
        "is not justified by Euler's theorem."
    )

    print("\nMistake 5: Confusing Euler's theorem with Fermat's little theorem.")
    print(
        "Fermat's little theorem concerns prime moduli; Euler's theorem "
        "works for any positive modulus when the base is coprime to it."
    )


# ============================================================================
# 26. LIMITATIONS AND TRADE-OFFS
# ============================================================================

def demonstrate_limitations() -> None:
    print("\n" + "=" * 78)
    print("26. LIMITATIONS AND TRADE-OFFS")
    print("=" * 78)

    print(
        "1. Computing phi(n) efficiently requires knowledge of the prime "
        "factorization of n."
    )
    print(
        "2. Factoring very large arbitrary integers can be computationally "
        "difficult."
    )
    print(
        "3. Euler exponent reduction cannot automatically be used when "
        "gcd(base, modulus) != 1."
    )
    print(
        "4. Euler's theorem provides a valid exponent bound, but the actual "
        "multiplicative order can be smaller."
    )
    print(
        "5. Carmichael's lambda function can sometimes provide a smaller "
        "universal exponent than phi(n)."
    )
    print(
        "6. In cryptographic applications, mathematical correctness alone "
        "does not guarantee security."
    )


# ============================================================================
# 27. PRACTICAL APPLICATIONS
# ============================================================================

def demonstrate_applications() -> None:
    print("\n" + "=" * 78)
    print("27. PRACTICAL APPLICATIONS")
    print("=" * 78)

    applications = [
        (
            "Modular inverses",
            "Computing a^(-1) modulo n when gcd(a,n)=1."
        ),
        (
            "Congruence solving",
            "Solving equations such as ax ≡ b (mod n)."
        ),
        (
            "RSA mathematics",
            "Understanding why modular exponentiation can be reversed "
            "with suitable exponents."
        ),
        (
            "Exponent reduction",
            "Simplifying very large powers modulo n."
        ),
        (
            "Multiplicative groups",
            "Understanding the structure of invertible residues modulo n."
        ),
        (
            "Number theory",
            "Studying periodicity, orders, inverses, and congruences."
        ),
    ]

    for name, description in applications:
        print(f"- {name}: {description}")


# ============================================================================
# 28. UNIT-STYLE TESTS
# ============================================================================

def run_unit_tests() -> None:
    print("\n" + "=" * 78)
    print("28. UNIT TESTS")
    print("=" * 78)

    # Totient tests.
    expected_totients = {
        1: 1,
        2: 1,
        3: 2,
        4: 2,
        5: 4,
        6: 2,
        7: 6,
        8: 4,
        9: 6,
        10: 4,
        12: 4,
        20: 8,
        36: 12,
        100: 40,
    }

    for n, expected in expected_totients.items():
        assert totient_from_prime_factorization(n) == expected
        assert totient_brute_force(n) == expected

    # Euler theorem tests.
    for n in range(2, 100):
        phi_n = totient_from_prime_factorization(n)

        for a in range(1, 30):
            if gcd(a, n) == 1:
                assert pow(a, phi_n, n) == 1

    # Fast exponentiation tests.
    for _ in range(500):
        base = random.randint(-1000, 1000)
        exponent = random.randint(0, 100)
        modulus = random.randint(2, 500)

        assert (
            modular_power_fast(base, exponent, modulus)
            == pow(base, exponent, modulus)
        )

    # Extended Euclidean algorithm tests.
    for _ in range(500):
        a = random.randint(-1000, 1000)
        b = random.randint(-1000, 1000)

        if a == 0 and b == 0:
            continue

        g, x, y = extended_gcd(a, b)

        assert g == gcd(a, b)
        assert a * x + b * y == g

    # Inverse tests.
    for modulus in range(2, 100):
        for a in range(1, modulus):
            if gcd(a, modulus) == 1:
                inverse = modular_inverse_extended_gcd(a, modulus)
                assert (a * inverse) % modulus == 1

    # Multiplicative order tests.
    for modulus in range(2, 50):
        for a in range(1, modulus):
            if gcd(a, modulus) == 1:
                order = multiplicative_order(a, modulus)
                phi_n = totient_from_prime_factorization(modulus)

                assert pow(a, order, modulus) == 1
                assert phi_n % order == 0

    print("All unit tests passed.")


# ============================================================================
# 29. A COMPACT EULER'S THEOREM WORKFLOW
# ============================================================================

def euler_theorem_workflow(
    base: int,
    modulus: int,
) -> dict[str, int | bool]:
    """
    Provide the essential information needed to apply Euler's theorem.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive.")

    common_divisor = gcd(base, modulus)
    phi_n = totient_from_prime_factorization(modulus)

    return {
        "base": base,
        "modulus": modulus,
        "gcd": common_divisor,
        "phi": phi_n,
        "coprime": common_divisor == 1,
        "theorem_applies": common_divisor == 1,
        "a_to_phi_mod_n": pow(base, phi_n, modulus),
    }


def demonstrate_workflow() -> None:
    print("\n" + "=" * 78)
    print("29. EULER'S THEOREM WORKFLOW")
    print("=" * 78)

    for base, modulus in [(7, 40), (9, 20), (6, 15)]:
        information = euler_theorem_workflow(base, modulus)

        print(f"\nInput: a={base}, n={modulus}")

        for key, value in information.items():
            print(f"{key}: {value}")


# ============================================================================
# 30. INTERACTIVE CALCULATOR
# ============================================================================

def interactive_euler_calculator() -> None:
    """
    Optional interactive calculator.

    It is disabled by default in main() so that the study file remains
    completely non-interactive when executed.
    """
    print("\nEuler's Theorem Calculator")
    print("Enter integers when prompted.")

    try:
        base = int(input("Base a: "))
        exponent = int(input("Exponent k: "))
        modulus = int(input("Modulus n: "))

        if modulus <= 0:
            raise ValueError("Modulus must be positive.")

        print(f"\ngcd(a,n) = {gcd(base, modulus)}")
        print(f"phi(n) = {totient_from_prime_factorization(modulus)}")
        print(
            f"a^k mod n = "
            f"{pow(base, exponent, modulus)}"
        )

        if gcd(base, modulus) == 1:
            phi_n = totient_from_prime_factorization(modulus)

            print(
                f"a^phi(n) mod n = "
                f"{pow(base, phi_n, modulus)}"
            )

            reduced_exponent = exponent % phi_n
            print(f"k mod phi(n) = {reduced_exponent}")
            print(
                f"a^(k mod phi(n)) mod n = "
                f"{pow(base, reduced_exponent, modulus)}"
            )
        else:
            print(
                "Euler exponent reduction is not directly applicable "
                "because gcd(a,n) != 1."
            )

    except ValueError as error:
        print(f"Input error: {error}")


# ============================================================================
# 31. MAIN STUDY PROGRAM
# ============================================================================

def main() -> None:
    """
    Run the complete educational demonstration.

    Each section is independent enough to be studied separately.
    """
    print("=" * 78)
    print("EULER'S THEOREM IN NUMBER THEORY")
    print("=" * 78)
    print(
        "Euler's theorem: if gcd(a,n)=1, then a^phi(n) ≡ 1 (mod n)."
    )

    explain_modular_arithmetic()
    demonstrate_coprimality()
    demonstrate_totient_function()
    demonstrate_totient_formulas()
    demonstrate_euler_theorem()
    demonstrate_coprime_condition()
    demonstrate_large_exponents()
    demonstrate_modular_exponentiation()
    demonstrate_fermat_as_special_case()
    demonstrate_modular_inverses()
    demonstrate_linear_congruence()
    demonstrate_rsa_style_arithmetic()
    demonstrate_crt_connection()
    demonstrate_carmichael_comparison()
    demonstrate_group_interpretation()
    demonstrate_conceptual_proof()
    demonstrate_edge_case_n_equals_one()
    demonstrate_negative_bases()
    demonstrate_zero_and_non_coprime_cases()
    demonstrate_multiplicative_order()
    demonstrate_order_optimization()
    demonstrate_general_power_reduction()
    benchmark_modular_exponentiation()
    randomized_euler_verification()
    demonstrate_common_mistakes()
    demonstrate_limitations()
    demonstrate_applications()
    run_unit_tests()
    demonstrate_workflow()

    print("\n" + "=" * 78)
    print("END OF EULER'S THEOREM STUDY SCRIPT")
    print("=" * 78)


if __name__ == "__main__":
    main()
