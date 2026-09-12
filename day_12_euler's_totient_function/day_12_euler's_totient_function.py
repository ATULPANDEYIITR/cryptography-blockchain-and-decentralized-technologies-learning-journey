"""
Euler's Totient Function
========================

A self-contained study script covering Euler's totient function from
absolute beginner concepts through advanced number-theoretic applications.

Euler's totient function is written as phi(n) or φ(n). It counts the
positive integers from 1 through n that are relatively prime to n.

This script demonstrates:
- Divisibility and greatest common divisor
- Coprime integers
- Definition of φ(n)
- Direct counting
- Important special cases
- Prime and prime-power formulas
- Product formula from prime factorization
- Inclusion-exclusion interpretation
- Multiplicativity
- The divisor-sum identity
- Möbius inversion
- Efficient computation
- Sieve computation of φ(1), ..., φ(N)
- Linear-time totient sieve
- Euler's theorem
- Modular inverses
- RSA-related mathematics
- Reduced residue systems
- Ratios and asymptotic behavior
- Summatory totients
- Farey sequence connection
- Jordan's totient function
- Carmichael-function comparison
- Edge cases, validation, testing, and performance
- Practical algorithm comparisons

Only the Python standard library is used.
"""

from __future__ import annotations

from math import gcd, isqrt
from random import randint, seed
from typing import Iterable


# ---------------------------------------------------------------------------
# FUNDAMENTAL NUMBER-THEORY BUILDING BLOCKS
# ---------------------------------------------------------------------------

def divisors(n: int) -> list[int]:
    """
    Return all positive divisors of n in sorted order.

    A divisor d of n satisfies n % d == 0.

    The square-root method checks divisor pairs:
        d and n // d

    This takes O(sqrt(n)) time rather than testing every integer up to n.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    result: list[int] = []

    for d in range(1, isqrt(n) + 1):
        if n % d == 0:
            result.append(d)

            paired = n // d
            if paired != d:
                result.append(paired)

    return sorted(result)


def gcd_euclidean(a: int, b: int) -> int:
    """
    Compute gcd(a, b) using the Euclidean algorithm.

    The fundamental identity is:

        gcd(a, b) = gcd(b, a mod b)

    until the second argument becomes zero.

    Time complexity is O(log(min(|a|, |b|))) for ordinary integer inputs.
    """
    a, b = abs(a), abs(b)

    while b != 0:
        a, b = b, a % b

    return a


def are_coprime(a: int, b: int) -> bool:
    """
    Two integers are coprime if their greatest common divisor is 1.
    """
    return gcd_euclidean(a, b) == 1


# ---------------------------------------------------------------------------
# EULER'S TOTIENT FUNCTION: DIRECT DEFINITION
# ---------------------------------------------------------------------------

def phi_bruteforce(n: int) -> int:
    """
    Compute Euler's totient function directly from its definition.

    φ(n) = number of integers k satisfying:

        1 <= k <= n
        gcd(k, n) = 1

    For n > 1, checking k = 1 through n is straightforward.

    φ(1) = 1 by the standard number-theoretic convention because 1 is
    coprime to itself and the set {1} contains one positive integer.

    Complexity:
        O(n log n) approximately because each gcd costs logarithmic time.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    return sum(1 for k in range(1, n + 1) if gcd_euclidean(k, n) == 1)


def coprime_numbers_up_to(n: int) -> list[int]:
    """
    Return the integers in [1, n] that are coprime to n.

    These numbers form the positive portion of the reduced residue system
    when restricted to the interval [1, n].
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    return [k for k in range(1, n + 1) if are_coprime(k, n)]


# ---------------------------------------------------------------------------
# SPECIAL CASES AND BASIC FORMULAS
# ---------------------------------------------------------------------------

def phi_for_prime(p: int) -> int:
    """
    For a prime p:

        φ(p) = p - 1

    Every integer 1, 2, ..., p-1 is coprime to p.
    """
    if p < 2:
        raise ValueError("p must be at least 2")

    # This function assumes the caller intends p to be prime.
    # The mathematical formula is valid only for prime p.
    return p - 1


def is_prime(n: int) -> bool:
    """
    Determine whether n is prime using trial division.

    The function is deliberately simple because it is used to teach
    factorization concepts, not to replace industrial-strength primality
    testing for enormous integers.
    """
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    limit = isqrt(n)

    for candidate in range(3, limit + 1, 2):
        if n % candidate == 0:
            return False

    return True


def prime_power_totient(p: int, exponent: int) -> int:
    """
    Compute φ(p^k) for a prime p and integer k >= 1.

        φ(p^k) = p^k - p^(k-1)
                 = p^k(1 - 1/p)

    The excluded numbers are precisely the multiples of p.
    """
    if not is_prime(p):
        raise ValueError("p must be prime")

    if exponent < 1:
        raise ValueError("exponent must be at least 1")

    return p**exponent - p ** (exponent - 1)


# ---------------------------------------------------------------------------
# PRIME FACTORIZATION
# ---------------------------------------------------------------------------

def prime_factorization(n: int) -> dict[int, int]:
    """
    Return the prime factorization of n as {prime: exponent}.

    Example:
        360 = 2^3 * 3^2 * 5

        prime_factorization(360)
        -> {2: 3, 3: 2, 5: 1}

    Trial division is used for clarity.

    Complexity is roughly O(sqrt(n)) in the worst case.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    factors: dict[int, int] = {}
    remaining = n

    while remaining % 2 == 0 and remaining > 1:
        factors[2] = factors.get(2, 0) + 1
        remaining //= 2

    candidate = 3

    while candidate * candidate <= remaining:
        while remaining % candidate == 0:
            factors[candidate] = factors.get(candidate, 0) + 1
            remaining //= candidate

        candidate += 2

    if remaining > 1:
        factors[remaining] = factors.get(remaining, 0) + 1

    return factors


def format_factorization(factors: dict[int, int]) -> str:
    """
    Convert a factorization dictionary into readable mathematical text.
    """
    if not factors:
        return "1"

    pieces = []

    for prime, exponent in sorted(factors.items()):
        if exponent == 1:
            pieces.append(str(prime))
        else:
            pieces.append(f"{prime}^{exponent}")

    return " * ".join(pieces)


# ---------------------------------------------------------------------------
# EFFICIENT TOTIENT FROM PRIME FACTORIZATION
# ---------------------------------------------------------------------------

def phi_from_factorization(n: int, factors: dict[int, int]) -> int:
    """
    Compute φ(n) from the distinct prime divisors of n.

    Euler's product formula is:

        φ(n) = n * product(1 - 1/p)

    where p runs over the distinct prime divisors of n.

    An integer-only equivalent is:

        result = n
        result -= result // p

    for every distinct prime divisor p.

    Integer arithmetic avoids floating-point rounding.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    result = n

    for prime in factors:
        result -= result // prime

    return result


def phi(n: int) -> int:
    """
    Efficient single-value implementation of Euler's totient function.

    The algorithm factors n and applies:

        φ(n) = n * ∏(1 - 1/p)

    over distinct prime factors p.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    if n == 1:
        return 1

    factors = prime_factorization(n)
    return phi_from_factorization(n, factors)


# ---------------------------------------------------------------------------
# WHY THE PRODUCT FORMULA WORKS
# ---------------------------------------------------------------------------

def phi_by_inclusion_exclusion(n: int) -> int:
    """
    Compute φ(n) using inclusion-exclusion over distinct prime divisors.

    If the distinct prime divisors are p1, p2, ..., pk, then the integers
    not coprime to n are those divisible by at least one pi.

    Inclusion-exclusion gives:

        n
        - sum(n/pi)
        + sum(n/(pi*pj))
        - ...
        + (-1)^k n/(p1*...*pk)

    This implementation explicitly constructs those terms.

    It is mainly educational. The product formula is usually simpler.
    """
    if n <= 0:
        raise ValueError("n must be a positive integer")

    if n == 1:
        return 1

    primes = list(prime_factorization(n).keys())
    total = 0
    number_of_primes = len(primes)

    # Each bitmask chooses a subset of distinct prime divisors.
    for mask in range(1 << number_of_primes):
        product = 1
        subset_size = 0

        for index, prime in enumerate(primes):
            if mask & (1 << index):
                product *= prime
                subset_size += 1

        term = n // product

        if subset_size % 2 == 0:
            total += term
        else:
            total -= term

    return total


# ---------------------------------------------------------------------------
# MULTIPLICATIVITY
# ---------------------------------------------------------------------------

def demonstrate_coprime_multiplicativity(a: int, b: int) -> tuple[int, int, int]:
    """
    For gcd(a, b) = 1:

        φ(ab) = φ(a)φ(b)

    This is called multiplicativity.

    Euler's totient function is multiplicative but is NOT completely
    multiplicative.

    For example:

        φ(2)φ(2) = 1
        φ(4) = 2

    so φ(4) != φ(2)φ(2).
    """
    if a <= 0 or b <= 0:
        raise ValueError("a and b must be positive")

    if gcd(a, b) != 1:
        raise ValueError("a and b must be coprime")

    return phi(a * b), phi(a) * phi(b), gcd(a, b)


# ---------------------------------------------------------------------------
# DIVISOR-SUM IDENTITY
# ---------------------------------------------------------------------------

def divisor_sum_totient(n: int) -> int:
    """
    Compute:

        sum_{d | n} φ(d)

    A fundamental identity states:

        sum_{d | n} φ(d) = n

    for every positive integer n.

    This identity can be understood by partitioning the integers
    1, ..., n according to gcd(k, n).
    """
    if n <= 0:
        raise ValueError("n must be positive")

    return sum(phi(d) for d in divisors(n))


# ---------------------------------------------------------------------------
# MÖBIUS FUNCTION AND MÖBIUS INVERSION
# ---------------------------------------------------------------------------

def mobius(n: int) -> int:
    """
    Compute the Möbius function μ(n).

    Definition:
        μ(1) = 1

        μ(n) = 0 if n has a squared prime factor.

        μ(n) = (-1)^k if n is a product of k distinct primes.

    Euler's totient can be represented as:

        φ(n) = n * sum_{d|n} μ(d)/d

    An integer form is:

        φ(n) = sum_{d|n} μ(d) * (n/d)
    """
    if n <= 0:
        raise ValueError("n must be positive")

    if n == 1:
        return 1

    factors = prime_factorization(n)

    if any(exponent >= 2 for exponent in factors.values()):
        return 0

    return -1 if len(factors) % 2 else 1


def phi_by_mobius(n: int) -> int:
    """
    Compute φ(n) from the Möbius-function identity.
    """
    if n <= 0:
        raise ValueError("n must be positive")

    return sum(mobius(d) * (n // d) for d in divisors(n))


# ---------------------------------------------------------------------------
# REDUCED RESIDUE SYSTEMS
# ---------------------------------------------------------------------------

def reduced_residue_system(n: int) -> list[int]:
    """
    Return the integers 1 <= a <= n that are coprime to n.

    There are exactly φ(n) such integers.

    Some texts use 1 <= a < n for the reduced residue system when n > 1.
    The value n itself is not coprime to n unless n = 1, so the resulting
    list is identical for n > 1.
    """
    return coprime_numbers_up_to(n)


# ---------------------------------------------------------------------------
# EULER'S THEOREM
# ---------------------------------------------------------------------------

def modular_power(a: int, exponent: int, modulus: int) -> int:
    """
    Compute a^exponent mod modulus using binary exponentiation.

    Repeated multiplication would require O(exponent) multiplications.

    Binary exponentiation reduces this to O(log exponent).

    The implementation uses Python's built-in pow for the actual operation
    because pow(a, b, m) is an optimized modular exponentiation primitive.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    return pow(a, exponent, modulus)


def verify_euler_theorem(a: int, n: int) -> bool:
    """
    Euler's theorem states:

        a^φ(n) ≡ 1 (mod n)

    whenever gcd(a, n) = 1.

    The coprimality condition is essential.
    """
    if n <= 1:
        raise ValueError("n must be greater than 1")

    if not are_coprime(a, n):
        return False

    return pow(a, phi(n), n) == 1


def demonstrate_euler_theorem(a: int, n: int) -> dict[str, int | bool]:
    """
    Return the important quantities in an Euler-theorem example.
    """
    if not are_coprime(a, n):
        raise ValueError("Euler's theorem requires gcd(a, n) = 1")

    phi_n = phi(n)
    result = pow(a, phi_n, n)

    return {
        "a": a,
        "n": n,
        "phi(n)": phi_n,
        "a^phi(n) mod n": result,
        "theorem_holds": result == 1,
    }


# ---------------------------------------------------------------------------
# MODULAR INVERSES
# ---------------------------------------------------------------------------

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean algorithm.

    Returns (g, x, y) satisfying:

        ax + by = g

    where:

        g = gcd(a, b)

    If gcd(a, m) = 1, then x is a modular inverse of a modulo m.
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

    An inverse exists exactly when:

        gcd(a, modulus) = 1

    The result x satisfies:

        ax ≡ 1 (mod modulus)
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise ValueError("modular inverse does not exist")

    return x % modulus


def inverse_using_euler(a: int, n: int) -> int:
    """
    For gcd(a, n) = 1, Euler's theorem gives:

        a^φ(n) ≡ 1 mod n

    Multiplying by a^(-1):

        a^(φ(n)-1) ≡ a^(-1) mod n

    Therefore:

        a^(-1) ≡ a^(φ(n)-1) mod n

    This method is useful for illustrating the relationship between
    Euler's theorem and modular inverses.

    For arbitrary moduli, extended Euclid is generally preferable.
    """
    if not are_coprime(a, n):
        raise ValueError("a and n must be coprime")

    return pow(a, phi(n) - 1, n)


# ---------------------------------------------------------------------------
# TOTIENT SIEVE: COMPUTE MANY VALUES
# ---------------------------------------------------------------------------

def totient_sieve(n: int) -> list[int]:
    """
    Compute φ(1), φ(2), ..., φ(n) using the classical totient sieve.

    Start with:

        phi[i] = i

    For every prime p, update every multiple m of p:

        phi[m] -= phi[m] // p

    The result is the product formula applied simultaneously to every
    integer.

    Time complexity:
        O(n log log n) approximately.

    Space complexity:
        O(n).
    """
    if n < 1:
        raise ValueError("n must be at least 1")

    values = list(range(n + 1))
    values[1] = 1

    for p in range(2, n + 1):
        if values[p] == p:
            # p is prime because no earlier prime has modified values[p].
            for multiple in range(p, n + 1, p):
                values[multiple] -= values[multiple] // p

    return values


# ---------------------------------------------------------------------------
# LINEAR TOTIENT SIEVE
# ---------------------------------------------------------------------------

def linear_totient_sieve(n: int) -> list[int]:
    """
    Compute all totients from 1 through n using a linear sieve.

    Each integer is processed in a way that ensures its composite
    construction is controlled by a smallest-prime-factor relationship.

    Complexity:
        O(n) time
        O(n) space

    This is especially useful when φ(1), ..., φ(n) are all required.
    """
    if n < 1:
        raise ValueError("n must be at least 1")

    phi_values = [0] * (n + 1)
    phi_values[1] = 1

    primes: list[int] = []
    is_composite = [False] * (n + 1)

    for i in range(2, n + 1):
        if not is_composite[i]:
            primes.append(i)
            phi_values[i] = i - 1

        for p in primes:
            product = i * p

            if product > n:
                break

            is_composite[product] = True

            if i % p == 0:
                # p already divides i, so:
                # φ(i*p) = φ(i) * p
                phi_values[product] = phi_values[i] * p
                break

            # p does not divide i, so multiplicativity applies:
            # φ(i*p) = φ(i) * (p - 1)
            phi_values[product] = phi_values[i] * (p - 1)

    return phi_values


# ---------------------------------------------------------------------------
# SUMMATIONS AND ASYMPTOTIC BEHAVIOR
# ---------------------------------------------------------------------------

def summatory_totient(n: int, method: str = "sieve") -> int:
    """
    Compute:

        Φ(n) = φ(1) + φ(2) + ... + φ(n)

    This summatory function counts reduced fractions with bounded
    denominators in several classical number-theoretic interpretations.
    """
    if n < 1:
        raise ValueError("n must be positive")

    if method == "sieve":
        values = totient_sieve(n)
        return sum(values[1:])

    if method == "linear":
        values = linear_totient_sieve(n)
        return sum(values[1:])

    raise ValueError("method must be 'sieve' or 'linear'")


def estimate_totient_density(n: int) -> float:
    """
    Return φ(n)/n.

    From the product formula:

        φ(n)/n = ∏_{p|n}(1 - 1/p)

    The density depends on the distinct prime factors of n.
    """
    if n <= 0:
        raise ValueError("n must be positive")

    return phi(n) / n


# ---------------------------------------------------------------------------
# FAREY-SEQUENCE CONNECTION
# ---------------------------------------------------------------------------

def farey_reduced_fraction_count(max_denominator: int) -> int:
    """
    Count reduced positive fractions a/b satisfying:

        1 <= b <= N
        1 <= a < b
        gcd(a, b) = 1

    For a fixed denominator b, there are φ(b) such numerators.

    Therefore:

        count = φ(2) + φ(3) + ... + φ(N)

    This is one reason the summatory totient is important.
    """
    if max_denominator < 1:
        raise ValueError("max_denominator must be positive")

    return sum(phi(d) for d in range(1, max_denominator + 1))


# ---------------------------------------------------------------------------
# GENERALIZATION: JORDAN'S TOTIENT FUNCTION
# ---------------------------------------------------------------------------

def jordan_totient(k: int, n: int) -> int:
    """
    Compute Jordan's totient function J_k(n).

    Jordan's totient function generalizes Euler's totient:

        J_k(n) = n^k * ∏_{p|n}(1 - 1/p^k)

    Euler's totient is the special case:

        J_1(n) = φ(n)

    Interpretation:
    J_k(n) counts k-tuples of integers modulo n that are collectively
    coprime to n.
    """
    if k < 1:
        raise ValueError("k must be at least 1")

    if n <= 0:
        raise ValueError("n must be positive")

    result = n**k

    for prime in prime_factorization(n):
        result -= result // (prime**k)

    return result


# ---------------------------------------------------------------------------
# CARMICHAEL FUNCTION: RELATED BUT DIFFERENT
# ---------------------------------------------------------------------------

def lcm(a: int, b: int) -> int:
    """
    Least common multiple.
    """
    if a == 0 or b == 0:
        return 0

    return abs(a // gcd(a, b) * b)


def carmichael_prime_power(p: int, exponent: int) -> int:
    """
    Compute the Carmichael function λ(p^k).

    For odd primes:

        λ(p^k) = φ(p^k)

    For powers of 2:

        λ(2) = 1
        λ(4) = 2
        λ(2^k) = 2^(k-2), k >= 3
    """
    if not is_prime(p):
        raise ValueError("p must be prime")

    if exponent < 1:
        raise ValueError("exponent must be positive")

    if p != 2:
        return prime_power_totient(p, exponent)

    if exponent == 1:
        return 1

    if exponent == 2:
        return 2

    return 2 ** (exponent - 2)


def carmichael_lambda(n: int) -> int:
    """
    Compute Carmichael's function λ(n) from prime powers.

    λ(n) is the smallest positive integer m such that:

        a^m ≡ 1 mod n

    for every a coprime to n.

    This can be smaller than φ(n).

    For coprime prime-power factors, λ of their product is the LCM of
    the individual λ values.
    """
    if n <= 0:
        raise ValueError("n must be positive")

    if n == 1:
        return 1

    factors = prime_factorization(n)
    result = 1

    for prime, exponent in factors.items():
        component = carmichael_prime_power(prime, exponent)
        result = lcm(result, component)

    return result


# ---------------------------------------------------------------------------
# RSA MATHEMATICAL DEMONSTRATION
# ---------------------------------------------------------------------------

def rsa_toy_key_generation(p: int, q: int, e: int) -> dict[str, int]:
    """
    Construct a small educational RSA key pair.

    Requirements:
        p and q are distinct primes.
        n = pq
        φ(n) = (p-1)(q-1)
        gcd(e, φ(n)) = 1
        d = e^(-1) mod φ(n)

    Public key:
        (e, n)

    Private key:
        (d, n)

    This function is purely educational. Real RSA requires large carefully
    generated primes, secure random generation, padding, key management,
    side-channel protections, and standardized cryptographic libraries.
    """
    if p == q:
        raise ValueError("p and q must be distinct")

    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must both be prime")

    if e <= 1:
        raise ValueError("e must be greater than 1")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    if gcd(e, phi_n) != 1:
        raise ValueError("e must be coprime to φ(n)")

    d = modular_inverse(e, phi_n)

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi_n": phi_n,
        "e": e,
        "d": d,
    }


def rsa_encrypt(message: int, e: int, n: int) -> int:
    """
    Educational RSA encryption:

        c = m^e mod n
    """
    if not 0 <= message < n:
        raise ValueError("message must satisfy 0 <= message < n")

    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, d: int, n: int) -> int:
    """
    Educational RSA decryption:

        m = c^d mod n

    This demonstrates the mathematical role of φ(n), but does not implement
    secure production RSA padding or cryptographic key handling.
    """
    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < n")

    return pow(ciphertext, d, n)


# ---------------------------------------------------------------------------
# ADVANCED TOTIENT IDENTITIES
# ---------------------------------------------------------------------------

def verify_product_formula(n: int) -> bool:
    """
    Verify:

        φ(n) = n * ∏_{p|n}(1 - 1/p)

    using integer arithmetic.
    """
    return phi(n) == phi_from_factorization(n, prime_factorization(n))


def verify_divisor_sum_identity(n: int) -> bool:
    """
    Verify:

        ∑_{d|n} φ(d) = n
    """
    return divisor_sum_totient(n) == n


def verify_mobius_identity(n: int) -> bool:
    """
    Verify:

        φ(n) = ∑_{d|n} μ(d)(n/d)
    """
    return phi(n) == phi_by_mobius(n)


def verify_multiplicativity(a: int, b: int) -> bool:
    """
    Verify the multiplicative property when gcd(a, b) = 1.
    """
    if gcd(a, b) != 1:
        raise ValueError("a and b must be coprime")

    return phi(a * b) == phi(a) * phi(b)


# ---------------------------------------------------------------------------
# EDGE CASES AND IMPORTANT DISTINCTIONS
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> dict[str, object]:
    """
    Return representative edge-case behavior.
    """
    return {
        "phi(1)": phi(1),
        "phi(2)": phi(2),
        "phi(3)": phi(3),
        "phi(4)": phi(4),
        "phi(6)": phi(6),
        "phi(8)": phi(8),
        "phi(9)": phi(9),
        "phi(10)": phi(10),
        "phi(12)": phi(12),
        "phi(36)": phi(36),
        "phi(100)": phi(100),
        "phi(1)_coprimes": coprime_numbers_up_to(1),
        "phi(10)_coprimes": coprime_numbers_up_to(10),
    }


# ---------------------------------------------------------------------------
# TESTING
# ---------------------------------------------------------------------------

def run_assertion_tests() -> None:
    """
    Execute deterministic correctness tests.

    Assertions cover:
    - Definition
    - Special cases
    - Prime powers
    - Product formula
    - Inclusion-exclusion
    - Möbius identity
    - Divisor-sum identity
    - Multiplicativity
    - Euler's theorem
    - Modular inverses
    - Sieve implementations
    - Jordan's totient
    - Carmichael function
    """
    known_values = {
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
        15: 8,
        16: 8,
        18: 6,
        20: 8,
        24: 8,
        30: 8,
        36: 12,
        100: 40,
    }

    for n, expected in known_values.items():
        assert phi_bruteforce(n) == expected
        assert phi(n) == expected
        assert phi_by_inclusion_exclusion(n) == expected
        assert phi_by_mobius(n) == expected
        assert verify_product_formula(n)
        assert verify_divisor_sum_identity(n)
        assert verify_mobius_identity(n)

    for p, exponent in [(2, 1), (2, 5), (3, 4), (5, 3), (7, 2)]:
        assert phi(p**exponent) == prime_power_totient(p, exponent)

    coprime_pairs = [
        (2, 3),
        (4, 9),
        (5, 8),
        (7, 10),
        (9, 25),
    ]

    for a, b in coprime_pairs:
        assert verify_multiplicativity(a, b)

    for n in range(2, 100):
        for a in range(1, n + 1):
            if gcd(a, n) == 1:
                assert verify_euler_theorem(a, n)

    inverse_cases = [
        (3, 7),
        (5, 11),
        (7, 20),
        (17, 3120),
    ]

    for a, modulus in inverse_cases:
        inverse = modular_inverse(a, modulus)
        assert (a * inverse) % modulus == 1
        assert inverse == inverse_using_euler(a, modulus)

    sieve_values = totient_sieve(100)
    linear_values = linear_totient_sieve(100)

    for n in range(1, 101):
        assert sieve_values[n] == phi(n)
        assert linear_values[n] == phi(n)

    assert jordan_totient(1, 12) == phi(12)
    assert carmichael_lambda(8) == 2
    assert carmichael_lambda(15) == 4

    # φ is multiplicative, but not completely multiplicative.
    assert phi(2 * 3) == phi(2) * phi(3)
    assert phi(2 * 2) != phi(2) * phi(2)


# ---------------------------------------------------------------------------
# PERFORMANCE COMPARISON
# ---------------------------------------------------------------------------

def compare_methods(numbers: Iterable[int]) -> list[dict[str, object]]:
    """
    Compare several single-value totient implementations.

    The function avoids timing because timing depends strongly on the
    execution environment. Instead it reports whether all methods agree.

    For larger values, the brute-force method is intentionally omitted
    because its purpose is conceptual rather than performance-oriented.
    """
    results = []

    for n in numbers:
        efficient = phi(n)
        factorized = phi_from_factorization(n, prime_factorization(n))
        inclusion_exclusion = phi_by_inclusion_exclusion(n)
        mobius_result = phi_by_mobius(n)

        results.append(
            {
                "n": n,
                "phi(n)": efficient,
                "factorization_method": factorized,
                "inclusion_exclusion_method": inclusion_exclusion,
                "mobius_method": mobius_result,
                "all_agree": (
                    efficient
                    == factorized
                    == inclusion_exclusion
                    == mobius_result
                ),
            }
        )

    return results


# ---------------------------------------------------------------------------
# EDUCATIONAL TABLES
# ---------------------------------------------------------------------------

def print_totient_table(limit: int) -> None:
    """
    Print n, prime factorization, φ(n), and φ(n)/n for small values.
    """
    if limit < 1:
        raise ValueError("limit must be positive")

    print("\nTotient table")
    print("-" * 64)
    print(f"{'n':>4} {'factorization':>20} {'phi(n)':>10} {'phi(n)/n':>12}")
    print("-" * 64)

    for n in range(1, limit + 1):
        factors = format_factorization(prime_factorization(n))
        value = phi(n)
        density = value / n

        print(f"{n:>4} {factors:>20} {value:>10} {density:>12.6f}")


def print_reduced_residue_examples(numbers: Iterable[int]) -> None:
    """
    Display reduced residue systems and their sizes.
    """
    print("\nReduced residue systems")
    print("-" * 64)

    for n in numbers:
        residues = reduced_residue_system(n)

        print(
            f"n={n:>3} | residues={residues} | "
            f"count={len(residues)} | phi(n)={phi(n)}"
        )


# ---------------------------------------------------------------------------
# CONCEPTUAL DEMONSTRATIONS
# ---------------------------------------------------------------------------

def demonstrate_definition() -> None:
    """
    Show the definition of φ(12).
    """
    n = 12
    residues = coprime_numbers_up_to(n)

    print("\nDefinition of Euler's totient function")
    print("-" * 64)
    print(f"n = {n}")
    print(f"Positive integers from 1 through {n}: {list(range(1, n + 1))}")
    print(f"Integers coprime to {n}: {residues}")
    print(f"φ({n}) = {len(residues)}")


def demonstrate_prime_power() -> None:
    """
    Show the prime-power formula.
    """
    p = 3
    exponent = 4
    n = p**exponent

    print("\nPrime-power formula")
    print("-" * 64)
    print(f"n = {p}^{exponent} = {n}")
    print(f"φ({n}) = {p}^{exponent} - {p}^{exponent - 1}")
    print(f"φ({n}) = {prime_power_totient(p, exponent)}")


def demonstrate_product_formula() -> None:
    """
    Show the product formula on a composite integer.
    """
    n = 360
    factors = prime_factorization(n)
    distinct_primes = list(factors.keys())

    print("\nEuler product formula")
    print("-" * 64)
    print(f"{n} = {format_factorization(factors)}")
    print(f"Distinct prime divisors: {distinct_primes}")
    print(f"φ({n}) = {n} * " + " * ".join(
        f"(1 - 1/{p})" for p in distinct_primes
    ))
    print(f"φ({n}) = {phi(n)}")


def demonstrate_multiplicativity() -> None:
    """
    Show multiplicativity and its limitation.
    """
    a, b = 8, 9

    print("\nMultiplicativity")
    print("-" * 64)
    print(f"gcd({a}, {b}) = {gcd(a, b)}")
    print(f"φ({a}) = {phi(a)}")
    print(f"φ({b}) = {phi(b)}")
    print(f"φ({a}*{b}) = {phi(a * b)}")
    print(f"φ({a})φ({b}) = {phi(a) * phi(b)}")

    a, b = 2, 2

    print("\nNot completely multiplicative")
    print(f"φ({a}*{b}) = {phi(a * b)}")
    print(f"φ({a})φ({b}) = {phi(a) * phi(b)}")


def demonstrate_divisor_identity() -> None:
    """
    Show the divisor-sum identity.
    """
    n = 12
    values = [(d, phi(d)) for d in divisors(n)]

    print("\nDivisor-sum identity")
    print("-" * 64)
    print(f"Divisors of {n}: {[d for d, _ in values]}")
    print(f"Totient values: {[value for _, value in values]}")
    print(f"Sum = {sum(value for _, value in values)}")
    print(f"n = {n}")


def demonstrate_euler() -> None:
    """
    Show Euler's theorem.
    """
    a, n = 5, 12
    phi_n = phi(n)
    result = pow(a, phi_n, n)

    print("\nEuler's theorem")
    print("-" * 64)
    print(f"gcd({a}, {n}) = {gcd(a, n)}")
    print(f"φ({n}) = {phi_n}")
    print(f"{a}^{phi_n} mod {n} = {result}")


def demonstrate_modular_inverse() -> None:
    """
    Show two ways to obtain a modular inverse.
    """
    a, n = 7, 20

    inverse_euclid = modular_inverse(a, n)
    inverse_euler = inverse_using_euler(a, n)

    print("\nModular inverse")
    print("-" * 64)
    print(f"a = {a}, modulus = {n}")
    print(f"Inverse from extended Euclid = {inverse_euclid}")
    print(f"Inverse from Euler's theorem = {inverse_euler}")
    print(f"Verification: ({a} * {inverse_euclid}) mod {n} = {(a * inverse_euclid) % n}")


def demonstrate_rsa() -> None:
    """
    Demonstrate the arithmetic behind a small RSA example.
    """
    keys = rsa_toy_key_generation(61, 53, 17)

    message = 65
    ciphertext = rsa_encrypt(message, keys["e"], keys["n"])
    recovered = rsa_decrypt(ciphertext, keys["d"], keys["n"])

    print("\nToy RSA example")
    print("-" * 64)
    print(f"p = {keys['p']}")
    print(f"q = {keys['q']}")
    print(f"n = {keys['n']}")
    print(f"φ(n) = {keys['phi_n']}")
    print(f"public exponent e = {keys['e']}")
    print(f"private exponent d = {keys['d']}")
    print(f"message = {message}")
    print(f"ciphertext = {ciphertext}")
    print(f"decrypted message = {recovered}")


def demonstrate_carmichael_difference() -> None:
    """
    Show why φ(n) and λ(n) should not be confused.
    """
    numbers = [8, 15, 16, 20, 24]

    print("\nEuler's totient versus Carmichael's function")
    print("-" * 64)

    for n in numbers:
        print(
            f"n={n:>3} | φ(n)={phi(n):>3} | "
            f"λ(n)={carmichael_lambda(n):>3}"
        )


def demonstrate_jordan_totient() -> None:
    """
    Show J_k(n), including J_1(n) = φ(n).
    """
    n = 12

    print("\nJordan's totient function")
    print("-" * 64)

    for k in range(1, 4):
        print(f"J_{k}({n}) = {jordan_totient(k, n)}")

    print(f"φ({n}) = J_1({n}) = {jordan_totient(1, n)}")


# ---------------------------------------------------------------------------
# RANDOMIZED CROSS-CHECKING
# ---------------------------------------------------------------------------

def randomized_cross_check(seed_value: int = 2026, trials: int = 100) -> None:
    """
    Compare the efficient implementation against brute force on random
    small integers.

    Randomized cross-checking is useful because deterministic examples can
    accidentally miss classes of inputs.
    """
    seed(seed_value)

    for _ in range(trials):
        n = randint(1, 300)

        expected = phi_bruteforce(n)
        actual = phi(n)

        assert expected == actual, (
            f"Mismatch for n={n}: expected {expected}, got {actual}"
        )

    print(f"\nRandomized cross-check passed for {trials} cases.")


# ---------------------------------------------------------------------------
# MAIN EDUCATIONAL PROGRAM
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the complete educational demonstration.
    """
    print("=" * 72)
    print("EULER'S TOTIENT FUNCTION")
    print("=" * 72)

    print(
        """
Definition:
    φ(n) counts the positive integers k with 1 <= k <= n such that
    gcd(k, n) = 1.

Core formula:
    If the distinct prime divisors of n are p1, ..., pk,

        φ(n) = n * ∏(1 - 1/pi)

Important identities:
    ∑_{d|n} φ(d) = n
    φ(ab) = φ(a)φ(b) when gcd(a,b) = 1
    a^φ(n) ≡ 1 (mod n) when gcd(a,n) = 1
"""
    )

    demonstrate_definition()
    demonstrate_prime_power()
    demonstrate_product_formula()
    demonstrate_multiplicativity()
    demonstrate_divisor_identity()
    demonstrate_euler()
    demonstrate_modular_inverse()
    demonstrate_rsa()
    demonstrate_carmichael_difference()
    demonstrate_jordan_totient()

    print_totient_table(20)
    print_reduced_residue_examples([5, 8, 10, 12, 15])

    print("\nSieve comparison")
    print("-" * 64)

    classical = totient_sieve(20)
    linear = linear_totient_sieve(20)

    print(f"Classical sieve: {classical[1:]}")
    print(f"Linear sieve:    {linear[1:]}")
    print(f"Sieve results agree: {classical == linear}")

    print("\nSummatory totient")
    print("-" * 64)

    for n in [5, 10, 20]:
        print(
            f"sum(phi(1)..phi({n})) = "
            f"{summatory_totient(n)}"
        )

    print("\nFarey-related reduced-fraction count")
    print("-" * 64)

    for n in [5, 10, 20]:
        print(
            f"Number of fractions with denominator <= {n} "
            f"and 0 < numerator < denominator in lowest terms: "
            f"{farey_reduced_fraction_count(n)}"
        )

    print("\nTotient density")
    print("-" * 64)

    for n in [10, 30, 100, 210, 2310]:
        print(f"φ({n}) / {n} = {estimate_totient_density(n):.8f}")

    print("\nMethod agreement")
    print("-" * 64)

    for result in compare_methods([1, 12, 36, 100, 360, 1000]):
        print(result)

    randomized_cross_check()

    print("\nRunning assertion-based correctness tests...")
    run_assertion_tests()
    print("All correctness tests passed.")

    print("\nImportant edge cases")
    print("-" * 64)

    for name, value in demonstrate_edge_cases().items():
        print(f"{name}: {value}")

    print("\nStudy observations")
    print("-" * 64)
    print(
        "1. φ(1) = 1."
    )
    print(
        "2. If p is prime, φ(p) = p - 1."
    )
    print(
        "3. If n = p^k, φ(n) = p^k - p^(k-1)."
    )
    print(
        "4. The product formula depends only on distinct prime divisors."
    )
    print(
        "5. φ is multiplicative for coprime arguments, but not completely multiplicative."
    )
    print(
        "6. The classical sieve computes all totients in approximately O(n log log n)."
    )
    print(
        "7. The linear sieve computes all totients in O(n) time."
    )
    print(
        "8. Euler's theorem requires gcd(a, n) = 1."
    )
    print(
        "9. Euler's totient and Carmichael's function are related but different."
    )
    print(
        "10. Euler's totient is central to modular arithmetic and the mathematics of RSA."
    )


if __name__ == "__main__":
    main()
