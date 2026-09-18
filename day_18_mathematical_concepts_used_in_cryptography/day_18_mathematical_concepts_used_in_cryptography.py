"""
Mathematical Concepts Used in Cryptography
==========================================

A self-contained study and demonstration program covering mathematical ideas
that form the foundation of classical and modern cryptography.

Topics demonstrated:
- Integers, divisibility, primes, factorization, gcd, Euclid's algorithm
- Extended Euclidean algorithm and modular inverses
- Modular arithmetic and modular exponentiation
- Congruences and residue classes
- Fermat's little theorem and Euler's totient function
- Euler's theorem
- Chinese Remainder Theorem
- Multiplicative groups modulo n
- Finite fields GF(p) and GF(2^8)
- Polynomial arithmetic over finite fields
- Quadratic residues and Legendre symbols
- Discrete logarithms
- Diffie-Hellman key exchange
- RSA key generation, encryption, and signatures
- Elliptic-curve arithmetic over finite fields
- Elliptic-curve Diffie-Hellman concepts
- Hash-oriented mathematical ideas
- Entropy and probability
- Hamming distance and error-detecting intuition
- Complexity considerations
- Cryptographic implementation pitfalls

The examples are educational. They deliberately use small parameters so that
the mathematics can be inspected directly. Such parameters are NOT secure
for real cryptographic use.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd, isqrt, log2
from collections import Counter
from typing import Iterable, Optional
import hashlib
import secrets
import random


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def subsection(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78)


def normalize_mod(value: int, modulus: int) -> int:
    """Return the canonical representative in {0, ..., modulus - 1}."""
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")
    return value % modulus


# ---------------------------------------------------------------------------
# 1. Integers, divisibility, primes, and factorization
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Simple trial-division primality test for educational-sized integers."""
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


def prime_factors(n: int) -> list[int]:
    """Return the prime factors of n with multiplicity."""
    if n < 2:
        return []

    factors = []
    divisor = 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor
        divisor += 1

    if n > 1:
        factors.append(n)
    return factors


def demonstrate_integers() -> None:
    subsection("Integers, divisibility, primes, and factorization")

    examples = [1, 2, 17, 25, 97, 100]
    for number in examples:
        print(f"{number:3d} prime={is_prime(number):5} factors={prime_factors(number)}")

    print("\nWhy primes matter:")
    print("A prime has exactly two positive divisors: 1 and itself.")
    print("Integer factorization is easy for small values but can be computationally")
    print("difficult for sufficiently large carefully chosen integers.")


# ---------------------------------------------------------------------------
# 2. Euclidean algorithm
# ---------------------------------------------------------------------------

def euclidean_gcd(a: int, b: int) -> int:
    """Compute gcd(a, b) using repeated remainders."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return (g, x, y) satisfying:

        ax + by = g

    where g = gcd(a, b).
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    if old_r < 0:
        return -old_r, -old_x, -old_y
    return old_r, old_x, old_y


def modular_inverse(a: int, modulus: int) -> int:
    """
    Find a^{-1} modulo modulus.

    An inverse exists exactly when gcd(a, modulus) = 1.
    """
    if modulus <= 1:
        raise ValueError("The modulus must be greater than 1.")

    gcd_value, coefficient, _ = extended_gcd(a, modulus)
    if gcd_value != 1:
        raise ValueError(
            f"{a} has no multiplicative inverse modulo {modulus}; "
            f"gcd={gcd_value}."
        )
    return coefficient % modulus


def demonstrate_gcd_and_inverse() -> None:
    subsection("Euclid's algorithm, Bézout coefficients, and modular inverses")

    a, b = 240, 46
    gcd_value = euclidean_gcd(a, b)
    print(f"gcd({a}, {b}) = {gcd_value}")

    gcd_value, x, y = extended_gcd(a, b)
    print(f"Extended GCD: {a}({x}) + {b}({y}) = {gcd_value}")

    value, modulus = 17, 3120
    inverse = modular_inverse(value, modulus)
    print(f"{value}^(-1) mod {modulus} = {inverse}")
    print(f"Verification: ({value} * {inverse}) mod {modulus} = "
          f"{value * inverse % modulus}")

    try:
        modular_inverse(12, 18)
    except ValueError as error:
        print(f"Expected failure: {error}")


# ---------------------------------------------------------------------------
# 3. Modular arithmetic
# ---------------------------------------------------------------------------

def modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Fast modular exponentiation by repeated squaring.

    Runtime is O(log exponent) multiplications instead of O(exponent).
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")
    if exponent < 0:
        base = modular_inverse(base, modulus)
        exponent = -exponent

    result = 1 % modulus
    base %= modulus

    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1

    return result


def demonstrate_modular_arithmetic() -> None:
    subsection("Modular arithmetic and congruences")

    print("17 mod 5 =", 17 % 5)
    print("-17 mod 5 =", -17 % 5)

    a, b, modulus = 29, 41, 7
    print(f"{a} ≡ {b} (mod {modulus}) because both have remainder "
          f"{a % modulus}.")

    left = (a + b) % modulus
    right = ((a % modulus) + (b % modulus)) % modulus
    print("Addition preserves congruence:", left == right)

    left = (a * b) % modulus
    right = ((a % modulus) * (b % modulus)) % modulus
    print("Multiplication preserves congruence:", left == right)

    print("3^100 mod 13 =", modular_power(3, 100, 13))


# ---------------------------------------------------------------------------
# 4. Euler's totient and related theorems
# ---------------------------------------------------------------------------

def euler_totient(n: int) -> int:
    """
    Compute Euler's phi(n): the number of integers from 1 through n
    that are relatively prime to n.
    """
    if n <= 0:
        raise ValueError("n must be positive.")

    result = n
    for prime in set(prime_factors(n)):
        result -= result // prime
    return result


def demonstrate_totient_and_theorems() -> None:
    subsection("Euler's totient, Fermat's little theorem, and Euler's theorem")

    for n in range(1, 16):
        print(f"phi({n:2d}) = {euler_totient(n)}")

    prime = 13
    base = 5
    print(
        f"\nFermat: {base}^({prime}-1) mod {prime} =",
        modular_power(base, prime - 1, prime),
    )

    modulus = 35
    base = 2
    phi = euler_totient(modulus)
    print(
        f"Euler: {base}^{phi} mod {modulus} =",
        modular_power(base, phi, modulus),
    )


# ---------------------------------------------------------------------------
# 5. Chinese Remainder Theorem
# ---------------------------------------------------------------------------

def chinese_remainder_theorem(residues: list[int], moduli: list[int]) -> int:
    """
    Solve x = residues[i] (mod moduli[i]) for pairwise-coprime moduli.

    Returns the unique solution modulo the product of all moduli.
    """
    if len(residues) != len(moduli) or not residues:
        raise ValueError("Residues and moduli must have the same nonzero length.")

    for i in range(len(moduli)):
        if moduli[i] <= 1:
            raise ValueError("Each modulus must be greater than 1.")
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError("Moduli must be pairwise coprime.")

    product = 1
    for modulus in moduli:
        product *= modulus

    solution = 0
    for residue, modulus in zip(residues, moduli):
        partial = product // modulus
        inverse = modular_inverse(partial, modulus)
        solution += residue * partial * inverse

    return solution % product


def demonstrate_crt() -> None:
    subsection("Chinese Remainder Theorem")

    residues = [2, 3, 2]
    moduli = [3, 5, 7]
    solution = chinese_remainder_theorem(residues, moduli)

    print("Solve:")
    for residue, modulus in zip(residues, moduli):
        print(f"  x ≡ {residue} (mod {modulus})")
    print("Solution =", solution)
    print("Check =", [solution % modulus for modulus in moduli])


# ---------------------------------------------------------------------------
# 6. Groups and finite fields
# ---------------------------------------------------------------------------

def units_modulo(n: int) -> list[int]:
    """Return the multiplicative units in Z/nZ."""
    return [x for x in range(1, n) if gcd(x, n) == 1]


def multiplicative_order(element: int, modulus: int) -> int:
    """Find the multiplicative order of an element in a finite unit group."""
    if gcd(element, modulus) != 1:
        raise ValueError("The element must be invertible modulo the modulus.")

    value = 1
    for order in range(1, euler_totient(modulus) + 1):
        value = (value * element) % modulus
        if value == 1:
            return order

    raise RuntimeError("Order was not found.")


def demonstrate_groups() -> None:
    subsection("Groups, cyclic groups, and finite fields")

    modulus = 11
    units = units_modulo(modulus)
    print(f"Units modulo {modulus}: {units}")

    for element in units:
        print(
            f"order({element}) = {multiplicative_order(element, modulus)}"
        )

    print(
        "\nFor prime p, the nonzero residues modulo p form a multiplicative "
        "group of size p-1."
    )
    print("A field additionally provides well-defined addition, multiplication,")
    print("and division by every nonzero element.")


# ---------------------------------------------------------------------------
# 7. Legendre symbols and quadratic residues
# ---------------------------------------------------------------------------

def legendre_symbol(a: int, prime: int) -> int:
    """
    Compute the Legendre symbol (a/p) for an odd prime p.

    Returns:
        0 if p divides a
        1 if a is a nonzero quadratic residue
        -1 if a is a quadratic non-residue
    """
    if not is_prime(prime) or prime == 2:
        raise ValueError("prime must be an odd prime.")

    value = a % prime
    if value == 0:
        return 0

    result = modular_power(value, (prime - 1) // 2, prime)
    return 1 if result == 1 else -1


def demonstrate_quadratic_residues() -> None:
    subsection("Quadratic residues and the Legendre symbol")

    prime = 11
    residues = sorted({(x * x) % prime for x in range(prime)})
    print(f"Quadratic residues modulo {prime}: {residues}")

    for value in range(1, prime):
        print(
            f"({value}/{prime}) = {legendre_symbol(value, prime)}"
        )


# ---------------------------------------------------------------------------
# 8. Discrete logarithm
# ---------------------------------------------------------------------------

def brute_force_discrete_log(base: int, target: int, modulus: int) -> Optional[int]:
    """
    Educational discrete-log search.

    Finds x such that base^x = target mod modulus.

    This intentionally demonstrates why naive discrete-log computation
    becomes infeasible when parameters become cryptographically large.
    """
    current = 1
    for exponent in range(modulus):
        if current == target % modulus:
            return exponent
        current = (current * base) % modulus
    return None


def demonstrate_discrete_log() -> None:
    subsection("Discrete logarithms")

    base = 5
    modulus = 23
    secret_exponent = 7
    target = modular_power(base, secret_exponent, modulus)

    recovered = brute_force_discrete_log(base, target, modulus)
    print(f"{base}^{secret_exponent} mod {modulus} = {target}")
    print(f"Brute-force discrete logarithm recovered exponent = {recovered}")

    print(
        "\nForward modular exponentiation is efficient with repeated squaring."
    )
    print(
        "The reverse problem, the discrete logarithm, is deliberately difficult "
        "for suitable cryptographic groups."
    )


# ---------------------------------------------------------------------------
# 9. Diffie-Hellman key exchange
# ---------------------------------------------------------------------------

@dataclass
class DiffieHellmanParticipant:
    name: str
    private_key: int
    public_key: int = 0


def diffie_hellman_demo() -> None:
    subsection("Diffie-Hellman key exchange")

    # Tiny educational parameters.
    # Real systems use standardized groups or elliptic-curve constructions.
    prime = 23
    generator = 5

    alice = DiffieHellmanParticipant("Alice", private_key=6)
    bob = DiffieHellmanParticipant("Bob", private_key=15)

    alice.public_key = modular_power(generator, alice.private_key, prime)
    bob.public_key = modular_power(generator, bob.private_key, prime)

    alice_shared = modular_power(bob.public_key, alice.private_key, prime)
    bob_shared = modular_power(alice.public_key, bob.private_key, prime)

    print(f"Public prime p = {prime}")
    print(f"Generator g = {generator}")
    print(f"Alice public value = {alice.public_key}")
    print(f"Bob public value   = {bob.public_key}")
    print(f"Alice shared value = {alice_shared}")
    print(f"Bob shared value   = {bob_shared}")
    print("Shared values equal:", alice_shared == bob_shared)

    print(
        "\nImportant limitation: unauthenticated Diffie-Hellman is vulnerable "
        "to a man-in-the-middle attack. Authentication must be added."
    )


# ---------------------------------------------------------------------------
# 10. RSA
# ---------------------------------------------------------------------------

def rsa_key_generation(p: int, q: int, e: int) -> tuple[int, int, int, int]:
    """Generate a small educational RSA key pair."""
    if not is_prime(p) or not is_prime(q) or p == q:
        raise ValueError("p and q must be distinct primes.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e must be relatively prime to phi(n).")

    d = modular_inverse(e, phi)
    return n, phi, e, d


def rsa_encrypt(message: int, e: int, n: int) -> int:
    if not 0 <= message < n:
        raise ValueError("Message must be in the interval [0, n).")
    return modular_power(message, e, n)


def rsa_decrypt(ciphertext: int, d: int, n: int) -> int:
    return modular_power(ciphertext, d, n)


def rsa_sign(message: int, d: int, n: int) -> int:
    return modular_power(message, d, n)


def rsa_verify(message: int, signature: int, e: int, n: int) -> bool:
    return modular_power(signature, e, n) == message


def demonstrate_rsa() -> None:
    subsection("RSA: factorization, Euler's totient, and modular inverses")

    p, q, e = 61, 53, 17
    n, phi, public_exponent, private_exponent = rsa_key_generation(p, q, e)

    print("p =", p)
    print("q =", q)
    print("n = p*q =", n)
    print("phi(n) =", phi)
    print("Public exponent e =", public_exponent)
    print("Private exponent d =", private_exponent)

    message = 65
    ciphertext = rsa_encrypt(message, public_exponent, n)
    recovered = rsa_decrypt(ciphertext, private_exponent, n)

    print("Message =", message)
    print("Ciphertext =", ciphertext)
    print("Decrypted =", recovered)

    signature = rsa_sign(message, private_exponent, n)
    print("Signature =", signature)
    print("Signature valid =", rsa_verify(
        message, signature, public_exponent, n
    ))

    print(
        "\nReal RSA uses very large keys and standardized padding schemes. "
        "Textbook RSA is not suitable for production encryption."
    )


# ---------------------------------------------------------------------------
# 11. GF(2^8) arithmetic
# ---------------------------------------------------------------------------

def gf256_multiply(a: int, b: int) -> int:
    """
    Multiply two elements of GF(2^8) using the AES irreducible polynomial.

    AES uses:
        x^8 + x^4 + x^3 + x + 1

    represented by 0x11B.
    """
    if not (0 <= a <= 0xFF and 0 <= b <= 0xFF):
        raise ValueError("GF(2^8) values must be bytes.")

    result = 0
    multiplicand = a
    multiplier = b

    for _ in range(8):
        if multiplier & 1:
            result ^= multiplicand

        high_bit = multiplicand & 0x80
        multiplicand = (multiplicand << 1) & 0xFF

        if high_bit:
            multiplicand ^= 0x1B

        multiplier >>= 1

    return result


def gf256_power(value: int, exponent: int) -> int:
    """Exponentiation in GF(2^8)."""
    result = 1
    while exponent:
        if exponent & 1:
            result = gf256_multiply(result, value)
        value = gf256_multiply(value, value)
        exponent >>= 1
    return result


def gf256_inverse(value: int) -> int:
    """Multiplicative inverse in GF(2^8), excluding zero."""
    if value == 0:
        raise ValueError("Zero has no multiplicative inverse.")
    return gf256_power(value, 254)


def demonstrate_gf256() -> None:
    subsection("Finite-field arithmetic in GF(2^8)")

    a, b = 0x57, 0x83
    product = gf256_multiply(a, b)
    inverse = gf256_inverse(a)

    print(f"0x{a:02X} * 0x{b:02X} in GF(2^8) = 0x{product:02X}")
    print(f"Inverse of 0x{a:02X} = 0x{inverse:02X}")
    print(
        "Verification:",
        f"0x{gf256_multiply(a, inverse):02X}",
        "(expected 0x01)",
    )

    print(
        "\nFinite fields are important in symmetric cryptography because "
        "operations can be defined algebraically over fixed-size symbols."
    )


# ---------------------------------------------------------------------------
# 12. Elliptic curves
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ECPoint:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


class EllipticCurve:
    """
    Short Weierstrass elliptic curve over a prime field:

        y^2 = x^3 + ax + b (mod p)

    This educational implementation assumes p is an odd prime and that
    4a^3 + 27b^2 is nonzero modulo p.
    """

    def __init__(self, a: int, b: int, prime: int):
        if not is_prime(prime) or prime == 2:
            raise ValueError("The field modulus must be an odd prime.")

        self.a = a % prime
        self.b = b % prime
        self.p = prime

        discriminant = (
            4 * self.a**3 + 27 * self.b**2
        ) % self.p

        if discriminant == 0:
            raise ValueError("Singular elliptic curve.")

        self.infinity = ECPoint(None, None)

    def contains(self, point: ECPoint) -> bool:
        if point.is_infinity:
            return True

        x, y = point.x, point.y
        return (
            y * y - (x * x * x + self.a * x + self.b)
        ) % self.p == 0

    def negate(self, point: ECPoint) -> ECPoint:
        if point.is_infinity:
            return point
        return ECPoint(point.x, (-point.y) % self.p)

    def add(self, first: ECPoint, second: ECPoint) -> ECPoint:
        if not self.contains(first) or not self.contains(second):
            raise ValueError("Both points must lie on the curve.")

        if first.is_infinity:
            return second
        if second.is_infinity:
            return first

        x1, y1 = first.x, first.y
        x2, y2 = second.x, second.y

        # P + (-P) = point at infinity.
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return self.infinity

        if first == second:
            if y1 % self.p == 0:
                return self.infinity

            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = modular_inverse(2 * y1, self.p)
            slope = numerator * denominator % self.p
        else:
            numerator = (y2 - y1) % self.p
            denominator = modular_inverse((x2 - x1) % self.p, self.p)
            slope = numerator * denominator % self.p

        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p

        return ECPoint(x3, y3)

    def multiply(self, scalar: int, point: ECPoint) -> ECPoint:
        """Double-and-add scalar multiplication."""
        if scalar < 0:
            return self.multiply(-scalar, self.negate(point))

        result = self.infinity
        addend = point

        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1

        return result


def demonstrate_elliptic_curves() -> None:
    subsection("Elliptic-curve arithmetic over a finite field")

    curve = EllipticCurve(a=2, b=2, prime=17)
    point = ECPoint(5, 1)

    print("Curve: y^2 = x^3 + 2x + 2 mod 17")
    print("Point =", point)
    print("Point is valid =", curve.contains(point))

    for scalar in range(1, 8):
        print(f"{scalar}P =", curve.multiply(scalar, point))

    print(
        "\nElliptic-curve cryptography uses scalar multiplication on a curve."
    )
    print(
        "The security assumption is related to the difficulty of recovering "
        "the scalar from a public point under suitable parameters."
    )


# ---------------------------------------------------------------------------
# 13. ECDH-style demonstration
# ---------------------------------------------------------------------------

def demonstrate_ecdh() -> None:
    subsection("Elliptic-curve Diffie-Hellman concept")

    curve = EllipticCurve(a=2, b=2, prime=17)
    generator = ECPoint(5, 1)

    alice_private = 5
    bob_private = 7

    alice_public = curve.multiply(alice_private, generator)
    bob_public = curve.multiply(bob_private, generator)

    alice_shared = curve.multiply(alice_private, bob_public)
    bob_shared = curve.multiply(bob_private, alice_public)

    print("Generator =", generator)
    print("Alice public =", alice_public)
    print("Bob public   =", bob_public)
    print("Alice shared =", alice_shared)
    print("Bob shared   =", bob_shared)
    print("Shared points equal =", alice_shared == bob_shared)

    print(
        "\nProduction elliptic-curve cryptography uses standardized curves, "
        "validated points, carefully implemented scalar multiplication, "
        "side-channel protections, and authenticated protocols."
    )


# ---------------------------------------------------------------------------
# 14. Cryptographic hashes
# ---------------------------------------------------------------------------

def demonstrate_hashes() -> None:
    subsection("Hash functions and avalanche behavior")

    messages = [
        b"cryptography",
        b"Cryptography",
        b"cryptography!",
    ]

    for message in messages:
        digest = hashlib.sha256(message).hexdigest()
        print(message, "->", digest)

    first = hashlib.sha256(b"cryptography").digest()
    second = hashlib.sha256(b"Cryptography").digest()

    differing_bits = sum(
        (left ^ right).bit_count()
        for left, right in zip(first, second)
    )

    print("SHA-256 digest size =", len(first) * 8, "bits")
    print("Changed digest bits in this pair =", differing_bits)

    print(
        "\nA cryptographic hash should make finding collisions computationally "
        "difficult and should exhibit strong diffusion."
    )


# ---------------------------------------------------------------------------
# 15. Entropy and probability
# ---------------------------------------------------------------------------

def shannon_entropy(symbols: Iterable[str]) -> float:
    """
    Estimate Shannon entropy in bits per symbol from an observed sequence.

    This measures uncertainty in the empirical distribution. It is not
    automatically the same thing as cryptographic key entropy.
    """
    sequence = list(symbols)
    if not sequence:
        return 0.0

    counts = Counter(sequence)
    total = len(sequence)

    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * log2(probability)

    return entropy


def demonstrate_entropy() -> None:
    subsection("Entropy and randomness")

    predictable = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    balanced = "ABABABABABABABABABABABABABABABAB"
    varied = "Q7m!2xL9#pR4$zT8@kN1%wC6"

    for sample in [predictable, balanced, varied]:
        print(
            f"{sample!r}: empirical entropy = "
            f"{shannon_entropy(sample):.4f} bits/symbol"
        )

    print(
        "\nCryptographic secrets should be generated with a cryptographically "
        "secure random source. General-purpose pseudo-random generators are "
        "not suitable for secret keys or nonces."
    )

    secure_token = secrets.token_hex(16)
    print("Example secure random token:", secure_token)


# ---------------------------------------------------------------------------
# 16. Hamming distance and coding intuition
# ---------------------------------------------------------------------------

def hamming_distance(first: bytes, second: bytes) -> int:
    """Count differing bits between two equal-length byte strings."""
    if len(first) != len(second):
        raise ValueError("Inputs must have equal length.")

    return sum(
        (left ^ right).bit_count()
        for left, right in zip(first, second)
    )


def demonstrate_hamming_distance() -> None:
    subsection("Hamming distance and bit-level comparison")

    first = bytes([0b10101010])
    second = bytes([0b11100010])

    print("First =", bin(first[0]))
    print("Second =", bin(second[0]))
    print("Hamming distance =", hamming_distance(first, second))

    print(
        "\nHamming distance is central to coding theory and is also useful "
        "when reasoning about bit-level diffusion and differences."
    )


# ---------------------------------------------------------------------------
# 17. Probability of guessing
# ---------------------------------------------------------------------------

def guessing_probability(entropy_bits: int) -> float:
    """Probability of guessing one uniformly random secret on one attempt."""
    if entropy_bits < 0:
        raise ValueError("Entropy cannot be negative.")
    return 2.0 ** (-entropy_bits)


def demonstrate_security_scale() -> None:
    subsection("Entropy, search spaces, and brute-force scaling")

    for bits in [8, 16, 32, 64, 128, 256]:
        probability = guessing_probability(bits)
        search_space = 2 ** bits
        print(
            f"{bits:3d} bits: search space = 2^{bits}, "
            f"single-guess probability ≈ {probability:.3e}"
        )

    print(
        "\nCryptographic strength depends on the complete construction, not "
        "only on the nominal key length."
    )


# ---------------------------------------------------------------------------
# 18. Timing and implementation considerations
# ---------------------------------------------------------------------------

def variable_time_power(base: int, exponent: int, modulus: int) -> int:
    """
    Educational example of ordinary square-and-multiply.

    The sequence of multiplications depends on exponent bits. In sensitive
    implementations, this can contribute to timing side channels.
    """
    result = 1
    while exponent:
        if exponent & 1:
            result = result * base % modulus
        base = base * base % modulus
        exponent >>= 1
    return result


def fixed_iteration_power(base: int, exponent: int, modulus: int) -> int:
    """
    A conceptual fixed-bit-length variant.

    Real constant-time cryptographic implementations require substantially
    more care than this educational example.
    """
    if exponent < 0:
        raise ValueError("This demonstration expects a nonnegative exponent.")

    bit_length = max(1, exponent.bit_length())
    result = 1
    base %= modulus

    for position in range(bit_length - 1, -1, -1):
        result = result * result % modulus

        bit = (exponent >> position) & 1
        multiplied = result * base % modulus

        # This Python conditional is NOT guaranteed constant-time.
        # It illustrates the algorithmic idea only.
        if bit:
            result = multiplied

    return result


def demonstrate_side_channel_concept() -> None:
    subsection("Side-channel awareness")

    base, exponent, modulus = 7, 123, 1009
    first = variable_time_power(base, exponent, modulus)
    second = fixed_iteration_power(base, exponent, modulus)

    print("Variable-time result =", first)
    print("Fixed-iteration result =", second)
    print("Results equal =", first == second)

    print(
        "\nIn real cryptographic software, constant-time behavior must be "
        "implemented and audited at the appropriate abstraction level."
    )


# ---------------------------------------------------------------------------
# 19. Comparison of major mathematical constructions
# ---------------------------------------------------------------------------

def demonstrate_concept_comparison() -> None:
    subsection("Conceptual comparison of major cryptographic constructions")

    comparison = [
        ("RSA", "integer arithmetic", "factoring-related hardness"),
        ("Diffie-Hellman", "finite-group arithmetic", "discrete logarithm"),
        ("ECC", "elliptic-curve groups", "elliptic-curve discrete logarithm"),
        ("AES", "finite-field and bitwise arithmetic", "keyed permutation security"),
        ("Hash functions", "bit operations and algebraic design", "preimage/collision resistance"),
    ]

    for construction, mathematics, security_basis in comparison:
        print(
            f"{construction:16} | mathematics: {mathematics:36} | "
            f"security concept: {security_basis}"
        )


# ---------------------------------------------------------------------------
# 20. Edge cases and mathematical failure conditions
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    subsection("Important mathematical edge cases")

    cases = [
        ("gcd(0, 15)", lambda: euclidean_gcd(0, 15)),
        ("gcd(0, 0)", lambda: euclidean_gcd(0, 0)),
        ("inverse(1, 17)", lambda: modular_inverse(1, 17)),
        ("inverse(0, 17)", lambda: modular_inverse(0, 17)),
        ("inverse(6, 15)", lambda: modular_inverse(6, 15)),
        ("phi(1)", lambda: euler_totient(1)),
    ]

    for description, operation in cases:
        try:
            print(f"{description} = {operation()}")
        except Exception as error:
            print(f"{description} -> {type(error).__name__}: {error}")

    print(
        "\nTypical implementation errors include assuming every number has "
        "an inverse, using a composite modulus where a field is required, "
        "using weak random values, accepting invalid public parameters, "
        "and confusing encryption with authentication."
    )


# ---------------------------------------------------------------------------
# 21. Mini end-to-end hybrid cryptography model
# ---------------------------------------------------------------------------

def toy_key_derivation(shared_secret: int) -> bytes:
    """
    Turn a toy shared integer into a deterministic byte string.

    This is only a conceptual bridge to key derivation. Real protocols use
    standardized KDF constructions such as HKDF rather than this function.
    """
    raw = shared_secret.to_bytes(32, "big")
    return hashlib.sha256(b"toy-kdf|" + raw).digest()


def toy_xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Educational XOR construction.

    This is NOT authenticated encryption and must not be used for real data.
    """
    return bytes(
        value ^ key[index % len(key)]
        for index, value in enumerate(data)
    )


def demonstrate_hybrid_concept() -> None:
    subsection("Toy hybrid cryptography pipeline")

    # DH derives a shared secret.
    p, g = 23, 5
    alice_private, bob_private = 6, 15

    alice_public = modular_power(g, alice_private, p)
    bob_public = modular_power(g, bob_private, p)

    shared = modular_power(bob_public, alice_private, p)
    assert shared == modular_power(alice_public, bob_private, p)

    key = toy_key_derivation(shared)
    plaintext = b"mathematics drives cryptographic design"
    ciphertext = toy_xor_encrypt(plaintext, key)
    recovered = toy_xor_encrypt(ciphertext, key)

    print("Shared secret =", shared)
    print("Derived key prefix =", key[:8].hex())
    print("Plaintext =", plaintext)
    print("Ciphertext =", ciphertext.hex())
    print("Recovered =", recovered)

    print(
        "\nReal hybrid protocols combine public-key mechanisms for key "
        "establishment with authenticated symmetric encryption for bulk data."
    )


# ---------------------------------------------------------------------------
# 22. Small mathematical test suite
# ---------------------------------------------------------------------------

def run_tests() -> None:
    subsection("Built-in correctness checks")

    assert euclidean_gcd(240, 46) == 2

    gcd_value, x, y = extended_gcd(240, 46)
    assert gcd_value == 2
    assert 240 * x + 46 * y == 2

    assert modular_inverse(3, 11) == 4
    assert 3 * modular_inverse(3, 11) % 11 == 1

    assert modular_power(2, 10, 1000) == 24

    assert euler_totient(1) == 1
    assert euler_totient(9) == 6
    assert euler_totient(35) == 24

    crt_solution = chinese_remainder_theorem([2, 3, 2], [3, 5, 7])
    assert crt_solution == 23

    curve = EllipticCurve(2, 2, 17)
    point = ECPoint(5, 1)
    assert curve.contains(point)
    assert curve.add(point, curve.negate(point)).is_infinity

    assert gf256_multiply(0x57, 0x83) == 0xC1

    print("All correctness checks passed.")


# ---------------------------------------------------------------------------
# Main educational sequence
# ---------------------------------------------------------------------------

def main() -> None:
    print("MATHEMATICAL CONCEPTS USED IN CRYPTOGRAPHY")
    print("Educational implementation laboratory")
    print("All cryptographic parameters used for demonstrations are intentionally small.")

    demonstrate_integers()
    demonstrate_gcd_and_inverse()
    demonstrate_modular_arithmetic()
    demonstrate_totient_and_theorems()
    demonstrate_crt()
    demonstrate_groups()
    demonstrate_quadratic_residues()
    demonstrate_discrete_log()
    diffie_hellman_demo()
    demonstrate_rsa()
    demonstrate_gf256()
    demonstrate_elliptic_curves()
    demonstrate_ecdh()
    demonstrate_hashes()
    demonstrate_entropy()
    demonstrate_hamming_distance()
    demonstrate_security_scale()
    demonstrate_side_channel_concept()
    demonstrate_concept_comparison()
    demonstrate_edge_cases()
    demonstrate_hybrid_concept()
    run_tests()

    section("Production cryptography principles")
    principles = [
        "Use established cryptographic libraries instead of implementing primitives yourself.",
        "Use cryptographically secure random number generation for secrets.",
        "Use standardized parameter sizes and protocol constructions.",
        "Authenticate public-key exchanges when active attackers are possible.",
        "Use authenticated encryption rather than unauthenticated encryption.",
        "Use standardized password hashing and key-derivation functions.",
        "Protect private keys and sensitive intermediate values.",
        "Validate public parameters and protocol inputs.",
        "Consider side channels, fault attacks, memory handling, and error behavior.",
        "Separate mathematical correctness from cryptographic security.",
        "Treat small classroom examples as demonstrations, never as secure deployments.",
    ]

    for principle in principles:
        print("*", principle)


if __name__ == "__main__":
    main()
