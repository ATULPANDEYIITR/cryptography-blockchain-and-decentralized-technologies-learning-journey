#!/usr/bin/env python3
"""
Comparing RSA, Diffie-Hellman and Elliptic Curve Cryptography (ECC).

Educational implementation covering:
- RSA public-key encryption and digital signatures
- Diffie-Hellman key agreement
- Elliptic curve point arithmetic and ECDH
- Key sizes and security comparisons
- Hybrid encryption architecture
- Cryptographic policy evaluation
- Validation and failure handling

IMPORTANT:
The mathematical examples use deliberately small parameters and are NOT
suitable for protecting real information. Production cryptography should
use established cryptographic libraries and standardized parameters.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum
from math import gcd
from typing import Optional


# ============================================================
# 1. DOMAIN MODEL
# ============================================================

class Algorithm(Enum):
    RSA = "RSA"
    DIFFIE_HELLMAN = "Diffie-Hellman"
    ECC = "ECC"


class Purpose(Enum):
    ENCRYPTION = "Encryption"
    KEY_AGREEMENT = "Key Agreement"
    DIGITAL_SIGNATURE = "Digital Signature"


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    category: str
    primary_purpose: str
    security_strength: str
    typical_parameters: str
    quantum_resistance: str


PROFILES = [
    AlgorithmProfile(
        "RSA",
        "Integer factorization",
        "Encryption and digital signatures",
        "Approximately 128 bits with RSA-3072",
        "2048, 3072 or 4096-bit modulus",
        "Not resistant"
    ),
    AlgorithmProfile(
        "Diffie-Hellman",
        "Discrete logarithm",
        "Key agreement",
        "Approximately 128 bits with suitable 3072-bit finite-field parameters",
        "3072-bit or larger finite-field group",
        "Not resistant"
    ),
    AlgorithmProfile(
        "ECC",
        "Elliptic curve discrete logarithm",
        "Key agreement and digital signatures",
        "Approximately 128 bits with a 256-bit standardized curve",
        "P-256, P-384 or comparable standardized curves",
        "Not resistant"
    )
]


def display_profiles() -> None:
    print("\nCRYPTOGRAPHIC ALGORITHM COMPARISON")
    print("=" * 95)

    for profile in PROFILES:
        print(f"\nAlgorithm: {profile.name}")
        print(f"Mathematical foundation: {profile.category}")
        print(f"Purpose: {profile.primary_purpose}")
        print(f"Security strength: {profile.security_strength}")
        print(f"Parameters: {profile.typical_parameters}")
        print(f"Quantum resistance: {profile.quantum_resistance}")


# ============================================================
# 2. MATHEMATICAL UTILITIES
# ============================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return gcd(a, b) and Bezout coefficients."""

    if b == 0:
        return a, 1, 0

    divisor, x1, y1 = extended_gcd(b, a % b)
    return divisor, y1, x1 - (a // b) * y1


def modular_inverse(a: int, modulus: int) -> int:
    """Calculate the modular multiplicative inverse."""

    divisor, x, _ = extended_gcd(a, modulus)

    if divisor != 1:
        raise ValueError("Modular inverse does not exist.")

    return x % modulus


def is_prime(number: int) -> bool:
    """Deterministic trial-division primality check for small examples."""

    if number < 2:
        return False

    if number in (2, 3):
        return True

    if number % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2

    return True


# ============================================================
# 3. RSA IMPLEMENTATION
# ============================================================

@dataclass(frozen=True)
class RSAKeyPair:
    public_exponent: int
    private_exponent: int
    modulus: int

    @property
    def public_key(self) -> tuple[int, int]:
        return self.public_exponent, self.modulus

    @property
    def private_key(self) -> tuple[int, int]:
        return self.private_exponent, self.modulus


class EducationalRSA:
    """
    Educational RSA implementation.

    Raw RSA is intentionally used to expose the mathematics.
    Production RSA must use RSA-OAEP for encryption and RSA-PSS
    for signatures through a vetted cryptographic library.
    """

    @staticmethod
    def generate_keys(p: int, q: int, e: int = 17) -> RSAKeyPair:

        if not is_prime(p) or not is_prime(q):
            raise ValueError("RSA inputs must be prime.")

        if p == q:
            raise ValueError("RSA primes must be different.")

        modulus = p * q
        phi = (p - 1) * (q - 1)

        if not 1 < e < phi:
            raise ValueError("Invalid public exponent.")

        if gcd(e, phi) != 1:
            raise ValueError("Public exponent must be coprime to phi.")

        private_exponent = modular_inverse(e, phi)

        return RSAKeyPair(e, private_exponent, modulus)

    @staticmethod
    def encrypt(message: int, public_key: tuple[int, int]) -> int:

        e, n = public_key

        if not 0 <= message < n:
            raise ValueError("Message must be in the RSA numeric range.")

        return pow(message, e, n)

    @staticmethod
    def decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:

        d, n = private_key

        if not 0 <= ciphertext < n:
            raise ValueError("Ciphertext outside RSA numeric range.")

        return pow(ciphertext, d, n)

    @staticmethod
    def sign(message: str, private_key: tuple[int, int]) -> int:
        """Educational raw modular signing demonstration."""

        d, n = private_key
        digest = hashlib.sha256(message.encode()).digest()
        representative = int.from_bytes(digest, "big") % n

        return pow(representative, d, n)

    @staticmethod
    def verify(
        message: str,
        signature: int,
        public_key: tuple[int, int]
    ) -> bool:

        e, n = public_key

        if not 0 <= signature < n:
            return False

        digest = hashlib.sha256(message.encode()).digest()
        representative = int.from_bytes(digest, "big") % n

        return pow(signature, e, n) == representative


def demonstrate_rsa() -> None:

    print("\nRSA DEMONSTRATION")
    print("-" * 50)

    keys = EducationalRSA.generate_keys(61, 53, 17)

    message = 65

    encrypted = EducationalRSA.encrypt(message, keys.public_key)
    decrypted = EducationalRSA.decrypt(encrypted, keys.private_key)

    print("Public key:", keys.public_key)
    print("Encrypted integer:", encrypted)
    print("Decrypted integer:", decrypted)
    assert decrypted == message

    document = "Approve the repository release."

    signature = EducationalRSA.sign(document, keys.private_key)

    print("Signature valid:",
          EducationalRSA.verify(document, signature, keys.public_key))

    print("Modified document valid:",
          EducationalRSA.verify(
              document + " modified",
              signature,
              keys.public_key
          ))


# ============================================================
# 4. DIFFIE-HELLMAN KEY AGREEMENT
# ============================================================

@dataclass(frozen=True)
class DHParameters:
    prime: int
    generator: int


class EducationalDiffieHellman:

    @staticmethod
    def validate_parameters(parameters: DHParameters) -> None:

        p = parameters.prime
        g = parameters.generator

        if not is_prime(p):
            raise ValueError("DH modulus must be prime in this example.")

        if not 1 < g < p:
            raise ValueError("Invalid generator.")

    @staticmethod
    def generate_private_key(parameters: DHParameters) -> int:

        EducationalDiffieHellman.validate_parameters(parameters)

        return secrets.randbelow(parameters.prime - 3) + 2

    @staticmethod
    def generate_public_key(
        private_key: int,
        parameters: DHParameters
    ) -> int:

        EducationalDiffieHellman.validate_parameters(parameters)

        if not 2 <= private_key < parameters.prime - 1:
            raise ValueError("Invalid private key.")

        return pow(
            parameters.generator,
            private_key,
            parameters.prime
        )

    @staticmethod
    def derive_shared_secret(
        private_key: int,
        other_public_key: int,
        parameters: DHParameters
    ) -> int:

        p = parameters.prime

        if not 1 < other_public_key < p - 1:
            raise ValueError("Invalid public DH value.")

        return pow(other_public_key, private_key, p)


def demonstrate_diffie_hellman() -> None:

    print("\nDIFFIE-HELLMAN DEMONSTRATION")
    print("-" * 50)

    parameters = DHParameters(prime=23, generator=5)

    alice_private = EducationalDiffieHellman.generate_private_key(parameters)
    bob_private = EducationalDiffieHellman.generate_private_key(parameters)

    alice_public = EducationalDiffieHellman.generate_public_key(
        alice_private, parameters
    )

    bob_public = EducationalDiffieHellman.generate_public_key(
        bob_private, parameters
    )

    alice_secret = EducationalDiffieHellman.derive_shared_secret(
        alice_private, bob_public, parameters
    )

    bob_secret = EducationalDiffieHellman.derive_shared_secret(
        bob_private, alice_public, parameters
    )

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_secret)
    print("Bob shared secret:", bob_secret)

    assert alice_secret == bob_secret

    print("Key agreement successful.")

    # Basic invalid public-value test.
    try:
        EducationalDiffieHellman.derive_shared_secret(
            alice_private, 1, parameters
        )
    except ValueError as error:
        print("Rejected invalid public value:", error)


# ============================================================
# 5. ELLIPTIC CURVE CRYPTOGRAPHY
# ============================================================

@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


class EducationalECC:
    """
    Implements arithmetic over a small prime-field elliptic curve.

    Curve equation:
        y^2 = x^3 + ax + b (mod p)

    This implementation is for mathematical learning only.
    """

    def __init__(self, p: int, a: int, b: int, generator: Point):

        if not is_prime(p):
            raise ValueError("Field modulus must be prime.")

        self.p = p
        self.a = a % p
        self.b = b % p
        self.generator = generator

        discriminant = (
            4 * pow(self.a, 3, p) +
            27 * pow(self.b, 2, p)
        ) % p

        if discriminant == 0:
            raise ValueError("Singular elliptic curve.")

        if not self.is_on_curve(generator):
            raise ValueError("Generator is not on the curve.")

        self.infinity = Point(None, None)

    def is_on_curve(self, point: Point) -> bool:

        if point.is_infinity:
            return True

        if point.x is None or point.y is None:
            return False

        x = point.x % self.p
        y = point.y % self.p

        return (
            y * y -
            (x * x * x + self.a * x + self.b)
        ) % self.p == 0

    def add(self, first: Point, second: Point) -> Point:

        if not self.is_on_curve(first):
            raise ValueError("First point is not on the curve.")

        if not self.is_on_curve(second):
            raise ValueError("Second point is not on the curve.")

        if first.is_infinity:
            return second

        if second.is_infinity:
            return first

        x1, y1 = first.x, first.y
        x2, y2 = second.x, second.y

        if x1 == x2 and (y1 + y2) % self.p == 0:
            return self.infinity

        if first == second:

            if y1 == 0:
                return self.infinity

            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = (2 * y1) % self.p

        else:

            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p

        slope = (
            numerator *
            modular_inverse(denominator, self.p)
        ) % self.p

        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p

        result = Point(x3, y3)

        if not self.is_on_curve(result):
            raise ArithmeticError("Invalid elliptic curve result.")

        return result

    def multiply(self, scalar: int, point: Point) -> Point:
        """Double-and-add scalar multiplication."""

        if scalar < 0:
            raise ValueError("Negative scalar not supported.")

        if not self.is_on_curve(point):
            raise ValueError("Point is not on the curve.")

        result = self.infinity
        addend = point

        while scalar:

            if scalar & 1:
                result = self.add(result, addend)

            addend = self.add(addend, addend)
            scalar >>= 1

        return result

    def derive_public_key(self, private_key: int) -> Point:

        if private_key <= 0:
            raise ValueError("Private key must be positive.")

        return self.multiply(private_key, self.generator)


def demonstrate_ecc() -> None:

    print("\nELLIPTIC CURVE CRYPTOGRAPHY DEMONSTRATION")
    print("-" * 50)

    curve = EducationalECC(
        p=17,
        a=2,
        b=2,
        generator=Point(5, 1)
    )

    alice_private = 5
    bob_private = 7

    alice_public = curve.derive_public_key(alice_private)
    bob_public = curve.derive_public_key(bob_private)

    alice_secret = curve.multiply(alice_private, bob_public)
    bob_secret = curve.multiply(bob_private, alice_public)

    print("Alice public point:", alice_public)
    print("Bob public point:", bob_public)
    print("Alice shared point:", alice_secret)
    print("Bob shared point:", bob_secret)

    assert alice_secret == bob_secret

    print("Elliptic curve key agreement successful.")

    # Verify that scalar multiplication respects the identity.
    assert curve.multiply(0, curve.generator).is_infinity

    # Invalid-point rejection.
    try:
        curve.add(Point(1, 1), curve.generator)
    except ValueError as error:
        print("Invalid point rejected:", error)


# ============================================================
# 6. CRYPTOGRAPHIC SECURITY POLICY
# ============================================================

@dataclass(frozen=True)
class KeyConfiguration:
    algorithm: Algorithm
    purpose: Purpose
    parameter_size: int
    authenticated: bool
    approved_parameters: bool
    forward_secrecy: bool


@dataclass
class PolicyResult:
    approved: bool
    findings: list[str]


class CryptographicPolicy:

    MINIMUMS = {
        Algorithm.RSA: 3072,
        Algorithm.DIFFIE_HELLMAN: 3072,
        Algorithm.ECC: 256
    }

    @classmethod
    def evaluate(
        cls,
        configuration: KeyConfiguration
    ) -> PolicyResult:

        findings = []

        minimum = cls.MINIMUMS[configuration.algorithm]

        if configuration.parameter_size < minimum:
            findings.append(
                f"Parameter size below policy minimum of {minimum}."
            )

        if not configuration.approved_parameters:
            findings.append("Cryptographic parameters are not approved.")

        if configuration.algorithm == Algorithm.DIFFIE_HELLMAN:

            if configuration.purpose != Purpose.KEY_AGREEMENT:
                findings.append(
                    "Diffie-Hellman is a key-agreement mechanism, "
                    "not a standalone encryption or signature algorithm."
                )

            if not configuration.authenticated:
                findings.append(
                    "Unauthenticated DH permits man-in-the-middle attacks."
                )

        if configuration.algorithm == Algorithm.ECC:

            if configuration.purpose == Purpose.ENCRYPTION:
                findings.append(
                    "ECC requires an encryption construction such as "
                    "ECIES or an authenticated hybrid-encryption protocol."
                )

        if configuration.algorithm == Algorithm.RSA:

            if configuration.purpose == Purpose.KEY_AGREEMENT:
                findings.append(
                    "RSA is not a Diffie-Hellman-style key-agreement protocol."
                )

        if not configuration.authenticated:
            findings.append("Peer authentication is missing.")

        return PolicyResult(
            approved=len(findings) == 0,
            findings=findings
        )


def demonstrate_policy() -> None:

    print("\nCRYPTOGRAPHIC POLICY EVALUATION")
    print("-" * 50)

    configurations = [
        KeyConfiguration(
            Algorithm.RSA,
            Purpose.DIGITAL_SIGNATURE,
            3072,
            True,
            True,
            False
        ),
        KeyConfiguration(
            Algorithm.DIFFIE_HELLMAN,
            Purpose.KEY_AGREEMENT,
            2048,
            False,
            True,
            True
        ),
        KeyConfiguration(
            Algorithm.ECC,
            Purpose.KEY_AGREEMENT,
            256,
            True,
            True,
            True
        )
    ]

    for configuration in configurations:

        result = CryptographicPolicy.evaluate(configuration)

        print(f"\nAlgorithm: {configuration.algorithm.value}")
        print(f"Approved: {result.approved}")

        for finding in result.findings:
            print("Finding:", finding)


# ============================================================
# 7. HYBRID ENCRYPTION WORKFLOW
# ============================================================

def demonstrate_hybrid_encryption() -> None:
    """
    Demonstrate the architecture of hybrid encryption.

    The example derives a demonstration key from ECDH output.
    It does not implement authenticated encryption.

    Production implementations should use:
    - Authenticated ephemeral ECDH
    - HKDF with protocol-specific context
    - AES-256-GCM or ChaCha20-Poly1305
    - Certificate or public-key authentication
    """

    print("\nHYBRID ENCRYPTION ARCHITECTURE")
    print("-" * 50)

    curve = EducationalECC(17, 2, 2, Point(5, 1))

    alice_private = 3
    bob_private = 9

    alice_public = curve.derive_public_key(alice_private)
    bob_public = curve.derive_public_key(bob_private)

    shared_point = curve.multiply(alice_private, bob_public)

    if shared_point.is_infinity:
        raise ArithmeticError("Invalid shared point.")

    material = (
        f"{shared_point.x}:{shared_point.y}:"
        "educational-hybrid-example"
    ).encode()

    derived_key = hashlib.sha256(material).hexdigest()

    print("ECDH shared point:", shared_point)
    print("Demonstration derived key:", derived_key)
    print("Production design: ECDH + HKDF + AEAD.")


# ============================================================
# 8. SECURITY AND PERFORMANCE COMPARISON
# ============================================================

def comparison_report() -> None:

    rows = [
        ("RSA", "Factorization", "Encryption, signatures",
         "Larger keys", "RSA-OAEP / RSA-PSS"),
        ("DH", "Discrete logarithm", "Key agreement",
         "Public-value exchange", "Authenticated DH"),
        ("ECC", "Elliptic curve discrete logarithm",
         "ECDH / ECDSA", "Smaller keys",
         "ECDH / ECDSA")
    ]

    print("\nCOMPARATIVE ENGINEERING REPORT")
    print("-" * 95)

    print(
        f"{'Algorithm':<12}"
        f"{'Problem':<39}"
        f"{'Primary use':<24}"
        f"{'Implementation'}"
    )

    for algorithm, problem, purpose, characteristic, implementation in rows:

        print(
            f"{algorithm:<12}"
            f"{problem:<39}"
            f"{purpose:<24}"
            f"{implementation}"
        )
        print(" " * 12 + characteristic)


# ============================================================
# 9. EXECUTABLE VALIDATION TESTS
# ============================================================

def run_tests() -> None:

    assert modular_inverse(3, 11) == 4
    assert is_prime(97)
    assert not is_prime(100)

    rsa = EducationalRSA.generate_keys(61, 53, 17)

    message = 42
    ciphertext = EducationalRSA.encrypt(message, rsa.public_key)

    assert EducationalRSA.decrypt(
        ciphertext, rsa.private_key
    ) == message

    dh = DHParameters(23, 5)

    alice = 6
    bob = 15

    alice_public = EducationalDiffieHellman.generate_public_key(
        alice, dh
    )

    bob_public = EducationalDiffieHellman.generate_public_key(
        bob, dh
    )

    assert (
        EducationalDiffieHellman.derive_shared_secret(
            alice, bob_public, dh
        )
        ==
        EducationalDiffieHellman.derive_shared_secret(
            bob, alice_public, dh
        )
    )

    curve = EducationalECC(17, 2, 2, Point(5, 1))

    assert curve.multiply(19, curve.generator).is_infinity

    alice_public = curve.derive_public_key(5)
    bob_public = curve.derive_public_key(7)

    assert (
        curve.multiply(5, bob_public)
        ==
        curve.multiply(7, alice_public)
    )

    print("\nAll mathematical validation tests passed.")


# ============================================================
# 10. APPLICATION ENTRY POINT
# ============================================================

def main() -> None:

    print("=" * 95)
    print("RSA vs DIFFIE-HELLMAN vs ELLIPTIC CURVE CRYPTOGRAPHY")
    print("=" * 95)

    display_profiles()

    demonstrate_rsa()
    demonstrate_diffie_hellman()
    demonstrate_ecc()

    demonstrate_policy()
    demonstrate_hybrid_encryption()

    comparison_report()
    run_tests()

    print("\nSECURITY NOTICE")
    print(
        "Small mathematical parameters and custom arithmetic are "
        "for education only. Production cryptography requires "
        "standardized algorithms, vetted libraries, secure key "
        "storage, authenticated protocols and current security policies."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, ArithmeticError) as error:
        print(f"Execution failed: {error}")
        raise
