#!/usr/bin/env python3
"""
RSA Basics: Key Generation, Encryption, Decryption, and Digital Signatures.

Educational implementation using Python's arbitrary-precision integers.
Textbook RSA is demonstrated for learning purposes only.

Production systems must use a vetted cryptographic library, RSA-OAEP
for encryption, and RSA-PSS for signatures.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import secrets
import hashlib
import hmac


class RSAError(Exception):
    """Base exception for RSA operations."""


class InvalidKeyError(RSAError):
    """Raised when RSA key parameters are invalid."""


class InvalidMessageError(RSAError):
    """Raised when a message is outside the permitted RSA range."""


class Operation(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def validate(self) -> None:
        if self.n <= 1 or self.e <= 1 or self.e >= self.n:
            raise InvalidKeyError("Invalid RSA public key.")


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: int
    q: int

    def validate(self) -> None:
        if self.n != self.p * self.q:
            raise InvalidKeyError("Modulus does not match prime factors.")
        if self.p == self.q or min(self.p, self.q) <= 1:
            raise InvalidKeyError("Invalid prime factors.")
        if self.d <= 0:
            raise InvalidKeyError("Invalid private exponent.")


@dataclass(frozen=True)
class RSAKeyPair:
    public_key: PublicKey
    private_key: PrivateKey
    phi: int


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int):
    """Return gcd(a,b) and Bezout coefficients."""
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modular_inverse(e: int, phi: int) -> int:
    """Calculate d such that (e*d) mod phi = 1."""
    g, x, _ = extended_gcd(e, phi)

    if g != 1:
        raise InvalidKeyError("Public exponent has no modular inverse.")

    return x % phi


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin probabilistic primality test."""

    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime with the requested bit length."""

    if bits < 32:
        raise ValueError("Prime size must be at least 32 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


def generate_key_pair(bits: int = 512) -> RSAKeyPair:
    """
    Generate an educational RSA key pair.

    The default 512-bit modulus is intentionally insecure.
    It must not be used for real security.
    """

    if bits < 128:
        raise ValueError("Modulus size must be at least 128 bits.")

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits - bits // 2)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537

        if gcd(e, phi) != 1:
            continue

        d = modular_inverse(e, phi)

        public = PublicKey(n, e)
        private = PrivateKey(n, d, p, q)

        return RSAKeyPair(public, private, phi)


def rsa_encrypt(message: int, key: PublicKey) -> int:
    """Textbook RSA encryption of a single integer."""

    key.validate()

    if not 0 <= message < key.n:
        raise InvalidMessageError("Message must satisfy 0 <= m < n.")

    return pow(message, key.e, key.n)


def rsa_decrypt(ciphertext: int, key: PrivateKey) -> int:
    """RSA decryption using CRT optimization."""

    key.validate()

    if not 0 <= ciphertext < key.n:
        raise InvalidMessageError("Ciphertext must satisfy 0 <= c < n.")

    # Chinese Remainder Theorem reduces exponentiation sizes.
    dp = key.d % (key.p - 1)
    dq = key.d % (key.q - 1)
    q_inverse = modular_inverse(key.q, key.p)

    m1 = pow(ciphertext, dp, key.p)
    m2 = pow(ciphertext, dq, key.q)

    h = (q_inverse * (m1 - m2)) % key.p
    return m2 + h * key.q


def rsa_sign_digest(digest: int, key: PrivateKey) -> int:
    """
    Educational raw RSA signature operation.

    A real implementation must use RSA-PSS encoding.
    """

    key.validate()

    if not 0 <= digest < key.n:
        raise InvalidMessageError("Digest representative must be below n.")

    return pow(digest, key.d, key.n)


def rsa_verify_digest(
    digest: int,
    signature: int,
    key: PublicKey
) -> bool:
    """Verify an educational raw RSA signature."""

    key.validate()

    if not 0 <= signature < key.n:
        return False

    if not 0 <= digest < key.n:
        return False

    recovered = pow(signature, key.e, key.n)
    return recovered == digest


def sha256_integer(message: bytes) -> int:
    """Convert a SHA-256 digest into an integer."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def demonstrate_classic_example() -> None:
    """Classic RSA example using small educational primes."""

    p = 61
    q = 53
    e = 17

    n = p * q
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)

    public = PublicKey(n, e)
    private = PrivateKey(n, d, p, q)

    message = 65
    ciphertext = rsa_encrypt(message, public)
    recovered = rsa_decrypt(ciphertext, private)

    print("\nCLASSIC RSA EXAMPLE")
    print("-------------------")
    print("p:", p)
    print("q:", q)
    print("n:", n)
    print("phi(n):", phi)
    print("Public exponent:", e)
    print("Private exponent:", d)
    print("Original message:", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted message:", recovered)

    assert recovered == message


def demonstrate_key_generation() -> None:
    """Generate and exercise a randomly generated educational key."""

    print("\nGENERATED RSA KEY")
    print("-----------------")

    key_pair = generate_key_pair(512)

    message = 123456789

    encrypted = rsa_encrypt(message, key_pair.public_key)
    decrypted = rsa_decrypt(encrypted, key_pair.private_key)

    print("Modulus bits:", key_pair.public_key.n.bit_length())
    print("Public exponent:", key_pair.public_key.e)
    print("Message:", message)
    print("Ciphertext:", encrypted)
    print("Decrypted:", decrypted)

    assert message == decrypted

    sample = b"RSA digital signature demonstration"
    digest = sha256_integer(sample)

    signature = rsa_sign_digest(
        digest,
        key_pair.private_key
    )

    verified = rsa_verify_digest(
        digest,
        signature,
        key_pair.public_key
    )

    print("\nSIGNATURE DEMONSTRATION")
    print("Signature verified:", verified)

    assert verified

    changed_digest = sha256_integer(b"Modified message")

    print(
        "Modified message accepted:",
        rsa_verify_digest(
            changed_digest,
            signature,
            key_pair.public_key
        )
    )


def demonstrate_edge_cases() -> None:
    print("\nEDGE CASE TESTS")
    print("---------------")

    public = PublicKey(3233, 17)
    private = PrivateKey(3233, 2753, 61, 53)

    assert rsa_encrypt(0, public) == 0
    assert rsa_decrypt(0, private) == 0

    try:
        rsa_encrypt(3233, public)
    except InvalidMessageError as error:
        print("Invalid message rejected:", error)

    try:
        modular_inverse(12, 18)
    except InvalidKeyError as error:
        print("Invalid inverse rejected:", error)

    assert not is_probable_prime(1)
    assert not is_probable_prime(91)
    assert is_probable_prime(97)

    print("Primality and boundary tests passed.")


def main() -> None:
    print("=" * 55)
    print("RSA BASICS: EDUCATIONAL IMPLEMENTATION")
    print("=" * 55)

    demonstrate_classic_example()
    demonstrate_key_generation()
    demonstrate_edge_cases()

    print("\nSECURITY NOTES")
    print("--------------")
    print("1. Textbook RSA is deterministic and insecure.")
    print("2. Use RSA-OAEP for encryption.")
    print("3. Use RSA-PSS for digital signatures.")
    print("4. Use at least a 2048-bit modulus in appropriate")
    print("   production configurations.")
    print("5. Never expose private exponents.")
    print("6. Protect against timing and fault attacks.")
    print("7. Use vetted cryptographic libraries.")


if __name__ == "__main__":
    main()
