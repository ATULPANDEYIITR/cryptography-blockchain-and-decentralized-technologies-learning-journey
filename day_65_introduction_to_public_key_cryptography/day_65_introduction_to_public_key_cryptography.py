"""
Introduction to Public-Key Cryptography
Educational RSA, Diffie-Hellman, digital signatures, and key management.

Uses Python standard-library arithmetic and hashing.
The small RSA implementation is educational and is NOT production-safe.
Production applications should use vetted cryptographic libraries and
standardized padding such as RSA-OAEP and RSA-PSS.
"""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import gcd
from secrets import randbelow, randbits
from typing import Optional


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class InvalidKeyError(CryptoError):
    pass


class VerificationError(CryptoError):
    pass


class KeyStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


def is_prime(number: int) -> bool:
    """Probabilistic Miller-Rabin primality test."""
    if number < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for prime in small_primes:
        if number == prime:
            return True
        if number % prime == 0:
            return False

    d = number - 1
    power = 0

    while d % 2 == 0:
        power += 1
        d //= 2

    for base in small_primes:
        if base >= number - 1:
            continue

        x = pow(base, d, number)

        if x in (1, number - 1):
            continue

        for _ in range(power - 1):
            x = pow(x, 2, number)

            if x == number - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int = 128) -> int:
    if bits < 32:
        raise ValueError("Prime size must be at least 32 bits.")

    while True:
        candidate = randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_prime(candidate):
            return candidate


def extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0

    divisor, x1, y1 = extended_gcd(b, a % b)
    return divisor, y1, x1 - (a // b) * y1


def modular_inverse(a: int, modulus: int) -> int:
    divisor, x, _ = extended_gcd(a, modulus)

    if divisor != 1:
        raise InvalidKeyError("Modular inverse does not exist.")

    return x % modulus


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int


@dataclass
class KeyPair:
    public: PublicKey
    private: PrivateKey


class RSA:
    """Educational textbook RSA implementation."""

    PUBLIC_EXPONENT = 65537

    @staticmethod
    def generate_keypair(bits: int = 256) -> KeyPair:
        if bits < 128:
            raise ValueError("Use at least 128 bits for this demonstration.")

        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)

        while q == p:
            q = generate_prime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = RSA.PUBLIC_EXPONENT

        if gcd(e, phi) != 1:
            return RSA.generate_keypair(bits)

        d = modular_inverse(e, phi)

        return KeyPair(
            PublicKey(n, e),
            PrivateKey(n, d)
        )

    @staticmethod
    def encrypt(message: bytes, public_key: PublicKey) -> list[int]:
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")

        if public_key.n <= 255:
            raise InvalidKeyError("RSA modulus is too small.")

        return [
            pow(byte, public_key.e, public_key.n)
            for byte in message
        ]

    @staticmethod
    def decrypt(ciphertext: list[int], private_key: PrivateKey) -> bytes:
        result = bytearray()

        for value in ciphertext:
            if not isinstance(value, int) or not 0 <= value < private_key.n:
                raise ValueError("Invalid ciphertext integer.")

            decoded = pow(value, private_key.d, private_key.n)

            if not 0 <= decoded <= 255:
                raise CryptoError("Invalid decrypted byte.")

            result.append(decoded)

        return bytes(result)

    @staticmethod
    def sign(message: bytes, private_key: PrivateKey) -> int:
        digest = int.from_bytes(sha256(message).digest(), "big")
        digest %= private_key.n
        return pow(digest, private_key.d, private_key.n)

    @staticmethod
    def verify(
        message: bytes,
        signature: int,
        public_key: PublicKey
    ) -> bool:
        if not 0 <= signature < public_key.n:
            return False

        digest = int.from_bytes(sha256(message).digest(), "big")
        expected = digest % public_key.n

        recovered = pow(
            signature,
            public_key.e,
            public_key.n
        )

        return recovered == expected


class DiffieHellman:
    """Educational finite-field Diffie-Hellman key agreement."""

    @staticmethod
    def generate_private_key(prime: int) -> int:
        if prime <= 5:
            raise ValueError("Prime modulus is too small.")

        return randbelow(prime - 3) + 2

    @staticmethod
    def generate_public_key(
        generator: int,
        private_key: int,
        prime: int
    ) -> int:
        if not 2 <= generator < prime:
            raise ValueError("Invalid generator.")

        if not 2 <= private_key < prime - 1:
            raise ValueError("Invalid private exponent.")

        return pow(generator, private_key, prime)

    @staticmethod
    def calculate_shared_secret(
        received_public_key: int,
        private_key: int,
        prime: int
    ) -> int:
        if not 2 <= received_public_key < prime - 1:
            raise ValueError("Invalid peer public key.")

        return pow(received_public_key, private_key, prime)


class KeyRegistry:
    """Simple in-memory public-key lifecycle manager."""

    def __init__(self):
        self._keys: dict[str, PublicKey] = {}
        self._statuses: dict[str, KeyStatus] = {}

    def register(self, identity: str, public_key: PublicKey):
        if not identity.strip():
            raise ValueError("Identity cannot be empty.")

        if identity in self._keys:
            raise ValueError("Identity already registered.")

        if public_key.n <= 255 or public_key.e <= 1:
            raise InvalidKeyError("Invalid public key.")

        self._keys[identity] = public_key
        self._statuses[identity] = KeyStatus.ACTIVE

    def revoke(self, identity: str):
        if identity not in self._keys:
            raise KeyError("Unknown identity.")

        self._statuses[identity] = KeyStatus.REVOKED

    def get_active_key(self, identity: str) -> PublicKey:
        if self._statuses.get(identity) != KeyStatus.ACTIVE:
            raise InvalidKeyError("Key is unavailable or revoked.")

        return self._keys[identity]


def demonstrate_rsa():
    print("\n--- RSA Encryption and Decryption ---")

    keypair = RSA.generate_keypair(256)
    message = b"Public key cryptography"

    ciphertext = RSA.encrypt(message, keypair.public)
    recovered = RSA.decrypt(ciphertext, keypair.private)

    print("Original:", message.decode())
    print("Encrypted integer count:", len(ciphertext))
    print("Decrypted:", recovered.decode())

    assert recovered == message

    print("\n--- RSA Digital Signature ---")

    signature = RSA.sign(message, keypair.private)

    print("Valid signature:", RSA.verify(
        message, signature, keypair.public
    ))

    modified = b"Modified message"

    print("Modified message accepted:", RSA.verify(
        modified, signature, keypair.public
    ))

    assert not RSA.verify(modified, signature, keypair.public)


def demonstrate_diffie_hellman():
    print("\n--- Diffie-Hellman Key Agreement ---")

    prime = 23
    generator = 5

    alice_private = DiffieHellman.generate_private_key(prime)
    bob_private = DiffieHellman.generate_private_key(prime)

    alice_public = DiffieHellman.generate_public_key(
        generator, alice_private, prime
    )

    bob_public = DiffieHellman.generate_public_key(
        generator, bob_private, prime
    )

    alice_secret = DiffieHellman.calculate_shared_secret(
        bob_public, alice_private, prime
    )

    bob_secret = DiffieHellman.calculate_shared_secret(
        alice_public, bob_private, prime
    )

    print("Alice public key:", alice_public)
    print("Bob public key:", bob_public)
    print("Shared secrets match:", alice_secret == bob_secret)

    assert alice_secret == bob_secret


def demonstrate_registry():
    print("\n--- Public-Key Registry ---")

    keypair = RSA.generate_keypair(256)
    registry = KeyRegistry()

    registry.register("alice@example.com", keypair.public)

    print(
        "Registered key:",
        registry.get_active_key("alice@example.com")
    )

    registry.revoke("alice@example.com")

    try:
        registry.get_active_key("alice@example.com")
    except InvalidKeyError as error:
        print("Registry rejected revoked key:", error)


def run_tests():
    assert is_prime(101)
    assert not is_prime(100)
    assert modular_inverse(3, 11) == 4

    keypair = RSA.generate_keypair(256)

    message = b"Test message"
    ciphertext = RSA.encrypt(message, keypair.public)

    assert RSA.decrypt(ciphertext, keypair.private) == message

    signature = RSA.sign(message, keypair.private)

    assert RSA.verify(message, signature, keypair.public)
    assert not RSA.verify(b"Different", signature, keypair.public)

    print("\nAll educational assertions passed.")


def main():
    print("INTRODUCTION TO PUBLIC-KEY CRYPTOGRAPHY")

    run_tests()
    demonstrate_rsa()
    demonstrate_diffie_hellman()
    demonstrate_registry()

    print("\nSecurity note:")
    print("This script demonstrates RSA mathematics, not production RSA.")
    print("Raw RSA encryption and signatures are deterministic and insecure.")
    print("Use RSA-OAEP, RSA-PSS, authenticated key exchange, and vetted libraries.")


if __name__ == "__main__":
    main()
