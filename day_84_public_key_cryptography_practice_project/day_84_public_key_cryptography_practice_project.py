#!/usr/bin/env python3
"""
Public-Key Cryptography Practice Project

Demonstrates:
- RSA key generation using small educational primes
- Modular arithmetic and Euler's totient
- Public-key encryption and private-key decryption
- Digital signatures and verification
- RSA mathematical validation
- Key lifecycle and revocation
- Input validation and failure handling

SECURITY:
The custom RSA implementation is educational only.
It uses textbook RSA without OAEP or PSS padding.
Never use it to protect real information.
"""

from dataclasses import dataclass
from enum import Enum
from math import gcd
import secrets
import hashlib
import json
from pathlib import Path


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class InvalidKeyError(CryptoError):
    pass


class InvalidMessageError(CryptoError):
    pass


class KeyStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int


@dataclass
class RSAKeyPair:
    public: PublicKey
    private: PrivateKey
    p: int
    q: int
    phi: int


@dataclass
class KeyRecord:
    key_id: str
    public_key: PublicKey
    status: KeyStatus
    created_at: str


def extended_gcd(a: int, b: int):
    """Return gcd and Bézout coefficients."""
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modular_inverse(a: int, modulus: int) -> int:
    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise InvalidKeyError("Modular inverse does not exist.")

    return x % modulus


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin primality test."""
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


def generate_prime(bits: int = 16) -> int:
    if bits < 8 or bits > 32:
        raise ValueError("Educational prime size must be 8-32 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 16) -> RSAKeyPair:
    """Generate a small educational RSA key pair."""
    if not 16 <= bits <= 32:
        raise ValueError("Key size must be between 16 and 32 bits.")

    p = generate_prime(bits)
    q = generate_prime(bits)

    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    if gcd(e, phi) != 1:
        e = 3

        while gcd(e, phi) != 1:
            e += 2

    d = modular_inverse(e, phi)

    return RSAKeyPair(
        public=PublicKey(n, e),
        private=PrivateKey(n, d),
        p=p,
        q=q,
        phi=phi
    )


def encrypt_integer(message: int, key: PublicKey) -> int:
    if message < 0 or message >= key.n:
        raise InvalidMessageError("Message must satisfy 0 <= m < n.")

    if key.n <= 1 or key.e <= 1:
        raise InvalidKeyError("Invalid public key.")

    return pow(message, key.e, key.n)


def decrypt_integer(ciphertext: int, key: PrivateKey) -> int:
    if not 0 <= ciphertext < key.n:
        raise InvalidMessageError("Ciphertext must satisfy 0 <= c < n.")

    if key.d <= 0 or key.n <= 1:
        raise InvalidKeyError("Invalid private key.")

    return pow(ciphertext, key.d, key.n)


def sign_integer(message: int, key: PrivateKey) -> int:
    if not 0 <= message < key.n:
        raise InvalidMessageError("Message must satisfy 0 <= m < n.")

    return pow(message, key.d, key.n)


def verify_signature(
    message: int,
    signature: int,
    key: PublicKey
) -> bool:
    if not 0 <= message < key.n:
        return False

    if not 0 <= signature < key.n:
        return False

    return pow(signature, key.e, key.n) == message


def sha256_integer(message: str) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


class KeyRegistry:
    """Maintain public-key records and revocation state."""

    def __init__(self):
        self.records = {}

    def register(self, key_id: str, public_key: PublicKey):
        if not key_id or key_id in self.records:
            raise ValueError("Invalid or duplicate key identifier.")

        if public_key.n <= 1 or public_key.e <= 1:
            raise InvalidKeyError("Invalid public key.")

        from datetime import datetime, timezone

        self.records[key_id] = KeyRecord(
            key_id=key_id,
            public_key=public_key,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc).isoformat()
        )

    def revoke(self, key_id: str):
        record = self.records.get(key_id)

        if record is None:
            raise KeyError("Key does not exist.")

        record.status = KeyStatus.REVOKED

    def get_active_key(self, key_id: str) -> PublicKey:
        record = self.records.get(key_id)

        if record is None:
            raise KeyError("Unknown key.")

        if record.status != KeyStatus.ACTIVE:
            raise InvalidKeyError("Key is not active.")

        return record.public_key

    def export_public_registry(self, filename: str):
        data = {
            key_id: {
                "n": str(record.public_key.n),
                "e": record.public_key.e,
                "status": record.status.value,
                "created_at": record.created_at
            }
            for key_id, record in self.records.items()
        }

        path = Path(filename)
        path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8"
        )


def demonstrate_rsa():
    print("PUBLIC-KEY CRYPTOGRAPHY PRACTICE")
    print("=" * 45)

    keypair = generate_rsa_keypair(16)

    print("\n1. RSA KEY GENERATION")
    print("Prime p:", keypair.p)
    print("Prime q:", keypair.q)
    print("Modulus n:", keypair.public.n)
    print("Euler totient:", keypair.phi)
    print("Public exponent:", keypair.public.e)
    print("Private exponent:", keypair.private.d)

    print("\n2. INTEGER ENCRYPTION")

    message = 12345
    ciphertext = encrypt_integer(message, keypair.public)
    decrypted = decrypt_integer(ciphertext, keypair.private)

    print("Original:", message)
    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypted)

    assert message == decrypted

    print("\n3. DIGITAL SIGNATURE")

    original_text = "Repository artifact version 1"
    digest = sha256_integer(original_text) % keypair.public.n

    signature = sign_integer(digest, keypair.private)

    valid = verify_signature(
        digest,
        signature,
        keypair.public
    )

    altered_digest = (digest + 1) % keypair.public.n

    altered_valid = verify_signature(
        altered_digest,
        signature,
        keypair.public
    )

    print("Signature:", signature)
    print("Original verification:", valid)
    print("Modified message verification:", altered_valid)

    assert valid
    assert not altered_valid

    print("\n4. KEY REGISTRY")

    registry = KeyRegistry()
    registry.register("rsa-practice-001", keypair.public)

    active = registry.get_active_key("rsa-practice-001")
    assert active == keypair.public

    registry.revoke("rsa-practice-001")

    try:
        registry.get_active_key("rsa-practice-001")
    except InvalidKeyError as error:
        print("Revocation enforced:", error)

    print("\n5. EDGE CASES")

    try:
        encrypt_integer(keypair.public.n, keypair.public)
    except InvalidMessageError as error:
        print("Invalid message rejected:", error)

    assert not is_probable_prime(1)
    assert is_probable_prime(101)
    assert not is_probable_prime(100)

    print("Primality checks passed.")

    print("\n6. MATHEMATICAL VALIDATION")

    assert gcd(keypair.public.e, keypair.phi) == 1
    assert (keypair.public.e * keypair.private.d) % keypair.phi == 1

    print("RSA inverse relationship verified.")
    print("All educational tests passed.")


if __name__ == "__main__":
    demonstrate_rsa()
