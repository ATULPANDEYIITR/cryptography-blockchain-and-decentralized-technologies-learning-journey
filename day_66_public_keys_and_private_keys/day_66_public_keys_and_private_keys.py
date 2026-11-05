#!/usr/bin/env python3
"""
Public Keys and Private Keys
Demonstrates RSA key generation, asymmetric encryption, digital signatures,
Diffie-Hellman key exchange, key validation, and key lifecycle management.

Educational implementation:
- RSA and Diffie-Hellman use small parameters for demonstration.
- Textbook RSA is not production-safe.
- Production applications should use vetted cryptographic libraries,
  RSA-OAEP, RSA-PSS, Ed25519, or X25519.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import unittest

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ============================================================
# Exceptions
# ============================================================

class CryptographicError(Exception):
    """Base exception for cryptographic operations."""


class InvalidKeyError(CryptographicError):
    pass


class EncryptionError(CryptographicError):
    pass


class SignatureError(CryptographicError):
    pass


class KeyLifecycleError(CryptographicError):
    pass


# ============================================================
# Key states
# ============================================================

class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KeyPurpose(Enum):
    ENCRYPTION = "encryption"
    SIGNING = "signing"
    KEY_EXCHANGE = "key_exchange"


# ============================================================
# RSA mathematical utilities
# ============================================================

def is_probable_prime(number: int, rounds: int = 32) -> bool:
    """Miller-Rabin probable-prime test."""

    if number < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for prime in small_primes:
        if number == prime:
            return True
        if number % prime == 0:
            return False

    d = number - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        value = pow(base, d, number)

        if value in (1, number - 1):
            continue

        for _ in range(s - 1):
            value = pow(value, 2, number)

            if value == number - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("Prime size must be at least 16 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


def modular_inverse(value: int, modulus: int) -> int:
    if math.gcd(value, modulus) != 1:
        raise InvalidKeyError("Modular inverse does not exist.")

    return pow(value, -1, modulus)


# ============================================================
# RSA key models
# ============================================================

@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    def validate(self) -> None:
        if self.n <= 0 or self.e <= 1:
            raise InvalidKeyError("Invalid RSA public key.")

        if self.e >= self.n:
            raise InvalidKeyError("Public exponent must be smaller than modulus.")


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int

    def validate(self) -> None:
        if self.n <= 0 or self.d <= 0:
            raise InvalidKeyError("Invalid RSA private key.")


@dataclass(frozen=True)
class RSAKeyPair:
    public_key: RSAPublicKey
    private_key: RSAPrivateKey


# ============================================================
# RSA implementation
# ============================================================

class EducationalRSA:

    PUBLIC_EXPONENT = 65537

    @classmethod
    def generate_key_pair(cls, bits: int = 512) -> RSAKeyPair:
        """
        Generate an educational RSA key pair.

        Small keys are intentionally used for demonstration.
        """

        if bits < 512:
            raise ValueError("Educational RSA requires at least 512 bits.")

        half = bits // 2

        while True:
            p = generate_prime(half)
            q = generate_prime(bits - half)

            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)
            e = cls.PUBLIC_EXPONENT

            if math.gcd(e, phi) != 1:
                continue

            d = modular_inverse(e, phi)

            return RSAKeyPair(
                public_key=RSAPublicKey(n, e),
                private_key=RSAPrivateKey(n, d)
            )

    @staticmethod
    def encrypt_integer(message: int, public_key: RSAPublicKey) -> int:
        public_key.validate()

        if not 0 <= message < public_key.n:
            raise EncryptionError("Message must be within the RSA modulus.")

        return pow(message, public_key.e, public_key.n)

    @staticmethod
    def decrypt_integer(ciphertext: int, private_key: RSAPrivateKey) -> int:
        private_key.validate()

        if not 0 <= ciphertext < private_key.n:
            raise EncryptionError("Invalid ciphertext.")

        return pow(ciphertext, private_key.d, private_key.n)

    @classmethod
    def encrypt_text(
        cls,
        message: str,
        public_key: RSAPublicKey
    ) -> list[int]:
        """
        Demonstrate character-by-character textbook RSA encryption.

        This is not secure encryption. It does not use OAEP padding.
        """

        if not isinstance(message, str):
            raise TypeError("Message must be a string.")

        encrypted = []

        for character in message:
            encrypted.append(
                cls.encrypt_integer(ord(character), public_key)
            )

        return encrypted

    @staticmethod
    def decrypt_text(
        ciphertext: list[int],
        private_key: RSAPrivateKey
    ) -> str:

        decrypted = []

        for value in ciphertext:
            codepoint = EducationalRSA.decrypt_integer(
                value,
                private_key
            )

            try:
                decrypted.append(chr(codepoint))
            except ValueError as exc:
                raise EncryptionError("Invalid decrypted character.") from exc

        return "".join(decrypted)


# ============================================================
# Digital signatures
# ============================================================

class EducationalSignature:

    @staticmethod
    def sign(message: bytes, private_key: RSAPrivateKey) -> int:
        """
        Educational raw RSA signature.

        Real systems must use RSA-PSS with a cryptographic library.
        """

        private_key.validate()

        digest = hashlib.sha256(message).digest()
        digest_number = int.from_bytes(digest, "big")

        encoded = digest_number % private_key.n

        return pow(encoded, private_key.d, private_key.n)

    @staticmethod
    def verify(
        message: bytes,
        signature: int,
        public_key: RSAPublicKey
    ) -> bool:

        public_key.validate()

        if not 0 <= signature < public_key.n:
            return False

        digest = hashlib.sha256(message).digest()
        expected = int.from_bytes(digest, "big") % public_key.n

        recovered = pow(
            signature,
            public_key.e,
            public_key.n
        )

        return recovered == expected


# ============================================================
# Diffie-Hellman key exchange
# ============================================================

@dataclass(frozen=True)
class DHParameters:
    prime: int
    generator: int


class DiffieHellman:

    @staticmethod
    def generate_private_value(prime: int) -> int:
        if prime <= 5:
            raise ValueError("Prime must be greater than five.")

        return secrets.randbelow(prime - 3) + 2

    @staticmethod
    def generate_public_value(
        private_value: int,
        parameters: DHParameters
    ) -> int:

        if not 2 <= private_value < parameters.prime - 1:
            raise InvalidKeyError("Invalid private DH value.")

        return pow(
            parameters.generator,
            private_value,
            parameters.prime
        )

    @staticmethod
    def derive_shared_secret(
        peer_public_value: int,
        private_value: int,
        parameters: DHParameters
    ) -> int:

        p = parameters.prime

        if not 2 <= peer_public_value <= p - 2:
            raise InvalidKeyError("Invalid peer public value.")

        if not 2 <= private_value < p - 1:
            raise InvalidKeyError("Invalid private value.")

        return pow(peer_public_value, private_value, p)


# ============================================================
# Key lifecycle management
# ============================================================

@dataclass
class ManagedKey:
    key_id: str
    owner: str
    purpose: KeyPurpose
    fingerprint: str
    created_at: datetime
    expires_at: Optional[datetime]
    status: KeyStatus = KeyStatus.ACTIVE


class KeyRegistry:

    def __init__(self):
        self._keys: dict[str, ManagedKey] = {}

    def register(
        self,
        owner: str,
        purpose: KeyPurpose,
        public_key: RSAPublicKey,
        validity_days: int = 365
    ) -> ManagedKey:

        if not owner.strip():
            raise ValueError("Owner cannot be empty.")

        if validity_days <= 0:
            raise ValueError("Validity must be positive.")

        public_key.validate()

        fingerprint_data = (
            f"{public_key.n}:{public_key.e}".encode()
        )

        fingerprint = hashlib.sha256(
            fingerprint_data
        ).hexdigest()

        if any(
            key.fingerprint == fingerprint
            and key.status != KeyStatus.REVOKED
            for key in self._keys.values()
        ):
            raise KeyLifecycleError("Public key already registered.")

        now = datetime.now(timezone.utc)

        record = ManagedKey(
            key_id=secrets.token_hex(12),
            owner=owner,
            purpose=purpose,
            fingerprint=fingerprint,
            created_at=now,
            expires_at=now.replace(
                year=now.year + 1
            ) if validity_days == 365 and now.month == 1
            and now.day == 1 else None
        )

        # Calculate expiry without assuming every year has 365 days.
        from datetime import timedelta
        record.expires_at = now + timedelta(days=validity_days)

        self._keys[record.key_id] = record

        return record

    def get(self, key_id: str) -> ManagedKey:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise KeyLifecycleError("Key does not exist.") from exc

    def revoke(self, key_id: str) -> None:
        record = self.get(key_id)

        if record.status == KeyStatus.REVOKED:
            raise KeyLifecycleError("Key is already revoked.")

        record.status = KeyStatus.REVOKED

    def rotate(self, old_key_id: str) -> None:
        record = self.get(old_key_id)

        if record.status != KeyStatus.ACTIVE:
            raise KeyLifecycleError("Only active keys can be rotated.")

        record.status = KeyStatus.ROTATED

    def is_usable(self, key_id: str) -> bool:
        record = self.get(key_id)

        if record.status != KeyStatus.ACTIVE:
            return False

        if record.expires_at and datetime.now(timezone.utc) >= record.expires_at:
            record.status = KeyStatus.EXPIRED
            return False

        return True

    def list_keys(self, owner: Optional[str] = None) -> list[ManagedKey]:
        records = list(self._keys.values())

        if owner is not None:
            records = [
                record for record in records
                if record.owner == owner
            ]

        return records


# ============================================================
# Fingerprints and public-key serialization
# ============================================================

def public_key_fingerprint(public_key: RSAPublicKey) -> str:
    public_key.validate()

    canonical = json.dumps(
        {"n": str(public_key.n), "e": public_key.e},
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hashlib.sha256(canonical).hexdigest()


def export_public_key(public_key: RSAPublicKey, filename: str) -> None:
    public_key.validate()

    document = {
        "algorithm": "educational-rsa",
        "n": str(public_key.n),
        "e": public_key.e,
        "fingerprint": public_key_fingerprint(public_key)
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(document, file, indent=2)


def import_public_key(filename: str) -> RSAPublicKey:
    with open(filename, "r", encoding="utf-8") as file:
        document = json.load(file)

    if document.get("algorithm") != "educational-rsa":
        raise InvalidKeyError("Unsupported key algorithm.")

    key = RSAPublicKey(
        n=int(document["n"]),
        e=int(document["e"])
    )

    key.validate()

    if document.get("fingerprint") != public_key_fingerprint(key):
        raise InvalidKeyError("Public key fingerprint mismatch.")

    return key


# ============================================================
# Demonstration
# ============================================================

def demonstrate_rsa() -> RSAKeyPair:
    print("\nRSA PUBLIC AND PRIVATE KEY DEMONSTRATION")

    key_pair = EducationalRSA.generate_key_pair(512)

    message = "Public key cryptography"

    ciphertext = EducationalRSA.encrypt_text(
        message,
        key_pair.public_key
    )

    plaintext = EducationalRSA.decrypt_text(
        ciphertext,
        key_pair.private_key
    )

    print("Original:", message)
    print("Ciphertext blocks:", len(ciphertext))
    print("Decrypted:", plaintext)

    assert plaintext == message

    return key_pair


def demonstrate_signatures(key_pair: RSAKeyPair) -> None:
    print("\nDIGITAL SIGNATURE DEMONSTRATION")

    message = b"Approve transaction TX-2026-1001"

    signature = EducationalSignature.sign(
        message,
        key_pair.private_key
    )

    valid = EducationalSignature.verify(
        message,
        signature,
        key_pair.public_key
    )

    tampered = EducationalSignature.verify(
        b"Approve transaction TX-2026-1002",
        signature,
        key_pair.public_key
    )

    print("Original message verification:", valid)
    print("Modified message verification:", tampered)

    assert valid
    assert not tampered


def demonstrate_diffie_hellman() -> None:
    print("\nDIFFIE-HELLMAN KEY EXCHANGE")

    # Small parameters are for demonstration only.
    parameters = DHParameters(prime=23, generator=5)

    alice_private = 6
    bob_private = 15

    alice_public = DiffieHellman.generate_public_value(
        alice_private,
        parameters
    )

    bob_public = DiffieHellman.generate_public_value(
        bob_private,
        parameters
    )

    alice_secret = DiffieHellman.derive_shared_secret(
        bob_public,
        alice_private,
        parameters
    )

    bob_secret = DiffieHellman.derive_shared_secret(
        alice_public,
        bob_private,
        parameters
    )

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_secret)
    print("Bob shared secret:", bob_secret)

    assert alice_secret == bob_secret


def demonstrate_registry(key_pair: RSAKeyPair) -> None:
    print("\nPUBLIC KEY REGISTRY")

    registry = KeyRegistry()

    record = registry.register(
        owner="finance-service",
        purpose=KeyPurpose.SIGNING,
        public_key=key_pair.public_key,
        validity_days=365
    )

    print("Key ID:", record.key_id)
    print("Fingerprint:", record.fingerprint)
    print("Usable:", registry.is_usable(record.key_id))

    registry.rotate(record.key_id)

    print("After rotation:", registry.get(record.key_id).status.value)


# ============================================================
# Automated tests
# ============================================================

class CryptographyTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keys = EducationalRSA.generate_key_pair(512)

    def test_rsa_round_trip(self):
        message = 123456

        encrypted = EducationalRSA.encrypt_integer(
            message,
            self.keys.public_key
        )

        decrypted = EducationalRSA.decrypt_integer(
            encrypted,
            self.keys.private_key
        )

        self.assertEqual(message, decrypted)

    def test_invalid_rsa_message(self):
        with self.assertRaises(EncryptionError):
            EducationalRSA.encrypt_integer(
                self.keys.public_key.n,
                self.keys.public_key
            )

    def test_signature(self):
        message = b"Verified document"

        signature = EducationalSignature.sign(
            message,
            self.keys.private_key
        )

        self.assertTrue(
            EducationalSignature.verify(
                message,
                signature,
                self.keys.public_key
            )
        )

    def test_modified_signature_message(self):
        signature = EducationalSignature.sign(
            b"Original",
            self.keys.private_key
        )

        self.assertFalse(
            EducationalSignature.verify(
                b"Modified",
                signature,
                self.keys.public_key
            )
        )

    def test_diffie_hellman(self):
        parameters = DHParameters(23, 5)

        a = 6
        b = 15

        A = DiffieHellman.generate_public_value(a, parameters)
        B = DiffieHellman.generate_public_value(b, parameters)

        self.assertEqual(
            DiffieHellman.derive_shared_secret(B, a, parameters),
            DiffieHellman.derive_shared_secret(A, b, parameters)
        )

    def test_key_registry(self):
        registry = KeyRegistry()

        record = registry.register(
            "application",
            KeyPurpose.ENCRYPTION,
            self.keys.public_key
        )

        self.assertTrue(registry.is_usable(record.key_id))

        registry.revoke(record.key_id)

        self.assertFalse(registry.is_usable(record.key_id))

    def test_invalid_private_key(self):
        with self.assertRaises(InvalidKeyError):
            EducationalRSA.decrypt_integer(
                10,
                RSAPrivateKey(0, 0)
            )


def main():
    print("=" * 65)
    print("PUBLIC KEYS AND PRIVATE KEYS")
    print("=" * 65)

    keys = demonstrate_rsa()
    demonstrate_signatures(keys)
    demonstrate_diffie_hellman()
    demonstrate_registry(keys)

    print("\nPUBLIC KEY FINGERPRINT")
    print(public_key_fingerprint(keys.public_key))

    print("\nRUNNING AUTOMATED TESTS")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        CryptographyTests
    )

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print("\nAll tests passed:", result.wasSuccessful())

    if not result.wasSuccessful():
        raise SystemExit(1)

    print("\nDemonstration completed.")


if __name__ == "__main__":
    main()
