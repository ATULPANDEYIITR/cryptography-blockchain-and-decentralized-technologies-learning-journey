#!/usr/bin/env python3
"""
RSA Encryption and Decryption
Educational implementation of RSA key generation, OAEP padding,
encryption, decryption, digital signatures, and verification.

Uses Python standard-library components only.

Security note:
This implementation demonstrates RSA-OAEP and RSA-PSS-like
cryptographic concepts. It is not a replacement for a professionally
maintained cryptographic library in production systems.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unittest
from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ============================================================
# Configuration and domain types
# ============================================================

HASH_NAME = "sha256"
HASH_LENGTH = hashlib.sha256().digest_size
PUBLIC_EXPONENT = 65537


class RSAError(Exception):
    """Base exception for RSA operations."""


class InvalidKeyError(RSAError):
    pass


class EncryptionError(RSAError):
    pass


class DecryptionError(RSAError):
    pass


class SignatureError(RSAError):
    pass


class KeyState(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def validate(self) -> None:
        if self.n <= 0 or self.e <= 1:
            raise InvalidKeyError("Invalid public key parameters.")

        if self.e >= self.n:
            raise InvalidKeyError("Public exponent must be smaller than n.")


@dataclass(frozen=True)
class PrivateKey:
    public_key: PublicKey
    d: int
    p: int
    q: int

    def validate(self) -> None:
        self.public_key.validate()

        if self.d <= 0 or self.p <= 1 or self.q <= 1:
            raise InvalidKeyError("Invalid private key parameters.")

        if self.p * self.q != self.public_key.n:
            raise InvalidKeyError("Private key factors do not match modulus.")


@dataclass
class RSAKeyPair:
    public_key: PublicKey
    private_key: PrivateKey
    state: KeyState = KeyState.ACTIVE


# ============================================================
# Number theory
# ============================================================

def gcd(a: int, b: int) -> int:
    """Calculate the greatest common divisor."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return gcd(a, b) and Bezout coefficients."""
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modular_inverse(a: int, modulus: int) -> int:
    """Calculate the modular multiplicative inverse."""
    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise InvalidKeyError("Modular inverse does not exist.")

    return x % modulus


def is_probable_prime(n: int, rounds: int = 64) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False

    small_primes = (
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47
    )

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

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate an odd probable prime using a cryptographic RNG."""
    if bits < 512:
        raise ValueError("RSA prime size must be at least 512 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


# ============================================================
# RSA key generation
# ============================================================

def generate_key_pair(bits: int = 2048) -> RSAKeyPair:
    """
    Generate an RSA key pair.

    Production RSA deployments should use at least 2048-bit keys
    and a vetted cryptographic implementation.
    """
    if bits < 2048 or bits % 2 != 0:
        raise ValueError("RSA modulus size must be even and at least 2048.")

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)

        if p == q:
            continue

        n = p * q

        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)

        if gcd(PUBLIC_EXPONENT, phi) != 1:
            continue

        d = modular_inverse(PUBLIC_EXPONENT, phi)
        public = PublicKey(n=n, e=PUBLIC_EXPONENT)
        private = PrivateKey(public, d, p, q)

        private.validate()

        return RSAKeyPair(public, private)


# ============================================================
# Mask Generation Function
# ============================================================

def mgf1(seed: bytes, length: int) -> bytes:
    """Generate a mask using MGF1 with SHA-256."""
    if length < 0:
        raise ValueError("Mask length cannot be negative.")

    if length > HASH_LENGTH * (2**32):
        raise ValueError("Requested mask is too large.")

    output = bytearray()

    for counter in range((length + HASH_LENGTH - 1) // HASH_LENGTH):
        digest = hashlib.sha256(
            seed + counter.to_bytes(4, "big")
        ).digest()

        output.extend(digest)

    return bytes(output[:length])


# ============================================================
# RSA-OAEP encoding
# ============================================================

def oaep_encode(
    message: bytes,
    modulus_length: int,
    label: bytes = b""
) -> bytes:
    """
    Encode a message using RSA-OAEP with SHA-256.

    Maximum message length:
        modulus_length - 2 * HASH_LENGTH - 2
    """
    maximum = modulus_length - 2 * HASH_LENGTH - 2

    if len(message) > maximum:
        raise EncryptionError(
            f"Message exceeds OAEP limit of {maximum} bytes."
        )

    label_hash = hashlib.sha256(label).digest()

    padding_length = (
        modulus_length - len(message) - 2 * HASH_LENGTH - 2
    )

    data_block = (
        label_hash
        + b"\x00" * padding_length
        + b"\x01"
        + message
    )

    seed = secrets.token_bytes(HASH_LENGTH)

    db_mask = mgf1(seed, modulus_length - HASH_LENGTH - 1)

    masked_db = bytes(
        a ^ b for a, b in zip(data_block, db_mask)
    )

    seed_mask = mgf1(masked_db, HASH_LENGTH)

    masked_seed = bytes(
        a ^ b for a, b in zip(seed, seed_mask)
    )

    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    encoded: bytes,
    modulus_length: int,
    label: bytes = b""
) -> bytes:
    """Decode RSA-OAEP encoded data."""
    if len(encoded) != modulus_length:
        raise DecryptionError("Invalid encoded message length.")

    if modulus_length < 2 * HASH_LENGTH + 2:
        raise DecryptionError("RSA modulus is too small for OAEP.")

    if encoded[0] != 0:
        raise DecryptionError("OAEP decoding failed.")

    masked_seed = encoded[1:HASH_LENGTH + 1]
    masked_db = encoded[HASH_LENGTH + 1:]

    seed_mask = mgf1(masked_db, HASH_LENGTH)

    seed = bytes(
        a ^ b for a, b in zip(masked_seed, seed_mask)
    )

    db_mask = mgf1(seed, modulus_length - HASH_LENGTH - 1)

    data_block = bytes(
        a ^ b for a, b in zip(masked_db, db_mask)
    )

    expected_hash = hashlib.sha256(label).digest()
    actual_hash = data_block[:HASH_LENGTH]

    if not hmac.compare_digest(actual_hash, expected_hash):
        raise DecryptionError("OAEP decoding failed.")

    separator_position = HASH_LENGTH

    while (
        separator_position < len(data_block)
        and data_block[separator_position] == 0
    ):
        separator_position += 1

    if (
        separator_position >= len(data_block)
        or data_block[separator_position] != 1
    ):
        raise DecryptionError("OAEP decoding failed.")

    return data_block[separator_position + 1:]


# ============================================================
# Encryption and decryption
# ============================================================

def rsa_encrypt(
    message: bytes,
    public_key: PublicKey,
    label: bytes = b""
) -> bytes:
    """Encrypt data using RSA-OAEP."""
    public_key.validate()

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    encoded = oaep_encode(
        message,
        public_key.size_bytes,
        label
    )

    message_integer = int.from_bytes(encoded, "big")

    if message_integer >= public_key.n:
        raise EncryptionError("Encoded message exceeds RSA modulus.")

    ciphertext = pow(
        message_integer,
        public_key.e,
        public_key.n
    )

    return ciphertext.to_bytes(
        public_key.size_bytes,
        "big"
    )


def rsa_decrypt(
    ciphertext: bytes,
    private_key: PrivateKey,
    label: bytes = b""
) -> bytes:
    """Decrypt RSA-OAEP ciphertext."""
    private_key.validate()

    modulus_length = private_key.public_key.size_bytes

    if len(ciphertext) != modulus_length:
        raise DecryptionError("Invalid ciphertext length.")

    encrypted_integer = int.from_bytes(ciphertext, "big")

    if encrypted_integer >= private_key.public_key.n:
        raise DecryptionError("Ciphertext outside RSA modulus.")

    try:
        decrypted_integer = pow(
            encrypted_integer,
            private_key.d,
            private_key.public_key.n
        )

        encoded = decrypted_integer.to_bytes(
            modulus_length,
            "big"
        )

        return oaep_decode(encoded, modulus_length, label)

    except (ValueError, OverflowError) as exc:
        raise DecryptionError("Decryption failed.") from exc


# ============================================================
# RSA-PSS digital signatures
# ============================================================

def pss_encode(
    message_hash: bytes,
    modulus_bits: int,
    salt: bytes
) -> bytes:
    """Encode an RSA-PSS signature representative."""
    em_bits = modulus_bits - 1
    em_length = (em_bits + 7) // 8

    if len(message_hash) != HASH_LENGTH:
        raise SignatureError("Invalid message digest.")

    if em_length < HASH_LENGTH + len(salt) + 2:
        raise SignatureError("RSA modulus too small for PSS.")

    h = hashlib.sha256(
        b"\x00" * 8 + message_hash + salt
    ).digest()

    data_block = (
        b"\x00" * (
            em_length - HASH_LENGTH - len(salt) - 2
        )
        + b"\x01"
        + salt
    )

    db_mask = mgf1(h, em_length - HASH_LENGTH - 1)

    masked_db = bytearray(
        a ^ b for a, b in zip(data_block, db_mask)
    )

    unused_bits = 8 * em_length - em_bits
    masked_db[0] &= 0xFF >> unused_bits

    return bytes(masked_db) + h + b"\xbc"


def rsa_sign(
    message: bytes,
    private_key: PrivateKey
) -> bytes:
    """Create an RSA-PSS signature using SHA-256 and 32-byte salt."""
    private_key.validate()

    modulus_bits = private_key.public_key.n.bit_length()
    em_bits = modulus_bits - 1
    em_length = (em_bits + 7) // 8

    salt_length = 32

    if em_length < HASH_LENGTH + salt_length + 2:
        raise SignatureError("RSA key too small for PSS.")

    message_hash = hashlib.sha256(message).digest()
    salt = secrets.token_bytes(salt_length)

    encoded = pss_encode(message_hash, modulus_bits, salt)
    representative = int.from_bytes(encoded, "big")

    signature_integer = pow(
        representative,
        private_key.d,
        private_key.public_key.n
    )

    return signature_integer.to_bytes(
        private_key.public_key.size_bytes,
        "big"
    )


def rsa_verify(
    message: bytes,
    signature: bytes,
    public_key: PublicKey
) -> bool:
    """Verify an RSA-PSS signature."""
    try:
        public_key.validate()

        modulus_length = public_key.size_bytes

        if len(signature) != modulus_length:
            return False

        signature_integer = int.from_bytes(signature, "big")

        if signature_integer >= public_key.n:
            return False

        representative = pow(
            signature_integer,
            public_key.e,
            public_key.n
        )

        modulus_bits = public_key.n.bit_length()
        em_bits = modulus_bits - 1
        em_length = (em_bits + 7) // 8

        encoded = representative.to_bytes(em_length, "big")

        if encoded[-1] != 0xBC:
            return False

        masked_db = encoded[:em_length - HASH_LENGTH - 1]
        h = encoded[em_length - HASH_LENGTH - 1:-1]

        unused_bits = 8 * em_length - em_bits

        if masked_db[0] & (0xFF << (8 - unused_bits) & 0xFF):
            return False

        db_mask = mgf1(h, len(masked_db))

        data_block = bytearray(
            a ^ b for a, b in zip(masked_db, db_mask)
        )

        data_block[0] &= 0xFF >> unused_bits

        salt_length = 32
        separator = len(data_block) - salt_length - 1

        if separator < 0:
            return False

        if data_block[:separator] != b"\x00" * separator:
            return False

        if data_block[separator] != 1:
            return False

        salt = bytes(data_block[separator + 1:])

        expected_hash = hashlib.sha256(
            b"\x00" * 8
            + hashlib.sha256(message).digest()
            + salt
        ).digest()

        return hmac.compare_digest(h, expected_hash)

    except (RSAError, ValueError, OverflowError, IndexError):
        return False


# ============================================================
# Demonstration workflow
# ============================================================

def demonstrate() -> None:
    print("=" * 65)
    print("RSA ENCRYPTION AND DECRYPTION")
    print("=" * 65)

    print("\nGenerating a 2048-bit RSA key pair...")

    key_pair = generate_key_pair(2048)

    print("Public exponent:", key_pair.public_key.e)
    print("Modulus size:", key_pair.public_key.size_bytes * 8, "bits")

    original_message = (
        b"Confidential repository credentials and transaction data."
    )

    label = b"rsa-demo-v1"

    print("\nOriginal message:", original_message.decode())

    ciphertext = rsa_encrypt(
        original_message,
        key_pair.public_key,
        label
    )

    print("Ciphertext size:", len(ciphertext), "bytes")

    recovered = rsa_decrypt(
        ciphertext,
        key_pair.private_key,
        label
    )

    print("Decrypted message:", recovered.decode())

    assert recovered == original_message

    print("\nEncryption/decryption: PASSED")

    signature = rsa_sign(
        original_message,
        key_pair.private_key
    )

    valid = rsa_verify(
        original_message,
        signature,
        key_pair.public_key
    )

    print("Signature verification:", valid)

    assert valid

    tampered_message = original_message + b" modified"

    tampered_valid = rsa_verify(
        tampered_message,
        signature,
        key_pair.public_key
    )

    print("Tampered message verification:", tampered_valid)

    assert not tampered_valid

    # OAEP encryption uses randomness, so repeated encryptions differ.
    second_ciphertext = rsa_encrypt(
        original_message,
        key_pair.public_key,
        label
    )

    assert ciphertext != second_ciphertext

    print("Randomized encryption: PASSED")

    # A wrong label must not decrypt successfully.
    try:
        rsa_decrypt(
            ciphertext,
            key_pair.private_key,
            b"incorrect-label"
        )
    except DecryptionError:
        print("Wrong-label rejection: PASSED")


# ============================================================
# Automated tests
# ============================================================

class RSATests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key_pair = generate_key_pair(2048)

    def test_round_trip(self):
        message = b"Secure RSA message"

        encrypted = rsa_encrypt(
            message,
            self.key_pair.public_key
        )

        decrypted = rsa_decrypt(
            encrypted,
            self.key_pair.private_key
        )

        self.assertEqual(message, decrypted)

    def test_empty_message(self):
        encrypted = rsa_encrypt(
            b"",
            self.key_pair.public_key
        )

        self.assertEqual(
            rsa_decrypt(encrypted, self.key_pair.private_key),
            b""
        )

    def test_randomized_ciphertext(self):
        message = b"Repeated plaintext"

        first = rsa_encrypt(message, self.key_pair.public_key)
        second = rsa_encrypt(message, self.key_pair.public_key)

        self.assertNotEqual(first, second)

    def test_oversized_message(self):
        maximum = (
            self.key_pair.public_key.size_bytes
            - 2 * HASH_LENGTH
            - 2
        )

        with self.assertRaises(EncryptionError):
            rsa_encrypt(
                b"A" * (maximum + 1),
                self.key_pair.public_key
            )

    def test_wrong_label(self):
        ciphertext = rsa_encrypt(
            b"Protected data",
            self.key_pair.public_key,
            b"correct"
        )

        with self.assertRaises(DecryptionError):
            rsa_decrypt(
                ciphertext,
                self.key_pair.private_key,
                b"incorrect"
            )

    def test_signature(self):
        message = b"Document approval"

        signature = rsa_sign(
            message,
            self.key_pair.private_key
        )

        self.assertTrue(
            rsa_verify(
                message,
                signature,
                self.key_pair.public_key
            )
        )

    def test_tampered_signature(self):
        message = b"Original document"

        signature = rsa_sign(
            message,
            self.key_pair.private_key
        )

        self.assertFalse(
            rsa_verify(
                message + b" modified",
                signature,
                self.key_pair.public_key
            )
        )

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(DecryptionError):
            rsa_decrypt(
                b"\x00",
                self.key_pair.private_key
            )


if __name__ == "__main__":
    demonstrate()

    print("\nRunning automated tests...")
    unittest.main(argv=["rsa.py"], exit=False, verbosity=2)
