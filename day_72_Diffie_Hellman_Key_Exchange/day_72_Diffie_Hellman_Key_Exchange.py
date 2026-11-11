#!/usr/bin/env python3
"""
Diffie-Hellman Key Exchange
Educational implementation covering:
- Modular arithmetic and modular exponentiation
- Prime and subgroup validation
- Public and private key generation
- Shared-secret computation
- Key agreement verification
- HKDF-style key derivation
- Transcript hashing
- Input validation and failure handling

IMPORTANT:
The small parameters are exclusively for education.
Production systems must use standardized groups or
validated elliptic-curve implementations through
maintained cryptographic libraries and authenticated protocols.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unittest

from dataclasses import dataclass
from typing import Optional


class DHError(Exception):
    """Base exception for Diffie-Hellman operations."""


class ParameterError(DHError):
    """Invalid group parameters."""


class KeyExchangeError(DHError):
    """Invalid key exchange operation."""


class VerificationError(DHError):
    """Shared-secret verification failure."""


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin probable-prime test."""
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

    # Multiple independent bases reduce the probability
    # of incorrectly accepting a composite integer.
    for base in (2, 3, 5, 7, 11, 13, 17):
        if base >= n - 1:
            continue

        x = pow(base, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


@dataclass(frozen=True)
class DHGroup:
    p: int
    q: int
    g: int

    def validate(self) -> None:
        if self.p <= 5:
            raise ParameterError("Modulus is too small.")

        if not is_probable_prime(self.p):
            raise ParameterError("Modulus must be prime.")

        if not is_probable_prime(self.q):
            raise ParameterError("Subgroup order must be prime.")

        if self.p != 2 * self.q + 1:
            raise ParameterError("Expected safe-prime group parameters.")

        if not 1 < self.g < self.p:
            raise ParameterError("Generator is outside the valid range.")

        if pow(self.g, self.q, self.p) != 1:
            raise ParameterError("Generator does not belong to subgroup.")

        if self.g == 1:
            raise ParameterError("Generator has trivial order.")


# Educational safe-prime group.
# p = 23, q = 11, g = 2.
# Never use these parameters for actual security.
EDUCATIONAL_GROUP = DHGroup(p=23, q=11, g=2)


def generate_private_key(group: DHGroup) -> int:
    group.validate()
    return secrets.randbelow(group.q - 1) + 1


def generate_public_key(private_key: int, group: DHGroup) -> int:
    group.validate()

    if not 1 <= private_key < group.q:
        raise KeyExchangeError("Private key is outside the subgroup range.")

    return pow(group.g, private_key, group.p)


def validate_public_key(public_key: int, group: DHGroup) -> None:
    group.validate()

    if not 1 < public_key < group.p - 1:
        raise KeyExchangeError("Public key is outside the valid range.")

    if pow(public_key, group.q, group.p) != 1:
        raise KeyExchangeError("Public key is outside the selected subgroup.")


def compute_shared_secret(
    private_key: int,
    peer_public_key: int,
    group: DHGroup
) -> int:
    if not 1 <= private_key < group.q:
        raise KeyExchangeError("Invalid private key.")

    validate_public_key(peer_public_key, group)

    secret = pow(peer_public_key, private_key, group.p)

    if secret == 1:
        raise KeyExchangeError("Trivial shared secret rejected.")

    return secret


def hkdf_sha256(
    input_key_material: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32
) -> bytes:
    """RFC 5869 HKDF using SHA-256."""

    if not 1 <= length <= 255 * 32:
        raise ValueError("Invalid HKDF output length.")

    if not salt:
        salt = bytes(32)

    pseudorandom_key = hmac.new(
        salt,
        input_key_material,
        hashlib.sha256
    ).digest()

    output = b""
    previous = b""

    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([counter]),
            hashlib.sha256
        ).digest()

        output += previous

    return output[:length]


def encode_secret(secret: int, group: DHGroup) -> bytes:
    width = (group.p.bit_length() + 7) // 8
    return secret.to_bytes(width, byteorder="big")


@dataclass
class Participant:
    name: str
    private_key: int
    public_key: int

    @classmethod
    def create(cls, name: str, group: DHGroup) -> "Participant":
        if not name.strip():
            raise ValueError("Participant name cannot be empty.")

        private = generate_private_key(group)
        public = generate_public_key(private, group)

        return cls(name, private, public)

    def establish_secret(
        self,
        peer: "Participant",
        group: DHGroup
    ) -> int:
        return compute_shared_secret(
            self.private_key,
            peer.public_key,
            group
        )


@dataclass(frozen=True)
class ExchangeResult:
    alice_public: int
    bob_public: int
    shared_secret: int
    derived_key: bytes
    transcript_hash: str


def perform_exchange(
    group: DHGroup = EDUCATIONAL_GROUP
) -> ExchangeResult:

    group.validate()

    alice = Participant.create("Alice", group)
    bob = Participant.create("Bob", group)

    alice_secret = alice.establish_secret(bob, group)
    bob_secret = bob.establish_secret(alice, group)

    if alice_secret != bob_secret:
        raise VerificationError("Key agreement failed.")

    # The transcript records both public values and group parameters.
    transcript = (
        f"DH-v1|{group.p}|{group.q}|{group.g}|"
        f"{alice.public_key}|{bob.public_key}"
    ).encode("utf-8")

    transcript_hash = hashlib.sha256(transcript).hexdigest()

    # Derive an application key rather than using the raw DH integer.
    derived_key = hkdf_sha256(
        encode_secret(alice_secret, group),
        salt=bytes.fromhex(transcript_hash),
        info=b"educational-dh-session-key",
        length=32
    )

    return ExchangeResult(
        alice_public=alice.public_key,
        bob_public=bob.public_key,
        shared_secret=alice_secret,
        derived_key=derived_key,
        transcript_hash=transcript_hash
    )


def demonstrate_failure_cases() -> None:
    group = EDUCATIONAL_GROUP

    cases = [
        ("Public key outside range", 1),
        ("Public key outside subgroup", 5),
        ("Invalid private key", 0),
    ]

    for description, value in cases:
        try:
            if description == "Invalid private key":
                compute_shared_secret(value, 8, group)
            else:
                validate_public_key(value, group)

        except DHError as exc:
            print(f"{description}: REJECTED ({exc})")


class DiffieHellmanTests(unittest.TestCase):

    def test_group_validation(self):
        EDUCATIONAL_GROUP.validate()

    def test_key_agreement(self):
        alice = Participant.create("Alice", EDUCATIONAL_GROUP)
        bob = Participant.create("Bob", EDUCATIONAL_GROUP)

        self.assertEqual(
            alice.establish_secret(bob, EDUCATIONAL_GROUP),
            bob.establish_secret(alice, EDUCATIONAL_GROUP)
        )

    def test_public_key_validation(self):
        with self.assertRaises(KeyExchangeError):
            validate_public_key(1, EDUCATIONAL_GROUP)

    def test_subgroup_validation(self):
        with self.assertRaises(KeyExchangeError):
            validate_public_key(5, EDUCATIONAL_GROUP)

    def test_private_key_validation(self):
        with self.assertRaises(KeyExchangeError):
            generate_public_key(0, EDUCATIONAL_GROUP)

    def test_hkdf_output(self):
        result = hkdf_sha256(b"secret", b"salt", b"context", 32)
        self.assertEqual(len(result), 32)

    def test_hkdf_length_validation(self):
        with self.assertRaises(ValueError):
            hkdf_sha256(b"secret", b"salt", b"context", 0)

    def test_different_exchange_keys(self):
        first = perform_exchange()
        second = perform_exchange()

        self.assertNotEqual(
            first.derived_key,
            second.derived_key
        )


def main() -> None:
    print("DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 55)

    group = EDUCATIONAL_GROUP
    result = perform_exchange(group)

    print(f"Prime modulus p:       {group.p}")
    print(f"Subgroup order q:      {group.q}")
    print(f"Generator g:           {group.g}")
    print(f"Alice public key:      {result.alice_public}")
    print(f"Bob public key:        {result.bob_public}")
    print(f"Shared secret:         {result.shared_secret}")
    print(f"Derived session key:   {result.derived_key.hex()}")
    print(f"Transcript SHA-256:    {result.transcript_hash}")

    print("\nKey agreement: VERIFIED")
    print("Security level: EDUCATIONAL ONLY")

    print("\nFailure handling:")
    demonstrate_failure_cases()

    print("\nRunning tests:")
    unittest.main(argv=["dh"], exit=False)


if __name__ == "__main__":
    main()
