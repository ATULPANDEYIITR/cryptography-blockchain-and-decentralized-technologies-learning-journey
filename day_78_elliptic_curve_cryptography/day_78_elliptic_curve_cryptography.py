#!/usr/bin/env python3
"""
Elliptic Curve Cryptography (ECC)
Educational implementation of secp256k1, ECDH, ECDSA, key validation,
digital signatures, and cryptographic workflow management.

Standard library only.

SECURITY NOTICE:
This implementation demonstrates ECC mathematics and cryptographic
workflows. Python big-integer operations are not constant-time.
Use a vetted cryptographic library for production systems.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unittest
from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ------------------------------------------------------------
# 1. Curve parameters: secp256k1
# ------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


class ECCError(Exception):
    """Base ECC exception."""


class InvalidPointError(ECCError):
    """Point does not belong to the selected curve."""


class InvalidKeyError(ECCError):
    """Private or public key is invalid."""


class SignatureError(ECCError):
    """Digital signature verification failed."""


class CurveType(Enum):
    SECP256K1 = "secp256k1"


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


INFINITY = Point(None, None)
G = Point(GX, GY)


# ------------------------------------------------------------
# 2. Finite-field arithmetic
# ------------------------------------------------------------

def mod_inverse(value: int, modulus: int) -> int:
    """Compute modular inverse using the extended Euclidean algorithm."""
    value %= modulus

    if value == 0:
        raise ZeroDivisionError("Zero has no modular inverse.")

    gcd = pow(value, -1, modulus)

    return gcd


def is_on_curve(point: Point) -> bool:
    if point.is_infinity:
        return True

    if point.x is None or point.y is None:
        return False

    if not (0 <= point.x < P and 0 <= point.y < P):
        return False

    return (
        pow(point.y, 2, P)
        == (pow(point.x, 3, P) + A * point.x + B) % P
    )


# ------------------------------------------------------------
# 3. Elliptic curve point operations
# ------------------------------------------------------------

def point_negate(point: Point) -> Point:
    if point.is_infinity:
        return INFINITY

    return Point(point.x, (-point.y) % P)


def point_add(left: Point, right: Point) -> Point:
    """
    Add two points using the elliptic curve group law.
    """
    if not is_on_curve(left) or not is_on_curve(right):
        raise InvalidPointError("Cannot operate on invalid points.")

    if left.is_infinity:
        return right

    if right.is_infinity:
        return left

    x1, y1 = left.x, left.y
    x2, y2 = right.x, right.y

    if x1 == x2 and (y1 + y2) % P == 0:
        return INFINITY

    if left == right:
        if y1 == 0:
            return INFINITY

        numerator = (3 * x1 * x1 + A) % P
        denominator = mod_inverse(2 * y1, P)
    else:
        numerator = (y2 - y1) % P
        denominator = mod_inverse((x2 - x1) % P, P)

    slope = numerator * denominator % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    result = Point(x3, y3)

    if not is_on_curve(result):
        raise InvalidPointError("Point addition produced invalid output.")

    return result


def scalar_multiply(scalar: int, point: Point = G) -> Point:
    """
    Double-and-add scalar multiplication.

    Complexity: O(log scalar) point operations.
    This implementation is not constant-time.
    """
    if not is_on_curve(point):
        raise InvalidPointError("Invalid input point.")

    if not isinstance(scalar, int):
        raise TypeError("Scalar must be an integer.")

    if scalar < 0:
        return scalar_multiply(-scalar, point_negate(point))

    result = INFINITY
    current = point

    while scalar:
        if scalar & 1:
            result = point_add(result, current)

        current = point_add(current, current)
        scalar >>= 1

    return result


# ------------------------------------------------------------
# 4. Key generation and validation
# ------------------------------------------------------------

@dataclass(frozen=True)
class ECCKeyPair:
    private_key: int
    public_key: Point


def validate_private_key(private_key: int) -> None:
    if not isinstance(private_key, int):
        raise InvalidKeyError("Private key must be an integer.")

    if not 1 <= private_key < N:
        raise InvalidKeyError("Private key is outside the valid range.")


def validate_public_key(public_key: Point) -> None:
    if not isinstance(public_key, Point):
        raise InvalidKeyError("Public key must be a Point.")

    if public_key.is_infinity or not is_on_curve(public_key):
        raise InvalidKeyError("Invalid public key.")

    # secp256k1 has cofactor 1. The subgroup check is still explicit.
    if not scalar_multiply(N, public_key).is_infinity:
        raise InvalidKeyError("Public key is outside the expected subgroup.")


def generate_key_pair() -> ECCKeyPair:
    private_key = secrets.randbelow(N - 1) + 1
    public_key = scalar_multiply(private_key)

    return ECCKeyPair(private_key, public_key)


# ------------------------------------------------------------
# 5. Public-key serialization
# ------------------------------------------------------------

def encode_public_key(point: Point, compressed: bool = True) -> bytes:
    validate_public_key(point)

    if compressed:
        prefix = 2 + (point.y & 1)
        return bytes([prefix]) + point.x.to_bytes(32, "big")

    return (
        b"\x04"
        + point.x.to_bytes(32, "big")
        + point.y.to_bytes(32, "big")
    )


def decode_public_key(data: bytes) -> Point:
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")

        if x >= P:
            raise InvalidPointError("Invalid x coordinate.")

        alpha = (pow(x, 3, P) + B) % P
        beta = pow(alpha, (P + 1) // 4, P)

        if pow(beta, 2, P) != alpha:
            raise InvalidPointError("Point has no valid y coordinate.")

        y = beta if beta % 2 == data[0] % 2 else P - beta
        point = Point(x, y)

    elif len(data) == 65 and data[0] == 4:
        point = Point(
            int.from_bytes(data[1:33], "big"),
            int.from_bytes(data[33:65], "big")
        )

    else:
        raise InvalidPointError("Unsupported public-key encoding.")

    validate_public_key(point)

    return point


# ------------------------------------------------------------
# 6. ECDH key agreement
# ------------------------------------------------------------

def derive_shared_secret(
    private_key: int,
    peer_public_key: Point
) -> bytes:
    validate_private_key(private_key)
    validate_public_key(peer_public_key)

    shared_point = scalar_multiply(private_key, peer_public_key)

    if shared_point.is_infinity:
        raise InvalidKeyError("ECDH generated point at infinity.")

    return shared_point.x.to_bytes(32, "big")


def derive_session_key(
    shared_secret: bytes,
    context: bytes = b"ECC-SESSION-V1"
) -> bytes:
    """
    Apply domain-separated HMAC-based extraction and expansion.

    A production protocol should use a standardized HKDF implementation
    and bind both public keys, protocol identity, and session context.
    """
    salt = hashlib.sha256(context).digest()

    pseudorandom_key = hmac.new(
        salt, shared_secret, hashlib.sha256
    ).digest()

    return hmac.new(
        pseudorandom_key,
        b"session-key\x01",
        hashlib.sha256
    ).digest()


# ------------------------------------------------------------
# 7. ECDSA digital signatures
# ------------------------------------------------------------

def hash_message(message: bytes) -> int:
    return int.from_bytes(
        hashlib.sha256(message).digest(), "big"
    )


def ecdsa_sign(
    private_key: int,
    message: bytes
) -> tuple[int, int]:
    validate_private_key(private_key)

    z = hash_message(message)

    while True:
        nonce = secrets.randbelow(N - 1) + 1
        point = scalar_multiply(nonce)

        r = point.x % N

        if r == 0:
            continue

        s = (
            mod_inverse(nonce, N)
            * (z + r * private_key)
        ) % N

        if s == 0:
            continue

        # Low-S normalization reduces signature malleability.
        if s > N // 2:
            s = N - s

        return r, s


def ecdsa_verify(
    public_key: Point,
    message: bytes,
    signature: tuple[int, int]
) -> bool:
    try:
        validate_public_key(public_key)

        r, s = signature

        if not (1 <= r < N and 1 <= s <= N // 2):
            return False

        z = hash_message(message)
        inverse_s = mod_inverse(s, N)

        u1 = z * inverse_s % N
        u2 = r * inverse_s % N

        result = point_add(
            scalar_multiply(u1),
            scalar_multiply(u2, public_key)
        )

        if result.is_infinity:
            return False

        return result.x % N == r

    except (ECCError, ValueError, ZeroDivisionError, TypeError):
        return False


# ------------------------------------------------------------
# 8. Cryptographic key lifecycle
# ------------------------------------------------------------

class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass
class ManagedKey:
    key_id: str
    key_pair: ECCKeyPair
    status: KeyStatus
    version: int


class KeyRegistry:
    def __init__(self):
        self._keys: dict[str, ManagedKey] = {}

    def register(self, key_id: str, key_pair: ECCKeyPair) -> None:
        if not key_id or key_id in self._keys:
            raise ValueError("Invalid or duplicate key identifier.")

        validate_private_key(key_pair.private_key)
        validate_public_key(key_pair.public_key)

        if scalar_multiply(key_pair.private_key) != key_pair.public_key:
            raise InvalidKeyError("Private and public keys do not match.")

        self._keys[key_id] = ManagedKey(
            key_id,
            key_pair,
            KeyStatus.ACTIVE,
            1
        )

    def rotate(self, key_id: str, replacement: ECCKeyPair) -> None:
        key = self._get_active(key_id)

        validate_private_key(replacement.private_key)
        validate_public_key(replacement.public_key)

        if scalar_multiply(replacement.private_key) != replacement.public_key:
            raise InvalidKeyError("Replacement key pair mismatch.")

        key.status = KeyStatus.ROTATED

        new_id = f"{key_id}-v{key.version + 1}"

        self.register(new_id, replacement)

    def revoke(self, key_id: str) -> None:
        key = self._get_active(key_id)
        key.status = KeyStatus.REVOKED

    def _get_active(self, key_id: str) -> ManagedKey:
        key = self._keys.get(key_id)

        if key is None or key.status != KeyStatus.ACTIVE:
            raise InvalidKeyError("Key is missing or inactive.")

        return key

    def get_public_key(self, key_id: str) -> Point:
        return self._get_active(key_id).key_pair.public_key


# ------------------------------------------------------------
# 9. Demonstration
# ------------------------------------------------------------

def demonstration() -> None:
    print("ELLIPTIC CURVE CRYPTOGRAPHY")
    print("=" * 55)

    alice = generate_key_pair()
    bob = generate_key_pair()

    print("Curve:", CurveType.SECP256K1.value)
    print("Generator valid:", is_on_curve(G))

    # Public-key consistency.
    assert scalar_multiply(alice.private_key) == alice.public_key
    assert scalar_multiply(bob.private_key) == bob.public_key

    # Group identity.
    assert point_add(G, INFINITY) == G
    assert point_add(G, point_negate(G)) == INFINITY

    # Compressed key serialization.
    encoded = encode_public_key(alice.public_key)
    decoded = decode_public_key(encoded)

    assert decoded == alice.public_key

    # ECDH.
    alice_secret = derive_shared_secret(
        alice.private_key, bob.public_key
    )

    bob_secret = derive_shared_secret(
        bob.private_key, alice.public_key
    )

    assert alice_secret == bob_secret

    session_key = derive_session_key(alice_secret)

    # ECDSA.
    message = b"Approve secure repository deployment"

    signature = ecdsa_sign(alice.private_key, message)

    assert ecdsa_verify(alice.public_key, message, signature)

    assert not ecdsa_verify(
        alice.public_key,
        b"Modified deployment request",
        signature
    )

    print("Public-key serialization: verified")
    print("ECDH agreement: verified")
    print("Session key:", session_key.hex())
    print("ECDSA signature: valid")
    print("Modified message rejected: verified")

    # Key lifecycle.
    registry = KeyRegistry()
    registry.register("alice", alice)
    registry.rotate("alice", generate_key_pair())

    try:
        registry.get_public_key("alice")
    except InvalidKeyError:
        print("Old key rejected after rotation")

    registry.revoke("alice-v2")

    try:
        registry.get_public_key("alice-v2")
    except InvalidKeyError:
        print("Revoked key rejected")

    # Invalid input handling.
    try:
        validate_private_key(0)
    except InvalidKeyError:
        print("Invalid private key rejected")

    try:
        decode_public_key(b"invalid")
    except InvalidPointError:
        print("Invalid public-key encoding rejected")


# ------------------------------------------------------------
# 10. Automated tests
# ------------------------------------------------------------

class ECCTests(unittest.TestCase):

    def test_generator(self):
        self.assertTrue(is_on_curve(G))

    def test_group_identity(self):
        self.assertEqual(point_add(G, INFINITY), G)

    def test_inverse(self):
        self.assertEqual(
            point_add(G, point_negate(G)),
            INFINITY
        )

    def test_order(self):
        self.assertTrue(scalar_multiply(N).is_infinity)

    def test_key_serialization(self):
        pair = generate_key_pair()
        self.assertEqual(
            decode_public_key(encode_public_key(pair.public_key)),
            pair.public_key
        )

    def test_ecdh(self):
        alice = generate_key_pair()
        bob = generate_key_pair()

        self.assertEqual(
            derive_shared_secret(alice.private_key, bob.public_key),
            derive_shared_secret(bob.private_key, alice.public_key)
        )

    def test_ecdsa(self):
        pair = generate_key_pair()
        message = b"ECC security test"

        signature = ecdsa_sign(pair.private_key, message)

        self.assertTrue(
            ecdsa_verify(pair.public_key, message, signature)
        )

        self.assertFalse(
            ecdsa_verify(pair.public_key, b"wrong", signature)
        )

    def test_invalid_private_key(self):
        with self.assertRaises(InvalidKeyError):
            validate_private_key(N)

    def test_registry(self):
        registry = KeyRegistry()
        registry.register("test", generate_key_pair())
        registry.revoke("test")

        with self.assertRaises(InvalidKeyError):
            registry.get_public_key("test")


if __name__ == "__main__":
    demonstration()
    print("\nRUNNING AUTOMATED TESTS")
    unittest.main(argv=["ecc.py"], exit=False)
