#!/usr/bin/env python3
"""
ECDSA IN BLOCKCHAIN AND CRYPTOGRAPHY
Educational implementation of elliptic-curve cryptography, deterministic
ECDSA signing, signature verification, and a simplified blockchain.

The secp256k1 implementation is intended for cryptographic education.
Production systems should use independently audited cryptographic libraries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================
# 1. Cryptographic parameters: secp256k1
# ============================================================

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

A = 0
B = 7

G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = Optional[tuple[int, int]]


class CryptographicError(Exception):
    """Base exception for cryptographic failures."""


class InvalidPrivateKey(CryptographicError):
    pass


class InvalidSignature(CryptographicError):
    pass


class InvalidPoint(CryptographicError):
    pass


# ============================================================
# 2. Elliptic-curve arithmetic
# ============================================================

def modular_inverse(value: int, modulus: int) -> int:
    """Calculate the modular multiplicative inverse."""

    value %= modulus

    if value == 0:
        raise ZeroDivisionError("Zero has no modular inverse")

    return pow(value, -1, modulus)


def point_is_valid(point: Point) -> bool:
    """Check whether a point belongs to secp256k1."""

    if point is None:
        return True

    x, y = point

    if not (0 <= x < P and 0 <= y < P):
        return False

    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_negate(point: Point) -> Point:
    if point is None:
        return None

    x, y = point
    return x, (-y) % P


def point_add(first: Point, second: Point) -> Point:
    """Elliptic-curve point addition."""

    if first is None:
        return second

    if second is None:
        return first

    x1, y1 = first
    x2, y2 = second

    if not point_is_valid(first) or not point_is_valid(second):
        raise InvalidPoint("Point is not on secp256k1")

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if first == second:
        if y1 == 0:
            return None

        slope = (
            3 * x1 * x1 * modular_inverse(2 * y1, P)
        ) % P
    else:
        slope = (
            (y2 - y1) * modular_inverse(x2 - x1, P)
        ) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    return x3, y3


def scalar_multiply(scalar: int, point: Point = G) -> Point:
    """Double-and-add scalar multiplication."""

    if scalar < 0:
        return scalar_multiply(-scalar, point_negate(point))

    if point is None:
        return None

    if not point_is_valid(point):
        raise InvalidPoint("Invalid input point")

    result = None
    addend = point

    while scalar:
        if scalar & 1:
            result = point_add(result, addend)

        addend = point_add(addend, addend)
        scalar >>= 1

    return result


# ============================================================
# 3. Hashing and key generation
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_to_integer(digest: bytes) -> int:
    return int.from_bytes(digest, "big") % N


def generate_private_key() -> int:
    """Generate a cryptographically random private scalar."""

    while True:
        private_key = secrets.randbelow(N)

        if 1 <= private_key < N:
            return private_key


def public_key_from_private(private_key: int) -> tuple[int, int]:
    if not 1 <= private_key < N:
        raise InvalidPrivateKey("Private key must be between 1 and N-1")

    public_key = scalar_multiply(private_key, G)

    if public_key is None:
        raise InvalidPrivateKey("Invalid public key")

    return public_key


def serialize_public_key(public_key: tuple[int, int]) -> bytes:
    """Serialize a public key using compressed SEC1 encoding."""

    if not point_is_valid(public_key):
        raise InvalidPoint("Invalid public key")

    x, y = public_key
    prefix = 2 + (y & 1)

    return bytes([prefix]) + x.to_bytes(32, "big")


def public_key_address(public_key: tuple[int, int]) -> str:
    """
    Derive a demonstration address.

    This is not the Ethereum address derivation procedure.
    """

    digest = sha256(serialize_public_key(public_key))
    return "bc_" + digest.hex()[:40]


# ============================================================
# 4. RFC6979 deterministic nonce generation
# ============================================================

def deterministic_nonce(private_key: int, digest: bytes) -> int:
    """
    Generate deterministic ECDSA nonce using RFC6979-style HMAC-SHA256.

    The implementation uses secp256k1's 256-bit scalar range.
    """

    if len(digest) != 32:
        raise ValueError("Expected a SHA-256 digest")

    x = private_key.to_bytes(32, "big")
    h1 = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")

    v = b"\x01" * 32
    k = b"\x00" * 32

    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")

        if 1 <= candidate < N:
            return candidate

        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ============================================================
# 5. ECDSA signing and verification
# ============================================================

@dataclass(frozen=True)
class Signature:
    r: int
    s: int

    def to_dict(self) -> dict[str, str]:
        return {
            "r": format(self.r, "064x"),
            "s": format(self.s, "064x"),
        }


def sign_digest(private_key: int, digest: bytes) -> Signature:
    """Create an ECDSA signature with low-S normalization."""

    if not 1 <= private_key < N:
        raise InvalidPrivateKey("Private key outside valid range")

    if len(digest) != 32:
        raise ValueError("Digest must contain 32 bytes")

    z = int.from_bytes(digest, "big")

    nonce = deterministic_nonce(private_key, digest)

    point = scalar_multiply(nonce, G)

    if point is None:
        raise InvalidSignature("Invalid nonce point")

    r = point[0] % N

    if r == 0:
        raise InvalidSignature("Invalid signature component r")

    s = (
        modular_inverse(nonce, N) *
        (z + r * private_key)
    ) % N

    if s == 0:
        raise InvalidSignature("Invalid signature component s")

    # Low-S normalization reduces signature malleability.
    if s > N // 2:
        s = N - s

    return Signature(r, s)


def verify_digest(
    public_key: tuple[int, int],
    digest: bytes,
    signature: Signature,
    require_low_s: bool = True,
) -> bool:
    """Verify an ECDSA signature."""

    if len(digest) != 32:
        return False

    if not point_is_valid(public_key) or public_key is None:
        return False

    r, s = signature.r, signature.s

    if not (1 <= r < N and 1 <= s < N):
        return False

    if require_low_s and s > N // 2:
        return False

    z = int.from_bytes(digest, "big")

    try:
        inverse_s = modular_inverse(s, N)

        u1 = (z * inverse_s) % N
        u2 = (r * inverse_s) % N

        point = point_add(
            scalar_multiply(u1, G),
            scalar_multiply(u2, public_key),
        )

        return point is not None and point[0] % N == r

    except (ValueError, ZeroDivisionError, InvalidPoint):
        return False


def sign_message(private_key: int, message: bytes) -> Signature:
    return sign_digest(private_key, sha256(message))


def verify_message(
    public_key: tuple[int, int],
    message: bytes,
    signature: Signature,
) -> bool:
    return verify_digest(public_key, sha256(message), signature)


# ============================================================
# 6. Transaction modeling
# ============================================================

class TransactionStatus(Enum):
    CREATED = "CREATED"
    SIGNED = "SIGNED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INCLUDED = "INCLUDED"


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    nonce: int
    timestamp: int = field(default_factory=lambda: int(time.time()))
    signature: Optional[Signature] = None
    status: TransactionStatus = TransactionStatus.CREATED
    transaction_id: str = ""

    def __post_init__(self) -> None:
        if not self.sender or not self.recipient:
            raise ValueError("Sender and recipient are required")

        if self.amount <= 0:
            raise ValueError("Amount must be positive")

        if self.nonce < 0:
            raise ValueError("Nonce cannot be negative")

        self.transaction_id = sha256(
            self.canonical_payload()
        ).hex()

    def canonical_payload(self) -> bytes:
        """
        Deterministic serialization prevents ambiguity in signed data.

        The signature itself is excluded from the signed payload.
        """

        payload = {
            "amount": self.amount,
            "nonce": self.nonce,
            "recipient": self.recipient,
            "sender": self.sender,
            "timestamp": self.timestamp,
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sign(self, private_key: int) -> None:
        public_key = public_key_from_private(private_key)

        if public_key_address(public_key) != self.sender:
            raise InvalidPrivateKey(
                "Signing key does not belong to transaction sender"
            )

        self.signature = sign_message(
            private_key,
            self.canonical_payload(),
        )

        self.status = TransactionStatus.SIGNED

    def verify(self, public_key: tuple[int, int]) -> bool:
        if self.signature is None:
            self.status = TransactionStatus.REJECTED
            return False

        if public_key_address(public_key) != self.sender:
            self.status = TransactionStatus.REJECTED
            return False

        valid = verify_message(
            public_key,
            self.canonical_payload(),
            self.signature,
        )

        self.status = (
            TransactionStatus.VERIFIED
            if valid
            else TransactionStatus.REJECTED
        )

        return valid


# ============================================================
# 7. Blockchain blocks
# ============================================================

@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: int = field(default_factory=lambda: int(time.time()))
    nonce: int = 0
    block_hash: str = ""

    def calculate_hash(self) -> str:
        transaction_ids = [
            transaction.transaction_id
            for transaction in self.transactions
        ]

        payload = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "transactions": transaction_ids,
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return sha256(serialized).hex()


class Blockchain:
    def __init__(self) -> None:
        self.blocks: list[Block] = []

        genesis = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[],
        )

        genesis.block_hash = genesis.calculate_hash()
        self.blocks.append(genesis)

    def add_block(self, transactions: list[Transaction]) -> Block:
        if not transactions:
            raise ValueError("A block must contain transactions")

        if any(
            tx.status != TransactionStatus.VERIFIED
            for tx in transactions
        ):
            raise ValueError("Unverified transactions cannot be included")

        previous = self.blocks[-1]

        block = Block(
            index=len(self.blocks),
            previous_hash=previous.block_hash,
            transactions=list(transactions),
        )

        block.block_hash = block.calculate_hash()

        for tx in transactions:
            tx.status = TransactionStatus.INCLUDED

        self.blocks.append(block)

        return block

    def validate_chain(self) -> bool:
        for index, block in enumerate(self.blocks):
            if block.calculate_hash() != block.block_hash:
                return False

            if index > 0:
                previous = self.blocks[index - 1]

                if block.previous_hash != previous.block_hash:
                    return False

                if block.index != index:
                    return False

        return True


# ============================================================
# 8. Security demonstrations
# ============================================================

def demonstrate_tampering(
    public_key: tuple[int, int],
    transaction: Transaction,
) -> bool:
    """A modified transaction must fail signature verification."""

    original = transaction.canonical_payload()

    transaction.amount += 1
    modified = transaction.canonical_payload()

    valid = verify_message(
        public_key,
        modified,
        transaction.signature,
    ) if transaction.signature else False

    transaction.amount -= 1

    assert transaction.canonical_payload() == original

    return valid


def demonstrate_signature_reuse(
    private_key: int,
    first_message: bytes,
    second_message: bytes,
) -> bool:
    """The same deterministic nonce is not reused across different digests."""

    first_nonce = deterministic_nonce(
        private_key,
        sha256(first_message),
    )

    second_nonce = deterministic_nonce(
        private_key,
        sha256(second_message),
    )

    return first_nonce != second_nonce


# ============================================================
# 9. Executable workflow
# ============================================================

def main() -> None:
    print("=" * 65)
    print("ECDSA AND BLOCKCHAIN DEMONSTRATION")
    print("=" * 65)

    private_key = generate_private_key()
    public_key = public_key_from_private(private_key)
    address = public_key_address(public_key)

    print("\n1. KEY GENERATION")
    print("Curve: secp256k1")
    print("Public key:", serialize_public_key(public_key).hex())
    print("Address:", address)
    print("Private key: [REDACTED]")

    print("\n2. STANDALONE ECDSA SIGNATURE")

    message = b"Authorize blockchain transfer of 250 units"

    signature = sign_message(private_key, message)

    print("Signature r:", format(signature.r, "064x"))
    print("Signature s:", format(signature.s, "064x"))
    print("Valid signature:", verify_message(
        public_key, message, signature
    ))

    print("Modified message accepted:", verify_message(
        public_key,
        message + b" modified",
        signature,
    ))

    print("\n3. TRANSACTION SIGNING")

    recipient_private = generate_private_key()
    recipient_public = public_key_from_private(recipient_private)

    transaction = Transaction(
        sender=address,
        recipient=public_key_address(recipient_public),
        amount=250,
        nonce=1,
    )

    transaction.sign(private_key)

    print("Transaction ID:", transaction.transaction_id)
    print("Signature attached:", transaction.signature is not None)
    print("Verification:", transaction.verify(public_key))
    print("Tampered transaction accepted:",
          demonstrate_tampering(public_key, transaction))

    print("\n4. BLOCKCHAIN INCLUSION")

    chain = Blockchain()
    block = chain.add_block([transaction])

    print("Block index:", block.index)
    print("Block hash:", block.block_hash)
    print("Chain valid:", chain.validate_chain())

    print("\n5. SECURITY VALIDATION")

    print("Nonce differs for distinct messages:",
          demonstrate_signature_reuse(
              private_key,
              b"payment A",
              b"payment B",
          ))

    invalid_signature = Signature(r=0, s=0)

    print("Invalid signature rejected:",
          not verify_digest(
              public_key,
              sha256(message),
              invalid_signature,
          ))

    print("\n6. EDGE CASES")

    try:
        public_key_from_private(0)
    except InvalidPrivateKey as error:
        print("Zero private key rejected:", error)

    try:
        Transaction(
            sender=address,
            recipient="invalid",
            amount=-10,
            nonce=0,
        )
    except ValueError as error:
        print("Negative amount rejected:", error)

    assert verify_message(public_key, message, signature)
    assert not verify_message(public_key, message + b"x", signature)
    assert chain.validate_chain()

    print("\nAll demonstration assertions passed.")


if __name__ == "__main__":
    main()
