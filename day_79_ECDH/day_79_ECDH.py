#!/usr/bin/env python3
"""
Elliptic Curve Diffie-Hellman (ECDH) in Blockchain

Educational implementation demonstrating:
- secp256k1 elliptic-curve arithmetic
- ECDH key agreement
- HKDF-SHA256 key derivation
- Blockchain wallet identities
- Public-key registration
- Off-chain secure-channel establishment
- On-chain transaction commitments
- Block hashing and chain validation
- Tamper detection and replay protection

The custom elliptic-curve implementation is for education only.
Use audited cryptographic libraries and authenticated encryption
for production systems.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Optional


# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = Optional[tuple[int, int]]


class CryptoError(Exception):
    """Raised when a cryptographic operation is invalid."""


class BlockchainError(Exception):
    """Raised when blockchain validation fails."""


def inverse(value: int, modulus: int) -> int:
    if value % modulus == 0:
        raise CryptoError("Modular inverse does not exist.")
    return pow(value, -1, modulus)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two elliptic-curve points."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if p1 == p2:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + A) * inverse(2 * y1, P) % P
    else:
        slope = (y2 - y1) * inverse(x2 - x1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    return x3, y3


def point_multiply(scalar: int, point: Point = G) -> Point:
    """Double-and-add scalar multiplication."""
    if not 0 <= scalar < N:
        raise CryptoError("Scalar must be between 0 and curve order - 1.")

    result = None
    addend = point

    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1

    return result


def validate_public_key(public_key: Point) -> None:
    if public_key is None:
        raise CryptoError("Point at infinity is not a valid public key.")

    x, y = public_key

    if not (0 <= x < P and 0 <= y < P):
        raise CryptoError("Public-key coordinates are out of range.")

    if (y * y - (x * x * x + A * x + B)) % P != 0:
        raise CryptoError("Public key is not on secp256k1.")

    # secp256k1 has cofactor 1 and prime group order.
    if point_multiply(N, public_key) is not None:
        raise CryptoError("Public key has an invalid subgroup.")


def encode_public_key(public_key: Point) -> bytes:
    validate_public_key(public_key)
    assert public_key is not None
    x, y = public_key
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_sha256(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """RFC 5869 HKDF using HMAC-SHA256."""
    if not 1 <= length <= 255 * 32:
        raise ValueError("Invalid HKDF output length.")

    pseudorandom_key = hmac.new(
        salt or bytes(32), input_key, hashlib.sha256
    ).digest()

    output = b""
    previous = b""

    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        output += previous

    return output[:length]


@dataclass(frozen=True)
class Wallet:
    address: str
    public_key: Point

    @classmethod
    def generate(cls) -> tuple["Wallet", int]:
        private_key = secrets.randbelow(N - 1) + 1
        public_key = point_multiply(private_key)

        address = sha256(encode_public_key(public_key)).hex()[:40]

        return cls(address, public_key), private_key


def establish_shared_key(
    private_key: int,
    peer_public_key: Point,
    context: bytes,
) -> bytes:
    """Derive an application-specific symmetric key."""
    if not 1 <= private_key < N:
        raise CryptoError("Invalid private key.")

    validate_public_key(peer_public_key)

    shared_point = point_multiply(private_key, peer_public_key)

    if shared_point is None:
        raise CryptoError("Invalid ECDH shared point.")

    shared_secret = shared_point[0].to_bytes(32, "big")

    salt = sha256(b"blockchain-ecdh-v1" + context)

    return hkdf_sha256(
        shared_secret,
        salt,
        b"secp256k1-secure-channel",
        32,
    )


@dataclass
class Transaction:
    transaction_id: str
    sender: str
    recipient: str
    public_key_commitment: str
    channel_commitment: str
    nonce: int
    timestamp: float
    amount: int

    def validate(self) -> None:
        if self.sender == self.recipient:
            raise BlockchainError("Self-transfers are not permitted.")

        if self.amount <= 0:
            raise BlockchainError("Transaction amount must be positive.")

        if self.nonce < 0:
            raise BlockchainError("Invalid transaction nonce.")

        if len(self.public_key_commitment) != 64:
            raise BlockchainError("Invalid public-key commitment.")

        if len(self.channel_commitment) != 64:
            raise BlockchainError("Invalid channel commitment.")


@dataclass
class Block:
    index: int
    previous_hash: str
    timestamp: float
    transactions: list[Transaction]
    nonce: int
    block_hash: str = ""

    def calculate_hash(self) -> str:
        payload = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [
                asdict(transaction) for transaction in self.transactions
            ],
            "nonce": self.nonce,
        }

        serialized = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode()

        return sha256(serialized).hex()


class Blockchain:
    def __init__(self):
        self.chain: list[Block] = []
        self.pending: list[Transaction] = []
        self.used_ids: set[str] = set()
        self.account_nonces: dict[str, int] = {}

        genesis = Block(
            index=0,
            previous_hash="0" * 64,
            timestamp=time.time(),
            transactions=[],
            nonce=0,
        )
        genesis.block_hash = genesis.calculate_hash()
        self.chain.append(genesis)

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def submit_transaction(self, transaction: Transaction) -> None:
        transaction.validate()

        if transaction.transaction_id in self.used_ids:
            raise BlockchainError("Duplicate transaction identifier.")

        expected_nonce = self.account_nonces.get(transaction.sender, 0)

        if transaction.nonce != expected_nonce:
            raise BlockchainError(
                f"Invalid nonce: expected {expected_nonce}."
            )

        self.used_ids.add(transaction.transaction_id)
        self.account_nonces[transaction.sender] = expected_nonce + 1
        self.pending.append(transaction)

    def mine_block(self) -> Block:
        if not self.pending:
            raise BlockchainError("No transactions available.")

        block = Block(
            index=len(self.chain),
            previous_hash=self.latest_block.block_hash,
            timestamp=time.time(),
            transactions=self.pending.copy(),
            nonce=0,
        )

        block.block_hash = block.calculate_hash()

        self.chain.append(block)
        self.pending.clear()

        return block

    def validate_chain(self) -> bool:
        for index, block in enumerate(self.chain):
            if block.block_hash != block.calculate_hash():
                return False

            if index == 0:
                if block.previous_hash != "0" * 64:
                    return False
            else:
                previous = self.chain[index - 1]

                if block.previous_hash != previous.block_hash:
                    return False

                if block.index != previous.index + 1:
                    return False

            try:
                for transaction in block.transactions:
                    transaction.validate()
            except BlockchainError:
                return False

        return True


def create_channel_context(
    initiator: str,
    responder: str,
    session_id: str,
) -> bytes:
    """Both participants must use the same canonical context."""
    if not session_id:
        raise ValueError("Session identifier cannot be empty.")

    participants = sorted([initiator, responder])

    return (
        "|".join(participants + [session_id]).encode()
    )


def demonstrate() -> None:
    print("=" * 65)
    print("ECDH IN BLOCKCHAIN: SECURE WALLET COMMUNICATION")
    print("=" * 65)

    alice, alice_private = Wallet.generate()
    bob, bob_private = Wallet.generate()

    print("\n1. Wallet registration")
    print("Alice:", alice.address)
    print("Bob:  ", bob.address)

    session_id = secrets.token_hex(16)
    context = create_channel_context(
        alice.address,
        bob.address,
        session_id,
    )

    print("\n2. ECDH key agreement")

    alice_key = establish_shared_key(
        alice_private,
        bob.public_key,
        context,
    )

    bob_key = establish_shared_key(
        bob_private,
        alice.public_key,
        context,
    )

    assert hmac.compare_digest(alice_key, bob_key)

    print("Alice and Bob derived identical channel keys.")
    print("Key fingerprint:", sha256(alice_key).hex()[:24])

    print("\n3. Channel commitment")

    channel_commitment = sha256(
        b"channel-commitment-v1" + alice_key
    ).hex()

    public_key_commitment = sha256(
        encode_public_key(alice.public_key)
        + encode_public_key(bob.public_key)
    ).hex()

    print("Channel commitment:", channel_commitment[:32])
    print("Public-key commitment:", public_key_commitment[:32])

    print("\n4. Blockchain transaction")

    blockchain = Blockchain()

    transaction = Transaction(
        transaction_id=secrets.token_hex(16),
        sender=alice.address,
        recipient=bob.address,
        public_key_commitment=public_key_commitment,
        channel_commitment=channel_commitment,
        nonce=0,
        timestamp=time.time(),
        amount=100,
    )

    blockchain.submit_transaction(transaction)

    block = blockchain.mine_block()

    print("Block index:", block.index)
    print("Block hash:", block.block_hash)
    print("Transaction count:", len(block.transactions))

    print("\n5. Blockchain integrity verification")
    print("Valid chain:", blockchain.validate_chain())

    print("\n6. Tampering detection")

    original_hash = blockchain.chain[1].block_hash
    blockchain.chain[1].transactions[0].amount = 9999

    print("Valid after tampering:", blockchain.validate_chain())

    blockchain.chain[1].transactions[0].amount = 100
    blockchain.chain[1].block_hash = original_hash

    print("Valid after restoration:", blockchain.validate_chain())

    print("\n7. Replay protection")

    try:
        blockchain.submit_transaction(transaction)
    except BlockchainError as error:
        print("Replay rejected:", error)

    print("\n8. ECDH security validation")

    try:
        establish_shared_key(alice_private, None, context)
    except CryptoError as error:
        print("Invalid peer key rejected:", error)

    print("\nDemonstration completed.")


if __name__ == "__main__":
    demonstrate()
