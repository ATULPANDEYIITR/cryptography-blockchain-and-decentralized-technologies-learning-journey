#!/usr/bin/env python3
"""
MAC IN CRYPTOGRAPHY AND BLOCKCHAIN
Message Authentication Code implementation and blockchain simulation.

Features:
- HMAC-SHA256 generation and verification
- Constant-time MAC comparison
- Key management and validation
- Message tampering detection
- Replay protection using nonces
- Transaction authentication
- Hash-linked blockchain simulation
- Block integrity verification
- Authentication failure handling
- Unit-style assertions
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
# 1. CONFIGURATION
# ============================================================

HASH_ALGORITHM = "sha256"
KEY_MIN_LENGTH = 32


class MACError(Exception):
    """Base exception for MAC operations."""


class InvalidKeyError(MACError):
    pass


class InvalidMessageError(MACError):
    pass


class AuthenticationError(MACError):
    pass


class ReplayError(MACError):
    pass


# ============================================================
# 2. KEY MANAGEMENT
# ============================================================

@dataclass(frozen=True)
class MACKey:
    key_id: str
    secret: bytes = field(repr=False)
    algorithm: str = HASH_ALGORITHM

    def __post_init__(self):
        if not self.key_id:
            raise InvalidKeyError("Key identifier cannot be empty")

        if len(self.secret) < KEY_MIN_LENGTH:
            raise InvalidKeyError(
                f"Key must contain at least {KEY_MIN_LENGTH} bytes"
            )

        if self.algorithm != HASH_ALGORITHM:
            raise InvalidKeyError("Unsupported MAC algorithm")


class KeyManager:
    def __init__(self):
        self._keys: dict[str, MACKey] = {}

    def generate_key(self, key_id: str) -> MACKey:
        if key_id in self._keys:
            raise InvalidKeyError("Key identifier already exists")

        key = MACKey(
            key_id=key_id,
            secret=secrets.token_bytes(32)
        )

        self._keys[key_id] = key
        return key

    def register_key(self, key: MACKey) -> None:
        if key.key_id in self._keys:
            raise InvalidKeyError("Duplicate key identifier")

        self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> MACKey:
        try:
            return self._keys[key_id]
        except KeyError:
            raise InvalidKeyError("Unknown key identifier") from None


# ============================================================
# 3. HMAC-SHA256 IMPLEMENTATION
# ============================================================

class HMACService:

    @staticmethod
    def generate(message: bytes, key: MACKey) -> str:
        if not isinstance(message, bytes):
            raise InvalidMessageError("Message must be bytes")

        return hmac.new(
            key.secret,
            message,
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify(
        message: bytes,
        supplied_mac: str,
        key: MACKey
    ) -> bool:

        if not isinstance(message, bytes):
            raise InvalidMessageError("Message must be bytes")

        if not isinstance(supplied_mac, str):
            return False

        try:
            supplied = bytes.fromhex(supplied_mac)
        except ValueError:
            return False

        expected = hmac.new(
            key.secret,
            message,
            hashlib.sha256
        ).digest()

        # Constant-time comparison avoids ordinary early-exit comparison.
        return hmac.compare_digest(expected, supplied)


# ============================================================
# 4. MESSAGE AUTHENTICATION
# ============================================================

@dataclass
class AuthenticatedMessage:
    message_id: str
    sender: str
    receiver: str
    payload: str
    timestamp: int
    nonce: str
    key_id: str
    mac: str


class MessageAuthenticator:

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    @staticmethod
    def canonicalize(data: dict) -> bytes:
        """
        Deterministic serialization ensures both parties authenticate
        identical bytes rather than differently formatted JSON.
        """
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False
        ).encode("utf-8")

    def create_message(
        self,
        sender: str,
        receiver: str,
        payload: str,
        key_id: str
    ) -> AuthenticatedMessage:

        if not sender or not receiver:
            raise InvalidMessageError("Sender and receiver are required")

        if not isinstance(payload, str) or not payload:
            raise InvalidMessageError("Payload cannot be empty")

        key = self.key_manager.get_key(key_id)

        message_id = secrets.token_hex(16)
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())

        content = {
            "message_id": message_id,
            "sender": sender,
            "receiver": receiver,
            "payload": payload,
            "timestamp": timestamp,
            "nonce": nonce,
            "key_id": key_id
        }

        signature = HMACService.generate(
            self.canonicalize(content),
            key
        )

        return AuthenticatedMessage(
            **content,
            mac=signature
        )

    def verify_message(
        self,
        message: AuthenticatedMessage
    ) -> bool:

        key = self.key_manager.get_key(message.key_id)

        content = {
            "message_id": message.message_id,
            "sender": message.sender,
            "receiver": message.receiver,
            "payload": message.payload,
            "timestamp": message.timestamp,
            "nonce": message.nonce,
            "key_id": message.key_id
        }

        return HMACService.verify(
            self.canonicalize(content),
            message.mac,
            key
        )


# ============================================================
# 5. REPLAY PROTECTION
# ============================================================

class ReplayProtection:

    def __init__(self, maximum_age_seconds: int = 300):
        if maximum_age_seconds <= 0:
            raise ValueError("Maximum age must be positive")

        self.maximum_age_seconds = maximum_age_seconds
        self._used_nonces: set[tuple[str, str]] = set()

    def accept(
        self,
        message: AuthenticatedMessage,
        current_time: Optional[int] = None
    ) -> None:

        now = int(time.time()) if current_time is None else current_time

        if message.timestamp > now + 30:
            raise AuthenticationError("Message timestamp is in the future")

        if now - message.timestamp > self.maximum_age_seconds:
            raise AuthenticationError("Message has expired")

        nonce_key = (message.sender, message.nonce)

        if nonce_key in self._used_nonces:
            raise ReplayError("Duplicate message nonce")

        self._used_nonces.add(nonce_key)


# ============================================================
# 6. BLOCKCHAIN TRANSACTION AUTHENTICATION
# ============================================================

@dataclass
class Transaction:
    transaction_id: str
    sender: str
    receiver: str
    amount: float
    nonce: int
    key_id: str
    mac: str = ""


class TransactionService:

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    @staticmethod
    def serialize(transaction: Transaction) -> bytes:
        data = {
            "transaction_id": transaction.transaction_id,
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "amount": transaction.amount,
            "nonce": transaction.nonce,
            "key_id": transaction.key_id
        }

        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False
        ).encode("utf-8")

    def authenticate(self, transaction: Transaction) -> Transaction:
        if not transaction.sender or not transaction.receiver:
            raise InvalidMessageError("Invalid transaction participants")

        if transaction.sender == transaction.receiver:
            raise InvalidMessageError("Self-transfer is not permitted")

        if transaction.amount <= 0 or not float(
            transaction.amount
        ) < float("inf"):
            raise InvalidMessageError("Invalid transaction amount")

        if transaction.nonce < 0:
            raise InvalidMessageError("Invalid transaction nonce")

        key = self.key_manager.get_key(transaction.key_id)

        transaction.mac = HMACService.generate(
            self.serialize(transaction),
            key
        )

        return transaction

    def verify(self, transaction: Transaction) -> bool:
        key = self.key_manager.get_key(transaction.key_id)

        return HMACService.verify(
            self.serialize(transaction),
            transaction.mac,
            key
        )


# ============================================================
# 7. BLOCKCHAIN DATA MODEL
# ============================================================

@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: int
    block_hash: str = ""


class Blockchain:

    def __init__(self):
        self.chain: list[Block] = []

        genesis = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[],
            timestamp=int(time.time())
        )

        genesis.block_hash = self.calculate_hash(genesis)
        self.chain.append(genesis)

    @staticmethod
    def calculate_hash(block: Block) -> str:
        data = {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "transactions": [
                {
                    "transaction_id": tx.transaction_id,
                    "sender": tx.sender,
                    "receiver": tx.receiver,
                    "amount": tx.amount,
                    "nonce": tx.nonce,
                    "key_id": tx.key_id,
                    "mac": tx.mac
                }
                for tx in block.transactions
            ]
        }

        serialized = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False
        ).encode("utf-8")

        return hashlib.sha256(serialized).hexdigest()

    def add_block(self, transactions: list[Transaction]) -> Block:
        if not transactions:
            raise ValueError("A non-genesis block needs transactions")

        previous = self.chain[-1]

        block = Block(
            index=len(self.chain),
            previous_hash=previous.block_hash,
            transactions=transactions,
            timestamp=int(time.time())
        )

        block.block_hash = self.calculate_hash(block)
        self.chain.append(block)

        return block

    def validate(self, transaction_service: TransactionService) -> bool:
        for index, block in enumerate(self.chain):

            if block.block_hash != self.calculate_hash(block):
                return False

            if index == 0:
                if block.previous_hash != "0" * 64:
                    return False
            else:
                previous = self.chain[index - 1]

                if block.previous_hash != previous.block_hash:
                    return False

            for transaction in block.transactions:
                if not transaction_service.verify(transaction):
                    return False

        return True


# ============================================================
# 8. EXECUTION AND TESTING
# ============================================================

def run_demo():

    print("\nMAC AND BLOCKCHAIN AUTHENTICATION")
    print("=" * 55)

    manager = KeyManager()
    manager.generate_key("node-key-001")

    key = manager.get_key("node-key-001")

    # Basic HMAC demonstration.
    message = b"Transfer 100 tokens"

    generated_mac = HMACService.generate(message, key)

    print("\n1. HMAC-SHA256")
    print("MAC:", generated_mac)
    print("Valid:", HMACService.verify(message, generated_mac, key))
    print(
        "Tampered:",
        HMACService.verify(
            b"Transfer 900 tokens",
            generated_mac,
            key
        )
    )

    # Authenticated messaging.
    print("\n2. Authenticated Messaging")

    authenticator = MessageAuthenticator(manager)

    authenticated = authenticator.create_message(
        "node-A",
        "node-B",
        "Consensus proposal",
        "node-key-001"
    )

    print("Message valid:", authenticator.verify_message(authenticated))

    # Replay detection.
    print("\n3. Replay Protection")

    replay_guard = ReplayProtection()

    replay_guard.accept(authenticated)

    try:
        replay_guard.accept(authenticated)
    except ReplayError as error:
        print("Replay blocked:", error)

    # Blockchain transaction.
    print("\n4. Blockchain Transaction")

    transaction_service = TransactionService(manager)

    transaction = Transaction(
        transaction_id="TX-1001",
        sender="wallet-A",
        receiver="wallet-B",
        amount=100.50,
        nonce=1,
        key_id="node-key-001"
    )

    transaction_service.authenticate(transaction)

    print("Transaction authenticated:",
          transaction_service.verify(transaction))

    # Block creation.
    print("\n5. Blockchain Integrity")

    blockchain = Blockchain()

    block = blockchain.add_block([transaction])

    print("Block index:", block.index)
    print("Block hash:", block.block_hash)
    print("Blockchain valid:", blockchain.validate(transaction_service))

    # Tampering demonstration.
    print("\n6. Tampering Detection")

    original_amount = transaction.amount
    transaction.amount = 9999.99

    print("Modified transaction valid:",
          transaction_service.verify(transaction))

    transaction.amount = original_amount

    print("Restored transaction valid:",
          transaction_service.verify(transaction))

    # Assertions.
    assert HMACService.verify(message, generated_mac, key)
    assert not HMACService.verify(
        b"Modified message",
        generated_mac,
        key
    )

    assert authenticator.verify_message(authenticated)
    assert transaction_service.verify(transaction)
    assert blockchain.validate(transaction_service)

    print("\nAll integrity and authentication tests passed.")


if __name__ == "__main__":
    run_demo()
