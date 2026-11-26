#!/usr/bin/env python3
"""
HMAC in Cryptography and Blockchain
------------------------------------
Demonstrates:
1. HMAC-SHA256 message authentication.
2. Key management and key identifiers.
3. Blockchain transaction authentication.
4. Canonical transaction serialization.
5. Hash-linked block construction.
6. Nonce-based replay protection.
7. Chain integrity validation.
8. Tampering detection and key rotation.

Python 3.10+
No external dependencies.
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
# 1. CONSTANTS AND DOMAIN TYPES
# ============================================================

HASH_ALGORITHM = "sha256"
HMAC_ALGORITHM = "HMAC-SHA256"
ZERO_HASH = "0" * 64


class AuthenticationError(Exception):
    """Raised when message authentication fails."""


class ValidationError(Exception):
    """Raised when transaction or block validation fails."""


class ReplayError(Exception):
    """Raised when a transaction nonce has already been used."""


class KeyStatus(Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


# ============================================================
# 2. CANONICAL SERIALIZATION
# ============================================================

def canonical_json(data: dict) -> bytes:
    """
    Produce deterministic JSON bytes.

    Canonical serialization ensures that equivalent transaction
    structures generate identical authenticated messages.
    """
    try:
        serialized = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False
        )
        return serialized.encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"Transaction serialization failed: {exc}"
        ) from exc


# ============================================================
# 3. HASHING AND HMAC
# ============================================================

def sha256(data: bytes) -> str:
    """Calculate a SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def calculate_hmac(message: bytes, secret_key: bytes) -> str:
    """
    Calculate HMAC-SHA256.

    HMAC uses:
        inner = H((K xor ipad) || message)
        outer = H((K xor opad) || inner)

    The standard library handles block-size normalization,
    key processing and cryptographic operations.
    """
    if not isinstance(secret_key, bytes):
        raise TypeError("Secret key must be bytes.")

    if len(secret_key) < 32:
        raise ValidationError(
            "Use at least 32 bytes of key material."
        )

    return hmac.new(
        secret_key,
        message,
        hashlib.sha256
    ).hexdigest()


def verify_hmac(
    message: bytes,
    supplied_tag: str,
    secret_key: bytes
) -> bool:
    """Verify a tag using constant-time comparison."""
    if not isinstance(supplied_tag, str):
        return False

    try:
        expected = calculate_hmac(message, secret_key)
    except (ValidationError, TypeError):
        return False

    return hmac.compare_digest(expected, supplied_tag)


# ============================================================
# 4. KEY MANAGEMENT
# ============================================================

@dataclass
class KeyRecord:
    key_id: str
    secret: bytes = field(repr=False)
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: float = field(default_factory=time.time)


class KeyManager:
    """
    Educational key registry.

    Production systems should store key material in a KMS,
    HSM or dedicated secrets-management service.
    """

    def __init__(self):
        self._keys: dict[str, KeyRecord] = {}

    def generate_key(self, key_id: str) -> KeyRecord:
        if not key_id or key_id in self._keys:
            raise ValidationError("Invalid or duplicate key ID.")

        record = KeyRecord(
            key_id=key_id,
            secret=secrets.token_bytes(32)
        )

        self._keys[key_id] = record
        return record

    def get_key(self, key_id: str) -> KeyRecord:
        record = self._keys.get(key_id)

        if record is None:
            raise AuthenticationError("Unknown key identifier.")

        if record.status == KeyStatus.REVOKED:
            raise AuthenticationError("Key has been revoked.")

        return record

    def rotate_key(self, old_key_id: str, new_key_id: str):
        old = self.get_key(old_key_id)

        if old.status != KeyStatus.ACTIVE:
            raise ValidationError("Only active keys can be rotated.")

        old.status = KeyStatus.RETIRED
        return self.generate_key(new_key_id)

    def revoke_key(self, key_id: str):
        self.get_key(key_id).status = KeyStatus.REVOKED

    def sign(self, key_id: str, message: bytes) -> str:
        record = self.get_key(key_id)

        if record.status != KeyStatus.ACTIVE:
            raise AuthenticationError("Key is not active for signing.")

        return calculate_hmac(message, record.secret)

    def verify(
        self,
        key_id: str,
        message: bytes,
        supplied_tag: str
    ) -> bool:
        record = self.get_key(key_id)

        return verify_hmac(
            message,
            supplied_tag,
            record.secret
        )


# ============================================================
# 5. BLOCKCHAIN TRANSACTION MODEL
# ============================================================

@dataclass
class Transaction:
    transaction_id: str
    sender: str
    receiver: str
    amount: int
    nonce: int
    timestamp: int
    key_id: str
    signature: Optional[str] = None

    def unsigned_payload(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "key_id": self.key_id
        }

    def serialize(self) -> bytes:
        return canonical_json(self.unsigned_payload())

    def to_dict(self) -> dict:
        return {
            **self.unsigned_payload(),
            "signature": self.signature
        }


class TransactionFactory:

    @staticmethod
    def create(
        sender: str,
        receiver: str,
        amount: int,
        nonce: int,
        key_id: str
    ) -> Transaction:

        if not sender or not receiver:
            raise ValidationError("Sender and receiver are required.")

        if sender == receiver:
            raise ValidationError("Self-transfers are not supported.")

        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValidationError("Amount must be an integer.")

        if amount <= 0:
            raise ValidationError("Amount must be positive.")

        if isinstance(nonce, bool) or not isinstance(nonce, int):
            raise ValidationError("Nonce must be an integer.")

        if nonce < 0:
            raise ValidationError("Nonce cannot be negative.")

        return Transaction(
            transaction_id=secrets.token_hex(16),
            sender=sender,
            receiver=receiver,
            amount=amount,
            nonce=nonce,
            timestamp=int(time.time()),
            key_id=key_id
        )


# ============================================================
# 6. TRANSACTION AUTHENTICATION
# ============================================================

class TransactionAuthenticator:

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def sign(self, transaction: Transaction):
        transaction.signature = self.key_manager.sign(
            transaction.key_id,
            transaction.serialize()
        )

    def verify(self, transaction: Transaction) -> bool:
        if not transaction.signature:
            return False

        return self.key_manager.verify(
            transaction.key_id,
            transaction.serialize(),
            transaction.signature
        )


# ============================================================
# 7. BLOCKCHAIN BLOCK
# ============================================================

@dataclass
class Block:
    index: int
    previous_hash: str
    timestamp: int
    transactions: list[Transaction]
    nonce: int = 0
    block_hash: str = ""

    def calculate_hash(self) -> str:
        payload = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "transactions": [
                transaction.to_dict()
                for transaction in self.transactions
            ]
        }

        return sha256(canonical_json(payload))


# ============================================================
# 8. BLOCKCHAIN LEDGER
# ============================================================

class Blockchain:

    def __init__(self, authenticator: TransactionAuthenticator):
        self.authenticator = authenticator
        self.blocks: list[Block] = []
        self.used_nonces: dict[str, set[int]] = {}

        genesis = Block(
            index=0,
            previous_hash=ZERO_HASH,
            timestamp=int(time.time()),
            transactions=[]
        )

        genesis.block_hash = genesis.calculate_hash()
        self.blocks.append(genesis)

    def submit_transaction(self, transaction: Transaction):
        if not self.authenticator.verify(transaction):
            raise AuthenticationError(
                "Transaction HMAC verification failed."
            )

        sender_nonces = self.used_nonces.get(
            transaction.sender, set()
        )

        if transaction.nonce in sender_nonces:
            raise ReplayError("Transaction nonce already used.")

        if any(
            tx.transaction_id == transaction.transaction_id
            for block in self.blocks
            for tx in block.transactions
        ):
            raise ValidationError("Duplicate transaction ID.")

        # A nonce is consumed only after successful block inclusion
        # in this simplified implementation.
        self._pending.append(transaction) if hasattr(
            self, "_pending"
        ) else None

        if not hasattr(self, "_pending"):
            self._pending = []

        self._pending.append(transaction)

    def mine_block(self) -> Block:
        if not self._pending:
            raise ValidationError("No pending transactions.")

        previous = self.blocks[-1]

        block = Block(
            index=len(self.blocks),
            previous_hash=previous.block_hash,
            timestamp=int(time.time()),
            transactions=list(self._pending)
        )

        block.block_hash = block.calculate_hash()

        # Validate before committing state.
        for transaction in block.transactions:
            if not self.authenticator.verify(transaction):
                raise AuthenticationError(
                    "Transaction authentication failed during mining."
                )

            if transaction.nonce in self.used_nonces.get(
                transaction.sender, set()
            ):
                raise ReplayError("Duplicate nonce during mining.")

        self.blocks.append(block)

        for transaction in block.transactions:
            self.used_nonces.setdefault(
                transaction.sender, set()
            ).add(transaction.nonce)

        self._pending.clear()
        return block

    def validate_chain(self) -> bool:
        if not self.blocks:
            return False

        for index, block in enumerate(self.blocks):

            if block.index != index:
                return False

            if block.calculate_hash() != block.block_hash:
                return False

            if index == 0:
                if block.previous_hash != ZERO_HASH:
                    return False
                continue

            previous = self.blocks[index - 1]

            if block.previous_hash != previous.block_hash:
                return False

            for transaction in block.transactions:
                if not self.authenticator.verify(transaction):
                    return False

        return True

    def balance(self, address: str) -> int:
        """
        Calculate balance from authenticated ledger history.

        This simplified example starts balances at zero.
        """
        result = 0

        for block in self.blocks:
            for transaction in block.transactions:
                if transaction.sender == address:
                    result -= transaction.amount

                if transaction.receiver == address:
                    result += transaction.amount

        return result

    def audit(self):
        print("\nBLOCKCHAIN AUDIT")

        for block in self.blocks:
            print(
                f"Block {block.index} | "
                f"Transactions: {len(block.transactions)} | "
                f"Hash: {block.block_hash[:20]}..."
            )


# ============================================================
# 9. DEMONSTRATION
# ============================================================

def main():
    print("=" * 65)
    print("HMAC-SHA256 AND BLOCKCHAIN DEMONSTRATION")
    print("=" * 65)

    keys = KeyManager()
    keys.generate_key("wallet-key-v1")

    authenticator = TransactionAuthenticator(keys)
    ledger = Blockchain(authenticator)

    # Create and authenticate a transaction.
    transaction = TransactionFactory.create(
        sender="ALICE",
        receiver="BOB",
        amount=250,
        nonce=1,
        key_id="wallet-key-v1"
    )

    authenticator.sign(transaction)

    print("\n1. TRANSACTION AUTHENTICATION")
    print("Transaction ID:", transaction.transaction_id)
    print("HMAC:", transaction.signature)
    print("Valid:", authenticator.verify(transaction))

    # Submit and mine.
    print("\n2. BLOCKCHAIN PROCESSING")
    ledger.submit_transaction(transaction)

    block = ledger.mine_block()

    print("Block index:", block.index)
    print("Block hash:", block.block_hash)
    print("Chain valid:", ledger.validate_chain())

    # Balance calculation.
    print("\n3. LEDGER BALANCES")
    print("Alice:", ledger.balance("ALICE"))
    print("Bob:", ledger.balance("BOB"))

    # Replay attack.
    print("\n4. REPLAY PROTECTION")

    try:
        ledger.submit_transaction(transaction)
    except (ReplayError, AuthenticationError, ValidationError) as exc:
        print("Replay rejected:", exc)

    # Tampering.
    print("\n5. TAMPERING DETECTION")

    original_amount = transaction.amount
    transaction.amount = 9999

    print(
        "Modified transaction authenticated:",
        authenticator.verify(transaction)
    )

    transaction.amount = original_amount

    print("Restored transaction:", authenticator.verify(transaction))

    # Key rotation.
    print("\n6. KEY ROTATION")

    new_key = keys.rotate_key(
        "wallet-key-v1",
        "wallet-key-v2"
    )

    print("New key ID:", new_key.key_id)
    print("Old key status:", keys.get_key("wallet-key-v1").status.value)

    new_transaction = TransactionFactory.create(
        sender="BOB",
        receiver="CHARLIE",
        amount=100,
        nonce=1,
        key_id="wallet-key-v2"
    )

    authenticator.sign(new_transaction)
    print("New transaction authenticated:",
          authenticator.verify(new_transaction))

    # A retired key can verify existing signatures, but cannot sign.
    print("\n7. HISTORICAL SIGNATURE VERIFICATION")
    print(
        "Old transaction verification:",
        authenticator.verify(transaction)
    )

    ledger.audit()

    print("\n8. FINAL VALIDATION")
    print("Blockchain integrity:", ledger.validate_chain())

    # Additional edge-case assertions.
    assert verify_hmac(
        b"message",
        calculate_hmac(b"message", new_key.secret),
        new_key.secret
    )

    assert not verify_hmac(
        b"modified",
        calculate_hmac(b"message", new_key.secret),
        new_key.secret
    )

    print("All demonstration assertions passed.")


if __name__ == "__main__":
    main()
