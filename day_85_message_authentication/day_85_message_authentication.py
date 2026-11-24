#!/usr/bin/env python3
"""
MESSAGE AUTHENTICATION
HMAC-SHA256, message integrity, sender authentication,
replay protection, timestamp validation, and key rotation.

Requirements: Python 3.10+
Dependencies: Python standard library only.
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
# 1. DOMAIN TYPES
# ============================================================

class AuthenticationStatus(Enum):
    AUTHENTICATED = "authenticated"
    INVALID_SIGNATURE = "invalid_signature"
    UNKNOWN_KEY = "unknown_key"
    EXPIRED_MESSAGE = "expired_message"
    REPLAY_DETECTED = "replay_detected"
    INVALID_MESSAGE = "invalid_message"
    REVOKED_KEY = "revoked_key"


class AuthenticationError(Exception):
    pass


class KeyManagementError(Exception):
    pass


@dataclass(frozen=True)
class Message:
    sender: str
    receiver: str
    message_id: str
    timestamp: int
    payload: str
    key_id: str
    signature: str


@dataclass
class VerificationResult:
    status: AuthenticationStatus
    sender: Optional[str] = None
    message_id: Optional[str] = None
    detail: str = ""

    @property
    def authenticated(self) -> bool:
        return self.status == AuthenticationStatus.AUTHENTICATED


@dataclass
class AuthenticationKey:
    key_id: str
    secret: bytes = field(repr=False)
    owner: str = ""
    active: bool = True
    created_at: int = field(default_factory=lambda: int(time.time()))


# ============================================================
# 2. CANONICAL MESSAGE SERIALIZATION
# ============================================================

class MessageSerializer:
    """
    Produces deterministic bytes before calculating an HMAC.

    Canonical serialization prevents ambiguity caused by
    different field ordering, whitespace, and encoding.
    """

    REQUIRED_FIELDS = {
        "sender",
        "receiver",
        "message_id",
        "timestamp",
        "payload",
        "key_id",
    }

    @staticmethod
    def validate_fields(data: dict) -> None:
        if set(data) != MessageSerializer.REQUIRED_FIELDS:
            raise AuthenticationError("Unexpected or missing fields")

        for field_name in (
            "sender",
            "receiver",
            "message_id",
            "payload",
            "key_id",
        ):
            value = data[field_name]

            if not isinstance(value, str) or not value:
                raise AuthenticationError(
                    f"Invalid field: {field_name}"
                )

            if len(value.encode("utf-8")) > 65536:
                raise AuthenticationError(
                    f"Field too large: {field_name}"
                )

        timestamp = data["timestamp"]

        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise AuthenticationError("Timestamp must be an integer")

        if timestamp <= 0:
            raise AuthenticationError("Invalid timestamp")

    @classmethod
    def serialize(cls, message: Message) -> bytes:
        data = {
            "sender": message.sender,
            "receiver": message.receiver,
            "message_id": message.message_id,
            "timestamp": message.timestamp,
            "payload": message.payload,
            "key_id": message.key_id,
        }

        cls.validate_fields(data)

        canonical = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return canonical.encode("utf-8")


# ============================================================
# 3. HMAC ENGINE
# ============================================================

class HMACEngine:
    """
    HMAC-SHA256 provides message authentication and integrity.

    It does not provide confidentiality or non-repudiation.
    """

    ALGORITHM = "sha256"

    @staticmethod
    def generate_signature(secret: bytes, message: bytes) -> str:
        if len(secret) < 32:
            raise KeyManagementError(
                "HMAC keys must contain at least 32 random bytes"
            )

        return hmac.new(
            secret,
            message,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_signature(
        secret: bytes,
        message: bytes,
        supplied_signature: str,
    ) -> bool:

        if not isinstance(supplied_signature, str):
            return False

        if len(supplied_signature) != 64:
            return False

        try:
            bytes.fromhex(supplied_signature)
        except ValueError:
            return False

        expected = HMACEngine.generate_signature(
            secret,
            message,
        )

        # Constant-time comparison reduces timing leakage.
        return hmac.compare_digest(
            expected,
            supplied_signature.lower(),
        )


# ============================================================
# 4. KEY MANAGEMENT
# ============================================================

class KeyManager:

    def __init__(self):
        self._keys: dict[str, AuthenticationKey] = {}

    def generate_key(self, owner: str) -> AuthenticationKey:
        if not owner:
            raise KeyManagementError("Owner cannot be empty")

        key = AuthenticationKey(
            key_id=secrets.token_hex(8),
            secret=secrets.token_bytes(32),
            owner=owner,
        )

        self._keys[key.key_id] = key
        return key

    def get_key(self, key_id: str) -> Optional[AuthenticationKey]:
        return self._keys.get(key_id)

    def rotate_key(self, old_key_id: str) -> AuthenticationKey:
        old_key = self.get_key(old_key_id)

        if old_key is None or not old_key.active:
            raise KeyManagementError("Old key is unavailable")

        new_key = self.generate_key(old_key.owner)

        # New messages use the new key. Existing messages
        # cannot use the revoked old key after this operation.
        old_key.active = False

        return new_key

    def revoke_key(self, key_id: str) -> None:
        key = self.get_key(key_id)

        if key is None:
            raise KeyManagementError("Unknown key")

        key.active = False


# ============================================================
# 5. REPLAY PROTECTION
# ============================================================

class ReplayProtection:

    def __init__(self, retention_seconds: int = 600):
        if retention_seconds <= 0:
            raise ValueError("Retention must be positive")

        self.retention_seconds = retention_seconds
        self._seen: dict[tuple[str, str], int] = {}

    def register(
        self,
        sender: str,
        message_id: str,
        current_time: int,
    ) -> bool:

        self.cleanup(current_time)

        identifier = (sender, message_id)

        if identifier in self._seen:
            return False

        self._seen[identifier] = (
            current_time + self.retention_seconds
        )

        return True

    def cleanup(self, current_time: int) -> None:
        expired = [
            identifier
            for identifier, expiry in self._seen.items()
            if expiry <= current_time
        ]

        for identifier in expired:
            del self._seen[identifier]


# ============================================================
# 6. MESSAGE AUTHENTICATION SERVICE
# ============================================================

class MessageAuthenticationService:

    def __init__(
        self,
        key_manager: KeyManager,
        replay_protection: ReplayProtection,
        allowed_clock_skew: int = 60,
        maximum_payload_bytes: int = 65536,
    ):

        if allowed_clock_skew < 0:
            raise ValueError("Clock skew cannot be negative")

        self.key_manager = key_manager
        self.replay_protection = replay_protection
        self.allowed_clock_skew = allowed_clock_skew
        self.maximum_payload_bytes = maximum_payload_bytes

    def create_message(
        self,
        sender: str,
        receiver: str,
        payload: str,
        key_id: str,
        current_time: Optional[int] = None,
    ) -> Message:

        key = self.key_manager.get_key(key_id)

        if key is None or not key.active:
            raise KeyManagementError("Signing key unavailable")

        if key.owner != sender:
            raise KeyManagementError(
                "Sender does not own the signing key"
            )

        if not sender or not receiver:
            raise AuthenticationError("Sender and receiver are required")

        if not isinstance(payload, str):
            raise AuthenticationError("Payload must be text")

        if len(payload.encode("utf-8")) > self.maximum_payload_bytes:
            raise AuthenticationError("Payload exceeds maximum size")

        message = Message(
            sender=sender,
            receiver=receiver,
            message_id=secrets.token_hex(16),
            timestamp=(
                int(time.time())
                if current_time is None
                else current_time
            ),
            payload=payload,
            key_id=key_id,
            signature="",
        )

        signature = HMACEngine.generate_signature(
            key.secret,
            MessageSerializer.serialize(message),
        )

        return Message(
            sender=message.sender,
            receiver=message.receiver,
            message_id=message.message_id,
            timestamp=message.timestamp,
            payload=message.payload,
            key_id=message.key_id,
            signature=signature,
        )

    def verify_message(
        self,
        message: Message,
        current_time: Optional[int] = None,
    ) -> VerificationResult:

        now = int(time.time()) if current_time is None else current_time

        def failure(status, detail):
            return VerificationResult(
                status=status,
                sender=message.sender,
                message_id=message.message_id,
                detail=detail,
            )

        try:
            serialized = MessageSerializer.serialize(message)

        except (AuthenticationError, TypeError, AttributeError) as exc:
            return failure(
                AuthenticationStatus.INVALID_MESSAGE,
                str(exc),
            )

        if len(message.payload.encode("utf-8")) > self.maximum_payload_bytes:
            return failure(
                AuthenticationStatus.INVALID_MESSAGE,
                "Payload exceeds maximum size",
            )

        if abs(now - message.timestamp) > self.allowed_clock_skew:
            return failure(
                AuthenticationStatus.EXPIRED_MESSAGE,
                "Timestamp outside the permitted clock window",
            )

        key = self.key_manager.get_key(message.key_id)

        if key is None:
            return failure(
                AuthenticationStatus.UNKNOWN_KEY,
                "Signing key not found",
            )

        if not key.active:
            return failure(
                AuthenticationStatus.REVOKED_KEY,
                "Signing key has been revoked",
            )

        if key.owner != message.sender:
            return failure(
                AuthenticationStatus.INVALID_SIGNATURE,
                "Sender does not match key ownership",
            )

        if not HMACEngine.verify_signature(
            key.secret,
            serialized,
            message.signature,
        ):
            return failure(
                AuthenticationStatus.INVALID_SIGNATURE,
                "HMAC verification failed",
            )

        # Register only after successful cryptographic verification.
        # Production systems must make this operation atomic across
        # all application instances.
        if not self.replay_protection.register(
            message.sender,
            message.message_id,
            now,
        ):
            return failure(
                AuthenticationStatus.REPLAY_DETECTED,
                "Message identifier has already been processed",
            )

        return VerificationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            sender=message.sender,
            message_id=message.message_id,
            detail="Message authenticated successfully",
        )


# ============================================================
# 7. TESTING AND DEMONSTRATION
# ============================================================

def run_tests() -> None:

    keys = KeyManager()
    replay = ReplayProtection()
    service = MessageAuthenticationService(
        keys,
        replay,
        allowed_clock_skew=60,
    )

    now = int(time.time())

    alice_key = keys.generate_key("alice")

    print("\nMESSAGE AUTHENTICATION DEMONSTRATION")
    print("=" * 55)

    original = service.create_message(
        sender="alice",
        receiver="bob",
        payload="Transfer request: INR 5000",
        key_id=alice_key.key_id,
        current_time=now,
    )

    result = service.verify_message(original, now)

    assert result.authenticated
    print("1. Valid message:", result.status.value)

    replay_result = service.verify_message(original, now)

    assert replay_result.status == AuthenticationStatus.REPLAY_DETECTED
    print("2. Replay attempt:", replay_result.status.value)

    tampered = Message(
        sender=original.sender,
        receiver=original.receiver,
        message_id=original.message_id,
        timestamp=original.timestamp,
        payload="Transfer request: INR 500000",
        key_id=original.key_id,
        signature=original.signature,
    )

    tampered_result = service.verify_message(
        tampered,
        now,
    )

    assert (
        tampered_result.status
        == AuthenticationStatus.INVALID_SIGNATURE
    )

    print("3. Modified payload:", tampered_result.status.value)

    expired = service.create_message(
        sender="alice",
        receiver="bob",
        payload="Old transaction",
        key_id=alice_key.key_id,
        current_time=now - 300,
    )

    expired_result = service.verify_message(expired, now)

    assert (
        expired_result.status
        == AuthenticationStatus.EXPIRED_MESSAGE
    )

    print("4. Expired message:", expired_result.status.value)

    unknown = Message(
        sender="alice",
        receiver="bob",
        message_id=secrets.token_hex(16),
        timestamp=now,
        payload="Unknown key message",
        key_id="unknown-key",
        signature="0" * 64,
    )

    unknown_result = service.verify_message(unknown, now)

    assert unknown_result.status == AuthenticationStatus.UNKNOWN_KEY

    print("5. Unknown key:", unknown_result.status.value)

    new_key = keys.rotate_key(alice_key.key_id)

    assert not alice_key.active
    assert new_key.active

    rotated_message = service.create_message(
        sender="alice",
        receiver="bob",
        payload="Message signed using rotated key",
        key_id=new_key.key_id,
        current_time=now,
    )

    assert service.verify_message(
        rotated_message,
        now,
    ).authenticated

    print("6. Key rotation: successful")

    revoked_message = service.create_message(
        sender="alice",
        receiver="bob",
        payload="Test revoked key",
        key_id=new_key.key_id,
        current_time=now,
    )

    keys.revoke_key(new_key.key_id)

    revoked_result = service.verify_message(
        revoked_message,
        now,
    )

    assert revoked_result.status == AuthenticationStatus.REVOKED_KEY

    print("7. Revoked key:", revoked_result.status.value)

    print("\nAll authentication tests passed.")


if __name__ == "__main__":
    run_tests()
