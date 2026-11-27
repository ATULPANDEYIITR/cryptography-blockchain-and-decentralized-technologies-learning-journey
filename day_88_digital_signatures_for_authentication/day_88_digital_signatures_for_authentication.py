#!/usr/bin/env python3
"""
DIGITAL SIGNATURES FOR AUTHENTICATION
Python 3.10+

Dependency:
    pip install cryptography

Demonstrates:
- Ed25519 asymmetric key generation
- Digital signing and signature verification
- Challenge-response authentication
- Nonce replay prevention
- Key registration and revocation
- Signature tampering detection
- Expiration and authentication policies
- Audit logging
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuthenticationError(Exception):
    """Raised when authentication cannot be completed."""


class KeyStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ChallengeStatus(Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"


@dataclass
class RegisteredKey:
    user_id: str
    key_id: str
    public_key: Ed25519PublicKey
    fingerprint: str
    status: KeyStatus = KeyStatus.ACTIVE
    registered_at: float = field(default_factory=time.time)


@dataclass
class Challenge:
    challenge_id: str
    user_id: str
    nonce: bytes
    issued_at: float
    expires_at: float
    status: ChallengeStatus = ChallengeStatus.ISSUED


@dataclass
class AuditEvent:
    timestamp: float
    user_id: str
    event: str
    success: bool
    reason: str


def canonical_message(
    challenge_id: str,
    user_id: str,
    nonce: bytes,
    audience: str,
) -> bytes:
    """
    Create an unambiguous, domain-separated authentication message.

    JSON fields are serialized deterministically. The audience prevents
    a signature intended for one service from being reused at another.
    """
    payload = {
        "version": 1,
        "purpose": "authentication",
        "challenge_id": challenge_id,
        "user_id": user_id,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "audience": audience,
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


class DigitalIdentity:
    """An Ed25519 identity containing private and public keys."""

    def __init__(self, user_id: str):
        if not user_id or len(user_id) > 128:
            raise ValueError("Invalid user identifier")

        self.user_id = user_id
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def export_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def fingerprint(self) -> str:
        return hashlib.sha256(self.export_public_key()).hexdigest()


class AuthenticationServer:
    """
    In-memory authentication service.

    A production implementation should persist keys, challenges,
    revocations, and audit records in durable transactional storage.
    """

    def __init__(
        self,
        audience: str = "secure-api",
        challenge_ttl: int = 120,
        max_pending_per_user: int = 5,
    ):
        if challenge_ttl <= 0:
            raise ValueError("Challenge lifetime must be positive")

        if max_pending_per_user <= 0:
            raise ValueError("Pending challenge limit must be positive")

        self.audience = audience
        self.challenge_ttl = challenge_ttl
        self.max_pending_per_user = max_pending_per_user

        self.keys: dict[str, RegisteredKey] = {}
        self.challenges: dict[str, Challenge] = {}
        self.audit_log: list[AuditEvent] = []

    def _audit(
        self,
        user_id: str,
        event: str,
        success: bool,
        reason: str,
    ) -> None:
        self.audit_log.append(
            AuditEvent(time.time(), user_id, event, success, reason)
        )

    def register_identity(self, identity: DigitalIdentity) -> str:
        key_id = secrets.token_hex(16)

        public_bytes = identity.export_public_key()
        fingerprint = hashlib.sha256(public_bytes).hexdigest()

        if fingerprint in (
            key.fingerprint for key in self.keys.values()
        ):
            raise AuthenticationError("Public key already registered")

        self.keys[key_id] = RegisteredKey(
            user_id=identity.user_id,
            key_id=key_id,
            public_key=identity.public_key,
            fingerprint=fingerprint,
        )

        self._audit(
            identity.user_id,
            "KEY_REGISTERED",
            True,
            fingerprint,
        )

        return key_id

    def revoke_key(self, key_id: str) -> None:
        key = self.keys.get(key_id)

        if key is None:
            raise AuthenticationError("Unknown key")

        if key.status == KeyStatus.REVOKED:
            return

        key.status = KeyStatus.REVOKED

        self._audit(
            key.user_id,
            "KEY_REVOKED",
            True,
            key_id,
        )

    def issue_challenge(self, user_id: str, key_id: str) -> Challenge:
        key = self.keys.get(key_id)

        if key is None or key.user_id != user_id:
            raise AuthenticationError("Identity or key not found")

        if key.status != KeyStatus.ACTIVE:
            raise AuthenticationError("Public key is revoked")

        now = time.time()

        pending = [
            challenge
            for challenge in self.challenges.values()
            if challenge.user_id == user_id
            and challenge.status == ChallengeStatus.ISSUED
            and challenge.expires_at > now
        ]

        if len(pending) >= self.max_pending_per_user:
            raise AuthenticationError("Too many pending challenges")

        challenge = Challenge(
            challenge_id=secrets.token_hex(16),
            user_id=user_id,
            nonce=secrets.token_bytes(32),
            issued_at=now,
            expires_at=now + self.challenge_ttl,
        )

        self.challenges[challenge.challenge_id] = challenge

        self._audit(
            user_id,
            "CHALLENGE_ISSUED",
            True,
            challenge.challenge_id,
        )

        return challenge

    def authenticate(
        self,
        user_id: str,
        key_id: str,
        challenge_id: str,
        signature: bytes,
    ) -> bool:
        challenge = self.challenges.get(challenge_id)
        key = self.keys.get(key_id)

        try:
            if challenge is None:
                raise AuthenticationError("Unknown challenge")

            if challenge.user_id != user_id:
                raise AuthenticationError("Challenge identity mismatch")

            if key is None or key.user_id != user_id:
                raise AuthenticationError("Unknown identity key")

            if key.status != KeyStatus.ACTIVE:
                raise AuthenticationError("Key is revoked")

            if challenge.status != ChallengeStatus.ISSUED:
                raise AuthenticationError("Challenge already consumed")

            now = time.time()

            if now > challenge.expires_at:
                challenge.status = ChallengeStatus.EXPIRED
                raise AuthenticationError("Challenge expired")

            if not isinstance(signature, bytes) or len(signature) != 64:
                raise AuthenticationError("Invalid signature length")

            message = canonical_message(
                challenge.challenge_id,
                user_id,
                challenge.nonce,
                self.audience,
            )

            try:
                key.public_key.verify(signature, message)
            except InvalidSignature as exc:
                raise AuthenticationError(
                    "Digital signature verification failed"
                ) from exc

            # Consume only after successful verification.
            challenge.status = ChallengeStatus.CONSUMED

            self._audit(
                user_id,
                "AUTHENTICATION",
                True,
                "Ed25519 signature verified",
            )

            return True

        except AuthenticationError as exc:
            self._audit(
                user_id,
                "AUTHENTICATION",
                False,
                str(exc),
            )
            raise

    def report(self) -> dict:
        return {
            "registered_keys": len(self.keys),
            "active_keys": sum(
                key.status == KeyStatus.ACTIVE
                for key in self.keys.values()
            ),
            "revoked_keys": sum(
                key.status == KeyStatus.REVOKED
                for key in self.keys.values()
            ),
            "challenges": len(self.challenges),
            "successful_authentications": sum(
                event.event == "AUTHENTICATION" and event.success
                for event in self.audit_log
            ),
            "failed_authentications": sum(
                event.event == "AUTHENTICATION" and not event.success
                for event in self.audit_log
            ),
        }


def demonstrate() -> None:
    server = AuthenticationServer(
        audience="payments-api",
        challenge_ttl=120,
    )

    alice = DigitalIdentity("alice")
    alice_key_id = server.register_identity(alice)

    print("\n1. Public-key registration")
    print("User:", alice.user_id)
    print("Key fingerprint:", alice.fingerprint())

    print("\n2. Challenge issuance")
    challenge = server.issue_challenge(
        alice.user_id,
        alice_key_id,
    )

    print("Challenge:", challenge.challenge_id)

    print("\n3. Challenge signing")

    message = canonical_message(
        challenge.challenge_id,
        alice.user_id,
        challenge.nonce,
        server.audience,
    )

    signature = alice.sign(message)

    print("Signature length:", len(signature))

    print("\n4. Authentication")

    assert server.authenticate(
        alice.user_id,
        alice_key_id,
        challenge.challenge_id,
        signature,
    )

    print("Authentication successful")

    print("\n5. Replay prevention")

    try:
        server.authenticate(
            alice.user_id,
            alice_key_id,
            challenge.challenge_id,
            signature,
        )
    except AuthenticationError as exc:
        print("Replay rejected:", exc)

    print("\n6. Tampering detection")

    second = server.issue_challenge(
        alice.user_id,
        alice_key_id,
    )

    altered_message = canonical_message(
        second.challenge_id,
        alice.user_id,
        second.nonce,
        server.audience,
    ) + b"tampered"

    altered_signature = alice.sign(altered_message)

    try:
        server.authenticate(
            alice.user_id,
            alice_key_id,
            second.challenge_id,
            altered_signature,
        )
    except AuthenticationError as exc:
        print("Tampered message rejected:", exc)

    print("\n7. Key revocation")

    server.revoke_key(alice_key_id)

    try:
        server.issue_challenge(alice.user_id, alice_key_id)
    except AuthenticationError as exc:
        print("Revoked key rejected:", exc)

    print("\n8. Operational report")
    print(json.dumps(server.report(), indent=2))

    print("\n9. Audit events")
    for event in server.audit_log:
        print(
            f"{event.event:22} "
            f"success={event.success!s:5} "
            f"reason={event.reason}"
        )


if __name__ == "__main__":
    demonstrate()
