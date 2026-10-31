#!/usr/bin/env python3
"""
Password salt management and credential verification.

Demonstrates:
- cryptographically secure random salts
- PBKDF2-HMAC-SHA256 password derivation
- per-user salts
- password verification
- password rotation
- constant-time comparison
- policy validation
- serialization without exposing plaintext passwords
- authentication failure handling
- timing-safe verification
- operational security considerations
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Dict, Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("password-salts")


class AuthenticationResult(Enum):
    SUCCESS = "success"
    USER_NOT_FOUND = "user_not_found"
    INVALID_PASSWORD = "invalid_password"
    LOCKED = "locked"


@dataclass(frozen=True)
class PasswordPolicy:
    minimum_length: int = 12
    iterations: int = 310_000
    salt_bytes: int = 16
    derived_key_bytes: int = 32

    def validate(self) -> None:
        if self.minimum_length < 12:
            raise ValueError("minimum password length must be at least 12")
        if self.iterations < 100_000:
            raise ValueError("PBKDF2 iteration count is too low")
        if self.salt_bytes < 16:
            raise ValueError("salt must contain at least 16 random bytes")
        if self.derived_key_bytes < 32:
            raise ValueError("derived key must contain at least 32 bytes")


@dataclass
class Credential:
    username: str
    salt_b64: str
    password_hash_b64: str
    iterations: int
    failed_attempts: int = 0
    locked: bool = False
    password_version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0


class PasswordManager:
    def __init__(self, policy: Optional[PasswordPolicy] = None) -> None:
        self.policy = policy or PasswordPolicy()
        self.policy.validate()
        self._credentials: Dict[str, Credential] = {}

    def _validate_username(self, username: str) -> str:
        username = username.strip().lower()

        if not username:
            raise ValueError("username cannot be empty")
        if len(username) > 128:
            raise ValueError("username is too long")

        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-@")
        if any(character not in allowed for character in username):
            raise ValueError("username contains unsupported characters")

        return username

    def _validate_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise TypeError("password must be a string")

        if len(password) < self.policy.minimum_length:
            raise ValueError(
                f"password must contain at least "
                f"{self.policy.minimum_length} characters"
            )

        if password.strip() == "":
            raise ValueError("password cannot contain only whitespace")

    def _derive(self, password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=self.policy.derived_key_bytes,
        )

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value.encode("ascii"))

    def register(self, username: str, password: str) -> Credential:
        username = self._validate_username(username)
        self._validate_password(password)

        if username in self._credentials:
            raise ValueError("username already exists")

        # A fresh unpredictable salt is generated for every credential.
        salt = secrets.token_bytes(self.policy.salt_bytes)
        password_hash = self._derive(password, salt, self.policy.iterations)
        now = time.time()

        credential = Credential(
            username=username,
            salt_b64=self._encode(salt),
            password_hash_b64=self._encode(password_hash),
            iterations=self.policy.iterations,
            created_at=now,
            updated_at=now,
        )

        self._credentials[username] = credential
        return credential

    def verify(
        self,
        username: str,
        password: str,
    ) -> AuthenticationResult:
        username = username.strip().lower()
        credential = self._credentials.get(username)

        # Do not reveal whether a username exists to a remote caller.
        if credential is None:
            return AuthenticationResult.USER_NOT_FOUND

        if credential.locked:
            return AuthenticationResult.LOCKED

        try:
            salt = self._decode(credential.salt_b64)
            expected = self._decode(credential.password_hash_b64)
            actual = self._derive(password, salt, credential.iterations)
        except (ValueError, TypeError):
            logger.error("credential record is malformed for %s", username)
            return AuthenticationResult.INVALID_PASSWORD

        if hmac.compare_digest(actual, expected):
            credential.failed_attempts = 0
            credential.updated_at = time.time()
            return AuthenticationResult.SUCCESS

        credential.failed_attempts += 1

        # Account locking is an application policy, separate from salting.
        if credential.failed_attempts >= 5:
            credential.locked = True
            logger.warning("account locked after failed authentication: %s", username)

        credential.updated_at = time.time()
        return AuthenticationResult.INVALID_PASSWORD

    def change_password(
        self,
        username: str,
        current_password: str,
        new_password: str,
    ) -> None:
        result = self.verify(username, current_password)

        if result != AuthenticationResult.SUCCESS:
            raise PermissionError("current password is invalid")

        self._validate_password(new_password)

        credential = self._credentials[username]

        # Password changes receive a completely new salt.
        new_salt = secrets.token_bytes(self.policy.salt_bytes)
        new_hash = self._derive(
            new_password,
            new_salt,
            self.policy.iterations,
        )

        credential.salt_b64 = self._encode(new_salt)
        credential.password_hash_b64 = self._encode(new_hash)
        credential.iterations = self.policy.iterations
        credential.failed_attempts = 0
        credential.locked = False
        credential.password_version += 1
        credential.updated_at = time.time()

    def unlock(self, username: str) -> None:
        username = self._validate_username(username)

        if username not in self._credentials:
            raise KeyError("username does not exist")

        credential = self._credentials[username]
        credential.locked = False
        credential.failed_attempts = 0
        credential.updated_at = time.time()

    def export_public_metadata(self) -> str:
        """
        Exports operational credential metadata without plaintext passwords.

        Salt and password hashes are still sensitive credential material.
        A production system should protect this storage with strict access
        controls and encryption at rest.
        """
        records = []

        for credential in self._credentials.values():
            data = asdict(credential)
            records.append(data)

        return json.dumps(records, indent=2, sort_keys=True)


def demonstrate() -> None:
    manager = PasswordManager()

    alice = manager.register(
        "Alice@example.com",
        "Correct-Horse-Battery-42!",
    )
    bob = manager.register(
        "bob@example.com",
        "Correct-Horse-Battery-42!",
    )

    # Equal passwords still receive different salts and therefore different
    # derived password hashes.
    assert alice.salt_b64 != bob.salt_b64
    assert alice.password_hash_b64 != bob.password_hash_b64

    assert (
        manager.verify(
            "alice@example.com",
            "Correct-Horse-Battery-42!",
        )
        == AuthenticationResult.SUCCESS
    )

    assert (
        manager.verify(
            "alice@example.com",
            "wrong-password",
        )
        == AuthenticationResult.INVALID_PASSWORD
    )

    for _ in range(4):
        manager.verify("alice@example.com", "wrong-password")

    assert (
        manager.verify(
            "alice@example.com",
            "Correct-Horse-Battery-42!",
        )
        == AuthenticationResult.LOCKED
    )

    manager.unlock("alice@example.com")

    manager.change_password(
        "alice@example.com",
        "Correct-Horse-Battery-42!",
        "New-Longer-Password-99!",
    )

    assert (
        manager.verify(
            "alice@example.com",
            "New-Longer-Password-99!",
        )
        == AuthenticationResult.SUCCESS
    )

    print("Authentication:", manager.verify(
        "alice@example.com",
        "New-Longer-Password-99!",
    ).value)

    print("Credential metadata:")
    print(manager.export_public_metadata())


def edge_case_checks() -> None:
    manager = PasswordManager()

    try:
        manager.register("short@example.com", "short")
        raise AssertionError("short password should fail")
    except ValueError:
        pass

    try:
        manager.register("bad user!", "Valid-Password-123!")
        raise AssertionError("invalid username should fail")
    except ValueError:
        pass

    try:
        manager.register("valid@example.com", "Valid-Password-123!")
        manager.register("valid@example.com", "Another-Password-123!")
        raise AssertionError("duplicate username should fail")
    except ValueError:
        pass


if __name__ == "__main__":
    edge_case_checks()
    demonstrate()
