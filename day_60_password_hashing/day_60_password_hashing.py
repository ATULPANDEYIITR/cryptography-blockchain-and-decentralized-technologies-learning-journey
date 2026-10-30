#!/usr/bin/env python3
"""
Secure Password Hashing and Authentication
PBKDF2-HMAC-SHA256 implementation using Python standard libraries.

Features:
- Random, unique password salts
- Versioned password-hash encoding
- Adaptive iteration counts
- Constant-time verification
- Unicode NFC normalization
- Password policy validation
- Legacy credential upgrades
- Account-level login throttling
- Thread-safe account operations
- Automated security assertions

Production configuration should prefer Argon2id where available.
PBKDF2-HMAC-SHA256 is used here for portability and FIPS-oriented deployments.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
import unicodedata

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


CURRENT_ITERATIONS = 600_000
MIN_STORED_ITERATIONS = 100_000
MAX_STORED_ITERATIONS = 2_000_000
SALT_LENGTH = 16
KEY_LENGTH = 32
ALGORITHM = "pbkdf2-sha256"


class AuthenticationResult(Enum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"


class PasswordPolicyError(ValueError):
    """Raised when a proposed password violates security policy."""


class DuplicateAccountError(ValueError):
    """Raised when an account identifier already exists."""


@dataclass(frozen=True)
class PasswordPolicy:
    minimum_length: int = 15
    maximum_length: int = 256
    maximum_bytes: int = 1024

    blocked_passwords: frozenset[str] = frozenset({
        "password",
        "password123",
        "123456789012345",
        "qwerty123456789",
        "letmein123456",
    })

    def validate(self, password: str, username: str = "") -> str:
        if not isinstance(password, str):
            raise PasswordPolicyError("Password must be a string.")

        normalized = unicodedata.normalize("NFC", password)

        if "\x00" in normalized:
            raise PasswordPolicyError("Null characters are not permitted.")

        if not self.minimum_length <= len(normalized) <= self.maximum_length:
            raise PasswordPolicyError("Password length is outside permitted limits.")

        if len(normalized.encode("utf-8")) > self.maximum_bytes:
            raise PasswordPolicyError("Password exceeds the byte limit.")

        folded = normalized.casefold()

        if folded in self.blocked_passwords:
            raise PasswordPolicyError("Password appears on the blocked-password list.")

        if username and folded == username.casefold():
            raise PasswordPolicyError("Password cannot equal the account identifier.")

        return normalized


class PasswordHasher:
    """
    Creates and verifies adaptive password hashes.

    Encoded format:
    pbkdf2-sha256$iterations$salt_base64url$derived_key_base64url
    """

    def __init__(self, iterations: int = CURRENT_ITERATIONS):
        if not MIN_STORED_ITERATIONS <= iterations <= MAX_STORED_ITERATIONS:
            raise ValueError("Unsupported PBKDF2 iteration count.")

        self.iterations = iterations

    @staticmethod
    def _encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _decode(value: str) -> bytes:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("Invalid Base64URL encoding.")

        padded = value + "=" * (-len(value) % 4)

        return base64.b64decode(
            padded,
            altchars=b"-_",
            validate=True,
        )

    @staticmethod
    def _derive(
        password: str,
        salt: bytes,
        iterations: int,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=KEY_LENGTH,
        )

    def hash_password(self, password: str) -> str:
        normalized = unicodedata.normalize("NFC", password)
        salt = secrets.token_bytes(SALT_LENGTH)

        derived_key = self._derive(
            normalized,
            salt,
            self.iterations,
        )

        return "$".join((
            ALGORITHM,
            str(self.iterations),
            self._encode(salt),
            self._encode(derived_key),
        ))

    @staticmethod
    def parse(encoded_hash: str) -> tuple[int, bytes, bytes]:
        parts = encoded_hash.split("$")

        if len(parts) != 4 or parts[0] != ALGORITHM:
            raise ValueError("Unsupported password hash format.")

        iteration_text = parts[1]

        if not iteration_text.isdigit():
            raise ValueError("Invalid iteration count.")

        iterations = int(iteration_text)

        if not MIN_STORED_ITERATIONS <= iterations <= MAX_STORED_ITERATIONS:
            raise ValueError("Stored iteration count is outside permitted limits.")

        salt = PasswordHasher._decode(parts[2])
        expected = PasswordHasher._decode(parts[3])

        if not SALT_LENGTH <= len(salt) <= 64:
            raise ValueError("Invalid salt length.")

        if len(expected) != KEY_LENGTH:
            raise ValueError("Invalid derived-key length.")

        return iterations, salt, expected

    def verify(self, password: str, encoded_hash: str) -> bool:
        try:
            normalized = unicodedata.normalize("NFC", password)

            if len(normalized.encode("utf-8")) > 1024:
                return False

            iterations, salt, expected = self.parse(encoded_hash)

            actual = self._derive(
                normalized,
                salt,
                iterations,
            )

            return hmac.compare_digest(actual, expected)

        except (ValueError, TypeError, OverflowError):
            # Malformed or unsupported credentials never authenticate.
            return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        try:
            iterations, _, _ = self.parse(encoded_hash)
            return iterations < self.iterations
        except ValueError:
            return True


@dataclass
class Account:
    username: str
    password_hash: str
    enabled: bool = True
    failed_attempts: int = 0
    locked_until: float = 0.0
    lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )


class PasswordAuthenticationService:
    """
    Repository-style authentication service.

    Password derivation is protected by per-account locks so that
    simultaneous requests cannot corrupt account failure state.
    """

    def __init__(
        self,
        hasher: Optional[PasswordHasher] = None,
        policy: Optional[PasswordPolicy] = None,
    ):
        self.hasher = hasher or PasswordHasher()
        self.policy = policy or PasswordPolicy()

        self._accounts: dict[str, Account] = {}
        self._accounts_lock = threading.RLock()

        # Dummy verification reduces username-enumeration timing differences.
        self._dummy_hash = self.hasher.hash_password(
            "internal dummy credential not for authentication"
        )

        self.maximum_failures = 5
        self.lock_duration_seconds = 60

    @staticmethod
    def normalize_username(username: str) -> str:
        username = username.strip().lower()

        if not re.fullmatch(r"[a-z0-9._-]{3,64}", username):
            raise ValueError("Invalid account identifier.")

        return username

    def register(self, username: str, password: str) -> None:
        key = self.normalize_username(username)
        normalized_password = self.policy.validate(password, key)

        password_hash = self.hasher.hash_password(normalized_password)

        account = Account(
            username=key,
            password_hash=password_hash,
        )

        with self._accounts_lock:
            if key in self._accounts:
                raise DuplicateAccountError("Account already exists.")

            self._accounts[key] = account

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> AuthenticationResult:

        try:
            key = self.normalize_username(username)
        except ValueError:
            self.hasher.verify(password, self._dummy_hash)
            return AuthenticationResult.INVALID_CREDENTIALS

        with self._accounts_lock:
            account = self._accounts.get(key)

        if account is None:
            self.hasher.verify(password, self._dummy_hash)
            return AuthenticationResult.INVALID_CREDENTIALS

        with account.lock:
            if not account.enabled:
                return AuthenticationResult.ACCOUNT_DISABLED

            now = time.monotonic()

            if now < account.locked_until:
                return AuthenticationResult.ACCOUNT_LOCKED

            if not self.hasher.verify(password, account.password_hash):
                account.failed_attempts += 1

                if account.failed_attempts >= self.maximum_failures:
                    account.locked_until = (
                        now + self.lock_duration_seconds
                    )

                return AuthenticationResult.INVALID_CREDENTIALS

            account.failed_attempts = 0
            account.locked_until = 0.0

            # Upgrade weaker historical parameters only after successful
            # verification of the existing password.
            if self.hasher.needs_rehash(account.password_hash):
                account.password_hash = self.hasher.hash_password(password)

            return AuthenticationResult.SUCCESS

    def disable_account(self, username: str) -> None:
        key = self.normalize_username(username)

        with self._accounts_lock:
            account = self._accounts.get(key)

        if account is None:
            raise KeyError("Account does not exist.")

        with account.lock:
            account.enabled = False

    def get_credential_iterations(self, username: str) -> int:
        key = self.normalize_username(username)
        account = self._accounts[key]

        with account.lock:
            iterations, _, _ = self.hasher.parse(account.password_hash)
            return iterations


def demonstrate_password_hashing() -> None:
    print("PASSWORD HASHING SECURITY DEMONSTRATION")

    service = PasswordAuthenticationService()

    username = "alex.developer"
    password = "Correct-Horse-Battery-Staple-2026!"

    # Account registration.
    service.register(username, password)

    # Simulate an account created by an older application version.
    account = service._accounts[username]
    legacy_hasher = PasswordHasher(iterations=120_000)

    account.password_hash = legacy_hasher.hash_password(password)

    print("Registration: successful")

    # Incorrect password.
    wrong_result = service.authenticate(
        username,
        "incorrect-password-value",
    )

    print("Incorrect password:", wrong_result.value)

    # Correct password verifies and upgrades the historical credential.
    correct_result = service.authenticate(username, password)

    print("Correct password:", correct_result.value)

    upgraded_iterations = service.get_credential_iterations(username)

    print("Credential iterations after authentication:", upgraded_iterations)

    assert correct_result == AuthenticationResult.SUCCESS
    assert upgraded_iterations == CURRENT_ITERATIONS

    # Different random salts produce different encoded hashes.
    hash_one = service.hasher.hash_password(password)
    hash_two = service.hasher.hash_password(password)

    assert hash_one != hash_two
    assert service.hasher.verify(password, hash_one)
    assert not service.hasher.verify("wrong-password", hash_one)

    # Malformed credential input must fail safely.
    assert not service.hasher.verify(password, "invalid$credential")

    # Password policy must reject known weak values.
    try:
        service.register("weak.account", "password123456789")
    except PasswordPolicyError:
        print("Weak password rejection: successful")
    else:
        raise AssertionError("Weak password was incorrectly accepted.")

    # Account throttling.
    service.register(
        "throttle.user",
        "A-Long-Unique-Authentication-Secret-2026!",
    )

    for _ in range(5):
        service.authenticate(
            "throttle.user",
            "incorrect-authentication-secret",
        )

    locked_result = service.authenticate(
        "throttle.user",
        "A-Long-Unique-Authentication-Secret-2026!",
    )

    assert locked_result == AuthenticationResult.ACCOUNT_LOCKED

    print("Repeated-failure throttling: successful")
    print("All security assertions passed.")


if __name__ == "__main__":
    demonstrate_password_hashing()
