#!/usr/bin/env python3
"""
Rainbow Tables and Password Attacks
A defensive laboratory covering password hashing, dictionary attacks,
rainbow-table mechanics, salting, password storage, and authentication security.

All attack demonstrations use a tiny synthetic password space.
No real credential files or external accounts are accessed.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import os
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------
# 1. Password hashing fundamentals
# ---------------------------------------------------------

def sha256_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def salted_sha256(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def pbkdf2_password(
    password: str,
    salt: bytes,
    iterations: int = 600_000
) -> bytes:
    if iterations < 100_000:
        raise ValueError("Iteration count is below the configured minimum")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )


# ---------------------------------------------------------
# 2. Synthetic password dataset
# ---------------------------------------------------------

@dataclass(frozen=True)
class Account:
    username: str
    password: str


SAMPLE_ACCOUNTS = [
    Account("alice", "ab"),
    Account("bob", "ba"),
    Account("charlie", "aa"),
    Account("david", "bb"),
]

TOY_ALPHABET = "ab"


# ---------------------------------------------------------
# 3. Dictionary attack simulation
# ---------------------------------------------------------

def dictionary_attack(
    target_hash: str,
    candidates: list[str]
) -> Optional[str]:
    """
    Demonstrates why unsalted fast hashes are unsuitable
    for password storage.
    """
    for candidate in candidates:
        if hmac.compare_digest(
            sha256_password(candidate),
            target_hash
        ):
            return candidate

    return None


# ---------------------------------------------------------
# 4. Rainbow table construction
# ---------------------------------------------------------

def reduction_function(
    digest: str,
    position: int,
    alphabet: str = TOY_ALPHABET,
    password_length: int = 2
) -> str:
    """
    Converts a hash into a candidate password.

    Position-dependent reduction functions are essential
    because rainbow tables use a different reduction at
    each chain position.
    """
    number = int(digest[:16], 16) + position

    result = []
    base = len(alphabet)

    for _ in range(password_length):
        result.append(alphabet[number % base])
        number //= base

    return "".join(result)


@dataclass
class RainbowTable:
    chain_length: int
    chains: dict[str, str] = field(default_factory=dict)

    def generate_chain(self, start: str) -> str:
        current = start

        for position in range(self.chain_length):
            digest = sha256_password(current)
            current = reduction_function(digest, position)

        return current

    def build(self, passwords: list[str]) -> None:
        for password in passwords:
            endpoint = self.generate_chain(password)

            # Multiple starts can produce the same endpoint.
            # Keep one representative chain for this toy model.
            self.chains.setdefault(endpoint, password)

    def lookup(self, target_hash: str) -> Optional[str]:
        """
        Reconstructs possible chain suffixes and checks
        their corresponding starting points.
        """
        for position in range(self.chain_length - 1, -1, -1):
            candidate = target_hash

            for step in range(position, self.chain_length):
                candidate = reduction_function(
                    candidate,
                    step
                )

                if step < self.chain_length - 1:
                    candidate = sha256_password(candidate)

            start = self.chains.get(candidate)

            if start is None:
                continue

            current = start

            for step in range(self.chain_length):
                digest = sha256_password(current)

                if hmac.compare_digest(digest, target_hash):
                    return current

                current = reduction_function(digest, step)

        return None


# ---------------------------------------------------------
# 5. Demonstrating rainbow table limitations
# ---------------------------------------------------------

def demonstrate_rainbow_tables() -> None:
    print("\nRAINBOW TABLE DEMONSTRATION")

    password_space = [
        "".join(chars)
        for chars in itertools.product(
            TOY_ALPHABET,
            repeat=2
        )
    ]

    table = RainbowTable(chain_length=2)
    table.build(password_space)

    target = "ab"
    target_hash = sha256_password(target)

    recovered = table.lookup(target_hash)

    print("Target password:", target)
    print("Target hash:", target_hash)
    print("Recovered:", recovered)
    print("Stored chain endpoints:", len(table.chains))
    print("Original password space:", len(password_space))

    # A rainbow table built for unsalted SHA-256 cannot
    # directly match an independently salted hash.
    salt = secrets.token_bytes(16)
    salted_hash = salted_sha256(target, salt)

    print(
        "Salted hash equals unsalted hash:",
        hmac.compare_digest(salted_hash, target_hash)
    )


# ---------------------------------------------------------
# 6. Salt effectiveness demonstration
# ---------------------------------------------------------

def demonstrate_salts() -> None:
    print("\nSALT DEMONSTRATION")

    password = "ab"

    salt_one = secrets.token_bytes(16)
    salt_two = secrets.token_bytes(16)

    hash_one = salted_sha256(password, salt_one)
    hash_two = salted_sha256(password, salt_two)

    print("First account hash:", hash_one)
    print("Second account hash:", hash_two)
    print("Hashes identical:", hash_one == hash_two)

    assert hash_one != hash_two


# ---------------------------------------------------------
# 7. Secure password storage
# ---------------------------------------------------------

@dataclass
class PasswordCredential:
    salt: bytes
    password_hash: bytes
    iterations: int
    algorithm: str = "PBKDF2-HMAC-SHA256"


class PasswordHasher:
    def __init__(self, iterations: int = 600_000):
        self.iterations = iterations

    def hash_password(self, password: str) -> PasswordCredential:
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")

        if len(password.encode("utf-8")) > 1024:
            raise ValueError("Password exceeds maximum supported size")

        salt = secrets.token_bytes(16)

        digest = pbkdf2_password(
            password,
            salt,
            self.iterations
        )

        return PasswordCredential(
            salt=salt,
            password_hash=digest,
            iterations=self.iterations
        )

    def verify(
        self,
        password: str,
        credential: PasswordCredential
    ) -> bool:
        if credential.algorithm != "PBKDF2-HMAC-SHA256":
            raise ValueError("Unsupported password hashing algorithm")

        if credential.iterations < 100_000:
            raise ValueError("Unsafe password hashing configuration")

        if len(password.encode("utf-8")) > 1024:
            return False

        candidate = pbkdf2_password(
            password,
            credential.salt,
            credential.iterations
        )

        return hmac.compare_digest(
            candidate,
            credential.password_hash
        )


# ---------------------------------------------------------
# 8. Password policy
# ---------------------------------------------------------

class PasswordPolicy:
    COMMON_PASSWORDS = {
        "password123!",
        "qwerty123456",
        "admin123456!",
        "welcome12345",
    }

    @classmethod
    def validate(cls, password: str) -> list[str]:
        errors = []

        if len(password) < 12:
            errors.append("Minimum length is 12 characters")

        if len(password.encode("utf-8")) > 1024:
            errors.append("Maximum byte length is 1024")

        if password.lower() in cls.COMMON_PASSWORDS:
            errors.append("Password appears in the common-password list")

        if not any(char.isalpha() for char in password):
            errors.append("At least one letter is required")

        if not any(char.isdigit() for char in password):
            errors.append("At least one digit is required")

        return errors


# ---------------------------------------------------------
# 9. Authentication and rate limiting
# ---------------------------------------------------------

class AuthenticationStatus(Enum):
    SUCCESS = "success"
    INVALID = "invalid"
    LOCKED = "locked"


@dataclass
class LoginState:
    failed_attempts: int = 0
    locked_until: float = 0.0


class AuthenticationService:
    def __init__(
        self,
        hasher: PasswordHasher,
        maximum_attempts: int = 5,
        lockout_seconds: int = 30
    ):
        self.hasher = hasher
        self.maximum_attempts = maximum_attempts
        self.lockout_seconds = lockout_seconds

        self.credentials: dict[str, PasswordCredential] = {}
        self.states: dict[str, LoginState] = defaultdict(LoginState)

    def register(self, username: str, password: str) -> None:
        if not username or username in self.credentials:
            raise ValueError("Invalid or duplicate username")

        errors = PasswordPolicy.validate(password)

        if errors:
            raise ValueError("; ".join(errors))

        self.credentials[username] = self.hasher.hash_password(password)

    def authenticate(
        self,
        username: str,
        password: str
    ) -> AuthenticationStatus:
        state = self.states[username]
        now = time.monotonic()

        if now < state.locked_until:
            return AuthenticationStatus.LOCKED

        credential = self.credentials.get(username)

        if credential is None or not self.hasher.verify(
            password,
            credential
        ):
            state.failed_attempts += 1

            if state.failed_attempts >= self.maximum_attempts:
                state.locked_until = now + self.lockout_seconds
                return AuthenticationStatus.LOCKED

            return AuthenticationStatus.INVALID

        state.failed_attempts = 0
        state.locked_until = 0.0

        return AuthenticationStatus.SUCCESS


# ---------------------------------------------------------
# 10. Password attack classification
# ---------------------------------------------------------

class AttackType(Enum):
    DICTIONARY = "Dictionary attack"
    BRUTE_FORCE = "Brute-force attack"
    RAINBOW_TABLE = "Rainbow-table attack"
    CREDENTIAL_STUFFING = "Credential stuffing"
    PASSWORD_SPRAYING = "Password spraying"
    PHISHING = "Phishing"


ATTACK_DEFENSES = {
    AttackType.DICTIONARY: [
        "Block common and compromised passwords",
        "Use adaptive password hashing"
    ],
    AttackType.BRUTE_FORCE: [
        "Apply rate limits",
        "Use progressive authentication delays"
    ],
    AttackType.RAINBOW_TABLE: [
        "Generate a unique random salt per credential",
        "Use an adaptive password hashing algorithm"
    ],
    AttackType.CREDENTIAL_STUFFING: [
        "Use MFA",
        "Detect unusual login patterns",
        "Prevent password reuse"
    ],
    AttackType.PASSWORD_SPRAYING: [
        "Monitor distributed authentication failures",
        "Apply account-aware and network-aware rate limits"
    ],
    AttackType.PHISHING: [
        "Use phishing-resistant authentication",
        "Educate users about credential theft"
    ],
}


def display_attack_defenses() -> None:
    print("\nATTACK CLASSIFICATION")

    for attack, defenses in ATTACK_DEFENSES.items():
        print(f"\n{attack.value}")

        for defense in defenses:
            print(" -", defense)


# ---------------------------------------------------------
# 11. Tests and executable workflow
# ---------------------------------------------------------

def run_tests() -> None:
    assert sha256_password("test") == hashlib.sha256(
        b"test"
    ).hexdigest()

    assert dictionary_attack(
        sha256_password("ab"),
        ["aa", "ab", "ba"]
    ) == "ab"

    assert dictionary_attack(
        sha256_password("zz"),
        ["aa", "ab", "ba"]
    ) is None

    hasher = PasswordHasher(iterations=100_000)

    credential = hasher.hash_password("SecurePass123!")

    assert hasher.verify("SecurePass123!", credential)
    assert not hasher.verify("IncorrectPass123!", credential)

    assert credential.salt != b""

    assert PasswordPolicy.validate("weak") != []
    assert PasswordPolicy.validate("SecurePass123!") == []

    print("\nAll tests passed.")


def main() -> None:
    print("=" * 60)
    print("RAINBOW TABLES AND PASSWORD ATTACKS")
    print("Defensive Security Laboratory")
    print("=" * 60)

    accounts = SAMPLE_ACCOUNTS

    candidates = [
        "aa",
        "ab",
        "ba",
        "bb"
    ]

    print("\nSYNTHETIC DICTIONARY ATTACK")

    for account in accounts:
        result = dictionary_attack(
            sha256_password(account.password),
            candidates
        )

        print(f"{account.username}: {result}")

    demonstrate_rainbow_tables()
    demonstrate_salts()
    display_attack_defenses()

    print("\nSECURE AUTHENTICATION")

    hasher = PasswordHasher(iterations=100_000)

    authentication = AuthenticationService(
        hasher,
        maximum_attempts=3,
        lockout_seconds=10
    )

    authentication.register(
        "researcher",
        "SecurePass123!"
    )

    print(
        "Valid login:",
        authentication.authenticate(
            "researcher",
            "SecurePass123!"
        ).value
    )

    print(
        "Invalid login:",
        authentication.authenticate(
            "researcher",
            "WrongPassword123!"
        ).value
    )

    print("\nRUNNING VALIDATION")

    run_tests()


if __name__ == "__main__":
    main()
