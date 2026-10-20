"""
Introduction to Hash Functions
A self-contained learning implementation covering:
- Deterministic hashing
- Hash values and avalanche behavior
- Collision handling
- Hash tables
- SHA-256 and SHA-3
- Password hashing concepts
- File integrity verification
- HMAC authentication
- Merkle-tree hashing
- Validation and failure handling

Run with:
    python hash_functions.py
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class HashFunctionError(ValueError):
    """Raised when hash-function input violates a required condition."""


def validate_text(value: str, field_name: str = "value") -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise HashFunctionError(f"{field_name} must not be empty")


def sha256_hex(data: bytes) -> str:
    """Return the hexadecimal SHA-256 digest of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def sha3_256_hex(data: bytes) -> str:
    """Return the hexadecimal SHA3-256 digest."""
    return hashlib.sha3_256(data).hexdigest()


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """
    Hash UTF-8 text using a standard-library cryptographic hash.

    The algorithm name is restricted to algorithms exposed by hashlib.
    """
    validate_text(text, "text")

    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise HashFunctionError(f"Unsupported hash algorithm: {algorithm}") from exc

    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def demonstrate_determinism() -> tuple[str, str]:
    first = sha256_hex(b"repository commit")
    second = sha256_hex(b"repository commit")

    if first != second:
        raise RuntimeError("A deterministic hash produced inconsistent results")

    return first, second


def demonstrate_avalanche() -> tuple[str, str, int]:
    """
    A one-character change should normally produce a substantially
    different digest. This measures differing hexadecimal characters.
    """
    first = sha256_hex(b"hash-function")
    second = sha256_hex(b"hash-functions")
    differences = sum(a != b for a, b in zip(first, second))
    return first, second, differences


@dataclass(frozen=True)
class HashRecord:
    key: str
    value: str


class ChainedHashTable:
    """
    Educational hash table using separate chaining.

    Python's built-in hash() is deliberately used only for table indexing.
    It is not a cryptographic hash and must not be used for integrity,
    authentication, or password storage.
    """

    def __init__(self, capacity: int = 8) -> None:
        if capacity < 2:
            raise ValueError("capacity must be at least 2")
        self._buckets: list[list[HashRecord]] = [[] for _ in range(capacity)]
        self._size = 0

    def _index(self, key: str) -> int:
        validate_text(key, "key")
        return hash(key) % len(self._buckets)

    def put(self, key: str, value: str) -> None:
        index = self._index(key)
        bucket = self._buckets[index]

        for position, record in enumerate(bucket):
            if record.key == key:
                bucket[position] = HashRecord(key, value)
                return

        bucket.append(HashRecord(key, value))
        self._size += 1

    def get(self, key: str) -> str | None:
        index = self._index(key)

        for record in self._buckets[index]:
            if record.key == key:
                return record.value

        return None

    def delete(self, key: str) -> bool:
        index = self._index(key)
        bucket = self._buckets[index]

        for position, record in enumerate(bucket):
            if record.key == key:
                del bucket[position]
                self._size -= 1
                return True

        return False

    @property
    def size(self) -> int:
        return self._size


def compare_hashes(left: str, right: str) -> bool:
    """
    Constant-time comparison is appropriate when comparing authentication
    tags or other security-sensitive digest values.
    """
    return hmac.compare_digest(left, right)


def file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Hash a file incrementally so large files do not need to be loaded
    entirely into memory.
    """
    if not path.is_file():
        raise FileNotFoundError(path)

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    digest = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def verify_file_sha256(path: Path, expected_digest: str) -> bool:
    if len(expected_digest) != 64:
        raise HashFunctionError("SHA-256 digest must contain 64 hexadecimal characters")

    try:
        int(expected_digest, 16)
    except ValueError as exc:
        raise HashFunctionError("Expected digest is not hexadecimal") from exc

    actual_digest = file_sha256(path)
    return hmac.compare_digest(actual_digest, expected_digest.lower())


def hmac_sha256(secret_key: bytes, message: bytes) -> str:
    """
    HMAC uses a cryptographic hash together with a secret key.
    A plain hash of a secret concatenated with a message is not a
    substitute for HMAC.
    """
    if not secret_key:
        raise HashFunctionError("HMAC key must not be empty")

    return hmac.new(secret_key, message, hashlib.sha256).hexdigest()


def verify_hmac(secret_key: bytes, message: bytes, expected_tag: str) -> bool:
    actual_tag = hmac_sha256(secret_key, message)
    return hmac.compare_digest(actual_tag, expected_tag)


def password_demo(password: str) -> tuple[str, str]:
    """
    Demonstrates salted password hashing with PBKDF2-HMAC.

    Production password storage should use a password-specific scheme
    such as Argon2id, scrypt, or bcrypt when available. A fast general
    hash such as SHA-256 is intentionally not used for password storage.
    """
    validate_text(password, "password")

    salt = secrets.token_bytes(16)
    iterations = 600_000

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    encoded = f"pbkdf2_sha256${iterations}${salt.hex()}${derived_key.hex()}"
    return encoded, salt.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iteration_text, salt_hex, expected_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iteration_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (ValueError, TypeError):
        return False

    if iterations <= 0 or not salt or not expected:
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(actual, expected)


def merkle_root(leaves: Iterable[bytes]) -> str:
    """
    Build a binary Merkle tree.

    Each leaf is hashed first. At every level, adjacent hashes are
    concatenated and hashed. An odd node is duplicated so every node
    has a sibling.
    """
    items = list(leaves)

    if not items:
        raise HashFunctionError("A Merkle tree requires at least one leaf")

    level = [hashlib.sha256(item).digest() for item in items]

    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])

        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]

    return level[0].hex()


def run() -> None:
    print("=== Determinism ===")
    digest, repeated_digest = demonstrate_determinism()
    print(digest)
    print(digest == repeated_digest)

    print("\n=== Avalanche Effect ===")
    original, changed, difference_count = demonstrate_avalanche()
    print("Original :", original)
    print("Changed  :", changed)
    print("Different hexadecimal positions:", difference_count)

    print("\n=== SHA-256 and SHA3-256 ===")
    message = "Repository artifact"
    print("SHA-256 :", hash_text(message, "sha256"))
    print("SHA3-256:", hash_text(message, "sha3_256"))

    print("\n=== Hash Table ===")
    table = ChainedHashTable()
    table.put("commit-001", "Initial repository structure")
    table.put("commit-002", "Add validation")
    table.put("commit-002", "Add validation and tests")
    print("commit-002:", table.get("commit-002"))
    print("Missing key:", table.get("commit-999"))
    print("Deleted:", table.delete("commit-001"))
    print("Entries:", table.size)

    print("\n=== File Integrity ===")
    with tempfile.NamedTemporaryFile(delete=False) as temporary:
        path = Path(temporary.name)
        temporary.write(b"release artifact v1")

    try:
        expected = file_sha256(path)
        print("Original digest:", expected)
        print("Valid:", verify_file_sha256(path, expected))

        path.write_bytes(b"release artifact v2")
        print("After modification:", verify_file_sha256(path, expected))
    finally:
        path.unlink(missing_ok=True)

    print("\n=== HMAC ===")
    key = secrets.token_bytes(32)
    payload = b"transfer=25000&account=ACCT-1042"
    tag = hmac_sha256(key, payload)
    print("Valid tag:", verify_hmac(key, payload, tag))
    print("Tampered message:", verify_hmac(key, b"transfer=99000&account=ACCT-1042", tag))

    print("\n=== Password Derivation ===")
    stored, salt = password_demo("CorrectHorseBatteryStaple")
    print("Stored record:", stored)
    print("Salt:", salt)
    print("Correct password:", verify_password("CorrectHorseBatteryStaple", stored))
    print("Wrong password:", verify_password("WrongPassword", stored))

    print("\n=== Merkle Root ===")
    transactions = [
        b"TX-001 Alice -> Bob 10",
        b"TX-002 Bob -> Carol 5",
        b"TX-003 Carol -> Dave 2",
        b"TX-004 Dave -> Erin 1",
    ]
    print(merkle_root(transactions))


if __name__ == "__main__":
    run()
