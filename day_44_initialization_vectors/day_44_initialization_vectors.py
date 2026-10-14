#!/usr/bin/env python3
"""
Initialization Vectors (IVs) in Cryptography
=============================================

Executable demonstrations of IV generation, uniqueness, validation,
nonce lifecycle management, AES-GCM integration, CBC configuration,
failure handling, and persistent IV allocation.

Python standard library only. Actual AES encryption is demonstrated through
an optional OpenSSL command-line integration when OpenSSL is installed.
The script never implements a substitute cipher or claims that generating
an IV alone provides encryption security.

Run:
    python initialization_vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


class IVError(ValueError):
    """Raised when an initialization vector violates a cryptographic policy."""


class NonceReuseError(RuntimeError):
    """Raised when a nonce is reused within the same key scope."""


class IVRegistry:
    """
    Tracks IVs or nonces for a particular key identifier.

    The registry demonstrates application-level reuse prevention.
    Production systems need durable, atomic storage shared by every
    process that encrypts under the same key.
    """

    def __init__(self, key_id: str, iv_length: int = 12):
        if not key_id.strip():
            raise IVError("A non-empty key identifier is required.")
        if iv_length <= 0:
            raise IVError("IV length must be positive.")

        self.key_id = key_id
        self.iv_length = iv_length
        self._seen: set[bytes] = set()

    def register(self, iv: bytes) -> None:
        if not isinstance(iv, bytes):
            raise IVError("IV must be bytes.")
        if len(iv) != self.iv_length:
            raise IVError(
                f"Expected {self.iv_length} bytes; received {len(iv)}."
            )
        if iv in self._seen:
            raise NonceReuseError(
                f"IV reuse detected for key scope {self.key_id!r}."
            )
        self._seen.add(iv)

    @property
    def count(self) -> int:
        return len(self._seen)


def generate_random_iv(length: int = 16) -> bytes:
    """Generate cryptographically strong random bytes."""
    if not 1 <= length <= 1024:
        raise IVError("Length must be between 1 and 1024 bytes.")
    return secrets.token_bytes(length)


def generate_gcm_nonce() -> bytes:
    """
    Return the conventional 96-bit nonce used by AES-GCM.

    Random generation is appropriate only when the collision probability
    is acceptable for the key's total encryption volume. A deterministic,
    persistent allocator may be preferable for high-volume systems.
    """
    return secrets.token_bytes(12)


def validate_cbc_iv(iv: bytes) -> None:
    """AES-CBC requires a 16-byte IV and unpredictability before encryption."""
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise IVError("AES-CBC requires an IV exactly 16 bytes long.")


def validate_gcm_nonce(nonce: bytes) -> None:
    """This project standardizes on 12-byte AES-GCM nonces."""
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise IVError("This AES-GCM implementation requires a 12-byte nonce.")


def demonstrate_randomness() -> None:
    print("\n--- Cryptographically secure random IVs ---")
    first = generate_random_iv(16)
    second = generate_random_iv(16)

    print("CBC IV A:", first.hex())
    print("CBC IV B:", second.hex())
    print("Different in this sample:", first != second)
    print("IV A length:", len(first), "bytes")

    # Different output in one sample does not prove randomness or uniqueness.
    # secrets uses the operating system's cryptographically secure generator.


def demonstrate_validation() -> None:
    print("\n--- Length and type validation ---")
    validate_cbc_iv(generate_random_iv(16))
    validate_gcm_nonce(generate_gcm_nonce())
    print("Valid CBC and GCM lengths accepted.")

    for description, operation in [
        ("Short CBC IV", lambda: validate_cbc_iv(b"short")),
        ("Wrong GCM nonce length", lambda: validate_gcm_nonce(b"x" * 16)),
        ("Invalid random length", lambda: generate_random_iv(0)),
    ]:
        try:
            operation()
        except IVError as error:
            print(f"{description}: rejected ({error})")


def demonstrate_reuse_detection() -> None:
    print("\n--- Key-scoped nonce reuse detection ---")
    registry = IVRegistry("payments-key-v4", iv_length=12)
    nonce = generate_gcm_nonce()

    registry.register(nonce)
    print("First registration accepted.")

    try:
        registry.register(nonce)
    except NonceReuseError as error:
        print("Second registration rejected:", error)

    print("Registered nonce count:", registry.count)


def estimate_collision_probability(number_of_nonces: int, bits: int) -> float:
    """
    Birthday-bound approximation for uniformly random nonces.

    P(collision) ~= n(n-1) / 2^(bits+1).
    This approximation is useful when the probability is small.
    """
    if number_of_nonces < 0 or bits <= 0:
        raise ValueError("Count must be non-negative and bits positive.")

    if number_of_nonces < 2:
        return 0.0

    log_probability = (
        2 * (number_of_nonces.bit_length() - 1)
        - bits - 1
    )

    if log_probability < -1074:
        return 0.0

    # Use floating-point arithmetic for a readable estimate.
    estimate = number_of_nonces * (number_of_nonces - 1) / (2 ** (bits + 1))
    return min(1.0, estimate)


def demonstrate_collision_risk() -> None:
    print("\n--- Random nonce collision estimates ---")
    samples = 1_000_000
    probability = estimate_collision_probability(samples, 96)
    print(f"Nonces generated under one key: {samples:,}")
    print(f"Approximate collision probability: {probability:.6e}")
    print(
        "The estimate is not a guarantee. The nonce budget must also "
        "respect the chosen cipher's security limits."
    )


@dataclass(frozen=True)
class EncryptionRecord:
    key_id: str
    algorithm: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str


class OpenSSLGCM:
    """
    Optional real AES-256-GCM demonstration using OpenSSL.

    This requires a recent OpenSSL executable supporting enc -aes-256-gcm.
    Some OpenSSL builds do not expose GCM through the enc command.
    If unavailable, the script reports that limitation instead of using
    insecure substitute encryption.
    """

    def __init__(self, executable: str):
        self.executable = executable

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        validate_gcm_nonce(nonce)
        if len(key) != 32:
            raise IVError("AES-256 requires a 32-byte key.")

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plain.bin"
            destination = Path(directory) / "cipher.bin"
            source.write_bytes(plaintext)

            command = [
                self.executable,
                "enc",
                "-aes-256-gcm",
                "-K", key.hex(),
                "-iv", nonce.hex(),
                "-in", str(source),
                "-out", str(destination),
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    "This OpenSSL build does not support the requested "
                    "GCM operation through 'enc', or encryption failed. "
                    + result.stderr.strip()
                )

            return destination.read_bytes()


def demonstrate_optional_openssl() -> None:
    print("\n--- Optional real AES-GCM integration ---")
    executable = shutil.which("openssl")

    if executable is None:
        print("OpenSSL is not installed; skipping actual encryption.")
        return

    key = secrets.token_bytes(32)
    nonce = generate_gcm_nonce()

    try:
        ciphertext = OpenSSLGCM(executable).encrypt(
            key, nonce, b"Confidential deployment configuration"
        )
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        print("AES-GCM integration unavailable:", error)
        print("No insecure fallback cipher was used.")
        return

    print("AES-256-GCM encryption succeeded.")
    print("Nonce:", nonce.hex())
    print("Ciphertext length:", len(ciphertext))
    print(
        "Note: a production AEAD implementation must retain and verify "
        "the authentication tag. Use a maintained cryptographic library "
        "with an explicit tag API for complete encryption and decryption."
    )


class CounterNonceAllocator:
    """
    Demonstrates deterministic nonce construction from a fixed prefix
    and a monotonically increasing 64-bit counter.

    This in-memory version is for learning only. Restarting it with the
    same prefix can repeat nonces. Production allocation must persist the
    counter atomically or assign disjoint ranges to independent workers.
    """

    def __init__(self, prefix: bytes, initial_counter: int = 0):
        if len(prefix) != 4:
            raise IVError("The example requires a four-byte prefix.")
        if not 0 <= initial_counter < 2**64:
            raise IVError("Counter is outside the unsigned 64-bit range.")

        self.prefix = prefix
        self.counter = initial_counter

    def next_nonce(self) -> bytes:
        if self.counter >= 2**64:
            raise OverflowError("Nonce counter exhausted; rotate the key.")

        nonce = self.prefix + self.counter.to_bytes(8, "big")
        self.counter += 1
        return nonce


def demonstrate_counter_allocator() -> None:
    print("\n--- Deterministic nonce allocation ---")
    allocator = CounterNonceAllocator(b"NODE")
    registry = IVRegistry("analytics-key-v2", 12)

    for _ in range(3):
        nonce = allocator.next_nonce()
        registry.register(nonce)
        print(nonce.hex())

    print("Unique allocations:", registry.count)
    print(
        "Operational requirement: persist counter state before use, "
        "coordinate workers, and never reuse a nonce after restoring "
        "a backup or rotating deployment instances."
    )


def demonstrate_iv_misconceptions() -> None:
    print("\n--- Important security distinctions ---")
    print("CBC IV: 16 bytes for AES; must be unpredictable.")
    print("GCM nonce: commonly 12 bytes; must never repeat under a key.")
    print("An IV or nonce is generally not secret and may be stored openly.")
    print("An IV alone does not encrypt, authenticate, or protect a message.")
    print("GCM nonce reuse can expose plaintext relationships and undermine "
          "authentication.")
    print("CBC does not authenticate ciphertext; use an authenticated design "
          "or a correctly composed encrypt-then-MAC construction.")


def main() -> None:
    demonstrate_randomness()
    demonstrate_validation()
    demonstrate_reuse_detection()
    demonstrate_collision_risk()
    demonstrate_counter_allocator()
    demonstrate_iv_misconceptions()
    demonstrate_optional_openssl()


if __name__ == "__main__":
    main()
