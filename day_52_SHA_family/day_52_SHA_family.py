#!/usr/bin/env python3
"""
SHA family practical case study.

Covers:
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA-3 and SHAKE
- Incremental hashing
- File hashing
- HMAC
- Password-derived verification with PBKDF2-HMAC
- Digest comparison and validation
- Length-extension distinction between raw SHA-256 and HMAC
- Streaming and performance considerations

Run with Python 3.10+.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


SHA_ALGORITHMS = (
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512_224",
    "sha512_256",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "shake_128",
    "shake_256",
)


def require_algorithm(name: str) -> None:
    if name not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported hashlib algorithm: {name}")


def digest_text(text: str, algorithm: str = "sha256") -> str:
    require_algorithm(algorithm)

    if algorithm.startswith("shake_"):
        raise ValueError("SHAKE requires an explicit output length.")

    return hashlib.new(
        algorithm,
        text.encode("utf-8"),
    ).hexdigest()


def digest_shake(text: str, algorithm: str = "shake_256", length: int = 32) -> str:
    require_algorithm(algorithm)

    if algorithm not in {"shake_128", "shake_256"}:
        raise ValueError("SHAKE algorithm must be shake_128 or shake_256.")
    if length <= 0:
        raise ValueError("SHAKE output length must be positive.")

    digest = hashlib.new(algorithm, text.encode("utf-8"))
    return digest.hexdigest(length)


def incremental_sha256(chunks: list[bytes]) -> str:
    hasher = hashlib.sha256()

    for chunk in chunks:
        hasher.update(chunk)

    return hasher.hexdigest()


def hash_file(
    path: Path,
    algorithm: str = "sha256",
    chunk_size: int = 1024 * 1024,
) -> str:
    require_algorithm(algorithm)

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive.")
    if not path.is_file():
        raise FileNotFoundError(path)

    hasher = hashlib.new(algorithm)

    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


def secure_digest_equal(expected: str, actual: str) -> bool:
    """
    compare_digest avoids ordinary early-exit string comparison.

    It does not authenticate an untrusted digest by itself. The expected
    digest must come from a trusted source.
    """
    return hmac.compare_digest(expected.lower(), actual.lower())


def create_hmac(key: bytes, message: bytes, algorithm: str = "sha256") -> str:
    require_algorithm(algorithm)
    return hmac.new(key, message, algorithm).hexdigest()


def verify_hmac(
    key: bytes,
    message: bytes,
    expected_hex: str,
    algorithm: str = "sha256",
) -> bool:
    actual = create_hmac(key, message, algorithm)
    return secure_digest_equal(expected_hex, actual)


@dataclass(frozen=True)
class PasswordRecord:
    salt: bytes
    digest: bytes
    iterations: int
    algorithm: str = "sha256"


def derive_password_record(
    password: str,
    *,
    iterations: int = 600_000,
    salt: bytes | None = None,
) -> PasswordRecord:
    """
    PBKDF2-HMAC is deliberately slower than a single SHA operation.
    A salt prevents identical passwords from sharing identical stored
    derived values and makes precomputed rainbow tables ineffective.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if iterations < 100_000:
        raise ValueError("Iteration count is intentionally required to be high.")

    actual_salt = salt if salt is not None else secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        actual_salt,
        iterations,
    )

    return PasswordRecord(
        salt=actual_salt,
        digest=digest,
        iterations=iterations,
    )


def verify_password(password: str, record: PasswordRecord) -> bool:
    candidate = hashlib.pbkdf2_hmac(
        record.algorithm,
        password.encode("utf-8"),
        record.salt,
        record.iterations,
    )

    return hmac.compare_digest(candidate, record.digest)


def demonstrate_family() -> None:
    message = "SHA family integrity example"

    print("SHA-family digests")
    print("=" * 72)

    for algorithm in SHA_ALGORITHMS:
        if algorithm.startswith("shake_"):
            value = digest_shake(message, algorithm, 32)
        else:
            value = digest_text(message, algorithm)

        print(f"{algorithm:12} {value}")


def demonstrate_incremental_hashing() -> None:
    chunks = [
        b"Repository artifact\n",
        b"commit: 8e1a7d\n",
        b"status: verified\n",
    ]

    one_shot = hashlib.sha256(b"".join(chunks)).hexdigest()
    incremental = incremental_sha256(chunks)

    if one_shot != incremental:
        raise RuntimeError("Incremental hashing produced an unexpected result.")

    print("\nIncremental hashing")
    print("=" * 72)
    print(incremental)


def demonstrate_file_hashing() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as temporary:
        temporary.write(os.urandom(2 * 1024 * 1024))
        temporary_path = Path(temporary.name)

    try:
        digest = hash_file(temporary_path)
        print("\nStreaming file hashing")
        print("=" * 72)
        print(f"File:   {temporary_path}")
        print(f"SHA256: {digest}")
    finally:
        temporary_path.unlink(missing_ok=True)


def demonstrate_hmac() -> None:
    key = secrets.token_bytes(32)
    message = b"release-artifact:v4"

    tag = create_hmac(key, message)
    valid = verify_hmac(key, message, tag)
    tampered = verify_hmac(key, message + b"-tampered", tag)

    print("\nHMAC authentication")
    print("=" * 72)
    print(f"Tag:       {tag}")
    print(f"Valid:     {valid}")
    print(f"Tampered:  {tampered}")

    if not valid or tampered:
        raise RuntimeError("HMAC verification demonstration failed.")


def demonstrate_password_storage() -> None:
    record = derive_password_record("correct horse battery staple")

    accepted = verify_password("correct horse battery staple", record)
    rejected = verify_password("incorrect password", record)

    print("\nPassword-derived verification")
    print("=" * 72)
    print(f"Salt:              {record.salt.hex()}")
    print(f"Iterations:        {record.iterations}")
    print(f"Stored digest:     {record.digest.hex()}")
    print(f"Correct password:  {accepted}")
    print(f"Wrong password:    {rejected}")

    if not accepted or rejected:
        raise RuntimeError("Password verification demonstration failed.")


def benchmark() -> None:
    payload = b"x" * (1024 * 1024)

    print("\nBasic performance comparison")
    print("=" * 72)

    for algorithm in ("sha256", "sha512", "sha3_256", "sha3_512"):
        start = time.perf_counter()
        hashlib.new(algorithm, payload).digest()
        elapsed = time.perf_counter() - start

        print(f"{algorithm:10} {elapsed * 1000:8.3f} ms for 1 MiB")


def main() -> None:
    demonstrate_family()
    demonstrate_incremental_hashing()
    demonstrate_file_hashing()
    demonstrate_hmac()
    demonstrate_password_storage()
    benchmark()

    print("\nSecurity notes")
    print("=" * 72)
    print("SHA-1 is unsuitable for collision-resistant security.")
    print("SHA-256/SHA-512 and SHA-3 are appropriate modern hash families.")
    print("Raw hashes provide integrity fingerprints, not secret authentication.")
    print("Use HMAC when a shared secret is required.")
    print("Use salted, deliberately expensive password KDFs for passwords.")
    print("Digest comparison should use constant-time comparison where relevant.")


if __name__ == "__main__":
    main()
