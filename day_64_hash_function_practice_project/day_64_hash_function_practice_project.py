#!/usr/bin/env python3
"""
Hash Functions Practice Project

Demonstrates:
- SHA-256, SHA-512, SHA3-256 and SHA3-512
- Streaming file hashing
- HMAC-SHA256 authentication
- PBKDF2-HMAC-SHA256 password derivation
- File integrity manifests and verification
- Input validation and failure handling

Run:
    python hash_functions.py
    python hash_functions.py hash sha256 example.bin
    python hash_functions.py manifest ./releases ./manifest.json sha256
    python hash_functions.py verify-manifest ./releases ./manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile

from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable


class HashLabError(Exception):
    """Base exception for the project."""


class UnsupportedAlgorithmError(HashLabError):
    """Raised when an algorithm is not supported by the project."""


class ManifestError(HashLabError):
    """Raised when a manifest is malformed or unsafe."""


class HashAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"

    @property
    def digest_size(self) -> int:
        return hashlib.new(self.value).digest_size


@dataclass(frozen=True)
class DigestResult:
    algorithm: str
    hexadecimal: str
    bytes_processed: int

    def __post_init__(self) -> None:
        if self.bytes_processed < 0:
            raise ValueError("bytes_processed cannot be negative")

        if not self.hexadecimal:
            raise ValueError("A digest cannot be empty")


@dataclass(frozen=True)
class VerificationResult:
    relative_path: str
    expected_digest: str
    actual_digest: str | None
    passed: bool
    error: str | None = None


class HashEngine:
    """Provides approved digest, HMAC and password-hashing operations."""

    SUPPORTED_ALGORITHMS = frozenset(item.value for item in HashAlgorithm)
    PBKDF2_ITERATIONS = 310_000
    MIN_PBKDF2_ITERATIONS = 100_000
    MAX_PBKDF2_ITERATIONS = 2_000_000
    SALT_SIZE = 16

    @classmethod
    def validate_algorithm(cls, algorithm: str) -> str:
        normalized = algorithm.strip().lower()

        if normalized not in cls.SUPPORTED_ALGORITHMS:
            raise UnsupportedAlgorithmError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(sorted(cls.SUPPORTED_ALGORITHMS))}"
            )

        return normalized

    @classmethod
    def hash_bytes(
        cls,
        data: bytes,
        algorithm: str = "sha256",
    ) -> DigestResult:
        if not isinstance(data, bytes):
            raise TypeError("Hash input must be bytes")

        normalized = cls.validate_algorithm(algorithm)
        digest = hashlib.new(normalized)
        digest.update(data)

        return DigestResult(
            algorithm=normalized,
            hexadecimal=digest.hexdigest(),
            bytes_processed=len(data),
        )

    @classmethod
    def hash_stream(
        cls,
        stream: BinaryIO,
        algorithm: str = "sha256",
        chunk_size: int = 1024 * 1024,
    ) -> DigestResult:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        normalized = cls.validate_algorithm(algorithm)
        digest = hashlib.new(normalized)
        total_bytes = 0

        while True:
            chunk = stream.read(chunk_size)

            if chunk == b"":
                break

            if not isinstance(chunk, bytes):
                raise TypeError("Binary stream must return bytes")

            digest.update(chunk)
            total_bytes += len(chunk)

        return DigestResult(
            algorithm=normalized,
            hexadecimal=digest.hexdigest(),
            bytes_processed=total_bytes,
        )

    @classmethod
    def hash_file(
        cls,
        file_path: str | Path,
        algorithm: str = "sha256",
        chunk_size: int = 1024 * 1024,
    ) -> DigestResult:
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File does not exist: {path}")

        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        if path.is_symlink():
            raise ValueError("Symbolic links are not accepted as direct file inputs")

        with path.open("rb") as stream:
            return cls.hash_stream(stream, algorithm, chunk_size)

    @staticmethod
    def hmac_sha256(data: bytes, secret_key: bytes) -> str:
        if not isinstance(data, bytes) or not isinstance(secret_key, bytes):
            raise TypeError("HMAC data and key must be bytes")

        if not secret_key:
            raise ValueError("HMAC key cannot be empty")

        return hmac.new(
            secret_key,
            data,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_hmac_sha256(
        data: bytes,
        secret_key: bytes,
        supplied_hex_digest: str,
    ) -> bool:
        if not isinstance(supplied_hex_digest, str):
            return False

        try:
            supplied = bytes.fromhex(supplied_hex_digest)
        except ValueError:
            return False

        expected = bytes.fromhex(
            HashEngine.hmac_sha256(data, secret_key)
        )

        if len(supplied) != len(expected):
            return False

        return hmac.compare_digest(expected, supplied)

    @classmethod
    def hash_password(
        cls,
        password: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> str:
        if not isinstance(password, str) or not password:
            raise ValueError("Password must be a non-empty string")

        if not (
            cls.MIN_PBKDF2_ITERATIONS
            <= iterations
            <= cls.MAX_PBKDF2_ITERATIONS
        ):
            raise ValueError("PBKDF2 iteration count is outside the allowed range")

        salt = secrets.token_bytes(cls.SALT_SIZE)

        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )

        return (
            f"pbkdf2_sha256${iterations}"
            f"${salt.hex()}${derived_key.hex()}"
        )

    @classmethod
    def verify_password(
        cls,
        password: str,
        encoded_record: str,
    ) -> bool:
        if not isinstance(password, str) or not isinstance(encoded_record, str):
            return False

        try:
            algorithm, iteration_text, salt_hex, expected_hex = (
                encoded_record.split("$")
            )

            if algorithm != "pbkdf2_sha256":
                return False

            iterations = int(iteration_text)

            if not (
                cls.MIN_PBKDF2_ITERATIONS
                <= iterations
                <= cls.MAX_PBKDF2_ITERATIONS
            ):
                return False

            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(expected_hex)

            if len(salt) != cls.SALT_SIZE or len(expected) != 32:
                return False

            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                iterations,
                dklen=32,
            )

            return hmac.compare_digest(expected, actual)

        except (ValueError, TypeError):
            return False


def _safe_manifest_path(root: Path, relative_path: str) -> Path:
    """Resolve a manifest path without allowing traversal or symlink escapes."""

    if not isinstance(relative_path, str) or not relative_path:
        raise ManifestError("Manifest contains an empty file path")

    if "\\" in relative_path or relative_path.startswith("/"):
        raise ManifestError(f"Invalid manifest path: {relative_path}")

    parsed = PurePosixPath(relative_path)

    if any(part in ("", ".", "..") for part in parsed.parts):
        raise ManifestError(f"Unsafe manifest path: {relative_path}")

    resolved_root = root.resolve(strict=True)
    candidate = resolved_root.joinpath(*parsed.parts)

    if candidate.is_symlink():
        raise ManifestError(f"Symbolic link not permitted: {relative_path}")

    resolved_file = candidate.resolve(strict=True)

    if os.path.commonpath(
        [str(resolved_root), str(resolved_file)]
    ) != str(resolved_root):
        raise ManifestError(f"Path escapes the manifest root: {relative_path}")

    if not resolved_file.is_file():
        raise ManifestError(f"Manifest entry is not a regular file: {relative_path}")

    return resolved_file


def build_manifest(
    root_directory: str | Path,
    algorithm: str = "sha256",
    excluded_paths: Iterable[Path] = (),
) -> dict:
    root = Path(root_directory).resolve(strict=True)

    if not root.is_dir():
        raise ValueError("Manifest root must be a directory")

    normalized = HashEngine.validate_algorithm(algorithm)
    excluded = {Path(item).resolve() for item in excluded_paths}

    entries = []

    for current_directory, directories, filenames in os.walk(
        root,
        followlinks=False,
    ):
        current = Path(current_directory)

        directories[:] = sorted(
            directory
            for directory in directories
            if not (current / directory).is_symlink()
        )

        for filename in sorted(filenames):
            file_path = current / filename

            if file_path.is_symlink() or file_path.resolve() in excluded:
                continue

            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(root).as_posix()
            result = HashEngine.hash_file(file_path, normalized)

            entries.append(
                {
                    "path": relative_path,
                    "size": result.bytes_processed,
                    "digest": result.hexadecimal,
                }
            )

    entries.sort(key=lambda item: item["path"])

    return {
        "format_version": 1,
        "algorithm": normalized,
        "files": entries,
    }


def write_manifest(
    root_directory: str | Path,
    output_file: str | Path,
    algorithm: str = "sha256",
) -> int:
    root = Path(root_directory).resolve(strict=True)
    output = Path(output_file).resolve()

    if not root.is_dir():
        raise ValueError("Manifest root must be a directory")

    manifest = build_manifest(
        root,
        algorithm,
        excluded_paths=[output],
    )

    output.parent.mkdir(parents=True, exist_ok=True)

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(manifest, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())

        os.replace(temporary_path, output)
        return len(manifest["files"])

    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def verify_manifest(
    root_directory: str | Path,
    manifest_file: str | Path,
) -> list[VerificationResult]:
    root = Path(root_directory).resolve(strict=True)
    manifest_path = Path(manifest_file)

    if not root.is_dir():
        raise ValueError("Verification root must be a directory")

    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest does not exist: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)

    if not isinstance(manifest, dict):
        raise ManifestError("Manifest root must be a JSON object")

    if manifest.get("format_version") != 1:
        raise ManifestError("Unsupported manifest format version")

    algorithm = HashEngine.validate_algorithm(
        manifest.get("algorithm", "")
    )

    entries = manifest.get("files")

    if not isinstance(entries, list):
        raise ManifestError("Manifest files field must be a list")

    seen_paths: set[str] = set()
    results: list[VerificationResult] = []

    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError("Every manifest entry must be an object")

        relative_path = entry.get("path")
        expected_digest = entry.get("digest")
        expected_size = entry.get("size")

        if not isinstance(relative_path, str):
            raise ManifestError("Manifest path must be a string")

        if relative_path in seen_paths:
            raise ManifestError(f"Duplicate path in manifest: {relative_path}")

        seen_paths.add(relative_path)

        if not isinstance(expected_digest, str):
            raise ManifestError("Manifest digest must be a hexadecimal string")

        try:
            digest_bytes = bytes.fromhex(expected_digest)
        except ValueError as exc:
            raise ManifestError(
                f"Invalid digest for {relative_path}"
            ) from exc

        if len(digest_bytes) != HashAlgorithm(algorithm).digest_size:
            raise ManifestError(f"Incorrect digest length for {relative_path}")

        if not isinstance(expected_size, int) or expected_size < 0:
            raise ManifestError(f"Invalid file size for {relative_path}")

        try:
            file_path = _safe_manifest_path(root, relative_path)
            actual = HashEngine.hash_file(file_path, algorithm)

            size_matches = actual.bytes_processed == expected_size
            digest_matches = hmac.compare_digest(
                actual.hexadecimal,
                expected_digest.lower(),
            )

            passed = size_matches and digest_matches

            results.append(
                VerificationResult(
                    relative_path=relative_path,
                    expected_digest=expected_digest,
                    actual_digest=actual.hexadecimal,
                    passed=passed,
                    error=None if passed else "Size or digest mismatch",
                )
            )

        except (OSError, ValueError, ManifestError) as exc:
            results.append(
                VerificationResult(
                    relative_path=relative_path,
                    expected_digest=expected_digest,
                    actual_digest=None,
                    passed=False,
                    error=str(exc),
                )
            )

    return results


def run_self_tests() -> None:
    """Known-answer tests detect implementation or library misuse."""

    sha256_abc = HashEngine.hash_bytes(b"abc", "sha256")
    assert sha256_abc.hexadecimal == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )

    sha3_abc = HashEngine.hash_bytes(b"abc", "sha3_256")
    assert sha3_abc.hexadecimal == (
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )

    hmac_key = bytes([0x0B] * 20)
    hmac_message = b"Hi There"

    expected_hmac = (
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )

    actual_hmac = HashEngine.hmac_sha256(hmac_message, hmac_key)
    assert actual_hmac == expected_hmac

    assert HashEngine.verify_hmac_sha256(
        hmac_message,
        hmac_key,
        actual_hmac,
    )

    assert not HashEngine.verify_hmac_sha256(
        b"Modified message",
        hmac_key,
        actual_hmac,
    )

    empty_digest = HashEngine.hash_bytes(b"", "sha256")
    assert empty_digest.bytes_processed == 0

    password_record = HashEngine.hash_password("Practice-Password-2026")
    assert HashEngine.verify_password(
        "Practice-Password-2026",
        password_record,
    )
    assert not HashEngine.verify_password(
        "Incorrect-Password",
        password_record,
    )


def run_demo() -> None:
    run_self_tests()

    print("Hash Functions Practice Project")
    print("=" * 36)

    sample = b"release=2.4.0;component=payment-service"

    print("\nDigest examples:")

    for algorithm in HashAlgorithm:
        result = HashEngine.hash_bytes(sample, algorithm.value)
        print(f"{algorithm.value:10} {result.hexadecimal}")

    print("\nStreaming demonstration:")

    from io import BytesIO

    stream_result = HashEngine.hash_stream(
        BytesIO(sample),
        algorithm="sha256",
        chunk_size=8,
    )

    print(f"Bytes processed: {stream_result.bytes_processed}")
    print(f"SHA-256: {stream_result.hexadecimal}")

    print("\nHMAC demonstration:")

    demo_key = secrets.token_bytes(32)
    signature = HashEngine.hmac_sha256(sample, demo_key)

    print(f"Signature: {signature}")
    print(
        "Authentic message:",
        HashEngine.verify_hmac_sha256(sample, demo_key, signature),
    )
    print(
        "Modified message:",
        HashEngine.verify_hmac_sha256(
            sample + b";status=changed",
            demo_key,
            signature,
        ),
    )

    print("\nPassword derivation demonstration:")

    password_record = HashEngine.hash_password("Practice-Password-2026")
    print(f"Stored representation: {password_record}")
    print(
        "Correct password:",
        HashEngine.verify_password(
            "Practice-Password-2026",
            password_record,
        ),
    )
    print(
        "Incorrect password:",
        HashEngine.verify_password(
            "Wrong-Password",
            password_record,
        ),
    )

    print("\nAll known-answer tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hashing, HMAC, password derivation and file integrity"
    )

    subparsers = parser.add_subparsers(dest="command")

    hash_parser = subparsers.add_parser(
        "hash",
        help="Calculate a file digest",
    )
    hash_parser.add_argument("algorithm", choices=sorted(HashEngine.SUPPORTED_ALGORITHMS))
    hash_parser.add_argument("file")

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Create a directory integrity manifest",
    )
    manifest_parser.add_argument("root")
    manifest_parser.add_argument("output")
    manifest_parser.add_argument(
        "algorithm",
        nargs="?",
        default="sha256",
        choices=sorted(HashEngine.SUPPORTED_ALGORITHMS),
    )

    verify_parser = subparsers.add_parser(
        "verify-manifest",
        help="Verify files against an integrity manifest",
    )
    verify_parser.add_argument("root")
    verify_parser.add_argument("manifest")

    args = parser.parse_args()

    try:
        if args.command is None:
            run_demo()
            return 0

        if args.command == "hash":
            result = HashEngine.hash_file(args.file, args.algorithm)

            print(f"Algorithm: {result.algorithm}")
            print(f"File: {Path(args.file)}")
            print(f"Bytes: {result.bytes_processed}")
            print(f"Digest: {result.hexadecimal}")
            return 0

        if args.command == "manifest":
            count = write_manifest(
                args.root,
                args.output,
                args.algorithm,
            )

            print(f"Manifest created: {args.output}")
            print(f"Algorithm: {args.algorithm}")
            print(f"Files processed: {count}")
            return 0

        if args.command == "verify-manifest":
            results = verify_manifest(args.root, args.manifest)

            passed = sum(item.passed for item in results)
            failed = len(results) - passed

            for result in results:
                status = "PASS" if result.passed else "FAIL"
                print(f"[{status}] {result.relative_path}")

                if result.error:
                    print(f"       {result.error}")

            print(f"\nVerified: {passed}")
            print(f"Failed: {failed}")

            return 0 if failed == 0 else 1

        return 2

    except (
        HashLabError,
        OSError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
