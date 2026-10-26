from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable


class HashAlgorithm(Enum):
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    BLAKE2B = "blake2b"


@dataclass(frozen=True)
class HashResult:
    algorithm: HashAlgorithm
    digest_hex: str
    input_length: int


class HashingError(Exception):
    """Raised when hashing input or configuration is invalid."""


class CollisionResistanceModel:
    """
    Educational collision-resistance model.

    A cryptographic hash maps arbitrary-length input to a fixed-size digest.
    Collision resistance means that finding x != y with H(x) == H(y)
    should be computationally infeasible for a secure hash function.
    """

    _ALGORITHMS: dict[HashAlgorithm, Callable[[bytes], "hashlib._Hash"]] = {
        HashAlgorithm.SHA256: hashlib.sha256,
        HashAlgorithm.SHA3_256: hashlib.sha3_256,
        HashAlgorithm.BLAKE2B: lambda data: hashlib.blake2b(data, digest_size=32),
    }

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> None:
        if algorithm not in self._ALGORITHMS:
            raise HashingError(f"Unsupported algorithm: {algorithm}")
        self.algorithm = algorithm

    def hash_bytes(self, data: bytes) -> HashResult:
        if not isinstance(data, bytes):
            raise HashingError("hash_bytes requires bytes")
        digest = self._ALGORITHMS[self.algorithm](data).hexdigest()
        return HashResult(self.algorithm, digest, len(data))

    def hash_text(self, text: str) -> HashResult:
        if not isinstance(text, str):
            raise HashingError("hash_text requires a string")
        return self.hash_bytes(text.encode("utf-8"))

    def verify(self, data: bytes, expected_hex: str) -> bool:
        actual = self.hash_bytes(data).digest_hex
        return hmac.compare_digest(actual.lower(), expected_hex.lower())

    def hash_file(self, path: str | Path, chunk_size: int = 1024 * 1024) -> HashResult:
        if chunk_size <= 0:
            raise HashingError("chunk_size must be positive")

        file_path = Path(path)
        if not file_path.is_file():
            raise HashingError(f"File does not exist: {file_path}")

        constructor = self._ALGORITHMS[self.algorithm]
        digest = constructor(b"")

        try:
            with file_path.open("rb") as stream:
                while chunk := stream.read(chunk_size):
                    digest.update(chunk)
        except OSError as exc:
            raise HashingError(f"Unable to read {file_path}: {exc}") from exc

        return HashResult(self.algorithm, digest.hexdigest(), file_path.stat().st_size)


def truncated_digest(data: bytes, bits: int) -> int:
    """
    Produce a deliberately shortened digest for collision experiments.

    This is not suitable for security. It makes collisions observable at
    small output sizes so the birthday-bound effect can be demonstrated.
    """
    if bits <= 0 or bits > 64:
        raise ValueError("bits must be between 1 and 64")

    digest = hashlib.sha256(data).digest()
    value = int.from_bytes(digest[:8], "big")
    return value >> (64 - bits)


def find_demo_collision(bits: int, max_attempts: int = 100_000) -> tuple[bytes, bytes, int]:
    """
    Find a collision against a deliberately truncated SHA-256 digest.

    Expected work is approximately 2^(bits/2), illustrating the birthday
    bound. The full SHA-256 output remains 256 bits and is not being attacked.
    """
    if bits <= 0 or bits > 24:
        raise ValueError("Demo collision search supports 1..24 bits")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")

    seen: dict[int, bytes] = {}

    for _ in range(max_attempts):
        candidate = secrets.token_bytes(16)
        digest = truncated_digest(candidate, bits)

        previous = seen.get(digest)
        if previous is not None and previous != candidate:
            return previous, candidate, digest

        seen[digest] = candidate

    raise RuntimeError(
        f"No collision found in {max_attempts} attempts for {bits}-bit digest"
    )


@dataclass
class Document:
    document_id: str
    content: bytes
    digest: str


class IntegrityRegistry:
    """
    Small content-addressed registry.

    A digest identifies the exact byte sequence under the selected algorithm.
    The registry rejects an impossible hash collision if the same digest is
    presented for different content.
    """

    def __init__(self, hasher: CollisionResistanceModel) -> None:
        self.hasher = hasher
        self._documents: dict[str, Document] = {}

    def add(self, document_id: str, content: bytes) -> Document:
        if not document_id.strip():
            raise ValueError("document_id cannot be empty")

        digest = self.hasher.hash_bytes(content).digest_hex
        existing = self._documents.get(digest)

        if existing is not None and existing.content != content:
            raise RuntimeError(
                "Hash collision detected: identical digest for different content"
            )

        document = Document(document_id, content, digest)
        self._documents[digest] = document
        return document

    def verify(self, document_id: str, content: bytes) -> bool:
        digest = self.hasher.hash_bytes(content).digest_hex
        document = self._documents.get(digest)
        return document is not None and document.document_id == document_id


def demonstrate() -> None:
    print("=== Collision Resistance and Cryptographic Hashing ===")

    hasher = CollisionResistanceModel(HashAlgorithm.SHA256)

    messages = [
        b"repository commit A",
        b"repository commit B",
        b"repository commit A.",
        b"",
    ]

    for message in messages:
        result = hasher.hash_bytes(message)
        print(
            f"SHA-256 input={message!r}, "
            f"length={result.input_length}, "
            f"digest={result.digest_hex}"
        )

    first = hasher.hash_text("collision resistance")
    assert hasher.verify(b"collision resistance", first.digest_hex)
    assert not hasher.verify(b"collision resistance!", first.digest_hex)

    registry = IntegrityRegistry(hasher)
    stored = registry.add("commit-001", b"git-like commit content")
    print(f"\nStored digest: {stored.digest}")
    print(f"Valid content: {registry.verify('commit-001', b'git-like commit content')}")
    print(f"Modified content: {registry.verify('commit-001', b'changed commit content')}")

    print("\n=== Birthday-Bound Demonstration ===")
    for bits in (8, 12, 16):
        first_value, second_value, digest = find_demo_collision(bits)
        print(
            f"{bits}-bit collision: "
            f"{first_value.hex()} != {second_value.hex()}, "
            f"truncated_digest={digest}"
        )

    print("\n=== Security Notes ===")
    print("A collision is not the same as a preimage.")
    print("A collision attack seeks any two distinct inputs with the same digest.")
    print("For an n-bit ideal hash, generic collision search requires about 2^(n/2) work.")
    print("SHA-256 has a 256-bit output, giving a generic collision-security target near 128 bits.")
    print("Do not use truncated hashes for security-critical identity or signatures.")


if __name__ == "__main__":
    demonstrate()
