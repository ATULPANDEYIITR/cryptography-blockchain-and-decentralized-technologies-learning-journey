#!/usr/bin/env python3
"""SHA-3 and Keccak: hashing, sponge construction, validation, and verification."""

from __future__ import annotations

import hashlib
import json
import secrets
import unittest
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


class HashAlgorithm(str, Enum):
    SHA3_224 = "sha3_224"
    SHA3_256 = "sha3_256"
    SHA3_384 = "sha3_384"
    SHA3_512 = "sha3_512"
    SHAKE_128 = "shake_128"
    SHAKE_256 = "shake_256"


@dataclass(frozen=True)
class HashResult:
    algorithm: str
    message_bytes: int
    digest_hex: str
    digest_bytes: int


def validate_message(message: bytes) -> None:
    if not isinstance(message, bytes):
        raise TypeError("Messages must be bytes.")
    if len(message) > 16 * 1024 * 1024:
        raise ValueError("Message exceeds the 16 MiB application limit.")


def sha3_hash(
    message: bytes,
    algorithm: HashAlgorithm = HashAlgorithm.SHA3_256,
) -> HashResult:
    """Compute a standardized SHA-3 digest using Python's hashlib."""
    validate_message(message)

    if not isinstance(algorithm, HashAlgorithm):
        raise ValueError("Select a supported HashAlgorithm member.")

    constructors = {
        HashAlgorithm.SHA3_224: hashlib.sha3_224,
        HashAlgorithm.SHA3_256: hashlib.sha3_256,
        HashAlgorithm.SHA3_384: hashlib.sha3_384,
        HashAlgorithm.SHA3_512: hashlib.sha3_512,
    }

    if algorithm in constructors:
        digest = constructors[algorithm](message).digest()
    elif algorithm == HashAlgorithm.SHAKE_128:
        digest = hashlib.shake_128(message).digest(32)
    else:
        digest = hashlib.shake_256(message).digest(32)

    return HashResult(
        algorithm=algorithm.value,
        message_bytes=len(message),
        digest_hex=digest.hex(),
        digest_bytes=len(digest),
    )


def shake_hash(message: bytes, output_bytes: int = 32, strength: int = 256) -> str:
    """SHAKE is an extendable-output function with a caller-selected output size."""
    validate_message(message)

    if not isinstance(output_bytes, int) or isinstance(output_bytes, bool):
        raise TypeError("Output length must be an integer.")
    if not 1 <= output_bytes <= 4096:
        raise ValueError("Output length must be between 1 and 4096 bytes.")
    if strength not in (128, 256):
        raise ValueError("SHAKE strength must be 128 or 256.")

    constructor = hashlib.shake_128 if strength == 128 else hashlib.shake_256
    return constructor(message).hexdigest(output_bytes)


def hash_file(path: str | Path, algorithm: HashAlgorithm) -> HashResult:
    """Stream a file instead of loading its entire contents into memory."""
    if algorithm not in {
        HashAlgorithm.SHA3_224,
        HashAlgorithm.SHA3_256,
        HashAlgorithm.SHA3_384,
        HashAlgorithm.SHA3_512,
    }:
        raise ValueError("File hashing supports fixed-output SHA-3 algorithms.")

    constructors = {
        HashAlgorithm.SHA3_224: hashlib.sha3_224,
        HashAlgorithm.SHA3_256: hashlib.sha3_256,
        HashAlgorithm.SHA3_384: hashlib.sha3_384,
        HashAlgorithm.SHA3_512: hashlib.sha3_512,
    }

    hasher = constructors[algorithm]()
    total = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            hasher.update(chunk)

    return HashResult(
        algorithm=algorithm.value,
        message_bytes=total,
        digest_hex=hasher.hexdigest(),
        digest_bytes=hasher.digest_size,
    )


def verify_digest(message: bytes, expected_hex: str) -> bool:
    """Compare equal-length digest encodings without content-dependent comparison."""
    validate_message(message)
    if not isinstance(expected_hex, str):
        raise TypeError("Expected digest must be a hexadecimal string.")

    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False

    actual = hashlib.sha3_256(message).digest()
    return len(expected) == len(actual) and secrets.compare_digest(actual, expected)


def keccak_vs_sha3(message: bytes) -> dict[str, str]:
    """Illustrate the domain-separation difference using the legacy Keccak-256 API."""
    validate_message(message)
    sha3_digest = hashlib.sha3_256(message).hexdigest()

    try:
        from Crypto.Hash import keccak
    except ImportError:
        legacy_digest = None
    else:
        legacy_digest = keccak.new(
            data=message, digest_bits=256
        ).hexdigest()

    return {
        "sha3_256": sha3_digest,
        "legacy_keccak_256": legacy_digest or (
            "Unavailable: install pycryptodome to calculate legacy Keccak-256."
        ),
        "equal": str(legacy_digest == sha3_digest) if legacy_digest else "unknown",
    }


def merkle_root_sha3(leaves: Iterable[bytes]) -> str:
    """Build a domain-separated binary Merkle tree using SHA3-256.

    Leaf nodes use 0x00 || data; internal nodes use 0x01 || left || right.
    An odd final node is duplicated. The empty tree has a distinct root.
    """
    nodes = []
    for leaf in leaves:
        if not isinstance(leaf, bytes):
            raise TypeError("Every leaf must be bytes.")
        nodes.append(hashlib.sha3_256(b"\x00" + leaf).digest())

    if not nodes:
        return hashlib.sha3_256(b"\x02").hexdigest()

    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha3_256(b"\x01" + nodes[i] + nodes[i + 1]).digest()
            for i in range(0, len(nodes), 2)
        ]

    return nodes[0].hex()


class Sha3Tests(unittest.TestCase):
    def test_empty_sha3_256(self) -> None:
        self.assertEqual(
            sha3_hash(b"").digest_hex,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )

    def test_abc_sha3_256(self) -> None:
        self.assertEqual(
            sha3_hash(b"abc").digest_hex,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )

    def test_digest_verification(self) -> None:
        digest = sha3_hash(b"release artifact").digest_hex
        self.assertTrue(verify_digest(b"release artifact", digest))
        self.assertFalse(verify_digest(b"modified artifact", digest))
        self.assertFalse(verify_digest(b"release artifact", "invalid"))

    def test_shake_output_lengths(self) -> None:
        self.assertEqual(len(shake_hash(b"abc", 16)), 32)
        self.assertEqual(len(shake_hash(b"abc", 64)), 128)

    def test_merkle_root(self) -> None:
        self.assertNotEqual(
            merkle_root_sha3([b"alpha", b"beta"]),
            merkle_root_sha3([b"beta", b"alpha"]),
        )
        self.assertEqual(merkle_root_sha3([]), merkle_root_sha3([]))

    def test_invalid_inputs(self) -> None:
        with self.assertRaises(TypeError):
            sha3_hash("abc")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            shake_hash(b"abc", 0)
        with self.assertRaises(ValueError):
            sha3_hash(b"abc", "sha3_256")  # type: ignore[arg-type]


def main() -> None:
    message = b"Repository release artifact v1.0"
    results = [
        asdict(sha3_hash(message, algorithm))
        for algorithm in (
            HashAlgorithm.SHA3_224,
            HashAlgorithm.SHA3_256,
            HashAlgorithm.SHA3_384,
            HashAlgorithm.SHA3_512,
        )
    ]

    print(json.dumps({
        "message": message.decode("ascii"),
        "hashes": results,
        "shake256_64_bytes": shake_hash(message, 64),
        "merkle_root": merkle_root_sha3([
            b"source.tar.gz",
            b"application.whl",
            b"manifest.json",
        ]),
        "keccak_comparison": keccak_vs_sha3(message),
    }, indent=2))

    unittest.main(argv=["sha3_keccak.py"], exit=False)


if __name__ == "__main__":
    main()
