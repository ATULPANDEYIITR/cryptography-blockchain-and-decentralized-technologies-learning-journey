#!/usr/bin/env python3
"""
Cryptographic hash function properties:
- Determinism
- Fixed-length output
- Avalanche effect
- Preimage resistance demonstration
- Collision resistance experiment
- Second-preimage distinction
- Domain separation
- Integrity verification
- Hash chaining
- Password hashing warning
- File hashing
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path


SUPPORTED = {
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "blake2b": lambda data: hashlib.blake2b(data, digest_size=32),
}


def digest(data: bytes, algorithm: str = "sha256") -> bytes:
    """Return a cryptographic digest using an explicitly selected algorithm."""
    try:
        factory = SUPPORTED[algorithm.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from exc
    return factory(data).digest()


def digest_hex(data: bytes, algorithm: str = "sha256") -> str:
    return digest(data, algorithm).hex()


def demonstrate_determinism() -> None:
    message = b"repository commit: 8f42"
    first = digest_hex(message)
    second = digest_hex(message)

    assert first == second
    print("Determinism")
    print(f"  digest 1: {first}")
    print(f"  digest 2: {second}")


def demonstrate_fixed_length() -> None:
    print("\nFixed output length")
    for size in (0, 1, 10, 100, 100_000):
        data = os.urandom(size)
        result = digest(data)
        print(f"  input={size:6d} bytes -> output={len(result):2d} bytes")


def bit_difference(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("Inputs must have equal digest lengths")

    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def demonstrate_avalanche() -> None:
    original = b"transfer=1000;account=42"
    modified = b"transfer=1001;account=42"

    first = digest(original)
    second = digest(modified)
    changed_bits = bit_difference(first, second)
    total_bits = len(first) * 8

    print("\nAvalanche effect")
    print(f"  changed digest bits: {changed_bits}/{total_bits}")
    print(f"  percentage: {changed_bits / total_bits * 100:.2f}%")


def demonstrate_domain_separation() -> None:
    """Prefixing contexts prevents accidental cross-protocol reuse."""
    message = b"user=42"

    registration = digest(b"registration:" + message)
    audit = digest(b"audit:" + message)
    raw = digest(message)

    print("\nDomain separation")
    print(f"  raw          : {raw.hex()}")
    print(f"  registration : {registration.hex()}")
    print(f"  audit        : {audit.hex()}")

    assert registration != audit
    assert registration != raw


def demonstrate_integrity() -> None:
    original = b"release=2026.10.21;artifact=build-1842"
    expected = digest(original)

    received = original
    tampered = b"release=2026.10.21;artifact=build-1843"

    valid = hmac.compare_digest(expected, digest(received))
    invalid = hmac.compare_digest(expected, digest(tampered))

    print("\nIntegrity verification")
    print(f"  original accepted: {valid}")
    print(f"  tampered accepted: {invalid}")


def demonstrate_preimage_search() -> None:
    """
    A deliberately tiny truncated digest makes brute force practical.
    This is an educational experiment, not a secure attack against SHA-256.
    """
    target_input = b"invoice-731"
    target = digest(target_input)[:2]

    attempts = 0
    found: bytes | None = None

    for number in range(1_000_000):
        candidate = f"invoice-{number}".encode()
        attempts += 1
        if digest(candidate)[:2] == target:
            found = candidate
            break

    print("\nPreimage-resistance demonstration")
    print(f"  target truncated digest: {target.hex()}")
    print(f"  attempts: {attempts}")
    print(f"  candidate found: {found!r}")
    print("  security lesson: truncating a digest dramatically reduces brute-force cost.")


def demonstrate_collision_experiment() -> None:
    """
    Search for a collision in only 16 digest bits.
    A collision is expected quickly because the search space is tiny.
    """
    seen: dict[bytes, bytes] = {}

    for number in range(1_000_000):
        message = f"record-{number}".encode()
        short_digest = digest(message)[:2]

        previous = seen.get(short_digest)
        if previous is not None and previous != message:
            print("\nCollision experiment")
            print(f"  digest prefix: {short_digest.hex()}")
            print(f"  first message:  {previous!r}")
            print(f"  second message: {message!r}")
            print("  security lesson: collision resistance depends strongly on digest size.")
            return

        seen[short_digest] = message

    print("\nNo 16-bit collision found within the experiment limit.")


@dataclass(frozen=True)
class Block:
    index: int
    previous_hash: str
    payload: bytes
    current_hash: str


def make_block(index: int, previous_hash: str, payload: bytes) -> Block:
    material = (
        index.to_bytes(8, "big")
        + previous_hash.encode("ascii")
        + payload
    )
    current_hash = digest_hex(material)
    return Block(index, previous_hash, payload, current_hash)


def validate_chain(chain: list[Block]) -> bool:
    if not chain:
        return False

    for position, block in enumerate(chain):
        expected_previous = "0" * 64 if position == 0 else chain[position - 1].current_hash

        if block.previous_hash != expected_previous:
            return False

        rebuilt = make_block(block.index, block.previous_hash, block.payload)
        if not hmac.compare_digest(rebuilt.current_hash, block.current_hash):
            return False

    return True


def demonstrate_hash_chain() -> None:
    chain: list[Block] = []
    previous = "0" * 64

    for index, payload in enumerate(
        (b"commit:8f42", b"review:approved", b"merge:main")
    ):
        block = make_block(index, previous, payload)
        chain.append(block)
        previous = block.current_hash

    print("\nHash chain")
    print(f"  valid before modification: {validate_chain(chain)}")

    tampered = list(chain)
    changed = tampered[1]
    tampered[1] = make_block(
        changed.index,
        changed.previous_hash,
        b"review:rejected",
    )

    print(f"  valid after modification:  {validate_chain(tampered)}")


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    factory = SUPPORTED.get(algorithm.lower())
    if factory is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hasher = factory()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            hasher.update(chunk)

    return hasher.hexdigest()


def demonstrate_file_integrity() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "artifact.bin"
        path.write_bytes(os.urandom(4096))

        original_hash = hash_file(path)

        with path.open("ab") as file:
            file.write(b"\x00")

        modified_hash = hash_file(path)

        print("\nFile integrity")
        print(f"  original digest: {original_hash}")
        print(f"  modified digest: {modified_hash}")
        print(f"  unchanged: {hmac.compare_digest(original_hash, modified_hash)}")


def demonstrate_algorithm_properties() -> None:
    message = b"cryptographic hash properties"

    print("\nAlgorithm comparison")
    for name in SUPPORTED:
        result = digest_hex(message, name)
        print(f"  {name:8s}: {len(result) * 4:3d} bits")


def main() -> None:
    demonstrate_determinism()
    demonstrate_fixed_length()
    demonstrate_avalanche()
    demonstrate_domain_separation()
    demonstrate_integrity()
    demonstrate_preimage_search()
    demonstrate_collision_experiment()
    demonstrate_hash_chain()
    demonstrate_file_integrity()
    demonstrate_algorithm_properties()

    print("\nSecurity boundary")
    print("  Hashes are not encryption.")
    print("  A hash does not provide secrecy or confidentiality.")
    print("  Plain SHA-256 is not a password-storage scheme.")
    print("  Password storage should use a dedicated password KDF such as Argon2id, scrypt, or bcrypt.")
    print("  For authenticity, use a MAC such as HMAC or a digital signature rather than an unkeyed hash.")


if __name__ == "__main__":
    main()
