#!/usr/bin/env python3

"""
Second-preimage resistance simulator.

A second-preimage attack starts with a fixed message M and attempts to find
a different message M' such that H(M) == H(M'). This differs from collision
searching, where both messages may be chosen freely.

This program uses a deliberately small hash width so that experiments finish
quickly. It is an educational model, not a secure cryptographic hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import secrets
import time
from typing import Callable, Optional


class AttackResult(Enum):
    NOT_FOUND = "not-found"
    FOUND = "found"
    INVALID_TARGET = "invalid-target"


@dataclass(frozen=True)
class Message:
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("Message data must be bytes")
        if not self.data:
            raise ValueError("Message cannot be empty")


@dataclass(frozen=True)
class SearchResult:
    result: AttackResult
    target_digest: bytes
    original: bytes
    second_preimage: Optional[bytes]
    attempts: int
    elapsed_seconds: float


class HashModel:
    """A configurable truncated hash model for controlled experiments."""

    def __init__(self, bits: int = 16) -> None:
        if bits <= 0 or bits > 256:
            raise ValueError("bits must be between 1 and 256")
        self.bits = bits

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def digest(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("Hash input must be bytes")

        raw = hashlib.sha256(data).digest()
        value = int.from_bytes(raw, "big") & self.mask
        width = (self.bits + 7) // 8
        return value.to_bytes(width, "big")

    def hex_digest(self, data: bytes) -> str:
        return self.digest(data).hex()


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


def make_candidate(original: bytes, counter: int) -> bytes:
    """
    Generate deterministic candidates that are guaranteed to differ from
    the target message. Length-prefixing prevents simple textual ambiguity.
    """
    return original + b"\x00SECOND-PREIMAGE\x00" + counter.to_bytes(8, "big")


def find_second_preimage(
    hasher: Callable[[bytes], bytes],
    original: bytes,
    max_attempts: int = 1_000_000,
) -> SearchResult:
    if not isinstance(original, bytes) or not original:
        raise ValueError("original must be non-empty bytes")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")

    target = hasher(original)
    started = time.perf_counter()

    for attempt in range(1, max_attempts + 1):
        candidate = make_candidate(original, attempt)

        if candidate == original:
            continue

        if constant_time_equal(hasher(candidate), target):
            return SearchResult(
                result=AttackResult.FOUND,
                target_digest=target,
                original=original,
                second_preimage=candidate,
                attempts=attempt,
                elapsed_seconds=time.perf_counter() - started,
            )

    return SearchResult(
        result=AttackResult.NOT_FOUND,
        target_digest=target,
        original=original,
        second_preimage=None,
        attempts=max_attempts,
        elapsed_seconds=time.perf_counter() - started,
    )


def verify_second_preimage(
    hasher: Callable[[bytes], bytes],
    original: bytes,
    candidate: bytes,
) -> bool:
    if not original or not candidate:
        return False
    if original == candidate:
        return False

    return constant_time_equal(hasher(original), hasher(candidate))


def demonstrate_real_sha256() -> None:
    """
    SHA-256 is used without truncation here. A practical second-preimage
    search is computationally infeasible, so the demonstration intentionally
    performs only a single verification rather than an exhaustive search.
    """
    original = b"approved transaction: account-A -> account-B : 100"
    modified = original + b" with unrelated metadata"

    original_hash = hashlib.sha256(original).hexdigest()
    modified_hash = hashlib.sha256(modified).hexdigest()

    print("\nReal SHA-256 verification")
    print("Original digest :", original_hash)
    print("Modified digest :", modified_hash)
    print("Second preimage :", verify_second_preimage(hashlib.sha256_digest if False else lambda x: hashlib.sha256(x).digest(), original, modified))


def main() -> None:
    print("Second-Preimage Resistance Laboratory")
    print("=" * 42)

    # A small digest makes an accidental second preimage observable.
    model = HashModel(bits=16)
    original = Message(
        b"release-artifact: repository=ledger, version=4.2.1, "
        b"sha-policy=second-preimage-test"
    )

    print(f"Experimental digest width: {model.bits} bits")
    print(f"Target message: {original.data!r}")
    print(f"Target digest: {model.hex_digest(original.data)}")

    result = find_second_preimage(model.digest, original.data, 500_000)

    print("\nControlled search")
    print(f"Result: {result.result.value}")
    print(f"Attempts: {result.attempts:,}")
    print(f"Elapsed: {result.elapsed_seconds:.6f} seconds")

    if result.second_preimage is not None:
        valid = verify_second_preimage(
            model.digest,
            result.original,
            result.second_preimage,
        )
        print(f"Candidate differs: {result.second_preimage != result.original}")
        print(f"Digest equality verified: {valid}")
        print(f"Candidate: {result.second_preimage!r}")
    else:
        print("No second preimage was found within the configured budget.")

    demonstrate_real_sha256()

    print("\nSecurity observations")
    print("- Second-preimage resistance fixes the original message and its digest.")
    print("- Truncating a digest makes experiments practical but weakens security.")
    print("- SHA-256 has a 256-bit output and is not realistically searchable this way.")
    print("- Applications must authenticate or sign data when authenticity is required.")
    print("- Hash equality alone does not prove that a message came from a trusted party.")


if __name__ == "__main__":
    main()
