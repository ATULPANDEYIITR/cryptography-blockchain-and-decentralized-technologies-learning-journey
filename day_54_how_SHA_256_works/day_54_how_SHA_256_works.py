#!/usr/bin/env python3
"""
SHA-256 from first principles.

This module demonstrates:
1. Message preprocessing and padding
2. 512-bit block processing
3. Message schedule expansion
4. SHA-256 compression rounds
5. Chaining state updates
6. Comparison with Python's hashlib implementation
7. Avalanche-effect experimentation
8. Input validation and error handling

The implementation uses only the Python standard library.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Iterable


MASK32 = 0xFFFFFFFF

INITIAL_HASH = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def rotr32(value: int, amount: int) -> int:
    """Rotate a 32-bit integer right."""
    value &= MASK32
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def ch(x: int, y: int, z: int) -> int:
    """Choose bits from y or z according to x."""
    return ((x & y) ^ (~x & z)) & MASK32


def maj(x: int, y: int, z: int) -> int:
    """Majority function."""
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def big_sigma0(x: int) -> int:
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def big_sigma1(x: int) -> int:
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def small_sigma0(x: int) -> int:
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)


def small_sigma1(x: int) -> int:
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)


def pad_message(message: bytes) -> bytes:
    """
    SHA-256 padding:
    message || 0x80 || zeroes || 64-bit big-endian bit length.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")

    bit_length = len(message) * 8

    if bit_length >= 2**64:
        raise ValueError("SHA-256 input is limited to fewer than 2^64 bits")

    padded = bytearray(message)
    padded.append(0x80)

    while len(padded) % 64 != 56:
        padded.append(0)

    padded.extend(bit_length.to_bytes(8, "big"))
    return bytes(padded)


def build_schedule(block: bytes) -> list[int]:
    """Build the 64-word message schedule from one 512-bit block."""
    if len(block) != 64:
        raise ValueError("SHA-256 compression blocks must contain 64 bytes")

    words = [
        int.from_bytes(block[index:index + 4], "big")
        for index in range(0, 64, 4)
    ]

    schedule = words + [0] * 48

    for i in range(16, 64):
        schedule[i] = (
            small_sigma1(schedule[i - 2])
            + schedule[i - 7]
            + small_sigma0(schedule[i - 15])
            + schedule[i - 16]
        ) & MASK32

    return schedule


def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Process one 512-bit block through 64 SHA-256 rounds."""
    if len(state) != 8:
        raise ValueError("SHA-256 state must contain eight words")

    schedule = build_schedule(block)
    a, b, c, d, e, f, g, h = state

    for i in range(64):
        temp1 = (
            h
            + big_sigma1(e)
            + ch(e, f, g)
            + ROUND_CONSTANTS[i]
            + schedule[i]
        ) & MASK32

        temp2 = (big_sigma0(a) + maj(a, b, c)) & MASK32

        h = g
        g = f
        f = e
        e = (d + temp1) & MASK32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK32

    return tuple(
        (old + new) & MASK32
        for old, new in zip(state, (a, b, c, d, e, f, g, h))
    )


def sha256_bytes(message: bytes) -> bytes:
    """Compute SHA-256 without calling hashlib.sha256 internally."""
    padded = pad_message(message)
    state = INITIAL_HASH

    for offset in range(0, len(padded), 64):
        state = compress(state, padded[offset:offset + 64])

    return b"".join(word.to_bytes(4, "big") for word in state)


def sha256_hex(message: str) -> str:
    """Hash UTF-8 text and return the hexadecimal digest."""
    if not isinstance(message, str):
        raise TypeError("message must be a string")

    return sha256_bytes(message.encode("utf-8")).hex()


def hamming_distance(first: bytes, second: bytes) -> int:
    """Count differing bits between two equal-length byte strings."""
    if len(first) != len(second):
        raise ValueError("inputs must have equal length")

    return sum(
        (left ^ right).bit_count()
        for left, right in zip(first, second)
    )


@dataclass(frozen=True)
class HashExperiment:
    original: str
    modified: str
    original_digest: str
    modified_digest: str
    differing_bits: int


def avalanche_experiment(text: str) -> HashExperiment:
    """
    Change one bit of the UTF-8 message and measure digest differences.
    SHA-256 produces a 256-bit digest.
    """
    original = text.encode("utf-8")
    if not original:
        raise ValueError("avalanche experiment requires non-empty input")

    modified = bytearray(original)
    modified[0] ^= 0x01

    original_digest = sha256_bytes(original)
    modified_digest = sha256_bytes(bytes(modified))

    return HashExperiment(
        original=text,
        modified=bytes(modified).decode("utf-8", errors="replace"),
        original_digest=original_digest.hex(),
        modified_digest=modified_digest.hex(),
        differing_bits=hamming_distance(original_digest, modified_digest),
    )


def run_known_answer_tests() -> None:
    """Verify the implementation against standardized well-known inputs."""
    vectors = {
        b"": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
        b"abc": (
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        ),
        b"The quick brown fox jumps over the lazy dog": (
            "d7a8fbb307d7809469ca9abcb0082e4f"
            "8d5651e46d3cdb762d02d0bf37c9e592"
        ),
    }

    for message, expected in vectors.items():
        actual = sha256_bytes(message).hex()
        assert actual == expected, f"Known-answer test failed for {message!r}"

        standard = hashlib.sha256(message).hexdigest()
        assert actual == standard, "hashlib comparison failed"

    print("Known-answer tests: PASS")


def run_randomized_tests(count: int = 100) -> None:
    """Compare the custom implementation with hashlib on random messages."""
    if count <= 0:
        raise ValueError("count must be positive")

    for _ in range(count):
        message = secrets.token_bytes(secrets.randbelow(2049))
        custom = sha256_bytes(message).hex()
        standard = hashlib.sha256(message).hexdigest()
        assert custom == standard

    print(f"Randomized tests: PASS ({count} cases)")


def demonstrate_padding() -> None:
    message = b"abc"
    padded = pad_message(message)

    print("\nPadding demonstration")
    print(f"Original bytes: {len(message)}")
    print(f"Padded bytes:   {len(padded)}")
    print(f"Block count:    {len(padded) // 64}")
    print(f"Last 8 bytes:   {padded[-8:].hex()}")


def main() -> None:
    run_known_answer_tests()
    run_randomized_tests()
    demonstrate_padding()

    text = "Hello, SHA-256!"
    print("\nDigest demonstration")
    print(f"Input:  {text}")
    print(f"SHA-256: {sha256_hex(text)}")

    experiment = avalanche_experiment("security")
    print("\nAvalanche experiment")
    print(f"Original:        {experiment.original!r}")
    print(f"Modified:        {experiment.modified!r}")
    print(f"Original digest: {experiment.original_digest}")
    print(f"Modified digest: {experiment.modified_digest}")
    print(f"Differing bits:  {experiment.differing_bits} / 256")

    print("\nSecurity notes")
    print("- SHA-256 is a cryptographic hash, not encryption.")
    print("- Hashes are deterministic and one-way in the intended security model.")
    print("- Collision resistance does not mean collisions are mathematically impossible.")
    print("- Passwords should use dedicated password hashing schemes such as Argon2id, not raw SHA-256.")
    print("- SHA-256 operates on 512-bit blocks and maintains an eight-word 256-bit state.")


if __name__ == "__main__":
    main()
