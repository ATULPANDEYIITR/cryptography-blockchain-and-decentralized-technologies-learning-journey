#!/usr/bin/env python3

"""
SHA-256 learning implementation.

This script implements SHA-256 directly from the FIPS 180-4 algorithm,
without external cryptographic dependencies. It demonstrates:

- message preprocessing and padding
- 512-bit block processing
- SHA-256 compression rounds
- hexadecimal digest generation
- comparison with hashlib
- streaming file hashing
- validation and failure handling
- a small integrity-verification workflow
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import tempfile
from pathlib import Path


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


def rotr(value: int, amount: int) -> int:
    """Rotate a 32-bit integer right."""
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x) & z)


def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def pad_message(message: bytes) -> bytes:
    """
    SHA-256 uses a 64-bit big-endian bit length.

    The message receives one '1' bit, zero bits, and the original
    length so that the final size is a multiple of 512 bits.
    """
    bit_length = len(message) * 8
    padded = message + b"\x80"

    zero_count = (56 - len(padded) % 64) % 64
    padded += b"\x00" * zero_count
    padded += struct.pack(">Q", bit_length)

    return padded


def compress_block(block: bytes, state: tuple[int, ...]) -> tuple[int, ...]:
    """Process one 512-bit message block."""
    if len(block) != 64:
        raise ValueError("SHA-256 compression requires exactly 64 bytes.")

    words = list(struct.unpack(">16I", block))
    schedule = words + [0] * 48

    for i in range(16, 64):
        schedule[i] = (
            small_sigma1(schedule[i - 2])
            + schedule[i - 7]
            + small_sigma0(schedule[i - 15])
            + schedule[i - 16]
        ) & MASK32

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
    """Return the raw 32-byte SHA-256 digest."""
    padded = pad_message(message)
    state = INITIAL_HASH

    for offset in range(0, len(padded), 64):
        state = compress_block(padded[offset:offset + 64], state)

    return b"".join(struct.pack(">I", word) for word in state)


def sha256_hex(message: bytes) -> str:
    return sha256_bytes(message).hex()


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    """
    Hash a file incrementally.

    A streaming implementation avoids loading large files into memory.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive.")

    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(f"File does not exist: {file_path}")

    digest = hashlib.sha256()

    with file_path.open("rb") as source:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def verify_digest(message: bytes, expected_hex: str) -> bool:
    """Use constant-time comparison for digest verification."""
    if len(expected_hex) != 64:
        return False

    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False

    actual = sha256_bytes(message)
    return hmac.compare_digest(actual, expected)


def verify_file(path: str | os.PathLike[str], expected_hex: str) -> bool:
    actual = bytes.fromhex(sha256_file(path))
    expected = bytes.fromhex(expected_hex)
    return hmac.compare_digest(actual, expected)


def run_known_vectors() -> None:
    vectors = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"hello world": (
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ),
    }

    for message, expected in vectors.items():
        actual = sha256_hex(message)
        assert actual == expected, f"Known vector failed for {message!r}"
        assert actual == hashlib.sha256(message).hexdigest()

    million_a = b"a" * 1_000_000
    expected = (
        "cdc76e5c9914fb9281a1c7e284d73e67"
        "f1809a48a497200e046d39ccc7112cd0"
    )
    assert sha256_hex(million_a) == expected
    print("Known SHA-256 vectors: PASS")


def run_file_demo() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "artifact.bin"
        payload = bytes(range(256)) * 4096
        path.write_bytes(payload)

        expected = hashlib.sha256(payload).hexdigest()
        actual = sha256_file(path)

        if not hmac.compare_digest(actual, expected):
            raise AssertionError("File integrity verification failed.")

        print(f"File SHA-256: {actual}")
        print(f"File verification: {'PASS' if verify_file(path, expected) else 'FAIL'}")


def main() -> None:
    run_known_vectors()

    examples = (
        b"repository artifact",
        b"SHA-256 is deterministic",
        bytes(range(32)),
    )

    for message in examples:
        digest = sha256_hex(message)
        reference = hashlib.sha256(message).hexdigest()

        print(f"\nMessage: {message!r}")
        print(f"SHA-256: {digest}")
        print(f"Matches hashlib: {hmac.compare_digest(digest, reference)}")
        print(f"Verification: {verify_digest(message, digest)}")

    run_file_demo()


if __name__ == "__main__":
    main()
