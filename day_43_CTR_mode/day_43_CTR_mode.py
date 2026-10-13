"""
CTR Mode: Counter Mode Encryption and Decryption
================================================

A self-contained educational implementation of AES-CTR using Python's
standard library for counter management and the optional cryptography
package for AES block encryption.

Install the required package:
    python -m pip install cryptography

CTR encrypts by XORing plaintext with encrypted counter blocks. Encryption
and decryption use the same operation. This file demonstrates counter
construction, streaming, random-access processing, file encryption, input
validation, nonce management, and integrity protection with AES-GCM as a
separate authenticated-encryption alternative.

Security note:
AES-CTR alone does not authenticate data. Never reuse a nonce and initial
counter with the same key for different messages.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    raise SystemExit(
        "Install the dependency with: python -m pip install cryptography"
    ) from exc


AES_BLOCK_SIZE = 16
AES_KEY_LENGTHS = {16, 24, 32}
COUNTER_BITS = 128
COUNTER_SPACE = 1 << COUNTER_BITS


class CTRModeError(Exception):
    """Base exception for CTR-specific failures."""


class InvalidCounterError(CTRModeError):
    """Raised when a counter or counter range is invalid."""


class CounterOverflowError(CTRModeError):
    """Raised when processing would wrap the counter."""


class NonceReuseError(CTRModeError):
    """Raised when a nonce is reused by the demonstration key registry."""


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equally sized byte sequences."""
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths.")
    return bytes(a ^ b for a, b in zip(left, right))


def encode_counter(counter: int, width: int = AES_BLOCK_SIZE) -> bytes:
    """
    Encode a nonnegative integer as a fixed-width, big-endian counter.

    Big-endian encoding is conventional, but CTR counter layout is a
    protocol choice. Both parties must use the same layout.
    """
    if width <= 0:
        raise ValueError("Counter width must be positive.")
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise TypeError("Counter must be an integer.")
    if not 0 <= counter < (1 << (8 * width)):
        raise InvalidCounterError("Counter does not fit the selected width.")
    return counter.to_bytes(width, byteorder="big")


def decode_counter(encoded: bytes) -> int:
    """Decode a fixed-width, big-endian counter block."""
    if not encoded:
        raise ValueError("Counter encoding cannot be empty.")
    return int.from_bytes(encoded, byteorder="big")


@dataclass(frozen=True)
class CTRParameters:
    """Immutable AES-CTR parameters for one message."""
    key: bytes
    initial_counter: int

    def __post_init__(self) -> None:
        if len(self.key) not in AES_KEY_LENGTHS:
            raise ValueError("AES key must contain 16, 24, or 32 bytes.")
        if not 0 <= self.initial_counter < COUNTER_SPACE:
            raise InvalidCounterError("Initial counter is out of range.")


class AESCTR:
    """
    AES-CTR encryption and decryption.

    The initial_counter is a complete 128-bit counter block interpreted
    as a big-endian integer. The implementation deliberately increments
    the complete 128-bit block. It does not implement a nonce-prefix plus
    truncated-counter layout used by some protocols.
    """

    def __init__(self, key: bytes, initial_counter: int) -> None:
        self.parameters = CTRParameters(key, initial_counter)

    def _encrypt_counter_block(self, counter: int) -> bytes:
        """Encrypt one counter block with AES-ECB as the block primitive."""
        encryptor = Cipher(
            algorithms.AES(self.parameters.key),
            modes.ECB(),
        ).encryptor()
        return encryptor.update(encode_counter(counter)) + encryptor.finalize()

    def transform_at(self, data: bytes, byte_offset: int = 0) -> bytes:
        """
        Transform bytes starting at a byte offset within the CTR stream.

        The method supports random access without processing preceding
        plaintext. The same method encrypts and decrypts.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if not isinstance(byte_offset, int) or isinstance(byte_offset, bool):
            raise TypeError("Byte offset must be an integer.")
        if byte_offset < 0:
            raise ValueError("Byte offset cannot be negative.")
        if not data:
            return b""

        first_block = byte_offset // AES_BLOCK_SIZE
        intra_block_offset = byte_offset % AES_BLOCK_SIZE
        first_counter = self.parameters.initial_counter + first_block

        # Determine every counter block touched by this byte range.
        blocks_needed = (
            intra_block_offset + len(data) + AES_BLOCK_SIZE - 1
        ) // AES_BLOCK_SIZE
        last_counter = first_counter + blocks_needed - 1

        if last_counter >= COUNTER_SPACE:
            raise CounterOverflowError(
                "The requested data would wrap the 128-bit counter."
            )

        output = bytearray()
        remaining = memoryview(data)
        skip = intra_block_offset
        counter = first_counter

        while remaining:
            keystream = self._encrypt_counter_block(counter)
            usable = keystream[skip:]
            take = min(len(usable), len(remaining))
            output.extend(xor_bytes(bytes(remaining[:take]), usable[:take]))
            remaining = remaining[take:]
            skip = 0
            counter += 1

        return bytes(output)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a complete message."""
        return self.transform_at(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a complete message using the same CTR operation."""
        return self.transform_at(ciphertext)

    def iter_transform(
        self,
        chunks: Iterable[bytes],
    ) -> Iterable[bytes]:
        """
        Transform sequential chunks while preserving byte alignment.

        This method intentionally maintains a byte offset so that a final
        partial block does not cause the next chunk to restart the stream.
        """
        offset = 0
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise TypeError("Every chunk must be bytes.")
            transformed = self.transform_at(chunk, offset)
            yield transformed
            offset += len(chunk)


class NonceRegistry:
    """
    Demonstration-only registry preventing accidental nonce reuse.

    Production systems need durable, distributed allocation or another
    documented uniqueness strategy. An in-memory set does not survive
    restarts and cannot coordinate independent processes.
    """

    def __init__(self) -> None:
        self._used: dict[bytes, set[bytes]] = {}

    def reserve(self, key: bytes, nonce: bytes) -> None:
        if len(key) not in AES_KEY_LENGTHS:
            raise ValueError("Invalid AES key length.")
        if not nonce:
            raise ValueError("Nonce cannot be empty.")

        used_for_key = self._used.setdefault(key, set())
        if nonce in used_for_key:
            raise NonceReuseError(
                "This nonce has already been used with the same key."
            )
        used_for_key.add(nonce)


def aes_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Encrypt and authenticate using AES-GCM.

    AES-GCM is provided to demonstrate an authenticated alternative.
    A 12-byte nonce is the usual recommendation. The nonce must be unique
    for every encryption performed with a particular key.
    """
    if len(key) not in AES_KEY_LENGTHS:
        raise ValueError("Invalid AES key length.")
    if len(nonce) != 12:
        raise ValueError("Use a 12-byte AES-GCM nonce.")
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_and_tag: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Verify the authentication tag before returning plaintext."""
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)


def encrypt_file(
    source: Path,
    destination: Path,
    cipher: AESCTR,
    chunk_size: int = 64 * 1024,
) -> int:
    """
    Encrypt a file in bounded memory.

    The destination contains ciphertext only. The key and initial counter
    must be stored separately and securely. This function does not provide
    authentication, atomic publication, or crash-safe metadata management.
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive.")
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")

    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True)

    with source.open("rb") as input_file, destination.open("wb") as output_file:
        offset = 0
        while True:
            chunk = input_file.read(chunk_size)
            if not chunk:
                break
            encrypted = cipher.transform_at(chunk, offset)
            output_file.write(encrypted)
            offset += len(chunk)
            total += len(chunk)

    return total


def decrypt_file(
    source: Path,
    destination: Path,
    cipher: AESCTR,
    chunk_size: int = 64 * 1024,
) -> int:
    """Decrypt a file using the same counter and chunk-alignment rules."""
    return encrypt_file(source, destination, cipher, chunk_size)


def demonstrate_counter_blocks() -> None:
    print("\nCounter representation")
    for value in (0, 1, 255, 256, 65535):
        encoded = encode_counter(value)
        print(f"{value:>5} -> {encoded.hex()} -> {decode_counter(encoded)}")


def demonstrate_ctr() -> None:
    print("\nCTR encryption and decryption")
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    initial_counter = 7
    plaintext = (
        b"Release candidate: review passed; required checks are green."
    )

    ctr = AESCTR(key, initial_counter)
    ciphertext = ctr.encrypt(plaintext)
    recovered = ctr.decrypt(ciphertext)

    print("Plaintext: ", plaintext.decode("utf-8"))
    print("Ciphertext:", ciphertext.hex())
    print("Recovered: ", recovered.decode("utf-8"))
    assert recovered == plaintext

    # CTR has no padding requirement, so arbitrary message lengths work.
    for sample in (b"", b"A", b"15-bytes-text!", bytes(range(33))):
        assert ctr.decrypt(ctr.encrypt(sample)) == sample

    print("Arbitrary-length round trips passed.")


def demonstrate_random_access() -> None:
    print("\nRandom-access processing")
    key = os.urandom(32)
    ctr = AESCTR(key, 100)
    plaintext = b"Inspection report: defect count = 4; severity = high."
    ciphertext = ctr.encrypt(plaintext)

    start, end = 12, 30
    recovered_slice = ctr.decrypt(ciphertext[start:end], byte_offset=start)
    assert recovered_slice == plaintext[start:end]
    print("Recovered slice:", recovered_slice.decode("utf-8"))


def demonstrate_chunked_processing() -> None:
    print("\nChunked processing")
    key = os.urandom(16)
    ctr = AESCTR(key, 900)
    plaintext = b"Streaming data must preserve the same continuous keystream."
    chunks = [plaintext[:3], plaintext[3:19], plaintext[19:27], plaintext[27:]]

    ciphertext = b"".join(ctr.iter_transform(chunks))
    recovered = b"".join(
        ctr.iter_transform([ciphertext[:8], ciphertext[8:25], ciphertext[25:]])
    )
    assert recovered == plaintext
    print("Chunk sizes:", [len(chunk) for chunk in chunks])
    print("Streaming round trip passed.")


def demonstrate_nonce_safety() -> None:
    print("\nNonce allocation and authenticated encryption")
    key = os.urandom(32)
    registry = NonceRegistry()
    nonce = os.urandom(12)
    registry.reserve(key, nonce)

    try:
        registry.reserve(key, nonce)
    except NonceReuseError as exc:
        print("Duplicate rejected:", exc)

    associated_data = b"record-type=inspection;version=1"
    plaintext = b"Confidential inspection record"
    protected = aes_gcm_encrypt(key, nonce, plaintext, associated_data)
    assert aes_gcm_decrypt(key, nonce, protected, associated_data) == plaintext

    try:
        aes_gcm_decrypt(key, nonce, protected, b"record-type=altered")
    except Exception as exc:
        print("Modified associated data rejected:", type(exc).__name__)

    damaged = protected[:-1] + bytes([protected[-1] ^ 1])
    try:
        aes_gcm_decrypt(key, nonce, damaged, associated_data)
    except Exception as exc:
        print("Modified ciphertext rejected:", type(exc).__name__)


def demonstrate_file_round_trip() -> None:
    print("\nFile round trip")
    key = os.urandom(32)
    initial_counter = 12345
    ctr = AESCTR(key, initial_counter)
    content = (
        b"Daily inspection report\n"
        b"Equipment status: operational\n"
        b"Open findings: 2\n"
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        original = directory / "report.txt"
        encrypted = directory / "report.bin"
        recovered = directory / "recovered.txt"

        original.write_bytes(content)
        encrypt_file(original, encrypted, ctr, chunk_size=11)
        decrypt_file(encrypted, recovered, ctr, chunk_size=7)

        assert recovered.read_bytes() == content
        print("Original bytes:", original.stat().st_size)
        print("Ciphertext bytes:", encrypted.stat().st_size)
        print("File round trip passed.")


class CTRTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(16))
        self.cipher = AESCTR(self.key, 42)

    def test_round_trip_various_lengths(self) -> None:
        for length in (0, 1, 15, 16, 17, 31, 32, 257):
            data = bytes(index % 256 for index in range(length))
            self.assertEqual(self.cipher.decrypt(self.cipher.encrypt(data)), data)

    def test_random_access(self) -> None:
        data = bytes(range(100))
        encrypted = self.cipher.encrypt(data)
        self.assertEqual(
            self.cipher.decrypt(encrypted[13:49], byte_offset=13),
            data[13:49],
        )

    def test_chunk_boundaries(self) -> None:
        data = b"Variable-sized chunks are not block aligned."
        chunks = [data[:1], data[1:9], data[9:24], data[24:]]
        encrypted = b"".join(self.cipher.iter_transform(chunks))
        self.assertEqual(self.cipher.decrypt(encrypted), data)

    def test_invalid_key(self) -> None:
        with self.assertRaises(ValueError):
            AESCTR(b"short", 0)

    def test_counter_overflow(self) -> None:
        cipher = AESCTR(self.key, COUNTER_SPACE - 1)
        with self.assertRaises(CounterOverflowError):
            cipher.encrypt(b"x" * (AES_BLOCK_SIZE + 1))

    def test_invalid_offset(self) -> None:
        with self.assertRaises(ValueError):
            self.cipher.transform_at(b"x", -1)

    def test_nonce_reuse(self) -> None:
        registry = NonceRegistry()
        registry.reserve(self.key, b"unique-nonce")
        with self.assertRaises(NonceReuseError):
            registry.reserve(self.key, b"unique-nonce")


def main() -> None:
    demonstrate_counter_blocks()
    demonstrate_ctr()
    demonstrate_random_access()
    demonstrate_chunked_processing()
    demonstrate_nonce_safety()
    demonstrate_file_round_trip()

    print("\nUnit tests")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CTRTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
