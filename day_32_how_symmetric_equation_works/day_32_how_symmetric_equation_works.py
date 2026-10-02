#!/usr/bin/env python3
"""
Symmetric Encryption Laboratory

A self-contained educational implementation of symmetric encryption concepts,
progressing from byte-level XOR, through a Feistel construction, to a
production-oriented authenticated-encryption demonstration using Python's
standard library primitives where available.

This file intentionally distinguishes:
- Encryption: confidentiality transformation.
- Decryption: reversal using secret key material.
- Key: shared secret required by both communicating parties.
- Nonce/IV: public per-message value used by many secure constructions.
- Authentication: detection of tampering and wrong keys.
- AEAD: authenticated encryption with associated data.

The toy ciphers below are educational and are NOT suitable for protecting
real secrets. The standard-library AEAD demonstration uses AES-GCM when the
cryptography package is available; the script reports how to install it
rather than silently substituting an insecure construction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Fundamental byte operations
# ---------------------------------------------------------------------------

def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings.

    XOR is useful for understanding stream-cipher mechanics, but XORing
    plaintext with a repeated or predictable key is not a secure encryption
    scheme.
    """
    if len(left) != len(right):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(a ^ b for a, b in zip(left, right))


def xor_with_repeating_key(data: bytes, key: bytes) -> bytes:
    """Educational repeating-key XOR.

    Reusing the key periodically leaks structure and makes this construction
    vulnerable to frequency and known-plaintext analysis.
    """
    if not key:
        raise ValueError("key must not be empty")

    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def demonstrate_repeating_xor() -> None:
    print("\n=== Fundamental XOR model ===")

    plaintext = b"meet at gate seven"
    key = b"ICE"

    ciphertext = xor_with_repeating_key(plaintext, key)
    recovered = xor_with_repeating_key(ciphertext, key)

    print(f"Plaintext : {plaintext!r}")
    print(f"Key       : {key!r}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered : {recovered!r}")

    # The same keystream position is reused for many plaintext bytes.
    # Comparing two ciphertexts can therefore reveal relationships between
    # their plaintexts.
    first = b"payment approved"
    second = b"payment denied!"
    first_ct = xor_with_repeating_key(first, key)
    second_ct = xor_with_repeating_key(second, key)

    shared_length = min(len(first_ct), len(second_ct))
    relation = xor_bytes(first_ct[:shared_length], second_ct[:shared_length])

    print(f"Ciphertext XOR: {relation.hex()}")
    print(
        "Security lesson: key reuse exposes XOR relationships between "
        "plaintexts."
    )


# ---------------------------------------------------------------------------
# Educational Feistel network
# ---------------------------------------------------------------------------

BLOCK_SIZE = 8
HALF_SIZE = 4
ROUND_COUNT = 8


def rotate_left_32(value: int, amount: int) -> int:
    """Rotate a 32-bit integer left."""
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def feistel_round_function(right: int, subkey: int, round_number: int) -> int:
    """Produce a deterministic 32-bit round transformation.

    This is not a standardized cipher round function. It exists to expose
    the Feistel structure: only the round function and subkeys change from
    round to round, while the same structural transformation can be reversed.
    """
    value = (right ^ subkey) & 0xFFFFFFFF
    value = (value * 0x9E3779B1) & 0xFFFFFFFF
    value ^= (value >> 16)
    value = rotate_left_32(value, (round_number * 5) % 32)
    value ^= (value >> 13)
    return value & 0xFFFFFFFF


def derive_toy_subkeys(key: bytes) -> list[int]:
    """Derive educational round keys from arbitrary key bytes."""
    if len(key) < 8:
        raise ValueError("toy Feistel key must contain at least 8 bytes")

    digest = hashlib.sha256(key).digest()
    subkeys: list[int] = []

    for index in range(ROUND_COUNT):
        start = (index * 4) % (len(digest) - 3)
        subkeys.append(int.from_bytes(digest[start:start + 4], "big"))

    return subkeys


def feistel_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 64-bit block using the educational Feistel network."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Feistel block must be exactly 8 bytes")

    subkeys = derive_toy_subkeys(key)
    left = int.from_bytes(block[:HALF_SIZE], "big")
    right = int.from_bytes(block[HALF_SIZE:], "big")

    for round_number, subkey in enumerate(subkeys):
        left, right = right, left ^ feistel_round_function(
            right,
            subkey,
            round_number,
        )

    # A Feistel network normally swaps halves as part of its final layout.
    return right.to_bytes(HALF_SIZE, "big") + left.to_bytes(HALF_SIZE, "big")


def feistel_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Reverse the educational Feistel network.

    The crucial property is structural: the same round operation can be
    unwound by applying subkeys in reverse order.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Feistel block must be exactly 8 bytes")

    subkeys = derive_toy_subkeys(key)
    left = int.from_bytes(block[:HALF_SIZE], "big")
    right = int.from_bytes(block[HALF_SIZE:], "big")

    for round_number in reversed(range(ROUND_COUNT)):
        left, right = (
            right ^ feistel_round_function(left, subkeys[round_number], round_number),
            left,
        )

    return left.to_bytes(HALF_SIZE, "big") + right.to_bytes(HALF_SIZE, "big")


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad data so its length becomes an exact block-size multiple."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Validate and remove PKCS#7-style padding."""
    if not data or len(data) % block_size:
        raise ValueError("invalid padded data length")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise ValueError("invalid padding length")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid padding bytes")

    return data[:-padding_length]


def feistel_encrypt_message(message: bytes, key: bytes) -> bytes:
    """Encrypt an arbitrary message with the toy block construction."""
    padded = pkcs7_pad(message, BLOCK_SIZE)
    return b"".join(
        feistel_encrypt_block(padded[index:index + BLOCK_SIZE], key)
        for index in range(0, len(padded), BLOCK_SIZE)
    )


def feistel_decrypt_message(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt and unpad a toy Feistel ciphertext."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("invalid Feistel ciphertext length")

    padded = b"".join(
        feistel_decrypt_block(ciphertext[index:index + BLOCK_SIZE], key)
        for index in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return pkcs7_unpad(padded, BLOCK_SIZE)


def demonstrate_feistel() -> None:
    print("\n=== Feistel block-cipher structure ===")

    key = b"shared-secret-key"
    message = b"Confidential inventory transfer."

    ciphertext = feistel_encrypt_message(message, key)
    recovered = feistel_decrypt_message(ciphertext, key)

    print(f"Message   : {message!r}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered : {recovered!r}")

    assert recovered == message

    try:
        feistel_decrypt_message(ciphertext, b"wrong-secret")
    except ValueError as exc:
        print(f"Wrong key produced an error in this toy construction: {exc}")
    except Exception as exc:
        print(f"Wrong-key behavior is not a security guarantee: {type(exc).__name__}")

    print(
        "Important limitation: this construction is intentionally educational "
        "and provides neither modern security analysis nor authentication."
    )


# ---------------------------------------------------------------------------
# Stream-cipher model using a cryptographic hash as a keystream generator
# ---------------------------------------------------------------------------

def hmac_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a deterministic pseudorandom-looking keystream for education.

    HMAC-SHA-256 is used as a keystream generator here only to demonstrate
    counter-based stream encryption. This is not presented as a replacement
    for a standardized stream cipher or AEAD mode.
    """
    if not key:
        raise ValueError("key must not be empty")
    if not nonce:
        raise ValueError("nonce must not be empty")
    if length < 0:
        raise ValueError("length cannot be negative")

    output = bytearray()
    counter = 0

    while len(output) < length:
        block = hmac.new(
            key,
            nonce + struct.pack(">Q", counter),
            hashlib.sha256,
        ).digest()
        output.extend(block)
        counter += 1

    return bytes(output[:length])


def stream_encrypt_demo(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt by XORing plaintext with a generated keystream."""
    return xor_bytes(plaintext, hmac_keystream(key, nonce, len(plaintext)))


def demonstrate_stream_model() -> None:
    print("\n=== Stream-encryption model ===")

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    plaintext = b"stream encryption processes data byte by byte"

    ciphertext = stream_encrypt_demo(plaintext, key, nonce)
    recovered = stream_encrypt_demo(ciphertext, key, nonce)

    print(f"Nonce     : {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered : {recovered!r}")

    assert recovered == plaintext

    # A fresh nonce changes the keystream even when the secret key remains
    # constant. Nonce uniqueness is essential for many stream constructions.
    second_nonce = secrets.token_bytes(16)
    second_ciphertext = stream_encrypt_demo(plaintext, key, second_nonce)

    print(
        "Same plaintext with a fresh nonce has different ciphertext:",
        ciphertext != second_ciphertext,
    )


# ---------------------------------------------------------------------------
# Authenticated encryption using AES-GCM when cryptography is installed
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptedMessage:
    """Transport representation for an AEAD-encrypted message."""

    nonce: bytes
    ciphertext_and_tag: bytes
    associated_data: bytes

    def encode(self) -> str:
        """Serialize fields independently so they can cross a text channel."""
        return ".".join(
            base64.urlsafe_b64encode(part).decode("ascii").rstrip("=")
            for part in (
                self.nonce,
                self.ciphertext_and_tag,
                self.associated_data,
            )
        )

    @staticmethod
    def _decode_part(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    @classmethod
    def decode(cls, encoded: str) -> "EncryptedMessage":
        parts = encoded.split(".")
        if len(parts) != 3:
            raise ValueError("encrypted message must contain three fields")

        return cls(
            nonce=cls._decode_part(parts[0]),
            ciphertext_and_tag=cls._decode_part(parts[1]),
            associated_data=cls._decode_part(parts[2]),
        )


def import_aesgcm():
    """Import AES-GCM lazily so the rest of the educational file remains usable."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        return None


def generate_aes_key() -> bytes:
    """Generate a 256-bit AES key using the operating system CSPRNG."""
    return secrets.token_bytes(32)


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes = b"",
) -> EncryptedMessage:
    """Encrypt and authenticate plaintext using AES-GCM."""
    AESGCM = import_aesgcm()

    if AESGCM is None:
        raise RuntimeError(
            "AES-GCM demonstration requires the 'cryptography' package."
        )

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 128, 192, or 256 bits")

    # A 96-bit random nonce is the conventional AES-GCM choice. The nonce is
    # transmitted with the ciphertext and does not need to be secret.
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)

    ciphertext_and_tag = cipher.encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    return EncryptedMessage(
        nonce=nonce,
        ciphertext_and_tag=ciphertext_and_tag,
        associated_data=associated_data,
    )


def decrypt_aes_gcm(
    message: EncryptedMessage,
    key: bytes,
) -> bytes:
    """Authenticate and decrypt an AES-GCM message."""
    AESGCM = import_aesgcm()

    if AESGCM is None:
        raise RuntimeError(
            "AES-GCM demonstration requires the 'cryptography' package."
        )

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 128, 192, or 256 bits")

    return AESGCM(key).decrypt(
        message.nonce,
        message.ciphertext_and_tag,
        message.associated_data,
    )


def demonstrate_aead() -> None:
    print("\n=== Authenticated encryption with AES-GCM ===")

    AESGCM = import_aesgcm()

    if AESGCM is None:
        print(
            "AES-GCM demonstration skipped because 'cryptography' is not installed."
        )
        print("Install it with: python -m pip install cryptography")
        return

    key = generate_aes_key()
    plaintext = (
        b"Purchase order PO-4821: transfer 12500 INR "
        b"to the approved supplier."
    )
    associated_data = b"tenant=finance;version=1"

    encrypted = encrypt_aes_gcm(plaintext, key, associated_data)
    wire_format = encrypted.encode()
    decoded = EncryptedMessage.decode(wire_format)

    recovered = decrypt_aes_gcm(decoded, key)

    print(f"Nonce      : {encrypted.nonce.hex()}")
    print(f"Ciphertext : {encrypted.ciphertext_and_tag.hex()}")
    print(f"Wire format: {wire_format}")
    print(f"Recovered  : {recovered!r}")

    assert recovered == plaintext

    # GCM authenticates both ciphertext and associated data. Changing either
    # should cause decryption to fail rather than returning altered plaintext.
    tampered_ciphertext = bytearray(encrypted.ciphertext_and_tag)
    tampered_ciphertext[0] ^= 0x01

    tampered_message = EncryptedMessage(
        nonce=encrypted.nonce,
        ciphertext_and_tag=bytes(tampered_ciphertext),
        associated_data=encrypted.associated_data,
    )

    try:
        decrypt_aes_gcm(tampered_message, key)
    except Exception as exc:
        print(
            "Tampered ciphertext rejected:",
            type(exc).__name__,
        )

    altered_metadata = EncryptedMessage(
        nonce=encrypted.nonce,
        ciphertext_and_tag=encrypted.ciphertext_and_tag,
        associated_data=b"tenant=attacker;version=1",
    )

    try:
        decrypt_aes_gcm(altered_metadata, key)
    except Exception as exc:
        print(
            "Tampered associated data rejected:",
            type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Password-derived keys
# ---------------------------------------------------------------------------

def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = 600_000,
) -> bytes:
    """Derive a 256-bit key with PBKDF2-HMAC-SHA-256.

    Passwords should not normally be used directly as AES keys. A password
    KDF deliberately makes guessing more expensive and uses a unique salt.
    """
    if not password:
        raise ValueError("password must not be empty")
    if len(salt) < 16:
        raise ValueError("salt should contain at least 16 bytes")
    if iterations < 100_000:
        raise ValueError("iteration count is intentionally required to be high")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


def demonstrate_password_key_derivation() -> None:
    print("\n=== Password-to-key derivation ===")

    password = "Correct horse battery staple"
    salt = secrets.token_bytes(16)

    started = time.perf_counter()
    key = derive_key_from_password(password, salt)
    elapsed = time.perf_counter() - started

    print(f"Salt: {salt.hex()}")
    print(f"Derived AES-256 key: {key.hex()}")
    print(f"PBKDF2 derivation time: {elapsed:.4f}s")

    same_key = derive_key_from_password(password, salt)
    different_salt_key = derive_key_from_password(
        password,
        secrets.token_bytes(16),
    )

    assert key == same_key
    assert key != different_salt_key

    print("Same password + same salt produces the same key.")
    print("Same password + different salt produces a different key.")


# ---------------------------------------------------------------------------
# Secure file encryption demonstration
# ---------------------------------------------------------------------------

def encrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
    associated_data: bytes = b"",
) -> None:
    """Encrypt an entire file with AES-GCM.

    This demonstration reads the file into memory. Production applications
    should choose a chunked authenticated format for very large files instead
    of treating an unbounded file as one AES-GCM message.
    """
    if source.resolve() == destination.resolve():
        raise ValueError("source and destination must differ")

    plaintext = source.read_bytes()
    encrypted = encrypt_aes_gcm(plaintext, key, associated_data)

    # The file format stores lengths explicitly, preventing ambiguous parsing:
    # magic | version | nonce length | AAD length | ciphertext length | fields
    header = struct.pack(
        ">4sBBBBQ",
        b"SE01",
        1,
        len(encrypted.nonce),
        len(encrypted.associated_data),
        0,
        len(encrypted.ciphertext_and_tag),
    )

    payload = (
        header
        + encrypted.nonce
        + encrypted.associated_data
        + encrypted.ciphertext_and_tag
    )

    destination.write_bytes(payload)


def decrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
) -> None:
    """Parse and authenticate a file encrypted by encrypt_file."""
    payload = source.read_bytes()

    header_size = struct.calcsize(">4sBBBBQ")
    if len(payload) < header_size:
        raise ValueError("encrypted file is truncated")

    magic, version, nonce_length, aad_length, _, ciphertext_length = struct.unpack(
        ">4sBBBBQ",
        payload[:header_size],
    )

    if magic != b"SE01" or version != 1:
        raise ValueError("unsupported encrypted-file format")

    if nonce_length != 12:
        raise ValueError("unexpected nonce length")

    expected_size = (
        header_size
        + nonce_length
        + aad_length
        + ciphertext_length
    )

    if len(payload) != expected_size:
        raise ValueError("encrypted file has inconsistent lengths")

    cursor = header_size
    nonce = payload[cursor:cursor + nonce_length]
    cursor += nonce_length

    associated_data = payload[cursor:cursor + aad_length]
    cursor += aad_length

    ciphertext_and_tag = payload[cursor:cursor + ciphertext_length]

    message = EncryptedMessage(
        nonce=nonce,
        ciphertext_and_tag=ciphertext_and_tag,
        associated_data=associated_data,
    )

    plaintext = decrypt_aes_gcm(message, key)
    destination.write_bytes(plaintext)


def demonstrate_file_encryption() -> None:
    print("\n=== Authenticated file encryption ===")

    if import_aesgcm() is None:
        print("File demonstration skipped because 'cryptography' is unavailable.")
        return

    base = Path.cwd() / "symmetric_encryption_demo"
    base.mkdir(exist_ok=True)

    source = base / "transaction.txt"
    encrypted = base / "transaction.sealed"
    recovered = base / "transaction.recovered.txt"

    source.write_text(
        "Transaction reference: TX-2026-1002\n"
        "Amount: 12500 INR\n"
        "Status: approved\n",
        encoding="utf-8",
    )

    key = generate_aes_key()

    encrypt_file(
        source,
        encrypted,
        key,
        associated_data=b"format=SE01;purpose=transaction",
    )
    decrypt_file(encrypted, recovered, key)

    print(f"Source    : {source}")
    print(f"Encrypted : {encrypted}")
    print(f"Recovered : {recovered}")
    print("Recovered content matches:", source.read_bytes() == recovered.read_bytes())

    # Do not leave a reusable secret or sensitive demo artifacts scattered
    # across a real project. This example removes the generated files after
    # demonstrating the format.
    for path in (source, encrypted, recovered):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    try:
        base.rmdir()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Key and nonce validation
# ---------------------------------------------------------------------------

def validate_aes_gcm_inputs(key: bytes, nonce: bytes) -> None:
    """Apply explicit validation before a cryptographic operation."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key length must be 16, 24, or 32 bytes")

    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce should be 12 bytes in this application")


def demonstrate_validation() -> None:
    print("\n=== Validation and failure conditions ===")

    try:
        validate_aes_gcm_inputs(b"short", secrets.token_bytes(12))
    except ValueError as exc:
        print(f"Invalid key rejected: {exc}")

    try:
        validate_aes_gcm_inputs(secrets.token_bytes(32), b"short")
    except ValueError as exc:
        print(f"Invalid nonce rejected: {exc}")


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------

def demonstrate_constant_time_comparison() -> None:
    print("\n=== Authentication-tag comparison ===")

    expected_tag = hashlib.sha256(b"authenticated message").digest()
    received_tag = bytes(expected_tag)

    # Do not compare authentication tags with ordinary early-exit equality
    # when implementing your own authentication layer. Constant-time
    # comparison reduces timing information available to an attacker.
    print(
        "Tag accepted:",
        hmac.compare_digest(expected_tag, received_tag),
    )

    modified_tag = bytearray(received_tag)
    modified_tag[-1] ^= 1

    print(
        "Modified tag accepted:",
        hmac.compare_digest(expected_tag, bytes(modified_tag)),
    )


# ---------------------------------------------------------------------------
# Secure design checklist represented as executable assertions
# ---------------------------------------------------------------------------

def demonstrate_secure_design_invariants() -> None:
    print("\n=== Security invariants ===")

    key_a = generate_aes_key()
    key_b = generate_aes_key()

    assert len(key_a) == 32
    assert len(key_b) == 32
    assert key_a != key_b

    nonce_a = secrets.token_bytes(12)
    nonce_b = secrets.token_bytes(12)

    assert nonce_a != nonce_b

    print("Cryptographically random 256-bit keys are generated.")
    print("Fresh nonces are generated independently for messages.")
    print(
        "The key remains secret; nonce and associated data can be transmitted "
        "alongside ciphertext."
    )


# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

def main() -> None:
    print("SYMMETRIC ENCRYPTION LABORATORY")
    print("=" * 80)
    print(
        "The examples move from reversible XOR mechanics to block-cipher "
        "structure, stream-style processing, password-derived keys, and "
        "authenticated encryption."
    )

    demonstrate_repeating_xor()
    demonstrate_feistel()
    demonstrate_stream_model()
    demonstrate_aead()
    demonstrate_password_key_derivation()
    demonstrate_file_encryption()
    demonstrate_validation()
    demonstrate_constant_time_comparison()
    demonstrate_secure_design_invariants()

    print("\n=== Practical security boundary ===")
    print(
        "For real applications, use a vetted cryptographic library and a "
        "standard authenticated-encryption construction such as AES-GCM. "
        "Do not deploy the toy XOR, Feistel, or hash-keystream constructions "
        "from this file as cryptographic protocols."
    )


if __name__ == "__main__":
    main()
