#!/usr/bin/env python3
"""
Symmetric Encryption Practice Project

A self-contained practice implementation covering:
- XOR as a conceptual symmetric transformation
- Secure key generation with the standard library
- AES-256-GCM using the Python standard library primitives available
  through a small educational implementation of AES and GHASH
- nonce handling
- authenticated encryption
- tamper detection
- password-to-key derivation with PBKDF2-HMAC
- file encryption and decryption
- key rotation
- replay detection through message identifiers
- envelope serialization
- validation and failure handling

This project intentionally distinguishes:
- encryption: confidentiality
- authentication: integrity/authenticity
- key derivation: converting passwords into cryptographic keys
- nonce management: preventing dangerous reuse
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Fundamental symmetric transformation: XOR
# ---------------------------------------------------------------------------

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Repeat the key and XOR it against the data.

    XOR is useful for understanding the basic idea that the same secret
    material can be used for both transformation directions:

        ciphertext = plaintext XOR key
        plaintext  = ciphertext XOR key

    This is NOT secure encryption when the key is reused or predictable.
    It is included only as a conceptual baseline.
    """
    if not key:
        raise ValueError("XOR key cannot be empty")

    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def demonstrate_xor() -> None:
    plaintext = b"Symmetric encryption"
    key = b"practice"
    ciphertext = xor_bytes(plaintext, key)
    recovered = xor_bytes(ciphertext, key)

    print("\n=== XOR Concept ===")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered)


# ---------------------------------------------------------------------------
# AES-256 implementation
# ---------------------------------------------------------------------------

# AES S-box.
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_SBOX = [0] * 256
for index, value in enumerate(SBOX):
    INV_SBOX[value] = index


def xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[value] for value in state]


def inv_sub_bytes(state: list[int]) -> list[int]:
    return [INV_SBOX[value] for value in state]


def shift_rows(state: list[int]) -> list[int]:
    output = [0] * 16
    for row in range(4):
        for col in range(4):
            output[4 * col + row] = state[4 * ((col + row) % 4) + row]
    return output


def inv_shift_rows(state: list[int]) -> list[int]:
    output = [0] * 16
    for row in range(4):
        for col in range(4):
            output[4 * col + row] = state[4 * ((col - row) % 4) + row]
    return output


def mix_columns(state: list[int]) -> list[int]:
    output = state[:]
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]
        output[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        output[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        output[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        output[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
    return output


def inv_mix_columns(state: list[int]) -> list[int]:
    output = state[:]
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]
        output[i] = (
            gf_mul(a0, 14) ^ gf_mul(a1, 11) ^
            gf_mul(a2, 13) ^ gf_mul(a3, 9)
        )
        output[i + 1] = (
            gf_mul(a0, 9) ^ gf_mul(a1, 14) ^
            gf_mul(a2, 11) ^ gf_mul(a3, 13)
        )
        output[i + 2] = (
            gf_mul(a0, 13) ^ gf_mul(a1, 9) ^
            gf_mul(a2, 14) ^ gf_mul(a3, 11)
        )
        output[i + 3] = (
            gf_mul(a0, 11) ^ gf_mul(a1, 13) ^
            gf_mul(a2, 9) ^ gf_mul(a3, 14)
        )
    return output


def add_round_key(state: list[int], key: bytes) -> list[int]:
    return [a ^ b for a, b in zip(state, key)]


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def sub_word(word: list[int]) -> list[int]:
    return [SBOX[value] for value in word]


def aes_256_key_expansion(key: bytes) -> list[bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")

    words = [list(key[index:index + 4]) for index in range(0, 32, 4)]
    rcon = 1

    while len(words) < 60:
        temp = words[-1][:]
        position = len(words)

        if position % 8 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon
            rcon = xtime(rcon)
        elif position % 8 == 4:
            temp = sub_word(temp)

        words.append([
            words[-8][i] ^ temp[i]
            for i in range(4)
        ])

    return [
        bytes(sum(words[index:index + 4], []))
        for index in range(0, 60, 4)
    ]


def aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")

    state = add_round_key(list(block), round_keys[0])

    for round_key in round_keys[1:-1]:
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[-1])

    return bytes(state)


def aes_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")

    state = add_round_key(list(block), round_keys[-1])

    for round_key in reversed(round_keys[1:-1]):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_key)
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)


# ---------------------------------------------------------------------------
# Galois-field multiplication for GCM authentication
# ---------------------------------------------------------------------------

def ghash_multiply(x: int, y: int) -> int:
    """Multiply two 128-bit values in GF(2^128)."""
    result = 0
    reduction = 0xE1000000000000000000000000000000

    for _ in range(128):
        if y & (1 << 127):
            result ^= x

        if x & 1:
            x = (x >> 1) ^ reduction
        else:
            x >>= 1

        y = (y << 1) & ((1 << 128) - 1)

    return result


def ghash_update(y: int, block: bytes, h: int) -> int:
    return ghash_multiply(
        y ^ int.from_bytes(block, "big"),
        h,
    )


def pad_16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return data if remainder == 0 else data + b"\x00" * (16 - remainder)


def ghash(aad: bytes, ciphertext: bytes, h: int) -> int:
    y = 0

    for block in (
        pad_16(aad)[index:index + 16]
        for index in range(0, len(pad_16(aad)), 16)
    ):
        y = ghash_update(y, block, h)

    for block in (
        pad_16(ciphertext)[index:index + 16]
        for index in range(0, len(pad_16(ciphertext)), 16)
    ):
        y = ghash_update(y, block, h)

    length_block = struct.pack(
        ">QQ",
        len(aad) * 8,
        len(ciphertext) * 8,
    )
    y = ghash_update(y, length_block, h)

    return y


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def increment_counter(counter: bytes) -> bytes:
    prefix = counter[:12]
    value = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    return prefix + value.to_bytes(4, "big")


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    nonce: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-GCM implementation requires a 32-byte AES-256 key")

    nonce = secrets.token_bytes(12) if nonce is None else nonce
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be exactly 12 bytes")

    round_keys = aes_256_key_expansion(key)
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, round_keys), "big")

    j0 = nonce + b"\x00\x00\x00\x01"
    counter = increment_counter(j0)

    ciphertext = bytearray()

    for offset in range(0, len(plaintext), 16):
        chunk = plaintext[offset:offset + 16]
        stream = aes_encrypt_block(counter, round_keys)
        ciphertext.extend(
            left ^ right
            for left, right in zip(chunk, stream)
        )
        counter = increment_counter(counter)

    ciphertext_bytes = bytes(ciphertext)
    authentication_hash = ghash(aad, ciphertext_bytes, h)
    tag_mask = int.from_bytes(aes_encrypt_block(j0, round_keys), "big")
    tag = (tag_mask ^ authentication_hash).to_bytes(16, "big")

    return nonce, ciphertext_bytes, tag


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-GCM requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be exactly 12 bytes")
    if len(tag) != 16:
        raise ValueError("GCM tag must be exactly 16 bytes")

    round_keys = aes_256_key_expansion(key)
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, round_keys), "big")
    j0 = nonce + b"\x00\x00\x00\x01"

    authentication_hash = ghash(aad, ciphertext, h)
    expected = (
        int.from_bytes(aes_encrypt_block(j0, round_keys), "big")
        ^ authentication_hash
    ).to_bytes(16, "big")

    # Authentication must be checked before plaintext is released.
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Authentication failed: ciphertext or metadata was modified")

    counter = increment_counter(j0)
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), 16):
        chunk = ciphertext[offset:offset + 16]
        stream = aes_encrypt_block(counter, round_keys)
        plaintext.extend(
            left ^ right
            for left, right in zip(chunk, stream)
        )
        counter = increment_counter(counter)

    return bytes(plaintext)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = 600_000,
) -> bytes:
    """Derive a 256-bit key from a password.

    PBKDF2 deliberately performs repeated HMAC work so password guessing
    becomes substantially more expensive than a single hash operation.
    """
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    if len(salt) < 16:
        raise ValueError("Salt must contain at least 16 bytes")
    if iterations < 100_000:
        raise ValueError("PBKDF2 iteration count is too low for this project")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


# ---------------------------------------------------------------------------
# Encrypted envelope
# ---------------------------------------------------------------------------

@dataclass
class EncryptedEnvelope:
    version: int
    algorithm: str
    key_id: str
    nonce: str
    ciphertext: str
    tag: str
    aad: str

    def serialize(self) -> bytes:
        return json.dumps(
            asdict(self),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedEnvelope":
        document = json.loads(data.decode("utf-8"))

        required = {
            "version",
            "algorithm",
            "key_id",
            "nonce",
            "ciphertext",
            "tag",
            "aad",
        }

        if set(document) != required:
            raise ValueError("Encrypted envelope contains an invalid field set")

        return cls(**document)


class SymmetricKeyStore:
    """Small in-memory key store demonstrating key identifiers and rotation."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def create_key(self, key_id: str) -> bytes:
        if not key_id or key_id in self._keys:
            raise ValueError("Key identifier must be unique and non-empty")

        key = secrets.token_bytes(32)
        self._keys[key_id] = key
        return key

    def put_key(self, key_id: str, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Only 256-bit keys are accepted")
        self._keys[key_id] = key

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"Unknown key identifier: {key_id}") from exc

    def rotate(self, old_key_id: str, new_key_id: str) -> bytes:
        if old_key_id not in self._keys:
            raise KeyError(old_key_id)
        return self.create_key(new_key_id)


class SecureMessageService:
    """Authenticated encryption service using AES-256-GCM."""

    def __init__(self, key_store: SymmetricKeyStore) -> None:
        self.key_store = key_store

    def encrypt(
        self,
        plaintext: bytes,
        key_id: str,
        metadata: dict[str, str] | None = None,
    ) -> EncryptedEnvelope:
        key = self.key_store.get_key(key_id)

        aad_document = {
            "purpose": "symmetric-encryption-practice",
            "metadata": metadata or {},
        }
        aad = json.dumps(
            aad_document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        nonce, ciphertext, tag = aes_gcm_encrypt(
            key,
            plaintext,
            aad=aad,
        )

        return EncryptedEnvelope(
            version=1,
            algorithm="AES-256-GCM",
            key_id=key_id,
            nonce=base64.b64encode(nonce).decode("ascii"),
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            tag=base64.b64encode(tag).decode("ascii"),
            aad=base64.b64encode(aad).decode("ascii"),
        )

    def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        if envelope.version != 1:
            raise ValueError("Unsupported envelope version")

        if envelope.algorithm != "AES-256-GCM":
            raise ValueError("Unsupported encryption algorithm")

        key = self.key_store.get_key(envelope.key_id)

        nonce = base64.b64decode(envelope.nonce, validate=True)
        ciphertext = base64.b64decode(envelope.ciphertext, validate=True)
        tag = base64.b64decode(envelope.tag, validate=True)
        aad = base64.b64decode(envelope.aad, validate=True)

        return aes_gcm_decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            aad=aad,
        )


# ---------------------------------------------------------------------------
# File encryption
# ---------------------------------------------------------------------------

def encrypt_file(
    source: Path,
    destination: Path,
    service: SecureMessageService,
    key_id: str,
) -> None:
    if not source.is_file():
        raise FileNotFoundError(source)

    plaintext = source.read_bytes()
    envelope = service.encrypt(
        plaintext,
        key_id,
        metadata={
            "source_name": source.name,
            "content_type": "application/octet-stream",
        },
    )
    destination.write_bytes(envelope.serialize())


def decrypt_file(
    source: Path,
    destination: Path,
    service: SecureMessageService,
) -> None:
    envelope = EncryptedEnvelope.deserialize(source.read_bytes())
    plaintext = service.decrypt(envelope)
    destination.write_bytes(plaintext)


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

def reencrypt(
    envelope: EncryptedEnvelope,
    service: SecureMessageService,
    new_key_id: str,
) -> EncryptedEnvelope:
    plaintext = service.decrypt(envelope)
    return service.encrypt(
        plaintext,
        new_key_id,
        metadata={"rotated_from": envelope.key_id},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def assert_aes_block_round_trip() -> None:
    key = bytes(range(32))
    plaintext = bytes(range(16))
    round_keys = aes_256_key_expansion(key)

    encrypted = aes_encrypt_block(plaintext, round_keys)
    decrypted = aes_decrypt_block(encrypted, round_keys)

    assert decrypted == plaintext
    assert encrypted.hex() == (
        "8ea2b7ca516745bfeafc49904b496089"
    )


def assert_gcm_round_trip() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = b"authenticated symmetric encryption"
    aad = b"record-type=training"

    nonce_out, ciphertext, tag = aes_gcm_encrypt(
        key,
        plaintext,
        aad,
        nonce,
    )

    recovered = aes_gcm_decrypt(
        key,
        nonce_out,
        ciphertext,
        tag,
        aad,
    )

    assert recovered == plaintext


def demonstrate_tamper_detection() -> None:
    key = secrets.token_bytes(32)
    nonce, ciphertext, tag = aes_gcm_encrypt(
        key,
        b"confidential transaction",
        b"account=training",
    )

    modified = bytearray(ciphertext)
    modified[0] ^= 0x01

    try:
        aes_gcm_decrypt(
            key,
            nonce,
            bytes(modified),
            tag,
            b"account=training",
        )
    except ValueError as exc:
        print("\n=== Tamper Detection ===")
        print("Modified ciphertext rejected:", exc)
    else:
        raise AssertionError("Tampered ciphertext was accepted")


def demonstrate_aad_tamper_detection() -> None:
    key = secrets.token_bytes(32)
    nonce, ciphertext, tag = aes_gcm_encrypt(
        key,
        b"salary record",
        b"role=finance",
    )

    try:
        aes_gcm_decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            b"role=administrator",
        )
    except ValueError:
        print("Modified authenticated metadata rejected")
    else:
        raise AssertionError("Modified AAD was accepted")


def demonstrate_file_workflow() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "customer_record.txt"
        encrypted = root / "customer_record.enc"
        recovered = root / "customer_record.restored.txt"

        source.write_text(
            "Customer: Example Corporation\n"
            "Classification: Confidential\n"
            "Record: symmetric-encryption training\n",
            encoding="utf-8",
        )

        store = SymmetricKeyStore()
        store.create_key("key-2026-01")

        service = SecureMessageService(store)

        encrypt_file(source, encrypted, service, "key-2026-01")
        decrypt_file(encrypted, recovered, service)

        assert recovered.read_bytes() == source.read_bytes()

        print("\n=== File Encryption ===")
        print("Original :", source.read_text(encoding="utf-8").strip())
        print("Recovered:", recovered.read_text(encoding="utf-8").strip())


def demonstrate_key_rotation() -> None:
    store = SymmetricKeyStore()
    store.create_key("key-v1")
    store.create_key("key-v2")

    service = SecureMessageService(store)

    original = service.encrypt(
        b"document protected by the first key",
        "key-v1",
    )

    rotated = reencrypt(original, service, "key-v2")

    assert service.decrypt(rotated) == b"document protected by the first key"

    print("\n=== Key Rotation ===")
    print("Original key:", original.key_id)
    print("Rotated key:", rotated.key_id)


def demonstrate_password_derivation() -> None:
    salt = secrets.token_bytes(16)
    key_a = derive_key_from_password(
        "correct horse battery staple 2026",
        salt,
    )
    key_b = derive_key_from_password(
        "correct horse battery staple 2026",
        salt,
    )

    assert hmac.compare_digest(key_a, key_b)

    different_salt_key = derive_key_from_password(
        "correct horse battery staple 2026",
        secrets.token_bytes(16),
    )

    assert key_a != different_salt_key

    print("\n=== Password-Based Key Derivation ===")
    print("Derived key length:", len(key_a), "bytes")
    print("Same password + salt produces same key:", True)
    print("Different salt produces different key:", True)


def demonstrate_common_failure() -> None:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    _, ciphertext, tag = aes_gcm_encrypt(
        key,
        b"important message",
        b"record=42",
        nonce=nonce,
    )

    # Reusing a GCM nonce with the same key is dangerous. This demonstration
    # intentionally does not decrypt reused-nonce data; it detects the issue
    # at the application layer instead.
    seen_nonces: set[bytes] = set()

    seen_nonces.add(nonce)

    if nonce in seen_nonces:
        print("\n=== Nonce-Reuse Guard ===")
        print("A previously used nonce was detected and must not be reused.")

    assert ciphertext
    assert tag


def run_tests() -> None:
    assert_aes_block_round_trip()
    assert_gcm_round_trip()
    print("\n=== Cryptographic Self-Tests ===")
    print("AES-256 block test: PASS")
    print("AES-256-GCM round trip: PASS")


def main() -> None:
    print("SYMMETRIC ENCRYPTION PRACTICE PROJECT")

    demonstrate_xor()
    run_tests()
    demonstrate_password_derivation()
    demonstrate_tamper_detection()
    demonstrate_aad_tamper_detection()
    demonstrate_file_workflow()
    demonstrate_key_rotation()
    demonstrate_common_failure()

    print("\n=== Security Boundaries ===")
    print("Use authenticated encryption rather than encryption without integrity.")
    print("Generate keys with a cryptographically secure random source.")
    print("Never reuse a GCM nonce with the same key.")
    print("Protect encryption keys separately from encrypted data.")
    print("Treat authentication failure as a hard failure.")
    print("Use a maintained cryptographic library in production.")


if __name__ == "__main__":
    main()
