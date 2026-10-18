"""
AES-GCM and ChaCha20-Poly1305
Executable educational implementation using Python's standard library.

The script implements:
- AES-128/192/256 block encryption
- AES-GCM authenticated encryption
- ChaCha20 stream encryption
- Poly1305 message authentication
- ChaCha20-Poly1305 AEAD
- AAD authentication
- nonce and tag validation
- tamper detection
- key separation examples
- deterministic test vectors
- performance-oriented reusable APIs

No third-party package is required.
"""

from __future__ import annotations

import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Callable


# ---------------------------------------------------------------------------
# Common validation helpers
# ---------------------------------------------------------------------------

class AuthenticationError(ValueError):
    """Raised when authenticated ciphertext cannot be verified."""


def require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def constant_time_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    result = 0
    for a, b in zip(left, right):
        result |= a ^ b
    return result == 0


# ---------------------------------------------------------------------------
# AES block cipher
# ---------------------------------------------------------------------------

AES_SBOX = (
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

AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def aes_xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def aes_mix_column(column: list[int]) -> list[int]:
    a, b, c, d = column
    return [
        aes_xtime(a) ^ (aes_xtime(b) ^ b) ^ c ^ d,
        a ^ aes_xtime(b) ^ (aes_xtime(c) ^ c) ^ d,
        a ^ b ^ aes_xtime(c) ^ (aes_xtime(d) ^ d),
        (aes_xtime(a) ^ a) ^ b ^ c ^ aes_xtime(d),
    ]


def aes_expand_key(key: bytes) -> list[bytes]:
    require_bytes("key", key)
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24, or 32 bytes")

    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]

    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1].copy()
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[x] for x in temp]
            temp[0] ^= AES_RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [AES_SBOX[x] for x in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

    return [
        bytes(sum(words[4*r:4*r + 4], []))
        for r in range(nr + 1)
    ]


def aes_add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def aes_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = AES_SBOX[state[i]]


def aes_shift_rows(state: list[int]) -> None:
    original = state.copy()
    for row in range(4):
        for col in range(4):
            state[4 * col + row] = original[4 * ((col + row) % 4) + row]


def aes_mix_columns(state: list[int]) -> None:
    for col in range(4):
        start = 4 * col
        state[start:start + 4] = aes_mix_column(state[start:start + 4])


def aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES encrypt_block requires exactly 16 bytes")

    rounds = len(round_keys) - 1
    state = list(block)
    aes_add_round_key(state, round_keys[0])

    for round_index in range(1, rounds):
        aes_sub_bytes(state)
        aes_shift_rows(state)
        aes_mix_columns(state)
        aes_add_round_key(state, round_keys[round_index])

    aes_sub_bytes(state)
    aes_shift_rows(state)
    aes_add_round_key(state, round_keys[-1])
    return bytes(state)


# ---------------------------------------------------------------------------
# GCM arithmetic
# ---------------------------------------------------------------------------

def gf128_multiply(x: int, y: int) -> int:
    result = 0
    reduction = 0xE1000000000000000000000000000000

    for _ in range(128):
        if y & 1:
            result ^= x
        y >>= 1
        if x & 1:
            x = (x >> 1) ^ reduction
        else:
            x >>= 1

    return result


def ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_int = int.from_bytes(h, "big")
    y = 0

    def absorb(data: bytes) -> None:
        nonlocal y
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16]
            if len(block) < 16:
                block += b"\x00" * (16 - len(block))
            y = gf128_multiply(y ^ int.from_bytes(block, "big"), h_int)

    absorb(aad)
    absorb(ciphertext)

    lengths = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    y = gf128_multiply(y ^ int.from_bytes(lengths, "big"), h_int)
    return y.to_bytes(16, "big")


def inc32(counter: bytes) -> bytes:
    prefix = counter[:12]
    value = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    return prefix + value.to_bytes(4, "big")


def gcm_counter_stream(
    round_keys: list[bytes],
    initial_counter: bytes,
    length: int,
) -> bytes:
    output = bytearray()
    counter = initial_counter

    while len(output) < length:
        counter = inc32(counter)
        output.extend(aes_encrypt_block(counter, round_keys))

    return bytes(output[:length])


def gcm_derive_j0(round_keys: list[bytes], nonce: bytes) -> bytes:
    if len(nonce) == 12:
        return nonce + b"\x00\x00\x00\x01"

    h = aes_encrypt_block(b"\x00" * 16, round_keys)
    y = 0
    h_int = int.from_bytes(h, "big")

    padded = nonce + b"\x00" * ((16 - len(nonce) % 16) % 16)
    for offset in range(0, len(padded), 16):
        y = gf128_multiply(
            y ^ int.from_bytes(padded[offset:offset + 16], "big"),
            h_int,
        )

    length_block = (len(nonce) * 8).to_bytes(8, "big")
    block = b"\x00" * 8 + length_block
    y = gf128_multiply(y ^ int.from_bytes(block, "big"), h_int)
    return y.to_bytes(16, "big")


def aes_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    require_bytes("key", key)
    require_bytes("nonce", nonce)
    require_bytes("plaintext", plaintext)
    require_bytes("aad", aad)

    if len(nonce) < 8:
        raise ValueError("GCM nonce is too short")
    if len(nonce) > 2**64 - 1:
        raise ValueError("GCM nonce is too long")

    round_keys = aes_expand_key(key)
    h = aes_encrypt_block(b"\x00" * 16, round_keys)
    j0 = gcm_derive_j0(round_keys, nonce)

    ciphertext = xor_bytes(
        plaintext,
        gcm_counter_stream(round_keys, j0, len(plaintext)),
    )

    authentication_data = ghash(h, aad, ciphertext)
    tag = xor_bytes(
        aes_encrypt_block(j0, round_keys),
        authentication_data,
    )
    return ciphertext, tag


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    require_bytes("key", key)
    require_bytes("nonce", nonce)
    require_bytes("ciphertext", ciphertext)
    require_bytes("tag", tag)
    require_bytes("aad", aad)

    if len(tag) != 16:
        raise ValueError("This implementation requires a 16-byte GCM tag")

    round_keys = aes_expand_key(key)
    h = aes_encrypt_block(b"\x00" * 16, round_keys)
    j0 = gcm_derive_j0(round_keys, nonce)

    expected_tag = xor_bytes(
        aes_encrypt_block(j0, round_keys),
        ghash(h, aad, ciphertext),
    )

    if not constant_time_equal(tag, expected_tag):
        raise AuthenticationError("AES-GCM authentication failed")

    return xor_bytes(
        ciphertext,
        gcm_counter_stream(round_keys, j0, len(ciphertext)),
    )


# ---------------------------------------------------------------------------
# ChaCha20
# ---------------------------------------------------------------------------

def rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def chacha_quarter_round(
    state: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("IETF ChaCha20 requires a 12-byte nonce")
    if not 0 <= counter <= 0xFFFFFFFF:
        raise ValueError("ChaCha20 counter must fit in 32 bits")

    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))

    working = state.copy()

    for _ in range(10):
        chacha_quarter_round(working, 0, 4, 8, 12)
        chacha_quarter_round(working, 1, 5, 9, 13)
        chacha_quarter_round(working, 2, 6, 10, 14)
        chacha_quarter_round(working, 3, 7, 11, 15)

        chacha_quarter_round(working, 0, 5, 10, 15)
        chacha_quarter_round(working, 1, 6, 11, 12)
        chacha_quarter_round(working, 2, 7, 8, 13)
        chacha_quarter_round(working, 3, 4, 9, 14)

    result = [
        (working[i] + state[i]) & 0xFFFFFFFF
        for i in range(16)
    ]
    return struct.pack("<16I", *result)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 requires a 12-byte nonce")

    output = bytearray()

    while data:
        if counter > 0xFFFFFFFF:
            raise ValueError("ChaCha20 counter exhausted")

        stream = chacha20_block(key, counter, nonce)
        chunk = data[:64]
        output.extend(a ^ b for a, b in zip(chunk, stream))
        data = data[64:]
        counter += 1

    return bytes(output)


# ---------------------------------------------------------------------------
# Poly1305
# ---------------------------------------------------------------------------

def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 requires a 32-byte one-time key")

    r = int.from_bytes(one_time_key[:16], "little")
    s = int.from_bytes(one_time_key[16:], "little")

    # RFC 8439 clamps r before using it as the polynomial multiplier.
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF

    modulus = (1 << 130) - 5
    accumulator = 0

    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + n) * r) % modulus

    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")


def poly1305_padding_length(length: int) -> int:
    return (16 - (length % 16)) % 16


def pad16(data: bytes) -> bytes:
    return data + b"\x00" * poly1305_padding_length(len(data))


def chacha20_poly1305_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        pad16(aad)
        + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    require_bytes("key", key)
    require_bytes("nonce", nonce)
    require_bytes("plaintext", plaintext)
    require_bytes("aad", aad)

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 requires a 12-byte nonce")

    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    tag = poly1305_mac(
        chacha20_poly1305_mac_data(aad, ciphertext),
        one_time_key,
    )
    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    require_bytes("key", key)
    require_bytes("nonce", nonce)
    require_bytes("ciphertext", ciphertext)
    require_bytes("tag", tag)
    require_bytes("aad", aad)

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 requires a 12-byte nonce")
    if len(tag) != 16:
        raise ValueError("This implementation requires a 16-byte Poly1305 tag")

    one_time_key = chacha20_block(key, 0, nonce)[:32]
    expected_tag = poly1305_mac(
        chacha20_poly1305_mac_data(aad, ciphertext),
        one_time_key,
    )

    if not constant_time_equal(tag, expected_tag):
        raise AuthenticationError("ChaCha20-Poly1305 authentication failed")

    return chacha20_xor(key, nonce, ciphertext, counter=1)


# ---------------------------------------------------------------------------
# High-level AEAD record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AeadRecord:
    algorithm: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes


class AeadBox:
    """
    Small application-facing abstraction.

    A unique random nonce is generated for every encryption operation.
    The nonce is public metadata and is therefore stored in the record.
    """

    def __init__(self, algorithm: str, key: bytes):
        if algorithm not in {"AES-GCM", "ChaCha20-Poly1305"}:
            raise ValueError("Unsupported AEAD algorithm")

        expected = 32 if algorithm == "ChaCha20-Poly1305" else len(key)
        if algorithm == "AES-GCM" and len(key) not in (16, 24, 32):
            raise ValueError("AES-GCM requires a 128, 192, or 256-bit key")
        if algorithm == "ChaCha20-Poly1305" and len(key) != expected:
            raise ValueError("ChaCha20-Poly1305 requires a 256-bit key")

        self.algorithm = algorithm
        self.key = key

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> AeadRecord:
        nonce = secrets.token_bytes(12)

        if self.algorithm == "AES-GCM":
            ciphertext, tag = aes_gcm_encrypt(
                self.key, nonce, plaintext, aad
            )
        else:
            ciphertext, tag = chacha20_poly1305_encrypt(
                self.key, nonce, plaintext, aad
            )

        return AeadRecord(
            algorithm=self.algorithm,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            aad=aad,
        )

    def decrypt(self, record: AeadRecord) -> bytes:
        if record.algorithm != self.algorithm:
            raise ValueError("Record algorithm does not match the key context")

        if self.algorithm == "AES-GCM":
            return aes_gcm_decrypt(
                self.key,
                record.nonce,
                record.ciphertext,
                record.tag,
                record.aad,
            )

        return chacha20_poly1305_decrypt(
            self.key,
            record.nonce,
            record.ciphertext,
            record.tag,
            record.aad,
        )


# ---------------------------------------------------------------------------
# Known-answer tests
# ---------------------------------------------------------------------------

def run_known_answer_tests() -> None:
    # AES-128 single-block NIST/FIPS-style test.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    actual = aes_encrypt_block(plaintext, aes_expand_key(key))
    assert actual == expected, "AES block encryption test failed"

    # RFC 8439 ChaCha20 block test.
    chacha_key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    chacha_nonce = bytes.fromhex("000000090000004a00000000")
    expected_chacha = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    actual_chacha = chacha20_block(
        chacha_key,
        1,
        chacha_nonce,
    )[:64]
    assert actual_chacha == expected_chacha, "ChaCha20 block test failed"

    # Round-trip tests exercise both confidentiality and authentication.
    message = b"authenticated repository metadata"
    aad = b"record-type=deployment;version=7"

    aes_key = bytes.fromhex(
        "feffe9928665731c6d6a8f9467308308"
        "feffe9928665731c6d6a8f9467308308"
    )
    aes_nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    ciphertext, tag = aes_gcm_encrypt(
        aes_key,
        aes_nonce,
        message,
        aad,
    )
    assert aes_gcm_decrypt(
        aes_key,
        aes_nonce,
        ciphertext,
        tag,
        aad,
    ) == message

    chacha_key = bytes(range(32))
    chacha_nonce = bytes(range(12))
    ciphertext, tag = chacha20_poly1305_encrypt(
        chacha_key,
        chacha_nonce,
        message,
        aad,
    )
    assert chacha20_poly1305_decrypt(
        chacha_key,
        chacha_nonce,
        ciphertext,
        tag,
        aad,
    ) == message

    print("Known-answer and round-trip tests passed.")


# ---------------------------------------------------------------------------
# Failure demonstrations
# ---------------------------------------------------------------------------

def demonstrate_authentication_failures() -> None:
    message = b"confidential deployment artifact"
    aad = b"service=payments;environment=production"

    for algorithm, key in (
        ("AES-GCM", secrets.token_bytes(32)),
        ("ChaCha20-Poly1305", secrets.token_bytes(32)),
    ):
        box = AeadBox(algorithm, key)
        record = box.encrypt(message, aad)

        altered_ciphertext = bytearray(record.ciphertext)
        if altered_ciphertext:
            altered_ciphertext[0] ^= 0x01
        else:
            altered_ciphertext = bytearray(b"\x01")

        tampered = AeadRecord(
            record.algorithm,
            record.nonce,
            bytes(altered_ciphertext),
            record.tag,
            record.aad,
        )

        try:
            box.decrypt(tampered)
        except AuthenticationError:
            print(f"{algorithm}: ciphertext modification rejected")

        altered_aad = record.aad + b";role=admin"
        wrong_metadata = AeadRecord(
            record.algorithm,
            record.nonce,
            record.ciphertext,
            record.tag,
            altered_aad,
        )

        try:
            box.decrypt(wrong_metadata)
        except AuthenticationError:
            print(f"{algorithm}: AAD modification rejected")


# ---------------------------------------------------------------------------
# Practical comparison
# ---------------------------------------------------------------------------

def benchmark_algorithm(
    name: str,
    encrypt: Callable[[bytes], tuple[bytes, bytes]],
    payload: bytes,
) -> None:
    start = time.perf_counter()
    for _ in range(20):
        encrypt(payload)
    elapsed = time.perf_counter() - start
    throughput = (len(payload) * 20) / elapsed / (1024 * 1024)

    print(
        f"{name}: {throughput:.2f} MiB/s using this pure-Python educational implementation"
    )


def run_practical_demo() -> None:
    message = (
        b"Database backup manifest: "
        b"customer records remain encrypted and authenticated."
    )
    aad = b"tenant=acme;object=backup-manifest;version=42"

    print("\nAES-GCM")
    aes_box = AeadBox("AES-GCM", secrets.token_bytes(32))
    aes_record = aes_box.encrypt(message, aad)
    print("nonce:", aes_record.nonce.hex())
    print("ciphertext:", aes_record.ciphertext.hex())
    print("tag:", aes_record.tag.hex())
    print("recovered:", aes_box.decrypt(aes_record).decode())

    print("\nChaCha20-Poly1305")
    chacha_box = AeadBox(
        "ChaCha20-Poly1305",
        secrets.token_bytes(32),
    )
    chacha_record = chacha_box.encrypt(message, aad)
    print("nonce:", chacha_record.nonce.hex())
    print("ciphertext:", chacha_record.ciphertext.hex())
    print("tag:", chacha_record.tag.hex())
    print("recovered:", chacha_box.decrypt(chacha_record).decode())

    print("\nNonce discipline")
    first = aes_box.encrypt(b"same plaintext")
    second = aes_box.encrypt(b"same plaintext")
    print("random nonces differ:", first.nonce != second.nonce)

    benchmark_payload = b"x" * (16 * 1024)
    benchmark_algorithm(
        "AES-GCM",
        lambda payload: aes_gcm_encrypt(
            aes_box.key,
            secrets.token_bytes(12),
            payload,
        ),
        benchmark_payload,
    )
    benchmark_algorithm(
        "ChaCha20-Poly1305",
        lambda payload: chacha20_poly1305_encrypt(
            chacha_box.key,
            secrets.token_bytes(12),
            payload,
        ),
        benchmark_payload,
    )


def main() -> None:
    print("AES-GCM and ChaCha20-Poly1305 demonstration")
    print("=" * 48)

    run_known_answer_tests()
    demonstrate_authentication_failures()
    run_practical_demo()

    print("\nSecurity properties demonstrated:")
    print("Confidentiality: ciphertext hides plaintext without the key.")
    print("Integrity: modified ciphertext fails authentication.")
    print("Authenticated metadata: modified AAD fails authentication.")
    print("Nonce requirement: every encryption needs a unique nonce per key.")
    print("Key separation: an AES key is not accepted by the ChaCha20 API.")
    print(
        "Production note: established cryptographic libraries should normally "
        "be preferred over educational implementations such as this one."
    )


if __name__ == "__main__":
    main()
