#!/usr/bin/env python3
"""
AES Introduction
================

A self-contained educational implementation of AES-128 plus practical
demonstrations of:

- AES block structure and terminology
- AES-128 key expansion
- SubBytes, ShiftRows, MixColumns, AddRoundKey
- AES-128 block encryption and decryption
- CBC mode with PKCS#7 padding
- CTR mode
- HMAC-SHA-256 for authenticated encryption construction
- AES-GCM when the optional standard-library-free dependency is available
  is intentionally not used; the script implements the AES primitive itself
  and demonstrates why authenticated encryption is preferable to raw CBC.

This file uses only the Python standard library.

The pure-Python AES implementation is intended for learning and verification,
not production cryptography. Real applications should use a reviewed
cryptographic library such as Python's cryptography package.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Iterable


BLOCK_SIZE = 16
AES_128_KEY_SIZE = 16
AES_192_KEY_SIZE = 24
AES_256_KEY_SIZE = 32

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

INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36
)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Byte strings must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def gf_multiply(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def sub_word(word: list[int]) -> list[int]:
    return [SBOX[value] for value in word]


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def expand_key_128(key: bytes) -> list[list[int]]:
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("AES-128 requires exactly 16 key bytes")

    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    while len(words) < 44:
        temp = words[-1].copy()
        if len(words) % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[len(words) // 4]
        words.append([
            words[-4][i] ^ temp[i]
            for i in range(4)
        ])

    return [
        sum(words[round_index * 4:(round_index + 1) * 4], [])
        for round_index in range(11)
    ]


def add_round_key(state: list[int], round_key: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(state, round_key)]


def sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[value] for value in state]


def inv_sub_bytes(state: list[int]) -> list[int]:
    return [INV_SBOX[value] for value in state]


def shift_rows(state: list[int]) -> list[int]:
    # AES stores a 4x4 state column-by-column.
    result = state.copy()
    for row in range(4):
        for column in range(4):
            result[4 * column + row] = state[
                4 * ((column + row) % 4) + row
            ]
    return result


def inv_shift_rows(state: list[int]) -> list[int]:
    result = state.copy()
    for row in range(4):
        for column in range(4):
            result[4 * column + row] = state[
                4 * ((column - row) % 4) + row
            ]
    return result


def mix_columns(state: list[int]) -> list[int]:
    result = state.copy()
    for column in range(4):
        index = column * 4
        a0, a1, a2, a3 = state[index:index + 4]

        result[index] = (
            gf_multiply(a0, 2)
            ^ gf_multiply(a1, 3)
            ^ a2
            ^ a3
        )
        result[index + 1] = (
            a0
            ^ gf_multiply(a1, 2)
            ^ gf_multiply(a2, 3)
            ^ a3
        )
        result[index + 2] = (
            a0
            ^ a1
            ^ gf_multiply(a2, 2)
            ^ gf_multiply(a3, 3)
        )
        result[index + 3] = (
            gf_multiply(a0, 3)
            ^ a1
            ^ a2
            ^ gf_multiply(a3, 2)
        )

    return result


def inv_mix_columns(state: list[int]) -> list[int]:
    result = state.copy()
    for column in range(4):
        index = column * 4
        a0, a1, a2, a3 = state[index:index + 4]

        result[index] = (
            gf_multiply(a0, 14)
            ^ gf_multiply(a1, 11)
            ^ gf_multiply(a2, 13)
            ^ gf_multiply(a3, 9)
        )
        result[index + 1] = (
            gf_multiply(a0, 9)
            ^ gf_multiply(a1, 14)
            ^ gf_multiply(a2, 11)
            ^ gf_multiply(a3, 13)
        )
        result[index + 2] = (
            gf_multiply(a0, 13)
            ^ gf_multiply(a1, 9)
            ^ gf_multiply(a2, 14)
            ^ gf_multiply(a3, 11)
        )
        result[index + 3] = (
            gf_multiply(a0, 11)
            ^ gf_multiply(a1, 13)
            ^ gf_multiply(a2, 9)
            ^ gf_multiply(a3, 14)
        )

    return result


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES encrypts exactly one 16-byte block")
    round_keys = expand_key_128(key)
    state = add_round_key(list(block), round_keys[0])

    for round_index in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_index])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return bytes(state)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES decrypts exactly one 16-byte block")
    round_keys = expand_key_128(key)
    state = add_round_key(list(block), round_keys[10])

    for round_index in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return bytes(state)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    padding_length = data[-1]
    if not 1 <= padding_length <= block_size:
        raise ValueError("Invalid PKCS#7 padding length")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-padding_length]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("CBC example requires an AES-128 key")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")

    padded = pkcs7_pad(plaintext)
    previous = iv
    output = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        encrypted = aes_encrypt_block(xor_bytes(block, previous), key)
        output.extend(encrypted)
        previous = encrypted

    return bytes(output)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext must contain complete blocks")
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("CBC example requires an AES-128 key")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")

    previous = iv
    output = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = aes_decrypt_block(block, key)
        output.extend(xor_bytes(decrypted, previous))
        previous = block

    return pkcs7_unpad(bytes(output))


def increment_counter(counter: bytearray) -> None:
    for index in range(len(counter) - 1, -1, -1):
        counter[index] = (counter[index] + 1) & 0xFF
        if counter[index] != 0:
            return


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("CTR example requires an AES-128 key")
    if len(nonce) != BLOCK_SIZE:
        raise ValueError("CTR nonce/counter block must be 16 bytes")

    counter = bytearray(nonce)
    output = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        keystream = aes_encrypt_block(bytes(counter), key)
        chunk = data[offset:offset + BLOCK_SIZE]
        output.extend(xor_bytes(chunk, keystream[:len(chunk)]))
        increment_counter(counter)

    return bytes(output)


@dataclass(frozen=True)
class AuthenticatedMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def derive_demo_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive separate encryption and MAC keys for an educational
    encrypt-then-MAC construction.

    This is not a replacement for a production KDF such as HKDF.
    """
    encryption_key = hmac.new(
        master_key, b"AES encryption key", hashlib.sha256
    ).digest()[:16]

    authentication_key = hmac.new(
        master_key, b"AES authentication key", hashlib.sha256
    ).digest()

    return encryption_key, authentication_key


def authenticated_cbc_encrypt(
    plaintext: bytes,
    master_key: bytes,
) -> AuthenticatedMessage:
    encryption_key, authentication_key = derive_demo_keys(master_key)
    iv = secrets.token_bytes(BLOCK_SIZE)
    ciphertext = aes_cbc_encrypt(plaintext, encryption_key, iv)

    tag = hmac.new(
        authentication_key,
        iv + ciphertext,
        hashlib.sha256,
    ).digest()

    return AuthenticatedMessage(iv, ciphertext, tag)


def authenticated_cbc_decrypt(
    message: AuthenticatedMessage,
    master_key: bytes,
) -> bytes:
    encryption_key, authentication_key = derive_demo_keys(master_key)

    expected_tag = hmac.new(
        authentication_key,
        message.nonce + message.ciphertext,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(message.tag, expected_tag):
        raise ValueError("Authentication failed; ciphertext was altered")

    return aes_cbc_decrypt(
        message.ciphertext,
        encryption_key,
        message.nonce,
    )


def print_block(title: str, value: bytes) -> None:
    print(f"{title:<24}: {value.hex()}")


def known_answer_test() -> None:
    """
    FIPS-style AES-128 test vector.

    Key:
        000102030405060708090a0b0c0d0e0f

    Plaintext:
        00112233445566778899aabbccddeeff

    Ciphertext:
        69c4e0d86a7b0430d8cdb78070b4c55a
    """
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    actual = aes_encrypt_block(plaintext, key)
    assert actual == expected, "AES-128 known-answer encryption test failed"
    assert aes_decrypt_block(actual, key) == plaintext
    print("AES-128 known-answer test: PASS")


def demonstrate_round_structure() -> None:
    print("\nAES-128 structure")
    print("-----------------")
    print("Block size : 128 bits (16 bytes)")
    print("Key size   : 128 bits (16 bytes)")
    print("Rounds     : 10")
    print("State      : 4 x 4 bytes")
    print("Each round : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey")
    print("Final round omits MixColumns.")
    print("The key schedule expands the 16-byte key into 11 round keys.")


def demonstrate_cbc() -> None:
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    message = (
        b"Confidential procurement record: supplier payment is approved."
    )

    ciphertext = aes_cbc_encrypt(message, key, iv)
    recovered = aes_cbc_decrypt(ciphertext, key, iv)

    print("\nCBC mode demonstration")
    print("----------------------")
    print_block("Key", key)
    print_block("IV", iv)
    print_block("Ciphertext", ciphertext)
    print(f"Recovered plaintext     : {recovered.decode()}")
    assert recovered == message


def demonstrate_ctr() -> None:
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    message = (
        b"CTR treats AES as a keystream generator and does not require padding."
    )

    ciphertext = aes_ctr_crypt(message, key, nonce)
    recovered = aes_ctr_crypt(ciphertext, key, nonce)

    print("\nCTR mode demonstration")
    print("----------------------")
    print_block("Key", key)
    print_block("Nonce/counter", nonce)
    print_block("Ciphertext", ciphertext)
    print(f"Recovered plaintext     : {recovered.decode()}")
    assert recovered == message


def demonstrate_tamper_detection() -> None:
    master_key = secrets.token_bytes(32)
    message = b"Transfer amount: 500000 INR"

    protected = authenticated_cbc_encrypt(message, master_key)
    modified_ciphertext = bytearray(protected.ciphertext)
    modified_ciphertext[0] ^= 0x01

    modified = AuthenticatedMessage(
        protected.nonce,
        bytes(modified_ciphertext),
        protected.tag,
    )

    print("\nAuthenticated CBC demonstration")
    print("--------------------------------")
    try:
        authenticated_cbc_decrypt(modified, master_key)
    except ValueError as exc:
        print(f"Tampering detected       : {exc}")
    else:
        raise AssertionError("Modified ciphertext unexpectedly passed")


def demonstrate_bad_key_and_padding() -> None:
    key = secrets.token_bytes(16)
    wrong_key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    message = b"Sensitive payroll data"

    ciphertext = aes_cbc_encrypt(message, key, iv)

    print("\nFailure-condition demonstrations")
    print("---------------------------------")

    try:
        aes_cbc_decrypt(ciphertext, wrong_key, iv)
    except ValueError as exc:
        print(f"Wrong key rejected       : {exc}")

    try:
        aes_encrypt_block(b"too short", key)
    except ValueError as exc:
        print(f"Invalid block rejected   : {exc}")

    try:
        aes_cbc_decrypt(ciphertext[:-1], key, iv)
    except ValueError as exc:
        print(f"Invalid ciphertext      : {exc}")


def demonstrate_key_sensitivity() -> None:
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    key_a = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    key_b = bytes.fromhex("000102030405060708090a0b0c0d0e00")

    cipher_a = aes_encrypt_block(plaintext, key_a)
    cipher_b = aes_encrypt_block(plaintext, key_b)

    print("\nKey sensitivity")
    print("---------------")
    print_block("Cipher with key A", cipher_a)
    print_block("Cipher with key B", cipher_b)
    print(f"Different ciphertext : {cipher_a != cipher_b}")


def run_self_tests() -> None:
    key = bytes(range(16))
    plaintexts = [
        b"",
        b"A",
        b"Sixteen byte text",
        b"Longer text that crosses several AES blocks.",
        bytes(range(64)),
    ]

    for plaintext in plaintexts:
        iv = secrets.token_bytes(16)
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
        assert aes_cbc_decrypt(ciphertext, key, iv) == plaintext

        nonce = secrets.token_bytes(16)
        ciphertext = aes_ctr_crypt(plaintext, key, nonce)
        assert aes_ctr_crypt(ciphertext, key, nonce) == plaintext

    print("CBC/CTR round-trip tests: PASS")


def main() -> None:
    print("AES INTRODUCTION")
    print("================")
    print("Educational AES-128 implementation and mode demonstrations.")

    known_answer_test()
    run_self_tests()
    demonstrate_round_structure()
    demonstrate_key_sensitivity()
    demonstrate_cbc()
    demonstrate_ctr()
    demonstrate_tamper_detection()
    demonstrate_bad_key_and_padding()

    print("\nSecurity observations")
    print("---------------------")
    print("AES itself provides confidentiality, not authentication.")
    print("CBC requires unpredictable, non-repeating IVs and authenticated ciphertext.")
    print("CTR requires a never-reused nonce/counter with the same key.")
    print("For new application designs, authenticated encryption such as AES-GCM")
    print("or AES-GCM-SIV is generally preferable to constructing CBC + HMAC manually.")
    print("Keys should come from a cryptographically secure random source or a")
    print("proper password-based KDF, never directly from a human password.")
    print("This pure-Python implementation is for learning and testing only.")


if __name__ == "__main__":
    main()
