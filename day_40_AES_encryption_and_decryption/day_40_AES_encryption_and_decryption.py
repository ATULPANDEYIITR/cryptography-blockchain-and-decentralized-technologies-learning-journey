"""
AES encryption and decryption demonstration.

This self-contained module implements AES-128 at the block-cipher level and
builds authenticated encryption from AES-128-CTR + HMAC-SHA256.

AES itself provides confidentiality. The HMAC layer provides integrity and
authentication because encryption without authentication cannot reliably detect
tampering.

No third-party packages are required.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass


S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _gf_multiply(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _sub_word(word: list[int]) -> list[int]:
    return [S_BOX[x] for x in word]


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("AES-128 requires exactly 16 key bytes.")

    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    while len(words) < 44:
        temp = words[-1].copy()
        if len(words) % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[len(words) // 4]
        words.append([words[-4][i] ^ temp[i] for i in range(4)])

    return [
        bytes(sum(words[i:i + 4], []))
        for i in range(0, 44, 4)
    ]


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for i, value in enumerate(round_key):
        state[i] ^= value


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = S_BOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    original = state.copy()
    for row in range(4):
        for col in range(4):
            state[4 * col + row] = original[4 * ((col + row) % 4) + row]


def _inv_shift_rows(state: list[int]) -> None:
    original = state.copy()
    for row in range(4):
        for col in range(4):
            state[4 * col + row] = original[4 * ((col - row) % 4) + row]


def _mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i:i + 4]
        state[i] = _gf_multiply(a0, 2) ^ _gf_multiply(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_multiply(a1, 2) ^ _gf_multiply(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_multiply(a2, 2) ^ _gf_multiply(a3, 3)
        state[i + 3] = _gf_multiply(a0, 3) ^ a1 ^ a2 ^ _gf_multiply(a3, 2)


def _inv_mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i:i + 4]
        state[i] = (
            _gf_multiply(a0, 14) ^ _gf_multiply(a1, 11) ^
            _gf_multiply(a2, 13) ^ _gf_multiply(a3, 9)
        )
        state[i + 1] = (
            _gf_multiply(a0, 9) ^ _gf_multiply(a1, 14) ^
            _gf_multiply(a2, 11) ^ _gf_multiply(a3, 13)
        )
        state[i + 2] = (
            _gf_multiply(a0, 13) ^ _gf_multiply(a1, 9) ^
            _gf_multiply(a2, 14) ^ _gf_multiply(a3, 11)
        )
        state[i + 3] = (
            _gf_multiply(a0, 11) ^ _gf_multiply(a1, 13) ^
            _gf_multiply(a2, 9) ^ _gf_multiply(a3, 14)
        )


def aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks.")

    state = list(block)
    _add_round_key(state, round_keys[0])

    for round_number in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_number])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state)


def aes_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks.")

    state = list(block)
    _add_round_key(state, round_keys[10])

    for round_number in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[round_number])
        _inv_mix_columns(state)

    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def _increment_counter(counter: bytearray) -> None:
    for i in range(15, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i]:
            return


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("The CTR initial counter must be 16 bytes.")

    round_keys = expand_key(key)
    counter = bytearray(nonce)
    output = bytearray()

    for offset in range(0, len(data), 16):
        keystream = aes_encrypt_block(bytes(counter), round_keys)
        chunk = data[offset:offset + 16]
        output.extend(a ^ b for a, b in zip(chunk, keystream))
        _increment_counter(counter)

    return bytes(output)


@dataclass(frozen=True)
class EncryptedMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def encode(self) -> str:
        packed = self.nonce + self.ciphertext + self.tag
        return base64.urlsafe_b64encode(packed).decode("ascii")

    @staticmethod
    def decode(value: str) -> "EncryptedMessage":
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) < 16 + 32:
            raise ValueError("Encrypted message is too short.")
        return EncryptedMessage(
            nonce=raw[:16],
            ciphertext=raw[16:-32],
            tag=raw[-32:],
        )


def derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    if len(master_key) != 32:
        raise ValueError("The master key must contain 32 bytes.")

    encryption_key = hashlib.sha256(b"encryption:" + master_key).digest()[:16]
    authentication_key = hashlib.sha256(b"authentication:" + master_key).digest()
    return encryption_key, authentication_key


def encrypt_authenticated(plaintext: bytes, master_key: bytes) -> EncryptedMessage:
    encryption_key, authentication_key = derive_keys(master_key)
    nonce = os.urandom(16)
    ciphertext = aes_ctr_crypt(plaintext, encryption_key, nonce)
    tag = hmac.new(
        authentication_key,
        nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    return EncryptedMessage(nonce, ciphertext, tag)


def decrypt_authenticated(message: EncryptedMessage, master_key: bytes) -> bytes:
    encryption_key, authentication_key = derive_keys(master_key)

    expected_tag = hmac.new(
        authentication_key,
        message.nonce + message.ciphertext,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(message.tag, expected_tag):
        raise ValueError("Authentication failed: ciphertext or nonce was modified.")

    return aes_ctr_crypt(message.ciphertext, encryption_key, message.nonce)


def demonstrate() -> None:
    print("AES encryption and decryption")
    print("=" * 36)

    master_key = hashlib.sha256(
        b"repository-secret-used-only-for-demo"
    ).digest()

    plaintext = (
        b"Repository governance record: "
        b"pull request #184 requires two approvals."
    )

    message = encrypt_authenticated(plaintext, master_key)
    encoded = message.encode()

    print("Plaintext :", plaintext.decode())
    print("Ciphertext:", encoded)

    recovered = decrypt_authenticated(
        EncryptedMessage.decode(encoded),
        master_key,
    )
    print("Decrypted :", recovered.decode())
    print("Integrity :", recovered == plaintext)

    print("\nTamper detection")
    print("-" * 36)

    modified = bytearray(message.ciphertext)
    modified[0] ^= 0x01

    try:
        decrypt_authenticated(
            EncryptedMessage(message.nonce, bytes(modified), message.tag),
            master_key,
        )
    except ValueError as exc:
        print("Tampering rejected:", exc)

    print("\nAES block round-trip")
    print("-" * 36)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    round_keys = expand_key(key)

    encrypted_block = aes_encrypt_block(block, round_keys)
    decrypted_block = aes_decrypt_block(encrypted_block, round_keys)

    print("Known plaintext :", block.hex())
    print("Encrypted block :", encrypted_block.hex())
    print("Expected AES-128: 69c4e0d86a7b0430d8cdb78070b4c55a")
    print("Decrypted block :", decrypted_block.hex())
    print("Round-trip      :", decrypted_block == block)


def validate_key_length(key: bytes) -> None:
    if len(key) not in {16, 24, 32}:
        raise ValueError(
            "AES keys must contain 16, 24, or 32 bytes for AES-128, AES-192, or AES-256."
        )


if __name__ == "__main__":
    demonstrate()
