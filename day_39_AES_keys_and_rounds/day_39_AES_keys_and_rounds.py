#!/usr/bin/env python3
"""
AES Keys and Rounds: executable educational implementation.

Demonstrates:
- AES-128, AES-192, and AES-256 key sizes and round counts.
- AES byte-state representation and finite-field arithmetic.
- SubBytes, ShiftRows, MixColumns, and AddRoundKey.
- Key expansion and round-key generation.
- Complete AES block encryption and decryption.
- NIST known-answer tests.
- ECB limitations, CBC mechanics, and PKCS#7 padding validation.
- Secure application encryption using the optional cryptography package.

The educational AES implementation is intended for understanding the
algorithm, not for production security. Production applications should
use a maintained cryptographic library and authenticated encryption.
"""

from __future__ import annotations

import secrets
import unittest
from dataclasses import dataclass
from typing import Iterable


BLOCK_SIZE = 16
MASK = 0xFF


def xtime(value: int) -> int:
    """Multiply a byte by x in GF(2^8), reducing modulo 0x11B."""
    value &= MASK
    result = value << 1
    if value & 0x80:
        result ^= 0x11B
    return result & MASK


def gf_multiply(left: int, right: int) -> int:
    """Multiply two bytes in the AES finite field GF(2^8)."""
    left &= MASK
    right &= MASK
    result = 0

    while right:
        if right & 1:
            result ^= left
        left = xtime(left)
        right >>= 1

    return result


def gf_power(value: int, exponent: int) -> int:
    """Exponentiation by squaring in GF(2^8)."""
    result = 1
    base = value & MASK

    while exponent:
        if exponent & 1:
            result = gf_multiply(result, base)
        base = gf_multiply(base, base)
        exponent >>= 1

    return result


def rotate_byte_left(value: int, count: int) -> int:
    """Rotate an eight-bit value without introducing wider bits."""
    count %= 8
    value &= MASK
    return ((value << count) | (value >> (8 - count))) & MASK


def generate_sboxes() -> tuple[list[int], list[int]]:
    """
    Generate AES forward and inverse substitution tables.

    Every nonzero field element has multiplicative inverse a^254.
    The AES affine transformation then constructs the forward S-box.
    """
    forward = []

    for value in range(256):
        inverse = 0 if value == 0 else gf_power(value, 254)
        substituted = (
            inverse
            ^ rotate_byte_left(inverse, 1)
            ^ rotate_byte_left(inverse, 2)
            ^ rotate_byte_left(inverse, 3)
            ^ rotate_byte_left(inverse, 4)
            ^ 0x63
        )
        forward.append(substituted)

    reverse = [0] * 256
    for original, substituted in enumerate(forward):
        reverse[substituted] = original

    return forward, reverse


SBOX, INV_SBOX = generate_sboxes()


def bytes_to_state(block: bytes) -> list[list[int]]:
    """
    Map a 16-byte block into the AES 4x4 state.

    AES fills state columns first: state[row][column] = block[4*column+row].
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("An AES block must contain exactly 16 bytes.")

    return [
        [block[4 * column + row] for column in range(4)]
        for row in range(4)
    ]


def state_to_bytes(state: list[list[int]]) -> bytes:
    """Serialize the AES state in column-major order."""
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("AES state must be a 4x4 matrix.")

    return bytes(state[row][column] for column in range(4) for row in range(4))


def sub_bytes(state: list[list[int]]) -> None:
    """Apply the nonlinear forward S-box to every state byte."""
    for row in range(4):
        for column in range(4):
            state[row][column] = SBOX[state[row][column]]


def inverse_sub_bytes(state: list[list[int]]) -> None:
    """Apply the inverse S-box during decryption."""
    for row in range(4):
        for column in range(4):
            state[row][column] = INV_SBOX[state[row][column]]


def shift_rows(state: list[list[int]]) -> None:
    """Cyclically rotate row r left by r positions."""
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def inverse_shift_rows(state: list[list[int]]) -> None:
    """Reverse ShiftRows by rotating each row right by its index."""
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def mix_columns(state: list[list[int]]) -> None:
    """
    Mix each column using the AES matrix over GF(2^8).

    [02 03 01 01]
    [01 02 03 01]
    [01 01 02 03]
    [03 01 01 02]
    """
    for column in range(4):
        a = [state[row][column] for row in range(4)]
        state[0][column] = (
            gf_multiply(a[0], 2) ^ gf_multiply(a[1], 3) ^ a[2] ^ a[3]
        )
        state[1][column] = (
            a[0] ^ gf_multiply(a[1], 2) ^ gf_multiply(a[2], 3) ^ a[3]
        )
        state[2][column] = (
            a[0] ^ a[1] ^ gf_multiply(a[2], 2) ^ gf_multiply(a[3], 3)
        )
        state[3][column] = (
            gf_multiply(a[0], 3) ^ a[1] ^ a[2] ^ gf_multiply(a[3], 2)
        )


def inverse_mix_columns(state: list[list[int]]) -> None:
    """Apply the inverse MixColumns matrix to each column."""
    for column in range(4):
        a = [state[row][column] for row in range(4)]
        state[0][column] = (
            gf_multiply(a[0], 14)
            ^ gf_multiply(a[1], 11)
            ^ gf_multiply(a[2], 13)
            ^ gf_multiply(a[3], 9)
        )
        state[1][column] = (
            gf_multiply(a[0], 9)
            ^ gf_multiply(a[1], 14)
            ^ gf_multiply(a[2], 11)
            ^ gf_multiply(a[3], 13)
        )
        state[2][column] = (
            gf_multiply(a[0], 13)
            ^ gf_multiply(a[1], 9)
            ^ gf_multiply(a[2], 14)
            ^ gf_multiply(a[3], 11)
        )
        state[3][column] = (
            gf_multiply(a[0], 11)
            ^ gf_multiply(a[1], 13)
            ^ gf_multiply(a[2], 9)
            ^ gf_multiply(a[3], 14)
        )


def add_round_key(
    state: list[list[int]], round_key: bytes
) -> None:
    """XOR a 16-byte round key into the state."""
    if len(round_key) != BLOCK_SIZE:
        raise ValueError("Each AES round key must contain 16 bytes.")

    key_state = bytes_to_state(round_key)
    for row in range(4):
        for column in range(4):
            state[row][column] ^= key_state[row][column]


def rotate_word(word: bytes) -> bytes:
    """Rotate a four-byte key-schedule word one byte to the left."""
    if len(word) != 4:
        raise ValueError("A key-schedule word must contain four bytes.")
    return word[1:] + word[:1]


def substitute_word(word: bytes) -> bytes:
    """Apply the forward S-box to all four bytes of a word."""
    return bytes(SBOX[value] for value in word)


def make_rcon(count: int) -> list[int]:
    """Generate the round constants used by key expansion."""
    constants = [0] * count
    value = 1

    for index in range(count):
        constants[index] = value
        value = xtime(value)

    return constants


@dataclass(frozen=True)
class AESParameters:
    key_bytes: int
    rounds: int

    @classmethod
    def from_key_length(cls, length: int) -> "AESParameters":
        parameters = {
            16: cls(16, 10),
            24: cls(24, 12),
            32: cls(32, 14),
        }
        try:
            return parameters[length]
        except KeyError as exc:
            raise ValueError(
                "AES accepts 128-, 192-, or 256-bit keys."
            ) from exc


class EducationalAES:
    """Readable AES block cipher with all three standard key sizes."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("The AES key must be bytes.")

        self.parameters = AESParameters.from_key_length(len(key))
        self.key = key
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> list[bytes]:
        nk = len(key) // 4
        nr = self.parameters.rounds
        word_count = 4 * (nr + 1)

        words = [
            key[index:index + 4]
            for index in range(0, len(key), 4)
        ]
        rcon = make_rcon(word_count)

        for index in range(nk, word_count):
            temporary = words[index - 1]

            if index % nk == 0:
                rotated = rotate_word(temporary)
                substituted = substitute_word(rotated)
                temporary = bytes(
                    [substituted[0] ^ rcon[index // nk - 1]]
                ) + substituted[1:]
            elif nk > 6 and index % nk == 4:
                temporary = substitute_word(temporary)

            words.append(bytes(
                words[index - nk][position] ^ temporary[position]
                for position in range(4)
            ))

        return [
            b"".join(words[start:start + 4])
            for start in range(0, word_count, 4)
        ]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 16-byte block using the FIPS AES round structure."""
        state = bytes_to_state(plaintext)
        add_round_key(state, self.round_keys[0])

        for round_number in range(1, self.parameters.rounds):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self.round_keys[round_number])

        # The final AES round intentionally omits MixColumns.
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, self.round_keys[-1])
        return state_to_bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Invert the encryption transformations in reverse order."""
        state = bytes_to_state(ciphertext)
        add_round_key(state, self.round_keys[-1])
        inverse_shift_rows(state)
        inverse_sub_bytes(state)

        for round_number in range(
            self.parameters.rounds - 1, 0, -1
        ):
            add_round_key(state, self.round_keys[round_number])
            inverse_mix_columns(state)
            inverse_shift_rows(state)
            inverse_sub_bytes(state)

        add_round_key(state, self.round_keys[0])
        return state_to_bytes(state)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad a byte string to a block boundary."""
    if not 1 <= block_size <= 255:
        raise ValueError("Padding block size must be between 1 and 255.")

    amount = block_size - len(data) % block_size
    return data + bytes([amount]) * amount


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Validate PKCS#7 padding.

    This function is for demonstrations only. Padding errors must never
    be exposed as a distinguishable oracle in a real network protocol.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded-data length.")

    amount = data[-1]
    if amount < 1 or amount > block_size:
        raise ValueError("Invalid padding length.")

    expected = bytes([amount]) * amount
    if not secrets.compare_digest(data[-amount:], expected):
        raise ValueError("Invalid padding bytes.")

    return data[:-amount]


def xor_blocks(left: bytes, right: bytes) -> bytes:
    """XOR equally sized blocks for the CBC chaining demonstration."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal lengths.")
    return bytes(a ^ b for a, b in zip(left, right))


def educational_cbc_encrypt(
    cipher: EducationalAES, plaintext: bytes, iv: bytes
) -> bytes:
    """
    Demonstrate CBC chaining with PKCS#7 padding.

    CBC alone does not authenticate ciphertext and must not be used
    for new production designs without a secure authentication layer.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must contain exactly 16 bytes.")

    padded = pkcs7_pad(plaintext)
    previous = iv
    result = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        encrypted = cipher.encrypt_block(xor_blocks(block, previous))
        result.extend(encrypted)
        previous = encrypted

    return bytes(result)


def educational_cbc_decrypt(
    cipher: EducationalAES, ciphertext: bytes, iv: bytes
) -> bytes:
    """Reverse CBC chaining and validate its demonstration padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must contain exactly 16 bytes.")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("CBC ciphertext must contain complete blocks.")

    previous = iv
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = cipher.decrypt_block(block)
        plaintext.extend(xor_blocks(decrypted, previous))
        previous = block

    return pkcs7_unpad(bytes(plaintext))


def secure_application_example() -> None:
    """
    Use AES-GCM from the optional cryptography package.

    Unlike the educational block-mode demonstrations, GCM authenticates
    ciphertext and associated data. Nonces must never repeat under a key.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print(
            "Production AES-GCM example skipped: install the "
            "'cryptography' package to run it."
        )
        return

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = b"repository signing service configuration"
    associated_data = b"record-id:842"

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    recovered = aesgcm.decrypt(nonce, ciphertext, associated_data)

    assert recovered == plaintext

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    try:
        aesgcm.decrypt(nonce, bytes(tampered), associated_data)
    except Exception as error:
        print(f"AES-GCM correctly rejected tampered ciphertext: {type(error).__name__}")


class AESTests(unittest.TestCase):
    def test_fips_aes128_vector(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        cipher = EducationalAES(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected)
        self.assertEqual(cipher.decrypt_block(expected), plaintext)

    def test_fips_aes192_vector(self) -> None:
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "1011121314151617"
        )
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        cipher = EducationalAES(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected)

    def test_fips_aes256_vector(self) -> None:
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        cipher = EducationalAES(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected)

    def test_all_key_sizes_round_trip(self) -> None:
        for length in (16, 24, 32):
            cipher = EducationalAES(bytes(range(length)))
            plaintext = bytes(range(16))
            self.assertEqual(
                cipher.decrypt_block(cipher.encrypt_block(plaintext)),
                plaintext,
            )

    def test_invalid_key_and_block_sizes(self) -> None:
        with self.assertRaises(ValueError):
            EducationalAES(b"short")
        with self.assertRaises(ValueError):
            EducationalAES(bytes(16)).encrypt_block(b"short")

    def test_padding_edge_cases(self) -> None:
        for data in (b"", b"A", b"1234567890123456", bytes(range(100))):
            padded = pkcs7_pad(data)
            self.assertEqual(pkcs7_unpad(padded), data)

        with self.assertRaises(ValueError):
            pkcs7_unpad(b"\x00" * 16)

    def test_cbc_round_trip(self) -> None:
        cipher = EducationalAES(bytes(range(16)))
        iv = bytes(range(16, 32))
        message = b"Confidential engineering report."
        encrypted = educational_cbc_encrypt(cipher, message, iv)
        self.assertEqual(
            educational_cbc_decrypt(cipher, encrypted, iv), message
        )


def show_round_key_schedule() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = EducationalAES(key)

    print("\nAES-128 round keys")
    for index, round_key in enumerate(cipher.round_keys):
        print(f"Round {index:02d}: {round_key.hex()}")


def main() -> None:
    print("AES key sizes and rounds")
    for key_length in (16, 24, 32):
        parameters = AESParameters.from_key_length(key_length)
        print(
            f"{parameters.key_bytes * 8}-bit key: "
            f"{parameters.rounds} rounds, "
            f"{parameters.rounds + 1} round keys"
        )

    show_round_key_schedule()

    cipher = EducationalAES(bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    ))
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = cipher.encrypt_block(plaintext)

    print(f"\nPlaintext : {plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered : {cipher.decrypt_block(ciphertext).hex()}")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AESTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    secure_application_example()

    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
