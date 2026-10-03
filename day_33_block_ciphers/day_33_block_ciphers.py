"""
Block Ciphers: from fundamentals to an executable AES-128 implementation.

This self-contained script demonstrates:
- What a fixed-width block cipher does
- Confusion, diffusion, substitution, permutation, and key dependence
- A small Feistel cipher whose structure is easy to inspect
- PKCS#7 padding and its validation rules
- ECB, CBC, and CTR mode behavior
- A complete AES-128 block implementation
- AES-128 ECB/CBC/CTR helpers
- Known-answer testing
- Avalanche-effect measurement
- IV/nonce requirements
- Common failure modes and security limitations

The AES implementation is educational. Production systems should use a
well-reviewed cryptographic library and an authenticated-encryption mode
such as AES-GCM or ChaCha20-Poly1305 rather than composing encryption and
integrity mechanisms manually.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


# ---------------------------------------------------------------------------
# Core block-cipher concepts
# ---------------------------------------------------------------------------

BLOCK_SIZE = 16


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings, which is central to many block modes."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def bit_count(data: bytes) -> int:
    """Count changed bits so the avalanche effect can be measured."""
    return sum(byte.bit_count() for byte in data)


def print_hex(label: str, data: bytes) -> None:
    print(f"{label:<28} {data.hex()}")


# ---------------------------------------------------------------------------
# A deliberately small Feistel cipher
# ---------------------------------------------------------------------------

def rotl8(value: int, amount: int) -> int:
    """Rotate one byte so every bit can influence another position."""
    amount %= 8
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def toy_round_function(right: int, subkey: int) -> int:
    """
    A small nonlinear-looking round function.

    This is not intended to be cryptographically secure. Its purpose is to
    expose the Feistel mechanism: only one half is transformed, then XORed
    into the other half.
    """
    x = (right ^ subkey) & 0xFF
    x = (x * 0x5D + 0x17) & 0xFF
    x ^= rotl8(x, 3)
    return x & 0xFF


def toy_feistel_encrypt(block: bytes, key: bytes, rounds: int = 8) -> bytes:
    """
    Encrypt an 8-byte block using a small Feistel construction.

    Feistel networks are useful educationally because decryption can reuse
    the same round function with the round keys in reverse order.
    """
    if len(block) != 8:
        raise ValueError("Toy Feistel requires an 8-byte block")
    if not key:
        raise ValueError("Toy Feistel requires a non-empty key")

    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")

    for round_index in range(rounds):
        subkey = key[round_index % len(key)]
        transformed = (
            toy_round_function((right >> 24) & 0xFF, subkey) << 24
        ) | (
            toy_round_function((right >> 16) & 0xFF, subkey ^ 0x31) << 16
        ) | (
            toy_round_function((right >> 8) & 0xFF, subkey ^ 0x63) << 8
        ) | toy_round_function(right & 0xFF, subkey ^ 0xA7)

        left, right = right, (left ^ transformed) & 0xFFFFFFFF

    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def toy_feistel_decrypt(block: bytes, key: bytes, rounds: int = 8) -> bytes:
    """Reverse the Feistel rounds without writing a separate inverse F."""
    if len(block) != 8:
        raise ValueError("Toy Feistel requires an 8-byte block")
    if not key:
        raise ValueError("Toy Feistel requires a non-empty key")

    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")

    for round_index in range(rounds - 1, -1, -1):
        subkey = key[round_index % len(key)]
        previous_right = left
        transformed = (
            toy_round_function((previous_right >> 24) & 0xFF, subkey) << 24
        ) | (
            toy_round_function((previous_right >> 16) & 0xFF, subkey ^ 0x31) << 16
        ) | (
            toy_round_function((previous_right >> 8) & 0xFF, subkey ^ 0x63) << 8
        ) | toy_round_function(previous_right & 0xFF, subkey ^ 0xA7)

        previous_left = (right ^ transformed) & 0xFFFFFFFF
        left, right = previous_left, previous_right

    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Add PKCS#7 padding.

    A complete block receives a complete padding block, so unpadding remains
    unambiguous even when the original plaintext length is block-aligned.
    """
    if not 1 <= block_size <= 255:
        raise ValueError("PKCS#7 block size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Validate every padding byte instead of trusting only the final byte."""
    if not data or len(data) % block_size:
        raise ValueError("Invalid padded data length")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid PKCS#7 padding length")

    padding = data[-padding_length:]
    if padding != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-padding_length]


# ---------------------------------------------------------------------------
# AES-128
# ---------------------------------------------------------------------------

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _index, _value in enumerate(SBOX):
    INV_SBOX[_value] = _index

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def gf_mul(a: int, b: int) -> int:
    """Multiply bytes in AES's GF(2^8) finite field."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


def aes_key_expansion(key: bytes) -> list[list[int]]:
    """
    Expand a 16-byte AES-128 key into eleven 16-byte round keys.

    AES-128 has ten transformation rounds plus the initial AddRoundKey step.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires exactly a 16-byte key")

    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for index in range(4, 44):
        temp = words[index - 1].copy()

        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[value] for value in temp]
            temp[0] ^= RCON[index // 4]

        words.append([
            words[index - 4][byte_index] ^ temp[byte_index]
            for byte_index in range(4)
        ])

    return [
        sum(words[round_index * 4:(round_index + 1) * 4], [])
        for round_index in range(11)
    ]


def add_round_key(state: list[int], round_key: list[int]) -> None:
    """XOR the state with one expanded AES round key."""
    for index in range(16):
        state[index] ^= round_key[index]


def sub_bytes(state: list[int]) -> None:
    """Apply AES's nonlinear S-box independently to every state byte."""
    for index in range(16):
        state[index] = SBOX[state[index]]


def inv_sub_bytes(state: list[int]) -> None:
    """Reverse the S-box substitution."""
    for index in range(16):
        state[index] = INV_SBOX[state[index]]


def shift_rows(state: list[int]) -> None:
    """
    Rotate AES state rows.

    AES stores the state column-major, so a row consists of indices
    0,4,8,12; 1,5,9,13; and so on.
    """
    original = state.copy()

    for row in range(4):
        for column in range(4):
            source_column = (column + row) % 4
            state[4 * column + row] = original[4 * source_column + row]


def inv_shift_rows(state: list[int]) -> None:
    """Reverse ShiftRows by rotating each state row in the opposite direction."""
    original = state.copy()

    for row in range(4):
        for column in range(4):
            source_column = (column - row) % 4
            state[4 * column + row] = original[4 * source_column + row]


def mix_columns(state: list[int]) -> None:
    """
    Mix each four-byte column using multiplication in GF(2^8).

    This spreads a changed byte into multiple positions.
    """
    for column in range(4):
        base = column * 4
        a0, a1, a2, a3 = state[base:base + 4]

        state[base] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        state[base + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        state[base + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        state[base + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)


def inv_mix_columns(state: list[int]) -> None:
    """Reverse MixColumns with the inverse matrix coefficients."""
    for column in range(4):
        base = column * 4
        a0, a1, a2, a3 = state[base:base + 4]

        state[base] = (
            gf_mul(a0, 14) ^ gf_mul(a1, 11) ^
            gf_mul(a2, 13) ^ gf_mul(a3, 9)
        )
        state[base + 1] = (
            gf_mul(a0, 9) ^ gf_mul(a1, 14) ^
            gf_mul(a2, 11) ^ gf_mul(a3, 13)
        )
        state[base + 2] = (
            gf_mul(a0, 13) ^ gf_mul(a1, 9) ^
            gf_mul(a2, 14) ^ gf_mul(a3, 11)
        )
        state[base + 3] = (
            gf_mul(a0, 11) ^ gf_mul(a1, 13) ^
            gf_mul(a2, 9) ^ gf_mul(a3, 14)
        )


class AES128:
    """A complete educational AES-128 block cipher."""

    block_size = 16
    key_size = 16

    def __init__(self, key: bytes):
        if len(key) != self.key_size:
            raise ValueError("AES-128 keys must contain exactly 16 bytes")
        self.round_keys = aes_key_expansion(key)

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt exactly one 128-bit block."""
        if len(block) != self.block_size:
            raise ValueError("AES encrypt_block requires 16 bytes")

        state = list(block)

        add_round_key(state, self.round_keys[0])

        for round_index in range(1, 11):
            sub_bytes(state)
            shift_rows(state)

            if round_index != 10:
                mix_columns(state)

            add_round_key(state, self.round_keys[round_index])

        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt exactly one 128-bit block using inverse AES operations."""
        if len(block) != self.block_size:
            raise ValueError("AES decrypt_block requires 16 bytes")

        state = list(block)

        add_round_key(state, self.round_keys[10])

        for round_index in range(9, -1, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, self.round_keys[round_index])

            if round_index != 0:
                inv_mix_columns(state)

        return bytes(state)


# ---------------------------------------------------------------------------
# Block modes
# ---------------------------------------------------------------------------

def require_full_blocks(data: bytes) -> None:
    if len(data) % BLOCK_SIZE:
        raise ValueError("Data length must be a multiple of 16 bytes")


def aes_ecb_encrypt(aes: AES128, plaintext: bytes) -> bytes:
    """
    ECB encrypts each block independently.

    It is included to demonstrate the mode's mechanics, not recommended for
    structured application data because equal plaintext blocks produce equal
    ciphertext blocks under the same key.
    """
    require_full_blocks(plaintext)
    return b"".join(
        aes.encrypt_block(plaintext[index:index + BLOCK_SIZE])
        for index in range(0, len(plaintext), BLOCK_SIZE)
    )


def aes_ecb_decrypt(aes: AES128, ciphertext: bytes) -> bytes:
    require_full_blocks(ciphertext)
    return b"".join(
        aes.decrypt_block(ciphertext[index:index + BLOCK_SIZE])
        for index in range(0, len(ciphertext), BLOCK_SIZE)
    )


def aes_cbc_encrypt(aes: AES128, plaintext: bytes, iv: bytes) -> bytes:
    """
    CBC chains each plaintext block with the previous ciphertext block.

    The IV must be unpredictable for normal randomized encryption. CBC by
    itself provides confidentiality only and does not authenticate data.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")

    padded = pkcs7_pad(plaintext)
    previous = iv
    output = bytearray()

    for index in range(0, len(padded), BLOCK_SIZE):
        block = padded[index:index + BLOCK_SIZE]
        encrypted = aes.encrypt_block(xor_bytes(block, previous))
        output.extend(encrypted)
        previous = encrypted

    return bytes(output)


def aes_cbc_decrypt(aes: AES128, ciphertext: bytes, iv: bytes) -> bytes:
    """Reverse CBC and reject malformed padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    require_full_blocks(ciphertext)
    if not ciphertext:
        raise ValueError("CBC ciphertext cannot be empty")

    previous = iv
    plaintext = bytearray()

    for index in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[index:index + BLOCK_SIZE]
        decrypted = aes.decrypt_block(block)
        plaintext.extend(xor_bytes(decrypted, previous))
        previous = block

    return pkcs7_unpad(bytes(plaintext))


def increment_counter(counter: bytearray) -> None:
    """
    Increment a 128-bit counter in big-endian order.

    CTR never pads the plaintext because encryption is a keystream XOR.
    """
    for index in range(len(counter) - 1, -1, -1):
        counter[index] = (counter[index] + 1) & 0xFF
        if counter[index]:
            break


def aes_ctr_crypt(aes: AES128, data: bytes, nonce_counter: bytes) -> bytes:
    """
    CTR turns a block cipher into a stream cipher.

    The complete nonce/counter starting value must never repeat with the same
    key. This function deliberately accepts a 16-byte starting counter so the
    counter allocation policy remains visible to the caller.
    """
    if len(nonce_counter) != BLOCK_SIZE:
        raise ValueError("CTR initial counter must be 16 bytes")

    counter = bytearray(nonce_counter)
    output = bytearray()

    for index in range(0, len(data), BLOCK_SIZE):
        keystream = aes.encrypt_block(bytes(counter))
        chunk = data[index:index + BLOCK_SIZE]
        output.extend(xor_bytes(chunk, keystream[:len(chunk)]))
        increment_counter(counter)

    return bytes(output)


# ---------------------------------------------------------------------------
# Higher-level demonstrations
# ---------------------------------------------------------------------------

def known_answer_test() -> None:
    """
    FIPS-197 AES-128 example.

    This verifies the block primitive against a standardized known-answer
    vector instead of merely checking that encryption and decryption are
    inverses of each other.
    """
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    aes = AES128(key)
    ciphertext = aes.encrypt_block(plaintext)
    recovered = aes.decrypt_block(ciphertext)

    print_hex("AES known-answer ciphertext", ciphertext)
    assert ciphertext == expected, "AES-128 known-answer test failed"
    assert recovered == plaintext, "AES-128 decryption test failed"
    print("Known-answer test: PASS")


def demonstrate_padding() -> None:
    print("\nPKCS#7 padding")
    samples = [b"", b"A", b"1234567890123456", b"confidential record"]

    for sample in samples:
        padded = pkcs7_pad(sample)
        recovered = pkcs7_unpad(padded)
        print(
            f"length={len(sample):2d} padded_length={len(padded):2d} "
            f"padding_byte={padded[-1]:2d} valid={recovered == sample}"
        )

    malformed = b"ABC\x02\x03"
    try:
        pkcs7_unpad(malformed)
    except ValueError as exc:
        print(f"Malformed padding rejected: {exc}")


def demonstrate_modes() -> None:
    print("\nAES modes")
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    aes = AES128(key)
    plaintext = (
        b"Quarterly transaction report: "
        b"account=4821;amount=1750;currency=INR"
    )

    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    cbc_ciphertext = aes_cbc_encrypt(aes, plaintext, iv)
    cbc_recovered = aes_cbc_decrypt(aes, cbc_ciphertext, iv)

    print_hex("CBC ciphertext", cbc_ciphertext)
    print("CBC round trip:", cbc_recovered == plaintext)

    counter = bytes.fromhex("00000000000000000000000000000001")
    ctr_ciphertext = aes_ctr_crypt(aes, plaintext, counter)
    ctr_recovered = aes_ctr_crypt(aes, ctr_ciphertext, counter)

    print_hex("CTR ciphertext", ctr_ciphertext)
    print("CTR round trip:", ctr_recovered == plaintext)

    # Repeated blocks expose ECB's deterministic behavior.
    repeated = b"PAYLOAD-12345678" * 4
    ecb_ciphertext = aes_ecb_encrypt(aes, repeated)
    ecb_blocks = [
        ecb_ciphertext[i:i + BLOCK_SIZE]
        for i in range(0, len(ecb_ciphertext), BLOCK_SIZE)
    ]

    print("ECB repeated ciphertext blocks:", len(set(ecb_blocks)), "unique of", len(ecb_blocks))
    print("ECB equality leakage demonstrated:", len(set(ecb_blocks)) < len(ecb_blocks))


def demonstrate_avalanche() -> None:
    """
    Flip one plaintext bit and measure the number of changed ciphertext bits.

    A strong block cipher should make a tiny input change produce a large,
    apparently unrelated output change after its full round structure.
    """
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    plaintext = bytearray(b"Block cipher test")
    aes = AES128(key)

    original = aes.encrypt_block(bytes(plaintext))

    modified = plaintext.copy()
    modified[0] ^= 0x01
    changed = aes.encrypt_block(bytes(modified))

    changed_bits = bit_count(xor_bytes(original, changed))

    print("\nAvalanche behavior")
    print_hex("Original ciphertext", original)
    print_hex("One-bit-change ciphertext", changed)
    print("Changed ciphertext bits:", changed_bits, "of", BLOCK_SIZE * 8)


def demonstrate_feistel() -> None:
    print("\nFeistel structure")
    key = b"secure-demo-key"
    block = b"FEISTEL!"
    ciphertext = toy_feistel_encrypt(block, key)
    recovered = toy_feistel_decrypt(ciphertext, key)

    print_hex("Toy Feistel ciphertext", ciphertext)
    print("Feistel round trip:", recovered == block)
    print(
        "Security note: this construction is intentionally small and "
        "educational, not suitable for protecting real data."
    )


def demonstrate_failures() -> None:
    print("\nValidation and failure cases")
    aes = AES128(b"0123456789abcdef")

    checks: list[tuple[str, Callable[[], object]]] = [
        ("wrong AES block length", lambda: aes.encrypt_block(b"short")),
        ("wrong AES key length", lambda: AES128(b"short")),
        ("wrong CBC IV length", lambda: aes_cbc_encrypt(aes, b"data", b"short")),
        ("non-block ECB input", lambda: aes_ecb_encrypt(aes, b"not-aligned")),
        ("invalid CBC ciphertext", lambda: aes_cbc_decrypt(aes, b"", bytes(16))),
        ("invalid padding", lambda: pkcs7_unpad(b"1234567890123456")),
    ]

    for name, operation in checks:
        try:
            operation()
        except (ValueError, AssertionError) as exc:
            print(f"{name}: rejected -> {exc}")


def security_notes() -> None:
    print("\nSecurity model")
    print("AES is a block cipher, not a complete application encryption protocol.")
    print("ECB reveals equality patterns and should not protect structured data.")
    print("CBC needs a fresh unpredictable IV and separate authentication.")
    print("CTR needs a unique counter/nonce for every encryption under one key.")
    print("Unauthenticated encryption does not reliably detect malicious modification.")
    print("Production systems should prefer an authenticated-encryption construction.")
    print("Keys should come from a cryptographically secure key-management process.")
    print("Do not log plaintext, secret keys, or reusable nonces.")
    print("Avoid rolling your own cryptographic primitive in production.")


def run_self_tests() -> None:
    """Run deterministic correctness checks before demonstrations."""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    aes = AES128(key)

    for length in range(0, 80):
        plaintext = bytes((index * 37 + length) & 0xFF for index in range(length))

        iv = bytes(16)
        cbc = aes_cbc_encrypt(aes, plaintext, iv)
        assert aes_cbc_decrypt(aes, cbc, iv) == plaintext

        counter = bytes(15) + b"\x01"
        ctr = aes_ctr_crypt(aes, plaintext, counter)
        assert aes_ctr_crypt(aes, ctr, counter) == plaintext

    for block_value in range(0, 32):
        block = bytes([block_value]) * 16
        encrypted = aes.encrypt_block(block)
        assert aes.decrypt_block(encrypted) == block

    print("Round-trip self-tests: PASS")


def main() -> None:
    print("=" * 72)
    print("BLOCK CIPHERS: FUNDAMENTALS THROUGH AES-128")
    print("=" * 72)

    run_self_tests()
    known_answer_test()
    demonstrate_padding()
    demonstrate_feistel()
    demonstrate_modes()
    demonstrate_avalanche()
    demonstrate_failures()
    security_notes()

    print("\nCompleted all demonstrations.")


if __name__ == "__main__":
    main()
