"""
ECB and CBC Block-Cipher Modes

This self-contained program uses a small educational 64-bit Feistel block cipher
to expose the mechanics of ECB and CBC without external cryptographic packages.

The cipher is deliberately NOT cryptographically secure. It exists so that the
mode behavior can be inspected directly:

ECB:
    C_i = E_K(P_i)

CBC:
    C_0 = IV
    C_i = E_K(P_i XOR C_{i-1})

Decryption:
    ECB: P_i = D_K(C_i)
    CBC: P_i = D_K(C_i) XOR C_{i-1}

The program demonstrates:
- block padding
- ECB encryption/decryption
- CBC encryption/decryption
- why repeated plaintext blocks remain repeated under ECB
- why CBC changes repeated blocks when the IV and previous ciphertext differ
- IV validation
- tampering behavior
- ECB and CBC parallelism differences
- error propagation
- secure design considerations
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
from typing import Iterable


BLOCK_SIZE = 8
WORD_MASK = 0xFFFFFFFF
BLOCK_MASK = 0xFFFFFFFFFFFFFFFF


class CryptoError(Exception):
    """Base exception for this educational cryptographic implementation."""


class InvalidKeyError(CryptoError):
    """Raised when a key is invalid."""


class InvalidBlockError(CryptoError):
    """Raised when a block has the wrong size."""


class InvalidPaddingError(CryptoError):
    """Raised when PKCS#7-style padding is invalid."""


class InvalidIVError(CryptoError):
    """Raised when a CBC IV is invalid."""


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Add PKCS#7 padding.

    A full padding block is added when the input already aligns to the block
    size. This makes padding unambiguous during decryption.
    """
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Validate and remove PKCS#7 padding."""
    if not data or len(data) % block_size != 0:
        raise InvalidPaddingError("Padded data must contain complete blocks")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise InvalidPaddingError("Invalid padding length")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise InvalidPaddingError("Invalid padding bytes")

    return data[:-padding_length]


@dataclass(frozen=True)
class EducationalFeistelCipher:
    """
    Small 64-bit Feistel cipher for demonstrating block-mode mechanics.

    This is not AES and must not be used to protect real information.
    """

    key: bytes
    rounds: int = 8

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes):
            raise InvalidKeyError("Key must be bytes")
        if len(self.key) < 8:
            raise InvalidKeyError("Key must contain at least 8 bytes")
        if self.rounds < 4:
            raise InvalidKeyError("At least four rounds are required")

    def _round_key(self, round_number: int) -> int:
        """Derive a deterministic 32-bit round key from the user key."""
        digest = hashlib.sha256(
            self.key + round_number.to_bytes(4, "big")
        ).digest()
        return int.from_bytes(digest[:4], "big")

    def _round_function(self, right: int, round_number: int) -> int:
        """
        Nonlinear-ish mixing function used only for this demonstration.

        The construction is intentionally simple enough to inspect while still
        allowing the Feistel structure to produce reversible encryption.
        """
        value = (right + self._round_key(round_number)) & WORD_MASK
        value ^= ((value << 7) & WORD_MASK)
        value ^= value >> 9
        value = (value * 0x45D9F3B) & WORD_MASK
        value ^= value >> 16
        return value & WORD_MASK

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt exactly one 64-bit block."""
        if len(block) != BLOCK_SIZE:
            raise InvalidBlockError("A block must contain exactly 8 bytes")

        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:], "big")

        for round_number in range(self.rounds):
            left, right = right, (
                left ^ self._round_function(right, round_number)
            ) & WORD_MASK

        return (
            left.to_bytes(4, "big") +
            right.to_bytes(4, "big")
        )

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt exactly one 64-bit block."""
        if len(block) != BLOCK_SIZE:
            raise InvalidBlockError("A block must contain exactly 8 bytes")

        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:], "big")

        for round_number in reversed(range(self.rounds)):
            left, right = (
                right ^ self._round_function(left, round_number)
            ) & WORD_MASK, left

        return (
            left.to_bytes(4, "big") +
            right.to_bytes(4, "big")
        )


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into complete fixed-size blocks."""
    if len(data) % block_size != 0:
        raise InvalidBlockError("Data length must be block aligned")
    return [
        data[index:index + block_size]
        for index in range(0, len(data), block_size)
    ]


def encrypt_ecb(cipher: EducationalFeistelCipher, plaintext: bytes) -> bytes:
    """
    Encrypt using Electronic Codebook mode.

    Every plaintext block is independently encrypted under the same key.
    """
    padded = pkcs7_pad(plaintext)
    return b"".join(
        cipher.encrypt_block(block)
        for block in split_blocks(padded)
    )


def decrypt_ecb(cipher: EducationalFeistelCipher, ciphertext: bytes) -> bytes:
    """Decrypt ECB ciphertext and validate padding."""
    plaintext = b"".join(
        cipher.decrypt_block(block)
        for block in split_blocks(ciphertext)
    )
    return pkcs7_unpad(plaintext)


def encrypt_cbc(
    cipher: EducationalFeistelCipher,
    plaintext: bytes,
    iv: bytes,
) -> bytes:
    """
    Encrypt using Cipher Block Chaining.

    Each plaintext block is XORed with the previous ciphertext block before
    block-cipher encryption. The IV acts as the synthetic previous ciphertext
    for the first block.
    """
    if len(iv) != BLOCK_SIZE:
        raise InvalidIVError("CBC IV must be exactly 8 bytes")

    padded = pkcs7_pad(plaintext)
    previous = iv
    ciphertext_blocks: list[bytes] = []

    for plaintext_block in split_blocks(padded):
        mixed = xor_bytes(plaintext_block, previous)
        encrypted = cipher.encrypt_block(mixed)
        ciphertext_blocks.append(encrypted)
        previous = encrypted

    return b"".join(ciphertext_blocks)


def decrypt_cbc(
    cipher: EducationalFeistelCipher,
    ciphertext: bytes,
    iv: bytes,
) -> bytes:
    """Decrypt CBC ciphertext and validate padding."""
    if len(iv) != BLOCK_SIZE:
        raise InvalidIVError("CBC IV must be exactly 8 bytes")

    previous = iv
    plaintext_blocks: list[bytes] = []

    for ciphertext_block in split_blocks(ciphertext):
        decrypted = cipher.decrypt_block(ciphertext_block)
        plaintext_blocks.append(xor_bytes(decrypted, previous))
        previous = ciphertext_block

    return pkcs7_unpad(b"".join(plaintext_blocks))


def format_blocks(data: bytes) -> str:
    """Return hexadecimal blocks for visual inspection."""
    return " | ".join(
        block.hex()
        for block in split_blocks(data)
    )


def demonstrate_basic_round_trip(cipher: EducationalFeistelCipher) -> None:
    message = (
        b"Repository governance uses protected branches. "
        b"Review approval controls merge eligibility."
    )

    iv = secrets.token_bytes(BLOCK_SIZE)

    ecb_ciphertext = encrypt_ecb(cipher, message)
    cbc_ciphertext = encrypt_cbc(cipher, message, iv)

    assert decrypt_ecb(cipher, ecb_ciphertext) == message
    assert decrypt_cbc(cipher, cbc_ciphertext, iv) == message

    print("=== Basic encryption and decryption ===")
    print(f"Plaintext:       {message.decode()}")
    print(f"ECB ciphertext:  {ecb_ciphertext.hex()}")
    print(f"CBC IV:          {iv.hex()}")
    print(f"CBC ciphertext:  {cbc_ciphertext.hex()}")
    print(f"ECB recovered:   {decrypt_ecb(cipher, ecb_ciphertext).decode()}")
    print(f"CBC recovered:   {decrypt_cbc(cipher, cbc_ciphertext, iv).decode()}")
    print()


def demonstrate_ecb_pattern_leakage(
    cipher: EducationalFeistelCipher,
) -> None:
    """
    Use repeated blocks to show ECB's deterministic mapping.

    Because each identical plaintext block receives exactly the same
    encryption operation, repeated blocks produce repeated ciphertext blocks.
    """
    repeated_block = b"ABCDEFGH"
    plaintext = repeated_block * 6

    ciphertext = encrypt_ecb(cipher, plaintext)

    print("=== ECB pattern leakage ===")
    print(f"Plaintext blocks:  {format_blocks(pkcs7_pad(plaintext))}")
    print(f"Ciphertext blocks: {format_blocks(ciphertext)}")

    ciphertext_blocks = split_blocks(ciphertext)
    unique_count = len(set(ciphertext_blocks))

    print(f"Total ciphertext blocks:  {len(ciphertext_blocks)}")
    print(f"Distinct ciphertext blocks: {unique_count}")
    print(
        "Observation: identical plaintext blocks produce identical "
        "ciphertext blocks under ECB."
    )
    print()


def demonstrate_cbc_pattern_hiding(
    cipher: EducationalFeistelCipher,
) -> None:
    """
    Encrypt repeated blocks with CBC.

    After the first block, the previous ciphertext becomes part of the input
    to the block cipher, so repeated plaintext blocks normally encrypt to
    different ciphertext blocks.
    """
    repeated_block = b"ABCDEFGH"
    plaintext = repeated_block * 6
    iv = secrets.token_bytes(BLOCK_SIZE)

    ciphertext = encrypt_cbc(cipher, plaintext, iv)

    print("=== CBC chaining ===")
    print(f"IV:               {iv.hex()}")
    print(f"Plaintext blocks:  {format_blocks(pkcs7_pad(plaintext))}")
    print(f"Ciphertext blocks: {format_blocks(ciphertext)}")

    ciphertext_blocks = split_blocks(ciphertext)
    print(f"Distinct ciphertext blocks: {len(set(ciphertext_blocks))}")
    print(
        "Observation: the chaining value makes equal plaintext blocks "
        "dependent on their preceding ciphertext."
    )
    print()


def demonstrate_iv_effect(
    cipher: EducationalFeistelCipher,
) -> None:
    """
    Show that changing the CBC IV changes the first ciphertext block and,
    through chaining, generally changes all following ciphertext blocks.
    """
    plaintext = b"ABCDEFGHABCDEFGHABCDEFGH"

    iv_one = b"\x00" * BLOCK_SIZE
    iv_two = b"\x01" + b"\x00" * (BLOCK_SIZE - 1)

    first = encrypt_cbc(cipher, plaintext, iv_one)
    second = encrypt_cbc(cipher, plaintext, iv_two)

    print("=== CBC IV sensitivity ===")
    print(f"IV 1:              {iv_one.hex()}")
    print(f"IV 2:              {iv_two.hex()}")
    print(f"Ciphertext with IV1: {first.hex()}")
    print(f"Ciphertext with IV2: {second.hex()}")
    print(f"Ciphertexts equal: {first == second}")
    print(
        "The IV does not need to be secret, but it must be unpredictable "
        "when CBC encryption is used in a security-sensitive protocol."
    )
    print()


def demonstrate_bit_flipping(
    cipher: EducationalFeistelCipher,
) -> None:
    """
    Demonstrate CBC's malleability.

    Flipping a bit in ciphertext block C_i causes the corresponding bit to
    flip in plaintext block P_{i+1}, while the modified C_i also causes the
    decrypted P_i to become unpredictable.

    This is one reason CBC must be combined with authentication, such as an
    encrypt-then-MAC construction. Modern applications generally prefer an
    authenticated-encryption mode such as AES-GCM.
    """
    plaintext = b"TRANSFER=1000;TO=ALICE;"

    iv = b"\x11" * BLOCK_SIZE
    ciphertext = bytearray(encrypt_cbc(cipher, plaintext, iv))

    original = decrypt_cbc(cipher, bytes(ciphertext), iv)

    # Change a byte in the first ciphertext block. The corresponding plaintext
    # byte in the second block is predictably XORed with the same mask.
    ciphertext[0] ^= 0x01

    try:
        modified = decrypt_cbc(cipher, bytes(ciphertext), iv)
    except InvalidPaddingError as exc:
        modified = b"<padding failure: " + str(exc).encode() + b">"

    print("=== CBC ciphertext modification ===")
    print(f"Original plaintext: {original!r}")
    print(f"Modified result:    {modified!r}")
    print(
        "A successful decryption does not prove integrity. CBC provides "
        "confidentiality mechanics, not message authentication."
    )
    print()


def demonstrate_padding_edges(
    cipher: EducationalFeistelCipher,
) -> None:
    print("=== Padding edge cases ===")

    messages = [
        b"",
        b"A",
        b"1234567",
        b"12345678",
        b"123456789",
    ]

    for message in messages:
        padded = pkcs7_pad(message)
        recovered = decrypt_cbc(
            cipher,
            encrypt_cbc(cipher, message, b"\x22" * BLOCK_SIZE),
            b"\x22" * BLOCK_SIZE,
        )

        print(
            f"input={message!r:12} "
            f"padded_length={len(padded):2} "
            f"recovered={recovered!r}"
        )

    print()


def demonstrate_validation(
    cipher: EducationalFeistelCipher,
) -> None:
    print("=== Validation and failure conditions ===")

    invalid_cases = [
        ("short ECB ciphertext", lambda: decrypt_ecb(cipher, b"short")),
        (
            "short CBC IV",
            lambda: decrypt_cbc(cipher, b"\x00" * 8, b"\x00" * 7),
        ),
        (
            "invalid padding",
            lambda: pkcs7_unpad(b"ABCDEFG\x02"),
        ),
    ]

    for name, operation in invalid_cases:
        try:
            operation()
        except CryptoError as exc:
            print(f"{name}: rejected -> {exc}")

    print()


def compare_mode_properties() -> None:
    """
    Print architectural properties rather than pretending both modes provide
    the same operational behavior.
    """
    properties = {
        "ECB": {
            "independent_blocks": True,
            "requires_iv": False,
            "encryption_parallelism": True,
            "pattern_preservation": True,
            "integrity": False,
        },
        "CBC": {
            "independent_blocks": False,
            "requires_iv": True,
            "encryption_parallelism": False,
            "pattern_preservation": False,
            "integrity": False,
        },
    }

    print("=== Mode properties ===")

    for mode, values in properties.items():
        print(mode)
        for name, value in values.items():
            print(f"  {name}: {value}")

    print()


def main() -> None:
    key = hashlib.sha256(
        b"educational-key-for-ecb-cbc-demonstration"
    ).digest()

    cipher = EducationalFeistelCipher(key=key)

    demonstrate_basic_round_trip(cipher)
    demonstrate_ecb_pattern_leakage(cipher)
    demonstrate_cbc_pattern_hiding(cipher)
    demonstrate_iv_effect(cipher)
    demonstrate_bit_flipping(cipher)
    demonstrate_padding_edges(cipher)
    demonstrate_validation(cipher)
    compare_mode_properties()

    print("Educational demonstration completed.")
    print(
        "Do not deploy this cipher or unauthenticated ECB/CBC encryption "
        "for real security-sensitive data."
    )


if __name__ == "__main__":
    main()
