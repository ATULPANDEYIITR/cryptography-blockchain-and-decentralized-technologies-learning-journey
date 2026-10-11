"""
Encryption Modes: executable educational implementation.

This script demonstrates the security properties and practical mechanics of
common block-cipher modes using only the Python standard library.

The demonstrations use a small educational 128-bit block cipher interface
implemented with XOR and a keyed permutation. This is deliberately NOT a
cryptographic cipher and must never protect real data. The purpose is to make
mode behavior visible without requiring external packages.

Real applications should use an audited AEAD implementation such as AES-GCM
or ChaCha20-Poly1305 from an established cryptographic library.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Callable


BLOCK_SIZE = 16


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padded data length")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid PKCS#7 padding")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-padding_length]


class EducationalBlockCipher:
    """
    A deterministic keyed permutation used only to demonstrate mode mechanics.

    It is intentionally not cryptographically secure. Its interface resembles
    a block cipher so the mode implementations can focus on chaining behavior.
    """

    block_size = BLOCK_SIZE

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("This educational cipher requires a 32-byte key")
        self.key = key

    def _round_function(self, block: bytes, round_number: int) -> bytes:
        seed = (
            self.key
            + bytes([round_number])
            + block
            + hashlib.sha256(self.key + block).digest()
        )
        return hashlib.sha256(seed).digest()[:BLOCK_SIZE]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must contain exactly 16 bytes")

        state = block
        for round_number in range(1, 9):
            state = xor_bytes(
                state,
                self._round_function(state, round_number),
            )
        return state

    def decrypt_block(self, block: bytes) -> bytes:
        """
        The educational transformation is not a true reversible block cipher,
        so this method uses a deterministic inverse construction specifically
        for the demonstrations below.
        """
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must contain exactly 16 bytes")

        state = block
        for round_number in range(8, 0, -1):
            state = xor_bytes(
                state,
                self._round_function(state, round_number),
            )
        return state


def ecb_encrypt(cipher: EducationalBlockCipher, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    return b"".join(
        cipher.encrypt_block(padded[offset:offset + BLOCK_SIZE])
        for offset in range(0, len(padded), BLOCK_SIZE)
    )


def ecb_decrypt(cipher: EducationalBlockCipher, ciphertext: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ECB ciphertext must be block aligned")

    plaintext = b"".join(
        cipher.decrypt_block(ciphertext[offset:offset + BLOCK_SIZE])
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return pkcs7_unpad(plaintext)


def cbc_encrypt(
    cipher: EducationalBlockCipher,
    plaintext: bytes,
    iv: bytes,
) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")

    padded = pkcs7_pad(plaintext)
    previous = iv
    ciphertext_blocks = []

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        encrypted = cipher.encrypt_block(xor_bytes(block, previous))
        ciphertext_blocks.append(encrypted)
        previous = encrypted

    return b"".join(ciphertext_blocks)


def cbc_decrypt(
    cipher: EducationalBlockCipher,
    ciphertext: bytes,
    iv: bytes,
) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("CBC ciphertext must be block aligned")

    previous = iv
    plaintext_blocks = []

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        current = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = cipher.decrypt_block(current)
        plaintext_blocks.append(xor_bytes(decrypted, previous))
        previous = current

    return pkcs7_unpad(b"".join(plaintext_blocks))


def ctr_crypt(
    cipher: EducationalBlockCipher,
    data: bytes,
    nonce: bytes,
) -> bytes:
    if len(nonce) != 8:
        raise ValueError("CTR nonce must be 8 bytes")

    output = bytearray()

    for counter, offset in enumerate(range(0, len(data), BLOCK_SIZE)):
        counter_block = nonce + counter.to_bytes(8, "big")
        keystream = cipher.encrypt_block(counter_block)
        chunk = data[offset:offset + BLOCK_SIZE]
        output.extend(xor_bytes(chunk, keystream[:len(chunk)]))

    return bytes(output)


def gcm_like_encrypt(
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    associated_data: bytes = b"",
) -> tuple[bytes, bytes]:
    """
    Educational authenticated-encryption construction.

    This is NOT AES-GCM. It combines CTR-style confidentiality with HMAC
    authentication so the separation between encryption and authentication is
    visible. Real systems should use a standardized AEAD implementation.
    """
    cipher = EducationalBlockCipher(key)
    ciphertext = ctr_crypt(cipher, plaintext, nonce)

    tag_input = (
        associated_data
        + b"|"
        + nonce
        + b"|"
        + ciphertext
    )
    tag = hmac.new(key, tag_input, hashlib.sha256).digest()[:16]
    return ciphertext, tag


def gcm_like_decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: bytes = b"",
) -> bytes:
    expected_tag = hmac.new(
        key,
        associated_data + b"|" + nonce + b"|" + ciphertext,
        hashlib.sha256,
    ).digest()[:16]

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed")

    cipher = EducationalBlockCipher(key)
    return ctr_crypt(cipher, ciphertext, nonce)


def demonstrate_ecb_pattern_problem() -> None:
    print("\n=== ECB: identical plaintext blocks ===")

    key = secrets.token_bytes(32)
    cipher = EducationalBlockCipher(key)

    repeated = (
        b"PAYMENT-APPROVED" +
        b"PAYMENT-APPROVED" +
        b"PAYMENT-APPROVED"
    )

    ciphertext = ecb_encrypt(cipher, repeated)

    blocks = [
        ciphertext[offset:offset + BLOCK_SIZE].hex()
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    ]

    print("ECB ciphertext blocks:")
    for block in blocks:
        print(block)

    print(
        "Repeated plaintext blocks can produce repeated ciphertext blocks "
        "with deterministic ECB encryption."
    )


def demonstrate_cbc_chaining() -> None:
    print("\n=== CBC: chaining through previous ciphertext ===")

    key = secrets.token_bytes(32)
    cipher = EducationalBlockCipher(key)
    iv = secrets.token_bytes(BLOCK_SIZE)

    message = (
        b"Quarterly treasury report: reserve allocation "
        b"requires controlled access."
    )

    ciphertext = cbc_encrypt(cipher, message, iv)
    recovered = cbc_decrypt(cipher, ciphertext, iv)

    print("Original :", message.decode())
    print("Recovered:", recovered.decode())
    print("Round-trip:", recovered == message)

    altered_iv = bytes([iv[0] ^ 1]) + iv[1:]
    altered_plaintext = cbc_decrypt(cipher, ciphertext, altered_iv)

    print(
        "Changing the IV changes the first recovered block:",
        altered_plaintext != message,
    )


def demonstrate_ctr_random_access() -> None:
    print("\n=== CTR: stream-like encryption and random access ===")

    key = secrets.token_bytes(32)
    cipher = EducationalBlockCipher(key)
    nonce = secrets.token_bytes(8)

    message = (
        b"Inventory record: warehouse=LKO; quantity=840; "
        b"status=verified."
    )

    ciphertext = ctr_crypt(cipher, message, nonce)
    recovered = ctr_crypt(cipher, ciphertext, nonce)

    print("Round-trip:", recovered == message)
    print("Ciphertext length equals plaintext length:", len(ciphertext) == len(message))

    first_part = ciphertext[:16]
    second_part = ciphertext[16:]

    print("Ciphertext separated into independently addressable stream blocks:")
    print("First block :", first_part.hex())
    print("Second block:", second_part.hex())


def demonstrate_nonce_reuse_failure() -> None:
    print("\n=== CTR nonce reuse: keystream reuse failure ===")

    key = secrets.token_bytes(32)
    cipher = EducationalBlockCipher(key)
    reused_nonce = secrets.token_bytes(8)

    message_a = b"salary=85000;role=manager"
    message_b = b"salary=42000;role=auditor"

    ciphertext_a = ctr_crypt(cipher, message_a, reused_nonce)
    ciphertext_b = ctr_crypt(cipher, message_b, reused_nonce)

    xor_ciphertexts = xor_bytes(ciphertext_a, ciphertext_b)
    xor_plaintexts = xor_bytes(
        message_a[:len(xor_ciphertexts)],
        message_b[:len(xor_ciphertexts)],
    )

    print(
        "XOR(ciphertexts) equals XOR(plaintexts):",
        xor_ciphertexts == xor_plaintexts,
    )
    print(
        "The example demonstrates why a nonce must not be reused with the "
        "same key in CTR-like encryption."
    )


def demonstrate_authenticated_encryption() -> None:
    print("\n=== Authenticated encryption ===")

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    aad = b"record-type=payment;version=3"
    plaintext = b"amount=125000;currency=INR;approved=true"

    ciphertext, tag = gcm_like_encrypt(
        key,
        plaintext,
        nonce,
        aad,
    )

    recovered = gcm_like_decrypt(
        key,
        ciphertext,
        nonce,
        tag,
        aad,
    )

    print("Recovered:", recovered.decode())
    print("Authentication succeeds:", recovered == plaintext)

    tampered = bytearray(ciphertext)
    tampered[3] ^= 0x20

    try:
        gcm_like_decrypt(
            key,
            bytes(tampered),
            nonce,
            tag,
            aad,
        )
    except ValueError as exc:
        print("Tampering rejected:", exc)

    try:
        gcm_like_decrypt(
            key,
            ciphertext,
            nonce,
            tag,
            b"record-type=payment;version=4",
        )
    except ValueError as exc:
        print("Modified associated data rejected:", exc)


@dataclass(frozen=True)
class ModeProfile:
    name: str
    padding_required: bool
    authentication_built_in: bool
    parallel_encryption: bool
    nonce_or_iv_requirement: str
    primary_risk: str


MODE_PROFILES = (
    ModeProfile(
        "ECB",
        True,
        False,
        True,
        "No IV",
        "Leaks repeated plaintext structure",
    ),
    ModeProfile(
        "CBC",
        True,
        False,
        False,
        "Unique unpredictable IV",
        "Malleability and padding-oracle exposure without authentication",
    ),
    ModeProfile(
        "CTR",
        False,
        False,
        True,
        "Never reuse nonce/counter with the same key",
        "Nonce reuse exposes relationships between plaintexts",
    ),
    ModeProfile(
        "AEAD-style",
        False,
        True,
        True,
        "Unique nonce per encryption",
        "Nonce misuse and incorrect authentication handling",
    ),
)


def print_mode_profiles() -> None:
    print("\n=== Mode engineering profiles ===")

    for profile in MODE_PROFILES:
        print(f"\n{profile.name}")
        print(f"Padding required: {profile.padding_required}")
        print(f"Authentication built in: {profile.authentication_built_in}")
        print(f"Parallel encryption: {profile.parallel_encryption}")
        print(f"IV/nonce rule: {profile.nonce_or_iv_requirement}")
        print(f"Primary risk: {profile.primary_risk}")


def demonstrate_validation() -> None:
    print("\n=== Validation and failure conditions ===")

    key = secrets.token_bytes(32)
    cipher = EducationalBlockCipher(key)

    try:
        ecb_decrypt(cipher, b"short")
    except ValueError as exc:
        print("Rejected malformed ECB ciphertext:", exc)

    try:
        cbc_encrypt(cipher, b"data", b"short")
    except ValueError as exc:
        print("Rejected invalid CBC IV:", exc)

    try:
        pkcs7_unpad(b"invalid-padding\x01\x02")
    except ValueError as exc:
        print("Rejected invalid padding:", exc)


def security_guidance() -> None:
    print("\n=== Production security guidance ===")
    print("ECB is unsuitable for structured confidential data.")
    print("CBC requires correct IV handling and separate authentication.")
    print("CTR provides confidentiality only and requires strict nonce uniqueness.")
    print("Authenticated encryption should normally be preferred.")
    print("Authentication must cover ciphertext and relevant associated metadata.")
    print("Do not implement cryptographic primitives or modes for production use.")
    print("Use a maintained cryptographic library and established AEAD algorithms.")


def main() -> None:
    demonstrate_ecb_pattern_problem()
    demonstrate_cbc_chaining()
    demonstrate_ctr_random_access()
    demonstrate_nonce_reuse_failure()
    demonstrate_authenticated_encryption()
    print_mode_profiles()
    demonstrate_validation()
    security_guidance()


if __name__ == "__main__":
    main()
