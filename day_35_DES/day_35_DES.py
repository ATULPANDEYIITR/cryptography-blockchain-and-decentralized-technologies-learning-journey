"""
DES in Cryptography and Blockchain
==================================

A self-contained educational implementation of the Data Encryption Standard
(DES), followed by demonstrations of how legacy symmetric encryption can be
used around blockchain data without confusing confidentiality with integrity.

The implementation includes:
- DES initial/final permutations
- 16-round Feistel network
- Key parity handling and effective 56-bit key
- PC-1, PC-2, left rotations, S-boxes, P permutation
- DES encryption/decryption
- CBC mode with PKCS#7-style padding
- HMAC-SHA-256 for modern integrity protection
- A small blockchain whose block payload can optionally be encrypted
- Chain validation and tamper detection
- Weak-key warnings and brute-force cost demonstration
- Performance and security observations

DES is implemented here for educational purposes. DES should not be used for
new security systems because its 56-bit effective key is obsolete.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256, sha512
import hmac
import os
import secrets
import time
from typing import Iterable


# ---------------------------------------------------------------------------
# DES constants
# ---------------------------------------------------------------------------

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOXES = [
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]


def permute(value: int, table: list[int], input_bits: int) -> int:
    """Apply a DES permutation table, treating the leftmost bit as position 1."""
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_bits - position)) & 1)
    return result


def rotate_left(value: int, amount: int, width: int) -> int:
    """Rotate a fixed-width bit field without allowing bits to escape its width."""
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def normalize_des_key(key: bytes) -> bytes:
    """
    DES accepts 64 transmitted key bits, but every eighth bit is parity.
    This function accepts exactly eight bytes and verifies that each byte has
    odd parity. Applications sometimes repair parity automatically, but
    explicit validation is useful when studying DES key representation.
    """
    if len(key) != 8:
        raise ValueError("DES keys must contain exactly 8 bytes.")

    for byte in key:
        if byte.bit_count() % 2 == 0:
            raise ValueError(
                "DES key parity is invalid. Each key byte must contain odd parity."
            )
    return key


def set_odd_parity(key: bytes) -> bytes:
    """Return an 8-byte DES key with the least significant bit set for odd parity."""
    if len(key) != 8:
        raise ValueError("DES keys must contain exactly 8 bytes.")

    result = bytearray()
    for byte in key:
        data_bits = byte & 0xFE
        parity_bit = 1 if data_bits.bit_count() % 2 == 0 else 0
        result.append(data_bits | parity_bit)
    return bytes(result)


def generate_round_keys(key: bytes) -> list[int]:
    """Generate the sixteen 48-bit DES round keys."""
    key = normalize_des_key(key)
    permuted = permute(bytes_to_int(key), PC1, 64)

    c = permuted >> 28
    d = permuted & ((1 << 28) - 1)

    round_keys = []
    for rotation in ROTATIONS:
        c = rotate_left(c, rotation, 28)
        d = rotate_left(d, rotation, 28)
        combined = (c << 28) | d
        round_keys.append(permute(combined, PC2, 56))
    return round_keys


def des_f(right: int, round_key: int) -> int:
    """DES Feistel function: expansion, XOR, S-box substitution, P permutation."""
    expanded = permute(right, E, 32)
    mixed = expanded ^ round_key

    substituted = 0
    for box_index in range(8):
        six_bits = (mixed >> (42 - box_index * 6)) & 0x3F
        row = ((six_bits >> 5) << 1) | (six_bits & 1)
        column = (six_bits >> 1) & 0x0F
        four_bits = SBOXES[box_index][row][column]
        substituted = (substituted << 4) | four_bits

    return permute(substituted, P, 32)


def des_block(block: bytes, round_keys: list[int]) -> bytes:
    """Encrypt or decrypt one 64-bit block using the supplied round-key order."""
    if len(block) != 8:
        raise ValueError("DES operates on 8-byte blocks.")

    state = permute(bytes_to_int(block), IP, 64)
    left = state >> 32
    right = state & 0xFFFFFFFF

    for round_key in round_keys:
        left, right = right, left ^ des_f(right, round_key)

    # DES swaps the final Feistel halves before the final permutation.
    preoutput = (right << 32) | left
    return int_to_bytes(permute(preoutput, FP, 64), 8)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    return des_block(block, generate_round_keys(key))


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    return des_block(block, list(reversed(generate_round_keys(key))))


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Pad arbitrary data to an integral number of DES blocks."""
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding]) * padding


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    """Validate and remove padding; malformed padding is treated as an error."""
    if not data or len(data) % block_size:
        raise ValueError("Padded DES data has an invalid length.")

    padding = data[-1]
    if padding < 1 or padding > block_size:
        raise ValueError("Invalid padding length.")

    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding bytes.")

    return data[:-padding]


def des_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Educational CBC implementation.

    CBC requires a fresh unpredictable IV for each encryption. The IV is not
    secret and can be stored next to the ciphertext.
    """
    normalize_des_key(key)
    if len(iv) != 8:
        raise ValueError("DES-CBC requires an 8-byte IV.")

    padded = pkcs7_pad(plaintext)
    previous = iv
    ciphertext = bytearray()

    for offset in range(0, len(padded), 8):
        block = padded[offset:offset + 8]
        encrypted = des_encrypt_block(
            bytes(a ^ b for a, b in zip(block, previous)), key
        )
        ciphertext.extend(encrypted)
        previous = encrypted

    return bytes(ciphertext)


def des_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    normalize_des_key(key)
    if len(iv) != 8:
        raise ValueError("DES-CBC requires an 8-byte IV.")
    if not ciphertext or len(ciphertext) % 8:
        raise ValueError("DES-CBC ciphertext must contain complete blocks.")

    previous = iv
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset:offset + 8]
        decrypted = des_decrypt_block(block, key)
        plaintext.extend(bytes(a ^ b for a, b in zip(decrypted, previous)))
        previous = block

    return pkcs7_unpad(bytes(plaintext))


def is_weak_des_key(key: bytes) -> bool:
    """
    Detect the well-known DES weak and semi-weak key set.

    The parity bits are normalized before comparison because parity does not
    contribute to the effective 56-bit DES key.
    """
    normalized = set_odd_parity(key)

    weak_hex = {
        "0101010101010101",
        "FEFEFEFEFEFEFEFE",
        "E0E0E0E0E0E0E0E0",
        "1F1F1F1F1F1F1F1F",
        "01FE01FE01FE01FE",
        "FE01FE01FE01FE01",
        "1FE01FE00EF10EF1",
        "E01FE01FF10EF10E",
    }
    return normalized.hex().upper() in weak_hex


# ---------------------------------------------------------------------------
# Blockchain model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Block:
    index: int
    previous_hash: str
    timestamp: float
    payload: str
    ciphertext_hex: str
    iv_hex: str
    mac_hex: str
    nonce: int

    def canonical_bytes(self) -> bytes:
        """
        Serialize consensus-relevant fields deterministically.

        A real blockchain needs a formally specified canonical serialization.
        Ambiguous serialization can allow different nodes to hash different
        representations of apparently identical data.
        """
        fields = (
            str(self.index),
            self.previous_hash,
            f"{self.timestamp:.6f}",
            self.payload,
            self.ciphertext_hex,
            self.iv_hex,
            self.mac_hex,
            str(self.nonce),
        )
        return "|".join(fields).encode("utf-8")

    def hash(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


class EducationalBlockchain:
    """
    A small append-only chain demonstrating the distinction between:

    - DES: confidentiality of selected payload data
    - HMAC: authentication/integrity of protected ciphertext
    - SHA-256: block-linking digest
    - Proof-of-work: computational cost for changing accepted history

    These mechanisms solve different problems and do not replace one another.
    """

    def __init__(self, des_key: bytes, mac_key: bytes):
        self.des_key = set_odd_parity(des_key)
        normalize_des_key(self.des_key)
        self.mac_key = mac_key
        self.blocks: list[Block] = []

    def _encrypt_payload(self, payload: str) -> tuple[str, str, str]:
        iv = secrets.token_bytes(8)
        ciphertext = des_cbc_encrypt(payload.encode("utf-8"), self.des_key, iv)

        # HMAC covers the IV and ciphertext. Encryption alone does not provide
        # integrity, so an attacker could otherwise manipulate CBC ciphertext.
        mac = hmac.new(
            self.mac_key,
            iv + ciphertext,
            sha256,
        ).hexdigest()

        return ciphertext.hex(), iv.hex(), mac

    def _verify_payload_mac(self, block: Block) -> bool:
        try:
            expected = hmac.new(
                self.mac_key,
                bytes.fromhex(block.iv_hex) + bytes.fromhex(block.ciphertext_hex),
                sha256,
            ).hexdigest()
        except ValueError:
            return False

        return hmac.compare_digest(expected, block.mac_hex)

    def decrypt_payload(self, block: Block) -> str:
        if not self._verify_payload_mac(block):
            raise ValueError("Payload authentication failed.")

        plaintext = des_cbc_decrypt(
            bytes.fromhex(block.ciphertext_hex),
            self.des_key,
            bytes.fromhex(block.iv_hex),
        )
        return plaintext.decode("utf-8")

    def _mine_nonce(
        self,
        index: int,
        previous_hash: str,
        timestamp: float,
        payload: str,
        ciphertext_hex: str,
        iv_hex: str,
        mac_hex: str,
        difficulty: int,
    ) -> int:
        """
        Simple proof-of-work.

        This is deliberately separate from DES. Proof-of-work does not make DES
        stronger; it makes rewriting accepted history computationally costly in
        a blockchain that uses this consensus mechanism.
        """
        target = "0" * difficulty
        nonce = 0

        while True:
            candidate = Block(
                index=index,
                previous_hash=previous_hash,
                timestamp=timestamp,
                payload=payload,
                ciphertext_hex=ciphertext_hex,
                iv_hex=iv_hex,
                mac_hex=mac_hex,
                nonce=nonce,
            )
            if candidate.hash().startswith(target):
                return nonce
            nonce += 1

    def add_block(self, payload: str, difficulty: int = 3) -> Block:
        if not payload.strip():
            raise ValueError("A blockchain payload cannot be empty.")

        previous_hash = self.blocks[-1].hash() if self.blocks else "0" * 64
        ciphertext_hex, iv_hex, mac_hex = self._encrypt_payload(payload)
        timestamp = time.time()

        nonce = self._mine_nonce(
            len(self.blocks),
            previous_hash,
            timestamp,
            payload,
            ciphertext_hex,
            iv_hex,
            mac_hex,
            difficulty,
        )

        block = Block(
            index=len(self.blocks),
            previous_hash=previous_hash,
            timestamp=timestamp,
            payload=payload,
            ciphertext_hex=ciphertext_hex,
            iv_hex=iv_hex,
            mac_hex=mac_hex,
            nonce=nonce,
        )
        self.blocks.append(block)
        return block

    def validate(self, difficulty: int = 3) -> tuple[bool, list[str]]:
        errors: list[str] = []
        target = "0" * difficulty

        for position, block in enumerate(self.blocks):
            if block.index != position:
                errors.append(f"Block index mismatch at position {position}.")

            expected_previous = (
                "0" * 64 if position == 0 else self.blocks[position - 1].hash()
            )
            if block.previous_hash != expected_previous:
                errors.append(f"Broken previous-hash link at block {block.index}.")

            if not block.hash().startswith(target):
                errors.append(f"Proof-of-work failure at block {block.index}.")

            if not self._verify_payload_mac(block):
                errors.append(f"Payload MAC failure at block {block.index}.")

            try:
                self.decrypt_payload(block)
            except (ValueError, UnicodeDecodeError):
                errors.append(f"Encrypted payload cannot be authenticated/decrypted "
                              f"at block {block.index}.")

        return not errors, errors


# ---------------------------------------------------------------------------
# Demonstrations
# ---------------------------------------------------------------------------

def known_answer_test() -> None:
    """
    FIPS-style classic DES test vector:
        key       = 133457799BBCDFF1
        plaintext = 0123456789ABCDEF
        ciphertext= 85E813540F0AB405
    """
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")

    actual = des_encrypt_block(plaintext, key)
    assert actual == expected, (
        f"DES test vector failed: {actual.hex().upper()} != "
        f"{expected.hex().upper()}"
    )
    assert des_decrypt_block(actual, key) == plaintext


def beginner_demo() -> None:
    print("\n=== DES fundamentals ===")
    key = set_odd_parity(b"Crypto!!")
    block = b"12345678"

    print("Key:", key.hex().upper())
    print("Effective DES key size: 56 bits")
    print("Block size: 64 bits")
    print("Plain block:", block)

    encrypted = des_encrypt_block(block, key)
    recovered = des_decrypt_block(encrypted, key)

    print("Cipher block:", encrypted.hex().upper())
    print("Recovered:", recovered)
    print("Round-trip:", recovered == block)
    print("Weak key:", is_weak_des_key(key))


def cbc_demo() -> None:
    print("\n=== DES-CBC message encryption ===")
    key = set_odd_parity(b"LegacyK!")
    iv = secrets.token_bytes(8)
    message = (
        b"Historical blockchain archive record: block 17 contains an audit event."
    )

    ciphertext = des_cbc_encrypt(message, key, iv)
    recovered = des_cbc_decrypt(ciphertext, key, iv)

    print("IV:", iv.hex().upper())
    print("Ciphertext:", ciphertext.hex().upper())
    print("Recovered:", recovered.decode())
    print("Round-trip:", recovered == message)

    # Reusing an IV in CBC undermines semantic security. A fresh IV is generated
    # for every encryption in the blockchain class.
    second_ciphertext = des_cbc_encrypt(message, key, iv)
    print("Same IV + same plaintext gives same ciphertext:",
          ciphertext == second_ciphertext)


def validation_demo() -> None:
    print("\n=== Validation and failure handling ===")

    invalid_key = b"bad"
    try:
        generate_round_keys(invalid_key)
    except ValueError as exc:
        print("Invalid key rejected:", exc)

    weak_key = bytes.fromhex("0101010101010101")
    print("Known weak key detected:", is_weak_des_key(weak_key))

    key = set_odd_parity(b"Secure!!")
    iv = secrets.token_bytes(8)
    ciphertext = des_cbc_encrypt(b"Authenticated data", key, iv)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    try:
        # Padding may fail or may accidentally remain syntactically valid.
        # Either result illustrates why unauthenticated encryption is unsafe.
        des_cbc_decrypt(bytes(tampered), key, iv)
        print("Tampered CBC ciphertext happened to pass padding validation.")
    except ValueError as exc:
        print("Tampering caused decryption failure:", exc)


def blockchain_demo() -> None:
    print("\n=== DES around a blockchain payload ===")

    des_key = set_odd_parity(secrets.token_bytes(8))
    mac_key = secrets.token_bytes(32)

    chain = EducationalBlockchain(des_key, mac_key)

    chain.add_block("Asset transfer: account-A -> account-B, amount=250", difficulty=2)
    chain.add_block("Audit event: settlement confirmed by validator", difficulty=2)
    chain.add_block("Contract state: escrow=RELEASED", difficulty=2)

    valid, errors = chain.validate(difficulty=2)
    print("Chain valid:", valid)
    if errors:
        print("Validation errors:", errors)

    for block in chain.blocks:
        print(
            f"Block {block.index}: hash={block.hash()[:20]}... "
            f"nonce={block.nonce} payload={chain.decrypt_payload(block)}"
        )

    # Changing the plaintext field changes the block hash and therefore breaks
    # the relationship between the stored ciphertext and the authenticated data.
    original = chain.blocks[1]
    tampered = Block(
        index=original.index,
        previous_hash=original.previous_hash,
        timestamp=original.timestamp,
        payload="Asset transfer changed by attacker",
        ciphertext_hex=original.ciphertext_hex,
        iv_hex=original.iv_hex,
        mac_hex=original.mac_hex,
        nonce=original.nonce,
    )
    chain.blocks[1] = tampered

    valid, errors = chain.validate(difficulty=2)
    print("After payload tampering:", valid)
    for error in errors:
        print("  ", error)


def complexity_demo() -> None:
    print("\n=== Performance perspective ===")
    key = set_odd_parity(b"PerfTest")
    blocks = [secrets.token_bytes(8) for _ in range(100)]

    start = time.perf_counter()
    for block in blocks:
        des_encrypt_block(block, key)
    elapsed = time.perf_counter() - start

    print(f"Pure-Python DES block operations: {len(blocks)}")
    print(f"Elapsed time: {elapsed:.4f} seconds")
    print(
        "DES's 56-bit key space is the critical security limitation, "
        "not merely the implementation speed."
    )


def main() -> None:
    known_answer_test()
    beginner_demo()
    cbc_demo()
    validation_demo()
    blockchain_demo()
    complexity_demo()

    print("\n=== Security boundary ===")
    print(
        "DES provides historical confidentiality, not modern blockchain "
        "security. Blockchain integrity normally relies on hashes, digital "
        "signatures, authenticated consensus, or combinations of these."
    )
    print(
        "For modern applications, use an authenticated modern cipher such as "
        "AES-GCM or ChaCha20-Poly1305 instead of DES-CBC."
    )


if __name__ == "__main__":
    main()
