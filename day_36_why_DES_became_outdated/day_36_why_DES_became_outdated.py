"""
DES: Why the Data Encryption Standard Became Outdated

A self-contained technical demonstration of:
- DES's 64-bit block size
- 56-bit effective key size
- Feistel structure
- Triple DES as a transitional improvement
- Brute-force search economics
- Meet-in-the-middle intuition
- Birthday-bound pressure from small block sizes
- Why AES became the preferred modern replacement

The implementation includes a complete educational DES implementation using
only the Python standard library. It is intentionally written for clarity
rather than performance.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import time
from dataclasses import dataclass
from typing import Iterable


# DES tables are fixed by the DES specification.
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

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def permute(value: int, table: list[int], input_bits: int) -> int:
    """Apply a DES permutation table to an integer bit representation."""
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_bits - position)) & 1)
    return result


def left_rotate(value: int, width: int, amount: int) -> int:
    """Rotate a fixed-width integer left, as required by DES key scheduling."""
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def generate_round_keys(key: int) -> list[int]:
    """Generate the sixteen 48-bit DES round keys."""
    if not 0 <= key < (1 << 64):
        raise ValueError("DES keys must be represented as 64-bit values.")

    permuted = permute(key, PC1, 64)
    c = permuted >> 28
    d = permuted & ((1 << 28) - 1)

    round_keys = []
    for rotation in ROTATIONS:
        c = left_rotate(c, 28, rotation)
        d = left_rotate(d, 28, rotation)
        combined = (c << 28) | d
        round_keys.append(permute(combined, PC2, 56))

    return round_keys


def feistel(right: int, round_key: int) -> int:
    """Execute the DES expansion, XOR, substitution, and permutation steps."""
    expanded = permute(right, E, 32)
    mixed = expanded ^ round_key

    substituted = 0
    for box_index in range(8):
        six_bits = (mixed >> (42 - 6 * box_index)) & 0x3F
        row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01)
        column = (six_bits >> 1) & 0x0F
        value = S_BOXES[box_index][row][column]
        substituted = (substituted << 4) | value

    return permute(substituted, P, 32)


def des_block(block: int, key: int, decrypt: bool = False) -> int:
    """Encrypt or decrypt one 64-bit DES block."""
    if not 0 <= block < (1 << 64):
        raise ValueError("DES operates on exactly 64-bit blocks.")

    round_keys = generate_round_keys(key)
    if decrypt:
        round_keys.reverse()

    state = permute(block, IP, 64)
    left = state >> 32
    right = state & 0xFFFFFFFF

    for round_key in round_keys:
        left, right = right, left ^ feistel(right, round_key)

    preoutput = (right << 32) | left
    return permute(preoutput, FP, 64)


def des_encrypt(block: bytes, key: bytes) -> bytes:
    """Encrypt exactly eight bytes using DES ECB for educational demonstration."""
    if len(block) != 8:
        raise ValueError("This demonstration requires exactly one 8-byte block.")
    if len(key) != 8:
        raise ValueError("DES requires an 8-byte key representation.")

    result = des_block(int.from_bytes(block, "big"), int.from_bytes(key, "big"))
    return result.to_bytes(8, "big")


def des_decrypt(block: bytes, key: bytes) -> bytes:
    """Decrypt exactly one DES block."""
    if len(block) != 8:
        raise ValueError("This demonstration requires exactly one 8-byte block.")
    if len(key) != 8:
        raise ValueError("DES requires an 8-byte key representation.")

    result = des_block(
        int.from_bytes(block, "big"),
        int.from_bytes(key, "big"),
        decrypt=True,
    )
    return result.to_bytes(8, "big")


def demonstrate_known_vector() -> None:
    """
    Verify the classic DES test vector.

    Key       = 133457799BBCDFF1
    Plaintext = 0123456789ABCDEF
    Cipher    = 85E813540F0AB405
    """
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")

    ciphertext = des_encrypt(plaintext, key)
    recovered = des_decrypt(ciphertext, key)

    print("Classic DES test vector")
    print("  plaintext :", plaintext.hex().upper())
    print("  key        :", key.hex().upper())
    print("  ciphertext :", ciphertext.hex().upper())
    print("  expected   :", expected.hex().upper())
    print("  valid      :", ciphertext == expected)
    print("  recovered  :", recovered.hex().upper())
    print()


def explain_key_space() -> None:
    """Quantify the central cryptographic problem: DES has only 2^56 effective keys."""
    key_space = 2**56
    print("DES key-space analysis")
    print(f"  Effective key size : 56 bits")
    print(f"  Possible keys      : {key_space:,}")
    print(f"  Approx. keys       : {key_space / 1e15:.3f} quadrillion")
    print(f"  Average brute-force trials: {2**55:,}")
    print()


def brute_force_demo() -> None:
    """
    Demonstrate exhaustive key search without attempting the real 56-bit space.

    A deliberately tiny keyspace is used so the mechanism can be observed
    safely and quickly. The demonstration makes clear that the algorithmic
    weakness is not a broken DES round function: it is the feasibility of
    searching the finite keyspace.
    """
    plaintext = b"DESDEMO!"
    secret_low_bits = 0x0A5B
    fixed_prefix = 0x133457799BBC0000
    secret_key_int = fixed_prefix | secret_low_bits
    secret_key = secret_key_int.to_bytes(8, "big")

    ciphertext = des_encrypt(plaintext, secret_key)

    print("Reduced-key-space brute-force demonstration")
    print("  Real DES search space : 2^56")
    print("  Demonstration space   : 2^16")
    print("  Secret key suffix     :", hex(secret_low_bits))
    print("  Ciphertext            :", ciphertext.hex().upper())

    start = time.perf_counter()
    found = None

    for candidate_suffix in range(2**16):
        candidate_key_int = fixed_prefix | candidate_suffix
        candidate_key = candidate_key_int.to_bytes(8, "big")
        if des_encrypt(plaintext, candidate_key) == ciphertext:
            found = candidate_suffix
            break

    elapsed = time.perf_counter() - start

    print("  Recovered suffix      :", hex(found) if found is not None else "not found")
    print(f"  Search time           : {elapsed:.4f} seconds")
    print("  Lesson                : exhaustive search scales with keyspace size")
    print()


def block_size_analysis() -> None:
    """
    Explain why the 64-bit block size is a second-generation limitation.

    The birthday bound is roughly 2^(n/2) blocks for an n-bit block cipher.
    For DES, this is 2^32 blocks, or about 34.4 billion blocks. At eight
    bytes per block this is approximately 256 GiB of data.
    """
    blocks = 2**32
    bytes_processed = blocks * 8
    gib = bytes_processed / (1024**3)

    print("DES block-size analysis")
    print("  Block size              : 64 bits")
    print("  Birthday-bound scale    : approximately 2^32 blocks")
    print(f"  Data at that scale      : approximately {gib:.1f} GiB")
    print("  Modern lesson            : larger block sizes reduce collision and")
    print("                             multi-block mode limitations.")
    print()


def triple_des_analysis() -> None:
    """
    Explain why 3DES was transitional rather than a long-term solution.

    3DES applies DES three times. It substantially increases resistance to
    simple DES brute force, but it retains DES's 64-bit block size and is
    computationally expensive compared with AES.
    """
    des_bits = 56
    triple_des_nominal_bits = 168
    triple_des_effective_security = 112

    print("Triple DES transition analysis")
    print(f"  DES effective key size             : {des_bits} bits")
    print(f"  3DES nominal key material         : {triple_des_nominal_bits} bits")
    print(f"  Commonly cited effective strength : about {triple_des_effective_security} bits")
    print("  Structural limitation retained    : 64-bit block size")
    print("  Main engineering limitation       : substantially slower than AES")
    print("  Role                               : migration technology, not modern default")
    print()


def avalanche_demo() -> None:
    """Show that DES can still exhibit strong avalanche behavior despite being obsolete."""
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext_a = bytes.fromhex("0123456789ABCDEF")
    plaintext_b = bytes.fromhex("0123456789ABCDEE")

    ciphertext_a = des_encrypt(plaintext_a, key)
    ciphertext_b = des_encrypt(plaintext_b, key)

    a = int.from_bytes(ciphertext_a, "big")
    b = int.from_bytes(ciphertext_b, "big")
    changed_bits = (a ^ b).bit_count()

    print("Avalanche demonstration")
    print("  Plaintext A :", plaintext_a.hex().upper())
    print("  Plaintext B :", plaintext_b.hex().upper())
    print("  Cipher A    :", ciphertext_a.hex().upper())
    print("  Cipher B    :", ciphertext_b.hex().upper())
    print(f"  Changed ciphertext bits: {changed_bits}/64")
    print("  Interpretation: DES's obsolescence is not because its basic")
    print("  substitution-permutation behavior stopped working.")
    print()


def modern_cipher_comparison() -> None:
    """Compare the design characteristics that made AES a better modern choice."""
    comparison = [
        ("DES", "56 bits", "64 bits", "16 Feistel rounds", "obsolete"),
        ("3DES", "112 effective bits commonly cited", "64 bits", "48 DES operations", "legacy transition"),
        ("AES-128", "128 bits", "128 bits", "10 rounds", "modern"),
        ("AES-256", "256 bits", "128 bits", "14 rounds", "modern"),
    ]

    print("Symmetric-cipher design comparison")
    print(f"{'Cipher':<12}{'Key':<28}{'Block':<12}{'Structure':<24}{'Status'}")
    print("-" * 90)
    for row in comparison:
        print(f"{row[0]:<12}{row[1]:<28}{row[2]:<12}{row[3]:<24}{row[4]}")
    print()


def security_policy_demo() -> None:
    """
    Apply a simple policy model to realistic algorithm choices.

    This models an engineering decision rather than attempting to judge
    cryptography solely by whether encryption/decryption still functions.
    """
    policy = {
        "DES": False,
        "3DES": False,
        "AES-128": True,
        "AES-256": True,
    }

    requested_algorithms = ["DES", "3DES", "AES-256"]

    print("Algorithm acceptance policy")
    for algorithm in requested_algorithms:
        if policy.get(algorithm, False):
            print(f"  ACCEPT: {algorithm}")
        else:
            print(f"  REJECT: {algorithm}")
    print()


def hash_based_fingerprint(data: bytes) -> str:
    """
    Produce a SHA-256 fingerprint for demonstration.

    Hashing is not encryption and is included only to show the importance of
    selecting a primitive according to its purpose.
    """
    return hashlib.sha256(data).hexdigest()


def common_mistakes() -> None:
    print("Common DES migration mistakes")
    print("  - Treating a successful DES decrypt as evidence that DES is secure.")
    print("  - Assuming 64-bit blocks are equivalent to 64-bit keys.")
    print("  - Counting DES's parity-encoded 64-bit key representation as 64")
    print("    independent secret bits.")
    print("  - Replacing DES with 3DES without considering its 64-bit block size.")
    print("  - Using raw ECB mode for multi-block application data.")
    print("  - Confusing encryption with hashing or authentication.")
    print("  - Leaving DES enabled because an old configuration still works.")
    print()


def main() -> None:
    print("=" * 90)
    print("WHY DES BECAME OUTDATED")
    print("=" * 90)
    print()

    demonstrate_known_vector()
    explain_key_space()
    brute_force_demo()
    block_size_analysis()
    triple_des_analysis()
    avalanche_demo()
    modern_cipher_comparison()
    security_policy_demo()
    common_mistakes()

    sample = b"repository encryption migration"
    print("Purpose-sensitive cryptography example")
    print("  Data       :", sample.decode())
    print("  SHA-256    :", hash_based_fingerprint(sample))
    print("  Reminder   : hashing provides integrity-oriented primitives, not reversible encryption.")
    print()

    print("Final engineering interpretation")
    print("  DES became outdated primarily because its 56-bit effective key space")
    print("  became economically searchable. Its 64-bit block size also became")
    print("  increasingly restrictive for high-volume modern systems. 3DES extended")
    print("  the useful life of DES but retained important architectural limitations.")
    print("  AES provided substantially larger key and block sizes with much better")
    print("  performance and became the mainstream replacement.")


if __name__ == "__main__":
    main()
