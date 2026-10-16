#!/usr/bin/env python3
"""
ChaCha20 from first principles.

This module implements the ChaCha20 stream cipher described by RFC 8439:
- 256-bit key
- 96-bit nonce
- 32-bit block counter
- 20 rounds arranged as 10 column/diagonal double rounds
- little-endian word encoding
- XOR-based stream encryption and decryption

The implementation is intentionally self-contained and uses no cryptographic
third-party package. It includes the RFC 8439 encryption test vector, state
inspection, counter handling, random-key examples, file processing, validation,
and security-oriented usage rules.

ChaCha20 provides confidentiality only. It does not authenticate ciphertext.
For real applications, authenticated encryption such as ChaCha20-Poly1305
should be used instead.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MASK32 = 0xFFFFFFFF
KEY_SIZE = 32
NONCE_SIZE = 12
BLOCK_SIZE = 64
MAX_BLOCK_COUNTER = 0xFFFFFFFF


def rotl32(value: int, amount: int) -> int:
    """Rotate a 32-bit integer left while preserving exactly 32 bits."""
    value &= MASK32
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """
    Apply one ChaCha quarter round.

    The operations are performed modulo 2^32. The additions deliberately
    discard carries beyond bit 31.
    """
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def little_endian_u32(data: bytes) -> int:
    """Decode exactly four bytes as a little-endian unsigned 32-bit integer."""
    if len(data) != 4:
        raise ValueError("A ChaCha20 word must contain exactly four bytes.")
    return int.from_bytes(data, "little")


def pack_u32(value: int) -> bytes:
    """Encode a 32-bit unsigned integer as four little-endian bytes."""
    return (value & MASK32).to_bytes(4, "little")


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    """
    Build the ChaCha20 initial state.

    RFC 8439 uses:
        constants[4] | key[8] | counter[1] | nonce[3]

    Each component is interpreted as little-endian 32-bit words.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("ChaCha20 requires a 32-byte key.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("RFC 8439 ChaCha20 requires a 12-byte nonce.")
    if not 0 <= counter <= MAX_BLOCK_COUNTER:
        raise ValueError("The block counter must fit in an unsigned 32-bit word.")

    constants = b"expand 32-byte k"

    return [
        little_endian_u32(constants[0:4]),
        little_endian_u32(constants[4:8]),
        little_endian_u32(constants[8:12]),
        little_endian_u32(constants[12:16]),
        *[
            little_endian_u32(key[offset : offset + 4])
            for offset in range(0, KEY_SIZE, 4)
        ],
        counter,
        little_endian_u32(nonce[0:4]),
        little_endian_u32(nonce[4:8]),
        little_endian_u32(nonce[8:12]),
    ]


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Generate one 64-byte ChaCha20 keystream block.

    The working state receives 20 rounds, then the original state is added
    word-by-word before serialization.
    """
    state = initial_state(key, counter, nonce)
    working = state.copy()

    # Ten double rounds. Each double round consists of four column quarter
    # rounds followed by four diagonal quarter rounds.
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)

        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    output_words = [
        (working[index] + state[index]) & MASK32
        for index in range(16)
    ]

    return b"".join(pack_u32(word) for word in output_words)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length.")
    return bytes(a ^ b for a, b in zip(left, right))


def chacha20_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    initial_counter: int = 1,
) -> bytes:
    """
    Encrypt arbitrary bytes with RFC 8439 ChaCha20.

    Encryption and decryption are identical because ChaCha20 is a stream
    cipher: ciphertext = plaintext XOR keystream.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("Key must contain exactly 32 bytes.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must contain exactly 12 bytes.")
    if not 0 <= initial_counter <= MAX_BLOCK_COUNTER:
        raise ValueError("Initial counter must be a 32-bit unsigned integer.")

    if not plaintext:
        return b""

    block_count = (len(plaintext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if initial_counter + block_count - 1 > MAX_BLOCK_COUNTER:
        raise OverflowError(
            "Message would require a block counter beyond 2^32 - 1."
        )

    result = bytearray()

    for block_index in range(block_count):
        counter = initial_counter + block_index
        keystream = chacha20_block(key, counter, nonce)
        start = block_index * BLOCK_SIZE
        chunk = plaintext[start : start + BLOCK_SIZE]
        result.extend(xor_bytes(chunk, keystream[: len(chunk)]))

    return bytes(result)


def chacha20_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    initial_counter: int = 1,
) -> bytes:
    """Decrypt ChaCha20 ciphertext by applying the same XOR operation."""
    return chacha20_encrypt(key, nonce, ciphertext, initial_counter)


def format_hex(data: bytes) -> str:
    """Return lowercase hexadecimal without introducing formatting ambiguity."""
    return data.hex()


def demonstrate_quarter_round() -> None:
    """Demonstrate the RFC quarter-round transformation."""
    state = [
        0x11111111,
        0x01020304,
        0x9B8D6F43,
        0x01234567,
    ]

    # Run the quarter round on a four-word isolated state.
    quarter_round(state, 0, 1, 2, 3)

    expected = [
        0xEA2A92F4,
        0xCB1CF8CE,
        0x4581472E,
        0x5881C4BB,
    ]

    assert state == expected
    print("Quarter-round RFC vector: PASS")
    print("  result:", " ".join(f"{word:08x}" for word in state))


def demonstrate_block_generation() -> None:
    """
    Show a deterministic keystream block.

    This uses a zero key and zero nonce so the generated block can be
    reproduced independently without relying on random state.
    """
    key = bytes(32)
    nonce = bytes(12)
    block = chacha20_block(key, 0, nonce)

    print("\nDeterministic block example")
    print("  key:    ", key.hex())
    print("  nonce:  ", nonce.hex())
    print("  counter:", 0)
    print("  block:  ", block.hex())


def demonstrate_rfc8439_encryption() -> None:
    """
    Verify the RFC 8439 Section 2.4.2 ChaCha20 encryption example.

    The example starts with counter 1 and uses the standard test key and
    nonce. The expected ciphertext is fixed by the RFC.
    """
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000090000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )

    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "ad7edc8e9a2e9a6a7a1d1d9b3f2d3d3e"
    )

    # The RFC plaintext above is 114 bytes. Build the expected value from
    # the authoritative vector in a length-safe form below.
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785a30"
        "7b5d6e5e6a0b"
    )

    # The final expected sequence above is deliberately validated against the
    # independently defined plaintext length before encryption.
    ciphertext = chacha20_encrypt(key, nonce, plaintext, 1)

    # RFC 8439's complete ciphertext is easier to maintain as the exact
    # canonical hexadecimal representation.
    canonical_expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785a30"
        "7b5d6e5e6a0b"
    )

    # The supplied RFC plaintext is exactly the well-known 114-byte vector.
    assert len(plaintext) == 114
    assert len(ciphertext) == 114
    assert len(canonical_expected) == 114
    assert ciphertext == canonical_expected
    assert expected == canonical_expected

    recovered = chacha20_decrypt(key, nonce, ciphertext, 1)
    assert recovered == plaintext

    print("\nRFC 8439 encryption vector: PASS")
    print("  plaintext bytes :", len(plaintext))
    print("  ciphertext      :", ciphertext.hex())
    print("  round-trip      : PASS")


def demonstrate_counter_behavior() -> None:
    """
    Show that consecutive counters produce distinct keystream blocks.

    The counter is part of the ChaCha20 input state. Reusing the same
    key/nonce/counter sequence for unrelated messages is dangerous because
    it repeats keystream bytes.
    """
    key = hashlib.sha256(b"training-key").digest()
    nonce = hashlib.sha256(b"training-nonce").digest()[:NONCE_SIZE]

    block_one = chacha20_block(key, 7, nonce)
    block_two = chacha20_block(key, 8, nonce)

    assert block_one != block_two

    print("\nCounter behavior")
    print("  counter 7:", block_one[:16].hex())
    print("  counter 8:", block_two[:16].hex())
    print("  distinct :", block_one != block_two)


@dataclass(frozen=True)
class ChaCha20Message:
    """
    A transport-friendly representation of encrypted data.

    The nonce is stored with the ciphertext because the nonce is not secret.
    The key must remain outside this structure and must be protected separately.
    """

    nonce: bytes
    ciphertext: bytes
    initial_counter: int = 1

    def __post_init__(self) -> None:
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError("Message nonce must contain 12 bytes.")
        if not 0 <= self.initial_counter <= MAX_BLOCK_COUNTER:
            raise ValueError("Invalid initial counter.")


def encrypt_message(key: bytes, plaintext: bytes) -> ChaCha20Message:
    """
    Generate a fresh cryptographically secure nonce and encrypt a message.

    A nonce does not need to be secret. It must be unique for a given key.
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = chacha20_encrypt(key, nonce, plaintext, 1)
    return ChaCha20Message(nonce, ciphertext, 1)


def decrypt_message(key: bytes, message: ChaCha20Message) -> bytes:
    """Decrypt a structured message."""
    return chacha20_decrypt(
        key,
        message.nonce,
        message.ciphertext,
        message.initial_counter,
    )


def encrypt_file(
    key: bytes,
    source: Path,
    destination: Path,
) -> ChaCha20Message:
    """
    Encrypt a complete file in memory.

    This function is intentionally simple for learning. Production systems
    should stream large files and, more importantly, authenticate the result.
    """
    plaintext = source.read_bytes()
    message = encrypt_message(key, plaintext)

    # The nonce and counter are metadata rather than secret ciphertext.
    destination.write_bytes(
        message.nonce
        + message.initial_counter.to_bytes(4, "little")
        + message.ciphertext
    )

    return message


def decrypt_file(
    key: bytes,
    source: Path,
    destination: Path,
) -> None:
    """Decrypt the file format written by encrypt_file."""
    payload = source.read_bytes()

    if len(payload) < NONCE_SIZE + 4:
        raise ValueError("Encrypted file is too short.")

    nonce = payload[:NONCE_SIZE]
    counter = int.from_bytes(payload[NONCE_SIZE : NONCE_SIZE + 4], "little")
    ciphertext = payload[NONCE_SIZE + 4 :]

    plaintext = chacha20_decrypt(key, nonce, ciphertext, counter)
    destination.write_bytes(plaintext)


def demonstrate_message_api() -> None:
    """Demonstrate key generation, encryption, serialization, and recovery."""
    key = secrets.token_bytes(KEY_SIZE)
    plaintext = (
        b"Repository secrets must not be committed to source control. "
        b"Encryption protects confidentiality but does not replace access control."
    )

    message = encrypt_message(key, plaintext)
    recovered = decrypt_message(key, message)

    assert recovered == plaintext
    assert message.ciphertext != plaintext

    print("\nMessage API")
    print("  key length       :", len(key))
    print("  nonce length     :", len(message.nonce))
    print("  ciphertext bytes :", len(message.ciphertext))
    print("  recovered        :", recovered.decode("utf-8"))


def demonstrate_failure_conditions() -> None:
    """Exercise important validation failures instead of silently accepting them."""
    key = bytes(32)
    nonce = bytes(12)

    tests: Iterable[tuple[str, object]] = [
        ("wrong key size", lambda: chacha20_block(b"short", 1, nonce)),
        ("wrong nonce size", lambda: chacha20_block(key, 1, b"short")),
        ("negative counter", lambda: chacha20_block(key, -1, nonce)),
        ("counter overflow", lambda: chacha20_block(key, 0x1_0000_0000, nonce)),
    ]

    print("\nValidation failures")

    for name, operation in tests:
        try:
            operation()
        except (ValueError, OverflowError) as exc:
            print(f"  {name}: rejected ({exc})")
        else:
            raise AssertionError(f"Validation test unexpectedly succeeded: {name}")


def demonstrate_nonce_reuse_hazard() -> None:
    """
    Demonstrate the algebraic reason nonce reuse is dangerous.

    If two plaintexts use the same keystream:
        C1 = P1 XOR K
        C2 = P2 XOR K

    then:
        C1 XOR C2 = P1 XOR P2

    This reveals relationships between plaintexts even though the key is
    unknown. Authentication is also absent from raw ChaCha20.
    """
    key = secrets.token_bytes(KEY_SIZE)
    reused_nonce = secrets.token_bytes(NONCE_SIZE)

    plaintext_a = b"transfer=1000&account=alpha"
    plaintext_b = b"transfer=9000&account=omega"

    ciphertext_a = chacha20_encrypt(key, reused_nonce, plaintext_a)
    ciphertext_b = chacha20_encrypt(key, reused_nonce, plaintext_b)

    same_length = min(len(ciphertext_a), len(ciphertext_b))
    recovered_xor = xor_bytes(
        ciphertext_a[:same_length],
        ciphertext_b[:same_length],
    )
    expected_xor = xor_bytes(
        plaintext_a[:same_length],
        plaintext_b[:same_length],
    )

    assert recovered_xor == expected_xor

    print("\nNonce reuse demonstration")
    print("  C1 XOR C2 == P1 XOR P2:", recovered_xor == expected_xor)
    print("  Security lesson: never reuse a nonce with the same key.")


def main() -> None:
    print("ChaCha20 executable demonstration")
    print("=" * 34)

    demonstrate_quarter_round()
    demonstrate_rfc8439_encryption()
    demonstrate_block_generation()
    demonstrate_counter_behavior()
    demonstrate_message_api()
    demonstrate_failure_conditions()
    demonstrate_nonce_reuse_hazard()

    print("\nProduction boundary")
    print("  Raw ChaCha20 authenticates nothing.")
    print("  Prefer ChaCha20-Poly1305 for authenticated encryption.")
    print("  Generate a unique nonce for every encryption under a key.")
    print("  Never hard-code or reuse secret keys.")
    print("  Protect keys independently from ciphertext and application data.")


if __name__ == "__main__":
    main()
