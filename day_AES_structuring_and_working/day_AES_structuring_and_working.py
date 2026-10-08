"""
AES Structure and Working
A self-contained educational implementation of AES-128.

The implementation exposes the actual AES transformations:
SubBytes, ShiftRows, MixColumns, AddRoundKey, key expansion,
encryption, decryption, and round-by-round state tracing.

It intentionally implements AES-128 directly rather than depending on
a cryptography package so that the internal structure is visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


S_BOX = [
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
]

INV_S_BOX = [0] * 256
for index, value in enumerate(S_BOX):
    INV_S_BOX[value] = index

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def validate_block(block: bytes) -> None:
    if len(block) != 16:
        raise ValueError("AES has a fixed 128-bit block size: exactly 16 bytes are required.")


def validate_key(key: bytes) -> None:
    if len(key) != 16:
        raise ValueError("This implementation supports AES-128: the key must contain 16 bytes.")


def bytes_to_state(block: bytes) -> list[list[int]]:
    validate_block(block)
    # AES fills the state column by column. state[row][column] is used here.
    return [[block[4 * column + row] for column in range(4)] for row in range(4)]


def state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[row][column] for column in range(4) for row in range(4))


def format_state(state: list[list[int]]) -> str:
    return "\n".join(" ".join(f"{value:02x}" for value in row) for row in state)


def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[S_BOX[value] for value in row] for row in state]


def inverse_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[INV_S_BOX[value] for value in row] for row in state]


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    # Row r is rotated left by r positions.
    return [state[row][row:] + state[row][:row] for row in range(4)]


def inverse_shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [state[row][-row:] + state[row][:-row] if row else state[row][:] for row in range(4)]


def xtime(value: int) -> int:
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def gmul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    result = [row[:] for row in state]

    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        result[0][column] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        result[1][column] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        result[2][column] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        result[3][column] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)

    return result


def inverse_mix_columns(state: list[list[int]]) -> list[list[int]]:
    result = [row[:] for row in state]

    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        result[0][column] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        result[1][column] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        result[2][column] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        result[3][column] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)

    return result


def add_round_key(state: list[list[int]], round_key: bytes) -> list[list[int]]:
    key_state = bytes_to_state(round_key)
    return [
        [state[row][column] ^ key_state[row][column] for column in range(4)]
        for row in range(4)
    ]


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def sub_word(word: list[int]) -> list[int]:
    return [S_BOX[value] for value in word]


def expand_key(key: bytes) -> list[bytes]:
    validate_key(key)

    words = [list(key[index:index + 4]) for index in range(0, 16, 4)]

    while len(words) < 44:
        temp = words[-1][:]
        word_index = len(words)

        if word_index % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[word_index // 4]

        words.append([
            words[-4][i] ^ temp[i]
            for i in range(4)
        ])

    round_keys = []
    for start in range(0, 44, 4):
        round_keys.append(bytes(sum(words[start:start + 4], [])))

    return round_keys


@dataclass
class RoundSnapshot:
    round_number: int
    stage: str
    state: bytes


class AES128:
    ROUNDS = 10

    def __init__(self, key: bytes):
        validate_key(key)
        self.key = key
        self.round_keys = expand_key(key)

    def encrypt_block(self, plaintext: bytes, trace: bool = False) -> tuple[bytes, list[RoundSnapshot]]:
        validate_block(plaintext)

        snapshots: list[RoundSnapshot] = []
        state = bytes_to_state(plaintext)

        state = add_round_key(state, self.round_keys[0])
        if trace:
            snapshots.append(RoundSnapshot(0, "AddRoundKey", state_to_bytes(state)))

        for round_number in range(1, self.ROUNDS + 1):
            state = sub_bytes(state)
            if trace:
                snapshots.append(
                    RoundSnapshot(round_number, "SubBytes", state_to_bytes(state))
                )

            state = shift_rows(state)
            if trace:
                snapshots.append(
                    RoundSnapshot(round_number, "ShiftRows", state_to_bytes(state))
                )

            if round_number != self.ROUNDS:
                state = mix_columns(state)
                if trace:
                    snapshots.append(
                        RoundSnapshot(round_number, "MixColumns", state_to_bytes(state))
                    )

            state = add_round_key(state, self.round_keys[round_number])
            if trace:
                snapshots.append(
                    RoundSnapshot(round_number, "AddRoundKey", state_to_bytes(state))
                )

        return state_to_bytes(state), snapshots

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        validate_block(ciphertext)
        state = bytes_to_state(ciphertext)

        state = add_round_key(state, self.round_keys[self.ROUNDS])

        for round_number in range(self.ROUNDS - 1, -1, -1):
            state = inverse_shift_rows(state)
            state = inverse_sub_bytes(state)
            state = add_round_key(state, self.round_keys[round_number])

            if round_number != 0:
                state = inverse_mix_columns(state)

        return state_to_bytes(state)


def print_round_keys(round_keys: list[bytes]) -> None:
    print("\nAES-128 expanded round keys")
    for number, key in enumerate(round_keys):
        print(f"Round {number:2d}: {key.hex()}")


def print_trace(trace: list[RoundSnapshot]) -> None:
    print("\nAES encryption state trace")
    current_round = None

    for snapshot in trace:
        if snapshot.round_number != current_round:
            current_round = snapshot.round_number
            print(f"\nRound {current_round}")

        print(f"{snapshot.stage}:")
        print(format_state(bytes_to_state(snapshot.state)))


def demonstrate_galois_field() -> None:
    print("\nFinite-field multiplication example")
    print("0x57 × 0x13 =", f"{gmul(0x57, 0x13):02x}")
    print("AES MixColumns operates over GF(2^8), not ordinary integer multiplication.")


def run_known_answer_test() -> None:
    # FIPS-197 AES-128 example.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    cipher = AES128(key)
    ciphertext, _ = cipher.encrypt_block(plaintext)

    if ciphertext != expected_ciphertext:
        raise AssertionError(
            f"AES known-answer test failed: {ciphertext.hex()} != {expected_ciphertext.hex()}"
        )

    recovered = cipher.decrypt_block(ciphertext)

    if recovered != plaintext:
        raise AssertionError("AES decryption failed to recover the original plaintext.")

    print("\nFIPS-197 known-answer test: PASS")
    print("Plaintext :", plaintext.hex())
    print("Key       :", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered.hex())


def demonstrate_validation() -> None:
    print("\nValidation examples")

    for invalid_key in (b"short", b"", b"x" * 24):
        try:
            AES128(invalid_key)
        except ValueError as exc:
            print("Rejected key:", exc)

    try:
        AES128(b"0123456789abcdef").encrypt_block(b"too short")
    except ValueError as exc:
        print("Rejected block:", exc)


def main() -> None:
    print("AES-128 Structure and Working")
    print("=" * 32)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    cipher = AES128(key)

    print("\nState representation")
    print(format_state(bytes_to_state(plaintext)))
    print("\nAES uses a 4 × 4 byte state matrix and a fixed 128-bit block.")

    print_round_keys(cipher.round_keys)
    demonstrate_galois_field()

    ciphertext, trace = cipher.encrypt_block(plaintext, trace=True)

    print("\nCiphertext:", ciphertext.hex())
    print_trace(trace)

    recovered = cipher.decrypt_block(ciphertext)
    print("\nDecrypted:", recovered.hex())

    run_known_answer_test()
    demonstrate_validation()

    print("\nSecurity boundary")
    print(
        "AES itself is a block cipher. Real applications normally use an authenticated "
        "mode such as AES-GCM rather than constructing encryption protocols from raw "
        "AES blocks. Keys must be generated and stored securely, IVs/nonces must obey "
        "the selected mode's uniqueness requirements, and plaintext should not be "
        "encrypted with ECB merely because the primitive is correct."
    )


if __name__ == "__main__":
    main()
