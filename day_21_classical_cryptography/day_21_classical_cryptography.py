"""
Classical Cryptography: From Fundamentals to Cryptanalysis

A self-contained study and experimentation program covering:
- plaintext, ciphertext, keys, encryption, decryption
- substitution and transposition
- Caesar cipher
- affine cipher
- monoalphabetic substitution
- Vigenere cipher
- Beaufort and variant Beaufort
- Autokey cipher
- Playfair cipher
- Hill cipher
- columnar transposition
- one-time pad
- modular arithmetic and modular inverses
- frequency analysis
- index of coincidence
- Kasiski examination
- known-plaintext and brute-force attacks
- cryptanalysis demonstrations
- implementation pitfalls
- validation, testing, and performance observations

The program uses only the Python standard library.
It is intentionally educational: classical ciphers are historically important
but should not be used to protect modern sensitive information.
"""

from __future__ import annotations

import math
import random
import string
from collections import Counter
from typing import Iterable, List, Optional, Sequence, Tuple


ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = 26


# ---------------------------------------------------------------------------
# Section 1: Fundamental concepts and common utility functions
# ---------------------------------------------------------------------------

def normalize_letters(text: str) -> str:
    """Keep alphabetic characters and convert them to uppercase."""
    return "".join(character for character in text.upper() if character.isalpha())


def letters_only_ascii(text: str) -> str:
    """Keep only A-Z. This is useful when a cipher is defined over 26 letters."""
    return "".join(character for character in text.upper() if character in ALPHABET)


def restore_case(original: str, transformed_letters: str) -> str:
    """
    Put transformed letters back into the approximate formatting of the
    original text.

    Non-letters are preserved. This is useful for readable demonstrations.
    """
    result = []
    transformed_index = 0

    for character in original:
        if character.isalpha() and transformed_index < len(transformed_letters):
            replacement = transformed_letters[transformed_index]
            result.append(replacement if character.isupper() else replacement.lower())
            transformed_index += 1
        else:
            result.append(character)

    return "".join(result)


def letter_to_number(letter: str) -> int:
    """Map A-Z to 0-25."""
    letter = letter.upper()
    if letter not in ALPHABET:
        raise ValueError(f"Expected A-Z, received {letter!r}")
    return ord(letter) - ord("A")


def number_to_letter(number: int) -> str:
    """Map an integer modulo 26 to A-Z."""
    return chr((number % ALPHABET_SIZE) + ord("A"))


def modular_inverse(value: int, modulus: int) -> int:
    """
    Return x such that value*x ≡ 1 (mod modulus).

    A modular inverse exists exactly when gcd(value, modulus) == 1.
    """
    value %= modulus

    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = extended_gcd(b, a % b)
        return gcd, y1, x1 - (a // b) * y1

    gcd, x, _ = extended_gcd(value, modulus)

    if gcd != 1:
        raise ValueError(
            f"{value} has no modular inverse modulo {modulus}; gcd is {gcd}."
        )

    return x % modulus


def gcd_many(values: Iterable[int]) -> int:
    """Calculate the greatest common divisor of several integers."""
    values = list(values)
    if not values:
        return 0

    result = abs(values[0])
    for value in values[1:]:
        result = math.gcd(result, abs(value))
    return result


# ---------------------------------------------------------------------------
# Section 2: Caesar cipher
# ---------------------------------------------------------------------------

def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypt using a Caesar shift.

    E(x) = (x + k) mod 26
    """
    result = []

    for character in text:
        if character.upper() in ALPHABET:
            number = letter_to_number(character)
            encrypted = number_to_letter(number + shift)
            result.append(encrypted if character.isupper() else encrypted.lower())
        else:
            result.append(character)

    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt by reversing the Caesar shift."""
    return caesar_encrypt(ciphertext, -shift)


def demonstrate_caesar() -> None:
    print("\n=== Caesar Cipher ===")

    plaintext = "Attack at dawn!"
    ciphertext = caesar_encrypt(plaintext, 3)
    recovered = caesar_decrypt(ciphertext, 3)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    print("\nAll Caesar candidates for a short ciphertext:")
    sample = "Khoor"
    for shift in range(ALPHABET_SIZE):
        print(f"shift={shift:2d}: {caesar_decrypt(sample, shift)}")


# ---------------------------------------------------------------------------
# Section 3: Affine cipher
# ---------------------------------------------------------------------------

def validate_affine_multiplier(a: int) -> None:
    """Affine encryption requires gcd(a, 26) == 1."""
    if math.gcd(a, ALPHABET_SIZE) != 1:
        raise ValueError(
            f"Affine multiplier {a} is invalid because gcd({a}, 26) != 1."
        )


def affine_encrypt(text: str, a: int, b: int) -> str:
    """
    Affine cipher:

        E(x) = (a*x + b) mod 26

    The multiplier a must be relatively prime to 26.
    """
    validate_affine_multiplier(a)

    result = []

    for character in text:
        if character.upper() in ALPHABET:
            x = letter_to_number(character)
            y = (a * x + b) % ALPHABET_SIZE
            replacement = number_to_letter(y)
            result.append(replacement if character.isupper() else replacement.lower())
        else:
            result.append(character)

    return "".join(result)


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    """
    Affine decryption:

        D(y) = a^(-1) * (y - b) mod 26
    """
    validate_affine_multiplier(a)
    inverse_a = modular_inverse(a, ALPHABET_SIZE)

    result = []

    for character in ciphertext:
        if character.upper() in ALPHABET:
            y = letter_to_number(character)
            x = (inverse_a * (y - b)) % ALPHABET_SIZE
            replacement = number_to_letter(x)
            result.append(replacement if character.isupper() else replacement.lower())
        else:
            result.append(character)

    return "".join(result)


def demonstrate_affine() -> None:
    print("\n=== Affine Cipher ===")

    plaintext = "Classical cryptography"
    ciphertext = affine_encrypt(plaintext, a=5, b=8)
    recovered = affine_decrypt(ciphertext, a=5, b=8)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    print("\nValid affine multipliers modulo 26:")
    valid = [a for a in range(ALPHABET_SIZE) if math.gcd(a, 26) == 1]
    print(valid)


# ---------------------------------------------------------------------------
# Section 4: Monoalphabetic substitution cipher
# ---------------------------------------------------------------------------

def validate_substitution_key(key: str) -> str:
    """A substitution key must be a permutation of A-Z."""
    normalized = letters_only_ascii(key)

    if len(normalized) != 26:
        raise ValueError("A substitution key must contain exactly 26 letters.")

    if len(set(normalized)) != 26:
        raise ValueError("A substitution key must contain every letter exactly once.")

    return normalized


def substitution_encrypt(text: str, key: str) -> str:
    """Encrypt with a fixed monoalphabetic substitution."""
    key = validate_substitution_key(key)
    mapping = dict(zip(ALPHABET, key))

    result = []
    for character in text:
        upper = character.upper()
        if upper in mapping:
            replacement = mapping[upper]
            result.append(replacement if character.isupper() else replacement.lower())
        else:
            result.append(character)

    return "".join(result)


def substitution_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt by reversing the substitution mapping."""
    key = validate_substitution_key(key)
    reverse_mapping = dict(zip(key, ALPHABET))

    result = []
    for character in ciphertext:
        upper = character.upper()
        if upper in reverse_mapping:
            replacement = reverse_mapping[upper]
            result.append(replacement if character.isupper() else replacement.lower())
        else:
            result.append(character)

    return "".join(result)


def demonstrate_substitution() -> None:
    print("\n=== Monoalphabetic Substitution ===")

    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    plaintext = "Meet me at the library."
    ciphertext = substitution_encrypt(plaintext, key)
    recovered = substitution_decrypt(ciphertext, key)

    print("Key       :", key)
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)


# ---------------------------------------------------------------------------
# Section 5: Vigenere family
# ---------------------------------------------------------------------------

def normalize_keyword(keyword: str) -> str:
    keyword = letters_only_ascii(keyword)
    if not keyword:
        raise ValueError("The keyword must contain at least one A-Z letter.")
    return keyword


def vigenere_encrypt(text: str, keyword: str) -> str:
    """
    Vigenere encryption:

        C_i = (P_i + K_i) mod 26

    The key repeats over alphabetic characters.
    """
    keyword = normalize_keyword(keyword)
    key_numbers = [letter_to_number(c) for c in keyword]

    result = []
    key_index = 0

    for character in text:
        if character.upper() in ALPHABET:
            plaintext_number = letter_to_number(character)
            key_number = key_numbers[key_index % len(key_numbers)]
            encrypted = number_to_letter(plaintext_number + key_number)

            result.append(encrypted if character.isupper() else encrypted.lower())
            key_index += 1
        else:
            result.append(character)

    return "".join(result)


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    """Reverse Vigenere encryption."""
    keyword = normalize_keyword(keyword)
    key_numbers = [letter_to_number(c) for c in keyword]

    result = []
    key_index = 0

    for character in ciphertext:
        if character.upper() in ALPHABET:
            ciphertext_number = letter_to_number(character)
            key_number = key_numbers[key_index % len(key_numbers)]
            decrypted = number_to_letter(ciphertext_number - key_number)

            result.append(decrypted if character.isupper() else decrypted.lower())
            key_index += 1
        else:
            result.append(character)

    return "".join(result)


def beaufort_transform(text: str, keyword: str, variant: str = "beaufort") -> str:
    """
    Demonstrate two closely related reciprocal/polyalphabetic transformations.

    Standard Beaufort:
        C = K - P

    Variant Beaufort:
        C = P - K
    """
    keyword = normalize_keyword(keyword)
    key_numbers = [letter_to_number(c) for c in keyword]

    if variant not in {"beaufort", "variant"}:
        raise ValueError("variant must be 'beaufort' or 'variant'.")

    result = []
    key_index = 0

    for character in text:
        if character.upper() in ALPHABET:
            p = letter_to_number(character)
            k = key_numbers[key_index % len(key_numbers)]

            if variant == "beaufort":
                value = k - p
            else:
                value = p - k

            replacement = number_to_letter(value)
            result.append(replacement if character.isupper() else replacement.lower())
            key_index += 1
        else:
            result.append(character)

    return "".join(result)


def autokey_encrypt(text: str, primer: str) -> str:
    """
    Autokey cipher.

    The initial primer is followed by plaintext letters, so the key stream
    does not repeat periodically in the same way as Vigenere.
    """
    primer = normalize_keyword(primer)
    plaintext = letters_only_ascii(text)

    key_stream = [
        letter_to_number(c)
        for c in (primer + plaintext)
    ]

    encrypted = []
    for index, character in enumerate(plaintext):
        value = letter_to_number(character) + key_stream[index]
        encrypted.append(number_to_letter(value))

    return "".join(encrypted)


def autokey_decrypt(ciphertext: str, primer: str) -> str:
    """Decrypt the plaintext-autokey construction."""
    primer = normalize_keyword(primer)
    ciphertext = letters_only_ascii(ciphertext)

    recovered = []
    key_stream = [letter_to_number(c) for c in primer]

    for index, character in enumerate(ciphertext):
        if index >= len(key_stream):
            key_stream.append(letter_to_number(recovered[index - len(primer)]))

        value = letter_to_number(character) - key_stream[index]
        plaintext_character = number_to_letter(value)
        recovered.append(plaintext_character)

        if len(key_stream) < len(ciphertext):
            key_stream.append(letter_to_number(plaintext_character))

    return "".join(recovered)


def demonstrate_polyalphabetic_ciphers() -> None:
    print("\n=== Vigenere and Related Ciphers ===")

    plaintext = "THE EAGLE HAS LANDED"
    keyword = "LEMON"

    encrypted = vigenere_encrypt(plaintext, keyword)
    decrypted = vigenere_decrypt(encrypted, keyword)

    print("Vigenere plaintext :", plaintext)
    print("Vigenere ciphertext:", encrypted)
    print("Vigenere recovered :", decrypted)

    beaufort = beaufort_transform(plaintext, keyword)
    print("Beaufort           :", beaufort)

    variant = beaufort_transform(plaintext, keyword, variant="variant")
    print("Variant Beaufort   :", variant)

    autokey_cipher = autokey_encrypt(plaintext, "QUEEN")
    autokey_plaintext = autokey_decrypt(autokey_cipher, "QUEEN")

    print("Autokey ciphertext :", autokey_cipher)
    print("Autokey recovered  :", autokey_plaintext)


# ---------------------------------------------------------------------------
# Section 6: Playfair cipher
# ---------------------------------------------------------------------------

def build_playfair_square(keyword: str) -> List[List[str]]:
    """
    Build a 5x5 Playfair square.

    Traditional Playfair merges I and J.
    """
    keyword = letters_only_ascii(keyword).replace("J", "I")

    sequence = []
    for character in keyword + ALPHABET:
        character = "I" if character == "J" else character
        if character not in sequence and character != "J":
            sequence.append(character)

    return [sequence[index:index + 5] for index in range(0, 25, 5)]


def playfair_positions(square: List[List[str]]) -> dict[str, Tuple[int, int]]:
    return {
        square[row][column]: (row, column)
        for row in range(5)
        for column in range(5)
    }


def prepare_playfair_plaintext(text: str) -> str:
    """
    Split plaintext into digraphs.

    Repeated letters in a pair are separated by X.
    An odd final character receives X.
    """
    letters = letters_only_ascii(text).replace("J", "I")
    prepared = []
    index = 0

    while index < len(letters):
        first = letters[index]

        if index + 1 >= len(letters):
            prepared.extend([first, "X"])
            index += 1
            continue

        second = letters[index + 1]

        if first == second:
            prepared.extend([first, "X"])
            index += 1
        else:
            prepared.extend([first, second])
            index += 2

    return "".join(prepared)


def playfair_transform_pair(
    first: str,
    second: str,
    square: List[List[str]],
    encrypting: bool,
) -> Tuple[str, str]:
    positions = playfair_positions(square)

    row1, col1 = positions[first]
    row2, col2 = positions[second]

    direction = 1 if encrypting else -1

    if row1 == row2:
        return (
            square[row1][(col1 + direction) % 5],
            square[row2][(col2 + direction) % 5],
        )

    if col1 == col2:
        return (
            square[(row1 + direction) % 5][col1],
            square[(row2 + direction) % 5][col2],
        )

    return square[row1][col2], square[row2][col1]


def playfair_encrypt(text: str, keyword: str) -> str:
    square = build_playfair_square(keyword)
    prepared = prepare_playfair_plaintext(text)

    result = []
    for index in range(0, len(prepared), 2):
        pair = playfair_transform_pair(
            prepared[index],
            prepared[index + 1],
            square,
            encrypting=True,
        )
        result.extend(pair)

    return "".join(result)


def playfair_decrypt(ciphertext: str, keyword: str) -> str:
    square = build_playfair_square(keyword)
    ciphertext = letters_only_ascii(ciphertext).replace("J", "I")

    if len(ciphertext) % 2 != 0:
        raise ValueError("Playfair ciphertext must have an even number of letters.")

    result = []
    for index in range(0, len(ciphertext), 2):
        pair = playfair_transform_pair(
            ciphertext[index],
            ciphertext[index + 1],
            square,
            encrypting=False,
        )
        result.extend(pair)

    return "".join(result)


def print_square(square: List[List[str]]) -> None:
    for row in square:
        print(" ".join(row))


def demonstrate_playfair() -> None:
    print("\n=== Playfair Cipher ===")

    square = build_playfair_square("MONARCHY")
    print("Playfair square:")
    print_square(square)

    plaintext = "INSTRUMENTS"
    ciphertext = playfair_encrypt(plaintext, "MONARCHY")
    recovered = playfair_decrypt(ciphertext, "MONARCHY")

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)
    print("Note: removing padding X characters can require contextual judgment.")


# ---------------------------------------------------------------------------
# Section 7: Hill cipher
# ---------------------------------------------------------------------------

Matrix = List[List[int]]


def matrix_determinant_2x2(matrix: Matrix) -> int:
    if len(matrix) != 2 or any(len(row) != 2 for row in matrix):
        raise ValueError("Expected a 2x2 matrix.")
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]


def inverse_matrix_mod_26_2x2(matrix: Matrix) -> Matrix:
    """
    Invert a 2x2 Hill-cipher matrix modulo 26.

    For [[a,b],[c,d]], the inverse is:
        det^-1 * [[d,-b],[-c,a]] mod 26
    """
    determinant = matrix_determinant_2x2(matrix)
    inverse_determinant = modular_inverse(determinant, 26)

    return [
        [
            (inverse_determinant * matrix[1][1]) % 26,
            (-inverse_determinant * matrix[0][1]) % 26,
        ],
        [
            (-inverse_determinant * matrix[1][0]) % 26,
            (inverse_determinant * matrix[0][0]) % 26,
        ],
    ]


def matrix_vector_mod_26(matrix: Matrix, vector: Sequence[int]) -> List[int]:
    return [
        sum(matrix[row][column] * vector[column] for column in range(len(vector))) % 26
        for row in range(len(matrix))
    ]


def hill_encrypt(text: str, key_matrix: Matrix) -> str:
    """Educational 2x2 Hill cipher."""
    if len(key_matrix) != 2 or any(len(row) != 2 for row in key_matrix):
        raise ValueError("This implementation requires a 2x2 key matrix.")

    letters = letters_only_ascii(text)
    if len(letters) % 2 != 0:
        letters += "X"

    result = []

    for index in range(0, len(letters), 2):
        vector = [
            letter_to_number(letters[index]),
            letter_to_number(letters[index + 1]),
        ]
        encrypted = matrix_vector_mod_26(key_matrix, vector)
        result.extend(number_to_letter(value) for value in encrypted)

    return "".join(result)


def hill_decrypt(ciphertext: str, key_matrix: Matrix) -> str:
    inverse = inverse_matrix_mod_26_2x2(key_matrix)
    ciphertext = letters_only_ascii(ciphertext)

    if len(ciphertext) % 2 != 0:
        raise ValueError("Hill ciphertext must contain an even number of letters.")

    result = []

    for index in range(0, len(ciphertext), 2):
        vector = [
            letter_to_number(ciphertext[index]),
            letter_to_number(ciphertext[index + 1]),
        ]
        decrypted = matrix_vector_mod_26(inverse, vector)
        result.extend(number_to_letter(value) for value in decrypted)

    return "".join(result)


def demonstrate_hill() -> None:
    print("\n=== Hill Cipher ===")

    key_matrix = [
        [3, 3],
        [2, 5],
    ]

    plaintext = "HELP"
    ciphertext = hill_encrypt(plaintext, key_matrix)
    recovered = hill_decrypt(ciphertext, key_matrix)

    print("Key matrix:")
    for row in key_matrix:
        print(row)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    determinant = matrix_determinant_2x2(key_matrix)
    print("Determinant:", determinant)
    print("gcd(det, 26):", math.gcd(determinant, 26))


# ---------------------------------------------------------------------------
# Section 8: Columnar transposition
# ---------------------------------------------------------------------------

def column_order(keyword: str) -> List[int]:
    """
    Return column indices in alphabetical key order.

    Ties are resolved by original position, making the ordering deterministic.
    """
    keyword = letters_only_ascii(keyword)
    if not keyword:
        raise ValueError("Columnar transposition keyword cannot be empty.")

    return [
        index
        for index, _ in sorted(
            enumerate(keyword),
            key=lambda item: (item[1], item[0]),
        )
    ]


def columnar_encrypt(text: str, keyword: str, padding: str = "X") -> str:
    keyword = letters_only_ascii(keyword)
    if not keyword:
        raise ValueError("Keyword cannot be empty.")

    plaintext = letters_only_ascii(text)
    columns = len(keyword)

    if padding and len(plaintext) % columns:
        plaintext += padding * (columns - len(plaintext) % columns)

    rows = [
        plaintext[index:index + columns]
        for index in range(0, len(plaintext), columns)
    ]

    order = column_order(keyword)

    return "".join(
        row[column]
        for column in order
        for row in rows
    )


def columnar_decrypt(
    ciphertext: str,
    keyword: str,
    padding: Optional[str] = "X",
) -> str:
    keyword = letters_only_ascii(keyword)
    ciphertext = letters_only_ascii(ciphertext)

    if not keyword:
        raise ValueError("Keyword cannot be empty.")

    columns = len(keyword)
    if len(ciphertext) % columns != 0:
        raise ValueError(
            "This simple rectangular implementation requires ciphertext "
            "length to be divisible by the number of columns."
        )

    rows_count = len(ciphertext) // columns
    order = column_order(keyword)
    grid = [[""] * columns for _ in range(rows_count)]

    position = 0

    for column in order:
        for row in range(rows_count):
            grid[row][column] = ciphertext[position]
            position += 1

    plaintext = "".join("".join(row) for row in grid)

    if padding:
        plaintext = plaintext.rstrip(padding)

    return plaintext


def demonstrate_transposition() -> None:
    print("\n=== Columnar Transposition ===")

    plaintext = "WE ARE DISCOVERED"
    keyword = "ZEBRA"

    ciphertext = columnar_encrypt(plaintext, keyword)
    recovered = columnar_decrypt(ciphertext, keyword)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)


# ---------------------------------------------------------------------------
# Section 9: One-time pad
# ---------------------------------------------------------------------------

def generate_random_key(length: int, rng: Optional[random.Random] = None) -> str:
    """
    Generate an educational random A-Z key.

    For a true one-time pad, the key must be:
    1. uniformly random,
    2. at least as long as the message,
    3. secret,
    4. used only once.
    """
    if length < 0:
        raise ValueError("Length cannot be negative.")

    rng = rng or random.SystemRandom()
    return "".join(rng.choice(ALPHABET) for _ in range(length))


def otp_encrypt(text: str, key: str) -> str:
    plaintext = letters_only_ascii(text)
    key = letters_only_ascii(key)

    if len(plaintext) != len(key):
        raise ValueError("One-time-pad key length must equal plaintext length.")

    return "".join(
        number_to_letter(
            letter_to_number(p) + letter_to_number(k)
        )
        for p, k in zip(plaintext, key)
    )


def otp_decrypt(ciphertext: str, key: str) -> str:
    ciphertext = letters_only_ascii(ciphertext)
    key = letters_only_ascii(key)

    if len(ciphertext) != len(key):
        raise ValueError("One-time-pad key length must equal ciphertext length.")

    return "".join(
        number_to_letter(
            letter_to_number(c) - letter_to_number(k)
        )
        for c, k in zip(ciphertext, key)
    )


def demonstrate_otp() -> None:
    print("\n=== One-Time Pad ===")

    plaintext = "MEET"
    key = "XMCK"

    ciphertext = otp_encrypt(plaintext, key)
    recovered = otp_decrypt(ciphertext, key)

    print("Plaintext :", plaintext)
    print("Key       :", key)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    print(
        "Security condition: a theoretical OTP requires a truly random, "
        "secret, non-reused key as long as the message."
    )


# ---------------------------------------------------------------------------
# Section 10: Frequency analysis
# ---------------------------------------------------------------------------

ENGLISH_FREQUENCIES = {
    "E": 12.70,
    "T": 9.06,
    "A": 8.17,
    "O": 7.51,
    "I": 6.97,
    "N": 6.75,
    "S": 6.33,
    "H": 6.09,
    "R": 5.99,
    "D": 4.25,
    "L": 4.03,
    "C": 2.78,
    "U": 2.76,
    "M": 2.41,
    "W": 2.36,
    "F": 2.23,
    "G": 2.02,
    "Y": 1.97,
    "P": 1.93,
    "B": 1.49,
    "V": 0.98,
    "K": 0.77,
    "J": 0.15,
    "X": 0.15,
    "Q": 0.10,
    "Z": 0.07,
}


def frequency_table(text: str) -> List[Tuple[str, int, float]]:
    letters = letters_only_ascii(text)
    counts = Counter(letters)
    total = len(letters)

    if total == 0:
        return []

    return sorted(
        [
            (letter, counts.get(letter, 0), counts.get(letter, 0) / total * 100)
            for letter in ALPHABET
        ],
        key=lambda row: (-row[1], row[0]),
    )


def index_of_coincidence(text: str) -> float:
    """
    IC = sum(f_i(f_i - 1)) / (N(N - 1))

    It measures how likely two randomly selected letters are identical.
    """
    letters = letters_only_ascii(text)
    n = len(letters)

    if n < 2:
        return 0.0

    counts = Counter(letters)

    numerator = sum(
        count * (count - 1)
        for count in counts.values()
    )

    return numerator / (n * (n - 1))


def chi_squared_score(text: str) -> float:
    """
    Compare observed letter counts to expected English frequencies.

    Lower scores indicate a closer match to the reference distribution.
    This is a statistical heuristic, not a proof of English plaintext.
    """
    letters = letters_only_ascii(text)
    total = len(letters)

    if total == 0:
        return float("inf")

    counts = Counter(letters)
    score = 0.0

    for letter in ALPHABET:
        expected = total * ENGLISH_FREQUENCIES[letter] / 100
        observed = counts.get(letter, 0)

        if expected > 0:
            score += (observed - expected) ** 2 / expected

    return score


def demonstrate_frequency_analysis() -> None:
    print("\n=== Frequency Analysis ===")

    text = (
        "THIS IS A LONGER ENGLISH SAMPLE TEXT THAT CONTAINS "
        "COMMON LETTERS AND REPEATED WORD PATTERNS"
    )

    print("Letter  Count  Percentage")
    for letter, count, percentage in frequency_table(text)[:10]:
        print(f"{letter:>6} {count:>6} {percentage:>10.2f}%")

    print("Index of coincidence:", f"{index_of_coincidence(text):.4f}")
    print("Chi-squared score   :", f"{chi_squared_score(text):.2f}")


# ---------------------------------------------------------------------------
# Section 11: Caesar cryptanalysis
# ---------------------------------------------------------------------------

def crack_caesar(ciphertext: str) -> List[Tuple[int, str, float]]:
    """
    Try all 26 Caesar shifts and rank them by chi-squared score.
    """
    candidates = []

    for shift in range(26):
        plaintext = caesar_decrypt(ciphertext, shift)
        score = chi_squared_score(plaintext)
        candidates.append((shift, plaintext, score))

    return sorted(candidates, key=lambda item: item[2])


def demonstrate_caesar_cracking() -> None:
    print("\n=== Caesar Cryptanalysis ===")

    plaintext = (
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
        "AND THEN RETURNS TO THE QUIET FOREST"
    )
    ciphertext = caesar_encrypt(plaintext, 7)

    print("Ciphertext:", ciphertext)
    print("\nBest candidates:")

    for shift, candidate, score in crack_caesar(ciphertext)[:5]:
        print(f"shift={shift:2d}, score={score:8.2f}, text={candidate}")


# ---------------------------------------------------------------------------
# Section 12: Vigenere cryptanalysis
# ---------------------------------------------------------------------------

def repeated_ngram_distances(
    ciphertext: str,
    ngram_length: int = 3,
) -> List[int]:
    """
    Find distances between repeated n-grams.

    Repeated patterns can reveal factors related to a periodic key length.
    This is the basis of the Kasiski examination.
    """
    ciphertext = letters_only_ascii(ciphertext)
    locations: dict[str, List[int]] = {}

    for index in range(len(ciphertext) - ngram_length + 1):
        ngram = ciphertext[index:index + ngram_length]
        locations.setdefault(ngram, []).append(index)

    distances = []

    for positions in locations.values():
        if len(positions) > 1:
            for first, second in zip(positions, positions[1:]):
                distances.append(second - first)

    return distances


def kasiski_factors(
    ciphertext: str,
    ngram_length: int = 3,
) -> Counter[int]:
    """Count possible key-length factors from repeated n-gram distances."""
    distances = repeated_ngram_distances(ciphertext, ngram_length)
    factors = Counter()

    for distance in distances:
        for divisor in range(2, min(distance, 20) + 1):
            if distance % divisor == 0:
                factors[divisor] += 1

    return factors


def average_column_ic(ciphertext: str, key_length: int) -> float:
    """
    Split ciphertext into columns corresponding to key positions and
    calculate the average IC.
    """
    letters = letters_only_ascii(ciphertext)

    if key_length <= 0:
        raise ValueError("Key length must be positive.")

    columns = [
        letters[offset::key_length]
        for offset in range(key_length)
    ]

    non_empty = [index_of_coincidence(column) for column in columns if column]
    return sum(non_empty) / len(non_empty) if non_empty else 0.0


def rank_vigenere_key_lengths(
    ciphertext: str,
    maximum_length: int = 12,
) -> List[Tuple[int, float]]:
    """
    Rank key lengths by average IC.

    This is only a heuristic. Short texts and unusual plaintexts can make
    IC-based key-length estimation unreliable.
    """
    return sorted(
        [
            (length, average_column_ic(ciphertext, length))
            for length in range(1, maximum_length + 1)
        ],
        key=lambda item: item[1],
        reverse=True,
    )


def best_caesar_shift_for_text(text: str) -> int:
    """Find the Caesar shift giving the lowest chi-squared score."""
    return min(
        range(26),
        key=lambda shift: chi_squared_score(caesar_decrypt(text, shift)),
    )


def estimate_vigenere_key(ciphertext: str, key_length: int) -> str:
    """
    Estimate a Vigenere key by treating each key-position column as a
    Caesar cipher and selecting its best statistical shift.
    """
    letters = letters_only_ascii(ciphertext)
    key = []

    for offset in range(key_length):
        column = letters[offset::key_length]
        shift = best_caesar_shift_for_text(column)
        key.append(number_to_letter(shift))

    return "".join(key)


def demonstrate_vigenere_analysis() -> None:
    print("\n=== Vigenere Cryptanalysis Heuristics ===")

    plaintext = (
        "THE HISTORY OF CLASSICAL CRYPTOGRAPHY CONTAINS MANY "
        "EXAMPLES OF CIPHERS THAT WERE ONCE CONSIDERED DIFFICULT "
        "BUT BECAME VULNERABLE WHEN THEIR STRUCTURAL PATTERNS "
        "WERE UNDERSTOOD BY CRYPTANALYSTS"
    )

    keyword = "LEMON"
    ciphertext = vigenere_encrypt(plaintext, keyword)

    print("Ciphertext:", letters_only_ascii(ciphertext))

    print("\nRepeated trigram distances:")
    distances = repeated_ngram_distances(ciphertext)
    print(distances[:20])

    print("\nFrequent Kasiski factors:")
    print(kasiski_factors(ciphertext).most_common(8))

    print("\nCandidate key lengths by average IC:")
    print(rank_vigenere_key_lengths(ciphertext, 10))

    estimated = estimate_vigenere_key(ciphertext, len(keyword))
    print("Estimated key:", estimated)


# ---------------------------------------------------------------------------
# Section 13: Information-theoretic observations
# ---------------------------------------------------------------------------

def entropy_bits_per_character(text: str) -> float:
    """
    Shannon entropy of the observed letter distribution.

    H = -sum(p_i log2(p_i))
    """
    letters = letters_only_ascii(text)

    if not letters:
        return 0.0

    counts = Counter(letters)
    total = len(letters)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def demonstrate_entropy() -> None:
    print("\n=== Letter Distribution and Entropy ===")

    repetitive = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    varied = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"

    print("Repetitive sample entropy:", f"{entropy_bits_per_character(repetitive):.4f}")
    print("Varied sample entropy    :", f"{entropy_bits_per_character(varied):.4f}")
    print(
        "Classical substitution ciphers preserve letter-frequency structure "
        "because they replace symbols deterministically."
    )


# ---------------------------------------------------------------------------
# Section 14: Common mistakes and validation examples
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    print("\n=== Edge Cases and Validation ===")

    cases = [
        ("Caesar with negative shift", caesar_encrypt("ABC", -3)),
        ("Caesar with large shift", caesar_encrypt("ABC", 55)),
        ("Empty Caesar text", repr(caesar_encrypt("", 4))),
        ("Punctuation preserved", caesar_encrypt("Hello, World!", 13)),
        ("Vigenere mixed formatting", vigenere_encrypt("Attack at 9 PM!", "KEY")),
    ]

    for label, value in cases:
        print(f"{label}: {value}")

    print("\nInvalid affine multiplier demonstration:")
    try:
        affine_encrypt("HELLO", 13, 5)
    except ValueError as error:
        print("Caught:", error)

    print("\nInvalid OTP key length demonstration:")
    try:
        otp_encrypt("HELLO", "KEY")
    except ValueError as error:
        print("Caught:", error)

    print("\nInvalid substitution key demonstration:")
    try:
        substitution_encrypt("HELLO", "AAAAAAAAAAAAAAAAAAAAAAAAAA")
    except ValueError as error:
        print("Caught:", error)


# ---------------------------------------------------------------------------
# Section 15: Comparative experiment
# ---------------------------------------------------------------------------

def compare_ciphertext_patterns() -> None:
    print("\n=== Pattern Comparison ===")

    plaintext = (
        "ATTACK AT DAWN ATTACK AT DAWN ATTACK AT DAWN "
        "ATTACK AT DAWN"
    )

    caesar = caesar_encrypt(plaintext, 3)
    vigenere = vigenere_encrypt(plaintext, "LEMON")
    transposition = columnar_encrypt(plaintext, "ZEBRA")

    print("Plaintext:")
    print(plaintext)

    print("\nCaesar:")
    print(caesar)

    print("\nVigenere:")
    print(vigenere)

    print("\nColumnar transposition:")
    print(transposition)

    print(
        "\nObservation: Caesar preserves exact equality of repeated plaintext "
        "letters, monoalphabetic substitution preserves equality patterns, "
        "while a transposition changes positions without changing symbols."
    )


# ---------------------------------------------------------------------------
# Section 16: Automated tests
# ---------------------------------------------------------------------------

def run_round_trip_tests() -> None:
    print("\n=== Automated Round-Trip Tests ===")

    caesar_plaintext = "Hello, Classical Cryptography!"
    for shift in [-100, -3, 0, 3, 100]:
        encrypted = caesar_encrypt(caesar_plaintext, shift)
        decrypted = caesar_decrypt(encrypted, shift)
        assert decrypted == caesar_plaintext

    affine_plaintext = "Affine ciphers use modular arithmetic."
    encrypted = affine_encrypt(affine_plaintext, 5, 8)
    decrypted = affine_decrypt(encrypted, 5, 8)
    assert decrypted == affine_plaintext

    substitution_plaintext = "Substitution"
    substitution_key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    encrypted = substitution_encrypt(substitution_plaintext, substitution_key)
    decrypted = substitution_decrypt(encrypted, substitution_key)
    assert decrypted == substitution_plaintext

    vigenere_plaintext = "Attack at dawn with the entire fleet."
    encrypted = vigenere_encrypt(vigenere_plaintext, "LEMON")
    decrypted = vigenere_decrypt(encrypted, "LEMON")
    assert decrypted == vigenere_plaintext

    autokey_plaintext = "MEETMEATTHESTATION"
    encrypted = autokey_encrypt(autokey_plaintext, "QUEEN")
    decrypted = autokey_decrypt(encrypted, "QUEEN")
    assert decrypted == autokey_plaintext

    playfair_plaintext = "HIDETHEGOLD"
    encrypted = playfair_encrypt(playfair_plaintext, "MONARCHY")
    decrypted = playfair_decrypt(encrypted, "MONARCHY")
    assert decrypted.startswith("HIDETHEGOLD")

    hill_plaintext = "HELP"
    hill_key = [[3, 3], [2, 5]]
    encrypted = hill_encrypt(hill_plaintext, hill_key)
    decrypted = hill_decrypt(encrypted, hill_key)
    assert decrypted == hill_plaintext

    transposition_plaintext = "WEAREDISCOVERED"
    encrypted = columnar_encrypt(transposition_plaintext, "ZEBRA")
    decrypted = columnar_decrypt(encrypted, "ZEBRA")
    assert decrypted == transposition_plaintext

    otp_plaintext = "SECRETMESSAGE"
    otp_key = "XMCKLQWERTYUI"
    encrypted = otp_encrypt(otp_plaintext, otp_key)
    decrypted = otp_decrypt(encrypted, otp_key)
    assert decrypted == otp_plaintext

    print("All round-trip tests passed.")


# ---------------------------------------------------------------------------
# Section 17: Educational attack comparison
# ---------------------------------------------------------------------------

def attack_surface_demo() -> None:
    print("\n=== Attack Surface Comparison ===")

    examples = [
        (
            "Caesar",
            "Only 26 possible shifts; brute force is trivial.",
            "Small key space and preserved language statistics.",
        ),
        (
            "Monoalphabetic substitution",
            "Much larger key space than Caesar.",
            "Frequency analysis and language structure remain useful.",
        ),
        (
            "Vigenere",
            "Key length can hide simple frequency distributions.",
            "Periodic keys leak structure; Kasiski and IC can help.",
        ),
        (
            "Columnar transposition",
            "Letters themselves are not changed.",
            "Anagram/frequency and positional analysis can exploit structure.",
        ),
        (
            "One-time pad",
            "No cryptanalytic attack exists under its ideal assumptions.",
            "Key distribution, secrecy, randomness, and one-time use are difficult.",
        ),
    ]

    for name, weakness, lesson in examples:
        print(f"\n{name}")
        print("  Attack observation:", weakness)
        print("  Practical lesson   :", lesson)


# ---------------------------------------------------------------------------
# Section 18: Main educational sequence
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 78)
    print("CLASSICAL CRYPTOGRAPHY: COMPLETE PYTHON STUDY PROGRAM")
    print("=" * 78)

    print(
        "\nCore model:"
        "\n  plaintext -> encryption + key -> ciphertext"
        "\n  ciphertext -> decryption + key -> plaintext"
        "\n\nClassical cryptography mainly uses substitution, transposition, "
        "or combinations of both."
    )

    demonstrate_caesar()
    demonstrate_affine()
    demonstrate_substitution()
    demonstrate_polyalphabetic_ciphers()
    demonstrate_playfair()
    demonstrate_hill()
    demonstrate_transposition()
    demonstrate_otp()
    demonstrate_frequency_analysis()
    demonstrate_caesar_cracking()
    demonstrate_vigenere_analysis()
    demonstrate_entropy()
    demonstrate_edge_cases()
    compare_ciphertext_patterns()
    attack_surface_demo()
    run_round_trip_tests()

    print("\n" + "=" * 78)
    print("STUDY NOTES")
    print("=" * 78)
    print(
        "\n1. Caesar is a special case of substitution and modular arithmetic."
        "\n2. Affine combines multiplication and addition modulo 26."
        "\n3. Monoalphabetic substitution hides direct symbol identities but "
        "preserves frequency relationships."
        "\n4. Vigenere uses a repeating sequence of Caesar shifts."
        "\n5. Playfair encrypts letter pairs and therefore changes the unit of "
        "encryption from one character to a digraph."
        "\n6. Hill uses linear algebra over modular arithmetic."
        "\n7. Transposition rearranges positions without replacing symbols."
        "\n8. A theoretical one-time pad provides perfect secrecy only when "
        "its assumptions are satisfied."
        "\n9. Cryptanalysis studies information leaked by ciphertext and "
        "the structure of the cipher."
        "\n10. These historical algorithms are not substitutes for modern "
        "authenticated encryption."
    )


if __name__ == "__main__":
    main()
