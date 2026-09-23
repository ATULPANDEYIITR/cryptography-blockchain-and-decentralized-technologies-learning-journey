"""
TRANSPOSITION CIPHERS
=====================

A comprehensive standalone study and implementation file covering classical
transposition ciphers from beginner to advanced level.

The central idea of a transposition cipher is simple:

    plaintext characters are rearranged without changing the characters
    themselves.

This file demonstrates:
    - What transposition means
    - Permutations and positions
    - Rail Fence cipher
    - Columnar transposition
    - Keyed columnar transposition
    - Irregular final rows
    - Double transposition
    - Route transposition
    - Encryption/decryption validation
    - Cryptanalysis concepts
    - Frequency-preserving behavior
    - Edge cases
    - Performance considerations
    - Security limitations
    - A small educational attack demonstration
    - Automated tests

The implementations are intentionally self-contained and use only Python's
standard library.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import permutations
import math
import re
import string
from typing import Iterable, Optional


# ============================================================================
# 1. FUNDAMENTAL CONCEPTS
# ============================================================================

def explain_fundamentals() -> None:
    """Print the most important beginner-level ideas."""

    print("\n" + "=" * 78)
    print("1. FUNDAMENTAL CONCEPTS")
    print("=" * 78)

    print(
        """
A substitution cipher changes symbols into other symbols.

A transposition cipher does not change the symbols. It changes their
positions.

Example:

    Plaintext:  ATTACKATDAWN
    Rearranged: TTAACAKNDWTA

Both strings contain exactly the same characters.

This means that a transposition cipher preserves:

    - character frequencies
    - the number of characters
    - the character alphabet

but changes:

    - character positions
    - adjacent character relationships
    - readable word boundaries

Mathematically, a transposition cipher can be viewed as a permutation.

If the plaintext is:

    P = p0 p1 p2 ... pn-1

encryption applies a permutation:

    E(P) = p[k0] p[k1] ... p[kn-1]

Decryption applies the inverse permutation.

The inverse-permutation idea is one of the most important concepts in
understanding why transposition encryption can be reversed exactly.
"""
    )


def normalize_text(
    text: str,
    *,
    keep_spaces: bool = False,
    keep_punctuation: bool = False,
) -> str:
    """
    Normalize text for classical cipher demonstrations.

    By default, only A-Z characters are retained.

    Keeping spaces/punctuation is useful for demonstrations but generally
    makes classical cipher analysis less uniform.
    """
    result = []

    for character in text.upper():
        if character.isalpha():
            result.append(character)
        elif keep_spaces and character == " ":
            result.append(character)
        elif keep_punctuation and character in string.punctuation:
            result.append(character)

    return "".join(result)


def same_multiset(left: str, right: str) -> bool:
    """Return True if both strings contain the same characters."""
    return Counter(left) == Counter(right)


# ============================================================================
# 2. PERMUTATIONS
# ============================================================================

def demonstrate_permutation() -> None:
    """Show how a simple positional permutation works."""

    print("\n" + "=" * 78)
    print("2. PERMUTATIONS")
    print("=" * 78)

    plaintext = "ABCDEFGH"
    permutation = [2, 0, 6, 4, 1, 7, 3, 5]

    ciphertext = "".join(plaintext[index] for index in permutation)

    inverse = [0] * len(permutation)
    for encrypted_position, original_position in enumerate(permutation):
        inverse[original_position] = encrypted_position

    recovered = [""] * len(ciphertext)
    for original_position, encrypted_position in enumerate(inverse):
        recovered[original_position] = ciphertext[encrypted_position]

    print("Plaintext:              ", plaintext)
    print("Permutation:            ", permutation)
    print("Ciphertext:             ", ciphertext)
    print("Inverse permutation:    ", inverse)
    print("Recovered plaintext:    ", "".join(recovered))


# ============================================================================
# 3. RAIL FENCE CIPHER
# ============================================================================

def rail_fence_encrypt(text: str, rails: int) -> str:
    """
    Encrypt using the Rail Fence transposition cipher.

    The characters are written diagonally across a fixed number of rails and
    then read row by row.

    Example for 3 rails:

        W . . . E . . . C
        . E . R . T . R .
        . . A . . . A . .

    The exact pattern depends on the message length.
    """
    if rails < 1:
        raise ValueError("Number of rails must be at least 1.")

    if rails == 1 or len(text) <= 1:
        return text

    if rails >= len(text):
        return text

    rows = [[] for _ in range(rails)]
    row = 0
    direction = 1

    for character in text:
        rows[row].append(character)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    return "".join("".join(current_row) for current_row in rows)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    """
    Reverse the Rail Fence cipher.

    Decryption first reconstructs the zig-zag path, determines how many
    characters belong to each rail, fills those rails, and then follows the
    zig-zag path to recover the original message.
    """
    if rails < 1:
        raise ValueError("Number of rails must be at least 1.")

    if rails == 1 or len(ciphertext) <= 1:
        return ciphertext

    if rails >= len(ciphertext):
        return ciphertext

    path = []
    row = 0
    direction = 1

    for _ in ciphertext:
        path.append(row)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    counts = Counter(path)

    rail_contents = []
    position = 0

    for rail in range(rails):
        count = counts[rail]
        rail_contents.append(list(ciphertext[position:position + count]))
        position += count

    rail_offsets = [0] * rails
    plaintext = []

    for current_rail in path:
        plaintext.append(
            rail_contents[current_rail][rail_offsets[current_rail]]
        )
        rail_offsets[current_rail] += 1

    return "".join(plaintext)


def show_rail_fence_pattern(text: str, rails: int) -> None:
    """Display the positions used by a Rail Fence cipher."""
    if rails < 2:
        print(text)
        return

    if not text:
        print("(empty)")
        return

    positions = []
    row = 0
    direction = 1

    for _ in text:
        positions.append(row)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    matrix = [[" " for _ in text] for _ in range(rails)]

    for column, current_row in enumerate(positions):
        matrix[current_row][column] = text[column]

    for line in matrix:
        print(" ".join(line))


# ============================================================================
# 4. COLUMNAR TRANSPOSITION
# ============================================================================

def columnar_encrypt(
    plaintext: str,
    columns: int,
    padding: Optional[str] = None,
) -> str:
    """
    Encrypt using ordinary columnar transposition.

    Plaintext is written left-to-right in rows and then read top-to-bottom
    by columns.

    If padding is None, the final row may be incomplete.
    If padding is provided, it must be a single character.
    """
    if columns < 1:
        raise ValueError("Number of columns must be at least 1.")

    if padding is not None and len(padding) != 1:
        raise ValueError("Padding must be exactly one character.")

    if not plaintext:
        return ""

    rows = math.ceil(len(plaintext) / columns)

    working = plaintext
    if padding is not None:
        required = rows * columns - len(working)
        working += padding * required

    ciphertext = []

    for column in range(columns):
        for position in range(column, len(working), columns):
            ciphertext.append(working[position])

    return "".join(ciphertext)


def columnar_decrypt(
    ciphertext: str,
    columns: int,
    padding: Optional[str] = None,
) -> str:
    """
    Decrypt an ordinary columnar transposition.

    For an unpadded message, the last row is incomplete. Columns on the left
    therefore contain one more character than columns on the right when the
    message length is not divisible by the number of columns.
    """
    if columns < 1:
        raise ValueError("Number of columns must be at least 1.")

    if padding is not None and len(padding) != 1:
        raise ValueError("Padding must be exactly one character.")

    if not ciphertext:
        return ""

    length = len(ciphertext)
    rows = math.ceil(length / columns)
    remainder = length % columns

    column_lengths = []
    for column in range(columns):
        if remainder == 0:
            column_lengths.append(rows)
        elif column < remainder:
            column_lengths.append(rows)
        else:
            column_lengths.append(rows - 1)

    columns_data = []
    offset = 0

    for column_length in column_lengths:
        columns_data.append(
            list(ciphertext[offset:offset + column_length])
        )
        offset += column_length

    plaintext = []

    for row in range(rows):
        for column in range(columns):
            if row < len(columns_data[column]):
                plaintext.append(columns_data[column][row])

    result = "".join(plaintext)

    if padding is not None:
        result = result.rstrip(padding)

    return result


def display_column_grid(text: str, columns: int) -> None:
    """Display plaintext in the rectangular writing grid."""
    if columns < 1:
        raise ValueError("Columns must be at least 1.")

    print("\nGrid:")
    for start in range(0, len(text), columns):
        print(" ".join(text[start:start + columns]))


# ============================================================================
# 5. KEYED COLUMNAR TRANSPOSITION
# ============================================================================

def key_order(key: str) -> list[int]:
    """
    Determine the read order of columns from a keyword.

    Ties are resolved by original column position, making duplicate letters
    deterministic.

    Example:

        KEY = ZEBRA

        alphabetical order:
        A, B, E, R, Z

        original indices:
        4, 2, 1, 3, 0
    """
    cleaned_key = normalize_text(key)

    if not cleaned_key:
        raise ValueError("Key must contain at least one alphabetic character.")

    return sorted(
        range(len(cleaned_key)),
        key=lambda index: (cleaned_key[index], index),
    )


def keyed_columnar_encrypt(
    plaintext: str,
    key: str,
    padding: Optional[str] = None,
) -> str:
    """
    Encrypt using a keyword-controlled column order.
    """
    plaintext = plaintext
    order = key_order(key)
    columns = len(order)

    if padding is not None and len(padding) != 1:
        raise ValueError("Padding must be exactly one character.")

    if not plaintext:
        return ""

    rows = math.ceil(len(plaintext) / columns)
    working = plaintext

    if padding is not None:
        working += padding * (rows * columns - len(working))

    ciphertext = []

    for column in order:
        for position in range(column, len(working), columns):
            ciphertext.append(working[position])

    return "".join(ciphertext)


def keyed_columnar_decrypt(
    ciphertext: str,
    key: str,
    padding: Optional[str] = None,
) -> str:
    """
    Decrypt keyed columnar transposition with an incomplete final row.
    """
    order = key_order(key)
    columns = len(order)

    if padding is not None and len(padding) != 1:
        raise ValueError("Padding must be exactly one character.")

    if not ciphertext:
        return ""

    length = len(ciphertext)
    rows = math.ceil(length / columns)
    remainder = length % columns

    column_lengths = {}
    for column in range(columns):
        if remainder == 0:
            column_lengths[column] = rows
        else:
            column_lengths[column] = rows if column < remainder else rows - 1

    column_data = {}
    offset = 0

    for column in order:
        count = column_lengths[column]
        column_data[column] = list(
            ciphertext[offset:offset + count]
        )
        offset += count

    plaintext = []

    for row in range(rows):
        for column in range(columns):
            values = column_data[column]
            if row < len(values):
                plaintext.append(values[row])

    result = "".join(plaintext)

    if padding is not None:
        result = result.rstrip(padding)

    return result


# ============================================================================
# 6. DOUBLE TRANSPOSITION
# ============================================================================

def double_columnar_encrypt(
    plaintext: str,
    first_key: str,
    second_key: str,
    padding: Optional[str] = None,
) -> str:
    """
    Apply two keyed columnar transpositions sequentially.

    Double transposition is historically important because composing two
    permutations produces another permutation, but the resulting permutation
    can be considerably less obvious than a single simple arrangement.
    """
    first_stage = keyed_columnar_encrypt(
        plaintext,
        first_key,
        padding=padding,
    )

    return keyed_columnar_encrypt(
        first_stage,
        second_key,
        padding=padding,
    )


def double_columnar_decrypt(
    ciphertext: str,
    first_key: str,
    second_key: str,
    padding: Optional[str] = None,
) -> str:
    """Reverse the second transposition first, then the first."""
    second_stage = keyed_columnar_decrypt(
        ciphertext,
        second_key,
        padding=padding,
    )

    return keyed_columnar_decrypt(
        second_stage,
        first_key,
        padding=padding,
    )


# ============================================================================
# 7. ROUTE TRANSPOSITION
# ============================================================================

def route_encrypt(
    plaintext: str,
    rows: int,
    columns: int,
    *,
    reverse_rows: bool = False,
    reverse_columns: bool = False,
) -> str:
    """
    A rectangular route transposition.

    Plaintext is placed into a matrix row-by-row. Ciphertext is extracted
    column-by-column. Optional direction changes provide additional route
    variants.
    """
    if rows < 1 or columns < 1:
        raise ValueError("Rows and columns must be positive.")

    capacity = rows * columns
    if len(plaintext) > capacity:
        raise ValueError(
            "Plaintext is longer than the matrix capacity."
        )

    matrix = [[None] * columns for _ in range(rows)]

    index = 0

    row_range = range(rows - 1, -1, -1) if reverse_rows else range(rows)

    for row in row_range:
        column_range = (
            range(columns - 1, -1, -1)
            if reverse_columns
            else range(columns)
        )

        for column in column_range:
            if index < len(plaintext):
                matrix[row][column] = plaintext[index]
                index += 1

    ciphertext = []

    for column in range(columns):
        for row in range(rows):
            value = matrix[row][column]
            if value is not None:
                ciphertext.append(value)

    return "".join(ciphertext)


def route_decrypt(
    ciphertext: str,
    rows: int,
    columns: int,
    *,
    reverse_rows: bool = False,
    reverse_columns: bool = False,
) -> str:
    """Reverse the route transposition."""
    if rows < 1 or columns < 1:
        raise ValueError("Rows and columns must be positive.")

    capacity = rows * columns

    if len(ciphertext) > capacity:
        raise ValueError(
            "Ciphertext is longer than the matrix capacity."
        )

    matrix = [[None] * columns for _ in range(rows)]

    index = 0

    for column in range(columns):
        for row in range(rows):
            if index < len(ciphertext):
                matrix[row][column] = ciphertext[index]
                index += 1

    plaintext = []

    row_range = range(rows - 1, -1, -1) if reverse_rows else range(rows)

    for row in row_range:
        column_range = (
            range(columns - 1, -1, -1)
            if reverse_columns
            else range(columns)
        )

        for column in column_range:
            value = matrix[row][column]
            if value is not None:
                plaintext.append(value)

    return "".join(plaintext)


# ============================================================================
# 8. PERMUTATION REPRESENTATION
# ============================================================================

def permutation_for_key(key: str, length: int) -> list[int]:
    """
    Build a positional permutation for a keyed columnar arrangement.

    This is useful for studying a transposition cipher as a mathematical
    permutation rather than as a grid operation.
    """
    order = key_order(key)
    columns = len(order)

    if length == 0:
        return []

    rows = math.ceil(length / columns)

    positions = []

    for column in order:
        for row in range(rows):
            position = row * columns + column
            if position < length:
                positions.append(position)

    return positions


def apply_permutation(text: str, permutation: list[int]) -> str:
    """Apply a positional permutation."""
    if len(text) != len(permutation):
        raise ValueError("Permutation length must equal text length.")

    if sorted(permutation) != list(range(len(text))):
        raise ValueError("Permutation must contain every position exactly once.")

    return "".join(text[index] for index in permutation)


def invert_permutation(permutation: list[int]) -> list[int]:
    """Return the inverse of a permutation."""
    inverse = [0] * len(permutation)

    for new_position, old_position in enumerate(permutation):
        inverse[old_position] = new_position

    return inverse


# ============================================================================
# 9. FREQUENCY ANALYSIS
# ============================================================================

ENGLISH_FREQUENCIES = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07,
}


def frequency_table(text: str) -> dict[str, int]:
    """Count alphabetic characters."""
    cleaned = normalize_text(text)
    return dict(sorted(Counter(cleaned).items()))


def chi_square_frequency_score(text: str) -> float:
    """
    Compare observed character counts with a basic English frequency model.

    Lower values indicate a closer match to the model.

    This is only a rough educational statistic. A transposition cipher does
    not change character frequencies, so frequency analysis cannot reveal
    the ordering by itself.
    """
    cleaned = normalize_text(text)

    if not cleaned:
        return float("inf")

    counts = Counter(cleaned)
    length = len(cleaned)

    score = 0.0

    for letter, expected_percentage in ENGLISH_FREQUENCIES.items():
        expected = length * expected_percentage / 100
        observed = counts.get(letter, 0)

        if expected > 0:
            score += ((observed - expected) ** 2) / expected

    return score


COMMON_ENGLISH_BIGRAMS = (
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT",
    "EN", "ND", "TI", "ES", "OR", "TE", "OF", "ED",
)

COMMON_ENGLISH_TRIGRAMS = (
    "THE", "AND", "ING", "HER", "ERE", "ENT", "THA",
    "NTH", "WAS", "ETH", "FOR", "DTH",
)


def ngram_score(text: str) -> int:
    """
    Very small educational language score.

    Real cryptanalysis commonly uses much larger statistical language models.
    """
    cleaned = normalize_text(text)

    score = 0

    for bigram in COMMON_ENGLISH_BIGRAMS:
        score += cleaned.count(bigram)

    for trigram in COMMON_ENGLISH_TRIGRAMS:
        score += 2 * cleaned.count(trigram)

    return score


# ============================================================================
# 10. SMALL COLUMN-COUNT CRYPTANALYSIS DEMONSTRATION
# ============================================================================

def crack_by_column_count(
    ciphertext: str,
    min_columns: int = 2,
    max_columns: int = 12,
) -> list[tuple[int, float, int, str]]:
    """
    Try several column counts for an unkeyed columnar transposition.

    The function cannot magically recover a key. It simply demonstrates one
    important cryptanalytic idea: hypothesize structural parameters, decrypt
    each candidate, and score the results.

    Returned tuples contain:

        (columns, chi_square_score, ngram_score, candidate_text)

    Candidates are sorted using the simple n-gram score first.
    """
    if not ciphertext:
        return []

    cleaned = normalize_text(ciphertext)

    candidates = []

    for columns in range(
        max(2, min_columns),
        min(max_columns, len(cleaned)) + 1,
    ):
        plaintext = columnar_decrypt(cleaned, columns)

        candidates.append(
            (
                columns,
                chi_square_frequency_score(plaintext),
                ngram_score(plaintext),
                plaintext,
            )
        )

    candidates.sort(
        key=lambda item: (-item[2], item[1])
    )

    return candidates


# ============================================================================
# 11. KEY SEARCH FOR A SMALL EDUCATIONAL EXAMPLE
# ============================================================================

def recover_small_keyed_columnar(
    ciphertext: str,
    key_letters: str,
    *,
    limit: Optional[int] = None,
) -> list[tuple[str, int, str]]:
    """
    Demonstrate brute-force permutation search for a very small key.

    This function treats the supplied key_letters as distinct labels and
    tries every possible column order.

    It is deliberately restricted to small inputs because factorial growth
    quickly becomes impractical:

        4 columns -> 24 permutations
        6 columns -> 720
        8 columns -> 40,320
        10 columns -> 3,628,800

    The search illustrates why key size and structural constraints matter.
    """
    cleaned_key = normalize_text(key_letters)

    if len(cleaned_key) < 2:
        raise ValueError("At least two key letters are required.")

    if len(cleaned_key) > 8:
        raise ValueError(
            "This educational brute-force function is limited to 8 columns."
        )

    columns = len(cleaned_key)
    results = []

    # Every permutation describes one possible column-read order.
    for count, order_tuple in enumerate(permutations(range(columns))):
        if limit is not None and count >= limit:
            break

        order = list(order_tuple)

        length = len(ciphertext)
        rows = math.ceil(length / columns)

        remainder = length % columns

        column_lengths = [
            rows if remainder == 0 or column < remainder else rows - 1
            for column in range(columns)
        ]

        data = {}
        offset = 0

        for column in order:
            size = column_lengths[column]
            data[column] = list(ciphertext[offset:offset + size])
            offset += size

        candidate = []

        for row in range(rows):
            for column in range(columns):
                if row < len(data[column]):
                    candidate.append(data[column][row])

        candidate_text = "".join(candidate)

        results.append(
            (
                str(order),
                ngram_score(candidate_text),
                candidate_text,
            )
        )

    results.sort(key=lambda item: item[1], reverse=True)
    return results


# ============================================================================
# 12. DATACLASS FOR A REUSABLE CIPHER MODEL
# ============================================================================

@dataclass
class TranspositionResult:
    """Store the result of an encryption/decryption operation."""

    algorithm: str
    input_text: str
    output_text: str
    reversible: bool
    metadata: dict[str, object]

    def display(self) -> None:
        print(f"\nAlgorithm: {self.algorithm}")
        print(f"Input:     {self.input_text}")
        print(f"Output:    {self.output_text}")
        print(f"Reversible: {self.reversible}")
        if self.metadata:
            print("Metadata:")
            for name, value in self.metadata.items():
                print(f"  {name}: {value}")


class TranspositionToolkit:
    """
    Small object-oriented wrapper around the core implementations.

    The class demonstrates how individual cipher functions can be organized
    into a reusable application-level interface.
    """

    @staticmethod
    def rail_fence(text: str, rails: int) -> TranspositionResult:
        ciphertext = rail_fence_encrypt(text, rails)
        recovered = rail_fence_decrypt(ciphertext, rails)

        return TranspositionResult(
            algorithm="Rail Fence",
            input_text=text,
            output_text=ciphertext,
            reversible=recovered == text,
            metadata={
                "rails": rails,
                "length": len(text),
            },
        )

    @staticmethod
    def keyed_columnar(
        text: str,
        key: str,
        padding: Optional[str] = None,
    ) -> TranspositionResult:
        ciphertext = keyed_columnar_encrypt(
            text,
            key,
            padding=padding,
        )

        recovered = keyed_columnar_decrypt(
            ciphertext,
            key,
            padding=padding,
        )

        return TranspositionResult(
            algorithm="Keyed Columnar",
            input_text=text,
            output_text=ciphertext,
            reversible=recovered == text,
            metadata={
                "key": key,
                "columns": len(normalize_text(key)),
                "padding": padding,
            },
        )


# ============================================================================
# 13. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    """Show behavior for unusual but valid or invalid inputs."""

    print("\n" + "=" * 78)
    print("13. EDGE CASES")
    print("=" * 78)

    cases = [
        ("empty", ""),
        ("one character", "A"),
        ("two characters", "AB"),
        ("short message", "HELLO"),
        ("exact grid", "ABCDEFGH"),
        ("incomplete grid", "ABCDEFGHI"),
    ]

    for name, text in cases:
        encrypted = rail_fence_encrypt(text, 3)
        decrypted = rail_fence_decrypt(encrypted, 3)

        print(
            f"{name:18} plaintext={text!r:12} "
            f"ciphertext={encrypted!r:12} recovered={decrypted!r}"
        )

    print("\nInvalid argument examples:")

    invalid_calls = [
        lambda: rail_fence_encrypt("HELLO", 0),
        lambda: columnar_encrypt("HELLO", 0),
        lambda: keyed_columnar_encrypt("HELLO", ""),
        lambda: route_encrypt("HELLO", 0, 3),
        lambda: route_encrypt("TOOLONG", 2, 2),
    ]

    for call in invalid_calls:
        try:
            call()
        except ValueError as error:
            print("  ValueError:", error)


# ============================================================================
# 14. SECURITY CHARACTERISTICS
# ============================================================================

def demonstrate_security_properties() -> None:
    """
    Show why transposition differs fundamentally from substitution.

    Character frequencies remain exactly the same.
    """
    print("\n" + "=" * 78)
    print("14. SECURITY CHARACTERISTICS")
    print("=" * 78)

    plaintext = normalize_text(
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    )

    ciphertext = keyed_columnar_encrypt(
        plaintext,
        "ZEBRA",
    )

    print("Plaintext frequency:")
    print(frequency_table(plaintext))

    print("\nCiphertext frequency:")
    print(frequency_table(ciphertext))

    print(
        "\nSame character multiset:",
        same_multiset(plaintext, ciphertext),
    )

    print(
        "\nImportant implication: simple frequency counts are not destroyed "
        "by transposition."
    )


# ============================================================================
# 15. COMPARISON OF CLASSICAL TRANSPOSITION METHODS
# ============================================================================

def compare_methods() -> None:
    """Compare several educational transposition mechanisms."""

    print("\n" + "=" * 78)
    print("15. METHOD COMPARISON")
    print("=" * 78)

    message = "WEAREDISCOVEREDFLEEATONCE"
    message = normalize_text(message)

    rail = rail_fence_encrypt(message, 3)
    columnar = columnar_encrypt(message, 5)
    keyed = keyed_columnar_encrypt(message, "ZEBRA")
    double = double_columnar_encrypt(
        message,
        "ZEBRA",
        "TIGER",
    )

    print(f"Plaintext:       {message}")
    print(f"Rail Fence:      {rail}")
    print(f"Columnar:        {columnar}")
    print(f"Keyed Columnar:  {keyed}")
    print(f"Double Columnar: {double}")

    print(
        """
Interpretation:

Rail Fence:
    Uses a zig-zag geometric pattern.

Columnar:
    Uses a rectangular grid and a column-reading order.

Keyed Columnar:
    Derives the column order from a keyword.

Double Columnar:
    Applies two transpositions sequentially.

None of these should be treated as modern secure encryption.
They are valuable for studying permutations, cryptanalysis, and the history
of cryptography.
"""
    )


# ============================================================================
# 16. PERFORMANCE DISCUSSION THROUGH MEASUREMENT
# ============================================================================

def performance_demo() -> None:
    """
    Perform a small runtime-oriented demonstration.

    Classical transposition implementations are generally O(n) for a fixed
    number of columns or rails because each character is visited a bounded
    number of times.

    The brute-force key-search example is different: it can become O(k! * n).
    """
    import time

    print("\n" + "=" * 78)
    print("16. PERFORMANCE")
    print("=" * 78)

    message = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 1000

    start = time.perf_counter()
    ciphertext = keyed_columnar_encrypt(message, "CRYPTO")
    recovered = keyed_columnar_decrypt(ciphertext, "CRYPTO")
    elapsed = time.perf_counter() - start

    print(f"Characters processed: {len(message):,}")
    print(f"Correctly recovered:  {recovered == message}")
    print(f"Encryption + decryption time: {elapsed:.6f} seconds")

    print(
        """
Typical complexity:

    Rail Fence encryption:       O(n)
    Rail Fence decryption:       O(n)
    Columnar encryption:         O(n)
    Columnar decryption:         O(n)
    Keyed columnar:              O(n)
    Double transposition:        O(n)
    Small brute-force key search: O(k! * n)

Memory use is usually O(n) for these straightforward implementations.
"""
    )


# ============================================================================
# 17. AUTOMATED TESTS
# ============================================================================

def run_tests() -> None:
    """Run correctness tests for all major algorithms."""

    print("\n" + "=" * 78)
    print("17. AUTOMATED TESTS")
    print("=" * 78)

    messages = [
        "",
        "A",
        "AB",
        "HELLO",
        "HELLOWORLD",
        "WEAREDISCOVEREDFLEEATONCE",
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        "ABCDEFGHIJK",
        "CRYPTOGRAPHY",
    ]

    passed = 0
    total = 0

    def check(condition: bool, description: str) -> None:
        nonlocal passed, total
        total += 1

        if condition:
            passed += 1
            print("PASS:", description)
        else:
            print("FAIL:", description)

    for message in messages:
        for rails in range(1, min(6, max(1, len(message))) + 1):
            encrypted = rail_fence_encrypt(message, rails)
            recovered = rail_fence_decrypt(encrypted, rails)
            check(
                recovered == message,
                f"Rail Fence round trip, rails={rails}, text={message!r}",
            )

    for message in messages:
        for columns in range(1, 7):
            encrypted = columnar_encrypt(message, columns)
            recovered = columnar_decrypt(encrypted, columns)
            check(
                recovered == message,
                f"Columnar round trip, columns={columns}, text={message!r}",
            )

    keys = ["A", "KEY", "ZEBRA", "BALLOON", "CRYPTO"]

    for message in messages:
        for key in keys:
            encrypted = keyed_columnar_encrypt(message, key)
            recovered = keyed_columnar_decrypt(encrypted, key)
            check(
                recovered == message,
                f"Keyed columnar round trip, key={key}, text={message!r}",
            )

    for message in messages:
        if len(message) <= 16:
            for rows, columns in [(1, 1), (2, 3), (3, 4), (4, 2)]:
                if len(message) <= rows * columns:
                    encrypted = route_encrypt(
                        message,
                        rows,
                        columns,
                    )

                    recovered = route_decrypt(
                        encrypted,
                        rows,
                        columns,
                    )

                    check(
                        recovered == message,
                        (
                            "Route round trip, "
                            f"{rows}x{columns}, text={message!r}"
                        ),
                    )

    for message in messages:
        encrypted = double_columnar_encrypt(
            message,
            "ZEBRA",
            "TIGER",
        )

        recovered = double_columnar_decrypt(
            encrypted,
            "ZEBRA",
            "TIGER",
        )

        check(
            recovered == message,
            f"Double columnar round trip, text={message!r}",
        )

    # Mathematical permutation tests.
    for key in ["KEY", "ZEBRA", "CRYPTO"]:
        message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:11]
        permutation = permutation_for_key(key, len(message))
        encrypted = apply_permutation(message, permutation)
        inverse = invert_permutation(permutation)
        recovered = apply_permutation(encrypted, inverse)

        check(
            recovered == message,
            f"Permutation inversion, key={key}",
        )

    print(f"\nTests passed: {passed}/{total}")

    if passed != total:
        raise AssertionError("At least one test failed.")


# ============================================================================
# 18. COMPLETE PRACTICAL EXAMPLE
# ============================================================================

def practical_case_study() -> None:
    """
    A complete workflow resembling a small educational message-protection
    application.

    The message is normalized, encrypted, decrypted, and validated.
    """
    print("\n" + "=" * 78)
    print("18. PRACTICAL CASE STUDY")
    print("=" * 78)

    original = (
        "Transposition ciphers rearrange symbols while preserving their "
        "individual identities."
    )

    plaintext = normalize_text(original)
    key = "SECURE"

    print("Original message:")
    print(original)

    print("\nNormalized plaintext:")
    print(plaintext)

    encrypted = keyed_columnar_encrypt(
        plaintext,
        key,
    )

    print("\nEncrypted:")
    print(encrypted)

    decrypted = keyed_columnar_decrypt(
        encrypted,
        key,
    )

    print("\nDecrypted:")
    print(decrypted)

    print("\nRound-trip successful:", decrypted == plaintext)

    result = TranspositionToolkit.keyed_columnar(
        plaintext,
        key,
    )

    print("\nObject-oriented result:")
    result.display()


# ============================================================================
# 19. CRYPTANALYSIS EXAMPLE
# ============================================================================

def cryptanalysis_demo() -> None:
    """
    Demonstrate structural cryptanalysis without pretending that a simple
    scoring function is a complete modern attack.
    """
    print("\n" + "=" * 78)
    print("19. CRYPTANALYSIS DEMONSTRATION")
    print("=" * 78)

    plaintext = normalize_text(
        """
        Transposition ciphers preserve the frequency of individual letters.
        An analyst therefore needs to study ordering, adjacency, repeated
        patterns, possible dimensions, and likely keys.
        """
    )

    ciphertext = columnar_encrypt(
        plaintext,
        7,
    )

    print("Ciphertext:")
    print(ciphertext)

    candidates = crack_by_column_count(
        ciphertext,
        min_columns=2,
        max_columns=12,
    )

    print("\nCandidate column counts:")
    for columns, chi, ngram, candidate in candidates[:8]:
        preview = candidate[:80]
        print(
            f"columns={columns:2} "
            f"chi={chi:8.2f} "
            f"ngram={ngram:3} "
            f"candidate={preview}"
        )

    print(
        """
The important lesson is methodological:

    1. Identify what the cipher preserves.
    2. Identify what the cipher changes.
    3. Hypothesize structural parameters.
    4. Generate candidate decryptions.
    5. Score candidates using language evidence.
    6. Inspect promising candidates.
    7. Validate the recovered structure.

Real transposition cryptanalysis usually requires substantially richer
language models and search strategies than the small demonstration above.
"""
    )


# ============================================================================
# 20. MAIN DEMONSTRATION
# ============================================================================

def main() -> None:
    print("=" * 78)
    print("TRANSPOSITION CIPHERS: BEGINNER TO ADVANCED STUDY PROGRAM")
    print("=" * 78)

    explain_fundamentals()
    demonstrate_permutation()

    print("\n" + "=" * 78)
    print("3. RAIL FENCE")
    print("=" * 78)

    rail_plaintext = "WEAREDISCOVEREDFLEEATONCE"
    rail_ciphertext = rail_fence_encrypt(rail_plaintext, 3)

    print("Plaintext: ", rail_plaintext)
    print("Pattern:")
    show_rail_fence_pattern(rail_plaintext, 3)
    print("Ciphertext:", rail_ciphertext)
    print(
        "Decrypted:",
        rail_fence_decrypt(rail_ciphertext, 3),
    )

    print("\n" + "=" * 78)
    print("4. COLUMNAR TRANSPOSITION")
    print("=" * 78)

    columnar_plaintext = "WEAREDISCOVEREDFLEEATONCE"
    columnar_ciphertext = columnar_encrypt(
        columnar_plaintext,
        5,
    )

    print("Plaintext: ", columnar_plaintext)
    display_column_grid(columnar_plaintext, 5)
    print("Ciphertext:", columnar_ciphertext)
    print(
        "Decrypted:",
        columnar_decrypt(columnar_ciphertext, 5),
    )

    print("\n" + "=" * 78)
    print("5. KEYED COLUMNAR")
    print("=" * 78)

    keyed_plaintext = "ATTACKATDAWN"
    keyed_ciphertext = keyed_columnar_encrypt(
        keyed_plaintext,
        "ZEBRA",
    )

    print("Plaintext: ", keyed_plaintext)
    print("Key:       ZEBRA")
    print("Key order: ", key_order("ZEBRA"))
    print("Ciphertext:", keyed_ciphertext)
    print(
        "Decrypted:",
        keyed_columnar_decrypt(
            keyed_ciphertext,
            "ZEBRA",
        ),
    )

    print("\n" + "=" * 78)
    print("6. DOUBLE TRANSPOSITION")
    print("=" * 78)

    double_plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    double_ciphertext = double_columnar_encrypt(
        double_plaintext,
        "ZEBRA",
        "TIGER",
    )

    print("Plaintext: ", double_plaintext)
    print("Ciphertext:", double_ciphertext)
    print(
        "Decrypted:",
        double_columnar_decrypt(
            double_ciphertext,
            "ZEBRA",
            "TIGER",
        ),
    )

    print("\n" + "=" * 78)
    print("7. ROUTE TRANSPOSITION")
    print("=" * 78)

    route_plaintext = "THISISAROUTECIPHER"
    route_ciphertext = route_encrypt(
        route_plaintext,
        4,
        5,
    )

    print("Plaintext: ", route_plaintext)
    print("Ciphertext:", route_ciphertext)
    print(
        "Decrypted:",
        route_decrypt(
            route_ciphertext,
            4,
            5,
        ),
    )

    demonstrate_edge_cases()
    demonstrate_security_properties()
    compare_methods()
    performance_demo()
    cryptanalysis_demo()
    practical_case_study()
    run_tests()

    print("\n" + "=" * 78)
    print("PROGRAM COMPLETE")
    print("=" * 78)


if __name__ == "__main__":
    main()
