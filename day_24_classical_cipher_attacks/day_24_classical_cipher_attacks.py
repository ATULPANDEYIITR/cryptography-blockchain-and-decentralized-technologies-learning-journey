"""
Classical Cipher Attacks
========================

A self-contained study and laboratory script covering attacks against
classical substitution, transposition, affine, Caesar, Vigenere, and
columnar-transposition ciphers.

The emphasis is educational: understand why classical ciphers leak
information, how attackers exploit that leakage, and how different
cryptanalytic techniques fit different cipher structures.

All cryptanalysis here is designed for historical/educational ciphers.
It is not a substitute for modern authenticated encryption.
"""

from __future__ import annotations

import math
import random
import string
from collections import Counter
from dataclasses import dataclass
from itertools import product
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ALPHABET = string.ascii_uppercase
A_TO_I = {ch: i for i, ch in enumerate(ALPHABET)}
I_TO_A = {i: ch for i, ch in enumerate(ALPHABET)}

ENGLISH_FREQUENCIES = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253,
    "E": 0.12702, "F": 0.02228, "G": 0.02015, "H": 0.06094,
    "I": 0.06966, "J": 0.00153, "K": 0.00772, "L": 0.04025,
    "M": 0.02406, "N": 0.06749, "O": 0.07507, "P": 0.01929,
    "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150,
    "Y": 0.01974, "Z": 0.00074,
}

# Compact tetragram frequencies. Values are approximate relative scores.
# A real cryptanalytic system would normally use a much larger corpus.
COMMON_TETRAGRAMS = {
    "TION": 5.0, "THER": 4.9, "WITH": 4.8, "THAT": 4.7,
    "OFTH": 4.6, "FTHE": 4.6, "THIS": 4.5, "HERE": 4.4,
    "ATIO": 4.4, "MENT": 4.3, "IONS": 4.2, "EVER": 4.1,
    "FROM": 4.0, "OUGH": 3.9, "HAVE": 3.9, "IGHT": 3.8,
    "HICH": 3.7, "WHIC": 3.7, "THEM": 3.6, "WERE": 3.6,
    "THEI": 3.5, "TING": 3.5, "ANDT": 3.4, "EDTH": 3.4,
    "THES": 3.3, "MENT": 3.3, "ATIO": 3.2, "ANCE": 3.2,
}

COMMON_WORDS = {
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT",
    "HE", "WAS", "FOR", "ON", "ARE", "AS", "WITH", "HIS", "THEY",
    "I", "AT", "BE", "THIS", "HAVE", "FROM", "OR", "ONE", "HAD",
    "BY", "WORD", "BUT", "NOT", "WHAT", "ALL", "WERE", "WE",
    "WHEN", "YOUR", "CAN", "SAID", "THERE", "USE", "AN", "EACH",
    "WHICH", "SHE", "DO", "HOW", "THEIR", "IF", "WILL", "UP",
    "OTHER", "ABOUT", "OUT", "MANY", "THEN", "THEM", "THESE",
    "SO", "SOME", "HER", "WOULD", "MAKE", "LIKE", "HIM", "INTO",
    "TIME", "HAS", "LOOK", "TWO", "MORE", "WRITE", "GO", "SEE",
    "NUMBER", "NO", "WAY", "COULD", "PEOPLE", "MY", "THAN",
    "FIRST", "WATER", "BEEN", "CALL", "WHO", "OIL", "ITS",
    "NOW", "FIND", "LONG", "DOWN", "DAY", "DID", "GET", "COME",
    "MADE", "MAY", "PART",
}


# ---------------------------------------------------------------------------
# General utilities
# ---------------------------------------------------------------------------

def normalize_letters(text: str) -> str:
    """Keep only A-Z and normalize to uppercase."""
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def preserve_nonletters(original: str, transformed_letters: str) -> str:
    """Reinsert transformed letters while preserving punctuation/spacing."""
    result = []
    index = 0
    for ch in original:
        if ch.upper() in ALPHABET:
            result.append(transformed_letters[index])
            index += 1
        else:
            result.append(ch)
    return "".join(result)


def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def gcd(a: int, b: int) -> int:
    return math.gcd(a, b)


def modular_inverse(a: int, modulus: int = 26) -> Optional[int]:
    """Return x such that a*x == 1 mod modulus, or None."""
    a %= modulus
    for x in range(1, modulus):
        if (a * x) % modulus == 1:
            return x
    return None


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------

def caesar_encrypt(text: str, shift: int) -> str:
    shift %= 26
    output = []
    for ch in text.upper():
        if ch in ALPHABET:
            output.append(I_TO_A[(A_TO_I[ch] + shift) % 26])
        else:
            output.append(ch)
    return "".join(output)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def caesar_bruteforce(ciphertext: str) -> List[Tuple[int, str]]:
    """
    Caesar has only 26 possible keys.
    Exhaustive search is therefore trivial.
    """
    return [(shift, caesar_decrypt(ciphertext, shift)) for shift in range(26)]


def chi_squared_score(text: str) -> float:
    """
    Lower is better.
    Compare observed letter counts with expected English frequencies.
    """
    letters = normalize_letters(text)
    if not letters:
        return float("inf")

    counts = Counter(letters)
    length = len(letters)
    score = 0.0

    for letter in ALPHABET:
        expected = ENGLISH_FREQUENCIES[letter] * length
        observed = counts.get(letter, 0)
        if expected:
            score += ((observed - expected) ** 2) / expected

    return score


def crack_caesar(ciphertext: str) -> Tuple[int, str]:
    candidates = caesar_bruteforce(ciphertext)
    return min(candidates, key=lambda pair: chi_squared_score(pair[1]))


# ---------------------------------------------------------------------------
# Affine cipher
# ---------------------------------------------------------------------------

def affine_encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("Affine multiplier a must be coprime with 26.")

    output = []
    for ch in text.upper():
        if ch in ALPHABET:
            x = A_TO_I[ch]
            output.append(I_TO_A[(a * x + b) % 26])
        else:
            output.append(ch)
    return "".join(output)


def affine_decrypt(text: str, a: int, b: int) -> str:
    inverse = modular_inverse(a)
    if inverse is None:
        raise ValueError("Affine multiplier has no modular inverse modulo 26.")

    output = []
    for ch in text.upper():
        if ch in ALPHABET:
            y = A_TO_I[ch]
            output.append(I_TO_A[(inverse * (y - b)) % 26])
        else:
            output.append(ch)
    return "".join(output)


def affine_keyspace() -> List[Tuple[int, int]]:
    """
    Only a values relatively prime to 26 are valid.
    There are phi(26) = 12 possible multipliers and 26 shifts.
    """
    valid_a = [a for a in range(26) if gcd(a, 26) == 1]
    return [(a, b) for a in valid_a for b in range(26)]


def crack_affine(ciphertext: str) -> Tuple[Tuple[int, int], str]:
    best_key = None
    best_text = ""
    best_score = float("inf")

    for a, b in affine_keyspace():
        plaintext = affine_decrypt(ciphertext, a, b)
        score = chi_squared_score(plaintext)
        if score < best_score:
            best_score = score
            best_key = (a, b)
            best_text = plaintext

    assert best_key is not None
    return best_key, best_text


# ---------------------------------------------------------------------------
# Monoalphabetic substitution
# ---------------------------------------------------------------------------

def substitution_encrypt(text: str, key: str) -> str:
    """
    key[i] is the ciphertext letter corresponding to plaintext letter i.
    Example: key="QWERTY..." means plaintext A becomes Q.
    """
    key = key.upper()
    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError("Substitution key must be a permutation of A-Z.")

    output = []
    for ch in text.upper():
        if ch in ALPHABET:
            output.append(key[A_TO_I[ch]])
        else:
            output.append(ch)
    return "".join(output)


def substitution_decrypt(text: str, key: str) -> str:
    key = key.upper()
    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError("Substitution key must be a permutation of A-Z.")

    inverse = {cipher: plain for plain, cipher in zip(ALPHABET, key)}
    output = []
    for ch in text.upper():
        output.append(inverse.get(ch, ch))
    return "".join(output)


def frequency_table(text: str) -> List[Tuple[str, int]]:
    return Counter(normalize_letters(text)).most_common()


def index_of_coincidence(text: str) -> float:
    """
    IC = sum(f_i(f_i-1)) / (N(N-1))

    English-like monoalphabetic substitution tends to preserve the
    underlying frequency structure and therefore often has an IC
    near natural-language values.
    """
    letters = normalize_letters(text)
    n = len(letters)

    if n < 2:
        return 0.0

    counts = Counter(letters)
    numerator = sum(count * (count - 1) for count in counts.values())
    return numerator / (n * (n - 1))


def pattern_signature(word: str) -> Tuple[int, ...]:
    """
    DOG -> (0,1,2)
    MOM -> (0,1,0)
    ALL -> (0,1,1)
    """
    mapping = {}
    next_id = 0
    signature = []

    for ch in word.upper():
        if ch not in mapping:
            mapping[ch] = next_id
            next_id += 1
        signature.append(mapping[ch])

    return tuple(signature)


def word_pattern_dictionary(words: Iterable[str]) -> Dict[Tuple[int, ...], List[str]]:
    result: Dict[Tuple[int, ...], List[str]] = {}
    for word in words:
        normalized = normalize_letters(word)
        if normalized:
            result.setdefault(pattern_signature(normalized), []).append(normalized)
    return result


def apply_partial_substitution(
    ciphertext: str,
    cipher_to_plain: Dict[str, str],
) -> str:
    """
    Unknown mappings are represented by '_'. This is useful during
    manual-style cryptanalysis because a partial key can be inspected
    without pretending unknown letters are known.
    """
    output = []
    for ch in ciphertext.upper():
        if ch in ALPHABET:
            output.append(cipher_to_plain.get(ch, "_"))
        else:
            output.append(ch)
    return "".join(output)


# ---------------------------------------------------------------------------
# N-gram scoring for substitution hill climbing
# ---------------------------------------------------------------------------

def tetragram_score(text: str) -> float:
    letters = normalize_letters(text)
    if len(letters) < 4:
        return -1000.0

    score = 0.0
    for i in range(len(letters) - 3):
        gram = letters[i:i + 4]
        score += COMMON_TETRAGRAMS.get(gram, -1.2)

    return score


def english_likeness_score(text: str) -> float:
    """
    Combines several weak signals. No single heuristic is reliable enough
    for every ciphertext.
    """
    letters = normalize_letters(text)
    if not letters:
        return -float("inf")

    score = tetragram_score(letters)

    words = letters.split()
    if words:
        score += 2.5 * sum(1 for word in words if word in COMMON_WORDS)

    # Favor plausible English IC without making it decisive.
    ic = index_of_coincidence(letters)
    score -= abs(ic - 0.066) * 40

    return score


def random_substitution_key(rng: random.Random) -> str:
    letters = list(ALPHABET)
    rng.shuffle(letters)
    return "".join(letters)


def swap_key_positions(key: str, i: int, j: int) -> str:
    chars = list(key)
    chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def crack_substitution_hill_climbing(
    ciphertext: str,
    restarts: int = 20,
    iterations: int = 3000,
    seed: int = 42,
) -> Tuple[str, str, float]:
    """
    A stochastic heuristic attack.

    It does not mathematically guarantee recovery of the original key.
    It searches the enormous 26! substitution-key space by repeatedly
    swapping two mappings and retaining improvements.
    """
    rng = random.Random(seed)
    best_key = ""
    best_plaintext = ""
    best_score = -float("inf")

    for _ in range(restarts):
        key = random_substitution_key(rng)
        plaintext = substitution_decrypt(ciphertext, key)
        current_score = english_likeness_score(plaintext)

        temperature = 8.0

        for _ in range(iterations):
            i, j = rng.sample(range(26), 2)
            candidate_key = swap_key_positions(key, i, j)
            candidate_plaintext = substitution_decrypt(ciphertext, candidate_key)
            candidate_score = english_likeness_score(candidate_plaintext)

            # Simulated-annealing-like acceptance permits occasional
            # downhill moves, helping escape local maxima.
            delta = candidate_score - current_score
            accept = delta >= 0 or rng.random() < math.exp(
                max(-50.0, min(0.0, delta / max(temperature, 0.001)))
            )

            if accept:
                key = candidate_key
                current_score = candidate_score

            temperature *= 0.9985

            if current_score > best_score:
                best_score = current_score
                best_key = key
                best_plaintext = substitution_decrypt(ciphertext, key)

    return best_key, best_plaintext, best_score


# ---------------------------------------------------------------------------
# Vigenere cipher
# ---------------------------------------------------------------------------

def validate_keyword(keyword: str) -> str:
    key = normalize_letters(keyword)
    if not key:
        raise ValueError("Keyword must contain at least one alphabetic character.")
    return key


def vigenere_encrypt(text: str, keyword: str) -> str:
    keyword = validate_keyword(keyword)
    output = []
    key_index = 0

    for ch in text.upper():
        if ch in ALPHABET:
            shift = A_TO_I[keyword[key_index % len(keyword)]]
            output.append(I_TO_A[(A_TO_I[ch] + shift) % 26])
            key_index += 1
        else:
            output.append(ch)

    return "".join(output)


def vigenere_decrypt(text: str, keyword: str) -> str:
    keyword = validate_keyword(keyword)
    output = []
    key_index = 0

    for ch in text.upper():
        if ch in ALPHABET:
            shift = A_TO_I[keyword[key_index % len(keyword)]]
            output.append(I_TO_A[(A_TO_I[ch] - shift) % 26])
            key_index += 1
        else:
            output.append(ch)

    return "".join(output)


def repeated_ngram_distances(ciphertext: str, n: int = 3) -> Dict[str, List[int]]:
    letters = normalize_letters(ciphertext)
    positions: Dict[str, List[int]] = {}

    for i in range(len(letters) - n + 1):
        gram = letters[i:i + n]
        positions.setdefault(gram, []).append(i)

    return {
        gram: positions_list
        for gram, positions_list in positions.items()
        if len(positions_list) >= 2
    }


def factorize(number: int) -> List[int]:
    factors = []
    for candidate in range(2, number + 1):
        if number % candidate == 0:
            factors.append(candidate)
    return factors


def kasiski_candidates(ciphertext: str, n: int = 3) -> Counter:
    """
    Kasiski examination looks for repeated ciphertext fragments.
    Distances between repetitions can share factors associated with
    the Vigenere key length.
    """
    repeats = repeated_ngram_distances(ciphertext, n)
    factor_counts = Counter()

    for positions in repeats.values():
        for left, right in zip(positions, positions[1:]):
            distance = right - left
            for factor in factorize(distance):
                if factor <= 20:
                    factor_counts[factor] += 1

    return factor_counts


def average_ic_for_key_length(ciphertext: str, key_length: int) -> float:
    letters = normalize_letters(ciphertext)
    columns = [letters[i::key_length] for i in range(key_length)]
    nonempty = [index_of_coincidence(column) for column in columns if len(column) > 1]
    return sum(nonempty) / len(nonempty) if nonempty else 0.0


def rank_vigenere_key_lengths(
    ciphertext: str,
    maximum_length: int = 12,
) -> List[Tuple[int, float]]:
    candidates = []
    for length in range(1, min(maximum_length, len(normalize_letters(ciphertext))) + 1):
        ic = average_ic_for_key_length(ciphertext, length)
        candidates.append((length, ic))

    return sorted(candidates, key=lambda item: item[1], reverse=True)


def solve_vigenere_by_frequency(
    ciphertext: str,
    key_length: int,
) -> str:
    """
    For each key position, assume that column is Caesar-shifted English.
    Chi-squared identifies the likely shift.
    """
    letters = normalize_letters(ciphertext)
    key = []

    for position in range(key_length):
        column = letters[position::key_length]

        best_shift = 0
        best_score = float("inf")

        for shift in range(26):
            decrypted = "".join(
                I_TO_A[(A_TO_I[ch] - shift) % 26] for ch in column
            )
            score = chi_squared_score(decrypted)

            if score < best_score:
                best_score = score
                best_shift = shift

        key.append(I_TO_A[best_shift])

    return "".join(key)


# ---------------------------------------------------------------------------
# Transposition cipher
# ---------------------------------------------------------------------------

def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 1:
        raise ValueError("Number of rails must be positive.")

    letters = normalize_letters(text)
    if rails == 1 or rails >= len(letters):
        return letters

    rows = [[] for _ in range(rails)]
    row = 0
    direction = 1

    for ch in letters:
        rows[row].append(ch)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    return "".join("".join(r) for r in rows)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    if rails < 1:
        raise ValueError("Number of rails must be positive.")

    cipher = normalize_letters(ciphertext)

    if rails == 1 or rails >= len(cipher):
        return cipher

    pattern = []
    row = 0
    direction = 1

    for _ in cipher:
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    counts = Counter(pattern)
    rows = []
    index = 0

    for rail in range(rails):
        count = counts[rail]
        rows.append(list(cipher[index:index + count]))
        index += count

    row_offsets = [0] * rails
    output = []

    for rail in pattern:
        output.append(rows[rail][row_offsets[rail]])
        row_offsets[rail] += 1

    return "".join(output)


def columnar_encrypt(text: str, keyword: str) -> str:
    keyword = validate_keyword(keyword)
    letters = normalize_letters(text)
    columns = len(keyword)

    rows = [
        letters[i:i + columns]
        for i in range(0, len(letters), columns)
    ]

    # Stable ranking handles repeated keyword letters by using original
    # column position as a tiebreaker.
    order = sorted(range(columns), key=lambda i: (keyword[i], i))

    output = []
    for column in order:
        for row in rows:
            if column < len(row):
                output.append(row[column])

    return "".join(output)


def columnar_decrypt(ciphertext: str, keyword: str) -> str:
    keyword = validate_keyword(keyword)
    cipher = normalize_letters(ciphertext)

    columns = len(keyword)
    length = len(cipher)
    full_rows, remainder = divmod(length, columns)

    column_lengths = [
        full_rows + (1 if column < remainder else 0)
        for column in range(columns)
    ]

    order = sorted(range(columns), key=lambda i: (keyword[i], i))

    column_data: Dict[int, List[str]] = {}
    cursor = 0

    for column in order:
        count = column_lengths[column]
        column_data[column] = list(cipher[cursor:cursor + count])
        cursor += count

    output = []
    for row in range(full_rows + (1 if remainder else 0)):
        for column in range(columns):
            if row < len(column_data[column]):
                output.append(column_data[column][row])

    return "".join(output)


# ---------------------------------------------------------------------------
# Known-plaintext and crib attacks
# ---------------------------------------------------------------------------

def find_crib_positions(ciphertext: str, crib: str) -> List[int]:
    """
    A crib is a suspected plaintext fragment. In classical cryptanalysis,
    known words can dramatically reduce the search space.
    """
    cipher = normalize_letters(ciphertext)
    crib = normalize_letters(crib)

    if not crib or len(crib) > len(cipher):
        return []

    return [
        i
        for i in range(len(cipher) - len(crib) + 1)
        if cipher[i:i + len(crib)] == crib
    ]


def caesar_crib_test(ciphertext: str, expected_plaintext: str) -> Optional[int]:
    """
    If a plaintext fragment and corresponding ciphertext fragment are
    aligned, their letter differences reveal the Caesar shift.
    """
    cipher = normalize_letters(ciphertext)
    plain = normalize_letters(expected_plaintext)

    if len(cipher) != len(plain) or not plain:
        return None

    differences = {
        (A_TO_I[c] - A_TO_I[p]) % 26
        for c, p in zip(cipher, plain)
    }

    return differences.pop() if len(differences) == 1 else None


# ---------------------------------------------------------------------------
# Statistical attack comparison
# ---------------------------------------------------------------------------

@dataclass
class AttackResult:
    attack: str
    recovered_key: str
    plaintext: str
    confidence_note: str


def compare_attack_models(ciphertext: str) -> List[AttackResult]:
    results = []

    shift, plaintext = crack_caesar(ciphertext)
    results.append(
        AttackResult(
            "Caesar frequency attack",
            str(shift),
            plaintext,
            "Useful when a single substitution shift explains the text.",
        )
    )

    affine_key, affine_plain = crack_affine(ciphertext)
    results.append(
        AttackResult(
            "Affine exhaustive key search",
            f"a={affine_key[0]}, b={affine_key[1]}",
            affine_plain,
            "Exhaustive because the affine keyspace is small.",
        )
    )

    return results


# ---------------------------------------------------------------------------
# Demonstration datasets
# ---------------------------------------------------------------------------

CAESAR_SAMPLE = (
    "THE SECURITY OF A CLASSICAL CIPHER DEPENDS ON THE SECRECY OF ITS KEY "
    "BUT A SMALL KEYSPACE CAN MAKE EXHAUSTIVE SEARCH PRACTICAL"
)

AFFINE_SAMPLE = (
    "CLASSICAL CRYPTOGRAPHY SHOWS HOW MATHEMATICAL STRUCTURE CAN LEAK "
    "INFORMATION ABOUT A MESSAGE"
)

VIGENERE_SAMPLE = (
    "THE REPEATED KEY CREATES STATISTICAL STRUCTURE THAT CAN BE STUDIED "
    "USING COINCIDENCE TESTS AND FREQUENCY ANALYSIS"
)

TRANSPOSITION_SAMPLE = (
    "TRANSPOSITION CHANGES POSITION RATHER THAN LETTER IDENTITY "
    "SO LETTER FREQUENCIES CAN REMAIN VISIBLE"
)


# ---------------------------------------------------------------------------
# Educational attack demonstrations
# ---------------------------------------------------------------------------

def demonstrate_caesar() -> None:
    print_section("1. Caesar cipher: exhaustive search and frequency analysis")

    key = 7
    ciphertext = caesar_encrypt(CAESAR_SAMPLE, key)

    print("Plaintext :", CAESAR_SAMPLE)
    print("Key       :", key)
    print("Ciphertext:", ciphertext)

    recovered_key, recovered_plaintext = crack_caesar(ciphertext)

    print("Recovered :", recovered_plaintext)
    print("Recovered key:", recovered_key)
    print("Chi-squared score:", chi_squared_score(recovered_plaintext))

    print("\nAll 26 candidates:")
    for shift, candidate in caesar_bruteforce(ciphertext):
        marker = " <-- likely candidate" if shift == recovered_key else ""
        print(f"{shift:2d}: {candidate[:80]}{marker}")


def demonstrate_affine() -> None:
    print_section("2. Affine cipher: constrained exhaustive search")

    a, b = 5, 8
    ciphertext = affine_encrypt(AFFINE_SAMPLE, a, b)

    print("Plaintext :", AFFINE_SAMPLE)
    print("Key       :", (a, b))
    print("Ciphertext:", ciphertext)

    recovered_key, plaintext = crack_affine(ciphertext)

    print("Recovered key:", recovered_key)
    print("Recovered text:", plaintext)

    print("\nValid affine multipliers:")
    print([a for a in range(26) if gcd(a, 26) == 1])

    print("Total affine keys:", len(affine_keyspace()))


def demonstrate_frequency_analysis() -> None:
    print_section("3. Frequency analysis: why substitution is structurally weak")

    ciphertext = substitution_encrypt(
        CAESAR_SAMPLE,
        "QWERTYUIOPASDFGHJKLZXCVBNM",
    )

    print("Ciphertext:")
    print(ciphertext)

    print("\nCiphertext frequency:")
    for letter, count in frequency_table(ciphertext):
        print(f"{letter}: {count}")

    print("\nIndex of coincidence:")
    print(index_of_coincidence(ciphertext))

    print(
        "\nA monoalphabetic substitution preserves the frequency of each "
        "underlying plaintext letter, although the letter labels change."
    )

    partial_mapping = {
        "Q": "A",
        "W": "B",
        "E": "C",
    }

    print("\nPartial substitution view:")
    print(apply_partial_substitution(ciphertext, partial_mapping))


def demonstrate_pattern_analysis() -> None:
    print_section("4. Pattern analysis for substitution ciphers")

    examples = ["THE", "MOM", "ALL", "TEST", "SEES", "LEVEL"]

    for word in examples:
        print(f"{word:8s} -> {pattern_signature(word)}")

    print(
        "\nWords with the same repeated-letter pattern can become candidates "
        "for the same ciphertext word pattern."
    )

    dictionary = word_pattern_dictionary(
        ["THE", "THAT", "ALL", "MOM", "LEVEL", "TEST", "SEES", "HERE"]
    )

    for pattern, words in dictionary.items():
        print(pattern, ":", words)


def demonstrate_vigenere() -> None:
    print_section("5. Vigenere: Kasiski examination and index of coincidence")

    key = "LEMON"
    ciphertext = vigenere_encrypt(VIGENERE_SAMPLE, key)

    print("Key       :", key)
    print("Ciphertext:", ciphertext)

    print("\nRepeated trigrams:")
    repeats = repeated_ngram_distances(ciphertext, 3)
    for gram, positions in sorted(repeats.items()):
        print(f"{gram}: {positions}")

    print("\nKasiski factor counts:")
    for factor, count in kasiski_candidates(ciphertext, 3).most_common():
        print(f"key-length factor {factor}: {count}")

    print("\nAverage IC by candidate key length:")
    for length, ic in rank_vigenere_key_lengths(ciphertext, 12):
        print(f"{length:2d}: {ic:.4f}")

    estimated_key = solve_vigenere_by_frequency(ciphertext, len(key))
    estimated_plaintext = vigenere_decrypt(ciphertext, estimated_key)

    print("\nActual key      :", key)
    print("Estimated key   :", estimated_key)
    print("Estimated plain :", estimated_plaintext)


def demonstrate_transposition() -> None:
    print_section("6. Transposition attacks: structural differences")

    rails = 3
    rail_cipher = rail_fence_encrypt(TRANSPOSITION_SAMPLE, rails)
    rail_plain = rail_fence_decrypt(rail_cipher, rails)

    print("Rail Fence")
    print("Rails     :", rails)
    print("Ciphertext:", rail_cipher)
    print("Decrypted :", rail_plain)

    keyword = "ZEBRA"
    column_cipher = columnar_encrypt(TRANSPOSITION_SAMPLE, keyword)
    column_plain = columnar_decrypt(column_cipher, keyword)

    print("\nColumnar Transposition")
    print("Keyword   :", keyword)
    print("Ciphertext:", column_cipher)
    print("Decrypted :", column_plain)

    print(
        "\nUnlike substitution, transposition rearranges symbols instead of "
        "changing their identities. Letter-frequency statistics can therefore "
        "remain very informative."
    )


def demonstrate_known_plaintext() -> None:
    print_section("7. Known-plaintext and crib reasoning")

    plaintext_fragment = "ATTACK"
    ciphertext_fragment = caesar_encrypt(plaintext_fragment, 11)

    print("Known plaintext :", plaintext_fragment)
    print("Observed cipher :", ciphertext_fragment)

    recovered_shift = caesar_crib_test(
        ciphertext_fragment,
        plaintext_fragment,
    )

    print("Recovered shift :", recovered_shift)

    if recovered_shift is not None:
        print(
            "Once the aligned plaintext/ciphertext pair is trusted, the "
            "Caesar key is determined immediately."
        )


# ---------------------------------------------------------------------------
# Edge cases and failure modes
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    print_section("8. Edge cases and failure conditions")

    print("Empty Caesar input:", repr(caesar_encrypt("", 5)))
    print("Large Caesar shift:", caesar_encrypt("ABC", 52 + 3))
    print("Negative Caesar shift:", caesar_encrypt("ABC", -3))

    try:
        affine_encrypt("ABC", 13, 4)
    except ValueError as exc:
        print("Invalid affine multiplier:", exc)

    try:
        validate_keyword("12345")
    except ValueError as exc:
        print("Invalid Vigenere keyword:", exc)

    try:
        substitution_encrypt("ABC", "ABC")
    except ValueError as exc:
        print("Invalid substitution key:", exc)

    print("IC of a single character:", index_of_coincidence("A"))
    print("IC of empty text:", index_of_coincidence(""))

    print(
        "\nImportant limitation: statistical attacks become less reliable on "
        "very short ciphertexts, unusual language, compressed text, random "
        "padding, or plaintext with highly atypical vocabulary."
    )


# ---------------------------------------------------------------------------
# Educational complexity analysis
# ---------------------------------------------------------------------------

def demonstrate_complexity() -> None:
    print_section("9. Search-space and complexity analysis")

    print("Caesar keyspace:", 26)
    print("Affine keyspace :", len(affine_keyspace()))
    print("Monoalphabetic substitution keyspace: 26! =", math.factorial(26))
    print(
        "Approximate log2(26!) bits:",
        math.log2(math.factorial(26)),
    )

    print(
        "\nA 26-key Caesar cipher is trivial to enumerate. An exhaustive "
        "search over all monoalphabetic substitutions is computationally "
        "enormous, so practical attacks use language statistics, word "
        "patterns, heuristics, constraint solving, and search."
    )


# ---------------------------------------------------------------------------
# Automated verification
# ---------------------------------------------------------------------------

def run_self_tests() -> None:
    print_section("10. Self-tests")

    assert caesar_decrypt(caesar_encrypt("HELLO WORLD", 13), 13) == "HELLO WORLD"
    assert affine_decrypt(affine_encrypt("HELLO WORLD", 5, 8), 5, 8) == "HELLO WORLD"

    substitution_key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    assert (
        substitution_decrypt(
            substitution_encrypt("HELLO WORLD", substitution_key),
            substitution_key,
        )
        == "HELLO WORLD"
    )

    assert vigenere_decrypt(
        vigenere_encrypt("HELLO WORLD", "KEY"),
        "KEY",
    ) == "HELLO WORLD"

    assert rail_fence_decrypt(
        rail_fence_encrypt("HELLOWORLD", 3),
        3,
    ) == "HELLOWORLD"

    assert columnar_decrypt(
        columnar_encrypt("THISISATESTMESSAGE", "ZEBRA"),
        "ZEBRA",
    ) == "THISISATESTMESSAGE"

    assert modular_inverse(5, 26) == 21
    assert pattern_signature("MOM") == (0, 1, 0)

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# Main study laboratory
# ---------------------------------------------------------------------------

def main() -> None:
    print_section("Classical Cipher Attack Laboratory")
    print(
        "This program demonstrates cryptanalysis as the study of information "
        "leakage, key-space size, statistical structure, and cipher-specific "
        "attack models."
    )

    demonstrate_caesar()
    demonstrate_affine()
    demonstrate_frequency_analysis()
    demonstrate_pattern_analysis()
    demonstrate_vigenere()
    demonstrate_transposition()
    demonstrate_known_plaintext()
    demonstrate_edge_cases()
    demonstrate_complexity()
    run_self_tests()

    print_section("11. Attack-selection decision model")

    decision_table = [
        ("Caesar", "26 shifts", "Exhaustive search + frequency scoring"),
        ("Affine", "312 valid keys", "Exhaustive search + frequency scoring"),
        (
            "Monoalphabetic substitution",
            "26!",
            "Frequency, patterns, word constraints, heuristic search",
        ),
        (
            "Vigenere",
            "26^key_length",
            "Kasiski, IC, column frequency analysis",
        ),
        (
            "Transposition",
            "Depends on construction",
            "Anagram/structure analysis, route/key search",
        ),
        (
            "Known-plaintext",
            "Depends on cipher",
            "Use aligned plaintext/ciphertext relationships",
        ),
    ]

    for cipher, space, attack in decision_table:
        print(f"{cipher:32s} | {space:20s} | {attack}")

    print(
        "\nThe central lesson is that an attack should be matched to the "
        "structure of the cipher. A method that works well against a "
        "monoalphabetic substitution does not automatically recover a "
        "Vigenere keyword, and an exhaustive attack is only practical when "
        "the relevant keyspace is sufficiently small."
    )


if __name__ == "__main__":
    main()
