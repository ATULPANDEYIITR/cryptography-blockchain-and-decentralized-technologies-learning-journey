"""
Substitution Ciphers: From Classical Cryptography to Practical Analysis

This standalone study program teaches substitution ciphers from beginner to
advanced level. It implements several substitution techniques, demonstrates
their properties, performs validation and cryptanalysis, and includes a
non-trivial simulated message-analysis workflow.

The implementations are educational. Classical substitution ciphers are not
appropriate for protecting modern sensitive information.
"""

from __future__ import annotations

import collections
import math
import random
import string
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ALPHABET = string.ascii_uppercase


# ---------------------------------------------------------------------------
# 1. Fundamental concepts
# ---------------------------------------------------------------------------

def normalize_letters(text: str) -> str:
    """Return only alphabetic ASCII characters in uppercase."""
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def validate_key(key: str) -> str:
    """
    Validate a monoalphabetic substitution key.

    A key is a permutation of the 26-letter alphabet. For example:
        QWERTYUIOPASDFGHJKLZXCVBNM

    Every plaintext letter must map to exactly one ciphertext letter, and
    every ciphertext letter must have exactly one plaintext predecessor.
    """
    normalized = normalize_letters(key)

    if len(normalized) != 26:
        raise ValueError("A substitution key must contain exactly 26 letters.")

    if len(set(normalized)) != 26:
        raise ValueError("A substitution key cannot contain duplicate letters.")

    return normalized


def preserve_case(original: str, replacement: str) -> str:
    """Preserve the case of a replaced character."""
    if original.isupper():
        return replacement.upper()
    if original.islower():
        return replacement.lower()
    return replacement


# ---------------------------------------------------------------------------
# 2. Caesar cipher
# ---------------------------------------------------------------------------

def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypt text with a Caesar substitution.

    Mathematical model:
        C = (P + k) mod 26

    where P is the numerical plaintext letter and k is the shift.
    """
    result = []

    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            encrypted = chr((ord(ch) - base + shift) % 26 + base)
            result.append(encrypted)
        else:
            result.append(ch)

    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt a Caesar cipher using the inverse shift."""
    return caesar_encrypt(text, -shift)


def demonstrate_caesar() -> None:
    plaintext = "Attack at dawn!"
    ciphertext = caesar_encrypt(plaintext, 3)
    recovered = caesar_decrypt(ciphertext, 3)

    print("\n=== Caesar Cipher ===")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Decrypted :", recovered)

    print("\nAll 26 Caesar decryptions:")
    sample = "KHOOR"
    for shift in range(26):
        print(f"shift={shift:2d}: {caesar_decrypt(sample, shift)}")


# ---------------------------------------------------------------------------
# 3. General monoalphabetic substitution
# ---------------------------------------------------------------------------

def build_substitution_maps(key: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Build encryption and decryption dictionaries.

    If key[i] is the ciphertext replacement for ALPHABET[i], then:
        A -> key[0]
        B -> key[1]
        ...
    """
    key = validate_key(key)

    encryption = dict(zip(ALPHABET, key))
    decryption = {cipher: plain for plain, cipher in encryption.items()}

    return encryption, decryption


def substitute_text(
    text: str,
    mapping: Dict[str, str],
    preserve_nonletters: bool = True,
) -> str:
    """Apply a substitution mapping to text."""
    result = []

    for ch in text:
        upper = ch.upper()

        if upper in mapping:
            replacement = mapping[upper]
            result.append(preserve_case(ch, replacement))
        elif preserve_nonletters:
            result.append(ch)

    return "".join(result)


def substitution_encrypt(text: str, key: str) -> str:
    """Encrypt with a general monoalphabetic substitution."""
    encryption, _ = build_substitution_maps(key)
    return substitute_text(text, encryption)


def substitution_decrypt(text: str, key: str) -> str:
    """Decrypt with a general monoalphabetic substitution."""
    _, decryption = build_substitution_maps(key)
    return substitute_text(text, decryption)


def demonstrate_general_substitution() -> None:
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    plaintext = "Meet me near the old bridge at seven."

    ciphertext = substitution_encrypt(plaintext, key)
    recovered = substitution_decrypt(ciphertext, key)

    print("\n=== General Monoalphabetic Substitution ===")
    print("Key       :", key)
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)


# ---------------------------------------------------------------------------
# 4. Random key generation
# ---------------------------------------------------------------------------

def generate_random_key(seed: Optional[int] = None) -> str:
    """
    Generate a random permutation of the alphabet.

    A supplied seed is useful for reproducible demonstrations.
    For real cryptographic key generation, use the operating system's secure
    random facilities rather than the standard pseudo-random generator.
    """
    rng = random.Random(seed)
    letters = list(ALPHABET)
    rng.shuffle(letters)
    return "".join(letters)


def demonstrate_random_key() -> None:
    key = generate_random_key(seed=42)
    plaintext = "Substitution ciphers replace symbols according to a key."
    ciphertext = substitution_encrypt(plaintext, key)

    print("\n=== Random Substitution Key ===")
    print("Generated key:", key)
    print("Plaintext    :", plaintext)
    print("Ciphertext   :", ciphertext)
    print("Recovered    :", substitution_decrypt(ciphertext, key))


# ---------------------------------------------------------------------------
# 5. Key inversion and validation
# ---------------------------------------------------------------------------

def invert_key(key: str) -> str:
    """
    Return the inverse permutation.

    If A -> Q, then Q -> A in the inverse key.
    """
    key = validate_key(key)
    inverse = [""] * 26

    for plain_index, cipher_letter in enumerate(key):
        cipher_index = ord(cipher_letter) - ord("A")
        inverse[cipher_index] = ALPHABET[plain_index]

    return "".join(inverse)


def demonstrate_key_properties() -> None:
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    inverse = invert_key(key)

    print("\n=== Key Properties ===")
    print("Encryption key:", key)
    print("Inverse key   :", inverse)

    for letter in "ABCXYZ":
        encrypted = substitution_encrypt(letter, key)
        decrypted = substitution_decrypt(encrypted, key)
        print(f"{letter} -> {encrypted} -> {decrypted}")


# ---------------------------------------------------------------------------
# 6. Frequency analysis
# ---------------------------------------------------------------------------

ENGLISH_FREQUENCIES = {
    "E": 0.1270,
    "T": 0.0906,
    "A": 0.0817,
    "O": 0.0751,
    "I": 0.0697,
    "N": 0.0675,
    "S": 0.0633,
    "H": 0.0609,
    "R": 0.0599,
    "D": 0.0425,
    "L": 0.0403,
    "C": 0.0278,
    "U": 0.0276,
    "M": 0.0241,
    "W": 0.0236,
    "F": 0.0223,
    "G": 0.0202,
    "Y": 0.0197,
    "P": 0.0193,
    "B": 0.0149,
    "V": 0.0098,
    "K": 0.0077,
    "J": 0.0015,
    "X": 0.0015,
    "Q": 0.0010,
    "Z": 0.0007,
}


COMMON_BIGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
}

COMMON_TRIGRAMS = {
    "THE", "AND", "ING", "HER", "ERE", "ENT", "THA", "NTH", "WAS",
    "ETH", "FOR", "DTH", "HAT", "ION", "TIO",
}

COMMON_WORDS = {
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT", "HE",
    "WAS", "FOR", "ON", "ARE", "AS", "WITH", "HIS", "THEY", "I",
    "AT", "BE", "THIS", "HAVE", "FROM", "OR", "ONE", "HAD", "BY",
    "WORD", "BUT", "NOT", "WHAT", "ALL", "WERE", "WE", "WHEN",
}


def letter_frequency(text: str) -> Dict[str, int]:
    """Count letters in normalized text."""
    counts = collections.Counter(normalize_letters(text))
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def frequency_table(text: str) -> List[Tuple[str, int, float]]:
    """Return letters, counts, and percentages sorted by count."""
    normalized = normalize_letters(text)
    counts = collections.Counter(normalized)
    total = len(normalized)

    if total == 0:
        return []

    return [
        (letter, counts.get(letter, 0), counts.get(letter, 0) / total * 100)
        for letter in ALPHABET
    ]


def print_frequency_table(text: str) -> None:
    print("\nLetter frequency:")
    for letter, count, percentage in sorted(
        frequency_table(text),
        key=lambda row: (-row[1], row[0]),
    ):
        if count:
            print(f"{letter}: {count:4d} ({percentage:6.2f}%)")


def demonstrate_frequency_analysis() -> None:
    text = """
    Cryptanalysis studies the structure of encrypted messages.
    A monoalphabetic substitution preserves many statistical properties
    of the underlying language, including approximate letter frequencies.
    """
    print("\n=== Frequency Analysis ===")
    print_frequency_table(text)


# ---------------------------------------------------------------------------
# 7. N-gram analysis
# ---------------------------------------------------------------------------

def ngram_counts(text: str, n: int) -> collections.Counter:
    """Count contiguous n-letter sequences."""
    normalized = normalize_letters(text)

    if n <= 0:
        raise ValueError("n must be positive.")

    return collections.Counter(
        normalized[index:index + n]
        for index in range(len(normalized) - n + 1)
    )


def demonstrate_ngrams() -> None:
    text = """
    The three most important concepts in classical cryptanalysis are
    patterns, frequency, and repeated structures.
    """

    print("\n=== N-Gram Analysis ===")

    for n in (1, 2, 3):
        print(f"\nTop {n}-grams:")
        for gram, count in ngram_counts(text, n).most_common(10):
            print(f"{gram}: {count}")


# ---------------------------------------------------------------------------
# 8. Pattern signatures
# ---------------------------------------------------------------------------

def pattern_signature(word: str) -> Tuple[int, ...]:
    """
    Convert a word into a structural pattern.

    Example:
        PAPER -> (0, 1, 0, 2, 3)
        because P=A? Actually repeated letters determine equal positions.

    A precise example:
        LEVEL -> (0, 1, 2, 2, 1)
    """
    normalized = normalize_letters(word)
    indexes: Dict[str, int] = {}
    next_index = 0
    signature = []

    for char in normalized:
        if char not in indexes:
            indexes[char] = next_index
            next_index += 1
        signature.append(indexes[char])

    return tuple(signature)


def demonstrate_pattern_signatures() -> None:
    print("\n=== Pattern Signatures ===")

    for word in ["LEVEL", "PAPER", "APPLE", "TEST", "HELLO", "CRYPTO"]:
        print(f"{word:8s} -> {pattern_signature(word)}")


# ---------------------------------------------------------------------------
# 9. Word-aware substitution helpers
# ---------------------------------------------------------------------------

def words_in_text(text: str) -> List[str]:
    """Extract alphabetic words while preserving word boundaries."""
    words = []
    current = []

    for ch in text.upper():
        if ch in ALPHABET:
            current.append(ch)
        elif current:
            words.append("".join(current))
            current.clear()

    if current:
        words.append("".join(current))

    return words


def candidate_plaintext_words(
    cipher_word: str,
    dictionary: Iterable[str],
) -> List[str]:
    """
    Return dictionary words with the same length and pattern signature.

    This is a useful cryptanalysis constraint because a substitution cipher
    preserves equality relationships between repeated letters.
    """
    normalized_cipher = normalize_letters(cipher_word)
    signature = pattern_signature(normalized_cipher)

    candidates = []

    for candidate in dictionary:
        normalized_candidate = normalize_letters(candidate)

        if len(normalized_candidate) != len(normalized_cipher):
            continue

        if pattern_signature(normalized_candidate) == signature:
            candidates.append(normalized_candidate)

    return candidates


def demonstrate_pattern_matching() -> None:
    dictionary = [
        "LEVEL",
        "HELLO",
        "APPLE",
        "PAPER",
        "RADAR",
        "REFER",
        "METER",
        "TEST",
        "SHEEP",
        "QUEUE",
        "BANANA",
        "CRANE",
    ]

    print("\n=== Pattern-Based Candidate Matching ===")

    for cipher_word in ["XQXQ", "ABBCD", "ABACA"]:
        candidates = candidate_plaintext_words(cipher_word, dictionary)
        print(f"{cipher_word:8s} -> {candidates}")


# ---------------------------------------------------------------------------
# 10. Known-plaintext reasoning
# ---------------------------------------------------------------------------

def derive_partial_mapping(
    plaintext: str,
    ciphertext: str,
) -> Dict[str, str]:
    """
    Derive plaintext -> ciphertext relationships from aligned messages.

    This demonstrates why knowledge of even part of the plaintext can reveal
    substantial information about a monoalphabetic substitution.
    """
    plain = normalize_letters(plaintext)
    cipher = normalize_letters(ciphertext)

    if len(plain) != len(cipher):
        raise ValueError("Plaintext and ciphertext must have equal letter counts.")

    mapping: Dict[str, str] = {}

    for p, c in zip(plain, cipher):
        existing = mapping.get(p)

        if existing is not None and existing != c:
            raise ValueError(
                f"Inconsistent mapping: plaintext {p} maps to both "
                f"{existing} and {c}."
            )

        mapping[p] = c

    if len(set(mapping.values())) != len(mapping):
        raise ValueError("Mapping is not one-to-one.")

    return mapping


def demonstrate_known_plaintext() -> None:
    plaintext = "MEET"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = substitution_encrypt(plaintext, key)

    print("\n=== Known-Plaintext Mapping ===")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Derived   :", derive_partial_mapping(plaintext, ciphertext))


# ---------------------------------------------------------------------------
# 11. Affine cipher
# ---------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Greatest common divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def modular_inverse(a: int, modulus: int) -> Optional[int]:
    """Find a^-1 mod modulus by brute force for the small teaching case."""
    a %= modulus

    for candidate in range(1, modulus):
        if (a * candidate) % modulus == 1:
            return candidate

    return None


def affine_encrypt(text: str, a: int, b: int) -> str:
    """
    Affine cipher:
        C = (aP + b) mod 26

    Security requirement:
        gcd(a, 26) must equal 1, otherwise encryption is not a permutation.
    """
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26.")

    result = []

    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            p = ord(ch) - base
            c = (a * p + b) % 26
            result.append(chr(base + c))
        else:
            result.append(ch)

    return "".join(result)


def affine_decrypt(text: str, a: int, b: int) -> str:
    """Inverse affine transformation."""
    inverse_a = modular_inverse(a, 26)

    if inverse_a is None:
        raise ValueError("a has no modular inverse modulo 26.")

    result = []

    for ch in text:
        if ch.upper() in ALPHABET:
            base = ord("A") if ch.isupper() else ord("a")
            c = ord(ch) - base
            p = (inverse_a * (c - b)) % 26
            result.append(chr(base + p))
        else:
            result.append(ch)

    return "".join(result)


def demonstrate_affine() -> None:
    plaintext = "Affine ciphers are mathematical substitutions."
    ciphertext = affine_encrypt(plaintext, a=5, b=8)
    recovered = affine_decrypt(ciphertext, a=5, b=8)

    print("\n=== Affine Cipher ===")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)


# ---------------------------------------------------------------------------
# 12. Atbash
# ---------------------------------------------------------------------------

def atbash(text: str) -> str:
    """Atbash maps A<->Z, B<->Y, C<->X, and so forth."""
    mapping = {
        plain: cipher
        for plain, cipher in zip(ALPHABET, ALPHABET[::-1])
    }
    return substitute_text(text, mapping)


def demonstrate_atbash() -> None:
    plaintext = "Atbash is a reciprocal substitution."
    encrypted = atbash(plaintext)

    print("\n=== Atbash ===")
    print("Plaintext :", plaintext)
    print("Transformed:", encrypted)
    print("Recovered :", atbash(encrypted))


# ---------------------------------------------------------------------------
# 13. Cryptanalysis scoring
# ---------------------------------------------------------------------------

def score_frequency_similarity(text: str) -> float:
    """
    Compute a simple chi-square-based English frequency score.

    Lower chi-square is closer to expected English frequencies.
    This is only a rough statistical measure and should not be treated as
    a complete plaintext detector.
    """
    normalized = normalize_letters(text)

    if not normalized:
        return float("inf")

    observed = collections.Counter(normalized)
    total = len(normalized)
    chi_square = 0.0

    for letter in ALPHABET:
        expected = ENGLISH_FREQUENCIES[letter] * total
        actual = observed.get(letter, 0)

        if expected > 0:
            chi_square += (actual - expected) ** 2 / expected

    return chi_square


def score_english_structure(text: str) -> float:
    """
    Combine rough unigram, bigram, trigram, and word evidence.

    Higher scores indicate more English-like structure.
    """
    normalized = normalize_letters(text)

    if not normalized:
        return float("-inf")

    score = 0.0

    counts_2 = ngram_counts(normalized, 2)
    counts_3 = ngram_counts(normalized, 3)

    for gram in COMMON_BIGRAMS:
        score += counts_2.get(gram, 0) * 1.0

    for gram in COMMON_TRIGRAMS:
        score += counts_3.get(gram, 0) * 2.5

    for word in words_in_text(text):
        if word in COMMON_WORDS:
            score += 5.0

    score -= score_frequency_similarity(normalized) * 0.02

    return score


def demonstrate_scoring() -> None:
    examples = [
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        "QXZV JKLPM NQWERTY ZZZXQ",
        "THIS IS A SIMPLE ENGLISH MESSAGE",
    ]

    print("\n=== English-Likeness Scoring ===")

    for text in examples:
        print(f"{score_english_structure(text):10.2f} | {text}")


# ---------------------------------------------------------------------------
# 14. Simple Caesar cryptanalysis
# ---------------------------------------------------------------------------

def crack_caesar(text: str) -> List[Tuple[float, int, str]]:
    """
    Try all 26 Caesar keys and rank them using English-frequency distance.

    This is intentionally exhaustive because Caesar has only 26 possible
    shifts.
    """
    candidates = []

    for shift in range(26):
        plaintext = caesar_decrypt(text, shift)
        score = score_frequency_similarity(plaintext)
        candidates.append((score, shift, plaintext))

    return sorted(candidates, key=lambda item: item[0])


def demonstrate_caesar_cracking() -> None:
    ciphertext = caesar_encrypt(
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        11,
    )

    print("\n=== Caesar Cryptanalysis ===")
    print("Ciphertext:", ciphertext)
    print("Best candidates:")

    for score, shift, plaintext in crack_caesar(ciphertext)[:5]:
        print(f"score={score:8.2f}, shift={shift:2d}, {plaintext}")


# ---------------------------------------------------------------------------
# 15. Demonstrating why substitution is not modern encryption
# ---------------------------------------------------------------------------

def substitution_keyspace() -> int:
    """Return 26!, the number of possible monoalphabetic substitutions."""
    return math.factorial(26)


def estimate_keyspace_digits() -> int:
    """Number of decimal digits in 26!."""
    return len(str(substitution_keyspace()))


def demonstrate_keyspace() -> None:
    print("\n=== Keyspace ===")
    print("26! =", substitution_keyspace())
    print("Decimal digits:", estimate_keyspace_digits())

    print(
        "\nA large keyspace alone does not make a cipher secure. "
        "A substitution cipher leaks statistical structure because the same "
        "plaintext letter always produces the same ciphertext letter."
    )


# ---------------------------------------------------------------------------
# 16. Practical message-preserving encryption
# ---------------------------------------------------------------------------

@dataclass
class SubstitutionCipher:
    """Reusable object-oriented substitution cipher."""

    key: str

    def __post_init__(self) -> None:
        self.key = validate_key(self.key)
        self._encrypt_map, self._decrypt_map = build_substitution_maps(self.key)

    def encrypt(self, text: str) -> str:
        return substitute_text(text, self._encrypt_map)

    def decrypt(self, text: str) -> str:
        return substitute_text(text, self._decrypt_map)

    @property
    def inverse_key(self) -> str:
        return invert_key(self.key)


def demonstrate_class_api() -> None:
    cipher = SubstitutionCipher("MNBVCXZLKJHGFDSAPOIUYTREWQ")
    plaintext = "A reusable class makes encryption operations easier to test."

    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print("\n=== Object-Oriented API ===")
    print("Key       :", cipher.key)
    print("Inverse   :", cipher.inverse_key)
    print("Plaintext :", plaintext)
    print("Ciphertext:", encrypted)
    print("Decrypted :", decrypted)


# ---------------------------------------------------------------------------
# 17. Self-tests
# ---------------------------------------------------------------------------

def run_self_tests() -> None:
    """Verify important invariants and edge cases."""
    print("\n=== Self Tests ===")

    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    message = "Hello, World! 123"

    encrypted = substitution_encrypt(message, key)
    decrypted = substitution_decrypt(encrypted, key)

    assert decrypted == message
    assert substitution_decrypt("", key) == ""
    assert caesar_decrypt(caesar_encrypt(message, 13), 13) == message
    assert affine_decrypt(affine_encrypt(message, 5, 8), 5, 8) == message
    assert atbash(atbash(message)) == message

    assert gcd(5, 26) == 1
    assert modular_inverse(5, 26) == 21
    assert pattern_signature("LEVEL") == (0, 1, 2, 2, 1)

    try:
        validate_key("AAAAAAAAAAAAAAAAAAAAAAAAAA")
    except ValueError:
        pass
    else:
        raise AssertionError("Duplicate-key validation failed.")

    try:
        affine_encrypt("TEST", 2, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("Affine coprimality validation failed.")

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# 18. Integrated cryptanalysis case study
# ---------------------------------------------------------------------------

def simulated_cryptanalysis_case() -> None:
    """
    Encrypt a realistic educational message and inspect the ciphertext.

    The purpose is to demonstrate what an analyst can observe without knowing
    the key: repeated letters, word lengths, frequency distributions, and
    structural patterns.
    """
    key = "PHQGIUMEAYLNOFDXJKRCVSTZWB"

    plaintext = (
        "The archive contains three sealed records. "
        "The first record describes a bridge inspection. "
        "The second record describes a laboratory inventory. "
        "The third record contains a schedule for routine maintenance."
    )

    cipher = SubstitutionCipher(key)
    ciphertext = cipher.encrypt(plaintext)

    print("\n=== Integrated Case Study ===")
    print("Ciphertext:")
    print(ciphertext)

    print("\nMost common ciphertext letters:")
    for letter, count in letter_frequency(ciphertext).items():
        print(f"{letter}: {count}")

    print("\nCiphertext word patterns:")
    for word in words_in_text(ciphertext)[:20]:
        print(f"{word:15s} -> {pattern_signature(word)}")

    print("\nKnown-key verification:")
    print(cipher.decrypt(ciphertext))


# ---------------------------------------------------------------------------
# 19. Security and implementation notes
# ---------------------------------------------------------------------------

def print_security_notes() -> None:
    print(
        """
=== Security Notes ===

1. Caesar, Atbash, affine, and monoalphabetic substitution are classical
   educational ciphers rather than modern secure encryption.

2. Monoalphabetic substitution preserves letter equality patterns:
       plaintext A repeated twice -> ciphertext letter repeated twice.

3. Long messages reveal frequency information more reliably than short
   messages because statistical estimates become more stable.

4. Spaces and punctuation can expose word boundaries if they are preserved.

5. Known plaintext, guessed words, repeated phrases, and language statistics
   can combine to recover a substitution mapping.

6. A modern application should use a reviewed cryptographic construction and
   a vetted implementation rather than inventing a cipher.

7. Encryption and authentication solve different problems. Confidentiality
   does not automatically prove that a message was not modified.
"""
    )


# ---------------------------------------------------------------------------
# 20. Main program
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 78)
    print("SUBSTITUTION CIPHERS: COMPLETE EDUCATIONAL STUDY PROGRAM")
    print("=" * 78)

    demonstrate_caesar()
    demonstrate_general_substitution()
    demonstrate_random_key()
    demonstrate_key_properties()
    demonstrate_frequency_analysis()
    demonstrate_ngrams()
    demonstrate_pattern_signatures()
    demonstrate_pattern_matching()
    demonstrate_known_plaintext()
    demonstrate_affine()
    demonstrate_atbash()
    demonstrate_scoring()
    demonstrate_caesar_cracking()
    demonstrate_keyspace()
    demonstrate_class_api()
    run_self_tests()
    simulated_cryptanalysis_case()
    print_security_notes()

    print("\nProgram completed successfully.")


if __name__ == "__main__":
    main()
