"""
Tests for Day 20 encryption and decryption demonstrations.
"""

from cryptography.fernet import Fernet

from src.crypto_utils import (
    decrypt_text,
    demonstrate_round_trip,
    encrypt_text,
    generate_key,
)


def test_key_generation_returns_valid_fernet_key():
    """A generated key should be accepted by Fernet."""
    key = generate_key()

    cipher = Fernet(key)

    assert cipher is not None


def test_encryption_produces_ciphertext_different_from_plaintext():
    """Encrypted output should not equal the original plaintext."""
    key = generate_key()
    plaintext = "This is a plaintext message."

    ciphertext = encrypt_text(plaintext, key)

    assert ciphertext != plaintext


def test_decryption_recovers_original_plaintext():
    """Correct decryption should recover the original message."""
    key = generate_key()
    plaintext = "Encryption transforms readable information."

    ciphertext = encrypt_text(plaintext, key)
    recovered = decrypt_text(ciphertext, key)

    assert recovered == plaintext


def test_round_trip_contains_expected_values():
    """The complete demonstration should successfully round-trip."""
    plaintext = "Plaintext becomes ciphertext and can be recovered."

    result = demonstrate_round_trip(plaintext)

    assert result["plaintext"] == plaintext
    assert result["decrypted_plaintext"] == plaintext
    assert result["ciphertext"] != plaintext
    assert result["key"]


def test_wrong_key_fails_decryption():
    """A different key should not decrypt the ciphertext."""
    key = generate_key()
    wrong_key = generate_key()
    plaintext = "This message requires the correct key."

    ciphertext = encrypt_text(plaintext, key)

    try:
        decrypt_text(ciphertext, wrong_key)
    except ValueError as exc:
        assert "Decryption failed" in str(exc)
    else:
        raise AssertionError(
            "Decryption unexpectedly succeeded with the wrong key."
        )


def test_modified_ciphertext_fails_decryption():
    """Changing ciphertext should cause authenticated decryption to fail."""
    key = generate_key()
    plaintext = "Ciphertext integrity matters."

    ciphertext = encrypt_text(plaintext, key)

    modified_ciphertext = (
        ciphertext[:-1]
        + ("A" if ciphertext[-1] != "A" else "B")
    )

    try:
        decrypt_text(modified_ciphertext, key)
    except ValueError as exc:
        assert "Decryption failed" in str(exc)
    else:
        raise AssertionError(
            "Modified ciphertext was unexpectedly accepted."
        )


def test_empty_plaintext_is_rejected():
    """Empty plaintext should not be encrypted by the helper."""
    key = generate_key()

    try:
        encrypt_text("", key)
    except ValueError as exc:
        assert "plaintext cannot be empty" in str(exc)
    else:
        raise AssertionError("Empty plaintext was unexpectedly accepted.")


def test_empty_ciphertext_is_rejected():
    """Empty ciphertext should not be passed to decryption."""
    key = generate_key()

    try:
        decrypt_text("", key)
    except ValueError as exc:
        assert "ciphertext cannot be empty" in str(exc)
    else:
        raise AssertionError("Empty ciphertext was unexpectedly accepted.")