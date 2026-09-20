"""
Day 20: Plaintext, Ciphertext, Keys, Encryption and Decryption

Reusable cryptographic utilities for the Day 20 learning project.

This module uses Fernet from the Python cryptography package.
Fernet provides authenticated symmetric encryption.

Educational flow:

    Plaintext + secret key
            |
            v
       Encryption
            |
            v
       Ciphertext
            |
            | + same secret key
            v
       Decryption
            |
            v
       Plaintext

Do not implement cryptographic algorithms from scratch for
production security. Use established, reviewed cryptographic
libraries and protocols.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate and return a new Fernet symmetric encryption key."""
    return Fernet.generate_key()


def encrypt_text(plaintext: str, key: bytes) -> str:
    """
    Encrypt a plaintext string with a Fernet key.

    Parameters
    ----------
    plaintext:
        Human-readable text that should be protected.

    key:
        Fernet encryption key in bytes.

    Returns
    -------
    str
        Ciphertext represented as a URL-safe Base64 string.

    Raises
    ------
    TypeError
        If plaintext or key has an incorrect type.

    ValueError
        If plaintext is empty.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not plaintext:
        raise ValueError("plaintext cannot be empty")

    cipher = Fernet(key)

    ciphertext = cipher.encrypt(
        plaintext.encode("utf-8")
    )

    return ciphertext.decode("utf-8")


def decrypt_text(ciphertext: str, key: bytes) -> str:
    """
    Decrypt Fernet ciphertext with the correct key.

    Parameters
    ----------
    ciphertext:
        Encrypted data represented as a string.

    key:
        The same Fernet key used for encryption.

    Returns
    -------
    str
        The original plaintext.

    Raises
    ------
    TypeError
        If ciphertext or key has an incorrect type.

    ValueError
        If ciphertext is empty, the key is invalid, or the
        ciphertext cannot be authenticated/decrypted.
    """
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a string")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not ciphertext:
        raise ValueError("ciphertext cannot be empty")

    try:
        cipher = Fernet(key)

        plaintext = cipher.decrypt(
            ciphertext.encode("utf-8")
        )

    except (InvalidToken, ValueError, TypeError) as exc:
        raise ValueError(
            "Decryption failed: the key may be incorrect or "
            "the ciphertext may have been modified."
        ) from exc

    return plaintext.decode("utf-8")


def demonstrate_round_trip(plaintext: str) -> dict[str, str]:
    """
    Perform a complete encryption/decryption round trip.

    The function creates a fresh key, encrypts the plaintext,
    decrypts the ciphertext, and returns all educational values.
    """
    key = generate_key()

    ciphertext = encrypt_text(
        plaintext,
        key,
    )

    recovered_plaintext = decrypt_text(
        ciphertext,
        key,
    )

    return {
        "key": key.decode("utf-8"),
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "decrypted_plaintext": recovered_plaintext,
    }


if __name__ == "__main__":
    example_plaintext = (
        "Plaintext is transformed into ciphertext using "
        "a secret encryption key."
    )

    result = demonstrate_round_trip(
        example_plaintext
    )

    print("=" * 72)
    print("DAY 20 - CRYPTOGRAPHY UTILITY DEMONSTRATION")
    print("=" * 72)
    print()
    print(f"Plaintext:\n{result['plaintext']}")
    print()
    print(f"Key:\n{result['key']}")
    print()
    print(f"Ciphertext:\n{result['ciphertext']}")
    print()
    print(f"Decrypted plaintext:\n{result['decrypted_plaintext']}")
    print()
    print(
        "Successful round trip:",
        result["plaintext"] == result["decrypted_plaintext"],
    )
    print("=" * 72)