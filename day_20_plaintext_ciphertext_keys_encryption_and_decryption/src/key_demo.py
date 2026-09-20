"""
Day 20: Encryption Key Demonstration

This program explains the role of a cryptographic key in symmetric
encryption.

Important educational distinction:

    Plaintext + Key -> Encryption -> Ciphertext

    Ciphertext + Key -> Decryption -> Plaintext

The program also demonstrates that using a different key for
decryption causes authentication/decryption to fail.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate a new Fernet symmetric key."""
    return Fernet.generate_key()


def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext using a Fernet key."""
    return Fernet(key).encrypt(
        plaintext.encode("utf-8")
    ).decode("utf-8")


def decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypt ciphertext using a Fernet key."""
    return Fernet(key).decrypt(
        ciphertext.encode("utf-8")
    ).decode("utf-8")


def print_title(title: str) -> None:
    """Print a formatted section title."""
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def main() -> None:
    """Run the key demonstration."""

    plaintext = (
        "A cryptographic key controls access to encrypted information."
    )

    print_title("DAY 20 - CRYPTOGRAPHIC KEY DEMONSTRATION")

    print("Plaintext:")
    print(plaintext)

    print_title("1. Generate the correct key")

    correct_key = generate_key()

    print("Correct key:")
    print(correct_key.decode("utf-8"))

    print_title("2. Encrypt the plaintext")

    ciphertext = encrypt(plaintext, correct_key)

    print("Ciphertext:")
    print(ciphertext)

    print_title("3. Decrypt using the correct key")

    recovered = decrypt(ciphertext, correct_key)

    print("Recovered plaintext:")
    print(recovered)

    if recovered == plaintext:
        print()
        print("SUCCESS: the original plaintext was recovered.")

    print_title("4. Generate a different key")

    wrong_key = generate_key()

    print("Different key:")
    print(wrong_key.decode("utf-8"))

    print()
    print(
        "This key is not the key that was used to encrypt the message."
    )

    print_title("5. Attempt decryption with the wrong key")

    try:
        decrypt(ciphertext, wrong_key)
        print("Unexpected result: decryption succeeded.")
    except InvalidToken:
        print(
            "EXPECTED RESULT: decryption failed because the wrong "
            "key was supplied."
        )

    print_title("6. Key lesson")

    print("Encryption:")
    print("    Plaintext + correct key -> Ciphertext")

    print()
    print("Decryption:")
    print("    Ciphertext + correct key -> Plaintext")

    print()
    print("Wrong key:")
    print("    Ciphertext + wrong key -> Decryption failure")

    print()
    print(
        "A key is not the plaintext and is not the ciphertext. "
        "It is secret cryptographic material used by the encryption "
        "and decryption process."
    )


if __name__ == "__main__":
    main()