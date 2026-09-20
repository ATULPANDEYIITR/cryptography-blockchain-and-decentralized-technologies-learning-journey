"""
Day 20: Plaintext, Ciphertext, Keys, Encryption and Decryption

Main command-line demonstration for the learning project.

The program shows the complete lifecycle:

    Plaintext
        |
        | encryption + secret key
        v
    Ciphertext
        |
        | decryption + same secret key
        v
    Plaintext

The implementation uses Fernet from the Python cryptography package.
It does not implement cryptographic algorithms from scratch.
"""

from __future__ import annotations

import argparse
import sys

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate a new symmetric encryption key."""
    return Fernet.generate_key()


def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext using the supplied Fernet key."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")

    return Fernet(key).encrypt(
        plaintext.encode("utf-8")
    ).decode("utf-8")


def decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypt ciphertext using the supplied Fernet key."""
    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty.")

    try:
        return Fernet(key).decrypt(
            ciphertext.encode("utf-8")
        ).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed. Check the encryption key and "
            "make sure the ciphertext has not been modified."
        ) from exc


def print_separator() -> None:
    """Print a visual separator."""
    print("=" * 72)


def demonstrate(message: str) -> None:
    """Run and display a complete encryption/decryption demonstration."""
    print_separator()
    print("DAY 20 - PLAINTEXT, CIPHERTEXT, KEYS,")
    print("         ENCRYPTION AND DECRYPTION")
    print_separator()
    print()

    print("1. Original data")
    print("-" * 72)
    print(f"Plaintext:\n{message}")
    print()

    key = generate_key()

    print("2. Generated encryption key")
    print("-" * 72)
    print(key.decode("utf-8"))
    print()
    print(
        "The key is sensitive information. Anyone who obtains the key "
        "may be able to decrypt data protected by it."
    )
    print()

    ciphertext = encrypt(message, key)

    print("3. Encryption")
    print("-" * 72)
    print("The plaintext is transformed into ciphertext.")
    print()
    print(f"Ciphertext:\n{ciphertext}")
    print()

    recovered = decrypt(ciphertext, key)

    print("4. Decryption")
    print("-" * 72)
    print("The ciphertext is transformed back into plaintext.")
    print()
    print(f"Recovered plaintext:\n{recovered}")
    print()

    print("5. Verification")
    print("-" * 72)

    if recovered == message:
        print("SUCCESS: decrypted text matches the original plaintext.")
    else:
        print("ERROR: decrypted text does not match the original plaintext.")

    print()
    print_separator()


def encrypt_mode(message: str) -> None:
    """Generate a key and encrypt a supplied message."""
    key = generate_key()
    ciphertext = encrypt(message, key)

    print_separator()
    print("ENCRYPTION RESULT")
    print_separator()
    print(f"Plaintext : {message}")
    print(f"Key       : {key.decode('utf-8')}")
    print(f"Ciphertext: {ciphertext}")
    print_separator()


def decrypt_mode(ciphertext: str, key_text: str) -> None:
    """Decrypt supplied ciphertext using a supplied key."""
    try:
        key = key_text.encode("utf-8")
        plaintext = decrypt(ciphertext, key)
    except (ValueError, TypeError) as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    print_separator()
    print("DECRYPTION RESULT")
    print_separator()
    print(f"Ciphertext: {ciphertext}")
    print(f"Plaintext : {plaintext}")
    print_separator()


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Educational demonstration of plaintext, ciphertext, "
            "keys, encryption and decryption."
        )
    )

    parser.add_argument(
        "--message",
        default=(
            "Cryptography protects information by transforming "
            "readable data into protected ciphertext."
        ),
        help="Plaintext message used by the demonstration.",
    )

    parser.add_argument(
        "--encrypt",
        metavar="TEXT",
        help="Encrypt TEXT and print the generated key and ciphertext.",
    )

    parser.add_argument(
        "--decrypt",
        metavar="CIPHERTEXT",
        help="Decrypt CIPHERTEXT using --key.",
    )

    parser.add_argument(
        "--key",
        help="Fernet key used with --decrypt.",
    )

    return parser


def main() -> None:
    """Application entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.encrypt is not None:
        encrypt_mode(args.encrypt)
        return

    if args.decrypt is not None:
        if not args.key:
            parser.error("--decrypt requires --key")

        decrypt_mode(args.decrypt, args.key)
        return

    demonstrate(args.message)


if __name__ == "__main__":
    main()