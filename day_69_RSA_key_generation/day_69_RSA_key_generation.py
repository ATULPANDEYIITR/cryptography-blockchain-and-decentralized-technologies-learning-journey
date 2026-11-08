#!/usr/bin/env python3
"""
RSA Key Generation and Management
Python 3.10+

Dependency:
    pip install cryptography

Generates RSA key pairs, validates parameters, exports PEM files,
calculates public-key fingerprints, and verifies digital signatures.

Production keys must be generated using a vetted cryptographic library.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("rsa-key-generation")


class RSAConfigurationError(Exception):
    """Raised when RSA configuration is invalid."""


class RSAOperationError(Exception):
    """Raised when an RSA operation fails."""


@dataclass(frozen=True)
class RSAConfig:
    key_size: int = 3072
    public_exponent: int = 65537
    output_directory: Path = Path("rsa_keys")

    def validate(self) -> None:
        if self.key_size not in (2048, 3072, 4096):
            raise RSAConfigurationError(
                "Key size must be 2048, 3072, or 4096 bits."
            )

        if self.public_exponent != 65537:
            raise RSAConfigurationError(
                "This implementation requires public exponent 65537."
            )


@dataclass
class RSAKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    fingerprint: str

    @property
    def modulus_bits(self) -> int:
        return self.public_key.key_size

    @property
    def public_exponent(self) -> int:
        return self.public_key.public_numbers().e


class RSAKeyManager:
    """Manages RSA generation, serialization, signatures, and validation."""

    def __init__(self, config: RSAConfig):
        config.validate()
        self.config = config

    @staticmethod
    def calculate_fingerprint(public_key: rsa.RSAPublicKey) -> str:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_pem).hexdigest()

    def generate(self) -> RSAKeyPair:
        logger.info(
            "Generating RSA key pair with %d-bit modulus.",
            self.config.key_size,
        )

        try:
            private_key = rsa.generate_private_key(
                public_exponent=self.config.public_exponent,
                key_size=self.config.key_size,
            )

            public_key = private_key.public_key()

            pair = RSAKeyPair(
                private_key=private_key,
                public_key=public_key,
                fingerprint=self.calculate_fingerprint(public_key),
            )

            self.validate_pair(pair)

            logger.info("RSA key pair generated successfully.")
            return pair

        except Exception as exc:
            raise RSAOperationError(
                f"RSA key generation failed: {exc}"
            ) from exc

    @staticmethod
    def validate_pair(pair: RSAKeyPair) -> None:
        numbers = pair.private_key.private_numbers()

        if pair.private_key.key_size < 2048:
            raise RSAConfigurationError("RSA modulus is too small.")

        if numbers.public_numbers.e != 65537:
            raise RSAConfigurationError("Unexpected public exponent.")

        if numbers.p == numbers.q:
            raise RSAConfigurationError("RSA prime factors must differ.")

        if pair.private_key.public_key().public_numbers() != (
            pair.public_key.public_numbers()
        ):
            raise RSAConfigurationError("Public/private key mismatch.")

        expected = RSAKeyManager.calculate_fingerprint(pair.public_key)

        if expected != pair.fingerprint:
            raise RSAConfigurationError("Fingerprint validation failed.")

    def export_keys(
        self,
        pair: RSAKeyPair,
        passphrase: str,
    ) -> tuple[Path, Path]:
        if len(passphrase) < 12:
            raise RSAConfigurationError(
                "Private-key passphrase must contain at least 12 characters."
            )

        output = self.config.output_directory
        output.mkdir(parents=True, exist_ok=True)

        private_path = output / "private_key.pem"
        public_path = output / "public_key.pem"

        private_data = pair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            ),
        )

        public_data = pair.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create files exclusively to avoid silently overwriting existing keys.
        private_fd = os.open(
            private_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        try:
            with os.fdopen(private_fd, "wb") as file:
                file.write(private_data)

            public_fd = os.open(
                public_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )

            with os.fdopen(public_fd, "wb") as file:
                file.write(public_data)

        except Exception:
            # Remove incomplete output when an export operation fails.
            private_path.unlink(missing_ok=True)
            public_path.unlink(missing_ok=True)
            raise

        logger.info("Private and public keys exported.")
        return private_path, public_path

    @staticmethod
    def load_private_key(
        path: Path,
        passphrase: str,
    ) -> rsa.RSAPrivateKey:
        try:
            key = serialization.load_pem_private_key(
                path.read_bytes(),
                password=passphrase.encode("utf-8"),
            )

            if not isinstance(key, rsa.RSAPrivateKey):
                raise RSAOperationError("The supplied key is not an RSA key.")

            return key

        except (ValueError, TypeError) as exc:
            raise RSAOperationError(
                "Unable to load private key. Check the file and passphrase."
            ) from exc

    @staticmethod
    def load_public_key(path: Path) -> rsa.RSAPublicKey:
        try:
            key = serialization.load_pem_public_key(path.read_bytes())

            if not isinstance(key, rsa.RSAPublicKey):
                raise RSAOperationError("The supplied key is not an RSA key.")

            return key

        except (ValueError, TypeError) as exc:
            raise RSAOperationError(
                "Unable to load public key."
            ) from exc

    @staticmethod
    def sign(
        private_key: rsa.RSAPrivateKey,
        message: bytes,
    ) -> bytes:
        if not message:
            raise RSAConfigurationError("Message cannot be empty.")

        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def verify(
        public_key: rsa.RSAPublicKey,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True

        except InvalidSignature:
            return False

    @staticmethod
    def encrypt(
        public_key: rsa.RSAPublicKey,
        plaintext: bytes,
    ) -> bytes:
        if not plaintext:
            raise RSAConfigurationError("Plaintext cannot be empty.")

        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def decrypt(
        private_key: rsa.RSAPrivateKey,
        ciphertext: bytes,
    ) -> bytes:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


def run_tests(manager: RSAKeyManager, pair: RSAKeyPair) -> None:
    message = b"RSA key generation security verification."

    signature = manager.sign(pair.private_key, message)

    assert manager.verify(pair.public_key, message, signature)

    assert not manager.verify(
        pair.public_key,
        b"Modified message",
        signature,
    )

    ciphertext = manager.encrypt(pair.public_key, message)
    plaintext = manager.decrypt(pair.private_key, ciphertext)

    assert plaintext == message

    logger.info("Digital signature tests passed.")
    logger.info("RSA encryption/decryption tests passed.")

    try:
        manager.decrypt(pair.private_key, ciphertext[:-1])
        raise AssertionError("Invalid ciphertext was unexpectedly accepted.")
    except ValueError:
        logger.info("Invalid ciphertext correctly rejected.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and validate RSA key pairs."
    )

    parser.add_argument(
        "--bits",
        type=int,
        choices=(2048, 3072, 4096),
        default=3072,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("rsa_keys"),
    )

    parser.add_argument(
        "--passphrase",
        help="Private-key encryption passphrase.",
    )

    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Run cryptographic tests without exporting keys.",
    )

    args = parser.parse_args()

    try:
        config = RSAConfig(
            key_size=args.bits,
            output_directory=args.output,
        )

        manager = RSAKeyManager(config)
        pair = manager.generate()

        print("\nRSA KEY GENERATION")
        print("------------------")
        print(f"Modulus size: {pair.modulus_bits} bits")
        print(f"Public exponent: {pair.public_exponent}")
        print(f"SHA-256 fingerprint: {pair.fingerprint}")

        run_tests(manager, pair)

        if not args.test_only:
            passphrase = args.passphrase or os.environ.get(
                "RSA_KEY_PASSPHRASE"
            )

            if not passphrase:
                import getpass
                passphrase = getpass.getpass(
                    "Enter private-key encryption passphrase: "
                )

            private_path, public_path = manager.export_keys(
                pair,
                passphrase,
            )

            print(f"Private key: {private_path}")
            print(f"Public key: {public_path}")

        return 0

    except (RSAConfigurationError, RSAOperationError, OSError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
