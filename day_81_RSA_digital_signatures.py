#!/usr/bin/env python3
"""
RSA Digital Signatures
----------------------
RSA-PSS signatures using SHA-256.

Dependency:
    python -m pip install cryptography

Features:
    - RSA key generation
    - Secure private/public key serialization
    - RSA-PSS signing and verification
    - SHA-256 message digests
    - Canonical JSON serialization
    - Signature tampering detection
    - Key fingerprinting
    - Signature records and validation
    - File signing and verification
    - Negative test cases

RSA-PSS is preferred over textbook RSA and legacy PKCS#1 v1.5
for new digital-signature applications.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("rsa-signatures")


class SignatureStatus(Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    ERROR = "ERROR"


class SignatureError(Exception):
    """Base exception for signature operations."""


class KeyValidationError(SignatureError):
    """Raised when RSA key material is invalid."""


@dataclass(frozen=True)
class SignatureRecord:
    algorithm: str
    key_fingerprint: str
    message_digest: str
    signature: str
    created_at: str
    status: SignatureStatus


class RSASignatureManager:
    """
    Manages RSA-PSS signing and verification.

    Private keys never participate in verification.
    Public keys are sufficient to verify signatures.
    """

    HASH_NAME = "SHA256"
    ALGORITHM = "RSA-PSS-SHA256"

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey | None = None,
        public_key: rsa.RSAPublicKey | None = None,
    ):
        self.private_key = private_key
        self.public_key = public_key or (
            private_key.public_key() if private_key else None
        )

        self._validate_keys()

    def _validate_keys(self) -> None:
        for key in (self.private_key, self.public_key):
            if key is not None:
                if not isinstance(
                    key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)
                ):
                    raise KeyValidationError("Unsupported key type.")

                if key.key_size < 2048:
                    raise KeyValidationError(
                        "RSA keys must contain at least 2048 bits."
                    )

        if self.private_key and self.public_key:
            if (
                self.private_key.public_key().public_numbers()
                != self.public_key.public_numbers()
            ):
                raise KeyValidationError(
                    "Private and public keys do not match."
                )

    @classmethod
    def generate(cls, key_size: int = 3072) -> RSASignatureManager:
        if key_size not in (2048, 3072, 4096):
            raise ValueError(
                "Supported key sizes are 2048, 3072 and 4096."
            )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        return cls(private_key=private_key)

    @staticmethod
    def _pss_padding() -> padding.PSS:
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

    @staticmethod
    def digest(message: bytes) -> str:
        return hashlib.sha256(message).hexdigest()

    @staticmethod
    def fingerprint(public_key: rsa.RSAPublicKey) -> str:
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def canonical_json(data: Any) -> bytes:
        """
        Produces deterministic JSON bytes.

        Applications must agree on the canonicalization rules
        before independently signing and verifying structured data.
        """
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def sign(self, message: bytes) -> SignatureRecord:
        if self.private_key is None:
            raise SignatureError("A private key is required for signing.")

        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")

        signature = self.private_key.sign(
            message,
            self._pss_padding(),
            hashes.SHA256(),
        )

        return SignatureRecord(
            algorithm=self.ALGORITHM,
            key_fingerprint=self.fingerprint(self.public_key),
            message_digest=self.digest(message),
            signature=base64.b64encode(signature).decode("ascii"),
            created_at=datetime.now(timezone.utc).isoformat(),
            status=SignatureStatus.VALID,
        )

    def verify(
        self,
        message: bytes,
        signature: bytes,
    ) -> SignatureStatus:
        if self.public_key is None:
            raise SignatureError("A public key is required for verification.")

        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")

        if not isinstance(signature, bytes):
            raise TypeError("Signature must be bytes.")

        try:
            self.public_key.verify(
                signature,
                message,
                self._pss_padding(),
                hashes.SHA256(),
            )
            return SignatureStatus.VALID

        except InvalidSignature:
            return SignatureStatus.INVALID

        except ValueError:
            return SignatureStatus.INVALID

    def verify_record(
        self,
        message: bytes,
        record: SignatureRecord,
    ) -> SignatureStatus:
        if record.algorithm != self.ALGORITHM:
            return SignatureStatus.INVALID

        if record.key_fingerprint != self.fingerprint(self.public_key):
            return SignatureStatus.INVALID

        if record.message_digest != self.digest(message):
            return SignatureStatus.INVALID

        try:
            signature = base64.b64decode(
                record.signature,
                validate=True,
            )
        except (ValueError, TypeError):
            return SignatureStatus.INVALID

        return self.verify(message, signature)

    def export_private_key(
        self,
        password: bytes | None = None,
    ) -> bytes:
        if self.private_key is None:
            raise SignatureError("No private key available.")

        encryption = (
            BestAvailableEncryption(password)
            if password
            else NoEncryption()
        )

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def export_public_key(self) -> bytes:
        if self.public_key is None:
            raise SignatureError("No public key available.")

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def load_private_key(
        cls,
        pem_data: bytes,
        password: bytes | None = None,
    ) -> RSASignatureManager:
        try:
            key = serialization.load_pem_private_key(
                pem_data,
                password=password,
            )
            if not isinstance(key, rsa.RSAPrivateKey):
                raise KeyValidationError("PEM does not contain an RSA key.")

            return cls(private_key=key)

        except (ValueError, TypeError) as exc:
            raise KeyValidationError(
                "Unable to load private key."
            ) from exc

    @classmethod
    def load_public_key(
        cls,
        pem_data: bytes,
    ) -> RSASignatureManager:
        try:
            key = serialization.load_pem_public_key(pem_data)

            if not isinstance(key, rsa.RSAPublicKey):
                raise KeyValidationError("PEM does not contain an RSA key.")

            return cls(public_key=key)

        except (ValueError, TypeError) as exc:
            raise KeyValidationError(
                "Unable to load public key."
            ) from exc

    def sign_file(self, path: Path) -> SignatureRecord:
        if not path.is_file():
            raise FileNotFoundError(path)

        if path.is_symlink():
            raise SignatureError("Symbolic links are not accepted.")

        # Read in binary mode to preserve the exact signed bytes.
        with path.open("rb") as file:
            message = file.read()

        return self.sign(message)

    def verify_file(
        self,
        path: Path,
        record: SignatureRecord,
    ) -> SignatureStatus:
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(path)

        with path.open("rb") as file:
            message = file.read()

        return self.verify_record(message, record)


def save_key_files(
    manager: RSASignatureManager,
    directory: Path,
    password: bytes,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)

    private_path = directory / "rsa_private.pem"
    public_path = directory / "rsa_public.pem"

    private_path.write_bytes(manager.export_private_key(password))
    public_path.write_bytes(manager.export_public_key())

    try:
        os.chmod(private_path, 0o600)
    except OSError:
        logger.warning("Unable to restrict private-key file permissions.")

    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")


def demonstration() -> None:
    print("\nRSA DIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 48)

    manager = RSASignatureManager.generate(3072)

    document = {
        "document_id": "DOC-2026-001",
        "issuer": "Repository Governance Service",
        "purpose": "Release authorization",
        "version": 1,
        "approved": True,
    }

    message = manager.canonical_json(document)

    record = manager.sign(message)
    signature = base64.b64decode(record.signature)

    print("Algorithm:", record.algorithm)
    print("Key fingerprint:", record.key_fingerprint)
    print("SHA-256:", record.message_digest)
    print("Signature size:", len(signature), "bytes")

    print(
        "Original verification:",
        manager.verify_record(message, record).value,
    )

    modified_document = dict(document)
    modified_document["approved"] = False

    modified_message = manager.canonical_json(modified_document)

    print(
        "Modified message:",
        manager.verify_record(modified_message, record).value,
    )

    damaged_signature = bytearray(signature)
    damaged_signature[0] ^= 1

    print(
        "Modified signature:",
        manager.verify(modified_message, bytes(damaged_signature)).value,
    )

    public_manager = RSASignatureManager.load_public_key(
        manager.export_public_key()
    )

    print(
        "Public-key-only verification:",
        public_manager.verify(message, signature).value,
    )

    try:
        public_manager.sign(message)
    except SignatureError as exc:
        print("Expected signing failure:", exc)

    # Private-key encryption protects the key at rest.
    encrypted = manager.export_private_key(b"Example-Password-2026!")

    restored = RSASignatureManager.load_private_key(
        encrypted,
        b"Example-Password-2026!",
    )

    print(
        "Restored-key verification:",
        restored.verify_record(message, record).value,
    )

    assert manager.verify_record(message, record) == SignatureStatus.VALID
    assert (
        manager.verify_record(modified_message, record)
        == SignatureStatus.INVALID
    )
    assert public_manager.verify(message, signature) == SignatureStatus.VALID

    print("\nAll demonstration assertions passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RSA-PSS digital signature utility."
    )

    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate RSA keys.",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=3072,
        choices=(2048, 3072, 4096),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("rsa_keys"),
    )
    parser.add_argument(
        "--password",
        help="Password used to encrypt the private key.",
    )

    args = parser.parse_args()

    try:
        if args.generate:
            password = args.password

            if not password:
                raise ValueError(
                    "Provide --password to encrypt the private key."
                )

            manager = RSASignatureManager.generate(args.key_size)

            save_key_files(
                manager,
                args.output,
                password.encode("utf-8"),
            )
        else:
            demonstration()

        return 0

    except (SignatureError, ValueError, OSError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
