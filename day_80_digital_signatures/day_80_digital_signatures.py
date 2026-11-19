#!/usr/bin/env python3
"""
Digital Signatures: Cryptographic Signing, Verification, Key Management,
Certificate Validation, Revocation, and Audit.

Dependency:
    pip install cryptography

Uses Ed25519 for digital signatures and SHA-256 for document fingerprints.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import tempfile
import unittest

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

LOGGER = logging.getLogger("digital-signatures")


class SignatureError(Exception):
    """Base exception for signature operations."""


class KeyManagementError(SignatureError):
    """Raised for invalid key operations."""


class DocumentError(SignatureError):
    """Raised for invalid document operations."""


class VerificationError(SignatureError):
    """Raised when verification cannot be completed."""


class KeyStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class VerificationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    REVOKED_KEY = "revoked_key"
    UNKNOWN_KEY = "unknown_key"
    EXPIRED_KEY = "expired_key"


@dataclass
class KeyRecord:
    key_id: str
    owner: str
    public_key: Ed25519PublicKey
    created_at: datetime
    expires_at: Optional[datetime] = None
    status: KeyStatus = KeyStatus.ACTIVE
    revoked_at: Optional[datetime] = None

    def is_usable(self, at: datetime) -> bool:
        if self.status != KeyStatus.ACTIVE:
            return False

        if self.expires_at and at >= self.expires_at:
            return False

        return True


@dataclass
class DigitalSignature:
    signature_id: str
    key_id: str
    owner: str
    algorithm: str
    document_hash: str
    signature: bytes
    signed_at: datetime
    document_name: str


@dataclass
class VerificationResult:
    status: VerificationStatus
    message: str
    document_hash: str
    key_id: str


class KeyManager:
    """Maintains public-key records and private-key ownership."""

    def __init__(self):
        self._private_keys: dict[str, Ed25519PrivateKey] = {}
        self._records: dict[str, KeyRecord] = {}

    def generate_key_pair(
        self,
        owner: str,
        validity_days: Optional[int] = 365
    ) -> str:

        if not owner or not owner.strip():
            raise KeyManagementError("Owner cannot be empty.")

        if validity_days is not None and validity_days <= 0:
            raise KeyManagementError("Validity must be positive.")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        key_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)

        expiry = None
        if validity_days is not None:
            from datetime import timedelta
            expiry = now + timedelta(days=validity_days)

        self._private_keys[key_id] = private_key

        self._records[key_id] = KeyRecord(
            key_id=key_id,
            owner=owner.strip(),
            public_key=public_key,
            created_at=now,
            expires_at=expiry
        )

        LOGGER.info("Generated key pair for %s", owner)

        return key_id

    def get_private_key(self, key_id: str) -> Ed25519PrivateKey:
        if key_id not in self._private_keys:
            raise KeyManagementError(
                "Private key is unavailable."
            )

        record = self._records[key_id]

        if not record.is_usable(datetime.now(timezone.utc)):
            raise KeyManagementError(
                "Private key is not authorized for signing."
            )

        return self._private_keys[key_id]

    def get_public_record(self, key_id: str) -> KeyRecord:
        if key_id not in self._records:
            raise KeyManagementError("Unknown key identifier.")

        return self._records[key_id]

    def revoke_key(self, key_id: str) -> None:
        record = self.get_public_record(key_id)

        if record.status == KeyStatus.REVOKED:
            raise KeyManagementError("Key is already revoked.")

        record.status = KeyStatus.REVOKED
        record.revoked_at = datetime.now(timezone.utc)

        # Remove signing capability from this manager.
        self._private_keys.pop(key_id, None)

        LOGGER.warning("Revoked key %s", key_id)

    def export_public_key(self, key_id: str) -> bytes:
        record = self.get_public_record(key_id)

        return record.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def import_public_key(
        self,
        pem_data: bytes,
        owner: str
    ) -> str:

        try:
            public_key = serialization.load_pem_public_key(
                pem_data
            )
        except (ValueError, TypeError) as exc:
            raise KeyManagementError(
                "Invalid public-key encoding."
            ) from exc

        if not isinstance(public_key, Ed25519PublicKey):
            raise KeyManagementError(
                "Only Ed25519 public keys are supported."
            )

        key_id = secrets.token_hex(16)

        self._records[key_id] = KeyRecord(
            key_id=key_id,
            owner=owner,
            public_key=public_key,
            created_at=datetime.now(timezone.utc)
        )

        return key_id


class DocumentStore:
    """Provides controlled document loading and hashing."""

    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024

    @staticmethod
    def load(path: str | Path) -> bytes:
        file_path = Path(path)

        if not file_path.is_file():
            raise DocumentError("Document does not exist.")

        if file_path.stat().st_size > DocumentStore.MAX_DOCUMENT_SIZE:
            raise DocumentError("Document exceeds maximum size.")

        return file_path.read_bytes()

    @staticmethod
    def fingerprint(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def validate_content(data: bytes) -> None:
        if not isinstance(data, bytes):
            raise DocumentError("Document must be supplied as bytes.")

        if not data:
            raise DocumentError("Empty documents cannot be signed.")

        if len(data) > DocumentStore.MAX_DOCUMENT_SIZE:
            raise DocumentError("Document exceeds maximum size.")


class SignatureService:
    """Creates and verifies Ed25519 digital signatures."""

    ALGORITHM = "Ed25519"
    HASH_ALGORITHM = "SHA-256"

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.signatures: dict[str, DigitalSignature] = {}

    def sign(
        self,
        key_id: str,
        document: bytes,
        document_name: str
    ) -> DigitalSignature:

        DocumentStore.validate_content(document)

        if not document_name or not document_name.strip():
            raise DocumentError("Document name is required.")

        private_key = self.key_manager.get_private_key(key_id)
        record = self.key_manager.get_public_record(key_id)

        signature_bytes = private_key.sign(document)

        signature = DigitalSignature(
            signature_id=secrets.token_hex(16),
            key_id=key_id,
            owner=record.owner,
            algorithm=self.ALGORITHM,
            document_hash=DocumentStore.fingerprint(document),
            signature=signature_bytes,
            signed_at=datetime.now(timezone.utc),
            document_name=document_name.strip()
        )

        self.signatures[signature.signature_id] = signature

        LOGGER.info(
            "Signed document %s using key %s",
            document_name,
            key_id
        )

        return signature

    def verify(
        self,
        signature: DigitalSignature,
        document: bytes,
        at: Optional[datetime] = None
    ) -> VerificationResult:

        DocumentStore.validate_content(document)

        current_time = at or datetime.now(timezone.utc)

        if signature.algorithm != self.ALGORITHM:
            return VerificationResult(
                VerificationStatus.INVALID,
                "Unsupported signature algorithm.",
                DocumentStore.fingerprint(document),
                signature.key_id
            )

        try:
            record = self.key_manager.get_public_record(
                signature.key_id
            )
        except KeyManagementError:
            return VerificationResult(
                VerificationStatus.UNKNOWN_KEY,
                "Public key is not registered.",
                DocumentStore.fingerprint(document),
                signature.key_id
            )

        actual_hash = DocumentStore.fingerprint(document)

        if actual_hash != signature.document_hash:
            return VerificationResult(
                VerificationStatus.INVALID,
                "Document content has changed.",
                actual_hash,
                signature.key_id
            )

        if record.status == KeyStatus.REVOKED:
            return VerificationResult(
                VerificationStatus.REVOKED_KEY,
                "Signing key has been revoked.",
                actual_hash,
                signature.key_id
            )

        if record.expires_at and current_time >= record.expires_at:
            return VerificationResult(
                VerificationStatus.EXPIRED_KEY,
                "Signing key has expired.",
                actual_hash,
                signature.key_id
            )

        try:
            record.public_key.verify(
                signature.signature,
                document
            )
        except InvalidSignature:
            return VerificationResult(
                VerificationStatus.INVALID,
                "Cryptographic verification failed.",
                actual_hash,
                signature.key_id
            )

        return VerificationResult(
            VerificationStatus.VALID,
            "Signature and document integrity verified.",
            actual_hash,
            signature.key_id
        )

    def verify_detached(
        self,
        public_key: Ed25519PublicKey,
        signature_bytes: bytes,
        document: bytes
    ) -> bool:

        DocumentStore.validate_content(document)

        try:
            public_key.verify(signature_bytes, document)
            return True
        except InvalidSignature:
            return False


class SignatureArchive:
    """Persists detached signatures and metadata."""

    @staticmethod
    def save(
        signature: DigitalSignature,
        directory: str | Path
    ) -> Path:

        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        data = {
            "signature_id": signature.signature_id,
            "key_id": signature.key_id,
            "owner": signature.owner,
            "algorithm": signature.algorithm,
            "hash_algorithm": "SHA-256",
            "document_hash": signature.document_hash,
            "signature": base64.b64encode(
                signature.signature
            ).decode("ascii"),
            "signed_at": signature.signed_at.isoformat(),
            "document_name": signature.document_name
        }

        output = directory / f"{signature.signature_id}.json"

        with output.open("x", encoding="utf-8") as file:
            json.dump(data, file, indent=2)

        return output

    @staticmethod
    def load(path: str | Path) -> DigitalSignature:
        try:
            with Path(path).open("r", encoding="utf-8") as file:
                data = json.load(file)

            if data["algorithm"] != "Ed25519":
                raise SignatureError("Unsupported stored algorithm.")

            return DigitalSignature(
                signature_id=data["signature_id"],
                key_id=data["key_id"],
                owner=data["owner"],
                algorithm=data["algorithm"],
                document_hash=data["document_hash"],
                signature=base64.b64decode(
                    data["signature"],
                    validate=True
                ),
                signed_at=datetime.fromisoformat(data["signed_at"]),
                document_name=data["document_name"]
            )

        except (OSError, KeyError, ValueError, TypeError) as exc:
            raise SignatureError(
                "Unable to load signature archive."
            ) from exc


class SignatureTests(unittest.TestCase):

    def setUp(self):
        self.manager = KeyManager()
        self.service = SignatureService(self.manager)

        self.key_id = self.manager.generate_key_pair(
            "Research Department"
        )

        self.document = b"Approved research agreement version 1"

    def test_valid_signature(self):
        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        result = self.service.verify(
            signature,
            self.document
        )

        self.assertEqual(
            result.status,
            VerificationStatus.VALID
        )

    def test_tampered_document(self):
        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        result = self.service.verify(
            signature,
            b"Modified agreement"
        )

        self.assertEqual(
            result.status,
            VerificationStatus.INVALID
        )

    def test_revoked_key(self):
        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        self.manager.revoke_key(self.key_id)

        result = self.service.verify(
            signature,
            self.document
        )

        self.assertEqual(
            result.status,
            VerificationStatus.REVOKED_KEY
        )

    def test_wrong_key(self):
        other_key = Ed25519PrivateKey.generate()

        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        self.assertFalse(
            self.service.verify_detached(
                other_key.public_key(),
                signature.signature,
                self.document
            )
        )

    def test_empty_document(self):
        with self.assertRaises(DocumentError):
            self.service.sign(
                self.key_id,
                b"",
                "empty.txt"
            )

    def test_public_key_export_import(self):
        pem = self.manager.export_public_key(self.key_id)

        imported_id = self.manager.import_public_key(
            pem,
            "External Auditor"
        )

        imported = self.manager.get_public_record(imported_id)

        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        self.assertTrue(
            self.service.verify_detached(
                imported.public_key,
                signature.signature,
                self.document
            )
        )

    def test_archive_round_trip(self):
        signature = self.service.sign(
            self.key_id,
            self.document,
            "agreement.pdf"
        )

        with tempfile.TemporaryDirectory() as directory:
            path = SignatureArchive.save(
                signature,
                directory
            )

            loaded = SignatureArchive.load(path)

            self.assertEqual(
                loaded.signature,
                signature.signature
            )


def demonstration():
    manager = KeyManager()
    service = SignatureService(manager)

    key_id = manager.generate_key_pair(
        "Digital Governance Department",
        validity_days=365
    )

    document = (
        b"Digital contract: Contract ID 2026-001. "
        b"Approved for execution."
    )

    signature = service.sign(
        key_id,
        document,
        "contract-2026-001.txt"
    )

    print("\nDIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 48)

    print("Algorithm:", signature.algorithm)
    print("Hash:", signature.document_hash)
    print("Key ID:", signature.key_id)
    print("Signature:", base64.b64encode(
        signature.signature
    ).decode("ascii"))

    valid = service.verify(signature, document)

    print("\nOriginal document:", valid.status.value)
    print(valid.message)

    modified = service.verify(
        signature,
        document + b" Unauthorized modification."
    )

    print("\nModified document:", modified.status.value)
    print(modified.message)

    public_key = manager.get_public_record(
        key_id
    ).public_key

    print(
        "\nDetached verification:",
        service.verify_detached(
            public_key,
            signature.signature,
            document
        )
    )

    with tempfile.TemporaryDirectory() as directory:
        archive_path = SignatureArchive.save(
            signature,
            directory
        )

        print("\nSignature archive:", archive_path.name)


if __name__ == "__main__":
    demonstration()
    print("\nRUNNING AUTOMATED TESTS")
    unittest.main(argv=["digital_signatures.py"], exit=False)
