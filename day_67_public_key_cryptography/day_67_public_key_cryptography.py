#!/usr/bin/env python3
"""
Public-Key Cryptography: RSA, Digital Signatures, and Secure Communication.

Dependency:
    pip install cryptography

Run:
    python public_key_cryptography.py

Demonstrates:
    - RSA key-pair generation
    - Public and private key separation
    - PEM serialization
    - Public-key encryption
    - Private-key decryption
    - Digital signatures
    - Signature verification
    - SHA-256 hashing
    - Hybrid encryption using AES-GCM and RSA-OAEP
    - Key fingerprints
    - Tampering detection
    - Key rotation and validation

Security note:
RSA is used for key establishment and signatures.
AES-GCM encrypts application data efficiently.
Private keys must remain confidential.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class KeyValidationError(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass


class SignatureVerificationError(CryptoError):
    pass


class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    key_id: str
    created_at: datetime
    status: KeyStatus = KeyStatus.ACTIVE

    @classmethod
    def generate(cls, key_size: int = 3072) -> "KeyPair":
        if key_size not in (2048, 3072, 4096):
            raise KeyValidationError(
                "RSA key size must be 2048, 3072, or 4096 bits."
            )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        key_id = hashlib.sha256(public_pem).hexdigest()

        return cls(
            private_key=private_key,
            public_key=public_key,
            key_id=key_id,
            created_at=datetime.now(timezone.utc),
        )

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_pem(self, password: Optional[bytes] = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def load_public(pem: bytes) -> rsa.RSAPublicKey:
        key = serialization.load_pem_public_key(pem)

        if not isinstance(key, rsa.RSAPublicKey):
            raise KeyValidationError("Expected an RSA public key.")

        return key

    @staticmethod
    def load_private(
        pem: bytes,
        password: Optional[bytes] = None,
    ) -> rsa.RSAPrivateKey:
        key = serialization.load_pem_private_key(
            pem,
            password=password,
        )

        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyValidationError("Expected an RSA private key.")

        return key

    def revoke(self) -> None:
        self.status = KeyStatus.REVOKED

    def rotate(self) -> None:
        if self.status != KeyStatus.ACTIVE:
            raise KeyValidationError("Only active keys can be rotated.")

        self.status = KeyStatus.ROTATED


class RSAService:
    """Provides RSA encryption and digital signature operations."""

    @staticmethod
    def encrypt(
        public_key: rsa.RSAPublicKey,
        plaintext: bytes,
    ) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes.")

        # RSA-OAEP uses SHA-256 for secure padding and masking.
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def decrypt(
        private_key: rsa.RSAPrivateKey,
        ciphertext: bytes,
    ) -> bytes:
        try:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as exc:
            raise DecryptionError(
                "Decryption failed. Invalid ciphertext or incorrect key."
            ) from exc

    @staticmethod
    def sign(
        private_key: rsa.RSAPrivateKey,
        message: bytes,
    ) -> bytes:
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
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
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError):
            return False


@dataclass
class EncryptedEnvelope:
    encrypted_session_key: bytes
    nonce: bytes
    ciphertext: bytes
    recipient_key_id: str
    algorithm: str = "AES-256-GCM + RSA-OAEP-SHA256"

    def to_json(self) -> str:
        return json.dumps({
            "algorithm": self.algorithm,
            "recipient_key_id": self.recipient_key_id,
            "encrypted_session_key": base64.b64encode(
                self.encrypted_session_key
            ).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(
                self.ciphertext
            ).decode("ascii"),
        }, indent=2)

    @classmethod
    def from_json(cls, value: str) -> "EncryptedEnvelope":
        try:
            data = json.loads(value)

            if data["algorithm"] != "AES-256-GCM + RSA-OAEP-SHA256":
                raise CryptoError("Unsupported encryption algorithm.")

            return cls(
                encrypted_session_key=base64.b64decode(
                    data["encrypted_session_key"],
                    validate=True,
                ),
                nonce=base64.b64decode(
                    data["nonce"],
                    validate=True,
                ),
                ciphertext=base64.b64decode(
                    data["ciphertext"],
                    validate=True,
                ),
                recipient_key_id=data["recipient_key_id"],
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise CryptoError("Invalid encrypted envelope.") from exc


class HybridEncryption:
    """
    Encrypts large messages with AES-GCM.

    RSA encrypts only the randomly generated AES session key.
    """

    @staticmethod
    def encrypt(
        recipient: KeyPair,
        plaintext: bytes,
    ) -> EncryptedEnvelope:
        if recipient.status != KeyStatus.ACTIVE:
            raise KeyValidationError("Recipient key is not active.")

        session_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        # Bind the recipient key identifier to the authenticated data.
        aad = recipient.key_id.encode("ascii")

        ciphertext = AESGCM(session_key).encrypt(
            nonce,
            plaintext,
            aad,
        )

        encrypted_session_key = RSAService.encrypt(
            recipient.public_key,
            session_key,
        )

        return EncryptedEnvelope(
            encrypted_session_key=encrypted_session_key,
            nonce=nonce,
            ciphertext=ciphertext,
            recipient_key_id=recipient.key_id,
        )

    @staticmethod
    def decrypt(
        recipient: KeyPair,
        envelope: EncryptedEnvelope,
    ) -> bytes:
        if recipient.status == KeyStatus.REVOKED:
            raise KeyValidationError("Recipient key has been revoked.")

        if envelope.recipient_key_id != recipient.key_id:
            raise KeyValidationError("Recipient key identifier mismatch.")

        try:
            session_key = RSAService.decrypt(
                recipient.private_key,
                envelope.encrypted_session_key,
            )

            return AESGCM(session_key).decrypt(
                envelope.nonce,
                envelope.ciphertext,
                recipient.key_id.encode("ascii"),
            )

        except (DecryptionError, InvalidTag, ValueError) as exc:
            raise DecryptionError(
                "Envelope authentication or decryption failed."
            ) from exc


class KeyStore:
    """Maintains public-key records and key lifecycle information."""

    def __init__(self):
        self.keys: dict[str, KeyPair] = {}

    def register(self, key_pair: KeyPair) -> None:
        if key_pair.key_id in self.keys:
            raise KeyValidationError("Key already registered.")

        self.keys[key_pair.key_id] = key_pair

    def get_active(self, key_id: str) -> KeyPair:
        key = self.keys.get(key_id)

        if key is None:
            raise KeyValidationError("Unknown key identifier.")

        if key.status != KeyStatus.ACTIVE:
            raise KeyValidationError("Key is not active.")

        return key

    def revoke(self, key_id: str) -> None:
        key = self.keys.get(key_id)

        if key is None:
            raise KeyValidationError("Unknown key identifier.")

        key.revoke()


class DigitalCertificate:
    """
    Simplified educational certificate representation.

    The issuer signature is verified using the issuer's public key.
    This is not a complete X.509 implementation.
    """

    def __init__(
        self,
        subject: str,
        public_key_pem: bytes,
        issuer: str,
        issuer_key_id: str,
        expires_at: datetime,
        signature: bytes,
    ):
        self.subject = subject
        self.public_key_pem = public_key_pem
        self.issuer = issuer
        self.issuer_key_id = issuer_key_id
        self.expires_at = expires_at
        self.signature = signature

    def signed_content(self) -> bytes:
        return json.dumps({
            "subject": self.subject,
            "public_key": base64.b64encode(
                self.public_key_pem
            ).decode("ascii"),
            "issuer": self.issuer,
            "issuer_key_id": self.issuer_key_id,
            "expires_at": self.expires_at.isoformat(),
        }, sort_keys=True).encode("utf-8")

    @classmethod
    def issue(
        cls,
        subject: str,
        subject_key: KeyPair,
        issuer: str,
        issuer_key: KeyPair,
        expires_at: datetime,
    ) -> "DigitalCertificate":
        if issuer_key.status != KeyStatus.ACTIVE:
            raise KeyValidationError("Issuer key is not active.")

        if expires_at <= datetime.now(timezone.utc):
            raise KeyValidationError("Certificate expiry must be in the future.")

        certificate = cls(
            subject=subject,
            public_key_pem=subject_key.public_pem(),
            issuer=issuer,
            issuer_key_id=issuer_key.key_id,
            expires_at=expires_at,
            signature=b"",
        )

        certificate.signature = RSAService.sign(
            issuer_key.private_key,
            certificate.signed_content(),
        )

        return certificate

    def verify(self, issuer_key: KeyPair) -> bool:
        if issuer_key.status != KeyStatus.ACTIVE:
            return False

        if issuer_key.key_id != self.issuer_key_id:
            return False

        if datetime.now(timezone.utc) >= self.expires_at:
            return False

        return RSAService.verify(
            issuer_key.public_key,
            self.signed_content(),
            self.signature,
        )


def save_key_pair(key_pair: KeyPair, directory: Path) -> None:
    """
    Demonstration-only storage.

    Production private keys should use encrypted storage,
    an HSM, or a managed key service.
    """
    directory.mkdir(parents=True, exist_ok=True)

    public_path = directory / f"{key_pair.key_id}.public.pem"
    private_path = directory / f"{key_pair.key_id}.private.pem"

    public_path.write_bytes(key_pair.public_pem())

    private_path.write_bytes(
        key_pair.private_pem(password=b"Example-Password-2026")
    )

    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass


class CryptographyTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sender = KeyPair.generate(2048)
        cls.receiver = KeyPair.generate(2048)

    def test_rsa_encryption(self):
        message = b"Confidential transaction"
        encrypted = RSAService.encrypt(
            self.receiver.public_key,
            message,
        )
        decrypted = RSAService.decrypt(
            self.receiver.private_key,
            encrypted,
        )
        self.assertEqual(message, decrypted)

    def test_signature(self):
        message = b"Approved financial transaction"
        signature = RSAService.sign(
            self.sender.private_key,
            message,
        )
        self.assertTrue(
            RSAService.verify(
                self.sender.public_key,
                message,
                signature,
            )
        )

    def test_modified_message(self):
        message = b"Original"
        signature = RSAService.sign(
            self.sender.private_key,
            message,
        )
        self.assertFalse(
            RSAService.verify(
                self.sender.public_key,
                b"Modified",
                signature,
            )
        )

    def test_hybrid_encryption(self):
        message = b"Large encrypted document" * 100
        envelope = HybridEncryption.encrypt(
            self.receiver,
            message,
        )
        result = HybridEncryption.decrypt(
            self.receiver,
            envelope,
        )
        self.assertEqual(message, result)

    def test_tampering(self):
        envelope = HybridEncryption.encrypt(
            self.receiver,
            b"Sensitive data",
        )
        envelope.ciphertext = envelope.ciphertext[:-1] + bytes([
            envelope.ciphertext[-1] ^ 1
        ])

        with self.assertRaises(DecryptionError):
            HybridEncryption.decrypt(self.receiver, envelope)

    def test_envelope_serialization(self):
        envelope = HybridEncryption.encrypt(
            self.receiver,
            b"Serialized message",
        )
        restored = EncryptedEnvelope.from_json(envelope.to_json())

        self.assertEqual(
            b"Serialized message",
            HybridEncryption.decrypt(self.receiver, restored),
        )

    def test_wrong_key(self):
        envelope = HybridEncryption.encrypt(
            self.receiver,
            b"Private data",
        )

        with self.assertRaises(KeyValidationError):
            HybridEncryption.decrypt(self.sender, envelope)


def demonstrate():
    print("=" * 65)
    print("PUBLIC-KEY CRYPTOGRAPHY DEMONSTRATION")
    print("=" * 65)

    alice = KeyPair.generate(2048)
    bob = KeyPair.generate(2048)

    print("\n1. RSA KEY GENERATION")
    print("Alice public key fingerprint:", alice.key_id[:32])
    print("Bob public key fingerprint:", bob.key_id[:32])

    print("\n2. PUBLIC-KEY ENCRYPTION")
    message = b"Hello Bob. This message is confidential."

    encrypted = RSAService.encrypt(
        bob.public_key,
        message,
    )

    print("Original:", message.decode())
    print("Ciphertext length:", len(encrypted))

    decrypted = RSAService.decrypt(
        bob.private_key,
        encrypted,
    )

    print("Decrypted:", decrypted.decode())
    assert decrypted == message

    print("\n3. DIGITAL SIGNATURE")
    document = b"Payment authorization: transaction-1001"

    signature = RSAService.sign(
        alice.private_key,
        document,
    )

    print("Signature generated:", len(signature), "bytes")

    verified = RSAService.verify(
        alice.public_key,
        document,
        signature,
    )

    print("Original document verified:", verified)

    modified = document + b" modified"

    print(
        "Modified document verified:",
        RSAService.verify(
            alice.public_key,
            modified,
            signature,
        ),
    )

    print("\n4. HYBRID ENCRYPTION")

    large_message = (
        b"Confidential enterprise information. " * 1000
    )

    envelope = HybridEncryption.encrypt(
        bob,
        large_message,
    )

    restored = EncryptedEnvelope.from_json(
        envelope.to_json()
    )

    recovered = HybridEncryption.decrypt(
        bob,
        restored,
    )

    print("Plaintext size:", len(large_message))
    print("AES-GCM ciphertext size:", len(envelope.ciphertext))
    print("RSA encrypted AES key:", len(envelope.encrypted_session_key))
    print("Recovery successful:", recovered == large_message)

    print("\n5. DIGITAL CERTIFICATE")

    authority = KeyPair.generate(2048)

    certificate = DigitalCertificate.issue(
        subject="Bob",
        subject_key=bob,
        issuer="Example Certificate Authority",
        issuer_key=authority,
        expires_at=datetime.now(timezone.utc).replace(
            year=datetime.now(timezone.utc).year + 1
        ),
    )

    print("Certificate subject:", certificate.subject)
    print("Certificate issuer:", certificate.issuer)
    print("Certificate valid:", certificate.verify(authority))

    print("\n6. KEY MANAGEMENT")

    store = KeyStore()
    store.register(bob)

    print("Registered:", store.get_active(bob.key_id).key_id[:32])

    bob.rotate()

    try:
        store.get_active(bob.key_id)
    except KeyValidationError as exc:
        print("Expected lifecycle rejection:", exc)

    print("\n7. PEM SERIALIZATION")

    public_pem = alice.public_pem()

    restored_public = KeyPair.load_public(public_pem)

    print(
        "Public key successfully restored:",
        restored_public.public_numbers() == alice.public_key.public_numbers(),
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        save_key_pair(alice, Path(temporary_directory))
        print("Demonstration PEM files saved successfully.")

    print("\n8. RUNNING AUTOMATED TESTS")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        CryptographyTests
    )

    result = unittest.TextTestRunner(verbosity=1).run(suite)

    if not result.wasSuccessful():
        raise SystemExit("Cryptographic tests failed.")

    print("\nAll cryptographic demonstrations completed successfully.")


if __name__ == "__main__":
    demonstrate()
