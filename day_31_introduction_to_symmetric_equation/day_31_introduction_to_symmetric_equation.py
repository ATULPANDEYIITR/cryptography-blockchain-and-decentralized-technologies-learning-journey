#!/usr/bin/env python3
"""
Introduction to Symmetric Encryption

A self-contained educational implementation of symmetric encryption using
Python's standard library.

The program progresses from:
- bytes, keys, plaintext, ciphertext, and XOR
- reusable XOR transformation
- authenticated encryption concepts
- a practical stream-encryption construction using HMAC-SHA256
- nonce handling
- authenticated file encryption
- tamper detection
- password-derived keys using PBKDF2
- envelope-style encrypted records
- security failures and validation

This implementation is intentionally educational. The custom constructions
demonstrate the mechanics of symmetric encryption, but production systems
should use a reviewed cryptographic library and an authenticated encryption
mode such as AES-GCM or ChaCha20-Poly1305.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Fundamental symmetric-encryption concepts
# ---------------------------------------------------------------------------

def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def repeat_key(key: bytes, length: int) -> bytes:
    """
    Repeat a key until the requested number of bytes exists.

    This is useful for demonstrating why simple repeating-key XOR is not a
    secure modern cipher: repeated key material creates exploitable patterns.
    """
    if not key:
        raise ValueError("Key cannot be empty")
    return (key * ((length + len(key) - 1) // len(key)))[:length]


def repeating_xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Educational repeating-key XOR encryption."""
    return xor_bytes(plaintext, repeat_key(key, len(plaintext)))


def repeating_xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """XOR is its own inverse, so the same operation decrypts the data."""
    return repeating_xor_encrypt(ciphertext, key)


def demonstrate_basic_concepts() -> None:
    print("\n=== Symmetric Encryption Fundamentals ===")

    plaintext = b"confidential repository configuration"
    key = b"demo-key"

    ciphertext = repeating_xor_encrypt(plaintext, key)
    recovered = repeating_xor_decrypt(ciphertext, key)

    print(f"Plaintext : {plaintext!r}")
    print(f"Key       : {key!r}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered : {recovered!r}")

    assert recovered == plaintext

    # Encryption requires the same secret key for both directions in this
    # symmetric construction.
    print("The same secret key transforms plaintext to ciphertext and back.")


# ---------------------------------------------------------------------------
# Why XOR alone is not enough
# ---------------------------------------------------------------------------

def demonstrate_xor_weakness() -> None:
    print("\n=== Why Repeating-Key XOR Is Not Secure ===")

    key = b"repo"
    first = b"database-password=secret"
    second = b"database-token=example"

    encrypted_first = repeating_xor_encrypt(first, key)
    encrypted_second = repeating_xor_encrypt(second, key)

    print(f"First ciphertext : {encrypted_first.hex()}")
    print(f"Second ciphertext: {encrypted_second.hex()}")

    # Equal plaintext positions encrypted with the same repeated key reveal
    # relationships between plaintexts because C1 XOR C2 = P1 XOR P2.
    overlapping = xor_bytes(
        encrypted_first[:len(encrypted_second)],
        encrypted_second,
    )

    expected = xor_bytes(first[:len(second)], second)
    print(f"C1 XOR C2        : {overlapping.hex()}")
    print(f"P1 XOR P2        : {expected.hex()}")

    assert overlapping == expected
    print("Repeated-key XOR leaks relationships between messages.")


# ---------------------------------------------------------------------------
# A deterministic keystream construction for educational purposes
# ---------------------------------------------------------------------------

def derive_keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """
    Produce a deterministic 32-byte keystream block.

    HMAC is used here as a pseudorandom-function-like building block.
    Counter separation prevents two blocks from using identical input.
    """
    if len(key) < 16:
        raise ValueError("Encryption key must contain at least 128 bits")
    if len(nonce) != 16:
        raise ValueError("Nonce must be exactly 16 bytes")

    counter_bytes = struct.pack(">Q", counter)
    return hmac.new(
        key,
        b"SYMMETRIC-STREAM|" + nonce + counter_bytes,
        hashlib.sha256,
    ).digest()


def xor_with_keystream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt or decrypt data using the generated keystream.

    Because XOR is reversible, the same function performs both operations.
    """
    if not data:
        return b""

    output = bytearray()
    block_size = hashlib.sha256().digest_size

    for block_number, offset in enumerate(range(0, len(data), block_size)):
        block = data[offset:offset + block_size]
        keystream = derive_keystream_block(key, nonce, block_number)
        output.extend(x ^ y for x, y in zip(block, keystream))

    return bytes(output)


# ---------------------------------------------------------------------------
# Authenticated encryption model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptedMessage:
    """
    Serialized components of an encrypted message.

    nonce identifies the keystream instance, ciphertext hides the plaintext,
    and tag authenticates the encrypted payload and associated metadata.
    """

    version: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def serialize(self) -> bytes:
        """Serialize the envelope into JSON-safe binary fields."""
        document = {
            "version": self.version,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "tag": base64.b64encode(self.tag).decode("ascii"),
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, payload: bytes) -> "EncryptedMessage":
        """Parse and validate an encrypted message envelope."""
        try:
            document = json.loads(payload.decode("utf-8"))
            version = int(document["version"])
            nonce = base64.b64decode(document["nonce"], validate=True)
            ciphertext = base64.b64decode(
                document["ciphertext"],
                validate=True,
            )
            tag = base64.b64decode(document["tag"], validate=True)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Malformed encrypted message") from exc

        if version != 1:
            raise ValueError(f"Unsupported encrypted-message version: {version}")
        if len(nonce) != 16:
            raise ValueError("Invalid nonce length")
        if len(tag) != 32:
            raise ValueError("Invalid authentication-tag length")

        return cls(version, nonce, ciphertext, tag)


class AuthenticatedStreamCipher:
    """
    Educational authenticated-encryption construction.

    Confidentiality:
        HMAC-derived keystream + XOR.

    Integrity/authenticity:
        HMAC-SHA256 over version, nonce, associated data, and ciphertext.

    Important:
        This class is educational and should not replace AES-GCM or
        ChaCha20-Poly1305 in production software.
    """

    VERSION = 1

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("This construction requires a 32-byte key")
        self._encryption_key = hmac.new(
            key,
            b"encryption-key",
            hashlib.sha256,
        ).digest()
        self._authentication_key = hmac.new(
            key,
            b"authentication-key",
            hashlib.sha256,
        ).digest()

    def _authentication_input(
        self,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes,
    ) -> bytes:
        return (
            bytes([self.VERSION])
            + struct.pack(">H", len(associated_data))
            + associated_data
            + nonce
            + ciphertext
        )

    def encrypt(
        self,
        plaintext: bytes,
        *,
        associated_data: bytes = b"",
        nonce: bytes | None = None,
    ) -> EncryptedMessage:
        """Encrypt and authenticate a plaintext message."""
        if nonce is None:
            nonce = secrets.token_bytes(16)

        if len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes")

        ciphertext = xor_with_keystream(
            plaintext,
            self._encryption_key,
            nonce,
        )

        auth_input = self._authentication_input(
            nonce,
            ciphertext,
            associated_data,
        )
        tag = hmac.new(
            self._authentication_key,
            auth_input,
            hashlib.sha256,
        ).digest()

        return EncryptedMessage(
            version=self.VERSION,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt(
        self,
        message: EncryptedMessage,
        *,
        associated_data: bytes = b"",
    ) -> bytes:
        """Verify authenticity before releasing decrypted plaintext."""
        if message.version != self.VERSION:
            raise ValueError("Unsupported message version")
        if len(message.nonce) != 16:
            raise ValueError("Invalid nonce length")
        if len(message.tag) != 32:
            raise ValueError("Invalid authentication tag")

        auth_input = self._authentication_input(
            message.nonce,
            message.ciphertext,
            associated_data,
        )
        expected_tag = hmac.new(
            self._authentication_key,
            auth_input,
            hashlib.sha256,
        ).digest()

        # Constant-time comparison avoids leaking tag equality through
        # ordinary early-exit string comparison behavior.
        if not hmac.compare_digest(message.tag, expected_tag):
            raise ValueError("Authentication failed: ciphertext was modified")

        return xor_with_keystream(
            message.ciphertext,
            self._encryption_key,
            message.nonce,
        )


def demonstrate_authenticated_encryption() -> None:
    print("\n=== Authenticated Symmetric Encryption ===")

    key = secrets.token_bytes(32)
    cipher = AuthenticatedStreamCipher(key)

    plaintext = (
        b"Deployment configuration for production repository infrastructure"
    )
    metadata = b"record-type=deployment-config"

    message = cipher.encrypt(
        plaintext,
        associated_data=metadata,
    )

    serialized = message.serialize()
    restored_message = EncryptedMessage.deserialize(serialized)
    recovered = cipher.decrypt(
        restored_message,
        associated_data=metadata,
    )

    print(f"Plaintext bytes : {len(plaintext)}")
    print(f"Ciphertext bytes: {len(message.ciphertext)}")
    print(f"Nonce           : {message.nonce.hex()}")
    print(f"Authentication  : {message.tag.hex()}")
    print(f"Recovered       : {recovered.decode('utf-8')}")

    assert recovered == plaintext

    # Modifying ciphertext must cause verification to fail before plaintext
    # is returned to the caller.
    tampered_ciphertext = bytearray(message.ciphertext)
    if tampered_ciphertext:
        tampered_ciphertext[0] ^= 0x01

    tampered = EncryptedMessage(
        version=message.version,
        nonce=message.nonce,
        ciphertext=bytes(tampered_ciphertext),
        tag=message.tag,
    )

    try:
        cipher.decrypt(tampered, associated_data=metadata)
    except ValueError as exc:
        print(f"Tampering detected: {exc}")


# ---------------------------------------------------------------------------
# Associated data
# ---------------------------------------------------------------------------

def demonstrate_associated_data() -> None:
    print("\n=== Associated Data ===")

    key = secrets.token_bytes(32)
    cipher = AuthenticatedStreamCipher(key)

    plaintext = b"billing export: customer data"
    associated_data = b"tenant=finance;format=v1"

    message = cipher.encrypt(
        plaintext,
        associated_data=associated_data,
    )

    assert cipher.decrypt(
        message,
        associated_data=associated_data,
    ) == plaintext

    try:
        cipher.decrypt(
            message,
            associated_data=b"tenant=engineering;format=v1",
        )
    except ValueError as exc:
        print(f"Metadata modification detected: {exc}")

    print(
        "Associated data remains visible but is authenticated, "
        "so changing it invalidates the message."
    )


# ---------------------------------------------------------------------------
# Password-derived symmetric keys
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PasswordProtectedMessage:
    """
    Envelope containing a random salt and encrypted message.

    The password itself is never stored in the envelope.
    """

    kdf: str
    iterations: int
    salt: bytes
    encrypted_message: EncryptedMessage

    def serialize(self) -> bytes:
        document = {
            "kdf": self.kdf,
            "iterations": self.iterations,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "message": base64.b64encode(
                self.encrypted_message.serialize()
            ).decode("ascii"),
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, payload: bytes) -> "PasswordProtectedMessage":
        try:
            document = json.loads(payload.decode("utf-8"))
            kdf = document["kdf"]
            iterations = int(document["iterations"])
            salt = base64.b64decode(document["salt"], validate=True)
            message_bytes = base64.b64decode(
                document["message"],
                validate=True,
            )
            encrypted_message = EncryptedMessage.deserialize(message_bytes)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Malformed password-protected message") from exc

        if kdf != "PBKDF2-HMAC-SHA256":
            raise ValueError("Unsupported key-derivation function")
        if not 100_000 <= iterations <= 5_000_000:
            raise ValueError("Unsafe PBKDF2 iteration count")
        if len(salt) != 16:
            raise ValueError("Invalid salt length")

        return cls(kdf, iterations, salt, encrypted_message)


def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = 310_000,
) -> bytes:
    """
    Derive a 256-bit symmetric key from a password.

    A fresh random salt prevents identical passwords from automatically
    producing identical derived keys across separate records.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if len(salt) < 16:
        raise ValueError("Salt must contain at least 128 bits")
    if not 100_000 <= iterations <= 5_000_000:
        raise ValueError("PBKDF2 iteration count is outside the accepted range")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


def encrypt_with_password(
    plaintext: bytes,
    password: str,
    *,
    associated_data: bytes = b"",
    iterations: int = 310_000,
) -> PasswordProtectedMessage:
    salt = secrets.token_bytes(16)
    key = derive_key_from_password(password, salt, iterations)
    cipher = AuthenticatedStreamCipher(key)

    encrypted = cipher.encrypt(
        plaintext,
        associated_data=associated_data,
    )

    return PasswordProtectedMessage(
        kdf="PBKDF2-HMAC-SHA256",
        iterations=iterations,
        salt=salt,
        encrypted_message=encrypted,
    )


def decrypt_with_password(
    envelope: PasswordProtectedMessage,
    password: str,
    *,
    associated_data: bytes = b"",
) -> bytes:
    key = derive_key_from_password(
        password,
        envelope.salt,
        envelope.iterations,
    )
    cipher = AuthenticatedStreamCipher(key)

    return cipher.decrypt(
        envelope.encrypted_message,
        associated_data=associated_data,
    )


def demonstrate_password_encryption() -> None:
    print("\n=== Password-Derived Symmetric Encryption ===")

    password = "correct horse battery staple"
    plaintext = b"private deployment secret"
    associated_data = b"application=release-manager"

    envelope = encrypt_with_password(
        plaintext,
        password,
        associated_data=associated_data,
    )

    serialized = envelope.serialize()
    print(f"Serialized envelope bytes: {len(serialized)}")
    print(f"Salt: {envelope.salt.hex()}")
    print(f"PBKDF2 iterations: {envelope.iterations}")

    restored = PasswordProtectedMessage.deserialize(serialized)

    recovered = decrypt_with_password(
        restored,
        password,
        associated_data=associated_data,
    )

    assert recovered == plaintext
    print(f"Recovered: {recovered.decode()}")

    try:
        decrypt_with_password(
            restored,
            "incorrect password",
            associated_data=associated_data,
        )
    except ValueError as exc:
        print(f"Wrong password rejected: {exc}")


# ---------------------------------------------------------------------------
# File encryption
# ---------------------------------------------------------------------------

FILE_MAGIC = b"SYMENC01"


def encrypt_file(
    source: Path,
    destination: Path,
    password: str,
    *,
    associated_data: bytes = b"",
) -> None:
    """
    Encrypt a complete file into an authenticated envelope.

    The complete source is read into memory for simplicity. Large production
    files should use a streaming authenticated-encryption design.
    """
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files")
    if not source.is_file():
        raise FileNotFoundError(source)

    plaintext = source.read_bytes()
    envelope = encrypt_with_password(
        plaintext,
        password,
        associated_data=associated_data,
    )

    payload = FILE_MAGIC + envelope.serialize()

    destination.parent.mkdir(parents=True, exist_ok=True)

    # Writing to a temporary file before replacement reduces the chance of
    # leaving a partially written destination after an I/O failure.
    temporary = destination.with_suffix(destination.suffix + ".tmp")

    try:
        temporary.write_bytes(payload)
        temporary.replace(destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def decrypt_file(
    source: Path,
    destination: Path,
    password: str,
    *,
    associated_data: bytes = b"",
) -> None:
    """Verify and decrypt an authenticated encrypted file."""
    if not source.is_file():
        raise FileNotFoundError(source)

    payload = source.read_bytes()

    if not payload.startswith(FILE_MAGIC):
        raise ValueError("File does not contain a recognized encrypted format")

    envelope = PasswordProtectedMessage.deserialize(
        payload[len(FILE_MAGIC):]
    )

    plaintext = decrypt_with_password(
        envelope,
        password,
        associated_data=associated_data,
    )

    temporary = destination.with_suffix(destination.suffix + ".tmp")

    try:
        temporary.write_bytes(plaintext)
        temporary.replace(destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def demonstrate_file_encryption() -> None:
    print("\n=== Authenticated File Encryption ===")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "deployment.txt"
        encrypted = root / "deployment.sym"
        recovered = root / "deployment.recovered.txt"

        original_text = (
            "Production deployment manifest\n"
            "service=payments-api\n"
            "environment=production\n"
            "rotation=enabled\n"
        )
        source.write_text(original_text, encoding="utf-8")

        encrypt_file(
            source,
            encrypted,
            "repository-secret",
            associated_data=b"file-type=deployment-manifest",
        )

        decrypt_file(
            encrypted,
            recovered,
            "repository-secret",
            associated_data=b"file-type=deployment-manifest",
        )

        assert recovered.read_text(encoding="utf-8") == original_text

        print(f"Source size    : {source.stat().st_size} bytes")
        print(f"Encrypted size : {encrypted.stat().st_size} bytes")
        print(f"Recovered size : {recovered.stat().st_size} bytes")
        print("File encryption/decryption succeeded.")


# ---------------------------------------------------------------------------
# Security-oriented validation examples
# ---------------------------------------------------------------------------

def demonstrate_security_properties() -> None:
    print("\n=== Security Properties and Failure Conditions ===")

    key = secrets.token_bytes(32)
    cipher = AuthenticatedStreamCipher(key)
    plaintext = b"same plaintext encrypted twice"

    first = cipher.encrypt(plaintext)
    second = cipher.encrypt(plaintext)

    # Random nonces cause independent keystreams, so identical plaintexts
    # do not automatically produce identical ciphertexts.
    print(f"First nonce : {first.nonce.hex()}")
    print(f"Second nonce: {second.nonce.hex()}")
    print(f"Ciphertexts differ: {first.ciphertext != second.ciphertext}")

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext

    # Reusing a nonce with the same encryption key recreates the keystream.
    # This demonstrates why nonce management is a security-critical rule.
    fixed_nonce = b"\x42" * 16
    a = cipher.encrypt(b"message A", nonce=fixed_nonce)
    b = cipher.encrypt(b"message B", nonce=fixed_nonce)

    xor_ciphertexts = xor_bytes(a.ciphertext, b.ciphertext)
    xor_plaintexts = xor_bytes(b"message A", b"message B")

    assert xor_ciphertexts == xor_plaintexts
    print("Nonce reuse exposes the XOR relationship between plaintexts.")

    # Associated-data mismatch is an integrity failure even though the
    # ciphertext itself has not changed.
    protected = cipher.encrypt(
        b"approved configuration",
        associated_data=b"version=7",
    )

    try:
        cipher.decrypt(
            protected,
            associated_data=b"version=8",
        )
    except ValueError:
        print("Associated-data modification rejected.")

    # Empty plaintext is valid and still receives an authentication tag.
    empty_message = cipher.encrypt(b"")
    assert cipher.decrypt(empty_message) == b""
    print("Empty plaintext is handled without a special insecure shortcut.")


# ---------------------------------------------------------------------------
# A small key-management model
# ---------------------------------------------------------------------------

@dataclass
class KeyRecord:
    key_id: str
    key: bytes
    active: bool = True


class KeyRing:
    """
    Minimal in-memory key-ring model.

    A real key-management service would normally control access, auditing,
    rotation, hardware-backed storage, retention, and destruction.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}

    def add_key(self, key_id: str, key: bytes) -> None:
        if not key_id.strip():
            raise ValueError("Key ID cannot be empty")
        if len(key) != 32:
            raise ValueError("Only 256-bit keys are accepted")
        if key_id in self._keys:
            raise ValueError("Key ID already exists")

        self._keys[key_id] = KeyRecord(key_id, key)

    def deactivate(self, key_id: str) -> None:
        record = self.get(key_id)
        record.active = False

    def get(self, key_id: str) -> KeyRecord:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"Unknown key ID: {key_id}") from exc

    def active_key(self, key_id: str) -> bytes:
        record = self.get(key_id)
        if not record.active:
            raise ValueError(f"Key {key_id} is inactive")
        return record.key


def demonstrate_key_rotation() -> None:
    print("\n=== Key Identification and Rotation ===")

    key_ring = KeyRing()
    old_key = secrets.token_bytes(32)
    new_key = secrets.token_bytes(32)

    key_ring.add_key("key-2026-09", old_key)
    key_ring.add_key("key-2026-10", new_key)

    data = b"configuration encrypted during the old key epoch"

    old_cipher = AuthenticatedStreamCipher(
        key_ring.active_key("key-2026-09")
    )
    encrypted = old_cipher.encrypt(data)

    key_ring.deactivate("key-2026-09")

    new_cipher = AuthenticatedStreamCipher(
        key_ring.active_key("key-2026-10")
    )

    # New writes use the active key. Existing data may still need the old key
    # until a controlled re-encryption migration has completed.
    new_encrypted = new_cipher.encrypt(data)

    assert old_cipher.decrypt(encrypted) == data
    assert new_cipher.decrypt(new_encrypted) == data

    try:
        key_ring.active_key("key-2026-09")
    except ValueError as exc:
        print(f"Old key blocked for new operations: {exc}")

    print(
        "Key rotation separates key identity from ciphertext and permits "
        "controlled migration."
    )


# ---------------------------------------------------------------------------
# Deterministic tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    print("\n=== Self-Tests ===")

    key = b"K" * 32
    cipher = AuthenticatedStreamCipher(key)

    test_vectors = [
        b"",
        b"a",
        b"short message",
        b"\x00" * 64,
        bytes(range(256)),
        b"Unicode is encoded before encryption: \xe2\x9c\x93",
    ]

    nonce = b"N" * 16

    for plaintext in test_vectors:
        message = cipher.encrypt(plaintext, nonce=nonce)
        recovered = cipher.decrypt(message)
        assert recovered == plaintext

    # Wrong key must not produce accepted plaintext.
    message = cipher.encrypt(b"secret", nonce=b"Z" * 16)
    wrong_cipher = AuthenticatedStreamCipher(b"W" * 32)

    try:
        wrong_cipher.decrypt(message)
    except ValueError:
        pass
    else:
        raise AssertionError("Wrong key unexpectedly authenticated")

    # Changing the nonce invalidates the tag.
    modified_nonce = EncryptedMessage(
        version=message.version,
        nonce=b"Y" * 16,
        ciphertext=message.ciphertext,
        tag=message.tag,
    )

    try:
        cipher.decrypt(modified_nonce)
    except ValueError:
        pass
    else:
        raise AssertionError("Nonce modification unexpectedly authenticated")

    # Serialization must preserve all message components.
    serialized = message.serialize()
    restored = EncryptedMessage.deserialize(serialized)
    assert restored == message

    print(f"Passed {len(test_vectors)} encryption/decryption vectors.")
    print("Passed wrong-key, nonce-tampering, and serialization tests.")


# ---------------------------------------------------------------------------
# Operational demonstration
# ---------------------------------------------------------------------------

def print_security_guidance() -> None:
    print("\n=== Production Security Guidance ===")
    guidance = {
        "cipher": (
            "Use a reviewed AEAD construction such as AES-GCM or "
            "ChaCha20-Poly1305 instead of custom cryptography."
        ),
        "keys": (
            "Generate high-entropy keys with a secure random source and "
            "protect them with an appropriate key-management system."
        ),
        "nonces": (
            "Follow the nonce requirements of the selected AEAD algorithm; "
            "never improvise nonce reuse rules."
        ),
        "passwords": (
            "Use a password KDF with an appropriate work factor and unique "
            "salt when passwords are unavoidable."
        ),
        "integrity": (
            "Do not decrypt unauthenticated ciphertext and then trust the "
            "result as valid application data."
        ),
        "secrets": (
            "Do not commit encryption keys, passwords, or decrypted secrets "
            "to source control, logs, crash reports, or public artifacts."
        ),
        "files": (
            "For large files, use a library-supported streaming construction "
            "rather than loading the entire file into memory."
        ),
    }

    for name, description in guidance.items():
        print(f"{name}: {description}")


def main() -> None:
    demonstrate_basic_concepts()
    demonstrate_xor_weakness()
    demonstrate_authenticated_encryption()
    demonstrate_associated_data()
    demonstrate_password_encryption()
    demonstrate_file_encryption()
    demonstrate_security_properties()
    demonstrate_key_rotation()
    run_tests()
    print_security_guidance()


if __name__ == "__main__":
    main()
