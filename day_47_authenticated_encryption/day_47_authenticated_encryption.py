from __future__ import annotations

"""
Authenticated Encryption: AES-GCM learning implementation.

Dependency:
    pip install cryptography

The program demonstrates:
- plaintext confidentiality
- ciphertext and authentication-tag generation
- associated authenticated data (AAD)
- nonce/IV handling
- successful decryption
- authentication failure after ciphertext tampering
- authentication failure after AAD tampering
- authentication failure with the wrong key
- nonce uniqueness requirements
- serialization of an encrypted message
- key rotation metadata
- a small repository-artifact protection workflow

AES-GCM is used through the well-tested cryptography library rather than
implementing AES or GCM primitives manually.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE: Final[int] = 32
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16


class AuthenticationFailure(Exception):
    """Raised when authenticated decryption cannot verify the message."""


@dataclass(frozen=True)
class EncryptedMessage:
    """
    A portable representation of an AES-GCM message.

    AESGCM.encrypt() returns ciphertext followed by the 16-byte GCM tag.
    Keeping the nonce and AAD beside the ciphertext makes the message
    self-describing while the secret key remains outside the message.
    """

    algorithm: str
    key_id: str
    nonce: bytes
    ciphertext_and_tag: bytes
    aad: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(
                self.ciphertext_and_tag[:-TAG_SIZE]
            ).decode("ascii"),
            "tag": base64.b64encode(
                self.ciphertext_and_tag[-TAG_SIZE:]
            ).decode("ascii"),
            "aad": base64.b64encode(self.aad).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, value: dict[str, str]) -> "EncryptedMessage":
        required = {
            "algorithm",
            "key_id",
            "nonce",
            "ciphertext",
            "tag",
            "aad",
        }

        missing = required.difference(value)
        if missing:
            raise ValueError(f"Missing encrypted-message fields: {sorted(missing)}")

        nonce = base64.b64decode(value["nonce"], validate=True)
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        tag = base64.b64decode(value["tag"], validate=True)
        aad = base64.b64decode(value["aad"], validate=True)

        if value["algorithm"] != "AES-256-GCM":
            raise ValueError("Unsupported authenticated-encryption algorithm")

        if len(nonce) != NONCE_SIZE:
            raise ValueError("AES-GCM nonce must be 12 bytes in this example")

        if len(tag) != TAG_SIZE:
            raise ValueError("AES-GCM tag must be 16 bytes in this example")

        return cls(
            algorithm=value["algorithm"],
            key_id=value["key_id"],
            nonce=nonce,
            ciphertext_and_tag=ciphertext + tag,
            aad=aad,
        )


class AeadKey:
    """Represents one AES-256-GCM key managed under an application key ID."""

    def __init__(self, key_id: str, key: bytes) -> None:
        if not key_id:
            raise ValueError("key_id cannot be empty")
        if len(key) != KEY_SIZE:
            raise ValueError("AES-256 requires exactly 32 key bytes")

        self.key_id = key_id
        self._key = bytes(key)

    @classmethod
    def generate(cls, key_id: str) -> "AeadKey":
        return cls(key_id, AESGCM.generate_key(bit_length=256))

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> EncryptedMessage:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("AAD must be bytes")

        # A fresh random 96-bit nonce is generated for every encryption.
        # Reusing a nonce with the same AES-GCM key is unsafe.
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self._key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

        return EncryptedMessage(
            algorithm="AES-256-GCM",
            key_id=self.key_id,
            nonce=nonce,
            ciphertext_and_tag=ciphertext_and_tag,
            aad=aad,
        )

    def decrypt(self, message: EncryptedMessage) -> bytes:
        if message.key_id != self.key_id:
            raise AuthenticationFailure(
                f"Message belongs to key {message.key_id}, "
                f"not currently selected key {self.key_id}"
            )

        try:
            return AESGCM(self._key).decrypt(
                message.nonce,
                message.ciphertext_and_tag,
                message.aad,
            )
        except InvalidTag as exc:
            # Do not reveal whether the ciphertext, tag, key, or AAD was
            # responsible. Applications should expose a generic failure.
            raise AuthenticationFailure(
                "Authenticated decryption failed"
            ) from exc


class KeyRing:
    """
    Minimal key-rotation model.

    A key ring allows old messages to remain decryptable while new messages
    are encrypted with the current key.
    """

    def __init__(self) -> None:
        self._keys: dict[str, AeadKey] = {}
        self._current_key_id: str | None = None

    def add_key(self, key: AeadKey, make_current: bool = False) -> None:
        self._keys[key.key_id] = key
        if make_current or self._current_key_id is None:
            self._current_key_id = key.key_id

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> EncryptedMessage:
        if self._current_key_id is None:
            raise RuntimeError("No encryption key is configured")
        return self._keys[self._current_key_id].encrypt(plaintext, aad)

    def decrypt(self, message: EncryptedMessage) -> bytes:
        key = self._keys.get(message.key_id)
        if key is None:
            raise AuthenticationFailure(
                f"No trusted key is available for key ID {message.key_id}"
            )
        return key.decrypt(message)

    def rotate(self, new_key: AeadKey) -> None:
        self.add_key(new_key, make_current=True)


def serialize_message(message: EncryptedMessage) -> str:
    return json.dumps(message.to_dict(), indent=2, sort_keys=True)


def deserialize_message(serialized: str) -> EncryptedMessage:
    value = json.loads(serialized)

    if not isinstance(value, dict):
        raise ValueError("Encrypted message must be a JSON object")

    return EncryptedMessage.from_dict(value)


def tamper_bytes(value: bytes, index: int = 0) -> bytes:
    if not value:
        raise ValueError("Cannot tamper with an empty byte sequence")

    modified = bytearray(value)
    modified[index % len(modified)] ^= 0x01
    return bytes(modified)


def demonstrate_basic_encryption() -> None:
    print("\n=== Basic AES-GCM encryption ===")

    key = AeadKey.generate("key-2026-01")
    plaintext = (
        b"Repository policy: protected branches require review before merge."
    )

    message = key.encrypt(plaintext)

    print(f"Algorithm: {message.algorithm}")
    print(f"Key ID: {message.key_id}")
    print(f"Nonce bytes: {len(message.nonce)}")
    print(f"Ciphertext + tag bytes: {len(message.ciphertext_and_tag)}")
    print(f"Recovered: {key.decrypt(message).decode()}")


def demonstrate_aad() -> None:
    print("\n=== Associated authenticated data ===")

    key = AeadKey.generate("repository-key")
    plaintext = b"encrypted repository configuration"

    aad = b"repository=security-platform;environment=production"

    message = key.encrypt(plaintext, aad)

    print("AAD is authenticated but is not encrypted.")
    print(f"AAD visible to the recipient: {message.aad.decode()}")
    print(f"Recovered plaintext: {key.decrypt(message).decode()}")

    altered_aad = b"repository=security-platform;environment=staging"
    altered_message = EncryptedMessage(
        algorithm=message.algorithm,
        key_id=message.key_id,
        nonce=message.nonce,
        ciphertext_and_tag=message.ciphertext_and_tag,
        aad=altered_aad,
    )

    try:
        key.decrypt(altered_message)
    except AuthenticationFailure:
        print("AAD modification correctly caused authentication failure.")


def demonstrate_tampering() -> None:
    print("\n=== Tamper detection ===")

    key = AeadKey.generate("audit-key")
    message = key.encrypt(
        b"merge-policy=required-review",
        aad=b"record-type=repository-policy",
    )

    tampered_ciphertext = EncryptedMessage(
        algorithm=message.algorithm,
        key_id=message.key_id,
        nonce=message.nonce,
        ciphertext_and_tag=tamper_bytes(message.ciphertext_and_tag),
        aad=message.aad,
    )

    try:
        key.decrypt(tampered_ciphertext)
    except AuthenticationFailure:
        print("Ciphertext/tag modification was rejected.")


def demonstrate_wrong_key() -> None:
    print("\n=== Wrong-key rejection ===")

    encrypting_key = AeadKey.generate("key-A")
    other_key = AeadKey.generate("key-B")

    message = encrypting_key.encrypt(b"confidential repository metadata")

    try:
        other_key.decrypt(message)
    except AuthenticationFailure:
        print("The wrong key could not authenticate the message.")


def demonstrate_serialization() -> None:
    print("\n=== Message serialization ===")

    key = AeadKey.generate("transport-key")

    message = key.encrypt(
        b"review decision: approved",
        aad=b"pull-request=482",
    )

    serialized = serialize_message(message)
    restored = deserialize_message(serialized)

    print(serialized)
    print(f"Recovered after serialization: {key.decrypt(restored).decode()}")


def demonstrate_nonce_uniqueness() -> None:
    print("\n=== Nonce uniqueness ===")

    key = AeadKey.generate("nonce-safety-key")
    nonces: set[bytes] = set()

    for _ in range(1000):
        message = key.encrypt(b"same logical message")
        nonces.add(message.nonce)

    print(f"Unique nonces generated: {len(nonces)}")
    print("A new nonce is generated for every encryption operation.")


def demonstrate_key_rotation() -> None:
    print("\n=== Key rotation ===")

    key_ring = KeyRing()

    old_key = AeadKey.generate("key-2026-Q3")
    new_key = AeadKey.generate("key-2026-Q4")

    key_ring.add_key(old_key, make_current=True)

    old_message = key_ring.encrypt(
        b"policy created before rotation",
        aad=b"policy-version=1",
    )

    key_ring.rotate(new_key)

    new_message = key_ring.encrypt(
        b"policy created after rotation",
        aad=b"policy-version=2",
    )

    # Retaining the old trusted key permits existing data to be read.
    print(f"Old message: {key_ring.decrypt(old_message).decode()}")
    print(f"New message: {key_ring.decrypt(new_message).decode()}")


def protect_repository_artifact(
    key_ring: KeyRing,
    repository: str,
    artifact: str,
    contents: bytes,
) -> EncryptedMessage:
    """
    Protect a repository artifact while binding its identity as AAD.

    The repository and artifact names remain visible because AAD is not
    encrypted. Altering either value makes authentication fail.
    """

    aad = (
        f"repository={repository};artifact={artifact}"
        .encode("utf-8")
    )

    return key_ring.encrypt(contents, aad)


def demonstrate_repository_workflow() -> None:
    print("\n=== Repository artifact protection workflow ===")

    keys = KeyRing()
    keys.add_key(AeadKey.generate("repo-key-v1"), make_current=True)

    artifact = protect_repository_artifact(
        keys,
        repository="platform-security",
        artifact="branch-policy.json",
        contents=json.dumps(
            {
                "required_reviews": 2,
                "required_status_checks": [
                    "unit-tests",
                    "security-scan",
                ],
                "allow_force_push": False,
            },
            sort_keys=True,
        ).encode("utf-8"),
    )

    recovered = keys.decrypt(artifact)
    print(recovered.decode("utf-8"))

    # The metadata itself is authenticated. An attacker cannot change the
    # artifact identity without invalidating the GCM authentication tag.
    altered_identity = EncryptedMessage(
        algorithm=artifact.algorithm,
        key_id=artifact.key_id,
        nonce=artifact.nonce,
        ciphertext_and_tag=artifact.ciphertext_and_tag,
        aad=b"repository=platform-security;artifact=other-policy.json",
    )

    try:
        keys.decrypt(altered_identity)
    except AuthenticationFailure:
        print("Artifact identity modification was rejected.")


def demonstrate_file_round_trip() -> None:
    print("\n=== File round trip ===")

    key = AeadKey.generate("file-key")

    source = Path("aead_demo_message.json")

    message = key.encrypt(
        b"Encrypted content stored outside the Python process.",
        aad=b"format=aead-demo-v1",
    )

    source.write_text(serialize_message(message), encoding="utf-8")

    restored = deserialize_message(source.read_text(encoding="utf-8"))
    recovered = key.decrypt(restored)

    print(f"Stored encrypted message in: {source}")
    print(f"Recovered content: {recovered.decode()}")

    # The demo removes its generated artifact so repeated executions do not
    # accumulate files in the working directory.
    source.unlink(missing_ok=True)


def demonstrate_failure_handling() -> None:
    print("\n=== Failure handling ===")

    key = AeadKey.generate("failure-demo")
    message = key.encrypt(b"authenticated payload")

    cases = {
        "ciphertext modification": EncryptedMessage(
            algorithm=message.algorithm,
            key_id=message.key_id,
            nonce=message.nonce,
            ciphertext_and_tag=tamper_bytes(message.ciphertext_and_tag, 3),
            aad=message.aad,
        ),
        "nonce modification": EncryptedMessage(
            algorithm=message.algorithm,
            key_id=message.key_id,
            nonce=tamper_bytes(message.nonce),
            ciphertext_and_tag=message.ciphertext_and_tag,
            aad=message.aad,
        ),
        "AAD modification": EncryptedMessage(
            algorithm=message.algorithm,
            key_id=message.key_id,
            nonce=message.nonce,
            ciphertext_and_tag=message.ciphertext_and_tag,
            aad=b"modified",
        ),
    }

    for name, altered in cases.items():
        try:
            key.decrypt(altered)
        except AuthenticationFailure:
            print(f"{name}: rejected")


def main() -> None:
    print("Authenticated Encryption with AES-256-GCM")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    demonstrate_basic_encryption()
    demonstrate_aad()
    demonstrate_tampering()
    demonstrate_wrong_key()
    demonstrate_serialization()
    demonstrate_nonce_uniqueness()
    demonstrate_key_rotation()
    demonstrate_repository_workflow()
    demonstrate_file_round_trip()
    demonstrate_failure_handling()

    print("\n=== Security boundaries ===")
    print("The key must remain secret; ciphertext alone does not reveal it.")
    print("Nonce reuse with the same GCM key must be prevented.")
    print("Authentication failure must not be treated as valid plaintext.")
    print("AAD is authenticated and visible, not encrypted.")
    print("Production key storage should use an appropriate secret-management system.")


if __name__ == "__main__":
    main()
