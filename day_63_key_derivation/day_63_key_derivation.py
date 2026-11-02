#!/usr/bin/env python3
"""
Key derivation in blockchain and cryptography.

Demonstrates:
- PBKDF2-HMAC-SHA256
- scrypt
- HKDF-SHA256
- hierarchical deterministic-style derivation paths
- domain separation
- deterministic wallet/account key derivation
- validation, state handling, secure byte handling, and test vectors
- encrypted-at-rest simulation using derived keys only; no real funds or network calls
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


HASH_NAME = "sha256"
MASTER_KEY_SIZE = 32
CHAIN_CODE_SIZE = 32
MAX_DERIVATION_DEPTH = 32


class KDFAlgorithm(str, Enum):
    PBKDF2 = "pbkdf2-sha256"
    SCRYPT = "scrypt"
    HKDF = "hkdf-sha256"


class KDFError(ValueError):
    """Raised when key-derivation input violates a security or format rule."""


@dataclass(frozen=True)
class KDFParameters:
    algorithm: KDFAlgorithm
    output_length: int = 32
    iterations: int = 310_000
    salt_length: int = 16
    scrypt_n: int = 2**14
    scrypt_r: int = 8
    scrypt_p: int = 1

    def validate(self) -> None:
        if not 16 <= self.output_length <= 64:
            raise KDFError("output_length must be between 16 and 64 bytes")

        if self.algorithm is KDFAlgorithm.PBKDF2:
            if self.iterations < 100_000:
                raise KDFError("PBKDF2 iterations are below the configured security floor")

        elif self.algorithm is KDFAlgorithm.SCRYPT:
            if self.scrypt_n < 2**14 or self.scrypt_n & (self.scrypt_n - 1):
                raise KDFError("scrypt N must be a power of two and at least 2^14")
            if self.scrypt_r <= 0 or self.scrypt_p <= 0:
                raise KDFError("scrypt r and p must be positive")

        elif self.algorithm is KDFAlgorithm.HKDF:
            if self.output_length > 255 * hashlib.sha256().digest_size:
                raise KDFError("HKDF output exceeds RFC 5869 expansion limit")


def secure_random(length: int) -> bytes:
    if length <= 0:
        raise KDFError("random byte length must be positive")
    return secrets.token_bytes(length)


def pbkdf2_sha256(
    password: bytes,
    salt: bytes,
    iterations: int = 310_000,
    length: int = 32,
) -> bytes:
    if not password:
        raise KDFError("password must not be empty")
    if len(salt) < 16:
        raise KDFError("salt must contain at least 16 bytes")
    if iterations < 100_000:
        raise KDFError("PBKDF2 iteration count is too low")
    if not 16 <= length <= 64:
        raise KDFError("derived key length must be between 16 and 64 bytes")

    return hashlib.pbkdf2_hmac(
        HASH_NAME,
        password,
        salt,
        iterations,
        dklen=length,
    )


def scrypt_derive(
    password: bytes,
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    length: int = 32,
) -> bytes:
    if not password:
        raise KDFError("password must not be empty")
    if len(salt) < 16:
        raise KDFError("salt must contain at least 16 bytes")
    if n < 2**14 or n & (n - 1):
        raise KDFError("scrypt N must be a power of two and at least 2^14")
    if r <= 0 or p <= 0:
        raise KDFError("scrypt r and p must be positive")
    if not 16 <= length <= 64:
        raise KDFError("derived key length must be between 16 and 64 bytes")

    return hashlib.scrypt(
        password,
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=length,
    )


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not ikm:
        raise KDFError("HKDF input key material must not be empty")
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size

    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if len(prk) != hashlib.sha256().digest_size:
        raise KDFError("HKDF PRK must be 32 bytes")
    if length <= 0:
        raise KDFError("HKDF output length must be positive")
    if length > 255 * hashlib.sha256().digest_size:
        raise KDFError("HKDF output exceeds RFC 5869 limit")

    result = bytearray()
    previous = b""

    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        result.extend(previous)

    return bytes(result[:length])


def hkdf_sha256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return hashlib.sha256(
        len(tag_bytes).to_bytes(2, "big")
        + tag_bytes
        + payload
    ).digest()


def encode_path_component(index: int, hardened: bool = False) -> bytes:
    if not 0 <= index < 2**31:
        raise KDFError("normal derivation index must be below 2^31")

    value = index | (0x80000000 if hardened else 0)
    return value.to_bytes(4, "big")


@dataclass(frozen=True)
class DerivedNode:
    depth: int
    index: int
    key: bytes
    chain_code: bytes
    path: str


class HDKeyTree:
    """
    Educational HD-style tree using HMAC-SHA256.

    This is deliberately not a BIP-32 implementation. It illustrates the
    cryptographic structure of hierarchical derivation without pretending
    that a custom implementation is compatible with Bitcoin wallets.
    """

    def __init__(self, seed: bytes):
        if len(seed) < 16:
            raise KDFError("seed must contain at least 16 bytes")

        material = hmac.new(
            b"Blockchain HD Root",
            seed,
            hashlib.sha256,
        ).digest()

        chain_code = hmac.new(
            b"Blockchain Chain Code",
            seed,
            hashlib.sha256,
        ).digest()

        self.root = DerivedNode(
            depth=0,
            index=0,
            key=material,
            chain_code=chain_code,
            path="m",
        )

    def derive(
        self,
        parent: DerivedNode,
        index: int,
        hardened: bool = False,
    ) -> DerivedNode:
        if parent.depth >= MAX_DERIVATION_DEPTH:
            raise KDFError("maximum derivation depth exceeded")

        encoded = encode_path_component(index, hardened)
        context = (
            b"HD-NODE"
            + bytes([parent.depth + 1])
            + encoded
            + parent.key
        )

        child_key = hmac.new(
            parent.chain_code,
            context,
            hashlib.sha256,
        ).digest()

        child_chain_code = hmac.new(
            parent.key,
            b"CHAIN" + context,
            hashlib.sha256,
        ).digest()

        suffix = f"{index}{\"'\" if hardened else \"\"}"

        return DerivedNode(
            depth=parent.depth + 1,
            index=index,
            key=child_key,
            chain_code=child_chain_code,
            path=f"{parent.path}/{suffix}",
        )

    def derive_path(self, path: str) -> DerivedNode:
        if not path or path == "m":
            return self.root

        if not path.startswith("m/"):
            raise KDFError("derivation path must begin with m/")

        node = self.root

        for component in path[2:].split("/"):
            if not component:
                raise KDFError("empty derivation path component")

            hardened = component.endswith("'")
            number = component[:-1] if hardened else component

            if not number.isdigit():
                raise KDFError(f"invalid derivation component: {component}")

            node = self.derive(node, int(number), hardened)

        return node


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def derive_wallet_keys(mnemonic: str, network: str) -> dict[str, str]:
    if not mnemonic.strip():
        raise KDFError("mnemonic/passphrase material must not be empty")
    if network not in {"mainnet", "testnet"}:
        raise KDFError("unsupported network")

    salt = hashlib.sha256(
        f"wallet:{network}".encode()
    ).digest()

    seed = pbkdf2_sha256(
        mnemonic.encode("utf-8"),
        salt,
        iterations=310_000,
        length=64,
    )

    tree = HDKeyTree(seed)

    account = tree.derive_path("m/44'/0'/0'")
    external = tree.derive(account, 0, hardened=False)
    address = tree.derive(external, 0, hardened=False)

    signing_key = hkdf_sha256(
        ikm=address.key,
        salt=address.chain_code,
        info=b"blockchain/signing-key/v1",
        length=32,
    )

    encryption_key = hkdf_sha256(
        ikm=address.key,
        salt=address.chain_code,
        info=b"blockchain/storage-key/v1",
        length=32,
    )

    return {
        "network": network,
        "path": address.path,
        "address_key_fingerprint": fingerprint(address.key),
        "signing_key_fingerprint": fingerprint(signing_key),
        "encryption_key_fingerprint": fingerprint(encryption_key),
    }


def demonstrate_kdfs() -> None:
    password = b"correct horse battery staple"
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")

    pbkdf_key = pbkdf2_sha256(password, salt)
    scrypt_key = scrypt_derive(password, salt)

    hkdf_key = hkdf_sha256(
        ikm=pbkdf_key,
        salt=salt,
        info=b"demo/blockchain/account",
    )

    print("KDF demonstrations")
    print("------------------")
    print("PBKDF2 :", pbkdf_key.hex())
    print("scrypt :", scrypt_key.hex())
    print("HKDF   :", hkdf_key.hex())

    assert len(pbkdf_key) == 32
    assert len(scrypt_key) == 32
    assert len(hkdf_key) == 32

    assert pbkdf_key == pbkdf2_sha256(password, salt)
    assert scrypt_key == scrypt_derive(password, salt)


def demonstrate_wallet() -> None:
    result = derive_wallet_keys(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "testnet",
    )

    print("\nHD-style wallet derivation")
    print("--------------------------")
    for name, value in result.items():
        print(f"{name:28}: {value}")


def demonstrate_failure_conditions() -> None:
    print("\nValidation checks")
    print("-----------------")

    failures = [
        lambda: pbkdf2_sha256(b"", b"0123456789abcdef"),
        lambda: pbkdf2_sha256(b"secret", b"short"),
        lambda: scrypt_derive(b"secret", b"0123456789abcdef", n=1000),
        lambda: HDKeyTree(b"short"),
        lambda: HDKeyTree(secure_random(32)).derive_path("x/44'/0'"),
        lambda: HDKeyTree(secure_random(32)).derive_path("m/44'/abc"),
    ]

    for operation in failures:
        try:
            operation()
        except KDFError as exc:
            print(f"Rejected safely: {exc}")
        else:
            raise AssertionError("expected KDFError")


def demonstrate_file_handling() -> None:
    """
    Store only non-secret audit metadata.

    Secret key material is never written to disk by this example.
    """
    audit_path = Path("kdf_audit.txt")
    lines = [
        "operation=wallet-derivation",
        "algorithm=PBKDF2-HMAC-SHA256",
        "secret_material_persisted=false",
    ]

    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    loaded = audit_path.read_text(encoding="utf-8")
    assert "secret_material_persisted=false" in loaded

    audit_path.unlink(missing_ok=True)


def main() -> None:
    demonstrate_kdfs()
    demonstrate_wallet()
    demonstrate_failure_conditions()
    demonstrate_file_handling()

    print("\nSecurity notes")
    print("--------------")
    print("Use unique random salts for password-derived keys.")
    print("Use memory-hard scrypt or Argon2id for password protection when supported.")
    print("Use HKDF for deriving independent subkeys from already-secret key material.")
    print("Never use a KDF as a substitute for a secure signature algorithm.")
    print("Never log mnemonic phrases, passwords, seeds, private keys, or raw derived keys.")


if __name__ == "__main__":
    main()
