#!/usr/bin/env python3
"""
Digital Certificates: PKI Lifecycle and Trust Validation

Demonstrates:
- Certificate and public key concepts
- Certificate authorities and trust anchors
- Certificate issuance and validation
- Certificate chains
- Expiration and revocation
- Key usage and identity validation
- TLS certificate inspection
- Certificate inventory and lifecycle management

The registry is an educational PKI policy simulator. It does not
replace cryptographic X.509 validation performed by a TLS library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import ssl
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

LOGGER = logging.getLogger("digital_certificates")


class CertificateError(Exception):
    """Base exception for certificate operations."""


class ValidationError(CertificateError):
    """Raised when certificate validation fails."""


class CertificateStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class CertificateType(Enum):
    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code_signing"
    DOCUMENT_SIGNING = "document_signing"


class KeyUsage(Enum):
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    KEY_ENCIPHERMENT = "key_encipherment"


@dataclass(frozen=True)
class Certificate:
    serial_number: str
    subject: str
    issuer: str
    public_key_fingerprint: str
    certificate_type: CertificateType
    not_before: datetime
    not_after: datetime
    key_usages: frozenset[KeyUsage]
    is_ca: bool
    path_length: Optional[int] = None
    status: CertificateStatus = CertificateStatus.ACTIVE
    revocation_reason: Optional[str] = None
    subject_alt_names: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.serial_number:
            raise ValueError("Serial number is required.")

        if not self.subject or not self.issuer:
            raise ValueError("Subject and issuer are required.")

        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("Certificate dates must be timezone-aware.")

        if self.not_after <= self.not_before:
            raise ValueError("Invalid certificate validity period.")

        if not re.fullmatch(r"[0-9a-f]{64}", self.public_key_fingerprint):
            raise ValueError("Fingerprint must be a SHA-256 hexadecimal value.")

        if self.is_ca and KeyUsage.KEY_CERT_SIGN not in self.key_usages:
            raise ValueError("CA certificates require keyCertSign usage.")

        if self.path_length is not None and (
            not self.is_ca or self.path_length < 0
        ):
            raise ValueError("Invalid CA path length.")

    def fingerprint(self) -> str:
        """Identify the modeled certificate using canonical attributes."""
        content = "|".join([
            self.serial_number,
            self.subject,
            self.issuer,
            self.public_key_fingerprint,
            self.not_before.isoformat(),
            self.not_after.isoformat()
        ])

        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def is_valid_at(self, moment: datetime) -> bool:
        return (
            self.status == CertificateStatus.ACTIVE
            and self.not_before <= moment <= self.not_after
        )


@dataclass
class CertificateAuthority:
    name: str
    certificate: Certificate
    trusted: bool = False

    def __post_init__(self):
        if not self.certificate.is_ca:
            raise ValueError("A CA must have a CA certificate.")

        if self.certificate.subject != self.name:
            raise ValueError("CA name must match certificate subject.")


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)

    def display(self):
        print("\nCertificate Validation")
        print("=" * 45)
        print(f"Valid: {self.valid}")

        for name in self.chain:
            print(f"  Chain: {name}")

        for error in self.errors:
            print(f"  ERROR: {error}")


class CertificateRegistry:
    """Maintains certificates and their lifecycle states."""

    def __init__(self):
        self.certificates: dict[str, Certificate] = {}
        self.authorities: dict[str, CertificateAuthority] = {}
        self.revoked_serials: set[str] = set()

    def register_ca(self, authority: CertificateAuthority):
        name = authority.name

        if name in self.authorities:
            raise CertificateError(f"CA already registered: {name}")

        self.authorities[name] = authority
        self.certificates[authority.certificate.serial_number] = (
            authority.certificate
        )

    def issue(self, certificate: Certificate):
        if certificate.serial_number in self.certificates:
            raise CertificateError("Duplicate certificate serial number.")

        issuer = self.authorities.get(certificate.issuer)

        if issuer is None:
            raise CertificateError("Unknown issuing authority.")

        if not issuer.certificate.is_valid_at(datetime.now(timezone.utc)):
            raise CertificateError("Issuing CA is not currently valid.")

        if not issuer.certificate.trusted and (
            issuer.certificate.certificate_type == CertificateType.ROOT_CA
        ):
            raise CertificateError("Root CA is not trusted.")

        if not issuer.certificate.is_ca:
            raise CertificateError("Issuer is not a CA.")

        if not certificate.is_ca and KeyUsage.KEY_CERT_SIGN in certificate.key_usages:
            raise CertificateError("End-entity certificate has CA signing usage.")

        self.certificates[certificate.serial_number] = certificate

    def revoke(self, serial_number: str, reason: str):
        certificate = self.certificates.get(serial_number)

        if certificate is None:
            raise CertificateError("Certificate not found.")

        if certificate.status == CertificateStatus.REVOKED:
            raise CertificateError("Certificate already revoked.")

        if not reason.strip():
            raise ValueError("Revocation reason is required.")

        updated = Certificate(
            serial_number=certificate.serial_number,
            subject=certificate.subject,
            issuer=certificate.issuer,
            public_key_fingerprint=certificate.public_key_fingerprint,
            certificate_type=certificate.certificate_type,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            key_usages=certificate.key_usages,
            is_ca=certificate.is_ca,
            path_length=certificate.path_length,
            status=CertificateStatus.REVOKED,
            revocation_reason=reason,
            subject_alt_names=certificate.subject_alt_names
        )

        self.certificates[serial_number] = updated
        self.revoked_serials.add(serial_number)

    def get(self, serial_number: str) -> Certificate:
        try:
            return self.certificates[serial_number]
        except KeyError:
            raise CertificateError(
                f"Unknown certificate: {serial_number}"
            ) from None

    def inventory(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        results = []

        for certificate in self.certificates.values():
            if certificate.status == CertificateStatus.REVOKED:
                status = "revoked"
            elif now < certificate.not_before:
                status = "not_yet_valid"
            elif now > certificate.not_after:
                status = "expired"
            else:
                status = "active"

            results.append({
                "serial_number": certificate.serial_number,
                "subject": certificate.subject,
                "issuer": certificate.issuer,
                "type": certificate.certificate_type.value,
                "status": status,
                "expires": certificate.not_after.isoformat(),
                "fingerprint": certificate.fingerprint()
            })

        return sorted(results, key=lambda item: item["serial_number"])

    def save_inventory(self, filename: str):
        """Write inventory using an atomic replacement."""
        destination = Path(filename)
        destination.parent.mkdir(parents=True, exist_ok=True)

        temporary = destination.with_suffix(destination.suffix + ".tmp")

        try:
            temporary.write_text(
                json.dumps(self.inventory(), indent=2),
                encoding="utf-8"
            )
            temporary.replace(destination)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise


class CertificateValidator:
    """Validates modeled certificate paths and identity constraints."""

    def __init__(self, registry: CertificateRegistry):
        self.registry = registry

    def validate(
        self,
        serial_number: str,
        hostname: Optional[str] = None,
        required_usage: Optional[KeyUsage] = None,
        moment: Optional[datetime] = None
    ) -> ValidationResult:

        moment = moment or datetime.now(timezone.utc)
        errors = []
        chain = []
        visited = set()

        try:
            current = self.registry.get(serial_number)
        except CertificateError as error:
            return ValidationResult(False, [str(error)])

        original = current

        while True:
            if current.serial_number in visited:
                errors.append("Certificate chain contains a cycle.")
                break

            visited.add(current.serial_number)
            chain.append(current.subject)

            if current.serial_number in self.registry.revoked_serials:
                errors.append(f"Certificate revoked: {current.subject}")

            if not current.is_valid_at(moment):
                errors.append(
                    f"Certificate is expired, suspended, or not yet valid: "
                    f"{current.subject}"
                )

            if current.is_ca and KeyUsage.KEY_CERT_SIGN not in current.key_usages:
                errors.append(f"Invalid CA key usage: {current.subject}")

            if current.issuer == current.subject:
                authority = self.registry.authorities.get(current.subject)

                if authority is None or not authority.trusted:
                    errors.append("Untrusted root certificate.")

                break

            issuer_authority = self.registry.authorities.get(current.issuer)

            if issuer_authority is None:
                errors.append(f"Unknown issuer: {current.issuer}")
                break

            issuer = issuer_authority.certificate

            if not issuer.is_ca:
                errors.append("Issuer certificate is not a CA.")

            if not issuer.is_valid_at(moment):
                errors.append("Issuing CA is not currently valid.")

            if issuer.certificate_type == CertificateType.ROOT_CA:
                if not issuer_authority.trusted:
                    errors.append("Untrusted root CA.")

            current = issuer

        if hostname:
            if original.certificate_type != CertificateType.SERVER:
                errors.append("Hostname validation requires a server certificate.")
            elif hostname not in original.subject_alt_names:
                errors.append(f"Hostname mismatch: {hostname}")

        if required_usage and required_usage not in original.key_usages:
            errors.append(f"Required key usage missing: {required_usage.value}")

        return ValidationResult(
            valid=not errors,
            errors=errors,
            chain=chain
        )


def inspect_tls_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0
) -> dict:
    """
    Retrieve a live server certificate using Python's TLS validation.

    The default SSL context validates the certificate chain and hostname
    against the operating system's configured trust store.
    """
    if not hostname or not 1 <= port <= 65535:
        raise ValueError("Invalid hostname or port.")

    context = ssl.create_default_context()

    with socket.create_connection(
        (hostname, port), timeout=timeout
    ) as connection:
        with context.wrap_socket(
            connection, server_hostname=hostname
        ) as secure_connection:

            certificate = secure_connection.getpeercert()
            der_certificate = secure_connection.getpeercert(binary_form=True)

            return {
                "hostname": hostname,
                "port": secure_connection.getpeername()[1],
                "tls_version": secure_connection.version(),
                "cipher": secure_connection.cipher(),
                "subject": certificate.get("subject"),
                "issuer": certificate.get("issuer"),
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
                "sha256_fingerprint": hashlib.sha256(
                    der_certificate
                ).hexdigest()
            }


def create_demo_registry() -> CertificateRegistry:
    registry = CertificateRegistry()

    now = datetime.now(timezone.utc)
    root_name = "Example Root CA"
    intermediate_name = "Example Intermediate CA"

    root = Certificate(
        serial_number="1000",
        subject=root_name,
        issuer=root_name,
        public_key_fingerprint=hashlib.sha256(
            b"example-root-public-key"
        ).hexdigest(),
        certificate_type=CertificateType.ROOT_CA,
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=3650),
        key_usages=frozenset({
            KeyUsage.KEY_CERT_SIGN,
            KeyUsage.CRL_SIGN
        }),
        is_ca=True,
        path_length=1
    )

    registry.register_ca(
        CertificateAuthority(root_name, root, trusted=True)
    )

    intermediate = Certificate(
        serial_number="2000",
        subject=intermediate_name,
        issuer=root_name,
        public_key_fingerprint=hashlib.sha256(
            b"example-intermediate-public-key"
        ).hexdigest(),
        certificate_type=CertificateType.INTERMEDIATE_CA,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=730),
        key_usages=frozenset({
            KeyUsage.KEY_CERT_SIGN,
            KeyUsage.CRL_SIGN
        }),
        is_ca=True,
        path_length=0
    )

    registry.register_ca(
        CertificateAuthority(intermediate_name, intermediate)
    )

    server = Certificate(
        serial_number="3000",
        subject="www.example.com",
        issuer=intermediate_name,
        public_key_fingerprint=hashlib.sha256(
            b"example-server-public-key"
        ).hexdigest(),
        certificate_type=CertificateType.SERVER,
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=90),
        key_usages=frozenset({
            KeyUsage.DIGITAL_SIGNATURE,
            KeyUsage.KEY_ENCIPHERMENT
        }),
        is_ca=False,
        subject_alt_names=("www.example.com", "api.example.com")
    )

    registry.issue(server)

    client = Certificate(
        serial_number="3001",
        subject="service-account@example.com",
        issuer=intermediate_name,
        public_key_fingerprint=hashlib.sha256(
            b"example-client-public-key"
        ).hexdigest(),
        certificate_type=CertificateType.CLIENT,
        not_before=now - timedelta(days=2),
        not_after=now + timedelta(days=180),
        key_usages=frozenset({
            KeyUsage.DIGITAL_SIGNATURE
        }),
        is_ca=False
    )

    registry.issue(client)

    return registry


def run_tests(registry: CertificateRegistry):
    validator = CertificateValidator(registry)

    valid = validator.validate(
        "3000",
        hostname="www.example.com",
        required_usage=KeyUsage.DIGITAL_SIGNATURE
    )

    assert valid.valid, valid.errors

    invalid_hostname = validator.validate(
        "3000",
        hostname="attacker.example.net"
    )

    assert not invalid_hostname.valid

    invalid_usage = validator.validate(
        "3001",
        required_usage=KeyUsage.KEY_CERT_SIGN
    )

    assert not invalid_usage.valid

    registry.revoke("3001", "Key compromise")

    revoked = validator.validate("3001")
    assert not revoked.valid

    LOGGER.info("All certificate lifecycle tests passed.")


def main():
    parser = argparse.ArgumentParser(
        description="Digital certificate lifecycle simulator"
    )

    parser.add_argument(
        "--inspect",
        help="Inspect a live TLS certificate for a hostname"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=443
    )

    parser.add_argument(
        "--inventory",
        default="certificate_inventory.json"
    )

    args = parser.parse_args()

    if args.inspect:
        try:
            result = inspect_tls_certificate(args.inspect, args.port)
            print(json.dumps(result, indent=2))
        except (
            ssl.SSLError,
            socket.timeout,
            OSError,
            ValueError
        ) as error:
            LOGGER.error("TLS inspection failed: %s", error)
            raise SystemExit(1)

        return

    registry = create_demo_registry()
    validator = CertificateValidator(registry)

    run_tests(registry)

    validator.validate(
        "3000",
        hostname="www.example.com",
        required_usage=KeyUsage.DIGITAL_SIGNATURE
    ).display()

    registry.save_inventory(args.inventory)

    print("\nCertificate Inventory")
    print("=" * 45)

    for item in registry.inventory():
        print(
            f"{item['serial_number']} | "
            f"{item['subject']} | "
            f"{item['status']} | "
            f"Expires: {item['expires']}"
        )

    print(f"\nInventory saved to: {args.inventory}")


if __name__ == "__main__":
    main()
