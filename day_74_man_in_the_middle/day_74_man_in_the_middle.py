#!/usr/bin/env python3
"""
Man-in-the-Middle Attack on Key Exchange
----------------------------------------
Educational simulation of:
1. Unauthenticated Diffie-Hellman key exchange.
2. A man-in-the-middle replacing public key values.
3. Independent session keys established with each victim.
4. Authentication using a pre-shared secret.
5. Transcript integrity verification.
6. Detection and rejection of unauthenticated exchanges.

IMPORTANT:
The small Diffie-Hellman parameters are intentionally insecure.
They demonstrate protocol mechanics and must never be used in production.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Educational parameters only. Not cryptographically secure.
PRIME = 23
GENERATOR = 5


class ExchangeState(Enum):
    CREATED = "created"
    NEGOTIATING = "negotiating"
    ESTABLISHED = "established"
    REJECTED = "rejected"
    COMPROMISED = "compromised"


class SecurityError(Exception):
    """Raised when a security verification fails."""


class ValidationError(Exception):
    """Raised when protocol input is invalid."""


def validate_public_key(public_key: int) -> None:
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise ValidationError("Public key must be an integer.")

    if not 1 < public_key < PRIME:
        raise ValidationError("Public key is outside the permitted range.")


def derive_key(shared_secret: int, transcript: str) -> bytes:
    """Derive a demonstration session key using SHA-256."""
    material = f"{shared_secret}:{transcript}".encode()
    return hashlib.sha256(material).digest()


def calculate_tag(key: bytes, transcript: str) -> str:
    """Authenticate the exchange transcript using HMAC-SHA256."""
    return hmac.new(
        key,
        transcript.encode(),
        hashlib.sha256
    ).hexdigest()


@dataclass
class Participant:
    name: str
    private_key: int = field(
        default_factory=lambda: secrets.randbelow(PRIME - 2) + 1
    )
    state: ExchangeState = ExchangeState.CREATED

    @property
    def public_key(self) -> int:
        return pow(GENERATOR, self.private_key, PRIME)

    def calculate_shared_secret(self, peer_public_key: int) -> int:
        validate_public_key(peer_public_key)
        return pow(peer_public_key, self.private_key, PRIME)


@dataclass
class ExchangeResult:
    initiator_key: bytes
    responder_key: bytes
    attacker_key_left: Optional[bytes] = None
    attacker_key_right: Optional[bytes] = None
    intercepted_messages: list[str] = field(default_factory=list)
    authenticated: bool = False
    compromised: bool = False


class ManInTheMiddle:
    """
    Simulates interception and replacement of public key values.

    The attacker independently establishes one shared secret with
    each participant.
    """

    def __init__(self, name: str = "Mallory"):
        self.name = name
        self.intercepted_messages: list[str] = []

    def intercept(self, sender: str, message: str) -> str:
        self.intercepted_messages.append(
            f"{sender}: {message}"
        )
        return message

    def attack(
        self,
        alice: Participant,
        bob: Participant
    ) -> ExchangeResult:

        alice.state = ExchangeState.NEGOTIATING
        bob.state = ExchangeState.NEGOTIATING

        # Mallory generates two independent private keys.
        mallory_left = secrets.randbelow(PRIME - 2) + 1
        mallory_right = secrets.randbelow(PRIME - 2) + 1

        mallory_public_left = pow(
            GENERATOR, mallory_left, PRIME
        )
        mallory_public_right = pow(
            GENERATOR, mallory_right, PRIME
        )

        # Alice believes Mallory's public key belongs to Bob.
        alice_secret = alice.calculate_shared_secret(
            mallory_public_left
        )

        # Bob believes Mallory's public key belongs to Alice.
        bob_secret = bob.calculate_shared_secret(
            mallory_public_right
        )

        # Mallory calculates both corresponding secrets.
        attacker_secret_left = pow(
            alice.public_key, mallory_left, PRIME
        )
        attacker_secret_right = pow(
            bob.public_key, mallory_right, PRIME
        )

        assert alice_secret == attacker_secret_left
        assert bob_secret == attacker_secret_right

        alice_key = derive_key(
            alice_secret, "Alice-Mallory"
        )
        bob_key = derive_key(
            bob_secret, "Mallory-Bob"
        )

        attacker_key_left = derive_key(
            attacker_secret_left, "Alice-Mallory"
        )
        attacker_key_right = derive_key(
            attacker_secret_right, "Mallory-Bob"
        )

        alice.state = ExchangeState.ESTABLISHED
        bob.state = ExchangeState.ESTABLISHED

        return ExchangeResult(
            initiator_key=alice_key,
            responder_key=bob_key,
            attacker_key_left=attacker_key_left,
            attacker_key_right=attacker_key_right,
            intercepted_messages=self.intercepted_messages.copy(),
            compromised=True
        )


class AuthenticatedKeyExchange:
    """
    Demonstrates authentication using a pre-shared key.

    Both parties must already possess the same trusted secret.
    HMAC binds the exchanged public values to the participants.
    """

    def __init__(self, identity_secrets: dict[str, bytes]):
        self.identity_secrets = identity_secrets

    def authenticate(
        self,
        participant: Participant,
        peer_name: str,
        peer_public_key: int,
        received_tag: str,
        transcript: str
    ) -> bool:

        validate_public_key(peer_public_key)

        secret = self.identity_secrets.get(participant.name)

        if secret is None:
            raise SecurityError("Missing trusted identity secret.")

        expected = calculate_tag(secret, transcript)

        if not hmac.compare_digest(expected, received_tag):
            participant.state = ExchangeState.REJECTED
            raise SecurityError(
                f"Authentication failed for {peer_name}."
            )

        return True

    def establish(
        self,
        alice: Participant,
        bob: Participant
    ) -> bytes:

        alice.state = ExchangeState.NEGOTIATING
        bob.state = ExchangeState.NEGOTIATING

        alice_public = alice.public_key
        bob_public = bob.public_key

        validate_public_key(alice_public)
        validate_public_key(bob_public)

        # The transcript includes both identities and both public keys.
        transcript = (
            f"DH-v1|Alice={alice.name}|Bob={bob.name}"
            f"|A={alice_public}|B={bob_public}"
        )

        alice_secret = self.identity_secrets["Alice"]
        bob_secret = self.identity_secrets["Bob"]

        # This example uses a common trusted exchange key.
        if not hmac.compare_digest(alice_secret, bob_secret):
            alice.state = ExchangeState.REJECTED
            bob.state = ExchangeState.REJECTED
            raise SecurityError("Participants do not share a trusted key.")

        alice_tag = calculate_tag(alice_secret, transcript)
        bob_tag = calculate_tag(bob_secret, transcript)

        self.authenticate(
            alice, bob.name, bob_public, bob_tag, transcript
        )

        self.authenticate(
            bob, alice.name, alice_public, alice_tag, transcript
        )

        alice_shared = alice.calculate_shared_secret(bob_public)
        bob_shared = bob.calculate_shared_secret(alice_public)

        if alice_shared != bob_shared:
            raise SecurityError("Shared-secret disagreement.")

        alice.state = ExchangeState.ESTABLISHED
        bob.state = ExchangeState.ESTABLISHED

        return derive_key(alice_shared, transcript)


def demonstrate_unauthenticated_attack() -> ExchangeResult:
    print("\n1. Unauthenticated Diffie-Hellman demonstration")

    alice = Participant("Alice")
    bob = Participant("Bob")
    attacker = ManInTheMiddle()

    print("Alice public key:", alice.public_key)
    print("Bob public key:", bob.public_key)

    result = attacker.attack(alice, bob)

    print("Alice session key:", result.initiator_key.hex())
    print("Bob session key:  ", result.responder_key.hex())

    print(
        "Alice and Bob have the same key:",
        hmac.compare_digest(
            result.initiator_key,
            result.responder_key
        )
    )

    print(
        "Attacker can derive Alice's key:",
        hmac.compare_digest(
            result.initiator_key,
            result.attacker_key_left
        )
    )

    print(
        "Attacker can derive Bob's key:",
        hmac.compare_digest(
            result.responder_key,
            result.attacker_key_right
        )
    )

    print("Attack status:", "COMPROMISED")
    return result


def demonstrate_authenticated_exchange() -> bytes:
    print("\n2. Authenticated key exchange demonstration")

    alice = Participant("Alice")
    bob = Participant("Bob")

    trusted_secret = secrets.token_bytes(32)

    exchange = AuthenticatedKeyExchange({
        "Alice": trusted_secret,
        "Bob": trusted_secret
    })

    session_key = exchange.establish(alice, bob)

    print("Authentication:", "SUCCESS")
    print("Alice state:", alice.state.value)
    print("Bob state:", bob.state.value)
    print("Session key:", session_key.hex())

    return session_key


def demonstrate_tampering_detection() -> None:
    print("\n3. Public-key substitution detection")

    alice = Participant("Alice")
    bob = Participant("Bob")

    trusted_secret = secrets.token_bytes(32)

    exchange = AuthenticatedKeyExchange({
        "Alice": trusted_secret,
        "Bob": trusted_secret
    })

    original_transcript = (
        f"DH-v1|Alice=Alice|Bob=Bob"
        f"|A={alice.public_key}|B={bob.public_key}"
    )

    legitimate_tag = calculate_tag(
        trusted_secret, original_transcript
    )

    tampered_transcript = original_transcript.replace(
        f"|B={bob.public_key}",
        "|B=7"
    )

    try:
        exchange.authenticate(
            alice,
            "Bob",
            7,
            legitimate_tag,
            tampered_transcript
        )
    except (SecurityError, ValidationError) as error:
        print("Tampering detected:", error)


class SecurityTests(unittest.TestCase):

    def test_dh_shared_secret(self):
        alice = Participant("Alice")
        bob = Participant("Bob")

        self.assertEqual(
            alice.calculate_shared_secret(bob.public_key),
            bob.calculate_shared_secret(alice.public_key)
        )

    def test_mitm_creates_separate_keys(self):
        alice = Participant("Alice")
        bob = Participant("Bob")

        result = ManInTheMiddle().attack(alice, bob)

        self.assertNotEqual(
            result.initiator_key,
            result.responder_key
        )

        self.assertTrue(result.compromised)

    def test_authenticated_exchange(self):
        alice = Participant("Alice")
        bob = Participant("Bob")
        trusted = secrets.token_bytes(32)

        exchange = AuthenticatedKeyExchange({
            "Alice": trusted,
            "Bob": trusted
        })

        key = exchange.establish(alice, bob)

        self.assertEqual(len(key), 32)
        self.assertEqual(
            alice.state, ExchangeState.ESTABLISHED
        )

    def test_wrong_trust_secret_rejected(self):
        alice = Participant("Alice")
        bob = Participant("Bob")

        exchange = AuthenticatedKeyExchange({
            "Alice": b"A" * 32,
            "Bob": b"B" * 32
        })

        with self.assertRaises(SecurityError):
            exchange.establish(alice, bob)

    def test_invalid_public_key(self):
        with self.assertRaises(ValidationError):
            validate_public_key(0)


def main():
    print("=" * 65)
    print("MAN-IN-THE-MIDDLE ATTACK ON KEY EXCHANGE")
    print("=" * 65)
    print("Educational simulation using insecure toy DH parameters.")

    demonstrate_unauthenticated_attack()
    demonstrate_authenticated_exchange()
    demonstrate_tampering_detection()

    print("\n4. Automated security tests")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        SecurityTests
    )

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print("\nExecution completed.")
    print("Tests passed:", result.testsRun - len(result.failures) - len(result.errors))
    print("Tests failed:", len(result.failures) + len(result.errors))

    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
