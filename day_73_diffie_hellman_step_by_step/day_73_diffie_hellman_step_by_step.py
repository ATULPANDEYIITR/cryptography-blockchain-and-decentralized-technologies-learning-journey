#!/usr/bin/env python3
"""
DIFFIE-HELLMAN KEY EXCHANGE: STEP-BY-STEP IMPLEMENTATION

Demonstrates:
1. Prime modulus and generator selection.
2. Private key generation.
3. Public key computation.
4. Public key exchange.
5. Shared secret computation.
6. Independent secret verification.
7. Subgroup and public-key validation.
8. HKDF-style key derivation using HMAC-SHA256.
9. Man-in-the-middle attack simulation.
10. Security considerations and automated tests.

IMPORTANT:
The small parameters are exclusively for mathematical learning.
Production systems should use authenticated X25519 or another
approved key-agreement implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DiffieHellmanError(Exception):
    """Base exception for key exchange failures."""


class InvalidParametersError(DiffieHellmanError):
    """Raised when cryptographic parameters are invalid."""


class InvalidPublicKeyError(DiffieHellmanError):
    """Raised when a received public key is invalid."""


class ExchangeState(Enum):
    INITIALIZED = "initialized"
    KEYS_GENERATED = "keys_generated"
    EXCHANGED = "exchanged"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class DHParameters:
    """
    Finite-field Diffie-Hellman parameters.

    p: prime modulus.
    q: prime subgroup order.
    g: generator of the subgroup.
    """

    p: int
    q: int
    g: int

    def validate(self) -> None:
        if self.p <= 5 or self.q <= 2:
            raise InvalidParametersError("Parameters are too small.")

        if not self._is_prime(self.p):
            raise InvalidParametersError("p must be prime.")

        if not self._is_prime(self.q):
            raise InvalidParametersError("q must be prime.")

        if (self.p - 1) % self.q != 0:
            raise InvalidParametersError("q must divide p - 1.")

        if not 1 < self.g < self.p:
            raise InvalidParametersError("Generator is out of range.")

        if pow(self.g, self.q, self.p) != 1:
            raise InvalidParametersError(
                "Generator does not belong to the required subgroup."
            )

        if self.g == 1:
            raise InvalidParametersError("Generator cannot be 1.")

    @staticmethod
    def _is_prime(number: int) -> bool:
        if number < 2:
            return False

        if number % 2 == 0:
            return number == 2

        divisor = 3

        while divisor * divisor <= number:
            if number % divisor == 0:
                return False
            divisor += 2

        return True


@dataclass
class Participant:
    name: str
    parameters: DHParameters
    private_key: Optional[int] = None
    public_key: Optional[int] = None

    def generate_keys(self) -> None:
        self.parameters.validate()

        # The private exponent is sampled from the subgroup range.
        self.private_key = secrets.randbelow(
            self.parameters.q - 1
        ) + 1

        self.public_key = pow(
            self.parameters.g,
            self.private_key,
            self.parameters.p
        )

    def validate_public_key(self, received_key: int) -> None:
        p = self.parameters.p
        q = self.parameters.q

        if not isinstance(received_key, int) or isinstance(received_key, bool):
            raise InvalidPublicKeyError("Public key must be an integer.")

        if not 2 <= received_key <= p - 2:
            raise InvalidPublicKeyError(
                "Public key is outside the accepted range."
            )

        # Reject values outside the intended prime-order subgroup.
        if pow(received_key, q, p) != 1:
            raise InvalidPublicKeyError(
                "Public key is not in the required subgroup."
            )

    def compute_shared_secret(self, received_key: int) -> int:
        if self.private_key is None:
            raise DiffieHellmanError("Private key has not been generated.")

        self.validate_public_key(received_key)

        return pow(
            received_key,
            self.private_key,
            self.parameters.p
        )


class DiffieHellmanExchange:
    def __init__(self, parameters: DHParameters):
        parameters.validate()

        self.parameters = parameters

        self.alice = Participant("Alice", parameters)
        self.bob = Participant("Bob", parameters)

        self.state = ExchangeState.INITIALIZED

        self.shared_secret: Optional[int] = None

    def execute(self, verbose: bool = True) -> int:
        try:
            if verbose:
                print("\nSTEP 1: Public parameters")

                print(f"Prime modulus (p): {self.parameters.p}")
                print(f"Subgroup order (q): {self.parameters.q}")
                print(f"Generator (g): {self.parameters.g}")

            self.alice.generate_keys()
            self.bob.generate_keys()

            self.state = ExchangeState.KEYS_GENERATED

            if verbose:
                print("\nSTEP 2: Private key generation")

                print(f"Alice private key: {self.alice.private_key}")
                print(f"Bob private key:   {self.bob.private_key}")

                print("\nSTEP 3: Public key computation")

                print(
                    f"Alice public key: "
                    f"{self.parameters.g}^{self.alice.private_key} "
                    f"mod {self.parameters.p} = "
                    f"{self.alice.public_key}"
                )

                print(
                    f"Bob public key: "
                    f"{self.parameters.g}^{self.bob.private_key} "
                    f"mod {self.parameters.p} = "
                    f"{self.bob.public_key}"
                )

            # Only public keys are exchanged.
            alice_received = self.bob.public_key
            bob_received = self.alice.public_key

            self.state = ExchangeState.EXCHANGED

            if verbose:
                print("\nSTEP 4: Public key exchange")
                print(f"Alice receives: {alice_received}")
                print(f"Bob receives:   {bob_received}")

            alice_secret = self.alice.compute_shared_secret(
                alice_received
            )

            bob_secret = self.bob.compute_shared_secret(
                bob_received
            )

            if verbose:
                print("\nSTEP 5: Shared secret calculation")

                print(
                    f"Alice computes: "
                    f"{alice_received}^{self.alice.private_key} "
                    f"mod {self.parameters.p}"
                )

                print(
                    f"Bob computes: "
                    f"{bob_received}^{self.bob.private_key} "
                    f"mod {self.parameters.p}"
                )

                print(f"Alice shared secret: {alice_secret}")
                print(f"Bob shared secret:   {bob_secret}")

            if alice_secret != bob_secret:
                raise DiffieHellmanError(
                    "Shared secret verification failed."
                )

            self.shared_secret = alice_secret
            self.state = ExchangeState.COMPLETED

            if verbose:
                print("\nSTEP 6: Secret verification")
                print("Both participants calculated the same secret.")
                print("Exchange state:", self.state.value)

            return alice_secret

        except Exception:
            self.state = ExchangeState.FAILED
            raise


def derive_session_key(
    shared_secret: int,
    context: bytes,
    output_length: int = 32
) -> bytes:
    """
    Educational HKDF-SHA256 implementation.

    The DH output is input key material, not a directly
    usable encryption key.
    """

    if not isinstance(shared_secret, int) or shared_secret <= 0:
        raise ValueError("Shared secret must be a positive integer.")

    if not isinstance(context, bytes):
        raise TypeError("Context must be bytes.")

    if not 1 <= output_length <= 255 * 32:
        raise ValueError("Invalid HKDF output length.")

    input_key_material = shared_secret.to_bytes(
        max(1, (shared_secret.bit_length() + 7) // 8),
        "big"
    )

    salt = b"DH educational demonstration salt"

    pseudorandom_key = hmac.new(
        salt,
        input_key_material,
        hashlib.sha256
    ).digest()

    output = b""
    previous_block = b""

    counter = 1

    while len(output) < output_length:
        previous_block = hmac.new(
            pseudorandom_key,
            previous_block + context + bytes([counter]),
            hashlib.sha256
        ).digest()

        output += previous_block
        counter += 1

    return output[:output_length]


def simulate_man_in_the_middle(
    parameters: DHParameters
) -> None:
    """
    Demonstrates why unauthenticated DH is vulnerable.

    Mallory establishes one secret with Alice and another
    independent secret with Bob.
    """

    print("\nMAN-IN-THE-MIDDLE ATTACK")

    alice = Participant("Alice", parameters)
    bob = Participant("Bob", parameters)

    mallory_to_alice = Participant("Mallory-A", parameters)
    mallory_to_bob = Participant("Mallory-B", parameters)

    for participant in (
        alice,
        bob,
        mallory_to_alice,
        mallory_to_bob
    ):
        participant.generate_keys()

    # Mallory substitutes her public keys.
    alice_secret = alice.compute_shared_secret(
        mallory_to_alice.public_key
    )

    mallory_alice_secret = mallory_to_alice.compute_shared_secret(
        alice.public_key
    )

    bob_secret = bob.compute_shared_secret(
        mallory_to_bob.public_key
    )

    mallory_bob_secret = mallory_to_bob.compute_shared_secret(
        bob.public_key
    )

    assert alice_secret == mallory_alice_secret
    assert bob_secret == mallory_bob_secret

    assert alice_secret != bob_secret or (
        mallory_to_alice.private_key == mallory_to_bob.private_key
    )

    print("Alice shares a secret with Mallory.")
    print("Bob shares a separate secret with Mallory.")
    print("Mallory can independently derive both secrets.")
    print("Alice and Bob do not have an authenticated shared identity.")

    print("Alice-Mallory secret:", alice_secret)
    print("Mallory-Bob secret:  ", bob_secret)

    print(
        "Protection: authenticate the key exchange using "
        "certificates, signatures, or an authenticated protocol."
    )


def run_tests() -> None:
    print("\nAUTOMATED VALIDATION")

    parameters = DHParameters(p=23, q=11, g=2)

    parameters.validate()

    alice = Participant("TestAlice", parameters)
    bob = Participant("TestBob", parameters)

    alice.generate_keys()
    bob.generate_keys()

    assert alice.compute_shared_secret(bob.public_key) == (
        bob.compute_shared_secret(alice.public_key)
    )

    try:
        alice.validate_public_key(1)
        raise AssertionError("Invalid public key was accepted.")
    except InvalidPublicKeyError:
        pass

    try:
        alice.validate_public_key(5)
        raise AssertionError("Non-subgroup key was accepted.")
    except InvalidPublicKeyError:
        pass

    try:
        DHParameters(21, 5, 2).validate()
        raise AssertionError("Composite modulus was accepted.")
    except InvalidParametersError:
        pass

    try:
        derive_session_key(0, b"test")
        raise AssertionError("Invalid secret was accepted.")
    except ValueError:
        pass

    key1 = derive_session_key(123, b"session-A")
    key2 = derive_session_key(123, b"session-B")

    assert len(key1) == 32
    assert key1 != key2

    print("Valid exchange: PASS")
    print("Public key range validation: PASS")
    print("Subgroup validation: PASS")
    print("Composite modulus rejection: PASS")
    print("Invalid secret rejection: PASS")
    print("Context-dependent key derivation: PASS")


def main() -> None:
    # Tiny educational parameters, NOT production parameters.
    parameters = DHParameters(
        p=23,
        q=11,
        g=2
    )

    exchange = DiffieHellmanExchange(parameters)

    shared_secret = exchange.execute()

    print("\nSTEP 7: Session key derivation")

    session_key = derive_session_key(
        shared_secret,
        b"Alice-Bob|DH-demo|session-001"
    )

    print("Derived session key:", session_key.hex())

    simulate_man_in_the_middle(parameters)

    run_tests()

    print("\nSECURITY CONSIDERATIONS")
    print("1. Never transmit private exponents.")
    print("2. Never use small demonstration parameters in production.")
    print("3. Validate received public values.")
    print("4. Authenticate the peer and the key exchange.")
    print("5. Use ephemeral keys for forward secrecy.")
    print("6. Derive encryption keys with a standard KDF.")
    print("7. Bind keys to identities and the complete transcript.")
    print("8. Use a vetted X25519 or approved DH implementation.")
    print("9. Protect private keys against memory disclosure.")
    print("10. Use authenticated encryption for application data.")

    print("\nAll demonstrations completed successfully.")


if __name__ == "__main__":
    main()
