# Day 20: Plaintext, Ciphertext, Keys, Encryption and Decryption

Educational cryptography utilities using **Fernet** from the Python `cryptography` package.

Fernet provides **authenticated symmetric encryption**. The same secret key is required for both encryption and decryption.

This module intentionally uses a well-established cryptographic library instead of implementing a cryptographic algorithm manually.

## Source Code

```
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate a new URL-safe 32-byte Fernet key."""
    return Fernet.generate_key()


def encrypt_text(plaintext: str, key: bytes) -> str:
    """
    Encrypt plaintext and return the ciphertext as a string.

    Parameters
    ----------
    plaintext:
        The readable message that will be encrypted.

    key:
        A valid Fernet key.

    Returns
    -------
    str
        Base64-encoded Fernet ciphertext.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    if not plaintext:
        raise ValueError("plaintext cannot be empty")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    cipher = Fernet(key)
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

    return ciphertext.decode("utf-8")


def decrypt_text(ciphertext: str, key: bytes) -> str:
    """
    Decrypt ciphertext and return the original plaintext.

    Invalid keys and modified ciphertext raise ValueError instead
    of exposing cryptographic implementation details to callers.
    """
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a string")

    if not ciphertext:
        raise ValueError("ciphertext cannot be empty")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    cipher = Fernet(key)

    try:
        plaintext = cipher.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed: the key may be incorrect or "
            "the ciphertext may have been modified."
        ) from exc

    return plaintext.decode("utf-8")


def demonstrate_round_trip(plaintext: str) -> dict[str, str]:
    """
    Perform a complete educational encryption/decryption round trip.

    Returns a dictionary containing the key, plaintext, ciphertext,
    and recovered plaintext.
    """
    key = generate_key()
    ciphertext = encrypt_text(plaintext, key)
    recovered = decrypt_text(ciphertext, key)

    return {
        "key": key.decode("utf-8"),
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "decrypted_plaintext": recovered,
    }


if __name__ == "__main__":
    result = demonstrate_round_trip(
        "Plaintext is transformed into ciphertext using a secret key."
    )

    print("=== Day 20 Encryption Demonstration ===")
    print()

    print(f"Plaintext:           {result['plaintext']}")
    print(f"Encryption key:      {result['key']}")
    print(f"Ciphertext:          {result['ciphertext']}")
    print(f"Decrypted plaintext: {result['decrypted_plaintext']}")

    print()

    print(
        "Round-trip successful:",
        result["plaintext"] == result["decrypted_plaintext"],
    )
```

## What the Code Demonstrates

### Key generation

`generate_key()` creates a new Fernet key using the cryptographic library's secure key-generation mechanism.

The key is represented as bytes:

```
key = generate_key()
```

The key must be protected because anyone who obtains the required secret key may be able to decrypt data protected with that key.

### Encryption

`encrypt_text()` accepts readable plaintext and a secret key.

The plaintext is first converted into UTF-8 bytes:

```
plaintext.encode("utf-8")
```

Fernet then encrypts those bytes:

```
ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
```

The resulting encrypted bytes are converted into a string so that the ciphertext can be displayed and stored conveniently.

The conceptual process is:

```
Plaintext + Secret Key
        |
        v
    Encryption
        |
        v
    Ciphertext
```

### Decryption

`decrypt_text()` performs the reverse operation.

The ciphertext is converted back into bytes and passed to Fernet:

```
plaintext = cipher.decrypt(ciphertext.encode("utf-8"))
```

If the correct key is supplied and the ciphertext is valid, the original plaintext is recovered.

The conceptual process is:

```
Ciphertext + Secret Key
        |
        v
    Decryption
        |
        v
    Plaintext
```

### Wrong keys and modified ciphertext

The function catches `InvalidToken` and converts it into a simpler `ValueError`.

This can occur when:

* the wrong key is supplied
* the ciphertext has been modified
* the ciphertext is invalid
* authentication verification fails

The caller therefore receives a clear application-level error instead of having to handle the underlying cryptographic exception directly.

### Encryption and decryption round trip

`demonstrate_round_trip()` combines the complete process:

```
key = generate_key()

ciphertext = encrypt_text(plaintext, key)

recovered = decrypt_text(ciphertext, key)
```

The resulting dictionary contains:

* the encryption key
* the original plaintext
* the ciphertext
* the recovered plaintext

The demonstration can then verify that:

```
original plaintext == recovered plaintext
```

If the values are equal, the complete encryption and decryption round trip succeeded.

## Important Security Concepts

### Plaintext

Plaintext is the original readable information before encryption.

Example:

```
Plaintext is transformed into ciphertext using a secret key.
```

### Ciphertext

Ciphertext is the protected output produced by encryption.

It is designed so that someone without the required cryptographic key cannot simply read the original message.

### Key

A cryptographic key is secret cryptographic material used by the encryption and decryption process.

For symmetric encryption, the same secret key is used for both operations.

### Encryption

Encryption transforms plaintext into ciphertext.

```
Plaintext -> Encryption -> Ciphertext
```

### Decryption

Decryption transforms valid ciphertext back into plaintext.

```
Ciphertext -> Decryption -> Plaintext
```

### Authenticated encryption

Fernet provides confidentiality together with authentication and integrity protection.

This means the system does not only attempt to hide the plaintext. It also verifies that the protected data has not been altered and that the ciphertext is valid for the supplied key.

## Why a Cryptographic Library Is Used

This project does not implement a new encryption algorithm.

Implementing cryptography manually is dangerous because secure cryptographic systems require careful handling of:

* algorithms
* keys
* randomness
* authentication
* integrity
* serialization
* encoding
* error handling
* implementation details
* security vulnerabilities

Established cryptographic libraries are designed and reviewed specifically for these purposes.

For educational projects, it is useful to understand the concepts while relying on established libraries for actual cryptographic operations.

## Example Workflow

A complete encryption workflow can be represented as:

```
Original Message
      |
      v
   Plaintext
      |
      | Secret Key
      v
  Encryption
      |
      v
  Ciphertext
      |
      | Same Secret Key
      v
  Decryption
      |
      v
   Plaintext
      |
      v
Original Message
```

The important relationship is:

```
Encryption:
Plaintext + Key -> Ciphertext

Decryption:
Ciphertext + Key -> Plaintext
```

## Running the Demonstration

From the project root, run:

```
python src\crypto_utils.py
```

The program generates a key, encrypts a sample plaintext, decrypts the ciphertext, and verifies that the recovered plaintext matches the original.

A successful execution ends with a result similar to:

```
Round-trip successful: True
```

The generated key and ciphertext will change between executions because secure cryptographic systems use fresh values rather than producing identical encrypted output every time.

## Learning Outcome

After studying this module, a learner should understand the relationship between:

```
Plaintext
    |
    v
Encryption + Key
    |
    v
Ciphertext
    |
    v
Decryption + Key
    |
    v
Plaintext
```

The central idea is simple:

**Encryption protects readable information by transforming it into ciphertext using cryptographic key material, while decryption uses the appropriate key to recover the original information.**
