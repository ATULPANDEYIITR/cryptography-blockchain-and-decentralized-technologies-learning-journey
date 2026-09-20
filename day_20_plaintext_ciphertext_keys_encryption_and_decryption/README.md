# Day 20: Plaintext, Ciphertext, Keys, Encryption and Decryption



Educational cryptography utilities using Fernet from the Python

cryptography package.



Fernet provides authenticated symmetric encryption. The same secret

key is required for both encryption and decryption.



This module intentionally uses a well-established cryptographic

library instead of implementing a cryptographic algorithm manually.

from \_\_future\_\_ import annotations

from cryptography.fernet import Fernet, InvalidToken

def generate\_key() -> bytes:

&#x20;   """Generate a new URL-safe 32-byte Fernet key."""

&#x20;   return Fernet.generate\_key()

def encrypt\_text(plaintext: str, key: bytes) -> str:

&#x20;   """

&#x20;   Encrypt plaintext and return the ciphertext as a string.

&#x20;   Parameters

&#x20;   ----------

&#x20;   plaintext:

&#x20;       The readable message that will be encrypted.

&#x20;   key:

&#x20;       A valid Fernet key.

&#x20;   Returns

&#x20;   -------

&#x20;   str

&#x20;       Base64-encoded Fernet ciphertext.

&#x20;   """

&#x20;   if not isinstance(plaintext, str):

&#x20;       raise TypeError("plaintext must be a string")

&#x20;   if not plaintext:

&#x20;       raise ValueError("plaintext cannot be empty")

&#x20;   if not isinstance(key, bytes):

&#x20;       raise TypeError("key must be bytes")

&#x20;   cipher = Fernet(key)

&#x20;   ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

&#x20;   return ciphertext.decode("utf-8")

def decrypt\_text(ciphertext: str, key: bytes) -> str:

&#x20;   """

&#x20;   Decrypt ciphertext and return the original plaintext.

&#x20;   Invalid keys and modified ciphertext raise ValueError instead

&#x20;   of exposing cryptographic implementation details to callers.

&#x20;   """

&#x20;   if not isinstance(ciphertext, str):

&#x20;       raise TypeError("ciphertext must be a string")



&#x20;   if not ciphertext:

&#x20;       raise ValueError("ciphertext cannot be empty")



&#x20;   if not isinstance(key, bytes):

&#x20;       raise TypeError("key must be bytes")



&#x20;   cipher = Fernet(key)



&#x20;   try:

&#x20;       plaintext = cipher.decrypt(ciphertext.encode("utf-8"))

&#x20;   except InvalidToken as exc:

&#x20;       raise ValueError(

&#x20;           "Decryption failed: the key may be incorrect or "

&#x20;           "the ciphertext may have been modified."

&#x20;       ) from exc



&#x20;   return plaintext.decode("utf-8")





def demonstrate\_round\_trip(plaintext: str) -> dict\[str, str]:

&#x20;   """

&#x20;   Perform a complete educational encryption/decryption round trip.



&#x20;   Returns a dictionary containing the key, plaintext, ciphertext,

&#x20;   and recovered plaintext.

&#x20;   """

&#x20;   key = generate\_key()

&#x20;   ciphertext = encrypt\_text(plaintext, key)

&#x20;   recovered = decrypt\_text(ciphertext, key)



&#x20;   return {

&#x20;       "key": key.decode("utf-8"),

&#x20;       "plaintext": plaintext,

&#x20;       "ciphertext": ciphertext,

&#x20;       "decrypted\_plaintext": recovered,

&#x20;   }





if \_\_name\_\_ == "\_\_main\_\_":

&#x20;   result = demonstrate\_round\_trip(

&#x20;       "Plaintext is transformed into ciphertext using a secret key."

&#x20;   )



&#x20;   print("=== Day 20 Encryption Demonstration ===")

&#x20;   print()

&#x20;   print(f"Plaintext:           {result\['plaintext']}")

&#x20;   print(f"Encryption key:      {result\['key']}")

&#x20;   print(f"Ciphertext:          {result\['ciphertext']}")

&#x20;   print(f"Decrypted plaintext: {result\['decrypted\_plaintext']}")

&#x20;   print()

&#x20;   print(

&#x20;       "Round-trip successful:",

&#x20;       result\["plaintext"] == result\["decrypted\_plaintext"],

&#x20;   )

