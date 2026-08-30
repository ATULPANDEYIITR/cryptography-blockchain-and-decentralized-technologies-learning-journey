# ============================================================
# DAY 01: CRYPTOGRAPHY BASICS
# ============================================================

print("DAY 01 - CRYPTOGRAPHY BASICS")


# ============================================================
# 1. WHAT IS CRYPTOGRAPHY?
# ============================================================

print("\n1. WHAT IS CRYPTOGRAPHY?")

print("Cryptography is the practice of protecting information")
print("by transforming it into a form that unauthorized users")
print("cannot easily understand.")


# ============================================================
# 2. PLAINTEXT
# ============================================================

print("\n2. PLAINTEXT")

plaintext = "HELLO"

print("Plaintext:", plaintext)

print("Plaintext is the original readable information")
print("before encryption.")


# ============================================================
# 3. CIPHERTEXT
# ============================================================

print("\n3. CIPHERTEXT")

ciphertext = "KHOOR"

print("Ciphertext:", ciphertext)

print("Ciphertext is the transformed form of plaintext")
print("produced through encryption.")


# ============================================================
# 4. KEY
# ============================================================

print("\n4. KEY")

key = 3

print("Key:", key)

print("A cryptographic key is information used by")
print("a cryptographic algorithm to perform encryption")
print("or decryption.")


# ============================================================
# 5. SIMPLE CAESAR CIPHER
# ============================================================

print("\n5. SIMPLE CAESAR CIPHER")

plaintext = "HELLO"
shift = 3

encrypted_text = ""

for character in plaintext:

    if character.isalpha():

        position = ord(character) - ord("A")
        new_position = (position + shift) % 26

        encrypted_character = chr(
            new_position + ord("A")
        )

        encrypted_text += encrypted_character

    else:
        encrypted_text += character


print("Plaintext :", plaintext)
print("Shift     :", shift)
print("Ciphertext:", encrypted_text)


# ============================================================
# 6. DECRYPTION
# ============================================================

print("\n6. DECRYPTION")

decrypted_text = ""

for character in encrypted_text:

    if character.isalpha():

        position = ord(character) - ord("A")
        new_position = (position - shift) % 26

        decrypted_character = chr(
            new_position + ord("A")
        )

        decrypted_text += decrypted_character

    else:
        decrypted_text += character


print("Ciphertext:", encrypted_text)
print("Decrypted :", decrypted_text)


# ============================================================
# 7. ENCRYPTION AND DECRYPTION FLOW
# ============================================================

print("\n7. ENCRYPTION AND DECRYPTION")

print("""
Plaintext
    ↓
Encryption + Key
    ↓
Ciphertext
    ↓
Decryption + Key
    ↓
Plaintext
""")


# ============================================================
# 8. SYMMETRIC AND ASYMMETRIC CRYPTOGRAPHY
# ============================================================

print("\n8. TYPES OF CRYPTOGRAPHY")

print("Symmetric Cryptography:")
print("Uses the same key for encryption and decryption.")

print("\nAsymmetric Cryptography:")
print("Uses a pair of related keys:")
print("- Public Key")
print("- Private Key")


# ============================================================
# 9. HASHING
# ============================================================

print("\n9. HASHING")

print("Hashing transforms data into a fixed-length")
print("value using a hash function.")

print("\nImportant distinction:")
print("Encryption is designed to be reversible with a key.")
print("Hashing is generally designed as a one-way operation.")


# ============================================================
# 10. BASIC CRYPTOGRAPHIC GOALS
# ============================================================

print("\n10. BASIC CRYPTOGRAPHIC GOALS")

goals = [
    "Confidentiality",
    "Integrity",
    "Authentication",
    "Non-repudiation"
]

for goal in goals:
    print("-", goal)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DAY 01 COMPLETED")
print("=" * 60)

print("""
Today you learned:

1. What Cryptography is
2. Plaintext
3. Ciphertext
4. Cryptographic Keys
5. Encryption
6. Decryption
7. Caesar Cipher
8. Symmetric Cryptography
9. Asymmetric Cryptography
10. Hashing
11. Basic Cryptographic Goals
""")
