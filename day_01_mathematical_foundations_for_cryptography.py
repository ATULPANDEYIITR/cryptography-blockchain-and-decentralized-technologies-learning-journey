# ============================================================
# DAY 01: MATHEMATICAL FOUNDATIONS FOR CRYPTOGRAPHY
# ============================================================

print("DAY 01 - MATHEMATICAL FOUNDATIONS FOR CRYPTOGRAPHY")


# ============================================================
# 1. BASIC ARITHMETIC
# ============================================================

print("\n1. BASIC ARITHMETIC")

a = 17
b = 5

print("a =", a)
print("b =", b)

print("Addition:", a + b)
print("Subtraction:", a - b)
print("Multiplication:", a * b)
print("Division:", a / b)


# ============================================================
# 2. INTEGER DIVISION
# ============================================================

print("\n2. INTEGER DIVISION")

print("17 / 5 =", 17 / 5)
print("17 // 5 =", 17 // 5)
print("17 % 5 =", 17 % 5)

print("\n// gives the integer quotient.")
print("% gives the remainder.")


# ============================================================
# 3. DIVISIBILITY
# ============================================================

print("\n3. DIVISIBILITY")

number = 24

print("Number:", number)

if number % 2 == 0:
    print("The number is divisible by 2.")

if number % 3 == 0:
    print("The number is divisible by 3.")

if number % 5 == 0:
    print("The number is divisible by 5.")


# ============================================================
# 4. FACTORS
# ============================================================

print("\n4. FACTORS")

number = 24
factors = []

for i in range(1, number + 1):

    if number % i == 0:
        factors.append(i)

print("Number:", number)
print("Factors:", factors)


# ============================================================
# 5. PRIME NUMBERS
# ============================================================

print("\n5. PRIME NUMBERS")


def is_prime(number):

    if number < 2:
        return False

    for i in range(2, number):

        if number % i == 0:
            return False

    return True


numbers = [2, 3, 4, 5, 7, 10, 11, 13]

for number in numbers:

    if is_prime(number):
        print(number, "-> Prime")
    else:
        print(number, "-> Not Prime")


# ============================================================
# 6. FIND PRIME NUMBERS
# ============================================================

print("\n6. PRIME NUMBERS FROM 1 TO 50")

for number in range(1, 51):

    if is_prime(number):
        print(number, end=" ")

print()


# ============================================================
# 7. GREATEST COMMON DIVISOR
# ============================================================

print("\n7. GREATEST COMMON DIVISOR")

a = 48
b = 18

print("a =", a)
print("b =", b)


def gcd(a, b):

    while b != 0:
        a, b = b, a % b

    return a


print("GCD:", gcd(a, b))


# ============================================================
# 8. MODULAR ARITHMETIC
# ============================================================

print("\n8. MODULAR ARITHMETIC")

a = 17
m = 5

remainder = a % m

print("17 mod 5 =", remainder)

print("\nIn modular arithmetic:")
print("17 ≡ 2 (mod 5)")


# ============================================================
# 9. MODULAR ADDITION
# ============================================================

print("\n9. MODULAR ADDITION")

a = 17
b = 8
m = 5

result = (a + b) % m

print("(", a, "+", b, ") mod", m, "=", result)


# ============================================================
# 10. MODULAR MULTIPLICATION
# ============================================================

print("\n10. MODULAR MULTIPLICATION")

a = 7
b = 6
m = 5

result = (a * b) % m

print("(", a, "*", b, ") mod", m, "=", result)


# ============================================================
# 11. MODULAR EXPONENTIATION
# ============================================================

print("\n11. MODULAR EXPONENTIATION")

base = 3
exponent = 4
modulus = 5

result = (base ** exponent) % modulus

print(
    base,
    "^",
    exponent,
    "mod",
    modulus,
    "=",
    result
)


# ============================================================
# 12. PYTHON'S MODULAR POWER
# ============================================================

print("\n12. EFFICIENT MODULAR POWER")

result = pow(3, 4, 5)

print("3^4 mod 5 =", result)

print("\nThe pow() function can calculate modular")
print("exponentiation efficiently.")


# ============================================================
# 13. CRYPTOGRAPHY CONNECTION
# ============================================================

print("\n13. CONNECTION TO CRYPTOGRAPHY")

print("""
Many cryptographic algorithms rely heavily on:

- Integers
- Prime Numbers
- Divisibility
- Factors
- GCD
- Modular Arithmetic
- Modular Exponentiation

These concepts will become important when studying
modern cryptographic algorithms and protocols.
""")


# ============================================================
# 14. SIMPLE MODULAR EXAMPLE
# ============================================================

print("\n14. SIMPLE MODULAR EXAMPLE")

number = 29
modulus = 7

print("Number:", number)
print("Modulus:", modulus)
print("Remainder:", number % modulus)

print("\n29 ≡", number % modulus, "(mod 7)")


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DAY 01 COMPLETED")
print("=" * 60)

print("""
Today you learned:

1. Basic arithmetic
2. Integer division
3. Remainders
4. Divisibility
5. Factors
6. Prime numbers
7. Greatest Common Divisor
8. Modular arithmetic
9. Modular addition
10. Modular multiplication
11. Modular exponentiation
12. Python's modular power
13. Connection between mathematics and cryptography
""")
