/*
 * Mathematical Concepts Used in Cryptography
 * ===========================================
 *
 * C++17 case study:
 * A secure-message key-establishment laboratory built around the mathematical
 * foundations of modular arithmetic, finite groups, Diffie-Hellman, RSA,
 * hashing, and elliptic curves.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic cryptography_math.cpp -o cryptography_math
 *
 * The parameters are intentionally small. This program is educational and
 * must not be used as production cryptographic software.
 */

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

using namespace std;

// ---------------------------------------------------------------------------
// Basic arithmetic
// ---------------------------------------------------------------------------

long long gcd_euclid(long long a, long long b) {
    a = llabs(a);
    b = llabs(b);

    while (b != 0) {
        long long remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}

tuple<long long, long long, long long>
extended_gcd(long long a, long long b) {
    long long old_r = a;
    long long r = b;
    long long old_x = 1;
    long long x = 0;
    long long old_y = 0;
    long long y = 1;

    while (r != 0) {
        long long quotient = old_r / r;

        tie(old_r, r) = make_tuple(r, old_r - quotient * r);
        tie(old_x, x) = make_tuple(x, old_x - quotient * x);
        tie(old_y, y) = make_tuple(y, old_y - quotient * y);
    }

    if (old_r < 0) {
        return {-old_r, -old_x, -old_y};
    }

    return {old_r, old_x, old_y};
}

long long modular_inverse(long long a, long long modulus) {
    auto [g, x, y] = extended_gcd(a, modulus);

    if (g != 1) {
        throw invalid_argument("No multiplicative inverse exists.");
    }

    return (x % modulus + modulus) % modulus;
}

long long modular_power(long long base, long long exponent, long long modulus) {
    if (modulus <= 0 || exponent < 0) {
        throw invalid_argument("Invalid modular exponentiation arguments.");
    }

    long long result = 1 % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1LL) {
            result = static_cast<long long>(
                (__int128)result * base % modulus
            );
        }

        base = static_cast<long long>(
            (__int128)base * base % modulus
        );

        exponent >>= 1LL;
    }

    return result;
}

bool is_prime(long long n) {
    if (n < 2) {
        return false;
    }

    if (n == 2) {
        return true;
    }

    if (n % 2 == 0) {
        return false;
    }

    for (long long divisor = 3; divisor * divisor <= n; divisor += 2) {
        if (n % divisor == 0) {
            return false;
        }
    }

    return true;
}

long long phi(long long n) {
    if (n <= 0) {
        throw invalid_argument("n must be positive.");
    }

    long long result = n;
    long long remaining = n;

    for (long long p = 2; p * p <= remaining; ++p) {
        if (remaining % p == 0) {
            while (remaining % p == 0) {
                remaining /= p;
            }

            result -= result / p;
        }
    }

    if (remaining > 1) {
        result -= result / remaining;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Chinese Remainder Theorem
// ---------------------------------------------------------------------------

long long chinese_remainder(
    const vector<long long>& residues,
    const vector<long long>& moduli
) {
    if (residues.empty() || residues.size() != moduli.size()) {
        throw invalid_argument("Invalid CRT input.");
    }

    long long product = 1;

    for (size_t i = 0; i < moduli.size(); ++i) {
        for (size_t j = i + 1; j < moduli.size(); ++j) {
            if (gcd_euclid(moduli[i], moduli[j]) != 1) {
                throw invalid_argument("CRT moduli must be coprime.");
            }
        }

        product *= moduli[i];
    }

    long long solution = 0;

    for (size_t i = 0; i < residues.size(); ++i) {
        long long partial = product / moduli[i];
        long long inverse = modular_inverse(partial, moduli[i]);

        solution += residues[i] * partial * inverse;
    }

    return (solution % product + product) % product;
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

struct RSAKeyPair {
    long long n;
    long long phi_n;
    long long e;
    long long d;
};

RSAKeyPair generate_rsa_keys(
    long long p,
    long long q,
    long long e
) {
    if (!is_prime(p) || !is_prime(q) || p == q) {
        throw invalid_argument("p and q must be distinct primes.");
    }

    long long n = p * q;
    long long phi_n = (p - 1) * (q - 1);

    if (gcd_euclid(e, phi_n) != 1) {
        throw invalid_argument("e must be coprime to phi(n).");
    }

    long long d = modular_inverse(e, phi_n);

    return {n, phi_n, e, d};
}

long long rsa_encrypt(long long message, const RSAKeyPair& key) {
    if (message < 0 || message >= key.n) {
        throw invalid_argument("RSA message is outside the valid range.");
    }

    return modular_power(message, key.e, key.n);
}

long long rsa_decrypt(long long ciphertext, const RSAKeyPair& key) {
    return modular_power(ciphertext, key.d, key.n);
}

// ---------------------------------------------------------------------------
// GF(2^8)
// ---------------------------------------------------------------------------

uint8_t gf256_multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;

    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }

        bool high_bit = a & 0x80;
        a <<= 1;

        // AES irreducible polynomial:
        // x^8 + x^4 + x^3 + x + 1
        if (high_bit) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return result;
}

uint8_t gf256_power(uint8_t value, unsigned exponent) {
    uint8_t result = 1;

    while (exponent > 0) {
        if (exponent & 1U) {
            result = gf256_multiply(result, value);
        }

        value = gf256_multiply(value, value);
        exponent >>= 1U;
    }

    return result;
}

uint8_t gf256_inverse(uint8_t value) {
    if (value == 0) {
        throw invalid_argument("Zero has no inverse in GF(2^8).");
    }

    return gf256_power(value, 254);
}

// ---------------------------------------------------------------------------
// Elliptic curve arithmetic
// ---------------------------------------------------------------------------

struct Point {
    long long x;
    long long y;
    bool infinity;

    static Point Infinity() {
        return {0, 0, true};
    }
};

bool operator==(const Point& first, const Point& second) {
    if (first.infinity != second.infinity) {
        return false;
    }

    if (first.infinity) {
        return true;
    }

    return first.x == second.x && first.y == second.y;
}

class EllipticCurve {
private:
    long long a_;
    long long b_;
    long long p_;

public:
    EllipticCurve(long long a, long long b, long long p)
        : a_(a % p), b_(b % p), p_(p) {
        if (!is_prime(p_) || p_ == 2) {
            throw invalid_argument("Curve modulus must be an odd prime.");
        }

        long long discriminant =
            (4 * a_ * a_ * a_ + 27 * b_ * b_) % p_;

        if (discriminant == 0) {
            throw invalid_argument("The curve is singular.");
        }
    }

    long long normalize(long long value) const {
        return (value % p_ + p_) % p_;
    }

    bool contains(const Point& point) const {
        if (point.infinity) {
            return true;
        }

        long long left = normalize(point.y * point.y);
        long long right = normalize(
            point.x * point.x * point.x +
            a_ * point.x +
            b_
        );

        return left == right;
    }

    Point negate(const Point& point) const {
        if (point.infinity) {
            return point;
        }

        return {
            point.x,
            normalize(-point.y),
            false
        };
    }

    Point add(const Point& first, const Point& second) const {
        if (!contains(first) || !contains(second)) {
            throw invalid_argument("Point is not on the curve.");
        }

        if (first.infinity) {
            return second;
        }

        if (second.infinity) {
            return first;
        }

        long long x1 = first.x;
        long long y1 = first.y;
        long long x2 = second.x;
        long long y2 = second.y;

        // P + (-P) = O
        if (x1 == x2 && normalize(y1 + y2) == 0) {
            return Point::Infinity();
        }

        long long slope;

        if (first == second) {
            if (y1 == 0) {
                return Point::Infinity();
            }

            long long numerator = normalize(3 * x1 * x1 + a_);
            long long denominator = normalize(2 * y1);

            slope = normalize(
                numerator * modular_inverse(denominator, p_)
            );
        } else {
            long long numerator = normalize(y2 - y1);
            long long denominator = normalize(x2 - x1);

            slope = normalize(
                numerator * modular_inverse(denominator, p_)
            );
        }

        long long x3 = normalize(
            slope * slope - x1 - x2
        );

        long long y3 = normalize(
            slope * (x1 - x3) - y1
        );

        return {x3, y3, false};
    }

    Point multiply(long long scalar, Point point) const {
        if (scalar < 0) {
            return multiply(-scalar, negate(point));
        }

        Point result = Point::Infinity();

        // Double-and-add reduces scalar multiplication from O(k)
        // point additions to O(log k) point operations.
        while (scalar > 0) {
            if (scalar & 1LL) {
                result = add(result, point);
            }

            point = add(point, point);
            scalar >>= 1LL;
        }

        return result;
    }
};

ostream& operator<<(ostream& output, const Point& point) {
    if (point.infinity) {
        output << "O";
    } else {
        output << "(" << point.x << ", " << point.y << ")";
    }

    return output;
}

// ---------------------------------------------------------------------------
// Toy authenticated-message architecture
// ---------------------------------------------------------------------------

/*
 * This case study models the mathematical structure of a secure messaging
 * pipeline:
 *
 *     long-term/public parameters
 *              |
 *              v
 *       key establishment
 *              |
 *              v
 *        shared secret
 *              |
 *              v
 *       key derivation
 *              |
 *              v
 *      symmetric encryption
 *
 * The final encryption below is deliberately a toy XOR construction.
 * It demonstrates data flow but does NOT provide authentication, nonce
 * management, confidentiality guarantees, or production security.
 */

class MessageSession {
private:
    uint64_t shared_secret_;

    uint64_t mix(uint64_t value) const {
        value ^= value >> 30;
        value *= 0xbf58476d1ce4e5b9ULL;
        value ^= value >> 27;
        value *= 0x94d049bb133111ebULL;
        value ^= value >> 31;
        return value;
    }

public:
    explicit MessageSession(uint64_t shared_secret)
        : shared_secret_(shared_secret) {}

    uint64_t derived_key() const {
        // A simple educational mixer.
        // Production systems use standardized KDFs such as HKDF.
        return mix(shared_secret_ ^ 0xA5A5A5A5A5A5A5A5ULL);
    }

    string toy_xor(const string& plaintext) const {
        uint64_t key = derived_key();
        string result = plaintext;

        for (size_t i = 0; i < result.size(); ++i) {
            uint8_t key_byte =
                static_cast<uint8_t>(
                    (key >> ((i % 8) * 8)) & 0xFF
                );

            result[i] =
                static_cast<char>(
                    static_cast<uint8_t>(result[i]) ^ key_byte
                );
        }

        return result;
    }
};

// ---------------------------------------------------------------------------
// Case-study workflow
// ---------------------------------------------------------------------------

void run_case_study() {
    cout << "\n" << string(78, '=') << '\n';
    cout << "INDUSTRY-STYLE MATHEMATICAL CRYPTOGRAPHY CASE STUDY\n";
    cout << string(78, '=') << '\n';

    cout << "\nProblem model:\n";
    cout << "Two participants need to establish a common secret over a public\n";
    cout << "channel. The implementation illustrates the mathematical stages\n";
    cout << "that can support such a protocol.\n";

    // Stage 1: public finite-group parameters.
    const long long p = 23;
    const long long g = 5;

    // Stage 2: private values.
    const long long alice_private = 6;
    const long long bob_private = 15;

    // Stage 3: public values.
    const long long alice_public =
        modular_power(g, alice_private, p);

    const long long bob_public =
        modular_power(g, bob_private, p);

    // Stage 4: independent shared-secret computation.
    const long long alice_shared =
        modular_power(bob_public, alice_private, p);

    const long long bob_shared =
        modular_power(alice_public, bob_private, p);

    cout << "\nDiffie-Hellman parameters:\n";
    cout << "p = " << p << '\n';
    cout << "g = " << g << '\n';

    cout << "\nPublic values:\n";
    cout << "Alice A = " << alice_public << '\n';
    cout << "Bob B   = " << bob_public << '\n';

    cout << "\nShared values:\n";
    cout << "Alice computes = " << alice_shared << '\n';
    cout << "Bob computes   = " << bob_shared << '\n';

    if (alice_shared != bob_shared) {
        throw runtime_error("Key agreement failed.");
    }

    // Stage 5: key derivation.
    MessageSession session(
        static_cast<uint64_t>(alice_shared)
    );

    uint64_t derived_key = session.derived_key();

    cout << "\nDerived educational key = 0x"
         << hex << setw(16) << setfill('0')
         << derived_key << dec << setfill(' ') << '\n';

    // Stage 6: message transformation.
    const string message = "cryptographic mathematics";

    string encrypted = session.toy_xor(message);
    string decrypted = session.toy_xor(encrypted);

    cout << "Plaintext  = " << message << '\n';
    cout << "Encrypted  = ";

    for (unsigned char byte : encrypted) {
        cout << hex << setw(2) << setfill('0')
             << static_cast<int>(byte);
    }

    cout << dec << setfill(' ') << '\n';
    cout << "Decrypted  = " << decrypted << '\n';

    if (decrypted != message) {
        throw runtime_error("Message recovery failed.");
    }

    cout << "\nArchitecture validation: passed.\n";

    cout << "\nProduction differences:\n";
    cout << "* Use standardized authenticated key exchange.\n";
    cout << "* Use authenticated encryption such as a standardized AEAD mode.\n";
    cout << "* Use a standardized KDF instead of the educational mixer.\n";
    cout << "* Use cryptographically secure random private values.\n";
    cout << "* Authenticate peers to prevent active man-in-the-middle attacks.\n";
    cout << "* Protect implementations against timing and memory side channels.\n";
}

// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

void demonstrate_foundations() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "FOUNDATIONAL MATHEMATICS\n";
    cout << string(78, '-') << '\n';

    cout << "gcd(240, 46) = "
         << gcd_euclid(240, 46) << '\n';

    auto [g, x, y] = extended_gcd(240, 46);

    cout << "Bezout identity: "
         << "240(" << x << ") + 46(" << y << ") = "
         << g << '\n';

    cout << "17 inverse mod 3120 = "
         << modular_inverse(17, 3120) << '\n';

    cout << "3^100 mod 13 = "
         << modular_power(3, 100, 13) << '\n';

    cout << "phi(35) = "
         << phi(35) << '\n';

    cout << "CRT solution = "
         << chinese_remainder({2, 3, 2}, {3, 5, 7}) << '\n';

    cout << "Prime tests:\n";
    for (long long value : {2, 17, 25, 97}) {
        cout << "  " << value
             << " -> "
             << (is_prime(value) ? "prime" : "composite")
             << '\n';
    }
}

void demonstrate_rsa() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "RSA\n";
    cout << string(78, '-') << '\n';

    RSAKeyPair key = generate_rsa_keys(61, 53, 17);

    cout << "n = " << key.n << '\n';
    cout << "phi(n) = " << key.phi_n << '\n';
    cout << "e = " << key.e << '\n';
    cout << "d = " << key.d << '\n';

    long long message = 65;
    long long ciphertext = rsa_encrypt(message, key);
    long long recovered = rsa_decrypt(ciphertext, key);

    cout << "message = " << message << '\n';
    cout << "ciphertext = " << ciphertext << '\n';
    cout << "recovered = " << recovered << '\n';

    assert(message == recovered);

    cout << "Textbook RSA demonstration passed.\n";
    cout << "Textbook RSA itself must not be deployed as a secure encryption scheme.\n";
}

void demonstrate_gf256() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "GF(2^8)\n";
    cout << string(78, '-') << '\n';

    uint8_t a = 0x57;
    uint8_t b = 0x83;

    uint8_t product = gf256_multiply(a, b);
    uint8_t inverse = gf256_inverse(a);

    cout << hex << uppercase;
    cout << "0x57 * 0x83 = 0x"
         << static_cast<int>(product) << '\n';

    cout << "inverse(0x57) = 0x"
         << static_cast<int>(inverse) << '\n';

    cout << "0x57 * inverse(0x57) = 0x"
         << static_cast<int>(gf256_multiply(a, inverse))
         << '\n';

    cout << dec << nouppercase;

    assert(product == 0xC1);
    assert(gf256_multiply(a, inverse) == 1);
}

void demonstrate_elliptic_curve() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "ELLIPTIC-CURVE ARITHMETIC\n";
    cout << string(78, '-') << '\n';

    EllipticCurve curve(2, 2, 17);
    Point generator{5, 1, false};

    cout << "Generator = " << generator << '\n';
    cout << "Generator valid = "
         << boolalpha
         << curve.contains(generator)
         << '\n';

    for (long long scalar = 1; scalar <= 7; ++scalar) {
        cout << scalar << "P = "
             << curve.multiply(scalar, generator)
             << '\n';
    }

    Point inverse = curve.negate(generator);
    Point identity = curve.add(generator, inverse);

    cout << "P + (-P) = " << identity << '\n';

    assert(identity.infinity);
}

void demonstrate_entropy_and_randomness() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "RANDOMNESS AND SEARCH SPACES\n";
    cout << string(78, '-') << '\n';

    cout << "A uniformly random b-bit secret has 2^b possible values.\n";

    for (int bits : {8, 16, 32, 64, 128, 256}) {
        cout << setw(3) << bits
             << " bits -> 2^"
             << bits
             << " possible values\n";
    }

    cout << "\nThe standard C++ random facilities are not automatically suitable\n";
    cout << "for cryptographic key generation. Cryptographic software should\n";
    cout << "use a CSPRNG provided by an appropriate cryptographic platform.\n";
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

void demonstrate_edge_cases() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "EDGE CASES AND FAILURE CONDITIONS\n";
    cout << string(78, '-') << '\n';

    try {
        cout << "Inverse of 6 modulo 15 = "
             << modular_inverse(6, 15) << '\n';
    } catch (const exception& error) {
        cout << "Expected inverse failure: "
             << error.what() << '\n';
    }

    try {
        EllipticCurve curve(2, 2, 17);
        Point invalid{1, 1, false};

        cout << "Invalid point accepted? "
             << curve.contains(invalid) << '\n';

        curve.add(invalid, invalid);
    } catch (const exception& error) {
        cout << "Expected curve validation failure: "
             << error.what() << '\n';
    }

    cout << "Zero has no multiplicative inverse modulo any modulus > 1.\n";
    cout << "A modular inverse exists only when gcd(a, n) = 1.\n";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void run_tests() {
    cout << "\n" << string(78, '-') << '\n';
    cout << "CORRECTNESS TESTS\n";
    cout << string(78, '-') << '\n';

    assert(gcd_euclid(240, 46) == 2);

    auto [g, x, y] = extended_gcd(240, 46);
    assert(g == 2);
    assert(240 * x + 46 * y == 2);

    assert(modular_inverse(3, 11) == 4);
    assert(modular_power(2, 10, 1000) == 24);
    assert(phi(35) == 24);
    assert(chinese_remainder({2, 3, 2}, {3, 5, 7}) == 23);

    assert(gf256_multiply(0x57, 0x83) == 0xC1);

    EllipticCurve curve(2, 2, 17);
    Point p{5, 1, false};

    assert(curve.contains(p));
    assert(curve.add(p, curve.negate(p)).infinity);

    RSAKeyPair rsa = generate_rsa_keys(61, 53, 17);
    long long message = 65;
    long long ciphertext = rsa_encrypt(message, rsa);
    assert(rsa_decrypt(ciphertext, rsa) == message);

    cout << "All tests passed.\n";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    try {
        cout << "MATHEMATICAL CONCEPTS USED IN CRYPTOGRAPHY\n";
        cout << "C++17 educational case study\n";
        cout << "All cryptographic parameters are intentionally small.\n";

        demonstrate_foundations();
        demonstrate_rsa();
        demonstrate_gf256();
        demonstrate_elliptic_curve();
        demonstrate_entropy_and_randomness();
        demonstrate_edge_cases();
        run_tests();
        run_case_study();

        cout << "\n" << string(78, '=') << '\n';
        cout << "PRODUCTION DESIGN PRINCIPLES\n";
        cout << string(78, '=') << '\n';

        vector<string> principles = {
            "Use established cryptographic libraries.",
            "Use standardized algorithms and parameter sizes.",
            "Generate secrets using a cryptographically secure random source.",
            "Authenticate key exchanges against active attackers.",
            "Use authenticated encryption for protected application data.",
            "Use standardized KDFs for deriving cryptographic keys.",
            "Validate public parameters and protocol messages.",
            "Consider timing, cache, fault, memory, and other side channels.",
            "Do not treat mathematically correct toy code as production security.",
            "Separate confidentiality, integrity, authentication, and key management."
        };

        for (const string& principle : principles) {
            cout << "* " << principle << '\n';
        }

        return 0;
    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
