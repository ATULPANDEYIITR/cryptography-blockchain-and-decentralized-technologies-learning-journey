#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * Public-Key Cryptography Practice Project
 *
 * C++17 educational RSA implementation.
 *
 * Features:
 * - Modular exponentiation
 * - Overflow-safe modular multiplication
 * - Deterministic Miller-Rabin primality testing
 * - RSA key generation
 * - Encryption and decryption
 * - Digital signatures
 * - Key registry and revocation
 * - Merge-independent cryptographic state management
 *
 * SECURITY WARNING:
 * This program uses small integer RSA and textbook operations.
 * It is not suitable for real encryption or authentication.
 */

using u64 = std::uint64_t;

enum class KeyStatus {
    ACTIVE,
    REVOKED
};

struct PublicKey {
    u64 n;
    u64 e;
};

struct PrivateKey {
    u64 n;
    u64 d;
};

struct RSAKeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;
    u64 p;
    u64 q;
    u64 phi;
};

struct KeyRecord {
    PublicKey key;
    KeyStatus status;
};

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message)
        : std::runtime_error(message) {}
};

class RSAEngine {
private:
    std::mt19937_64 randomEngine;

    static u64 addMod(u64 a, u64 b, u64 mod) {
        // Preconditions: a < mod and b < mod.
        return a >= mod - b ? a - (mod - b) : a + b;
    }

    static u64 multiplyMod(u64 a, u64 b, u64 mod) {
        if (mod == 0) {
            throw CryptoException("Modulus cannot be zero.");
        }

        a %= mod;
        u64 result = 0;

        // Repeated doubling avoids multiplication overflow.
        while (b > 0) {
            if (b & 1ULL) {
                result = addMod(result, a, mod);
            }

            a = addMod(a, a, mod);
            b >>= 1;
        }

        return result;
    }

    static u64 powerMod(u64 base, u64 exponent, u64 mod) {
        if (mod == 0) {
            throw CryptoException("Invalid modulus.");
        }

        u64 result = 1 % mod;
        base %= mod;

        while (exponent > 0) {
            if (exponent & 1ULL) {
                result = multiplyMod(result, base, mod);
            }

            base = multiplyMod(base, base, mod);
            exponent >>= 1;
        }

        return result;
    }

    static bool millerRabin(u64 n) {
        if (n < 2) return false;

        const std::vector<u64> smallPrimes = {
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
        };

        for (u64 p : smallPrimes) {
            if (n == p) return true;
            if (n % p == 0) return false;
        }

        u64 d = n - 1;
        unsigned int s = 0;

        while ((d & 1ULL) == 0) {
            d >>= 1;
            ++s;
        }

        // Deterministic Miller-Rabin bases for uint64_t.
        const u64 bases[] = {
            2ULL, 325ULL, 9375ULL, 28178ULL,
            450775ULL, 9780504ULL, 1795265022ULL
        };

        for (u64 base : bases) {
            if (base % n == 0) continue;

            u64 x = powerMod(base, d, n);

            if (x == 1 || x == n - 1) continue;

            bool passed = false;

            for (unsigned int r = 1; r < s; ++r) {
                x = multiplyMod(x, x, n);

                if (x == n - 1) {
                    passed = true;
                    break;
                }
            }

            if (!passed) return false;
        }

        return true;
    }

    u64 generatePrime() {
        std::uniform_int_distribution<u64> distribution(
            10000, 60000
        );

        while (true) {
            u64 candidate = distribution(randomEngine) | 1ULL;

            if (millerRabin(candidate)) {
                return candidate;
            }
        }
    }

    static u64 inverseMod(u64 a, u64 mod) {
        // Extended Euclidean algorithm.
        // Values are small enough for signed 64-bit intermediates here.
        std::int64_t t = 0;
        std::int64_t newT = 1;
        std::int64_t r = static_cast<std::int64_t>(mod);
        std::int64_t newR = static_cast<std::int64_t>(a);

        while (newR != 0) {
            std::int64_t quotient = r / newR;

            std::int64_t tempT = t - quotient * newT;
            t = newT;
            newT = tempT;

            std::int64_t tempR = r - quotient * newR;
            r = newR;
            newR = tempR;
        }

        if (r != 1) {
            throw CryptoException("Modular inverse does not exist.");
        }

        if (t < 0) t += static_cast<std::int64_t>(mod);

        return static_cast<u64>(t);
    }

public:
    RSAEngine()
        : randomEngine(std::random_device{}()) {}

    static bool isPrime(u64 n) {
        return millerRabin(n);
    }

    RSAKeyPair generateKeyPair() {
        u64 p = generatePrime();
        u64 q = generatePrime();

        while (p == q) {
            q = generatePrime();
        }

        u64 n = p * q;
        u64 phi = (p - 1) * (q - 1);

        u64 e = 65537;

        if (std::gcd(e, phi) != 1) {
            e = 3;

            while (std::gcd(e, phi) != 1) {
                e += 2;
            }
        }

        u64 d = inverseMod(e, phi);

        return {
            {n, e},
            {n, d},
            p,
            q,
            phi
        };
    }

    u64 encrypt(u64 message, const PublicKey& key) const {
        if (key.n <= 1 || key.e <= 1) {
            throw CryptoException("Invalid public key.");
        }

        if (message >= key.n) {
            throw CryptoException("Message exceeds RSA modulus.");
        }

        return powerMod(message, key.e, key.n);
    }

    u64 decrypt(u64 ciphertext, const PrivateKey& key) const {
        if (key.n <= 1 || key.d == 0) {
            throw CryptoException("Invalid private key.");
        }

        if (ciphertext >= key.n) {
            throw CryptoException("Invalid ciphertext.");
        }

        return powerMod(ciphertext, key.d, key.n);
    }

    u64 sign(u64 message, const PrivateKey& key) const {
        if (message >= key.n) {
            throw CryptoException("Message exceeds RSA modulus.");
        }

        return powerMod(message, key.d, key.n);
    }

    bool verify(
        u64 message,
        u64 signature,
        const PublicKey& key
    ) const {
        if (message >= key.n || signature >= key.n) {
            return false;
        }

        return powerMod(signature, key.e, key.n) == message;
    }
};

class KeyRegistry {
private:
    std::unordered_map<std::string, KeyRecord> records;

public:
    void registerKey(
        const std::string& id,
        const PublicKey& key
    ) {
        if (id.empty() || key.n <= 1 || key.e <= 1) {
            throw CryptoException("Invalid key registration.");
        }

        if (records.find(id) != records.end()) {
            throw CryptoException("Duplicate key identifier.");
        }

        records.emplace(id, KeyRecord{key, KeyStatus::ACTIVE});
    }

    void revoke(const std::string& id) {
        auto it = records.find(id);

        if (it == records.end()) {
            throw CryptoException("Unknown key identifier.");
        }

        it->second.status = KeyStatus::REVOKED;
    }

    PublicKey getActive(const std::string& id) const {
        auto it = records.find(id);

        if (it == records.end()) {
            throw CryptoException("Unknown key.");
        }

        if (it->second.status != KeyStatus::ACTIVE) {
            throw CryptoException("Key has been revoked.");
        }

        return it->second.key;
    }
};

int main() {
    try {
        std::cout << "PUBLIC-KEY CRYPTOGRAPHY PRACTICE\n";
        std::cout << "================================\n";

        RSAEngine engine;

        std::cout << "\n1. RSA KEY GENERATION\n";

        RSAKeyPair pair = engine.generateKeyPair();

        std::cout << "Prime p: " << pair.p << '\n';
        std::cout << "Prime q: " << pair.q << '\n';
        std::cout << "Modulus: " << pair.publicKey.n << '\n';
        std::cout << "Public exponent: " << pair.publicKey.e << '\n';
        std::cout << "Private exponent: " << pair.privateKey.d << '\n';

        std::cout << "\n2. ENCRYPTION AND DECRYPTION\n";

        const u64 message = 12345;

        u64 ciphertext = engine.encrypt(
            message,
            pair.publicKey
        );

        u64 decrypted = engine.decrypt(
            ciphertext,
            pair.privateKey
        );

        std::cout << "Original: " << message << '\n';
        std::cout << "Ciphertext: " << ciphertext << '\n';
        std::cout << "Recovered: " << decrypted << '\n';

        if (message != decrypted) {
            throw CryptoException("Decryption verification failed.");
        }

        std::cout << "\n3. DIGITAL SIGNATURE\n";

        const u64 digestRepresentative = 54321;

        u64 signature = engine.sign(
            digestRepresentative,
            pair.privateKey
        );

        std::cout << "Signature: " << signature << '\n';

        bool valid = engine.verify(
            digestRepresentative,
            signature,
            pair.publicKey
        );

        bool altered = engine.verify(
            digestRepresentative + 1,
            signature,
            pair.publicKey
        );

        std::cout << "Original verified: " << std::boolalpha
                  << valid << '\n';

        std::cout << "Modified message verified: "
                  << altered << '\n';

        if (!valid || altered) {
            throw CryptoException("Signature test failed.");
        }

        std::cout << "\n4. KEY REGISTRY\n";

        KeyRegistry registry;

        registry.registerKey(
            "deployment-key-001",
            pair.publicKey
        );

        PublicKey active = registry.getActive(
            "deployment-key-001"
        );

        std::cout << "Active key modulus: " << active.n << '\n';

        registry.revoke("deployment-key-001");

        try {
            registry.getActive("deployment-key-001");
        } catch (const CryptoException& error) {
            std::cout << "Revocation enforced: "
                      << error.what() << '\n';
        }

        std::cout << "\n5. EDGE CASES\n";

        try {
            engine.encrypt(pair.publicKey.n, pair.publicKey);
        } catch (const CryptoException& error) {
            std::cout << "Invalid message rejected: "
                      << error.what() << '\n';
        }

        std::cout << "Prime 101: "
                  << RSAEngine::isPrime(101) << '\n';

        std::cout << "Composite 100: "
                  << RSAEngine::isPrime(100) << '\n';

        std::cout << "\n6. MATHEMATICAL VALIDATION\n";

        if (std::gcd(
                pair.publicKey.e,
                pair.phi
            ) != 1) {
            throw CryptoException("Invalid RSA exponent.");
        }

        std::cout << "Coprimality verified.\n";
        std::cout << "All tests passed.\n";

        std::cout << "\nSecurity limitation: educational RSA only.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Execution error: "
                  << error.what() << '\n';

        return 1;
    }

    return 0;
}
