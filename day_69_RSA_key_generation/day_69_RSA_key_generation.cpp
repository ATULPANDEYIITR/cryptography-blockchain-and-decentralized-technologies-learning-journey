#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * RSA Key Generation: Educational C++17 Implementation
 *
 * This implementation demonstrates:
 * - Prime candidate generation
 * - Miller-Rabin primality testing
 * - RSA modulus construction
 * - Euler totient calculation
 * - Public and private exponent calculation
 * - Modular exponentiation
 * - Encryption and decryption
 * - Key validation
 *
 * IMPORTANT:
 * This implementation is restricted to 64-bit integers.
 * It is an educational demonstration, NOT production RSA.
 * Production RSA requires large-integer arithmetic and a
 * vetted cryptographic implementation.
 */

using u64 = std::uint64_t;
using u128 = unsigned __int128;

enum class KeyState {
    GENERATED,
    VALIDATED,
    ACTIVE,
    REVOKED
};

struct RSAParameters {
    u64 p;
    u64 q;
    u64 n;
    u64 phi;
    u64 e;
    u64 d;
};

struct KeyPolicy {
    std::size_t minimumPrimeBits;
    u64 publicExponent;
};

class RSAException : public std::runtime_error {
public:
    explicit RSAException(const std::string& message)
        : std::runtime_error(message) {}
};

class ModularArithmetic {
public:
    static u64 multiply(u64 a, u64 b, u64 mod) {
        return static_cast<u64>(
            (static_cast<u128>(a) * b) % mod
        );
    }

    static u64 power(u64 base, u64 exponent, u64 mod) {
        if (mod == 0) {
            throw RSAException("Modulo cannot be zero.");
        }

        u64 result = 1;
        base %= mod;

        while (exponent > 0) {
            if (exponent & 1) {
                result = multiply(result, base, mod);
            }

            base = multiply(base, base, mod);
            exponent >>= 1;
        }

        return result;
    }

    static u64 inverse(u64 a, u64 mod) {
        if (mod < 2) {
            throw RSAException("Invalid inverse modulus.");
        }

        // Extended Euclidean algorithm using signed 128-bit values.
        __int128 oldR = static_cast<__int128>(a);
        __int128 r = static_cast<__int128>(mod);

        __int128 oldS = 1;
        __int128 s = 0;

        while (r != 0) {
            const __int128 quotient = oldR / r;

            __int128 temp = oldR - quotient * r;
            oldR = r;
            r = temp;

            temp = oldS - quotient * s;
            oldS = s;
            s = temp;
        }

        if (oldR != 1) {
            throw RSAException("Modular inverse does not exist.");
        }

        oldS %= static_cast<__int128>(mod);

        if (oldS < 0) {
            oldS += mod;
        }

        return static_cast<u64>(oldS);
    }
};

class PrimeGenerator {
private:
    std::mt19937_64 generator;

    static constexpr std::array<u64, 12> bases = {
        2ULL, 325ULL, 9375ULL, 28178ULL,
        450775ULL, 9780504ULL, 1795265022ULL,
        3ULL, 5ULL, 7ULL, 11ULL, 13ULL
    };

public:
    PrimeGenerator()
        : generator(std::random_device{}()) {}

    static bool isPrime(u64 n) {
        if (n < 2) {
            return false;
        }

        const std::array<u64, 12> smallPrimes = {
            2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL,
            17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL
        };

        for (u64 prime : smallPrimes) {
            if (n == prime) {
                return true;
            }

            if (n % prime == 0) {
                return false;
            }
        }

        u64 d = n - 1;
        unsigned int s = 0;

        while ((d & 1) == 0) {
            d >>= 1;
            ++s;
        }

        // Miller-Rabin with deterministic bases for uint64_t.
        for (u64 base : bases) {
            if (base % n == 0) {
                continue;
            }

            u64 x = ModularArithmetic::power(base, d, n);

            if (x == 1 || x == n - 1) {
                continue;
            }

            bool composite = true;

            for (unsigned int r = 1; r < s; ++r) {
                x = ModularArithmetic::multiply(x, x, n);

                if (x == n - 1) {
                    composite = false;
                    break;
                }
            }

            if (composite) {
                return false;
            }
        }

        return true;
    }

    u64 generatePrime(std::size_t bits) {
        if (bits < 8 || bits > 32) {
            throw RSAException(
                "Educational prime size must be between 8 and 32 bits."
            );
        }

        const u64 lower = 1ULL << (bits - 1);
        const u64 upper = (1ULL << bits) - 1;

        std::uniform_int_distribution<u64> distribution(lower, upper);

        for (std::size_t attempt = 0; attempt < 1000000; ++attempt) {
            u64 candidate = distribution(generator);

            candidate |= 1ULL;
            candidate |= lower;

            if (candidate <= upper && isPrime(candidate)) {
                return candidate;
            }
        }

        throw RSAException("Prime generation attempt limit exceeded.");
    }
};

class RSAKeyGenerator {
private:
    PrimeGenerator primeGenerator;
    KeyPolicy policy;

public:
    explicit RSAKeyGenerator(KeyPolicy configuration)
        : policy(configuration) {
        if (policy.minimumPrimeBits < 8 ||
            policy.minimumPrimeBits > 32) {
            throw RSAException("Unsupported educational prime size.");
        }

        if (policy.publicExponent < 3 ||
            policy.publicExponent % 2 == 0) {
            throw RSAException("Invalid public exponent.");
        }
    }

    RSAParameters generate() {
        u64 p = primeGenerator.generatePrime(
            policy.minimumPrimeBits
        );

        u64 q;

        do {
            q = primeGenerator.generatePrime(
                policy.minimumPrimeBits
            );
        } while (p == q);

        const u128 modulus =
            static_cast<u128>(p) * q;

        if (modulus > std::numeric_limits<u64>::max()) {
            throw RSAException("RSA modulus overflow.");
        }

        const u64 n = static_cast<u64>(modulus);

        const u64 phi = (p - 1) * (q - 1);

        const u64 e = policy.publicExponent;

        if (std::gcd(e, phi) != 1) {
            throw RSAException(
                "Public exponent is not coprime to Euler's totient."
            );
        }

        const u64 d = ModularArithmetic::inverse(e, phi);

        RSAParameters parameters{
            p, q, n, phi, e, d
        };

        validate(parameters);

        return parameters;
    }

    static void validate(const RSAParameters& key) {
        if (key.p == key.q) {
            throw RSAException("Prime factors must be different.");
        }

        if (!PrimeGenerator::isPrime(key.p) ||
            !PrimeGenerator::isPrime(key.q)) {
            throw RSAException("Invalid RSA prime factors.");
        }

        if (key.n != key.p * key.q) {
            throw RSAException("Incorrect modulus.");
        }

        if (key.phi != (key.p - 1) * (key.q - 1)) {
            throw RSAException("Incorrect Euler totient.");
        }

        if (std::gcd(key.e, key.phi) != 1) {
            throw RSAException("Invalid public exponent.");
        }

        if ((static_cast<u128>(key.e) * key.d) % key.phi != 1) {
            throw RSAException("Invalid private exponent.");
        }
    }
};

class RSAEngine {
private:
    RSAParameters parameters;
    KeyState state = KeyState::GENERATED;

public:
    explicit RSAEngine(const RSAParameters& key)
        : parameters(key) {
        RSAKeyGenerator::validate(parameters);
        state = KeyState::VALIDATED;
    }

    void activate() {
        if (state != KeyState::VALIDATED) {
            throw RSAException("Key cannot be activated.");
        }

        state = KeyState::ACTIVE;
    }

    void revoke() {
        if (state == KeyState::REVOKED) {
            throw RSAException("Key is already revoked.");
        }

        state = KeyState::REVOKED;
    }

    u64 encrypt(u64 plaintext) const {
        if (state != KeyState::ACTIVE) {
            throw RSAException("RSA key is not active.");
        }

        if (plaintext >= parameters.n) {
            throw RSAException(
                "Plaintext representative must be smaller than modulus."
            );
        }

        return ModularArithmetic::power(
            plaintext,
            parameters.e,
            parameters.n
        );
    }

    u64 decrypt(u64 ciphertext) const {
        if (state != KeyState::ACTIVE) {
            throw RSAException("RSA key is not active.");
        }

        if (ciphertext >= parameters.n) {
            throw RSAException("Invalid ciphertext representative.");
        }

        return ModularArithmetic::power(
            ciphertext,
            parameters.d,
            parameters.n
        );
    }

    KeyState getState() const {
        return state;
    }

    const RSAParameters& getParameters() const {
        return parameters;
    }
};

void demonstrateRSA() {
    // 32-bit primes create a modulus of at most 64 bits.
    RSAKeyGenerator generator({
        32,
        65537
    });

    RSAParameters key = generator.generate();

    RSAEngine engine(key);
    engine.activate();

    const u64 message = 123456;

    const u64 ciphertext = engine.encrypt(message);
    const u64 decrypted = engine.decrypt(ciphertext);

    if (decrypted != message) {
        throw RSAException("RSA round-trip verification failed.");
    }

    std::cout << "\nRSA KEY GENERATION\n";
    std::cout << "------------------\n";
    std::cout << "Prime p: " << key.p << '\n';
    std::cout << "Prime q: " << key.q << '\n';
    std::cout << "Modulus n: " << key.n << '\n';
    std::cout << "Totient: " << key.phi << '\n';
    std::cout << "Public exponent: " << key.e << '\n';
    std::cout << "Private exponent: " << key.d << '\n';
    std::cout << "Original message: " << message << '\n';
    std::cout << "Ciphertext: " << ciphertext << '\n';
    std::cout << "Decrypted message: " << decrypted << '\n';
    std::cout << "Round-trip verified: "
              << std::boolalpha
              << (message == decrypted) << '\n';

    engine.revoke();

    std::cout << "Final state: REVOKED\n";
}

int main() {
    try {
        demonstrateRSA();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "RSA failure: " << error.what() << '\n';
        return 1;
    }
}
