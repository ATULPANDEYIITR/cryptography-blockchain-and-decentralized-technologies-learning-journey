#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * RSA Repository Security Governance Engine
 *
 * Educational implementation of RSA mathematics using uint64_t.
 *
 * This implementation uses small RSA parameters and is NOT suitable
 * for protecting real information.
 *
 * The program demonstrates:
 * - Prime generation
 * - RSA key construction
 * - Modular arithmetic
 * - Encryption and decryption
 * - Key lifecycle management
 * - Access-control policies
 * - Operation auditing
 */

using namespace std;

using u64 = uint64_t;
using u128 = __uint128_t;

// ============================================================
// Exceptions
// ============================================================

class RSAException : public runtime_error {
public:
    explicit RSAException(const string& message)
        : runtime_error(message) {}
};

class InvalidKeyException : public RSAException {
public:
    using RSAException::RSAException;
};

class EncryptionException : public RSAException {
public:
    using RSAException::RSAException;
};

class DecryptionException : public RSAException {
public:
    using RSAException::RSAException;
};

// ============================================================
// Domain types
// ============================================================

enum class KeyStatus {
    ACTIVE,
    REVOKED,
    EXPIRED
};

enum class OperationType {
    ENCRYPT,
    DECRYPT
};

struct PublicKey {
    u64 n;
    u64 e;
};

struct PrivateKey {
    u64 n;
    u64 d;
    u64 p;
    u64 q;
};

struct RSAKeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;
    KeyStatus status = KeyStatus::ACTIVE;
};

struct AuditRecord {
    string actor;
    OperationType operation;
    string result;
    u64 value;
};

struct EncryptionResult {
    u64 ciphertext;
    string keyIdentifier;
};

// ============================================================
// Number theory
// ============================================================

u64 modularMultiply(u64 a, u64 b, u64 modulus) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero.");
    }

    return static_cast<u64>(
        (static_cast<u128>(a) * b) % modulus
    );
}

u64 modularPower(u64 base, u64 exponent, u64 modulus) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero.");
    }

    u64 result = 1 % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = modularMultiply(
                result, base, modulus
            );
        }

        base = modularMultiply(base, base, modulus);
        exponent >>= 1;
    }

    return result;
}

u64 gcdValue(u64 a, u64 b) {
    while (b != 0) {
        u64 temporary = b;
        b = a % b;
        a = temporary;
    }

    return a;
}

int64_t extendedGcd(
    int64_t a,
    int64_t b,
    int64_t& x,
    int64_t& y
) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }

    int64_t x1 = 0;
    int64_t y1 = 0;

    int64_t g = extendedGcd(
        b, a % b, x1, y1
    );

    x = y1;
    y = x1 - (a / b) * y1;

    return g;
}

u64 modularInverse(u64 a, u64 modulus) {
    int64_t x = 0;
    int64_t y = 0;

    int64_t g = extendedGcd(
        static_cast<int64_t>(a),
        static_cast<int64_t>(modulus),
        x,
        y
    );

    if (g != 1) {
        throw InvalidKeyException(
            "Modular inverse does not exist."
        );
    }

    int64_t result = x % static_cast<int64_t>(modulus);

    if (result < 0) {
        result += static_cast<int64_t>(modulus);
    }

    return static_cast<u64>(result);
}

// ============================================================
// Primality testing
// ============================================================

bool isPrime(u64 n) {
    if (n < 2) {
        return false;
    }

    if (n == 2 || n == 3) {
        return true;
    }

    if (n % 2 == 0) {
        return false;
    }

    for (u64 divisor = 3;
         divisor <= n / divisor;
         divisor += 2) {

        if (n % divisor == 0) {
            return false;
        }
    }

    return true;
}

u64 generateSmallPrime(
    mt19937_64& generator,
    u64 minimum,
    u64 maximum
) {
    if (minimum > maximum) {
        throw invalid_argument("Invalid prime range.");
    }

    uniform_int_distribution<u64> distribution(
        minimum, maximum
    );

    for (int attempts = 0; attempts < 100000; ++attempts) {
        u64 candidate = distribution(generator);

        if (candidate % 2 == 0) {
            ++candidate;
        }

        if (candidate <= maximum && isPrime(candidate)) {
            return candidate;
        }
    }

    throw RSAException("Prime generation failed.");
}

// ============================================================
// RSA key management
// ============================================================

class RSAKeyManager {
private:
    unordered_map<string, RSAKeyPair> keys;

public:
    RSAKeyPair generate(
        const string& identifier,
        u64 p,
        u64 q
    ) {
        if (identifier.empty()) {
            throw InvalidKeyException(
                "Key identifier cannot be empty."
            );
        }

        if (keys.count(identifier)) {
            throw InvalidKeyException(
                "Key identifier already exists."
            );
        }

        if (!isPrime(p) || !isPrime(q) || p == q) {
            throw InvalidKeyException(
                "RSA factors must be distinct primes."
            );
        }

        if (p > numeric_limits<u64>::max() / q) {
            throw InvalidKeyException(
                "RSA modulus overflows uint64_t."
            );
        }

        u64 n = p * q;

        u64 phi = (p - 1) * (q - 1);
        u64 e = 17;

        if (gcdValue(e, phi) != 1) {
            throw InvalidKeyException(
                "Public exponent is not coprime to phi."
            );
        }

        u64 d = modularInverse(e, phi);

        RSAKeyPair pair{
            PublicKey{n, e},
            PrivateKey{n, d, p, q},
            KeyStatus::ACTIVE
        };

        keys.emplace(identifier, pair);

        return pair;
    }

    const RSAKeyPair& get(const string& identifier) const {
        auto iterator = keys.find(identifier);

        if (iterator == keys.end()) {
            throw InvalidKeyException("Key not found.");
        }

        return iterator->second;
    }

    void revoke(const string& identifier) {
        auto iterator = keys.find(identifier);

        if (iterator == keys.end()) {
            throw InvalidKeyException("Key not found.");
        }

        iterator->second.status = KeyStatus::REVOKED;
    }

    size_t activeCount() const {
        return count_if(
            keys.begin(),
            keys.end(),
            [](const auto& entry) {
                return entry.second.status == KeyStatus::ACTIVE;
            }
        );
    }
};

// ============================================================
// RSA encryption engine
// ============================================================

class RSAEngine {
private:
    const RSAKeyManager& keyManager;
    vector<AuditRecord> auditLog;

    void record(
        const string& actor,
        OperationType operation,
        const string& result,
        u64 value
    ) {
        auditLog.push_back({
            actor,
            operation,
            result,
            value
        });
    }

public:
    explicit RSAEngine(const RSAKeyManager& manager)
        : keyManager(manager) {}

    EncryptionResult encrypt(
        const string& keyIdentifier,
        const string& actor,
        u64 plaintext
    ) {
        const auto& pair = keyManager.get(keyIdentifier);

        if (pair.status != KeyStatus::ACTIVE) {
            throw EncryptionException(
                "Key is not active."
            );
        }

        if (plaintext >= pair.publicKey.n) {
            throw EncryptionException(
                "Plaintext must be smaller than modulus."
            );
        }

        u64 ciphertext = modularPower(
            plaintext,
            pair.publicKey.e,
            pair.publicKey.n
        );

        record(
            actor,
            OperationType::ENCRYPT,
            "SUCCESS",
            ciphertext
        );

        return {
            ciphertext,
            keyIdentifier
        };
    }

    u64 decrypt(
        const string& keyIdentifier,
        const string& actor,
        u64 ciphertext
    ) {
        const auto& pair = keyManager.get(keyIdentifier);

        if (pair.status != KeyStatus::ACTIVE) {
            throw DecryptionException(
                "Key is not active."
            );
        }

        if (ciphertext >= pair.privateKey.n) {
            throw DecryptionException(
                "Ciphertext exceeds RSA modulus."
            );
        }

        u64 plaintext = modularPower(
            ciphertext,
            pair.privateKey.d,
            pair.privateKey.n
        );

        record(
            actor,
            OperationType::DECRYPT,
            "SUCCESS",
            plaintext
        );

        return plaintext;
    }

    const vector<AuditRecord>& getAuditLog() const {
        return auditLog;
    }
};

// ============================================================
// Demonstration and validation
// ============================================================

void runTests(
    RSAEngine& engine,
    RSAKeyManager& manager
) {
    auto encrypted = engine.encrypt(
        "training-key",
        "developer-01",
        65
    );

    u64 decrypted = engine.decrypt(
        "training-key",
        "authorized-service",
        encrypted.ciphertext
    );

    if (decrypted != 65) {
        throw RSAException("RSA round-trip test failed.");
    }

    cout << "Encryption/decryption: PASSED\n";

    try {
        engine.encrypt(
            "training-key",
            "developer-01",
            999999
        );

        throw RSAException(
            "Oversized plaintext was accepted."
        );

    } catch (const EncryptionException&) {
        cout << "Plaintext range validation: PASSED\n";
    }

    try {
        engine.decrypt(
            "training-key",
            "authorized-service",
            999999
        );

        throw RSAException(
            "Invalid ciphertext was accepted."
        );

    } catch (const DecryptionException&) {
        cout << "Ciphertext range validation: PASSED\n";
    }

    manager.revoke("training-key");

    try {
        engine.decrypt(
            "training-key",
            "authorized-service",
            encrypted.ciphertext
        );

        throw RSAException(
            "Revoked key was accepted."
        );

    } catch (const DecryptionException&) {
        cout << "Key revocation enforcement: PASSED\n";
    }
}

// ============================================================
// Main application
// ============================================================

int main() {
    try {
        cout << "RSA ENCRYPTION AND DECRYPTION\n";
        cout << "==============================\n\n";

        // Small primes are deliberately used for transparent
        // mathematical demonstration.
        RSAKeyManager keyManager;

        auto pair = keyManager.generate(
            "training-key",
            61,
            53
        );

        cout << "Public modulus: "
             << pair.publicKey.n << '\n';

        cout << "Public exponent: "
             << pair.publicKey.e << '\n';

        cout << "Private exponent: "
             << pair.privateKey.d << '\n';

        cout << "Key status: ACTIVE\n\n";

        RSAEngine engine(keyManager);

        u64 originalMessage = 65;

        cout << "Original message: "
             << originalMessage << '\n';

        auto result = engine.encrypt(
            "training-key",
            "developer-01",
            originalMessage
        );

        cout << "Ciphertext: "
             << result.ciphertext << '\n';

        u64 recovered = engine.decrypt(
            "training-key",
            "authorized-service",
            result.ciphertext
        );

        cout << "Decrypted message: "
             << recovered << '\n';

        cout << "\nRunning validation tests...\n";

        runTests(engine, keyManager);

        cout << "\nAudit records:\n";

        for (const auto& entry : engine.getAuditLog()) {
            cout << "Actor: " << entry.actor
                 << " | Operation: "
                 << (
                     entry.operation == OperationType::ENCRYPT
                     ? "ENCRYPT"
                     : "DECRYPT"
                 )
                 << " | Result: " << entry.result
                 << " | Value: " << entry.value
                 << '\n';
        }

        cout << "\nActive keys: "
             << keyManager.activeCount() << '\n';

        cout << "\nRSA demonstration completed.\n";

    } catch (const exception& error) {
        cerr << "Application error: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
