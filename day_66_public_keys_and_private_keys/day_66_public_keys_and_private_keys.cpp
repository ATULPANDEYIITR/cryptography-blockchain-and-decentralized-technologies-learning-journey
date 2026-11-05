#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * Public Keys and Private Keys
 *
 * C++17 educational cryptographic model.
 *
 * Implements:
 * - RSA key generation using small demonstration primes
 * - RSA encryption and decryption
 * - RSA digital signatures
 * - Diffie-Hellman key agreement
 * - Public-key fingerprints
 * - Key registry
 * - Rotation and revocation
 * - Repository-independent security policy evaluation
 *
 * IMPORTANT:
 * This program uses small integer cryptographic parameters.
 * It is an educational mathematical model, not production cryptography.
 * Production systems must use audited cryptographic libraries.
 */

using namespace std;


// ============================================================
// Exceptions
// ============================================================

class CryptoException : public runtime_error {
public:
    explicit CryptoException(const string& message)
        : runtime_error(message) {}
};


// ============================================================
// Domain types
// ============================================================

enum class KeyStatus {
    Active,
    Rotated,
    Revoked,
    Expired
};

enum class KeyPurpose {
    Encryption,
    Signing,
    KeyExchange
};

string statusName(KeyStatus status) {
    switch (status) {
        case KeyStatus::Active: return "ACTIVE";
        case KeyStatus::Rotated: return "ROTATED";
        case KeyStatus::Revoked: return "REVOKED";
        case KeyStatus::Expired: return "EXPIRED";
    }

    throw CryptoException("Unknown key status.");
}

string purposeName(KeyPurpose purpose) {
    switch (purpose) {
        case KeyPurpose::Encryption: return "ENCRYPTION";
        case KeyPurpose::Signing: return "SIGNING";
        case KeyPurpose::KeyExchange: return "KEY_EXCHANGE";
    }

    throw CryptoException("Unknown key purpose.");
}


// ============================================================
// Random generator
// ============================================================

class SecureRandom {

private:
    random_device device_;
    mt19937_64 engine_;

public:
    SecureRandom() : engine_(device_()) {}

    uint64_t between(uint64_t minimum, uint64_t maximum) {
        if (minimum > maximum) {
            throw invalid_argument("Invalid random range.");
        }

        uniform_int_distribution<uint64_t> distribution(
            minimum,
            maximum
        );

        return distribution(engine_);
    }
};


// ============================================================
// Modular arithmetic
// ============================================================

uint64_t modularMultiply(
    uint64_t a,
    uint64_t b,
    uint64_t modulus
) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero.");
    }

    return static_cast<uint64_t>(
        (static_cast<unsigned __int128>(a) * b) % modulus
    );
}


uint64_t modularPower(
    uint64_t base,
    uint64_t exponent,
    uint64_t modulus
) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero.");
    }

    uint64_t result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1ULL) {
            result = modularMultiply(result, base, modulus);
        }

        base = modularMultiply(base, base, modulus);
        exponent >>= 1;
    }

    return result;
}


uint64_t gcdValue(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}


int64_t extendedGCD(
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

    int64_t g = extendedGCD(b, a % b, x1, y1);

    x = y1;
    y = x1 - (a / b) * y1;

    return g;
}


uint64_t modularInverse(uint64_t value, uint64_t modulus) {
    int64_t x = 0;
    int64_t y = 0;

    int64_t g = extendedGCD(
        static_cast<int64_t>(value),
        static_cast<int64_t>(modulus),
        x,
        y
    );

    if (g != 1) {
        throw CryptoException("Modular inverse does not exist.");
    }

    int64_t result = x % static_cast<int64_t>(modulus);

    if (result < 0) {
        result += static_cast<int64_t>(modulus);
    }

    return static_cast<uint64_t>(result);
}


// ============================================================
// Prime generation
// ============================================================

bool isPrime(uint64_t number) {
    if (number < 2) return false;

    if (number == 2 || number == 3) return true;

    if (number % 2 == 0) return false;

    for (uint64_t divisor = 3;
         divisor <= number / divisor;
         divisor += 2) {

        if (number % divisor == 0) {
            return false;
        }
    }

    return true;
}


uint64_t generatePrime(
    uint64_t minimum,
    uint64_t maximum,
    SecureRandom& random
) {
    if (minimum > maximum || minimum < 2) {
        throw invalid_argument("Invalid prime generation range.");
    }

    for (int attempt = 0; attempt < 100000; ++attempt) {
        uint64_t candidate = random.between(minimum, maximum);

        if (candidate > 2 && candidate % 2 == 0) {
            ++candidate;
        }

        if (candidate <= maximum && isPrime(candidate)) {
            return candidate;
        }
    }

    throw CryptoException("Prime generation failed.");
}


// ============================================================
// RSA domain model
// ============================================================

struct RSAPublicKey {
    uint64_t modulus;
    uint64_t exponent;
};


struct RSAPrivateKey {
    uint64_t modulus;
    uint64_t exponent;
};


struct RSAKeyPair {
    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;
};


class RSAService {

private:
    SecureRandom random_;

public:
    RSAKeyPair generateKeyPair() {
        uint64_t p = generatePrime(1000, 3000, random_);
        uint64_t q = generatePrime(1000, 3000, random_);

        while (p == q) {
            q = generatePrime(1000, 3000, random_);
        }

        uint64_t modulus = p * q;
        uint64_t phi = (p - 1) * (q - 1);

        uint64_t publicExponent = 65537;

        if (gcdValue(publicExponent, phi) != 1) {
            publicExponent = 17;
        }

        uint64_t privateExponent = modularInverse(
            publicExponent,
            phi
        );

        return {
            {modulus, publicExponent},
            {modulus, privateExponent}
        };
    }

    uint64_t encrypt(
        uint64_t message,
        const RSAPublicKey& publicKey
    ) const {

        if (publicKey.modulus <= 1 ||
            publicKey.exponent <= 1) {
            throw CryptoException("Invalid RSA public key.");
        }

        if (message >= publicKey.modulus) {
            throw CryptoException("Message exceeds RSA modulus.");
        }

        return modularPower(
            message,
            publicKey.exponent,
            publicKey.modulus
        );
    }

    uint64_t decrypt(
        uint64_t ciphertext,
        const RSAPrivateKey& privateKey
    ) const {

        if (privateKey.modulus <= 1 ||
            privateKey.exponent <= 0) {
            throw CryptoException("Invalid RSA private key.");
        }

        if (ciphertext >= privateKey.modulus) {
            throw CryptoException("Invalid ciphertext.");
        }

        return modularPower(
            ciphertext,
            privateKey.exponent,
            privateKey.modulus
        );
    }

    uint64_t sign(
        uint64_t message,
        const RSAPrivateKey& privateKey
    ) const {

        if (message >= privateKey.modulus) {
            throw CryptoException("Digest exceeds RSA modulus.");
        }

        return modularPower(
            message,
            privateKey.exponent,
            privateKey.modulus
        );
    }

    bool verify(
        uint64_t message,
        uint64_t signature,
        const RSAPublicKey& publicKey
    ) const {

        if (signature >= publicKey.modulus ||
            message >= publicKey.modulus) {
            return false;
        }

        return modularPower(
            signature,
            publicKey.exponent,
            publicKey.modulus
        ) == message;
    }
};


// ============================================================
// Diffie-Hellman
// ============================================================

struct DHParameters {
    uint64_t prime;
    uint64_t generator;
};


class DiffieHellmanService {

public:
    uint64_t generatePublicValue(
        uint64_t privateValue,
        const DHParameters& parameters
    ) const {

        if (!isPrime(parameters.prime) ||
            parameters.generator < 2 ||
            parameters.generator >= parameters.prime) {
            throw CryptoException("Invalid DH parameters.");
        }

        if (privateValue < 2 ||
            privateValue >= parameters.prime - 1) {
            throw CryptoException("Invalid DH private value.");
        }

        return modularPower(
            parameters.generator,
            privateValue,
            parameters.prime
        );
    }

    uint64_t deriveSharedSecret(
        uint64_t peerPublicValue,
        uint64_t privateValue,
        const DHParameters& parameters
    ) const {

        if (peerPublicValue < 2 ||
            peerPublicValue > parameters.prime - 2) {
            throw CryptoException("Invalid peer public value.");
        }

        if (privateValue < 2 ||
            privateValue >= parameters.prime - 1) {
            throw CryptoException("Invalid private value.");
        }

        return modularPower(
            peerPublicValue,
            privateValue,
            parameters.prime
        );
    }
};


// ============================================================
// Public-key fingerprint
// ============================================================

string fingerprint(const RSAPublicKey& key) {
    ostringstream input;

    input << key.modulus << ':' << key.exponent;

    // FNV-1a is used only as an educational identifier.
    // It is not a cryptographic key fingerprint.
    uint64_t hash = 14695981039346656037ULL;

    for (unsigned char character : input.str()) {
        hash ^= character;
        hash *= 1099511628211ULL;
    }

    ostringstream output;

    output << hex << setw(16) << setfill('0') << hash;

    return output.str();
}


// ============================================================
// Key registry
// ============================================================

struct KeyRecord {
    string id;
    string owner;
    string fingerprint;
    KeyPurpose purpose;
    KeyStatus status;
    uint64_t createdAt;
    uint64_t expiresAt;
};


class KeyRegistry {

private:
    unordered_map<string, KeyRecord> records_;
    uint64_t nextId_ = 1;

public:
    string registerKey(
        const string& owner,
        KeyPurpose purpose,
        const RSAPublicKey& publicKey,
        uint64_t now,
        uint64_t validitySeconds
    ) {

        if (owner.empty()) {
            throw CryptoException("Owner cannot be empty.");
        }

        if (publicKey.modulus <= 1 ||
            publicKey.exponent <= 1 ||
            publicKey.exponent >= publicKey.modulus) {
            throw CryptoException("Invalid public key.");
        }

        if (validitySeconds == 0 ||
            now > numeric_limits<uint64_t>::max() - validitySeconds) {
            throw CryptoException("Invalid key expiration.");
        }

        string keyFingerprint = fingerprint(publicKey);

        for (const auto& entry : records_) {
            const auto& existing = entry.second;

            if (existing.fingerprint == keyFingerprint &&
                existing.status != KeyStatus::Revoked) {
                throw CryptoException("Duplicate public key.");
            }
        }

        string id = "KEY-" + to_string(nextId_++);

        records_.emplace(
            id,
            KeyRecord{
                id,
                owner,
                keyFingerprint,
                purpose,
                KeyStatus::Active,
                now,
                now + validitySeconds
            }
        );

        return id;
    }

    const KeyRecord& get(const string& id) const {
        auto iterator = records_.find(id);

        if (iterator == records_.end()) {
            throw CryptoException("Key not found.");
        }

        return iterator->second;
    }

    bool isUsable(
        const string& id,
        KeyPurpose expectedPurpose,
        uint64_t now
    ) {

        auto iterator = records_.find(id);

        if (iterator == records_.end()) {
            return false;
        }

        KeyRecord& record = iterator->second;

        if (record.status != KeyStatus::Active) {
            return false;
        }

        if (now >= record.expiresAt) {
            record.status = KeyStatus::Expired;
            return false;
        }

        return record.purpose == expectedPurpose;
    }

    void rotate(const string& id) {
        auto iterator = records_.find(id);

        if (iterator == records_.end() ||
            iterator->second.status != KeyStatus::Active) {
            throw CryptoException("Key cannot be rotated.");
        }

        iterator->second.status = KeyStatus::Rotated;
    }

    void revoke(const string& id) {
        auto iterator = records_.find(id);

        if (iterator == records_.end() ||
            iterator->second.status == KeyStatus::Revoked) {
            throw CryptoException("Key cannot be revoked.");
        }

        iterator->second.status = KeyStatus::Revoked;
    }

    vector<KeyRecord> listByOwner(const string& owner) const {
        vector<KeyRecord> result;

        for (const auto& entry : records_) {
            if (entry.second.owner == owner) {
                result.push_back(entry.second);
            }
        }

        sort(
            result.begin(),
            result.end(),
            [](const KeyRecord& a, const KeyRecord& b) {
                return a.createdAt < b.createdAt;
            }
        );

        return result;
    }
};


// ============================================================
// Application policy
// ============================================================

struct EncryptionPolicy {
    uint64_t minimumModulus = 2048;
    bool requireAuthenticatedEncryption = true;
    bool allowRawRSA = false;
    bool requireActiveKey = true;
};


class PolicyEvaluator {

public:
    static vector<string> evaluate(
        const EncryptionPolicy& policy,
        uint64_t modulusBits,
        KeyStatus status
    ) {
        vector<string> violations;

        if (modulusBits < policy.minimumModulus) {
            violations.push_back("RSA key is below minimum size.");
        }

        if (!policy.allowRawRSA) {
            violations.push_back(
                "Textbook RSA is prohibited by policy."
            );
        }

        if (policy.requireAuthenticatedEncryption) {
            violations.push_back(
                "Authenticated encryption is required."
            );
        }

        if (policy.requireActiveKey &&
            status != KeyStatus::Active) {
            violations.push_back("Key is not active.");
        }

        return violations;
    }
};


// ============================================================
// Demonstration
// ============================================================

int main() {

    try {
        cout << "PUBLIC KEYS AND PRIVATE KEYS\n";
        cout << string(60, '=') << "\n";

        RSAService rsa;

        RSAKeyPair keys = rsa.generateKeyPair();

        cout << "\nRSA KEY GENERATION\n";
        cout << "Public modulus: " << keys.publicKey.modulus << "\n";
        cout << "Public exponent: " << keys.publicKey.exponent << "\n";
        cout << "Private exponent: " << keys.privateKey.exponent << "\n";

        // RSA encryption and decryption.
        uint64_t message = 12345;

        uint64_t ciphertext = rsa.encrypt(
            message,
            keys.publicKey
        );

        uint64_t plaintext = rsa.decrypt(
            ciphertext,
            keys.privateKey
        );

        if (plaintext != message) {
            throw CryptoException("RSA round trip failed.");
        }

        cout << "\nRSA ENCRYPTION\n";
        cout << "Original: " << message << "\n";
        cout << "Ciphertext: " << ciphertext << "\n";
        cout << "Decrypted: " << plaintext << "\n";

        // Digital signature.
        uint64_t documentDigest = 9876;

        uint64_t signature = rsa.sign(
            documentDigest,
            keys.privateKey
        );

        bool verified = rsa.verify(
            documentDigest,
            signature,
            keys.publicKey
        );

        bool tampered = rsa.verify(
            9877,
            signature,
            keys.publicKey
        );

        cout << "\nDIGITAL SIGNATURE\n";
        cout << "Valid signature: " << boolalpha << verified << "\n";
        cout << "Tampered document: " << tampered << "\n";

        if (!verified || tampered) {
            throw CryptoException("Signature verification failed.");
        }

        // Diffie-Hellman.
        DiffieHellmanService dh;

        DHParameters parameters{23, 5};

        uint64_t alicePrivate = 6;
        uint64_t bobPrivate = 15;

        uint64_t alicePublic = dh.generatePublicValue(
            alicePrivate,
            parameters
        );

        uint64_t bobPublic = dh.generatePublicValue(
            bobPrivate,
            parameters
        );

        uint64_t aliceSecret = dh.deriveSharedSecret(
            bobPublic,
            alicePrivate,
            parameters
        );

        uint64_t bobSecret = dh.deriveSharedSecret(
            alicePublic,
            bobPrivate,
            parameters
        );

        cout << "\nDIFFIE-HELLMAN\n";
        cout << "Alice public value: " << alicePublic << "\n";
        cout << "Bob public value: " << bobPublic << "\n";
        cout << "Alice secret: " << aliceSecret << "\n";
        cout << "Bob secret: " << bobSecret << "\n";

        if (aliceSecret != bobSecret) {
            throw CryptoException("Key agreement failed.");
        }

        // Key lifecycle.
        KeyRegistry registry;

        string keyId = registry.registerKey(
            "payment-service",
            KeyPurpose::Signing,
            keys.publicKey,
            1000,
            86400 * 365
        );

        cout << "\nKEY REGISTRY\n";
        cout << "Key ID: " << keyId << "\n";
        cout << "Fingerprint: "
             << fingerprint(keys.publicKey) << "\n";

        cout << "Usable: "
             << registry.isUsable(
                 keyId,
                 KeyPurpose::Signing,
                 2000
             ) << "\n";

        registry.rotate(keyId);

        cout << "Status after rotation: "
             << statusName(registry.get(keyId).status)
             << "\n";

        // Revocation.
        string secondKeyId = registry.registerKey(
            "document-service",
            KeyPurpose::Encryption,
            keys.publicKey,
            1000,
            86400
        );

        // A rotated key can be revoked.
        registry.revoke(keyId);

        cout << "Status after revocation: "
             << statusName(registry.get(keyId).status)
             << "\n";

        // Expiration.
        string thirdKeyId = registry.registerKey(
            "archive-service",
            KeyPurpose::Encryption,
            RSAPublicKey{keys.publicKey.modulus + 1,
                         keys.publicKey.exponent},
            1000,
            100
        );

        cout << "Expired key usable: "
             << registry.isUsable(
                 thirdKeyId,
                 KeyPurpose::Encryption,
                 1200
             ) << "\n";

        // Policy evaluation.
        EncryptionPolicy policy;

        auto violations = PolicyEvaluator::evaluate(
            policy,
            512,
            KeyStatus::Active
        );

        cout << "\nSECURITY POLICY\n";
        cout << "Policy violations: " << violations.size() << "\n";

        for (const string& violation : violations) {
            cout << "- " << violation << "\n";
        }

        // Owner-based retrieval.
        cout << "\nOWNER KEY RECORDS\n";

        for (const auto& record :
             registry.listByOwner("payment-service")) {

            cout << record.id << " | "
                 << record.owner << " | "
                 << purposeName(record.purpose) << " | "
                 << statusName(record.status) << "\n";
        }

        // Negative tests.
        cout << "\nVALIDATION TESTS\n";

        bool invalidRejected = false;

        try {
            rsa.encrypt(
                keys.publicKey.modulus,
                keys.publicKey
            );
        } catch (const CryptoException&) {
            invalidRejected = true;
        }

        cout << "Out-of-range message rejected: "
             << invalidRejected << "\n";

        if (!invalidRejected) {
            throw CryptoException("Invalid input was accepted.");
        }

        bool invalidDHRejected = false;

        try {
            dh.deriveSharedSecret(
                1,
                alicePrivate,
                parameters
            );
        } catch (const CryptoException&) {
            invalidDHRejected = true;
        }

        cout << "Invalid DH public value rejected: "
             << invalidDHRejected << "\n";

        if (!invalidDHRejected) {
            throw CryptoException("Invalid DH input was accepted.");
        }

        cout << "\nAll demonstrations completed successfully.\n";

    } catch (const exception& error) {
        cerr << "Execution failed: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
