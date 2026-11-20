#include <algorithm>
#include <cstdint>
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
#include <vector>

/*
 * RSA DIGITAL SIGNATURES
 * C++17 educational implementation.
 *
 * This program implements the mathematical RSA signing and
 * verification process using small integer arithmetic.
 *
 * SECURITY WARNING:
 * This is an educational demonstration, NOT production cryptography.
 *
 * It deliberately uses:
 * - Small RSA keys
 * - A non-cryptographic demonstration hash
 * - Deterministic textbook RSA encoding
 *
 * Production RSA signatures require a vetted implementation
 * of RSA-PSS, SHA-256 and secure private-key protection.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra rsa_signatures.cpp -o rsa_signatures
 */

using namespace std;

using u64 = uint64_t;
using u128 = __uint128_t;

enum class VerificationStatus {
    VALID,
    INVALID
};

struct RSAKey {
    u64 modulus;
    u64 exponent;
};

struct RSAKeyPair {
    RSAKey publicKey;
    RSAKey privateKey;
};

struct SignatureRecord {
    string documentId;
    u64 signature;
    u64 messageHash;
    string keyId;
    bool verified = false;
};

class RSAArithmetic {
public:
    static u64 gcd(u64 a, u64 b) {
        return std::gcd(a, b);
    }

    static u64 modularMultiply(u64 a, u64 b, u64 mod) {
        return static_cast<u64>(
            (static_cast<u128>(a) * b) % mod
        );
    }

    static u64 modularPower(u64 base, u64 exponent, u64 mod) {
        if (mod == 0) {
            throw invalid_argument("Modulus cannot be zero.");
        }

        u64 result = 1 % mod;
        base %= mod;

        while (exponent > 0) {
            if (exponent & 1ULL) {
                result = modularMultiply(result, base, mod);
            }

            base = modularMultiply(base, base, mod);
            exponent >>= 1;
        }

        return result;
    }

    static optional<u64> modularInverse(u64 a, u64 mod) {
        if (mod <= 1) {
            return nullopt;
        }

        __int128 oldR = a;
        __int128 r = mod;
        __int128 oldS = 1;
        __int128 s = 0;

        while (r != 0) {
            __int128 quotient = oldR / r;

            __int128 tempR = oldR - quotient * r;
            oldR = r;
            r = tempR;

            __int128 tempS = oldS - quotient * s;
            oldS = s;
            s = tempS;
        }

        if (oldR != 1) {
            return nullopt;
        }

        oldS %= static_cast<__int128>(mod);

        if (oldS < 0) {
            oldS += mod;
        }

        return static_cast<u64>(oldS);
    }

    static bool isPrime(u64 n) {
        if (n < 2) return false;

        for (u64 divisor = 2;
             divisor <= n / divisor;
             ++divisor) {
            if (n % divisor == 0) {
                return false;
            }
        }

        return true;
    }
};

class DemonstrationHash {
public:
    // FNV-1a is used only to illustrate a digest interface.
    // It is not a secure cryptographic hash.
    static u64 digest(const string& message) {
        u64 hash = 14695981039346656037ULL;

        for (unsigned char ch : message) {
            hash ^= ch;
            hash *= 1099511628211ULL;
        }

        return hash;
    }
};

class RSAKeyGenerator {
private:
    static RSAKeyPair fromPrimes(u64 p, u64 q) {
        if (!RSAArithmetic::isPrime(p) ||
            !RSAArithmetic::isPrime(q) ||
            p == q) {
            throw invalid_argument("Invalid RSA prime factors.");
        }

        if (p > numeric_limits<u64>::max() / q) {
            throw overflow_error("RSA modulus overflow.");
        }

        u64 n = p * q;
        u64 phi = (p - 1) * (q - 1);

        u64 e = 65537;

        if (e >= phi || RSAArithmetic::gcd(e, phi) != 1) {
            e = 17;
        }

        if (RSAArithmetic::gcd(e, phi) != 1) {
            e = 3;
        }

        auto d = RSAArithmetic::modularInverse(e, phi);

        if (!d) {
            throw runtime_error("Unable to calculate private exponent.");
        }

        return {
            {n, e},
            {n, *d}
        };
    }

public:
    static RSAKeyPair generateDemonstrationKey() {
        // Small factors make the mathematics inspectable.
        return fromPrimes(1009, 1013);
    }
};

class RSASignatureEngine {
private:
    RSAKeyPair keys;

    static void validateKey(const RSAKey& key) {
        if (key.modulus <= 1 ||
            key.exponent <= 0 ||
            key.exponent >= key.modulus) {
            throw invalid_argument("Invalid RSA key parameters.");
        }
    }

public:
    explicit RSASignatureEngine(RSAKeyPair pair)
        : keys(std::move(pair)) {
        validateKey(keys.publicKey);
        validateKey(keys.privateKey);

        if (keys.publicKey.modulus != keys.privateKey.modulus) {
            throw invalid_argument("RSA modulus mismatch.");
        }
    }

    u64 sign(const string& message) const {
        u64 digest = DemonstrationHash::digest(message);
        u64 encoded = digest % keys.privateKey.modulus;

        return RSAArithmetic::modularPower(
            encoded,
            keys.privateKey.exponent,
            keys.privateKey.modulus
        );
    }

    VerificationStatus verify(
        const string& message,
        u64 signature
    ) const {
        if (signature >= keys.publicKey.modulus) {
            return VerificationStatus::INVALID;
        }

        u64 recovered = RSAArithmetic::modularPower(
            signature,
            keys.publicKey.exponent,
            keys.publicKey.modulus
        );

        u64 expected =
            DemonstrationHash::digest(message) %
            keys.publicKey.modulus;

        return recovered == expected
            ? VerificationStatus::VALID
            : VerificationStatus::INVALID;
    }

    const RSAKey& publicKey() const {
        return keys.publicKey;
    }
};

class RepositorySignatureRegistry {
private:
    unordered_map<string, SignatureRecord> records;
    set<string> revokedKeys;

public:
    void revokeKey(const string& keyId) {
        revokedKeys.insert(keyId);
    }

    void registerSignature(
        const string& documentId,
        u64 signature,
        u64 messageHash,
        const string& keyId
    ) {
        if (documentId.empty() || keyId.empty()) {
            throw invalid_argument("Document and key IDs are required.");
        }

        if (revokedKeys.count(keyId)) {
            throw runtime_error("Signing key has been revoked.");
        }

        if (records.count(documentId)) {
            throw runtime_error("Document already has a signature record.");
        }

        records.emplace(
            documentId,
            SignatureRecord{
                documentId,
                signature,
                messageHash,
                keyId,
                false
            }
        );
    }

    bool verifyDocument(
        const string& documentId,
        const string& message,
        const RSASignatureEngine& engine
    ) {
        auto it = records.find(documentId);

        if (it == records.end()) {
            throw out_of_range("Signature record not found.");
        }

        SignatureRecord& record = it->second;

        if (revokedKeys.count(record.keyId)) {
            record.verified = false;
            return false;
        }

        if (record.messageHash != DemonstrationHash::digest(message)) {
            record.verified = false;
            return false;
        }

        record.verified =
            engine.verify(message, record.signature) ==
            VerificationStatus::VALID;

        return record.verified;
    }

    size_t size() const {
        return records.size();
    }
};

string statusText(VerificationStatus status) {
    return status == VerificationStatus::VALID
        ? "VALID"
        : "INVALID";
}

int main() {
    try {
        cout << "RSA DIGITAL SIGNATURE ENGINE\n";
        cout << "============================\n\n";

        cout << "WARNING: Educational small-key implementation.\n\n";

        RSAKeyPair pair =
            RSAKeyGenerator::generateDemonstrationKey();

        RSASignatureEngine engine(pair);

        cout << "Public modulus: " << pair.publicKey.modulus << '\n';
        cout << "Public exponent: " << pair.publicKey.exponent << '\n';

        string document =
            "RELEASE-2026-001|repository=payment-platform|approved=true";

        u64 signature = engine.sign(document);

        cout << "\nOriginal document:\n" << document << '\n';

        cout << "Signature: " << signature << '\n';

        cout << "Verification: "
             << statusText(engine.verify(document, signature))
             << '\n';

        string modified =
            "RELEASE-2026-001|repository=payment-platform|approved=false";

        cout << "Modified document: "
             << statusText(engine.verify(modified, signature))
             << '\n';

        cout << "Out-of-range signature: "
             << statusText(
                    engine.verify(document, pair.publicKey.modulus)
                )
             << '\n';

        RepositorySignatureRegistry registry;

        registry.registerSignature(
            "RELEASE-2026-001",
            signature,
            DemonstrationHash::digest(document),
            "KEY-001"
        );

        cout << "\nRegistry verification: "
             << (registry.verifyDocument(
                    "RELEASE-2026-001",
                    document,
                    engine
                ) ? "VALID" : "INVALID")
             << '\n';

        cout << "Registered records: " << registry.size() << '\n';

        registry.revokeKey("KEY-001");

        cout << "Verification after key revocation: "
             << (registry.verifyDocument(
                    "RELEASE-2026-001",
                    document,
                    engine
                ) ? "VALID" : "REJECTED")
             << '\n';

        bool inverseExists =
            RSAArithmetic::modularInverse(12, 18).has_value();

        cout << "Inverse for non-coprime values exists: "
             << boolalpha << inverseExists << '\n';

        if (engine.verify(document, signature) !=
            VerificationStatus::VALID) {
            throw runtime_error("Signature self-test failed.");
        }

        if (engine.verify(modified, signature) !=
            VerificationStatus::INVALID) {
            throw runtime_error("Tampering test failed.");
        }

        cout << "\nAll educational tests passed.\n";

    } catch (const exception& error) {
        cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
