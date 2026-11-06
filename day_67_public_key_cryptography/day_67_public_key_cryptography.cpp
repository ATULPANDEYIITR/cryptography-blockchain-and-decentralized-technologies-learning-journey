#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Public-Key Cryptography: Educational RSA Implementation.
 *
 * Standard: C++17
 * Dependencies: Standard library only.
 *
 * Implements:
 * - Modular exponentiation
 * - Greatest common divisor
 * - Modular inverse
 * - Prime validation
 * - RSA key generation from small educational primes
 * - Public-key encryption
 * - Private-key decryption
 * - RSA-style signing and verification
 * - Key registry and lifecycle
 * - Message integrity checks
 *
 * SECURITY WARNING:
 * This implementation uses small integer keys and textbook RSA.
 * It is deliberately educational and NOT secure for real applications.
 * It does not implement OAEP, PSS, secure random prime generation,
 * constant-time arithmetic, or cryptographic padding.
 */

using namespace std;

using Integer = uint64_t;

enum class KeyStatus {
    ACTIVE,
    ROTATED,
    REVOKED
};

struct RSAKey {
    Integer modulus;
    Integer exponent;
};

struct RSAKeyPair {
    RSAKey publicKey;
    RSAKey privateKey;
    Integer p;
    Integer q;
    KeyStatus status = KeyStatus::ACTIVE;
    string identifier;
};

struct CipherMessage {
    vector<Integer> blocks;
    string recipientId;
};

class CryptoException : public runtime_error {
public:
    explicit CryptoException(const string& message)
        : runtime_error(message) {}
};

class NumberTheory {
public:
    static Integer gcd(Integer a, Integer b) {
        while (b != 0) {
            Integer remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }

    static Integer modularMultiply(
        Integer a,
        Integer b,
        Integer modulus
    ) {
        // Avoid overflow while multiplying modulo modulus.
        Integer result = 0;
        a %= modulus;

        while (b > 0) {
            if (b & 1) {
                result = (result >= modulus - a)
                    ? result - (modulus - a)
                    : result + a;
            }

            b >>= 1;

            if (b > 0) {
                a = (a >= modulus - a)
                    ? a - (modulus - a)
                    : a + a;
            }
        }

        return result;
    }

    static Integer modularPower(
        Integer base,
        Integer exponent,
        Integer modulus
    ) {
        if (modulus == 0) {
            throw CryptoException("Modulus cannot be zero.");
        }

        Integer result = 1;
        base %= modulus;

        while (exponent > 0) {
            if (exponent & 1) {
                result = modularMultiply(result, base, modulus);
            }

            exponent >>= 1;

            if (exponent > 0) {
                base = modularMultiply(base, base, modulus);
            }
        }

        return result;
    }

    static Integer modularInverse(Integer a, Integer modulus) {
        if (modulus == 0 ||
            modulus > static_cast<Integer>(
                numeric_limits<int64_t>::max()
            )) {
            throw CryptoException("Unsupported modular inverse range.");
        }

        int64_t oldR = static_cast<int64_t>(a % modulus);
        int64_t r = static_cast<int64_t>(modulus);

        int64_t oldS = 1;
        int64_t s = 0;

        while (r != 0) {
            int64_t quotient = oldR / r;

            int64_t nextR = oldR - quotient * r;
            oldR = r;
            r = nextR;

            int64_t nextS = oldS - quotient * s;
            oldS = s;
            s = nextS;
        }

        if (oldR != 1) {
            throw CryptoException("Modular inverse does not exist.");
        }

        int64_t result = oldS % static_cast<int64_t>(modulus);

        if (result < 0) {
            result += static_cast<int64_t>(modulus);
        }

        return static_cast<Integer>(result);
    }

    static bool isPrime(Integer number) {
        if (number < 2) {
            return false;
        }

        if (number % 2 == 0) {
            return number == 2;
        }

        for (Integer divisor = 3;
             divisor <= number / divisor;
             divisor += 2) {
            if (number % divisor == 0) {
                return false;
            }
        }

        return true;
    }
};

class RSAEngine {
private:
    static string calculateIdentifier(
        Integer modulus,
        Integer exponent
    ) {
        return to_string(modulus) + ":" + to_string(exponent);
    }

public:
    static RSAKeyPair generateKeyPair(
        Integer p,
        Integer q,
        Integer publicExponent = 65537
    ) {
        if (!NumberTheory::isPrime(p) ||
            !NumberTheory::isPrime(q)) {
            throw CryptoException("Both RSA factors must be prime.");
        }

        if (p == q) {
            throw CryptoException("RSA prime factors must be distinct.");
        }

        if (p > numeric_limits<Integer>::max() / q) {
            throw CryptoException("RSA modulus overflow.");
        }

        Integer modulus = p * q;
        Integer phi = (p - 1) * (q - 1);

        if (publicExponent <= 1 ||
            publicExponent >= phi ||
            NumberTheory::gcd(publicExponent, phi) != 1) {
            throw CryptoException("Invalid public exponent.");
        }

        Integer privateExponent =
            NumberTheory::modularInverse(publicExponent, phi);

        RSAKeyPair pair;

        pair.publicKey = {modulus, publicExponent};
        pair.privateKey = {modulus, privateExponent};
        pair.p = p;
        pair.q = q;

        pair.identifier = calculateIdentifier(
            modulus,
            publicExponent
        );

        return pair;
    }

    static Integer encryptBlock(
        Integer message,
        const RSAKey& publicKey
    ) {
        if (message >= publicKey.modulus) {
            throw CryptoException("Message block exceeds RSA modulus.");
        }

        return NumberTheory::modularPower(
            message,
            publicKey.exponent,
            publicKey.modulus
        );
    }

    static Integer decryptBlock(
        Integer ciphertext,
        const RSAKey& privateKey
    ) {
        if (ciphertext >= privateKey.modulus) {
            throw CryptoException("Invalid ciphertext block.");
        }

        return NumberTheory::modularPower(
            ciphertext,
            privateKey.exponent,
            privateKey.modulus
        );
    }

    static CipherMessage encryptMessage(
        const string& plaintext,
        const RSAKeyPair& recipient
    ) {
        if (recipient.status != KeyStatus::ACTIVE) {
            throw CryptoException("Recipient key is not active.");
        }

        CipherMessage message;
        message.recipientId = recipient.identifier;

        for (unsigned char character : plaintext) {
            message.blocks.push_back(
                encryptBlock(character, recipient.publicKey)
            );
        }

        return message;
    }

    static string decryptMessage(
        const CipherMessage& message,
        const RSAKeyPair& recipient
    ) {
        if (recipient.status == KeyStatus::REVOKED) {
            throw CryptoException("Recipient key has been revoked.");
        }

        if (message.recipientId != recipient.identifier) {
            throw CryptoException("Recipient identifier mismatch.");
        }

        string plaintext;

        for (Integer block : message.blocks) {
            Integer value = decryptBlock(
                block,
                recipient.privateKey
            );

            if (value > 255) {
                throw CryptoException("Invalid decoded byte.");
            }

            plaintext.push_back(static_cast<char>(value));
        }

        return plaintext;
    }

    static Integer signDigest(
        Integer digest,
        const RSAKeyPair& signer
    ) {
        if (signer.status != KeyStatus::ACTIVE) {
            throw CryptoException("Signing key is not active.");
        }

        if (digest >= signer.privateKey.modulus) {
            throw CryptoException("Digest exceeds modulus.");
        }

        return NumberTheory::modularPower(
            digest,
            signer.privateKey.exponent,
            signer.privateKey.modulus
        );
    }

    static bool verifySignature(
        Integer digest,
        Integer signature,
        const RSAKey& publicKey
    ) {
        if (digest >= publicKey.modulus ||
            signature >= publicKey.modulus) {
            return false;
        }

        return NumberTheory::modularPower(
            signature,
            publicKey.exponent,
            publicKey.modulus
        ) == digest;
    }
};

class KeyRegistry {
private:
    map<string, RSAKeyPair> keys;

public:
    void registerKey(const RSAKeyPair& key) {
        if (keys.count(key.identifier)) {
            throw CryptoException("Duplicate key registration.");
        }

        keys.emplace(key.identifier, key);
    }

    const RSAKeyPair& find(const string& identifier) const {
        auto iterator = keys.find(identifier);

        if (iterator == keys.end()) {
            throw CryptoException("Unknown key identifier.");
        }

        return iterator->second;
    }

    void rotate(const string& identifier) {
        auto iterator = keys.find(identifier);

        if (iterator == keys.end()) {
            throw CryptoException("Unknown key identifier.");
        }

        if (iterator->second.status != KeyStatus::ACTIVE) {
            throw CryptoException("Only active keys can rotate.");
        }

        iterator->second.status = KeyStatus::ROTATED;
    }

    void revoke(const string& identifier) {
        auto iterator = keys.find(identifier);

        if (iterator == keys.end()) {
            throw CryptoException("Unknown key identifier.");
        }

        iterator->second.status = KeyStatus::REVOKED;
    }

    vector<string> activeIdentifiers() const {
        vector<string> result;

        for (const auto& entry : keys) {
            if (entry.second.status == KeyStatus::ACTIVE) {
                result.push_back(entry.first);
            }
        }

        return result;
    }
};

class TransactionService {
private:
    map<string, Integer> signedTransactions;

public:
    void submit(
        const string& transactionId,
        Integer digest,
        Integer signature,
        const RSAKey& signerPublicKey
    ) {
        if (transactionId.empty()) {
            throw CryptoException("Transaction ID is required.");
        }

        if (signedTransactions.count(transactionId)) {
            throw CryptoException("Duplicate transaction.");
        }

        if (!RSAEngine::verifySignature(
            digest,
            signature,
            signerPublicKey
        )) {
            throw CryptoException("Invalid transaction signature.");
        }

        signedTransactions.emplace(transactionId, digest);
    }

    bool exists(const string& transactionId) const {
        return signedTransactions.count(transactionId) > 0;
    }
};

void printSection(const string& heading) {
    cout << "\n" << heading << "\n";
    cout << string(55, '-') << "\n";
}

int main() {
    try {
        cout << "PUBLIC-KEY CRYPTOGRAPHY: RSA\n";
        cout << string(55, '=') << "\n";

        printSection("1. KEY GENERATION");

        // Small textbook RSA values for demonstration only.
        RSAKeyPair alice = RSAEngine::generateKeyPair(
            61, 53, 17
        );

        RSAKeyPair bob = RSAEngine::generateKeyPair(
            47, 59, 17
        );

        cout << "Alice public modulus: "
             << alice.publicKey.modulus << "\n";

        cout << "Alice public exponent: "
             << alice.publicKey.exponent << "\n";

        cout << "Alice private exponent: "
             << alice.privateKey.exponent << "\n";

        cout << "Bob public modulus: "
             << bob.publicKey.modulus << "\n";

        printSection("2. PUBLIC-KEY ENCRYPTION");

        string plaintext = "HELLO";

        CipherMessage encrypted =
            RSAEngine::encryptMessage(plaintext, bob);

        cout << "Original: " << plaintext << "\n";
        cout << "Encrypted blocks: ";

        for (Integer block : encrypted.blocks) {
            cout << block << " ";
        }

        cout << "\n";

        string decrypted = RSAEngine::decryptMessage(
            encrypted,
            bob
        );

        cout << "Decrypted: " << decrypted << "\n";

        if (plaintext != decrypted) {
            throw CryptoException("Decryption verification failed.");
        }

        printSection("3. DIGITAL SIGNATURE");

        // A small numeric digest models the signature operation.
        // It is not a cryptographic hash implementation.
        Integer digest = 42;

        Integer signature = RSAEngine::signDigest(
            digest,
            alice
        );

        cout << "Digest: " << digest << "\n";
        cout << "Signature: " << signature << "\n";

        bool valid = RSAEngine::verifySignature(
            digest,
            signature,
            alice.publicKey
        );

        cout << "Signature valid: "
             << (valid ? "YES" : "NO") << "\n";

        cout << "Modified digest accepted: "
             << (RSAEngine::verifySignature(
                    43,
                    signature,
                    alice.publicKey
                ) ? "YES" : "NO") << "\n";

        printSection("4. TRANSACTION VERIFICATION");

        TransactionService transactions;

        transactions.submit(
            "TX-1001",
            digest,
            signature,
            alice.publicKey
        );

        cout << "Transaction TX-1001 accepted: "
             << transactions.exists("TX-1001") << "\n";

        try {
            transactions.submit(
                "TX-1002",
                43,
                signature,
                alice.publicKey
            );
        } catch (const CryptoException& error) {
            cout << "Invalid transaction rejected: "
                 << error.what() << "\n";
        }

        printSection("5. KEY REGISTRY");

        KeyRegistry registry;

        registry.registerKey(alice);
        registry.registerKey(bob);

        for (const string& id : registry.activeIdentifiers()) {
            cout << "Active key: " << id << "\n";
        }

        registry.rotate(alice.identifier);

        cout << "Alice key rotated successfully.\n";

        registry.revoke(bob.identifier);

        cout << "Bob key revoked successfully.\n";

        printSection("6. EDGE CASE VALIDATION");

        vector<pair<Integer, Integer>> invalidKeys = {
            {15, 53},
            {61, 61},
            {61, 53}
        };

        for (const auto& values : invalidKeys) {
            try {
                RSAEngine::generateKeyPair(
                    values.first,
                    values.second,
                    17
                );

                cout << "Key accepted.\n";
            } catch (const CryptoException& error) {
                cout << "Rejected: " << error.what() << "\n";
            }
        }

        try {
            RSAEngine::encryptBlock(
                3233,
                bob.publicKey
            );
        } catch (const CryptoException& error) {
            cout << "Oversized message rejected: "
                 << error.what() << "\n";
        }

        printSection("7. MATHEMATICAL VALIDATION");

        Integer p = 61;
        Integer q = 53;
        Integer n = p * q;
        Integer phi = (p - 1) * (q - 1);
        Integer e = 17;
        Integer d = NumberTheory::modularInverse(e, phi);

        cout << "p = " << p << "\n";
        cout << "q = " << q << "\n";
        cout << "n = p * q = " << n << "\n";
        cout << "phi(n) = " << phi << "\n";
        cout << "e = " << e << "\n";
        cout << "d = " << d << "\n";
        cout << "e * d mod phi(n) = "
             << ((e * d) % phi) << "\n";

        printSection("8. PERFORMANCE CHARACTERISTICS");

        cout << "Modular exponentiation: O(log exponent) "
             << "modular multiplications.\n";

        cout << "Prime validation: O(sqrt(n)) trial divisions.\n";

        cout << "Key registry lookup: O(log k).\n";

        cout << "\nDemonstration completed successfully.\n";

    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
