#include <algorithm>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

/*
 * Introduction to Public-Key Cryptography
 *
 * C++17 educational implementation.
 *
 * Demonstrates:
 * 1. RSA mathematical operations.
 * 2. Public-key encryption and private-key decryption.
 * 3. RSA-style modular digital signatures.
 * 4. Diffie-Hellman key agreement.
 * 5. Public-key registration and revocation.
 * 6. Cryptographic input validation.
 *
 * IMPORTANT:
 * This program uses small integers and textbook RSA.
 * It is NOT suitable for protecting real information.
 * Production systems require secure cryptographic libraries,
 * randomized padding, strong keys, and authenticated protocols.
 */

namespace crypto {

using Integer = uint64_t;

class CryptoException : public runtime_error {
public:
    explicit CryptoException(const string& message)
        : runtime_error(message) {}
};

struct PublicKey {
    Integer modulus;
    Integer exponent;
};

struct PrivateKey {
    Integer modulus;
    Integer exponent;
};

struct RSAKeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;
};

enum class KeyStatus {
    ACTIVE,
    REVOKED
};

struct KeyRecord {
    PublicKey key;
    KeyStatus status;
};

Integer modularMultiply(Integer a, Integer b, Integer modulus) {
    if (modulus == 0) {
        throw CryptoException("Zero modulus.");
    }

    return static_cast<Integer>(
        (static_cast<__uint128_t>(a) * b) % modulus
    );
}

Integer modularPower(Integer base, Integer exponent, Integer modulus) {
    if (modulus == 0) {
        throw CryptoException("Modulus cannot be zero.");
    }

    Integer result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = modularMultiply(result, base, modulus);
        }

        base = modularMultiply(base, base, modulus);
        exponent >>= 1;
    }

    return result;
}

bool isPrime(Integer number) {
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

Integer modularInverse(Integer a, Integer modulus) {
    if (modulus == 0 || a >= modulus) {
        throw CryptoException("Invalid modular inverse parameters.");
    }

    __int128 t = 0;
    __int128 newT = 1;

    __int128 r = modulus;
    __int128 newR = a;

    while (newR != 0) {
        Integer quotient = static_cast<Integer>(r / newR);

        __int128 tempT = t - quotient * newT;
        t = newT;
        newT = tempT;

        __int128 tempR = r - quotient * newR;
        r = newR;
        newR = tempR;
    }

    if (r != 1) {
        throw CryptoException("Modular inverse does not exist.");
    }

    t %= modulus;

    if (t < 0) {
        t += modulus;
    }

    return static_cast<Integer>(t);
}

class RSA {
public:
    static RSAKeyPair generateKeyPair(Integer p, Integer q) {
        if (!isPrime(p) || !isPrime(q) || p == q) {
            throw CryptoException("RSA requires distinct prime numbers.");
        }

        if (p > numeric_limits<Integer>::max() / q) {
            throw CryptoException("RSA modulus overflow.");
        }

        Integer n = p * q;
        Integer phi = (p - 1) * (q - 1);

        Integer e = 65537;

        if (gcd(e, phi) != 1) {
            e = 17;
        }

        if (gcd(e, phi) != 1) {
            throw CryptoException("Unable to select public exponent.");
        }

        Integer d = modularInverse(e, phi);

        return {
            {n, e},
            {n, d}
        };
    }

    static vector<Integer> encrypt(
        const string& message,
        const PublicKey& key
    ) {
        if (key.modulus <= 255 || key.exponent <= 1) {
            throw CryptoException("Invalid RSA public key.");
        }

        vector<Integer> ciphertext;

        for (unsigned char character : message) {
            ciphertext.push_back(
                modularPower(character, key.exponent, key.modulus)
            );
        }

        return ciphertext;
    }

    static string decrypt(
        const vector<Integer>& ciphertext,
        const PrivateKey& key
    ) {
        string plaintext;

        for (Integer value : ciphertext) {
            if (value >= key.modulus) {
                throw CryptoException("Invalid ciphertext value.");
            }

            Integer decoded = modularPower(
                value,
                key.exponent,
                key.modulus
            );

            if (decoded > 255) {
                throw CryptoException("Invalid decrypted byte.");
            }

            plaintext.push_back(static_cast<char>(decoded));
        }

        return plaintext;
    }

    static Integer sign(Integer messageDigest, const PrivateKey& key) {
        if (messageDigest >= key.modulus) {
            messageDigest %= key.modulus;
        }

        return modularPower(
            messageDigest,
            key.exponent,
            key.modulus
        );
    }

    static bool verify(
        Integer messageDigest,
        Integer signature,
        const PublicKey& key
    ) {
        if (signature >= key.modulus) {
            return false;
        }

        messageDigest %= key.modulus;

        Integer recovered = modularPower(
            signature,
            key.exponent,
            key.modulus
        );

        return recovered == messageDigest;
    }
};

class DiffieHellman {
public:
    static Integer generatePublic(
        Integer generator,
        Integer privateKey,
        Integer prime
    ) {
        if (!isPrime(prime)) {
            throw CryptoException("DH modulus must be prime.");
        }

        if (generator < 2 || generator >= prime ||
            privateKey < 2 || privateKey >= prime - 1) {
            throw CryptoException("Invalid DH parameters.");
        }

        return modularPower(generator, privateKey, prime);
    }

    static Integer generateSharedSecret(
        Integer receivedPublic,
        Integer privateKey,
        Integer prime
    ) {
        if (receivedPublic < 2 || receivedPublic >= prime - 1) {
            throw CryptoException("Invalid peer public value.");
        }

        return modularPower(receivedPublic, privateKey, prime);
    }
};

class PublicKeyDirectory {
private:
    unordered_map<string, KeyRecord> records;

public:
    void registerKey(
        const string& identity,
        const PublicKey& key
    ) {
        if (identity.empty()) {
            throw CryptoException("Identity cannot be empty.");
        }

        if (key.modulus <= 255 || key.exponent <= 1) {
            throw CryptoException("Invalid public key.");
        }

        if (records.count(identity)) {
            throw CryptoException("Identity already exists.");
        }

        records.emplace(
            identity,
            KeyRecord{key, KeyStatus::ACTIVE}
        );
    }

    PublicKey getActiveKey(const string& identity) const {
        auto iterator = records.find(identity);

        if (iterator == records.end()) {
            throw CryptoException("Unknown identity.");
        }

        if (iterator->second.status != KeyStatus::ACTIVE) {
            throw CryptoException("Public key has been revoked.");
        }

        return iterator->second.key;
    }

    void revoke(const string& identity) {
        auto iterator = records.find(identity);

        if (iterator == records.end()) {
            throw CryptoException("Unknown identity.");
        }

        iterator->second.status = KeyStatus::REVOKED;
    }

    size_t activeCount() const {
        return count_if(
            records.begin(),
            records.end(),
            [](const auto& entry) {
                return entry.second.status == KeyStatus::ACTIVE;
            }
        );
    }
};

} // namespace crypto

using namespace crypto;

void demonstrateRSA() {
    cout << "\n--- RSA Encryption and Decryption ---\n";

    RSAKeyPair keys = RSA::generateKeyPair(61, 53);

    string message = "HELLO";

    auto ciphertext = RSA::encrypt(message, keys.publicKey);

    cout << "Original: " << message << '\n';
    cout << "Encrypted integers: ";

    for (Integer value : ciphertext) {
        cout << value << ' ';
    }

    cout << '\n';

    string recovered = RSA::decrypt(
        ciphertext,
        keys.privateKey
    );

    cout << "Recovered: " << recovered << '\n';

    if (message != recovered) {
        throw CryptoException("RSA round trip failed.");
    }

    cout << "\n--- RSA-Style Digital Signature ---\n";

    Integer digest = 12345;

    Integer signature = RSA::sign(
        digest,
        keys.privateKey
    );

    cout << "Signature: " << signature << '\n';

    cout << "Valid signature: "
         << boolalpha
         << RSA::verify(digest, signature, keys.publicKey)
         << '\n';

    cout << "Modified message accepted: "
         << RSA::verify(54321, signature, keys.publicKey)
         << '\n';
}

void demonstrateDiffieHellman() {
    cout << "\n--- Diffie-Hellman Key Agreement ---\n";

    Integer prime = 23;
    Integer generator = 5;

    Integer alicePrivate = 6;
    Integer bobPrivate = 15;

    Integer alicePublic = DiffieHellman::generatePublic(
        generator,
        alicePrivate,
        prime
    );

    Integer bobPublic = DiffieHellman::generatePublic(
        generator,
        bobPrivate,
        prime
    );

    Integer aliceSecret = DiffieHellman::generateSharedSecret(
        bobPublic,
        alicePrivate,
        prime
    );

    Integer bobSecret = DiffieHellman::generateSharedSecret(
        alicePublic,
        bobPrivate,
        prime
    );

    cout << "Alice public value: " << alicePublic << '\n';
    cout << "Bob public value: " << bobPublic << '\n';

    cout << "Alice shared secret: " << aliceSecret << '\n';
    cout << "Bob shared secret: " << bobSecret << '\n';

    cout << "Agreement successful: "
         << boolalpha
         << (aliceSecret == bobSecret)
         << '\n';
}

void demonstrateKeyDirectory() {
    cout << "\n--- Public-Key Directory ---\n";

    auto keys = RSA::generateKeyPair(61, 53);

    PublicKeyDirectory directory;

    directory.registerKey("alice@example.com", keys.publicKey);

    cout << "Active keys: " << directory.activeCount() << '\n';

    directory.revoke("alice@example.com");

    cout << "Active keys after revocation: "
         << directory.activeCount()
         << '\n';

    try {
        directory.getActiveKey("alice@example.com");
    } catch (const CryptoException& error) {
        cout << "Access rejected: " << error.what() << '\n';
    }
}

void runTests() {
    if (!isPrime(101) || isPrime(100)) {
        throw CryptoException("Primality test failed.");
    }

    if (modularPower(2, 10, 1000) != 24) {
        throw CryptoException("Modular exponentiation failed.");
    }

    auto keys = RSA::generateKeyPair(61, 53);

    string message = "TEST";

    auto encrypted = RSA::encrypt(message, keys.publicKey);

    if (RSA::decrypt(encrypted, keys.privateKey) != message) {
        throw CryptoException("RSA test failed.");
    }

    Integer digest = 1234;
    Integer signature = RSA::sign(digest, keys.privateKey);

    if (!RSA::verify(digest, signature, keys.publicKey)) {
        throw CryptoException("Signature test failed.");
    }

    if (RSA::verify(4321, signature, keys.publicKey)) {
        throw CryptoException("Tampering test failed.");
    }

    cout << "All tests passed.\n";
}

int main() {
    try {
        cout << "INTRODUCTION TO PUBLIC-KEY CRYPTOGRAPHY\n";

        runTests();
        demonstrateRSA();
        demonstrateDiffieHellman();
        demonstrateKeyDirectory();

        cout << "\nSecurity limitations:\n";
        cout << "- Small RSA integers are educational only.\n";
        cout << "- Textbook RSA provides no secure padding.\n";
        cout << "- The signature example does not implement RSA-PSS.\n";
        cout << "- DH parameters are deliberately small.\n";
        cout << "- Production cryptography requires vetted libraries.\n";

    } catch (const exception& error) {
        cerr << "Cryptographic failure: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
