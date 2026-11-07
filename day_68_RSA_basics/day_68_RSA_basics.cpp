#include <algorithm>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * RSA Basics: C++17 implementation.

 * Scenario:
 * An educational secure-message gateway processes integer
 * representatives using RSA public and private keys.

 * This implementation intentionally uses small integer keys.
 * It is not suitable for production cryptography.
 *
 * Production RSA requires arbitrary-precision arithmetic,
 * secure padding, protected key storage, and vetted libraries.
 */

using namespace std;

using u64 = uint64_t;
using u128 = __uint128_t;

class RSAException : public runtime_error {
public:
    explicit RSAException(const string& message)
        : runtime_error(message) {}
};

enum class Operation {
    Encryption,
    Decryption,
    Verification
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
    u64 phi;
};

struct AuditRecord {
    string operation;
    bool successful;
    u64 input;
    u64 output;
};

class ModularArithmetic {
public:
    static u64 multiplyMod(u64 a, u64 b, u64 modulus) {
        if (modulus == 0) {
            throw RSAException("Modulus cannot be zero.");
        }

        return static_cast<u64>(
            (static_cast<u128>(a) * b) % modulus
        );
    }

    static u64 powerMod(u64 base, u64 exponent, u64 modulus) {
        if (modulus == 0) {
            throw RSAException("Modulus cannot be zero.");
        }

        u64 result = 1;
        base %= modulus;

        while (exponent > 0) {
            if (exponent & 1ULL) {
                result = multiplyMod(result, base, modulus);
            }

            base = multiplyMod(base, base, modulus);
            exponent >>= 1;
        }

        return result;
    }

    static u64 inverse(u64 a, u64 modulus) {
        if (modulus <= 1) {
            throw RSAException("Invalid inverse modulus.");
        }

        int64_t t = 0;
        int64_t newT = 1;
        int64_t r = static_cast<int64_t>(modulus);
        int64_t newR = static_cast<int64_t>(a);

        while (newR != 0) {
            int64_t quotient = r / newR;

            int64_t tempT = t - quotient * newT;
            t = newT;
            newT = tempT;

            int64_t tempR = r - quotient * newR;
            r = newR;
            newR = tempR;
        }

        if (r != 1) {
            throw RSAException("Modular inverse does not exist.");
        }

        t %= static_cast<int64_t>(modulus);

        if (t < 0) {
            t += static_cast<int64_t>(modulus);
        }

        return static_cast<u64>(t);
    }
};

class PrimeService {
public:
    static bool isPrime(u64 n) {
        if (n < 2) return false;

        if (n % 2 == 0) return n == 2;

        for (u64 divisor = 3;
             divisor <= n / divisor;
             divisor += 2) {
            if (n % divisor == 0) {
                return false;
            }
        }

        return true;
    }
};

class RSAKeyFactory {
public:
    static RSAKeyPair createEducationalKey(
        u64 p,
        u64 q,
        u64 e
    ) {
        if (!PrimeService::isPrime(p) ||
            !PrimeService::isPrime(q)) {
            throw RSAException(
                "Both factors must be prime."
            );
        }

        if (p == q) {
            throw RSAException(
                "Prime factors must be different."
            );
        }

        const u128 modulus =
            static_cast<u128>(p) * q;

        const u128 totient =
            static_cast<u128>(p - 1) * (q - 1);

        if (modulus > UINT64_MAX ||
            totient > INT64_MAX) {
            throw RSAException(
                "Key values exceed supported arithmetic limits."
            );
        }

        const u64 n = static_cast<u64>(modulus);
        const u64 phi = static_cast<u64>(totient);

        if (e <= 1 || e >= phi ||
            gcd(e, phi) != 1) {
            throw RSAException(
                "Invalid public exponent."
            );
        }

        const u64 d = ModularArithmetic::inverse(e, phi);

        return {
            {n, e},
            {n, d, p, q},
            phi
        };
    }
};

class RSAEngine {
private:
    PublicKey publicKey;
    PrivateKey privateKey;

    vector<AuditRecord> auditLog;

    void validatePublicKey() const {
        if (publicKey.n <= 1 ||
            publicKey.e <= 1 ||
            publicKey.e >= publicKey.n) {
            throw RSAException("Invalid public key.");
        }
    }

    void validatePrivateKey() const {
        if (privateKey.n <= 1 ||
            privateKey.p * privateKey.q != privateKey.n ||
            privateKey.p == privateKey.q ||
            privateKey.d == 0) {
            throw RSAException("Invalid private key.");
        }
    }

    void record(
        const string& operation,
        bool success,
        u64 input,
        u64 output
    ) {
        auditLog.push_back({
            operation,
            success,
            input,
            output
        });
    }

public:
    explicit RSAEngine(const RSAKeyPair& keyPair)
        : publicKey(keyPair.publicKey),
          privateKey(keyPair.privateKey) {
        validatePublicKey();
        validatePrivateKey();
    }

    u64 encrypt(u64 message) {
        validatePublicKey();

        if (message >= publicKey.n) {
            throw RSAException(
                "Message must be smaller than modulus."
            );
        }

        const u64 ciphertext =
            ModularArithmetic::powerMod(
                message,
                publicKey.e,
                publicKey.n
            );

        record("ENCRYPT", true, message, ciphertext);

        return ciphertext;
    }

    u64 decrypt(u64 ciphertext) {
        validatePrivateKey();

        if (ciphertext >= privateKey.n) {
            throw RSAException(
                "Ciphertext must be smaller than modulus."
            );
        }

        // CRT parameters reduce exponentiation cost.
        const u64 dp =
            privateKey.d % (privateKey.p - 1);

        const u64 dq =
            privateKey.d % (privateKey.q - 1);

        const u64 qInverse =
            ModularArithmetic::inverse(
                privateKey.q,
                privateKey.p
            );

        const u64 m1 =
            ModularArithmetic::powerMod(
                ciphertext,
                dp,
                privateKey.p
            );

        const u64 m2 =
            ModularArithmetic::powerMod(
                ciphertext,
                dq,
                privateKey.q
            );

        const u64 difference =
            (m1 + privateKey.p - m2) % privateKey.p;

        const u64 h =
            ModularArithmetic::multiplyMod(
                qInverse,
                difference,
                privateKey.p
            );

        const u128 result =
            static_cast<u128>(m2) +
            static_cast<u128>(h) * privateKey.q;

        if (result >= privateKey.n) {
            throw RSAException(
                "CRT reconstruction produced invalid output."
            );
        }

        const u64 message = static_cast<u64>(result);

        record("DECRYPT", true, ciphertext, message);

        return message;
    }

    bool verify(u64 message, u64 signature) {
        validatePublicKey();

        if (message >= publicKey.n ||
            signature >= publicKey.n) {
            return false;
        }

        const u64 recovered =
            ModularArithmetic::powerMod(
                signature,
                publicKey.e,
                publicKey.n
            );

        const bool valid = recovered == message;

        record(
            "VERIFY",
            valid,
            signature,
            recovered
        );

        return valid;
    }

    u64 signEducational(u64 message) {
        validatePrivateKey();

        if (message >= privateKey.n) {
            throw RSAException(
                "Message representative exceeds modulus."
            );
        }

        const u64 signature =
            ModularArithmetic::powerMod(
                message,
                privateKey.d,
                privateKey.n
            );

        record("SIGN", true, message, signature);

        return signature;
    }

    void displayAudit() const {
        cout << "\nOPERATION AUDIT\n";

        for (const auto& entry : auditLog) {
            cout
                << entry.operation
                << " | "
                << (entry.successful ? "SUCCESS" : "FAILURE")
                << " | Input: "
                << entry.input
                << " | Output: "
                << entry.output
                << '\n';
        }
    }
};

void demonstrateClassicRSA() {
    cout << "\nCLASSIC RSA EXAMPLE\n";
    cout << "-------------------\n";

    const RSAKeyPair key =
        RSAKeyFactory::createEducationalKey(
            61, 53, 17
        );

    cout << "p: " << key.privateKey.p << '\n';
    cout << "q: " << key.privateKey.q << '\n';
    cout << "n: " << key.publicKey.n << '\n';
    cout << "phi: " << key.phi << '\n';
    cout << "e: " << key.publicKey.e << '\n';
    cout << "d: " << key.privateKey.d << '\n';

    RSAEngine engine(key);

    const u64 message = 65;
    const u64 ciphertext = engine.encrypt(message);
    const u64 recovered = engine.decrypt(ciphertext);

    cout << "Original: " << message << '\n';
    cout << "Encrypted: " << ciphertext << '\n';
    cout << "Decrypted: " << recovered << '\n';

    if (message != recovered) {
        throw RSAException("Round-trip validation failed.");
    }

    const u64 signature = engine.signEducational(message);

    cout << "Signature: " << signature << '\n';
    cout << "Signature valid: "
         << boolalpha
         << engine.verify(message, signature)
         << '\n';

    cout << "Modified message valid: "
         << engine.verify(message + 1, signature)
         << '\n';

    engine.displayAudit();
}

void demonstrateFailureHandling() {
    cout << "\nFAILURE HANDLING\n";

    try {
        RSAKeyFactory::createEducationalKey(
            61, 61, 17
        );
    } catch (const RSAException& error) {
        cout << "Duplicate factors rejected: "
             << error.what() << '\n';
    }

    try {
        RSAKeyFactory::createEducationalKey(
            61, 53, 12
        );
    } catch (const RSAException& error) {
        cout << "Invalid exponent rejected: "
             << error.what() << '\n';
    }

    try {
        RSAKeyFactory::createEducationalKey(
            60, 53, 17
        );
    } catch (const RSAException& error) {
        cout << "Non-prime factor rejected: "
             << error.what() << '\n';
    }
}

int main() {
    try {
        cout << "RSA BASICS - C++17\n";
        cout << "==================\n";

        demonstrateClassicRSA();
        demonstrateFailureHandling();

        cout << "\nSECURITY CONSIDERATIONS\n";
        cout << "1. This implementation uses small integer keys.\n";
        cout << "2. It does not implement secure RSA padding.\n";
        cout << "3. Raw RSA is deterministic and malleable.\n";
        cout << "4. Use RSA-OAEP for encryption.\n";
        cout << "5. Use RSA-PSS for signatures.\n";
        cout << "6. Production systems need constant-time operations.\n";
        cout << "7. Private keys require protected storage.\n";

    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
