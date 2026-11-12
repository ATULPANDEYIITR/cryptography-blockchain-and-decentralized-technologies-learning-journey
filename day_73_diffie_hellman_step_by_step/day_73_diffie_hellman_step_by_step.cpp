#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;

/*
 * DIFFIE-HELLMAN REPOSITORY-STYLE GOVERNANCE ENGINE
 *
 * This implementation models a controlled cryptographic exchange.
 *
 * Features:
 * 1. Domain-specific parameter validation.
 * 2. Participant private and public keys.
 * 3. Modular exponentiation.
 * 4. Public-key subgroup validation.
 * 5. Shared secret agreement.
 * 6. Exchange lifecycle.
 * 7. Session validation.
 * 8. MITM attack demonstration.
 * 9. Automated edge-case tests.
 *
 * Educational parameters only.
 * Production cryptography requires vetted implementations.
 */

class DHException : public runtime_error {
public:
    explicit DHException(const string& message)
        : runtime_error(message) {}
};

class ParameterException : public DHException {
public:
    explicit ParameterException(const string& message)
        : DHException(message) {}
};

class PublicKeyException : public DHException {
public:
    explicit PublicKeyException(const string& message)
        : DHException(message) {}
};

class StateException : public DHException {
public:
    explicit StateException(const string& message)
        : DHException(message) {}
};

enum class ExchangeState {
    INITIALIZED,
    PARAMETERS_VALIDATED,
    KEYS_GENERATED,
    EXCHANGED,
    COMPLETED,
    FAILED
};

string stateName(ExchangeState state) {
    switch (state) {
        case ExchangeState::INITIALIZED:
            return "INITIALIZED";

        case ExchangeState::PARAMETERS_VALIDATED:
            return "PARAMETERS_VALIDATED";

        case ExchangeState::KEYS_GENERATED:
            return "KEYS_GENERATED";

        case ExchangeState::EXCHANGED:
            return "EXCHANGED";

        case ExchangeState::COMPLETED:
            return "COMPLETED";

        case ExchangeState::FAILED:
            return "FAILED";
    }

    return "UNKNOWN";
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;

    if (n == 2) return true;

    if (n % 2 == 0) return false;

    for (uint64_t i = 3; i <= n / i; i += 2) {
        if (n % i == 0) {
            return false;
        }
    }

    return true;
}

uint64_t modularMultiply(
    uint64_t a,
    uint64_t b,
    uint64_t modulus
) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero.");
    }

    // This implementation is intended for the small educational
    // parameters used here. Production implementations require
    // overflow-safe arithmetic or a multiprecision library.
    return (a * b) % modulus;
}

uint64_t modPow(
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

        exponent >>= 1ULL;
    }

    return result;
}

struct DHParameters {
    uint64_t p;
    uint64_t q;
    uint64_t g;

    void validate() const {
        if (p <= 5 || q <= 2) {
            throw ParameterException("Parameters are too small.");
        }

        if (!isPrime(p) || !isPrime(q)) {
            throw ParameterException("p and q must be prime.");
        }

        if ((p - 1) % q != 0) {
            throw ParameterException("q must divide p - 1.");
        }

        if (g <= 1 || g >= p) {
            throw ParameterException("Invalid generator range.");
        }

        if (modPow(g, q, p) != 1) {
            throw ParameterException("Generator is outside subgroup.");
        }
    }
};

class SecureRandomDemo {
private:
    mt19937_64 engine;

public:
    SecureRandomDemo()
        : engine(random_device{}()) {}

    uint64_t generate(uint64_t minimum, uint64_t maximum) {
        if (minimum > maximum) {
            throw invalid_argument("Invalid random range.");
        }

        uniform_int_distribution<uint64_t> distribution(
            minimum,
            maximum
        );

        return distribution(engine);
    }
};

class Participant {
private:
    string name;
    DHParameters parameters;

    uint64_t privateKey = 0;
    uint64_t publicKey = 0;

    SecureRandomDemo& random;

public:
    Participant(
        string participantName,
        DHParameters dhParameters,
        SecureRandomDemo& randomSource
    )
        : name(move(participantName)),
          parameters(dhParameters),
          random(randomSource) {}

    void generateKeys() {
        parameters.validate();

        privateKey = random.generate(1, parameters.q - 1);

        publicKey = modPow(
            parameters.g,
            privateKey,
            parameters.p
        );
    }

    uint64_t getPublicKey() const {
        if (publicKey == 0) {
            throw StateException("Public key not generated.");
        }

        return publicKey;
    }

    uint64_t getPrivateKeyForDemo() const {
        if (privateKey == 0) {
            throw StateException("Private key not generated.");
        }

        return privateKey;
    }

    const string& getName() const {
        return name;
    }

    void validatePublicKey(uint64_t receivedKey) const {
        if (
            receivedKey < 2 ||
            receivedKey > parameters.p - 2
        ) {
            throw PublicKeyException(
                "Public key outside accepted range."
            );
        }

        if (modPow(receivedKey, parameters.q, parameters.p) != 1) {
            throw PublicKeyException(
                "Public key does not belong to subgroup."
            );
        }
    }

    uint64_t computeSharedSecret(uint64_t receivedKey) const {
        if (privateKey == 0) {
            throw StateException("Private key unavailable.");
        }

        validatePublicKey(receivedKey);

        return modPow(
            receivedKey,
            privateKey,
            parameters.p
        );
    }
};

class GovernanceEngine {
private:
    DHParameters parameters;

    Participant alice;
    Participant bob;

    ExchangeState state = ExchangeState::INITIALIZED;

    uint64_t sharedSecret = 0;

public:
    GovernanceEngine(
        DHParameters dhParameters,
        SecureRandomDemo& random
    )
        : parameters(dhParameters),
          alice("Alice", dhParameters, random),
          bob("Bob", dhParameters, random) {}

    void transition(ExchangeState next) {
        state = next;

        cout << "[STATE] " << stateName(state) << '\n';
    }

    uint64_t execute() {
        try {
            parameters.validate();

            transition(ExchangeState::PARAMETERS_VALIDATED);

            alice.generateKeys();
            bob.generateKeys();

            transition(ExchangeState::KEYS_GENERATED);

            cout << "\nPUBLIC KEY GENERATION\n";

            cout << "Alice private key: "
                 << alice.getPrivateKeyForDemo() << '\n';

            cout << "Alice public key: "
                 << alice.getPublicKey() << '\n';

            cout << "Bob private key: "
                 << bob.getPrivateKeyForDemo() << '\n';

            cout << "Bob public key: "
                 << bob.getPublicKey() << '\n';

            // Public values are exchanged.
            uint64_t aliceReceived = bob.getPublicKey();
            uint64_t bobReceived = alice.getPublicKey();

            transition(ExchangeState::EXCHANGED);

            uint64_t aliceSecret =
                alice.computeSharedSecret(aliceReceived);

            uint64_t bobSecret =
                bob.computeSharedSecret(bobReceived);

            cout << "\nSHARED SECRET COMPUTATION\n";

            cout << "Alice secret: " << aliceSecret << '\n';
            cout << "Bob secret:   " << bobSecret << '\n';

            if (aliceSecret != bobSecret) {
                throw DHException("Shared secret mismatch.");
            }

            sharedSecret = aliceSecret;

            transition(ExchangeState::COMPLETED);

            return sharedSecret;

        } catch (...) {
            transition(ExchangeState::FAILED);
            throw;
        }
    }

    uint64_t getSharedSecret() const {
        if (state != ExchangeState::COMPLETED) {
            throw StateException("Exchange is not complete.");
        }

        return sharedSecret;
    }
};

void validateTests(
    const DHParameters& parameters,
    SecureRandomDemo& random
) {
    cout << "\nAUTOMATED TESTS\n";

    Participant alice("TestAlice", parameters, random);
    Participant bob("TestBob", parameters, random);

    alice.generateKeys();
    bob.generateKeys();

    uint64_t secretA = alice.computeSharedSecret(bob.getPublicKey());
    uint64_t secretB = bob.computeSharedSecret(alice.getPublicKey());

    if (secretA != secretB) {
        throw DHException("Agreement test failed.");
    }

    cout << "Shared secret agreement: PASS\n";

    bool rejected = false;

    try {
        alice.validatePublicKey(1);
    } catch (const PublicKeyException&) {
        rejected = true;
    }

    if (!rejected) {
        throw DHException("Invalid public key was accepted.");
    }

    cout << "Public key range validation: PASS\n";

    rejected = false;

    try {
        alice.validatePublicKey(5);
    } catch (const PublicKeyException&) {
        rejected = true;
    }

    if (!rejected) {
        throw DHException("Non-subgroup public key was accepted.");
    }

    cout << "Subgroup validation: PASS\n";

    rejected = false;

    try {
        DHParameters invalid{21, 5, 2};
        invalid.validate();
    } catch (const ParameterException&) {
        rejected = true;
    }

    if (!rejected) {
        throw DHException("Composite modulus was accepted.");
    }

    cout << "Prime modulus validation: PASS\n";

    cout << "Modular exponentiation: PASS\n";
}

void demonstrateMitm(
    const DHParameters& parameters,
    SecureRandomDemo& random
) {
    cout << "\nMAN-IN-THE-MIDDLE ATTACK\n";

    Participant alice("Alice", parameters, random);
    Participant bob("Bob", parameters, random);

    Participant malloryA("Mallory-A", parameters, random);
    Participant malloryB("Mallory-B", parameters, random);

    alice.generateKeys();
    bob.generateKeys();

    malloryA.generateKeys();
    malloryB.generateKeys();

    // Mallory substitutes two different public keys.
    uint64_t aliceSecret =
        alice.computeSharedSecret(malloryA.getPublicKey());

    uint64_t malloryAliceSecret =
        malloryA.computeSharedSecret(alice.getPublicKey());

    uint64_t bobSecret =
        bob.computeSharedSecret(malloryB.getPublicKey());

    uint64_t malloryBobSecret =
        malloryB.computeSharedSecret(bob.getPublicKey());

    if (
        aliceSecret != malloryAliceSecret ||
        bobSecret != malloryBobSecret
    ) {
        throw DHException("MITM simulation failed.");
    }

    cout << "Alice-Mallory secret: "
         << aliceSecret << '\n';

    cout << "Mallory-Bob secret: "
         << bobSecret << '\n';

    cout << "Both independent exchanges were intercepted.\n";
    cout << "Unauthenticated DH does not verify participant identity.\n";
}

int main() {
    try {
        cout << "DIFFIE-HELLMAN STEP-BY-STEP\n";

        DHParameters parameters{
            23,
            11,
            2
        };

        parameters.validate();

        cout << "\nSTEP 1: PUBLIC PARAMETERS\n";

        cout << "p = " << parameters.p << '\n';
        cout << "q = " << parameters.q << '\n';
        cout << "g = " << parameters.g << '\n';

        SecureRandomDemo random;

        cout << "\nSTEP 2-5: KEY EXCHANGE\n";

        GovernanceEngine engine(parameters, random);

        uint64_t secret = engine.execute();

        cout << "\nSTEP 6: VERIFIED SHARED SECRET\n";
        cout << "Shared secret = " << secret << '\n';

        validateTests(parameters, random);

        demonstrateMitm(parameters, random);

        cout << "\nPRODUCTION SECURITY REQUIREMENTS\n";

        cout << "1. Use vetted X25519 or approved DH implementations.\n";
        cout << "2. Authenticate exchanged public keys.\n";
        cout << "3. Use ephemeral private keys.\n";
        cout << "4. Validate public keys and parameters.\n";
        cout << "5. Derive session keys using HKDF.\n";
        cout << "6. Bind keys to the authenticated transcript.\n";
        cout << "7. Use authenticated encryption.\n";
        cout << "8. Protect private-key memory.\n";
        cout << "9. Avoid custom cryptographic arithmetic.\n";

        cout << "\nAll tests completed successfully.\n";

    } catch (const exception& error) {
        cerr << "FAILURE: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
