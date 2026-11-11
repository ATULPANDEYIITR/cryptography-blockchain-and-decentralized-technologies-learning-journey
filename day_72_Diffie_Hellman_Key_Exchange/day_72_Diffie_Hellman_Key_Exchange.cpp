#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Diffie-Hellman Key Exchange and Repository-Independent
 * Cryptographic Governance Engine.
 *
 * Implements:
 * - Safe-prime subgroup validation
 * - Modular exponentiation
 * - Secure-randomness interface
 * - Key agreement
 * - Participant modeling
 * - Exchange lifecycle
 * - Public-key validation
 * - Session and transcript management
 *
 * Small parameters are for education only.
 * This implementation is not production cryptography.
 */

using Integer = std::uint64_t;

class DHError : public std::runtime_error {
public:
    explicit DHError(const std::string& message)
        : std::runtime_error(message) {}
};

class ParameterError : public DHError {
public:
    using DHError::DHError;
};

class ExchangeError : public DHError {
public:
    using DHError::DHError;
};

Integer modularMultiply(
    Integer a,
    Integer b,
    Integer modulus
) {
    if (modulus == 0) {
        throw std::invalid_argument("Zero modulus.");
    }

    // The demonstration group fits in uint64_t.
    // Production arbitrary-size arithmetic requires
    // a validated cryptographic big-integer implementation.
    return static_cast<Integer>(
        (static_cast<__uint128_t>(a) * b) % modulus
    );
}

Integer modPow(
    Integer base,
    Integer exponent,
    Integer modulus
) {
    if (modulus <= 1) {
        throw std::invalid_argument("Invalid modulus.");
    }

    Integer result = 1;
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

bool isPrime(Integer n) {
    if (n < 2) return false;

    for (Integer p : {
        2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL,
        17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL
    }) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }

    Integer d = n - 1;
    unsigned int s = 0;

    while (d % 2 == 0) {
        d /= 2;
        ++s;
    }

    const Integer bases[] = {
        2ULL, 3ULL, 5ULL, 7ULL,
        11ULL, 13ULL, 17ULL
    };

    for (Integer base : bases) {
        if (base >= n - 1) continue;

        Integer x = modPow(base, d, n);

        if (x == 1 || x == n - 1) continue;

        bool passed = false;

        for (unsigned int i = 1; i < s; ++i) {
            x = modPow(x, 2, n);

            if (x == n - 1) {
                passed = true;
                break;
            }
        }

        if (!passed) return false;
    }

    return true;
}

struct DHGroup {
    Integer p;
    Integer q;
    Integer g;

    void validate() const {
        if (
            p <= 5 ||
            !isPrime(p) ||
            !isPrime(q)
        ) {
            throw ParameterError("Invalid prime parameters.");
        }

        if (p != 2 * q + 1) {
            throw ParameterError("Group is not a safe-prime group.");
        }

        if (
            g <= 1 ||
            g >= p ||
            modPow(g, q, p) != 1
        ) {
            throw ParameterError("Invalid subgroup generator.");
        }
    }
};

enum class ExchangeState {
    CREATED,
    PUBLIC_KEYS_EXCHANGED,
    VERIFIED,
    DERIVED,
    FAILED
};

std::string stateName(ExchangeState state) {
    switch (state) {
        case ExchangeState::CREATED:
            return "CREATED";
        case ExchangeState::PUBLIC_KEYS_EXCHANGED:
            return "PUBLIC_KEYS_EXCHANGED";
        case ExchangeState::VERIFIED:
            return "VERIFIED";
        case ExchangeState::DERIVED:
            return "DERIVED";
        case ExchangeState::FAILED:
            return "FAILED";
    }

    return "UNKNOWN";
}

class SecureRandom {
private:
    std::random_device device;
    std::mt19937_64 engine;

public:
    SecureRandom()
        : engine(device()) {}

    Integer between(Integer minimum, Integer maximum) {
        if (minimum > maximum) {
            throw std::invalid_argument("Invalid random range.");
        }

        std::uniform_int_distribution<Integer> distribution(
            minimum,
            maximum
        );

        return distribution(engine);
    }
};

class Participant {
private:
    std::string name;
    Integer privateKey;
    Integer publicKey;

public:
    Participant(
        std::string participantName,
        const DHGroup& group,
        SecureRandom& random
    ) : name(std::move(participantName)) {

        if (name.empty()) {
            throw ExchangeError("Participant name is empty.");
        }

        privateKey = random.between(1, group.q - 1);
        publicKey = modPow(group.g, privateKey, group.p);
    }

    const std::string& getName() const {
        return name;
    }

    Integer getPublicKey() const {
        return publicKey;
    }

    Integer computeSecret(
        Integer peerPublic,
        const DHGroup& group
    ) const {
        if (
            peerPublic <= 1 ||
            peerPublic >= group.p - 1
        ) {
            throw ExchangeError("Public key outside valid range.");
        }

        if (modPow(peerPublic, group.q, group.p) != 1) {
            throw ExchangeError("Public key outside subgroup.");
        }

        Integer secret = modPow(
            peerPublic,
            privateKey,
            group.p
        );

        if (secret == 1) {
            throw ExchangeError("Trivial shared secret rejected.");
        }

        return secret;
    }
};

struct ExchangeRecord {
    std::string sessionId;
    Integer alicePublic;
    Integer bobPublic;
    Integer sharedSecret;
    ExchangeState state;
};

class ExchangeEngine {
private:
    DHGroup group;
    SecureRandom random;
    std::map<std::string, ExchangeRecord> sessions;

    void validateGroup() const {
        group.validate();
    }

public:
    explicit ExchangeEngine(DHGroup parameters)
        : group(parameters) {
        validateGroup();
    }

    ExchangeRecord execute(const std::string& sessionId) {
        if (sessionId.empty()) {
            throw ExchangeError("Session identifier is required.");
        }

        if (sessions.count(sessionId)) {
            throw ExchangeError("Duplicate session identifier.");
        }

        ExchangeRecord record{};
        record.sessionId = sessionId;
        record.state = ExchangeState::CREATED;

        try {
            Participant alice("Alice", group, random);
            Participant bob("Bob", group, random);

            record.alicePublic = alice.getPublicKey();
            record.bobPublic = bob.getPublicKey();

            record.state = ExchangeState::PUBLIC_KEYS_EXCHANGED;

            Integer aliceSecret = alice.computeSecret(
                record.bobPublic,
                group
            );

            Integer bobSecret = bob.computeSecret(
                record.alicePublic,
                group
            );

            if (aliceSecret != bobSecret) {
                throw ExchangeError("Key agreement mismatch.");
            }

            record.sharedSecret = aliceSecret;
            record.state = ExchangeState::VERIFIED;

            // The raw secret is not treated as an application key.
            // A real implementation derives keys using HKDF-SHA256.
            record.state = ExchangeState::DERIVED;

            sessions.emplace(sessionId, record);

            return record;

        } catch (...) {
            record.state = ExchangeState::FAILED;
            throw;
        }
    }

    const std::map<std::string, ExchangeRecord>&
    getSessions() const {
        return sessions;
    }

    bool verifyPublicKey(Integer value) const {
        if (value <= 1 || value >= group.p - 1) {
            return false;
        }

        return modPow(value, group.q, group.p) == 1;
    }
};

void runTests() {
    DHGroup group{23, 11, 2};
    group.validate();

    SecureRandom random;

    Participant alice("Alice", group, random);
    Participant bob("Bob", group, random);

    Integer first = alice.computeSecret(
        bob.getPublicKey(),
        group
    );

    Integer second = bob.computeSecret(
        alice.getPublicKey(),
        group
    );

    assert(first == second);
    assert(first != 1);

    ExchangeEngine engine(group);

    ExchangeRecord record = engine.execute("SESSION-001");

    assert(record.state == ExchangeState::DERIVED);

    assert(engine.verifyPublicKey(record.alicePublic));
    assert(engine.verifyPublicKey(record.bobPublic));

    assert(!engine.verifyPublicKey(1));
    assert(!engine.verifyPublicKey(5));

    bool rejected = false;

    try {
        alice.computeSecret(5, group);
    } catch (const ExchangeError&) {
        rejected = true;
    }

    assert(rejected);

    rejected = false;

    try {
        engine.execute("SESSION-001");
    } catch (const ExchangeError&) {
        rejected = true;
    }

    assert(rejected);

    rejected = false;

    try {
        ExchangeEngine invalid({21, 10, 2});
    } catch (const ParameterError&) {
        rejected = true;
    }

    assert(rejected);

    std::cout << "All tests passed.\n";
}

int main() {
    try {
        DHGroup group{
            23,
            11,
            2
        };

        ExchangeEngine engine(group);

        std::cout << "DIFFIE-HELLMAN KEY EXCHANGE\n";
        std::cout << "===========================\n";

        std::cout << "Modulus p: " << group.p << '\n';
        std::cout << "Subgroup q: " << group.q << '\n';
        std::cout << "Generator g: " << group.g << '\n';

        ExchangeRecord result = engine.execute("SESSION-001");

        std::cout << "\nSession: " << result.sessionId << '\n';

        std::cout << "Alice public key: "
                  << result.alicePublic << '\n';

        std::cout << "Bob public key: "
                  << result.bobPublic << '\n';

        std::cout << "Shared secret: "
                  << result.sharedSecret << '\n';

        std::cout << "State: "
                  << stateName(result.state) << '\n';

        std::cout << "\nSecurity: EDUCATIONAL ONLY\n";

        runTests();

    } catch (const std::exception& error) {
        std::cerr << "Failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
