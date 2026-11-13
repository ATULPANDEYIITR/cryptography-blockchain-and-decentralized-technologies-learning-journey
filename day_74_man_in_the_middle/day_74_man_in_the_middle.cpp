#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Man-in-the-Middle Attack on Key Exchange
 *
 * C++17 repository-style security evaluation engine.
 *
 * Models:
 * - Diffie-Hellman public-key exchange.
 * - Public-key substitution.
 * - Identity verification.
 * - Trusted identity fingerprints.
 * - Transcript authentication.
 * - Status-based session acceptance.
 * - Security policy evaluation.
 *
 * The small modular arithmetic parameters are educational only.
 * This is NOT production cryptography.
 */

namespace security {

constexpr std::uint64_t PRIME = 23;
constexpr std::uint64_t GENERATOR = 5;

enum class SessionState {
    CREATED,
    NEGOTIATING,
    AUTHENTICATED,
    ESTABLISHED,
    REJECTED,
    COMPROMISED
};

enum class CheckResult {
    PASS,
    FAIL,
    NOT_RUN
};

struct Identity {
    std::string name;
    std::uint64_t privateKey;
    std::uint64_t publicKey;
};

struct KeyExchangeMessage {
    std::string sender;
    std::string recipient;
    std::string sessionId;
    std::uint64_t publicKey;
    std::string fingerprint;
};

struct SecurityPolicy {
    bool requireTrustedIdentity = true;
    bool requireTranscriptBinding = true;
    bool rejectDuplicateSessions = true;
    bool requireMatchingSharedSecrets = true;
};

struct Evaluation {
    CheckResult identity;
    CheckResult transcript;
    CheckResult keyAgreement;
    CheckResult sessionUniqueness;

    bool eligible;
    std::vector<std::string> violations;
};

class ValidationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CryptoDemo {
public:
    static std::uint64_t modPow(
        std::uint64_t base,
        std::uint64_t exponent,
        std::uint64_t modulus
    ) {
        if (modulus == 0) {
            throw ValidationError("Invalid modulus.");
        }

        std::uint64_t result = 1;
        base %= modulus;

        while (exponent > 0) {
            if (exponent & 1) {
                result = (result * base) % modulus;
            }

            base = (base * base) % modulus;
            exponent >>= 1;
        }

        return result;
    }

    static void validatePublicKey(std::uint64_t key) {
        if (key <= 1 || key >= PRIME) {
            throw ValidationError("Public key outside valid range.");
        }
    }

    static std::string fingerprint(
        const std::string& identity,
        std::uint64_t publicKey
    ) {
        // Educational identity identifier, not a secure hash.
        return identity + ":" + std::to_string(publicKey);
    }

    static std::uint64_t sharedSecret(
        std::uint64_t privateKey,
        std::uint64_t peerPublic
    ) {
        validatePublicKey(peerPublic);
        return modPow(peerPublic, privateKey, PRIME);
    }
};

class TrustStore {
private:
    std::map<std::string, std::string> trustedIdentities;

public:
    void registerIdentity(const Identity& identity) {
        if (identity.name.empty()) {
            throw ValidationError("Identity name cannot be empty.");
        }

        auto fingerprint = CryptoDemo::fingerprint(
            identity.name,
            identity.publicKey
        );

        if (!trustedIdentities.emplace(
            identity.name, fingerprint
        ).second) {
            throw ValidationError("Duplicate identity.");
        }
    }

    bool verify(const KeyExchangeMessage& message) const {
        auto iterator = trustedIdentities.find(message.sender);

        if (iterator == trustedIdentities.end()) {
            return false;
        }

        return iterator->second == message.fingerprint;
    }
};

class SessionRegistry {
private:
    std::set<std::string> sessions;

public:
    bool registerSession(const std::string& id) {
        if (id.empty()) {
            return false;
        }

        return sessions.insert(id).second;
    }

    bool contains(const std::string& id) const {
        return sessions.count(id) != 0;
    }
};

class GovernanceEngine {
private:
    SecurityPolicy policy;
    const TrustStore& trustStore;
    SessionRegistry registry;

public:
    GovernanceEngine(
        SecurityPolicy configuration,
        const TrustStore& trust
    ) : policy(configuration), trustStore(trust) {}

    Evaluation evaluate(
        const KeyExchangeMessage& message,
        std::uint64_t localPrivateKey,
        std::uint64_t expectedSecret,
        const std::string& expectedTranscript
    ) {
        Evaluation result{
            CheckResult::NOT_RUN,
            CheckResult::NOT_RUN,
            CheckResult::NOT_RUN,
            CheckResult::NOT_RUN,
            false,
            {}
        };

        if (policy.requireTrustedIdentity) {
            result.identity = trustStore.verify(message)
                ? CheckResult::PASS
                : CheckResult::FAIL;
        } else {
            result.identity = CheckResult::PASS;
        }

        if (result.identity == CheckResult::FAIL) {
            result.violations.push_back(
                "Peer identity is not trusted."
            );
        }

        const std::string receivedTranscript =
            message.sender + "|" +
            message.recipient + "|" +
            message.sessionId + "|" +
            std::to_string(message.publicKey);

        if (policy.requireTranscriptBinding) {
            result.transcript =
                receivedTranscript == expectedTranscript
                ? CheckResult::PASS
                : CheckResult::FAIL;
        } else {
            result.transcript = CheckResult::PASS;
        }

        if (result.transcript == CheckResult::FAIL) {
            result.violations.push_back(
                "Exchange transcript mismatch."
            );
        }

        try {
            const auto derived = CryptoDemo::sharedSecret(
                localPrivateKey,
                message.publicKey
            );

            if (policy.requireMatchingSharedSecrets) {
                result.keyAgreement =
                    derived == expectedSecret
                    ? CheckResult::PASS
                    : CheckResult::FAIL;
            } else {
                result.keyAgreement = CheckResult::PASS;
            }
        } catch (const ValidationError& error) {
            result.keyAgreement = CheckResult::FAIL;
            result.violations.push_back(error.what());
        }

        if (result.keyAgreement == CheckResult::FAIL) {
            result.violations.push_back(
                "Key agreement verification failed."
            );
        }

        if (policy.rejectDuplicateSessions) {
            result.sessionUniqueness =
                registry.registerSession(message.sessionId)
                ? CheckResult::PASS
                : CheckResult::FAIL;
        } else {
            result.sessionUniqueness = CheckResult::PASS;
        }

        if (result.sessionUniqueness == CheckResult::FAIL) {
            result.violations.push_back(
                "Duplicate session identifier."
            );
        }

        result.eligible =
            result.identity == CheckResult::PASS &&
            result.transcript == CheckResult::PASS &&
            result.keyAgreement == CheckResult::PASS &&
            result.sessionUniqueness == CheckResult::PASS;

        return result;
    }
};

class ExchangeSimulator {
private:
    Identity alice;
    Identity bob;
    Identity mallory;

public:
    ExchangeSimulator()
        : alice{"Alice", 6, 0},
          bob{"Bob", 15, 0},
          mallory{"Mallory", 8, 0} {

        alice.publicKey = CryptoDemo::modPow(
            GENERATOR, alice.privateKey, PRIME
        );

        bob.publicKey = CryptoDemo::modPow(
            GENERATOR, bob.privateKey, PRIME
        );

        mallory.publicKey = CryptoDemo::modPow(
            GENERATOR, mallory.privateKey, PRIME
        );
    }

    void demonstrateLegitimateExchange() {
        std::cout << "\n1. Legitimate exchange\n";

        TrustStore trust;
        trust.registerIdentity(alice);
        trust.registerIdentity(bob);

        const std::uint64_t aliceSecret =
            CryptoDemo::sharedSecret(
                alice.privateKey, bob.publicKey
            );

        const std::uint64_t bobSecret =
            CryptoDemo::sharedSecret(
                bob.privateKey, alice.publicKey
            );

        const std::string session = "SESSION-100";

        KeyExchangeMessage message{
            "Bob",
            "Alice",
            session,
            bob.publicKey,
            CryptoDemo::fingerprint(
                bob.name, bob.publicKey
            )
        };

        const std::string transcript =
            "Bob|Alice|SESSION-100|" +
            std::to_string(bob.publicKey);

        SecurityPolicy policy;
        GovernanceEngine engine(policy, trust);

        Evaluation evaluation = engine.evaluate(
            message,
            alice.privateKey,
            aliceSecret,
            transcript
        );

        printEvaluation(evaluation);

        std::cout << "Alice secret: " << aliceSecret << '\n';
        std::cout << "Bob secret:   " << bobSecret << '\n';
        std::cout << "Agreement: "
                  << (aliceSecret == bobSecret ? "PASS" : "FAIL")
                  << '\n';
    }

    void demonstrateMITM() {
        std::cout << "\n2. Public-key substitution attack\n";

        TrustStore trust;
        trust.registerIdentity(alice);
        trust.registerIdentity(bob);

        const auto aliceAttackerSecret =
            CryptoDemo::sharedSecret(
                alice.privateKey, mallory.publicKey
            );

        const auto bobAttackerSecret =
            CryptoDemo::sharedSecret(
                bob.privateKey, mallory.publicKey
            );

        const auto malloryAliceSecret =
            CryptoDemo::sharedSecret(
                mallory.privateKey, alice.publicKey
            );

        const auto malloryBobSecret =
            CryptoDemo::sharedSecret(
                mallory.privateKey, bob.publicKey
            );

        std::cout << "Alice-Mallory secret: "
                  << aliceAttackerSecret << '\n';

        std::cout << "Mallory-Alice secret: "
                  << malloryAliceSecret << '\n';

        std::cout << "Bob-Mallory secret: "
                  << bobAttackerSecret << '\n';

        std::cout << "Mallory-Bob secret: "
                  << malloryBobSecret << '\n';

        KeyExchangeMessage altered{
            "Bob",
            "Alice",
            "SESSION-200",
            mallory.publicKey,
            CryptoDemo::fingerprint(
                mallory.name, mallory.publicKey
            )
        };

        const std::string transcript =
            "Bob|Alice|SESSION-200|" +
            std::to_string(mallory.publicKey);

        SecurityPolicy policy;
        GovernanceEngine engine(policy, trust);

        Evaluation evaluation = engine.evaluate(
            altered,
            alice.privateKey,
            aliceAttackerSecret,
            transcript
        );

        printEvaluation(evaluation);

        std::cout << "Alice and Mallory share a secret: "
                  << (aliceAttackerSecret == malloryAliceSecret)
                  << '\n';

        std::cout << "Bob and Mallory share a secret: "
                  << (bobAttackerSecret == malloryBobSecret)
                  << '\n';
    }

    void demonstrateDuplicateSession() {
        std::cout << "\n3. Duplicate session rejection\n";

        TrustStore trust;
        trust.registerIdentity(alice);
        trust.registerIdentity(bob);

        SecurityPolicy policy;
        GovernanceEngine engine(policy, trust);

        KeyExchangeMessage message{
            "Bob",
            "Alice",
            "SESSION-300",
            bob.publicKey,
            CryptoDemo::fingerprint(
                bob.name, bob.publicKey
            )
        };

        const std::string transcript =
            "Bob|Alice|SESSION-300|" +
            std::to_string(bob.publicKey);

        const auto expected =
            CryptoDemo::sharedSecret(
                alice.privateKey, bob.publicKey
            );

        auto first = engine.evaluate(
            message, alice.privateKey, expected, transcript
        );

        auto second = engine.evaluate(
            message, alice.privateKey, expected, transcript
        );

        std::cout << "First exchange: "
                  << (first.eligible ? "ACCEPTED" : "REJECTED")
                  << '\n';

        std::cout << "Second exchange: "
                  << (second.eligible ? "ACCEPTED" : "REJECTED")
                  << '\n';
    }

    static void printEvaluation(const Evaluation& result) {
        std::cout << "Identity: "
                  << status(result.identity) << '\n';

        std::cout << "Transcript: "
                  << status(result.transcript) << '\n';

        std::cout << "Key agreement: "
                  << status(result.keyAgreement) << '\n';

        std::cout << "Session uniqueness: "
                  << status(result.sessionUniqueness) << '\n';

        std::cout << "Decision: "
                  << (result.eligible ? "ACCEPTED" : "REJECTED")
                  << '\n';

        for (const auto& violation : result.violations) {
            std::cout << "Violation: " << violation << '\n';
        }
    }

    static std::string status(CheckResult result) {
        switch (result) {
            case CheckResult::PASS:
                return "PASS";
            case CheckResult::FAIL:
                return "FAIL";
            default:
                return "NOT RUN";
        }
    }
};

} // namespace security

int main() {
    try {
        std::cout << "=================================================\n";
        std::cout << "MAN-IN-THE-MIDDLE KEY EXCHANGE GOVERNANCE ENGINE\n";
        std::cout << "=================================================\n";

        security::ExchangeSimulator simulator;

        simulator.demonstrateLegitimateExchange();
        simulator.demonstrateMITM();
        simulator.demonstrateDuplicateSession();

        std::cout << "\nExecution completed.\n";

    } catch (const std::exception& error) {
        std::cerr << "Security engine error: "
                  << error.what() << '\n';

        return 1;
    }

    return 0;
}
