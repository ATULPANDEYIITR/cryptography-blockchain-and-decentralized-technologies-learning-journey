#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

/*
 * DIGITAL SIGNATURES FOR AUTHENTICATION
 * C++17
 *
 * This implementation provides a repository-style authentication
 * governance engine using an explicitly educational RSA-like
 * arithmetic verifier.
 *
 * IMPORTANT:
 * The small integer RSA construction is NOT cryptographically secure.
 * It demonstrates asymmetric verification mechanics and policy
 * enforcement, not production authentication.
 *
 * Production implementations must use a vetted cryptographic
 * library and modern signature algorithms such as Ed25519.
 */

using namespace std;

enum class KeyState {
    ACTIVE,
    REVOKED
};

enum class ChallengeState {
    ISSUED,
    CONSUMED,
    EXPIRED
};

enum class CheckState {
    PASSED,
    FAILED,
    PENDING
};

struct RSAKey {
    uint64_t modulus;
    uint64_t publicExponent;
};

struct Identity {
    string userId;
    string keyId;
    RSAKey publicKey;
    KeyState state;
};

struct Challenge {
    string id;
    string userId;
    string nonce;
    string audience;
    uint64_t expiresAt;
    ChallengeState state;
};

struct StatusCheck {
    string name;
    CheckState state;
};

struct AuditRecord {
    string userId;
    string action;
    bool success;
    string reason;
};

class AuthenticationException : public runtime_error {
public:
    explicit AuthenticationException(const string& message)
        : runtime_error(message) {}
};

class EducationalRSA {
public:
    /*
     * Modular exponentiation using repeated squaring.
     *
     * Complexity: O(log exponent).
     * This implementation uses a 64-bit modulus and is intended
     * only for small educational values.
     */
    static uint64_t modPow(
        uint64_t base,
        uint64_t exponent,
        uint64_t modulus
    ) {
        if (modulus == 0) {
            throw invalid_argument("Zero modulus");
        }

        uint64_t result = 1;
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

    static bool verify(
        uint64_t messageRepresentative,
        uint64_t signature,
        const RSAKey& key
    ) {
        if (key.modulus <= 1 || signature >= key.modulus) {
            return false;
        }

        return modPow(
            signature,
            key.publicExponent,
            key.modulus
        ) == messageRepresentative;
    }
};

class AuthenticationGovernance {
private:
    map<string, Identity> identities;
    map<string, Challenge> challenges;
    map<string, vector<StatusCheck>> checks;
    set<string> consumedChallenges;
    vector<AuditRecord> audit;

    uint64_t currentTime = 1000;

    void record(
        const string& user,
        const string& action,
        bool success,
        const string& reason
    ) {
        audit.push_back({
            user,
            action,
            success,
            reason
        });
    }

public:
    void registerIdentity(
        const string& userId,
        const string& keyId,
        const RSAKey& publicKey
    ) {
        if (
            userId.empty() ||
            keyId.empty() ||
            publicKey.modulus <= 1
        ) {
            throw AuthenticationException(
                "Invalid identity registration"
            );
        }

        if (identities.count(keyId)) {
            throw AuthenticationException(
                "Key identifier already registered"
            );
        }

        identities.emplace(
            keyId,
            Identity{
                userId,
                keyId,
                publicKey,
                KeyState::ACTIVE
            }
        );

        record(userId, "KEY_REGISTERED", true, keyId);
    }

    void revokeKey(const string& keyId) {
        auto it = identities.find(keyId);

        if (it == identities.end()) {
            throw AuthenticationException("Unknown key");
        }

        it->second.state = KeyState::REVOKED;

        record(
            it->second.userId,
            "KEY_REVOKED",
            true,
            keyId
        );
    }

    void issueChallenge(
        const string& challengeId,
        const string& userId,
        const string& keyId,
        const string& nonce,
        const string& audience,
        uint64_t lifetime
    ) {
        auto it = identities.find(keyId);

        if (it == identities.end()) {
            throw AuthenticationException("Unknown identity");
        }

        if (it->second.userId != userId) {
            throw AuthenticationException(
                "Identity ownership mismatch"
            );
        }

        if (it->second.state != KeyState::ACTIVE) {
            throw AuthenticationException("Key revoked");
        }

        if (
            challengeId.empty() ||
            nonce.empty() ||
            audience.empty() ||
            lifetime == 0
        ) {
            throw AuthenticationException(
                "Invalid challenge parameters"
            );
        }

        if (challenges.count(challengeId)) {
            throw AuthenticationException(
                "Duplicate challenge identifier"
            );
        }

        challenges.emplace(
            challengeId,
            Challenge{
                challengeId,
                userId,
                nonce,
                audience,
                currentTime + lifetime,
                ChallengeState::ISSUED
            }
        );

        record(userId, "CHALLENGE_ISSUED", true, challengeId);
    }

    bool authenticate(
        const string& userId,
        const string& keyId,
        const string& challengeId,
        uint64_t messageRepresentative,
        uint64_t signature
    ) {
        try {
            auto keyIt = identities.find(keyId);
            auto challengeIt = challenges.find(challengeId);

            if (
                keyIt == identities.end() ||
                challengeIt == challenges.end()
            ) {
                throw AuthenticationException(
                    "Unknown key or challenge"
                );
            }

            Identity& identity = keyIt->second;
            Challenge& challenge = challengeIt->second;

            if (
                identity.userId != userId ||
                challenge.userId != userId
            ) {
                throw AuthenticationException(
                    "Identity mismatch"
                );
            }

            if (identity.state != KeyState::ACTIVE) {
                throw AuthenticationException("Key revoked");
            }

            if (challenge.state != ChallengeState::ISSUED) {
                throw AuthenticationException(
                    "Challenge already consumed"
                );
            }

            if (currentTime >= challenge.expiresAt) {
                challenge.state = ChallengeState::EXPIRED;

                throw AuthenticationException(
                    "Challenge expired"
                );
            }

            if (consumedChallenges.count(challengeId)) {
                throw AuthenticationException(
                    "Replay detected"
                );
            }

            if (!EducationalRSA::verify(
                messageRepresentative,
                signature,
                identity.publicKey
            )) {
                throw AuthenticationException(
                    "Signature verification failed"
                );
            }

            challenge.state = ChallengeState::CONSUMED;
            consumedChallenges.insert(challengeId);

            record(
                userId,
                "AUTHENTICATION",
                true,
                "Signature verified"
            );

            return true;

        } catch (const exception& error) {
            record(
                userId,
                "AUTHENTICATION",
                false,
                error.what()
            );

            throw;
        }
    }

    void configureStatusChecks(
        const string& challengeId,
        const vector<StatusCheck>& statusChecks
    ) {
        if (!challenges.count(challengeId)) {
            throw AuthenticationException(
                "Unknown challenge"
            );
        }

        set<string> uniqueNames;

        for (const auto& check : statusChecks) {
            if (
                check.name.empty() ||
                !uniqueNames.insert(check.name).second
            ) {
                throw AuthenticationException(
                    "Invalid or duplicate status check"
                );
            }
        }

        checks[challengeId] = statusChecks;
    }

    bool statusChecksPassed(const string& challengeId) const {
        auto it = checks.find(challengeId);

        if (it == checks.end() || it->second.empty()) {
            return false;
        }

        return all_of(
            it->second.begin(),
            it->second.end(),
            [](const StatusCheck& check) {
                return check.state == CheckState::PASSED;
            }
        );
    }

    void advanceTime(uint64_t seconds) {
        if (seconds > UINT64_MAX - currentTime) {
            throw overflow_error("Clock overflow");
        }

        currentTime += seconds;
    }

    void printAudit() const {
        cout << "\nAuthentication audit\n";

        for (const auto& event : audit) {
            cout
                << event.userId << " | "
                << event.action << " | "
                << (event.success ? "SUCCESS" : "FAILURE")
                << " | "
                << event.reason << '\n';
        }
    }
};

int main() {
    try {
        AuthenticationGovernance system;

        /*
         * Educational RSA example:
         *
         * p = 61, q = 53
         * n = 3233
         * phi(n) = 3120
         * e = 17
         * d = 2753
         *
         * Message representative = 65
         * Signature = 65^2753 mod 3233 = 588
         *
         * Verification: 588^17 mod 3233 = 65
         */

        const RSAKey publicKey{3233, 17};

        const uint64_t message = 65;
        const uint64_t signature = 588;

        cout << "1. Public key registration\n";

        system.registerIdentity(
            "alice",
            "alice-key-001",
            publicKey
        );

        cout << "Identity registered\n";

        cout << "\n2. Challenge issuance\n";

        system.issueChallenge(
            "challenge-001",
            "alice",
            "alice-key-001",
            "random-nonce-001",
            "identity-api",
            120
        );

        cout << "Challenge issued\n";

        cout << "\n3. Digital signature verification\n";

        bool authenticated = system.authenticate(
            "alice",
            "alice-key-001",
            "challenge-001",
            message,
            signature
        );

        cout << "Authenticated: "
             << boolalpha << authenticated << '\n';

        cout << "\n4. Replay attack\n";

        try {
            system.authenticate(
                "alice",
                "alice-key-001",
                "challenge-001",
                message,
                signature
            );
        } catch (const exception& error) {
            cout << "Rejected: " << error.what() << '\n';
        }

        cout << "\n5. Invalid signature\n";

        system.issueChallenge(
            "challenge-002",
            "alice",
            "alice-key-001",
            "random-nonce-002",
            "identity-api",
            120
        );

        try {
            system.authenticate(
                "alice",
                "alice-key-001",
                "challenge-002",
                message,
                signature + 1
            );
        } catch (const exception& error) {
            cout << "Rejected: " << error.what() << '\n';
        }

        cout << "\n6. Status-check governance\n";

        system.configureStatusChecks(
            "challenge-002",
            {
                {"identity-policy", CheckState::PASSED},
                {"device-policy", CheckState::PASSED},
                {"risk-policy", CheckState::PENDING}
            }
        );

        cout << "All checks passed: "
             << system.statusChecksPassed("challenge-002")
             << '\n';

        cout << "\n7. Challenge expiration\n";

        system.advanceTime(200);

        try {
            system.authenticate(
                "alice",
                "alice-key-001",
                "challenge-002",
                message,
                signature
            );
        } catch (const exception& error) {
            cout << "Rejected: " << error.what() << '\n';
        }

        cout << "\n8. Key revocation\n";

        system.revokeKey("alice-key-001");

        try {
            system.issueChallenge(
                "challenge-003",
                "alice",
                "alice-key-001",
                "random-nonce-003",
                "identity-api",
                120
            );
        } catch (const exception& error) {
            cout << "Rejected: " << error.what() << '\n';
        }

        system.printAudit();

    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
