#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Second-preimage resistance governance engine.
 *
 * The cryptographic primitive below is a deterministic educational hash
 * model. It is intentionally not a production cryptographic implementation.
 * Its reduced state permits controlled experiments while the surrounding
 * engine models the important security distinction:
 *
 *   fixed message M -> search for distinct M' with H(M') = H(M)
 *
 * The program also models artifact verification, evidence recording, and
 * policy decisions around hash strength.
 */

enum class VerificationState {
    NotChecked,
    Passed,
    Failed,
    Invalid
};

enum class SecurityDecision {
    Accept,
    Reject,
    ReviewRequired
};

struct Artifact {
    std::string id;
    std::string content;
    std::string algorithm;
};

struct VerificationRecord {
    VerificationState state;
    std::string targetDigest;
    std::string candidateDigest;
    bool distinctMessages;
    std::size_t attempts;
};

class EducationalHash {
public:
    explicit EducationalHash(unsigned bits = 16) : bits_(bits) {
        if (bits_ == 0 || bits_ > 64) {
            throw std::invalid_argument("bits must be in range 1..64");
        }
    }

    std::uint64_t digest(const std::string& input) const {
        // FNV-style mixing is used only as a compact deterministic model.
        std::uint64_t state = 1469598103934665603ULL;

        for (unsigned char c : input) {
            state ^= static_cast<std::uint64_t>(c);
            state *= 1099511628211ULL;
            state ^= state >> 29;
            state *= 0x9e3779b97f4a7c15ULL;
        }

        if (bits_ == 64) {
            return state;
        }

        return state & ((1ULL << bits_) - 1ULL);
    }

    std::string hexDigest(const std::string& input) const {
        std::ostringstream out;
        out << std::hex << std::setw((bits_ + 3) / 4)
            << std::setfill('0') << digest(input);
        return out.str();
    }

    unsigned bits() const {
        return bits_;
    }

private:
    unsigned bits_;
};

class SecondPreimageEngine {
public:
    explicit SecondPreimageEngine(const EducationalHash& hash)
        : hash_(hash) {}

    std::optional<VerificationRecord> search(
        const Artifact& target,
        std::size_t maximumAttempts) const {

        if (target.content.empty()) {
            throw std::invalid_argument("target content cannot be empty");
        }
        if (target.algorithm.empty()) {
            throw std::invalid_argument("hash algorithm is required");
        }
        if (maximumAttempts == 0) {
            throw std::invalid_argument("maximumAttempts must be positive");
        }

        const std::uint64_t targetDigest = hash_.digest(target.content);

        for (std::size_t attempt = 1; attempt <= maximumAttempts; ++attempt) {
            const std::string candidate =
                target.content + "\x1fSECOND-PREIMAGE\x1f" +
                std::to_string(attempt);

            if (candidate == target.content) {
                continue;
            }

            if (hash_.digest(candidate) == targetDigest) {
                return VerificationRecord{
                    VerificationState::Passed,
                    hash_.hexDigest(target.content),
                    hash_.hexDigest(candidate),
                    true,
                    attempt
                };
            }
        }

        return std::nullopt;
    }

private:
    const EducationalHash& hash_;
};

class RepositorySecurityPolicy {
public:
    RepositorySecurityPolicy(
        unsigned minimumBits,
        bool requireAuthenticatedOrigin)
        : minimumBits_(minimumBits),
          requireAuthenticatedOrigin_(requireAuthenticatedOrigin) {}

    SecurityDecision evaluate(
        unsigned digestBits,
        bool originAuthenticated,
        bool secondPreimageFound) const {

        if (digestBits < minimumBits_) {
            return SecurityDecision::Reject;
        }

        if (secondPreimageFound) {
            return SecurityDecision::Reject;
        }

        if (requireAuthenticatedOrigin_ && !originAuthenticated) {
            return SecurityDecision::ReviewRequired;
        }

        return SecurityDecision::Accept;
    }

private:
    unsigned minimumBits_;
    bool requireAuthenticatedOrigin_;
};

static std::string decisionName(SecurityDecision decision) {
    switch (decision) {
        case SecurityDecision::Accept:
            return "ACCEPT";
        case SecurityDecision::Reject:
            return "REJECT";
        case SecurityDecision::ReviewRequired:
            return "REVIEW_REQUIRED";
    }
    return "UNKNOWN";
}

int main() {
    try {
        EducationalHash experimentalHash(16);

        Artifact artifact{
            "release-4.2.1",
            "ledger-service|release=4.2.1|artifact=production",
            "EDU-16"
        };

        std::cout << "Second-Preimage Resistance Engine\n";
        std::cout << "================================\n";
        std::cout << "Artifact: " << artifact.id << '\n';
        std::cout << "Digest width: " << experimentalHash.bits() << '\n';
        std::cout << "Target digest: "
                  << experimentalHash.hexDigest(artifact.content) << "\n\n";

        SecondPreimageEngine engine(experimentalHash);

        const auto started = std::chrono::steady_clock::now();
        auto record = engine.search(artifact, 500000);
        const auto ended = std::chrono::steady_clock::now();

        const double seconds =
            std::chrono::duration<double>(ended - started).count();

        std::cout << "Controlled search\n";
        std::cout << "Elapsed seconds: " << std::fixed
                  << std::setprecision(6) << seconds << '\n';

        bool secondPreimageFound = record.has_value();

        if (record) {
            std::cout << "Second preimage: FOUND\n";
            std::cout << "Attempts: " << record->attempts << '\n';
            std::cout << "Messages distinct: "
                      << std::boolalpha << record->distinctMessages << '\n';
            std::cout << "Digest equality: "
                      << (record->targetDigest == record->candidateDigest)
                      << '\n';
        } else {
            std::cout << "Second preimage: NOT FOUND\n";
            std::cout << "Search budget exhausted without a matching candidate.\n";
        }

        /*
         * Production-oriented policy evaluation is intentionally separate
         * from the experimental attack engine. A secure hash may provide
         * second-preimage resistance while still not authenticating its
         * producer.
         */
        RepositorySecurityPolicy policy(128, true);

        const auto decision = policy.evaluate(
            256,
            false,
            secondPreimageFound
        );

        std::cout << "\nRepository security policy\n";
        std::cout << "Decision: " << decisionName(decision) << '\n';

        std::cout << "\nEngineering properties\n";
        std::cout << "- Second-preimage search fixes the original message.\n";
        std::cout << "- The candidate must be different from the original.\n";
        std::cout << "- Digest width directly affects brute-force resistance.\n";
        std::cout << "- Hash integrity does not establish message authenticity.\n";
        std::cout << "- Authentication should use an appropriate MAC or signature.\n";
        std::cout << "- Experimental hashes must never be substituted for SHA-2/SHA-3.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
