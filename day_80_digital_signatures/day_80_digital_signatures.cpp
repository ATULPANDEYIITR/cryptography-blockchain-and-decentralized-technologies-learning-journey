#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Digital Signature and Repository Trust Governance Engine.
 *
 * C++17 standalone educational implementation.
 *
 * Implements RSA digital signatures using:
 * - Modular exponentiation
 * - RSA key generation from bounded prime candidates
 * - SHA-256
 * - RSA PKCS#1 v1.5 SHA-256 encoding
 * - Signature verification
 * - Key lifecycle
 * - Revocation
 * - Approval and merge eligibility
 *
 * IMPORTANT:
 * The bounded RSA key sizes in this demonstration are NOT secure.
 * Production cryptographic operations require vetted libraries,
 * appropriately sized keys, secure randomness, and protected key storage.
 */

using namespace std;

using u64 = uint64_t;
using u128 = __uint128_t;


class SecurityError : public runtime_error {
public:
    explicit SecurityError(const string& message)
        : runtime_error(message) {}
};


class SHA256 {
private:
    static constexpr array<u32_dummy, 0> unused{};

    using Word = uint32_t;

    static constexpr array<Word, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static Word rotateRight(Word value, unsigned count) {
        return (value >> count) | (value << (32 - count));
    }

public:
    static string digest(const string& input) {
        vector<uint8_t> bytes(input.begin(), input.end());

        uint64_t bitLength =
            static_cast<uint64_t>(bytes.size()) * 8;

        bytes.push_back(0x80);

        while (bytes.size() % 64 != 56) {
            bytes.push_back(0);
        }

        for (int i = 7; i >= 0; --i) {
            bytes.push_back(
                static_cast<uint8_t>(bitLength >> (i * 8))
            );
        }

        array<Word, 8> state = {
            0x6a09e667, 0xbb67ae85,
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        };

        for (size_t offset = 0; offset < bytes.size(); offset += 64) {
            array<Word, 64> w{};

            for (int i = 0; i < 16; ++i) {
                size_t j = offset + i * 4;

                w[i] =
                    (static_cast<Word>(bytes[j]) << 24) |
                    (static_cast<Word>(bytes[j + 1]) << 16) |
                    (static_cast<Word>(bytes[j + 2]) << 8) |
                    static_cast<Word>(bytes[j + 3]);
            }

            for (int i = 16; i < 64; ++i) {
                Word s0 =
                    rotateRight(w[i - 15], 7) ^
                    rotateRight(w[i - 15], 18) ^
                    (w[i - 15] >> 3);

                Word s1 =
                    rotateRight(w[i - 2], 17) ^
                    rotateRight(w[i - 2], 19) ^
                    (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            Word a = state[0];
            Word b = state[1];
            Word c = state[2];
            Word d = state[3];
            Word e = state[4];
            Word f = state[5];
            Word g = state[6];
            Word h = state[7];

            for (int i = 0; i < 64; ++i) {
                Word S1 =
                    rotateRight(e, 6) ^
                    rotateRight(e, 11) ^
                    rotateRight(e, 25);

                Word choice = (e & f) ^ (~e & g);

                Word temp1 = h + S1 + choice + K[i] + w[i];

                Word S0 =
                    rotateRight(a, 2) ^
                    rotateRight(a, 13) ^
                    rotateRight(a, 22);

                Word majority =
                    (a & b) ^ (a & c) ^ (b & c);

                Word temp2 = S0 + majority;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        ostringstream output;
        output << hex << setfill('0');

        for (Word value : state) {
            output << setw(8) << value;
        }

        return output.str();
    }
};


u64 gcdValue(u64 a, u64 b) {
    while (b != 0) {
        u64 temp = b;
        b = a % b;
        a = temp;
    }

    return a;
}


u64 modularPower(u64 base, u64 exponent, u64 modulus) {
    if (modulus == 0) {
        throw SecurityError("Invalid modulus.");
    }

    u64 result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = static_cast<u64>(
                static_cast<u128>(result) * base % modulus
            );
        }

        base = static_cast<u64>(
            static_cast<u128>(base) * base % modulus
        );

        exponent >>= 1;
    }

    return result;
}


bool isPrime(u64 number) {
    if (number < 2) return false;

    for (u64 divisor = 2; divisor * divisor <= number; ++divisor) {
        if (number % divisor == 0) return false;
    }

    return true;
}


u64 modularInverse(u64 a, u64 modulus) {
    int64_t oldR = static_cast<int64_t>(a);
    int64_t r = static_cast<int64_t>(modulus);

    int64_t oldS = 1;
    int64_t s = 0;

    while (r != 0) {
        int64_t q = oldR / r;

        int64_t temp = oldR - q * r;
        oldR = r;
        r = temp;

        temp = oldS - q * s;
        oldS = s;
        s = temp;
    }

    if (oldR != 1) {
        throw SecurityError("Modular inverse does not exist.");
    }

    int64_t result = oldS % static_cast<int64_t>(modulus);

    if (result < 0) result += modulus;

    return static_cast<u64>(result);
}


struct RSAKey {
    u64 publicExponent;
    u64 privateExponent;
    u64 modulus;
    bool active = true;
};


class RSAEngine {
public:
    /*
     * Small fixed primes make this implementation demonstrable,
     * deterministic, and deliberately unsuitable for production.
     */
    static RSAKey generateDemonstrationKey() {
        constexpr u64 p = 1000003;
        constexpr u64 q = 1000033;

        if (!isPrime(p) || !isPrime(q) || p == q) {
            throw SecurityError("Invalid demonstration primes.");
        }

        u64 n = p * q;
        u64 phi = (p - 1) * (q - 1);

        u64 e = 65537;

        if (gcdValue(e, phi) != 1) {
            throw SecurityError("Invalid public exponent.");
        }

        u64 d = modularInverse(e, phi);

        return {e, d, n, true};
    }

    static string encodeSha256(const string& hash) {
        static const string prefix =
            "3031300d060960864801650304020105000420";

        if (hash.size() != 64) {
            throw SecurityError("Invalid SHA-256 digest.");
        }

        return prefix + hash;
    }

    static u64 sign(const RSAKey& key, const string& document) {
        if (!key.active) {
            throw SecurityError("Signing key is inactive.");
        }

        string encoded = encodeSha256(
            SHA256::digest(document)
        );

        /*
         * This bounded demonstration maps the SHA-256 encoding
         * to the integer domain. It is NOT standards-compliant
         * PKCS#1 v1.5 encoding and must not be used in production.
         */
        u64 value = 0;

        for (char c : encoded) {
            value = (
                static_cast<u128>(value) * 257 +
                static_cast<unsigned char>(c)
            ) % key.modulus;
        }

        return modularPower(
            value,
            key.privateExponent,
            key.modulus
        );
    }

    static bool verify(
        const RSAKey& key,
        const string& document,
        u64 signature
    ) {
        string encoded = encodeSha256(
            SHA256::digest(document)
        );

        u64 expected = 0;

        for (char c : encoded) {
            expected = (
                static_cast<u128>(expected) * 257 +
                static_cast<unsigned char>(c)
            ) % key.modulus;
        }

        return modularPower(
            signature,
            key.publicExponent,
            key.modulus
        ) == expected;
    }
};


enum class ReviewState {
    COMMENTED,
    APPROVED,
    CHANGES_REQUESTED,
    DISMISSED
};

enum class PullRequestState {
    DRAFT,
    OPEN,
    MERGED,
    CLOSED
};


struct Reviewer {
    string id;
    bool active = true;
    bool authorized = true;
};


struct Review {
    string reviewerId;
    ReviewState state;
    bool current = true;
    string comment;
};


struct StatusCheck {
    string name;
    bool required;
    bool passed;
};


struct BranchPolicy {
    int requiredApprovals = 2;
    bool requireSignedCommit = true;
    bool requireChecks = true;
    bool requireResolvedConversations = true;
    bool prohibitDirectPush = true;
    bool prohibitForcePush = true;
    bool prohibitDeletion = true;
    bool requireLinearHistory = true;
    bool administratorsMayBypass = false;
};


struct PullRequest {
    string id;
    string sourceBranch;
    string targetBranch;
    string proposedChangesHash;

    PullRequestState state = PullRequestState::OPEN;

    bool signedCommitVerified = false;
    bool conflicts = false;
    bool conversationsResolved = false;
    bool baseSynchronized = true;

    vector<Review> reviews;
    vector<StatusCheck> checks;
};


struct EligibilityResult {
    bool eligible = false;
    vector<string> failures;
};


class GovernanceEngine {
private:
    BranchPolicy policy;
    map<string, Reviewer> reviewers;
    map<string, PullRequest> requests;

public:
    explicit GovernanceEngine(BranchPolicy p)
        : policy(p) {}

    void addReviewer(const Reviewer& reviewer) {
        if (reviewer.id.empty()) {
            throw SecurityError("Reviewer ID is required.");
        }

        reviewers[reviewer.id] = reviewer;
    }

    void submit(PullRequest request) {
        if (request.id.empty() ||
            request.sourceBranch.empty() ||
            request.targetBranch.empty() ||
            request.proposedChangesHash.empty()) {
            throw SecurityError("Incomplete pull request.");
        }

        if (request.sourceBranch == request.targetBranch) {
            throw SecurityError("Source and target must differ.");
        }

        if (requests.count(request.id)) {
            throw SecurityError("Duplicate pull request.");
        }

        requests.emplace(request.id, move(request));
    }

    void addReview(
        const string& requestId,
        const Review& review
    ) {
        auto it = requests.find(requestId);

        if (it == requests.end()) {
            throw SecurityError("Unknown pull request.");
        }

        auto reviewer = reviewers.find(review.reviewerId);

        if (reviewer == reviewers.end() ||
            !reviewer->second.active ||
            !reviewer->second.authorized) {
            throw SecurityError("Reviewer is not eligible.");
        }

        PullRequest& request = it->second;

        if (request.state != PullRequestState::OPEN) {
            throw SecurityError("Request is not open.");
        }

        // A new decision supersedes the reviewer's previous decision.
        for (auto& old : request.reviews) {
            if (old.reviewerId == review.reviewerId) {
                old.current = false;
            }
        }

        request.reviews.push_back(review);
    }

    void setChecks(
        const string& requestId,
        vector<StatusCheck> checks
    ) {
        auto it = requests.find(requestId);

        if (it == requests.end()) {
            throw SecurityError("Unknown pull request.");
        }

        it->second.checks = move(checks);
    }

    EligibilityResult evaluate(const string& requestId) const {
        auto it = requests.find(requestId);

        if (it == requests.end()) {
            throw SecurityError("Unknown pull request.");
        }

        const PullRequest& request = it->second;
        EligibilityResult result;

        if (request.state != PullRequestState::OPEN) {
            result.failures.push_back("Request is not open.");
        }

        if (request.conflicts) {
            result.failures.push_back("Merge conflicts exist.");
        }

        if (!request.baseSynchronized) {
            result.failures.push_back("Base branch is outdated.");
        }

        if (policy.requireSignedCommit &&
            !request.signedCommitVerified) {
            result.failures.push_back(
                "Required signed commit verification failed."
            );
        }

        if (policy.requireResolvedConversations &&
            !request.conversationsResolved) {
            result.failures.push_back(
                "Review conversations remain unresolved."
            );
        }

        int approvals = 0;

        for (const Review& review : request.reviews) {
            auto reviewer = reviewers.find(review.reviewerId);

            if (!review.current ||
                reviewer == reviewers.end() ||
                !reviewer->second.active ||
                !reviewer->second.authorized) {
                continue;
            }

            if (review.state == ReviewState::APPROVED) {
                ++approvals;
            }

            if (review.state == ReviewState::CHANGES_REQUESTED) {
                result.failures.push_back(
                    "A reviewer requested changes: " +
                    review.reviewerId
                );
            }
        }

        if (approvals < policy.requiredApprovals) {
            result.failures.push_back(
                "Insufficient approvals."
            );
        }

        if (policy.requireChecks) {
            bool hasRequiredCheck = false;

            for (const StatusCheck& check : request.checks) {
                if (check.required) {
                    hasRequiredCheck = true;

                    if (!check.passed) {
                        result.failures.push_back(
                            "Required check failed: " + check.name
                        );
                    }
                }
            }

            if (!hasRequiredCheck) {
                result.failures.push_back(
                    "No required status checks are configured."
                );
            }
        }

        result.eligible = result.failures.empty();

        return result;
    }

    void merge(const string& requestId) {
        EligibilityResult result = evaluate(requestId);

        if (!result.eligible) {
            ostringstream error;

            error << "Merge rejected:";

            for (const auto& failure : result.failures) {
                error << "\n- " << failure;
            }

            throw SecurityError(error.str());
        }

        requests.at(requestId).state =
            PullRequestState::MERGED;
    }

    const PullRequest& get(const string& requestId) const {
        auto it = requests.find(requestId);

        if (it == requests.end()) {
            throw SecurityError("Unknown pull request.");
        }

        return it->second;
    }
};


void demonstrateDigitalSignatures() {
    cout << "\nDIGITAL SIGNATURE ENGINE\n";
    cout << "========================\n";

    RSAKey key = RSAEngine::generateDemonstrationKey();

    string document =
        "Approved procurement agreement 2026-001";

    u64 signature = RSAEngine::sign(key, document);

    cout << "Document SHA-256: "
         << SHA256::digest(document) << '\n';

    cout << "RSA signature: " << signature << '\n';

    cout << "Valid signature: "
         << boolalpha
         << RSAEngine::verify(key, document, signature)
         << '\n';

    cout << "Tampered document: "
         << RSAEngine::verify(
                key,
                document + " modified",
                signature
            )
         << '\n';
}


void demonstrateGovernance() {
    cout << "\nREPOSITORY GOVERNANCE ENGINE\n";
    cout << "============================\n";

    BranchPolicy policy;
    policy.requiredApprovals = 2;

    GovernanceEngine engine(policy);

    engine.addReviewer({"reviewer-1", true, true});
    engine.addReviewer({"reviewer-2", true, true});

    PullRequest request;

    request.id = "PR-2026-101";
    request.sourceBranch = "feature/digital-signatures";
    request.targetBranch = "main";
    request.proposedChangesHash = SHA256::digest(
        "Digital signature implementation"
    );

    request.signedCommitVerified = true;
    request.conversationsResolved = true;

    request.checks = {
        {"unit-tests", true, true},
        {"security-scan", true, true},
        {"documentation", false, true}
    };

    engine.submit(request);

    engine.addReview(
        request.id,
        {"reviewer-1", ReviewState::APPROVED, true, "Verified"}
    );

    engine.addReview(
        request.id,
        {"reviewer-2", ReviewState::APPROVED, true, "Approved"}
    );

    EligibilityResult eligibility = engine.evaluate(request.id);

    cout << "Merge eligible: "
         << boolalpha << eligibility.eligible << '\n';

    if (eligibility.eligible) {
        engine.merge(request.id);
        cout << "Pull request merged successfully.\n";
    }
}


int main() {
    try {
        // SHA-256 known-answer test.
        if (SHA256::digest("abc") !=
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad") {
            throw SecurityError("SHA-256 test failed.");
        }

        cout << "SHA-256 test passed.\n";

        demonstrateDigitalSignatures();
        demonstrateGovernance();

        cout << "\nAll demonstrations completed.\n";

    } catch (const exception& error) {
        cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
