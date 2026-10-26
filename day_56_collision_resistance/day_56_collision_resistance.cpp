#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * This program models collision resistance without relying on external
 * cryptographic libraries.
 *
 * The small demonstration hash is intentionally non-cryptographic and
 * intentionally truncated. It exists to make the birthday bound observable.
 * It must not be used for authentication, signatures, passwords, or integrity
 * protection in real systems.
 */

enum class ReviewState {
    Draft,
    Approved,
    Rejected
};

enum class Status {
    Passing,
    Failing
};

struct Commit {
    std::string id;
    std::string content;
};

struct HashRecord {
    std::uint64_t value{};
    std::string input;
};

class DemoHash {
public:
    static std::uint64_t hash64(const std::string& input) {
        /*
         * FNV-1a is deliberately used only as a deterministic teaching hash.
         * Cryptographic collision resistance cannot be inferred from it.
         */
        constexpr std::uint64_t offset = 14695981039346656037ULL;
        constexpr std::uint64_t prime = 1099511628211ULL;

        std::uint64_t value = offset;

        for (unsigned char byte : input) {
            value ^= byte;
            value *= prime;
        }

        return value;
    }

    static std::uint32_t truncate(std::uint64_t value, unsigned bits) {
        if (bits == 0 || bits > 24) {
            throw std::invalid_argument("bits must be between 1 and 24");
        }

        return static_cast<std::uint32_t>(
            value >> (64U - bits)
        );
    }
};

class CollisionExperiment {
public:
    explicit CollisionExperiment(unsigned bits)
        : bits_(bits), generator_(std::random_device{}()) {
        if (bits_ == 0 || bits_ > 24) {
            throw std::invalid_argument("experiment supports 1..24 bits");
        }
    }

    HashRecord run(std::size_t maxAttempts) {
        std::unordered_map<std::uint32_t, std::string> seen;
        std::uniform_int_distribution<int> distribution(0, 255);

        for (std::size_t attempt = 1; attempt <= maxAttempts; ++attempt) {
            std::string candidate(16, '\0');

            for (char& character : candidate) {
                character = static_cast<char>(distribution(generator_));
            }

            const auto full = DemoHash::hash64(candidate);
            const auto digest = DemoHash::truncate(full, bits_);

            auto [it, inserted] = seen.emplace(digest, candidate);

            if (!inserted && it->second != candidate) {
                return {
                    digest,
                    it->second + "|" + candidate
                };
            }
        }

        throw std::runtime_error("collision not found within attempt limit");
    }

private:
    unsigned bits_;
    std::mt19937 generator_;
};

class GovernanceEngine {
public:
    void addCommit(const Commit& commit) {
        if (commit.id.empty()) {
            throw std::invalid_argument("commit id cannot be empty");
        }

        const auto digest = DemoHash::hash64(commit.content);

        auto existing = commitsByHash_.find(digest);
        if (existing != commitsByHash_.end() &&
            existing->second.content != commit.content) {
            throw std::runtime_error(
                "Hash collision detected between distinct commit contents"
            );
        }

        commitsByHash_[digest] = commit;
    }

    bool contentMatches(const std::string& content) const {
        const auto digest = DemoHash::hash64(content);
        auto it = commitsByHash_.find(digest);

        return it != commitsByHash_.end() &&
               it->second.content == content;
    }

private:
    std::unordered_map<std::uint64_t, Commit> commitsByHash_;
};

struct PullRequest {
    std::string id;
    std::string sourceBranch;
    std::string targetBranch;
    std::string headCommit;
    ReviewState review = ReviewState::Draft;
    Status tests = Status::Failing;
};

class MergeEligibilityEngine {
public:
    static bool eligible(const PullRequest& request,
                         bool targetProtected,
                         bool requiredReview,
                         bool requiredTests) {
        if (request.sourceBranch.empty() ||
            request.targetBranch.empty() ||
            request.headCommit.empty()) {
            return false;
        }

        if (request.review == ReviewState::Rejected) {
            return false;
        }

        if (targetProtected && requiredReview &&
            request.review != ReviewState::Approved) {
            return false;
        }

        if (targetProtected && requiredTests &&
            request.tests != Status::Passing) {
            return false;
        }

        return true;
    }
};

static std::string hex64(std::uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << std::setw(16) << std::setfill('0') << value;
    return stream.str();
}

int main() {
    try {
        std::cout << "=== Collision Resistance Case Study ===\n";

        GovernanceEngine governance;

        Commit first{
            "commit-001",
            "source-tree-before-review"
        };

        governance.addCommit(first);

        std::cout
            << "Known content: "
            << std::boolalpha
            << governance.contentMatches("source-tree-before-review")
            << "\n";

        std::cout
            << "Modified content: "
            << governance.contentMatches("source-tree-after-review")
            << "\n";

        const auto fullHash = DemoHash::hash64(first.content);

        std::cout
            << "Demonstration hash: "
            << hex64(fullHash)
            << "\n";

        std::cout << "\n=== Birthday Bound Experiment ===\n";

        for (unsigned bits : {8U, 12U, 16U}) {
            CollisionExperiment experiment(bits);
            const HashRecord collision = experiment.run(100000);

            std::cout
                << bits
                << "-bit collision digest: "
                << collision.value
                << "\n";
        }

        std::cout << "\n=== Merge Eligibility ===\n";

        PullRequest request{
            "PR-100",
            "feature/collision-analysis",
            "main",
            "commit-001",
            ReviewState::Approved,
            Status::Passing
        };

        std::cout
            << "Eligible before merge: "
            << MergeEligibilityEngine::eligible(
                request,
                true,
                true,
                true
            )
            << "\n";

        request.tests = Status::Failing;

        std::cout
            << "Eligible after failed tests: "
            << MergeEligibilityEngine::eligible(
                request,
                true,
                true,
                true
            )
            << "\n";

        std::cout << "\nEngineering constraints:\n";
        std::cout
            << "- A cryptographic hash must resist deliberate collision finding.\n"
            << "- Generic collision search against an n-bit ideal hash costs about 2^(n/2).\n"
            << "- A short demonstration digest is useful for experimentation but unsafe for governance.\n"
            << "- A merge system should not treat a hash alone as proof of authorship or authorization.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Failure: " << error.what() << '\n';
        return 1;
    }
}
