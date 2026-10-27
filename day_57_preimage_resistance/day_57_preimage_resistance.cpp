#include <algorithm>
#include <array>
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
 * Preimage resistance governance engine.
 *
 * This standalone C++17 program implements a deterministic educational
 * hash model rather than claiming to implement a production cryptographic
 * hash. The model is deliberately separated from repository governance.
 *
 * It evaluates:
 *   - artifact digest verification
 *   - pull-request state
 *   - review decisions
 *   - approval eligibility
 *   - status checks
 *   - protected-branch rules
 *   - merge eligibility
 *
 * A compact toy hash is used because standard C++17 has no SHA-256 API.
 * The toy hash is suitable for demonstrating state flow only, not security.
 */

enum class PullRequestState {
    Draft,
    Open,
    Closed,
    Merged
};

enum class ReviewState {
    Commented,
    ChangesRequested,
    Approved,
    Dismissed
};

enum class CheckState {
    Pending,
    Passing,
    Failing
};

struct Digest {
    std::array<std::uint8_t, 32> bytes{};

    bool operator==(const Digest& other) const {
        return bytes == other.bytes;
    }
};

struct User {
    std::string id;
    std::string name;
    bool active{true};
};

struct Commit {
    std::string id;
    std::string branch;
    std::string content;
    Digest contentDigest;
};

struct Review {
    std::string reviewerId;
    ReviewState state;
    std::vector<std::string> comments;
    bool stale{false};
};

struct StatusCheck {
    std::string name;
    CheckState state;
    bool required{true};
};

struct PullRequest {
    int id{};
    std::string sourceBranch;
    std::string targetBranch;
    std::string headCommit;
    PullRequestState state{PullRequestState::Draft};
    std::vector<Review> reviews;
    std::vector<StatusCheck> checks;
    bool conversationsResolved{false};
    bool baseSynchronized{false};
};

struct BranchProtection {
    std::string branch;
    bool requirePullRequest{true};
    bool restrictDirectPush{true};
    bool restrictForcePush{true};
    bool restrictDeletion{true};
    bool requireLinearHistory{false};
    bool requireResolvedConversations{true};
    std::size_t requiredApprovals{2};
    std::vector<std::string> requiredChecks;
};

struct Repository {
    std::string name;
    std::map<std::string, User> users;
    std::map<std::string, Commit> commits;
    std::map<int, PullRequest> pullRequests;
    std::map<std::string, BranchProtection> protections;
};

class ToyHash {
public:
    /*
     * FNV-like mixing is intentionally not cryptographic.
     * The interface mirrors a digest service so that the governance
     * engine can demonstrate verification without external libraries.
     */
    static Digest digest(const std::string& input) {
        Digest result;

        std::uint64_t a = 0xcbf29ce484222325ULL;
        std::uint64_t b = 0x9e3779b97f4a7c15ULL;

        for (unsigned char c : input) {
            a ^= c;
            a *= 0x100000001b3ULL;

            b ^= (a >> 23);
            b *= 0x9e3779b97f4a7c15ULL;
            b ^= (b >> 29);
        }

        for (std::size_t i = 0; i < result.bytes.size(); ++i) {
            a ^= b + static_cast<std::uint64_t>(i) * 0x517cc1b727220a95ULL;
            a *= 0x100000001b3ULL;
            b ^= a >> 31;

            result.bytes[i] =
                static_cast<std::uint8_t>((a ^ b) >> ((i % 8) * 8));
        }

        return result;
    }

    static std::string hex(const Digest& digest) {
        std::ostringstream output;

        for (const auto byte : digest.bytes) {
            output << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned int>(byte);
        }

        return output.str();
    }
};

class DigestVerifier {
public:
    static bool verify(const Commit& commit, const std::string& content) {
        return commit.contentDigest == ToyHash::digest(content);
    }
};

class MergeEligibilityEngine {
public:
    static std::vector<std::string> evaluate(
        const Repository& repository,
        const PullRequest& pr
    ) {
        std::vector<std::string> failures;

        auto protectionIt = repository.protections.find(pr.targetBranch);

        if (protectionIt == repository.protections.end()) {
            failures.emplace_back("target branch has no protection policy");
            return failures;
        }

        const auto& protection = protectionIt->second;

        if (pr.state != PullRequestState::Open) {
            failures.emplace_back("pull request is not open");
        }

        if (pr.sourceBranch == pr.targetBranch) {
            failures.emplace_back("source and target branches must differ");
        }

        if (!pr.baseSynchronized) {
            failures.emplace_back("pull request base branch is stale");
        }

        if (protection.requireResolvedConversations &&
            !pr.conversationsResolved) {
            failures.emplace_back("unresolved review conversations remain");
        }

        std::size_t validApprovals = 0;

        for (const auto& review : pr.reviews) {
            auto userIt = repository.users.find(review.reviewerId);

            if (userIt == repository.users.end() || !userIt->second.active) {
                continue;
            }

            if (review.stale) {
                continue;
            }

            if (review.state == ReviewState::Approved) {
                ++validApprovals;
            }
        }

        if (validApprovals < protection.requiredApprovals) {
            failures.emplace_back("required approvals have not been satisfied");
        }

        for (const auto& requiredCheck : protection.requiredChecks) {
            auto checkIt = std::find_if(
                pr.checks.begin(),
                pr.checks.end(),
                [&](const StatusCheck& check) {
                    return check.name == requiredCheck;
                }
            );

            if (checkIt == pr.checks.end()) {
                failures.emplace_back("required status check is missing: " + requiredCheck);
            } else if (checkIt->state != CheckState::Passing) {
                failures.emplace_back("required status check is not passing: " + requiredCheck);
            }
        }

        auto commitIt = repository.commits.find(pr.headCommit);

        if (commitIt == repository.commits.end()) {
            failures.emplace_back("head commit does not exist");
        } else if (!DigestVerifier::verify(
                       commitIt->second,
                       commitIt->second.content
                   )) {
            failures.emplace_back("head commit content digest failed verification");
        }

        return failures;
    }
};

class RepositoryService {
private:
    Repository repository_;

public:
    explicit RepositoryService(std::string name) {
        if (name.empty()) {
            throw std::invalid_argument("repository name must not be empty");
        }
        repository_.name = std::move(name);
    }

    void addUser(User user) {
        if (user.id.empty() || user.name.empty()) {
            throw std::invalid_argument("user id and name are required");
        }

        repository_.users.emplace(user.id, std::move(user));
    }

    void addCommit(const std::string& id,
                   const std::string& branch,
                   const std::string& content) {
        if (id.empty() || branch.empty()) {
            throw std::invalid_argument("commit id and branch are required");
        }

        Commit commit;
        commit.id = id;
        commit.branch = branch;
        commit.content = content;
        commit.contentDigest = ToyHash::digest(content);

        repository_.commits[id] = std::move(commit);
    }

    void protectBranch(BranchProtection protection) {
        if (protection.branch.empty()) {
            throw std::invalid_argument("protected branch name is required");
        }

        repository_.protections[protection.branch] = std::move(protection);
    }

    void addPullRequest(PullRequest pr) {
        if (pr.id <= 0) {
            throw std::invalid_argument("pull request id must be positive");
        }

        if (repository_.commits.find(pr.headCommit) == repository_.commits.end()) {
            throw std::invalid_argument("pull request head commit does not exist");
        }

        repository_.pullRequests[pr.id] = std::move(pr);
    }

    const Repository& repository() const {
        return repository_;
    }
};

static void printEligibility(
    const Repository& repository,
    const PullRequest& pr
) {
    auto failures = MergeEligibilityEngine::evaluate(repository, pr);

    std::cout << "\nPull Request #" << pr.id << '\n';

    if (failures.empty()) {
        std::cout << "Merge eligibility: ELIGIBLE\n";
        return;
    }

    std::cout << "Merge eligibility: BLOCKED\n";

    for (const auto& failure : failures) {
        std::cout << "  - " << failure << '\n';
    }
}

static void demonstratePreimageExperiment() {
    std::cout << "\n=== Small preimage experiment ===\n";

    const std::string original = "cab";
    const auto digest = ToyHash::digest(original);

    std::cout << "Original: " << original << '\n';
    std::cout << "Digest:   " << ToyHash::hex(digest) << '\n';

    std::cout << "Candidate verification: "
              << (digest == ToyHash::digest("cab") ? "match" : "mismatch")
              << '\n';

    std::cout << "Tampered candidate verification: "
              << (digest == ToyHash::digest("cac") ? "match" : "mismatch")
              << '\n';

    std::cout
        << "This toy hash is not cryptographically secure and must not be used "
        << "for passwords, signatures, authentication, or production integrity.\n";
}

int main() {
    try {
        RepositoryService service("security-platform");

        service.addUser({"alice", "Alice", true});
        service.addUser({"bob", "Bob", true});
        service.addUser({"carol", "Carol", true});
        service.addUser({"disabled", "Disabled Reviewer", false});

        service.addCommit(
            "a1b2c3d4",
            "feature/preimage-demo",
            "validate digest before merge"
        );

        BranchProtection protection;
        protection.branch = "main";
        protection.requiredApprovals = 2;
        protection.requirePullRequest = true;
        protection.restrictDirectPush = true;
        protection.restrictForcePush = true;
        protection.restrictDeletion = true;
        protection.requireResolvedConversations = true;
        protection.requiredChecks = {
            "unit-tests",
            "security-scan"
        };

        service.protectBranch(std::move(protection));

        PullRequest pr;
        pr.id = 101;
        pr.sourceBranch = "feature/preimage-demo";
        pr.targetBranch = "main";
        pr.headCommit = "a1b2c3d4";
        pr.state = PullRequestState::Open;
        pr.baseSynchronized = true;
        pr.conversationsResolved = true;

        pr.reviews.push_back({
            "alice",
            ReviewState::Approved,
            {"Digest verification is explicit."},
            false
        });

        pr.reviews.push_back({
            "bob",
            ReviewState::Approved,
            {"Security boundary is documented."},
            false
        });

        pr.checks.push_back({
            "unit-tests",
            CheckState::Passing,
            true
        });

        pr.checks.push_back({
            "security-scan",
            CheckState::Passing,
            true
        });

        service.addPullRequest(pr);

        printEligibility(
            service.repository(),
            service.repository().pullRequests.at(101)
        );

        PullRequest blocked = pr;
        blocked.id = 102;
        blocked.reviews[1].stale = true;
        blocked.checks[1].state = CheckState::Failing;
        blocked.conversationsResolved = false;

        service.addPullRequest(blocked);

        printEligibility(
            service.repository(),
            service.repository().pullRequests.at(102)
        );

        demonstratePreimageExperiment();

        std::cout << "\n=== Security and engineering boundaries ===\n";
        std::cout << "Preimage resistance concerns recovering an input from a target digest.\n";
        std::cout << "Integrity verification requires a trusted expected digest.\n";
        std::cout << "Branch governance determines whether a verified change may merge.\n";
        std::cout << "A hash does not authenticate the party that supplied the digest.\n";
        std::cout << "A cryptographic implementation must use a vetted hash library.\n";

        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Fatal error: " << exception.what() << '\n';
        return 1;
    }
}
