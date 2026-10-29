#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum class ReviewState {
    Approved,
    ChangesRequested,
    Commented
};

enum class CheckState {
    Pass,
    Fail,
    Pending
};

enum class MergeState {
    Draft,
    Open,
    Eligible,
    Blocked,
    Merged
};

struct Review {
    std::string reviewer;
    ReviewState state;
};

struct StatusCheck {
    std::string name;
    CheckState state;
};

struct BranchProtection {
    std::size_t requiredApprovals{2};
    bool requireAllChecks{true};
    bool requireResolvedConversations{true};
    bool allowDirectPush{false};
    bool allowForcePush{false};
    bool requireLinearHistory{true};
};

struct PullRequest {
    std::uint64_t id{};
    std::string sourceBranch;
    std::string targetBranch;
    MergeState state{MergeState::Draft};
    std::vector<std::string> commits;
    std::vector<Review> reviews;
    std::vector<StatusCheck> checks;
    bool conversationsResolved{false};
    bool branchSynchronized{false};
    bool hasMergeConflict{false};
};

class BirthdayMath {
public:
    static long double collisionProbability(
        std::uint64_t samples,
        std::uint64_t space
    ) {
        if (space == 0) {
            throw std::invalid_argument("hash space must be non-zero");
        }
        if (samples <= 1) {
            return 0.0L;
        }
        if (samples > space) {
            return 1.0L;
        }

        long double logNoCollision = 0.0L;

        for (std::uint64_t i = 0; i < samples; ++i) {
            logNoCollision += std::log1pl(
                -static_cast<long double>(i) /
                static_cast<long double>(space)
            );
        }

        return -std::expm1l(logNoCollision);
    }

    static long double birthdayEstimate(std::uint64_t samples, unsigned bits) {
        if (bits >= 63) {
            long double n = std::ldexpl(1.0L, static_cast<int>(bits));
            long double exponent =
                -(static_cast<long double>(samples) *
                  static_cast<long double>(samples - 1)) /
                (2.0L * n);
            return -std::expm1l(exponent);
        }

        return collisionProbability(
            samples,
            std::uint64_t{1} << bits
        );
    }
};

class MergeEligibilityEngine {
private:
    BranchProtection protection_;

    bool approvalsSatisfied(const PullRequest& pr) const {
        std::unordered_map<std::string, bool> approvedReviewers;

        for (const auto& review : pr.reviews) {
            if (review.state == ReviewState::Approved) {
                approvedReviewers[review.reviewer] = true;
            }
        }

        return approvedReviewers.size() >= protection_.requiredApprovals;
    }

    bool checksSatisfied(const PullRequest& pr) const {
        if (!protection_.requireAllChecks) {
            return true;
        }

        if (pr.checks.empty()) {
            return false;
        }

        return std::all_of(
            pr.checks.begin(),
            pr.checks.end(),
            [](const StatusCheck& check) {
                return check.state == CheckState::Pass;
            }
        );
    }

public:
    explicit MergeEligibilityEngine(BranchProtection protection)
        : protection_(std::move(protection)) {}

    bool eligible(const PullRequest& pr) const {
        if (pr.state == MergeState::Draft ||
            pr.state == MergeState::Merged) {
            return false;
        }

        if (pr.sourceBranch.empty() || pr.targetBranch.empty()) {
            return false;
        }

        if (pr.commits.empty()) {
            return false;
        }

        if (!pr.branchSynchronized) {
            return false;
        }

        if (pr.hasMergeConflict) {
            return false;
        }

        if (!approvalsSatisfied(pr)) {
            return false;
        }

        if (!checksSatisfied(pr)) {
            return false;
        }

        if (protection_.requireResolvedConversations &&
            !pr.conversationsResolved) {
            return false;
        }

        return true;
    }

    MergeState evaluate(const PullRequest& pr) const {
        return eligible(pr)
            ? MergeState::Eligible
            : MergeState::Blocked;
    }
};

std::string stateName(MergeState state) {
    switch (state) {
        case MergeState::Draft: return "DRAFT";
        case MergeState::Open: return "OPEN";
        case MergeState::Eligible: return "ELIGIBLE";
        case MergeState::Blocked: return "BLOCKED";
        case MergeState::Merged: return "MERGED";
    }
    return "UNKNOWN";
}

void validatePullRequest(const PullRequest& pr) {
    if (pr.id == 0) {
        throw std::invalid_argument("pull request ID must be non-zero");
    }

    if (pr.sourceBranch == pr.targetBranch) {
        throw std::invalid_argument("source and target branches must differ");
    }

    if (pr.sourceBranch.empty() || pr.targetBranch.empty()) {
        throw std::invalid_argument("branch names cannot be empty");
    }
}

PullRequest buildScenario() {
    PullRequest pr;
    pr.id = 1042;
    pr.sourceBranch = "feature/hash-audit";
    pr.targetBranch = "main";
    pr.state = MergeState::Open;

    pr.commits = {
        "a1f3c2d",
        "b7e81aa",
        "d0c8f44"
    };

    pr.reviews = {
        {"alice", ReviewState::Approved},
        {"bob", ReviewState::Approved},
        {"charlie", ReviewState::Commented}
    };

    pr.checks = {
        {"unit-tests", CheckState::Pass},
        {"static-analysis", CheckState::Pass},
        {"security-scan", CheckState::Pass}
    };

    pr.conversationsResolved = true;
    pr.branchSynchronized = true;
    pr.hasMergeConflict = false;

    return pr;
}

void runAssertions() {
    const long double probability =
        BirthdayMath::collisionProbability(23, 365);

    if (probability < 0.49L || probability > 0.51L) {
        throw std::runtime_error("birthday probability assertion failed");
    }

    const auto pr = buildScenario();
    BranchProtection policy;
    MergeEligibilityEngine engine(policy);

    if (!engine.eligible(pr)) {
        throw std::runtime_error("valid merge scenario was rejected");
    }

    auto blocked = pr;
    blocked.hasMergeConflict = true;

    if (engine.eligible(blocked)) {
        throw std::runtime_error("conflicted pull request was accepted");
    }
}

void printBirthdayTable() {
    std::cout << "Birthday collision probabilities\n";
    std::cout << "--------------------------------\n";

    const std::vector<std::pair<unsigned, std::uint64_t>> cases = {
        {8, 20},
        {16, 300},
        {32, 77164}
    };

    for (const auto& [bits, samples] : cases) {
        const long double probability =
            BirthdayMath::birthdayEstimate(samples, bits);

        std::cout << bits << "-bit, "
                  << samples << " samples: "
                  << std::fixed << std::setprecision(6)
                  << static_cast<double>(probability)
                  << '\n';
    }

    const long double birthday365 =
        BirthdayMath::collisionProbability(23, 365);

    std::cout << "365-day space, 23 samples: "
              << static_cast<double>(birthday365)
              << '\n';
}

void demonstrateFailureModes() {
    BranchProtection policy;
    policy.requiredApprovals = 2;
    policy.requireAllChecks = true;
    policy.requireResolvedConversations = true;

    MergeEligibilityEngine engine(policy);

    auto pr = buildScenario();

    std::cout << "\nRepository governance evaluation\n";
    std::cout << "Initial state: "
              << stateName(engine.evaluate(pr))
              << '\n';

    pr.reviews[1].state = ReviewState::ChangesRequested;
    std::cout << "After requested changes: "
              << stateName(engine.evaluate(pr))
              << '\n';

    pr.reviews[1].state = ReviewState::Approved;
    pr.checks[2].state = CheckState::Fail;
    std::cout << "After security check failure: "
              << stateName(engine.evaluate(pr))
              << '\n';

    pr.checks[2].state = CheckState::Pass;
    pr.conversationsResolved = false;
    std::cout << "With unresolved conversation: "
              << stateName(engine.evaluate(pr))
              << '\n';

    pr.conversationsResolved = true;
    pr.hasMergeConflict = true;
    std::cout << "With merge conflict: "
              << stateName(engine.evaluate(pr))
              << '\n';

    pr.hasMergeConflict = false;
    std::cout << "After conflict resolution: "
              << stateName(engine.evaluate(pr))
              << '\n';
}

int main() {
    try {
        runAssertions();

        printBirthdayTable();

        const BranchProtection protection{
            2,
            true,
            true,
            false,
            false,
            true
        };

        const MergeEligibilityEngine engine(protection);
        const PullRequest pr = buildScenario();

        validatePullRequest(pr);

        std::cout << "\nCase-study pull request\n";
        std::cout << "PR #" << pr.id << ": "
                  << pr.sourceBranch << " -> "
                  << pr.targetBranch << '\n';
        std::cout << "Commits: " << pr.commits.size() << '\n';
        std::cout << "Merge state: "
                  << stateName(engine.evaluate(pr))
                  << '\n';

        demonstrateFailureModes();

        std::cout << "\nEngineering considerations\n";
        std::cout << "- Birthday collision work grows near the square root of the hash space.\n";
        std::cout << "- A k-bit digest provides approximately k/2 bits of generic collision security.\n";
        std::cout << "- Merge eligibility is evaluated from current repository state rather than cached approval counts.\n";
        std::cout << "- Reviewer identity is deduplicated before counting approvals.\n";
        std::cout << "- A failed status check, conflict, unresolved discussion, or missing approval blocks merging.\n";
        std::cout << "- Production systems should authenticate governance events and protect audit records.\n";

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << '\n';
        return 1;
    }
}
