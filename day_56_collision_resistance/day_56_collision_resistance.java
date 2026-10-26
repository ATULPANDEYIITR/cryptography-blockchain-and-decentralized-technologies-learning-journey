import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

public class CollisionResistanceGovernance {

    enum ReviewState {
        DRAFT,
        APPROVED,
        CHANGES_REQUESTED,
        DISMISSED
    }

    enum CheckState {
        PASSING,
        FAILING,
        PENDING
    }

    enum PullRequestState {
        OPEN,
        CLOSED,
        MERGED
    }

    record Commit(String id, String content) {
        Commit {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Commit id is required");
            }
            Objects.requireNonNull(content, "Commit content is required");
        }
    }

    record Review(
            String reviewer,
            ReviewState state,
            String comment
    ) {
        Review {
            if (reviewer == null || reviewer.isBlank()) {
                throw new IllegalArgumentException("Reviewer is required");
            }
            Objects.requireNonNull(state, "Review state is required");
            Objects.requireNonNull(comment, "Review comment is required");
        }
    }

    record StatusCheck(
            String name,
            CheckState state
    ) {
        StatusCheck {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Check name is required");
            }
            Objects.requireNonNull(state, "Check state is required");
        }
    }

    record BranchPolicy(
            boolean protectedBranch,
            int requiredApprovals,
            boolean requirePassingChecks,
            boolean requireLinearHistory,
            boolean allowForcePush
    ) {
        BranchPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                        "requiredApprovals cannot be negative"
                );
            }
        }
    }

    static final class HashService {
        private final String algorithm;

        HashService(String algorithm) {
            this.algorithm = switch (algorithm) {
                case "SHA-256", "SHA-512", "SHA3-256" -> algorithm;
                default -> throw new IllegalArgumentException(
                        "Unsupported algorithm: " + algorithm
                );
            };
        }

        String hash(String input) {
            Objects.requireNonNull(input, "Input cannot be null");

            try {
                MessageDigest digest = MessageDigest.getInstance(algorithm);
                byte[] result = digest.digest(
                        input.getBytes(StandardCharsets.UTF_8)
                );

                StringBuilder hex = new StringBuilder(result.length * 2);

                for (byte value : result) {
                    hex.append(String.format("%02x", value & 0xff));
                }

                return hex.toString();
            } catch (NoSuchAlgorithmException error) {
                throw new IllegalStateException(
                        "Configured hash algorithm is unavailable",
                        error
                );
            }
        }

        boolean verify(String input, String expected) {
            return MessageDigest.isEqual(
                    hash(input).getBytes(StandardCharsets.US_ASCII),
                    expected.getBytes(StandardCharsets.US_ASCII)
            );
        }
    }

    static final class PullRequest {
        private final String id;
        private final String sourceBranch;
        private final String targetBranch;
        private final List<Review> reviews = new ArrayList<>();
        private final List<StatusCheck> checks = new ArrayList<>();

        private PullRequestState state = PullRequestState.OPEN;
        private String headCommitId;

        PullRequest(
                String id,
                String sourceBranch,
                String targetBranch,
                String headCommitId
        ) {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Pull Request id is required");
            }
            if (sourceBranch == null || sourceBranch.isBlank()) {
                throw new IllegalArgumentException("Source branch is required");
            }
            if (targetBranch == null || targetBranch.isBlank()) {
                throw new IllegalArgumentException("Target branch is required");
            }

            this.id = id;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.headCommitId = Objects.requireNonNull(
                    headCommitId,
                    "Head commit is required"
            );
        }

        void addReview(Review review) {
            ensureOpen();
            reviews.add(Objects.requireNonNull(review));
        }

        void addCheck(StatusCheck check) {
            ensureOpen();
            checks.add(Objects.requireNonNull(check));
        }

        void synchronize(String newHeadCommitId) {
            ensureOpen();
            this.headCommitId = Objects.requireNonNull(newHeadCommitId);
        }

        void close() {
            if (state != PullRequestState.OPEN) {
                throw new IllegalStateException(
                        "Only an open Pull Request can be closed"
                );
            }
            state = PullRequestState.CLOSED;
        }

        void reopen() {
            if (state != PullRequestState.CLOSED) {
                throw new IllegalStateException(
                        "Only a closed Pull Request can be reopened"
                );
            }
            state = PullRequestState.OPEN;
        }

        void markMerged() {
            if (state != PullRequestState.OPEN) {
                throw new IllegalStateException(
                        "Only an open Pull Request can be merged"
                );
            }
            state = PullRequestState.MERGED;
        }

        int currentApprovals() {
            return (int) reviews.stream()
                    .filter(review -> review.state() == ReviewState.APPROVED)
                    .count();
        }

        boolean hasRequestedChanges() {
            return reviews.stream()
                    .anyMatch(
                            review ->
                                    review.state() == ReviewState.CHANGES_REQUESTED
                    );
        }

        boolean checksPassing() {
            return !checks.isEmpty()
                    && checks.stream()
                    .allMatch(check -> check.state() == CheckState.PASSING);
        }

        String headCommitId() {
            return headCommitId;
        }

        PullRequestState state() {
            return state;
        }

        private void ensureOpen() {
            if (state != PullRequestState.OPEN) {
                throw new IllegalStateException(
                        "Pull Request is not open"
                );
            }
        }
    }

    static final class RepositoryGovernanceService {
        private final Map<String, Commit> commits = new HashMap<>();
        private final Map<String, BranchPolicy> policies = new HashMap<>();

        void registerCommit(Commit commit) {
            commits.put(commit.id(), commit);
        }

        void protectBranch(String branch, BranchPolicy policy) {
            if (branch == null || branch.isBlank()) {
                throw new IllegalArgumentException("Branch is required");
            }
            policies.put(branch, Objects.requireNonNull(policy));
        }

        boolean canMerge(PullRequest request) {
            BranchPolicy policy = policies.get(request.targetBranch);

            if (policy == null || !policy.protectedBranch()) {
                return request.state() == PullRequestState.OPEN;
            }

            if (request.state() != PullRequestState.OPEN) {
                return false;
            }

            if (!commits.containsKey(request.headCommitId())) {
                return false;
            }

            if (request.hasRequestedChanges()) {
                return false;
            }

            if (request.currentApprovals() < policy.requiredApprovals()) {
                return false;
            }

            if (policy.requirePassingChecks() && !request.checksPassing()) {
                return false;
            }

            return true;
        }

        void merge(PullRequest request) {
            if (!canMerge(request)) {
                throw new IllegalStateException(
                        "Pull Request does not satisfy repository policy"
                );
            }

            request.markMerged();
        }
    }

    static int truncatedDigest(String input, int bits) {
        if (bits < 1 || bits > 20) {
            throw new IllegalArgumentException("bits must be between 1 and 20");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(
                    input.getBytes(StandardCharsets.UTF_8)
            );

            int value = ((bytes[0] & 0xff) << 24)
                    | ((bytes[1] & 0xff) << 16)
                    | ((bytes[2] & 0xff) << 8)
                    | (bytes[3] & 0xff);

            return (value >>> (32 - bits));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    static String findSmallDigestCollision(int bits, int maxAttempts) {
        Map<Integer, String> seen = new HashMap<>();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            byte[] bytes = new byte[16];
            ThreadLocalRandom.current().nextBytes(bytes);
            String candidate = java.util.HexFormat.of().formatHex(bytes);

            int digest = truncatedDigest(candidate, bits);
            String previous = seen.putIfAbsent(digest, candidate);

            if (previous != null && !previous.equals(candidate)) {
                return previous + " != " + candidate
                        + " -> digest " + digest;
            }
        }

        throw new IllegalStateException(
                "No demonstration collision found"
        );
    }

    public static void main(String[] args) {
        HashService hasher = new HashService("SHA-256");

        String original = "repository commit content";
        String digest = hasher.hash(original);

        System.out.println("=== Collision Resistance ===");
        System.out.println("SHA-256: " + digest);
        System.out.println(
                "Verification: "
                        + hasher.verify(original, digest)
        );
        System.out.println(
                "Modified content: "
                        + hasher.verify(
                                "repository commit changed",
                                digest
                        )
        );

        System.out.println("\n=== Birthday-Bound Demonstration ===");
        for (int bits : List.of(8, 12, 16)) {
            System.out.println(
                    bits + "-bit collision: "
                            + findSmallDigestCollision(bits, 100_000)
            );
        }

        RepositoryGovernanceService governance =
                new RepositoryGovernanceService();

        governance.registerCommit(
                new Commit("commit-001", "source tree state")
        );

        governance.protectBranch(
                "main",
                new BranchPolicy(
                        true,
                        2,
                        true,
                        true,
                        false
                )
        );

        PullRequest request = new PullRequest(
                "PR-100",
                "feature/collision-analysis",
                "main",
                "commit-001"
        );

        request.addReview(
                new Review(
                        "reviewer-a",
                        ReviewState.APPROVED,
                        "Digest handling is correct"
                )
        );

        request.addReview(
                new Review(
                        "reviewer-b",
                        ReviewState.APPROVED,
                        "Validation and failure handling are acceptable"
                )
        );

        request.addCheck(
                new StatusCheck(
                        "security-scan",
                        CheckState.PASSING
                )
        );

        request.addCheck(
                new StatusCheck(
                        "test-suite",
                        CheckState.PASSING
                )
        );

        System.out.println("\n=== Governance ===");
        System.out.println(
                "Merge eligible: " + governance.canMerge(request)
        );

        governance.merge(request);

        System.out.println("Final state: " + request.state());
        System.out.println("\nEngineering distinction:");
        System.out.println(
                "Collision resistance protects the hash primitive; "
                        + "review and branch policy govern repository behavior."
        );
    }
}
