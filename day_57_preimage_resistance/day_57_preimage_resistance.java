import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/*
 * Preimage resistance enterprise governance model.
 *
 * The application uses Java's standard MessageDigest implementation for
 * SHA-256 and models repository integrity as a service consumed by an
 * explicit merge-eligibility policy.
 *
 * Domain concepts are intentionally separated:
 * - ArtifactDigest represents integrity evidence.
 * - Review represents a review decision.
 * - ApprovalPolicy defines reviewer requirements.
 * - BranchProtection defines repository enforcement.
 * - MergeEligibilityService combines the independent conditions.
 */

public class PreimageResistanceEnterprise {

    enum PullRequestState {
        DRAFT,
        OPEN,
        CLOSED,
        MERGED
    }

    enum ReviewState {
        COMMENTED,
        CHANGES_REQUESTED,
        APPROVED,
        DISMISSED
    }

    enum CheckState {
        PENDING,
        PASSING,
        FAILING
    }

    enum EligibilityCode {
        PULL_REQUEST_NOT_OPEN,
        BASE_BRANCH_STALE,
        UNRESOLVED_CONVERSATIONS,
        INSUFFICIENT_APPROVALS,
        REQUIRED_CHECK_MISSING,
        REQUIRED_CHECK_FAILING,
        INVALID_HEAD_COMMIT,
        INTEGRITY_FAILURE
    }

    record User(String id, String displayName, boolean active) {
        User {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("user id is required");
            }
            if (displayName == null || displayName.isBlank()) {
                throw new IllegalArgumentException("display name is required");
            }
        }
    }

    record ArtifactDigest(
            String algorithm,
            String digestHex,
            String context
    ) {
        ArtifactDigest {
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(digestHex);
            Objects.requireNonNull(context);

            if (digestHex.isBlank() || context.isBlank()) {
                throw new IllegalArgumentException("digest and context must be non-empty");
            }
        }
    }

    record Commit(
            String id,
            String branch,
            String content,
            ArtifactDigest artifactDigest
    ) {
        Commit {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("commit id is required");
            }
            if (branch == null || branch.isBlank()) {
                throw new IllegalArgumentException("branch is required");
            }
            Objects.requireNonNull(content);
            Objects.requireNonNull(artifactDigest);
        }
    }

    record Review(
            String reviewerId,
            ReviewState state,
            boolean stale
    ) {
        Review {
            Objects.requireNonNull(reviewerId);
            Objects.requireNonNull(state);
        }
    }

    record StatusCheck(
            String name,
            CheckState state
    ) {
        StatusCheck {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("check name is required");
            }
            Objects.requireNonNull(state);
        }
    }

    record PullRequest(
            int id,
            String sourceBranch,
            String targetBranch,
            String headCommitId,
            PullRequestState state,
            List<Review> reviews,
            List<StatusCheck> statusChecks,
            boolean baseSynchronized,
            boolean conversationsResolved
    ) {
        PullRequest {
            if (id <= 0) {
                throw new IllegalArgumentException("pull request id must be positive");
            }
            if (sourceBranch == null || sourceBranch.isBlank()) {
                throw new IllegalArgumentException("source branch is required");
            }
            if (targetBranch == null || targetBranch.isBlank()) {
                throw new IllegalArgumentException("target branch is required");
            }

            Objects.requireNonNull(headCommitId);
            Objects.requireNonNull(state);
            reviews = List.copyOf(reviews);
            statusChecks = List.copyOf(statusChecks);
        }
    }

    record ApprovalPolicy(
            int requiredApprovals,
            Set<String> eligibleReviewers
    ) {
        ApprovalPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException("required approvals cannot be negative");
            }
            eligibleReviewers = Set.copyOf(eligibleReviewers);
        }

        long validApprovals(PullRequest pullRequest) {
            return pullRequest.reviews()
                    .stream()
                    .filter(review -> review.state() == ReviewState.APPROVED)
                    .filter(review -> !review.stale())
                    .filter(review -> eligibleReviewers.contains(review.reviewerId()))
                    .distinct()
                    .count();
        }
    }

    record BranchProtection(
            String branch,
            boolean requirePullRequest,
            boolean restrictDirectPush,
            boolean restrictForcePush,
            boolean restrictDeletion,
            boolean requireResolvedConversations,
            boolean requireLinearHistory,
            ApprovalPolicy approvalPolicy,
            Set<String> requiredChecks
    ) {
        BranchProtection {
            if (branch == null || branch.isBlank()) {
                throw new IllegalArgumentException("protected branch is required");
            }
            Objects.requireNonNull(approvalPolicy);
            requiredChecks = Set.copyOf(requiredChecks);
        }
    }

    record EligibilityResult(
            boolean eligible,
            List<EligibilityCode> failures
    ) {
        EligibilityResult {
            failures = List.copyOf(failures);
        }
    }

    static final class HashService {

        private static final String ALGORITHM = "SHA-256";

        private static byte[] sha256(byte[] input) {
            try {
                MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
                return digest.digest(input);
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                        "JVM does not provide SHA-256",
                        exception
                );
            }
        }

        static ArtifactDigest digest(String context, String value) {
            Objects.requireNonNull(context);
            Objects.requireNonNull(value);

            byte[] contextBytes = context.getBytes(StandardCharsets.UTF_8);
            byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);

            byte[] input = new byte[
                    contextBytes.length + 1 + valueBytes.length
            ];

            System.arraycopy(
                    contextBytes,
                    0,
                    input,
                    0,
                    contextBytes.length
            );

            input[contextBytes.length] = 0;

            System.arraycopy(
                    valueBytes,
                    0,
                    input,
                    contextBytes.length + 1,
                    valueBytes.length
            );

            return new ArtifactDigest(
                    ALGORITHM,
                    toHex(sha256(input)),
                    context
            );
        }

        static boolean verify(
                ArtifactDigest expected,
                String candidate,
                String context
        ) {
            ArtifactDigest actual = digest(context, candidate);

            return MessageDigest.isEqual(
                    expected.digestHex().getBytes(StandardCharsets.US_ASCII),
                    actual.digestHex().getBytes(StandardCharsets.US_ASCII)
            );
        }

        private static String toHex(byte[] bytes) {
            StringBuilder result = new StringBuilder(bytes.length * 2);

            for (byte value : bytes) {
                result.append(String.format("%02x", value & 0xff));
            }

            return result.toString();
        }
    }

    static final class RepositoryService {

        private final Map<String, User> users = new HashMap<>();
        private final Map<String, Commit> commits = new HashMap<>();
        private final Map<String, BranchProtection> protections = new HashMap<>();

        void registerUser(User user) {
            users.put(user.id(), user);
        }

        void registerCommit(Commit commit) {
            commits.put(commit.id(), commit);
        }

        void protectBranch(BranchProtection protection) {
            protections.put(protection.branch(), protection);
        }

        boolean userIsEligible(String userId, BranchProtection protection) {
            User user = users.get(userId);

            return user != null
                    && user.active()
                    && protection.approvalPolicy()
                            .eligibleReviewers()
                            .contains(userId);
        }

        Commit findCommit(String id) {
            return commits.get(id);
        }

        BranchProtection findProtection(String branch) {
            return protections.get(branch);
        }
    }

    static final class MergeEligibilityService {

        private final RepositoryService repositoryService;

        MergeEligibilityService(RepositoryService repositoryService) {
            this.repositoryService = repositoryService;
        }

        EligibilityResult evaluate(PullRequest pullRequest) {
            List<EligibilityCode> failures = new ArrayList<>();

            BranchProtection protection =
                    repositoryService.findProtection(pullRequest.targetBranch());

            if (protection == null) {
                failures.add(EligibilityCode.REQUIRED_CHECK_MISSING);
                return new EligibilityResult(false, failures);
            }

            if (pullRequest.state() != PullRequestState.OPEN) {
                failures.add(EligibilityCode.PULL_REQUEST_NOT_OPEN);
            }

            if (!pullRequest.baseSynchronized()) {
                failures.add(EligibilityCode.BASE_BRANCH_STALE);
            }

            if (protection.requireResolvedConversations()
                    && !pullRequest.conversationsResolved()) {
                failures.add(EligibilityCode.UNRESOLVED_CONVERSATIONS);
            }

            long approvals = pullRequest.reviews()
                    .stream()
                    .filter(review -> review.state() == ReviewState.APPROVED)
                    .filter(review -> !review.stale())
                    .filter(review ->
                            repositoryService.userIsEligible(
                                    review.reviewerId(),
                                    protection
                            )
                    )
                    .map(Review::reviewerId)
                    .distinct()
                    .count();

            if (approvals < protection.approvalPolicy().requiredApprovals()) {
                failures.add(EligibilityCode.INSUFFICIENT_APPROVALS);
            }

            Map<String, CheckState> checks = new HashMap<>();

            pullRequest.statusChecks()
                    .forEach(check -> checks.put(check.name(), check.state()));

            for (String required : protection.requiredChecks()) {
                CheckState state = checks.get(required);

                if (state == null) {
                    failures.add(EligibilityCode.REQUIRED_CHECK_MISSING);
                } else if (state != CheckState.PASSING) {
                    failures.add(EligibilityCode.REQUIRED_CHECK_FAILING);
                }
            }

            Commit head = repositoryService.findCommit(
                    pullRequest.headCommitId()
            );

            if (head == null) {
                failures.add(EligibilityCode.INVALID_HEAD_COMMIT);
            } else if (!HashService.verify(
                    head.artifactDigest(),
                    head.content(),
                    head.artifactDigest().context()
            )) {
                failures.add(EligibilityCode.INTEGRITY_FAILURE);
            }

            return new EligibilityResult(
                    failures.isEmpty(),
                    failures
            );
        }
    }

    private static void printResult(
            String label,
            EligibilityResult result
    ) {
        System.out.println("\n" + label);
        System.out.println(
                "Merge eligibility: " +
                        (result.eligible() ? "ELIGIBLE" : "BLOCKED")
        );

        for (EligibilityCode failure : result.failures()) {
            System.out.println("  - " + failure);
        }
    }

    private static void demonstrateHashProperty() {
        System.out.println("=== Preimage resistance ===");

        String context = "repository-artifact-v1";
        String original = "branch protection requires two approvals";

        ArtifactDigest digest = HashService.digest(context, original);

        System.out.println("Digest: " + digest.digestHex());

        System.out.println(
                "Correct candidate: " +
                        HashService.verify(digest, original, context)
        );

        System.out.println(
                "Incorrect candidate: " +
                        HashService.verify(
                                digest,
                                "branch protection requires one approval",
                                context
                        )
        );

        System.out.println(
                "The digest enables verification of a candidate without "
                        + "revealing the original input."
        );
    }

    public static void main(String[] args) {
        RepositoryService repository = new RepositoryService();

        repository.registerUser(new User("alice", "Alice", true));
        repository.registerUser(new User("bob", "Bob", true));
        repository.registerUser(new User("carol", "Carol", true));
        repository.registerUser(new User("disabled", "Disabled", false));

        String context = "repository-artifact-v1";
        String content = "security policy: require two independent approvals";

        Commit commit = new Commit(
                "a1b2c3d4",
                "feature/preimage",
                content,
                HashService.digest(context, content)
        );

        repository.registerCommit(commit);

        ApprovalPolicy approvalPolicy = new ApprovalPolicy(
                2,
                Set.of("alice", "bob", "carol")
        );

        BranchProtection protection = new BranchProtection(
                "main",
                true,
                true,
                true,
                true,
                true,
                true,
                approvalPolicy,
                Set.of("unit-tests", "security-scan")
        );

        repository.protectBranch(protection);

        PullRequest eligible = new PullRequest(
                101,
                "feature/preimage",
                "main",
                commit.id(),
                PullRequestState.OPEN,
                List.of(
                        new Review("alice", ReviewState.APPROVED, false),
                        new Review("bob", ReviewState.APPROVED, false)
                ),
                List.of(
                        new StatusCheck("unit-tests", CheckState.PASSING),
                        new StatusCheck("security-scan", CheckState.PASSING)
                ),
                true,
                true
        );

        MergeEligibilityService eligibility =
                new MergeEligibilityService(repository);

        printResult(
                "Eligible repository change",
                eligibility.evaluate(eligible)
        );

        PullRequest blocked = new PullRequest(
                102,
                "feature/preimage",
                "main",
                commit.id(),
                PullRequestState.OPEN,
                List.of(
                        new Review("alice", ReviewState.APPROVED, true),
                        new Review("disabled", ReviewState.APPROVED, false)
                ),
                List.of(
                        new StatusCheck("unit-tests", CheckState.PASSING),
                        new StatusCheck("security-scan", CheckState.FAILING)
                ),
                false,
                false
        );

        printResult(
                "Blocked repository change",
                eligibility.evaluate(blocked)
        );

        demonstrateHashProperty();

        System.out.println("\n=== Engineering boundaries ===");
        System.out.println(
                "Preimage resistance is a property of the hash construction "
                        + "and its output size."
        );
        System.out.println(
                "Approval policy is separate from cryptographic integrity."
        );
        System.out.println(
                "Branch protection consumes repository evidence; it does "
                        + "not make a hash cryptographically stronger."
        );
        System.out.println(
                "Password verification should use a dedicated password KDF "
                        + "rather than a single fast SHA-256 operation."
        );
    }
}
