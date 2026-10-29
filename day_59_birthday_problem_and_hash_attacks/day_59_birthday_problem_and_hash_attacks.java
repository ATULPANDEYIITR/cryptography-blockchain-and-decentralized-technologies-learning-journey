import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class BirthdayHashGovernance {

    enum PullRequestState {
        DRAFT, OPEN, BLOCKED, ELIGIBLE, MERGED, CLOSED
    }

    enum ReviewState {
        APPROVED, CHANGES_REQUESTED, COMMENTED
    }

    enum CheckState {
        PASS, FAIL, PENDING
    }

    enum RiskLevel {
        LOW, MODERATE, HIGH, CRITICAL
    }

    record Review(String reviewer, ReviewState state) {
        Review {
            if (reviewer == null || reviewer.isBlank()) {
                throw new IllegalArgumentException("reviewer is required");
            }
            if (state == null) {
                throw new IllegalArgumentException("review state is required");
            }
        }
    }

    record StatusCheck(String name, CheckState state) {
        StatusCheck {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("check name is required");
            }
            if (state == null) {
                throw new IllegalArgumentException("check state is required");
            }
        }
    }

    record BranchPolicy(
            int requiredApprovals,
            boolean requireSuccessfulChecks,
            boolean requireResolvedConversations,
            boolean requireLinearHistory,
            boolean allowDirectPush,
            boolean allowForcePush
    ) {
        BranchPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException("approval requirement cannot be negative");
            }
        }
    }

    static final class PullRequest {
        private final long id;
        private final String sourceBranch;
        private final String targetBranch;
        private final List<String> commits;
        private final List<Review> reviews = new ArrayList<>();
        private final List<StatusCheck> checks = new ArrayList<>();

        private PullRequestState state;
        private boolean conversationsResolved;
        private boolean branchSynchronized;
        private boolean mergeConflict;
        private boolean linearHistory;

        PullRequest(
                long id,
                String sourceBranch,
                String targetBranch,
                List<String> commits
        ) {
            if (id <= 0) {
                throw new IllegalArgumentException("invalid pull request ID");
            }
            if (sourceBranch == null || sourceBranch.isBlank()
                    || targetBranch == null || targetBranch.isBlank()) {
                throw new IllegalArgumentException("branches are required");
            }
            if (sourceBranch.equals(targetBranch)) {
                throw new IllegalArgumentException("source and target must differ");
            }
            if (commits == null || commits.isEmpty()) {
                throw new IllegalArgumentException("at least one commit is required");
            }

            this.id = id;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.commits = List.copyOf(commits);
            this.state = PullRequestState.DRAFT;
        }

        void publish() {
            requireState(PullRequestState.DRAFT);
            state = PullRequestState.OPEN;
        }

        void addReview(Review review) {
            if (state == PullRequestState.MERGED
                    || state == PullRequestState.CLOSED) {
                throw new IllegalStateException("closed PR cannot receive reviews");
            }
            reviews.add(review);
        }

        void addCheck(StatusCheck check) {
            checks.add(check);
        }

        void setConversationsResolved(boolean value) {
            conversationsResolved = value;
        }

        void setBranchSynchronized(boolean value) {
            branchSynchronized = value;
        }

        void setMergeConflict(boolean value) {
            mergeConflict = value;
        }

        void setLinearHistory(boolean value) {
            linearHistory = value;
        }

        void merge() {
            requireState(PullRequestState.ELIGIBLE);
            state = PullRequestState.MERGED;
        }

        void setState(PullRequestState newState) {
            state = newState;
        }

        PullRequestState state() {
            return state;
        }

        List<Review> reviews() {
            return List.copyOf(reviews);
        }

        List<StatusCheck> checks() {
            return List.copyOf(checks);
        }

        boolean conversationsResolved() {
            return conversationsResolved;
        }

        boolean branchSynchronized() {
            return branchSynchronized;
        }

        boolean mergeConflict() {
            return mergeConflict;
        }

        boolean linearHistory() {
            return linearHistory;
        }

        private void requireState(PullRequestState expected) {
            if (state != expected) {
                throw new IllegalStateException(
                        "expected " + expected + " but was " + state
                );
            }
        }

        @Override
        public String toString() {
            return "PR#" + id + " " + sourceBranch + " -> " + targetBranch
                    + " state=" + state;
        }
    }

    static final class MergeEligibilityService {
        private final BranchPolicy policy;

        MergeEligibilityService(BranchPolicy policy) {
            this.policy = policy;
        }

        boolean evaluate(PullRequest pr) {
            if (pr.state() != PullRequestState.OPEN
                    && pr.state() != PullRequestState.BLOCKED) {
                return false;
            }

            if (!pr.branchSynchronized() || pr.mergeConflict()) {
                return false;
            }

            if (policy.requireResolvedConversations()
                    && !pr.conversationsResolved()) {
                return false;
            }

            if (policy.requireLinearHistory() && !pr.linearHistory()) {
                return false;
            }

            if (!reviewsSatisfied(pr)) {
                return false;
            }

            return checksSatisfied(pr);
        }

        void updateState(PullRequest pr) {
            pr.setState(
                    evaluate(pr)
                            ? PullRequestState.ELIGIBLE
                            : PullRequestState.BLOCKED
            );
        }

        private boolean reviewsSatisfied(PullRequest pr) {
            Map<String, ReviewState> latestByReviewer = new HashMap<>();

            for (Review review : pr.reviews()) {
                latestByReviewer.put(review.reviewer(), review.state());
            }

            Set<String> approved = new HashSet<>();

            for (Map.Entry<String, ReviewState> entry : latestByReviewer.entrySet()) {
                if (entry.getValue() == ReviewState.APPROVED) {
                    approved.add(entry.getKey());
                }
            }

            boolean changesRequested = latestByReviewer.values()
                    .stream()
                    .anyMatch(state -> state == ReviewState.CHANGES_REQUESTED);

            return !changesRequested && approved.size() >= policy.requiredApprovals();
        }

        private boolean checksSatisfied(PullRequest pr) {
            if (!policy.requireSuccessfulChecks()) {
                return true;
            }

            return !pr.checks().isEmpty()
                    && pr.checks().stream()
                    .allMatch(check -> check.state() == CheckState.PASS);
        }
    }

    static final class HashSecurity {
        private HashSecurity() {
        }

        static double birthdayProbability(long samples, int bits) {
            if (samples < 0 || bits <= 0 || bits > 62) {
                throw new IllegalArgumentException("unsupported probability parameters");
            }

            double space = Math.scalb(1.0, bits);

            if (samples <= 1) {
                return 0.0;
            }

            if (samples >= space) {
                return 1.0;
            }

            double logNoCollision = 0.0;
            for (long i = 0; i < samples; i++) {
                logNoCollision += Math.log1p(-i / space);
            }

            return -Math.expm1(logNoCollision);
        }

        static double approximateBirthdayProbability(long samples, int bits) {
            if (samples < 0 || bits <= 0) {
                throw new IllegalArgumentException("invalid parameters");
            }

            double space = Math.pow(2.0, bits);
            double exponent =
                    -(samples * (double) (samples - 1)) / (2.0 * space);

            return -Math.expm1(exponent);
        }

        static RiskLevel riskFor(int digestBits) {
            double collisionBits = digestBits / 2.0;

            if (collisionBits < 64) return RiskLevel.CRITICAL;
            if (collisionBits < 96) return RiskLevel.HIGH;
            if (collisionBits < 128) return RiskLevel.MODERATE;
            return RiskLevel.LOW;
        }

        static byte[] sha256(byte[] input) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(input);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException("SHA-256 unavailable", ex);
            }
        }

        static String truncatedDigest(byte[] input, int bits) {
            if (bits < 8 || bits > 256) {
                throw new IllegalArgumentException("bits must be 8..256");
            }

            byte[] digest = sha256(input);
            int bytes = (bits + 7) / 8;
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < bytes; i++) {
                int value = digest[i] & 0xff;

                if (i == bytes - 1 && bits % 8 != 0) {
                    value &= 0xff << (8 - bits % 8);
                }

                result.append(String.format("%02x", value));
            }

            return result.toString();
        }

        static void demonstrateCollision(int bits, int maxAttempts) {
            SecureRandom random = new SecureRandom();
            Map<String, byte[]> seen = new HashMap<>();

            for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                byte[] candidate = new byte[16];
                random.nextBytes(candidate);

                String digest = truncatedDigest(candidate, bits);

                if (seen.containsKey(digest)) {
                    byte[] first = seen.get(digest);

                    if (!java.util.Arrays.equals(first, candidate)) {
                        System.out.println("Collision attempts: " + attempt);
                        System.out.println("Digest prefix: " + digest);
                        System.out.println("Input A: " + hex(first));
                        System.out.println("Input B: " + hex(candidate));
                        return;
                    }
                }

                seen.put(digest, candidate);
            }

            throw new IllegalStateException("collision not found within attempt limit");
        }

        private static String hex(byte[] value) {
            StringBuilder result = new StringBuilder();
            for (byte b : value) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        }
    }

    private static void assertions() {
        double birthday = HashSecurity.birthdayProbability(23, 8 + 1 + 8 + 8);
        if (birthday <= 0) {
            throw new AssertionError("birthday probability must be positive");
        }

        BranchPolicy policy = new BranchPolicy(2, true, true, true, false, false);
        PullRequest pr = new PullRequest(
                501,
                "feature/hash-policy",
                "main",
                List.of("c01", "c02")
        );

        pr.publish();
        pr.addReview(new Review("alice", ReviewState.APPROVED));
        pr.addReview(new Review("bob", ReviewState.APPROVED));
        pr.addCheck(new StatusCheck("tests", CheckState.PASS));
        pr.addCheck(new StatusCheck("security", CheckState.PASS));
        pr.setConversationsResolved(true);
        pr.setBranchSynchronized(true);
        pr.setLinearHistory(true);

        MergeEligibilityService service = new MergeEligibilityService(policy);
        service.updateState(pr);

        if (pr.state() != PullRequestState.ELIGIBLE) {
            throw new AssertionError("valid PR should be eligible");
        }
    }

    public static void main(String[] args) {
        try {
            assertions();

            System.out.println("Birthday problem");
            System.out.printf(
                    "23 samples in 365 equally likely outcomes: %.6f%n",
                    HashSecurity.birthdayProbability(23, 9)
            );

            System.out.println("\nHash collision security");
            for (int bits : List.of(64, 128, 160, 256)) {
                System.out.printf(
                        "%d-bit digest -> approximately %.0f collision-security bits -> %s%n",
                        bits,
                        bits / 2.0,
                        HashSecurity.riskFor(bits)
                );
            }

            System.out.println("\nControlled truncated SHA-256 collision");
            HashSecurity.demonstrateCollision(16, 100_000);

            System.out.println("\nEnterprise repository governance");
            BranchPolicy policy = new BranchPolicy(
                    2,
                    true,
                    true,
                    true,
                    false,
                    false
            );

            PullRequest pr = new PullRequest(
                    9001,
                    "feature/crypto-audit",
                    "main",
                    List.of("a1b2c3", "d4e5f6", "789abc")
            );

            pr.publish();
            pr.addReview(new Review("reviewer-a", ReviewState.APPROVED));
            pr.addReview(new Review("reviewer-b", ReviewState.APPROVED));
            pr.addCheck(new StatusCheck("unit-tests", CheckState.PASS));
            pr.addCheck(new StatusCheck("dependency-audit", CheckState.PASS));
            pr.addCheck(new StatusCheck("security-scan", CheckState.PASS));
            pr.setConversationsResolved(true);
            pr.setBranchSynchronized(true);
            pr.setLinearHistory(true);

            MergeEligibilityService service =
                    new MergeEligibilityService(policy);

            service.updateState(pr);
            System.out.println(pr);

            pr.setMergeConflict(true);
            service.updateState(pr);
            System.out.println("After conflict: " + pr.state());

            pr.setMergeConflict(false);
            pr.setLinearHistory(true);
            service.updateState(pr);
            System.out.println("After conflict resolution: " + pr.state());

            if (pr.state() == PullRequestState.ELIGIBLE) {
                pr.merge();
            }

            System.out.println("Final state: " + pr.state());

            System.out.println("\nSecurity controls");
            System.out.println("- Collision security is approximately half the digest length.");
            System.out.println("- Truncation reduces the collision search space.");
            System.out.println("- Latest reviewer state is used to avoid counting stale approvals.");
            System.out.println("- Governance checks are evaluated against current repository state.");
            System.out.println("- Direct pushes and force pushes can be prohibited independently of review policy.");

        } catch (RuntimeException ex) {
            System.err.println("Execution failed: " + ex.getMessage());
            System.exit(1);
        }
    }
}
