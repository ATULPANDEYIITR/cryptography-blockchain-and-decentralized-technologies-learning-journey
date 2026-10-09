import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/*
 * AES key lifecycle and enterprise release-signing service.
 *
 * Compile and run:
 *   javac AesKeysRounds.java
 *   java AesKeysRounds
 *
 * Java's standard cryptographic provider implements the actual AES primitive.
 * The program models key-size rules, round metadata, authenticated encryption,
 * release policies, and explicit approval and status-check requirements.
 */

public class AesKeysRounds {

    enum KeySize {
        AES_128(16, 10),
        AES_192(24, 12),
        AES_256(32, 14);

        private final int bytes;
        private final int rounds;

        KeySize(int bytes, int rounds) {
            this.bytes = bytes;
            this.rounds = rounds;
        }

        public int bytes() {
            return bytes;
        }

        public int rounds() {
            return rounds;
        }

        public int bits() {
            return bytes * 8;
        }

        public static KeySize fromBytes(int bytes) {
            return Arrays.stream(values())
                    .filter(size -> size.bytes == bytes)
                    .findFirst()
                    .orElseThrow(() ->
                            new IllegalArgumentException(
                                    "AES requires 16, 24, or 32 key bytes."
                            ));
        }
    }

    enum ReviewDecision {
        COMMENTED,
        APPROVED,
        CHANGES_REQUESTED
    }

    enum CheckState {
        PENDING,
        PASSED,
        FAILED
    }

    enum PullRequestState {
        DRAFT,
        OPEN,
        MERGED,
        CLOSED
    }

    record Reviewer(String id, boolean eligible, boolean author) {
        Reviewer {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Reviewer ID is required.");
            }
        }
    }

    record Review(String reviewerId, ReviewDecision decision, String commitId) {
        Review {
            Objects.requireNonNull(reviewerId);
            Objects.requireNonNull(decision);
            if (commitId == null || commitId.isBlank()) {
                throw new IllegalArgumentException("Reviewed commit is required.");
            }
        }
    }

    record StatusCheck(String name, CheckState state) {
        StatusCheck {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Check name is required.");
            }
            Objects.requireNonNull(state);
        }
    }

    record BranchProtection(
            int requiredApprovals,
            Set<String> requiredChecks,
            boolean requireConversationResolution,
            boolean requireLinearHistory,
            boolean allowDirectPush,
            boolean allowForcePush,
            boolean allowDeletion,
            boolean administratorBypass
    ) {
        BranchProtection {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                        "Required approval count cannot be negative."
                );
            }
            requiredChecks = Set.copyOf(requiredChecks);
        }
    }

    record PullRequest(
            String id,
            String repository,
            String sourceBranch,
            String targetBranch,
            String headCommit,
            PullRequestState state,
            boolean conversationsResolved,
            boolean linearHistory,
            boolean authorIsAdministrator,
            List<Review> reviews,
            List<StatusCheck> checks
    ) {
        PullRequest {
            for (String field : List.of(
                    id, repository, sourceBranch, targetBranch, headCommit)) {
                if (field == null || field.isBlank()) {
                    throw new IllegalArgumentException(
                            "Pull Request identity fields cannot be empty."
                    );
                }
            }

            if (sourceBranch.equals(targetBranch)) {
                throw new IllegalArgumentException(
                        "Source and target branches must differ."
                );
            }

            Objects.requireNonNull(state);
            reviews = List.copyOf(reviews);
            checks = List.copyOf(checks);
        }
    }

    record Eligibility(boolean eligible, List<String> reasons) {
        Eligibility {
            reasons = List.copyOf(reasons);
        }
    }

    static final class MergeEligibilityService {

        Eligibility evaluate(
                PullRequest pullRequest,
                BranchProtection policy,
                List<Reviewer> reviewers
        ) {
            List<String> reasons = new ArrayList<>();

            if (pullRequest.state() != PullRequestState.OPEN) {
                reasons.add("Pull Request must be open and not a draft.");
            }

            if (!pullRequest.conversationsResolved()
                    && policy.requireConversationResolution()) {
                reasons.add("Unresolved review conversations remain.");
            }

            if (!pullRequest.linearHistory() && policy.requireLinearHistory()) {
                reasons.add("Target branch requires linear history.");
            }

            if (!pullRequest.authorIsAdministrator()
                    && !policy.allowDirectPush()) {
                // Direct pushes are separately governed. This condition does
                // not reject a PR; the PR itself is the proposed merge path.
            }

            List<Reviewer> eligibleReviewers = reviewers.stream()
                    .filter(Reviewer::eligible)
                    .filter(reviewer -> !reviewer.author())
                    .toList();

            Set<String> eligibleIds = eligibleReviewers.stream()
                    .map(Reviewer::id)
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());

            Set<String> currentCommitApprovers = new java.util.HashSet<>();
            Set<String> currentCommitChangeRequests = new java.util.HashSet<>();

            for (Review review : pullRequest.reviews()) {
                if (!eligibleIds.contains(review.reviewerId())) {
                    continue;
                }

                // A review on an older commit does not count after the
                // Pull Request head changes. This models stale approvals.
                if (!review.commitId().equals(pullRequest.headCommit())) {
                    continue;
                }

                switch (review.decision()) {
                    case APPROVED ->
                            currentCommitApprovers.add(review.reviewerId());
                    case CHANGES_REQUESTED ->
                            currentCommitChangeRequests.add(review.reviewerId());
                    case COMMENTED -> {
                        // A comment is not an approval decision.
                    }
                }
            }

            if (!currentCommitChangeRequests.isEmpty()) {
                reasons.add("Eligible reviewers have requested changes.");
            }

            if (currentCommitApprovers.size() < policy.requiredApprovals()) {
                reasons.add(
                        "Insufficient current-commit approvals: "
                                + currentCommitApprovers.size()
                                + " of " + policy.requiredApprovals() + "."
                );
            }

            java.util.Map<String, CheckState> latestChecks =
                    new java.util.HashMap<>();

            for (StatusCheck check : pullRequest.checks()) {
                latestChecks.put(check.name(), check.state());
            }

            for (String required : policy.requiredChecks()) {
                if (latestChecks.get(required) != CheckState.PASSED) {
                    reasons.add("Required status check is not passing: " + required);
                }
            }

            // A bypass is an explicit governance exception, not ordinary
            // approval. Production policy should identify authorized actors.
            if (pullRequest.authorIsAdministrator()
                    && policy.administratorBypass()) {
                return new Eligibility(true, List.of(
                        "Eligible through configured administrator bypass."
                ));
            }

            return new Eligibility(reasons.isEmpty(), reasons);
        }
    }

    static final class AesGcmService {
        private final SecretKeySpec key;
        private final KeySize keySize;
        private final SecureRandom random = new SecureRandom();

        AesGcmService(byte[] rawKey) {
            Objects.requireNonNull(rawKey);
            this.keySize = KeySize.fromBytes(rawKey.length);
            this.key = new SecretKeySpec(rawKey.clone(), "AES");
        }

        byte[] encrypt(byte[] plaintext, byte[] associatedData)
                throws GeneralSecurityException {
            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    key,
                    new GCMParameterSpec(128, nonce)
            );
            cipher.updateAAD(associatedData);

            byte[] ciphertextAndTag = cipher.doFinal(plaintext);
            byte[] envelope = new byte[nonce.length + ciphertextAndTag.length];

            System.arraycopy(nonce, 0, envelope, 0, nonce.length);
            System.arraycopy(
                    ciphertextAndTag, 0, envelope, nonce.length,
                    ciphertextAndTag.length
            );

            return envelope;
        }

        byte[] decrypt(byte[] envelope, byte[] associatedData)
                throws GeneralSecurityException {
            if (envelope == null || envelope.length < 12 + 16) {
                throw new IllegalArgumentException("Malformed AES-GCM envelope.");
            }

            byte[] nonce = Arrays.copyOfRange(envelope, 0, 12);
            byte[] ciphertextAndTag = Arrays.copyOfRange(
                    envelope, 12, envelope.length
            );

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(128, nonce)
            );
            cipher.updateAAD(associatedData);

            // doFinal verifies the GCM authentication tag before returning
            // plaintext. Authentication failures raise a security exception.
            return cipher.doFinal(ciphertextAndTag);
        }

        KeySize keySize() {
            return keySize;
        }
    }

    private static byte[] fromHex(String hex) {
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex input length must be even.");
        }

        byte[] bytes = new byte[hex.length() / 2];

        for (int index = 0; index < bytes.length; index++) {
            int high = Character.digit(hex.charAt(index * 2), 16);
            int low = Character.digit(hex.charAt(index * 2 + 1), 16);

            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hexadecimal input.");
            }

            bytes[index] = (byte) ((high << 4) | low);
        }

        return bytes;
    }

    private static String toHex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private static void demonstrateKeySizes() {
        System.out.println("AES key sizes and round counts");

        for (KeySize size : KeySize.values()) {
            System.out.printf(
                    "%s: %d-bit key, %d rounds, %d round keys%n",
                    size.name().replace('_', '-'),
                    size.bits(),
                    size.rounds(),
                    size.rounds() + 1
            );
        }
    }

    private static void demonstrateBlockVector() throws Exception {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = fromHex("00112233445566778899aabbccddeeff");
        byte[] expected = fromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES")
        );

        byte[] ciphertext = cipher.doFinal(plaintext);

        if (!Arrays.equals(ciphertext, expected)) {
            throw new IllegalStateException("AES known-answer test failed.");
        }

        System.out.println("\nAES-128 known-answer test passed.");
        System.out.println("Ciphertext: " + toHex(ciphertext));
    }

    private static void demonstrateReleasePolicy() {
        BranchProtection protection = new BranchProtection(
                2,
                Set.of("unit-tests", "security-scan"),
                true,
                true,
                false,
                false,
                false,
                false
        );

        String head = "a91d42f";

        List<Reviewer> reviewers = List.of(
                new Reviewer("reviewer-alex", true, false),
                new Reviewer("reviewer-priya", true, false),
                new Reviewer("author-sam", true, true),
                new Reviewer("external-bot", false, false)
        );

        PullRequest request = new PullRequest(
                "PR-842",
                "payments-api",
                "feature/aes-key-rotation",
                "main",
                head,
                PullRequestState.OPEN,
                true,
                true,
                false,
                List.of(
                        new Review("reviewer-alex", ReviewDecision.APPROVED, head),
                        new Review("reviewer-priya", ReviewDecision.APPROVED, head),
                        new Review("author-sam", ReviewDecision.APPROVED, head),
                        new Review("external-bot", ReviewDecision.APPROVED, head)
                ),
                List.of(
                        new StatusCheck("unit-tests", CheckState.PASSED),
                        new StatusCheck("security-scan", CheckState.PASSED)
                )
        );

        MergeEligibilityService service = new MergeEligibilityService();
        Eligibility eligible = service.evaluate(request, protection, reviewers);

        System.out.println("\nRepository release governance");
        System.out.println("Eligible: " + eligible.eligible());
        eligible.reasons().forEach(reason -> System.out.println("Blocked: " + reason));

        PullRequest staleRequest = new PullRequest(
                request.id(),
                request.repository(),
                request.sourceBranch(),
                request.targetBranch(),
                "b80f631",
                request.state(),
                request.conversationsResolved(),
                request.linearHistory(),
                request.authorIsAdministrator(),
                request.reviews(),
                request.checks()
        );

        Eligibility staleResult = service.evaluate(
                staleRequest, protection, reviewers
        );

        if (staleResult.eligible()) {
            throw new IllegalStateException(
                    "Approvals for the previous commit must not satisfy the policy."
            );
        }

        System.out.println("Stale approvals rejected after the head commit changed.");
    }

    private static void demonstrateAuthenticatedEncryption() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        AesGcmService service = new AesGcmService(key);
        byte[] message = "release manifest".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "repository:payments-api".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = service.encrypt(message, aad);
        byte[] recovered = service.decrypt(envelope, aad);

        if (!Arrays.equals(message, recovered)) {
            throw new IllegalStateException("AES-GCM round trip failed.");
        }

        envelope[envelope.length - 1] ^= 1;

        try {
            service.decrypt(envelope, aad);
            throw new IllegalStateException(
                    "Tampered ciphertext was incorrectly accepted."
            );
        } catch (GeneralSecurityException expected) {
            System.out.println("AES-GCM rejected tampered release metadata.");
        }

        System.out.println(
                "Authenticated encryption uses AES-"
                        + service.keySize().bits()
                        + " with a 96-bit nonce and 128-bit tag."
        );
    }

    public static void main(String[] args) throws Exception {
        demonstrateKeySizes();
        demonstrateBlockVector();
        demonstrateReleasePolicy();
        demonstrateAuthenticatedEncryption();
    }
}
