import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;

/**
 * Enterprise-oriented AES-GCM example.
 *
 * The domain models encrypted repository-governance records. AES-GCM is used
 * because it provides confidentiality and integrity together.
 */
public class AesRepositorySecurityDemo {

    enum PullRequestState {
        DRAFT,
        OPEN,
        APPROVED,
        CHANGES_REQUESTED,
        MERGED,
        CLOSED
    }

    enum ReviewDecision {
        APPROVED,
        CHANGES_REQUESTED,
        COMMENTED
    }

    record RepositoryPolicy(
            String repository,
            String protectedBranch,
            int requiredApprovals,
            boolean requirePassingChecks,
            boolean allowForcePush
    ) {
        RepositoryPolicy {
            if (repository == null || repository.isBlank()) {
                throw new IllegalArgumentException("Repository is required.");
            }
            if (protectedBranch == null || protectedBranch.isBlank()) {
                throw new IllegalArgumentException("Protected branch is required.");
            }
            if (requiredApprovals < 1) {
                throw new IllegalArgumentException("At least one approval is required.");
            }
            if (allowForcePush) {
                throw new IllegalArgumentException(
                        "This governance policy does not permit force pushes."
                );
            }
        }
    }

    record Review(
            String reviewer,
            ReviewDecision decision,
            String commitId
    ) {
        Review {
            if (reviewer == null || reviewer.isBlank()) {
                throw new IllegalArgumentException("Reviewer is required.");
            }
            if (commitId == null || commitId.isBlank()) {
                throw new IllegalArgumentException("Review must identify a commit.");
            }
        }
    }

    static final class PullRequest {
        private final String id;
        private final String sourceBranch;
        private final String targetBranch;
        private final String headCommit;
        private PullRequestState state;
        private final Map<String, Review> reviews = new java.util.HashMap<>();

        PullRequest(
                String id,
                String sourceBranch,
                String targetBranch,
                String headCommit
        ) {
            if (id == null || sourceBranch == null || targetBranch == null ||
                    headCommit == null || id.isBlank() || sourceBranch.isBlank() ||
                    targetBranch.isBlank() || headCommit.isBlank()) {
                throw new IllegalArgumentException("Pull Request fields cannot be blank.");
            }

            this.id = id;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.headCommit = headCommit;
            this.state = PullRequestState.OPEN;
        }

        void submitReview(Review review) {
            if (state == PullRequestState.MERGED || state == PullRequestState.CLOSED) {
                throw new IllegalStateException(
                        "A merged or closed Pull Request cannot receive a new review."
                );
            }

            reviews.put(review.reviewer(), review);

            if (review.decision() == ReviewDecision.CHANGES_REQUESTED) {
                state = PullRequestState.CHANGES_REQUESTED;
            } else if (review.decision() == ReviewDecision.APPROVED) {
                state = PullRequestState.APPROVED;
            }
        }

        long approvalsForCurrentCommit() {
            return reviews.values()
                    .stream()
                    .filter(review -> review.commitId().equals(headCommit))
                    .filter(review -> review.decision() == ReviewDecision.APPROVED)
                    .count();
        }

        boolean hasCurrentCommitChangesRequested() {
            return reviews.values()
                    .stream()
                    .anyMatch(review ->
                            review.commitId().equals(headCommit) &&
                            review.decision() == ReviewDecision.CHANGES_REQUESTED
                    );
        }

        void markMerged() {
            if (state != PullRequestState.APPROVED) {
                throw new IllegalStateException(
                        "A Pull Request must be approved before it can be marked merged."
                );
            }
            state = PullRequestState.MERGED;
        }

        String id() {
            return id;
        }

        String sourceBranch() {
            return sourceBranch;
        }

        String targetBranch() {
            return targetBranch;
        }

        PullRequestState state() {
            return state;
        }
    }

    static final class MergeEligibilityService {

        boolean isEligible(
                PullRequest pullRequest,
                RepositoryPolicy policy,
                boolean checksPassed,
                boolean mergeConflict
        ) {
            if (!pullRequest.targetBranch().equals(policy.protectedBranch())) {
                return false;
            }

            if (!checksPassed || mergeConflict) {
                return false;
            }

            if (pullRequest.hasCurrentCommitChangesRequested()) {
                return false;
            }

            return pullRequest.approvalsForCurrentCommit()
                    >= policy.requiredApprovals();
        }
    }

    record EncryptedRecord(
            String algorithm,
            String iv,
            String ciphertext,
            String associatedData
    ) {}

    static final class AesGcmService {
        private static final int KEY_SIZE = 256;
        private static final int IV_SIZE = 12;
        private static final int TAG_SIZE = 128;

        private final SecureRandom secureRandom = new SecureRandom();

        SecretKey generateKey() throws GeneralSecurityException {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(KEY_SIZE);
            return generator.generateKey();
        }

        EncryptedRecord encrypt(
                String plaintext,
                SecretKey key,
                String associatedData
        ) throws GeneralSecurityException {
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    key,
                    new GCMParameterSpec(TAG_SIZE, iv)
            );

            if (associatedData != null) {
                cipher.updateAAD(
                        associatedData.getBytes(StandardCharsets.UTF_8)
                );
            }

            byte[] encrypted = cipher.doFinal(
                    plaintext.getBytes(StandardCharsets.UTF_8)
            );

            return new EncryptedRecord(
                    "AES-256-GCM",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(iv),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted),
                    associatedData
            );
        }

        String decrypt(
                EncryptedRecord record,
                SecretKey key
        ) throws GeneralSecurityException {
            if (!"AES-256-GCM".equals(record.algorithm())) {
                throw new GeneralSecurityException("Unsupported AES algorithm.");
            }

            byte[] iv = Base64.getUrlDecoder().decode(record.iv());
            byte[] encrypted =
                    Base64.getUrlDecoder().decode(record.ciphertext());

            if (iv.length != IV_SIZE) {
                throw new GeneralSecurityException("Invalid GCM IV length.");
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(TAG_SIZE, iv)
            );

            if (record.associatedData() != null) {
                cipher.updateAAD(
                        record.associatedData().getBytes(StandardCharsets.UTF_8)
                );
            }

            byte[] plaintext = cipher.doFinal(encrypted);
            return new String(plaintext, StandardCharsets.UTF_8);
        }
    }

    private static String governancePayload(
            PullRequest pullRequest,
            RepositoryPolicy policy
    ) {
        return String.format(
                "pr=%s;source=%s;target=%s;state=%s;requiredApprovals=%d",
                pullRequest.id(),
                pullRequest.sourceBranch(),
                pullRequest.targetBranch(),
                pullRequest.state(),
                policy.requiredApprovals()
        );
    }

    public static void main(String[] args) throws Exception {
        RepositoryPolicy policy = new RepositoryPolicy(
                "security-platform",
                "main",
                2,
                true,
                false
        );

        PullRequest pullRequest = new PullRequest(
                "PR-184",
                "feature/encrypted-audit",
                "main",
                "abc123"
        );

        pullRequest.submitReview(
                new Review("reviewer-a", ReviewDecision.APPROVED, "abc123")
        );

        pullRequest.submitReview(
                new Review("reviewer-b", ReviewDecision.APPROVED, "abc123")
        );

        MergeEligibilityService eligibilityService =
                new MergeEligibilityService();

        boolean eligible = eligibilityService.isEligible(
                pullRequest,
                policy,
                true,
                false
        );

        System.out.println("Repository governance");
        System.out.println("---------------------");
        System.out.println("Pull Request: " + pullRequest.id());
        System.out.println("Approvals: " + pullRequest.approvalsForCurrentCommit());
        System.out.println("Merge eligible: " + eligible);

        if (eligible) {
            pullRequest.markMerged();
        }

        System.out.println("Final state: " + pullRequest.state());

        AesGcmService encryptionService = new AesGcmService();
        SecretKey key = encryptionService.generateKey();

        String payload = governancePayload(pullRequest, policy);
        String aad = "repository=security-platform;branch=main";

        EncryptedRecord encrypted = encryptionService.encrypt(
                payload,
                key,
                aad
        );

        System.out.println("\nAES-GCM encryption");
        System.out.println("------------------");
        System.out.println("Algorithm : " + encrypted.algorithm());
        System.out.println("IV        : " + encrypted.iv());
        System.out.println("Ciphertext: " + encrypted.ciphertext());

        String recovered = encryptionService.decrypt(encrypted, key);

        System.out.println("Recovered : " + recovered);
        System.out.println("Round trip: " + payload.equals(recovered));

        EncryptedRecord tampered = new EncryptedRecord(
                encrypted.algorithm(),
                encrypted.iv(),
                encrypted.ciphertext().replaceFirst(".", "A"),
                encrypted.associatedData()
        );

        try {
            encryptionService.decrypt(tampered, key);
            System.out.println("Unexpected: tampered data accepted.");
        } catch (GeneralSecurityException error) {
            System.out.println(
                    "Tampered ciphertext rejected: authentication failure."
            );
        }

        PullRequest staleApprovalExample = new PullRequest(
                "PR-185",
                "feature/policy-change",
                "main",
                "new456"
        );

        staleApprovalExample.submitReview(
                new Review("reviewer-a", ReviewDecision.APPROVED, "old999")
        );

        boolean staleApprovalEligible = eligibilityService.isEligible(
                staleApprovalExample,
                policy,
                true,
                false
        );

        System.out.println("\nStale approval example");
        System.out.println("----------------------");
        System.out.println(
                "Approval attached to old commit accepted: "
                        + staleApprovalEligible
        );
    }
}
