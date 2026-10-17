/*
 * Authenticated Encryption Enterprise Repository Governance Model
 *
 * Java 17+
 *
 * Uses the standard JCA/JCE AES/GCM implementation.
 * No third-party dependencies are required.
 */

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class AuthenticatedEncryptionGovernance {

    private static final int AES_KEY_BITS = 256;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    enum PullRequestState {
        DRAFT,
        OPEN,
        CHANGES_REQUESTED,
        APPROVED,
        MERGEABLE,
        MERGED,
        CLOSED
    }

    enum ReviewState {
        COMMENTED,
        CHANGES_REQUESTED,
        APPROVED,
        DISMISSED
    }

    enum StatusCheck {
        UNIT_TESTS,
        SECURITY_SCAN,
        POLICY_VALIDATION
    }

    record Review(
        String reviewer,
        ReviewState state,
        String comment
    ) {
        Review {
            Objects.requireNonNull(reviewer);
            Objects.requireNonNull(state);
            Objects.requireNonNull(comment);

            if (reviewer.isBlank()) {
                throw new IllegalArgumentException(
                    "Reviewer identity cannot be blank"
                );
            }
        }
    }

    record PullRequest(
        int number,
        String sourceBranch,
        String targetBranch,
        PullRequestState state,
        List<Review> reviews,
        Set<StatusCheck> passedChecks,
        Set<StatusCheck> requiredChecks,
        boolean mergeConflict
    ) {
        PullRequest {
            if (number <= 0) {
                throw new IllegalArgumentException(
                    "Pull Request number must be positive"
                );
            }

            Objects.requireNonNull(sourceBranch);
            Objects.requireNonNull(targetBranch);
            Objects.requireNonNull(state);
            Objects.requireNonNull(reviews);
            Objects.requireNonNull(passedChecks);
            Objects.requireNonNull(requiredChecks);

            if (sourceBranch.equals(targetBranch)) {
                throw new IllegalArgumentException(
                    "Source and target branches must differ"
                );
            }
        }
    }

    record BranchProtectionPolicy(
        String branchName,
        int requiredApprovals,
        Set<StatusCheck> requiredChecks,
        boolean requireConversationResolution,
        boolean allowForcePush,
        boolean allowDeletion
    ) {
        BranchProtectionPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                    "Required approvals cannot be negative"
                );
            }

            if (branchName.isBlank()) {
                throw new IllegalArgumentException(
                    "Protected branch name cannot be blank"
                );
            }

            if (allowForcePush) {
                /*
                 * The enterprise policy intentionally rejects force pushes
                 * because protected-history integrity is part of governance.
                 */
                throw new IllegalArgumentException(
                    "This policy does not permit force pushes"
                );
            }
        }
    }

    static final class EncryptedEnvelope {
        private final String keyId;
        private final byte[] nonce;
        private final byte[] ciphertextAndTag;
        private final byte[] associatedData;

        EncryptedEnvelope(
            String keyId,
            byte[] nonce,
            byte[] ciphertextAndTag,
            byte[] associatedData
        ) {
            this.keyId = Objects.requireNonNull(keyId);
            this.nonce = nonce.clone();
            this.ciphertextAndTag = ciphertextAndTag.clone();
            this.associatedData = associatedData.clone();
        }

        String keyId() {
            return keyId;
        }

        byte[] nonce() {
            return nonce.clone();
        }

        byte[] ciphertextAndTag() {
            return ciphertextAndTag.clone();
        }

        byte[] associatedData() {
            return associatedData.clone();
        }
    }

    static final class AesGcmService {
        private final String keyId;
        private final SecretKey secretKey;

        AesGcmService(String keyId, SecretKey secretKey) {
            this.keyId = Objects.requireNonNull(keyId);
            this.secretKey = Objects.requireNonNull(secretKey);
        }

        static AesGcmService generate(String keyId)
            throws GeneralSecurityException {

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(AES_KEY_BITS);

            return new AesGcmService(keyId, generator.generateKey());
        }

        EncryptedEnvelope encrypt(
            String repository,
            String artifact,
            String plaintext
        ) throws GeneralSecurityException {

            byte[] nonce = new byte[GCM_NONCE_BYTES];
            SECURE_RANDOM.nextBytes(nonce);

            byte[] aad = authenticatedMetadata(repository, artifact);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                new GCMParameterSpec(GCM_TAG_BITS, nonce)
            );

            cipher.updateAAD(aad);

            byte[] ciphertextAndTag =
                cipher.doFinal(
                    plaintext.getBytes(StandardCharsets.UTF_8)
                );

            return new EncryptedEnvelope(
                keyId,
                nonce,
                ciphertextAndTag,
                aad
            );
        }

        String decrypt(
            String expectedRepository,
            String expectedArtifact,
            EncryptedEnvelope envelope
        ) throws GeneralSecurityException {

            if (!keyId.equals(envelope.keyId())) {
                throw new SecurityException(
                    "Envelope was created under an untrusted key ID"
                );
            }

            byte[] expectedAad =
                authenticatedMetadata(
                    expectedRepository,
                    expectedArtifact
                );

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                new GCMParameterSpec(
                    GCM_TAG_BITS,
                    envelope.nonce()
                )
            );

            /*
             * AAD is supplied before decryption. A mismatch causes GCM
             * authentication failure during doFinal().
             */
            cipher.updateAAD(expectedAad);

            try {
                byte[] plaintext =
                    cipher.doFinal(envelope.ciphertextAndTag());

                return new String(
                    plaintext,
                    StandardCharsets.UTF_8
                );
            } catch (AEADBadTagException error) {
                throw new SecurityException(
                    "Authenticated decryption failed",
                    error
                );
            }
        }

        private static byte[] authenticatedMetadata(
            String repository,
            String artifact
        ) {
            return (
                "repository=" + repository +
                ";artifact=" + artifact
            ).getBytes(StandardCharsets.UTF_8);
        }
    }

    static final class MergeEligibilityService {

        boolean isEligible(
            PullRequest pullRequest,
            BranchProtectionPolicy policy
        ) {
            if (!pullRequest.targetBranch()
                    .equals(policy.branchName())) {
                return false;
            }

            if (pullRequest.state() == PullRequestState.DRAFT
                || pullRequest.state() == PullRequestState.CLOSED
                || pullRequest.state() == PullRequestState.MERGED) {
                return false;
            }

            if (pullRequest.mergeConflict()) {
                return false;
            }

            long activeApprovals =
                pullRequest.reviews()
                    .stream()
                    .filter(review ->
                        review.state() == ReviewState.APPROVED)
                    .map(Review::reviewer)
                    .distinct()
                    .count();

            if (activeApprovals < policy.requiredApprovals()) {
                return false;
            }

            if (!pullRequest.passedChecks()
                    .containsAll(policy.requiredChecks())) {
                return false;
            }

            return pullRequest.reviews()
                .stream()
                .noneMatch(review ->
                    review.state() == ReviewState.CHANGES_REQUESTED);
        }

        List<String> explain(
            PullRequest pullRequest,
            BranchProtectionPolicy policy
        ) {
            List<String> failures = new ArrayList<>();

            if (!pullRequest.targetBranch()
                    .equals(policy.branchName())) {
                failures.add("target branch is not the protected branch");
            }

            if (pullRequest.state() == PullRequestState.DRAFT) {
                failures.add("Pull Request is still a draft");
            }

            if (pullRequest.mergeConflict()) {
                failures.add("merge conflict exists");
            }

            long approvals =
                pullRequest.reviews()
                    .stream()
                    .filter(review ->
                        review.state() == ReviewState.APPROVED)
                    .map(Review::reviewer)
                    .distinct()
                    .count();

            if (approvals < policy.requiredApprovals()) {
                failures.add(
                    "required approvals are not satisfied"
                );
            }

            for (StatusCheck check : policy.requiredChecks()) {
                if (!pullRequest.passedChecks().contains(check)) {
                    failures.add(
                        "required check failed: " + check
                    );
                }
            }

            if (pullRequest.reviews()
                    .stream()
                    .anyMatch(review ->
                        review.state()
                            == ReviewState.CHANGES_REQUESTED)) {
                failures.add(
                    "an active reviewer requested changes"
                );
            }

            return List.copyOf(failures);
        }
    }

    static void demonstrateEncryption(
        AesGcmService encryption
    ) throws GeneralSecurityException {

        System.out.println("\n=== Authenticated encryption ===");

        EncryptedEnvelope envelope =
            encryption.encrypt(
                "platform-security",
                "branch-protection-policy",
                "{\"requiredApprovals\":2,\"allowForcePush\":false}"
            );

        String recovered =
            encryption.decrypt(
                "platform-security",
                "branch-protection-policy",
                envelope
            );

        System.out.println("Key ID: " + envelope.keyId());
        System.out.println("Nonce bytes: " + envelope.nonce().length);
        System.out.println("Ciphertext + tag bytes: "
            + envelope.ciphertextAndTag().length);
        System.out.println("Recovered policy: " + recovered);

        byte[] tampered = envelope.ciphertextAndTag();
        tampered[0] ^= 0x01;

        EncryptedEnvelope modified =
            new EncryptedEnvelope(
                envelope.keyId(),
                envelope.nonce(),
                tampered,
                envelope.associatedData()
            );

        try {
            encryption.decrypt(
                "platform-security",
                "branch-protection-policy",
                modified
            );
            throw new AssertionError(
                "Tampered ciphertext was incorrectly accepted"
            );
        } catch (SecurityException expected) {
            System.out.println(
                "Ciphertext modification was rejected."
            );
        }
    }

    static void demonstrateGovernance(
        AesGcmService encryption
    ) throws GeneralSecurityException {

        System.out.println("\n=== Enterprise repository governance ===");

        BranchProtectionPolicy policy =
            new BranchProtectionPolicy(
                "main",
                2,
                EnumSet.of(
                    StatusCheck.UNIT_TESTS,
                    StatusCheck.SECURITY_SCAN,
                    StatusCheck.POLICY_VALIDATION
                ),
                true,
                false,
                false
            );

        List<Review> reviews = List.of(
            new Review(
                "security-reviewer",
                ReviewState.APPROVED,
                "Threat model reviewed"
            ),
            new Review(
                "platform-reviewer",
                ReviewState.APPROVED,
                "Policy implementation reviewed"
            )
        );

        PullRequest request =
            new PullRequest(
                482,
                "feature/security-policy",
                "main",
                PullRequestState.APPROVED,
                reviews,
                EnumSet.of(
                    StatusCheck.UNIT_TESTS,
                    StatusCheck.SECURITY_SCAN,
                    StatusCheck.POLICY_VALIDATION
                ),
                policy.requiredChecks(),
                false
            );

        MergeEligibilityService eligibility =
            new MergeEligibilityService();

        boolean mergeable =
            eligibility.isEligible(request, policy);

        System.out.println("PR #" + request.number()
            + " merge eligible: " + mergeable);

        if (!mergeable) {
            eligibility.explain(request, policy)
                .forEach(failure ->
                    System.out.println("Blocked: " + failure));
        }

        /*
         * The merge decision is itself encrypted. The protected branch name
         * is authenticated metadata, preventing substitution of the decision
         * into another repository or artifact context.
         */
        EncryptedEnvelope decision =
            encryption.encrypt(
                "platform-security",
                "merge-decision-" + request.number(),
                Boolean.toString(mergeable)
            );

        System.out.println(
            "Authenticated merge decision: "
            + encryption.decrypt(
                "platform-security",
                "merge-decision-" + request.number(),
                decision
            )
        );
    }

    public static void main(String[] args)
        throws Exception {

        System.out.println(
            "Authenticated Encryption with AES-256-GCM"
        );

        AesGcmService encryption =
            AesGcmService.generate("repo-key-2026");

        demonstrateEncryption(encryption);
        demonstrateGovernance(encryption);

        System.out.println("\nSecurity boundaries:");
        System.out.println(
            "AES-GCM provides confidentiality and authentication together."
        );
        System.out.println(
            "AAD is visible but authenticated."
        );
        System.out.println(
            "Authentication failures prevent modified ciphertext from being accepted."
        );
        System.out.println(
            "Unique nonces are generated for each encryption operation."
        );
        System.out.println(
            "Encryption keys should be held in controlled key-management infrastructure."
        );
    }
}
