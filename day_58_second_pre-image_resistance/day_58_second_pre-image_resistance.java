import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Enterprise-oriented second-preimage verification model.
 *
 * The application separates:
 * 1. Artifact identity and state.
 * 2. Hash computation.
 * 3. Candidate generation.
 * 4. Second-preimage verification.
 * 5. Security-policy evaluation.
 *
 * The search uses truncated SHA-256 only for an intentionally small
 * laboratory experiment. Full SHA-256 is used for production-oriented
 * verification examples.
 */
public class SecondPreimageResistance {

    enum ArtifactState {
        REGISTERED,
        VERIFIED,
        REJECTED
    }

    enum SecurityDecision {
        ACCEPT,
        REJECT,
        REVIEW_REQUIRED
    }

    record Artifact(
            String id,
            String content,
            String algorithm,
            ArtifactState state
    ) {
        Artifact {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Artifact id is required");
            }
            if (content == null || content.isEmpty()) {
                throw new IllegalArgumentException("Artifact content is required");
            }
            if (algorithm == null || algorithm.isBlank()) {
                throw new IllegalArgumentException("Hash algorithm is required");
            }
            Objects.requireNonNull(state, "state");
        }
    }

    record SearchResult(
            boolean found,
            String targetDigest,
            String candidateDigest,
            int attempts,
            long elapsedNanos
    ) {}

    record Policy(
            int minimumDigestBits,
            boolean requireAuthentication
    ) {
        Policy {
            if (minimumDigestBits <= 0 || minimumDigestBits > 256) {
                throw new IllegalArgumentException(
                        "minimumDigestBits must be between 1 and 256");
            }
        }
    }

    static final class HashService {
        private final int bits;

        HashService(int bits) {
            if (bits <= 0 || bits > 256) {
                throw new IllegalArgumentException(
                        "bits must be between 1 and 256");
            }
            this.bits = bits;
        }

        int bits() {
            return bits;
        }

        byte[] digest(String value) {
            Objects.requireNonNull(value, "value");

            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] full = md.digest(value.getBytes(StandardCharsets.UTF_8));

                if (bits == 256) {
                    return full;
                }

                int bytes = (bits + 7) / 8;
                byte[] result = new byte[bytes];
                System.arraycopy(full, 0, result, 0, bytes);

                int unused = bytes * 8 - bits;
                if (unused > 0) {
                    result[0] &= (byte) (0xFF >>> unused);
                }

                return result;
            } catch (NoSuchAlgorithmException error) {
                throw new IllegalStateException(
                        "Required SHA-256 provider is unavailable", error);
            }
        }

        String hex(String value) {
            byte[] digest = digest(value);
            StringBuilder result = new StringBuilder(digest.length * 2);

            for (byte b : digest) {
                result.append(String.format("%02x", b & 0xFF));
            }

            return result.toString();
        }

        boolean equal(String left, String right) {
            byte[] a = digest(left);
            byte[] b = digest(right);

            if (a.length != b.length) {
                return false;
            }

            int difference = 0;
            for (int i = 0; i < a.length; i++) {
                difference |= a[i] ^ b[i];
            }
            return difference == 0;
        }
    }

    static final class CandidateFactory {
        String create(String original, int attempt) {
            if (original == null || original.isEmpty()) {
                throw new IllegalArgumentException("Original cannot be empty");
            }
            if (attempt <= 0) {
                throw new IllegalArgumentException("Attempt must be positive");
            }

            return original + "\u0000SECOND-PREIMAGE\u0000" + attempt;
        }
    }

    static final class SecondPreimageService {
        private final HashService hashService;
        private final CandidateFactory candidateFactory;

        SecondPreimageService(
                HashService hashService,
                CandidateFactory candidateFactory) {
            this.hashService = Objects.requireNonNull(hashService);
            this.candidateFactory = Objects.requireNonNull(candidateFactory);
        }

        SearchResult search(Artifact artifact, int maximumAttempts) {
            if (maximumAttempts <= 0) {
                throw new IllegalArgumentException(
                        "maximumAttempts must be positive");
            }

            String target = artifact.content();
            String targetDigest = hashService.hex(target);
            long started = System.nanoTime();

            for (int attempt = 1; attempt <= maximumAttempts; attempt++) {
                String candidate = candidateFactory.create(target, attempt);

                if (!candidate.equals(target)
                        && hashService.equal(target, candidate)) {
                    return new SearchResult(
                            true,
                            targetDigest,
                            hashService.hex(candidate),
                            attempt,
                            System.nanoTime() - started
                    );
                }
            }

            return new SearchResult(
                    false,
                    targetDigest,
                    null,
                    maximumAttempts,
                    System.nanoTime() - started
            );
        }
    }

    static final class GovernanceService {
        SecurityDecision evaluate(
                Policy policy,
                int digestBits,
                boolean authenticatedOrigin,
                boolean secondPreimageFound) {

            if (digestBits < policy.minimumDigestBits()) {
                return SecurityDecision.REJECT;
            }

            if (secondPreimageFound) {
                return SecurityDecision.REJECT;
            }

            if (policy.requireAuthentication() && !authenticatedOrigin) {
                return SecurityDecision.REVIEW_REQUIRED;
            }

            return SecurityDecision.ACCEPT;
        }
    }

    static void printReviewCriteria() {
        List<String> criteria = List.of(
                "The target message is fixed before the search.",
                "The candidate must be different from the target.",
                "The target and candidate must have identical digests.",
                "A truncated digest is suitable only for controlled experiments.",
                "A cryptographic hash does not prove who produced the message."
        );

        System.out.println("\nSecurity criteria");
        criteria.forEach(item -> System.out.println("- " + item));

        Map<String, String> controls = Map.of(
                "Integrity", "Use SHA-256 or SHA-3 with an appropriate security level.",
                "Authenticity", "Use a digital signature or MAC when required.",
                "Auditability", "Record algorithm, digest, artifact identity, and verification time.",
                "Failure handling", "Reject or quarantine artifacts that violate policy."
        );

        System.out.println("\nOperational controls");
        controls.forEach((key, value) ->
                System.out.println(key + ": " + value));
    }

    public static void main(String[] args) {
        System.out.println("Second-Preimage Resistance Enterprise Model");
        System.out.println("==========================================");

        Artifact artifact = new Artifact(
                "artifact-4.2.1",
                "ledger-service|release=4.2.1|environment=production",
                "SHA-256",
                ArtifactState.REGISTERED
        );

        HashService laboratoryHash = new HashService(16);
        CandidateFactory candidateFactory = new CandidateFactory();
        SecondPreimageService service =
                new SecondPreimageService(laboratoryHash, candidateFactory);

        System.out.println("Artifact: " + artifact.id());
        System.out.println("Experimental digest: "
                + laboratoryHash.hex(artifact.content()));

        SearchResult result = service.search(artifact, 500_000);

        System.out.println("\nControlled search");
        System.out.println("Found: " + result.found());
        System.out.println("Attempts: " + result.attempts());
        System.out.printf(
                "Elapsed: %.6f seconds%n",
                result.elapsedNanos() / 1_000_000_000.0
        );

        if (result.found()) {
            System.out.println("Target digest: " + result.targetDigest());
            System.out.println("Candidate digest: " + result.candidateDigest());
            System.out.println("Digest equality: "
                    + result.targetDigest().equals(result.candidateDigest()));
        }

        /*
         * A 256-bit service represents the production-oriented security
         * configuration. No exhaustive search is attempted because such
         * a search is computationally infeasible.
         */
        HashService productionHash = new HashService(256);
        String changed = artifact.content() + "|metadata=changed";

        System.out.println("\nFull SHA-256 verification");
        System.out.println("Original: " + productionHash.hex(artifact.content()));
        System.out.println("Changed : " + productionHash.hex(changed));
        System.out.println("Same digest: "
                + productionHash.equal(artifact.content(), changed));

        GovernanceService governance = new GovernanceService();
        Policy policy = new Policy(128, true);

        SecurityDecision decision = governance.evaluate(
                policy,
                256,
                false,
                result.found()
        );

        System.out.println("\nGovernance decision: " + decision);
        printReviewCriteria();
    }
}
