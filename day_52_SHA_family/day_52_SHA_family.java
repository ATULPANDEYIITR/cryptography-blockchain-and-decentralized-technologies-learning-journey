import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/*
 * Enterprise-oriented SHA family integrity service.
 *
 * Compile:
 *   javac ShaFamily.java
 *
 * Run:
 *   java ShaFamily
 *
 * The design separates:
 * - algorithm policy
 * - domain records
 * - digest computation
 * - integrity verification
 * - password-derived verification
 * - failure handling
 *
 * The SHA primitives themselves are delegated to the JDK cryptographic
 * provider. This is preferable in production because cryptographic
 * implementations should be maintained and audited at the platform level.
 */
public final class ShaFamily {

    public static void main(String[] args) {
        IntegrityPolicy policy = new IntegrityPolicy(
                Set.of("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"),
                Set.of("SHA-1")
        );

        DigestService digestService = new DigestService(policy);
        IntegrityWorkflow workflow = new IntegrityWorkflow(digestService);

        Artifact artifact = new Artifact(
                "release-bundle-2026.10",
                "release payload: version=4.7.2",
                "SHA-256"
        );

        String digest = digestService.digest(
                artifact.algorithm(),
                artifact.payload()
        );

        Artifact stored = artifact.withExpectedDigest(digest);

        VerificationResult valid = workflow.verify(stored);

        Artifact tampered = stored.withPayload(
                stored.payload() + ";modified=true"
        );

        VerificationResult invalid = workflow.verify(tampered);

        System.out.println("SHA family enterprise integrity service");
        System.out.println("========================================");
        System.out.println("Algorithm policy: " + policy.allowedAlgorithms());
        System.out.println("Compatibility-only: " + policy.compatibilityAlgorithms());
        System.out.println();

        System.out.println("Original artifact");
        System.out.println("-----------------");
        System.out.println("Digest: " + stored.expectedDigest());
        System.out.println("Verified: " + valid.success());
        System.out.println("Message: " + valid.message());
        System.out.println();

        System.out.println("Tampered artifact");
        System.out.println("-----------------");
        System.out.println("Verified: " + invalid.success());
        System.out.println("Message: " + invalid.message());

        demonstrateIncrementalHashing(digestService);
        demonstratePasswordVerification();
        demonstrateAlgorithmPolicy(policy);
        demonstrateDigestMetadata();
    }

    private static void demonstrateIncrementalHashing(
            DigestService digestService
    ) {
        MessageDigest digest = digestService.newDigest("SHA-256");

        List<String> events = List.of(
                "commit=8e1a7d",
                "artifact=release.tar",
                "status=verified"
        );

        events.forEach(event ->
                digest.update(event.getBytes(StandardCharsets.UTF_8))
        );

        String incremental = HexFormat.of().formatHex(digest.digest());

        String oneShot = digestService.digest(
                "SHA-256",
                events.stream().collect(Collectors.joining()).getBytes(
                        StandardCharsets.UTF_8
                )
        );

        System.out.println();
        System.out.println("Incremental processing");
        System.out.println("----------------------");
        System.out.println("Incremental digest: " + incremental);
        System.out.println("Independent digest: " + oneShot);
        System.out.println(
                "Equal: " + digestService.constantTimeEquals(incremental, oneShot)
        );
    }

    private static void demonstratePasswordVerification() {
        PasswordService passwordService = new PasswordService();

        PasswordRecord record = passwordService.create(
                "correct horse battery staple"
        );

        boolean accepted = passwordService.verify(
                "correct horse battery staple",
                record
        );

        boolean rejected = passwordService.verify(
                "incorrect password",
                record
        );

        System.out.println();
        System.out.println("Password-derived verification");
        System.out.println("-----------------------------");
        System.out.println("Algorithm: " + record.algorithm());
        System.out.println("Iterations: " + record.iterations());
        System.out.println("Salt: " + HexFormat.of().formatHex(record.salt()));
        System.out.println("Accepted password: " + accepted);
        System.out.println("Rejected password: " + rejected);
    }

    private static void demonstrateAlgorithmPolicy(
            IntegrityPolicy policy
    ) {
        System.out.println();
        System.out.println("Algorithm policy");
        System.out.println("----------------");

        for (String algorithm : List.of(
                "SHA-1",
                "SHA-256",
                "SHA-512",
                "SHA3-256"
        )) {
            System.out.printf(
                    "%-10s allowed=%s compatibility=%s%n",
                    algorithm,
                    policy.isAllowed(algorithm),
                    policy.isCompatibilityOnly(algorithm)
            );
        }
    }

    private static void demonstrateDigestMetadata() {
        System.out.println();
        System.out.println("Digest metadata");
        System.out.println("---------------");

        Map<String, Integer> digestLengths = Map.of(
                "SHA-1", 160,
                "SHA-256", 256,
                "SHA-384", 384,
                "SHA-512", 512,
                "SHA3-256", 256,
                "SHA3-512", 512
        );

        digestLengths.forEach((algorithm, bits) ->
                System.out.printf(
                        "%-10s %3d bits%n",
                        algorithm,
                        bits
                )
        );
    }

    public record Artifact(
            String identifier,
            String payload,
            String algorithm,
            String expectedDigest
    ) {
        public Artifact {
            if (identifier == null || identifier.isBlank()) {
                throw new IllegalArgumentException("Artifact identifier is required.");
            }

            if (payload == null) {
                throw new IllegalArgumentException("Artifact payload is required.");
            }

            if (algorithm == null || algorithm.isBlank()) {
                throw new IllegalArgumentException("Hash algorithm is required.");
            }
        }

        public Artifact(
                String identifier,
                String payload,
                String algorithm
        ) {
            this(identifier, payload, algorithm, null);
        }

        public Artifact withExpectedDigest(String digest) {
            return new Artifact(
                    identifier,
                    payload,
                    algorithm,
                    digest
            );
        }

        public Artifact withPayload(String newPayload) {
            return new Artifact(
                    identifier,
                    newPayload,
                    algorithm,
                    expectedDigest
            );
        }
    }

    public record VerificationResult(
            boolean success,
            String message
    ) {
    }

    public record PasswordRecord(
            byte[] salt,
            byte[] derivedKey,
            int iterations,
            String algorithm
    ) {
        public PasswordRecord {
            Objects.requireNonNull(salt);
            Objects.requireNonNull(derivedKey);
            Objects.requireNonNull(algorithm);
        }
    }

    public static final class IntegrityPolicy {
        private final Set<String> allowedAlgorithms;
        private final Set<String> compatibilityAlgorithms;

        public IntegrityPolicy(
                Set<String> allowedAlgorithms,
                Set<String> compatibilityAlgorithms
        ) {
            this.allowedAlgorithms = Set.copyOf(allowedAlgorithms);
            this.compatibilityAlgorithms = Set.copyOf(compatibilityAlgorithms);
        }

        public Set<String> allowedAlgorithms() {
            return allowedAlgorithms;
        }

        public Set<String> compatibilityAlgorithms() {
            return compatibilityAlgorithms;
        }

        public boolean isAllowed(String algorithm) {
            return allowedAlgorithms.contains(algorithm)
                    || compatibilityAlgorithms.contains(algorithm);
        }

        public boolean isCompatibilityOnly(String algorithm) {
            return compatibilityAlgorithms.contains(algorithm)
                    && !allowedAlgorithms.contains(algorithm);
        }
    }

    public static final class DigestService {
        private final IntegrityPolicy policy;

        public DigestService(IntegrityPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        public String digest(String algorithm, String value) {
            Objects.requireNonNull(value);
            return digest(
                    algorithm,
                    value.getBytes(StandardCharsets.UTF_8)
            );
        }

        public String digest(String algorithm, byte[] value) {
            if (!policy.isAllowed(algorithm)) {
                throw new IllegalArgumentException(
                        "Algorithm rejected by integrity policy: " + algorithm
                );
            }

            if (policy.isCompatibilityOnly(algorithm)) {
                throw new IllegalArgumentException(
                        "Compatibility-only algorithm cannot be used for new artifacts: "
                                + algorithm
                );
            }

            MessageDigest digest = newDigest(algorithm);
            return HexFormat.of().formatHex(digest.digest(value));
        }

        public MessageDigest newDigest(String algorithm) {
            try {
                return MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException error) {
                throw new IllegalArgumentException(
                        "JDK provider does not support: " + algorithm,
                        error
                );
            }
        }

        public boolean constantTimeEquals(
                String expected,
                String actual
        ) {
            if (expected == null || actual == null) {
                return false;
            }

            byte[] left = HexFormat.of().parseHex(expected);
            byte[] right = HexFormat.of().parseHex(actual);

            return MessageDigest.isEqual(left, right);
        }
    }

    public static final class IntegrityWorkflow {
        private final DigestService digestService;

        public IntegrityWorkflow(DigestService digestService) {
            this.digestService = digestService;
        }

        public VerificationResult verify(Artifact artifact) {
            if (artifact.expectedDigest() == null) {
                return new VerificationResult(
                        false,
                        "No trusted reference digest is available."
                );
            }

            try {
                String actual = digestService.digest(
                        artifact.algorithm(),
                        artifact.payload()
                );

                boolean matches = digestService.constantTimeEquals(
                        artifact.expectedDigest(),
                        actual
                );

                return matches
                        ? new VerificationResult(
                                true,
                                "Artifact digest matches."
                        )
                        : new VerificationResult(
                                false,
                                "Artifact digest mismatch."
                        );
            } catch (RuntimeException error) {
                return new VerificationResult(
                        false,
                        "Verification failed: " + error.getMessage()
                );
            }
        }
    }

    public static final class PasswordService {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000;
        private static final int KEY_LENGTH_BITS = 256;
        private static final int SALT_LENGTH = 16;

        private final SecureRandom random = new SecureRandom();

        public PasswordRecord create(String password) {
            validatePassword(password);

            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);

            byte[] derived = derive(password, salt, ITERATIONS);

            return new PasswordRecord(
                    salt,
                    derived,
                    ITERATIONS,
                    ALGORITHM
            );
        }

        public boolean verify(
                String password,
                PasswordRecord record
        ) {
            if (password == null || record == null) {
                return false;
            }

            byte[] candidate = derive(
                    password,
                    record.salt(),
                    record.iterations()
            );

            return MessageDigest.isEqual(
                    candidate,
                    record.derivedKey()
            );
        }

        private byte[] derive(
                String password,
                byte[] salt,
                int iterations
        ) {
            try {
                var factory =
                        javax.crypto.SecretKeyFactory.getInstance(ALGORITHM);

                var specification =
                        new javax.crypto.spec.PBEKeySpec(
                                password.toCharArray(),
                                salt,
                                iterations,
                                KEY_LENGTH_BITS
                        );

                return factory.generateSecret(specification).getEncoded();
            } catch (Exception error) {
                throw new IllegalStateException(
                        "Password derivation failed.",
                        error
                );
            }
        }

        private static void validatePassword(String password) {
            if (password == null || password.isBlank()) {
                throw new IllegalArgumentException(
                        "Password must not be empty."
                );
            }
        }
    }
}
