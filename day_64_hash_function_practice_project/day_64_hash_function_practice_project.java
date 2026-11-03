import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/*
 * Hash Functions Practice Project - Java 17
 *
 * Enterprise-oriented release artifact integrity registry.
 *
 * Features:
 * - SHA-256, SHA-512, SHA3-256 and SHA3-512
 * - Java Cryptography Architecture (JCA)
 * - Streaming file hashing
 * - HMAC-SHA256 manifest authentication
 * - PBKDF2-HMAC-SHA256 password derivation
 * - Artifact registration and candidate verification
 * - Immutable domain records and verification audit events
 *
 * Compile:
 *   javac HashFunctions.java
 *
 * Run:
 *   java HashFunctions
 */

public class HashFunctions {

    enum Algorithm {
        SHA256("SHA-256"),
        SHA512("SHA-512"),
        SHA3_256("SHA3-256"),
        SHA3_512("SHA3-512");

        private final String jcaName;

        Algorithm(String jcaName) {
            this.jcaName = jcaName;
        }

        String jcaName() {
            return jcaName;
        }
    }

    enum VerificationState {
        NOT_CHECKED,
        VERIFIED,
        INTEGRITY_FAILED
    }

    record DigestResult(
        Algorithm algorithm,
        String hexadecimal,
        long bytesProcessed
    ) {
        DigestResult {
            if (algorithm == null || hexadecimal == null) {
                throw new IllegalArgumentException("Digest fields cannot be null");
            }

            if (bytesProcessed < 0) {
                throw new IllegalArgumentException("Negative byte count");
            }

            if (hexadecimal.isBlank()) {
                throw new IllegalArgumentException("Digest cannot be empty");
            }
        }
    }

    record HashPolicy(
        Set<Algorithm> permittedAlgorithms,
        boolean hmacRequiredForManifests
    ) {
        HashPolicy {
            if (permittedAlgorithms == null || permittedAlgorithms.isEmpty()) {
                throw new IllegalArgumentException(
                    "At least one algorithm must be permitted"
                );
            }

            permittedAlgorithms = Set.copyOf(permittedAlgorithms);
        }

        boolean permits(Algorithm algorithm) {
            return permittedAlgorithms.contains(algorithm);
        }

        static HashPolicy enterpriseDefault() {
            return new HashPolicy(
                Set.of(
                    Algorithm.SHA256,
                    Algorithm.SHA512,
                    Algorithm.SHA3_256,
                    Algorithm.SHA3_512
                ),
                true
            );
        }
    }

    record ArtifactRecord(
        UUID artifactId,
        String artifactName,
        String releaseVersion,
        Algorithm algorithm,
        String expectedDigest,
        long registeredBytes,
        Instant registeredAt
    ) {
        ArtifactRecord {
            if (artifactId == null || algorithm == null || registeredAt == null) {
                throw new IllegalArgumentException("Artifact identity fields are required");
            }

            if (artifactName == null || artifactName.isBlank()) {
                throw new IllegalArgumentException("Artifact name is required");
            }

            if (releaseVersion == null || releaseVersion.isBlank()) {
                throw new IllegalArgumentException("Release version is required");
            }

            if (expectedDigest == null || expectedDigest.isBlank()) {
                throw new IllegalArgumentException("Expected digest is required");
            }

            if (registeredBytes < 0) {
                throw new IllegalArgumentException("Registered byte count cannot be negative");
            }
        }
    }

    record AuditEvent(
        UUID artifactId,
        String verifier,
        String observedDigest,
        boolean passed,
        Instant verifiedAt
    ) {
        AuditEvent {
            if (artifactId == null || verifier == null || verifiedAt == null) {
                throw new IllegalArgumentException("Audit event fields cannot be null");
            }
        }
    }

    static final class HashLabException extends RuntimeException {
        HashLabException(String message) {
            super(message);
        }

        HashLabException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final class HashService {

        private final HashPolicy policy;
        private final SecureRandom secureRandom = new SecureRandom();

        HashService(HashPolicy policy) {
            this.policy = policy;
        }

        private void requireAllowed(Algorithm algorithm) {
            if (algorithm == null || !policy.permits(algorithm)) {
                throw new HashLabException(
                    "Algorithm is not permitted by the active hash policy"
                );
            }
        }

        DigestResult digest(byte[] input, Algorithm algorithm) {
            if (input == null) {
                throw new IllegalArgumentException("Input cannot be null");
            }

            requireAllowed(algorithm);

            try {
                MessageDigest digest = MessageDigest.getInstance(
                    algorithm.jcaName()
                );

                byte[] result = digest.digest(input);

                return new DigestResult(
                    algorithm,
                    HexFormat.of().formatHex(result),
                    input.length
                );

            } catch (NoSuchAlgorithmException error) {
                throw new HashLabException(
                    "JCA digest provider does not support " + algorithm,
                    error
                );
            }
        }

        DigestResult digestFile(Path file, Algorithm algorithm) {
            if (file == null || !Files.isRegularFile(file)) {
                throw new IllegalArgumentException(
                    "File must exist and be a regular file"
                );
            }

            requireAllowed(algorithm);

            try {
                MessageDigest digest = MessageDigest.getInstance(
                    algorithm.jcaName()
                );

                long totalBytes = 0;
                byte[] buffer = new byte[1024 * 1024];

                try (
                    InputStream input = new BufferedInputStream(
                        Files.newInputStream(file)
                    )
                ) {
                    int count;

                    while ((count = input.read(buffer)) != -1) {
                        digest.update(buffer, 0, count);
                        totalBytes += count;
                    }
                }

                return new DigestResult(
                    algorithm,
                    HexFormat.of().formatHex(digest.digest()),
                    totalBytes
                );

            } catch (IOException | NoSuchAlgorithmException error) {
                throw new HashLabException(
                    "Unable to calculate file digest: " + file,
                    error
                );
            }
        }

        String hmacSha256(byte[] data, byte[] secretKey) {
            if (data == null || secretKey == null || secretKey.length == 0) {
                throw new IllegalArgumentException(
                    "HMAC data and a non-empty key are required"
                );
            }

            try {
                Mac mac = Mac.getInstance("HmacSHA256");

                SecretKeySpec key = new SecretKeySpec(
                    secretKey,
                    "HmacSHA256"
                );

                mac.init(key);

                return HexFormat.of().formatHex(mac.doFinal(data));

            } catch (GeneralSecurityException error) {
                throw new HashLabException("HMAC operation failed", error);
            }
        }

        boolean verifyHmacSha256(
            byte[] data,
            byte[] secretKey,
            String suppliedHex
        ) {
            if (suppliedHex == null) {
                return false;
            }

            try {
                byte[] expected = HexFormat.of().parseHex(
                    hmacSha256(data, secretKey)
                );

                byte[] supplied = HexFormat.of().parseHex(suppliedHex);

                return MessageDigest.isEqual(expected, supplied);

            } catch (IllegalArgumentException error) {
                return false;
            }
        }

        String derivePasswordRecord(char[] password, int iterations) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password cannot be empty");
            }

            if (iterations < 100_000 || iterations > 2_000_000) {
                throw new IllegalArgumentException(
                    "PBKDF2 iteration count is outside the allowed range"
                );
            }

            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);

            byte[] derived = derivePassword(
                password,
                salt,
                iterations,
                32
            );

            return String.join(
                "$",
                "pbkdf2_sha256",
                Integer.toString(iterations),
                HexFormat.of().formatHex(salt),
                HexFormat.of().formatHex(derived)
            );
        }

        boolean verifyPassword(char[] password, String encodedRecord) {
            if (password == null || encodedRecord == null) {
                return false;
            }

            try {
                String[] fields = encodedRecord.split("\\$", -1);

                if (fields.length != 4 || !fields[0].equals("pbkdf2_sha256")) {
                    return false;
                }

                int iterations = Integer.parseInt(fields[1]);

                if (iterations < 100_000 || iterations > 2_000_000) {
                    return false;
                }

                byte[] salt = HexFormat.of().parseHex(fields[2]);
                byte[] expected = HexFormat.of().parseHex(fields[3]);

                if (salt.length != 16 || expected.length != 32) {
                    return false;
                }

                byte[] actual = derivePassword(
                    password,
                    salt,
                    iterations,
                    32
                );

                return MessageDigest.isEqual(expected, actual);

            } catch (IllegalArgumentException error) {
                return false;
            }
        }

        private static byte[] derivePassword(
            char[] password,
            byte[] salt,
            int iterations,
            int keyLength
        ) {
            PBEKeySpec specification = new PBEKeySpec(
                password,
                salt,
                iterations,
                keyLength * 8
            );

            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256"
                );

                return factory.generateSecret(specification).getEncoded();

            } catch (GeneralSecurityException error) {
                throw new HashLabException(
                    "Password derivation failed",
                    error
                );

            } finally {
                specification.clearPassword();
            }
        }
    }

    static final class ArtifactRegistry {

        private final HashService hashService;
        private final HashPolicy policy;

        private final Map<UUID, ArtifactRecord> artifacts =
            new ConcurrentHashMap<>();

        private final Map<UUID, VerificationState> states =
            new ConcurrentHashMap<>();

        private final CopyOnWriteArrayList<AuditEvent> auditEvents =
            new CopyOnWriteArrayList<>();

        ArtifactRegistry(HashService hashService, HashPolicy policy) {
            this.hashService = hashService;
            this.policy = policy;
        }

        ArtifactRecord register(
            String artifactName,
            String releaseVersion,
            byte[] payload,
            Algorithm algorithm
        ) {
            if (payload == null) {
                throw new IllegalArgumentException("Artifact payload is required");
            }

            if (!policy.permits(algorithm)) {
                throw new HashLabException(
                    "Registration rejected by hash policy"
                );
            }

            DigestResult digest = hashService.digest(payload, algorithm);

            UUID id = UUID.randomUUID();

            ArtifactRecord record = new ArtifactRecord(
                id,
                artifactName,
                releaseVersion,
                algorithm,
                digest.hexadecimal(),
                digest.bytesProcessed(),
                Instant.now()
            );

            if (artifacts.putIfAbsent(id, record) != null) {
                throw new HashLabException("Artifact identifier collision");
            }

            states.put(id, VerificationState.NOT_CHECKED);

            return record;
        }

        boolean verifyCandidate(
            UUID artifactId,
            byte[] candidatePayload,
            String verifier
        ) {
            if (candidatePayload == null) {
                throw new IllegalArgumentException("Candidate payload is required");
            }

            if (verifier == null || verifier.isBlank()) {
                throw new IllegalArgumentException("Verifier identity is required");
            }

            ArtifactRecord record = artifacts.get(artifactId);

            if (record == null) {
                throw new HashLabException("Artifact is not registered");
            }

            DigestResult observed = hashService.digest(
                candidatePayload,
                record.algorithm()
            );

            byte[] expected = HexFormat.of().parseHex(
                record.expectedDigest()
            );

            byte[] actual = HexFormat.of().parseHex(
                observed.hexadecimal()
            );

            boolean digestMatches = MessageDigest.isEqual(
                expected,
                actual
            );

            boolean sizeMatches =
                record.registeredBytes() == observed.bytesProcessed();

            boolean passed = digestMatches && sizeMatches;

            states.put(
                artifactId,
                passed
                    ? VerificationState.VERIFIED
                    : VerificationState.INTEGRITY_FAILED
            );

            auditEvents.add(
                new AuditEvent(
                    artifactId,
                    verifier,
                    observed.hexadecimal(),
                    passed,
                    Instant.now()
                )
            );

            return passed;
        }

        ArtifactRecord find(UUID artifactId) {
            return artifacts.get(artifactId);
        }

        VerificationState state(UUID artifactId) {
            if (!artifacts.containsKey(artifactId)) {
                throw new HashLabException("Artifact is not registered");
            }

            return states.get(artifactId);
        }

        java.util.List<AuditEvent> auditTrail(UUID artifactId) {
            if (!artifacts.containsKey(artifactId)) {
                throw new HashLabException("Artifact is not registered");
            }

            return auditEvents.stream()
                .filter(event -> event.artifactId().equals(artifactId))
                .toList();
        }

        int artifactCount() {
            return artifacts.size();
        }
    }

    private static void runSelfTests(HashService hashService) {
        String sha256 = hashService.digest(
            "abc".getBytes(StandardCharsets.UTF_8),
            Algorithm.SHA256
        ).hexadecimal();

        if (!sha256.equals(
            "ba7816bf8f01cfea414140de5dae2223" +
            "b00361a396177a9cb410ff61f20015ad"
        )) {
            throw new HashLabException("SHA-256 known-answer test failed");
        }

        String sha3 = hashService.digest(
            "abc".getBytes(StandardCharsets.UTF_8),
            Algorithm.SHA3_256
        ).hexadecimal();

        if (!sha3.equals(
            "3a985da74fe225b2045c172d6bd390bd" +
            "855f086e3e9d525b46bfe24511431532"
        )) {
            throw new HashLabException("SHA3-256 known-answer test failed");
        }

        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);

        String hmac = hashService.hmacSha256(
            "Hi There".getBytes(StandardCharsets.UTF_8),
            key
        );

        if (!hmac.equals(
            "b0344c61d8db38535ca8afceaf0bf12b" +
            "881dc200c9833da726e9376c2e32cff7"
        )) {
            throw new HashLabException("HMAC known-answer test failed");
        }
    }

    private static void runDemo() {
        HashPolicy policy = HashPolicy.enterpriseDefault();
        HashService service = new HashService(policy);

        runSelfTests(service);

        System.out.println("Hash Functions Practice Project");
        System.out.println("================================");

        byte[] releasePayload = (
            "release=2.4.0;component=payment-service"
        ).getBytes(StandardCharsets.UTF_8);

        System.out.println("\nDigest algorithms:");

        for (Algorithm algorithm : Algorithm.values()) {
            DigestResult result = service.digest(releasePayload, algorithm);

            System.out.printf(
                "%-9s %s%n",
                algorithm,
                result.hexadecimal()
            );
        }

        System.out.println("\nEnterprise artifact registry:");

        ArtifactRegistry registry = new ArtifactRegistry(
            service,
            policy
        );

        ArtifactRecord release = registry.register(
            "payment-service.jar",
            "2.4.0",
            releasePayload,
            Algorithm.SHA256
        );

        System.out.println("Artifact ID: " + release.artifactId());
        System.out.println("Expected digest: " + release.expectedDigest());

        boolean originalPassed = registry.verifyCandidate(
            release.artifactId(),
            releasePayload,
            "release-verification-service"
        );

        System.out.println("Original candidate: " + originalPassed);
        System.out.println("State: " + registry.state(release.artifactId()));

        byte[] modifiedPayload = (
            "release=2.4.0;component=payment-service;modified=true"
        ).getBytes(StandardCharsets.UTF_8);

        boolean modifiedPassed = registry.verifyCandidate(
            release.artifactId(),
            modifiedPayload,
            "release-verification-service"
        );

        System.out.println("Modified candidate: " + modifiedPassed);
        System.out.println("State: " + registry.state(release.artifactId()));

        System.out.println(
            "Audit events: " + registry.auditTrail(release.artifactId()).size()
        );

        System.out.println("\nHMAC manifest authentication:");

        byte[] demoSecret = (
            "demo-key-replace-in-production"
        ).getBytes(StandardCharsets.UTF_8);

        byte[] manifest = (
            "artifact=payment-service.jar;version=2.4.0"
        ).getBytes(StandardCharsets.UTF_8);

        String signature = service.hmacSha256(manifest, demoSecret);

        System.out.println("Signature: " + signature);

        System.out.println(
            "Valid manifest: " +
            service.verifyHmacSha256(manifest, demoSecret, signature)
        );

        byte[] changedManifest = (
            "artifact=payment-service.jar;version=2.4.1"
        ).getBytes(StandardCharsets.UTF_8);

        System.out.println(
            "Modified manifest: " +
            service.verifyHmacSha256(changedManifest, demoSecret, signature)
        );

        System.out.println("\nPassword derivation:");

        String passwordRecord = service.derivePasswordRecord(
            "Practice-Password-2026".toCharArray(),
            310_000
        );

        System.out.println("Stored representation: " + passwordRecord);

        System.out.println(
            "Correct password: " +
            service.verifyPassword(
                "Practice-Password-2026".toCharArray(),
                passwordRecord
            )
        );

        System.out.println(
            "Incorrect password: " +
            service.verifyPassword(
                "Incorrect-Password".toCharArray(),
                passwordRecord
            )
        );

        System.out.println("\nAll known-answer tests passed.");
    }

    public static void main(String[] args) {
        try {
            if (args.length != 0) {
                System.err.println(
                    "This project runs its complete enterprise demonstration " +
                    "without command-line arguments."
                );
                System.exit(2);
            }

            runDemo();

        } catch (RuntimeException error) {
            System.err.println("Error: " + error.getMessage());
            System.exit(1);
        }
    }
}
