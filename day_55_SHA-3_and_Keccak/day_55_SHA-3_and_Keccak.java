import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * SHA-3 and Keccak enterprise artifact verification.
 *
 * Compile: javac Sha3Keccak.java
 * Run: java Sha3Keccak
 */
public class Sha3Keccak {

    enum ArtifactStatus {
        REGISTERED,
        VERIFIED,
        REJECTED
    }

    enum VerificationPolicy {
        STRICT,
        REPORT_ONLY
    }

    record Digest(String algorithm, int inputBytes, String hexadecimal) {
        Digest {
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(hexadecimal);
            if (inputBytes < 0) {
                throw new IllegalArgumentException("Negative input length.");
            }
        }
    }

    static final class Artifact {
        private final String name;
        private final byte[] content;
        private final String expectedDigest;
        private ArtifactStatus status = ArtifactStatus.REGISTERED;

        Artifact(String name, byte[] content, String expectedDigest) {
            if (name == null || name.isBlank() || name.length() > 200) {
                throw new IllegalArgumentException("Invalid artifact name.");
            }
            Objects.requireNonNull(content, "Artifact content is required.");
            if (content.length > 16 * 1024 * 1024) {
                throw new IllegalArgumentException("Artifact exceeds 16 MiB.");
            }
            if (expectedDigest == null ||
                !expectedDigest.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("Invalid SHA3-256 digest.");
            }

            this.name = name;
            this.content = content.clone();
            this.expectedDigest = expectedDigest.toLowerCase();
        }

        String name() {
            return name;
        }

        byte[] content() {
            return content.clone();
        }

        String expectedDigest() {
            return expectedDigest;
        }

        ArtifactStatus status() {
            return status;
        }

        void setStatus(ArtifactStatus next) {
            this.status = Objects.requireNonNull(next);
        }
    }

    interface DigestProvider {
        Digest calculate(byte[] content, String algorithm);
    }

    static final class JdkDigestProvider implements DigestProvider {
        private static final Map<String, Integer> OUTPUT_LENGTHS = Map.of(
            "SHA3-224", 28,
            "SHA3-256", 32,
            "SHA3-384", 48,
            "SHA3-512", 64
        );

        @Override
        public Digest calculate(byte[] content, String algorithm) {
            Objects.requireNonNull(content);
            Objects.requireNonNull(algorithm);

            Integer expectedLength = OUTPUT_LENGTHS.get(algorithm);
            if (expectedLength == null) {
                throw new IllegalArgumentException(
                    "Unsupported fixed-output SHA-3 algorithm."
                );
            }

            try {
                MessageDigest engine = MessageDigest.getInstance(algorithm);
                byte[] bytes = engine.digest(content);

                if (bytes.length != expectedLength) {
                    throw new IllegalStateException("Unexpected digest length.");
                }

                return new Digest(
                    algorithm,
                    content.length,
                    HexFormat.of().formatHex(bytes)
                );
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                    "The Java runtime does not provide " + algorithm,
                    exception
                );
            }
        }
    }

    record VerificationResult(
        String artifactName,
        ArtifactStatus status,
        String actualDigest,
        String detail
    ) {}

    static final class ArtifactVerificationService {
        private final DigestProvider provider;
        private final VerificationPolicy policy;
        private final Map<String, Artifact> artifacts = new TreeMap<>();

        ArtifactVerificationService(
            DigestProvider provider,
            VerificationPolicy policy
        ) {
            this.provider = Objects.requireNonNull(provider);
            this.policy = Objects.requireNonNull(policy);
        }

        public synchronized void register(Artifact artifact) {
            Objects.requireNonNull(artifact);
            if (artifacts.containsKey(artifact.name())) {
                throw new IllegalArgumentException(
                    "Artifact is already registered: " + artifact.name()
                );
            }
            artifacts.put(artifact.name(), artifact);
        }

        public synchronized VerificationResult verify(String name) {
            Artifact artifact = artifacts.get(name);
            if (artifact == null) {
                throw new IllegalArgumentException("Unknown artifact: " + name);
            }

            Digest actual = provider.calculate(artifact.content(), "SHA3-256");
            boolean matches = MessageDigest.isEqual(
                HexFormat.of().parseHex(actual.hexadecimal()),
                HexFormat.of().parseHex(artifact.expectedDigest())
            );

            ArtifactStatus next = matches
                ? ArtifactStatus.VERIFIED
                : ArtifactStatus.REJECTED;

            // State changes only after digest computation and comparison succeed.
            artifact.setStatus(next);

            String detail = matches
                ? "Digest matches the registered release manifest."
                : "Digest mismatch; artifact integrity is not established.";

            return new VerificationResult(
                artifact.name(),
                next,
                actual.hexadecimal(),
                detail
            );
        }

        public synchronized List<VerificationResult> verifyAll() {
            List<VerificationResult> results = new ArrayList<>();
            for (String name : artifacts.keySet()) {
                results.add(verify(name));
            }

            if (policy == VerificationPolicy.STRICT &&
                results.stream().anyMatch(
                    result -> result.status() != ArtifactStatus.VERIFIED
                )) {
                throw new IllegalStateException(
                    "Strict verification rejected one or more artifacts."
                );
            }

            return Collections.unmodifiableList(results);
        }

        public synchronized Map<String, ArtifactStatus> statuses() {
            Map<String, ArtifactStatus> result = new TreeMap<>();
            artifacts.forEach((name, artifact) ->
                result.put(name, artifact.status())
            );
            return Collections.unmodifiableMap(result);
        }
    }

    private static void requireKnownAnswerTests(DigestProvider provider) {
        String expectedEmpty =
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        String expectedAbc =
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";

        if (!provider.calculate(new byte[0], "SHA3-256")
                .hexadecimal().equals(expectedEmpty)) {
            throw new IllegalStateException("Empty-message test failed.");
        }

        if (!provider.calculate("abc".getBytes(StandardCharsets.UTF_8), "SHA3-256")
                .hexadecimal().equals(expectedAbc)) {
            throw new IllegalStateException("abc test failed.");
        }
    }

    public static void main(String[] args) {
        DigestProvider provider = new JdkDigestProvider();
        requireKnownAnswerTests(provider);

        ArtifactVerificationService service = new ArtifactVerificationService(
            provider,
            VerificationPolicy.REPORT_ONLY
        );

        byte[] binary = new byte[] {0, 1, 2, 3, (byte) 0xff};
        String validDigest = provider.calculate(binary, "SHA3-256").hexadecimal();

        service.register(new Artifact(
            "release/package.bin",
            binary,
            validDigest
        ));

        service.register(new Artifact(
            "release/manifest.json",
            "{\"version\":\"1.0\"}".getBytes(StandardCharsets.UTF_8),
            "0".repeat(64)
        ));

        try {
            for (VerificationResult result : service.verifyAll()) {
                System.out.printf(
                    "%s | %s | %s | %s%n",
                    result.artifactName(),
                    result.status(),
                    result.actualDigest(),
                    result.detail()
                );
            }

            System.out.println("Known-answer tests: PASSED");
            System.out.println("Final statuses: " + service.statuses());
        } catch (RuntimeException exception) {
            System.err.println("Verification failed: " + exception.getMessage());
            System.exitCode = 1;
        }
    }
}
