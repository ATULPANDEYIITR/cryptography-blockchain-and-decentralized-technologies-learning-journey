import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class Sha256EnterpriseDemo {

    enum ArtifactState {
        RECEIVED,
        VERIFIED,
        REJECTED
    }

    record Artifact(
            String artifactId,
            byte[] content,
            String expectedDigest
    ) {
        Artifact {
            if (artifactId == null || artifactId.isBlank()) {
                throw new IllegalArgumentException("artifactId is required");
            }
            Objects.requireNonNull(content, "content is required");

            if (expectedDigest == null ||
                    !expectedDigest.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException(
                        "expectedDigest must contain exactly 64 hexadecimal characters"
                );
            }

            content = content.clone();
            expectedDigest = expectedDigest.toLowerCase();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }

    record VerificationResult(
            String artifactId,
            ArtifactState state,
            String actualDigest,
            String reason
    ) {
    }

    interface DigestService {
        String sha256(byte[] content);
        boolean constantTimeEquals(String expected, String actual);
    }

    static final class Sha256DigestService implements DigestService {
        private static final HexFormat HEX = HexFormat.of();

        @Override
        public String sha256(byte[] content) {
            Objects.requireNonNull(content, "content");

            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return HEX.formatHex(digest.digest(content));
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                        "Required SHA-256 implementation is unavailable",
                        exception
                );
            }
        }

        @Override
        public boolean constantTimeEquals(String expected, String actual) {
            if (expected == null || actual == null) {
                return false;
            }

            byte[] left = HEX.parseHex(expected);
            byte[] right = HEX.parseHex(actual);

            if (left.length != right.length) {
                return false;
            }

            int difference = 0;

            for (int i = 0; i < left.length; i++) {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
        }
    }

    static final class ArtifactVerifier {
        private final DigestService digestService;

        ArtifactVerifier(DigestService digestService) {
            this.digestService = Objects.requireNonNull(digestService);
        }

        VerificationResult verify(Artifact artifact) {
            String actual = digestService.sha256(artifact.content());

            boolean matches = digestService.constantTimeEquals(
                    artifact.expectedDigest(),
                    actual
            );

            if (matches) {
                return new VerificationResult(
                        artifact.artifactId(),
                        ArtifactState.VERIFIED,
                        actual,
                        "Digest matches the expected value"
                );
            }

            return new VerificationResult(
                    artifact.artifactId(),
                    ArtifactState.REJECTED,
                    actual,
                    "Digest mismatch"
            );
        }
    }

    static void runKnownVectors(DigestService service) {
        Map<String, String> vectors = Map.of(
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "hello world",
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        vectors.forEach((input, expected) -> {
            String actual = service.sha256(
                    input.getBytes(StandardCharsets.UTF_8)
            );

            if (!service.constantTimeEquals(expected, actual)) {
                throw new IllegalStateException(
                        "Known vector failed for input: " + input
                );
            }
        });

        System.out.println("Known SHA-256 vectors: PASS");
    }

    static void demonstrateWorkflow(ArtifactVerifier verifier) {
        String validContent = "signed release artifact";
        String validDigest = new Sha256DigestService().sha256(
                validContent.getBytes(StandardCharsets.UTF_8)
        );

        Artifact validArtifact = new Artifact(
                "artifact-1001",
                validContent.getBytes(StandardCharsets.UTF_8),
                validDigest
        );

        Artifact tamperedArtifact = new Artifact(
                "artifact-1002",
                "modified release artifact".getBytes(StandardCharsets.UTF_8),
                validDigest
        );

        List<Artifact> artifacts = List.of(validArtifact, tamperedArtifact);

        artifacts.stream()
                .map(verifier::verify)
                .forEach(result -> {
                    System.out.println();
                    System.out.println("Artifact: " + result.artifactId());
                    System.out.println("State: " + result.state());
                    System.out.println("Digest: " + result.actualDigest());
                    System.out.println("Reason: " + result.reason());
                });
    }

    public static void main(String[] args) {
        try {
            DigestService service = new Sha256DigestService();

            runKnownVectors(service);

            demonstrateWorkflow(new ArtifactVerifier(service));

            String multipart = String.join(
                    "",
                    "repository",
                    "-",
                    "artifact",
                    "-",
                    "verified"
            );

            String oneShot = service.sha256(
                    multipart.getBytes(StandardCharsets.UTF_8)
            );

            System.out.println();
            System.out.println("Enterprise artifact digest: " + oneShot);

        } catch (IllegalArgumentException | IllegalStateException exception) {
            System.err.println("SHA-256 workflow failed: "
                    + exception.getMessage());
            System.exit(1);
        }
    }
}
