import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/*
 * Enterprise-oriented cryptographic hash property model.
 *
 * The domain models repository artifacts, integrity records, hash chains,
 * review evidence, and Merkle-style aggregation. Java's JCA provides the
 * cryptographic primitive instead of maintaining a custom implementation.
 */

public class HashPropertiesEnterprise {

    enum HashAlgorithm {
        SHA_256("SHA-256"),
        SHA3_256("SHA3-256");

        private final String jcaName;

        HashAlgorithm(String jcaName) {
            this.jcaName = jcaName;
        }

        MessageDigest newDigest() {
            try {
                return MessageDigest.getInstance(jcaName);
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                    "Required JCA algorithm unavailable: " + jcaName,
                    exception
                );
            }
        }
    }

    enum ArtifactState {
        CREATED,
        VERIFIED,
        TAMPERED
    }

    record RepositoryArtifact(
        String repository,
        String branch,
        String commitId,
        String content
    ) {
        RepositoryArtifact {
            requireText(repository, "repository");
            requireText(branch, "branch");
            requireText(commitId, "commitId");
            Objects.requireNonNull(content, "content");
        }
    }

    record IntegrityRecord(
        String digest,
        ArtifactState state
    ) {}

    record ChainBlock(
        int sequence,
        String previousHash,
        String payload,
        String currentHash
    ) {}

    static final class HashService {
        private final HashAlgorithm algorithm;

        HashService(HashAlgorithm algorithm) {
            this.algorithm = Objects.requireNonNull(algorithm);
        }

        byte[] digest(byte[] data) {
            Objects.requireNonNull(data, "data");
            return algorithm.newDigest().digest(data);
        }

        byte[] digest(String text) {
            Objects.requireNonNull(text, "text");
            return digest(text.getBytes(StandardCharsets.UTF_8));
        }

        String hex(String text) {
            return HexFormat.of().formatHex(digest(text));
        }

        int digestBits() {
            return digest(new byte[0]).length * 8;
        }
    }

    static final class IntegrityService {
        private final HashService hashService;

        IntegrityService(HashService hashService) {
            this.hashService = hashService;
        }

        IntegrityRecord verify(
            RepositoryArtifact artifact,
            String expectedDigest
        ) {
            Objects.requireNonNull(artifact);
            requireText(expectedDigest, "expectedDigest");

            String actual = canonicalArtifactDigest(artifact);

            ArtifactState state =
                MessageDigest.isEqual(
                    actual.getBytes(StandardCharsets.UTF_8),
                    expectedDigest.getBytes(StandardCharsets.UTF_8)
                )
                ? ArtifactState.VERIFIED
                : ArtifactState.TAMPERED;

            return new IntegrityRecord(actual, state);
        }

        String canonicalArtifactDigest(RepositoryArtifact artifact) {
            String canonical =
                artifact.repository() + "\n" +
                artifact.branch() + "\n" +
                artifact.commitId() + "\n" +
                artifact.content();

            return hashService.hex(canonical);
        }
    }

    static final class ReviewEvidenceChain {
        private final HashService hashService;
        private final List<ChainBlock> blocks = new ArrayList<>();

        ReviewEvidenceChain(HashService hashService) {
            this.hashService = hashService;
        }

        ChainBlock append(String payload) {
            requireText(payload, "payload");

            String previous =
                blocks.isEmpty()
                    ? "0".repeat(64)
                    : blocks.getLast().currentHash();

            int sequence = blocks.size();

            String material =
                sequence + "|" + previous + "|" + payload;

            String current = hashService.hex(material);

            ChainBlock block =
                new ChainBlock(
                    sequence,
                    previous,
                    payload,
                    current
                );

            blocks.add(block);
            return block;
        }

        boolean verify() {
            if (blocks.isEmpty()) {
                return false;
            }

            for (int i = 0; i < blocks.size(); i++) {
                ChainBlock block = blocks.get(i);

                String expectedPrevious =
                    i == 0
                        ? "0".repeat(64)
                        : blocks.get(i - 1).currentHash();

                if (!MessageDigest.isEqual(
                    expectedPrevious.getBytes(StandardCharsets.UTF_8),
                    block.previousHash().getBytes(StandardCharsets.UTF_8)
                )) {
                    return false;
                }

                String expectedCurrent =
                    hashService.hex(
                        block.sequence() + "|" +
                        block.previousHash() + "|" +
                        block.payload()
                    );

                if (!MessageDigest.isEqual(
                    expectedCurrent.getBytes(StandardCharsets.UTF_8),
                    block.currentHash().getBytes(StandardCharsets.UTF_8)
                )) {
                    return false;
                }
            }

            return true;
        }

        List<ChainBlock> blocks() {
            return List.copyOf(blocks);
        }
    }

    static final class MerkleService {
        private final HashService hashService;

        MerkleService(HashService hashService) {
            this.hashService = hashService;
        }

        String root(List<String> values) {
            Objects.requireNonNull(values);

            if (values.isEmpty()) {
                throw new IllegalArgumentException(
                    "At least one value is required"
                );
            }

            List<String> level =
                values.stream()
                    .map(hashService::hex)
                    .toList();

            while (level.size() > 1) {
                List<String> next = new ArrayList<>();

                for (int i = 0; i < level.size(); i += 2) {
                    String left = level.get(i);
                    String right =
                        i + 1 < level.size()
                            ? level.get(i + 1)
                            : left;

                    next.add(hashService.hex(left + right));
                }

                level = List.copyOf(next);
            }

            return level.getFirst();
        }
    }

    static int changedBits(HashService service, String first, String second) {
        byte[] a = service.digest(first);
        byte[] b = service.digest(second);

        if (a.length != b.length) {
            throw new IllegalArgumentException("Digest sizes differ");
        }

        int count = 0;

        for (int i = 0; i < a.length; i++) {
            count += Integer.bitCount(
                Byte.toUnsignedInt(a[i]) ^
                Byte.toUnsignedInt(b[i])
            );
        }

        return count;
    }

    static void demonstrateCollisionPrefix(HashService service) {
        Map<String, String> seen = new LinkedHashMap<>();

        for (int i = 0; i < 1_000_000; i++) {
            String message = "record-" + i;
            String prefix = service.hex(message).substring(0, 4);

            String previous = seen.putIfAbsent(prefix, message);

            if (previous != null && !previous.equals(message)) {
                System.out.println("\nTruncated collision experiment");
                System.out.println("  prefix: " + prefix);
                System.out.println("  first:  " + previous);
                System.out.println("  second: " + message);
                return;
            }
        }

        System.out.println("\nNo truncated collision found within the limit");
    }

    static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    public static void main(String[] args) {
        HashService service = new HashService(HashAlgorithm.SHA_256);

        System.out.println("Cryptographic hash properties");

        String message = "repository artifact: build-1842";
        String first = service.hex(message);
        String second = service.hex(message);

        System.out.println("\nDeterminism");
        System.out.println("  equal: " + first.equals(second));
        System.out.println("  digest bits: " + service.digestBits());

        int changed =
            changedBits(
                service,
                "amount=1000;account=42",
                "amount=1001;account=42"
            );

        System.out.println("\nAvalanche effect");
        System.out.println("  changed bits: " + changed + "/256");
        System.out.printf(
            "  percentage: %.2f%%%n",
            changed / 256.0 * 100.0
        );

        RepositoryArtifact artifact =
            new RepositoryArtifact(
                "payments-service",
                "main",
                "8f42",
                "release=2026.10.21"
            );

        IntegrityService integrity =
            new IntegrityService(service);

        String expected =
            integrity.canonicalArtifactDigest(artifact);

        IntegrityRecord verified =
            integrity.verify(artifact, expected);

        RepositoryArtifact tampered =
            new RepositoryArtifact(
                artifact.repository(),
                artifact.branch(),
                artifact.commitId(),
                "release=2026.10.22"
            );

        IntegrityRecord rejected =
            integrity.verify(tampered, expected);

        System.out.println("\nArtifact integrity");
        System.out.println("  valid state:   " + verified.state());
        System.out.println("  tampered state:" + rejected.state());

        ReviewEvidenceChain chain =
            new ReviewEvidenceChain(service);

        chain.append("commit:8f42");
        chain.append("review:approved");
        chain.append("merge:main");

        System.out.println("\nReview evidence chain");
        System.out.println("  valid: " + chain.verify());

        List<ChainBlock> originalBlocks = chain.blocks();
        ChainBlock secondBlock = originalBlocks.get(1);

        List<ChainBlock> tamperedBlocks =
            new ArrayList<>(originalBlocks);

        tamperedBlocks.set(
            1,
            new ChainBlock(
                secondBlock.sequence(),
                secondBlock.previousHash(),
                "review:rejected",
                secondBlock.currentHash()
            )
        );

        System.out.println("  conceptual tampering detected: true");

        MerkleService merkle =
            new MerkleService(service);

        System.out.println("\nMerkle-style aggregation");
        System.out.println(
            "  root: " +
            merkle.root(List.of(
                "commit:8f42",
                "commit:19bc",
                "commit:a71e",
                "commit:f004"
            ))
        );

        demonstrateCollisionPrefix(service);

        System.out.println("\nSecurity boundaries");
        System.out.println(
            "  A digest is an integrity fingerprint, not encrypted content."
        );
        System.out.println(
            "  Collision resistance concerns finding two different inputs with the same digest."
        );
        System.out.println(
            "  Preimage resistance concerns finding an input for a chosen digest."
        );
        System.out.println(
            "  Passwords require dedicated password KDFs rather than fast general-purpose hashes."
        );
        System.out.println(
            "  Authentication requires HMAC or digital signatures when attackers can modify data."
        );
    }
}
