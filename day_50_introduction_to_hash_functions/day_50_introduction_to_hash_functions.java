import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/*
 * Introduction to Hash Functions
 *
 * Enterprise-oriented model for:
 * - SHA-256 and SHA3-256
 * - content-addressed artifacts
 * - integrity verification
 * - HMAC-style authentication concepts
 * - password key derivation
 * - Merkle roots
 * - immutable domain objects
 * - concurrent artifact indexing
 *
 * Compile:
 *     javac HashFunctionsEnterprise.java
 *
 * Run:
 *     java HashFunctionsEnterprise
 */

public class HashFunctionsEnterprise {

    enum HashAlgorithm {
        SHA_256("SHA-256"),
        SHA3_256("SHA3-256");

        private final String providerName;

        HashAlgorithm(String providerName) {
            this.providerName = providerName;
        }

        String providerName() {
            return providerName;
        }
    }

    record Artifact(
        String id,
        String repository,
        String branch,
        String author,
        String digest
    ) {
        Artifact {
            requireText(id, "id");
            requireText(repository, "repository");
            requireText(branch, "branch");
            requireText(author, "author");
            requireText(digest, "digest");
        }
    }

    record PasswordRecord(
        String algorithm,
        int iterations,
        byte[] salt,
        byte[] derivedKey
    ) {
        PasswordRecord {
            requireText(algorithm, "algorithm");

            if (iterations <= 0) {
                throw new IllegalArgumentException(
                    "Iterations must be positive"
                );
            }

            if (salt == null || salt.length < 16) {
                throw new IllegalArgumentException(
                    "Salt must contain at least 16 bytes"
                );
            }

            if (derivedKey == null || derivedKey.length == 0) {
                throw new IllegalArgumentException(
                    "Derived key must not be empty"
                );
            }

            salt = salt.clone();
            derivedKey = derivedKey.clone();
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] derivedKey() {
            return derivedKey.clone();
        }
    }

    static final class HashService {

        private HashService() {
        }

        static byte[] digest(
            byte[] data,
            HashAlgorithm algorithm
        ) {
            Objects.requireNonNull(data, "data");

            try {
                MessageDigest digest =
                    MessageDigest.getInstance(algorithm.providerName());

                return digest.digest(data);
            }
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                    "Required JDK hash algorithm is unavailable",
                    exception
                );
            }
        }

        static String hexDigest(
            String text,
            HashAlgorithm algorithm
        ) {
            requireText(text, "text");

            return HexFormat.of().formatHex(
                digest(
                    text.getBytes(StandardCharsets.UTF_8),
                    algorithm
                )
            );
        }

        static boolean secureDigestEquals(
            byte[] expected,
            byte[] actual
        ) {
            if (expected == null || actual == null) {
                return false;
            }

            int difference = expected.length ^ actual.length;
            int maximum = Math.max(expected.length, actual.length);

            for (int i = 0; i < maximum; i++) {
                byte left = i < expected.length ? expected[i] : 0;
                byte right = i < actual.length ? actual[i] : 0;

                difference |= left ^ right;
            }

            return difference == 0;
        }
    }

    static final class ArtifactRepository {
        /*
         * ConcurrentHashMap supports concurrent reads and updates.
         * The digest is a content identifier, not a secret.
         */
        private final Map<String, Artifact> artifacts =
            new ConcurrentHashMap<>();

        void save(Artifact artifact) {
            Objects.requireNonNull(artifact, "artifact");

            Artifact existing =
                artifacts.putIfAbsent(artifact.id(), artifact);

            if (existing != null &&
                !existing.digest().equals(artifact.digest())) {
                throw new IllegalStateException(
                    "Artifact identifier already maps to another digest"
                );
            }
        }

        Optional<Artifact> find(String id) {
            return Optional.ofNullable(artifacts.get(id));
        }

        List<Artifact> findByRepository(String repository) {
            return artifacts.values()
                .stream()
                .filter(artifact ->
                    artifact.repository().equals(repository))
                .collect(Collectors.toUnmodifiableList());
        }
    }

    static final class PasswordService {
        private static final int ITERATIONS = 600_000;
        private static final int SALT_LENGTH = 16;
        private static final int KEY_LENGTH = 32;

        private PasswordService() {
        }

        static PasswordRecord create(String password) {
            requireText(password, "password");

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);

            /*
             * PBKDF2-HMAC-SHA256 is a password key derivation mechanism.
             * A production deployment should select parameters through
             * current security policy and benchmark them on target hardware.
             */
            byte[] key = pbkdf2(password, salt, ITERATIONS);

            return new PasswordRecord(
                "PBKDF2WithHmacSHA256",
                ITERATIONS,
                salt,
                key
            );
        }

        static boolean verify(
            String password,
            PasswordRecord record
        ) {
            requireText(password, "password");
            Objects.requireNonNull(record, "record");

            byte[] actual = pbkdf2(
                password,
                record.salt(),
                record.iterations()
            );

            return HashService.secureDigestEquals(
                record.derivedKey(),
                actual
            );
        }

        private static byte[] pbkdf2(
            String password,
            byte[] salt,
            int iterations
        ) {
            try {
                var spec =
                    new javax.crypto.spec.PBEKeySpec(
                        password.toCharArray(),
                        salt,
                        iterations,
                        KEY_LENGTH * 8
                    );

                var factory =
                    javax.crypto.SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256"
                    );

                return factory.generateSecret(spec).getEncoded();
            }
            catch (Exception exception) {
                throw new IllegalStateException(
                    "Password derivation failed",
                    exception
                );
            }
        }
    }

    static final class MerkleTree {

        private MerkleTree() {
        }

        static String root(List<String> values) {
            if (values == null || values.isEmpty()) {
                throw new IllegalArgumentException(
                    "Merkle tree requires at least one leaf"
                );
            }

            List<byte[]> level = new ArrayList<>();

            for (String value : values) {
                requireText(value, "leaf");
                level.add(
                    HashService.digest(
                        value.getBytes(StandardCharsets.UTF_8),
                        HashAlgorithm.SHA_256
                    )
                );
            }

            while (level.size() > 1) {
                if (level.size() % 2 != 0) {
                    level.add(level.get(level.size() - 1));
                }

                List<byte[]> next = new ArrayList<>();

                for (int i = 0; i < level.size(); i += 2) {
                    byte[] combined =
                        new byte[
                            level.get(i).length +
                            level.get(i + 1).length
                        ];

                    System.arraycopy(
                        level.get(i),
                        0,
                        combined,
                        0,
                        level.get(i).length
                    );

                    System.arraycopy(
                        level.get(i + 1),
                        0,
                        combined,
                        level.get(i).length,
                        level.get(i + 1).length
                    );

                    next.add(
                        HashService.digest(
                            combined,
                            HashAlgorithm.SHA_256
                        )
                    );
                }

                level = next;
            }

            return HexFormat.of().formatHex(level.get(0));
        }
    }

    static CompletableFuture<String> asynchronousDigest(
        String value
    ) {
        return CompletableFuture.supplyAsync(
            () -> HashService.hexDigest(
                value,
                HashAlgorithm.SHA_256
            )
        );
    }

    private static void requireText(
        String value,
        String name
    ) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                name + " must not be blank"
            );
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("=== Hash Determinism ===");

            String first =
                HashService.hexDigest(
                    "repository artifact",
                    HashAlgorithm.SHA_256
                );

            String second =
                HashService.hexDigest(
                    "repository artifact",
                    HashAlgorithm.SHA_256
                );

            System.out.println(first);
            System.out.println(
                "Deterministic: " + first.equals(second)
            );

            System.out.println("\n=== Algorithm Comparison ===");

            System.out.println(
                "SHA-256: " +
                HashService.hexDigest(
                    "secure data",
                    HashAlgorithm.SHA_256
                )
            );

            System.out.println(
                "SHA3-256: " +
                HashService.hexDigest(
                    "secure data",
                    HashAlgorithm.SHA3_256
                )
            );

            System.out.println("\n=== Artifact Repository ===");

            String digest =
                HashService.hexDigest(
                    "commit-001",
                    HashAlgorithm.SHA_256
                );

            Artifact artifact = new Artifact(
                digest,
                "payments-service",
                "main",
                "developer@example.com",
                digest
            );

            ArtifactRepository repository =
                new ArtifactRepository();

            repository.save(artifact);

            repository.find(digest)
                .ifPresent(found ->
                    System.out.println(
                        found.repository() +
                        " / " +
                        found.branch() +
                        " / " +
                        found.author()
                    )
                );

            System.out.println(
                "Repository artifacts: " +
                repository.findByRepository("payments-service").size()
            );

            System.out.println("\n=== Password Derivation ===");

            PasswordRecord passwordRecord =
                PasswordService.create(
                    "CorrectHorseBatteryStaple"
                );

            System.out.println(
                "Correct password: " +
                PasswordService.verify(
                    "CorrectHorseBatteryStaple",
                    passwordRecord
                )
            );

            System.out.println(
                "Wrong password: " +
                PasswordService.verify(
                    "WrongPassword",
                    passwordRecord
                )
            );

            System.out.println("\n=== Merkle Root ===");

            List<String> transactions = List.of(
                "TX-001 Alice -> Bob 10",
                "TX-002 Bob -> Carol 5",
                "TX-003 Carol -> Dave 2",
                "TX-004 Dave -> Erin 1"
            );

            System.out.println(
                MerkleTree.root(transactions)
            );

            System.out.println("\n=== Asynchronous Hashing ===");

            String asynchronousResult =
                asynchronousDigest("event-driven artifact")
                    .join();

            System.out.println(asynchronousResult);

            System.out.println("\n=== Integrity Check ===");

            byte[] expected =
                HashService.digest(
                    "release artifact v1"
                        .getBytes(StandardCharsets.UTF_8),
                    HashAlgorithm.SHA_256
                );

            byte[] unchanged =
                HashService.digest(
                    "release artifact v1"
                        .getBytes(StandardCharsets.UTF_8),
                    HashAlgorithm.SHA_256
                );

            byte[] modified =
                HashService.digest(
                    "release artifact v2"
                        .getBytes(StandardCharsets.UTF_8),
                    HashAlgorithm.SHA_256
                );

            System.out.println(
                "Unchanged: " +
                HashService.secureDigestEquals(expected, unchanged)
            );

            System.out.println(
                "Modified: " +
                HashService.secureDigestEquals(expected, modified)
            );
        }
        catch (RuntimeException exception) {
            System.err.println(
                "Operation failed: " + exception.getMessage()
            );
            System.exit(1);
        }
    }
}
