import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/*
 * Enterprise Repository Configuration Encryption Case Study
 *
 * Java uses the JCA/JCE cryptographic APIs so the implementation demonstrates
 * real AES rather than a hand-written production cipher.
 *
 * The domain is repository governance configuration:
 * - protected branch policies
 * - required reviews
 * - status-check requirements
 * - merge-policy metadata
 *
 * The encryption layer is intentionally kept separate from authorization.
 * Encrypting a policy record does not make that policy trustworthy or valid.
 *
 * ECB:
 *   AES independently encrypts every 16-byte block.
 *
 * CBC:
 *   plaintext block is XORed with the previous ciphertext block before AES.
 *   The first block uses an IV.
 *
 * Neither mode provides authentication.
 */

public class EcbCbcEnterpriseDemo {

    private static final int AES_KEY_BYTES = 32;
    private static final int AES_BLOCK_BYTES = 16;

    enum EncryptionMode {
        ECB,
        CBC
    }

    record EncryptedRecord(
        EncryptionMode mode,
        byte[] iv,
        byte[] ciphertext
    ) {
        EncryptedRecord {
            iv = iv == null ? null : iv.clone();
            ciphertext = ciphertext.clone();
        }

        @Override
        public byte[] iv() {
            return iv == null ? null : iv.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }
    }

    enum ReviewState {
        COMMENTED,
        CHANGES_REQUESTED,
        APPROVED
    }

    record Review(
        String reviewer,
        ReviewState state,
        String comment
    ) {}

    record RepositoryPolicy(
        int requiredApprovals,
        boolean requirePassingChecks,
        boolean requireLinearHistory,
        boolean restrictDirectPush
    ) {
        RepositoryPolicy {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException(
                    "Required approvals cannot be negative"
                );
            }
        }
    }

    static final class CryptoService {
        private final SecretKeySpec key;
        private final SecureRandom random;

        CryptoService(byte[] keyBytes) {
            if (keyBytes.length != AES_KEY_BYTES) {
                throw new IllegalArgumentException(
                    "AES-256 requires a 32-byte key"
                );
            }

            this.key = new SecretKeySpec(keyBytes, "AES");
            this.random = new SecureRandom();
        }

        EncryptedRecord encrypt(
            String plaintext,
            EncryptionMode mode
        ) throws GeneralSecurityException {
            byte[] plaintextBytes =
                plaintext.getBytes(StandardCharsets.UTF_8);

            if (mode == EncryptionMode.ECB) {
                Cipher cipher =
                    Cipher.getInstance("AES/ECB/PKCS5Padding");

                cipher.init(Cipher.ENCRYPT_MODE, key);

                return new EncryptedRecord(
                    EncryptionMode.ECB,
                    null,
                    cipher.doFinal(plaintextBytes)
                );
            }

            byte[] iv = new byte[AES_BLOCK_BYTES];
            random.nextBytes(iv);

            Cipher cipher =
                Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new IvParameterSpec(iv)
            );

            return new EncryptedRecord(
                EncryptionMode.CBC,
                iv,
                cipher.doFinal(plaintextBytes)
            );
        }

        String decrypt(
            EncryptedRecord record
        ) throws GeneralSecurityException {
            Cipher cipher;

            if (record.mode() == EncryptionMode.ECB) {
                cipher =
                    Cipher.getInstance("AES/ECB/PKCS5Padding");

                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                if (record.iv() == null ||
                    record.iv().length != AES_BLOCK_BYTES) {
                    throw new IllegalArgumentException(
                        "CBC requires a 16-byte IV"
                    );
                }

                cipher =
                    Cipher.getInstance("AES/CBC/PKCS5Padding");

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new IvParameterSpec(record.iv())
                );
            }

            return new String(
                cipher.doFinal(record.ciphertext()),
                StandardCharsets.UTF_8
            );
        }
    }

    static final class RepositoryGovernanceService {
        boolean mergeEligible(
            RepositoryPolicy policy,
            List<Review> reviews,
            Map<String, Boolean> statusChecks,
            boolean directPushAttempt
        ) {
            if (directPushAttempt && policy.restrictDirectPush()) {
                return false;
            }

            long approvals = reviews.stream()
                .filter(review -> review.state() == ReviewState.APPROVED)
                .count();

            boolean hasChangeRequest = reviews.stream()
                .anyMatch(
                    review ->
                        review.state() == ReviewState.CHANGES_REQUESTED
                );

            if (hasChangeRequest) {
                return false;
            }

            if (approvals < policy.requiredApprovals()) {
                return false;
            }

            if (policy.requirePassingChecks()) {
                boolean everyCheckPassed =
                    statusChecks.values()
                        .stream()
                        .allMatch(Boolean::booleanValue);

                if (!everyCheckPassed) {
                    return false;
                }
            }

            return true;
        }
    }

    static byte[] deriveDemoKey() throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        return digest.digest(
            "repository-policy-ecb-cbc-demo".getBytes(
                StandardCharsets.UTF_8
            )
        );
    }

    static void demonstratePolicyWorkflow(
        CryptoService cryptoService
    ) throws GeneralSecurityException {
        RepositoryPolicy policy = new RepositoryPolicy(
            2,
            true,
            true,
            true
        );

        List<Review> reviews = new ArrayList<>(
            List.of(
                new Review(
                    "reviewer-alice",
                    ReviewState.APPROVED,
                    "Protected branch policy satisfied."
                ),
                new Review(
                    "reviewer-bob",
                    ReviewState.APPROVED,
                    "Status-check coverage is acceptable."
                )
            )
        );

        Map<String, Boolean> checks = Map.of(
            "unit-tests",
            true,
            "static-analysis",
            true,
            "integration-tests",
            true
        );

        RepositoryGovernanceService governance =
            new RepositoryGovernanceService();

        boolean eligible = governance.mergeEligible(
            policy,
            reviews,
            checks,
            false
        );

        String policyDocument =
            "requiredApprovals=" + policy.requiredApprovals()
            + ";requirePassingChecks=" + policy.requirePassingChecks()
            + ";requireLinearHistory=" + policy.requireLinearHistory()
            + ";restrictDirectPush=" + policy.restrictDirectPush();

        EncryptedRecord encrypted =
            cryptoService.encrypt(
                policyDocument,
                EncryptionMode.CBC
            );

        System.out.println("=== Enterprise governance policy ===");
        System.out.println("Merge eligible: " + eligible);
        System.out.println(
            "Encrypted policy: "
            + hex(encrypted.ciphertext())
        );
        System.out.println(
            "CBC IV: "
            + hex(encrypted.iv())
        );
        System.out.println(
            "Recovered policy: "
            + cryptoService.decrypt(encrypted)
        );
        System.out.println();
    }

    static void demonstrateECBPatternLeakage(
        CryptoService cryptoService
    ) throws GeneralSecurityException {
        String repeated =
            "ABCDEFGHIJKLMNOP".repeat(6);

        EncryptedRecord record =
            cryptoService.encrypt(
                repeated,
                EncryptionMode.ECB
            );

        byte[] ciphertext = record.ciphertext();
        List<String> blocks = splitHexBlocks(ciphertext);

        long distinct =
            blocks.stream().distinct().count();

        System.out.println("=== ECB pattern leakage ===");
        System.out.println("Ciphertext blocks:");

        for (String block : blocks) {
            System.out.println(block);
        }

        System.out.println(
            "Total blocks: " + blocks.size()
        );

        System.out.println(
            "Distinct blocks: " + distinct
        );

        System.out.println();
    }

    static void demonstrateCBCRandomization(
        CryptoService cryptoService
    ) throws GeneralSecurityException {
        String policy =
            "requiredApprovals=2;checks=passing;";

        EncryptedRecord first =
            cryptoService.encrypt(
                policy,
                EncryptionMode.CBC
            );

        EncryptedRecord second =
            cryptoService.encrypt(
                policy,
                EncryptionMode.CBC
            );

        System.out.println("=== CBC IV randomization ===");
        System.out.println(
            "First IV:  " + hex(first.iv())
        );
        System.out.println(
            "Second IV: " + hex(second.iv())
        );
        System.out.println(
            "Ciphertexts equal: "
            + Arrays.equals(
                first.ciphertext(),
                second.ciphertext()
            )
        );

        System.out.println();
    }

    static void demonstrateInvalidCBCData(
        CryptoService cryptoService
    ) {
        System.out.println("=== CBC validation failure ===");

        EncryptedRecord malformed =
            new EncryptedRecord(
                EncryptionMode.CBC,
                new byte[8],
                new byte[16]
            );

        try {
            cryptoService.decrypt(malformed);
            System.out.println(
                "Unexpectedly accepted malformed IV."
            );
        } catch (Exception exception) {
            System.out.println(
                "Malformed CBC record rejected: "
                + exception.getMessage()
            );
        }

        System.out.println();
    }

    static List<String> splitHexBlocks(byte[] data) {
        if (data.length % AES_BLOCK_BYTES != 0) {
            throw new IllegalArgumentException(
                "AES ciphertext must be block aligned"
            );
        }

        List<String> blocks = new ArrayList<>();

        for (
            int offset = 0;
            offset < data.length;
            offset += AES_BLOCK_BYTES
        ) {
            byte[] block =
                Arrays.copyOfRange(
                    data,
                    offset,
                    offset + AES_BLOCK_BYTES
                );

            blocks.add(hex(block));
        }

        return blocks;
    }

    static String hex(byte[] data) {
        if (data == null) {
            return "<none>";
        }

        StringBuilder builder = new StringBuilder();

        for (byte value : data) {
            builder.append(
                String.format("%02x", value & 0xFF)
            );
        }

        return builder.toString();
    }

    public static void main(String[] args) {
        try {
            byte[] key = deriveDemoKey();
            CryptoService cryptoService =
                new CryptoService(key);

            demonstratePolicyWorkflow(cryptoService);
            demonstrateECBPatternLeakage(cryptoService);
            demonstrateCBCRandomization(cryptoService);
            demonstrateInvalidCBCData(cryptoService);

            System.out.println(
                "The enterprise model keeps encryption separate from "
                + "repository governance decisions."
            );
            System.out.println(
                "Production systems should prefer authenticated encryption."
            );

        } catch (
            GeneralSecurityException |
            IllegalArgumentException exception
        ) {
            System.err.println(
                "Application failure: "
                + exception.getMessage()
            );
        }
    }
}
