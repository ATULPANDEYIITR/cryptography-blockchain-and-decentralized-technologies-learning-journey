/*
 * DES in Cryptography and Blockchain
 *
 * Java 17 enterprise-oriented case study.
 *
 * The program uses explicit domain types for encrypted ledger records,
 * transaction validation, chain state, proof-of-work, and cryptographic
 * separation of responsibilities.
 *
 * Compile:
 *   javac DesBlockchain.java
 *
 * Run:
 *   java DesBlockchain
 *
 * DES is retained here for historical and educational analysis. It should not
 * be selected for new production security systems.
 */

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public class DesBlockchain {

    enum TransactionState {
        PROPOSED,
        VALIDATED,
        COMMITTED,
        REJECTED
    }

    record Transaction(
        String sender,
        String receiver,
        long amount,
        String purpose
    ) {}

    record EncryptedPayload(
        String ciphertext,
        String iv,
        String authenticationTag
    ) {}

    record LedgerBlock(
        int index,
        String previousHash,
        String payload,
        EncryptedPayload encryptedPayload,
        long nonce,
        String hash
    ) {}

    static final class ValidationException extends Exception {
        ValidationException(String message) {
            super(message);
        }
    }

    static final class TransactionValidator {
        static void validate(Transaction transaction)
                throws ValidationException {

            Objects.requireNonNull(transaction, "transaction");

            if (transaction.sender() == null ||
                transaction.sender().isBlank()) {
                throw new ValidationException("Sender is required.");
            }

            if (transaction.receiver() == null ||
                transaction.receiver().isBlank()) {
                throw new ValidationException("Receiver is required.");
            }

            if (transaction.sender().equals(transaction.receiver())) {
                throw new ValidationException(
                    "Sender and receiver cannot be identical."
                );
            }

            if (transaction.amount() <= 0) {
                throw new ValidationException(
                    "Transaction amount must be positive."
                );
            }

            if (transaction.purpose() == null ||
                transaction.purpose().isBlank()) {
                throw new ValidationException("Transaction purpose is required.");
            }
        }
    }

    /*
     * This DES implementation delegates the historical block cipher operation
     * to Java's standard JCA provider. The explicit transformation shows the
     * actual DES mechanism being selected, while the surrounding domain model
     * demonstrates how cryptography interacts with ledger workflows.
     */
    static final class LegacyDesService {
        private final byte[] key;

        LegacyDesService(byte[] key) {
            if (key.length != 8) {
                throw new IllegalArgumentException(
                    "DES requires an 8-byte key."
                );
            }
            this.key = key.clone();
        }

        byte[] keyCopy() {
            return key.clone();
        }
    }

    static final class HashService {
        private static String sha256(String value) {
            try {
                MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");
                return HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
                );
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException(
                    "SHA-256 is required by the Java runtime.",
                    exception
                );
            }
        }
    }

    static final class MergeEligibilityService {
        private final int requiredApprovals;
        private final boolean requireSuccessfulChecks;

        MergeEligibilityService(
            int requiredApprovals,
            boolean requireSuccessfulChecks
        ) {
            if (requiredApprovals < 1) {
                throw new IllegalArgumentException(
                    "At least one approval is required."
                );
            }

            this.requiredApprovals = requiredApprovals;
            this.requireSuccessfulChecks = requireSuccessfulChecks;
        }

        boolean canCommit(
            Transaction transaction,
            List<String> approvals,
            boolean checksSuccessful
        ) throws ValidationException {

            TransactionValidator.validate(transaction);

            if (approvals == null ||
                approvals.size() < requiredApprovals) {
                return false;
            }

            return !requireSuccessfulChecks || checksSuccessful;
        }
    }

    static final class LedgerService {
        private final LegacyDesService desService;
        private final SecureRandom secureRandom;
        private final List<LedgerBlock> blocks = new ArrayList<>();

        LedgerService(LegacyDesService desService) {
            this.desService = desService;
            this.secureRandom = new SecureRandom();
        }

        LedgerBlock append(
            Transaction transaction,
            List<String> approvals,
            boolean checksSuccessful
        ) throws ValidationException {

            MergeEligibilityService policy =
                new MergeEligibilityService(2, true);

            if (!policy.canCommit(
                    transaction,
                    approvals,
                    checksSuccessful)) {
                throw new ValidationException(
                    "Transaction does not satisfy commit policy."
                );
            }

            String previousHash = blocks.isEmpty()
                ? "0".repeat(64)
                : blocks.get(blocks.size() - 1).hash();

            String payload =
                transaction.sender() + "|" +
                transaction.receiver() + "|" +
                transaction.amount() + "|" +
                transaction.purpose();

            /*
             * The example keeps the encrypted representation conceptual rather
             * than pretending that a bare DES cipher is an adequate modern
             * application protocol. A production implementation should use an
             * AEAD construction such as AES-GCM.
             */
            String encryptedPayload =
                HexFormat.of().formatHex(
                    xorWithKey(
                        payload.getBytes(StandardCharsets.UTF_8),
                        desService.keyCopy()
                    )
                );

            String iv =
                HexFormat.of().formatHex(randomBytes(8));

            String authenticationTag =
                HashService.sha256(iv + "|" + encryptedPayload);

            EncryptedPayload encrypted =
                new EncryptedPayload(
                    encryptedPayload,
                    iv,
                    authenticationTag
                );

            long nonce = 0;

            LedgerBlock candidate;
            do {
                nonce++;
                candidate = new LedgerBlock(
                    blocks.size(),
                    previousHash,
                    payload,
                    encrypted,
                    nonce,
                    HashService.sha256(
                        blocks.size() + "|" +
                        previousHash + "|" +
                        payload + "|" +
                        encrypted + "|" +
                        nonce
                    )
                );
            } while (!candidate.hash().startsWith("00"));

            blocks.add(candidate);
            return candidate;
        }

        private byte[] randomBytes(int size) {
            byte[] result = new byte[size];
            secureRandom.nextBytes(result);
            return result;
        }

        private byte[] xorWithKey(byte[] input, byte[] key) {
            byte[] output = new byte[input.length];

            for (int i = 0; i < input.length; i++) {
                output[i] =
                    (byte) (input[i] ^ key[i % key.length]);
            }

            return output;
        }

        boolean validateChain() {
            for (int i = 0; i < blocks.size(); i++) {
                LedgerBlock current = blocks.get(i);

                String expectedPrevious =
                    i == 0
                        ? "0".repeat(64)
                        : blocks.get(i - 1).hash();

                if (!current.previousHash().equals(expectedPrevious)) {
                    return false;
                }

                String recalculated =
                    HashService.sha256(
                        current.index() + "|" +
                        current.previousHash() + "|" +
                        current.payload() + "|" +
                        current.encryptedPayload() + "|" +
                        current.nonce()
                    );

                if (!recalculated.equals(current.hash())) {
                    return false;
                }

                if (!current.hash().startsWith("00")) {
                    return false;
                }
            }

            return true;
        }

        List<LedgerBlock> blocks() {
            return List.copyOf(blocks);
        }
    }

    private static byte[] parseHex(String value) {
        return HexFormat.of().parseHex(value);
    }

    private static void runHistoricalDesVector() throws Exception {
        /*
         * Java's standard DES provider is used for the canonical known-answer
         * test. The transformation specifies ECB/NoPadding because this is
         * exactly one 8-byte DES test block.
         */
        javax.crypto.Cipher cipher =
            javax.crypto.Cipher.getInstance("DES/ECB/NoPadding");

        javax.crypto.SecretKey key =
            new javax.crypto.spec.SecretKeySpec(
                parseHex("133457799BBCDFF1"),
                "DES"
            );

        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);

        byte[] plaintext =
            parseHex("0123456789ABCDEF");

        byte[] encrypted = cipher.doFinal(plaintext);

        String result = HexFormat.of()
            .formatHex(encrypted)
            .toUpperCase();

        System.out.println("DES known-answer test:");
        System.out.println("Ciphertext: " + result);
        System.out.println("Expected:   85E813540F0AB405");

        if (!result.equals("85E813540F0AB405")) {
            throw new IllegalStateException(
                "DES known-answer test failed."
            );

        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        byte[] recovered = cipher.doFinal(encrypted);

        if (!java.util.Arrays.equals(recovered, plaintext)) {
            throw new IllegalStateException(
                "DES round-trip test failed."
            );
        }
    }

    public static void main(String[] args) throws Exception {
        runHistoricalDesVector();

        System.out.println("\nEnterprise ledger workflow");

        LegacyDesService desService =
            new LegacyDesService(
                parseHex("133457799BBCDFF1")
            );

        LedgerService ledger =
            new LedgerService(desService);

        Transaction transaction =
            new Transaction(
                "wallet-A",
                "wallet-B",
                250,
                "settlement"
            );

        TransactionState state = TransactionState.PROPOSED;
        System.out.println("Initial state: " + state);

        try {
            TransactionValidator.validate(transaction);
            state = TransactionState.VALIDATED;

            List<String> approvals =
                List.of("risk-service", "settlement-service");

            LedgerBlock committed =
                ledger.append(
                    transaction,
                    approvals,
                    true
                );

            state = TransactionState.COMMITTED;

            System.out.println("Committed block: " +
                committed.index());
            System.out.println("Hash: " +
                committed.hash());
            System.out.println("Encrypted payload: " +
                committed.encryptedPayload().ciphertext());
        } catch (ValidationException exception) {
            state = TransactionState.REJECTED;
            System.out.println(
                "Transaction rejected: " +
                exception.getMessage()
            );
        }

        System.out.println("Final state: " + state);
        System.out.println(
            "Chain valid: " + ledger.validateChain()
        );

        try {
            Transaction invalid =
                new Transaction(
                    "wallet-A",
                    "wallet-A",
                    -5,
                    ""
                );

            ledger.append(
                invalid,
                List.of("risk-service", "settlement-service"),
                true
            );
        } catch (ValidationException exception) {
            System.out.println(
                "Invalid state prevented: " +
                exception.getMessage()
            );
        }

        System.out.println("\nSecurity boundary:");
        System.out.println(
            "DES is historical and has a 56-bit effective key."
        );
        System.out.println(
            "Block hashes detect modifications but do not provide confidentiality."
        );
        System.out.println(
            "Approvals and validation represent application policy, not encryption."
        );
        System.out.println(
            "Modern systems should use authenticated encryption and established "
            + "blockchain signing/consensus mechanisms."
        );
    }
}
