import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * ECDH in Blockchain - Enterprise Java 17 implementation.
 *
 * Features:
 * - secp256r1 ECDH using Java cryptographic providers
 * - HKDF-SHA256
 * - Typed wallet and transaction domain models
 * - Immutable transaction records
 * - Repository registration
 * - Policy-based transaction validation
 * - Nonce management
 * - Blockchain state transitions
 * - Hash-based integrity validation
 *
 * This implementation uses a simplified ledger rather than
 * a production distributed-consensus protocol.
 */

public class ECDHBlockchain {

    private static final String CURVE = "secp256r1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final HexFormat HEX = HexFormat.of();

    enum TransactionStatus {
        PENDING,
        INCLUDED,
        REJECTED
    }

    enum BlockStatus {
        CREATED,
        VALIDATED
    }

    static class DomainException extends RuntimeException {
        DomainException(String message) {
            super(message);
        }

        DomainException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record Wallet(
        String address,
        String publicKey,
        PrivateKey privateKey
    ) {}

    record Transaction(
        String id,
        String sender,
        String recipient,
        long amount,
        long nonce,
        String channelCommitment,
        long timestamp
    ) {
        Transaction {
            if (id == null || id.isBlank()) {
                throw new DomainException("Transaction ID is required.");
            }

            if (sender == null || recipient == null ||
                sender.isBlank() || recipient.isBlank()) {
                throw new DomainException("Wallet addresses are required.");
            }

            if (amount <= 0) {
                throw new DomainException("Amount must be positive.");
            }

            if (nonce < 0) {
                throw new DomainException("Nonce cannot be negative.");
            }

            if (channelCommitment == null ||
                !channelCommitment.matches("[a-f0-9]{64}")) {
                throw new DomainException("Invalid channel commitment.");
            }
        }
    }

    record ReviewResult(
        boolean eligible,
        List<String> violations
    ) {
        ReviewResult {
            violations = List.copyOf(violations);
        }
    }

    record Block(
        long index,
        String previousHash,
        long timestamp,
        List<Transaction> transactions,
        String hash,
        BlockStatus status
    ) {
        Block {
            transactions = List.copyOf(transactions);
        }
    }

    interface TransactionPolicy {
        List<String> evaluate(
            Transaction transaction,
            Map<String, Wallet> wallets,
            Map<String, Long> nonces
        );
    }

    static class StandardTransactionPolicy
        implements TransactionPolicy {

        @Override
        public List<String> evaluate(
            Transaction transaction,
            Map<String, Wallet> wallets,
            Map<String, Long> nonces
        ) {
            List<String> errors = new ArrayList<>();

            if (!wallets.containsKey(transaction.sender())) {
                errors.add("Sender is not registered.");
            }

            if (!wallets.containsKey(transaction.recipient())) {
                errors.add("Recipient is not registered.");
            }

            if (transaction.sender().equals(transaction.recipient())) {
                errors.add("Self-transfers are prohibited.");
            }

            long expected = nonces.getOrDefault(
                transaction.sender(), 0L
            );

            if (transaction.nonce() != expected) {
                errors.add(
                    "Nonce mismatch: expected " + expected
                );
            }

            return errors;
        }
    }

    static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HEX.formatHex(digest.digest(data));
        } catch (Exception exception) {
            throw new DomainException(
                "SHA-256 operation failed.", exception
            );
        }
    }

    static byte[] hkdf(
        byte[] inputKey,
        byte[] salt,
        byte[] info,
        int length
    ) {
        if (length <= 0 || length > 255 * 32) {
            throw new DomainException("Invalid HKDF output length.");
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            byte[] actualSalt = salt.length == 0
                ? new byte[32]
                : salt;

            mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));

            byte[] pseudorandomKey = mac.doFinal(inputKey);
            byte[] output = new byte[length];
            byte[] previous = new byte[0];

            int offset = 0;
            int counter = 1;

            while (offset < length) {
                mac.init(
                    new SecretKeySpec(
                        pseudorandomKey,
                        "HmacSHA256"
                    )
                );

                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);

                previous = mac.doFinal();

                int copyLength = Math.min(
                    previous.length,
                    length - offset
                );

                System.arraycopy(
                    previous, 0,
                    output, offset,
                    copyLength
                );

                offset += copyLength;
                counter++;
            }

            Arrays.fill(pseudorandomKey, (byte) 0);

            return output;

        } catch (Exception exception) {
            throw new DomainException(
                "HKDF derivation failed.", exception
            );
        }
    }

    static Wallet generateWallet() {
        try {
            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("EC");

            generator.initialize(
                new ECGenParameterSpec(CURVE),
                RANDOM
            );

            KeyPair pair = generator.generateKeyPair();

            byte[] encodedPublicKey =
                pair.getPublic().getEncoded();

            String publicKey = HEX.formatHex(encodedPublicKey);

            String address = sha256(encodedPublicKey).substring(0, 40);

            return new Wallet(
                address,
                publicKey,
                pair.getPrivate()
            );

        } catch (Exception exception) {
            throw new DomainException(
                "Wallet generation failed.", exception
            );
        }
    }

    static PublicKey decodePublicKey(String encoded) {
        try {
            byte[] bytes = HEX.parseHex(encoded);

            KeyFactory factory = KeyFactory.getInstance("EC");

            return factory.generatePublic(
                new X509EncodedKeySpec(bytes)
            );

        } catch (Exception exception) {
            throw new DomainException(
                "Invalid encoded public key.", exception
            );
        }
    }

    static byte[] establishSharedSecret(
        PrivateKey privateKey,
        String peerPublicKey
    ) {
        try {
            PublicKey publicKey = decodePublicKey(peerPublicKey);

            KeyAgreement agreement =
                KeyAgreement.getInstance("ECDH");

            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);

            return agreement.generateSecret();

        } catch (Exception exception) {
            throw new DomainException(
                "ECDH agreement failed.", exception
            );
        }
    }

    static byte[] deriveChannelKey(
        byte[] sharedSecret,
        String walletA,
        String walletB,
        String sessionId
    ) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new DomainException("Session ID is required.");
        }

        List<String> participants = new ArrayList<>(
            List.of(walletA, walletB)
        );

        Collections.sort(participants);

        String context = String.join(
            "|",
            participants
        ) + "|" + sessionId + "|blockchain-ecdh-v1";

        byte[] salt = hexToBytes(
            sha256(context.getBytes(StandardCharsets.UTF_8))
        );

        return hkdf(
            sharedSecret,
            salt,
            "secp256r1-secure-channel".getBytes(
                StandardCharsets.UTF_8
            ),
            32
        );
    }

    static byte[] hexToBytes(String hex) {
        return HEX.parseHex(hex);
    }

    static class BlockchainService {

        private final Map<String, Wallet> wallets =
            new HashMap<>();

        private final Map<String, Long> nonces =
            new HashMap<>();

        private final Set<String> transactionIds =
            new HashSet<>();

        private final List<Block> chain =
            new ArrayList<>();

        private final List<Transaction> pending =
            new ArrayList<>();

        private final TransactionPolicy policy;

        BlockchainService(TransactionPolicy policy) {
            this.policy = policy;
            createGenesisBlock();
        }

        private void createGenesisBlock() {
            String hash = sha256(
                "GENESIS".getBytes(StandardCharsets.UTF_8)
            );

            chain.add(new Block(
                0,
                "0".repeat(64),
                System.currentTimeMillis(),
                List.of(),
                hash,
                BlockStatus.VALIDATED
            ));
        }

        void registerWallet(Wallet wallet) {
            if (wallets.containsKey(wallet.address())) {
                throw new DomainException("Duplicate wallet.");
            }

            PublicKey decoded = decodePublicKey(wallet.publicKey());

            String expectedAddress = sha256(
                decoded.getEncoded()
            ).substring(0, 40);

            if (!expectedAddress.equals(wallet.address())) {
                throw new DomainException("Wallet identity mismatch.");
            }

            wallets.put(wallet.address(), wallet);
            nonces.put(wallet.address(), 0L);
        }

        ReviewResult validate(Transaction transaction) {
            List<String> errors = policy.evaluate(
                transaction,
                wallets,
                nonces
            );

            if (transactionIds.contains(transaction.id())) {
                errors.add("Duplicate transaction identifier.");
            }

            return new ReviewResult(errors.isEmpty(), errors);
        }

        void submit(Transaction transaction) {
            ReviewResult result = validate(transaction);

            if (!result.eligible()) {
                throw new DomainException(
                    String.join("; ", result.violations())
                );
            }

            transactionIds.add(transaction.id());

            nonces.put(
                transaction.sender(),
                transaction.nonce() + 1
            );

            pending.add(transaction);
        }

        Block mineBlock() {
            if (pending.isEmpty()) {
                throw new DomainException(
                    "No transactions to include."
                );
            }

            Block previous = chain.get(chain.size() - 1);

            List<Transaction> transactions =
                List.copyOf(pending);

            long index = chain.size();
            long timestamp = System.currentTimeMillis();

            String payload = serializeBlock(
                index,
                previous.hash(),
                timestamp,
                transactions
            );

            String hash = sha256(
                payload.getBytes(StandardCharsets.UTF_8)
            );

            Block block = new Block(
                index,
                previous.hash(),
                timestamp,
                transactions,
                hash,
                BlockStatus.CREATED
            );

            chain.add(block);
            pending.clear();

            return block;
        }

        private String serializeBlock(
            long index,
            String previousHash,
            long timestamp,
            List<Transaction> transactions
        ) {
            StringBuilder builder = new StringBuilder();

            builder.append(index)
                .append('|')
                .append(previousHash)
                .append('|')
                .append(timestamp);

            for (Transaction transaction : transactions) {
                builder.append('|')
                    .append(transaction.id())
                    .append('|')
                    .append(transaction.sender())
                    .append('|')
                    .append(transaction.recipient())
                    .append('|')
                    .append(transaction.amount())
                    .append('|')
                    .append(transaction.nonce())
                    .append('|')
                    .append(transaction.channelCommitment());
            }

            return builder.toString();
        }

        boolean verifyChain() {
            for (int i = 0; i < chain.size(); i++) {
                Block current = chain.get(i);

                String expectedHash;

                if (i == 0) {
                    expectedHash = sha256(
                        "GENESIS".getBytes(StandardCharsets.UTF_8)
                    );
                } else {
                    Block previous = chain.get(i - 1);

                    if (!current.previousHash().equals(previous.hash())) {
                        return false;
                    }

                    if (current.index() != previous.index() + 1) {
                        return false;
                    }

                    expectedHash = sha256(
                        serializeBlock(
                            current.index(),
                            current.previousHash(),
                            current.timestamp(),
                            current.transactions()
                        ).getBytes(StandardCharsets.UTF_8)
                    );
                }

                if (!current.hash().equals(expectedHash)) {
                    return false;
                }
            }

            return true;
        }

        List<Block> getChain() {
            return List.copyOf(chain);
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println(
                "ECDH IN BLOCKCHAIN - JAVA 17"
            );

            Wallet alice = generateWallet();
            Wallet bob = generateWallet();

            BlockchainService service =
                new BlockchainService(
                    new StandardTransactionPolicy()
                );

            service.registerWallet(alice);
            service.registerWallet(bob);

            String sessionId = HEX.formatHex(
                randomBytes(16)
            );

            byte[] aliceSecret = establishSharedSecret(
                alice.privateKey(),
                bob.publicKey()
            );

            byte[] bobSecret = establishSharedSecret(
                bob.privateKey(),
                alice.publicKey()
            );

            byte[] aliceKey = deriveChannelKey(
                aliceSecret,
                alice.address(),
                bob.address(),
                sessionId
            );

            byte[] bobKey = deriveChannelKey(
                bobSecret,
                bob.address(),
                alice.address(),
                sessionId
            );

            if (!MessageDigest.isEqual(aliceKey, bobKey)) {
                throw new DomainException(
                    "ECDH channel-key mismatch."
                );
            }

            System.out.println(
                "\nECDH agreement successful."
            );

            System.out.println(
                "Channel fingerprint: " +
                sha256(aliceKey).substring(0, 24)
            );

            String commitment = sha256(
                concatenate(
                    "channel-commitment-v1".getBytes(
                        StandardCharsets.UTF_8
                    ),
                    aliceKey
                )
            );

            Transaction transaction = new Transaction(
                "TX-ENTERPRISE-001",
                alice.address(),
                bob.address(),
                500,
                0,
                commitment,
                System.currentTimeMillis()
            );

            service.submit(transaction);

            Block block = service.mineBlock();

            System.out.println("\nBlock index: " + block.index());
            System.out.println("Block hash: " + block.hash());
            System.out.println(
                "Transaction count: " +
                block.transactions().size()
            );

            System.out.println(
                "\nBlockchain integrity: " +
                service.verifyChain()
            );

            try {
                service.submit(transaction);
            } catch (DomainException exception) {
                System.out.println(
                    "Replay rejected: " + exception.getMessage()
                );
            }

            System.out.println(
                "\nRegistered wallets: 2"
            );

            Arrays.fill(aliceSecret, (byte) 0);
            Arrays.fill(bobSecret, (byte) 0);
            Arrays.fill(aliceKey, (byte) 0);
            Arrays.fill(bobKey, (byte) 0);

            System.out.println(
                "ECDH blockchain demonstration completed."
            );

        } catch (Exception exception) {
            System.err.println(
                "Execution failed: " + exception.getMessage()
            );

            System.exit(1);
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] concatenate(byte[] first, byte[] second) {
        byte[] combined = Arrays.copyOf(
            first,
            first.length + second.length
        );

        System.arraycopy(
            second,
            0,
            combined,
            first.length,
            second.length
        );

        return combined;
    }
}
