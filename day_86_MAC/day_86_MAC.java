import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.time.Instant;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.HexFormat;
import java.util.UUID;

/**
 * MAC IN CRYPTOGRAPHY AND BLOCKCHAIN
 *
 * Enterprise-oriented Java 17 implementation.
 *
 * Features:
 * - HMAC-SHA256
 * - Cryptographic key registry
 * - Immutable transaction data
 * - Domain validation
 * - Nonce and replay management
 * - Transaction authentication
 * - Block integrity verification
 * - Blockchain state transitions
 * - Authentication policy enforcement
 * - Failure classification
 */

public class Main {

    // ========================================================
    // 1. DOMAIN EXCEPTIONS
    // ========================================================

    static class DomainException extends RuntimeException {
        DomainException(String message) {
            super(message);
        }
    }

    static class InvalidKeyException extends DomainException {
        InvalidKeyException(String message) {
            super(message);
        }
    }

    static class AuthenticationException extends DomainException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class ReplayException extends DomainException {
        ReplayException(String message) {
            super(message);
        }
    }

    // ========================================================
    // 2. CRYPTOGRAPHIC UTILITIES
    // ========================================================

    static final class CryptoUtils {

        private static final SecureRandom RANDOM =
                new SecureRandom();

        private CryptoUtils() {}

        static byte[] randomBytes(int length) {
            if (length <= 0) {
                throw new IllegalArgumentException(
                        "Length must be positive"
                );
            }

            byte[] result = new byte[length];
            RANDOM.nextBytes(result);

            return result;
        }

        static String hex(byte[] bytes) {
            return HexFormat.of().formatHex(bytes);
        }

        static byte[] unhex(String value) {
            try {
                return HexFormat.of().parseHex(value);
            } catch (IllegalArgumentException error) {
                throw new AuthenticationException(
                        "Invalid hexadecimal authentication tag"
                );
            }
        }

        static byte[] sha256(byte[] data) {
            try {
                return MessageDigest
                        .getInstance("SHA-256")
                        .digest(data);
            } catch (Exception error) {
                throw new DomainException(
                        "SHA-256 unavailable"
                );
            }
        }

        static String sha256Hex(byte[] data) {
            return hex(sha256(data));
        }

        static byte[] hmac(byte[] secret, byte[] message) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");

                mac.init(
                        new SecretKeySpec(
                                secret,
                                "HmacSHA256"
                        )
                );

                return mac.doFinal(message);

            } catch (Exception error) {
                throw new DomainException(
                        "HMAC processing failed"
                );
            }
        }

        static boolean constantTimeEquals(
                byte[] expected,
                byte[] supplied
        ) {

            if (
                    expected == null ||
                    supplied == null ||
                    expected.length != supplied.length
            ) {
                return false;
            }

            return MessageDigest.isEqual(
                    expected,
                    supplied
            );
        }
    }

    // ========================================================
    // 3. KEY MANAGEMENT
    // ========================================================

    record KeyMetadata(
            String keyId,
            String algorithm,
            Instant createdAt
    ) {}

    static final class KeyRegistry {

        private final Map<String, byte[]> keys =
                new HashMap<>();

        private final Map<String, KeyMetadata> metadata =
                new HashMap<>();

        public synchronized KeyMetadata generate(String keyId) {

            validateKeyId(keyId);

            if (keys.containsKey(keyId)) {
                throw new InvalidKeyException(
                        "Key already exists"
                );
            }

            byte[] secret = CryptoUtils.randomBytes(32);

            keys.put(keyId, secret);

            KeyMetadata details = new KeyMetadata(
                    keyId,
                    "HmacSHA256",
                    Instant.now()
            );

            metadata.put(keyId, details);

            return details;
        }

        public synchronized void register(
                String keyId,
                byte[] secret
        ) {

            validateKeyId(keyId);

            if (secret == null || secret.length < 32) {
                throw new InvalidKeyException(
                        "Key must contain at least 32 bytes"
                );
            }

            if (keys.containsKey(keyId)) {
                throw new InvalidKeyException(
                        "Duplicate key identifier"
                );
            }

            keys.put(keyId, secret.clone());

            metadata.put(
                    keyId,
                    new KeyMetadata(
                            keyId,
                            "HmacSHA256",
                            Instant.now()
                    )
            );
        }

        private void validateKeyId(String keyId) {
            if (keyId == null || keyId.isBlank()) {
                throw new InvalidKeyException(
                        "Invalid key identifier"
                );
            }
        }

        public synchronized byte[] get(String keyId) {

            byte[] secret = keys.get(keyId);

            if (secret == null) {
                throw new InvalidKeyException(
                        "Unknown key identifier"
                );
            }

            return secret.clone();
        }

        public synchronized KeyMetadata metadata(String keyId) {
            KeyMetadata result = metadata.get(keyId);

            if (result == null) {
                throw new InvalidKeyException("Unknown key");
            }

            return result;
        }
    }

    // ========================================================
    // 4. CANONICAL SERIALIZATION
    // ========================================================

    static final class CanonicalSerializer {

        private CanonicalSerializer() {}

        static byte[] serialize(Map<String, String> fields) {

            StringBuilder result = new StringBuilder();

            List<String> keys = new ArrayList<>(
                    fields.keySet()
            );

            Collections.sort(keys);

            for (String key : keys) {

                String value = Objects.requireNonNull(
                        fields.get(key)
                );

                // Length-prefixing prevents delimiter ambiguity.
                result.append(key.length())
                        .append(':')
                        .append(key)
                        .append(value.length())
                        .append(':')
                        .append(value);
            }

            return result.toString().getBytes(
                    StandardCharsets.UTF_8
            );
        }
    }

    // ========================================================
    // 5. MAC SERVICE
    // ========================================================

    static final class MACService {

        private final KeyRegistry registry;

        MACService(KeyRegistry registry) {
            this.registry = registry;
        }

        public String generate(
                String keyId,
                byte[] message
        ) {

            Objects.requireNonNull(message);

            return CryptoUtils.hex(
                    CryptoUtils.hmac(
                            registry.get(keyId),
                            message
                    )
            );
        }

        public boolean verify(
                String keyId,
                byte[] message,
                String suppliedMAC
        ) {

            if (
                    message == null ||
                    suppliedMAC == null
            ) {
                return false;
            }

            try {

                byte[] expected = CryptoUtils.hmac(
                        registry.get(keyId),
                        message
                );

                byte[] supplied =
                        CryptoUtils.unhex(suppliedMAC);

                return CryptoUtils.constantTimeEquals(
                        expected,
                        supplied
                );

            } catch (DomainException error) {
                return false;
            }
        }
    }

    // ========================================================
    // 6. TRANSACTION DOMAIN
    // ========================================================

    record Transaction(
            String transactionId,
            String sender,
            String receiver,
            long amountMinor,
            long nonce,
            String keyId
    ) {

        Transaction {

            if (
                    transactionId == null ||
                    transactionId.isBlank()
            ) {
                throw new DomainException(
                        "Transaction ID is required"
                );
            }

            if (
                    sender == null ||
                    receiver == null ||
                    sender.isBlank() ||
                    receiver.isBlank()
            ) {
                throw new DomainException(
                        "Transaction participants are required"
                );
            }

            if (sender.equals(receiver)) {
                throw new DomainException(
                        "Self-transfer is prohibited"
                );
            }

            if (amountMinor <= 0) {
                throw new DomainException(
                        "Amount must be positive"
                );
            }

            if (nonce < 0) {
                throw new DomainException(
                        "Nonce cannot be negative"
                );
            }

            if (keyId == null || keyId.isBlank()) {
                throw new DomainException(
                        "Key identifier is required"
                );
            }
        }

        Map<String, String> fields() {

            Map<String, String> values = new HashMap<>();

            values.put("transactionId", transactionId);
            values.put("sender", sender);
            values.put("receiver", receiver);
            values.put("amountMinor", Long.toString(amountMinor));
            values.put("nonce", Long.toString(nonce));
            values.put("keyId", keyId);

            return values;
        }

        byte[] canonicalBytes() {
            return CanonicalSerializer.serialize(fields());
        }
    }

    record AuthenticatedTransaction(
            Transaction transaction,
            String mac,
            Instant authenticatedAt
    ) {}

    // ========================================================
    // 7. TRANSACTION AUTHENTICATION SERVICE
    // ========================================================

    static final class TransactionService {

        private final MACService macService;

        TransactionService(MACService macService) {
            this.macService = macService;
        }

        public AuthenticatedTransaction authenticate(
                Transaction transaction
        ) {

            String mac = macService.generate(
                    transaction.keyId(),
                    transaction.canonicalBytes()
            );

            return new AuthenticatedTransaction(
                    transaction,
                    mac,
                    Instant.now()
            );
        }

        public boolean verify(
                AuthenticatedTransaction authenticated
        ) {

            if (authenticated == null) {
                return false;
            }

            Transaction transaction =
                    authenticated.transaction();

            return macService.verify(
                    transaction.keyId(),
                    transaction.canonicalBytes(),
                    authenticated.mac()
            );
        }
    }

    // ========================================================
    // 8. REPLAY PROTECTION
    // ========================================================

    static final class ReplayGuard {

        private final Set<String> accepted =
                new HashSet<>();

        public synchronized void accept(
                AuthenticatedTransaction authenticated
        ) {

            Transaction tx = authenticated.transaction();

            String identity =
                    tx.sender() + ":" + tx.nonce();

            if (!accepted.add(identity)) {
                throw new ReplayException(
                        "Transaction nonce already processed"
                );
            }
        }
    }

    // ========================================================
    // 9. BLOCK DOMAIN
    // ========================================================

    record Block(
            long index,
            Instant timestamp,
            String previousHash,
            List<AuthenticatedTransaction> transactions,
            String hash
    ) {

        Block {
            transactions = List.copyOf(transactions);
        }
    }

    // ========================================================
    // 10. BLOCKCHAIN HASHING
    // ========================================================

    static final class BlockHasher {

        private BlockHasher() {}

        static String hash(
                long index,
                Instant timestamp,
                String previousHash,
                List<AuthenticatedTransaction> transactions
        ) {

            StringBuilder data = new StringBuilder();

            data.append(index)
                    .append('|')
                    .append(timestamp.toEpochMilli())
                    .append('|')
                    .append(previousHash);

            for (AuthenticatedTransaction authenticated :
                    transactions) {

                Transaction tx = authenticated.transaction();

                data.append('|')
                        .append(tx.transactionId())
                        .append('|')
                        .append(authenticated.mac());
            }

            return CryptoUtils.sha256Hex(
                    data.toString().getBytes(
                            StandardCharsets.UTF_8
                    )
            );
        }
    }

    // ========================================================
    // 11. ENTERPRISE BLOCKCHAIN SERVICE
    // ========================================================

    enum BlockchainState {
        INITIALIZED,
        ACTIVE,
        VALIDATION_FAILED
    }

    static final class BlockchainService {

        private final List<Block> blocks =
                new ArrayList<>();

        private final TransactionService transactionService;

        private BlockchainState state =
                BlockchainState.INITIALIZED;

        BlockchainService(TransactionService service) {

            this.transactionService = service;

            Instant now = Instant.now();

            String genesisHash = BlockHasher.hash(
                    0,
                    now,
                    "0".repeat(64),
                    List.of()
            );

            blocks.add(
                    new Block(
                            0,
                            now,
                            "0".repeat(64),
                            List.of(),
                            genesisHash
                    )
            );
        }

        public synchronized Block append(
                List<AuthenticatedTransaction> transactions
        ) {

            if (
                    transactions == null ||
                    transactions.isEmpty()
            ) {
                throw new DomainException(
                        "Block requires at least one transaction"
                );
            }

            Set<String> identifiers = new HashSet<>();

            for (AuthenticatedTransaction tx : transactions) {

                if (!transactionService.verify(tx)) {
                    throw new AuthenticationException(
                            "Invalid transaction MAC"
                    );
                }

                String id = tx.transaction().transactionId();

                if (!identifiers.add(id)) {
                    throw new DomainException(
                            "Duplicate transaction in block"
                    );
                }

                for (Block existing : blocks) {
                    for (AuthenticatedTransaction stored :
                            existing.transactions()) {

                        if (
                                stored.transaction()
                                        .transactionId()
                                        .equals(id)
                        ) {
                            throw new DomainException(
                                    "Transaction already committed"
                            );
                        }
                    }
                }
            }

            Block previous = blocks.get(blocks.size() - 1);

            Instant now = Instant.now();

            List<AuthenticatedTransaction> immutableTransactions =
                    List.copyOf(transactions);

            long index = blocks.size();

            String hash = BlockHasher.hash(
                    index,
                    now,
                    previous.hash(),
                    immutableTransactions
            );

            Block block = new Block(
                    index,
                    now,
                    previous.hash(),
                    immutableTransactions,
                    hash
            );

            blocks.add(block);
            state = BlockchainState.ACTIVE;

            return block;
        }

        public synchronized boolean validate() {

            for (int i = 0; i < blocks.size(); i++) {

                Block current = blocks.get(i);

                String expectedPrevious =
                        i == 0
                                ? "0".repeat(64)
                                : blocks.get(i - 1).hash();

                if (!current.previousHash().equals(expectedPrevious)) {
                    state = BlockchainState.VALIDATION_FAILED;
                    return false;
                }

                String calculated = BlockHasher.hash(
                        current.index(),
                        current.timestamp(),
                        current.previousHash(),
                        current.transactions()
                );

                if (!calculated.equals(current.hash())) {
                    state = BlockchainState.VALIDATION_FAILED;
                    return false;
                }

                for (AuthenticatedTransaction tx :
                        current.transactions()) {

                    if (!transactionService.verify(tx)) {
                        state = BlockchainState.VALIDATION_FAILED;
                        return false;
                    }
                }
            }

            return true;
        }

        public synchronized List<Block> blocks() {
            return List.copyOf(blocks);
        }

        public BlockchainState state() {
            return state;
        }
    }

    // ========================================================
    // 12. EXECUTION
    // ========================================================

    public static void main(String[] args) {

        System.out.println("MAC AND BLOCKCHAIN");
        System.out.println("=".repeat(55));

        // Key management.
        KeyRegistry registry = new KeyRegistry();

        registry.generate("enterprise-node-001");

        MACService macService = new MACService(registry);

        // Basic HMAC.
        byte[] message = "Blockchain transaction"
                .getBytes(StandardCharsets.UTF_8);

        String tag = macService.generate(
                "enterprise-node-001",
                message
        );

        System.out.println("\n1. HMAC-SHA256");

        System.out.println("MAC: " + tag);

        System.out.println(
                "Valid: " +
                macService.verify(
                        "enterprise-node-001",
                        message,
                        tag
                )
        );

        System.out.println(
                "Tampered: " +
                macService.verify(
                        "enterprise-node-001",
                        "Modified transaction".getBytes(
                                StandardCharsets.UTF_8
                        ),
                        tag
                )
        );

        // Transaction.
        TransactionService transactionService =
                new TransactionService(macService);

        Transaction transaction = new Transaction(
                UUID.randomUUID().toString(),
                "wallet-A",
                "wallet-B",
                15000,
                1,
                "enterprise-node-001"
        );

        AuthenticatedTransaction authenticated =
                transactionService.authenticate(transaction);

        System.out.println("\n2. Transaction Authentication");

        System.out.println(
                "Valid: " +
                transactionService.verify(authenticated)
        );

        // Replay protection.
        ReplayGuard replayGuard = new ReplayGuard();

        System.out.println("\n3. Replay Protection");

        replayGuard.accept(authenticated);

        System.out.println("First transaction accepted");

        try {
            replayGuard.accept(authenticated);
        } catch (ReplayException error) {
            System.out.println("Replay blocked: " + error.getMessage());
        }

        // Blockchain.
        BlockchainService blockchain =
                new BlockchainService(transactionService);

        Block block = blockchain.append(
                List.of(authenticated)
        );

        System.out.println("\n4. Blockchain");

        System.out.println("Block index: " + block.index());

        System.out.println("Block hash: " + block.hash());

        System.out.println("Valid chain: " + blockchain.validate());

        System.out.println("State: " + blockchain.state());

        // Tampering.
        Transaction modified = new Transaction(
                transaction.transactionId(),
                transaction.sender(),
                transaction.receiver(),
                999999,
                transaction.nonce(),
                transaction.keyId()
        );

        AuthenticatedTransaction forged =
                new AuthenticatedTransaction(
                        modified,
                        authenticated.mac(),
                        Instant.now()
                );

        System.out.println("\n5. Tampering Detection");

        System.out.println(
                "Modified transaction valid: " +
                transactionService.verify(forged)
        );

        // Invalid domain state.
        System.out.println("\n6. Domain Validation");

        try {

            new Transaction(
                    "TX-INVALID",
                    "wallet-A",
                    "wallet-A",
                    100,
                    1,
                    "enterprise-node-001"
            );

        } catch (DomainException error) {
            System.out.println("Rejected: " + error.getMessage());
        }

        if (!blockchain.validate()) {
            throw new DomainException(
                    "Blockchain validation failed"
            );
        }

        if (transactionService.verify(forged)) {
            throw new DomainException(
                    "Tampering test failed"
            );
        }

        System.out.println("\nAll enterprise authentication tests passed.");
    }
}
