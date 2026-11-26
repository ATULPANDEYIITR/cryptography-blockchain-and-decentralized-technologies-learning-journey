import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/*
 * HMAC-SHA256 and Enterprise Blockchain Governance
 *
 * Java 17
 * No third-party dependencies.
 *
 * Enterprise-oriented implementation:
 * - Explicit domain records and enums.
 * - HMAC authentication service.
 * - Key lifecycle and rotation.
 * - Immutable transaction payloads.
 * - Nonce and replay controls.
 * - Transaction processing service.
 * - Blockchain integrity verification.
 * - Atomic block commitment.
 * - Audit reporting.
 */

public class HmacBlockchainEnterprise {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String HASH = "SHA-256";
    private static final String ZERO_HASH = "0".repeat(64);

    // ========================================================
    // 1. DOMAIN EXCEPTIONS
    // ========================================================

    static class DomainException extends RuntimeException {
        DomainException(String message) {
            super(message);
        }

        DomainException(String message, Throwable cause) {
            super(message, cause);
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

    static class PolicyException extends DomainException {
        PolicyException(String message) {
            super(message);
        }
    }

    // ========================================================
    // 2. DOMAIN ENUMS AND RECORDS
    // ========================================================

    enum KeyStatus {
        ACTIVE,
        RETIRED,
        REVOKED
    }

    enum TransactionStatus {
        CREATED,
        AUTHENTICATED,
        PENDING,
        COMMITTED,
        REJECTED
    }

    enum BlockStatus {
        VALID,
        INVALID
    }

    record KeyMetadata(
        String keyId,
        KeyStatus status,
        long createdAt
    ) {}

    record TransactionPayload(
        String transactionId,
        String sender,
        String receiver,
        long amount,
        long nonce,
        long timestamp,
        String keyId
    ) {
        TransactionPayload {
            Objects.requireNonNull(transactionId);
            Objects.requireNonNull(sender);
            Objects.requireNonNull(receiver);
            Objects.requireNonNull(keyId);

            if (
                transactionId.isBlank() ||
                sender.isBlank() ||
                receiver.isBlank() ||
                keyId.isBlank()
            ) {
                throw new PolicyException(
                    "Required transaction fields cannot be blank."
                );
            }

            if (sender.equals(receiver)) {
                throw new PolicyException(
                    "Self-transfers are not supported."
                );
            }

            if (amount <= 0 || nonce < 0) {
                throw new PolicyException(
                    "Invalid transaction amount or nonce."
                );
            }
        }

        byte[] serialize() {
            String data = String.join("|",
                transactionId,
                sender,
                receiver,
                Long.toString(amount),
                Long.toString(nonce),
                Long.toString(timestamp),
                keyId
            );

            return data.getBytes(StandardCharsets.UTF_8);
        }
    }

    record AuthenticatedTransaction(
        TransactionPayload payload,
        String signature,
        TransactionStatus status
    ) {
        AuthenticatedTransaction {
            Objects.requireNonNull(payload);
            Objects.requireNonNull(signature);
            Objects.requireNonNull(status);
        }
    }

    record Block(
        long index,
        String previousHash,
        long timestamp,
        List<AuthenticatedTransaction> transactions,
        String hash
    ) {
        Block {
            transactions = List.copyOf(transactions);
        }
    }

    record AuditResult(
        boolean valid,
        int blockCount,
        int transactionCount,
        String message
    ) {}

    // ========================================================
    // 3. CANONICAL SERIALIZATION
    // ========================================================

    static final class CanonicalSerializer {

        private CanonicalSerializer() {}

        static byte[] serialize(byte[] input) {
            return input.clone();
        }

        static byte[] serializeBlock(
            long index,
            String previousHash,
            long timestamp,
            List<AuthenticatedTransaction> transactions
        ) {
            StringBuilder builder = new StringBuilder();

            builder.append(index)
                .append('|')
                .append(previousHash)
                .append('|')
                .append(timestamp);

            for (AuthenticatedTransaction tx : transactions) {
                builder.append('|')
                    .append(HexFormat.of().formatHex(
                        tx.payload().serialize()
                    ))
                    .append('|')
                    .append(tx.signature());
            }

            return builder.toString().getBytes(
                StandardCharsets.UTF_8
            );
        }
    }

    // ========================================================
    // 4. CRYPTOGRAPHIC SERVICE
    // ========================================================

    static final class CryptographicService {

        private final SecureRandom random = new SecureRandom();

        byte[] generateSecret() {
            byte[] secret = new byte[32];
            random.nextBytes(secret);
            return secret;
        }

        String sha256(byte[] data) {
            try {
                return HexFormat.of().formatHex(
                    MessageDigest.getInstance(HASH).digest(data)
                );
            } catch (GeneralSecurityException e) {
                throw new DomainException(
                    "SHA-256 operation failed.", e
                );
            }
        }

        String hmac(byte[] data, byte[] secret) {
            if (secret == null || secret.length < 32) {
                throw new PolicyException(
                    "HMAC secret must contain at least 32 bytes."
                );
            }

            try {
                Mac mac = Mac.getInstance(ALGORITHM);

                mac.init(new SecretKeySpec(
                    secret,
                    ALGORITHM
                ));

                return HexFormat.of().formatHex(
                    mac.doFinal(data)
                );

            } catch (GeneralSecurityException e) {
                throw new DomainException(
                    "HMAC operation failed.", e
                );
            }
        }

        boolean verify(
            byte[] data,
            String suppliedTag,
            byte[] secret
        ) {
            if (
                suppliedTag == null ||
                !suppliedTag.matches("[0-9a-fA-F]{64}")
            ) {
                return false;
            }

            try {
                byte[] expected = HexFormat.of().parseHex(
                    hmac(data, secret)
                );

                byte[] supplied = HexFormat.of().parseHex(
                    suppliedTag
                );

                return MessageDigest.isEqual(
                    expected,
                    supplied
                );

            } catch (RuntimeException e) {
                return false;
            }
        }
    }

    // ========================================================
    // 5. ENTERPRISE KEY MANAGEMENT
    // ========================================================

    static final class KeyManagementService {

        private record InternalKey(
            byte[] secret,
            KeyStatus status,
            long createdAt
        ) {
            InternalKey {
                secret = secret.clone();
            }
        }

        private final Map<String, InternalKey> keys =
            new ConcurrentHashMap<>();

        private final CryptographicService crypto;

        KeyManagementService(CryptographicService crypto) {
            this.crypto = crypto;
        }

        synchronized KeyMetadata create(String keyId) {
            if (
                keyId == null ||
                keyId.isBlank() ||
                keys.containsKey(keyId)
            ) {
                throw new PolicyException(
                    "Invalid or duplicate key identifier."
                );
            }

            keys.put(
                keyId,
                new InternalKey(
                    crypto.generateSecret(),
                    KeyStatus.ACTIVE,
                    System.currentTimeMillis()
                )
            );

            return metadata(keyId);
        }

        private InternalKey requireKey(String keyId) {
            InternalKey key = keys.get(keyId);

            if (
                key == null ||
                key.status() == KeyStatus.REVOKED
            ) {
                throw new AuthenticationException(
                    "Key unavailable or revoked."
                );
            }

            return key;
        }

        KeyMetadata metadata(String keyId) {
            InternalKey key = requireKey(keyId);

            return new KeyMetadata(
                keyId,
                key.status(),
                key.createdAt()
            );
        }

        synchronized KeyMetadata rotate(
            String oldId,
            String newId
        ) {
            InternalKey old = requireKey(oldId);

            if (old.status() != KeyStatus.ACTIVE) {
                throw new PolicyException(
                    "Only active keys can be rotated."
                );
            }

            KeyMetadata created = create(newId);

            keys.put(
                oldId,
                new InternalKey(
                    old.secret(),
                    KeyStatus.RETIRED,
                    old.createdAt()
                )
            );

            return created;
        }

        synchronized void revoke(String keyId) {
            InternalKey old = requireKey(keyId);

            keys.put(
                keyId,
                new InternalKey(
                    old.secret(),
                    KeyStatus.REVOKED,
                    old.createdAt()
                )
            );
        }

        String sign(
            String keyId,
            byte[] message
        ) {
            InternalKey key = requireKey(keyId);

            if (key.status() != KeyStatus.ACTIVE) {
                throw new AuthenticationException(
                    "Retired key cannot create new signatures."
                );
            }

            return crypto.hmac(message, key.secret());
        }

        boolean verify(
            String keyId,
            byte[] message,
            String signature
        ) {
            InternalKey key = requireKey(keyId);

            return crypto.verify(
                message,
                signature,
                key.secret()
            );
        }
    }

    // ========================================================
    // 6. TRANSACTION AUTHENTICATION SERVICE
    // ========================================================

    static final class TransactionAuthenticationService {

        private final KeyManagementService keyService;

        TransactionAuthenticationService(
            KeyManagementService keyService
        ) {
            this.keyService = keyService;
        }

        AuthenticatedTransaction authenticate(
            TransactionPayload payload
        ) {
            String signature = keyService.sign(
                payload.keyId(),
                CanonicalSerializer.serialize(payload.serialize())
            );

            return new AuthenticatedTransaction(
                payload,
                signature,
                TransactionStatus.AUTHENTICATED
            );
        }

        boolean verify(AuthenticatedTransaction transaction) {
            try {
                return keyService.verify(
                    transaction.payload().keyId(),
                    transaction.payload().serialize(),
                    transaction.signature()
                );
            } catch (DomainException e) {
                return false;
            }
        }
    }

    // ========================================================
    // 7. TRANSACTION POLICY
    // ========================================================

    interface TransactionPolicy {
        void validate(TransactionPayload payload);
    }

    static final class StandardTransactionPolicy
        implements TransactionPolicy {

        private final long maximumAmount;

        StandardTransactionPolicy(long maximumAmount) {
            if (maximumAmount <= 0) {
                throw new PolicyException(
                    "Maximum amount must be positive."
                );
            }

            this.maximumAmount = maximumAmount;
        }

        @Override
        public void validate(TransactionPayload payload) {
            if (payload.amount() > maximumAmount) {
                throw new PolicyException(
                    "Transaction exceeds permitted amount."
                );
            }

            if (payload.timestamp() >
                System.currentTimeMillis() + 60_000) {
                throw new PolicyException(
                    "Transaction timestamp is in the future."
                );
            }
        }
    }

    // ========================================================
    // 8. BLOCKCHAIN SERVICE
    // ========================================================

    static final class BlockchainService {

        private final TransactionAuthenticationService authentication;
        private final TransactionPolicy policy;

        private final List<Block> chain = new ArrayList<>();

        private final Map<String, Set<Long>> committedNonces =
            new HashMap<>();

        private final Set<String> committedIds = new HashSet<>();

        private final Map<String, Set<Long>> pendingNonces =
            new HashMap<>();

        private final Set<String> pendingIds = new HashSet<>();

        private final List<AuthenticatedTransaction> pending =
            new ArrayList<>();

        private final ReentrantLock lock = new ReentrantLock();

        BlockchainService(
            TransactionAuthenticationService authentication,
            TransactionPolicy policy
        ) {
            this.authentication = authentication;
            this.policy = policy;

            Block genesis = new Block(
                0,
                ZERO_HASH,
                System.currentTimeMillis(),
                List.of(),
                ""
            );

            chain.add(withCalculatedHash(genesis));
        }

        private Block withCalculatedHash(Block block) {
            String hash = new CryptographicService().sha256(
                CanonicalSerializer.serializeBlock(
                    block.index(),
                    block.previousHash(),
                    block.timestamp(),
                    block.transactions()
                )
            );

            return new Block(
                block.index(),
                block.previousHash(),
                block.timestamp(),
                block.transactions(),
                hash
            );
        }

        void submit(AuthenticatedTransaction transaction) {
            lock.lock();

            try {
                TransactionPayload payload =
                    transaction.payload();

                policy.validate(payload);

                if (!authentication.verify(transaction)) {
                    throw new AuthenticationException(
                        "Invalid transaction HMAC."
                    );
                }

                if (committedIds.contains(payload.transactionId()) ||
                    pendingIds.contains(payload.transactionId())) {
                    throw new PolicyException(
                        "Duplicate transaction ID."
                    );
                }

                Set<Long> used = committedNonces.getOrDefault(
                    payload.sender(),
                    Collections.emptySet()
                );

                Set<Long> queued = pendingNonces.getOrDefault(
                    payload.sender(),
                    Collections.emptySet()
                );

                if (
                    used.contains(payload.nonce()) ||
                    queued.contains(payload.nonce())
                ) {
                    throw new ReplayException(
                        "Transaction nonce already used or pending."
                    );
                }

                pending.add(transaction);
                pendingIds.add(payload.transactionId());

                pendingNonces
                    .computeIfAbsent(
                        payload.sender(),
                        ignored -> new HashSet<>()
                    )
                    .add(payload.nonce());

            } finally {
                lock.unlock();
            }
        }

        Block commitBlock() {
            lock.lock();

            try {
                if (pending.isEmpty()) {
                    throw new PolicyException(
                        "No pending transactions."
                    );
                }

                // Revalidate all transactions before commitment.
                for (AuthenticatedTransaction tx : pending) {
                    policy.validate(tx.payload());

                    if (!authentication.verify(tx)) {
                        throw new AuthenticationException(
                            "Transaction failed revalidation."
                        );
                    }
                }

                Block previous = chain.get(chain.size() - 1);

                Block candidate = withCalculatedHash(
                    new Block(
                        chain.size(),
                        previous.hash(),
                        System.currentTimeMillis(),
                        List.copyOf(pending),
                        ""
                    )
                );

                // Atomic in-memory state transition.
                chain.add(candidate);

                for (AuthenticatedTransaction tx : pending) {
                    TransactionPayload payload = tx.payload();

                    committedIds.add(payload.transactionId());

                    committedNonces
                        .computeIfAbsent(
                            payload.sender(),
                            ignored -> new HashSet<>()
                        )
                        .add(payload.nonce());
                }

                pending.clear();
                pendingIds.clear();
                pendingNonces.clear();

                return candidate;

            } finally {
                lock.unlock();
            }
        }

        AuditResult audit() {
            lock.lock();

            try {
                int transactions = 0;

                for (int i = 0; i < chain.size(); i++) {
                    Block block = chain.get(i);

                    Block recalculated = withCalculatedHash(
                        new Block(
                            block.index(),
                            block.previousHash(),
                            block.timestamp(),
                            block.transactions(),
                            ""
                        )
                    );

                    if (!block.hash().equals(recalculated.hash())) {
                        return new AuditResult(
                            false,
                            chain.size(),
                            transactions,
                            "Block hash mismatch."
                        );
                    }

                    if (i == 0) {
                        if (!ZERO_HASH.equals(block.previousHash())) {
                            return new AuditResult(
                                false,
                                chain.size(),
                                transactions,
                                "Invalid genesis reference."
                            );
                        }
                    } else if (
                        !block.previousHash().equals(
                            chain.get(i - 1).hash()
                        )
                    ) {
                        return new AuditResult(
                            false,
                            chain.size(),
                            transactions,
                            "Previous block hash mismatch."
                        );
                    }

                    for (AuthenticatedTransaction tx :
                        block.transactions()) {

                        if (!authentication.verify(tx)) {
                            return new AuditResult(
                                false,
                                chain.size(),
                                transactions,
                                "Transaction HMAC mismatch."
                            );
                        }

                        transactions++;
                    }
                }

                return new AuditResult(
                    true,
                    chain.size(),
                    transactions,
                    "Blockchain integrity verified."
                );

            } finally {
                lock.unlock();
            }
        }

        long balance(String address) {
            lock.lock();

            try {
                return chain.stream()
                    .flatMap(block -> block.transactions().stream())
                    .map(AuthenticatedTransaction::payload)
                    .mapToLong(payload -> {
                        if (payload.sender().equals(address)) {
                            return -payload.amount();
                        }

                        if (payload.receiver().equals(address)) {
                            return payload.amount();
                        }

                        return 0;
                    })
                    .sum();

            } finally {
                lock.unlock();
            }
        }

        List<Block> getBlocks() {
            lock.lock();

            try {
                return List.copyOf(chain);
            } finally {
                lock.unlock();
            }
        }
    }

    // ========================================================
    // 9. ENTERPRISE APPLICATION SERVICE
    // ========================================================

    static final class BlockchainApplication {

        private final CryptographicService crypto =
            new CryptographicService();

        private final KeyManagementService keys =
            new KeyManagementService(crypto);

        private final TransactionAuthenticationService authentication =
            new TransactionAuthenticationService(keys);

        private final BlockchainService blockchain =
            new BlockchainService(
                authentication,
                new StandardTransactionPolicy(1_000_000)
            );

        void initialize() {
            keys.create("wallet-key-v1");
        }

        AuthenticatedTransaction createTransaction(
            String id,
            String sender,
            String receiver,
            long amount,
            long nonce,
            String keyId
        ) {
            TransactionPayload payload = new TransactionPayload(
                id,
                sender,
                receiver,
                amount,
                nonce,
                System.currentTimeMillis(),
                keyId
            );

            return authentication.authenticate(payload);
        }

        void process(AuthenticatedTransaction transaction) {
            blockchain.submit(transaction);
        }

        Block commit() {
            return blockchain.commitBlock();
        }

        AuditResult audit() {
            return blockchain.audit();
        }

        long balance(String address) {
            return blockchain.balance(address);
        }

        KeyMetadata rotate(String oldId, String newId) {
            return keys.rotate(oldId, newId);
        }

        boolean verify(AuthenticatedTransaction transaction) {
            return authentication.verify(transaction);
        }
    }

    // ========================================================
    // 10. EXECUTION AND TESTING
    // ========================================================

    public static void main(String[] args) {

        try {
            BlockchainApplication application =
                new BlockchainApplication();

            application.initialize();

            System.out.println(
                "HMAC-SHA256 ENTERPRISE BLOCKCHAIN\n"
            );

            // Create transactions.
            AuthenticatedTransaction first =
                application.createTransaction(
                    "TX-001",
                    "ALICE",
                    "BOB",
                    500,
                    1,
                    "wallet-key-v1"
                );

            AuthenticatedTransaction second =
                application.createTransaction(
                    "TX-002",
                    "BOB",
                    "CHARLIE",
                    150,
                    1,
                    "wallet-key-v1"
                );

            System.out.println("1. AUTHENTICATION");

            System.out.println(
                "TX-001 valid: " + application.verify(first)
            );

            System.out.println(
                "TX-002 valid: " + application.verify(second)
            );

            // Process transactions.
            System.out.println("\n2. TRANSACTION PROCESSING");

            application.process(first);
            application.process(second);

            Block block = application.commit();

            System.out.println("Block index: " + block.index());
            System.out.println("Block hash: " + block.hash());

            // Balances.
            System.out.println("\n3. ACCOUNT BALANCES");

            System.out.println(
                "Alice: " + application.balance("ALICE")
            );

            System.out.println(
                "Bob: " + application.balance("BOB")
            );

            System.out.println(
                "Charlie: " + application.balance("CHARLIE")
            );

            // Replay test.
            System.out.println("\n4. REPLAY PROTECTION");

            try {
                application.process(first);
            } catch (DomainException e) {
                System.out.println("Rejected: " + e.getMessage());
            }

            // Invalid transaction.
            System.out.println("\n5. TRANSACTION POLICY");

            try {
                application.createTransaction(
                    "TX-INVALID",
                    "ALICE",
                    "BOB",
                    -100,
                    2,
                    "wallet-key-v1"
                );
            } catch (DomainException e) {
                System.out.println("Rejected: " + e.getMessage());
            }

            // Key rotation.
            System.out.println("\n6. KEY ROTATION");

            System.out.println(
                "New key: " +
                application.rotate(
                    "wallet-key-v1",
                    "wallet-key-v2"
                ).keyId()
            );

            AuthenticatedTransaction third =
                application.createTransaction(
                    "TX-003",
                    "CHARLIE",
                    "DAVID",
                    50,
                    2,
                    "wallet-key-v2"
                );

            application.process(third);
            application.commit();

            System.out.println(
                "New-key transaction valid: " +
                application.verify(third)
            );

            System.out.println(
                "Historical signature valid: " +
                application.verify(first)
            );

            // Final audit.
            System.out.println("\n7. INTEGRITY AUDIT");

            AuditResult audit = application.audit();

            System.out.println("Valid: " + audit.valid());
            System.out.println("Blocks: " + audit.blockCount());
            System.out.println(
                "Transactions: " + audit.transactionCount()
            );
            System.out.println("Message: " + audit.message());

            if (!audit.valid()) {
                throw new DomainException(
                    "Blockchain integrity verification failed."
                );
            }

            System.out.println("\nALL TESTS PASSED");

        } catch (DomainException e) {
            System.err.println(
                "APPLICATION ERROR: " + e.getMessage()
            );

            System.exit(1);
        }
    }
}
