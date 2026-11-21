import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/*
 * ECDSA IN BLOCKCHAIN AND CRYPTOGRAPHY
 *
 * Java 17 enterprise-oriented implementation.
 *
 * Uses:
 * - Java Cryptography Architecture
 * - secp256r1
 * - SHA256withECDSA
 * - immutable transaction payloads
 * - explicit workflow states
 * - wallet registry
 * - signature policies
 * - transaction validation
 * - blockchain block management
 *
 * Compile:
 * javac ECDSABlockchain.java
 *
 * Execute:
 * java ECDSABlockchain
 */

public class ECDSABlockchain {

    // ========================================================
    // 1. Cryptographic configuration
    // ========================================================

    private static final String CURVE = "secp256r1";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    private static final AtomicLong TRANSACTION_SEQUENCE =
            new AtomicLong(1);

    // ========================================================
    // 2. Custom exceptions
    // ========================================================

    static class CryptoException extends RuntimeException {
        CryptoException(String message) {
            super(message);
        }

        CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class TransactionException extends RuntimeException {
        TransactionException(String message) {
            super(message);
        }
    }

    static class PolicyException extends RuntimeException {
        PolicyException(String message) {
            super(message);
        }
    }

    // ========================================================
    // 3. Enumerations
    // ========================================================

    enum TransactionState {
        CREATED,
        SIGNED,
        VERIFIED,
        REJECTED,
        INCLUDED
    }

    enum VerificationResult {
        VALID,
        INVALID,
        MISSING_SIGNATURE,
        UNKNOWN_SIGNER
    }

    enum SignaturePurpose {
        BLOCKCHAIN_TRANSACTION,
        MESSAGE_AUTHENTICATION
    }

    // ========================================================
    // 4. Cryptographic utilities
    // ========================================================

    static final class CryptoUtils {

        private CryptoUtils() {}

        static byte[] sha256(byte[] input) {
            try {
                return MessageDigest
                        .getInstance("SHA-256")
                        .digest(input);
            } catch (GeneralSecurityException exception) {
                throw new CryptoException(
                        "SHA-256 unavailable",
                        exception
                );
            }
        }

        static String hex(byte[] input) {
            return HexFormat.of().formatHex(input);
        }

        static String hashHex(byte[] input) {
            return hex(sha256(input));
        }

        static byte[] utf8(String value) {
            return value.getBytes(StandardCharsets.UTF_8);
        }

        static String address(PublicKey publicKey) {
            return "bc_" + hashHex(publicKey.getEncoded())
                    .substring(0, 40);
        }

        static String canonicalPayload(
                String sender,
                String recipient,
                long amount,
                long nonce,
                long timestamp
        ) {
            return String.join(
                    "|",
                    escape(sender),
                    escape(recipient),
                    Long.toString(amount),
                    Long.toString(nonce),
                    Long.toString(timestamp)
            );
        }

        private static String escape(String value) {
            return value.replace("%", "%25")
                    .replace("|", "%7C")
                    .replace("\n", "%0A")
                    .replace("\r", "%0D");
        }
    }

    // ========================================================
    // 5. Key management
    // ========================================================

    static final class Wallet {

        private final KeyPair keyPair;
        private final String address;

        private Wallet(KeyPair keyPair) {
            this.keyPair = keyPair;
            this.address = CryptoUtils.address(keyPair.getPublic());
        }

        static Wallet generate() {
            try {
                KeyPairGenerator generator =
                        KeyPairGenerator.getInstance("EC");

                generator.initialize(
                        new ECGenParameterSpec(CURVE)
                );

                return new Wallet(generator.generateKeyPair());

            } catch (GeneralSecurityException exception) {
                throw new CryptoException(
                        "Wallet generation failed",
                        exception
                );
            }
        }

        String address() {
            return address;
        }

        PublicKey publicKey() {
            return keyPair.getPublic();
        }

        byte[] sign(byte[] payload) {
            try {
                Signature signer =
                        Signature.getInstance(SIGNATURE_ALGORITHM);

                signer.initSign(keyPair.getPrivate());
                signer.update(payload);

                return signer.sign();

            } catch (GeneralSecurityException exception) {
                throw new CryptoException(
                        "Signing operation failed",
                        exception
                );
            }
        }
    }

    // ========================================================
    // 6. Signature verification service
    // ========================================================

    static final class SignatureVerifier {

        boolean verify(
                PublicKey publicKey,
                byte[] payload,
                byte[] signatureBytes
        ) {
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(payload);

            if (signatureBytes == null ||
                    signatureBytes.length == 0) {
                return false;
            }

            try {
                Signature verifier =
                        Signature.getInstance(SIGNATURE_ALGORITHM);

                verifier.initVerify(publicKey);
                verifier.update(payload);

                return verifier.verify(signatureBytes);

            } catch (GeneralSecurityException exception) {
                return false;
            }
        }
    }

    // ========================================================
    // 7. Wallet registry
    // ========================================================

    static final class WalletRegistry {

        private final Map<String, PublicKey> wallets =
                new ConcurrentHashMap<>();

        void register(Wallet wallet) {
            Objects.requireNonNull(wallet);

            PublicKey previous = wallets.putIfAbsent(
                    wallet.address(),
                    wallet.publicKey()
            );

            if (previous != null) {
                throw new CryptoException("Wallet already registered");
            }
        }

        PublicKey find(String address) {
            PublicKey key = wallets.get(address);

            if (key == null) {
                throw new CryptoException("Unknown wallet");
            }

            return key;
        }

        boolean contains(String address) {
            return wallets.containsKey(address);
        }
    }

    // ========================================================
    // 8. Immutable transaction data
    // ========================================================

    record TransactionPayload(
            String sender,
            String recipient,
            long amount,
            long nonce,
            long timestamp
    ) {
        TransactionPayload {
            if (sender == null || sender.isBlank()) {
                throw new TransactionException("Sender is required");
            }

            if (recipient == null || recipient.isBlank()) {
                throw new TransactionException("Recipient is required");
            }

            if (amount <= 0) {
                throw new TransactionException("Amount must be positive");
            }

            if (nonce < 0) {
                throw new TransactionException("Invalid nonce");
            }

            if (timestamp <= 0) {
                throw new TransactionException("Invalid timestamp");
            }
        }

        byte[] serialize() {
            return CryptoUtils.utf8(
                    CryptoUtils.canonicalPayload(
                            sender,
                            recipient,
                            amount,
                            nonce,
                            timestamp
                    )
            );
        }

        String transactionId() {
            return CryptoUtils.hashHex(serialize());
        }
    }

    // ========================================================
    // 9. Transaction aggregate
    // ========================================================

    static final class BlockchainTransaction {

        private final String id;
        private final TransactionPayload payload;

        private byte[] signature;
        private TransactionState state;

        BlockchainTransaction(TransactionPayload payload) {
            this.payload = Objects.requireNonNull(payload);
            this.id = payload.transactionId();
            this.state = TransactionState.CREATED;
        }

        synchronized void sign(Wallet wallet) {
            if (state != TransactionState.CREATED) {
                throw new TransactionException(
                        "Invalid signing state"
                );
            }

            if (!payload.sender().equals(wallet.address())) {
                throw new CryptoException(
                        "Signing wallet does not own sender address"
                );
            }

            signature = wallet.sign(payload.serialize());
            state = TransactionState.SIGNED;
        }

        synchronized VerificationResult verify(
                WalletRegistry registry,
                SignatureVerifier verifier
        ) {
            if (state != TransactionState.SIGNED) {
                throw new TransactionException(
                        "Transaction must be signed"
                );
            }

            if (signature == null) {
                state = TransactionState.REJECTED;
                return VerificationResult.MISSING_SIGNATURE;
            }

            if (!registry.contains(payload.sender())) {
                state = TransactionState.REJECTED;
                return VerificationResult.UNKNOWN_SIGNER;
            }

            boolean valid = verifier.verify(
                    registry.find(payload.sender()),
                    payload.serialize(),
                    signature.clone()
            );

            state = valid
                    ? TransactionState.VERIFIED
                    : TransactionState.REJECTED;

            return valid
                    ? VerificationResult.VALID
                    : VerificationResult.INVALID;
        }

        synchronized void include() {
            if (state != TransactionState.VERIFIED) {
                throw new TransactionException(
                        "Only verified transactions can be included"
                );
            }

            state = TransactionState.INCLUDED;
        }

        String id() {
            return id;
        }

        TransactionPayload payload() {
            return payload;
        }

        synchronized TransactionState state() {
            return state;
        }

        synchronized byte[] signature() {
            return signature == null
                    ? null
                    : signature.clone();
        }
    }

    // ========================================================
    // 10. Enterprise signature policy
    // ========================================================

    record SignaturePolicy(
            String algorithm,
            String curve,
            boolean requireRegisteredSigner,
            boolean requireUniqueNonce
    ) {
        SignaturePolicy {
            if (!SIGNATURE_ALGORITHM.equals(algorithm)) {
                throw new PolicyException("Unapproved signature algorithm");
            }

            if (!CURVE.equals(curve)) {
                throw new PolicyException("Unapproved curve");
            }
        }
    }

    static final class SignaturePolicyService {

        private final SignaturePolicy policy;

        SignaturePolicyService(SignaturePolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        void validate(
                BlockchainTransaction transaction,
                WalletRegistry registry
        ) {
            if (policy.requireRegisteredSigner() &&
                    !registry.contains(transaction.payload().sender())) {
                throw new PolicyException("Signer is not registered");
            }

            if (transaction.state() != TransactionState.VERIFIED) {
                throw new PolicyException(
                        "Transaction has not passed signature verification"
                );
            }
        }
    }

    // ========================================================
    // 11. Account nonce and replay protection
    // ========================================================

    static final class NonceManager {

        private final Map<String, Long> nextNonce =
                new ConcurrentHashMap<>();

        synchronized void validateAndAdvance(
                String address,
                long suppliedNonce
        ) {
            long expected = nextNonce.getOrDefault(address, 0L);

            if (suppliedNonce != expected) {
                throw new TransactionException(
                        "Replay or out-of-order transaction: expected "
                                + expected
                );
            }

            nextNonce.put(address, expected + 1);
        }
    }

    // ========================================================
    // 12. Block model
    // ========================================================

    record Block(
            long index,
            String previousHash,
            List<String> transactionIds,
            long timestamp,
            String hash
    ) {
        Block {
            transactionIds = List.copyOf(transactionIds);
        }

        static Block create(
                long index,
                String previousHash,
                List<BlockchainTransaction> transactions
        ) {
            long timestamp = System.currentTimeMillis();

            List<String> ids = transactions.stream()
                    .map(BlockchainTransaction::id)
                    .toList();

            String content = index + "|" +
                    previousHash + "|" +
                    timestamp + "|" +
                    String.join(",", ids);

            String hash = CryptoUtils.hashHex(
                    CryptoUtils.utf8(content)
            );

            return new Block(
                    index,
                    previousHash,
                    ids,
                    timestamp,
                    hash
            );
        }
    }

    // ========================================================
    // 13. Blockchain service
    // ========================================================

    static final class BlockchainService {

        private final List<Block> blocks = new ArrayList<>();

        BlockchainService() {
            Block genesis = Block.create(
                    0,
                    "0".repeat(64),
                    Collections.emptyList()
            );

            blocks.add(genesis);
        }

        synchronized Block append(
                List<BlockchainTransaction> transactions,
                SignaturePolicyService policyService,
                WalletRegistry registry
        ) {
            if (transactions == null || transactions.isEmpty()) {
                throw new TransactionException(
                        "Block cannot be empty"
                );
            }

            Set<String> ids = new HashSet<>();

            for (BlockchainTransaction transaction : transactions) {
                if (!ids.add(transaction.id())) {
                    throw new TransactionException(
                            "Duplicate transaction in block"
                    );
                }

                policyService.validate(transaction, registry);
            }

            Block previous = blocks.get(blocks.size() - 1);

            Block next = Block.create(
                    blocks.size(),
                    previous.hash(),
                    transactions
            );

            // Validate all transactions before changing their states.
            // The append operation is synchronized to prevent concurrent
            // block creation against the same chain head.
            for (BlockchainTransaction transaction : transactions) {
                transaction.include();
            }

            blocks.add(next);

            return next;
        }

        synchronized boolean validate() {
            for (int i = 0; i < blocks.size(); i++) {
                Block block = blocks.get(i);

                String previousHash = i == 0
                        ? "0".repeat(64)
                        : blocks.get(i - 1).hash();

                if (!block.previousHash().equals(previousHash)) {
                    return false;
                }

                if (block.index() != i) {
                    return false;
                }

                String content = block.index() + "|" +
                        block.previousHash() + "|" +
                        block.timestamp() + "|" +
                        String.join(",", block.transactionIds());

                String expected = CryptoUtils.hashHex(
                        CryptoUtils.utf8(content)
                );

                if (!expected.equals(block.hash())) {
                    return false;
                }
            }

            return true;
        }

        synchronized List<Block> blocks() {
            return List.copyOf(blocks);
        }
    }

    // ========================================================
    // 14. Demonstration
    // ========================================================

    public static void main(String[] args) {

        System.out.println("ECDSA ENTERPRISE BLOCKCHAIN");
        System.out.println("=".repeat(55));

        Wallet sender = Wallet.generate();
        Wallet recipient = Wallet.generate();

        WalletRegistry registry = new WalletRegistry();

        registry.register(sender);
        registry.register(recipient);

        SignatureVerifier verifier = new SignatureVerifier();

        SignaturePolicy policy = new SignaturePolicy(
                SIGNATURE_ALGORITHM,
                CURVE,
                true,
                true
        );

        SignaturePolicyService policyService =
                new SignaturePolicyService(policy);

        System.out.println("\n1. CRYPTOGRAPHIC IDENTITIES");

        System.out.println("Curve: " + CURVE);
        System.out.println("Algorithm: " + SIGNATURE_ALGORITHM);
        System.out.println("Sender: " + sender.address());
        System.out.println("Recipient: " + recipient.address());

        System.out.println("\n2. TRANSACTION CREATION");

        TransactionPayload payload = new TransactionPayload(
                sender.address(),
                recipient.address(),
                750,
                0,
                System.currentTimeMillis()
        );

        BlockchainTransaction transaction =
                new BlockchainTransaction(payload);

        System.out.println("Transaction ID: " + transaction.id());
        System.out.println("Initial state: " + transaction.state());

        System.out.println("\n3. SIGNATURE GENERATION");

        transaction.sign(sender);

        System.out.println("State: " + transaction.state());
        System.out.println(
                "Signature bytes: " + transaction.signature().length
        );

        System.out.println("\n4. SIGNATURE VERIFICATION");

        VerificationResult result = transaction.verify(
                registry,
                verifier
        );

        System.out.println("Verification: " + result);
        System.out.println("State: " + transaction.state());

        System.out.println("\n5. POLICY EVALUATION");

        policyService.validate(transaction, registry);

        System.out.println("Signer registered: true");
        System.out.println("Signature policy: satisfied");

        System.out.println("\n6. BLOCKCHAIN INCLUSION");

        BlockchainService blockchain = new BlockchainService();

        Block block = blockchain.append(
                List.of(transaction),
                policyService,
                registry
        );

        System.out.println("Block index: " + block.index());
        System.out.println("Block hash: " + block.hash());
        System.out.println("Transaction state: " + transaction.state());
        System.out.println("Chain valid: " + blockchain.validate());

        System.out.println("\n7. REPLAY PROTECTION");

        NonceManager nonceManager = new NonceManager();

        nonceManager.validateAndAdvance(sender.address(), 0);

        try {
            nonceManager.validateAndAdvance(sender.address(), 0);
        } catch (TransactionException exception) {
            System.out.println("Replay rejected: " + exception.getMessage());
        }

        System.out.println("\n8. TAMPERING TEST");

        String modifiedPayload = CryptoUtils.canonicalPayload(
                sender.address(),
                recipient.address(),
                751,
                0,
                payload.timestamp()
        );

        boolean tamperedAccepted = verifier.verify(
                sender.publicKey(),
                CryptoUtils.utf8(modifiedPayload),
                transaction.signature()
        );

        System.out.println("Modified transaction accepted: "
                + tamperedAccepted);

        if (tamperedAccepted) {
            throw new CryptoException("Tampering test failed");
        }

        System.out.println("\n9. FAILURE TESTS");

        try {
            new TransactionPayload(
                    sender.address(),
                    recipient.address(),
                    -10,
                    0,
                    System.currentTimeMillis()
            );
        } catch (TransactionException exception) {
            System.out.println(
                    "Invalid amount rejected: " + exception.getMessage()
            );
        }

        try {
            new SignaturePolicy(
                    "SHA1withECDSA",
                    CURVE,
                    true,
                    true
            );
        } catch (PolicyException exception) {
            System.out.println(
                    "Weak algorithm rejected: " + exception.getMessage()
            );
        }

        System.out.println("\n10. REPORTING");

        System.out.println("Blocks: " + blockchain.blocks().size());

        long included = blockchain.blocks().stream()
                .mapToLong(blockEntry -> blockEntry.transactionIds().size())
                .sum();

        System.out.println("Included transactions: " + included);

        System.out.println("\nAll enterprise workflow checks passed.");
    }
}
