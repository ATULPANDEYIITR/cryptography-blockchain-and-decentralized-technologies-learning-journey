import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Public-Key Cryptography: Enterprise Security Workflow.
 *
 * Java version: 17
 * Dependencies: Java standard library.
 *
 * Implements:
 * - RSA key generation
 * - Public-key encryption and private-key decryption
 * - RSA-PSS signatures
 * - SHA-256 fingerprints
 * - AES-GCM hybrid encryption
 * - Certificate authority workflow
 * - Key lifecycle and revocation
 * - Enterprise key registry
 * - Transaction authorization
 * - Concurrent audit recording
 *
 * The certificate model is educational and is not a complete
 * X.509 certificate or PKI path-validation implementation.
 */

public class PublicKeyCryptography {

    enum KeyStatus {
        ACTIVE,
        ROTATED,
        REVOKED
    }

    enum Operation {
        ENCRYPT,
        DECRYPT,
        SIGN,
        VERIFY,
        ISSUE_CERTIFICATE
    }

    static class CryptoException extends Exception {
        CryptoException(String message) {
            super(message);
        }

        CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class PolicyException extends CryptoException {
        PolicyException(String message) {
            super(message);
        }
    }

    record AuditEvent(
        long eventId,
        String operation,
        String subject,
        String outcome,
        Instant timestamp
    ) {}

    static class AuditService {
        private final AtomicLong sequence = new AtomicLong();

        private final List<AuditEvent> events =
            Collections.synchronizedList(new ArrayList<>());

        void record(
            String operation,
            String subject,
            String outcome
        ) {
            events.add(new AuditEvent(
                sequence.incrementAndGet(),
                operation,
                subject,
                outcome,
                Instant.now()
            ));
        }

        List<AuditEvent> getEvents() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }
    }

    static final class CryptoPolicy {
        private final int minimumRsaBits;
        private final boolean requireActiveKeys;
        private final boolean requirePssSignatures;

        CryptoPolicy(
            int minimumRsaBits,
            boolean requireActiveKeys,
            boolean requirePssSignatures
        ) {
            if (minimumRsaBits < 2048) {
                throw new IllegalArgumentException(
                    "RSA minimum must be at least 2048 bits."
                );
            }

            this.minimumRsaBits = minimumRsaBits;
            this.requireActiveKeys = requireActiveKeys;
            this.requirePssSignatures = requirePssSignatures;
        }

        void validateKey(KeyPairRecord key) throws PolicyException {
            if (key.publicKey().getEncoded().length == 0) {
                throw new PolicyException("Invalid public key.");
            }

            if (key.rsaBits() < minimumRsaBits) {
                throw new PolicyException("RSA key below policy minimum.");
            }

            if (requireActiveKeys && key.status() != KeyStatus.ACTIVE) {
                throw new PolicyException("Key is not active.");
            }
        }

        boolean requiresPssSignatures() {
            return requirePssSignatures;
        }
    }

    static final class KeyPairRecord {
        private final String owner;
        private final PublicKey publicKey;
        private final PrivateKey privateKey;
        private final String fingerprint;
        private final Instant createdAt;
        private KeyStatus status;

        KeyPairRecord(String owner, KeyPair pair)
            throws GeneralSecurityException {

            this.owner = Objects.requireNonNull(owner);

            if (owner.isBlank()) {
                throw new IllegalArgumentException("Owner is required.");
            }

            this.publicKey = pair.getPublic();
            this.privateKey = pair.getPrivate();

            this.fingerprint = calculateFingerprint(publicKey);

            this.createdAt = Instant.now();
            this.status = KeyStatus.ACTIVE;
        }

        private static String calculateFingerprint(PublicKey key)
            throws GeneralSecurityException {

            byte[] digest = MessageDigest
                .getInstance("SHA-256")
                .digest(key.getEncoded());

            return HexFormatSupport.encode(digest);
        }

        String owner() {
            return owner;
        }

        PublicKey publicKey() {
            return publicKey;
        }

        PrivateKey privateKey() {
            return privateKey;
        }

        String fingerprint() {
            return fingerprint;
        }

        Instant createdAt() {
            return createdAt;
        }

        KeyStatus status() {
            return status;
        }

        int rsaBits() {
            return publicKey.getEncoded().length * 8;
        }

        void rotate() throws PolicyException {
            if (status != KeyStatus.ACTIVE) {
                throw new PolicyException(
                    "Only active keys can be rotated."
                );
            }

            status = KeyStatus.ROTATED;
        }

        void revoke() throws PolicyException {
            if (status == KeyStatus.REVOKED) {
                throw new PolicyException("Key is already revoked.");
            }

            status = KeyStatus.REVOKED;
        }
    }

    static final class HexFormatSupport {
        private static final char[] HEX =
            "0123456789abcdef".toCharArray();

        static String encode(byte[] bytes) {
            StringBuilder result = new StringBuilder(bytes.length * 2);

            for (byte value : bytes) {
                int unsigned = value & 0xff;

                result.append(HEX[unsigned >>> 4]);
                result.append(HEX[unsigned & 0x0f]);
            }

            return result.toString();
        }
    }

    static class KeyGenerationService {

        KeyPairRecord generate(String owner, int bits)
            throws GeneralSecurityException {

            if (bits < 2048 || bits > 4096 || bits % 256 != 0) {
                throw new IllegalArgumentException(
                    "RSA size must be 2048 through 4096 in 256-bit steps."
                );
            }

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

            generator.initialize(bits, new SecureRandom());

            return new KeyPairRecord(owner, generator.generateKeyPair());
        }
    }

    static class KeyRegistry {
        private final Map<String, KeyPairRecord> records =
            new ConcurrentHashMap<>();

        void register(KeyPairRecord record) throws PolicyException {
            KeyPairRecord existing = records.putIfAbsent(
                record.fingerprint(),
                record
            );

            if (existing != null) {
                throw new PolicyException("Duplicate key registration.");
            }
        }

        Optional<KeyPairRecord> find(String fingerprint) {
            return Optional.ofNullable(records.get(fingerprint));
        }

        KeyPairRecord requireActive(String fingerprint)
            throws PolicyException {

            KeyPairRecord record = records.get(fingerprint);

            if (record == null) {
                throw new PolicyException("Unknown key fingerprint.");
            }

            if (record.status() != KeyStatus.ACTIVE) {
                throw new PolicyException("Key is not active.");
            }

            return record;
        }

        void revoke(String fingerprint) throws PolicyException {
            KeyPairRecord record = records.get(fingerprint);

            if (record == null) {
                throw new PolicyException("Unknown key.");
            }

            record.revoke();
        }

        List<KeyPairRecord> inventory() {
            return records.values()
                .stream()
                .sorted((a, b) ->
                    a.fingerprint().compareTo(b.fingerprint()))
                .toList();
        }
    }

    static final class EncryptedEnvelope {
        private final String algorithm;
        private final String recipientFingerprint;
        private final byte[] encryptedSessionKey;
        private final byte[] nonce;
        private final byte[] ciphertext;
        private final byte[] authenticationTag;

        EncryptedEnvelope(
            String recipientFingerprint,
            byte[] encryptedSessionKey,
            byte[] nonce,
            byte[] ciphertext,
            byte[] authenticationTag
        ) {
            this.algorithm = "RSA-OAEP-SHA256+A256GCM";
            this.recipientFingerprint = recipientFingerprint;
            this.encryptedSessionKey = encryptedSessionKey.clone();
            this.nonce = nonce.clone();
            this.ciphertext = ciphertext.clone();
            this.authenticationTag = authenticationTag.clone();
        }

        String algorithm() {
            return algorithm;
        }

        String recipientFingerprint() {
            return recipientFingerprint;
        }

        byte[] encryptedSessionKey() {
            return encryptedSessionKey.clone();
        }

        byte[] nonce() {
            return nonce.clone();
        }

        byte[] ciphertext() {
            return ciphertext.clone();
        }

        byte[] authenticationTag() {
            return authenticationTag.clone();
        }
    }

    static class HybridEncryptionService {

        private static final int GCM_TAG_BITS = 128;
        private static final int NONCE_BYTES = 12;

        private final SecureRandom random = new SecureRandom();

        EncryptedEnvelope encrypt(
            KeyPairRecord recipient,
            byte[] plaintext,
            CryptoPolicy policy
        ) throws GeneralSecurityException, CryptoException {

            policy.validateKey(recipient);

            KeyGenerator generator =
                KeyGenerator.getInstance("AES");

            generator.init(256);

            SecretKey sessionKey = generator.generateKey();

            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);

            byte[] aad = recipient.fingerprint()
                .getBytes(StandardCharsets.UTF_8);

            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");

            aesCipher.init(
                Cipher.ENCRYPT_MODE,
                sessionKey,
                new GCMParameterSpec(GCM_TAG_BITS, nonce)
            );

            aesCipher.updateAAD(aad);

            // GCM returns ciphertext followed by the authentication tag.
            byte[] combined = aesCipher.doFinal(plaintext);

            int tagLength = GCM_TAG_BITS / 8;

            byte[] ciphertext = new byte[
                combined.length - tagLength
            ];

            byte[] tag = new byte[tagLength];

            System.arraycopy(
                combined, 0,
                ciphertext, 0,
                ciphertext.length
            );

            System.arraycopy(
                combined, ciphertext.length,
                tag, 0,
                tagLength
            );

            Cipher rsaCipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            rsaCipher.init(
                Cipher.ENCRYPT_MODE,
                recipient.publicKey()
            );

            byte[] wrappedKey = rsaCipher.doFinal(
                sessionKey.getEncoded()
            );

            return new EncryptedEnvelope(
                recipient.fingerprint(),
                wrappedKey,
                nonce,
                ciphertext,
                tag
            );
        }

        byte[] decrypt(
            KeyPairRecord recipient,
            EncryptedEnvelope envelope,
            CryptoPolicy policy
        ) throws GeneralSecurityException, CryptoException {

            policy.validateKey(recipient);

            if (!recipient.fingerprint().equals(
                envelope.recipientFingerprint()
            )) {
                throw new PolicyException("Recipient mismatch.");
            }

            if (!"RSA-OAEP-SHA256+A256GCM".equals(
                envelope.algorithm()
            )) {
                throw new PolicyException("Unsupported algorithm.");
            }

            Cipher rsaCipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            rsaCipher.init(
                Cipher.DECRYPT_MODE,
                recipient.privateKey()
            );

            byte[] sessionKeyBytes = rsaCipher.doFinal(
                envelope.encryptedSessionKey()
            );

            if (sessionKeyBytes.length != 32 ||
                envelope.nonce().length != NONCE_BYTES ||
                envelope.authenticationTag().length != 16) {
                throw new CryptoException("Invalid envelope parameters.");
            }

            SecretKey sessionKey = new SecretKeySpec(
                sessionKeyBytes,
                "AES"
            );

            byte[] combined = new byte[
                envelope.ciphertext().length +
                envelope.authenticationTag().length
            ];

            System.arraycopy(
                envelope.ciphertext(), 0,
                combined, 0,
                envelope.ciphertext().length
            );

            System.arraycopy(
                envelope.authenticationTag(), 0,
                combined,
                envelope.ciphertext().length,
                envelope.authenticationTag().length
            );

            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");

            aesCipher.init(
                Cipher.DECRYPT_MODE,
                sessionKey,
                new GCMParameterSpec(
                    GCM_TAG_BITS,
                    envelope.nonce()
                )
            );

            aesCipher.updateAAD(
                recipient.fingerprint().getBytes(StandardCharsets.UTF_8)
            );

            return aesCipher.doFinal(combined);
        }
    }

    static class DigitalSignatureService {

        byte[] sign(
            KeyPairRecord signer,
            byte[] document,
            CryptoPolicy policy
        ) throws GeneralSecurityException, CryptoException {

            policy.validateKey(signer);

            Signature signature = Signature.getInstance(
                policy.requiresPssSignatures()
                    ? "RSASSA-PSS"
                    : "SHA256withRSA"
            );

            if (policy.requiresPssSignatures()) {
                signature.setParameter(
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256",
                        "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32,
                        1
                    )
                );
            }

            signature.initSign(signer.privateKey());

            signature.update(document);

            return signature.sign();
        }

        boolean verify(
            PublicKey publicKey,
            byte[] document,
            byte[] signedValue,
            CryptoPolicy policy
        ) throws GeneralSecurityException {

            Signature signature = Signature.getInstance(
                policy.requiresPssSignatures()
                    ? "RSASSA-PSS"
                    : "SHA256withRSA"
            );

            if (policy.requiresPssSignatures()) {
                signature.setParameter(
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256",
                        "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32,
                        1
                    )
                );
            }

            signature.initVerify(publicKey);
            signature.update(document);

            return signature.verify(signedValue);
        }
    }

    record Certificate(
        String subject,
        String subjectFingerprint,
        String issuerFingerprint,
        Instant issuedAt,
        Instant expiresAt,
        byte[] signature
    ) {
        Certificate {
            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    static class CertificateAuthority {
        private final DigitalSignatureService signatures;
        private final KeyPairRecord authorityKey;

        CertificateAuthority(
            DigitalSignatureService signatures,
            KeyPairRecord authorityKey
        ) {
            this.signatures = signatures;
            this.authorityKey = authorityKey;
        }

        private byte[] canonicalContent(
            String subject,
            String subjectFingerprint,
            Instant issuedAt,
            Instant expiresAt
        ) {
            String value = subject + "|" +
                subjectFingerprint + "|" +
                authorityKey.fingerprint() + "|" +
                issuedAt.toString() + "|" +
                expiresAt.toString();

            return value.getBytes(StandardCharsets.UTF_8);
        }

        Certificate issue(
            KeyPairRecord subject,
            long validityDays,
            CryptoPolicy policy
        ) throws GeneralSecurityException, CryptoException {

            if (authorityKey.status() != KeyStatus.ACTIVE) {
                throw new PolicyException("Authority key is inactive.");
            }

            if (subject.status() != KeyStatus.ACTIVE) {
                throw new PolicyException("Subject key is inactive.");
            }

            if (validityDays < 1 || validityDays > 825) {
                throw new PolicyException("Invalid certificate validity.");
            }

            Instant issued = Instant.now();
            Instant expires = issued.plus(
                validityDays,
                ChronoUnit.DAYS
            );

            byte[] content = canonicalContent(
                subject.owner(),
                subject.fingerprint(),
                issued,
                expires
            );

            byte[] signed = signatures.sign(
                authorityKey,
                content,
                policy
            );

            return new Certificate(
                subject.owner(),
                subject.fingerprint(),
                authorityKey.fingerprint(),
                issued,
                expires,
                signed
            );
        }

        boolean verify(
            Certificate certificate,
            CryptoPolicy policy
        ) throws GeneralSecurityException {

            if (authorityKey.status() != KeyStatus.ACTIVE) {
                return false;
            }

            if (!certificate.issuerFingerprint().equals(
                authorityKey.fingerprint()
            )) {
                return false;
            }

            if (!Instant.now().isBefore(certificate.expiresAt())) {
                return false;
            }

            byte[] content = canonicalContent(
                certificate.subject(),
                certificate.subjectFingerprint(),
                certificate.issuedAt(),
                certificate.expiresAt()
            );

            return signatures.verify(
                authorityKey.publicKey(),
                content,
                certificate.signature(),
                policy
            );
        }
    }

    static class TransactionAuthorizationService {
        private final DigitalSignatureService signatures;
        private final AuditService audit;
        private final CryptoPolicy policy;

        TransactionAuthorizationService(
            DigitalSignatureService signatures,
            AuditService audit,
            CryptoPolicy policy
        ) {
            this.signatures = signatures;
            this.audit = audit;
            this.policy = policy;
        }

        boolean authorize(
            String transactionId,
            String transactionData,
            KeyPairRecord signer,
            byte[] signature
        ) throws GeneralSecurityException {

            if (transactionId == null || transactionId.isBlank()) {
                audit.record("TRANSACTION", "unknown", "REJECTED");
                return false;
            }

            boolean verified = signatures.verify(
                signer.publicKey(),
                transactionData.getBytes(StandardCharsets.UTF_8),
                signature,
                policy
            );

            audit.record(
                "TRANSACTION",
                transactionId,
                verified ? "APPROVED" : "REJECTED"
            );

            return verified;
        }
    }

    private static void section(String title) {
        System.out.println("\n" + title);
        System.out.println("-".repeat(60));
    }

    public static void main(String[] args) throws Exception {

        System.out.println("PUBLIC-KEY CRYPTOGRAPHY");
        System.out.println("=".repeat(60));

        CryptoPolicy policy = new CryptoPolicy(
            2048,
            true,
            true
        );

        AuditService audit = new AuditService();

        KeyGenerationService generation =
            new KeyGenerationService();

        KeyRegistry registry = new KeyRegistry();

        section("1. ENTERPRISE KEY GENERATION");

        KeyPairRecord alice = generation.generate("Alice", 2048);
        KeyPairRecord bob = generation.generate("Bob", 2048);
        KeyPairRecord authority = generation.generate(
            "Enterprise CA",
            2048
        );

        registry.register(alice);
        registry.register(bob);
        registry.register(authority);

        policy.validateKey(alice);
        policy.validateKey(bob);

        System.out.println(
            "Alice fingerprint: " +
            alice.fingerprint().substring(0, 32)
        );

        System.out.println(
            "Bob fingerprint: " +
            bob.fingerprint().substring(0, 32)
        );

        section("2. RSA-OAEP HYBRID ENCRYPTION");

        HybridEncryptionService encryption =
            new HybridEncryptionService();

        byte[] plaintext = (
            "Confidential corporate information. ".repeat(1000)
        ).getBytes(StandardCharsets.UTF_8);

        EncryptedEnvelope envelope = encryption.encrypt(
            bob,
            plaintext,
            policy
        );

        byte[] decrypted = encryption.decrypt(
            bob,
            envelope,
            policy
        );

        System.out.println("Original bytes: " + plaintext.length);

        System.out.println(
            "Decrypted bytes: " + decrypted.length
        );

        System.out.println(
            "Recovery successful: " +
            MessageDigest.isEqual(plaintext, decrypted)
        );

        section("3. RSA-PSS DIGITAL SIGNATURE");

        DigitalSignatureService signatures =
            new DigitalSignatureService();

        byte[] document = (
            "Payment TX-1001; Amount=50000"
        ).getBytes(StandardCharsets.UTF_8);

        byte[] signed = signatures.sign(
            alice,
            document,
            policy
        );

        System.out.println(
            "Valid signature: " +
            signatures.verify(
                alice.publicKey(),
                document,
                signed,
                policy
            )
        );

        byte[] modified = (
            "Payment TX-1001; Amount=1"
        ).getBytes(StandardCharsets.UTF_8);

        System.out.println(
            "Modified document accepted: " +
            signatures.verify(
                alice.publicKey(),
                modified,
                signed,
                policy
            )
        );

        section("4. CERTIFICATE AUTHORITY");

        CertificateAuthority ca = new CertificateAuthority(
            signatures,
            authority
        );

        Certificate certificate = ca.issue(
            bob,
            365,
            policy
        );

        System.out.println("Certificate subject: " + certificate.subject());

        System.out.println(
            "Certificate valid: " + ca.verify(certificate, policy)
        );

        section("5. TRANSACTION AUTHORIZATION");

        TransactionAuthorizationService authorization =
            new TransactionAuthorizationService(
                signatures,
                audit,
                policy
            );

        boolean approved = authorization.authorize(
            "TX-1001",
            new String(document, StandardCharsets.UTF_8),
            alice,
            signed
        );

        System.out.println("Transaction approved: " + approved);

        section("6. INVALID ENVELOPE");

        EncryptedEnvelope damaged = new EncryptedEnvelope(
            envelope.recipientFingerprint(),
            envelope.encryptedSessionKey(),
            envelope.nonce(),
            new byte[] {1, 2, 3},
            envelope.authenticationTag()
        );

        try {
            encryption.decrypt(bob, damaged, policy);
            throw new IllegalStateException(
                "Tampering was not detected."
            );
        } catch (AEADBadTagException exception) {
            System.out.println("Tampering detected by AES-GCM.");
        }

        section("7. KEY GOVERNANCE");

        registry.revoke(bob.fingerprint());

        try {
            registry.requireActive(bob.fingerprint());
        } catch (PolicyException exception) {
            System.out.println(
                "Revoked key rejected: " + exception.getMessage()
            );
        }

        section("8. KEY INVENTORY");

        registry.inventory().forEach(record ->
            System.out.println(
                record.owner() + " | " +
                record.status() + " | " +
                record.fingerprint().substring(0, 24)
            )
        );

        section("9. AUDIT RECORDS");

        audit.getEvents().forEach(System.out::println);

        System.out.println("\nEnterprise demonstration completed.");
    }
}
