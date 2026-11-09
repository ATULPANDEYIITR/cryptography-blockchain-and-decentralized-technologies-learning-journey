import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/*
 * Enterprise RSA Encryption and Decryption System
 *
 * Java 17 implementation using JCA and JCE.
 *
 * Cryptographic mechanisms:
 * - RSA key generation
 * - RSA-OAEP with SHA-256
 * - RSA-PSS with SHA-256
 * - Public/private key separation
 * - Key lifecycle management
 * - Policy evaluation
 * - Operation auditing
 * - State transitions
 */

// ============================================================
// Domain exceptions
// ============================================================

class RSAApplicationException extends Exception {
    public RSAApplicationException(String message) {
        super(message);
    }

    public RSAApplicationException(
        String message,
        Throwable cause
    ) {
        super(message, cause);
    }
}

class KeyManagementException extends RSAApplicationException {
    public KeyManagementException(String message) {
        super(message);
    }
}

class CryptographicOperationException extends RSAApplicationException {
    public CryptographicOperationException(
        String message,
        Throwable cause
    ) {
        super(message, cause);
    }
}

// ============================================================
// Enumerations
// ============================================================

enum KeyStatus {
    ACTIVE,
    REVOKED,
    EXPIRED
}

enum OperationType {
    ENCRYPTION,
    DECRYPTION,
    SIGNING,
    VERIFICATION
}

enum SecurityLevel {
    STANDARD,
    HIGH
}

// ============================================================
// Immutable configuration
// ============================================================

record RSAConfiguration(
    int keySize,
    int publicExponent,
    String hashAlgorithm,
    SecurityLevel securityLevel
) {
    RSAConfiguration {
        if (keySize < 2048 || keySize > 8192
            || keySize % 256 != 0) {
            throw new IllegalArgumentException(
                "RSA key size must be 2048-8192 bits."
            );
        }

        if (publicExponent != 65537) {
            throw new IllegalArgumentException(
                "Only public exponent 65537 is permitted."
            );
        }

        if (!"SHA-256".equals(hashAlgorithm)) {
            throw new IllegalArgumentException(
                "SHA-256 is required."
            );
        }

        Objects.requireNonNull(securityLevel);
    }

    static RSAConfiguration standard() {
        return new RSAConfiguration(
            2048,
            65537,
            "SHA-256",
            SecurityLevel.STANDARD
        );
    }
}

// ============================================================
// Key record
// ============================================================

record ManagedRSAKey(
    String keyId,
    PublicKey publicKey,
    PrivateKey privateKey,
    String fingerprint,
    KeyStatus status,
    long createdAt
) {
    ManagedRSAKey {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(publicKey);
        Objects.requireNonNull(privateKey);
        Objects.requireNonNull(fingerprint);
        Objects.requireNonNull(status);

        if (keyId.isBlank()) {
            throw new IllegalArgumentException(
                "Key identifier cannot be empty."
            );
        }

        if (!(publicKey instanceof RSAKey rsaKey)
            || rsaKey.getModulus().bitLength() < 2048) {
            throw new IllegalArgumentException(
                "Invalid RSA public key."
            );
        }

        if (!(privateKey instanceof RSAKey rsaKey)
            || rsaKey.getModulus().bitLength() < 2048) {
            throw new IllegalArgumentException(
                "Invalid RSA private key."
            );
        }
    }

    ManagedRSAKey withStatus(KeyStatus newStatus) {
        return new ManagedRSAKey(
            keyId,
            publicKey,
            privateKey,
            fingerprint,
            newStatus,
            createdAt
        );
    }
}

// ============================================================
// Cryptographic utilities
// ============================================================

final class RSAUtilities {

    private RSAUtilities() {}

    static String fingerprint(PublicKey publicKey)
        throws GeneralSecurityException {

        byte[] digest = java.security.MessageDigest
            .getInstance("SHA-256")
            .digest(publicKey.getEncoded());

        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(digest);
    }

    static String exportPublicKey(PublicKey publicKey) {
        return Base64.getMimeEncoder(
            64,
            "\n".getBytes(StandardCharsets.UTF_8)
        ).encodeToString(publicKey.getEncoded());
    }

    static String exportPrivateKey(PrivateKey privateKey) {
        return Base64.getMimeEncoder(
            64,
            "\n".getBytes(StandardCharsets.UTF_8)
        ).encodeToString(privateKey.getEncoded());
    }

    static PublicKey importPublicKey(String encoded)
        throws GeneralSecurityException {

        byte[] bytes = Base64.getMimeDecoder().decode(encoded);

        return KeyFactory.getInstance("RSA").generatePublic(
            new X509EncodedKeySpec(bytes)
        );
    }

    static PrivateKey importPrivateKey(String encoded)
        throws GeneralSecurityException {

        byte[] bytes = Base64.getMimeDecoder().decode(encoded);

        return KeyFactory.getInstance("RSA").generatePrivate(
            new PKCS8EncodedKeySpec(bytes)
        );
    }
}

// ============================================================
// Key generation service
// ============================================================

class RSAKeyService {

    private final RSAConfiguration configuration;

    RSAKeyService(RSAConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration);
    }

    ManagedRSAKey generate(String keyId)
        throws KeyManagementException {

        if (keyId == null
            || !keyId.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new KeyManagementException(
                "Invalid key identifier."
            );
        }

        try {
            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

            generator.initialize(
                configuration.keySize()
            );

            KeyPair pair = generator.generateKeyPair();

            return new ManagedRSAKey(
                keyId,
                pair.getPublic(),
                pair.getPrivate(),
                RSAUtilities.fingerprint(pair.getPublic()),
                KeyStatus.ACTIVE,
                System.currentTimeMillis()
            );

        } catch (GeneralSecurityException exception) {
            throw new KeyManagementException(
                "RSA key generation failed."
            );
        }
    }
}

// ============================================================
// Repository for managed keys
// ============================================================

class RSAKeyRepository {

    private final Map<String, ManagedRSAKey> keys =
        new ConcurrentHashMap<>();

    void register(ManagedRSAKey key)
        throws KeyManagementException {

        Objects.requireNonNull(key);

        ManagedRSAKey previous = keys.putIfAbsent(
            key.keyId(),
            key
        );

        if (previous != null) {
            throw new KeyManagementException(
                "Duplicate key identifier."
            );
        }
    }

    ManagedRSAKey find(String keyId)
        throws KeyManagementException {

        ManagedRSAKey key = keys.get(keyId);

        if (key == null) {
            throw new KeyManagementException(
                "Key does not exist."
            );
        }

        return key;
    }

    ManagedRSAKey findActive(String keyId)
        throws KeyManagementException {

        ManagedRSAKey key = find(keyId);

        if (key.status() != KeyStatus.ACTIVE) {
            throw new KeyManagementException(
                "Key is not active."
            );
        }

        return key;
    }

    void revoke(String keyId)
        throws KeyManagementException {

        keys.compute(keyId, (identifier, existing) -> {
            if (existing == null) {
                throw new IllegalStateException(
                    "Key does not exist."
                );
            }

            if (existing.status() == KeyStatus.REVOKED) {
                return existing;
            }

            return existing.withStatus(KeyStatus.REVOKED);
        });
    }

    int activeCount() {
        return (int) keys.values().stream()
            .filter(key -> key.status() == KeyStatus.ACTIVE)
            .count();
    }
}

// ============================================================
// Cryptographic policy
// ============================================================

interface CryptographicPolicy {

    void validateEncryption(
        ManagedRSAKey key,
        byte[] plaintext
    ) throws RSAApplicationException;

    void validateDecryption(
        ManagedRSAKey key,
        byte[] ciphertext
    ) throws RSAApplicationException;
}

class StandardRSAPolicy implements CryptographicPolicy {

    private static final int HASH_LENGTH = 32;

    @Override
    public void validateEncryption(
        ManagedRSAKey key,
        byte[] plaintext
    ) throws RSAApplicationException {

        if (key.status() != KeyStatus.ACTIVE) {
            throw new RSAApplicationException(
                "Encryption key is not active."
            );
        }

        int modulusBytes =
            (((RSAKey) key.publicKey()).getModulus().bitLength() + 7) / 8;

        int maximum = modulusBytes - 2 * HASH_LENGTH - 2;

        if (plaintext.length > maximum) {
            throw new RSAApplicationException(
                "Plaintext exceeds RSA-OAEP message limit."
            );
        }
    }

    @Override
    public void validateDecryption(
        ManagedRSAKey key,
        byte[] ciphertext
    ) throws RSAApplicationException {

        if (key.status() != KeyStatus.ACTIVE) {
            throw new RSAApplicationException(
                "Decryption key is not active."
            );
        }

        int modulusBytes =
            (((RSAKey) key.privateKey()).getModulus().bitLength() + 7) / 8;

        if (ciphertext.length != modulusBytes) {
            throw new RSAApplicationException(
                "Invalid RSA ciphertext length."
            );
        }
    }
}

// ============================================================
// Operation audit
// ============================================================

record AuditEvent(
    long eventId,
    String keyId,
    OperationType operation,
    boolean successful,
    long timestamp,
    String detail
) {}

class AuditService {

    private final List<AuditEvent> events =
        Collections.synchronizedList(new ArrayList<>());

    private final AtomicLong sequence = new AtomicLong();

    void record(
        String keyId,
        OperationType operation,
        boolean successful,
        String detail
    ) {
        events.add(
            new AuditEvent(
                sequence.incrementAndGet(),
                keyId,
                operation,
                successful,
                System.currentTimeMillis(),
                detail
            )
        );
    }

    List<AuditEvent> getEvents() {
        synchronized (events) {
            return List.copyOf(events);
        }
    }

    Map<OperationType, Long> operationCounts() {
        Map<OperationType, Long> counts =
            new EnumMap<>(OperationType.class);

        synchronized (events) {
            for (AuditEvent event : events) {
                counts.merge(
                    event.operation(),
                    1L,
                    Long::sum
                );
            }
        }

        return Map.copyOf(counts);
    }
}

// ============================================================
// Encryption and decryption service
// ============================================================

class RSACryptoService {

    private final RSAKeyRepository repository;
    private final CryptographicPolicy policy;
    private final AuditService audit;

    RSACryptoService(
        RSAKeyRepository repository,
        CryptographicPolicy policy,
        AuditService audit
    ) {
        this.repository = repository;
        this.policy = policy;
        this.audit = audit;
    }

    byte[] encrypt(
        String keyId,
        byte[] plaintext,
        byte[] label
    ) throws RSAApplicationException {

        ManagedRSAKey key = repository.findActive(keyId);

        policy.validateEncryption(key, plaintext);

        try {
            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            var parameters = new javax.crypto.spec.OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                new javax.crypto.spec.PSource.PSpecified(label)
            );

            cipher.init(
                Cipher.ENCRYPT_MODE,
                key.publicKey(),
                parameters
            );

            byte[] ciphertext = cipher.doFinal(plaintext);

            audit.record(
                keyId,
                OperationType.ENCRYPTION,
                true,
                "RSA-OAEP-SHA256"
            );

            return ciphertext;

        } catch (GeneralSecurityException exception) {
            audit.record(
                keyId,
                OperationType.ENCRYPTION,
                false,
                "Cryptographic failure"
            );

            throw new CryptographicOperationException(
                "Encryption operation failed.",
                exception
            );
        }
    }

    byte[] decrypt(
        String keyId,
        byte[] ciphertext,
        byte[] label
    ) throws RSAApplicationException {

        ManagedRSAKey key = repository.findActive(keyId);

        policy.validateDecryption(key, ciphertext);

        try {
            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            var parameters = new javax.crypto.spec.OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                new javax.crypto.spec.PSource.PSpecified(label)
            );

            cipher.init(
                Cipher.DECRYPT_MODE,
                key.privateKey(),
                parameters
            );

            byte[] plaintext = cipher.doFinal(ciphertext);

            audit.record(
                keyId,
                OperationType.DECRYPTION,
                true,
                "RSA-OAEP-SHA256"
            );

            return plaintext;

        } catch (GeneralSecurityException exception) {
            audit.record(
                keyId,
                OperationType.DECRYPTION,
                false,
                "Cryptographic failure"
            );

            throw new CryptographicOperationException(
                "Decryption failed.",
                exception
            );
        }
    }

    byte[] sign(
        String keyId,
        byte[] message
    ) throws RSAApplicationException {

        ManagedRSAKey key = repository.findActive(keyId);

        try {
            Signature signature = Signature.getInstance(
                "RSASSA-PSS"
            );

            signature.setParameter(
                new PSSParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    32,
                    1
                )
            );

            signature.initSign(key.privateKey());
            signature.update(message);

            byte[] result = signature.sign();

            audit.record(
                keyId,
                OperationType.SIGNING,
                true,
                "RSA-PSS-SHA256"
            );

            return result;

        } catch (GeneralSecurityException exception) {
            throw new CryptographicOperationException(
                "Signing failed.",
                exception
            );
        }
    }

    boolean verify(
        String keyId,
        byte[] message,
        byte[] signedData
    ) throws RSAApplicationException {

        ManagedRSAKey key = repository.find(keyId);

        try {
            Signature signature = Signature.getInstance(
                "RSASSA-PSS"
            );

            signature.setParameter(
                new PSSParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    32,
                    1
                )
            );

            signature.initVerify(key.publicKey());
            signature.update(message);

            boolean valid = signature.verify(signedData);

            audit.record(
                keyId,
                OperationType.VERIFICATION,
                valid,
                "RSA-PSS-SHA256"
            );

            return valid;

        } catch (GeneralSecurityException exception) {
            throw new CryptographicOperationException(
                "Signature verification failed.",
                exception
            );
        }
    }
}

// ============================================================
// Enterprise application
// ============================================================

public class RSAEnterpriseApplication {

    private static void printSection(String heading) {
        System.out.println();
        System.out.println("========================================");
        System.out.println(heading);
        System.out.println("========================================");
    }

    public static void main(String[] args) {

        try {
            printSection("RSA ENTERPRISE ENCRYPTION SYSTEM");

            RSAConfiguration configuration =
                RSAConfiguration.standard();

            RSAKeyService keyService =
                new RSAKeyService(configuration);

            RSAKeyRepository repository =
                new RSAKeyRepository();

            AuditService audit = new AuditService();

            CryptographicPolicy policy =
                new StandardRSAPolicy();

            RSACryptoService crypto =
                new RSACryptoService(
                    repository,
                    policy,
                    audit
                );

            // Generate and register a key.
            ManagedRSAKey key = keyService.generate(
                "enterprise-key-001"
            );

            repository.register(key);

            System.out.println(
                "Key fingerprint: " + key.fingerprint()
            );

            System.out.println(
                "Key status: " + key.status()
            );

            // Original plaintext.
            String original =
                "Confidential enterprise financial transaction.";

            byte[] plaintext = original.getBytes(
                StandardCharsets.UTF_8
            );

            byte[] label = "enterprise-v1".getBytes(
                StandardCharsets.UTF_8
            );

            // Encrypt.
            printSection("ENCRYPTION");

            byte[] ciphertext = crypto.encrypt(
                key.keyId(),
                plaintext,
                label
            );

            System.out.println(
                "Ciphertext length: " + ciphertext.length
            );

            System.out.println(
                "Ciphertext Base64: "
                + Base64.getEncoder().encodeToString(ciphertext)
            );

            // Decrypt.
            printSection("DECRYPTION");

            byte[] decrypted = crypto.decrypt(
                key.keyId(),
                ciphertext,
                label
            );

            String recovered = new String(
                decrypted,
                StandardCharsets.UTF_8
            );

            System.out.println("Recovered: " + recovered);

            if (!original.equals(recovered)) {
                throw new IllegalStateException(
                    "RSA round-trip verification failed."
                );
            }

            System.out.println("Encryption/decryption: PASSED");

            // Digital signature.
            printSection("DIGITAL SIGNATURE");

            byte[] signedData = crypto.sign(
                key.keyId(),
                plaintext
            );

            boolean valid = crypto.verify(
                key.keyId(),
                plaintext,
                signedData
            );

            if (!valid) {
                throw new IllegalStateException(
                    "Signature verification failed."
                );
            }

            System.out.println("Signature: VALID");

            byte[] tampered = (
                original + " altered"
            ).getBytes(StandardCharsets.UTF_8);

            boolean tamperedValid = crypto.verify(
                key.keyId(),
                tampered,
                signedData
            );

            System.out.println(
                "Tampered signature accepted: " + tamperedValid
            );

            if (tamperedValid) {
                throw new IllegalStateException(
                    "Tampered content was accepted."
                );
            }

            // Wrong OAEP label.
            printSection("FAILURE VALIDATION");

            try {
                crypto.decrypt(
                    key.keyId(),
                    ciphertext,
                    "incorrect-label".getBytes(
                        StandardCharsets.UTF_8
                    )
                );

                throw new IllegalStateException(
                    "Incorrect OAEP label was accepted."
                );

            } catch (CryptographicOperationException expected) {
                System.out.println(
                    "Incorrect label rejection: PASSED"
                );
            }

            // Oversized message.
            try {
                crypto.encrypt(
                    key.keyId(),
                    new byte[191],
                    label
                );

                throw new IllegalStateException(
                    "Oversized message was accepted."
                );

            } catch (RSAApplicationException expected) {
                System.out.println(
                    "Message-size validation: PASSED"
                );
            }

            // Key revocation.
            printSection("KEY LIFECYCLE");

            repository.revoke(key.keyId());

            System.out.println(
                "Key status: "
                + repository.find(key.keyId()).status()
            );

            try {
                crypto.decrypt(
                    key.keyId(),
                    ciphertext,
                    label
                );

                throw new IllegalStateException(
                    "Revoked key was accepted."
                );

            } catch (KeyManagementException expected) {
                System.out.println(
                    "Revocation enforcement: PASSED"
                );
            }

            // Audit report.
            printSection("AUDIT REPORT");

            for (AuditEvent event : audit.getEvents()) {
                System.out.printf(
                    "ID=%d | KEY=%s | OPERATION=%s | SUCCESS=%s%n",
                    event.eventId(),
                    event.keyId(),
                    event.operation(),
                    event.successful()
                );
            }

            System.out.println(
                "Operation counts: "
                + audit.operationCounts()
            );

            System.out.println(
                "Active keys: " + repository.activeCount()
            );

        } catch (Exception exception) {
            System.err.println(
                "Application failure: " + exception.getMessage()
            );

            exception.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
