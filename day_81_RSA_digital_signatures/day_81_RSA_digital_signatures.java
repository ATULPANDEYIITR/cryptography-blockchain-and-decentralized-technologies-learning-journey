import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/*
 * RSA DIGITAL SIGNATURES
 *
 * Java 17 enterprise-oriented implementation.
 *
 * Features:
 * - RSA-3072 key generation
 * - RSA-PSS with SHA-256
 * - MGF1-SHA256
 * - Signature verification
 * - Immutable signature records
 * - Reviewer and key lifecycle management
 * - Key revocation
 * - Signature policy enforcement
 * - Tampering detection
 * - Audit records
 *
 * Compile:
 *   javac RsaDigitalSignatures.java
 *
 * Run:
 *   java RsaDigitalSignatures
 */

public class RsaDigitalSignatures {

    private static final String ALGORITHM = "RSASSA-PSS";

    private static final PSSParameterSpec PSS_PARAMETERS =
        new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,
            1
        );

    enum VerificationStatus {
        VALID,
        INVALID,
        REJECTED,
        ERROR
    }

    enum KeyStatus {
        ACTIVE,
        REVOKED,
        EXPIRED
    }

    enum SignaturePurpose {
        RELEASE_APPROVAL,
        DOCUMENT_AUTHENTICATION,
        SOFTWARE_ARTIFACT,
        API_ASSERTION
    }

    static class SignatureException extends Exception {
        SignatureException(String message) {
            super(message);
        }

        SignatureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record KeyMetadata(
        String keyId,
        String owner,
        Instant createdAt,
        KeyStatus status,
        int keySize
    ) {
        KeyMetadata {
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(owner);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(status);

            if (keyId.isBlank() || owner.isBlank()) {
                throw new IllegalArgumentException(
                    "Key ID and owner are required."
                );
            }

            if (keySize < 2048) {
                throw new IllegalArgumentException(
                    "RSA key size must be at least 2048."
                );
            }
        }
    }

    record SignatureRecord(
        String documentId,
        String keyId,
        String algorithm,
        String messageDigest,
        String signature,
        Instant createdAt,
        SignaturePurpose purpose
    ) {
        SignatureRecord {
            Objects.requireNonNull(documentId);
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(messageDigest);
            Objects.requireNonNull(signature);
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(purpose);

            if (documentId.isBlank()) {
                throw new IllegalArgumentException(
                    "Document ID cannot be empty."
                );
            }
        }
    }

    record AuditEvent(
        Instant timestamp,
        String documentId,
        String keyId,
        VerificationStatus status,
        String details
    ) {}

    static final class CanonicalJson {

        private CanonicalJson() {}

        static String serialize(Map<String, Object> data) {
            StringBuilder result = new StringBuilder("{");

            TreeMap<String, Object> sorted = new TreeMap<>(data);

            boolean first = true;

            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) {
                    result.append(',');
                }

                first = false;

                result.append(quote(entry.getKey()))
                    .append(':')
                    .append(value(entry.getValue()));
            }

            return result.append('}').toString();
        }

        private static String value(Object value) {
            if (value == null) {
                return "null";
            }

            if (value instanceof String text) {
                return quote(text);
            }

            if (value instanceof Boolean ||
                value instanceof Integer ||
                value instanceof Long) {
                return value.toString();
            }

            if (value instanceof Map<?, ?> map) {
                Map<String, Object> converted = new HashMap<>();

                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException(
                            "JSON object keys must be strings."
                        );
                    }

                    converted.put(key, entry.getValue());
                }

                return serialize(converted);
            }

            if (value instanceof List<?> list) {
                List<String> values = new ArrayList<>();

                for (Object item : list) {
                    values.add(value(item));
                }

                return "[" + String.join(",", values) + "]";
            }

            throw new IllegalArgumentException(
                "Unsupported canonical JSON value: " +
                value.getClass().getName()
            );
        }

        private static String quote(String text) {
            StringBuilder result = new StringBuilder("\"");

            for (char c : text.toCharArray()) {
                switch (c) {
                    case '"' -> result.append("\\\"");
                    case '\\' -> result.append("\\\\");
                    case '\n' -> result.append("\\n");
                    case '\r' -> result.append("\\r");
                    case '\t' -> result.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            result.append(String.format(
                                "\\u%04x",
                                (int) c
                            ));
                        } else {
                            result.append(c);
                        }
                    }
                }
            }

            return result.append('"').toString();
        }
    }

    static final class RSAKeyService {

        private RSAKeyService() {}

        static KeyPair generate(int keySize)
            throws GeneralSecurityException {

            if (keySize != 2048 &&
                keySize != 3072 &&
                keySize != 4096) {
                throw new IllegalArgumentException(
                    "Unsupported RSA key size."
                );
            }

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

            generator.initialize(keySize);

            return generator.generateKeyPair();
        }

        static String fingerprint(PublicKey key)
            throws GeneralSecurityException {

            byte[] digest = MessageDigest
                .getInstance("SHA-256")
                .digest(key.getEncoded());

            return HexFormatUtility.toHex(digest);
        }
    }

    static final class HexFormatUtility {

        private HexFormatUtility() {}

        static String toHex(byte[] bytes) {
            StringBuilder result = new StringBuilder();

            for (byte value : bytes) {
                result.append(String.format("%02x", value & 0xff));
            }

            return result.toString();
        }
    }

    static final class SignatureService {

        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        SignatureService(
            PrivateKey privateKey,
            PublicKey publicKey
        ) {
            this.privateKey = privateKey;
            this.publicKey = Objects.requireNonNull(publicKey);
        }

        SignatureRecord sign(
            String documentId,
            byte[] message,
            String keyId,
            SignaturePurpose purpose
        ) throws SignatureException {

            if (privateKey == null) {
                throw new SignatureException(
                    "Private key is required for signing."
                );
            }

            try {
                Signature signer = Signature.getInstance(ALGORITHM);

                signer.setParameter(PSS_PARAMETERS);
                signer.initSign(privateKey);
                signer.update(message);

                byte[] signedBytes = signer.sign();

                return new SignatureRecord(
                    documentId,
                    keyId,
                    ALGORITHM,
                    digest(message),
                    Base64.getEncoder().encodeToString(signedBytes),
                    Instant.now(),
                    purpose
                );

            } catch (GeneralSecurityException exception) {
                throw new SignatureException(
                    "Signing operation failed.",
                    exception
                );
            }
        }

        VerificationStatus verify(
            byte[] message,
            SignatureRecord record
        ) throws SignatureException {

            if (!ALGORITHM.equals(record.algorithm())) {
                return VerificationStatus.INVALID;
            }

            if (!digest(message).equals(record.messageDigest())) {
                return VerificationStatus.INVALID;
            }

            try {
                byte[] signatureBytes =
                    Base64.getDecoder().decode(record.signature());

                int expectedLength =
                    ((java.security.interfaces.RSAPublicKey) publicKey)
                        .getModulus().bitLength();

                expectedLength = (expectedLength + 7) / 8;

                if (signatureBytes.length != expectedLength) {
                    return VerificationStatus.INVALID;
                }

                Signature verifier =
                    Signature.getInstance(ALGORITHM);

                verifier.setParameter(PSS_PARAMETERS);
                verifier.initVerify(publicKey);
                verifier.update(message);

                return verifier.verify(signatureBytes)
                    ? VerificationStatus.VALID
                    : VerificationStatus.INVALID;

            } catch (IllegalArgumentException exception) {
                return VerificationStatus.INVALID;

            } catch (GeneralSecurityException exception) {
                throw new SignatureException(
                    "Verification operation failed.",
                    exception
                );
            }
        }

        static String digest(byte[] message)
            throws SignatureException {

            try {
                return HexFormatUtility.toHex(
                    MessageDigest.getInstance("SHA-256")
                        .digest(message)
                );

            } catch (GeneralSecurityException exception) {
                throw new SignatureException(
                    "SHA-256 unavailable.",
                    exception
                );
            }
        }
    }

    static final class KeyRegistry {

        private final Map<String, KeyMetadata> metadata =
            new HashMap<>();

        private final Map<String, PublicKey> publicKeys =
            new HashMap<>();

        synchronized void register(
            KeyMetadata keyMetadata,
            PublicKey publicKey
        ) {
            Objects.requireNonNull(keyMetadata);
            Objects.requireNonNull(publicKey);

            if (metadata.containsKey(keyMetadata.keyId())) {
                throw new IllegalStateException(
                    "Duplicate key identifier."
                );
            }

            if (keyMetadata.status() != KeyStatus.ACTIVE) {
                throw new IllegalArgumentException(
                    "Only active keys may be registered."
                );
            }

            metadata.put(keyMetadata.keyId(), keyMetadata);
            publicKeys.put(keyMetadata.keyId(), publicKey);
        }

        synchronized PublicKey getActiveKey(String keyId)
            throws SignatureException {

            KeyMetadata entry = metadata.get(keyId);

            if (entry == null) {
                throw new SignatureException("Unknown signing key.");
            }

            if (entry.status() != KeyStatus.ACTIVE) {
                throw new SignatureException(
                    "Signing key is not active."
                );
            }

            return publicKeys.get(keyId);
        }

        synchronized void revoke(String keyId)
            throws SignatureException {

            KeyMetadata existing = metadata.get(keyId);

            if (existing == null) {
                throw new SignatureException("Unknown key.");
            }

            metadata.put(
                keyId,
                new KeyMetadata(
                    existing.keyId(),
                    existing.owner(),
                    existing.createdAt(),
                    KeyStatus.REVOKED,
                    existing.keySize()
                )
            );
        }
    }

    static final class SignatureGovernanceService {

        private final KeyRegistry keyRegistry;
        private final Map<String, SignatureRecord> records =
            new HashMap<>();

        private final List<AuditEvent> auditLog =
            new ArrayList<>();

        SignatureGovernanceService(KeyRegistry registry) {
            this.keyRegistry = registry;
        }

        synchronized void registerSignature(
            SignatureRecord record
        ) throws SignatureException {

            keyRegistry.getActiveKey(record.keyId());

            if (records.containsKey(record.documentId())) {
                throw new SignatureException(
                    "Document already has a signature record."
                );
            }

            records.put(record.documentId(), record);

            auditLog.add(new AuditEvent(
                Instant.now(),
                record.documentId(),
                record.keyId(),
                VerificationStatus.ERROR,
                "Signature registered; verification pending."
            ));
        }

        synchronized VerificationStatus verifyDocument(
            String documentId,
            byte[] message
        ) throws SignatureException {

            SignatureRecord record = records.get(documentId);

            if (record == null) {
                throw new SignatureException(
                    "Signature record not found."
                );
            }

            VerificationStatus status;

            try {
                PublicKey key =
                    keyRegistry.getActiveKey(record.keyId());

                SignatureService service =
                    new SignatureService(null, key);

                status = service.verify(message, record);

            } catch (SignatureException exception) {
                status = VerificationStatus.REJECTED;
            }

            auditLog.add(new AuditEvent(
                Instant.now(),
                documentId,
                record.keyId(),
                status,
                "Signature verification completed."
            ));

            return status;
        }

        synchronized List<AuditEvent> auditEvents() {
            return Collections.unmodifiableList(
                new ArrayList<>(auditLog)
            );
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("RSA DIGITAL SIGNATURES");
            System.out.println("======================");

            KeyPair pair = RSAKeyService.generate(3072);

            String keyId = "KEY-RELEASE-001";

            KeyMetadata metadata = new KeyMetadata(
                keyId,
                "Release Engineering",
                Instant.now(),
                KeyStatus.ACTIVE,
                3072
            );

            KeyRegistry registry = new KeyRegistry();

            registry.register(metadata, pair.getPublic());

            SignatureService signingService =
                new SignatureService(
                    pair.getPrivate(),
                    pair.getPublic()
                );

            Map<String, Object> document = new HashMap<>();

            document.put("documentId", "RELEASE-2026-001");
            document.put("repository", "payment-platform");
            document.put("version", 3);
            document.put("approved", true);

            byte[] message = CanonicalJson.serialize(document)
                .getBytes(StandardCharsets.UTF_8);

            SignatureRecord record = signingService.sign(
                "RELEASE-2026-001",
                message,
                keyId,
                SignaturePurpose.RELEASE_APPROVAL
            );

            System.out.println(
                "Key fingerprint: " +
                RSAKeyService.fingerprint(pair.getPublic())
            );

            System.out.println(
                "Message digest: " + record.messageDigest()
            );

            System.out.println(
                "Original verification: " +
                signingService.verify(message, record)
            );

            Map<String, Object> modified = new HashMap<>(document);
            modified.put("approved", false);

            byte[] changedMessage =
                CanonicalJson.serialize(modified)
                    .getBytes(StandardCharsets.UTF_8);

            System.out.println(
                "Modified document: " +
                signingService.verify(changedMessage, record)
            );

            KeyRegistry publicRegistry = registry;

            SignatureGovernanceService governance =
                new SignatureGovernanceService(publicRegistry);

            governance.registerSignature(record);

            System.out.println(
                "Governance verification: " +
                governance.verifyDocument(
                    "RELEASE-2026-001",
                    message
                )
            );

            registry.revoke(keyId);

            System.out.println(
                "Verification after key revocation: " +
                governance.verifyDocument(
                    "RELEASE-2026-001",
                    message
                )
            );

            System.out.println(
                "Audit entries: " +
                governance.auditEvents().size()
            );

            if (signingService.verify(message, record)
                != VerificationStatus.VALID) {
                throw new IllegalStateException(
                    "Valid signature was rejected."
                );
            }

            if (signingService.verify(changedMessage, record)
                != VerificationStatus.INVALID) {
                throw new IllegalStateException(
                    "Tampering was not detected."
                );
            }

            System.out.println("All tests passed.");

        } catch (Exception exception) {
            System.err.println(
                "Execution failed: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
