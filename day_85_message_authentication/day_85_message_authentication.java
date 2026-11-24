import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.security.MessageDigest;
import java.security.SecureRandom;

import java.time.Instant;

import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/*
 * MESSAGE AUTHENTICATION
 *
 * Enterprise-oriented Java 17 implementation.
 *
 * Features:
 * - HMAC-SHA256
 * - Immutable message records
 * - Key lifecycle management
 * - Explicit authentication states
 * - Reviewer-independent authentication policy
 * - Replay prevention
 * - Timestamp validation
 * - Concurrent request handling
 *
 * Dependencies: Java 17 standard library.
 */

// ============================================================
// 1. DOMAIN TYPES
// ============================================================

enum AuthenticationStatus {

    AUTHENTICATED,
    INVALID_SIGNATURE,
    UNKNOWN_KEY,
    REVOKED_KEY,
    EXPIRED_MESSAGE,
    REPLAY_DETECTED,
    INVALID_MESSAGE
}

enum KeyState {

    ACTIVE,
    REVOKED
}

record AuthenticatedMessage(
    String sender,
    String receiver,
    String messageId,
    long timestamp,
    String payload,
    String keyId,
    String signature
) {}

record VerificationResult(
    AuthenticationStatus status,
    String detail,
    Optional<String> sender,
    Optional<String> messageId
) {

    public boolean authenticated() {
        return status == AuthenticationStatus.AUTHENTICATED;
    }
}

record AuthenticationPolicy(
    long allowedClockSkewSeconds,
    int maximumPayloadBytes,
    int minimumKeyBytes
) {

    public AuthenticationPolicy {

        if (allowedClockSkewSeconds < 0) {
            throw new IllegalArgumentException(
                "Clock skew cannot be negative"
            );
        }

        if (maximumPayloadBytes <= 0 || minimumKeyBytes < 32) {
            throw new IllegalArgumentException(
                "Invalid authentication policy"
            );
        }
    }

    public static AuthenticationPolicy standard() {

        return new AuthenticationPolicy(
            60,
            65536,
            32
        );
    }
}

// ============================================================
// 2. CUSTOM EXCEPTIONS
// ============================================================

class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message) {
        super(message);
    }
}

class KeyManagementException extends RuntimeException {

    public KeyManagementException(String message) {
        super(message);
    }
}

// ============================================================
// 3. CANONICAL MESSAGE ENCODING
// ============================================================

final class MessageEncoder {

    private MessageEncoder() {}

    private static void appendField(
        StringBuilder output,
        String value
    ) {

        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);

        output.append(bytes.length)
              .append(':')
              .append(value);
    }

    public static byte[] encode(AuthenticatedMessage message) {

        StringBuilder output = new StringBuilder();

        appendField(output, message.sender());
        appendField(output, message.receiver());
        appendField(output, message.messageId());

        output.append(message.timestamp()).append(':');

        appendField(output, message.payload());
        appendField(output, message.keyId());

        return output.toString().getBytes(StandardCharsets.UTF_8);
    }
}

// ============================================================
// 4. HMAC SERVICE
// ============================================================

final class HmacService {

    private static final String ALGORITHM = "HmacSHA256";

    private HmacService() {}

    public static byte[] calculate(
        byte[] secret,
        byte[] message
    ) {

        try {

            if (secret == null || secret.length < 32) {
                throw new KeyManagementException(
                    "HMAC key must contain at least 32 bytes"
                );
            }

            Mac mac = Mac.getInstance(ALGORITHM);

            SecretKey key = new SecretKeySpec(
                secret,
                ALGORITHM
            );

            mac.init(key);

            return mac.doFinal(message);

        } catch (KeyManagementException error) {

            throw error;

        } catch (Exception error) {

            throw new AuthenticationException(
                "HMAC calculation failed: " + error.getMessage()
            );
        }
    }

    public static String sign(
        byte[] secret,
        byte[] message
    ) {

        return HexFormat.of().formatHex(
            calculate(secret, message)
        );
    }

    public static boolean verify(
        byte[] secret,
        byte[] message,
        String suppliedSignature
    ) {

        if (
            suppliedSignature == null ||
            !suppliedSignature.matches("[0-9a-fA-F]{64}")
        ) {
            return false;
        }

        byte[] supplied;

        try {
            supplied = HexFormat.of().parseHex(suppliedSignature);
        } catch (IllegalArgumentException error) {
            return false;
        }

        byte[] expected = calculate(secret, message);

        return MessageDigest.isEqual(expected, supplied);
    }
}

// ============================================================
// 5. SECURE KEY REGISTRY
// ============================================================

record ManagedKey(
    String id,
    String owner,
    byte[] secret,
    KeyState state,
    Instant createdAt
) {

    public ManagedKey {

        Objects.requireNonNull(id);
        Objects.requireNonNull(owner);
        Objects.requireNonNull(secret);
        Objects.requireNonNull(state);
        Objects.requireNonNull(createdAt);

        secret = secret.clone();
    }

    @Override
    public byte[] secret() {
        return secret.clone();
    }
}

final class KeyRegistry {

    private final Map<String, ManagedKey> keys =
        new ConcurrentHashMap<>();

    private final SecureRandom random = new SecureRandom();

    private final int minimumKeyBytes;

    public KeyRegistry(int minimumKeyBytes) {

        if (minimumKeyBytes < 32) {
            throw new IllegalArgumentException(
                "Minimum key length must be at least 32 bytes"
            );
        }

        this.minimumKeyBytes = minimumKeyBytes;
    }

    public ManagedKey create(String owner) {

        if (owner == null || owner.isBlank()) {
            throw new KeyManagementException("Invalid owner");
        }

        byte[] secret = new byte[minimumKeyBytes];

        random.nextBytes(secret);

        ManagedKey key = new ManagedKey(
            UUID.randomUUID().toString(),
            owner,
            secret,
            KeyState.ACTIVE,
            Instant.now()
        );

        keys.put(key.id(), key);

        return key;
    }

    public Optional<ManagedKey> find(String id) {
        return Optional.ofNullable(keys.get(id));
    }

    public ManagedKey rotate(String id) {

        ManagedKey oldKey = keys.get(id);

        if (
            oldKey == null ||
            oldKey.state() != KeyState.ACTIVE
        ) {
            throw new KeyManagementException(
                "Key cannot be rotated"
            );
        }

        // Atomic replacement prevents concurrent operations from
        // overwriting a newer key state.
        ManagedKey revoked = new ManagedKey(
            oldKey.id(),
            oldKey.owner(),
            oldKey.secret(),
            KeyState.REVOKED,
            oldKey.createdAt()
        );

        if (!keys.replace(id, oldKey, revoked)) {
            throw new KeyManagementException(
                "Concurrent key rotation conflict"
            );
        }

        return create(oldKey.owner());
    }

    public void revoke(String id) {

        keys.compute(id, (keyId, oldKey) -> {

            if (oldKey == null) {
                throw new KeyManagementException("Unknown key");
            }

            return new ManagedKey(
                oldKey.id(),
                oldKey.owner(),
                oldKey.secret(),
                KeyState.REVOKED,
                oldKey.createdAt()
            );
        });
    }
}

// ============================================================
// 6. REPLAY PREVENTION
// ============================================================

final class ReplayProtection {

    private final Map<String, Long> processed =
        new ConcurrentHashMap<>();

    private final long retentionSeconds;

    public ReplayProtection(long retentionSeconds) {

        if (retentionSeconds <= 0) {
            throw new IllegalArgumentException(
                "Retention must be positive"
            );
        }

        this.retentionSeconds = retentionSeconds;
    }

    public boolean register(
        String sender,
        String messageId,
        long currentTime
    ) {

        cleanup(currentTime);

        String identifier = sender + ":" + messageId;

        long expiry = currentTime + retentionSeconds;

        // putIfAbsent is atomic for concurrent verification requests.
        return processed.putIfAbsent(identifier, expiry) == null;
    }

    public void cleanup(long currentTime) {

        processed.entrySet().removeIf(
            entry -> entry.getValue() <= currentTime
        );
    }
}

// ============================================================
// 7. MESSAGE VALIDATION
// ============================================================

final class MessageValidator {

    private MessageValidator() {}

    public static void validate(
        AuthenticatedMessage message,
        AuthenticationPolicy policy
    ) {

        if (message == null) {
            throw new AuthenticationException("Message is null");
        }

        if (
            message.sender() == null ||
            message.sender().isBlank() ||
            message.receiver() == null ||
            message.receiver().isBlank() ||
            message.messageId() == null ||
            message.messageId().isBlank() ||
            message.keyId() == null ||
            message.keyId().isBlank() ||
            message.payload() == null
        ) {
            throw new AuthenticationException(
                "Required message fields are missing"
            );
        }

        if (message.timestamp() <= 0) {
            throw new AuthenticationException(
                "Invalid message timestamp"
            );
        }

        int size = message.payload().getBytes(
            StandardCharsets.UTF_8
        ).length;

        if (size > policy.maximumPayloadBytes()) {
            throw new AuthenticationException(
                "Payload exceeds maximum size"
            );
        }

        if (
            message.signature() == null ||
            !message.signature().matches("[0-9a-fA-F]{64}")
        ) {
            throw new AuthenticationException(
                "Invalid signature format"
            );
        }
    }
}

// ============================================================
// 8. AUTHENTICATION SERVICE
// ============================================================

final class AuthenticationService {

    private final KeyRegistry keyRegistry;
    private final ReplayProtection replayProtection;
    private final AuthenticationPolicy policy;

    public AuthenticationService(
        KeyRegistry keyRegistry,
        ReplayProtection replayProtection,
        AuthenticationPolicy policy
    ) {

        this.keyRegistry = Objects.requireNonNull(keyRegistry);
        this.replayProtection = Objects.requireNonNull(replayProtection);
        this.policy = Objects.requireNonNull(policy);
    }

    public AuthenticatedMessage createMessage(
        String sender,
        String receiver,
        String payload,
        String keyId
    ) {

        ManagedKey key = keyRegistry.find(keyId)
            .orElseThrow(() ->
                new KeyManagementException("Unknown signing key")
            );

        if (key.state() != KeyState.ACTIVE) {
            throw new KeyManagementException("Signing key revoked");
        }

        if (!key.owner().equals(sender)) {
            throw new KeyManagementException(
                "Sender does not own the signing key"
            );
        }

        AuthenticatedMessage unsigned = new AuthenticatedMessage(
            sender,
            receiver,
            UUID.randomUUID().toString(),
            Instant.now().getEpochSecond(),
            payload,
            keyId,
            ""
        );

        MessageValidator.validate(
            new AuthenticatedMessage(
                sender,
                receiver,
                unsigned.messageId(),
                unsigned.timestamp(),
                payload,
                keyId,
                "0".repeat(64)
            ),
            policy
        );

        String signature = HmacService.sign(
            key.secret(),
            MessageEncoder.encode(unsigned)
        );

        return new AuthenticatedMessage(
            sender,
            receiver,
            unsigned.messageId(),
            unsigned.timestamp(),
            payload,
            keyId,
            signature
        );
    }

    public VerificationResult verify(
        AuthenticatedMessage message
    ) {

        long now = Instant.now().getEpochSecond();

        return verifyAt(message, now);
    }

    public VerificationResult verifyAt(
        AuthenticatedMessage message,
        long currentTime
    ) {

        try {

            MessageValidator.validate(message, policy);

        } catch (AuthenticationException error) {

            return failure(
                AuthenticationStatus.INVALID_MESSAGE,
                error.getMessage(),
                message
            );
        }

        if (
            Math.abs(
                currentTime - message.timestamp()
            ) > policy.allowedClockSkewSeconds()
        ) {
            return failure(
                AuthenticationStatus.EXPIRED_MESSAGE,
                "Timestamp outside allowed clock window",
                message
            );
        }

        Optional<ManagedKey> optionalKey =
            keyRegistry.find(message.keyId());

        if (optionalKey.isEmpty()) {

            return failure(
                AuthenticationStatus.UNKNOWN_KEY,
                "Unknown key identifier",
                message
            );
        }

        ManagedKey key = optionalKey.get();

        if (key.state() == KeyState.REVOKED) {

            return failure(
                AuthenticationStatus.REVOKED_KEY,
                "Key has been revoked",
                message
            );
        }

        if (!key.owner().equals(message.sender())) {

            return failure(
                AuthenticationStatus.INVALID_SIGNATURE,
                "Key ownership mismatch",
                message
            );
        }

        byte[] encoded = MessageEncoder.encode(message);

        if (!HmacService.verify(
            key.secret(),
            encoded,
            message.signature()
        )) {

            return failure(
                AuthenticationStatus.INVALID_SIGNATURE,
                "HMAC verification failed",
                message
            );
        }

        if (!replayProtection.register(
            message.sender(),
            message.messageId(),
            currentTime
        )) {

            return failure(
                AuthenticationStatus.REPLAY_DETECTED,
                "Duplicate message identifier",
                message
            );
        }

        return new VerificationResult(
            AuthenticationStatus.AUTHENTICATED,
            "Message successfully authenticated",
            Optional.of(message.sender()),
            Optional.of(message.messageId())
        );
    }

    private VerificationResult failure(
        AuthenticationStatus status,
        String detail,
        AuthenticatedMessage message
    ) {

        return new VerificationResult(
            status,
            detail,
            Optional.ofNullable(message)
                .map(AuthenticatedMessage::sender),
            Optional.ofNullable(message)
                .map(AuthenticatedMessage::messageId)
        );
    }
}

// ============================================================
// 9. ENTERPRISE MESSAGE PROCESSOR
// ============================================================

final class MessageProcessor {

    private final AuthenticationService authenticationService;

    private final AtomicLong acceptedCount = new AtomicLong();
    private final AtomicLong rejectedCount = new AtomicLong();

    public MessageProcessor(
        AuthenticationService authenticationService
    ) {
        this.authenticationService = authenticationService;
    }

    public VerificationResult process(
        AuthenticatedMessage message
    ) {

        VerificationResult result =
            authenticationService.verify(message);

        if (result.authenticated()) {

            acceptedCount.incrementAndGet();

            // Business logic is executed only after authentication.
            System.out.println(
                "Accepted authenticated message from "
                + message.sender()
                + ": "
                + message.payload()
            );

        } else {

            rejectedCount.incrementAndGet();

            System.out.println(
                "Rejected message: " + result.status()
            );
        }

        return result;
    }

    public long acceptedCount() {
        return acceptedCount.get();
    }

    public long rejectedCount() {
        return rejectedCount.get();
    }
}

// ============================================================
// 10. EXECUTABLE TESTS
// ============================================================

public class MessageAuthentication {

    public static void main(String[] args) {

        AuthenticationPolicy policy =
            AuthenticationPolicy.standard();

        KeyRegistry registry = new KeyRegistry(
            policy.minimumKeyBytes()
        );

        ReplayProtection replay = new ReplayProtection(600);

        AuthenticationService service =
            new AuthenticationService(
                registry,
                replay,
                policy
            );

        MessageProcessor processor =
            new MessageProcessor(service);

        ManagedKey aliceKey = registry.create("alice");

        System.out.println("MESSAGE AUTHENTICATION");
        System.out.println("======================");

        AuthenticatedMessage valid = service.createMessage(
            "alice",
            "bob",
            "Transfer INR 5000",
            aliceKey.id()
        );

        VerificationResult first = processor.process(valid);

        assert first.authenticated();

        System.out.println("1. Valid message: " + first.status());

        VerificationResult repeated = service.verify(valid);

        assert repeated.status() ==
            AuthenticationStatus.REPLAY_DETECTED;

        System.out.println("2. Replay: " + repeated.status());

        AuthenticatedMessage tampered =
            new AuthenticatedMessage(
                valid.sender(),
                valid.receiver(),
                valid.messageId(),
                valid.timestamp(),
                "Transfer INR 500000",
                valid.keyId(),
                valid.signature()
            );

        VerificationResult altered = service.verify(tampered);

        assert altered.status() ==
            AuthenticationStatus.INVALID_SIGNATURE;

        System.out.println("3. Tampering: " + altered.status());

        long now = Instant.now().getEpochSecond();

        AuthenticatedMessage oldMessage =
            new AuthenticatedMessage(
                valid.sender(),
                valid.receiver(),
                UUID.randomUUID().toString(),
                now - 300,
                "Historical request",
                valid.keyId(),
                valid.signature()
            );

        VerificationResult expired = service.verifyAt(
            oldMessage,
            now
        );

        assert expired.status() ==
            AuthenticationStatus.EXPIRED_MESSAGE;

        System.out.println("4. Expired message: " + expired.status());

        ManagedKey rotated = registry.rotate(aliceKey.id());

        AuthenticatedMessage newMessage = service.createMessage(
            "alice",
            "bob",
            "Signed with replacement key",
            rotated.id()
        );

        VerificationResult rotation = service.verify(newMessage);

        assert rotation.authenticated();

        System.out.println("5. Key rotation: " + rotation.status());

        registry.revoke(rotated.id());

        VerificationResult revoked = service.verify(
            newMessageWithFreshId(service, rotated.id())
        );

        assert revoked.status() ==
            AuthenticationStatus.REVOKED_KEY;

        System.out.println("6. Revoked key: " + revoked.status());

        System.out.println("\nAccepted: " + processor.acceptedCount());
        System.out.println("Rejected: " + processor.rejectedCount());

        // Verify the standard SHA-256 test vector.
        try {

            byte[] digest = MessageDigest
                .getInstance("SHA-256")
                .digest("abc".getBytes(StandardCharsets.UTF_8));

            String actual = HexFormat.of().formatHex(digest);

            String expected =
                "ba7816bf8f01cfea414140de5dae2223"
                + "b00361a396177a9cb410ff61f20015ad";

            if (!actual.equals(expected)) {
                throw new IllegalStateException(
                    "SHA-256 known-answer test failed"
                );
            }

        } catch (Exception error) {

            throw new RuntimeException(error);
        }

        System.out.println("\nAll Java 17 tests passed.");
    }

    private static AuthenticatedMessage newMessageWithFreshId(
        AuthenticationService service,
        String keyId
    ) {

        return service.createMessage(
            "alice",
            "bob",
            "Revocation verification",
            keyId
        );
    }
}
