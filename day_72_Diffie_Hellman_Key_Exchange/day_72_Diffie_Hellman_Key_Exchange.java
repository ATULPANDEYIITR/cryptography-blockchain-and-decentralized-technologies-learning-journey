import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Diffie-Hellman Key Exchange
 *
 * Java 17 enterprise-oriented implementation.
 *
 * Includes:
 * - Immutable domain records
 * - Safe-prime subgroup validation
 * - BigInteger modular exponentiation
 * - SecureRandom private-key generation
 * - Participant identity modeling
 * - Reviewable exchange state transitions
 * - Key agreement verification
 * - HKDF-SHA256
 * - Transcript binding
 * - Session auditing
 * - Custom exceptions and tests
 *
 * Parameters are deliberately small for education.
 * This program is not production cryptography.
 */

public class DiffieHellman {

    enum ExchangeState {
        CREATED,
        PUBLIC_KEYS_EXCHANGED,
        VERIFIED,
        DERIVED,
        FAILED
    }

    static class DHException extends RuntimeException {
        DHException(String message) {
            super(message);
        }
    }

    static class ParameterException extends DHException {
        ParameterException(String message) {
            super(message);
        }
    }

    static class ExchangeException extends DHException {
        ExchangeException(String message) {
            super(message);
        }
    }

    record DHGroup(BigInteger p, BigInteger q, BigInteger g) {

        DHGroup {
            Objects.requireNonNull(p);
            Objects.requireNonNull(q);
            Objects.requireNonNull(g);
        }

        void validate() {
            if (
                p.compareTo(BigInteger.valueOf(5)) <= 0 ||
                !p.isProbablePrime(100) ||
                !q.isProbablePrime(100)
            ) {
                throw new ParameterException(
                    "Invalid prime parameters."
                );
            }

            if (!p.equals(q.multiply(BigInteger.TWO).add(BigInteger.ONE))) {
                throw new ParameterException(
                    "Expected safe-prime group."
                );
            }

            if (
                g.compareTo(BigInteger.ONE) <= 0 ||
                g.compareTo(p) >= 0 ||
                !g.modPow(q, p).equals(BigInteger.ONE)
            ) {
                throw new ParameterException(
                    "Invalid subgroup generator."
                );
            }
        }
    }

    record PublicKey(String participant, BigInteger value) {

        PublicKey {
            if (participant == null || participant.isBlank()) {
                throw new IllegalArgumentException(
                    "Participant identity is required."
                );
            }

            Objects.requireNonNull(value);
        }
    }

    record SessionPolicy(
        int requiredParticipants,
        boolean requireSubgroupValidation,
        boolean requireKeyAgreementVerification,
        int derivedKeyLength
    ) {

        SessionPolicy {
            if (requiredParticipants != 2) {
                throw new IllegalArgumentException(
                    "This exchange requires exactly two participants."
                );
            }

            if (!requireSubgroupValidation ||
                !requireKeyAgreementVerification) {
                throw new IllegalArgumentException(
                    "Mandatory security controls cannot be disabled."
                );
            }

            if (derivedKeyLength < 1 || derivedKeyLength > 8160) {
                throw new IllegalArgumentException(
                    "Invalid derived-key length."
                );
            }
        }
    }

    record ExchangeResult(
        String sessionId,
        PublicKey alicePublic,
        PublicKey bobPublic,
        BigInteger sharedSecret,
        byte[] sessionKey,
        String transcriptHash,
        ExchangeState state
    ) {

        ExchangeResult {
            sessionKey = sessionKey.clone();
        }

        @Override
        public byte[] sessionKey() {
            return sessionKey.clone();
        }
    }

    static final class KeyValidator {

        private final DHGroup group;

        KeyValidator(DHGroup group) {
            this.group = group;
        }

        void validatePublicKey(BigInteger value) {
            if (
                value.compareTo(BigInteger.ONE) <= 0 ||
                value.compareTo(group.p().subtract(BigInteger.ONE)) >= 0
            ) {
                throw new ExchangeException(
                    "Public key outside valid range."
                );
            }

            if (!value.modPow(group.q(), group.p())
                .equals(BigInteger.ONE)) {

                throw new ExchangeException(
                    "Public key outside subgroup."
                );
            }
        }
    }

    static final class Participant {

        private final String identity;
        private final BigInteger privateKey;
        private final PublicKey publicKey;

        Participant(
            String identity,
            DHGroup group,
            SecureRandom random
        ) {
            if (identity == null || identity.isBlank()) {
                throw new IllegalArgumentException(
                    "Identity cannot be empty."
                );
            }

            this.identity = identity;

            // Random range: 1 through q - 1.
            this.privateKey = randomInteger(
                group.q().subtract(BigInteger.ONE),
                random
            ).add(BigInteger.ONE);

            this.publicKey = new PublicKey(
                identity,
                group.g().modPow(privateKey, group.p())
            );
        }

        String identity() {
            return identity;
        }

        PublicKey publicKey() {
            return publicKey;
        }

        BigInteger computeSharedSecret(
            PublicKey peer,
            DHGroup group
        ) {
            Objects.requireNonNull(peer);

            new KeyValidator(group)
                .validatePublicKey(peer.value());

            BigInteger secret = peer.value()
                .modPow(privateKey, group.p());

            if (secret.equals(BigInteger.ONE)) {
                throw new ExchangeException(
                    "Trivial shared secret rejected."
                );
            }

            return secret;
        }
    }

    static final class ExchangeAudit {

        private final List<String> events = new ArrayList<>();

        void record(ExchangeState state) {
            events.add(state.name());
        }

        List<String> events() {
            return Collections.unmodifiableList(events);
        }
    }

    static final class ExchangeService {

        private final DHGroup group;
        private final SessionPolicy policy;
        private final SecureRandom random;

        private final Map<String, ExchangeResult> sessions =
            new HashMap<>();

        private final Map<String, ExchangeAudit> audits =
            new HashMap<>();

        ExchangeService(
            DHGroup group,
            SessionPolicy policy
        ) {
            this.group = group;
            this.policy = policy;
            this.random = new SecureRandom();

            group.validate();
        }

        synchronized ExchangeResult execute(String sessionId) {
            if (sessionId == null || sessionId.isBlank()) {
                throw new IllegalArgumentException(
                    "Session identifier is required."
                );
            }

            if (sessions.containsKey(sessionId)) {
                throw new ExchangeException(
                    "Duplicate session identifier."
                );
            }

            ExchangeAudit audit = new ExchangeAudit();
            audits.put(sessionId, audit);

            ExchangeState state = ExchangeState.CREATED;
            audit.record(state);

            try {
                Participant alice = new Participant(
                    "Alice",
                    group,
                    random
                );

                Participant bob = new Participant(
                    "Bob",
                    group,
                    random
                );

                PublicKey alicePublic = alice.publicKey();
                PublicKey bobPublic = bob.publicKey();

                state = ExchangeState.PUBLIC_KEYS_EXCHANGED;
                audit.record(state);

                KeyValidator validator = new KeyValidator(group);

                validator.validatePublicKey(alicePublic.value());
                validator.validatePublicKey(bobPublic.value());

                BigInteger aliceSecret =
                    alice.computeSharedSecret(bobPublic, group);

                BigInteger bobSecret =
                    bob.computeSharedSecret(alicePublic, group);

                if (!aliceSecret.equals(bobSecret)) {
                    throw new ExchangeException(
                        "Shared-secret verification failed."
                    );
                }

                state = ExchangeState.VERIFIED;
                audit.record(state);

                String transcript = String.join(
                    "|",
                    "DH-v1",
                    group.p().toString(),
                    group.q().toString(),
                    group.g().toString(),
                    alice.identity(),
                    bob.identity(),
                    alicePublic.value().toString(),
                    bobPublic.value().toString()
                );

                byte[] transcriptBytes = transcript.getBytes(
                    StandardCharsets.UTF_8
                );

                byte[] transcriptHash = sha256(transcriptBytes);

                byte[] secretBytes = encodeInteger(
                    aliceSecret,
                    (group.p().bitLength() + 7) / 8
                );

                byte[] derivedKey = hkdf(
                    secretBytes,
                    transcriptHash,
                    "educational-dh-session-key".getBytes(
                        StandardCharsets.UTF_8
                    ),
                    policy.derivedKeyLength()
                );

                state = ExchangeState.DERIVED;
                audit.record(state);

                ExchangeResult result = new ExchangeResult(
                    sessionId,
                    alicePublic,
                    bobPublic,
                    aliceSecret,
                    derivedKey,
                    toHex(transcriptHash),
                    state
                );

                sessions.put(sessionId, result);

                return result;

            } catch (RuntimeException exception) {
                state = ExchangeState.FAILED;
                audit.record(state);
                throw exception;
            }
        }

        Optional<ExchangeResult> findSession(String id) {
            return Optional.ofNullable(sessions.get(id));
        }

        List<String> getAudit(String sessionId) {
            ExchangeAudit audit = audits.get(sessionId);

            return audit == null
                ? List.of()
                : audit.events();
        }
    }

    static BigInteger randomInteger(
        BigInteger upperExclusive,
        SecureRandom random
    ) {
        BigInteger value;

        do {
            value = new BigInteger(
                upperExclusive.bitLength(),
                random
            );
        } while (value.compareTo(upperExclusive) >= 0);

        return value;
    }

    static byte[] encodeInteger(BigInteger value, int width) {
        byte[] original = value.toByteArray();

        int offset = original.length > 1 && original[0] == 0
            ? 1
            : 0;

        int length = original.length - offset;

        if (length > width) {
            throw new ExchangeException(
                "Integer encoding exceeds group width."
            );
        }

        byte[] output = new byte[width];

        System.arraycopy(
            original,
            offset,
            output,
            width - length,
            length
        );

        return output;
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256")
                .digest(input);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    static byte[] hmac(byte[] key, byte[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            mac.init(new SecretKeySpec(key, "HmacSHA256"));

            return mac.doFinal(input);

        } catch (Exception exception) {
            throw new IllegalStateException(
                "HMAC operation failed.",
                exception
            );
        }
    }

    static byte[] hkdf(
        byte[] inputKeyMaterial,
        byte[] salt,
        byte[] info,
        int length
    ) {
        if (length < 1 || length > 255 * 32) {
            throw new IllegalArgumentException(
                "Invalid HKDF output length."
            );
        }

        byte[] actualSalt = salt.length == 0
            ? new byte[32]
            : salt;

        byte[] prk = hmac(actualSalt, inputKeyMaterial);

        byte[] output = new byte[length];
        byte[] previous = new byte[0];

        int offset = 0;

        for (int counter = 1; offset < length; counter++) {
            byte[] input = new byte[
                previous.length + info.length + 1
            ];

            System.arraycopy(
                previous, 0, input, 0, previous.length
            );

            System.arraycopy(
                info, 0, input, previous.length, info.length
            );

            input[input.length - 1] = (byte) counter;

            previous = hmac(prk, input);

            int copyLength = Math.min(
                previous.length,
                length - offset
            );

            System.arraycopy(
                previous,
                0,
                output,
                offset,
                copyLength
            );

            offset += copyLength;
        }

        return output;
    }

    static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }

        return result.toString();
    }

    static void runTests() {
        DHGroup group = new DHGroup(
            BigInteger.valueOf(23),
            BigInteger.valueOf(11),
            BigInteger.valueOf(2)
        );

        group.validate();

        SecureRandom random = new SecureRandom();

        Participant alice = new Participant("Alice", group, random);
        Participant bob = new Participant("Bob", group, random);

        BigInteger first = alice.computeSharedSecret(
            bob.publicKey(),
            group
        );

        BigInteger second = bob.computeSharedSecret(
            alice.publicKey(),
            group
        );

        if (!first.equals(second)) {
            throw new AssertionError("Key agreement failed.");
        }

        KeyValidator validator = new KeyValidator(group);

        try {
            validator.validatePublicKey(BigInteger.ONE);
            throw new AssertionError("Invalid key accepted.");
        } catch (ExchangeException expected) {
            // Expected rejection.
        }

        try {
            validator.validatePublicKey(BigInteger.valueOf(5));
            throw new AssertionError("Invalid subgroup accepted.");
        } catch (ExchangeException expected) {
            // Expected rejection.
        }

        SessionPolicy policy = new SessionPolicy(
            2, true, true, 32
        );

        ExchangeService service = new ExchangeService(
            group,
            policy
        );

        ExchangeResult result = service.execute("SESSION-001");

        if (result.state() != ExchangeState.DERIVED) {
            throw new AssertionError("Invalid final state.");
        }

        if (result.sessionKey().length != 32) {
            throw new AssertionError("Invalid key length.");
        }

        if (service.findSession("SESSION-001").isEmpty()) {
            throw new AssertionError("Session not stored.");
        }

        try {
            service.execute("SESSION-001");
            throw new AssertionError("Duplicate session accepted.");
        } catch (ExchangeException expected) {
            // Expected rejection.
        }

        byte[] derived = hkdf(
            "secret".getBytes(StandardCharsets.UTF_8),
            "salt".getBytes(StandardCharsets.UTF_8),
            "context".getBytes(StandardCharsets.UTF_8),
            32
        );

        if (derived.length != 32) {
            throw new AssertionError("HKDF failed.");
        }

        System.out.println("All tests passed.");
    }

    public static void main(String[] args) {

        DHGroup group = new DHGroup(
            BigInteger.valueOf(23),
            BigInteger.valueOf(11),
            BigInteger.valueOf(2)
        );

        SessionPolicy policy = new SessionPolicy(
            2,
            true,
            true,
            32
        );

        try {
            ExchangeService service = new ExchangeService(
                group,
                policy
            );

            ExchangeResult result = service.execute("SESSION-001");

            System.out.println("DIFFIE-HELLMAN KEY EXCHANGE");
            System.out.println("===========================");

            System.out.println("Modulus p: " + group.p());
            System.out.println("Subgroup q: " + group.q());
            System.out.println("Generator g: " + group.g());

            System.out.println(
                "Alice public key: " + result.alicePublic().value()
            );

            System.out.println(
                "Bob public key: " + result.bobPublic().value()
            );

            System.out.println(
                "Shared secret: " + result.sharedSecret()
            );

            System.out.println(
                "Derived key: " + toHex(result.sessionKey())
            );

            System.out.println(
                "Transcript hash: " + result.transcriptHash()
            );

            System.out.println("State: " + result.state());

            System.out.println("\nAudit trail:");

            for (String event : service.getAudit("SESSION-001")) {
                System.out.println("  " + event);
            }

            System.out.println("\nSecurity: EDUCATIONAL ONLY");

            runTests();

        } catch (RuntimeException exception) {
            System.err.println(
                "Exchange failed: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
