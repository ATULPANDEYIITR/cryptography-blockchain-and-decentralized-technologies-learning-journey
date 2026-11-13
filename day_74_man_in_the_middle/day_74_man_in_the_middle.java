import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Man-in-the-Middle Attack on Key Exchange
 *
 * Enterprise-oriented Java 17 implementation.
 *
 * Demonstrates:
 * - X25519 key agreement.
 * - Ed25519 identity authentication.
 * - Public-key substitution detection.
 * - Certificate-like trust registration.
 * - Signed exchange transcripts.
 * - Reviewable security policies.
 * - Session lifecycle and state transitions.
 * - Concurrent session tracking.
 *
 * Uses only standard Java security APIs.
 */

public class Main {

    enum SessionState {
        CREATED,
        OFFERED,
        VERIFYING,
        AUTHENTICATED,
        ESTABLISHED,
        REJECTED,
        CLOSED
    }

    enum VerificationStatus {
        PASS,
        FAIL
    }

    static class ProtocolException extends Exception {
        ProtocolException(String message) {
            super(message);
        }
    }

    record ExchangeOffer(
        String sessionId,
        String sender,
        String recipient,
        byte[] ephemeralPublicKey,
        byte[] identitySignature,
        String algorithm
    ) {
        ExchangeOffer {
            Objects.requireNonNull(sessionId);
            Objects.requireNonNull(sender);
            Objects.requireNonNull(recipient);
            Objects.requireNonNull(ephemeralPublicKey);
            Objects.requireNonNull(identitySignature);
            Objects.requireNonNull(algorithm);

            ephemeralPublicKey = ephemeralPublicKey.clone();
            identitySignature = identitySignature.clone();
        }

        @Override
        public byte[] ephemeralPublicKey() {
            return ephemeralPublicKey.clone();
        }

        @Override
        public byte[] identitySignature() {
            return identitySignature.clone();
        }
    }

    record VerificationResult(
        VerificationStatus identity,
        VerificationStatus transcript,
        VerificationStatus sessionUniqueness,
        boolean eligible,
        List<String> violations
    ) {
        VerificationResult {
            violations = List.copyOf(violations);
        }
    }

    record SecurityPolicy(
        boolean requireIdentitySignature,
        boolean requireTranscriptBinding,
        boolean rejectDuplicateSessions,
        boolean requireApprovedAlgorithm
    ) {
        static SecurityPolicy enterpriseDefault() {
            return new SecurityPolicy(
                true,
                true,
                true,
                true
            );
        }
    }

    static final class Identity {
        private final String name;
        private final KeyPair signingPair;

        Identity(String name) throws GeneralSecurityException {
            if (name == null ||
                !name.matches("[A-Za-z0-9_-]{1,64}")) {
                throw new IllegalArgumentException(
                    "Invalid identity name."
                );
            }

            this.name = name;

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("Ed25519");

            this.signingPair = generator.generateKeyPair();
        }

        String name() {
            return name;
        }

        PublicKey publicKey() {
            return signingPair.getPublic();
        }

        byte[] sign(byte[] data) throws GeneralSecurityException {
            Signature signature =
                Signature.getInstance("Ed25519");

            signature.initSign(signingPair.getPrivate());
            signature.update(data);

            return signature.sign();
        }

        static boolean verify(
            PublicKey publicKey,
            byte[] data,
            byte[] signedData
        ) throws GeneralSecurityException {

            Signature signature =
                Signature.getInstance("Ed25519");

            signature.initVerify(publicKey);
            signature.update(data);

            return signature.verify(signedData);
        }
    }

    static final class TrustRegistry {
        private final Map<String, PublicKey> trusted =
            new ConcurrentHashMap<>();

        void register(Identity identity) {
            PublicKey previous = trusted.putIfAbsent(
                identity.name(),
                identity.publicKey()
            );

            if (previous != null) {
                throw new IllegalArgumentException(
                    "Identity already registered."
                );
            }
        }

        PublicKey resolve(String identity)
            throws ProtocolException {

            PublicKey key = trusted.get(identity);

            if (key == null) {
                throw new ProtocolException(
                    "Unknown identity: " + identity
                );
            }

            return key;
        }

        boolean contains(String identity) {
            return trusted.containsKey(identity);
        }
    }

    static final class SessionRegistry {
        private final Set<String> active =
            ConcurrentHashMap.newKeySet();

        boolean register(String sessionId) {
            return active.add(sessionId);
        }

        void release(String sessionId) {
            active.remove(sessionId);
        }

        boolean contains(String sessionId) {
            return active.contains(sessionId);
        }
    }

    static final class KeyExchangeService {
        private final Identity identity;
        private final TrustRegistry trust;
        private final SessionRegistry sessions;
        private final SecurityPolicy policy;

        private final KeyPair ephemeralPair;

        private SessionState state = SessionState.CREATED;
        private byte[] sessionKey;
        private String sessionId;

        KeyExchangeService(
            Identity identity,
            TrustRegistry trust,
            SessionRegistry sessions,
            SecurityPolicy policy
        ) throws GeneralSecurityException {

            this.identity = identity;
            this.trust = trust;
            this.sessions = sessions;
            this.policy = policy;

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("X25519");

            this.ephemeralPair = generator.generateKeyPair();
        }

        synchronized ExchangeOffer createOffer(
            String recipient,
            String requestedSessionId
        ) throws GeneralSecurityException, ProtocolException {

            if (state != SessionState.CREATED) {
                throw new ProtocolException(
                    "Session has already been initialized."
                );
            }

            validateSessionId(requestedSessionId);

            if (!sessions.register(requestedSessionId)) {
                throw new ProtocolException(
                    "Duplicate session identifier."
                );
            }

            try {
                this.sessionId = requestedSessionId;

                byte[] publicBytes =
                    ephemeralPair.getPublic().getEncoded();

                byte[] transcript = createTranscript(
                    requestedSessionId,
                    identity.name(),
                    recipient,
                    publicBytes
                );

                byte[] signature = identity.sign(transcript);

                state = SessionState.OFFERED;

                return new ExchangeOffer(
                    requestedSessionId,
                    identity.name(),
                    recipient,
                    publicBytes,
                    signature,
                    "X25519-ED25519"
                );

            } catch (GeneralSecurityException | RuntimeException e) {
                sessions.release(requestedSessionId);
                state = SessionState.REJECTED;
                throw e;
            }
        }

        synchronized byte[] acceptOffer(
            ExchangeOffer offer
        ) throws GeneralSecurityException, ProtocolException {

            if (state != SessionState.CREATED) {
                throw new ProtocolException(
                    "Session cannot accept another offer."
                );
            }

            state = SessionState.VERIFYING;

            try {
                validateOffer(offer);

                if (policy.requireApprovedAlgorithm() &&
                    !"X25519-ED25519".equals(offer.algorithm())) {
                    throw new ProtocolException(
                        "Unapproved cryptographic algorithm."
                    );
                }

                PublicKey trustedIdentity =
                    trust.resolve(offer.sender());

                byte[] transcript = createTranscript(
                    offer.sessionId(),
                    offer.sender(),
                    offer.recipient(),
                    offer.ephemeralPublicKey()
                );

                if (policy.requireIdentitySignature()) {
                    boolean valid = Identity.verify(
                        trustedIdentity,
                        transcript,
                        offer.identitySignature()
                    );

                    if (!valid) {
                        throw new ProtocolException(
                            "Identity signature verification failed."
                        );
                    }
                }

                if (policy.requireTranscriptBinding()) {
                    if (transcript.length == 0) {
                        throw new ProtocolException(
                            "Empty transcript."
                        );
                    }
                }

                KeyFactory factory =
                    KeyFactory.getInstance("X25519");

                PublicKey peerEphemeral =
                    factory.generatePublic(
                        new java.security.spec.X509EncodedKeySpec(
                            offer.ephemeralPublicKey()
                        )
                    );

                KeyAgreement agreement =
                    KeyAgreement.getInstance("X25519");

                agreement.init(ephemeralPair.getPrivate());
                agreement.doPhase(peerEphemeral, true);

                byte[] rawSecret = agreement.generateSecret();

                // HKDF-style extraction and expansion using HMAC-SHA256.
                byte[] salt = MessageDigest.getInstance("SHA-256")
                    .digest(transcript);

                byte[] pseudorandomKey = hmac(salt, rawSecret);

                byte[] derived = hmac(
                    pseudorandomKey,
                    "KEY-EXCHANGE-SESSION-V1".getBytes(
                        StandardCharsets.UTF_8
                    )
                );

                sessionKey = Arrays.copyOf(derived, 32);

                Arrays.fill(rawSecret, (byte) 0);

                state = SessionState.ESTABLISHED;

                return sessionKey.clone();

            } catch (
                GeneralSecurityException |
                ProtocolException |
                RuntimeException error
            ) {
                state = SessionState.REJECTED;
                clearKey();
                throw error;
            }
        }

        private void validateOffer(ExchangeOffer offer)
            throws ProtocolException {

            if (offer == null) {
                throw new ProtocolException("Missing exchange offer.");
            }

            validateSessionId(offer.sessionId());

            if (!identity.name().equals(offer.recipient())) {
                throw new ProtocolException(
                    "Offer is addressed to another identity."
                );
            }

            if (offer.ephemeralPublicKey().length > 1024 ||
                offer.identitySignature().length > 256) {
                throw new ProtocolException(
                    "Exchange message exceeds permitted limits."
                );
            }
        }

        private static void validateSessionId(String id)
            throws ProtocolException {

            if (id == null ||
                !id.matches("[A-Za-z0-9_-]{8,64}")) {
                throw new ProtocolException(
                    "Invalid session identifier."
                );
            }
        }

        synchronized void close() {
            clearKey();

            if (sessionId != null) {
                sessions.release(sessionId);
            }

            state = SessionState.CLOSED;
        }

        private void clearKey() {
            if (sessionKey != null) {
                Arrays.fill(sessionKey, (byte) 0);
                sessionKey = null;
            }
        }

        synchronized SessionState state() {
            return state;
        }

        synchronized byte[] sessionKey() {
            if (state != SessionState.ESTABLISHED ||
                sessionKey == null) {
                throw new IllegalStateException(
                    "No established session key."
                );
            }

            return sessionKey.clone();
        }

        private static byte[] createTranscript(
            String sessionId,
            String sender,
            String recipient,
            byte[] publicKey
        ) {
            byte[] header = (
                "KEY-EXCHANGE-V1|" +
                sessionId + "|" +
                sender + "|" +
                recipient + "|"
            ).getBytes(StandardCharsets.UTF_8);

            byte[] transcript =
                Arrays.copyOf(header, header.length + publicKey.length);

            System.arraycopy(
                publicKey,
                0,
                transcript,
                header.length,
                publicKey.length
            );

            return transcript;
        }
    }

    static byte[] hmac(byte[] key, byte[] data)
        throws GeneralSecurityException {

        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(new SecretKeySpec(key, "HmacSHA256"));

        return mac.doFinal(data);
    }

    static final class GovernanceService {
        private final SecurityPolicy policy;
        private final TrustRegistry trust;
        private final SessionRegistry sessions;

        GovernanceService(
            SecurityPolicy policy,
            TrustRegistry trust,
            SessionRegistry sessions
        ) {
            this.policy = policy;
            this.trust = trust;
            this.sessions = sessions;
        }

        VerificationResult evaluate(
            ExchangeOffer offer
        ) {
            List<String> violations = new ArrayList<>();

            VerificationStatus identityStatus =
                VerificationStatus.PASS;

            VerificationStatus transcriptStatus =
                VerificationStatus.PASS;

            VerificationStatus uniquenessStatus =
                VerificationStatus.PASS;

            if (policy.requireIdentitySignature() &&
                !trust.contains(offer.sender())) {

                identityStatus = VerificationStatus.FAIL;
                violations.add("Untrusted peer identity.");
            }

            if (policy.requireApprovedAlgorithm() &&
                !"X25519-ED25519".equals(offer.algorithm())) {

                transcriptStatus = VerificationStatus.FAIL;
                violations.add("Unapproved algorithm.");
            }

            if (policy.requireTranscriptBinding() &&
                offer.ephemeralPublicKey().length == 0) {

                transcriptStatus = VerificationStatus.FAIL;
                violations.add("Invalid exchange transcript.");
            }

            if (policy.rejectDuplicateSessions() &&
                !sessions.register(offer.sessionId())) {

                uniquenessStatus = VerificationStatus.FAIL;
                violations.add("Duplicate session.");
            }

            boolean eligible =
                identityStatus == VerificationStatus.PASS &&
                transcriptStatus == VerificationStatus.PASS &&
                uniquenessStatus == VerificationStatus.PASS;

            return new VerificationResult(
                identityStatus,
                transcriptStatus,
                uniquenessStatus,
                eligible,
                violations
            );
        }
    }

    static ExchangeOffer replacePublicKey(
        ExchangeOffer original
    ) throws GeneralSecurityException {

        KeyPairGenerator generator =
            KeyPairGenerator.getInstance("X25519");

        KeyPair attacker = generator.generateKeyPair();

        return new ExchangeOffer(
            original.sessionId(),
            original.sender(),
            original.recipient(),
            attacker.getPublic().getEncoded(),
            original.identitySignature(),
            original.algorithm()
        );
    }

    static void demonstrateLegitimateExchange()
        throws Exception {

        System.out.println("\n1. Legitimate authenticated exchange");

        Identity aliceIdentity = new Identity("Alice");
        Identity bobIdentity = new Identity("Bob");

        TrustRegistry trust = new TrustRegistry();
        trust.register(aliceIdentity);
        trust.register(bobIdentity);

        SessionRegistry sessions = new SessionRegistry();

        SecurityPolicy policy =
            SecurityPolicy.enterpriseDefault();

        KeyExchangeService alice = new KeyExchangeService(
            aliceIdentity, trust, sessions, policy
        );

        KeyExchangeService bob = new KeyExchangeService(
            bobIdentity, trust, sessions, policy
        );

        ExchangeOffer offer = alice.createOffer(
            "Bob", "SESSION100"
        );

        byte[] bobKey = bob.acceptOffer(offer);

        System.out.println("Alice state: " + alice.state());
        System.out.println("Bob state: " + bob.state());
        System.out.println(
            "Bob established key length: " + bobKey.length
        );

        alice.close();
        bob.close();
    }

    static void demonstrateAttack() throws Exception {
        System.out.println("\n2. Man-in-the-middle substitution");

        Identity aliceIdentity = new Identity("Alice");
        Identity bobIdentity = new Identity("Bob");

        TrustRegistry trust = new TrustRegistry();
        trust.register(aliceIdentity);
        trust.register(bobIdentity);

        SessionRegistry sessions = new SessionRegistry();

        KeyExchangeService alice = new KeyExchangeService(
            aliceIdentity,
            trust,
            sessions,
            SecurityPolicy.enterpriseDefault()
        );

        KeyExchangeService bob = new KeyExchangeService(
            bobIdentity,
            trust,
            sessions,
            SecurityPolicy.enterpriseDefault()
        );

        ExchangeOffer offer = alice.createOffer(
            "Bob", "SESSION200"
        );

        ExchangeOffer modified = replacePublicKey(offer);

        try {
            bob.acceptOffer(modified);
            throw new IllegalStateException(
                "Attack was not detected."
            );
        } catch (ProtocolException error) {
            System.out.println("Attack detected: " + error.getMessage());
            System.out.println("Bob state: " + bob.state());
        }

        alice.close();
    }

    static void demonstrateUnknownIdentity() throws Exception {
        System.out.println("\n3. Unknown identity");

        Identity aliceIdentity = new Identity("Alice");
        Identity bobIdentity = new Identity("Bob");

        TrustRegistry trust = new TrustRegistry();
        trust.register(bobIdentity);

        SessionRegistry sessions = new SessionRegistry();

        KeyExchangeService bob = new KeyExchangeService(
            bobIdentity,
            trust,
            sessions,
            SecurityPolicy.enterpriseDefault()
        );

        // Alice is not registered in Bob's trust registry.
        ExchangeOffer offer = new KeyExchangeService(
            aliceIdentity,
            trust,
            sessions,
            SecurityPolicy.enterpriseDefault()
        ).createOffer("Bob", "SESSION300");

        try {
            bob.acceptOffer(offer);
        } catch (ProtocolException error) {
            System.out.println("Rejected: " + error.getMessage());
            System.out.println("State: " + bob.state());
        }
    }

    public static void main(String[] args) {
        System.out.println(
            "================================================="
        );

        System.out.println(
            "ENTERPRISE KEY EXCHANGE SECURITY MODEL"
        );

        System.out.println(
            "================================================="
        );

        try {
            demonstrateLegitimateExchange();
            demonstrateAttack();
            demonstrateUnknownIdentity();

            System.out.println("\nAll scenarios completed.");

        } catch (Exception error) {
            System.err.println(
                "Execution failed: " + error.getMessage()
            );

            System.exit(1);
        }
    }
}
