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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DIGITAL SIGNATURES FOR AUTHENTICATION
 *
 * Java 17
 *
 * Uses standard Java cryptography APIs and Ed25519.
 *
 * Demonstrates:
 * - Enterprise identity registration
 * - Immutable domain records
 * - Cryptographic key management
 * - Challenge-response authentication
 * - Signature verification
 * - Authentication policies
 * - Reviewer and administrator separation
 * - Key revocation
 * - Replay prevention
 * - Concurrent authentication controls
 * - Structured audit records
 */

public class DigitalSignatureAuthentication {

    enum KeyStatus {
        ACTIVE,
        REVOKED
    }

    enum ChallengeStatus {
        ISSUED,
        CONSUMED,
        EXPIRED
    }

    enum AuthenticationStatus {
        AUTHENTICATED,
        REJECTED
    }

    record RegisteredIdentity(
        String userId,
        String keyId,
        PublicKey publicKey,
        String fingerprint,
        KeyStatus status,
        Instant registeredAt
    ) {
        RegisteredIdentity {
            Objects.requireNonNull(userId);
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(fingerprint);
            Objects.requireNonNull(status);
            Objects.requireNonNull(registeredAt);
        }

        RegisteredIdentity revoke() {
            return new RegisteredIdentity(
                userId,
                keyId,
                publicKey,
                fingerprint,
                KeyStatus.REVOKED,
                registeredAt
            );
        }
    }

    record Challenge(
        String challengeId,
        String userId,
        String keyId,
        String nonce,
        String audience,
        Instant issuedAt,
        Instant expiresAt,
        ChallengeStatus status
    ) {
        Challenge {
            Objects.requireNonNull(challengeId);
            Objects.requireNonNull(userId);
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(nonce);
            Objects.requireNonNull(audience);
            Objects.requireNonNull(issuedAt);
            Objects.requireNonNull(expiresAt);
            Objects.requireNonNull(status);
        }

        Challenge consume() {
            return new Challenge(
                challengeId,
                userId,
                keyId,
                nonce,
                audience,
                issuedAt,
                expiresAt,
                ChallengeStatus.CONSUMED
            );
        }

        Challenge expire() {
            return new Challenge(
                challengeId,
                userId,
                keyId,
                nonce,
                audience,
                issuedAt,
                expiresAt,
                ChallengeStatus.EXPIRED
            );
        }
    }

    record AuthenticationRequest(
        String userId,
        String keyId,
        String challengeId,
        byte[] signature
    ) {
        AuthenticationRequest {
            Objects.requireNonNull(userId);
            Objects.requireNonNull(keyId);
            Objects.requireNonNull(challengeId);

            if (signature == null) {
                throw new IllegalArgumentException(
                    "Signature cannot be null"
                );
            }

            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    record AuthenticationResult(
        AuthenticationStatus status,
        String userId,
        String keyId,
        String reason,
        Instant timestamp
    ) {}

    record AuditEvent(
        Instant timestamp,
        String userId,
        String action,
        boolean successful,
        String details
    ) {}

    static class AuthenticationException extends Exception {
        AuthenticationException(String message) {
            super(message);
        }
    }

    interface SignatureVerifier {
        boolean verify(
            PublicKey publicKey,
            byte[] message,
            byte[] signature
        ) throws GeneralSecurityException;
    }

    static class Ed25519Verifier implements SignatureVerifier {

        @Override
        public boolean verify(
            PublicKey publicKey,
            byte[] message,
            byte[] signature
        ) throws GeneralSecurityException {

            Signature verifier = Signature.getInstance("Ed25519");

            verifier.initVerify(publicKey);
            verifier.update(message);

            return verifier.verify(signature);
        }
    }

    interface AuthenticationPolicy {
        void validate(
            RegisteredIdentity identity,
            Challenge challenge,
            Instant now
        ) throws AuthenticationException;
    }

    static class DefaultAuthenticationPolicy
        implements AuthenticationPolicy {

        private final long maximumChallengeAgeSeconds;

        DefaultAuthenticationPolicy(long maximumChallengeAgeSeconds) {
            if (maximumChallengeAgeSeconds <= 0) {
                throw new IllegalArgumentException(
                    "Challenge age must be positive"
                );
            }

            this.maximumChallengeAgeSeconds =
                maximumChallengeAgeSeconds;
        }

        @Override
        public void validate(
            RegisteredIdentity identity,
            Challenge challenge,
            Instant now
        ) throws AuthenticationException {

            if (identity.status() != KeyStatus.ACTIVE) {
                throw new AuthenticationException("Key revoked");
            }

            if (challenge.status() != ChallengeStatus.ISSUED) {
                throw new AuthenticationException(
                    "Challenge is not available"
                );
            }

            if (!now.isBefore(challenge.expiresAt())) {
                throw new AuthenticationException(
                    "Challenge expired"
                );
            }

            long age = now.getEpochSecond()
                - challenge.issuedAt().getEpochSecond();

            if (age < 0 || age > maximumChallengeAgeSeconds) {
                throw new AuthenticationException(
                    "Challenge age violates policy"
                );
            }
        }
    }

    static class IdentityService {

        private final Map<String, RegisteredIdentity> identities =
            new ConcurrentHashMap<>();

        private final Map<String, Challenge> challenges =
            new ConcurrentHashMap<>();

        private final Map<String, PrivateKey> privateKeys =
            new HashMap<>();

        private final Set<String> consumedChallenges =
            ConcurrentHashMap.newKeySet();

        private final List<AuditEvent> audit =
            new ArrayList<>();

        private final SecureRandom secureRandom = new SecureRandom();

        private final SignatureVerifier verifier;
        private final AuthenticationPolicy policy;

        private final String audience;
        private final int challengeLifetimeSeconds;
        private final int maximumPendingChallenges;

        IdentityService(
            SignatureVerifier verifier,
            AuthenticationPolicy policy,
            String audience,
            int challengeLifetimeSeconds,
            int maximumPendingChallenges
        ) {
            this.verifier = Objects.requireNonNull(verifier);
            this.policy = Objects.requireNonNull(policy);

            if (
                audience == null ||
                audience.isBlank() ||
                challengeLifetimeSeconds <= 0 ||
                maximumPendingChallenges <= 0
            ) {
                throw new IllegalArgumentException(
                    "Invalid service configuration"
                );
            }

            this.audience = audience;
            this.challengeLifetimeSeconds =
                challengeLifetimeSeconds;
            this.maximumPendingChallenges =
                maximumPendingChallenges;
        }

        private synchronized void record(
            String userId,
            String action,
            boolean success,
            String details
        ) {
            audit.add(new AuditEvent(
                Instant.now(),
                userId,
                action,
                success,
                details
            ));
        }

        private static String fingerprint(
            PublicKey publicKey
        ) throws GeneralSecurityException {

            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());

            return HexFormatSupport.toHex(digest);
        }

        synchronized String register(String userId)
            throws GeneralSecurityException,
                   AuthenticationException {

            if (
                userId == null ||
                userId.isBlank() ||
                userId.length() > 128
            ) {
                throw new IllegalArgumentException(
                    "Invalid user identifier"
                );
            }

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("Ed25519");

            KeyPair pair = generator.generateKeyPair();

            String keyId = UUID.randomUUID().toString();
            String fingerprint = fingerprint(pair.getPublic());

            for (RegisteredIdentity existing : identities.values()) {
                if (existing.fingerprint().equals(fingerprint)) {
                    throw new AuthenticationException(
                        "Duplicate public key"
                    );
                }
            }

            RegisteredIdentity identity = new RegisteredIdentity(
                userId,
                keyId,
                pair.getPublic(),
                fingerprint,
                KeyStatus.ACTIVE,
                Instant.now()
            );

            identities.put(keyId, identity);

            /*
             * In a production identity provider, private keys should
             * remain inside an HSM, secure enclave, or client device.
             * This in-memory example stores the private key only to
             * demonstrate the complete local signing workflow.
             */
            privateKeys.put(keyId, pair.getPrivate());

            record(
                userId,
                "KEY_REGISTERED",
                true,
                fingerprint
            );

            return keyId;
        }

        synchronized void revoke(String keyId)
            throws AuthenticationException {

            RegisteredIdentity identity = identities.get(keyId);

            if (identity == null) {
                throw new AuthenticationException("Unknown key");
            }

            identities.put(keyId, identity.revoke());

            record(
                identity.userId(),
                "KEY_REVOKED",
                true,
                keyId
            );
        }

        synchronized Challenge issueChallenge(
            String userId,
            String keyId
        ) throws AuthenticationException {

            RegisteredIdentity identity = identities.get(keyId);

            if (
                identity == null ||
                !identity.userId().equals(userId)
            ) {
                throw new AuthenticationException(
                    "Unknown identity"
                );
            }

            if (identity.status() != KeyStatus.ACTIVE) {
                throw new AuthenticationException("Key revoked");
            }

            Instant now = Instant.now();

            long pending = challenges.values().stream()
                .filter(c -> c.userId().equals(userId))
                .filter(c -> c.status() == ChallengeStatus.ISSUED)
                .filter(c -> now.isBefore(c.expiresAt()))
                .count();

            if (pending >= maximumPendingChallenges) {
                throw new AuthenticationException(
                    "Pending challenge limit exceeded"
                );
            }

            byte[] nonceBytes = new byte[32];
            secureRandom.nextBytes(nonceBytes);

            Challenge challenge = new Challenge(
                UUID.randomUUID().toString(),
                userId,
                keyId,
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(nonceBytes),
                audience,
                now,
                now.plusSeconds(challengeLifetimeSeconds),
                ChallengeStatus.ISSUED
            );

            challenges.put(challenge.challengeId(), challenge);

            record(
                userId,
                "CHALLENGE_ISSUED",
                true,
                challenge.challengeId()
            );

            return challenge;
        }

        private static byte[] canonicalMessage(
            Challenge challenge
        ) {
            /*
             * Length-prefixed UTF-8 encoding avoids ambiguous
             * concatenation of user-controlled values.
             */
            String[] fields = {
                "digital-authentication-v1",
                challenge.challengeId(),
                challenge.userId(),
                challenge.keyId(),
                challenge.nonce(),
                challenge.audience()
            };

            java.io.ByteArrayOutputStream output =
                new java.io.ByteArrayOutputStream();

            for (String field : fields) {
                byte[] bytes = field.getBytes(
                    StandardCharsets.UTF_8
                );

                int length = bytes.length;

                output.write((length >>> 24) & 0xff);
                output.write((length >>> 16) & 0xff);
                output.write((length >>> 8) & 0xff);
                output.write(length & 0xff);

                output.writeBytes(bytes);
            }

            return output.toByteArray();
        }

        byte[] signForDemonstration(
            String keyId,
            Challenge challenge
        ) throws GeneralSecurityException,
                 AuthenticationException {

            PrivateKey privateKey = privateKeys.get(keyId);

            if (privateKey == null) {
                throw new AuthenticationException(
                    "Private key unavailable"
                );
            }

            Signature signer = Signature.getInstance("Ed25519");

            signer.initSign(privateKey);
            signer.update(canonicalMessage(challenge));

            return signer.sign();
        }

        synchronized AuthenticationResult authenticate(
            AuthenticationRequest request
        ) throws AuthenticationException {

            try {
                RegisteredIdentity identity =
                    identities.get(request.keyId());

                Challenge challenge =
                    challenges.get(request.challengeId());

                if (identity == null || challenge == null) {
                    throw new AuthenticationException(
                        "Unknown key or challenge"
                    );
                }

                if (
                    !identity.userId().equals(request.userId()) ||
                    !challenge.userId().equals(request.userId()) ||
                    !challenge.keyId().equals(request.keyId())
                ) {
                    throw new AuthenticationException(
                        "Identity binding mismatch"
                    );
                }

                if (
                    consumedChallenges.contains(
                        request.challengeId()
                    )
                ) {
                    throw new AuthenticationException(
                        "Replay detected"
                    );
                }

                Instant now = Instant.now();

                policy.validate(identity, challenge, now);

                byte[] signature = request.signature();

                if (signature.length != 64) {
                    throw new AuthenticationException(
                        "Invalid Ed25519 signature length"
                    );
                }

                boolean valid;

                try {
                    valid = verifier.verify(
                        identity.publicKey(),
                        canonicalMessage(challenge),
                        signature
                    );
                } catch (GeneralSecurityException ex) {
                    throw new AuthenticationException(
                        "Cryptographic verification error"
                    );
                }

                if (!valid) {
                    throw new AuthenticationException(
                        "Invalid digital signature"
                    );
                }

                /*
                 * Synchronization ensures that the challenge cannot
                 * be consumed twice within this service instance.
                 */
                challenges.put(
                    challenge.challengeId(),
                    challenge.consume()
                );

                consumedChallenges.add(
                    challenge.challengeId()
                );

                record(
                    request.userId(),
                    "AUTHENTICATED",
                    true,
                    request.keyId()
                );

                return new AuthenticationResult(
                    AuthenticationStatus.AUTHENTICATED,
                    request.userId(),
                    request.keyId(),
                    "Ed25519 verification successful",
                    Instant.now()
                );

            } catch (AuthenticationException ex) {
                record(
                    request.userId(),
                    "AUTHENTICATION_REJECTED",
                    false,
                    ex.getMessage()
                );

                throw ex;
            }
        }

        synchronized void printReport() {
            long success = audit.stream()
                .filter(AuditEvent::successful)
                .filter(e -> e.action().equals("AUTHENTICATED"))
                .count();

            long failure = audit.stream()
                .filter(e -> e.action().equals(
                    "AUTHENTICATION_REJECTED"
                ))
                .count();

            System.out.println("Registered keys: " + identities.size());
            System.out.println("Challenges: " + challenges.size());
            System.out.println("Successful authentications: " + success);
            System.out.println("Failed authentications: " + failure);

            System.out.println("\nAudit trail:");

            audit.forEach(System.out::println);
        }
    }

    static class HexFormatSupport {
        static String toHex(byte[] data) {
            StringBuilder result = new StringBuilder();

            for (byte value : data) {
                result.append(
                    String.format("%02x", value & 0xff)
                );
            }

            return result.toString();
        }
    }

    public static void main(String[] args) {
        try {
            IdentityService service = new IdentityService(
                new Ed25519Verifier(),
                new DefaultAuthenticationPolicy(120),
                "enterprise-identity-api",
                120,
                5
            );

            System.out.println("1. Register enterprise identity");

            String keyId = service.register("alice");

            System.out.println("Registered key: " + keyId);

            System.out.println("\n2. Issue challenge");

            Challenge challenge = service.issueChallenge(
                "alice",
                keyId
            );

            System.out.println(
                "Challenge: " + challenge.challengeId()
            );

            System.out.println("\n3. Sign authentication request");

            byte[] signature = service.signForDemonstration(
                keyId,
                challenge
            );

            System.out.println(
                "Signature size: " + signature.length
            );

            System.out.println("\n4. Verify authentication");

            AuthenticationResult result =
                service.authenticate(
                    new AuthenticationRequest(
                        "alice",
                        keyId,
                        challenge.challengeId(),
                        signature
                    )
                );

            System.out.println(result);

            System.out.println("\n5. Replay attempt");

            try {
                service.authenticate(
                    new AuthenticationRequest(
                        "alice",
                        keyId,
                        challenge.challengeId(),
                        signature
                    )
                );
            } catch (AuthenticationException ex) {
                System.out.println("Rejected: " + ex.getMessage());
            }

            System.out.println("\n6. Tampered signature");

            Challenge second = service.issueChallenge(
                "alice",
                keyId
            );

            byte[] altered = service.signForDemonstration(
                keyId,
                second
            );

            altered[0] ^= 0x01;

            try {
                service.authenticate(
                    new AuthenticationRequest(
                        "alice",
                        keyId,
                        second.challengeId(),
                        altered
                    )
                );
            } catch (AuthenticationException ex) {
                System.out.println("Rejected: " + ex.getMessage());
            }

            System.out.println("\n7. Key revocation");

            service.revoke(keyId);

            try {
                service.issueChallenge("alice", keyId);
            } catch (AuthenticationException ex) {
                System.out.println("Rejected: " + ex.getMessage());
            }

            System.out.println("\n8. Enterprise authentication report");

            service.printReport();

        } catch (Exception ex) {
            System.err.println(
                "Application failure: " + ex.getMessage()
            );

            System.exit(1);
        }
    }
}
