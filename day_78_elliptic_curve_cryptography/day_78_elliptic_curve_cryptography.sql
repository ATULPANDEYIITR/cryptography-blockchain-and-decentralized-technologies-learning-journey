import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/*
 * Elliptic Curve Cryptography
 *
 * Java 17 enterprise-oriented implementation.
 *
 * Includes:
 * - secp256k1 arithmetic using BigInteger
 * - ECDH key agreement
 * - ECDSA signatures
 * - public-key validation
 * - immutable domain types
 * - key lifecycle management
 * - authorization policies
 * - asynchronous signature verification
 *
 * SECURITY:
 * This educational BigInteger implementation is not constant-time.
 * Use JCA providers and vetted cryptographic libraries in production.
 *
 * Compile:
 * javac ECCEnterprise.java
 *
 * Run:
 * java ECCEnterprise
 */

public class ECCEnterprise {

    // --------------------------------------------------------
    // 1. Cryptographic parameters
    // --------------------------------------------------------

    static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    );

    static final BigInteger A = BigInteger.ZERO;
    static final BigInteger B = BigInteger.valueOf(7);

    static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16
    );

    static final SecureRandom RANDOM = new SecureRandom();

    static final Point G = new Point(
        new BigInteger(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16
        ),
        new BigInteger(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16
        )
    );


    // --------------------------------------------------------
    // 2. Domain exceptions
    // --------------------------------------------------------

    static class ECCException extends RuntimeException {
        ECCException(String message) {
            super(message);
        }
    }

    static class InvalidKeyException extends ECCException {
        InvalidKeyException(String message) {
            super(message);
        }
    }

    static class PolicyViolationException extends ECCException {
        PolicyViolationException(String message) {
            super(message);
        }
    }

    static class InvalidSignatureException extends ECCException {
        InvalidSignatureException(String message) {
            super(message);
        }
    }


    // --------------------------------------------------------
    // 3. Immutable point model
    // --------------------------------------------------------

    record Point(BigInteger x, BigInteger y) {

        boolean isInfinity() {
            return x == null && y == null;
        }

        static Point infinity() {
            return new Point(null, null);
        }
    }


    // --------------------------------------------------------
    // 4. Finite-field operations
    // --------------------------------------------------------

    static BigInteger mod(BigInteger value) {
        return value.mod(P);
    }

    static BigInteger inverse(
        BigInteger value,
        BigInteger modulus
    ) {
        try {
            return value.mod(modulus).modInverse(modulus);
        } catch (ArithmeticException exception) {
            throw new ECCException(
                "Modular inverse does not exist."
            );
        }
    }

    static boolean isOnCurve(Point point) {
        if (point == null) return false;

        if (point.isInfinity()) return true;

        if (
            point.x() == null ||
            point.y() == null ||
            point.x().signum() < 0 ||
            point.x().compareTo(P) >= 0 ||
            point.y().signum() < 0 ||
            point.y().compareTo(P) >= 0
        ) {
            return false;
        }

        BigInteger left = point.y().multiply(point.y()).mod(P);

        BigInteger right = point.x()
            .multiply(point.x())
            .multiply(point.x())
            .add(A.multiply(point.x()))
            .add(B)
            .mod(P);

        return left.equals(right);
    }


    // --------------------------------------------------------
    // 5. Elliptic curve group operations
    // --------------------------------------------------------

    static Point negate(Point point) {
        if (point.isInfinity()) return point;

        return new Point(
            point.x(),
            point.y().negate().mod(P)
        );
    }

    static Point add(Point left, Point right) {
        if (!isOnCurve(left) || !isOnCurve(right)) {
            throw new ECCException("Invalid elliptic curve point.");
        }

        if (left.isInfinity()) return right;
        if (right.isInfinity()) return left;

        if (
            left.x().equals(right.x()) &&
            left.y().add(right.y()).mod(P).signum() == 0
        ) {
            return Point.infinity();
        }

        BigInteger numerator;
        BigInteger denominator;

        if (left.equals(right)) {
            if (left.y().signum() == 0) {
                return Point.infinity();
            }

            numerator = left.x()
                .multiply(left.x())
                .multiply(BigInteger.valueOf(3))
                .add(A);

            denominator = left.y().multiply(BigInteger.TWO);

        } else {
            numerator = right.y().subtract(left.y());
            denominator = right.x().subtract(left.x());
        }

        BigInteger slope = numerator
            .multiply(inverse(denominator, P))
            .mod(P);

        BigInteger x = slope.multiply(slope)
            .subtract(left.x())
            .subtract(right.x())
            .mod(P);

        BigInteger y = slope.multiply(left.x().subtract(x))
            .subtract(left.y())
            .mod(P);

        Point result = new Point(x, y);

        if (!isOnCurve(result)) {
            throw new ECCException("Invalid point addition result.");
        }

        return result;
    }

    static Point multiply(BigInteger scalar, Point point) {
        if (scalar.signum() < 0) {
            return multiply(scalar.negate(), negate(point));
        }

        if (!isOnCurve(point)) {
            throw new ECCException("Invalid scalar multiplication point.");
        }

        Point result = Point.infinity();
        Point current = point;

        BigInteger k = scalar;

        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = add(result, current);
            }

            current = add(current, current);
            k = k.shiftRight(1);
        }

        return result;
    }


    // --------------------------------------------------------
    // 6. Key domain and generation
    // --------------------------------------------------------

    record KeyPairData(
        BigInteger privateKey,
        Point publicKey
    ) {}

    static BigInteger randomScalar() {
        BigInteger value;

        do {
            value = new BigInteger(256, RANDOM);
        } while (
            value.signum() == 0 ||
            value.compareTo(N) >= 0
        );

        return value;
    }

    static KeyPairData generateKeyPair() {
        BigInteger privateKey = randomScalar();

        return new KeyPairData(
            privateKey,
            multiply(privateKey, G)
        );
    }

    static void validatePrivateKey(BigInteger privateKey) {
        if (
            privateKey == null ||
            privateKey.signum() <= 0 ||
            privateKey.compareTo(N) >= 0
        ) {
            throw new InvalidKeyException("Invalid private key.");
        }
    }

    static void validatePublicKey(Point publicKey) {
        if (
            publicKey == null ||
            publicKey.isInfinity() ||
            !isOnCurve(publicKey)
        ) {
            throw new InvalidKeyException("Invalid public key.");
        }

        if (!multiply(N, publicKey).isInfinity()) {
            throw new InvalidKeyException("Invalid subgroup.");
        }
    }

    static boolean keyPairMatches(KeyPairData pair) {
        validatePrivateKey(pair.privateKey());
        validatePublicKey(pair.publicKey());

        return multiply(pair.privateKey(), G)
            .equals(pair.publicKey());
    }


    // --------------------------------------------------------
    // 7. ECDH key agreement
    // --------------------------------------------------------

    static byte[] deriveSharedSecret(
        BigInteger privateKey,
        Point peerPublicKey
    ) {
        validatePrivateKey(privateKey);
        validatePublicKey(peerPublicKey);

        Point shared = multiply(privateKey, peerPublicKey);

        if (shared.isInfinity()) {
            throw new InvalidKeyException("Invalid shared point.");
        }

        return fixedLength(shared.x(), 32);
    }

    static byte[] deriveSessionKey(
        byte[] sharedSecret,
        String context
    ) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            digest.update(
                context.getBytes(StandardCharsets.UTF_8)
            );

            digest.update(sharedSecret);

            return digest.digest();

        } catch (Exception exception) {
            throw new ECCException("Session-key derivation failed.");
        }
    }

    static byte[] fixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();

        byte[] output = new byte[length];

        int sourceStart = Math.max(0, raw.length - length);
        int count = raw.length - sourceStart;

        System.arraycopy(
            raw,
            sourceStart,
            output,
            length - count,
            count
        );

        return output;
    }


    // --------------------------------------------------------
    // 8. ECDSA
    // --------------------------------------------------------

    static BigInteger hashMessage(byte[] message) {
        try {
            return new BigInteger(
                1,
                MessageDigest.getInstance("SHA-256").digest(message)
            );

        } catch (Exception exception) {
            throw new ECCException("Message hashing failed.");
        }
    }

    record Signature(BigInteger r, BigInteger s) {}

    static Signature sign(
        BigInteger privateKey,
        byte[] message
    ) {
        validatePrivateKey(privateKey);

        BigInteger z = hashMessage(message);

        while (true) {
            BigInteger nonce = randomScalar();

            Point point = multiply(nonce, G);

            BigInteger r = point.x().mod(N);

            if (r.signum() == 0) continue;

            BigInteger s = inverse(nonce, N)
                .multiply(z.add(r.multiply(privateKey)))
                .mod(N);

            if (s.signum() == 0) continue;

            if (s.compareTo(N.shiftRight(1)) > 0) {
                s = N.subtract(s);
            }

            return new Signature(r, s);
        }
    }

    static boolean verify(
        Point publicKey,
        byte[] message,
        Signature signature
    ) {
        try {
            validatePublicKey(publicKey);

            BigInteger r = signature.r();
            BigInteger s = signature.s();

            if (
                r.signum() <= 0 ||
                r.compareTo(N) >= 0 ||
                s.signum() <= 0 ||
                s.compareTo(N.shiftRight(1)) > 0
            ) {
                return false;
            }

            BigInteger z = hashMessage(message);

            BigInteger w = inverse(s, N);

            BigInteger u1 = z.multiply(w).mod(N);
            BigInteger u2 = r.multiply(w).mod(N);

            Point result = add(
                multiply(u1, G),
                multiply(u2, publicKey)
            );

            return !result.isInfinity() &&
                result.x().mod(N).equals(r);

        } catch (ECCException | ArithmeticException exception) {
            return false;
        }
    }


    // --------------------------------------------------------
    // 9. Enterprise key lifecycle
    // --------------------------------------------------------

    enum KeyStatus {
        ACTIVE,
        ROTATED,
        REVOKED
    }

    record KeyMetadata(
        String keyId,
        KeyPairData pair,
        KeyStatus status,
        int version,
        Instant createdAt
    ) {}

    static class KeyRegistry {

        private final Map<String, KeyMetadata> keys =
            new HashMap<>();

        public synchronized void register(
            String keyId,
            KeyPairData pair
        ) {
            if (
                keyId == null ||
                !keyId.matches("[a-zA-Z0-9_-]{1,64}")
            ) {
                throw new InvalidKeyException("Invalid key identifier.");
            }

            if (keys.containsKey(keyId)) {
                throw new InvalidKeyException("Duplicate key identifier.");
            }

            if (!keyPairMatches(pair)) {
                throw new InvalidKeyException("Key pair mismatch.");
            }

            keys.put(
                keyId,
                new KeyMetadata(
                    keyId,
                    pair,
                    KeyStatus.ACTIVE,
                    1,
                    Instant.now()
                )
            );
        }

        public synchronized String rotate(
            String oldId,
            KeyPairData replacement
        ) {
            KeyMetadata old = getActive(oldId);

            if (!keyPairMatches(replacement)) {
                throw new InvalidKeyException("Replacement mismatch.");
            }

            String newId = oldId + "-v" + (old.version() + 1);

            if (keys.containsKey(newId)) {
                throw new InvalidKeyException("Version identifier exists.");
            }

            // Register the new key before retiring the previous key.
            register(newId, replacement);

            keys.put(
                oldId,
                new KeyMetadata(
                    old.keyId(),
                    old.pair(),
                    KeyStatus.ROTATED,
                    old.version(),
                    old.createdAt()
                )
            );

            return newId;
        }

        public synchronized void revoke(String keyId) {
            KeyMetadata old = getActive(keyId);

            keys.put(
                keyId,
                new KeyMetadata(
                    old.keyId(),
                    old.pair(),
                    KeyStatus.REVOKED,
                    old.version(),
                    old.createdAt()
                )
            );
        }

        public synchronized KeyMetadata getActive(String keyId) {
            KeyMetadata metadata = keys.get(keyId);

            if (
                metadata == null ||
                metadata.status() != KeyStatus.ACTIVE
            ) {
                throw new InvalidKeyException("Key is unavailable.");
            }

            return metadata;
        }

        public synchronized List<KeyMetadata> snapshot() {
            return List.copyOf(keys.values());
        }
    }


    // --------------------------------------------------------
    // 10. Enterprise authorization policy
    // --------------------------------------------------------

    record ApprovalPolicy(
        int minimumApprovals,
        boolean requireActiveKey,
        boolean requireSignature,
        Set<String> permittedCurves
    ) {
        ApprovalPolicy {
            if (minimumApprovals < 1 || minimumApprovals > 20) {
                throw new IllegalArgumentException(
                    "Invalid approval threshold."
                );
            }

            permittedCurves = Set.copyOf(permittedCurves);
        }
    }

    record ApprovalRequest(
        String requestId,
        String requester,
        int approvalCount,
        byte[] payload,
        Signature signature,
        Point signingPublicKey,
        String curveName
    ) {}

    static class AuthorizationService {

        private final KeyRegistry registry;
        private final ApprovalPolicy policy;

        AuthorizationService(
            KeyRegistry registry,
            ApprovalPolicy policy
        ) {
            this.registry = Objects.requireNonNull(registry);
            this.policy = Objects.requireNonNull(policy);
        }

        public boolean authorize(
            ApprovalRequest request
        ) {
            if (
                request == null ||
                request.requestId() == null ||
                request.requestId().isBlank()
            ) {
                throw new PolicyViolationException(
                    "Invalid authorization request."
                );
            }

            if (
                !policy.permittedCurves().contains(
                    request.curveName()
                )
            ) {
                throw new PolicyViolationException(
                    "Curve is not permitted."
                );
            }

            if (
                request.approvalCount() <
                policy.minimumApprovals()
            ) {
                return false;
            }

            if (policy.requireActiveKey()) {
                registry.getActive(request.requester());
            }

            if (policy.requireSignature()) {
                if (!verify(
                    request.signingPublicKey(),
                    request.payload(),
                    request.signature()
                )) {
                    return false;
                }
            }

            return true;
        }
    }


    // --------------------------------------------------------
    // 11. Asynchronous verification service
    // --------------------------------------------------------

    static class AsyncVerificationService
        implements AutoCloseable {

        private final ExecutorService executor =
            Executors.newFixedThreadPool(2);

        public CompletableFuture<Boolean> verifyAsync(
            Point publicKey,
            byte[] message,
            Signature signature
        ) {
            byte[] immutableMessage = message.clone();

            return CompletableFuture.supplyAsync(
                () -> verify(
                    publicKey,
                    immutableMessage,
                    signature
                ),
                executor
            );
        }

        @Override
        public void close() {
            executor.shutdown();

            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException exception) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }


    // --------------------------------------------------------
    // 12. Integration demonstration
    // --------------------------------------------------------

    public static void main(String[] args) {

        System.out.println("ELLIPTIC CURVE CRYPTOGRAPHY");
        System.out.println("Curve: secp256k1\n");

        if (!isOnCurve(G)) {
            throw new ECCException("Generator validation failed.");
        }

        if (!multiply(N, G).isInfinity()) {
            throw new ECCException("Incorrect curve order.");
        }

        System.out.println("Curve validation: PASS");

        // Generate device identities.
        KeyPairData alice = generateKeyPair();
        KeyPairData bob = generateKeyPair();

        if (!keyPairMatches(alice) || !keyPairMatches(bob)) {
            throw new InvalidKeyException("Key consistency failure.");
        }

        System.out.println("Key-pair consistency: PASS");

        // ECDH.
        byte[] secretAlice = deriveSharedSecret(
            alice.privateKey(),
            bob.publicKey()
        );

        byte[] secretBob = deriveSharedSecret(
            bob.privateKey(),
            alice.publicKey()
        );

        if (!MessageDigest.isEqual(secretAlice, secretBob)) {
            throw new ECCException("ECDH mismatch.");
        }

        byte[] sessionKey = deriveSessionKey(
            secretAlice,
            "enterprise-device-session"
        );

        System.out.println("ECDH agreement: PASS");

        System.out.println(
            "Session key: " +
            java.util.HexFormat.of().formatHex(sessionKey)
        );

        // Digital signature.
        byte[] message = (
            "Authorize secure infrastructure deployment"
        ).getBytes(StandardCharsets.UTF_8);

        Signature signature = sign(
            alice.privateKey(),
            message
        );

        if (!verify(alice.publicKey(), message, signature)) {
            throw new InvalidSignatureException(
                "Signature verification failed."
            );
        }

        if (verify(
            alice.publicKey(),
            "Altered deployment".getBytes(StandardCharsets.UTF_8),
            signature
        )) {
            throw new InvalidSignatureException(
                "Tampered message accepted."
            );
        }

        System.out.println("ECDSA verification: PASS");
        System.out.println("Tampered message rejection: PASS");

        // Registry and lifecycle.
        KeyRegistry registry = new KeyRegistry();

        registry.register("alice", alice);
        registry.register("bob", bob);

        String replacementId = registry.rotate(
            "alice",
            generateKeyPair()
        );

        System.out.println("Key rotation: " + replacementId);

        // Enterprise policy.
        ApprovalPolicy policy = new ApprovalPolicy(
            2,
            true,
            true,
            Set.of("secp256k1")
        );

        AuthorizationService authorization =
            new AuthorizationService(registry, policy);

        ApprovalRequest request = new ApprovalRequest(
            "REQ-2026-001",
            "bob",
            2,
            message,
            sign(bob.privateKey(), message),
            bob.publicKey(),
            "secp256k1"
        );

        if (!authorization.authorize(request)) {
            throw new PolicyViolationException(
                "Authorization denied."
            );
        }

        System.out.println("Enterprise authorization: PASS");

        // Insufficient approvals.
        ApprovalRequest insufficient = new ApprovalRequest(
            "REQ-2026-002",
            "bob",
            1,
            message,
            request.signature(),
            bob.publicKey(),
            "secp256k1"
        );

        if (authorization.authorize(insufficient)) {
            throw new PolicyViolationException(
                "Insufficient approvals accepted."
            );
        }

        System.out.println("Approval threshold enforcement: PASS");

        // Asynchronous verification.
        try (AsyncVerificationService service =
                 new AsyncVerificationService()) {

            boolean asyncResult = service.verifyAsync(
                bob.publicKey(),
                message,
                request.signature()
            ).join();

            if (!asyncResult) {
                throw new ECCException(
                    "Asynchronous verification failed."
                );
            }
        }

        System.out.println("Asynchronous verification: PASS");

        // Key revocation.
        registry.revoke("alice-v2");

        try {
            registry.getActive("alice-v2");

            throw new ECCException("Revoked key was accepted.");

        } catch (InvalidKeyException exception) {
            System.out.println("Revocation enforcement: PASS");
        }

        // Invalid private key.
        try {
            validatePrivateKey(BigInteger.ZERO);

            throw new ECCException("Zero private key accepted.");

        } catch (InvalidKeyException exception) {
            System.out.println("Invalid key rejection: PASS");
        }

        // Policy conflict.
        ApprovalPolicy incompatible = new ApprovalPolicy(
            1,
            true,
            true,
            Set.of("p256")
        );

        AuthorizationService restricted =
            new AuthorizationService(registry, incompatible);

        try {
            restricted.authorize(request);

            throw new ECCException("Unsupported curve accepted.");

        } catch (PolicyViolationException exception) {
            System.out.println("Curve policy enforcement: PASS");
        }

        System.out.println("\nAll enterprise ECC checks passed.");
    }
}
