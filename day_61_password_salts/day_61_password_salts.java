import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/*
 * Enterprise password credential service.
 *
 * Domain separation:
 * - CredentialService owns account lifecycle.
 * - PasswordPolicy validates credential requirements.
 * - PasswordRecord stores only password-derived material and metadata.
 * - AuthenticationService applies state transitions.
 * - Approval-like policy concepts are deliberately not mixed into
 *   authentication state.
 *
 * PBKDF2-HMAC-SHA256 is supplied by the Java runtime.
 */

public class PasswordSaltEnterpriseDemo {

    enum AccountState {
        ACTIVE,
        LOCKED
    }

    record PasswordPolicy(
        int minimumLength,
        int saltBytes,
        int iterations,
        int derivedKeyBits,
        int maximumFailures
    ) {
        PasswordPolicy {
            if (minimumLength < 12) {
                throw new IllegalArgumentException(
                    "minimum password length must be at least 12"
                );
            }

            if (saltBytes < 16) {
                throw new IllegalArgumentException(
                    "salt must contain at least 16 bytes"
                );
            }

            if (iterations < 100_000) {
                throw new IllegalArgumentException(
                    "PBKDF2 iteration count is too low"
                );
            }

            if (derivedKeyBits < 256) {
                throw new IllegalArgumentException(
                    "derived key must contain at least 256 bits"
                );
            }

            if (maximumFailures < 1) {
                throw new IllegalArgumentException(
                    "maximum failures must be positive"
                );
            }
        }

        static PasswordPolicy productionBaseline() {
            return new PasswordPolicy(
                12,
                16,
                310_000,
                256,
                5
            );
        }
    }

    static final class CredentialException extends Exception {
        CredentialException(String message) {
            super(message);
        }
    }

    static final class PasswordRecord {
        private final String username;
        private byte[] salt;
        private byte[] passwordHash;
        private int iterations;
        private int failedAttempts;
        private AccountState state;
        private long passwordVersion;
        private final Instant createdAt;
        private Instant updatedAt;

        PasswordRecord(
            String username,
            byte[] salt,
            byte[] passwordHash,
            int iterations
        ) {
            this.username = username;
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
            this.iterations = iterations;
            this.createdAt = Instant.now();
            this.updatedAt = this.createdAt;
            this.state = AccountState.ACTIVE;
            this.passwordVersion = 1;
        }

        String username() {
            return username;
        }

        byte[] salt() {
            return salt.clone();
        }

        byte[] passwordHash() {
            return passwordHash.clone();
        }

        int iterations() {
            return iterations;
        }

        int failedAttempts() {
            return failedAttempts;
        }

        AccountState state() {
            return state;
        }

        long passwordVersion() {
            return passwordVersion;
        }

        void recordSuccess() {
            failedAttempts = 0;
            updatedAt = Instant.now();
        }

        void recordFailure(int maximumFailures) {
            failedAttempts++;

            if (failedAttempts >= maximumFailures) {
                state = AccountState.LOCKED;
            }

            updatedAt = Instant.now();
        }

        void rotate(
            byte[] newSalt,
            byte[] newHash,
            int newIterations
        ) {
            salt = newSalt.clone();
            passwordHash = newHash.clone();
            iterations = newIterations;
            failedAttempts = 0;
            state = AccountState.ACTIVE;
            passwordVersion++;
            updatedAt = Instant.now();
        }

        void unlock() {
            failedAttempts = 0;
            state = AccountState.ACTIVE;
            updatedAt = Instant.now();
        }
    }

    interface PasswordDeriver {
        byte[] derive(
            char[] password,
            byte[] salt,
            int iterations
        ) throws GeneralSecurityException;
    }

    static final class Pbkdf2Deriver implements PasswordDeriver {
        @Override
        public byte[] derive(
            char[] password,
            byte[] salt,
            int iterations
        ) throws GeneralSecurityException {
            PBEKeySpec specification =
                new PBEKeySpec(
                    password,
                    salt,
                    iterations,
                    256
                );

            try {
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256"
                    );

                return factory.generateSecret(specification)
                    .getEncoded();
            } finally {
                specification.clearPassword();
            }
        }
    }

    static final class PasswordPolicyService {
        private final PasswordPolicy policy;

        PasswordPolicyService(PasswordPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        void validateUsername(String username)
            throws CredentialException {

            if (username == null) {
                throw new CredentialException(
                    "username cannot be null"
                );
            }

            String normalized = username.trim().toLowerCase();

            if (
                normalized.isBlank() ||
                normalized.length() > 128 ||
                !normalized.matches("[a-z0-9._@-]+")
            ) {
                throw new CredentialException(
                    "username violates policy"
                );
            }
        }

        void validatePassword(char[] password)
            throws CredentialException {

            if (
                password == null ||
                password.length < policy.minimumLength()
            ) {
                throw new CredentialException(
                    "password violates length policy"
                );
            }

            boolean nonWhitespace = false;

            for (char character : password) {
                if (!Character.isWhitespace(character)) {
                    nonWhitespace = true;
                    break;
                }
            }

            if (!nonWhitespace) {
                throw new CredentialException(
                    "password cannot contain only whitespace"
                );
            }
        }
    }

    static final class AuthenticationService {
        private final Map<String, PasswordRecord> records =
            new HashMap<>();

        private final SecureRandom secureRandom =
            new SecureRandom();

        private final PasswordPolicy policy;
        private final PasswordPolicyService policyService;
        private final PasswordDeriver deriver;

        AuthenticationService(
            PasswordPolicy policy,
            PasswordDeriver deriver
        ) {
            this.policy = Objects.requireNonNull(policy);
            this.policyService =
                new PasswordPolicyService(policy);
            this.deriver = Objects.requireNonNull(deriver);
        }

        private String normalizeUsername(String username)
            throws CredentialException {

            policyService.validateUsername(username);
            return username.trim().toLowerCase();
        }

        private byte[] generateSalt() {
            byte[] salt = new byte[policy.saltBytes()];
            secureRandom.nextBytes(salt);
            return salt;
        }

        void register(
            String username,
            char[] password
        ) throws CredentialException, GeneralSecurityException {

            String normalized = normalizeUsername(username);
            policyService.validatePassword(password);

            if (records.containsKey(normalized)) {
                throw new CredentialException(
                    "account already exists"
                );
            }

            byte[] salt = generateSalt();

            byte[] hash = deriver.derive(
                password,
                salt,
                policy.iterations()
            );

            records.put(
                normalized,
                new PasswordRecord(
                    normalized,
                    salt,
                    hash,
                    policy.iterations()
                )
            );

            java.util.Arrays.fill(password, '\0');
        }

        boolean authenticate(
            String username,
            char[] password
        ) throws GeneralSecurityException {

            String normalized;

            try {
                normalized = normalizeUsername(username);
            } catch (CredentialException error) {
                return false;
            }

            PasswordRecord record = records.get(normalized);

            if (record == null) {
                return false;
            }

            if (record.state() == AccountState.LOCKED) {
                return false;
            }

            byte[] candidate =
                deriver.derive(
                    password,
                    record.salt(),
                    record.iterations()
                );

            boolean matches =
                MessageDigest.isEqual(
                    candidate,
                    record.passwordHash()
                );

            if (matches) {
                record.recordSuccess();
                return true;
            }

            record.recordFailure(
                policy.maximumFailures()
            );

            return false;
        }

        void changePassword(
            String username,
            char[] currentPassword,
            char[] newPassword
        ) throws Exception {

            if (!authenticate(username, currentPassword)) {
                throw new CredentialException(
                    "current password is invalid"
                );
            }

            policyService.validatePassword(newPassword);

            String normalized =
                normalizeUsername(username);

            PasswordRecord record =
                records.get(normalized);

            byte[] newSalt = generateSalt();

            byte[] newHash =
                deriver.derive(
                    newPassword,
                    newSalt,
                    policy.iterations()
                );

            record.rotate(
                newSalt,
                newHash,
                policy.iterations()
            );

            java.util.Arrays.fill(currentPassword, '\0');
            java.util.Arrays.fill(newPassword, '\0');
        }

        void unlock(String username)
            throws CredentialException {

            String normalized =
                normalizeUsername(username);

            PasswordRecord record = records.get(normalized);

            if (record == null) {
                throw new CredentialException(
                    "account does not exist"
                );
            }

            record.unlock();
        }

        PasswordRecord record(String username)
            throws CredentialException {

            String normalized =
                normalizeUsername(username);

            PasswordRecord record =
                records.get(normalized);

            if (record == null) {
                throw new CredentialException(
                    "account does not exist"
                );
            }

            return record;
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes);
    }

    public static void main(String[] args) throws Exception {
        PasswordPolicy policy =
            PasswordPolicy.productionBaseline();

        AuthenticationService service =
            new AuthenticationService(
                policy,
                new Pbkdf2Deriver()
            );

        char[] password =
            "Correct-Horse-Battery-42!".toCharArray();

        char[] samePassword =
            "Correct-Horse-Battery-42!".toCharArray();

        service.register(
            "alice@example.com",
            password
        );

        service.register(
            "bob@example.com",
            samePassword
        );

        PasswordRecord alice =
            service.record("alice@example.com");

        PasswordRecord bob =
            service.record("bob@example.com");

        if (MessageDigest.isEqual(alice.salt(), bob.salt())) {
            throw new IllegalStateException(
                "independent accounts unexpectedly share a salt"
            );
        }

        if (
            MessageDigest.isEqual(
                alice.passwordHash(),
                bob.passwordHash()
            )
        ) {
            throw new IllegalStateException(
                "equal passwords unexpectedly produced equal hashes"
            );
        }

        System.out.println(
            "Alice salt: " + base64(alice.salt())
        );

        System.out.println(
            "Bob salt:   " + base64(bob.salt())
        );

        System.out.println(
            "Valid login: " +
            service.authenticate(
                "alice@example.com",
                "Correct-Horse-Battery-42!".toCharArray()
            )
        );

        System.out.println(
            "Invalid login: " +
            service.authenticate(
                "alice@example.com",
                "wrong-password".toCharArray()
            )
        );

        for (int i = 0; i < 4; i++) {
            service.authenticate(
                "alice@example.com",
                "wrong-password".toCharArray()
            );
        }

        System.out.println(
            "Locked login: " +
            service.authenticate(
                "alice@example.com",
                "Correct-Horse-Battery-42!".toCharArray()
            )
        );

        service.unlock("alice@example.com");

        service.changePassword(
            "alice@example.com",
            "Correct-Horse-Battery-42!".toCharArray(),
            "New-Longer-Password-99!".toCharArray()
        );

        System.out.println(
            "Rotated password login: " +
            service.authenticate(
                "alice@example.com",
                "New-Longer-Password-99!".toCharArray()
            )
        );

        System.out.println(
            "Password version: " +
            service.record("alice@example.com")
                .passwordVersion()
        );
    }
}
