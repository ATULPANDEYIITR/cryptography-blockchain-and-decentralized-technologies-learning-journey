/*
 * Secure Password Hashing and Enterprise Authentication
 *
 * Java version: 17+
 *
 * Implements:
 * - PBKDF2-HMAC-SHA256
 * - SecureRandom salt generation
 * - PBEKeySpec password handling
 * - NFC normalization
 * - Immutable credential records
 * - Explicit account states
 * - Repository abstraction
 * - Validation and custom exceptions
 * - Account-level failure throttling
 * - Legacy credential migration
 * - Security audit events
 */

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.text.Normalizer;

import java.time.Instant;

import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;


public class PasswordHashing {

    private static final int CURRENT_ITERATIONS = 600_000;
    private static final int MIN_ITERATIONS = 100_000;
    private static final int MAX_ITERATIONS = 2_000_000;

    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 32;

    private static final int MAX_FAILURES = 5;
    private static final long LOCK_DURATION_NANOS =
            60_000_000_000L;

    private static final String ALGORITHM =
            "pbkdf2-sha256";


    enum AccountState {
        ACTIVE,
        DISABLED
    }


    enum AuthenticationStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED
    }


    static final class PasswordPolicyException
            extends IllegalArgumentException {

        PasswordPolicyException(String message) {
            super(message);
        }
    }


    static final class AccountConflictException
            extends IllegalStateException {

        AccountConflictException(String message) {
            super(message);
        }
    }


    /*
     * Credential objects are immutable.
     * The encoded representation preserves algorithm and work factor.
     */
    record PasswordCredential(String encodedValue) {

        PasswordCredential {
            if (encodedValue == null || encodedValue.isBlank()) {
                throw new IllegalArgumentException(
                        "Credential cannot be empty."
                );
            }
        }
    }


    record ParsedCredential(
            int iterations,
            byte[] salt,
            byte[] expected
    ) {
    }


    record AuthenticationEvent(
            String accountId,
            AuthenticationStatus status,
            Instant timestamp
    ) {
    }


    static final class PasswordPolicy {

        private final Set<String> blockedPasswords = Set.of(
                "password",
                "password123",
                "123456789012345",
                "qwerty123456789",
                "letmein123456"
        );

        String validate(String password, String username) {

            if (password == null) {
                throw new PasswordPolicyException(
                        "Password cannot be null."
                );
            }

            String normalized = Normalizer.normalize(
                    password,
                    Normalizer.Form.NFC
            );

            if (normalized.indexOf('\0') >= 0) {
                throw new PasswordPolicyException(
                        "Null characters are not permitted."
                );
            }

            int length = normalized.codePointCount(
                    0,
                    normalized.length()
            );

            if (length < 15 || length > 256) {
                throw new PasswordPolicyException(
                        "Password length is outside permitted limits."
                );
            }

            int byteLength = normalized.getBytes(
                    StandardCharsets.UTF_8
            ).length;

            if (byteLength > 1024) {
                throw new PasswordPolicyException(
                        "Password exceeds byte limit."
                );
            }

            String folded = normalized.toLowerCase(Locale.ROOT);

            if (blockedPasswords.contains(folded)) {
                throw new PasswordPolicyException(
                        "Password appears on the blocked-password list."
                );
            }

            if (
                    username != null &&
                    folded.equals(username.toLowerCase(Locale.ROOT))
            ) {
                throw new PasswordPolicyException(
                        "Password cannot equal account identifier."
                );
            }

            return normalized;
        }
    }


    /*
     * Password hashing is encapsulated behind one service.
     * SecretKeyFactory provides the JCA implementation of PBKDF2.
     */
    static final class PasswordHasher {

        private final SecureRandom random;
        private final int iterations;

        PasswordHasher() {
            this(CURRENT_ITERATIONS);
        }

        PasswordHasher(int iterations) {

            if (
                    iterations < MIN_ITERATIONS ||
                    iterations > MAX_ITERATIONS
            ) {
                throw new IllegalArgumentException(
                        "Unsupported iteration count."
                );
            }

            this.iterations = iterations;
            this.random = new SecureRandom();
        }

        private byte[] derive(
                String password,
                byte[] salt,
                int count
        ) throws GeneralSecurityException {

            char[] passwordCharacters = password.toCharArray();

            PBEKeySpec specification = new PBEKeySpec(
                    passwordCharacters,
                    salt,
                    count,
                    KEY_LENGTH * 8
            );

            try {
                SecretKeyFactory factory =
                        SecretKeyFactory.getInstance(
                                "PBKDF2WithHmacSHA256"
                        );

                return factory.generateSecret(
                        specification
                ).getEncoded();

            } finally {
                specification.clearPassword();

                // Clear the temporary mutable character array.
                Arrays.fill(passwordCharacters, '\0');
            }
        }

        PasswordCredential hash(String password)
                throws GeneralSecurityException {

            String normalized = Normalizer.normalize(
                    password,
                    Normalizer.Form.NFC
            );

            byte[] salt = new byte[SALT_LENGTH];

            random.nextBytes(salt);

            byte[] derived = derive(
                    normalized,
                    salt,
                    iterations
            );

            String encoded = String.join(
                    "$",
                    ALGORITHM,
                    Integer.toString(iterations),
                    Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(salt),
                    Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(derived)
            );

            Arrays.fill(derived, (byte) 0);

            return new PasswordCredential(encoded);
        }

        ParsedCredential parse(PasswordCredential credential) {

            String[] parts = credential.encodedValue().split(
                    "\\$",
                    -1
            );

            if (parts.length != 4 || !parts[0].equals(ALGORITHM)) {
                throw new IllegalArgumentException(
                        "Unsupported password hash format."
                );
            }

            int count;

            try {
                count = Integer.parseInt(parts[1]);
            } catch (NumberFormatException error) {
                throw new IllegalArgumentException(
                        "Invalid iteration count."
                );
            }

            if (
                    count < MIN_ITERATIONS ||
                    count > MAX_ITERATIONS
            ) {
                throw new IllegalArgumentException(
                        "Iteration count outside permitted limits."
                );
            }

            try {
                byte[] salt = Base64.getUrlDecoder().decode(parts[2]);
                byte[] expected = Base64.getUrlDecoder().decode(parts[3]);

                if (salt.length < SALT_LENGTH || salt.length > 64) {
                    throw new IllegalArgumentException(
                            "Invalid salt length."
                    );
                }

                if (expected.length != KEY_LENGTH) {
                    throw new IllegalArgumentException(
                            "Invalid derived-key length."
                    );
                }

                return new ParsedCredential(
                        count,
                        salt,
                        expected
                );

            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException(
                        "Invalid credential encoding.",
                        error
                );
            }
        }

        boolean verify(
                String password,
                PasswordCredential credential
        ) {

            try {
                String normalized = Normalizer.normalize(
                        password,
                        Normalizer.Form.NFC
                );

                if (
                        normalized.getBytes(StandardCharsets.UTF_8).length
                                > 1024
                ) {
                    return false;
                }

                ParsedCredential parsed = parse(credential);

                byte[] actual = derive(
                        normalized,
                        parsed.salt(),
                        parsed.iterations()
                );

                try {
                    return MessageDigest.isEqual(
                            actual,
                            parsed.expected()
                    );
                } finally {
                    Arrays.fill(actual, (byte) 0);
                }

            } catch (
                    IllegalArgumentException |
                    GeneralSecurityException error
            ) {
                return false;
            }
        }

        boolean needsRehash(PasswordCredential credential) {

            try {
                return parse(credential).iterations() < iterations;
            } catch (IllegalArgumentException error) {
                return true;
            }
        }
    }


    /*
     * Repository contract separates account storage from authentication.
     */
    interface AccountRepository {

        Account find(String username);

        boolean save(Account account);
    }


    static final class Account {

        private final String username;

        private PasswordCredential credential;

        private AccountState state;

        private int failedAttempts;

        private long lockedUntilNanos;

        Account(
                String username,
                PasswordCredential credential
        ) {
            this.username = username;
            this.credential = credential;
            this.state = AccountState.ACTIVE;
        }

        String username() {
            return username;
        }

        synchronized AccountState state() {
            return state;
        }

        synchronized PasswordCredential credential() {
            return credential;
        }

        synchronized void updateCredential(
                PasswordCredential replacement
        ) {
            credential = replacement;
        }

        synchronized void disable() {
            state = AccountState.DISABLED;
        }

        synchronized boolean isLocked(long now) {
            return now < lockedUntilNanos;
        }

        synchronized void recordFailure(long now) {

            failedAttempts++;

            if (failedAttempts >= MAX_FAILURES) {
                lockedUntilNanos = now + LOCK_DURATION_NANOS;
            }
        }

        synchronized void recordSuccess() {
            failedAttempts = 0;
            lockedUntilNanos = 0;
        }

        synchronized boolean hasTooManyFailures() {
            return failedAttempts >= MAX_FAILURES;
        }
    }


    static final class InMemoryAccountRepository
            implements AccountRepository {

        private final Map<String, Account> accounts =
                new ConcurrentHashMap<>();

        @Override
        public Account find(String username) {
            return accounts.get(username);
        }

        @Override
        public boolean save(Account account) {
            return accounts.putIfAbsent(
                    account.username(),
                    account
            ) == null;
        }
    }


    /*
     * Enterprise authentication service.
     *
     * Account synchronization protects failure counters and credential
     * upgrades while ConcurrentHashMap permits independent accounts
     * to authenticate concurrently.
     */
    static final class AuthenticationService {

        private final AccountRepository repository;
        private final PasswordHasher hasher;
        private final PasswordPolicy policy;

        private final Consumer<AuthenticationEvent> audit;

        private final PasswordCredential dummyCredential;

        AuthenticationService(
                AccountRepository repository,
                PasswordHasher hasher,
                PasswordPolicy policy,
                Consumer<AuthenticationEvent> audit
        ) throws GeneralSecurityException {

            this.repository = repository;
            this.hasher = hasher;
            this.policy = policy;
            this.audit = audit;

            this.dummyCredential = hasher.hash(
                    "internal dummy credential not for authentication"
            );
        }

        private String normalizeUsername(String username) {

            if (username == null) {
                throw new IllegalArgumentException(
                        "Username cannot be null."
                );
            }

            String normalized = username.trim().toLowerCase(
                    Locale.ROOT
            );

            if (!normalized.matches("[a-z0-9._-]{3,64}")) {
                throw new IllegalArgumentException(
                        "Invalid account identifier."
                );
            }

            return normalized;
        }

        void register(String username, String password)
                throws GeneralSecurityException {

            String key = normalizeUsername(username);

            String validPassword = policy.validate(
                    password,
                    key
            );

            PasswordCredential credential =
                    hasher.hash(validPassword);

            Account account = new Account(
                    key,
                    credential
            );

            if (!repository.save(account)) {
                throw new AccountConflictException(
                        "Account already exists."
                );
            }
        }

        AuthenticationStatus authenticate(
                String username,
                String password
        ) throws GeneralSecurityException {

            String key;

            try {
                key = normalizeUsername(username);
            } catch (IllegalArgumentException error) {
                hasher.verify(password, dummyCredential);
                return AuthenticationStatus.INVALID_CREDENTIALS;
            }

            Account account = repository.find(key);

            if (account == null) {
                hasher.verify(password, dummyCredential);

                return AuthenticationStatus.INVALID_CREDENTIALS;
            }

            AuthenticationStatus result;

            synchronized (account) {

                if (account.state() == AccountState.DISABLED) {
                    result = AuthenticationStatus.ACCOUNT_DISABLED;

                } else if (account.isLocked(System.nanoTime())) {
                    result = AuthenticationStatus.ACCOUNT_LOCKED;

                } else if (
                        !hasher.verify(
                                password,
                                account.credential()
                        )
                ) {

                    account.recordFailure(System.nanoTime());

                    result = account.hasTooManyFailures()
                            ? AuthenticationStatus.ACCOUNT_LOCKED
                            : AuthenticationStatus.INVALID_CREDENTIALS;

                } else {

                    account.recordSuccess();

                    if (hasher.needsRehash(account.credential())) {
                        account.updateCredential(
                                hasher.hash(password)
                        );
                    }

                    result = AuthenticationStatus.SUCCESS;
                }
            }

            audit.accept(
                    new AuthenticationEvent(
                            key,
                            result,
                            Instant.now()
                    )
            );

            return result;
        }

        void disableAccount(String username) {

            String key = normalizeUsername(username);
            Account account = repository.find(key);

            if (account == null) {
                throw new IllegalArgumentException(
                        "Account does not exist."
                );
            }

            synchronized (account) {
                account.disable();
            }
        }

        void seedLegacyCredential(
                String username,
                String password
        ) throws GeneralSecurityException {

            // Test fixture for migration from a previous iteration count.
            String key = normalizeUsername(username);
            Account account = repository.find(key);

            if (account == null) {
                throw new IllegalArgumentException(
                        "Account does not exist."
                );
            }

            synchronized (account) {
                PasswordHasher legacyHasher =
                        new PasswordHasher(120_000);

                account.updateCredential(
                        legacyHasher.hash(password)
                );
            }
        }
    }


    public static void main(String[] args) throws Exception {

        PasswordPolicy policy = new PasswordPolicy();

        PasswordHasher hasher = new PasswordHasher();

        InMemoryAccountRepository repository =
                new InMemoryAccountRepository();

        Consumer<AuthenticationEvent> audit =
                event -> System.out.println(
                        "AUDIT " +
                        event.accountId() +
                        " " +
                        event.status() +
                        " " +
                        event.timestamp()
                );

        AuthenticationService service =
                new AuthenticationService(
                        repository,
                        hasher,
                        policy,
                        audit
                );

        String username = "alex.developer";

        String password =
                "Correct-Horse-Battery-Staple-2026!";

        // Registration and credential creation.
        service.register(username, password);

        // Simulate a historical credential.
        service.seedLegacyCredential(username, password);

        AuthenticationStatus wrong = service.authenticate(
                username,
                "incorrect-authentication-secret"
        );

        AuthenticationStatus correct = service.authenticate(
                username,
                password
        );

        if (wrong == AuthenticationStatus.SUCCESS) {
            throw new AssertionError("Incorrect password accepted.");
        }

        if (correct != AuthenticationStatus.SUCCESS) {
            throw new AssertionError("Valid authentication failed.");
        }

        System.out.println("Legacy credential migration successful.");

        // Confirm invalid-password policy.
        try {
            service.register(
                    "weak.account",
                    "password123456789"
            );

            throw new AssertionError(
                    "Weak password was incorrectly accepted."
            );

        } catch (PasswordPolicyException expected) {
            System.out.println("Weak password rejected successfully.");
        }

        // Test different salts and independent credential verification.
        PasswordCredential first = hasher.hash(password);
        PasswordCredential second = hasher.hash(password);

        if (first.encodedValue().equals(second.encodedValue())) {
            throw new AssertionError("Salt uniqueness failed.");
        }

        if (!hasher.verify(password, first)) {
            throw new AssertionError("Valid credential rejected.");
        }

        if (hasher.verify("incorrect-secret", first)) {
            throw new AssertionError("Invalid credential accepted.");
        }

        // Test throttling.
        String throttlePassword =
                "A-Long-Unique-Authentication-Secret-2026!";

        service.register("throttle.user", throttlePassword);

        for (int i = 0; i < MAX_FAILURES; i++) {
            service.authenticate(
                    "throttle.user",
                    "incorrect-authentication-secret"
            );
        }

        AuthenticationStatus locked = service.authenticate(
                "throttle.user",
                throttlePassword
        );

        if (locked != AuthenticationStatus.ACCOUNT_LOCKED) {
            throw new AssertionError("Account throttling failed.");
        }

        System.out.println("Account throttling successful.");
        System.out.println("All Java security assertions passed.");
    }
}
