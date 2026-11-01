import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * Rainbow Tables and Password Attacks
 *
 * Enterprise password security and authentication governance.
 *
 * Features:
 * - Password attack classification
 * - Rainbow-table risk evaluation
 * - Secure password credential creation
 * - PBKDF2-HMAC-SHA256 verification
 * - Password policy enforcement
 * - Reviewer-independent security policies
 * - Explicit authentication state transitions
 * - Account lockout and security audit events
 *
 * Compile: javac PasswordSecurity.java
 * Run: java PasswordSecurity
 */

public class PasswordSecurity {

    // -----------------------------------------------------
    // 1. Domain enumerations
    // -----------------------------------------------------

    enum AttackType {
        DICTIONARY,
        BRUTE_FORCE,
        RAINBOW_TABLE,
        CREDENTIAL_STUFFING,
        PASSWORD_SPRAYING,
        PHISHING
    }

    enum AuthenticationState {
        ACTIVE,
        TEMPORARILY_LOCKED,
        DISABLED
    }

    enum AuthenticationResult {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED
    }

    enum RiskLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum HashAlgorithm {
        PBKDF2_HMAC_SHA256,
        ARGON2ID,
        BCRYPT,
        SHA256
    }

    // -----------------------------------------------------
    // 2. Attack classification
    // -----------------------------------------------------

    record AttackProfile(
        AttackType type,
        String description,
        List<String> defenses
    ) {}

    static class AttackCatalog {

        private final Map<AttackType, AttackProfile> profiles =
            new EnumMap<>(AttackType.class);

        AttackCatalog() {
            add(
                AttackType.DICTIONARY,
                "Testing likely passwords against stored hashes.",
                "Common-password screening",
                "Adaptive password hashing"
            );

            add(
                AttackType.BRUTE_FORCE,
                "Exhaustive password candidate enumeration.",
                "Rate limiting",
                "Progressive delays"
            );

            add(
                AttackType.RAINBOW_TABLE,
                "Precomputed hash-chain lookup.",
                "Unique random salts",
                "Memory-hard password hashing"
            );

            add(
                AttackType.CREDENTIAL_STUFFING,
                "Reuse of previously exposed credentials.",
                "Multi-factor authentication",
                "Credential reuse detection"
            );

            add(
                AttackType.PASSWORD_SPRAYING,
                "A small number of passwords tested across accounts.",
                "Account-aware monitoring",
                "Distributed failure detection"
            );

            add(
                AttackType.PHISHING,
                "Deceptive collection of authentication credentials.",
                "Passkeys",
                "Phishing-resistant authentication"
            );
        }

        private void add(
            AttackType type,
            String description,
            String... defenses
        ) {
            profiles.put(
                type,
                new AttackProfile(
                    type,
                    description,
                    List.of(defenses)
                )
            );
        }

        AttackProfile get(AttackType type) {
            AttackProfile profile = profiles.get(type);

            if (profile == null) {
                throw new IllegalArgumentException(
                    "Unknown attack classification"
                );
            }

            return profile;
        }

        void display() {
            profiles.values().forEach(profile -> {
                System.out.println(
                    "\n" + profile.type() + ": " +
                    profile.description()
                );

                profile.defenses().forEach(
                    defense -> System.out.println(" - " + defense)
                );
            });
        }
    }

    // -----------------------------------------------------
    // 3. Password policy
    // -----------------------------------------------------

    static class PasswordPolicy {

        private final int minimumLength;
        private final int maximumBytes;

        private final Set<String> commonPasswords;

        PasswordPolicy(
            int minimumLength,
            int maximumBytes,
            Set<String> commonPasswords
        ) {
            if (minimumLength < 12 || maximumBytes < minimumLength) {
                throw new IllegalArgumentException(
                    "Invalid password policy configuration"
                );
            }

            this.minimumLength = minimumLength;
            this.maximumBytes = maximumBytes;

            Set<String> normalized = new HashSet<>();

            commonPasswords.forEach(
                value -> normalized.add(value.toLowerCase())
            );

            this.commonPasswords = Set.copyOf(normalized);
        }

        List<String> validate(String password) {
            List<String> errors = new ArrayList<>();

            if (password == null) {
                return List.of("Password is required");
            }

            if (password.codePointCount(0, password.length())
                    < minimumLength) {
                errors.add("Password is too short");
            }

            if (
                password.getBytes(StandardCharsets.UTF_8).length
                    > maximumBytes
            ) {
                errors.add("Password exceeds maximum byte length");
            }

            if (!password.matches("(?s).*\\p{L}.*")) {
                errors.add("At least one letter is required");
            }

            if (!password.matches("(?s).*\\p{N}.*")) {
                errors.add("At least one digit is required");
            }

            if (commonPasswords.contains(password.toLowerCase())) {
                errors.add("Password appears in the common-password list");
            }

            return Collections.unmodifiableList(errors);
        }
    }

    // -----------------------------------------------------
    // 4. Secure credential representation
    // -----------------------------------------------------

    record PasswordCredential(
        byte[] salt,
        byte[] hash,
        int iterations,
        HashAlgorithm algorithm
    ) {
        PasswordCredential {
            salt = salt.clone();
            hash = hash.clone();

            if (iterations < 100000) {
                throw new IllegalArgumentException(
                    "Unsafe iteration count"
                );
            }

            if (algorithm != HashAlgorithm.PBKDF2_HMAC_SHA256) {
                throw new IllegalArgumentException(
                    "Unsupported credential algorithm"
                );
            }
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] hash() {
            return hash.clone();
        }
    }

    // -----------------------------------------------------
    // 5. Password hashing service
    // -----------------------------------------------------

    static class PasswordHashingService {

        private final SecureRandom secureRandom =
            new SecureRandom();

        private final int iterations;

        PasswordHashingService(int iterations) {
            if (iterations < 100000) {
                throw new IllegalArgumentException(
                    "Insufficient PBKDF2 work factor"
                );
            }

            this.iterations = iterations;
        }

        PasswordCredential create(String password)
                throws GeneralSecurityException {

            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);

            byte[] hash = derive(password, salt, iterations);

            return new PasswordCredential(
                salt,
                hash,
                iterations,
                HashAlgorithm.PBKDF2_HMAC_SHA256
            );
        }

        private byte[] derive(
            String password,
            byte[] salt,
            int workFactor
        ) throws GeneralSecurityException {

            PBEKeySpec specification = new PBEKeySpec(
                password.toCharArray(),
                salt,
                workFactor,
                256
            );

            try {
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256"
                    );

                return factory.generateSecret(specification).getEncoded();

            } finally {
                specification.clearPassword();
            }
        }

        boolean verify(
            String password,
            PasswordCredential credential
        ) throws GeneralSecurityException {

            if (
                credential.algorithm() !=
                HashAlgorithm.PBKDF2_HMAC_SHA256
            ) {
                throw new IllegalArgumentException(
                    "Unsupported password algorithm"
                );
            }

            byte[] candidate = derive(
                password,
                credential.salt(),
                credential.iterations()
            );

            return MessageDigest.isEqual(
                candidate,
                credential.hash()
            );
        }
    }

    // -----------------------------------------------------
    // 6. Account aggregate
    // -----------------------------------------------------

    static class Account {

        private final String username;
        private final PasswordCredential credential;

        private AuthenticationState state =
            AuthenticationState.ACTIVE;

        private int failedAttempts;
        private long lockedUntil;

        Account(
            String username,
            PasswordCredential credential
        ) {
            this.username = username;
            this.credential = credential;
        }

        synchronized boolean isLocked(long currentTime) {
            if (state == AuthenticationState.DISABLED) {
                return false;
            }

            if (state == AuthenticationState.TEMPORARILY_LOCKED) {
                if (currentTime < lockedUntil) {
                    return true;
                }

                state = AuthenticationState.ACTIVE;
                failedAttempts = 0;
                lockedUntil = 0;
            }

            return false;
        }

        synchronized void recordFailure(
            int maximumFailures,
            long lockDuration
        ) {
            failedAttempts++;

            if (failedAttempts >= maximumFailures) {
                state = AuthenticationState.TEMPORARILY_LOCKED;

                lockedUntil =
                    System.currentTimeMillis() + lockDuration;
            }
        }

        synchronized void recordSuccess() {
            failedAttempts = 0;
            lockedUntil = 0;
            state = AuthenticationState.ACTIVE;
        }

        synchronized void disable() {
            state = AuthenticationState.DISABLED;
        }

        String username() {
            return username;
        }

        PasswordCredential credential() {
            return credential;
        }

        synchronized AuthenticationState state() {
            return state;
        }
    }

    // -----------------------------------------------------
    // 7. Audit event model
    // -----------------------------------------------------

    record SecurityEvent(
        String username,
        String eventType,
        long timestamp
    ) {}

    static class SecurityAuditService {

        private final List<SecurityEvent> events =
            Collections.synchronizedList(new ArrayList<>());

        void record(String username, String eventType) {
            events.add(
                new SecurityEvent(
                    username,
                    eventType,
                    System.currentTimeMillis()
                )
            );
        }

        List<SecurityEvent> getEvents() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }
    }

    // -----------------------------------------------------
    // 8. Authentication service
    // -----------------------------------------------------

    static class AuthenticationService {

        private final Map<String, Account> accounts =
            new ConcurrentHashMap<>();

        private final PasswordHashingService hashingService;
        private final PasswordPolicy passwordPolicy;
        private final SecurityAuditService auditService;

        private final int maximumFailures;
        private final long lockDuration;

        AuthenticationService(
            PasswordHashingService hashingService,
            PasswordPolicy passwordPolicy,
            SecurityAuditService auditService,
            int maximumFailures,
            long lockDuration
        ) {
            if (maximumFailures < 1 || lockDuration <= 0) {
                throw new IllegalArgumentException(
                    "Invalid authentication configuration"
                );
            }

            this.hashingService = hashingService;
            this.passwordPolicy = passwordPolicy;
            this.auditService = auditService;
            this.maximumFailures = maximumFailures;
            this.lockDuration = lockDuration;
        }

        void register(
            String username,
            String password
        ) throws GeneralSecurityException {

            if (
                username == null ||
                !username.matches("[a-zA-Z0-9_.-]{3,64}")
            ) {
                throw new IllegalArgumentException(
                    "Invalid username"
                );
            }

            List<String> errors = passwordPolicy.validate(password);

            if (!errors.isEmpty()) {
                throw new IllegalArgumentException(
                    String.join("; ", errors)
                );
            }

            PasswordCredential credential =
                hashingService.create(password);

            Account account = new Account(
                username,
                credential
            );

            Account existing = accounts.putIfAbsent(
                username,
                account
            );

            if (existing != null) {
                throw new IllegalArgumentException(
                    "Account already exists"
                );
            }

            auditService.record(username, "ACCOUNT_REGISTERED");
        }

        AuthenticationResult authenticate(
            String username,
            String password
        ) throws GeneralSecurityException {

            Account account = accounts.get(username);

            if (account == null) {
                auditService.record(
                    "UNKNOWN",
                    "UNKNOWN_ACCOUNT_ATTEMPT"
                );

                return AuthenticationResult.INVALID_CREDENTIALS;
            }

            synchronized (account) {

                if (account.state() == AuthenticationState.DISABLED) {
                    return AuthenticationResult.ACCOUNT_DISABLED;
                }

                if (account.isLocked(System.currentTimeMillis())) {
                    auditService.record(
                        username,
                        "LOGIN_BLOCKED"
                    );

                    return AuthenticationResult.ACCOUNT_LOCKED;
                }

                boolean valid = hashingService.verify(
                    password,
                    account.credential()
                );

                if (!valid) {
                    account.recordFailure(
                        maximumFailures,
                        lockDuration
                    );

                    auditService.record(
                        username,
                        "LOGIN_FAILED"
                    );

                    if (
                        account.state() ==
                        AuthenticationState.TEMPORARILY_LOCKED
                    ) {
                        auditService.record(
                            username,
                            "ACCOUNT_LOCKED"
                        );

                        return AuthenticationResult.ACCOUNT_LOCKED;
                    }

                    return AuthenticationResult.INVALID_CREDENTIALS;
                }

                account.recordSuccess();

                auditService.record(
                    username,
                    "LOGIN_SUCCESS"
                );

                return AuthenticationResult.SUCCESS;
            }
        }

        void disableAccount(String username) {
            Account account = accounts.get(username);

            if (account == null) {
                throw new IllegalArgumentException(
                    "Account not found"
                );
            }

            account.disable();

            auditService.record(
                username,
                "ACCOUNT_DISABLED"
            );
        }

        int accountCount() {
            return accounts.size();
        }
    }

    // -----------------------------------------------------
    // 9. Storage policy evaluation
    // -----------------------------------------------------

    record StoragePolicy(
        HashAlgorithm algorithm,
        int iterations,
        boolean uniqueSalt,
        boolean memoryHard
    ) {}

    static class StoragePolicyEvaluator {

        static RiskLevel evaluate(StoragePolicy policy) {

            if (!policy.uniqueSalt()) {
                return RiskLevel.CRITICAL;
            }

            if (policy.algorithm() == HashAlgorithm.SHA256) {
                return RiskLevel.CRITICAL;
            }

            if (
                policy.algorithm() == HashAlgorithm.ARGON2ID &&
                policy.memoryHard()
            ) {
                return RiskLevel.LOW;
            }

            if (
                policy.algorithm() ==
                    HashAlgorithm.PBKDF2_HMAC_SHA256 &&
                policy.iterations() >= 600000
            ) {
                return RiskLevel.LOW;
            }

            if (
                policy.algorithm() == HashAlgorithm.BCRYPT &&
                policy.iterations() >= 12
            ) {
                return RiskLevel.MEDIUM;
            }

            return RiskLevel.HIGH;
        }
    }

    // -----------------------------------------------------
    // 10. Rainbow-table protection analysis
    // -----------------------------------------------------

    static class RainbowTableAnalyzer {

        static RiskLevel assess(
            boolean unsalted,
            boolean fastHash,
            boolean uniqueSalt,
            boolean memoryHard
        ) {
            if (unsalted && fastHash) {
                return RiskLevel.CRITICAL;
            }

            if (unsalted) {
                return RiskLevel.HIGH;
            }

            if (uniqueSalt && memoryHard) {
                return RiskLevel.LOW;
            }

            return uniqueSalt ? RiskLevel.MEDIUM : RiskLevel.HIGH;
        }
    }

    // -----------------------------------------------------
    // 11. Executable demonstration
    // -----------------------------------------------------

    public static void main(String[] args) {

        try {
            System.out.println(
                "RAINBOW TABLES AND PASSWORD ATTACKS"
            );

            System.out.println(
                "Enterprise Password Security Model\n"
            );

            AttackCatalog catalog = new AttackCatalog();
            catalog.display();

            System.out.println("\nSTORAGE POLICY");

            StoragePolicy legacy = new StoragePolicy(
                HashAlgorithm.SHA256,
                1,
                false,
                false
            );

            StoragePolicy modern = new StoragePolicy(
                HashAlgorithm.PBKDF2_HMAC_SHA256,
                600000,
                true,
                false
            );

            System.out.println(
                "Legacy storage: " +
                StoragePolicyEvaluator.evaluate(legacy)
            );

            System.out.println(
                "Modern storage: " +
                StoragePolicyEvaluator.evaluate(modern)
            );

            System.out.println("\nRAINBOW TABLE RISK");

            System.out.println(
                "Legacy: " +
                RainbowTableAnalyzer.assess(
                    true,
                    true,
                    false,
                    false
                )
            );

            System.out.println(
                "Modern: " +
                RainbowTableAnalyzer.assess(
                    false,
                    false,
                    true,
                    true
                )
            );

            System.out.println("\nPASSWORD AUTHENTICATION");

            PasswordPolicy passwordPolicy = new PasswordPolicy(
                12,
                1024,
                Set.of(
                    "password123!",
                    "admin123456!",
                    "welcome12345"
                )
            );

            SecurityAuditService audit =
                new SecurityAuditService();

            PasswordHashingService hashing =
                new PasswordHashingService(100000);

            AuthenticationService authentication =
                new AuthenticationService(
                    hashing,
                    passwordPolicy,
                    audit,
                    3,
                    10000
                );

            authentication.register(
                "researcher",
                "SecurePass123!"
            );

            System.out.println(
                "Valid login: " +
                authentication.authenticate(
                    "researcher",
                    "SecurePass123!"
                )
            );

            for (int i = 0; i < 3; i++) {
                System.out.println(
                    "Invalid login: " +
                    authentication.authenticate(
                        "researcher",
                        "WrongPassword123!"
                    )
                );
            }

            System.out.println("\nAUDIT EVENTS");

            for (SecurityEvent event : audit.getEvents()) {
                System.out.println(
                    event.username() + " | " +
                    event.eventType() + " | " +
                    event.timestamp()
                );
            }

            System.out.println(
                "\nRegistered accounts: " +
                authentication.accountCount()
            );

        } catch (GeneralSecurityException |
                 IllegalArgumentException exception) {

            System.err.println(
                "Security workflow error: " +
                exception.getMessage()
            );

            System.exit(1);
        }
    }
}
