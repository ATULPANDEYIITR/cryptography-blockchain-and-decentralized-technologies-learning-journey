-- ============================================================
-- RAINBOW TABLES AND PASSWORD ATTACKS
-- PostgreSQL 15+
--
-- Defensive password-security database and authentication model.
--
-- Models:
-- 1. Organizations and repositories of authentication data
-- 2. Accounts and credential metadata
-- 3. Password hashing algorithms and configurations
-- 4. Password attack classifications
-- 5. Password policy enforcement
-- 6. Authentication attempts and lockout state
-- 7. Security events and incident tracking
-- 8. Rainbow-table exposure assessments
-- 9. Security compliance and reporting
--
-- Passwords and plaintext credentials are never stored.
-- Password verifiers are supplied by a trusted application layer.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS password_security;

SET search_path TO password_security, public;

-- ============================================================
-- 1. Organizations
-- ============================================================

CREATE TABLE IF NOT EXISTS organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(150) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 2. Cryptographic algorithm registry
-- ============================================================

CREATE TABLE IF NOT EXISTS hashing_algorithms (
    algorithm_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    algorithm_name VARCHAR(40) NOT NULL UNIQUE,

    category VARCHAR(30) NOT NULL CHECK (
        category IN (
            'FAST_HASH',
            'PASSWORD_HASH',
            'MEMORY_HARD'
        )
    ),

    recommended BOOLEAN NOT NULL DEFAULT FALSE,

    minimum_work_factor INTEGER NOT NULL DEFAULT 1
        CHECK (minimum_work_factor > 0),

    supports_unique_salt BOOLEAN NOT NULL DEFAULT TRUE,

    description TEXT NOT NULL
);

INSERT INTO hashing_algorithms (
    algorithm_name,
    category,
    recommended,
    minimum_work_factor,
    supports_unique_salt,
    description
)
VALUES
(
    'SHA-256',
    'FAST_HASH',
    FALSE,
    1,
    TRUE,
    'Fast general-purpose digest. Not suitable alone for password storage.'
),
(
    'PBKDF2-HMAC-SHA256',
    'PASSWORD_HASH',
    TRUE,
    600000,
    TRUE,
    'Configurable password-based key derivation function.'
),
(
    'bcrypt',
    'PASSWORD_HASH',
    TRUE,
    12,
    TRUE,
    'Adaptive password hashing algorithm.'
),
(
    'Argon2id',
    'MEMORY_HARD',
    TRUE,
    1,
    TRUE,
    'Memory-hard password hashing algorithm.'
)
ON CONFLICT (algorithm_name) DO NOTHING;

-- ============================================================
-- 3. User accounts
-- ============================================================

CREATE TABLE IF NOT EXISTS accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    username VARCHAR(64) NOT NULL,

    email VARCHAR(254) NOT NULL,

    account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (
            account_status IN (
                'ACTIVE',
                'LOCKED',
                'DISABLED',
                'PENDING'
            )
        ),

    failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0),

    locked_until TIMESTAMPTZ,

    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_login_at TIMESTAMPTZ,

    UNIQUE (organization_id, username),
    UNIQUE (organization_id, email),

    UNIQUE (account_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_status
    ON accounts (organization_id, account_status);

-- ============================================================
-- 4. Password credentials
-- ============================================================

CREATE TABLE IF NOT EXISTS password_credentials (
    credential_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT NOT NULL UNIQUE
        REFERENCES accounts(account_id),

    algorithm_id SMALLINT NOT NULL
        REFERENCES hashing_algorithms(algorithm_id),

    password_hash TEXT NOT NULL,

    salt BYTEA NOT NULL,

    work_factor INTEGER NOT NULL CHECK (work_factor > 0),

    memory_cost_kib INTEGER NOT NULL DEFAULT 0
        CHECK (memory_cost_kib >= 0),

    parallelism INTEGER NOT NULL DEFAULT 1
        CHECK (parallelism > 0),

    credential_version INTEGER NOT NULL DEFAULT 1
        CHECK (credential_version > 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_salt_minimum
        CHECK (octet_length(salt) >= 16),

    CONSTRAINT nonempty_password_verifier
        CHECK (length(password_hash) > 0)
);

COMMENT ON TABLE password_credentials IS
'Stores password verifiers, unique random salts and work parameters. Never stores plaintext passwords.';

-- ============================================================
-- 5. Password policies
-- ============================================================

CREATE TABLE IF NOT EXISTS password_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    policy_name VARCHAR(120) NOT NULL,

    minimum_length INTEGER NOT NULL DEFAULT 12
        CHECK (minimum_length >= 12),

    maximum_bytes INTEGER NOT NULL DEFAULT 1024
        CHECK (maximum_bytes >= minimum_length),

    require_mfa BOOLEAN NOT NULL DEFAULT TRUE,

    reject_common_passwords BOOLEAN NOT NULL DEFAULT TRUE,

    reject_breached_passwords BOOLEAN NOT NULL DEFAULT TRUE,

    require_unique_salt BOOLEAN NOT NULL DEFAULT TRUE,

    minimum_work_factor INTEGER NOT NULL DEFAULT 600000
        CHECK (minimum_work_factor > 0),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (organization_id, policy_name)
);

-- ============================================================
-- 6. Attack classification
-- ============================================================

CREATE TABLE IF NOT EXISTS attack_types (
    attack_type_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    attack_code VARCHAR(40) NOT NULL UNIQUE,

    attack_name VARCHAR(100) NOT NULL,

    description TEXT NOT NULL,

    primary_defense TEXT NOT NULL
);

INSERT INTO attack_types (
    attack_code,
    attack_name,
    description,
    primary_defense
)
VALUES
(
    'DICTIONARY',
    'Dictionary attack',
    'Testing likely password candidates against password verifiers.',
    'Adaptive password hashing and common-password screening.'
),
(
    'BRUTE_FORCE',
    'Brute-force attack',
    'Exhaustive enumeration of possible password candidates.',
    'Rate limiting and progressive authentication delays.'
),
(
    'RAINBOW_TABLE',
    'Rainbow-table attack',
    'Precomputed hash-chain lookup designed to reduce repeated computation.',
    'Unique random salts and adaptive password hashing.'
),
(
    'CREDENTIAL_STUFFING',
    'Credential stuffing',
    'Reuse of previously compromised username and password combinations.',
    'MFA and credential reuse detection.'
),
(
    'PASSWORD_SPRAYING',
    'Password spraying',
    'Attempts using a limited set of passwords across multiple accounts.',
    'Distributed authentication monitoring.'
),
(
    'PHISHING',
    'Phishing',
    'Deceptive collection of user authentication credentials.',
    'Phishing-resistant authentication.'
)
ON CONFLICT (attack_code) DO NOTHING;

-- ============================================================
-- 7. Security assessments
-- ============================================================

CREATE TABLE IF NOT EXISTS security_assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    attack_type_id SMALLINT NOT NULL
        REFERENCES attack_types(attack_type_id),

    assessment_name VARCHAR(150) NOT NULL,

    hash_algorithm VARCHAR(40) NOT NULL,

    uses_unique_salts BOOLEAN NOT NULL,

    uses_adaptive_hashing BOOLEAN NOT NULL,

    uses_memory_hard_hashing BOOLEAN NOT NULL DEFAULT FALSE,

    risk_level VARCHAR(20) NOT NULL
        CHECK (
            risk_level IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    findings TEXT NOT NULL,

    assessed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assessment_risk
    ON security_assessments (
        organization_id,
        risk_level,
        assessed_at DESC
    );

-- ============================================================
-- 8. Authentication attempts
-- ============================================================

CREATE TABLE IF NOT EXISTS authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT
        REFERENCES accounts(account_id),

    username_submitted VARCHAR(64) NOT NULL,

    source_identifier_hash TEXT,

    result VARCHAR(20) NOT NULL
        CHECK (
            result IN (
                'SUCCESS',
                'FAILURE',
                'LOCKED',
                'BLOCKED'
            )
        ),

    failure_category VARCHAR(40),

    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    request_id UUID UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_attempt_account_time
    ON authentication_attempts (
        account_id,
        attempted_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_attempt_failure_time
    ON authentication_attempts (
        result,
        attempted_at DESC
    );

-- ============================================================
-- 9. Security incidents
-- ============================================================

CREATE TABLE IF NOT EXISTS security_incidents (
    incident_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    attack_type_id SMALLINT NOT NULL
        REFERENCES attack_types(attack_type_id),

    account_id BIGINT
        REFERENCES accounts(account_id),

    severity VARCHAR(20) NOT NULL
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    incident_status VARCHAR(20) NOT NULL DEFAULT 'OPEN'
        CHECK (
            incident_status IN (
                'OPEN',
                'INVESTIGATING',
                'CONTAINED',
                'CLOSED'
            )
        ),

    description TEXT NOT NULL,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    resolved_at TIMESTAMPTZ,

    CHECK (
        resolved_at IS NULL OR resolved_at >= detected_at
    )
);

-- ============================================================
-- 10. Database-level credential validation
-- ============================================================

CREATE OR REPLACE FUNCTION validate_password_credential()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    selected_algorithm hashing_algorithms%ROWTYPE;
BEGIN
    SELECT *
    INTO selected_algorithm
    FROM hashing_algorithms
    WHERE algorithm_id = NEW.algorithm_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown password hashing algorithm';
    END IF;

    IF NOT selected_algorithm.supports_unique_salt THEN
        RAISE EXCEPTION 'Algorithm configuration does not support unique salts';
    END IF;

    IF NEW.work_factor < selected_algorithm.minimum_work_factor THEN
        RAISE EXCEPTION
            'Work factor % is below the algorithm minimum %',
            NEW.work_factor,
            selected_algorithm.minimum_work_factor;
    END IF;

    IF selected_algorithm.category = 'FAST_HASH' THEN
        RAISE EXCEPTION
            'Fast general-purpose hashes cannot be used as password storage algorithms';
    END IF;

    NEW.updated_at = CURRENT_TIMESTAMP;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_credential
    ON password_credentials;

CREATE TRIGGER trg_validate_credential
BEFORE INSERT OR UPDATE
ON password_credentials
FOR EACH ROW
EXECUTE FUNCTION validate_password_credential();

-- ============================================================
-- 11. Authentication state management
-- ============================================================

CREATE OR REPLACE FUNCTION record_authentication_result(
    p_account_id BIGINT,
    p_success BOOLEAN,
    p_maximum_failures INTEGER DEFAULT 5,
    p_lock_minutes INTEGER DEFAULT 15
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    selected_account accounts%ROWTYPE;
    new_failure_count INTEGER;
BEGIN
    IF p_maximum_failures < 1 OR p_lock_minutes < 1 THEN
        RAISE EXCEPTION 'Invalid authentication policy parameters';
    END IF;

    SELECT *
    INTO selected_account
    FROM accounts
    WHERE account_id = p_account_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found';
    END IF;

    IF selected_account.account_status = 'DISABLED' THEN
        RETURN 'DISABLED';
    END IF;

    IF selected_account.account_status = 'LOCKED'
       AND selected_account.locked_until > CURRENT_TIMESTAMP THEN
        RETURN 'LOCKED';
    END IF;

    IF p_success THEN
        UPDATE accounts
        SET
            failed_attempts = 0,
            account_status = 'ACTIVE',
            locked_until = NULL,
            last_login_at = CURRENT_TIMESTAMP
        WHERE account_id = p_account_id;

        INSERT INTO authentication_attempts (
            account_id,
            username_submitted,
            result
        )
        VALUES (
            p_account_id,
            selected_account.username,
            'SUCCESS'
        );

        RETURN 'SUCCESS';
    END IF;

    new_failure_count := selected_account.failed_attempts + 1;

    IF new_failure_count >= p_maximum_failures THEN
        UPDATE accounts
        SET
            failed_attempts = new_failure_count,
            account_status = 'LOCKED',
            locked_until = CURRENT_TIMESTAMP
                + make_interval(mins => p_lock_minutes)
        WHERE account_id = p_account_id;

        INSERT INTO authentication_attempts (
            account_id,
            username_submitted,
            result,
            failure_category
        )
        VALUES (
            p_account_id,
            selected_account.username,
            'LOCKED',
            'MAXIMUM_FAILURES'
        );

        RETURN 'LOCKED';
    END IF;

    UPDATE accounts
    SET failed_attempts = new_failure_count
    WHERE account_id = p_account_id;

    INSERT INTO authentication_attempts (
        account_id,
        username_submitted,
        result,
        failure_category
    )
    VALUES (
        p_account_id,
        selected_account.username,
        'FAILURE',
        'INVALID_CREDENTIALS'
    );

    RETURN 'FAILURE';
END;
$$;

-- ============================================================
-- 12. Rainbow-table risk evaluation
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_rainbow_table_risk(
    p_unique_salt BOOLEAN,
    p_adaptive_hashing BOOLEAN,
    p_memory_hard BOOLEAN
)
RETURNS VARCHAR(20)
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF NOT p_unique_salt AND NOT p_adaptive_hashing THEN
        RETURN 'CRITICAL';
    END IF;

    IF NOT p_unique_salt THEN
        RETURN 'HIGH';
    END IF;

    IF p_unique_salt AND p_memory_hard THEN
        RETURN 'LOW';
    END IF;

    IF p_unique_salt AND p_adaptive_hashing THEN
        RETURN 'LOW';
    END IF;

    RETURN 'MEDIUM';
END;
$$;

-- ============================================================
-- 13. Credential security assessment view
-- ============================================================

CREATE OR REPLACE VIEW credential_security_report AS
SELECT
    a.organization_id,
    a.account_id,
    a.username,
    a.account_status,
    a.mfa_enabled,
    h.algorithm_name,
    h.category AS algorithm_category,
    h.recommended,
    c.work_factor,
    octet_length(c.salt) AS salt_bytes,
    CASE
        WHEN h.category = 'FAST_HASH'
            THEN 'CRITICAL'
        WHEN NOT h.recommended
            THEN 'HIGH'
        WHEN c.work_factor < h.minimum_work_factor
            THEN 'HIGH'
        ELSE 'LOW'
    END AS storage_risk
FROM accounts a
JOIN password_credentials c
    ON c.account_id = a.account_id
JOIN hashing_algorithms h
    ON h.algorithm_id = c.algorithm_id;

-- ============================================================
-- 14. Authentication failure aggregation
-- ============================================================

CREATE OR REPLACE VIEW authentication_failure_report AS
SELECT
    organization_id,
    username,
    account_status,
    failed_attempts,
    locked_until
FROM accounts
WHERE
    failed_attempts > 0
    OR account_status = 'LOCKED';

-- ============================================================
-- 15. Attack incident reporting
-- ============================================================

CREATE OR REPLACE VIEW attack_incident_report AS
SELECT
    i.incident_id,
    o.organization_name,
    t.attack_name,
    i.severity,
    i.incident_status,
    i.description,
    i.detected_at,
    i.resolved_at
FROM security_incidents i
JOIN organizations o
    ON o.organization_id = i.organization_id
JOIN attack_types t
    ON t.attack_type_id = i.attack_type_id;

-- ============================================================
-- 16. Sample organizational data
-- ============================================================

INSERT INTO organizations (organization_name)
VALUES ('Research Security Laboratory')
ON CONFLICT (organization_name) DO NOTHING;

INSERT INTO password_policies (
    organization_id,
    policy_name,
    minimum_length,
    maximum_bytes,
    require_mfa,
    reject_common_passwords,
    reject_breached_passwords,
    require_unique_salt,
    minimum_work_factor
)
SELECT
    organization_id,
    'Enterprise Password Policy',
    12,
    1024,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    600000
FROM organizations
WHERE organization_name = 'Research Security Laboratory'
ON CONFLICT (organization_id, policy_name) DO NOTHING;

-- ============================================================
-- 17. Sample accounts
-- ============================================================

INSERT INTO accounts (
    organization_id,
    username,
    email,
    mfa_enabled
)
SELECT
    organization_id,
    'alice',
    'alice@example.org',
    TRUE
FROM organizations
WHERE organization_name = 'Research Security Laboratory'
ON CONFLICT DO NOTHING;

INSERT INTO accounts (
    organization_id,
    username,
    email,
    mfa_enabled
)
SELECT
    organization_id,
    'bob',
    'bob@example.org',
    FALSE
FROM organizations
WHERE organization_name = 'Research Security Laboratory'
ON CONFLICT DO NOTHING;

INSERT INTO accounts (
    organization_id,
    username,
    email,
    mfa_enabled
)
SELECT
    organization_id,
    'charlie',
    'charlie@example.org',
    TRUE
FROM organizations
WHERE organization_name = 'Research Security Laboratory'
ON CONFLICT DO NOTHING;

-- ============================================================
-- 18. Sample credentials
--
-- These are synthetic verifier strings, not usable passwords.
-- A real application supplies a properly derived verifier.
-- ============================================================

INSERT INTO password_credentials (
    account_id,
    algorithm_id,
    password_hash,
    salt,
    work_factor
)
SELECT
    a.account_id,
    h.algorithm_id,
    'synthetic-pbkdf2-verifier-alice',
    decode('00112233445566778899aabbccddeeff', 'hex'),
    600000
FROM accounts a
CROSS JOIN hashing_algorithms h
WHERE
    a.username = 'alice'
    AND h.algorithm_name = 'PBKDF2-HMAC-SHA256'
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO password_credentials (
    account_id,
    algorithm_id,
    password_hash,
    salt,
    work_factor
)
SELECT
    a.account_id,
    h.algorithm_id,
    'synthetic-pbkdf2-verifier-bob',
    decode('10112233445566778899aabbccddeeff', 'hex'),
    600000
FROM accounts a
CROSS JOIN hashing_algorithms h
WHERE
    a.username = 'bob'
    AND h.algorithm_name = 'PBKDF2-HMAC-SHA256'
ON CONFLICT (account_id) DO NOTHING;

-- ============================================================
-- 19. Sample rainbow-table risk assessments
-- ============================================================

INSERT INTO security_assessments (
    organization_id,
    attack_type_id,
    assessment_name,
    hash_algorithm,
    uses_unique_salts,
    uses_adaptive_hashing,
    uses_memory_hard_hashing,
    risk_level,
    findings
)
SELECT
    o.organization_id,
    t.attack_type_id,
    'Legacy unsalted SHA-256 storage',
    'SHA-256',
    FALSE,
    FALSE,
    FALSE,
    'CRITICAL',
    'Fast unsalted hashes allow reusable precomputed hash lookups.'
FROM organizations o
CROSS JOIN attack_types t
WHERE
    o.organization_name = 'Research Security Laboratory'
    AND t.attack_code = 'RAINBOW_TABLE';

INSERT INTO security_assessments (
    organization_id,
    attack_type_id,
    assessment_name,
    hash_algorithm,
    uses_unique_salts,
    uses_adaptive_hashing,
    uses_memory_hard_hashing,
    risk_level,
    findings
)
SELECT
    o.organization_id,
    t.attack_type_id,
    'Modern salted password storage',
    'Argon2id',
    TRUE,
    TRUE,
    TRUE,
    'LOW',
    'Unique salts and memory-hard derivation prevent reusable rainbow-table lookups.'
FROM organizations o
CROSS JOIN attack_types t
WHERE
    o.organization_name = 'Research Security Laboratory'
    AND t.attack_code = 'RAINBOW_TABLE';

-- ============================================================
-- 20. Sample security incidents
-- ============================================================

INSERT INTO security_incidents (
    organization_id,
    attack_type_id,
    account_id,
    severity,
    description
)
SELECT
    o.organization_id,
    t.attack_type_id,
    a.account_id,
    'HIGH',
    'Repeated authentication failures detected for the account.'
FROM organizations o
JOIN attack_types t
    ON t.attack_code = 'BRUTE_FORCE'
JOIN accounts a
    ON a.organization_id = o.organization_id
WHERE
    o.organization_name = 'Research Security Laboratory'
    AND a.username = 'bob';

-- ============================================================
-- 21. Transactional authentication demonstration
-- ============================================================

DO $$
DECLARE
    alice_id BIGINT;
    authentication_result TEXT;
BEGIN
    SELECT account_id
    INTO alice_id
    FROM accounts
    WHERE username = 'alice';

    authentication_result := record_authentication_result(
        alice_id,
        TRUE,
        5,
        15
    );

    RAISE NOTICE 'Authentication result: %',
        authentication_result;
END;
$$;

-- ============================================================
-- 22. Failure handling demonstration
-- ============================================================

DO $$
DECLARE
    bob_id BIGINT;
    authentication_result TEXT;
    attempt INTEGER;
BEGIN
    SELECT account_id
    INTO bob_id
    FROM accounts
    WHERE username = 'bob';

    FOR attempt IN 1..5 LOOP
        authentication_result := record_authentication_result(
            bob_id,
            FALSE,
            5,
            15
        );

        RAISE NOTICE
            'Attempt %: %',
            attempt,
            authentication_result;
    END LOOP;
END;
$$;

COMMIT;

-- ============================================================
-- 23. Retrieval queries
-- ============================================================

SELECT
    username,
    account_status,
    mfa_enabled,
    failed_attempts
FROM password_security.accounts
ORDER BY username;

-- ============================================================
-- 24. Password storage security reporting
-- ============================================================

SELECT
    username,
    algorithm_name,
    algorithm_category,
    work_factor,
    salt_bytes,
    storage_risk
FROM password_security.credential_security_report
ORDER BY storage_risk DESC, username;

-- ============================================================
-- 25. Rainbow-table eligibility assessment
-- ============================================================

SELECT
    evaluate_rainbow_table_risk(
        FALSE,
        TRUE,
        TRUE
    ) AS salted_adaptive_hash_risk;

SELECT
    evaluate_rainbow_table_risk(
        FALSE,
        TRUE,
        FALSE
    ) AS unsalted_adaptive_hash_risk;

SELECT
    evaluate_rainbow_table_risk(
        FALSE,
        FALSE,
        TRUE
    ) AS salted_memory_hard_hash_risk;

-- ============================================================
-- 26. Attack classification retrieval
-- ============================================================

SELECT
    attack_code,
    attack_name,
    description,
    primary_defense
FROM password_security.attack_types
ORDER BY attack_type_id;

-- ============================================================
-- 27. Authentication failure reporting
-- ============================================================

SELECT
    username,
    account_status,
    failed_attempts,
    locked_until
FROM password_security.authentication_failure_report
ORDER BY failed_attempts DESC;

-- ============================================================
-- 28. Incident aggregation
-- ============================================================

SELECT
    attack_name,
    severity,
    incident_status,
    COUNT(*) AS incident_count
FROM password_security.attack_incident_report
GROUP BY
    attack_name,
    severity,
    incident_status
ORDER BY incident_count DESC;

-- ============================================================
-- 29. Recent authentication activity
-- ============================================================

SELECT
    username_submitted,
    result,
    failure_category,
    attempted_at
FROM password_security.authentication_attempts
WHERE attempted_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
ORDER BY attempted_at DESC;

-- ============================================================
-- 30. Organization-level security assessment
-- ============================================================

SELECT
    o.organization_name,
    s.risk_level,
    COUNT(*) AS assessment_count
FROM password_security.security_assessments s
JOIN password_security.organizations o
    ON o.organization_id = s.organization_id
GROUP BY
    o.organization_name,
    s.risk_level
ORDER BY
    o.organization_name,
    s.risk_level;

-- ============================================================
-- 31. Password policy retrieval
-- ============================================================

SELECT
    policy_name,
    minimum_length,
    maximum_bytes,
    require_mfa,
    reject_common_passwords,
    reject_breached_passwords,
    require_unique_salt,
    minimum_work_factor
FROM password_security.password_policies
WHERE enabled = TRUE;

-- ============================================================
-- 32. Security incident retrieval
-- ============================================================

SELECT *
FROM password_security.attack_incident_report
ORDER BY detected_at DESC;

-- ============================================================
-- END OF PASSWORD SECURITY DATABASE
-- ============================================================
