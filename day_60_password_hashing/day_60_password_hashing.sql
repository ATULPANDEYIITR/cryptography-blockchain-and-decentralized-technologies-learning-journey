/*
===============================================================================
PASSWORD HASHING AND AUTHENTICATION DATABASE
===============================================================================

Database: PostgreSQL 14+
Schema: password_security

Credential algorithm:
    PBKDF2-HMAC-SHA256

Application hashing parameters:
    Iterations: 600000
    Salt:       16 random bytes
    Verifier:   32 bytes

Database responsibilities:
    1. Account and credential metadata.
    2. Credential history.
    3. Authentication event auditing.
    4. Account throttling.
    5. Credential migration tracking.
    6. Referential and structural integrity.
    7. Security reporting.

IMPORTANT:
Password derivation and password comparison belong in the authentication
application, not in ordinary SQL statements.

The database never stores submitted plaintext passwords.
Credential sample values are precomputed test records.
The application must generate salts using a cryptographically secure
random-number generator and calculate PBKDF2 outside the database.

===============================================================================
*/

DROP SCHEMA IF EXISTS password_security CASCADE;

CREATE SCHEMA password_security;

SET search_path TO password_security, public;


/* ---------------------------------------------------------------------------
   1. DOMAIN TYPES
--------------------------------------------------------------------------- */

CREATE TYPE account_state AS ENUM (
    'active',
    'disabled',
    'suspended'
);


/* ---------------------------------------------------------------------------
   2. ACCOUNTS
--------------------------------------------------------------------------- */

CREATE TABLE accounts (
    account_id UUID PRIMARY KEY,

    username VARCHAR(64) NOT NULL,

    display_name VARCHAR(120) NOT NULL,

    status account_state NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        length(username) BETWEEN 3 AND 64
    ),

    CHECK (
        length(display_name) BETWEEN 1 AND 120
    )
);

-- Username comparison is case-insensitive without requiring an extension.
CREATE UNIQUE INDEX uq_accounts_username_lower
    ON accounts (lower(username));

CREATE INDEX idx_accounts_status
    ON accounts (status);


/* ---------------------------------------------------------------------------
   3. CURRENT PASSWORD CREDENTIALS
--------------------------------------------------------------------------- */

CREATE TABLE password_credentials (
    credential_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id UUID NOT NULL UNIQUE,

    algorithm VARCHAR(40) NOT NULL
        DEFAULT 'pbkdf2-sha256',

    iterations INTEGER NOT NULL,

    salt BYTEA NOT NULL,

    verifier BYTEA NOT NULL,

    credential_version INTEGER NOT NULL DEFAULT 1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    must_change BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT fk_credentials_account
        FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    CONSTRAINT chk_supported_algorithm
        CHECK (algorithm = 'pbkdf2-sha256'),

    /*
     * The lower bound permits historical credentials to be represented
     * during controlled migration. New credentials must use 600000.
     */
    CONSTRAINT chk_iteration_count
        CHECK (iterations BETWEEN 100000 AND 2000000),

    CONSTRAINT chk_salt_length
        CHECK (octet_length(salt) BETWEEN 16 AND 64),

    CONSTRAINT chk_verifier_length
        CHECK (octet_length(verifier) = 32),

    CONSTRAINT chk_credential_version
        CHECK (credential_version > 0)
);


/* ---------------------------------------------------------------------------
   4. PASSWORD HISTORY
--------------------------------------------------------------------------- */

CREATE TABLE password_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id UUID NOT NULL,

    algorithm VARCHAR(40) NOT NULL,

    iterations INTEGER NOT NULL,

    salt BYTEA NOT NULL,

    verifier BYTEA NOT NULL,

    archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_password_history_account
        FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    CHECK (algorithm = 'pbkdf2-sha256'),

    CHECK (iterations BETWEEN 100000 AND 2000000),

    CHECK (octet_length(salt) BETWEEN 16 AND 64),

    CHECK (octet_length(verifier) = 32)
);

CREATE INDEX idx_password_history_account
    ON password_history(account_id, archived_at DESC);


/* ---------------------------------------------------------------------------
   5. AUTOMATIC CREDENTIAL HISTORY ARCHIVING
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION archive_previous_credential()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        OLD.algorithm,
        OLD.iterations,
        OLD.salt,
        OLD.verifier
    ) IS DISTINCT FROM ROW(
        NEW.algorithm,
        NEW.iterations,
        NEW.salt,
        NEW.verifier
    ) THEN

        INSERT INTO password_history (
            account_id,
            algorithm,
            iterations,
            salt,
            verifier
        )
        VALUES (
            OLD.account_id,
            OLD.algorithm,
            OLD.iterations,
            OLD.salt,
            OLD.verifier
        );

        NEW.credential_version := OLD.credential_version + 1;
        NEW.updated_at := CURRENT_TIMESTAMP;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_archive_previous_credential
BEFORE UPDATE ON password_credentials
FOR EACH ROW
EXECUTE FUNCTION archive_previous_credential();


/* ---------------------------------------------------------------------------
   6. CREDENTIAL VERSION EVALUATION
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION credential_requires_rehash(
    p_iterations INTEGER
)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT p_iterations < 600000;
$$;


/* ---------------------------------------------------------------------------
   7. AUTHENTICATION THROTTLING STATE
--------------------------------------------------------------------------- */

CREATE TABLE auth_throttle_state (
    account_id UUID PRIMARY KEY,

    failed_attempts INTEGER NOT NULL DEFAULT 0,

    window_started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    locked_until TIMESTAMPTZ,

    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_throttle_account
        FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    CHECK (failed_attempts >= 0)
);

-- Supports efficient retrieval of currently locked accounts.
CREATE INDEX idx_active_account_locks
    ON auth_throttle_state(locked_until)
    WHERE locked_until IS NOT NULL;


/* ---------------------------------------------------------------------------
   8. AUTHENTICATION AUDIT EVENTS
--------------------------------------------------------------------------- */

CREATE TABLE authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id UUID NOT NULL,

    succeeded BOOLEAN NOT NULL,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    /*
     * Optional HMAC-based source identifier.
     * Do not store raw passwords, password fragments or unnecessary
     * personal information in audit records.
     */
    source_tag_hash BYTEA,

    failure_category VARCHAR(40),

    CONSTRAINT fk_attempt_account
        FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE,

    CHECK (
        source_tag_hash IS NULL
        OR octet_length(source_tag_hash) = 32
    ),

    CHECK (
        failure_category IS NULL
        OR failure_category IN (
            'invalid_credentials',
            'account_disabled',
            'account_locked',
            'policy_failure'
        )
    ),

    CHECK (
        succeeded = FALSE
        OR failure_category IS NULL
    )
);

CREATE INDEX idx_auth_attempt_account_time
    ON authentication_attempts (
        account_id,
        occurred_at DESC
    );

CREATE INDEX idx_auth_attempt_time
    ON authentication_attempts(occurred_at DESC);


/* ---------------------------------------------------------------------------
   9. TRANSACTIONAL THROTTLING TRIGGER
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION update_authentication_throttle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF NEW.succeeded THEN

        INSERT INTO auth_throttle_state (
            account_id,
            failed_attempts,
            window_started_at,
            locked_until,
            last_attempt_at
        )
        VALUES (
            NEW.account_id,
            0,
            NEW.occurred_at,
            NULL,
            NEW.occurred_at
        )
        ON CONFLICT (account_id)
        DO UPDATE SET
            failed_attempts = 0,
            window_started_at = NEW.occurred_at,
            locked_until = NULL,
            last_attempt_at = NEW.occurred_at;

    ELSE

        INSERT INTO auth_throttle_state (
            account_id,
            failed_attempts,
            window_started_at,
            locked_until,
            last_attempt_at
        )
        VALUES (
            NEW.account_id,
            1,
            NEW.occurred_at,
            NULL,
            NEW.occurred_at
        )
        ON CONFLICT (account_id)
        DO UPDATE SET

            failed_attempts =
                CASE
                    WHEN NEW.occurred_at -
                         auth_throttle_state.window_started_at
                         > INTERVAL '15 minutes'
                    THEN 1
                    ELSE auth_throttle_state.failed_attempts + 1
                END,

            window_started_at =
                CASE
                    WHEN NEW.occurred_at -
                         auth_throttle_state.window_started_at
                         > INTERVAL '15 minutes'
                    THEN NEW.occurred_at
                    ELSE auth_throttle_state.window_started_at
                END,

            locked_until =
                CASE
                    WHEN NEW.occurred_at -
                         auth_throttle_state.window_started_at
                         > INTERVAL '15 minutes'
                    THEN NULL

                    WHEN auth_throttle_state.failed_attempts + 1 >= 5
                    THEN
                        NEW.occurred_at
                        +
                        LEAST(
                            900,
                            60 * POWER(
                                2,
                                GREATEST(
                                    auth_throttle_state.failed_attempts
                                    + 1 - 5,
                                    0
                                )
                            )
                        )::INTEGER * INTERVAL '1 second'

                    ELSE auth_throttle_state.locked_until
                END,

            last_attempt_at = NEW.occurred_at;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_update_authentication_throttle
AFTER INSERT ON authentication_attempts
FOR EACH ROW
EXECUTE FUNCTION update_authentication_throttle();


/* ---------------------------------------------------------------------------
   10. LOGIN ELIGIBILITY
--------------------------------------------------------------------------- */

CREATE OR REPLACE FUNCTION authentication_allowed(
    p_account_id UUID
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM accounts a
        LEFT JOIN auth_throttle_state t
            ON t.account_id = a.account_id
        WHERE a.account_id = p_account_id
          AND a.status = 'active'
          AND (
              t.account_id IS NULL
              OR t.locked_until IS NULL
              OR t.locked_until <= CURRENT_TIMESTAMP
          )
    );
$$;


/* ---------------------------------------------------------------------------
   11. TRANSACTIONAL AUDIT PROCEDURE
--------------------------------------------------------------------------- */

CREATE OR REPLACE PROCEDURE record_authentication_attempt(
    p_account_id UUID,
    p_succeeded BOOLEAN,
    p_source_tag_hash BYTEA DEFAULT NULL,
    p_failure_category VARCHAR(40) DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM accounts
        WHERE account_id = p_account_id
    ) THEN
        RAISE EXCEPTION 'Unknown account identifier.';
    END IF;

    IF p_succeeded AND p_failure_category IS NOT NULL THEN
        RAISE EXCEPTION
            'Successful authentication cannot have a failure category.';
    END IF;

    INSERT INTO authentication_attempts (
        account_id,
        succeeded,
        source_tag_hash,
        failure_category
    )
    VALUES (
        p_account_id,
        p_succeeded,
        p_source_tag_hash,
        p_failure_category
    );

END;
$$;


/* ---------------------------------------------------------------------------
   12. SAMPLE ACCOUNTS
--------------------------------------------------------------------------- */

INSERT INTO accounts (
    account_id,
    username,
    display_name,
    status
)
VALUES
(
    '10000000-0000-0000-0000-000000000001',
    'alex.developer',
    'Alex Developer',
    'active'
),
(
    '10000000-0000-0000-0000-000000000002',
    'sam.legacy',
    'Sam Legacy',
    'active'
),
(
    '10000000-0000-0000-0000-000000000003',
    'disabled.operations',
    'Disabled Operations Account',
    'disabled'
);


/* ---------------------------------------------------------------------------
   13. SAMPLE CREDENTIALS
--------------------------------------------------------------------------- */

/*
 * These are precomputed PBKDF2 records.
 * Their original passwords are not included in this SQL script.
 */

INSERT INTO password_credentials (
    account_id,
    algorithm,
    iterations,
    salt,
    verifier
)
VALUES
(
    '10000000-0000-0000-0000-000000000001',
    'pbkdf2-sha256',
    600000,
    decode('235cbfd0f1448a63ec90d130a62d391e', 'hex'),
    decode(
        '6b2c24527ce11bb24ed0181bd3b202606642e294df9ff6137e6c2e3dcc40a1a7',
        'hex'
    )
),
(
    '10000000-0000-0000-0000-000000000002',
    'pbkdf2-sha256',
    120000,
    decode('414e1dee15fea477677e310205be135b', 'hex'),
    decode(
        '7344b405511facd4896c14634b5d2d9068783d707971139f21f746be429c10ed',
        'hex'
    )
),
(
    '10000000-0000-0000-0000-000000000003',
    'pbkdf2-sha256',
    600000,
    decode('92070c316f7478b163a5d4c4b7f237e8', 'hex'),
    decode(
        '5a77bf863d3e178b7943eb161d8e7f98bc31aabb7c24165454706c260cdbddc6',
        'hex'
    )
);


/* ---------------------------------------------------------------------------
   14. LEGACY CREDENTIAL MIGRATION
--------------------------------------------------------------------------- */

/*
 * Represents an application-side successful authentication.
 *
 * The application has already verified the legacy password and computed
 * the new verifier using:
 *
 * - The same submitted password
 * - A newly generated random salt
 * - 600000 PBKDF2-HMAC-SHA256 iterations
 *
 * All credential components are replaced atomically.
 *
 * The trigger archives the previous credential automatically.
 */

BEGIN;

UPDATE password_credentials
SET
    iterations = 600000,
    salt = decode('b6f182511f9d37fda1948420967ba974', 'hex'),
    verifier = decode(
        '484cc977275d1b92d925a5a3c1caad9a281050da77569763bd46a16f69675111',
        'hex'
    )
WHERE account_id =
    '10000000-0000-0000-0000-000000000002';

COMMIT;


/* ---------------------------------------------------------------------------
   15. AUTHENTICATION EVENT FIXTURES
--------------------------------------------------------------------------- */

-- Successful authentication resets any previous failure state.
CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000001',
    TRUE
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000001',
    FALSE,
    NULL,
    'invalid_credentials'
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000001',
    TRUE
);

-- Five failed attempts activate account throttling.
CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000002',
    FALSE,
    NULL,
    'invalid_credentials'
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000002',
    FALSE,
    NULL,
    'invalid_credentials'
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000002',
    FALSE,
    NULL,
    'invalid_credentials'
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000002',
    FALSE,
    NULL,
    'invalid_credentials'
);

CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000002',
    FALSE,
    NULL,
    'invalid_credentials'
);

-- Disabled account activity is independently recorded.
CALL record_authentication_attempt(
    '10000000-0000-0000-0000-000000000003',
    FALSE,
    NULL,
    'account_disabled'
);


/* ---------------------------------------------------------------------------
   16. CREDENTIAL INSPECTION VIEW
--------------------------------------------------------------------------- */

CREATE OR REPLACE VIEW credential_security_status AS
SELECT
    a.account_id,
    a.username,
    a.status,

    c.algorithm,
    c.iterations,

    octet_length(c.salt) AS salt_bytes,
    octet_length(c.verifier) AS verifier_bytes,

    c.credential_version,

    credential_requires_rehash(c.iterations)
        AS requires_rehash,

    c.must_change,

    c.created_at,
    c.updated_at

FROM accounts a
JOIN password_credentials c
    ON c.account_id = a.account_id;


/* ---------------------------------------------------------------------------
   17. AUTHENTICATION STATUS VIEW
--------------------------------------------------------------------------- */

CREATE OR REPLACE VIEW account_authentication_status AS
SELECT
    a.account_id,
    a.username,
    a.status,

    COALESCE(t.failed_attempts, 0) AS failed_attempts,

    t.window_started_at,
    t.locked_until,
    t.last_attempt_at,

    authentication_allowed(a.account_id) AS can_authenticate

FROM accounts a
LEFT JOIN auth_throttle_state t
    ON t.account_id = a.account_id;


/* ---------------------------------------------------------------------------
   18. RETRIEVAL AND VALIDATION
--------------------------------------------------------------------------- */

-- Inspect all current credential configurations.
SELECT
    account_id,
    username,
    algorithm,
    iterations,
    salt_bytes,
    verifier_bytes,
    requires_rehash,
    credential_version
FROM credential_security_status
ORDER BY username;


-- Verify minimum salt and verifier structure.
SELECT
    account_id,
    username,
    salt_bytes >= 16 AS valid_salt,
    verifier_bytes = 32 AS valid_verifier
FROM credential_security_status;


-- Find credentials requiring computational-cost upgrades.
SELECT
    username,
    iterations,
    requires_rehash
FROM credential_security_status
WHERE requires_rehash = TRUE;


/* ---------------------------------------------------------------------------
   19. ACCOUNT ELIGIBILITY REPORT
--------------------------------------------------------------------------- */

SELECT
    username,
    status,
    failed_attempts,
    locked_until,
    can_authenticate
FROM account_authentication_status
ORDER BY username;


/* ---------------------------------------------------------------------------
   20. AUTHENTICATION AGGREGATION
--------------------------------------------------------------------------- */

SELECT
    a.username,

    COUNT(*) AS total_attempts,

    COUNT(*) FILTER (
        WHERE e.succeeded = TRUE
    ) AS successful_attempts,

    COUNT(*) FILTER (
        WHERE e.succeeded = FALSE
    ) AS failed_attempts,

    MAX(e.occurred_at) AS latest_attempt

FROM accounts a
LEFT JOIN authentication_attempts e
    ON e.account_id = a.account_id

GROUP BY
    a.account_id,
    a.username

ORDER BY total_attempts DESC;


/* ---------------------------------------------------------------------------
   21. RECENT SECURITY EVENTS
--------------------------------------------------------------------------- */

SELECT
    a.username,
    e.succeeded,
    e.failure_category,
    e.occurred_at

FROM authentication_attempts e
JOIN accounts a
    ON a.account_id = e.account_id

WHERE e.occurred_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'

ORDER BY e.occurred_at DESC;


/* ---------------------------------------------------------------------------
   22. CREDENTIAL HISTORY REPORT
--------------------------------------------------------------------------- */

SELECT
    a.username,
    h.algorithm,
    h.iterations,
    octet_length(h.salt) AS historical_salt_bytes,
    h.archived_at

FROM password_history h
JOIN accounts a
    ON a.account_id = h.account_id

ORDER BY h.archived_at DESC;


/* ---------------------------------------------------------------------------
   23. CURRENT LOCKED ACCOUNTS
--------------------------------------------------------------------------- */

SELECT
    a.username,
    t.failed_attempts,
    t.locked_until,
    t.last_attempt_at

FROM auth_throttle_state t
JOIN accounts a
    ON a.account_id = t.account_id

WHERE t.locked_until > CURRENT_TIMESTAMP

ORDER BY t.locked_until;


/* ---------------------------------------------------------------------------
   24. CREDENTIAL UPGRADE AGGREGATION
--------------------------------------------------------------------------- */

SELECT
    algorithm,

    COUNT(*) AS credential_count,

    COUNT(*) FILTER (
        WHERE iterations >= 600000
    ) AS current_configuration_count,

    COUNT(*) FILTER (
        WHERE iterations < 600000
    ) AS upgrade_required_count

FROM password_credentials

GROUP BY algorithm;


/* ---------------------------------------------------------------------------
   25. TRANSACTIONAL CREDENTIAL INSPECTION
--------------------------------------------------------------------------- */

BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;

SELECT
    a.username,
    c.iterations,
    c.credential_version,
    octet_length(c.salt) AS salt_length,
    octet_length(c.verifier) AS verifier_length

FROM accounts a

JOIN password_credentials c
    ON c.account_id = a.account_id

WHERE a.status = 'active'

FOR UPDATE OF c;

COMMIT;


/* ---------------------------------------------------------------------------
   26. DATABASE SECURITY BOUNDARIES
--------------------------------------------------------------------------- */

/*
Security deployment requirements:

1. Do not grant ordinary application users unrestricted access to
   password_credentials or password_history.

2. Use a dedicated database role for credential updates.

3. Restrict UPDATE operations to the intended authentication service.

4. Use parameterized SQL statements.

5. Prevent database query logging from capturing submitted passwords.

6. Encrypt database connections and protect backups.

7. Keep pepper values, where used, outside this database.

8. Apply distributed request throttling at the application or gateway layer.

9. Use a breach-password blocklist in the registration and password-change
   application workflow.

10. Never treat database metadata validation as a substitute for actual
    cryptographic password verification.

===============================================================================
END OF PASSWORD HASHING DATABASE
===============================================================================
*/
