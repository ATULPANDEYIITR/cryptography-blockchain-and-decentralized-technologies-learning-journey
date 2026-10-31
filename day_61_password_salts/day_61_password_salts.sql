CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP SCHEMA IF EXISTS password_security CASCADE;
CREATE SCHEMA password_security;

SET search_path = password_security, public;

-- A repository-style identity is modeled independently from its credential.
-- This prevents account identity and password material from becoming one
-- undifferentiated record.

CREATE TABLE app_user (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT app_user_username_unique UNIQUE (username),
    CONSTRAINT app_user_email_unique UNIQUE (email),
    CONSTRAINT app_user_status_check
        CHECK (status IN ('active', 'locked', 'disabled')),
    CONSTRAINT app_user_username_length
        CHECK (char_length(username) BETWEEN 3 AND 128)
);

CREATE TABLE password_credential (
    credential_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_user(user_id)
        ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    salt_setting TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'bcrypt',
    cost_factor INTEGER NOT NULL DEFAULT 12,
    password_version INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT password_credential_user_unique
        UNIQUE (user_id),

    CONSTRAINT password_credential_algorithm_check
        CHECK (algorithm = 'bcrypt'),

    CONSTRAINT password_credential_cost_check
        CHECK (cost_factor BETWEEN 10 AND 15),

    CONSTRAINT password_credential_version_check
        CHECK (password_version > 0),

    CONSTRAINT password_credential_failures_check
        CHECK (failed_attempts >= 0),

    CONSTRAINT password_credential_hash_format_check
        CHECK (password_hash ~ '^\$2[aby]\$[0-9]{2}\$'),

    CONSTRAINT password_credential_salt_format_check
        CHECK (salt_setting ~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{22}$')
);

CREATE TABLE password_rotation (
    rotation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_user(user_id)
        ON DELETE CASCADE,
    old_password_version INTEGER NOT NULL,
    new_password_version INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL,

    CONSTRAINT password_rotation_version_check
        CHECK (new_password_version = old_password_version + 1)
);

CREATE TABLE authentication_event (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES app_user(user_id)
        ON DELETE SET NULL,
    username_attempted TEXT NOT NULL,
    outcome TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    source_ip INET,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT authentication_event_outcome_check
        CHECK (
            outcome IN (
                'success',
                'invalid_password',
                'unknown_user',
                'locked',
                'disabled'
            )
        )
);

CREATE INDEX authentication_event_user_time_idx
    ON authentication_event (user_id, occurred_at DESC);

CREATE INDEX authentication_event_username_time_idx
    ON authentication_event (username_attempted, occurred_at DESC);

CREATE INDEX password_rotation_user_time_idx
    ON password_rotation (user_id, changed_at DESC);

-- bcrypt stores its cost and salt as part of the password hash.
-- The salt_setting column stores the 29-character bcrypt setting so the
-- database can explicitly expose the salt-related policy metadata without
-- storing a plaintext password or a reusable application-level salt.

CREATE OR REPLACE FUNCTION update_credential_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER password_credential_timestamp_trigger
BEFORE UPDATE ON password_credential
FOR EACH ROW
EXECUTE FUNCTION update_credential_timestamp();

CREATE OR REPLACE FUNCTION enforce_credential_lock_consistency()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.failed_attempts >= 5 AND NEW.locked_until IS NULL THEN
        NEW.locked_until = clock_timestamp() + interval '15 minutes';
    END IF;

    IF NEW.failed_attempts = 0 THEN
        NEW.locked_until = NULL;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER password_credential_lock_trigger
BEFORE INSERT OR UPDATE ON password_credential
FOR EACH ROW
EXECUTE FUNCTION enforce_credential_lock_consistency();

CREATE OR REPLACE FUNCTION create_password_credential(
    p_user_id BIGINT,
    p_password TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = password_security, public
AS $$
DECLARE
    v_hash TEXT;
    v_salt_setting TEXT;
    v_credential_id BIGINT;
BEGIN
    IF p_password IS NULL OR char_length(p_password) < 12 THEN
        RAISE EXCEPTION
            'password must contain at least 12 characters';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM password_credential
        WHERE user_id = p_user_id
    ) THEN
        RAISE EXCEPTION
            'password credential already exists for user %',
            p_user_id;
    END IF;

    /*
     * gen_salt('bf', 12) generates a fresh bcrypt salt for every
     * credential. crypt() then performs the password hashing operation.
     */
    v_salt_setting = gen_salt('bf', 12);
    v_hash = crypt(p_password, v_salt_setting);

    INSERT INTO password_credential (
        user_id,
        password_hash,
        salt_setting,
        algorithm,
        cost_factor
    )
    VALUES (
        p_user_id,
        v_hash,
        v_salt_setting,
        'bcrypt',
        12
    )
    RETURNING credential_id
    INTO v_credential_id;

    RETURN v_credential_id;
END;
$$;

CREATE OR REPLACE FUNCTION verify_password(
    p_username TEXT,
    p_password TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = password_security, public
AS $$
DECLARE
    v_user app_user%ROWTYPE;
    v_credential password_credential%ROWTYPE;
    v_match BOOLEAN;
    v_outcome TEXT;
BEGIN
    SELECT *
    INTO v_user
    FROM app_user
    WHERE username = p_username;

    IF NOT FOUND THEN
        INSERT INTO authentication_event (
            user_id,
            username_attempted,
            outcome,
            details
        )
        VALUES (
            NULL,
            p_username,
            'unknown_user',
            jsonb_build_object('reason', 'username_not_found')
        );

        RETURN 'unknown_user';
    END IF;

    IF v_user.status = 'disabled' THEN
        INSERT INTO authentication_event (
            user_id,
            username_attempted,
            outcome
        )
        VALUES (
            v_user.user_id,
            p_username,
            'disabled'
        );

        RETURN 'disabled';
    END IF;

    SELECT *
    INTO v_credential
    FROM password_credential
    WHERE user_id = v_user.user_id;

    IF NOT FOUND THEN
        INSERT INTO authentication_event (
            user_id,
            username_attempted,
            outcome
        )
        VALUES (
            v_user.user_id,
            p_username,
            'invalid_password'
        );

        RETURN 'invalid_password';
    END IF;

    IF v_user.status = 'locked'
       AND (
           v_credential.locked_until IS NULL
           OR v_credential.locked_until > clock_timestamp()
       )
    THEN
        INSERT INTO authentication_event (
            user_id,
            username_attempted,
            outcome
        )
        VALUES (
            v_user.user_id,
            p_username,
            'locked'
        );

        RETURN 'locked';
    END IF;

    v_match =
        crypt(
            p_password,
            v_credential.password_hash
        ) = v_credential.password_hash;

    IF v_match THEN
        UPDATE password_credential
        SET failed_attempts = 0
        WHERE credential_id = v_credential.credential_id;

        UPDATE app_user
        SET status = 'active'
        WHERE user_id = v_user.user_id
          AND status = 'locked';

        v_outcome = 'success';
    ELSE
        UPDATE password_credential
        SET failed_attempts = failed_attempts + 1
        WHERE credential_id = v_credential.credential_id;

        UPDATE app_user
        SET status = CASE
            WHEN (
                SELECT failed_attempts
                FROM password_credential
                WHERE credential_id = v_credential.credential_id
            ) >= 5
            THEN 'locked'
            ELSE status
        END
        WHERE user_id = v_user.user_id;

        v_outcome = 'invalid_password';
    END IF;

    INSERT INTO authentication_event (
        user_id,
        username_attempted,
        outcome
    )
    VALUES (
        v_user.user_id,
        p_username,
        v_outcome
    );

    RETURN v_outcome;
END;
$$;

CREATE OR REPLACE FUNCTION rotate_password(
    p_username TEXT,
    p_current_password TEXT,
    p_new_password TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = password_security, public
AS $$
DECLARE
    v_user_id BIGINT;
    v_credential password_credential%ROWTYPE;
    v_old_version INTEGER;
    v_new_hash TEXT;
    v_new_salt TEXT;
    v_auth_result TEXT;
BEGIN
    IF p_new_password IS NULL
       OR char_length(p_new_password) < 12
    THEN
        RAISE EXCEPTION
            'new password must contain at least 12 characters';
    END IF;

    v_auth_result =
        verify_password(
            p_username,
            p_current_password
        );

    IF v_auth_result <> 'success' THEN
        RAISE EXCEPTION
            'current password authentication failed';
    END IF;

    SELECT u.user_id
    INTO v_user_id
    FROM app_user AS u
    WHERE u.username = p_username
    FOR UPDATE;

    SELECT *
    INTO v_credential
    FROM password_credential
    WHERE user_id = v_user_id
    FOR UPDATE;

    v_old_version = v_credential.password_version;

    -- A password rotation always receives a fresh random salt.
    v_new_salt = gen_salt('bf', v_credential.cost_factor);
    v_new_hash = crypt(p_new_password, v_new_salt);

    UPDATE password_credential
    SET password_hash = v_new_hash,
        salt_setting = v_new_salt,
        password_version = password_version + 1,
        failed_attempts = 0,
        locked_until = NULL
    WHERE credential_id = v_credential.credential_id;

    UPDATE app_user
    SET status = 'active'
    WHERE user_id = v_user_id;

    INSERT INTO password_rotation (
        user_id,
        old_password_version,
        new_password_version,
        reason
    )
    VALUES (
        v_user_id,
        v_old_version,
        v_old_version + 1,
        'user_initiated_password_change'
    );

    RETURN v_old_version + 1;
END;
$$;

INSERT INTO app_user (
    username,
    email
)
VALUES
    ('alice@example.com', 'alice@example.com'),
    ('bob@example.com', 'bob@example.com'),
    ('carol@example.com', 'carol@example.com');

BEGIN;

SELECT create_password_credential(
    (
        SELECT user_id
        FROM app_user
        WHERE username = 'alice@example.com'
    ),
    'Correct-Horse-Battery-42!'
);

SELECT create_password_credential(
    (
        SELECT user_id
        FROM app_user
        WHERE username = 'bob@example.com'
    ),
    'Correct-Horse-Battery-42!'
);

SELECT create_password_credential(
    (
        SELECT user_id
        FROM app_user
        WHERE username = 'carol@example.com'
    ),
    'Different-Password-88!'
);

COMMIT;

-- Equal plaintext passwords must still produce different bcrypt hashes
-- because each credential receives an independent salt.
SELECT
    a.username,
    pc.password_version,
    pc.algorithm,
    pc.cost_factor,
    pc.salt_setting,
    pc.password_hash <> (
        SELECT pc2.password_hash
        FROM password_credential pc2
        JOIN app_user b
          ON b.user_id = pc2.user_id
        WHERE b.username = 'bob@example.com'
    ) AS_hash_differs_from_bob
FROM app_user a
JOIN password_credential pc
  ON pc.user_id = a.user_id
WHERE a.username IN (
    'alice@example.com',
    'bob@example.com'
);

-- Successful verification.
SELECT verify_password(
    'alice@example.com',
    'Correct-Horse-Battery-42!'
) AS authentication_result;

-- Failure case.
SELECT verify_password(
    'alice@example.com',
    'wrong-password'
) AS authentication_result;

-- Password rotation is transactional and receives a new salt.
BEGIN;

SELECT rotate_password(
    'alice@example.com',
    'Correct-Horse-Battery-42!',
    'New-Longer-Password-99!'
) AS new_password_version;

COMMIT;

SELECT verify_password(
    'alice@example.com',
    'New-Longer-Password-99!'
) AS authentication_result;

-- The previous password must no longer authenticate.
SELECT verify_password(
    'alice@example.com',
    'Correct-Horse-Battery-42!'
) AS authentication_result;

-- Deliberate lockout example.
SELECT verify_password('bob@example.com', 'wrong-password');
SELECT verify_password('bob@example.com', 'wrong-password');
SELECT verify_password('bob@example.com', 'wrong-password');
SELECT verify_password('bob@example.com', 'wrong-password');
SELECT verify_password('bob@example.com', 'wrong-password');

-- Workflow and state report.
SELECT
    u.username,
    u.status,
    pc.password_version,
    pc.algorithm,
    pc.cost_factor,
    pc.failed_attempts,
    pc.locked_until,
    pc.created_at,
    pc.updated_at
FROM app_user u
JOIN password_credential pc
  ON pc.user_id = u.user_id
ORDER BY u.username;

-- Authentication reporting.
SELECT
    outcome,
    count(*) AS event_count
FROM authentication_event
GROUP BY outcome
ORDER BY event_count DESC, outcome;

-- Password rotation history.
SELECT
    u.username,
    pr.old_password_version,
    pr.new_password_version,
    pr.reason,
    pr.changed_at
FROM password_rotation pr
JOIN app_user u
  ON u.user_id = pr.user_id
ORDER BY pr.changed_at DESC;

-- CTE identifying accounts whose password state requires operational review.
WITH credential_health AS (
    SELECT
        u.user_id,
        u.username,
        u.status,
        pc.password_version,
        pc.cost_factor,
        pc.failed_attempts,
        pc.locked_until
    FROM app_user u
    JOIN password_credential pc
      ON pc.user_id = u.user_id
)
SELECT
    username,
    status,
    password_version,
    cost_factor,
    failed_attempts,
    CASE
        WHEN status = 'locked' THEN 'LOCKED'
        WHEN cost_factor < 12 THEN 'WEAK_KDF_COST'
        WHEN failed_attempts >= 3 THEN 'AUTHENTICATION_RISK'
        ELSE 'NORMAL'
    END AS security_state
FROM credential_health
ORDER BY username;

-- Transactional rollback example.
BEGIN;

SELECT rotate_password(
    'carol@example.com',
    'Different-Password-88!',
    'Temporary-Password-99!'
);

ROLLBACK;

-- The rollback means the temporary password is not active.
SELECT verify_password(
    'carol@example.com',
    'Different-Password-88!'
) AS authentication_result;

-- Salt uniqueness audit. A duplicate salt is not automatically a security
-- failure, but with 128-bit random salts collisions should be extraordinarily
-- unlikely. This query detects operational implementation defects.
SELECT
    salt_setting,
    count(*) AS credential_count
FROM password_credential
GROUP BY salt_setting
HAVING count(*) > 1;
