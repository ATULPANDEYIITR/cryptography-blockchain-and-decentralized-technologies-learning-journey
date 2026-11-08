-- ============================================================
-- RSA KEY GENERATION AND ENTERPRISE KEY MANAGEMENT
-- PostgreSQL 15+
--
-- This schema manages:
--   1. RSA generation requests
--   2. Key-generation policies
--   3. Public-key metadata
--   4. Key lifecycle states
--   5. Key ownership and permissions
--   6. Validation records
--   7. Audit events
--   8. Rotation and revocation
--
-- Cryptographic operations are performed by an application
-- using a vetted cryptographic library.
--
-- Private keys are NEVER stored in this database.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS rsa_management;

SET search_path TO rsa_management, public;

-- ------------------------------------------------------------
-- 1. Enumerated domain types
-- ------------------------------------------------------------

CREATE TYPE key_state AS ENUM (
    'REQUESTED',
    'GENERATED',
    'VALIDATED',
    'ACTIVE',
    'ROTATION_PENDING',
    'REVOKED',
    'EXPIRED',
    'FAILED'
);

CREATE TYPE generation_status AS ENUM (
    'PENDING',
    'PROCESSING',
    'COMPLETED',
    'FAILED'
);

CREATE TYPE validation_status AS ENUM (
    'PENDING',
    'PASSED',
    'FAILED'
);

CREATE TYPE key_event_type AS ENUM (
    'REQUEST_CREATED',
    'GENERATION_STARTED',
    'KEY_GENERATED',
    'KEY_VALIDATED',
    'KEY_ACTIVATED',
    'KEY_ROTATION_REQUESTED',
    'KEY_REVOKED',
    'KEY_EXPIRED',
    'GENERATION_FAILED'
);

-- ------------------------------------------------------------
-- 2. Organizational users
-- ------------------------------------------------------------

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(30) NOT NULL CHECK (
        role IN (
            'KEY_ADMIN',
            'SECURITY_OFFICER',
            'APPLICATION_OWNER',
            'AUDITOR'
        )
    ),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- 3. RSA generation policies
-- ------------------------------------------------------------

CREATE TABLE key_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    algorithm VARCHAR(20) NOT NULL DEFAULT 'RSA'
        CHECK (algorithm = 'RSA'),

    modulus_bits INTEGER NOT NULL
        CHECK (modulus_bits IN (2048, 3072, 4096)),

    public_exponent INTEGER NOT NULL DEFAULT 65537
        CHECK (public_exponent = 65537),

    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256'
        CHECK (hash_algorithm = 'SHA-256'),

    signature_scheme VARCHAR(30) NOT NULL DEFAULT 'RSA-PSS'
        CHECK (signature_scheme = 'RSA-PSS'),

    encryption_scheme VARCHAR(30) NOT NULL DEFAULT 'RSA-OAEP'
        CHECK (encryption_scheme = 'RSA-OAEP'),

    minimum_rotation_days INTEGER NOT NULL DEFAULT 365
        CHECK (minimum_rotation_days > 0),

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- 4. Key-generation requests
-- ------------------------------------------------------------

CREATE TABLE generation_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    requested_by BIGINT NOT NULL REFERENCES users(user_id),

    policy_id BIGINT NOT NULL REFERENCES key_policies(policy_id),

    application_name VARCHAR(150) NOT NULL,

    environment VARCHAR(30) NOT NULL CHECK (
        environment IN (
            'DEVELOPMENT',
            'TESTING',
            'STAGING',
            'PRODUCTION'
        )
    ),

    purpose TEXT NOT NULL CHECK (length(trim(purpose)) > 0),

    status generation_status NOT NULL DEFAULT 'PENDING',

    failure_reason TEXT,

    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CHECK (
        (status = 'FAILED' AND failure_reason IS NOT NULL)
        OR
        (status <> 'FAILED' AND failure_reason IS NULL)
    ),

    CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL)
        OR
        (status <> 'COMPLETED' AND completed_at IS NULL)
    )
);

-- ------------------------------------------------------------
-- 5. RSA public-key registry
-- ------------------------------------------------------------

CREATE TABLE rsa_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL UNIQUE
        REFERENCES generation_requests(request_id),

    owner_id BIGINT NOT NULL REFERENCES users(user_id),

    policy_id BIGINT NOT NULL REFERENCES key_policies(policy_id),

    key_identifier UUID NOT NULL UNIQUE,

    algorithm VARCHAR(20) NOT NULL DEFAULT 'RSA'
        CHECK (algorithm = 'RSA'),

    modulus_bits INTEGER NOT NULL
        CHECK (modulus_bits IN (2048, 3072, 4096)),

    public_exponent INTEGER NOT NULL
        CHECK (public_exponent = 65537),

    public_key_pem TEXT NOT NULL,

    fingerprint_sha256 CHAR(64) NOT NULL UNIQUE
        CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),

    state key_state NOT NULL DEFAULT 'GENERATED',

    generated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    activated_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    revocation_reason TEXT,

    rotated_from BIGINT REFERENCES rsa_keys(key_id),

    CHECK (
        expires_at IS NULL OR expires_at > generated_at
    ),

    CHECK (
        (state = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (state <> 'REVOKED' AND revoked_at IS NULL)
    ),

    CHECK (
        (state = 'ACTIVE' AND activated_at IS NOT NULL)
        OR
        (state <> 'ACTIVE' AND activated_at IS NULL)
    )
);

-- ------------------------------------------------------------
-- 6. Key validation records
-- ------------------------------------------------------------

CREATE TABLE key_validations (
    validation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL REFERENCES rsa_keys(key_id),

    validated_by BIGINT REFERENCES users(user_id),

    validation_status validation_status NOT NULL DEFAULT 'PENDING',

    modulus_valid BOOLEAN NOT NULL DEFAULT FALSE,

    exponent_valid BOOLEAN NOT NULL DEFAULT FALSE,

    fingerprint_valid BOOLEAN NOT NULL DEFAULT FALSE,

    public_key_parse_valid BOOLEAN NOT NULL DEFAULT FALSE,

    private_public_match BOOLEAN NOT NULL DEFAULT FALSE,

    signature_test_valid BOOLEAN NOT NULL DEFAULT FALSE,

    validation_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    validated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        validation_status <> 'PASSED'
        OR (
            modulus_valid
            AND exponent_valid
            AND fingerprint_valid
            AND public_key_parse_valid
            AND private_public_match
            AND signature_test_valid
        )
    )
);

-- ------------------------------------------------------------
-- 7. Immutable-style audit event history
-- ------------------------------------------------------------

CREATE TABLE key_audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT REFERENCES rsa_keys(key_id),

    request_id BIGINT REFERENCES generation_requests(request_id),

    actor_id BIGINT REFERENCES users(user_id),

    event_type key_event_type NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- 8. Indexes
-- ------------------------------------------------------------

CREATE INDEX idx_rsa_keys_owner
    ON rsa_keys(owner_id);

CREATE INDEX idx_rsa_keys_state
    ON rsa_keys(state);

CREATE INDEX idx_rsa_keys_expiration
    ON rsa_keys(expires_at)
    WHERE state = 'ACTIVE';

CREATE INDEX idx_rsa_keys_fingerprint
    ON rsa_keys(fingerprint_sha256);

CREATE INDEX idx_generation_requests_status
    ON generation_requests(status, requested_at);

CREATE INDEX idx_key_audit_history
    ON key_audit_events(key_id, occurred_at DESC);

CREATE INDEX idx_validation_key_status
    ON key_validations(key_id, validation_status);

CREATE INDEX idx_rotation_history
    ON rsa_keys(rotated_from)
    WHERE rotated_from IS NOT NULL;

-- ------------------------------------------------------------
-- 9. Key lifecycle validation trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_rsa_key_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    policy_bits INTEGER;
    policy_exponent INTEGER;
    request_state generation_status;
BEGIN
    SELECT modulus_bits, public_exponent
    INTO policy_bits, policy_exponent
    FROM key_policies
    WHERE policy_id = NEW.policy_id
      AND is_enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'RSA policy is unavailable or disabled';
    END IF;

    IF NEW.modulus_bits <> policy_bits THEN
        RAISE EXCEPTION
            'Modulus does not match configured key policy';
    END IF;

    IF NEW.public_exponent <> policy_exponent THEN
        RAISE EXCEPTION
            'Public exponent does not match configured policy';
    END IF;

    SELECT status
    INTO request_state
    FROM generation_requests
    WHERE request_id = NEW.request_id;

    IF request_state <> 'PROCESSING' THEN
        RAISE EXCEPTION
            'Generation request must be PROCESSING';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_rsa_key_insert
BEFORE INSERT ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION validate_rsa_key_insert();

-- ------------------------------------------------------------
-- 10. Key-state transition enforcement
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_key_state_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'GENERATED'
       AND NEW.state = 'VALIDATED' THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'VALIDATED'
       AND NEW.state = 'ACTIVE' THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'ACTIVE'
       AND NEW.state IN ('ROTATION_PENDING', 'REVOKED', 'EXPIRED') THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'ROTATION_PENDING'
       AND NEW.state IN ('REVOKED', 'EXPIRED') THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'Invalid RSA key transition: % -> %',
        OLD.state,
        NEW.state;
END;
$$;

CREATE TRIGGER trg_key_state_transition
BEFORE UPDATE OF state ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_key_state_transition();

-- ------------------------------------------------------------
-- 11. Audit generation trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_key_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    selected_event key_event_type;
BEGIN
    IF TG_OP = 'INSERT' THEN
        selected_event := 'KEY_GENERATED';

        INSERT INTO key_audit_events (
            key_id,
            request_id,
            event_type,
            event_details
        )
        VALUES (
            NEW.key_id,
            NEW.request_id,
            selected_event,
            jsonb_build_object(
                'state', NEW.state,
                'modulus_bits', NEW.modulus_bits,
                'algorithm', NEW.algorithm,
                'fingerprint', NEW.fingerprint_sha256
            )
        );

        RETURN NEW;
    END IF;

    IF OLD.state IS DISTINCT FROM NEW.state THEN
        selected_event := CASE NEW.state
            WHEN 'ACTIVE' THEN 'KEY_ACTIVATED'
            WHEN 'REVOKED' THEN 'KEY_REVOKED'
            WHEN 'EXPIRED' THEN 'KEY_EXPIRED'
            WHEN 'ROTATION_PENDING' THEN 'KEY_ROTATION_REQUESTED'
            ELSE 'KEY_VALIDATED'
        END;

        INSERT INTO key_audit_events (
            key_id,
            request_id,
            event_type,
            event_details
        )
        VALUES (
            NEW.key_id,
            NEW.request_id,
            selected_event,
            jsonb_build_object(
                'previous_state', OLD.state,
                'new_state', NEW.state
            )
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_key_changes
AFTER INSERT OR UPDATE OF state ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION audit_key_changes();

-- ------------------------------------------------------------
-- 12. Create a generation request
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION create_generation_request(
    p_user_id BIGINT,
    p_policy_id BIGINT,
    p_application VARCHAR,
    p_environment VARCHAR,
    p_purpose TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    new_request_id BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_user_id
          AND is_active = TRUE
          AND role IN ('KEY_ADMIN', 'APPLICATION_OWNER')
    ) THEN
        RAISE EXCEPTION 'User is not authorized to request RSA keys';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM key_policies
        WHERE policy_id = p_policy_id
          AND is_enabled = TRUE
    ) THEN
        RAISE EXCEPTION 'RSA policy is unavailable';
    END IF;

    INSERT INTO generation_requests (
        requested_by,
        policy_id,
        application_name,
        environment,
        purpose
    )
    VALUES (
        p_user_id,
        p_policy_id,
        p_application,
        p_environment,
        p_purpose
    )
    RETURNING request_id INTO new_request_id;

    INSERT INTO key_audit_events (
        request_id,
        actor_id,
        event_type,
        event_details
    )
    VALUES (
        new_request_id,
        p_user_id,
        'REQUEST_CREATED',
        jsonb_build_object(
            'application', p_application,
            'environment', p_environment
        )
    );

    RETURN new_request_id;
END;
$$;

-- ------------------------------------------------------------
-- 13. Record a generated key
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE register_generated_key(
    p_request_id BIGINT,
    p_owner_id BIGINT,
    p_key_identifier UUID,
    p_public_key_pem TEXT,
    p_fingerprint CHAR(64),
    p_modulus_bits INTEGER,
    p_public_exponent INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    request_record generation_requests%ROWTYPE;
    new_key_id BIGINT;
BEGIN
    SELECT *
    INTO request_record
    FROM generation_requests
    WHERE request_id = p_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Generation request not found';
    END IF;

    IF request_record.status <> 'PROCESSING' THEN
        RAISE EXCEPTION 'Request is not processing';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_owner_id
          AND is_active = TRUE
    ) THEN
        RAISE EXCEPTION 'Invalid or inactive key owner';
    END IF;

    INSERT INTO rsa_keys (
        request_id,
        owner_id,
        policy_id,
        key_identifier,
        public_key_pem,
        fingerprint_sha256,
        modulus_bits,
        public_exponent
    )
    VALUES (
        p_request_id,
        p_owner_id,
        request_record.policy_id,
        p_key_identifier,
        p_public_key_pem,
        p_fingerprint,
        p_modulus_bits,
        p_public_exponent
    )
    RETURNING key_id INTO new_key_id;

    UPDATE generation_requests
    SET status = 'COMPLETED',
        completed_at = CURRENT_TIMESTAMP
    WHERE request_id = p_request_id;

    RAISE NOTICE 'RSA key registered with key ID %', new_key_id;
END;
$$;

-- ------------------------------------------------------------
-- 14. Activate only a validated key
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION activate_rsa_key(
    p_key_id BIGINT,
    p_actor_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    key_record rsa_keys%ROWTYPE;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_actor_id
          AND is_active = TRUE
          AND role IN ('KEY_ADMIN', 'SECURITY_OFFICER')
    ) THEN
        RAISE EXCEPTION 'Activation permission denied';
    END IF;

    SELECT *
    INTO key_record
    FROM rsa_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'RSA key not found';
    END IF;

    IF key_record.state <> 'VALIDATED' THEN
        RAISE EXCEPTION 'Key must be validated before activation';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM key_validations
        WHERE key_id = p_key_id
          AND validation_status = 'PASSED'
    ) THEN
        RAISE EXCEPTION 'No successful validation record exists';
    END IF;

    UPDATE rsa_keys
    SET state = 'ACTIVE',
        activated_at = CURRENT_TIMESTAMP
    WHERE key_id = p_key_id;

    RETURN TRUE;
END;
$$;

-- ------------------------------------------------------------
-- 15. Key eligibility view
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW active_key_inventory AS
SELECT
    k.key_id,
    k.key_identifier,
    k.algorithm,
    k.modulus_bits,
    k.public_exponent,
    k.fingerprint_sha256,
    u.username AS owner,
    p.policy_name,
    k.generated_at,
    k.activated_at,
    k.expires_at,
    CASE
        WHEN k.expires_at IS NOT NULL
             AND k.expires_at <= CURRENT_TIMESTAMP
        THEN FALSE
        WHEN k.state = 'ACTIVE'
        THEN TRUE
        ELSE FALSE
    END AS operationally_eligible
FROM rsa_keys k
JOIN users u ON u.user_id = k.owner_id
JOIN key_policies p ON p.policy_id = k.policy_id;

-- ------------------------------------------------------------
-- 16. Validation reporting
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW key_validation_report AS
SELECT
    k.key_id,
    k.key_identifier,
    k.state,
    COUNT(v.validation_id) AS validation_attempts,
    BOOL_OR(
        v.validation_status = 'PASSED'
    ) AS has_successful_validation,
    MAX(v.validated_at) AS latest_validation
FROM rsa_keys k
LEFT JOIN key_validations v
    ON v.key_id = k.key_id
GROUP BY
    k.key_id,
    k.key_identifier,
    k.state;

-- ------------------------------------------------------------
-- 17. Seed organizational users
-- ------------------------------------------------------------

INSERT INTO users (
    username,
    email,
    role
)
VALUES
    (
        'security_admin',
        'security.admin@example.org',
        'KEY_ADMIN'
    ),
    (
        'security_officer',
        'security.officer@example.org',
        'SECURITY_OFFICER'
    ),
    (
        'application_owner',
        'application.owner@example.org',
        'APPLICATION_OWNER'
    ),
    (
        'audit_user',
        'audit@example.org',
        'AUDITOR'
    );

-- ------------------------------------------------------------
-- 18. Seed RSA policies
-- ------------------------------------------------------------

INSERT INTO key_policies (
    policy_name,
    modulus_bits,
    public_exponent,
    minimum_rotation_days
)
VALUES
    ('STANDARD_RSA_2048', 2048, 65537, 365),
    ('STANDARD_RSA_3072', 3072, 65537, 365),
    ('HIGH_ASSURANCE_RSA_4096', 4096, 65537, 730);

-- ------------------------------------------------------------
-- 19. Create realistic generation requests
-- ------------------------------------------------------------

INSERT INTO generation_requests (
    requested_by,
    policy_id,
    application_name,
    environment,
    purpose
)
VALUES
    (
        3,
        2,
        'PAYMENT_GATEWAY',
        'PRODUCTION',
        'RSA key pair for application-level encryption and signatures'
    ),
    (
        3,
        1,
        'INTERNAL_DOCUMENT_SERVICE',
        'STAGING',
        'Document signature verification'
    ),
    (
        3,
        3,
        'ARCHIVE_SECURITY_SERVICE',
        'PRODUCTION',
        'High-assurance archival signing'
    );

-- Start processing for the first two requests.
UPDATE generation_requests
SET status = 'PROCESSING'
WHERE request_id IN (1, 2);

-- Record a failed request.
UPDATE generation_requests
SET status = 'FAILED',
    failure_reason = 'External cryptographic service unavailable'
WHERE request_id = 3;

-- ------------------------------------------------------------
-- 20. Sample RSA key records
--
-- These PEM values are explicitly demonstration metadata.
-- They are not usable public keys and must not be used
-- for cryptographic operations.
-- Production records must contain validated public-key PEM.
-- ------------------------------------------------------------

INSERT INTO rsa_keys (
    request_id,
    owner_id,
    policy_id,
    key_identifier,
    public_key_pem,
    fingerprint_sha256,
    modulus_bits,
    public_exponent
)
VALUES
    (
        1,
        3,
        2,
        '11111111-1111-4111-8111-111111111111',
        'DEMO_ONLY_NOT_A_VALID_PUBLIC_KEY',
        repeat('a', 64),
        3072,
        65537
    ),
    (
        2,
        3,
        1,
        '22222222-2222-4222-8222-222222222222',
        'DEMO_ONLY_NOT_A_VALID_PUBLIC_KEY',
        repeat('b', 64),
        2048,
        65537
    );

UPDATE generation_requests
SET status = 'COMPLETED',
    completed_at = CURRENT_TIMESTAMP
WHERE request_id IN (1, 2);

-- ------------------------------------------------------------
-- 21. Sample validation decisions
-- ------------------------------------------------------------

INSERT INTO key_validations (
    key_id,
    validated_by,
    validation_status,
    modulus_valid,
    exponent_valid,
    fingerprint_valid,
    public_key_parse_valid,
    private_public_match,
    signature_test_valid,
    validation_details
)
VALUES
    (
        1,
        2,
        'PASSED',
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        '{"test_environment":"simulation","result":"passed"}'
    ),
    (
        2,
        2,
        'FAILED',
        TRUE,
        TRUE,
        FALSE,
        FALSE,
        FALSE,
        FALSE,
        '{"result":"failed","reason":"fingerprint and parsing validation failed"}'
    );

-- Record key 1 as validated.
UPDATE rsa_keys
SET state = 'VALIDATED'
WHERE key_id = 1;

-- Key 2 remains generated because its validation failed.

-- ------------------------------------------------------------
-- 22. Demonstrate successful activation
-- ------------------------------------------------------------

SELECT activate_rsa_key(1, 1);

-- ------------------------------------------------------------
-- 23. Retrieval queries
-- ------------------------------------------------------------

SELECT
    key_id,
    key_identifier,
    modulus_bits,
    public_exponent,
    state,
    fingerprint_sha256
FROM rsa_keys
ORDER BY key_id;

-- ------------------------------------------------------------
-- 24. Validation query
-- ------------------------------------------------------------

SELECT
    key_id,
    validation_status,
    modulus_valid,
    exponent_valid,
    fingerprint_valid,
    public_key_parse_valid,
    private_public_match,
    signature_test_valid
FROM key_validations
ORDER BY key_id;

-- ------------------------------------------------------------
-- 25. Aggregation query
-- ------------------------------------------------------------

SELECT
    modulus_bits,
    state,
    COUNT(*) AS total_keys
FROM rsa_keys
GROUP BY modulus_bits, state
ORDER BY modulus_bits, state;

-- ------------------------------------------------------------
-- 26. Operational eligibility query
-- ------------------------------------------------------------

SELECT
    key_id,
    key_identifier,
    owner,
    policy_name,
    operationally_eligible
FROM active_key_inventory
ORDER BY key_id;

-- ------------------------------------------------------------
-- 27. Validation evaluation using a CTE
-- ------------------------------------------------------------

WITH validation_summary AS (
    SELECT
        k.key_id,
        k.state,
        COUNT(v.validation_id) AS attempts,
        BOOL_OR(
            v.validation_status = 'PASSED'
        ) AS passed
    FROM rsa_keys k
    LEFT JOIN key_validations v
        ON v.key_id = k.key_id
    GROUP BY k.key_id, k.state
)
SELECT
    key_id,
    state,
    attempts,
    COALESCE(passed, FALSE) AS passed,
    CASE
        WHEN state = 'ACTIVE' AND passed THEN 'OPERATIONAL'
        WHEN NOT COALESCE(passed, FALSE) THEN 'VALIDATION_REQUIRED'
        ELSE 'NOT_ACTIVE'
    END AS eligibility
FROM validation_summary
ORDER BY key_id;

-- ------------------------------------------------------------
-- 28. Audit history
-- ------------------------------------------------------------

SELECT
    event_id,
    key_id,
    request_id,
    event_type,
    event_details,
    occurred_at
FROM key_audit_events
ORDER BY occurred_at, event_id;

-- ------------------------------------------------------------
-- 29. Key rotation request
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION request_key_rotation(
    p_key_id BIGINT,
    p_actor_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    selected_state key_state;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_actor_id
          AND is_active = TRUE
          AND role IN ('KEY_ADMIN', 'SECURITY_OFFICER')
    ) THEN
        RAISE EXCEPTION 'Rotation permission denied';
    END IF;

    SELECT state
    INTO selected_state
    FROM rsa_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'RSA key not found';
    END IF;

    IF selected_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Only active keys can enter rotation';
    END IF;

    UPDATE rsa_keys
    SET state = 'ROTATION_PENDING'
    WHERE key_id = p_key_id;

    RETURN TRUE;
END;
$$;

-- Example:
-- SELECT request_key_rotation(1, 1);

-- ------------------------------------------------------------
-- 30. Revocation operation
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE revoke_rsa_key(
    p_key_id BIGINT,
    p_actor_id BIGINT,
    p_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    selected_state key_state;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_actor_id
          AND is_active = TRUE
          AND role IN ('KEY_ADMIN', 'SECURITY_OFFICER')
    ) THEN
        RAISE EXCEPTION 'Revocation permission denied';
    END IF;

    IF p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'Revocation reason is required';
    END IF;

    SELECT state
    INTO selected_state
    FROM rsa_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'RSA key not found';
    END IF;

    IF selected_state NOT IN ('ACTIVE', 'ROTATION_PENDING') THEN
        RAISE EXCEPTION 'Key is not eligible for revocation';
    END IF;

    UPDATE rsa_keys
    SET state = 'REVOKED',
        revoked_at = CURRENT_TIMESTAMP,
        revocation_reason = p_reason
    WHERE key_id = p_key_id;
END;
$$;

-- ------------------------------------------------------------
-- 31. Expiration monitoring
-- ------------------------------------------------------------

SELECT
    key_id,
    key_identifier,
    expires_at,
    CURRENT_TIMESTAMP AS evaluated_at
FROM rsa_keys
WHERE state = 'ACTIVE'
  AND expires_at IS NOT NULL
  AND expires_at <= CURRENT_TIMESTAMP;

-- ------------------------------------------------------------
-- 32. Transactional failure-handling example
-- ------------------------------------------------------------

-- The following example is intentionally rolled back.
-- It demonstrates atomic state management without
-- changing the successful sample key.

SAVEPOINT before_rotation_demo;

-- A valid operational key can enter rotation.
SELECT request_key_rotation(1, 1);

-- Roll back the demonstration state change.
ROLLBACK TO SAVEPOINT before_rotation_demo;

-- ------------------------------------------------------------
-- 33. Operational reporting
-- ------------------------------------------------------------

SELECT
    p.policy_name,
    COUNT(k.key_id) AS registered_keys,
    COUNT(*) FILTER (
        WHERE k.state = 'ACTIVE'
    ) AS active_keys,
    COUNT(*) FILTER (
        WHERE k.state = 'REVOKED'
    ) AS revoked_keys,
    COUNT(*) FILTER (
        WHERE k.state = 'GENERATED'
    ) AS generated_keys
FROM key_policies p
LEFT JOIN rsa_keys k
    ON k.policy_id = p.policy_id
GROUP BY p.policy_id, p.policy_name
ORDER BY p.policy_name;

COMMIT;

-- ============================================================
-- Security note:
-- Database permissions should prevent application users from
-- modifying audit records or changing key states directly.
-- The application must independently validate PEM contents,
-- key correspondence, and cryptographic fingerprints.
-- Private-key generation, storage, backup, and destruction
-- belong in an approved secure key-management environment.
-- ============================================================
