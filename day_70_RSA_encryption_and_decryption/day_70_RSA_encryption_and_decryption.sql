/*
 * RSA ENCRYPTION AND DECRYPTION
 * PostgreSQL 15+
 *
 * Relational model for RSA key management, cryptographic operations,
 * key lifecycle, access policies, and audit reporting.
 *
 * Security design:
 * - Private key material is never stored in this database.
 * - Public key fingerprints identify registered public keys.
 * - Ciphertexts and signatures can be recorded as binary data.
 * - Private-key operations remain inside an approved cryptographic
 *   application or hardware security module.
 * - Database constraints enforce metadata integrity.
 *
 * This script models cryptographic operations and their governance.
 * PostgreSQL does not implement RSA encryption natively.
 */

BEGIN;

CREATE SCHEMA IF NOT EXISTS rsa_security;

SET search_path TO rsa_security, public;

-- ============================================================
-- Enumerations
-- ============================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED',
    'DISABLED'
);

CREATE TYPE operation_type AS ENUM (
    'ENCRYPT',
    'DECRYPT',
    'SIGN',
    'VERIFY'
);

CREATE TYPE operation_status AS ENUM (
    'PENDING',
    'SUCCESS',
    'FAILED',
    'REJECTED'
);

CREATE TYPE security_role AS ENUM (
    'CRYPTO_ADMIN',
    'ENCRYPTOR',
    'DECRYPTOR',
    'SIGNER',
    'VERIFIER',
    'AUDITOR'
);

CREATE TYPE policy_status AS ENUM (
    'ACTIVE',
    'INACTIVE'
);

-- ============================================================
-- Application users
-- ============================================================

CREATE TABLE application_users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(80) NOT NULL UNIQUE,

    email VARCHAR(255) NOT NULL UNIQUE,

    role security_role NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT username_format CHECK (
        username ~ '^[A-Za-z0-9_-]{3,80}$'
    )
);

-- ============================================================
-- Cryptographic policies
-- ============================================================

CREATE TABLE cryptographic_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    encryption_algorithm VARCHAR(80) NOT NULL
        DEFAULT 'RSA-OAEP-SHA256',

    signature_algorithm VARCHAR(80) NOT NULL
        DEFAULT 'RSA-PSS-SHA256',

    minimum_key_size INTEGER NOT NULL DEFAULT 2048,

    required_public_exponent BIGINT NOT NULL DEFAULT 65537,

    maximum_key_age_days INTEGER NOT NULL DEFAULT 730,

    maximum_message_size INTEGER NOT NULL DEFAULT 190,

    require_active_key BOOLEAN NOT NULL DEFAULT TRUE,

    status policy_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT minimum_key_size_valid CHECK (
        minimum_key_size BETWEEN 2048 AND 8192
        AND minimum_key_size % 256 = 0
    ),

    CONSTRAINT exponent_valid CHECK (
        required_public_exponent = 65537
    ),

    CONSTRAINT maximum_age_valid CHECK (
        maximum_key_age_days > 0
    ),

    CONSTRAINT maximum_message_valid CHECK (
        maximum_message_size > 0
    ),

    CONSTRAINT algorithms_valid CHECK (
        encryption_algorithm = 'RSA-OAEP-SHA256'
        AND signature_algorithm = 'RSA-PSS-SHA256'
    )
);

-- ============================================================
-- RSA key registry
-- ============================================================

CREATE TABLE rsa_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_reference VARCHAR(100) NOT NULL UNIQUE,

    owner_id BIGINT NOT NULL
        REFERENCES application_users(user_id),

    policy_id BIGINT NOT NULL
        REFERENCES cryptographic_policies(policy_id),

    modulus_bits INTEGER NOT NULL,

    public_exponent BIGINT NOT NULL DEFAULT 65537,

    public_key_fingerprint CHAR(64) NOT NULL UNIQUE,

    public_key_pem TEXT NOT NULL,

    key_status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    CONSTRAINT modulus_size_valid CHECK (
        modulus_bits BETWEEN 2048 AND 8192
        AND modulus_bits % 256 = 0
    ),

    CONSTRAINT public_exponent_valid CHECK (
        public_exponent = 65537
    ),

    CONSTRAINT fingerprint_valid CHECK (
        public_key_fingerprint ~ '^[0-9a-f]{64}$'
    ),

    CONSTRAINT expiry_valid CHECK (
        expires_at IS NULL OR expires_at > created_at
    ),

    CONSTRAINT revocation_consistent CHECK (
        (key_status = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (key_status <> 'REVOKED' AND revoked_at IS NULL)
    )
);

CREATE INDEX idx_rsa_keys_owner
    ON rsa_keys(owner_id);

CREATE INDEX idx_rsa_keys_status
    ON rsa_keys(key_status, expires_at);

CREATE INDEX idx_rsa_keys_policy
    ON rsa_keys(policy_id);

-- ============================================================
-- Key usage permissions
-- ============================================================

CREATE TABLE key_permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES rsa_keys(key_id) ON DELETE RESTRICT,

    user_id BIGINT NOT NULL
        REFERENCES application_users(user_id) ON DELETE RESTRICT,

    operation operation_type NOT NULL,

    granted_by BIGINT NOT NULL
        REFERENCES application_users(user_id),

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE(key_id, user_id, operation)
);

CREATE INDEX idx_key_permissions_lookup
    ON key_permissions(key_id, user_id, operation)
    WHERE active = TRUE;

-- ============================================================
-- Cryptographic operation records
-- ============================================================

CREATE TABLE cryptographic_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES rsa_keys(key_id),

    user_id BIGINT NOT NULL
        REFERENCES application_users(user_id),

    operation operation_type NOT NULL,

    operation_status operation_status NOT NULL DEFAULT 'PENDING',

    algorithm VARCHAR(80) NOT NULL,

    plaintext_size INTEGER,

    ciphertext BYTEA,

    signature BYTEA,

    message_digest CHAR(64),

    external_reference VARCHAR(150),

    error_code VARCHAR(80),

    error_message VARCHAR(500),

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CONSTRAINT operation_algorithm_valid CHECK (
        algorithm IN (
            'RSA-OAEP-SHA256',
            'RSA-PSS-SHA256'
        )
    ),

    CONSTRAINT plaintext_size_valid CHECK (
        plaintext_size IS NULL OR plaintext_size >= 0
    ),

    CONSTRAINT digest_valid CHECK (
        message_digest IS NULL
        OR message_digest ~ '^[0-9a-f]{64}$'
    ),

    CONSTRAINT completion_consistent CHECK (
        (operation_status = 'PENDING' AND completed_at IS NULL)
        OR
        (operation_status <> 'PENDING' AND completed_at IS NOT NULL)
    ),

    CONSTRAINT error_consistent CHECK (
        operation_status NOT IN ('FAILED', 'REJECTED')
        OR error_code IS NOT NULL
    )
);

CREATE INDEX idx_operations_key_time
    ON cryptographic_operations(key_id, started_at DESC);

CREATE INDEX idx_operations_user_time
    ON cryptographic_operations(user_id, started_at DESC);

CREATE INDEX idx_operations_status
    ON cryptographic_operations(operation_status, started_at DESC);

CREATE INDEX idx_operations_external_reference
    ON cryptographic_operations(external_reference)
    WHERE external_reference IS NOT NULL;

-- ============================================================
-- Key lifecycle events
-- ============================================================

CREATE TABLE key_lifecycle_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES rsa_keys(key_id),

    performed_by BIGINT NOT NULL
        REFERENCES application_users(user_id),

    previous_status key_status,

    new_status key_status NOT NULL,

    reason VARCHAR(500) NOT NULL,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_key_events_history
    ON key_lifecycle_events(key_id, occurred_at DESC);

-- ============================================================
-- Audit records
-- ============================================================

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT REFERENCES application_users(user_id),

    key_id BIGINT REFERENCES rsa_keys(key_id),

    action VARCHAR(100) NOT NULL,

    result VARCHAR(30) NOT NULL,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT audit_result_valid CHECK (
        result IN ('SUCCESS', 'FAILURE', 'REJECTED')
    )
);

CREATE INDEX idx_security_audit_time
    ON security_audit(occurred_at DESC);

CREATE INDEX idx_security_audit_details
    ON security_audit USING GIN(details);

-- ============================================================
-- Key permission evaluation
-- ============================================================

CREATE FUNCTION has_key_permission(
    p_key_id BIGINT,
    p_user_id BIGINT,
    p_operation operation_type
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM key_permissions kp
        JOIN application_users u
            ON u.user_id = kp.user_id
        WHERE kp.key_id = p_key_id
          AND kp.user_id = p_user_id
          AND kp.operation = p_operation
          AND kp.active = TRUE
          AND u.enabled = TRUE
    );
$$;

-- ============================================================
-- Key eligibility evaluation
-- ============================================================

CREATE FUNCTION is_key_eligible(
    p_key_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM rsa_keys k
        JOIN cryptographic_policies p
            ON p.policy_id = k.policy_id
        WHERE k.key_id = p_key_id
          AND k.key_status = 'ACTIVE'
          AND p.status = 'ACTIVE'
          AND k.modulus_bits >= p.minimum_key_size
          AND k.public_exponent = p.required_public_exponent
          AND (
              k.expires_at IS NULL
              OR k.expires_at > CURRENT_TIMESTAMP
          )
          AND k.created_at >= (
              CURRENT_TIMESTAMP
              - make_interval(days => p.maximum_key_age_days)
          )
    );
$$;

-- ============================================================
-- Operation authorization
-- ============================================================

CREATE FUNCTION authorize_rsa_operation(
    p_key_id BIGINT,
    p_user_id BIGINT,
    p_operation operation_type,
    p_plaintext_size INTEGER DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_policy cryptographic_policies%ROWTYPE;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM application_users
        WHERE user_id = p_user_id
          AND enabled = TRUE
    ) THEN
        RETURN FALSE;
    END IF;

    IF NOT is_key_eligible(p_key_id) THEN
        RETURN FALSE;
    END IF;

    IF NOT has_key_permission(
        p_key_id,
        p_user_id,
        p_operation
    ) THEN
        RETURN FALSE;
    END IF;

    SELECT p.*
    INTO v_policy
    FROM rsa_keys k
    JOIN cryptographic_policies p
        ON p.policy_id = k.policy_id
    WHERE k.key_id = p_key_id;

    IF p_plaintext_size IS NOT NULL THEN
        IF p_plaintext_size < 0
           OR p_plaintext_size > v_policy.maximum_message_size THEN
            RETURN FALSE;
        END IF;
    END IF;

    RETURN TRUE;
END;
$$;

-- ============================================================
-- Operation validation trigger
-- ============================================================

CREATE FUNCTION validate_operation_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_expected_algorithm VARCHAR(80);
BEGIN
    IF NEW.operation IN ('ENCRYPT', 'DECRYPT') THEN
        v_expected_algorithm := 'RSA-OAEP-SHA256';

    ELSE
        v_expected_algorithm := 'RSA-PSS-SHA256';
    END IF;

    IF NEW.algorithm <> v_expected_algorithm THEN
        RAISE EXCEPTION
            'Algorithm % is not valid for operation %',
            NEW.algorithm,
            NEW.operation;
    END IF;

    IF NOT authorize_rsa_operation(
        NEW.key_id,
        NEW.user_id,
        NEW.operation,
        CASE
            WHEN NEW.operation IN ('ENCRYPT', 'SIGN')
            THEN NEW.plaintext_size
            ELSE NULL
        END
    ) THEN
        RAISE EXCEPTION
            'RSA operation is not authorized or key is ineligible';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_operation_insert
BEFORE INSERT ON cryptographic_operations
FOR EACH ROW
EXECUTE FUNCTION validate_operation_insert();

-- ============================================================
-- Immutable operation identity
-- ============================================================

CREATE FUNCTION protect_operation_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.key_id <> NEW.key_id
       OR OLD.user_id <> NEW.user_id
       OR OLD.operation <> NEW.operation
       OR OLD.algorithm <> NEW.algorithm
       OR OLD.started_at <> NEW.started_at THEN

        RAISE EXCEPTION
            'Operation identity fields cannot be modified';
    END IF;

    IF OLD.operation_status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Completed operations cannot be modified';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protect_operation_identity
BEFORE UPDATE ON cryptographic_operations
FOR EACH ROW
EXECUTE FUNCTION protect_operation_identity();

-- ============================================================
-- Key lifecycle auditing
-- ============================================================

CREATE FUNCTION audit_key_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.key_status IS DISTINCT FROM NEW.key_status THEN

        IF NEW.key_status = 'REVOKED' THEN
            NEW.revoked_at := CURRENT_TIMESTAMP;
        ELSE
            NEW.revoked_at := NULL;
        END IF;

        INSERT INTO key_lifecycle_events (
            key_id,
            performed_by,
            previous_status,
            new_status,
            reason
        )
        VALUES (
            NEW.key_id,
            NEW.owner_id,
            OLD.key_status,
            NEW.key_status,
            'Key status changed'
        );

        INSERT INTO security_audit (
            user_id,
            key_id,
            action,
            result,
            details
        )
        VALUES (
            NEW.owner_id,
            NEW.key_id,
            'KEY_STATUS_CHANGE',
            'SUCCESS',
            jsonb_build_object(
                'old_status', OLD.key_status,
                'new_status', NEW.key_status
            )
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_status_audit
BEFORE UPDATE OF key_status ON rsa_keys
FOR EACH ROW
EXECUTE FUNCTION audit_key_status_change();

-- ============================================================
-- Operation completion procedure
-- ============================================================

CREATE PROCEDURE complete_rsa_operation(
    p_operation_id BIGINT,
    p_status operation_status,
    p_ciphertext BYTEA DEFAULT NULL,
    p_signature BYTEA DEFAULT NULL,
    p_error_code VARCHAR(80) DEFAULT NULL,
    p_error_message VARCHAR(500) DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_status = 'PENDING' THEN
        RAISE EXCEPTION
            'Operation completion requires a final status';
    END IF;

    IF p_status = 'SUCCESS'
       AND (
           p_error_code IS NOT NULL
           OR p_error_message IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'Successful operations cannot contain error details';
    END IF;

    IF p_status IN ('FAILED', 'REJECTED')
       AND p_error_code IS NULL THEN
        RAISE EXCEPTION
            'Failed operations require an error code';
    END IF;

    UPDATE cryptographic_operations
    SET operation_status = p_status,
        ciphertext = p_ciphertext,
        signature = p_signature,
        error_code = p_error_code,
        error_message = p_error_message,
        completed_at = CURRENT_TIMESTAMP
    WHERE operation_id = p_operation_id
      AND operation_status = 'PENDING';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Pending operation not found or already completed';
    END IF;

    INSERT INTO security_audit (
        key_id,
        action,
        result,
        details
    )
    SELECT
        key_id,
        'CRYPTO_OPERATION_COMPLETED',
        CASE
            WHEN p_status = 'SUCCESS' THEN 'SUCCESS'
            WHEN p_status = 'REJECTED' THEN 'REJECTED'
            ELSE 'FAILURE'
        END,
        jsonb_build_object(
            'operation_id', p_operation_id,
            'status', p_status,
            'error_code', p_error_code
        )
    FROM cryptographic_operations
    WHERE operation_id = p_operation_id;
END;
$$;

-- ============================================================
-- Reporting views
-- ============================================================

CREATE VIEW active_rsa_keys AS
SELECT
    k.key_id,
    k.key_reference,
    u.username AS owner,
    p.policy_name,
    k.modulus_bits,
    k.public_exponent,
    k.public_key_fingerprint,
    k.created_at,
    k.expires_at
FROM rsa_keys k
JOIN application_users u
    ON u.user_id = k.owner_id
JOIN cryptographic_policies p
    ON p.policy_id = k.policy_id
WHERE k.key_status = 'ACTIVE'
  AND p.status = 'ACTIVE'
  AND (
      k.expires_at IS NULL
      OR k.expires_at > CURRENT_TIMESTAMP
  );

CREATE VIEW rsa_operation_summary AS
SELECT
    k.key_reference,
    o.operation,
    o.operation_status,
    COUNT(*) AS total_operations,
    AVG(
        EXTRACT(
            EPOCH FROM (
                o.completed_at - o.started_at
            )
        )
    ) AS average_duration_seconds
FROM cryptographic_operations o
JOIN rsa_keys k
    ON k.key_id = o.key_id
GROUP BY
    k.key_reference,
    o.operation,
    o.operation_status;

-- ============================================================
-- Sample data
-- ============================================================

INSERT INTO application_users (
    username,
    email,
    role
)
VALUES
    (
        'crypto_admin',
        'admin@example.org',
        'CRYPTO_ADMIN'
    ),
    (
        'encryption_user',
        'encrypt@example.org',
        'ENCRYPTOR'
    ),
    (
        'decryption_user',
        'decrypt@example.org',
        'DECRYPTOR'
    ),
    (
        'signing_user',
        'sign@example.org',
        'SIGNER'
    ),
    (
        'verification_user',
        'verify@example.org',
        'VERIFIER'
    ),
    (
        'security_auditor',
        'audit@example.org',
        'AUDITOR'
    );

INSERT INTO cryptographic_policies (
    policy_name,
    minimum_key_size,
    maximum_key_age_days,
    maximum_message_size
)
VALUES
    (
        'RSA-Enterprise-Standard',
        2048,
        730,
        190
    );

INSERT INTO rsa_keys (
    key_reference,
    owner_id,
    policy_id,
    modulus_bits,
    public_exponent,
    public_key_fingerprint,
    public_key_pem,
    key_status,
    created_at,
    expires_at
)
SELECT
    'enterprise-rsa-key-001',
    u.user_id,
    p.policy_id,
    2048,
    65537,
    repeat('a', 64),
    '-----BEGIN PUBLIC KEY-----' || E'\n'
    || 'EDUCATIONAL_PUBLIC_KEY_METADATA_ONLY'
    || E'\n-----END PUBLIC KEY-----',
    'ACTIVE',
    CURRENT_TIMESTAMP - INTERVAL '30 days',
    CURRENT_TIMESTAMP + INTERVAL '700 days'
FROM application_users u
CROSS JOIN cryptographic_policies p
WHERE u.username = 'crypto_admin'
  AND p.policy_name = 'RSA-Enterprise-Standard';

-- A deliberately expired key demonstrates eligibility rejection.
INSERT INTO rsa_keys (
    key_reference,
    owner_id,
    policy_id,
    modulus_bits,
    public_exponent,
    public_key_fingerprint,
    public_key_pem,
    key_status,
    created_at,
    expires_at
)
SELECT
    'expired-rsa-key-002',
    u.user_id,
    p.policy_id,
    2048,
    65537,
    repeat('b', 64),
    'EXPIRED_KEY_METADATA_ONLY',
    'ACTIVE',
    CURRENT_TIMESTAMP - INTERVAL '800 days',
    CURRENT_TIMESTAMP - INTERVAL '70 days'
FROM application_users u
CROSS JOIN cryptographic_policies p
WHERE u.username = 'crypto_admin'
  AND p.policy_name = 'RSA-Enterprise-Standard';

-- Assign permissions.
INSERT INTO key_permissions (
    key_id,
    user_id,
    operation,
    granted_by
)
SELECT
    k.key_id,
    u.user_id,
    permission.operation,
    owner.user_id
FROM rsa_keys k
JOIN application_users owner
    ON owner.user_id = k.owner_id
CROSS JOIN (
    VALUES
        ('encryption_user', 'ENCRYPT'::operation_type),
        ('decryption_user', 'DECRYPT'::operation_type),
        ('signing_user', 'SIGN'::operation_type),
        ('verification_user', 'VERIFY'::operation_type)
) AS permission(username, operation)
JOIN application_users u
    ON u.username = permission.username
WHERE k.key_reference = 'enterprise-rsa-key-001';

-- ============================================================
-- Transactional cryptographic workflow metadata
-- ============================================================

DO $$
DECLARE
    v_key_id BIGINT;
    v_encrypt_user BIGINT;
    v_decrypt_user BIGINT;
    v_operation_id BIGINT;
BEGIN
    SELECT key_id
    INTO v_key_id
    FROM rsa_keys
    WHERE key_reference = 'enterprise-rsa-key-001';

    SELECT user_id
    INTO v_encrypt_user
    FROM application_users
    WHERE username = 'encryption_user';

    SELECT user_id
    INTO v_decrypt_user
    FROM application_users
    WHERE username = 'decryption_user';

    -- Create an authorized encryption operation.
    INSERT INTO cryptographic_operations (
        key_id,
        user_id,
        operation,
        algorithm,
        plaintext_size,
        message_digest,
        external_reference
    )
    VALUES (
        v_key_id,
        v_encrypt_user,
        'ENCRYPT',
        'RSA-OAEP-SHA256',
        45,
        repeat('c', 64),
        'TXN-RSA-0001'
    )
    RETURNING operation_id INTO v_operation_id;

    CALL complete_rsa_operation(
        v_operation_id,
        'SUCCESS',
        decode('a1b2c3d4', 'hex'),
        NULL,
        NULL,
        NULL
    );

    -- Create an authorized decryption operation.
    INSERT INTO cryptographic_operations (
        key_id,
        user_id,
        operation,
        algorithm,
        external_reference
    )
    VALUES (
        v_key_id,
        v_decrypt_user,
        'DECRYPT',
        'RSA-OAEP-SHA256',
        'TXN-RSA-0001-DECRYPT'
    )
    RETURNING operation_id INTO v_operation_id;

    CALL complete_rsa_operation(
        v_operation_id,
        'SUCCESS',
        NULL,
        NULL,
        NULL,
        NULL
    );
END;
$$;

-- ============================================================
-- Validation and eligibility queries
-- ============================================================

-- 1. Registered RSA keys and their eligibility.
SELECT
    key_reference,
    modulus_bits,
    key_status,
    is_key_eligible(key_id) AS eligible
FROM rsa_keys
ORDER BY key_id;

-- 2. Active keys.
SELECT *
FROM active_rsa_keys;

-- 3. Permission evaluation.
SELECT
    k.key_reference,
    u.username,
    p.operation,
    has_key_permission(
        k.key_id,
        u.user_id,
        p.operation
    ) AS permitted
FROM rsa_keys k
CROSS JOIN application_users u
CROSS JOIN (
    VALUES
        ('ENCRYPT'::operation_type),
        ('DECRYPT'::operation_type)
) AS p(operation)
WHERE k.key_reference = 'enterprise-rsa-key-001'
ORDER BY u.username, p.operation;

-- 4. Complete operation authorization.
SELECT
    k.key_reference,
    u.username,
    authorize_rsa_operation(
        k.key_id,
        u.user_id,
        'ENCRYPT',
        45
    ) AS authorized
FROM rsa_keys k
JOIN application_users u
    ON u.username = 'encryption_user'
WHERE k.key_reference = 'enterprise-rsa-key-001';

-- 5. Operation history.
SELECT
    o.operation_id,
    k.key_reference,
    u.username,
    o.operation,
    o.operation_status,
    o.algorithm,
    o.started_at,
    o.completed_at
FROM cryptographic_operations o
JOIN rsa_keys k
    ON k.key_id = o.key_id
JOIN application_users u
    ON u.user_id = o.user_id
ORDER BY o.started_at DESC;

-- 6. Aggregated operation statistics.
SELECT
    operation,
    operation_status,
    COUNT(*) AS operation_count
FROM cryptographic_operations
GROUP BY operation, operation_status
ORDER BY operation, operation_status;

-- 7. Failed and rejected operations.
SELECT
    operation_id,
    key_id,
    user_id,
    operation,
    error_code,
    error_message
FROM cryptographic_operations
WHERE operation_status IN ('FAILED', 'REJECTED');

-- 8. Key lifecycle report.
SELECT
    k.key_reference,
    e.previous_status,
    e.new_status,
    e.reason,
    e.occurred_at
FROM key_lifecycle_events e
JOIN rsa_keys k
    ON k.key_id = e.key_id
ORDER BY e.occurred_at DESC;

-- 9. Operation summary.
SELECT *
FROM rsa_operation_summary
ORDER BY key_reference, operation;

-- 10. Security audit report.
SELECT
    audit_id,
    action,
    result,
    details,
    occurred_at
FROM security_audit
ORDER BY occurred_at DESC;

-- ============================================================
-- Rejected workflow demonstration
-- ============================================================

DO $$
DECLARE
    v_key_id BIGINT;
    v_user_id BIGINT;
BEGIN
    SELECT key_id
    INTO v_key_id
    FROM rsa_keys
    WHERE key_reference = 'enterprise-rsa-key-001';

    SELECT user_id
    INTO v_user_id
    FROM application_users
    WHERE username = 'encryption_user';

    BEGIN
        -- The user has no permission to decrypt.
        INSERT INTO cryptographic_operations (
            key_id,
            user_id,
            operation,
            algorithm,
            external_reference
        )
        VALUES (
            v_key_id,
            v_user_id,
            'DECRYPT',
            'RSA-OAEP-SHA256',
            'UNAUTHORIZED-ATTEMPT'
        );

        RAISE EXCEPTION
            'Unauthorized operation was unexpectedly accepted';

    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM LIKE
                'Unauthorized operation was unexpectedly accepted%' THEN
                RAISE;
            END IF;

            RAISE NOTICE
                'Unauthorized operation rejected: %',
                SQLERRM;
    END;

    BEGIN
        -- OAEP plaintext exceeds the policy limit.
        INSERT INTO cryptographic_operations (
            key_id,
            user_id,
            operation,
            algorithm,
            plaintext_size
        )
        VALUES (
            v_key_id,
            v_user_id,
            'ENCRYPT',
            'RSA-OAEP-SHA256',
            191
        );

        RAISE EXCEPTION
            'Oversized message was unexpectedly accepted';

    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM LIKE
                'Oversized message was unexpectedly accepted%' THEN
                RAISE;
            END IF;

            RAISE NOTICE
                'Oversized message rejected: %',
                SQLERRM;
    END;
END;
$$;

COMMIT;
