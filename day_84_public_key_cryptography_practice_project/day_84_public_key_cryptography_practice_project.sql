/*
 * PUBLIC-KEY CRYPTOGRAPHY PRACTICE PROJECT
 * PostgreSQL 15+
 *
 * Models:
 * - Organizations and cryptographic identities
 * - Public-key registration
 * - RSA key metadata
 * - Key lifecycle and revocation
 * - Encryption operations
 * - Signed artifacts
 * - Signature verification records
 * - Access-control policies
 * - Cryptographic audit events
 * - Eligibility determination
 *
 * SECURITY:
 * Private keys are never stored in this database.
 * The database manages metadata and governance.
 * Cryptographic operations must execute in a trusted
 * application or dedicated cryptographic service.
 */

BEGIN;

CREATE SCHEMA IF NOT EXISTS crypto_lab;

SET search_path TO crypto_lab, public;

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_name VARCHAR(150) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (length(trim(organization_name)) >= 2)
);

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    username VARCHAR(100) NOT NULL,

    role VARCHAR(30) NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (organization_id, username),

    CHECK (role IN (
        'ADMIN',
        'CRYPTO_OPERATOR',
        'DEVELOPER',
        'AUDITOR'
    ))
);

CREATE TABLE cryptographic_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    owner_user_id BIGINT NOT NULL
        REFERENCES users(user_id),

    external_key_id VARCHAR(120) NOT NULL,

    algorithm VARCHAR(30) NOT NULL,

    key_usage VARCHAR(30) NOT NULL,

    public_key_pem TEXT NOT NULL,

    fingerprint CHAR(64) NOT NULL,

    modulus_bits INTEGER NOT NULL,

    public_exponent BIGINT NOT NULL,

    key_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    revoked_by BIGINT REFERENCES users(user_id),

    UNIQUE (organization_id, external_key_id),

    UNIQUE (organization_id, fingerprint),

    CHECK (algorithm IN ('RSA', 'EC', 'ED25519')),

    CHECK (key_usage IN (
        'ENCRYPTION',
        'SIGNING',
        'KEY_AGREEMENT'
    )),

    CHECK (key_status IN (
        'ACTIVE',
        'REVOKED',
        'EXPIRED',
        'SUSPENDED'
    )),

    CHECK (
        (algorithm <> 'RSA')
        OR (
            modulus_bits BETWEEN 2048 AND 8192
            AND public_exponent >= 3
        )
    ),

    CHECK (
        expires_at IS NULL OR expires_at > created_at
    ),

    CHECK (
        (key_status = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (key_status <> 'REVOKED' AND revoked_at IS NULL)
    )
);

CREATE TABLE key_permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    user_id BIGINT NOT NULL
        REFERENCES users(user_id),

    permission VARCHAR(30) NOT NULL,

    granted_by BIGINT NOT NULL
        REFERENCES users(user_id),

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (key_id, user_id, permission),

    CHECK (permission IN (
        'ENCRYPT',
        'DECRYPT',
        'SIGN',
        'VERIFY',
        'MANAGE'
    ))
);

CREATE TABLE artifacts (
    artifact_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    artifact_name VARCHAR(200) NOT NULL,

    content_sha256 CHAR(64) NOT NULL,

    content_version INTEGER NOT NULL DEFAULT 1,

    created_by BIGINT NOT NULL
        REFERENCES users(user_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        organization_id,
        artifact_name,
        content_version
    ),

    CHECK (content_version > 0)
);

CREATE TABLE digital_signatures (
    signature_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id),

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    signer_user_id BIGINT NOT NULL
        REFERENCES users(user_id),

    signature_algorithm VARCHAR(40) NOT NULL,

    signature_value TEXT NOT NULL,

    signed_digest CHAR(64) NOT NULL,

    signed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    signature_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',

    CHECK (signature_algorithm IN (
        'RSA-PSS-SHA256',
        'ECDSA-SHA256',
        'ED25519'
    )),

    CHECK (signature_status IN (
        'PENDING',
        'VALID',
        'INVALID',
        'REVOKED'
    )),

    CHECK (length(signature_value) > 0)
);

CREATE TABLE verification_records (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    signature_id BIGINT NOT NULL
        REFERENCES digital_signatures(signature_id),

    verifier_user_id BIGINT NOT NULL
        REFERENCES users(user_id),

    verification_result BOOLEAN NOT NULL,

    verification_reason VARCHAR(200) NOT NULL,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE encryption_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    performed_by BIGINT NOT NULL
        REFERENCES users(user_id),

    operation_type VARCHAR(20) NOT NULL,

    encryption_algorithm VARCHAR(50) NOT NULL,

    ciphertext_reference TEXT,

    operation_status VARCHAR(20) NOT NULL,

    failure_reason VARCHAR(250),

    performed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (operation_type IN ('ENCRYPT', 'DECRYPT')),

    CHECK (operation_status IN (
        'SUCCESS',
        'FAILED',
        'REJECTED'
    )),

    CHECK (
        (operation_status = 'SUCCESS' AND failure_reason IS NULL)
        OR
        (operation_status <> 'SUCCESS')
    )
);

CREATE TABLE audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    actor_user_id BIGINT REFERENCES users(user_id),

    entity_type VARCHAR(40) NOT NULL,

    entity_id BIGINT,

    event_type VARCHAR(50) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_keys_organization_status
    ON cryptographic_keys(organization_id, key_status);

CREATE INDEX idx_keys_expiration
    ON cryptographic_keys(expires_at)
    WHERE key_status = 'ACTIVE';

CREATE INDEX idx_permissions_user
    ON key_permissions(user_id, permission);

CREATE INDEX idx_artifacts_organization
    ON artifacts(organization_id, created_at DESC);

CREATE INDEX idx_signatures_artifact
    ON digital_signatures(artifact_id, signed_at DESC);

CREATE INDEX idx_verification_signature
    ON verification_records(signature_id, verified_at DESC);

CREATE INDEX idx_operations_user_time
    ON encryption_operations(performed_by, performed_at DESC);

CREATE INDEX idx_audit_organization_time
    ON audit_events(organization_id, occurred_at DESC);

CREATE INDEX idx_audit_details
    ON audit_events USING GIN(event_details);

/*
 * Prevent accidental modification of public-key identity
 * fields after registration.
 */

CREATE OR REPLACE FUNCTION protect_key_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.external_key_id <> OLD.external_key_id
       OR NEW.fingerprint <> OLD.fingerprint
       OR NEW.public_key_pem <> OLD.public_key_pem
       OR NEW.algorithm <> OLD.algorithm
       OR NEW.modulus_bits <> OLD.modulus_bits
       OR NEW.public_exponent <> OLD.public_exponent
       OR NEW.key_usage <> OLD.key_usage THEN

        RAISE EXCEPTION
            'Cryptographic key identity is immutable';
    END IF;

    IF OLD.key_status = 'REVOKED'
       AND NEW.key_status <> 'REVOKED' THEN

        RAISE EXCEPTION
            'Revoked keys cannot be reactivated';
    END IF;

    IF OLD.key_status <> 'REVOKED'
       AND NEW.key_status = 'REVOKED' THEN

        NEW.revoked_at := CURRENT_TIMESTAMP;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protect_key_identity
BEFORE UPDATE ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION protect_key_identity();

/*
 * Validate organization ownership and identity
 * when registering a key permission.
 */

CREATE OR REPLACE FUNCTION validate_key_permission()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_org BIGINT;
    user_org BIGINT;
    manager_org BIGINT;
BEGIN
    SELECT organization_id
    INTO key_org
    FROM cryptographic_keys
    WHERE key_id = NEW.key_id;

    SELECT organization_id
    INTO user_org
    FROM users
    WHERE user_id = NEW.user_id
      AND is_active = TRUE;

    SELECT organization_id
    INTO manager_org
    FROM users
    WHERE user_id = NEW.granted_by
      AND is_active = TRUE
      AND role IN ('ADMIN', 'CRYPTO_OPERATOR');

    IF key_org IS NULL OR user_org IS NULL THEN
        RAISE EXCEPTION
            'Key or active target user does not exist';
    END IF;

    IF key_org <> user_org THEN
        RAISE EXCEPTION
            'Cross-organization permission is prohibited';
    END IF;

    IF manager_org IS DISTINCT FROM key_org THEN
        RAISE EXCEPTION
            'Granting user is not an authorized organization operator';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_key_permission
BEFORE INSERT ON key_permissions
FOR EACH ROW
EXECUTE FUNCTION validate_key_permission();

/*
 * Determine whether a key is eligible for a requested operation.
 */

CREATE OR REPLACE FUNCTION is_key_eligible(
    p_key_id BIGINT,
    p_user_id BIGINT,
    p_operation VARCHAR
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    eligible BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM cryptographic_keys k
        JOIN users u
          ON u.user_id = p_user_id
        JOIN key_permissions p
          ON p.key_id = k.key_id
         AND p.user_id = u.user_id
        WHERE k.key_id = p_key_id
          AND k.organization_id = u.organization_id
          AND u.is_active = TRUE
          AND k.key_status = 'ACTIVE'
          AND (
              k.expires_at IS NULL
              OR k.expires_at > CURRENT_TIMESTAMP
          )
          AND p.permission = p_operation
          AND (
              (p_operation IN ('ENCRYPT', 'DECRYPT')
               AND k.key_usage = 'ENCRYPTION')
              OR
              (p_operation IN ('SIGN', 'VERIFY')
               AND k.key_usage = 'SIGNING')
              OR
              p_operation = 'MANAGE'
          )
    )
    INTO eligible;

    RETURN eligible;
END;
$$;

/*
 * Record a successful or failed encryption operation.
 * Cryptographic processing itself occurs outside PostgreSQL.
 */

CREATE OR REPLACE PROCEDURE record_crypto_operation(
    p_key_id BIGINT,
    p_user_id BIGINT,
    p_operation VARCHAR,
    p_algorithm VARCHAR,
    p_reference TEXT,
    p_status VARCHAR,
    p_failure_reason VARCHAR DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    key_org BIGINT;
BEGIN
    SELECT organization_id
    INTO key_org
    FROM cryptographic_keys
    WHERE key_id = p_key_id;

    IF key_org IS NULL THEN
        RAISE EXCEPTION 'Unknown cryptographic key';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = p_user_id
          AND organization_id = key_org
          AND is_active = TRUE
    ) THEN
        RAISE EXCEPTION
            'User is inactive or belongs to another organization';
    END IF;

    IF p_operation NOT IN ('ENCRYPT', 'DECRYPT') THEN
        RAISE EXCEPTION 'Unsupported encryption operation';
    END IF;

    IF p_status NOT IN ('SUCCESS', 'FAILED', 'REJECTED') THEN
        RAISE EXCEPTION 'Invalid operation status';
    END IF;

    IF p_status = 'SUCCESS'
       AND NOT is_key_eligible(
           p_key_id,
           p_user_id,
           p_operation
       ) THEN

        RAISE EXCEPTION
            'Key eligibility check failed';
    END IF;

    INSERT INTO encryption_operations (
        organization_id,
        key_id,
        performed_by,
        operation_type,
        encryption_algorithm,
        ciphertext_reference,
        operation_status,
        failure_reason
    )
    VALUES (
        key_org,
        p_key_id,
        p_user_id,
        p_operation,
        p_algorithm,
        p_reference,
        p_status,
        p_failure_reason
    );

    INSERT INTO audit_events (
        organization_id,
        actor_user_id,
        entity_type,
        entity_id,
        event_type,
        event_details
    )
    VALUES (
        key_org,
        p_user_id,
        'CRYPTOGRAPHIC_KEY',
        p_key_id,
        'CRYPTO_OPERATION_RECORDED',
        jsonb_build_object(
            'operation', p_operation,
            'algorithm', p_algorithm,
            'status', p_status
        )
    );
END;
$$;

/*
 * Public key directory view.
 * Private key material is intentionally excluded.
 */

CREATE OR REPLACE VIEW active_public_key_directory AS
SELECT
    k.key_id,
    k.organization_id,
    o.organization_name,
    k.external_key_id,
    k.algorithm,
    k.key_usage,
    k.public_key_pem,
    k.fingerprint,
    k.modulus_bits,
    k.public_exponent,
    k.created_at,
    k.expires_at
FROM cryptographic_keys k
JOIN organizations o
    ON o.organization_id = k.organization_id
WHERE k.key_status = 'ACTIVE'
  AND (
      k.expires_at IS NULL
      OR k.expires_at > CURRENT_TIMESTAMP
  );

/*
 * Reporting view: cryptographic activity by organization.
 */

CREATE OR REPLACE VIEW cryptographic_activity_report AS
SELECT
    o.organization_id,
    o.organization_name,
    COUNT(DISTINCT k.key_id) AS registered_keys,
    COUNT(DISTINCT k.key_id)
        FILTER (WHERE k.key_status = 'ACTIVE') AS active_keys,
    COUNT(DISTINCT k.key_id)
        FILTER (WHERE k.key_status = 'REVOKED') AS revoked_keys,
    COUNT(DISTINCT op.operation_id) AS total_operations,
    COUNT(DISTINCT op.operation_id)
        FILTER (
            WHERE op.operation_status = 'SUCCESS'
        ) AS successful_operations,
    COUNT(DISTINCT op.operation_id)
        FILTER (
            WHERE op.operation_status <> 'SUCCESS'
        ) AS unsuccessful_operations
FROM organizations o
LEFT JOIN cryptographic_keys k
    ON k.organization_id = o.organization_id
LEFT JOIN encryption_operations op
    ON op.organization_id = o.organization_id
GROUP BY
    o.organization_id,
    o.organization_name;

/*
 * Demonstration data.
 */

INSERT INTO organizations (organization_name)
VALUES
    ('Secure Systems Laboratory'),
    ('Digital Research Division');

INSERT INTO users (
    organization_id,
    username,
    role
)
VALUES
    (1, 'security_admin', 'ADMIN'),
    (1, 'crypto_operator', 'CRYPTO_OPERATOR'),
    (1, 'developer_alice', 'DEVELOPER'),
    (1, 'security_auditor', 'AUDITOR'),
    (2, 'external_operator', 'CRYPTO_OPERATOR');

INSERT INTO cryptographic_keys (
    organization_id,
    owner_user_id,
    external_key_id,
    algorithm,
    key_usage,
    public_key_pem,
    fingerprint,
    modulus_bits,
    public_exponent,
    key_status
)
VALUES
(
    1,
    3,
    'rsa-signing-001',
    'RSA',
    'SIGNING',
    '-----BEGIN PUBLIC KEY----- DEMO_PUBLIC_KEY_A -----END PUBLIC KEY-----',
    repeat('a', 64),
    3072,
    65537,
    'ACTIVE'
),
(
    1,
    3,
    'rsa-encryption-001',
    'RSA',
    'ENCRYPTION',
    '-----BEGIN PUBLIC KEY----- DEMO_PUBLIC_KEY_B -----END PUBLIC KEY-----',
    repeat('b', 64),
    3072,
    65537,
    'ACTIVE'
),
(
    1,
    3,
    'rsa-retired-001',
    'RSA',
    'SIGNING',
    '-----BEGIN PUBLIC KEY----- DEMO_PUBLIC_KEY_C -----END PUBLIC KEY-----',
    repeat('c', 64),
    3072,
    65537,
    'REVOKED'
),
(
    2,
    5,
    'rsa-external-001',
    'RSA',
    'ENCRYPTION',
    '-----BEGIN PUBLIC KEY----- DEMO_PUBLIC_KEY_D -----END PUBLIC KEY-----',
    repeat('d', 64),
    3072,
    65537,
    'ACTIVE'
);

/*
 * Set revocation timestamp for demonstration key.
 */

UPDATE cryptographic_keys
SET revoked_at = CURRENT_TIMESTAMP
WHERE external_key_id = 'rsa-retired-001';

INSERT INTO key_permissions (
    key_id,
    user_id,
    permission,
    granted_by
)
VALUES
    (1, 3, 'SIGN', 1),
    (1, 4, 'VERIFY', 1),
    (2, 3, 'ENCRYPT', 1),
    (2, 3, 'DECRYPT', 1),
    (2, 4, 'VERIFY', 1),
    (3, 3, 'SIGN', 1),
    (4, 5, 'ENCRYPT', 5);

/*
 * The permission trigger requires an ADMIN or CRYPTO_OPERATOR
 * in the same organization. The external operator grants
 * its own organization's permission.
 */

INSERT INTO artifacts (
    organization_id,
    artifact_name,
    content_sha256,
    content_version,
    created_by
)
VALUES
(
    1,
    'release-binary-001',
    repeat('1', 64),
    1,
    3
),
(
    1,
    'configuration-package-001',
    repeat('2', 64),
    1,
    3
);

INSERT INTO digital_signatures (
    artifact_id,
    key_id,
    signer_user_id,
    signature_algorithm,
    signature_value,
    signed_digest,
    signature_status
)
VALUES
(
    1,
    1,
    3,
    'RSA-PSS-SHA256',
    'DEMO_SIGNATURE_VALUE_001',
    repeat('1', 64),
    'VALID'
),
(
    2,
    1,
    3,
    'RSA-PSS-SHA256',
    'DEMO_SIGNATURE_VALUE_002',
    repeat('2', 64),
    'PENDING'
);

INSERT INTO verification_records (
    signature_id,
    verifier_user_id,
    verification_result,
    verification_reason
)
VALUES
(
    1,
    4,
    TRUE,
    'Valid signature verified by cryptographic service'
),
(
    2,
    4,
    FALSE,
    'Signature verification failed'
);

/*
 * Demonstrate eligible encryption.
 */

CALL record_crypto_operation(
    2,
    3,
    'ENCRYPT',
    'RSA-OAEP-SHA256',
    'vault://ciphertext/001',
    'SUCCESS'
);

/*
 * Record a rejected attempt without granting permission.
 * This operation is recorded as a failure, not executed.
 */

CALL record_crypto_operation(
    3,
    3,
    'ENCRYPT',
    'RSA-OAEP-SHA256',
    NULL,
    'REJECTED',
    'Key is revoked or lacks the required operation permission'
);

/*
 * RETRIEVAL: Active public-key directory.
 */

SELECT
    external_key_id,
    algorithm,
    key_usage,
    modulus_bits,
    fingerprint
FROM active_public_key_directory
ORDER BY external_key_id;

/*
 * VALIDATION: Key eligibility.
 */

SELECT
    k.external_key_id,
    u.username,
    p.permission,
    is_key_eligible(
        k.key_id,
        u.user_id,
        p.permission
    ) AS eligible
FROM cryptographic_keys k
JOIN key_permissions p
    ON p.key_id = k.key_id
JOIN users u
    ON u.user_id = p.user_id
ORDER BY k.key_id, u.user_id;

/*
 * AGGREGATION: Organization-level activity.
 */

SELECT *
FROM cryptographic_activity_report
ORDER BY organization_id;

/*
 * EVALUATION: Signature verification results.
 */

SELECT
    a.artifact_name,
    ds.signature_algorithm,
    ds.signature_status,
    vr.verification_result,
    vr.verification_reason,
    vr.verified_at
FROM verification_records vr
JOIN digital_signatures ds
    ON ds.signature_id = vr.signature_id
JOIN artifacts a
    ON a.artifact_id = ds.artifact_id
ORDER BY vr.verified_at DESC;

/*
 * REPORTING: Failed and rejected operations.
 */

SELECT
    o.organization_name,
    u.username,
    k.external_key_id,
    op.operation_type,
    op.operation_status,
    op.failure_reason,
    op.performed_at
FROM encryption_operations op
JOIN organizations o
    ON o.organization_id = op.organization_id
JOIN users u
    ON u.user_id = op.performed_by
JOIN cryptographic_keys k
    ON k.key_id = op.key_id
WHERE op.operation_status <> 'SUCCESS'
ORDER BY op.performed_at DESC;

/*
 * WORKFLOW PROCESSING:
 * Identify keys approaching expiration.
 */

SELECT
    external_key_id,
    expires_at,
    expires_at - CURRENT_TIMESTAMP AS remaining_lifetime
FROM cryptographic_keys
WHERE key_status = 'ACTIVE'
  AND expires_at IS NOT NULL
ORDER BY expires_at;

/*
 * ELIGIBILITY DETERMINATION:
 * Find active users who can sign using a signing key.
 */

SELECT
    u.username,
    k.external_key_id,
    is_key_eligible(
        k.key_id,
        u.user_id,
        'SIGN'
    ) AS can_sign
FROM users u
CROSS JOIN cryptographic_keys k
WHERE u.organization_id = k.organization_id
  AND u.is_active = TRUE
  AND k.key_usage = 'SIGNING'
ORDER BY u.username;

/*
 * TRANSACTION EXAMPLE:
 * A key can be revoked atomically with its audit event.
 */

SAVEPOINT before_key_revocation;

WITH revoked AS (
    UPDATE cryptographic_keys
    SET
        key_status = 'REVOKED',
        revoked_by = 1
    WHERE external_key_id = 'rsa-signing-001'
      AND key_status = 'ACTIVE'
    RETURNING key_id, organization_id
)
INSERT INTO audit_events (
    organization_id,
    actor_user_id,
    entity_type,
    entity_id,
    event_type,
    event_details
)
SELECT
    organization_id,
    1,
    'CRYPTographic_KEY',
    key_id,
    'KEY_REVOKED',
    jsonb_build_object(
        'reason', 'Demonstration of controlled revocation'
    )
FROM revoked;

-- Undo this demonstration so the sample directory remains active.
ROLLBACK TO SAVEPOINT before_key_revocation;

COMMIT;
