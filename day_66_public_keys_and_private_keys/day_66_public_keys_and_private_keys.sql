-- ============================================================
-- PUBLIC KEYS AND PRIVATE KEYS
-- PostgreSQL 16+ relational key-management implementation
--
-- Models:
--   Organizations
--   Users and service identities
--   Cryptographic algorithms
--   Public-key registration
--   Private-key custody metadata
--   Key purposes
--   Key fingerprints
--   Key versions
--   Certificates
--   Key rotation
--   Key revocation
--   Key expiration
--   Encryption operations
--   Digital signatures
--   Verification results
--   Key-exchange sessions
--   Access policies
--   Audit events
--
-- IMPORTANT:
-- This database stores public-key material and private-key
-- custody references, not plaintext private-key material.
-- Private keys must remain in a KMS, HSM, or protected keystore.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS cryptography;

SET search_path TO cryptography, public;


-- ============================================================
-- ENUM TYPES
-- ============================================================

CREATE TYPE key_algorithm AS ENUM (
    'RSA',
    'ED25519',
    'X25519',
    'ECDSA_P256',
    'ECDSA_P384',
    'AES_256'
);

CREATE TYPE key_purpose AS ENUM (
    'ENCRYPTION',
    'SIGNING',
    'KEY_AGREEMENT',
    'AUTHENTICATION'
);

CREATE TYPE key_status AS ENUM (
    'PENDING',
    'ACTIVE',
    'ROTATED',
    'REVOKED',
    'EXPIRED',
    'COMPROMISED',
    'DESTROYED'
);

CREATE TYPE key_storage_type AS ENUM (
    'HSM',
    'KMS',
    'SOFTWARE_KEYSTORE',
    'EXTERNAL_PROVIDER'
);

CREATE TYPE certificate_status AS ENUM (
    'VALID',
    'EXPIRED',
    'REVOKED',
    'SUSPENDED'
);

CREATE TYPE operation_type AS ENUM (
    'ENCRYPTION',
    'DECRYPTION',
    'SIGNING',
    'VERIFICATION',
    'KEY_AGREEMENT'
);

CREATE TYPE operation_status AS ENUM (
    'SUCCESS',
    'FAILED',
    'REJECTED'
);

CREATE TYPE access_decision AS ENUM (
    'ALLOW',
    'DENY'
);


-- ============================================================
-- ORGANIZATIONS
-- ============================================================

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_name VARCHAR(200) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT organization_name_not_empty
        CHECK (LENGTH(TRIM(organization_name)) > 0)
);


-- ============================================================
-- IDENTITIES
-- ============================================================

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    identity_name VARCHAR(200) NOT NULL,

    identity_type VARCHAR(30) NOT NULL
        CHECK (
            identity_type IN (
                'HUMAN',
                'SERVICE',
                'APPLICATION',
                'DEVICE'
            )
        ),

    email VARCHAR(255),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (organization_id, identity_name),

    CONSTRAINT identity_name_not_empty
        CHECK (LENGTH(TRIM(identity_name)) > 0)
);


-- ============================================================
-- CRYPTOGRAPHIC ALGORITHM CATALOG
-- ============================================================

CREATE TABLE algorithm_catalog (
    algorithm_id SMALLINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    algorithm_name key_algorithm NOT NULL UNIQUE,

    algorithm_family VARCHAR(40) NOT NULL,

    minimum_key_bits INTEGER,

    recommended_key_bits INTEGER,

    supports_encryption BOOLEAN NOT NULL DEFAULT FALSE,

    supports_signing BOOLEAN NOT NULL DEFAULT FALSE,

    supports_key_agreement BOOLEAN NOT NULL DEFAULT FALSE,

    approved_for_new_keys BOOLEAN NOT NULL DEFAULT TRUE,

    notes TEXT,

    CONSTRAINT valid_key_sizes
        CHECK (
            minimum_key_bits IS NULL
            OR recommended_key_bits IS NULL
            OR recommended_key_bits >= minimum_key_bits
        )
);


INSERT INTO algorithm_catalog (
    algorithm_name,
    algorithm_family,
    minimum_key_bits,
    recommended_key_bits,
    supports_encryption,
    supports_signing,
    supports_key_agreement,
    notes
)
VALUES
(
    'RSA',
    'ASYMMETRIC',
    2048,
    3072,
    TRUE,
    TRUE,
    FALSE,
    'RSA encryption should use OAEP. Signatures should use PSS.'
),
(
    'ED25519',
    'ASYMMETRIC',
    256,
    256,
    FALSE,
    TRUE,
    FALSE,
    'Ed25519 is used for digital signatures.'
),
(
    'X25519',
    'ASYMMETRIC',
    256,
    256,
    FALSE,
    FALSE,
    TRUE,
    'X25519 is used for Diffie-Hellman key agreement.'
),
(
    'ECDSA_P256',
    'ASYMMETRIC',
    256,
    256,
    FALSE,
    TRUE,
    FALSE,
    'Elliptic-curve digital signature algorithm.'
),
(
    'ECDSA_P384',
    'ASYMMETRIC',
    384,
    384,
    FALSE,
    TRUE,
    FALSE,
    'Higher-security elliptic-curve signature configuration.'
),
(
    'AES_256',
    'SYMMETRIC',
    256,
    256,
    TRUE,
    FALSE,
    FALSE,
    'Symmetric encryption key. Not a public/private key pair.'
);


-- ============================================================
-- KEY MANAGEMENT POLICIES
-- ============================================================

CREATE TABLE key_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    policy_name VARCHAR(150) NOT NULL,

    algorithm_name key_algorithm NOT NULL,

    purpose key_purpose NOT NULL,

    minimum_key_bits INTEGER NOT NULL,

    maximum_validity_days INTEGER NOT NULL,

    require_hsm BOOLEAN NOT NULL DEFAULT FALSE,

    require_rotation BOOLEAN NOT NULL DEFAULT TRUE,

    require_certificate BOOLEAN NOT NULL DEFAULT FALSE,

    allow_software_private_keys BOOLEAN NOT NULL DEFAULT FALSE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (
        organization_id,
        policy_name,
        algorithm_name,
        purpose
    ),

    CHECK (minimum_key_bits > 0),

    CHECK (maximum_validity_days BETWEEN 1 AND 3650)
);


-- ============================================================
-- KEY PAIRS
--
-- Public material can be stored in public_key_pem.
-- Private-key bytes are never stored in this table.
-- private_key_reference identifies an external secure store.
-- ============================================================

CREATE TABLE cryptographic_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    owner_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    algorithm_name key_algorithm NOT NULL
        REFERENCES algorithm_catalog(algorithm_name),

    purpose key_purpose NOT NULL,

    key_version INTEGER NOT NULL DEFAULT 1,

    key_status key_status NOT NULL DEFAULT 'PENDING',

    key_size_bits INTEGER NOT NULL,

    public_key_pem TEXT,

    public_key_fingerprint CHAR(64) NOT NULL,

    fingerprint_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',

    storage_type key_storage_type,

    private_key_reference VARCHAR(500),

    parent_key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    policy_id BIGINT
        REFERENCES key_policies(policy_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    activated_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    compromised_at TIMESTAMPTZ,

    destroyed_at TIMESTAMPTZ,

    revocation_reason TEXT,

    CONSTRAINT valid_key_size
        CHECK (key_size_bits > 0),

    CONSTRAINT valid_key_version
        CHECK (key_version > 0),

    CONSTRAINT valid_fingerprint
        CHECK (
            public_key_fingerprint ~ '^[0-9a-fA-F]{64}$'
        ),

    CONSTRAINT valid_key_dates
        CHECK (expires_at > created_at),

    CONSTRAINT valid_private_key_reference
        CHECK (
            key_status = 'DESTROYED'
            OR private_key_reference IS NOT NULL
            OR algorithm_name = 'AES_256'
        ),

    UNIQUE (
        owner_identity_id,
        algorithm_name,
        purpose,
        key_version
    )
);


-- Prevent accidental reuse of an active or retired public key
-- inside an organization.
CREATE UNIQUE INDEX uq_active_public_fingerprint
ON cryptographic_keys (
    organization_id,
    public_key_fingerprint
)
WHERE key_status IN (
    'PENDING',
    'ACTIVE',
    'ROTATED',
    'EXPIRED'
);


CREATE INDEX idx_keys_owner_status
ON cryptographic_keys (
    owner_identity_id,
    key_status
);

CREATE INDEX idx_keys_expiration
ON cryptographic_keys (
    expires_at
)
WHERE key_status = 'ACTIVE';

CREATE INDEX idx_keys_organization_purpose
ON cryptographic_keys (
    organization_id,
    purpose,
    algorithm_name
);

CREATE INDEX idx_keys_parent
ON cryptographic_keys(parent_key_id);


-- ============================================================
-- KEY STATUS VALIDATION TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION validate_key_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF TG_OP = 'UPDATE' THEN

        IF OLD.key_status = 'DESTROYED'
           AND NEW.key_status <> 'DESTROYED' THEN

            RAISE EXCEPTION
                'Destroyed keys cannot return to another state.';

        END IF;

        IF OLD.key_status = 'REVOKED'
           AND NEW.key_status <> 'REVOKED'
           AND NEW.key_status <> 'DESTROYED' THEN

            RAISE EXCEPTION
                'Revoked keys cannot be reactivated.';

        END IF;

        IF OLD.key_status = 'COMPROMISED'
           AND NEW.key_status NOT IN (
               'COMPROMISED',
               'DESTROYED'
           ) THEN

            RAISE EXCEPTION
                'Compromised keys cannot be reactivated.';

        END IF;

        IF NEW.key_status = 'ACTIVE'
           AND OLD.key_status NOT IN (
               'PENDING',
               'ACTIVE'
           ) THEN

            RAISE EXCEPTION
                'Invalid transition to ACTIVE.';

        END IF;

    END IF;

    IF NEW.key_status = 'ACTIVE'
       AND NEW.expires_at <= CURRENT_TIMESTAMP THEN

        RAISE EXCEPTION
            'Expired keys cannot be activated.';

    END IF;

    IF NEW.key_status = 'REVOKED'
       AND NEW.revoked_at IS NULL THEN

        NEW.revoked_at := CURRENT_TIMESTAMP;

    END IF;

    IF NEW.key_status = 'COMPROMISED'
       AND NEW.compromised_at IS NULL THEN

        NEW.compromised_at := CURRENT_TIMESTAMP;

    END IF;

    IF NEW.key_status = 'DESTROYED'
       AND NEW.destroyed_at IS NULL THEN

        NEW.destroyed_at := CURRENT_TIMESTAMP;

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_validate_key_transition
BEFORE INSERT OR UPDATE ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION validate_key_transition();


-- ============================================================
-- KEY CERTIFICATES
-- ============================================================

CREATE TABLE key_certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    serial_number VARCHAR(150) NOT NULL UNIQUE,

    issuer_name VARCHAR(255) NOT NULL,

    subject_name VARCHAR(255) NOT NULL,

    certificate_pem TEXT NOT NULL,

    certificate_status certificate_status NOT NULL DEFAULT 'VALID',

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (not_after > not_before)
);


CREATE INDEX idx_certificates_key_status
ON key_certificates(key_id, certificate_status);

CREATE INDEX idx_certificates_expiration
ON key_certificates(not_after);


-- ============================================================
-- KEY ACCESS POLICIES
-- ============================================================

CREATE TABLE key_access_policies (
    access_policy_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    policy_name VARCHAR(150) NOT NULL,

    allowed_purpose key_purpose NOT NULL,

    require_active_key BOOLEAN NOT NULL DEFAULT TRUE,

    require_owner_match BOOLEAN NOT NULL DEFAULT TRUE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (organization_id, policy_name)
);


CREATE TABLE key_access_grants (
    grant_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    access_policy_id BIGINT NOT NULL
        REFERENCES key_access_policies(access_policy_id),

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (key_id, identity_id, access_policy_id),

    CHECK (
        expires_at IS NULL
        OR expires_at > granted_at
    )
);


CREATE INDEX idx_grants_identity
ON key_access_grants(identity_id, is_active);


CREATE INDEX idx_grants_key
ON key_access_grants(key_id, is_active);


-- ============================================================
-- CRYPTOGRAPHIC OPERATIONS
-- ============================================================

CREATE TABLE cryptographic_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    requested_by BIGINT NOT NULL
        REFERENCES identities(identity_id),

    operation operation_type NOT NULL,

    operation_status operation_status NOT NULL,

    algorithm_used VARCHAR(100) NOT NULL,

    data_reference VARCHAR(500),

    error_code VARCHAR(100),

    execution_time_ms NUMERIC(12,3),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        execution_time_ms IS NULL
        OR execution_time_ms >= 0
    )
);


CREATE INDEX idx_operations_key_date
ON cryptographic_operations(
    key_id,
    created_at DESC
);

CREATE INDEX idx_operations_status_date
ON cryptographic_operations(
    operation_status,
    created_at DESC
);


-- ============================================================
-- DIGITAL SIGNATURE RECORDS
-- ============================================================

CREATE TABLE digital_signatures (
    signature_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    signer_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    document_reference VARCHAR(500) NOT NULL,

    document_hash CHAR(64) NOT NULL,

    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',

    signature_algorithm VARCHAR(50) NOT NULL,

    signature_value TEXT NOT NULL,

    signed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (key_id, document_reference, document_hash),

    CHECK (
        document_hash ~ '^[0-9a-fA-F]{64}$'
    )
);


CREATE TABLE signature_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    signature_id BIGINT NOT NULL
        REFERENCES digital_signatures(signature_id),

    verifier_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    is_valid BOOLEAN NOT NULL,

    verification_reason TEXT,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE INDEX idx_signatures_document
ON digital_signatures(document_reference);

CREATE INDEX idx_verifications_signature
ON signature_verifications(signature_id, verified_at DESC);


-- ============================================================
-- KEY AGREEMENT SESSIONS
-- ============================================================

CREATE TABLE key_agreement_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    initiator_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    responder_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    agreement_algorithm VARCHAR(50) NOT NULL DEFAULT 'X25519',

    initiator_public_key_fingerprint CHAR(64) NOT NULL,

    responder_public_key_fingerprint CHAR(64) NOT NULL,

    derived_key_reference VARCHAR(500),

    context_identifier VARCHAR(200) NOT NULL,

    established_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ NOT NULL,

    session_active BOOLEAN NOT NULL DEFAULT TRUE,

    CHECK (initiator_key_id <> responder_key_id),

    CHECK (expires_at > CURRENT_TIMESTAMP)
);


CREATE INDEX idx_sessions_expiration
ON key_agreement_sessions(expires_at)
WHERE session_active = TRUE;


-- ============================================================
-- AUDIT LOG
-- ============================================================

CREATE TABLE key_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    actor_identity_id BIGINT
        REFERENCES identities(identity_id),

    event_type VARCHAR(80) NOT NULL,

    old_status key_status,

    new_status key_status,

    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE INDEX idx_audit_key_date
ON key_audit_events(key_id, occurred_at DESC);

CREATE INDEX idx_audit_event_type
ON key_audit_events(event_type, occurred_at DESC);


-- ============================================================
-- KEY AUDIT TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION audit_key_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_event_type VARCHAR(80);
    v_old_status key_status;
BEGIN

    IF TG_OP = 'INSERT' THEN

        v_event_type := 'KEY_CREATED';
        v_old_status := NULL;

    ELSIF OLD.key_status IS DISTINCT FROM NEW.key_status THEN

        v_old_status := OLD.key_status;

        v_event_type := CASE NEW.key_status
            WHEN 'ACTIVE' THEN 'KEY_ACTIVATED'
            WHEN 'ROTATED' THEN 'KEY_ROTATED'
            WHEN 'REVOKED' THEN 'KEY_REVOKED'
            WHEN 'EXPIRED' THEN 'KEY_EXPIRED'
            WHEN 'COMPROMISED' THEN 'KEY_COMPROMISED'
            WHEN 'DESTROYED' THEN 'KEY_DESTROYED'
            ELSE 'KEY_STATUS_CHANGED'
        END;

    ELSE
        RETURN NEW;
    END IF;

    INSERT INTO key_audit_events (
        key_id,
        event_type,
        old_status,
        new_status,
        event_details
    )
    VALUES (
        NEW.key_id,
        v_event_type,
        v_old_status,
        NEW.key_status,
        jsonb_build_object(
            'algorithm', NEW.algorithm_name,
            'purpose', NEW.purpose,
            'fingerprint', NEW.public_key_fingerprint
        )
    );

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_audit_key_changes
AFTER INSERT OR UPDATE ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION audit_key_changes();


-- ============================================================
-- KEY REGISTRATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION register_public_key(
    p_organization_id BIGINT,
    p_owner_identity_id BIGINT,
    p_algorithm key_algorithm,
    p_purpose key_purpose,
    p_key_size_bits INTEGER,
    p_public_key_pem TEXT,
    p_fingerprint CHAR(64),
    p_storage_type key_storage_type,
    p_private_key_reference VARCHAR(500),
    p_validity_days INTEGER,
    p_policy_id BIGINT DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id BIGINT;
    v_max_validity INTEGER;
    v_minimum_bits INTEGER;
    v_policy_algorithm key_algorithm;
    v_policy_purpose key_purpose;
BEGIN

    IF p_validity_days <= 0 OR p_validity_days > 3650 THEN
        RAISE EXCEPTION 'Invalid key validity period.';
    END IF;

    IF p_fingerprint !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid SHA-256 fingerprint.';
    END IF;

    IF p_key_size_bits <= 0 THEN
        RAISE EXCEPTION 'Key size must be positive.';
    END IF;

    IF p_algorithm = 'RSA'
       AND p_key_size_bits < 2048 THEN

        RAISE EXCEPTION
            'RSA keys must contain at least 2048 bits.';
    END IF;

    IF p_algorithm = 'X25519'
       AND p_purpose <> 'KEY_AGREEMENT' THEN

        RAISE EXCEPTION
            'X25519 is restricted to key agreement.';
    END IF;

    IF p_algorithm = 'ED25519'
       AND p_purpose <> 'SIGNING' THEN

        RAISE EXCEPTION
            'Ed25519 is restricted to signing.';
    END IF;

    IF p_algorithm = 'AES_256'
       AND p_key_size_bits <> 256 THEN

        RAISE EXCEPTION
            'AES_256 requires exactly 256 bits.';
    END IF;

    IF p_policy_id IS NOT NULL THEN

        SELECT
            maximum_validity_days,
            minimum_key_bits,
            algorithm_name,
            purpose
        INTO
            v_max_validity,
            v_minimum_bits,
            v_policy_algorithm,
            v_policy_purpose
        FROM key_policies
        WHERE policy_id = p_policy_id
          AND organization_id = p_organization_id
          AND is_active = TRUE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Active policy not found.';
        END IF;

        IF p_validity_days > v_max_validity THEN
            RAISE EXCEPTION
                'Key validity exceeds policy.';
        END IF;

        IF p_key_size_bits < v_minimum_bits THEN
            RAISE EXCEPTION
                'Key size violates policy.';
        END IF;

        IF p_algorithm <> v_policy_algorithm
           OR p_purpose <> v_policy_purpose THEN

            RAISE EXCEPTION
                'Algorithm or purpose does not match policy.';
        END IF;

    END IF;

    INSERT INTO cryptographic_keys (
        organization_id,
        owner_identity_id,
        algorithm_name,
        purpose,
        key_status,
        key_size_bits,
        public_key_pem,
        public_key_fingerprint,
        storage_type,
        private_key_reference,
        policy_id,
        activated_at,
        expires_at
    )
    VALUES (
        p_organization_id,
        p_owner_identity_id,
        p_algorithm,
        p_purpose,
        'ACTIVE',
        p_key_size_bits,
        p_public_key_pem,
        p_fingerprint,
        p_storage_type,
        p_private_key_reference,
        p_policy_id,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP + make_interval(days => p_validity_days)
    )
    RETURNING key_id INTO v_key_id;

    RETURN v_key_id;
END;
$$;


-- ============================================================
-- KEY ROTATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE rotate_public_key(
    p_old_key_id BIGINT,
    p_new_public_key_pem TEXT,
    p_new_fingerprint CHAR(64),
    p_new_private_key_reference VARCHAR(500),
    p_new_storage_type key_storage_type
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_old cryptographic_keys%ROWTYPE;
    v_new_key_id BIGINT;
BEGIN

    SELECT *
    INTO v_old
    FROM cryptographic_keys
    WHERE key_id = p_old_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Original key not found.';
    END IF;

    IF v_old.key_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Only active keys can be rotated.';
    END IF;

    IF v_old.expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Expired keys cannot be rotated.';
    END IF;

    IF p_new_fingerprint !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid new fingerprint.';
    END IF;

    UPDATE cryptographic_keys
    SET key_status = 'ROTATED'
    WHERE key_id = p_old_key_id;

    INSERT INTO cryptographic_keys (
        organization_id,
        owner_identity_id,
        algorithm_name,
        purpose,
        key_version,
        key_status,
        key_size_bits,
        public_key_pem,
        public_key_fingerprint,
        storage_type,
        private_key_reference,
        parent_key_id,
        policy_id,
        activated_at,
        expires_at
    )
    VALUES (
        v_old.organization_id,
        v_old.owner_identity_id,
        v_old.algorithm_name,
        v_old.purpose,
        v_old.key_version + 1,
        'ACTIVE',
        v_old.key_size_bits,
        p_new_public_key_pem,
        p_new_fingerprint,
        p_new_storage_type,
        p_new_private_key_reference,
        p_old_key_id,
        v_old.policy_id,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP + (
            v_old.expires_at - v_old.created_at
        )
    )
    RETURNING key_id INTO v_new_key_id;

    INSERT INTO key_audit_events (
        key_id,
        event_type,
        old_status,
        new_status,
        event_details
    )
    VALUES (
        v_new_key_id,
        'KEY_ROTATION_SUCCESSOR_CREATED',
        NULL,
        'ACTIVE',
        jsonb_build_object(
            'previous_key_id', p_old_key_id,
            'new_key_id', v_new_key_id
        )
    );

END;
$$;


-- ============================================================
-- KEY REVOCATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION revoke_public_key(
    p_key_id BIGINT,
    p_reason TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_status key_status;
BEGIN

    IF p_reason IS NULL OR LENGTH(TRIM(p_reason)) = 0 THEN
        RAISE EXCEPTION 'Revocation reason is mandatory.';
    END IF;

    SELECT key_status
    INTO v_status
    FROM cryptographic_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Key not found.';
    END IF;

    IF v_status IN ('REVOKED', 'DESTROYED') THEN
        RAISE EXCEPTION 'Key cannot be revoked again.';
    END IF;

    UPDATE cryptographic_keys
    SET
        key_status = 'REVOKED',
        revoked_at = CURRENT_TIMESTAMP,
        revocation_reason = p_reason
    WHERE key_id = p_key_id;

    UPDATE key_certificates
    SET certificate_status = 'REVOKED'
    WHERE key_id = p_key_id
      AND certificate_status = 'VALID';

    RETURN TRUE;
END;
$$;


-- ============================================================
-- KEY ELIGIBILITY FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION is_key_eligible(
    p_key_id BIGINT,
    p_expected_purpose key_purpose
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_key cryptographic_keys%ROWTYPE;
    v_policy key_policies%ROWTYPE;
BEGIN

    SELECT *
    INTO v_key
    FROM cryptographic_keys
    WHERE key_id = p_key_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF v_key.key_status <> 'ACTIVE' THEN
        RETURN FALSE;
    END IF;

    IF v_key.expires_at <= CURRENT_TIMESTAMP THEN
        RETURN FALSE;
    END IF;

    IF v_key.purpose <> p_expected_purpose THEN
        RETURN FALSE;
    END IF;

    IF v_key.policy_id IS NOT NULL THEN

        SELECT *
        INTO v_policy
        FROM key_policies
        WHERE policy_id = v_key.policy_id;

        IF NOT FOUND OR NOT v_policy.is_active THEN
            RETURN FALSE;
        END IF;

        IF v_key.key_size_bits < v_policy.minimum_key_bits THEN
            RETURN FALSE;
        END IF;

        IF v_policy.require_hsm
           AND v_key.storage_type <> 'HSM' THEN

            RETURN FALSE;
        END IF;

    END IF;

    RETURN TRUE;
END;
$$;


-- ============================================================
-- ACCESS EVALUATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_key_access(
    p_key_id BIGINT,
    p_identity_id BIGINT,
    p_access_policy_id BIGINT
)
RETURNS access_decision
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_key cryptographic_keys%ROWTYPE;
    v_identity identities%ROWTYPE;
    v_policy key_access_policies%ROWTYPE;
    v_grant key_access_grants%ROWTYPE;
BEGIN

    SELECT *
    INTO v_key
    FROM cryptographic_keys
    WHERE key_id = p_key_id;

    IF NOT FOUND THEN
        RETURN 'DENY';
    END IF;

    SELECT *
    INTO v_identity
    FROM identities
    WHERE identity_id = p_identity_id
      AND is_active = TRUE;

    IF NOT FOUND THEN
        RETURN 'DENY';
    END IF;

    SELECT *
    INTO v_policy
    FROM key_access_policies
    WHERE access_policy_id = p_access_policy_id
      AND organization_id = v_key.organization_id
      AND is_active = TRUE;

    IF NOT FOUND THEN
        RETURN 'DENY';
    END IF;

    IF v_policy.require_active_key
       AND NOT is_key_eligible(
           p_key_id,
           v_policy.allowed_purpose
       ) THEN

        RETURN 'DENY';
    END IF;

    IF v_policy.require_owner_match
       AND v_key.owner_identity_id <> p_identity_id THEN

        SELECT *
        INTO v_grant
        FROM key_access_grants
        WHERE key_id = p_key_id
          AND identity_id = p_identity_id
          AND access_policy_id = p_access_policy_id
          AND is_active = TRUE
          AND (
              expires_at IS NULL
              OR expires_at > CURRENT_TIMESTAMP
          );

        IF NOT FOUND THEN
            RETURN 'DENY';
        END IF;

    END IF;

    RETURN 'ALLOW';
END;
$$;


-- ============================================================
-- KEY EXPIRATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE expire_inactive_keys()
LANGUAGE plpgsql
AS $$
BEGIN

    UPDATE cryptographic_keys
    SET key_status = 'EXPIRED'
    WHERE key_status = 'ACTIVE'
      AND expires_at <= CURRENT_TIMESTAMP;

    UPDATE key_certificates
    SET certificate_status = 'EXPIRED'
    WHERE certificate_status = 'VALID'
      AND not_after <= CURRENT_TIMESTAMP;

    UPDATE key_agreement_sessions
    SET session_active = FALSE
    WHERE session_active = TRUE
      AND expires_at <= CURRENT_TIMESTAMP;

END;
$$;


-- ============================================================
-- REPORTING VIEW: ACTIVE KEY INVENTORY
-- ============================================================

CREATE VIEW active_key_inventory AS
SELECT
    k.key_id,
    o.organization_name,
    i.identity_name AS owner,
    k.algorithm_name,
    k.purpose,
    k.key_version,
    k.key_size_bits,
    k.storage_type,
    k.public_key_fingerprint,
    k.created_at,
    k.expires_at,
    k.policy_id
FROM cryptographic_keys k
JOIN organizations o
    ON o.organization_id = k.organization_id
JOIN identities i
    ON i.identity_id = k.owner_identity_id
WHERE k.key_status = 'ACTIVE'
  AND k.expires_at > CURRENT_TIMESTAMP;


-- ============================================================
-- REPORTING VIEW: KEY LIFECYCLE
-- ============================================================

CREATE VIEW key_lifecycle_report AS
SELECT
    organization_id,
    algorithm_name,
    purpose,
    key_status,
    COUNT(*) AS total_keys,
    MIN(created_at) AS earliest_creation,
    MAX(created_at) AS latest_creation
FROM cryptographic_keys
GROUP BY
    organization_id,
    algorithm_name,
    purpose,
    key_status;


-- ============================================================
-- REPORTING VIEW: CRYPTOGRAPHIC OPERATION SUCCESS
-- ============================================================

CREATE VIEW cryptographic_operation_report AS
SELECT
    operation,
    algorithm_used,
    operation_status,
    COUNT(*) AS operation_count,
    ROUND(AVG(execution_time_ms), 3) AS average_execution_ms,
    ROUND(MAX(execution_time_ms), 3) AS maximum_execution_ms
FROM cryptographic_operations
GROUP BY
    operation,
    algorithm_used,
    operation_status;


-- ============================================================
-- SAMPLE ORGANIZATIONS
-- ============================================================

INSERT INTO organizations (
    organization_name
)
VALUES
    ('National Digital Finance'),
    ('Enterprise Research Systems');


-- ============================================================
-- SAMPLE IDENTITIES
-- ============================================================

INSERT INTO identities (
    organization_id,
    identity_name,
    identity_type,
    email
)
VALUES
    (1, 'payment-service', 'SERVICE', 'payments@example.org'),
    (1, 'identity-service', 'SERVICE', 'identity@example.org'),
    (1, 'security-admin', 'HUMAN', 'security@example.org'),
    (1, 'audit-service', 'SERVICE', 'audit@example.org'),
    (2, 'research-application', 'APPLICATION', 'research@example.org');


-- ============================================================
-- SAMPLE POLICIES
-- ============================================================

INSERT INTO key_policies (
    organization_id,
    policy_name,
    algorithm_name,
    purpose,
    minimum_key_bits,
    maximum_validity_days,
    require_hsm,
    require_rotation,
    require_certificate,
    allow_software_private_keys
)
VALUES
(
    1,
    'RSA Signing Standard',
    'RSA',
    'SIGNING',
    2048,
    365,
    TRUE,
    TRUE,
    TRUE,
    FALSE
),
(
    1,
    'Ed25519 Signing Standard',
    'ED25519',
    'SIGNING',
    256,
    365,
    FALSE,
    TRUE,
    FALSE,
    TRUE
),
(
    1,
    'X25519 Session Standard',
    'X25519',
    'KEY_AGREEMENT',
    256,
    90,
    TRUE,
    TRUE,
    FALSE,
    FALSE
),
(
    2,
    'Research RSA Encryption',
    'RSA',
    'ENCRYPTION',
    2048,
    730,
    FALSE,
    TRUE,
    FALSE,
    TRUE
);


-- ============================================================
-- SAMPLE KEY REGISTRATION
--
-- Public-key values below are illustrative metadata strings.
-- Fingerprints are fixed 64-character sample identifiers.
-- These rows do not contain usable cryptographic key material.
-- ============================================================

INSERT INTO cryptographic_keys (
    organization_id,
    owner_identity_id,
    algorithm_name,
    purpose,
    key_version,
    key_status,
    key_size_bits,
    public_key_pem,
    public_key_fingerprint,
    storage_type,
    private_key_reference,
    policy_id,
    activated_at,
    expires_at
)
VALUES
(
    1,
    1,
    'RSA',
    'SIGNING',
    1,
    'ACTIVE',
    3072,
    'PUBLIC-KEY-PEM-DEMO-RSA-001',
    repeat('a', 64),
    'HSM',
    'hsm://finance/payment/signing/v1',
    1,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '365 days'
),
(
    1,
    2,
    'ED25519',
    'SIGNING',
    1,
    'ACTIVE',
    256,
    'PUBLIC-KEY-PEM-DEMO-ED25519-001',
    repeat('b', 64),
    'SOFTWARE_KEYSTORE',
    'keystore://identity/signing/v1',
    2,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '365 days'
),
(
    1,
    1,
    'RSA',
    'ENCRYPTION',
    1,
    'ROTATED',
    3072,
    'PUBLIC-KEY-PEM-DEMO-RSA-OLD',
    repeat('c', 64),
    'HSM',
    'hsm://finance/payment/encryption/v1',
    NULL,
    CURRENT_TIMESTAMP - INTERVAL '400 days',
    CURRENT_TIMESTAMP - INTERVAL '30 days'
),
(
    1,
    1,
    'X25519',
    'KEY_AGREEMENT',
    1,
    'REVOKED',
    256,
    'PUBLIC-KEY-PEM-DEMO-X25519-001',
    repeat('d', 64),
    'HSM',
    'hsm://finance/payment/agreement/v1',
    3,
    CURRENT_TIMESTAMP - INTERVAL '30 days',
    CURRENT_TIMESTAMP + INTERVAL '60 days'
),
(
    2,
    5,
    'RSA',
    'ENCRYPTION',
    1,
    'EXPIRED',
    2048,
    'PUBLIC-KEY-PEM-DEMO-RESEARCH-001',
    repeat('e', 64),
    'SOFTWARE_KEYSTORE',
    'keystore://research/encryption/v1',
    4,
    CURRENT_TIMESTAMP - INTERVAL '800 days',
    CURRENT_TIMESTAMP - INTERVAL '70 days'
);


-- ============================================================
-- SAMPLE CERTIFICATES
-- ============================================================

INSERT INTO key_certificates (
    key_id,
    serial_number,
    issuer_name,
    subject_name,
    certificate_pem,
    certificate_status,
    not_before,
    not_after
)
VALUES
(
    1,
    'CERT-2026-0001',
    'National Digital Finance Root CA',
    'payment-service',
    'DEMO-CERTIFICATE-RSA',
    'VALID',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '364 days'
),
(
    2,
    'CERT-2026-0002',
    'National Digital Finance Root CA',
    'identity-service',
    'DEMO-CERTIFICATE-ED25519',
    'VALID',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '364 days'
),
(
    3,
    'CERT-2025-0003',
    'National Digital Finance Root CA',
    'payment-encryption-old',
    'DEMO-OLD-CERTIFICATE',
    'EXPIRED',
    CURRENT_TIMESTAMP - INTERVAL '500 days',
    CURRENT_TIMESTAMP - INTERVAL '30 days'
);


-- ============================================================
-- ACCESS POLICIES AND GRANTS
-- ============================================================

INSERT INTO key_access_policies (
    organization_id,
    policy_name,
    allowed_purpose,
    require_active_key,
    require_owner_match
)
VALUES
(
    1,
    'Payment Signing Access',
    'SIGNING',
    TRUE,
    FALSE
),
(
    1,
    'Identity Signing Access',
    'SIGNING',
    TRUE,
    TRUE
);


INSERT INTO key_access_grants (
    key_id,
    identity_id,
    access_policy_id,
    expires_at
)
VALUES
(
    1,
    4,
    1,
    CURRENT_TIMESTAMP + INTERVAL '30 days'
);


-- ============================================================
-- SAMPLE CRYPTOGRAPHIC OPERATIONS
-- ============================================================

INSERT INTO cryptographic_operations (
    key_id,
    requested_by,
    operation,
    operation_status,
    algorithm_used,
    data_reference,
    execution_time_ms
)
VALUES
(
    1,
    1,
    'SIGNING',
    'SUCCESS',
    'RSA-PSS-SHA256',
    'transaction/TXN-1001',
    12.50
),
(
    1,
    4,
    'VERIFICATION',
    'SUCCESS',
    'RSA-PSS-SHA256',
    'transaction/TXN-1001',
    8.20
),
(
    2,
    2,
    'SIGNING',
    'SUCCESS',
    'ED25519',
    'document/DOC-2026-001',
    2.10
),
(
    3,
    1,
    'DECRYPTION',
    'REJECTED',
    'RSA-OAEP-SHA256',
    'archive/OLD-KEY-REQUEST',
    0.40
),
(
    4,
    1,
    'KEY_AGREEMENT',
    'FAILED',
    'X25519',
    'session/SESSION-001',
    1.20
);


-- ============================================================
-- SAMPLE SIGNATURE RECORDS
-- ============================================================

INSERT INTO digital_signatures (
    key_id,
    signer_identity_id,
    document_reference,
    document_hash,
    signature_algorithm,
    signature_value
)
VALUES
(
    1,
    1,
    'transaction/TXN-1001',
    repeat('1', 64),
    'RSA-PSS-SHA256',
    'BASE64-DEMO-SIGNATURE-001'
),
(
    2,
    2,
    'document/DOC-2026-001',
    repeat('2', 64),
    'ED25519',
    'BASE64-DEMO-SIGNATURE-002'
);


INSERT INTO signature_verifications (
    signature_id,
    verifier_identity_id,
    is_valid,
    verification_reason
)
VALUES
(
    1,
    4,
    TRUE,
    'Signature matched registered public key.'
),
(
    2,
    4,
    TRUE,
    'Ed25519 verification succeeded.'
);


-- ============================================================
-- SAMPLE KEY AGREEMENT SESSION
-- ============================================================

INSERT INTO key_agreement_sessions (
    initiator_key_id,
    responder_key_id,
    agreement_algorithm,
    initiator_public_key_fingerprint,
    responder_public_key_fingerprint,
    derived_key_reference,
    context_identifier,
    established_at,
    expires_at
)
VALUES
(
    1,
    2,
    'X25519',
    repeat('f', 64),
    repeat('0', 64),
    'kms://session/derived/TXN-SESSION-001',
    'payment-session-v1',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '1 hour'
);


-- ============================================================
-- QUERY 1: ACTIVE PUBLIC KEY RETRIEVAL
-- ============================================================

SELECT
    key_id,
    owner,
    algorithm_name,
    purpose,
    key_size_bits,
    public_key_fingerprint,
    storage_type,
    expires_at
FROM active_key_inventory
ORDER BY organization_name, owner;


-- ============================================================
-- QUERY 2: KEY LIFECYCLE AGGREGATION
-- ============================================================

SELECT
    organization_id,
    algorithm_name,
    purpose,
    key_status,
    total_keys
FROM key_lifecycle_report
ORDER BY organization_id, algorithm_name, key_status;


-- ============================================================
-- QUERY 3: EXPIRING KEYS
-- ============================================================

SELECT
    key_id,
    owner_identity_id,
    algorithm_name,
    purpose,
    expires_at,
    EXTRACT(
        DAY FROM expires_at - CURRENT_TIMESTAMP
    ) AS days_remaining
FROM cryptographic_keys
WHERE key_status = 'ACTIVE'
  AND expires_at BETWEEN CURRENT_TIMESTAMP
                     AND CURRENT_TIMESTAMP + INTERVAL '30 days'
ORDER BY expires_at;


-- ============================================================
-- QUERY 4: INVALID OR NON-USABLE KEYS
-- ============================================================

SELECT
    key_id,
    algorithm_name,
    purpose,
    key_status,
    expires_at,
    CASE
        WHEN key_status = 'REVOKED'
            THEN 'REVOKED'
        WHEN key_status = 'COMPROMISED'
            THEN 'COMPROMISED'
        WHEN key_status = 'DESTROYED'
            THEN 'DESTROYED'
        WHEN key_status = 'ROTATED'
            THEN 'ROTATED'
        WHEN expires_at <= CURRENT_TIMESTAMP
            THEN 'EXPIRED'
        WHEN key_status <> 'ACTIVE'
            THEN 'NOT_ACTIVE'
        ELSE 'ELIGIBLE'
    END AS eligibility_status
FROM cryptographic_keys
ORDER BY key_id;


-- ============================================================
-- QUERY 5: SIGNATURE VERIFICATION REPORT
-- ============================================================

SELECT
    ds.signature_id,
    ds.document_reference,
    ds.signature_algorithm,
    signer.identity_name AS signer,
    verifier.identity_name AS verifier,
    sv.is_valid,
    sv.verification_reason,
    sv.verified_at
FROM digital_signatures ds
JOIN identities signer
    ON signer.identity_id = ds.signer_identity_id
JOIN signature_verifications sv
    ON sv.signature_id = ds.signature_id
JOIN identities verifier
    ON verifier.identity_id = sv.verifier_identity_id
ORDER BY sv.verified_at DESC;


-- ============================================================
-- QUERY 6: KEY USAGE PERFORMANCE
-- ============================================================

SELECT
    algorithm_used,
    operation,
    COUNT(*) AS total_operations,
    COUNT(*) FILTER (
        WHERE operation_status = 'SUCCESS'
    ) AS successful_operations,
    COUNT(*) FILTER (
        WHERE operation_status = 'FAILED'
    ) AS failed_operations,
    COUNT(*) FILTER (
        WHERE operation_status = 'REJECTED'
    ) AS rejected_operations,
    ROUND(
        AVG(execution_time_ms),
        3
    ) AS average_execution_ms
FROM cryptographic_operations
GROUP BY algorithm_used, operation
ORDER BY algorithm_used, operation;


-- ============================================================
-- QUERY 7: AUDIT HISTORY
-- ============================================================

SELECT
    audit_id,
    key_id,
    event_type,
    old_status,
    new_status,
    occurred_at,
    event_details
FROM key_audit_events
ORDER BY occurred_at DESC;


-- ============================================================
-- QUERY 8: ACCESS EVALUATION
-- ============================================================

SELECT
    key_id,
    identity_id,
    access_policy_id,
    evaluate_key_access(
        key_id,
        identity_id,
        access_policy_id
    ) AS decision
FROM key_access_grants
ORDER BY grant_id;


-- ============================================================
-- QUERY 9: CTE-BASED KEY RISK REPORT
-- ============================================================

WITH key_risk AS (
    SELECT
        k.key_id,
        k.organization_id,
        k.algorithm_name,
        k.purpose,
        k.key_status,
        k.expires_at,

        CASE
            WHEN k.key_status IN ('COMPROMISED', 'REVOKED')
                THEN 100
            WHEN k.key_status = 'DESTROYED'
                THEN 90
            WHEN k.key_status = 'EXPIRED'
                THEN 80
            WHEN k.expires_at <= CURRENT_TIMESTAMP
                THEN 70
            WHEN k.expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days'
                THEN 40
            WHEN k.key_status = 'ROTATED'
                THEN 20
            ELSE 0
        END AS risk_score

    FROM cryptographic_keys k
)
SELECT
    key_id,
    organization_id,
    algorithm_name,
    purpose,
    key_status,
    risk_score,
    CASE
        WHEN risk_score >= 80 THEN 'CRITICAL'
        WHEN risk_score >= 40 THEN 'HIGH'
        WHEN risk_score >= 20 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_level
FROM key_risk
ORDER BY risk_score DESC, key_id;


-- ============================================================
-- QUERY 10: KEY VERSION HISTORY
-- ============================================================

SELECT
    current.key_id,
    current.key_version,
    current.key_status,
    current.parent_key_id,
    previous.key_version AS previous_version,
    previous.key_status AS previous_status,
    current.created_at
FROM cryptographic_keys current
LEFT JOIN cryptographic_keys previous
    ON previous.key_id = current.parent_key_id
ORDER BY current.owner_identity_id, current.key_version;


-- ============================================================
-- TRANSACTION: REGISTER AND REVOKE A KEY
--
-- The example demonstrates rollback safety.
-- ============================================================

BEGIN;

SELECT register_public_key(
    2,
    5,
    'RSA',
    'ENCRYPTION',
    3072,
    'DEMO-PUBLIC-KEY-RESEARCH-002',
    repeat('9', 64),
    'SOFTWARE_KEYSTORE',
    'keystore://research/encryption/v2',
    365,
    4
) AS registered_key_id;

-- A real application would capture the returned ID and use it
-- in a subsequent operation.

ROLLBACK;


-- ============================================================
-- TRANSACTION: REVOKE AN EXISTING KEY
--
-- This sample revokes the demonstration X25519 key.
-- ============================================================

BEGIN;

SELECT revoke_public_key(
    4,
    'Demonstration of security-driven key revocation'
);

COMMIT;


-- ============================================================
-- WORKFLOW: EXPIRE KEYS AND CERTIFICATES
-- ============================================================

CALL expire_inactive_keys();


-- ============================================================
-- FINAL VALIDATION
-- ============================================================

DO $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM cryptographic_keys
        WHERE key_id = 1
          AND key_status = 'ACTIVE'
    ) THEN

        RAISE EXCEPTION
            'Expected active signing key was not found.';

    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM cryptographic_keys
        WHERE key_id = 4
          AND key_status = 'REVOKED'
    ) THEN

        RAISE EXCEPTION
            'Revoked key state was not recorded.';

    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM key_audit_events
        WHERE key_id = 4
          AND event_type = 'KEY_REVOKED'
    ) THEN

        RAISE EXCEPTION
            'Key revocation audit event is missing.';

    END IF;

    RAISE NOTICE
        'Cryptographic key-management validation completed.';

END;
$$;


-- ============================================================
-- FINAL REPORTS
-- ============================================================

SELECT * FROM active_key_inventory;

SELECT * FROM key_lifecycle_report;

SELECT * FROM cryptographic_operation_report;

SELECT
    event_type,
    COUNT(*) AS event_count
FROM key_audit_events
GROUP BY event_type
ORDER BY event_type;

COMMIT;
