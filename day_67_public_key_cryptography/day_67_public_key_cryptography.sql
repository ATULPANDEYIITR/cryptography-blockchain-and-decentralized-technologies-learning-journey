-- ============================================================
-- PUBLIC-KEY CRYPTOGRAPHY
-- PostgreSQL relational key management and secure messaging
-- ============================================================
--
-- Requirements:
-- PostgreSQL 15+
--
-- This script models:
--   Organizations and identities
--   RSA public-key registration
--   Public/private key separation
--   Key lifecycle and rotation
--   Key revocation
--   Certificate authorities
--   Digital certificates
--   Encrypted message envelopes
--   Digital signatures
--   Signature verification
--   Cryptographic algorithm policies
--   Security audit events
--   Key eligibility evaluation
--
-- The database stores public keys and encrypted material.
-- Private keys must never be stored in plaintext in this database.
--
-- Actual RSA-OAEP, RSA-PSS and AES-GCM operations are performed
-- by application cryptographic libraries, not ordinary SQL.
--
-- The certificate metadata model is educational and does not
-- replace complete X.509 path validation or CRL/OCSP processing.
--
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS public_key_security;

SET search_path TO public_key_security, public;

-- ------------------------------------------------------------
-- 1. DOMAIN TYPES
-- ------------------------------------------------------------

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'ROTATED',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE key_purpose AS ENUM (
    'ENCRYPTION',
    'SIGNING',
    'CERTIFICATE_AUTHORITY'
);

CREATE TYPE cryptographic_algorithm AS ENUM (
    'RSA-2048',
    'RSA-3072',
    'RSA-4096',
    'RSA-OAEP-SHA256',
    'RSA-PSS-SHA256',
    'AES-256-GCM',
    'SHA-256'
);

CREATE TYPE verification_status AS ENUM (
    'PENDING',
    'VALID',
    'INVALID',
    'FAILED',
    'EXPIRED'
);

CREATE TYPE message_status AS ENUM (
    'CREATED',
    'ENCRYPTED',
    'DELIVERED',
    'DECRYPTED',
    'FAILED'
);

CREATE TYPE certificate_status AS ENUM (
    'VALID',
    'EXPIRED',
    'REVOKED',
    'SUSPENDED'
);

-- ------------------------------------------------------------
-- 2. ORGANIZATIONS AND IDENTITIES
-- ------------------------------------------------------------

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(200) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT organization_name_nonempty
        CHECK (LENGTH(TRIM(organization_name)) > 0)
);

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    identity_name VARCHAR(150) NOT NULL,

    email VARCHAR(254) NOT NULL UNIQUE,

    identity_type VARCHAR(30) NOT NULL
        CHECK (
            identity_type IN (
                'USER',
                'SERVICE',
                'APPLICATION',
                'AUTHORITY'
            )
        ),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT identity_name_nonempty
        CHECK (LENGTH(TRIM(identity_name)) > 0)
);

CREATE INDEX idx_identities_organization
    ON identities(organization_id);

-- ------------------------------------------------------------
-- 3. CRYPTOGRAPHIC ALGORITHM POLICY
-- ------------------------------------------------------------

CREATE TABLE algorithm_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    algorithm cryptographic_algorithm NOT NULL,

    purpose key_purpose NOT NULL,

    minimum_strength INTEGER NOT NULL,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    requires_hardware_protection BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_algorithm_strength
        CHECK (minimum_strength > 0),

    CONSTRAINT unique_algorithm_purpose
        UNIQUE (algorithm, purpose)
);

INSERT INTO algorithm_policies (
    algorithm,
    purpose,
    minimum_strength,
    is_enabled,
    requires_hardware_protection
)
VALUES
    ('RSA-2048', 'ENCRYPTION', 2048, TRUE, FALSE),
    ('RSA-3072', 'ENCRYPTION', 3072, TRUE, FALSE),
    ('RSA-4096', 'ENCRYPTION', 4096, TRUE, TRUE),
    ('RSA-2048', 'SIGNING', 2048, TRUE, FALSE),
    ('RSA-3072', 'SIGNING', 3072, TRUE, FALSE),
    ('RSA-4096', 'SIGNING', 4096, TRUE, TRUE),
    ('RSA-OAEP-SHA256', 'ENCRYPTION', 256, TRUE, FALSE),
    ('RSA-PSS-SHA256', 'SIGNING', 256, TRUE, FALSE),
    ('SHA-256', 'SIGNING', 256, TRUE, FALSE);

-- ------------------------------------------------------------
-- 4. PUBLIC KEY REGISTRY
-- ------------------------------------------------------------

CREATE TABLE cryptographic_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    key_fingerprint CHAR(64) NOT NULL UNIQUE,

    public_key_pem TEXT NOT NULL,

    key_algorithm cryptographic_algorithm NOT NULL,

    key_purpose key_purpose NOT NULL,

    key_strength INTEGER NOT NULL,

    status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ,

    rotated_from BIGINT
        REFERENCES cryptographic_keys(key_id),

    hardware_protected BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT fingerprint_format
        CHECK (key_fingerprint ~ '^[0-9a-f]{64}$'),

    CONSTRAINT public_key_nonempty
        CHECK (LENGTH(TRIM(public_key_pem)) > 0),

    CONSTRAINT valid_key_strength
        CHECK (key_strength >= 2048),

    CONSTRAINT valid_key_expiration
        CHECK (
            expires_at IS NULL
            OR expires_at > created_at
        ),

    CONSTRAINT prevent_self_rotation
        CHECK (
            rotated_from IS NULL
            OR rotated_from <> key_id
        )
);

CREATE INDEX idx_keys_identity
    ON cryptographic_keys(identity_id);

CREATE INDEX idx_keys_status_expiry
    ON cryptographic_keys(status, expires_at);

CREATE INDEX idx_keys_purpose_status
    ON cryptographic_keys(key_purpose, status);

CREATE INDEX idx_keys_fingerprint
    ON cryptographic_keys(key_fingerprint);

-- ------------------------------------------------------------
-- 5. CERTIFICATE AUTHORITIES
-- ------------------------------------------------------------

CREATE TABLE certificate_authorities (
    authority_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL UNIQUE
        REFERENCES identities(identity_id),

    signing_key_id BIGINT NOT NULL UNIQUE
        REFERENCES cryptographic_keys(key_id),

    authority_name VARCHAR(200) NOT NULL UNIQUE,

    is_trusted BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE digital_certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    subject_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    authority_id BIGINT NOT NULL
        REFERENCES certificate_authorities(authority_id),

    serial_number VARCHAR(100) NOT NULL UNIQUE,

    subject_name VARCHAR(200) NOT NULL,

    issuer_name VARCHAR(200) NOT NULL,

    valid_from TIMESTAMPTZ NOT NULL,

    valid_until TIMESTAMPTZ NOT NULL,

    certificate_signature BYTEA NOT NULL,

    signature_algorithm cryptographic_algorithm NOT NULL
        DEFAULT 'RSA-PSS-SHA256',

    status certificate_status NOT NULL DEFAULT 'VALID',

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT certificate_validity
        CHECK (valid_until > valid_from),

    CONSTRAINT certificate_signature_nonempty
        CHECK (OCTET_LENGTH(certificate_signature) > 0)
);

CREATE INDEX idx_certificates_subject
    ON digital_certificates(subject_key_id);

CREATE INDEX idx_certificates_expiry
    ON digital_certificates(status, valid_until);

CREATE INDEX idx_certificates_authority
    ON digital_certificates(authority_id);

-- ------------------------------------------------------------
-- 6. SECURE MESSAGE ENVELOPES
-- ------------------------------------------------------------

CREATE TABLE encrypted_messages (
    message_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    sender_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    recipient_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    recipient_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    message_reference VARCHAR(100) NOT NULL UNIQUE,

    encryption_algorithm cryptographic_algorithm NOT NULL
        DEFAULT 'AES-256-GCM',

    key_wrapping_algorithm cryptographic_algorithm NOT NULL
        DEFAULT 'RSA-OAEP-SHA256',

    encrypted_session_key BYTEA NOT NULL,

    nonce BYTEA NOT NULL,

    ciphertext BYTEA NOT NULL,

    authentication_tag BYTEA NOT NULL,

    additional_authenticated_data BYTEA,

    status message_status NOT NULL DEFAULT 'CREATED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    delivered_at TIMESTAMPTZ,

    decrypted_at TIMESTAMPTZ,

    CONSTRAINT encrypted_session_key_nonempty
        CHECK (OCTET_LENGTH(encrypted_session_key) > 0),

    CONSTRAINT valid_gcm_nonce
        CHECK (OCTET_LENGTH(nonce) = 12),

    CONSTRAINT valid_gcm_tag
        CHECK (OCTET_LENGTH(authentication_tag) = 16),

    CONSTRAINT ciphertext_nonempty
        CHECK (OCTET_LENGTH(ciphertext) > 0),

    CONSTRAINT sender_not_recipient
        CHECK (sender_identity_id <> recipient_identity_id)
);

CREATE INDEX idx_messages_recipient
    ON encrypted_messages(recipient_identity_id, created_at DESC);

CREATE INDEX idx_messages_status
    ON encrypted_messages(status, created_at DESC);

CREATE INDEX idx_messages_recipient_key
    ON encrypted_messages(recipient_key_id);

-- ------------------------------------------------------------
-- 7. DIGITAL SIGNATURE RECORDS
-- ------------------------------------------------------------

CREATE TABLE signed_documents (
    document_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    signer_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),

    signing_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    document_reference VARCHAR(150) NOT NULL UNIQUE,

    document_digest BYTEA NOT NULL,

    digest_algorithm cryptographic_algorithm NOT NULL
        DEFAULT 'SHA-256',

    signature_algorithm cryptographic_algorithm NOT NULL
        DEFAULT 'RSA-PSS-SHA256',

    signature BYTEA NOT NULL,

    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_sha256_digest
        CHECK (OCTET_LENGTH(document_digest) = 32),

    CONSTRAINT signature_nonempty
        CHECK (OCTET_LENGTH(signature) > 0)
);

CREATE INDEX idx_signed_documents_signer
    ON signed_documents(signer_identity_id, signed_at DESC);

CREATE INDEX idx_signed_documents_key
    ON signed_documents(signing_key_id);

CREATE TABLE signature_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    document_id BIGINT NOT NULL
        REFERENCES signed_documents(document_id),

    verifier_identity_id BIGINT
        REFERENCES identities(identity_id),

    verified_key_id BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),

    result verification_status NOT NULL DEFAULT 'PENDING',

    verification_message TEXT,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_result
    ON signature_verifications(result, verified_at DESC);

CREATE INDEX idx_verification_document
    ON signature_verifications(document_id);

-- ------------------------------------------------------------
-- 8. SECURITY AUDIT
-- ------------------------------------------------------------

CREATE TABLE security_audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT
        REFERENCES identities(identity_id),

    key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    event_type VARCHAR(60) NOT NULL,

    event_outcome VARCHAR(30) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_event_outcome
        CHECK (
            event_outcome IN (
                'SUCCESS',
                'FAILURE',
                'REJECTED',
                'WARNING'
            )
        )
);

CREATE INDEX idx_audit_time
    ON security_audit_events(occurred_at DESC);

CREATE INDEX idx_audit_identity
    ON security_audit_events(identity_id, occurred_at DESC);

CREATE INDEX idx_audit_event_type
    ON security_audit_events(event_type, occurred_at DESC);

-- ------------------------------------------------------------
-- 9. KEY REGISTRATION VALIDATION
-- ------------------------------------------------------------

CREATE FUNCTION validate_key_registration()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    owner_active BOOLEAN;
    policy_enabled BOOLEAN;
    required_strength INTEGER;
BEGIN
    SELECT is_active
    INTO owner_active
    FROM identities
    WHERE identity_id = NEW.identity_id;

    IF owner_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Inactive or missing key owner';
    END IF;

    SELECT is_enabled, minimum_strength
    INTO policy_enabled, required_strength
    FROM algorithm_policies
    WHERE algorithm = NEW.key_algorithm
      AND purpose = NEW.key_purpose;

    IF NOT FOUND OR policy_enabled IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Cryptographic algorithm is not permitted';
    END IF;

    IF NEW.key_strength < required_strength THEN
        RAISE EXCEPTION
            'Key strength % is below required strength %',
            NEW.key_strength,
            required_strength;
    END IF;

    IF NEW.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'New keys must initially be ACTIVE';
    END IF;

    IF NEW.key_purpose = 'ENCRYPTION'
       AND NEW.key_algorithm NOT IN (
           'RSA-2048',
           'RSA-3072',
           'RSA-4096'
       ) THEN
        RAISE EXCEPTION 'Invalid key-generation algorithm';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_key_registration
BEFORE INSERT ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION validate_key_registration();

-- ------------------------------------------------------------
-- 10. KEY LIFECYCLE AUDIT TRIGGER
-- ------------------------------------------------------------

CREATE FUNCTION audit_key_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN

        INSERT INTO security_audit_events (
            identity_id,
            key_id,
            event_type,
            event_outcome,
            event_details
        )
        VALUES (
            NEW.identity_id,
            NEW.key_id,
            'KEY_STATUS_CHANGED',
            'SUCCESS',
            jsonb_build_object(
                'previous_status', OLD.status,
                'new_status', NEW.status,
                'fingerprint', NEW.key_fingerprint
            )
        );

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_lifecycle_audit
AFTER UPDATE OF status ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION audit_key_lifecycle();

-- ------------------------------------------------------------
-- 11. KEY LIFECYCLE FUNCTION
-- ------------------------------------------------------------

CREATE FUNCTION change_key_status(
    p_key_id BIGINT,
    p_new_status key_status
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    current_status key_status;
BEGIN
    SELECT status
    INTO current_status
    FROM cryptographic_keys
    WHERE key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown key ID %', p_key_id;
    END IF;

    IF current_status = 'REVOKED' THEN
        RAISE EXCEPTION 'Revoked keys cannot change status';
    END IF;

    IF current_status = 'EXPIRED'
       AND p_new_status <> 'EXPIRED' THEN
        RAISE EXCEPTION 'Expired keys cannot be reactivated';
    END IF;

    IF p_new_status = 'ACTIVE'
       AND current_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Reactivation requires a new key pair';
    END IF;

    IF current_status = p_new_status THEN
        RETURN FALSE;
    END IF;

    UPDATE cryptographic_keys
    SET status = p_new_status
    WHERE key_id = p_key_id;

    RETURN TRUE;
END;
$$;

-- ------------------------------------------------------------
-- 12. MESSAGE ELIGIBILITY FUNCTION
-- ------------------------------------------------------------

CREATE FUNCTION can_receive_encrypted_message(
    p_recipient_identity_id BIGINT,
    p_key_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    eligible BOOLEAN;
BEGIN
    SELECT
        i.is_active
        AND k.status = 'ACTIVE'
        AND k.key_purpose = 'ENCRYPTION'
        AND (k.expires_at IS NULL OR k.expires_at > NOW())
        AND k.identity_id = i.identity_id
    INTO eligible
    FROM identities i
    JOIN cryptographic_keys k
      ON k.identity_id = i.identity_id
    WHERE i.identity_id = p_recipient_identity_id
      AND k.key_id = p_key_id;

    RETURN COALESCE(eligible, FALSE);
END;
$$;

-- ------------------------------------------------------------
-- 13. MESSAGE REGISTRATION PROCEDURE
-- ------------------------------------------------------------

CREATE PROCEDURE register_encrypted_message(
    p_sender BIGINT,
    p_recipient BIGINT,
    p_key_id BIGINT,
    p_reference VARCHAR(100),
    p_wrapped_key BYTEA,
    p_nonce BYTEA,
    p_ciphertext BYTEA,
    p_auth_tag BYTEA
)
LANGUAGE plpgsql
AS $$
DECLARE
    new_message_id BIGINT;
BEGIN
    IF p_sender = p_recipient THEN
        RAISE EXCEPTION 'Sender and recipient must differ';
    END IF;

    IF NOT can_receive_encrypted_message(
        p_recipient,
        p_key_id
    ) THEN
        RAISE EXCEPTION 'Recipient encryption key is not eligible';
    END IF;

    INSERT INTO encrypted_messages (
        sender_identity_id,
        recipient_identity_id,
        recipient_key_id,
        message_reference,
        encrypted_session_key,
        nonce,
        ciphertext,
        authentication_tag,
        status
    )
    VALUES (
        p_sender,
        p_recipient,
        p_key_id,
        p_reference,
        p_wrapped_key,
        p_nonce,
        p_ciphertext,
        p_auth_tag,
        'ENCRYPTED'
    )
    RETURNING message_id INTO new_message_id;

    INSERT INTO security_audit_events (
        identity_id,
        key_id,
        event_type,
        event_outcome,
        event_details
    )
    VALUES (
        p_sender,
        p_key_id,
        'ENCRYPTED_MESSAGE_REGISTERED',
        'SUCCESS',
        jsonb_build_object(
            'message_id', new_message_id,
            'recipient', p_recipient
        )
    );
END;
$$;

-- ------------------------------------------------------------
-- 14. SIGNATURE VERIFICATION RECORDING
-- ------------------------------------------------------------

CREATE FUNCTION record_signature_verification(
    p_document_id BIGINT,
    p_verifier_id BIGINT,
    p_result verification_status,
    p_message TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    document_key BIGINT;
    verification_id BIGINT;
BEGIN
    IF p_result = 'PENDING' THEN
        RAISE EXCEPTION 'Verification cannot be recorded as PENDING';
    END IF;

    SELECT signing_key_id
    INTO document_key
    FROM signed_documents
    WHERE document_id = p_document_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signed document does not exist';
    END IF;

    INSERT INTO signature_verifications (
        document_id,
        verifier_identity_id,
        verified_key_id,
        result,
        verification_message
    )
    VALUES (
        p_document_id,
        p_verifier_id,
        document_key,
        p_result,
        p_message
    )
    RETURNING verification_id INTO verification_id;

    INSERT INTO security_audit_events (
        identity_id,
        key_id,
        event_type,
        event_outcome,
        event_details
    )
    VALUES (
        p_verifier_id,
        document_key,
        'SIGNATURE_VERIFICATION',
        CASE
            WHEN p_result = 'VALID' THEN 'SUCCESS'
            ELSE 'FAILURE'
        END,
        jsonb_build_object(
            'document_id', p_document_id,
            'result', p_result
        )
    );

    RETURN verification_id;
END;
$$;

-- ------------------------------------------------------------
-- 15. VIEWS
-- ------------------------------------------------------------

CREATE VIEW active_public_keys AS
SELECT
    k.key_id,
    i.identity_name,
    i.email,
    k.key_fingerprint,
    k.key_algorithm,
    k.key_purpose,
    k.key_strength,
    k.created_at,
    k.expires_at,
    k.hardware_protected
FROM cryptographic_keys k
JOIN identities i
  ON i.identity_id = k.identity_id
WHERE k.status = 'ACTIVE'
  AND i.is_active = TRUE
  AND (k.expires_at IS NULL OR k.expires_at > NOW());

CREATE VIEW certificate_inventory AS
SELECT
    c.certificate_id,
    c.serial_number,
    c.subject_name,
    c.issuer_name,
    c.valid_from,
    c.valid_until,
    c.status,
    k.key_fingerprint,
    ca.authority_name,
    CASE
        WHEN c.status <> 'VALID' THEN FALSE
        WHEN NOW() < c.valid_from THEN FALSE
        WHEN NOW() >= c.valid_until THEN FALSE
        ELSE TRUE
    END AS time_eligible
FROM digital_certificates c
JOIN cryptographic_keys k
  ON k.key_id = c.subject_key_id
JOIN certificate_authorities ca
  ON ca.authority_id = c.authority_id;

CREATE VIEW message_delivery_report AS
SELECT
    m.message_id,
    m.message_reference,
    sender.identity_name AS sender,
    recipient.identity_name AS recipient,
    m.encryption_algorithm,
    m.key_wrapping_algorithm,
    m.status,
    m.created_at,
    m.delivered_at,
    m.decrypted_at
FROM encrypted_messages m
JOIN identities sender
  ON sender.identity_id = m.sender_identity_id
JOIN identities recipient
  ON recipient.identity_id = m.recipient_identity_id;

CREATE VIEW signature_verification_report AS
SELECT
    d.document_reference,
    signer.identity_name AS signer,
    v.result,
    v.verification_message,
    v.verified_at
FROM signature_verifications v
JOIN signed_documents d
  ON d.document_id = v.document_id
JOIN identities signer
  ON signer.identity_id = d.signer_identity_id;

-- ------------------------------------------------------------
-- 16. SAMPLE ORGANIZATIONS AND IDENTITIES
-- ------------------------------------------------------------

INSERT INTO organizations (organization_name)
VALUES
    ('Example Financial Services'),
    ('Example Certificate Authority'),
    ('Example Enterprise Applications');

INSERT INTO identities (
    organization_id,
    identity_name,
    email,
    identity_type
)
VALUES
    (1, 'Alice', 'alice@example.com', 'USER'),
    (1, 'Bob', 'bob@example.com', 'USER'),
    (2, 'Enterprise Root CA', 'root-ca@example.com', 'AUTHORITY'),
    (3, 'Payment Service', 'payments@example.com', 'SERVICE'),
    (1, 'Carol', 'carol@example.com', 'USER');

-- ------------------------------------------------------------
-- 17. SAMPLE PUBLIC KEYS
-- ------------------------------------------------------------
-- These PEM values are illustrative metadata records.
-- Applications must validate actual key encoding and fingerprints.
-- They are not usable cryptographic keys.

INSERT INTO cryptographic_keys (
    identity_id,
    key_fingerprint,
    public_key_pem,
    key_algorithm,
    key_purpose,
    key_strength,
    status,
    expires_at,
    hardware_protected
)
VALUES
(
    1,
    REPEAT('a', 64),
    '-----BEGIN PUBLIC KEY----- EXAMPLE_ALICE_KEY -----END PUBLIC KEY-----',
    'RSA-3072',
    'SIGNING',
    3072,
    'ACTIVE',
    NOW() + INTERVAL '365 days',
    FALSE
),
(
    2,
    REPEAT('b', 64),
    '-----BEGIN PUBLIC KEY----- EXAMPLE_BOB_KEY -----END PUBLIC KEY-----',
    'RSA-3072',
    'ENCRYPTION',
    3072,
    'ACTIVE',
    NOW() + INTERVAL '365 days',
    FALSE
),
(
    3,
    REPEAT('c', 64),
    '-----BEGIN PUBLIC KEY----- EXAMPLE_CA_KEY -----END PUBLIC KEY-----',
    'RSA-4096',
    'CERTIFICATE_AUTHORITY',
    4096,
    'ACTIVE',
    NOW() + INTERVAL '730 days',
    TRUE
),
(
    4,
    REPEAT('d', 64),
    '-----BEGIN PUBLIC KEY----- EXAMPLE_SERVICE_KEY -----END PUBLIC KEY-----',
    'RSA-2048',
    'SIGNING',
    2048,
    'ACTIVE',
    NOW() + INTERVAL '180 days',
    FALSE
),
(
    5,
    REPEAT('e', 64),
    '-----BEGIN PUBLIC KEY----- EXAMPLE_CAROL_OLD_KEY -----END PUBLIC KEY-----',
    'RSA-2048',
    'ENCRYPTION',
    2048,
    'ACTIVE',
    NOW() + INTERVAL '90 days',
    FALSE
);

-- Register a certificate authority.
INSERT INTO certificate_authorities (
    identity_id,
    signing_key_id,
    authority_name
)
VALUES (
    3,
    3,
    'Example Enterprise Root CA'
);

-- Certificate metadata.
INSERT INTO digital_certificates (
    subject_key_id,
    authority_id,
    serial_number,
    subject_name,
    issuer_name,
    valid_from,
    valid_until,
    certificate_signature
)
VALUES
(
    2,
    1,
    'CERT-2026-0001',
    'Bob',
    'Example Enterprise Root CA',
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '364 days',
    DECODE(REPEAT('11', 256), 'hex')
),
(
    5,
    1,
    'CERT-2026-0002',
    'Carol',
    'Example Enterprise Root CA',
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '89 days',
    DECODE(REPEAT('22', 256), 'hex')
);

-- ------------------------------------------------------------
-- 18. SIGNED DOCUMENT RECORDS
-- ------------------------------------------------------------

INSERT INTO signed_documents (
    signer_identity_id,
    signing_key_id,
    document_reference,
    document_digest,
    signature,
    signature_algorithm
)
VALUES
(
    1,
    1,
    'PAYMENT-AUTH-1001',
    DECODE(REPEAT('ab', 32), 'hex'),
    DECODE(REPEAT('11', 256), 'hex'),
    'RSA-PSS-SHA256'
),
(
    4,
    4,
    'SERVICE-REPORT-2001',
    DECODE(REPEAT('cd', 32), 'hex'),
    DECODE(REPEAT('22', 256), 'hex'),
    'RSA-PSS-SHA256'
);

-- Record application-reported verification outcomes.
SELECT record_signature_verification(
    1,
    2,
    'VALID',
    'Signature verified by the application cryptographic provider.'
);

SELECT record_signature_verification(
    2,
    2,
    'INVALID',
    'Application detected a signature mismatch.'
);

-- ------------------------------------------------------------
-- 19. ENCRYPTED MESSAGE SAMPLE
-- ------------------------------------------------------------
-- The sample values demonstrate database structure.
-- They are not produced by a real encryption operation.

INSERT INTO encrypted_messages (
    sender_identity_id,
    recipient_identity_id,
    recipient_key_id,
    message_reference,
    encrypted_session_key,
    nonce,
    ciphertext,
    authentication_tag,
    status,
    delivered_at
)
VALUES
(
    1,
    2,
    2,
    'MSG-1001',
    DECODE(REPEAT('33', 384), 'hex'),
    DECODE(REPEAT('44', 12), 'hex'),
    DECODE(REPEAT('55', 64), 'hex'),
    DECODE(REPEAT('66', 16), 'hex'),
    'DELIVERED',
    NOW()
),
(
    4,
    2,
    2,
    'MSG-1002',
    DECODE(REPEAT('77', 384), 'hex'),
    DECODE(REPEAT('88', 12), 'hex'),
    DECODE(REPEAT('99', 64), 'hex'),
    DECODE(REPEAT('aa', 16), 'hex'),
    'ENCRYPTED',
    NULL
);

-- ------------------------------------------------------------
-- 20. SAMPLE SECURITY AUDIT RECORDS
-- ------------------------------------------------------------

INSERT INTO security_audit_events (
    identity_id,
    key_id,
    event_type,
    event_outcome,
    event_details
)
VALUES
(
    1,
    1,
    'DOCUMENT_SIGNED',
    'SUCCESS',
    '{"document":"PAYMENT-AUTH-1001","algorithm":"RSA-PSS-SHA256"}'
),
(
    2,
    2,
    'MESSAGE_RECEIVED',
    'SUCCESS',
    '{"message":"MSG-1001","algorithm":"AES-256-GCM"}'
),
(
    5,
    5,
    'INVALID_KEY_ACCESS',
    'REJECTED',
    '{"reason":"Unauthorized access attempt"}'
);

-- ------------------------------------------------------------
-- 21. RETRIEVAL QUERIES
-- ------------------------------------------------------------

-- Find active public keys.
SELECT *
FROM active_public_keys
ORDER BY identity_name;

-- Find Bob's certificates.
SELECT *
FROM certificate_inventory
WHERE subject_name = 'Bob';

-- Find encrypted messages received by Bob.
SELECT *
FROM message_delivery_report
WHERE recipient = 'Bob'
ORDER BY created_at DESC;

-- Find signature verification outcomes.
SELECT *
FROM signature_verification_report
ORDER BY verified_at DESC;

-- ------------------------------------------------------------
-- 22. VALIDATION QUERIES
-- ------------------------------------------------------------

-- Keys that have expired or are no longer active.
SELECT
    key_id,
    key_fingerprint,
    status,
    expires_at,
    CASE
        WHEN status = 'REVOKED' THEN 'REVOKED'
        WHEN status = 'EXPIRED' THEN 'EXPIRED'
        WHEN expires_at <= NOW() THEN 'EXPIRY_REACHED'
        ELSE 'ACTIVE'
    END AS validation_result
FROM cryptographic_keys;

-- Certificate time validation.
SELECT
    certificate_id,
    serial_number,
    subject_name,
    CASE
        WHEN status = 'REVOKED' THEN 'REJECTED_REVOKED'
        WHEN status <> 'VALID' THEN 'REJECTED_STATUS'
        WHEN NOW() < valid_from THEN 'NOT_YET_VALID'
        WHEN NOW() >= valid_until THEN 'EXPIRED'
        ELSE 'TIME_VALID'
    END AS validation_result
FROM digital_certificates;

-- Detect keys without matching enabled policies.
SELECT
    k.key_id,
    k.key_algorithm,
    k.key_purpose
FROM cryptographic_keys k
LEFT JOIN algorithm_policies p
  ON p.algorithm = k.key_algorithm
 AND p.purpose = k.key_purpose
WHERE p.policy_id IS NULL
   OR p.is_enabled = FALSE;

-- ------------------------------------------------------------
-- 23. ELIGIBILITY EVALUATION
-- ------------------------------------------------------------

SELECT
    i.identity_name,
    k.key_id,
    k.key_purpose,
    k.status,
    can_receive_encrypted_message(
        i.identity_id,
        k.key_id
    ) AS eligible_for_encrypted_message
FROM identities i
JOIN cryptographic_keys k
  ON k.identity_id = i.identity_id
ORDER BY i.identity_name;

-- ------------------------------------------------------------
-- 24. AGGREGATION AND REPORTING
-- ------------------------------------------------------------

-- Key inventory by purpose and status.
SELECT
    key_purpose,
    status,
    COUNT(*) AS key_count,
    AVG(key_strength) AS average_strength
FROM cryptographic_keys
GROUP BY key_purpose, status
ORDER BY key_purpose, status;

-- Message delivery distribution.
SELECT
    status,
    COUNT(*) AS message_count
FROM encrypted_messages
GROUP BY status
ORDER BY message_count DESC;

-- Signature verification success rate.
SELECT
    COUNT(*) AS total_verifications,
    COUNT(*) FILTER (
        WHERE result = 'VALID'
    ) AS successful_verifications,
    COUNT(*) FILTER (
        WHERE result = 'INVALID'
    ) AS invalid_verifications,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE result = 'VALID'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM signature_verifications;

-- Security events grouped by outcome.
SELECT
    event_type,
    event_outcome,
    COUNT(*) AS event_count
FROM security_audit_events
GROUP BY event_type, event_outcome
ORDER BY event_count DESC;

-- ------------------------------------------------------------
-- 25. CTE: KEY RISK EVALUATION
-- ------------------------------------------------------------

WITH key_risk AS (
    SELECT
        k.key_id,
        i.identity_name,
        k.key_fingerprint,
        k.status,
        k.key_strength,
        k.expires_at,
        CASE
            WHEN k.status = 'REVOKED' THEN 'CRITICAL'
            WHEN k.status = 'EXPIRED' THEN 'CRITICAL'
            WHEN k.expires_at <= NOW() THEN 'CRITICAL'
            WHEN k.expires_at <= NOW() + INTERVAL '30 days'
                THEN 'HIGH'
            WHEN k.key_strength < 3072 THEN 'MEDIUM'
            ELSE 'LOW'
        END AS risk_level
    FROM cryptographic_keys k
    JOIN identities i
      ON i.identity_id = k.identity_id
)
SELECT *
FROM key_risk
ORDER BY
    CASE risk_level
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    identity_name;

-- ------------------------------------------------------------
-- 26. CTE: CERTIFICATE CHAIN METADATA AUDIT
-- ------------------------------------------------------------

WITH certificate_audit AS (
    SELECT
        c.certificate_id,
        c.serial_number,
        c.subject_name,
        c.issuer_name,
        ca.authority_name,
        ca.is_trusted,
        ca_key.status AS authority_key_status,
        c.status AS certificate_status,
        c.valid_from,
        c.valid_until
    FROM digital_certificates c
    JOIN certificate_authorities ca
      ON ca.authority_id = c.authority_id
    JOIN cryptographic_keys ca_key
      ON ca_key.key_id = ca.signing_key_id
)
SELECT
    *,
    CASE
        WHEN NOT is_trusted THEN 'UNTRUSTED_ISSUER'
        WHEN authority_key_status <> 'ACTIVE'
            THEN 'INACTIVE_ISSUER_KEY'
        WHEN certificate_status <> 'VALID'
            THEN 'INVALID_CERTIFICATE_STATUS'
        WHEN NOW() < valid_from THEN 'NOT_YET_VALID'
        WHEN NOW() >= valid_until THEN 'EXPIRED'
        ELSE 'METADATA_ELIGIBLE'
    END AS eligibility
FROM certificate_audit;

-- This query evaluates metadata only.
-- It does not cryptographically verify certificate signatures.

-- ------------------------------------------------------------
-- 27. TRANSACTIONAL KEY ROTATION
-- ------------------------------------------------------------

-- Demonstration uses a transaction to preserve key lifecycle
-- consistency and register the replacement public key.

DO $$
DECLARE
    old_key_id BIGINT;
    new_key_id BIGINT;
BEGIN
    SELECT key_id
    INTO old_key_id
    FROM cryptographic_keys
    WHERE identity_id = 5
      AND key_purpose = 'ENCRYPTION'
      AND status = 'ACTIVE'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'No active Carol encryption key found';
    END IF;

    UPDATE cryptographic_keys
    SET status = 'ROTATED'
    WHERE key_id = old_key_id;

    INSERT INTO cryptographic_keys (
        identity_id,
        key_fingerprint,
        public_key_pem,
        key_algorithm,
        key_purpose,
        key_strength,
        status,
        expires_at,
        rotated_from
    )
    VALUES (
        5,
        REPEAT('f', 64),
        '-----BEGIN PUBLIC KEY----- CAROL_NEW_KEY -----END PUBLIC KEY-----',
        'RSA-3072',
        'ENCRYPTION',
        3072,
        'ACTIVE',
        NOW() + INTERVAL '365 days',
        old_key_id
    )
    RETURNING key_id INTO new_key_id;

    RAISE NOTICE
        'Rotated key % to replacement key %',
        old_key_id,
        new_key_id;
END;
$$;

-- ------------------------------------------------------------
-- 28. FAILURE CASE: REVOKE AN ACTIVE KEY
-- ------------------------------------------------------------

-- Revoke the service signing key.
SELECT change_key_status(4, 'REVOKED');

-- Attempting to reuse this key for new operations should be
-- rejected by application-level key eligibility checks.

SELECT
    key_id,
    status,
    key_fingerprint
FROM cryptographic_keys
WHERE key_id = 4;

-- ------------------------------------------------------------
-- 29. FAILURE CASE: INVALID REGISTRATION
-- ------------------------------------------------------------

-- Execute separately to observe the trigger rejection.
-- The exception is caught in a PL/pgSQL subtransaction so the
-- rest of the script remains executable.

DO $$
BEGIN
    BEGIN
        INSERT INTO cryptographic_keys (
            identity_id,
            key_fingerprint,
            public_key_pem,
            key_algorithm,
            key_purpose,
            key_strength
        )
        VALUES (
            2,
            REPEAT('1', 64),
            'INVALID LOW STRENGTH KEY',
            'RSA-2048',
            'ENCRYPTION',
            1024
        );

    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Invalid key rejected: %', SQLERRM;
    END;
END;
$$;

-- ------------------------------------------------------------
-- 30. WORKFLOW REPORT
-- ------------------------------------------------------------

SELECT
    'PUBLIC KEY REGISTRY' AS workflow,
    COUNT(*) AS records
FROM cryptographic_keys

UNION ALL

SELECT
    'CERTIFICATES',
    COUNT(*)
FROM digital_certificates

UNION ALL

SELECT
    'ENCRYPTED MESSAGES',
    COUNT(*)
FROM encrypted_messages

UNION ALL

SELECT
    'SIGNED DOCUMENTS',
    COUNT(*)
FROM signed_documents

UNION ALL

SELECT
    'SIGNATURE VERIFICATIONS',
    COUNT(*)
FROM signature_verifications

UNION ALL

SELECT
    'SECURITY AUDIT EVENTS',
    COUNT(*)
FROM security_audit_events;

-- ------------------------------------------------------------
-- 31. COMMIT
-- ------------------------------------------------------------

COMMIT;
