-- ============================================================
-- DIGITAL CERTIFICATES AND PUBLIC KEY INFRASTRUCTURE
-- PostgreSQL 15+
--
-- Models:
--   Certificate authorities
--   Trust anchors
--   Public key metadata
--   X.509 certificate inventory
--   Certificate issuance
--   Certificate chains
--   Certificate revocation
--   Certificate renewal
--   Validation policies
--   Certificate validation events
--   Administrative audit records
--
-- Cryptographic signatures are verified by a cryptographic
-- service, not by ordinary relational database constraints.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS pki;

SET search_path TO pki, public;

-- ------------------------------------------------------------
-- Enumerated domain types
-- ------------------------------------------------------------

CREATE TYPE ca_type AS ENUM (
    'ROOT',
    'INTERMEDIATE'
);

CREATE TYPE certificate_type AS ENUM (
    'ROOT_CA',
    'INTERMEDIATE_CA',
    'SERVER',
    'CLIENT',
    'CODE_SIGNING',
    'DOCUMENT_SIGNING'
);

CREATE TYPE certificate_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'SUSPENDED'
);

CREATE TYPE revocation_reason AS ENUM (
    'UNSPECIFIED',
    'KEY_COMPROMISE',
    'CA_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'CERTIFICATE_HOLD',
    'PRIVILEGE_WITHDRAWN'
);

CREATE TYPE validation_status AS ENUM (
    'VALID',
    'INVALID',
    'EXPIRED',
    'REVOKED',
    'UNTRUSTED',
    'UNKNOWN_ISSUER'
);

CREATE TYPE key_usage AS ENUM (
    'DIGITAL_SIGNATURE',
    'KEY_CERT_SIGN',
    'CRL_SIGN',
    'KEY_ENCIPHERMENT',
    'DATA_ENCIPHERMENT',
    'KEY_AGREEMENT'
);

-- ------------------------------------------------------------
-- Certificate authorities
-- ------------------------------------------------------------

CREATE TABLE certificate_authorities (
    ca_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ca_name VARCHAR(200) NOT NULL UNIQUE,

    ca_type ca_type NOT NULL,

    certificate_serial VARCHAR(80) NOT NULL UNIQUE,

    parent_ca_id BIGINT REFERENCES
        certificate_authorities(ca_id),

    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT root_parent_check CHECK (
        (ca_type = 'ROOT' AND parent_ca_id IS NULL)
        OR
        (ca_type = 'INTERMEDIATE' AND parent_ca_id IS NOT NULL)
    ),

    CONSTRAINT root_trust_check CHECK (
        ca_type <> 'INTERMEDIATE' OR is_trusted = FALSE
    )
);

CREATE INDEX idx_ca_parent
ON certificate_authorities(parent_ca_id);

-- ------------------------------------------------------------
-- Public keys
-- ------------------------------------------------------------

CREATE TABLE public_keys (
    public_key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    fingerprint CHAR(64) NOT NULL UNIQUE,

    algorithm VARCHAR(30) NOT NULL,

    key_size INTEGER NOT NULL,

    encoding VARCHAR(30) NOT NULL DEFAULT 'SPKI',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_key_algorithm CHECK (
        algorithm IN (
            'RSA',
            'ECDSA',
            'ED25519',
            'ED448'
        )
    ),

    CONSTRAINT valid_key_size CHECK (
        key_size > 0
    ),

    CONSTRAINT fingerprint_format CHECK (
        fingerprint ~ '^[0-9a-fA-F]{64}$'
    )
);

-- ------------------------------------------------------------
-- Certificates
-- ------------------------------------------------------------

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    serial_number VARCHAR(80) NOT NULL UNIQUE,

    subject VARCHAR(500) NOT NULL,

    issuer VARCHAR(500) NOT NULL,

    certificate_type certificate_type NOT NULL,

    public_key_id BIGINT NOT NULL REFERENCES public_keys(public_key_id),

    issuing_ca_id BIGINT REFERENCES
        certificate_authorities(ca_id),

    renewal_of BIGINT REFERENCES certificates(certificate_id),

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    status certificate_status NOT NULL DEFAULT 'ACTIVE',

    is_ca BOOLEAN NOT NULL DEFAULT FALSE,

    path_length INTEGER,

    signature_algorithm VARCHAR(50) NOT NULL,

    signature_value BYTEA NOT NULL,

    certificate_der BYTEA,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_by VARCHAR(150) NOT NULL,

    CONSTRAINT certificate_validity CHECK (
        not_after > not_before
    ),

    CONSTRAINT certificate_path_length CHECK (
        path_length IS NULL
        OR (is_ca = TRUE AND path_length >= 0)
    ),

    CONSTRAINT end_entity_path_length CHECK (
        is_ca = TRUE OR path_length IS NULL
    ),

    CONSTRAINT certificate_signature_not_empty CHECK (
        OCTET_LENGTH(signature_value) > 0
    ),

    CONSTRAINT ca_certificate_issuer_check CHECK (
        is_ca = FALSE OR issuing_ca_id IS NOT NULL
    )
);

CREATE INDEX idx_certificates_subject
ON certificates(subject);

CREATE INDEX idx_certificates_issuer
ON certificates(issuing_ca_id);

CREATE INDEX idx_certificates_expiry
ON certificates(not_after)
WHERE status = 'ACTIVE';

CREATE INDEX idx_certificates_status
ON certificates(status, not_after);

CREATE INDEX idx_certificates_type
ON certificates(certificate_type);

CREATE INDEX idx_certificates_renewal
ON certificates(renewal_of);

-- ------------------------------------------------------------
-- Certificate key usages
-- ------------------------------------------------------------

CREATE TABLE certificate_key_usages (
    certificate_id BIGINT NOT NULL REFERENCES
        certificates(certificate_id) ON DELETE CASCADE,

    usage key_usage NOT NULL,

    PRIMARY KEY (certificate_id, usage)
);

-- ------------------------------------------------------------
-- Subject alternative names
-- ------------------------------------------------------------

CREATE TABLE certificate_sans (
    san_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT NOT NULL REFERENCES
        certificates(certificate_id) ON DELETE CASCADE,

    san_type VARCHAR(20) NOT NULL,

    san_value VARCHAR(500) NOT NULL,

    CONSTRAINT san_type_check CHECK (
        san_type IN ('DNS', 'IP', 'EMAIL', 'URI')
    ),

    UNIQUE (certificate_id, san_type, san_value)
);

CREATE INDEX idx_certificate_sans_lookup
ON certificate_sans(san_type, san_value);

-- ------------------------------------------------------------
-- Trust anchors
-- ------------------------------------------------------------

CREATE TABLE trust_anchors (
    trust_anchor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ca_id BIGINT NOT NULL UNIQUE REFERENCES
        certificate_authorities(ca_id),

    approved_by VARCHAR(150) NOT NULL,

    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE
);

-- ------------------------------------------------------------
-- Certificate revocation
-- ------------------------------------------------------------

CREATE TABLE certificate_revocations (
    revocation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT NOT NULL UNIQUE REFERENCES
        certificates(certificate_id),

    reason revocation_reason NOT NULL,

    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_by VARCHAR(150) NOT NULL,

    remarks TEXT
);

CREATE INDEX idx_revocations_date
ON certificate_revocations(revoked_at);

-- ------------------------------------------------------------
-- Certificate revocation lists
-- ------------------------------------------------------------

CREATE TABLE certificate_revocation_lists (
    crl_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ca_id BIGINT NOT NULL REFERENCES
        certificate_authorities(ca_id),

    crl_number BIGINT NOT NULL,

    this_update TIMESTAMPTZ NOT NULL,

    next_update TIMESTAMPTZ NOT NULL,

    signature_value BYTEA NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT crl_validity CHECK (
        next_update > this_update
    ),

    UNIQUE (ca_id, crl_number)
);

-- ------------------------------------------------------------
-- Certificate validation policies
-- ------------------------------------------------------------

CREATE TABLE validation_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    certificate_type certificate_type NOT NULL,

    minimum_rsa_key_size INTEGER NOT NULL DEFAULT 2048,

    maximum_validity_days INTEGER NOT NULL DEFAULT 398,

    require_trusted_root BOOLEAN NOT NULL DEFAULT TRUE,

    require_hostname_match BOOLEAN NOT NULL DEFAULT FALSE,

    require_revocation_check BOOLEAN NOT NULL DEFAULT TRUE,

    require_ct BOOLEAN NOT NULL DEFAULT FALSE,

    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT policy_rsa_size CHECK (
        minimum_rsa_key_size >= 2048
    ),

    CONSTRAINT policy_validity CHECK (
        maximum_validity_days BETWEEN 1 AND 825
    )
);

-- ------------------------------------------------------------
-- Policy-specific key usage requirements
-- ------------------------------------------------------------

CREATE TABLE policy_required_usages (
    policy_id BIGINT NOT NULL REFERENCES
        validation_policies(policy_id) ON DELETE CASCADE,

    usage key_usage NOT NULL,

    PRIMARY KEY (policy_id, usage)
);

-- ------------------------------------------------------------
-- Validation events
-- ------------------------------------------------------------

CREATE TABLE certificate_validation_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT REFERENCES certificates(certificate_id),

    policy_id BIGINT REFERENCES validation_policies(policy_id),

    validation_status validation_status NOT NULL,

    requested_hostname VARCHAR(500),

    validated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    validator_identity VARCHAR(150) NOT NULL,

    failure_reason TEXT
);

CREATE INDEX idx_validation_certificate
ON certificate_validation_events(certificate_id, validated_at DESC);

CREATE INDEX idx_validation_status
ON certificate_validation_events(validation_status, validated_at DESC);

-- ------------------------------------------------------------
-- Audit events
-- ------------------------------------------------------------

CREATE TABLE pki_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    entity_type VARCHAR(50) NOT NULL,

    entity_id BIGINT NOT NULL,

    action VARCHAR(50) NOT NULL,

    actor VARCHAR(150) NOT NULL,

    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    details JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX idx_pki_audit_entity
ON pki_audit_events(entity_type, entity_id, event_time DESC);

-- ------------------------------------------------------------
-- Trigger: validate certificate issuance metadata
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_certificate_issuance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    issuer_ca certificate_authorities%ROWTYPE;
    issuer_certificate certificates%ROWTYPE;
    issuer_path_length INTEGER;
BEGIN
    IF NEW.issuing_ca_id IS NULL THEN
        RAISE EXCEPTION 'Issuing CA is mandatory';
    END IF;

    SELECT *
    INTO issuer_ca
    FROM certificate_authorities
    WHERE ca_id = NEW.issuing_ca_id
      AND is_enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Issuing CA is missing or disabled';
    END IF;

    SELECT *
    INTO issuer_certificate
    FROM certificates
    WHERE serial_number = issuer_ca.certificate_serial
      AND status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Issuing CA certificate is unavailable';
    END IF;

    IF NOW() < issuer_certificate.not_before
       OR NOW() > issuer_certificate.not_after THEN
        RAISE EXCEPTION 'Issuing CA certificate is outside validity';
    END IF;

    IF NEW.not_before < issuer_certificate.not_before
       OR NEW.not_after > issuer_certificate.not_after THEN
        RAISE EXCEPTION
            'Child certificate validity exceeds issuer validity';
    END IF;

    IF NEW.issuer <> issuer_ca.ca_name THEN
        RAISE EXCEPTION 'Certificate issuer name mismatch';
    END IF;

    IF NEW.is_ca THEN
        IF issuer_certificate.is_ca = FALSE THEN
            RAISE EXCEPTION 'End-entity certificate cannot issue a CA';
        END IF;

        issuer_path_length := issuer_certificate.path_length;

        IF issuer_path_length IS NOT NULL
           AND issuer_path_length = 0 THEN
            RAISE EXCEPTION 'Issuer path length exhausted';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_certificate_issuance
BEFORE INSERT ON certificates
FOR EACH ROW
EXECUTE FUNCTION validate_certificate_issuance();

-- ------------------------------------------------------------
-- Trigger: audit certificate lifecycle changes
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_certificate_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO pki_audit_events (
        entity_type,
        entity_id,
        action,
        actor,
        details
    )
    VALUES (
        'CERTIFICATE',
        NEW.certificate_id,
        CASE
            WHEN TG_OP = 'INSERT' THEN 'ISSUED'
            WHEN OLD.status <> NEW.status THEN 'STATUS_CHANGED'
            ELSE 'UPDATED'
        END,
        COALESCE(NEW.created_by, 'SYSTEM'),
        jsonb_build_object(
            'serial', NEW.serial_number,
            'subject', NEW.subject,
            'old_status',
                CASE WHEN TG_OP = 'UPDATE'
                THEN OLD.status::TEXT ELSE NULL END,
            'new_status', NEW.status::TEXT
        )
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_certificate_changes
AFTER INSERT OR UPDATE ON certificates
FOR EACH ROW
EXECUTE FUNCTION audit_certificate_changes();

-- ------------------------------------------------------------
-- Controlled revocation procedure
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE revoke_certificate(
    p_serial VARCHAR(80),
    p_reason revocation_reason,
    p_actor VARCHAR(150),
    p_remarks TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_certificate_id BIGINT;
    v_status certificate_status;
BEGIN
    SELECT certificate_id, status
    INTO v_certificate_id, v_status
    FROM certificates
    WHERE serial_number = p_serial
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Certificate serial % not found', p_serial;
    END IF;

    IF v_status = 'REVOKED' THEN
        RAISE EXCEPTION 'Certificate already revoked';
    END IF;

    UPDATE certificates
    SET status = 'REVOKED'
    WHERE certificate_id = v_certificate_id;

    INSERT INTO certificate_revocations (
        certificate_id,
        reason,
        revoked_by,
        remarks
    )
    VALUES (
        v_certificate_id,
        p_reason,
        p_actor,
        p_remarks
    );

    INSERT INTO pki_audit_events (
        entity_type,
        entity_id,
        action,
        actor,
        details
    )
    VALUES (
        'CERTIFICATE',
        v_certificate_id,
        'REVOKED',
        p_actor,
        jsonb_build_object(
            'reason', p_reason,
            'remarks', p_remarks
        )
    );
END;
$$;

-- ------------------------------------------------------------
-- Certificate chain retrieval
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION get_certificate_chain(
    p_serial VARCHAR(80)
)
RETURNS TABLE (
    depth INTEGER,
    certificate_id BIGINT,
    serial_number VARCHAR(80),
    subject VARCHAR(500),
    issuer VARCHAR(500),
    status certificate_status
)
LANGUAGE sql
STABLE
AS $$
    WITH RECURSIVE chain AS (
        SELECT
            0 AS depth,
            c.certificate_id,
            c.serial_number,
            c.subject,
            c.issuer,
            c.issuing_ca_id,
            c.status,
            ARRAY[c.certificate_id] AS visited
        FROM certificates c
        WHERE c.serial_number = p_serial

        UNION ALL

        SELECT
            chain.depth + 1,
            parent.certificate_id,
            parent.serial_number,
            parent.subject,
            parent.issuer,
            parent.issuing_ca_id,
            parent.status,
            chain.visited || parent.certificate_id
        FROM chain
        JOIN certificate_authorities ca
          ON ca.ca_id = chain.issuing_ca_id
        JOIN certificates parent
          ON parent.serial_number = ca.certificate_serial
        WHERE NOT parent.certificate_id = ANY(chain.visited)
    )
    SELECT
        chain.depth,
        chain.certificate_id,
        chain.serial_number,
        chain.subject,
        chain.issuer,
        chain.status
    FROM chain
    ORDER BY chain.depth;
$$;

-- ------------------------------------------------------------
-- Certificate eligibility evaluation
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION evaluate_certificate(
    p_serial VARCHAR(80),
    p_hostname VARCHAR(500),
    p_policy_id BIGINT
)
RETURNS TABLE (
    eligible BOOLEAN,
    result_message TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    cert certificates%ROWTYPE;
    policy validation_policies%ROWTYPE;
    key_record public_keys%ROWTYPE;
    trusted BOOLEAN;
    usage_missing BOOLEAN;
    hostname_valid BOOLEAN;
    revoked BOOLEAN;
    chain_invalid BOOLEAN;
BEGIN
    SELECT *
    INTO cert
    FROM certificates
    WHERE serial_number = p_serial;

    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 'Certificate not found';
        RETURN;
    END IF;

    SELECT *
    INTO policy
    FROM validation_policies
    WHERE policy_id = p_policy_id
      AND is_enabled = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 'Policy unavailable';
        RETURN;
    END IF;

    IF cert.certificate_type <> policy.certificate_type THEN
        RETURN QUERY SELECT FALSE, 'Certificate type mismatch';
        RETURN;
    END IF;

    IF cert.status <> 'ACTIVE' THEN
        RETURN QUERY SELECT FALSE, 'Certificate is not active';
        RETURN;
    END IF;

    IF NOW() < cert.not_before OR NOW() > cert.not_after THEN
        RETURN QUERY SELECT FALSE, 'Certificate outside validity period';
        RETURN;
    END IF;

    IF cert.not_after - cert.not_before >
       policy.maximum_validity_days * INTERVAL '1 day' THEN
        RETURN QUERY SELECT FALSE, 'Validity exceeds policy limit';
        RETURN;
    END IF;

    SELECT *
    INTO key_record
    FROM public_keys
    WHERE public_key_id = cert.public_key_id;

    IF key_record.algorithm = 'RSA'
       AND key_record.key_size < policy.minimum_rsa_key_size THEN
        RETURN QUERY SELECT FALSE, 'RSA key size below policy minimum';
        RETURN;
    END IF;

    IF policy.require_hostname_match THEN
        SELECT EXISTS (
            SELECT 1
            FROM certificate_sans
            WHERE certificate_id = cert.certificate_id
              AND san_type = 'DNS'
              AND san_value = p_hostname
        )
        INTO hostname_valid;

        IF NOT hostname_valid THEN
            RETURN QUERY SELECT FALSE, 'Hostname mismatch';
            RETURN;
        END IF;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM certificate_revocations
        WHERE certificate_id = cert.certificate_id
    )
    INTO revoked;

    IF policy.require_revocation_check AND revoked THEN
        RETURN QUERY SELECT FALSE, 'Certificate revoked';
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM policy_required_usages required
        WHERE required.policy_id = p_policy_id
          AND NOT EXISTS (
              SELECT 1
              FROM certificate_key_usages actual
              WHERE actual.certificate_id = cert.certificate_id
                AND actual.usage = required.usage
          )
    )
    INTO usage_missing;

    IF usage_missing THEN
        RETURN QUERY SELECT FALSE, 'Required key usage missing';
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM get_certificate_chain(p_serial) chain
        WHERE chain.status <> 'ACTIVE'
    )
    INTO chain_invalid;

    IF chain_invalid THEN
        RETURN QUERY SELECT FALSE, 'Certificate chain contains inactive certificate';
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM get_certificate_chain(p_serial) chain
        JOIN certificate_authorities ca
          ON ca.certificate_serial = chain.serial_number
        JOIN trust_anchors ta
          ON ta.ca_id = ca.ca_id
        WHERE chain.depth = (
            SELECT MAX(depth)
            FROM get_certificate_chain(p_serial)
        )
        AND ta.is_enabled = TRUE
    )
    INTO trusted;

    IF policy.require_trusted_root AND NOT trusted THEN
        RETURN QUERY SELECT FALSE, 'Trusted root not established';
        RETURN;
    END IF;

    RETURN QUERY SELECT TRUE, 'Certificate meets database policy';
END;
$$;

-- ------------------------------------------------------------
-- Views
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW active_certificate_inventory AS
SELECT
    c.certificate_id,
    c.serial_number,
    c.subject,
    c.issuer,
    c.certificate_type,
    c.not_before,
    c.not_after,
    c.not_after - NOW() AS remaining_validity,
    pk.algorithm,
    pk.key_size,
    c.status
FROM certificates c
JOIN public_keys pk
    ON pk.public_key_id = c.public_key_id
WHERE c.status = 'ACTIVE'
  AND NOW() BETWEEN c.not_before AND c.not_after;

CREATE OR REPLACE VIEW certificate_expiry_report AS
SELECT
    certificate_id,
    serial_number,
    subject,
    not_after,
    CEIL(
        EXTRACT(EPOCH FROM (not_after - NOW())) / 86400
    ) AS days_remaining
FROM certificates
WHERE status = 'ACTIVE'
  AND not_after > NOW()
  AND not_after <= NOW() + INTERVAL '90 days';

CREATE OR REPLACE VIEW certificate_revocation_report AS
SELECT
    c.serial_number,
    c.subject,
    r.reason,
    r.revoked_at,
    r.revoked_by,
    r.remarks
FROM certificate_revocations r
JOIN certificates c
    ON c.certificate_id = r.certificate_id;

-- ------------------------------------------------------------
-- Sample root CA
-- ------------------------------------------------------------

INSERT INTO public_keys (
    fingerprint,
    algorithm,
    key_size
)
VALUES
(
    REPEAT('a', 64),
    'RSA',
    4096
),
(
    REPEAT('b', 64),
    'RSA',
    3072
),
(
    REPEAT('c', 64),
    'RSA',
    3072
),
(
    REPEAT('d', 64),
    'ED25519',
    256
);

INSERT INTO certificate_authorities (
    ca_name,
    ca_type,
    certificate_serial,
    parent_ca_id,
    is_trusted
)
VALUES (
    'Enterprise Root CA',
    'ROOT',
    '1000',
    NULL,
    TRUE
);

INSERT INTO certificates (
    serial_number,
    subject,
    issuer,
    certificate_type,
    public_key_id,
    issuing_ca_id,
    not_before,
    not_after,
    is_ca,
    path_length,
    signature_algorithm,
    signature_value,
    created_by
)
SELECT
    '1000',
    'Enterprise Root CA',
    'Enterprise Root CA',
    'ROOT_CA',
    pk.public_key_id,
    ca.ca_id,
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '10 years',
    TRUE,
    1,
    'SHA256WITHRSA',
    DECODE(REPEAT('01', 256), 'hex'),
    'pki-bootstrap'
FROM public_keys pk
CROSS JOIN certificate_authorities ca
WHERE pk.fingerprint = REPEAT('a', 64)
  AND ca.ca_name = 'Enterprise Root CA';

INSERT INTO certificate_key_usages
SELECT certificate_id, 'KEY_CERT_SIGN'
FROM certificates
WHERE serial_number = '1000';

INSERT INTO certificate_key_usages
SELECT certificate_id, 'CRL_SIGN'
FROM certificates
WHERE serial_number = '1000';

INSERT INTO trust_anchors (
    ca_id,
    approved_by
)
SELECT ca_id, 'security-administrator'
FROM certificate_authorities
WHERE ca_name = 'Enterprise Root CA';

-- ------------------------------------------------------------
-- Intermediate CA
-- ------------------------------------------------------------

INSERT INTO certificate_authorities (
    ca_name,
    ca_type,
    certificate_serial,
    parent_ca_id,
    is_trusted
)
SELECT
    'Enterprise Issuing CA',
    'INTERMEDIATE',
    '2000',
    ca_id,
    FALSE
FROM certificate_authorities
WHERE ca_name = 'Enterprise Root CA';

INSERT INTO certificates (
    serial_number,
    subject,
    issuer,
    certificate_type,
    public_key_id,
    issuing_ca_id,
    not_before,
    not_after,
    is_ca,
    path_length,
    signature_algorithm,
    signature_value,
    created_by
)
SELECT
    '2000',
    'Enterprise Issuing CA',
    'Enterprise Root CA',
    'INTERMEDIATE_CA',
    pk.public_key_id,
    root.ca_id,
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '2 years',
    TRUE,
    0,
    'SHA256WITHRSA',
    DECODE(REPEAT('02', 256), 'hex'),
    'root-ca'
FROM public_keys pk
JOIN certificate_authorities root
  ON root.ca_name = 'Enterprise Root CA'
WHERE pk.fingerprint = REPEAT('b', 64);

INSERT INTO certificate_key_usages
SELECT certificate_id, 'KEY_CERT_SIGN'
FROM certificates
WHERE serial_number = '2000';

INSERT INTO certificate_key_usages
SELECT certificate_id, 'CRL_SIGN'
FROM certificates
WHERE serial_number = '2000';

-- ------------------------------------------------------------
-- Server certificate
-- ------------------------------------------------------------

INSERT INTO certificates (
    serial_number,
    subject,
    issuer,
    certificate_type,
    public_key_id,
    issuing_ca_id,
    not_before,
    not_after,
    is_ca,
    signature_algorithm,
    signature_value,
    created_by
)
SELECT
    '3000',
    'www.example.com',
    'Enterprise Issuing CA',
    'SERVER',
    pk.public_key_id,
    ca.ca_id,
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '90 days',
    FALSE,
    'SHA256WITHRSA',
    DECODE(REPEAT('03', 256), 'hex'),
    'issuing-ca'
FROM public_keys pk
JOIN certificate_authorities ca
  ON ca.ca_name = 'Enterprise Issuing CA'
WHERE pk.fingerprint = REPEAT('c', 64);

INSERT INTO certificate_key_usages
SELECT certificate_id, 'DIGITAL_SIGNATURE'
FROM certificates
WHERE serial_number = '3000';

INSERT INTO certificate_key_usages
SELECT certificate_id, 'KEY_ENCIPHERMENT'
FROM certificates
WHERE serial_number = '3000';

INSERT INTO certificate_sans (
    certificate_id,
    san_type,
    san_value
)
SELECT certificate_id, 'DNS', 'www.example.com'
FROM certificates
WHERE serial_number = '3000';

INSERT INTO certificate_sans (
    certificate_id,
    san_type,
    san_value
)
SELECT certificate_id, 'DNS', 'api.example.com'
FROM certificates
WHERE serial_number = '3000';

-- ------------------------------------------------------------
-- Client certificate
-- ------------------------------------------------------------

INSERT INTO certificates (
    serial_number,
    subject,
    issuer,
    certificate_type,
    public_key_id,
    issuing_ca_id,
    not_before,
    not_after,
    is_ca,
    signature_algorithm,
    signature_value,
    created_by
)
SELECT
    '3001',
    'service-account@example.com',
    'Enterprise Issuing CA',
    'CLIENT',
    pk.public_key_id,
    ca.ca_id,
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '180 days',
    FALSE,
    'SHA256WITHRSA',
    DECODE(REPEAT('04', 256), 'hex'),
    'issuing-ca'
FROM public_keys pk
JOIN certificate_authorities ca
  ON ca.ca_name = 'Enterprise Issuing CA'
WHERE pk.fingerprint = REPEAT('d', 64);

INSERT INTO certificate_key_usages
SELECT certificate_id, 'DIGITAL_SIGNATURE'
FROM certificates
WHERE serial_number = '3001';

-- ------------------------------------------------------------
-- Validation policies
-- ------------------------------------------------------------

INSERT INTO validation_policies (
    policy_name,
    certificate_type,
    minimum_rsa_key_size,
    maximum_validity_days,
    require_trusted_root,
    require_hostname_match,
    require_revocation_check
)
VALUES
(
    'Enterprise TLS Server Policy',
    'SERVER',
    2048,
    398,
    TRUE,
    TRUE,
    TRUE
),
(
    'Enterprise Client Authentication Policy',
    'CLIENT',
    2048,
    398,
    TRUE,
    FALSE,
    TRUE
);

INSERT INTO policy_required_usages (
    policy_id,
    usage
)
SELECT policy_id, 'DIGITAL_SIGNATURE'
FROM validation_policies
WHERE policy_name IN (
    'Enterprise TLS Server Policy',
    'Enterprise Client Authentication Policy'
);

-- ------------------------------------------------------------
-- Retrieval: certificate inventory
-- ------------------------------------------------------------

SELECT
    serial_number,
    subject,
    issuer,
    certificate_type,
    status,
    not_before,
    not_after
FROM certificates
ORDER BY serial_number;

-- ------------------------------------------------------------
-- Retrieval: certificate chain
-- ------------------------------------------------------------

SELECT *
FROM get_certificate_chain('3000');

-- ------------------------------------------------------------
-- Evaluation: TLS certificate
-- ------------------------------------------------------------

SELECT *
FROM evaluate_certificate(
    '3000',
    'www.example.com',
    (
        SELECT policy_id
        FROM validation_policies
        WHERE policy_name = 'Enterprise TLS Server Policy'
    )
);

-- ------------------------------------------------------------
-- Negative evaluation: hostname mismatch
-- ------------------------------------------------------------

SELECT *
FROM evaluate_certificate(
    '3000',
    'attacker.example.net',
    (
        SELECT policy_id
        FROM validation_policies
        WHERE policy_name = 'Enterprise TLS Server Policy'
    )
);

-- ------------------------------------------------------------
-- Negative evaluation: wrong certificate type
-- ------------------------------------------------------------

SELECT *
FROM evaluate_certificate(
    '3001',
    'www.example.com',
    (
        SELECT policy_id
        FROM validation_policies
        WHERE policy_name = 'Enterprise TLS Server Policy'
    )
);

-- ------------------------------------------------------------
-- Aggregation: certificate counts
-- ------------------------------------------------------------

SELECT
    certificate_type,
    status,
    COUNT(*) AS certificate_count
FROM certificates
GROUP BY certificate_type, status
ORDER BY certificate_type, status;

-- ------------------------------------------------------------
-- Aggregation: issuing authority utilization
-- ------------------------------------------------------------

SELECT
    ca.ca_name,
    COUNT(c.certificate_id) AS issued_certificates,
    COUNT(*) FILTER (
        WHERE c.status = 'ACTIVE'
    ) AS active_certificates,
    COUNT(*) FILTER (
        WHERE c.status = 'REVOKED'
    ) AS revoked_certificates
FROM certificate_authorities ca
LEFT JOIN certificates c
    ON c.issuing_ca_id = ca.ca_id
GROUP BY ca.ca_id, ca.ca_name
ORDER BY issued_certificates DESC;

-- ------------------------------------------------------------
-- Reporting: certificates approaching expiration
-- ------------------------------------------------------------

SELECT *
FROM certificate_expiry_report
ORDER BY days_remaining;

-- ------------------------------------------------------------
-- Reporting: certificate algorithm distribution
-- ------------------------------------------------------------

SELECT
    pk.algorithm,
    pk.key_size,
    COUNT(*) AS certificate_count
FROM certificates c
JOIN public_keys pk
    ON pk.public_key_id = c.public_key_id
GROUP BY pk.algorithm, pk.key_size
ORDER BY certificate_count DESC;

-- ------------------------------------------------------------
-- Reporting: certificates missing required usage
-- ------------------------------------------------------------

SELECT
    c.serial_number,
    c.subject,
    required.usage
FROM certificates c
CROSS JOIN policy_required_usages required
JOIN validation_policies p
    ON p.policy_id = required.policy_id
WHERE p.policy_name = 'Enterprise TLS Server Policy'
  AND c.certificate_type = 'SERVER'
  AND NOT EXISTS (
      SELECT 1
      FROM certificate_key_usages actual
      WHERE actual.certificate_id = c.certificate_id
        AND actual.usage = required.usage
  );

-- ------------------------------------------------------------
-- Demonstrate transactional revocation
-- ------------------------------------------------------------

DO $$
BEGIN
    CALL revoke_certificate(
        '3001',
        'KEY_COMPROMISE',
        'security-administrator',
        'Demonstration of controlled revocation'
    );
END;
$$;

-- ------------------------------------------------------------
-- Verify revocation
-- ------------------------------------------------------------

SELECT *
FROM certificate_revocation_report;

-- A revoked certificate must not satisfy the active policy.
SELECT *
FROM evaluate_certificate(
    '3001',
    NULL,
    (
        SELECT policy_id
        FROM validation_policies
        WHERE policy_name = 'Enterprise Client Authentication Policy'
    )
);

-- ------------------------------------------------------------
-- Validation event recording
-- ------------------------------------------------------------

INSERT INTO certificate_validation_events (
    certificate_id,
    policy_id,
    validation_status,
    requested_hostname,
    validator_identity,
    failure_reason
)
SELECT
    c.certificate_id,
    p.policy_id,
    CASE
        WHEN c.status = 'ACTIVE'
         AND NOW() BETWEEN c.not_before AND c.not_after
        THEN 'VALID'::validation_status
        WHEN c.status = 'REVOKED'
        THEN 'REVOKED'::validation_status
        ELSE 'INVALID'::validation_status
    END,
    'www.example.com',
    'tls-validation-service',
    CASE
        WHEN c.status = 'REVOKED'
        THEN 'Certificate revoked'
        ELSE NULL
    END
FROM certificates c
CROSS JOIN validation_policies p
WHERE c.serial_number = '3000'
  AND p.policy_name = 'Enterprise TLS Server Policy';

-- ------------------------------------------------------------
-- Validation reporting
-- ------------------------------------------------------------

SELECT
    validation_status,
    COUNT(*) AS total_events
FROM certificate_validation_events
GROUP BY validation_status
ORDER BY validation_status;

-- ------------------------------------------------------------
-- Audit reporting
-- ------------------------------------------------------------

SELECT
    entity_type,
    entity_id,
    action,
    actor,
    event_time,
    details
FROM pki_audit_events
ORDER BY event_time DESC;

-- ------------------------------------------------------------
-- Operational inventory
-- ------------------------------------------------------------

SELECT * FROM active_certificate_inventory;

-- ------------------------------------------------------------
-- Commit all schema and sample operations
-- ------------------------------------------------------------

COMMIT;
