-- PostgreSQL implementation of an encryption-mode governance model.
--
-- The schema separates:
--   * encryption mode characteristics,
--   * encryption policies,
--   * protected data records,
--   * nonce/IV usage,
--   * authentication requirements,
--   * policy evaluation decisions.
--
-- The encrypted_payload column represents ciphertext supplied by an
-- application using an audited cryptographic library. This SQL script does
-- not implement cryptographic primitives inside PostgreSQL.

DROP SCHEMA IF EXISTS encryption_governance CASCADE;

CREATE SCHEMA encryption_governance;

SET search_path TO encryption_governance;

CREATE TYPE encryption_mode AS ENUM (
    'ECB',
    'CBC',
    'CTR',
    'GCM',
    'CHACHA20_POLY1305'
);

CREATE TYPE record_state AS ENUM (
    'CREATED',
    'ENCRYPTED',
    'AUTHENTICATED',
    'REJECTED'
);

CREATE TYPE decision_state AS ENUM (
    'APPROVED',
    'REJECTED'
);

CREATE TABLE encryption_modes (
    mode encryption_mode PRIMARY KEY,
    provides_confidentiality BOOLEAN NOT NULL DEFAULT TRUE,
    provides_authentication BOOLEAN NOT NULL DEFAULT FALSE,
    requires_padding BOOLEAN NOT NULL,
    supports_parallel_encryption BOOLEAN NOT NULL,
    requires_unique_nonce BOOLEAN NOT NULL,
    operational_risk TEXT NOT NULL,
    CHECK (
        mode <> 'ECB'
        OR provides_authentication = FALSE
    ),
    CHECK (
        requires_unique_nonce = TRUE
        OR mode IN ('ECB', 'CBC')
    )
);

CREATE TABLE encryption_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    mode encryption_mode NOT NULL
        REFERENCES encryption_modes(mode),
    integrity_required BOOLEAN NOT NULL,
    minimum_key_bits INTEGER NOT NULL,
    require_unique_nonce BOOLEAN NOT NULL,
    allow_legacy_interoperability BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (minimum_key_bits >= 128)
);

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    data_classification TEXT NOT NULL,
    default_policy_id BIGINT
        REFERENCES encryption_policies(policy_id)
);

CREATE TABLE encrypted_records (
    record_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),
    external_reference TEXT NOT NULL,
    mode encryption_mode NOT NULL
        REFERENCES encryption_modes(mode),
    policy_id BIGINT NOT NULL
        REFERENCES encryption_policies(policy_id),
    state record_state NOT NULL DEFAULT 'CREATED',
    key_version INTEGER NOT NULL,
    encrypted_payload BYTEA NOT NULL,
    authentication_tag BYTEA,
    associated_data BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    encrypted_at TIMESTAMPTZ,
    authenticated_at TIMESTAMPTZ,
    UNIQUE (repository_id, external_reference),
    CHECK (key_version > 0),
    CHECK (
        (
            state = 'AUTHENTICATED'
            AND authentication_tag IS NOT NULL
        )
        OR state <> 'AUTHENTICATED'
    ),
    CHECK (
        (
            mode IN ('GCM', 'CHACHA20_POLY1305')
            AND authentication_tag IS NOT NULL
        )
        OR mode NOT IN ('GCM', 'CHACHA20_POLY1305')
        OR state <> 'AUTHENTICATED'
    )
);

CREATE TABLE nonce_usage (
    nonce_id BIGSERIAL PRIMARY KEY,
    record_id BIGINT NOT NULL
        REFERENCES encrypted_records(record_id)
        ON DELETE CASCADE,
    key_version INTEGER NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (key_version, nonce),
    UNIQUE (record_id),
    CHECK (octet_length(nonce) >= 8)
);

CREATE TABLE policy_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    record_id BIGINT NOT NULL
        REFERENCES encrypted_records(record_id)
        ON DELETE CASCADE,
    policy_id BIGINT NOT NULL
        REFERENCES encryption_policies(policy_id),
    decision decision_state NOT NULL,
    reason TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_encrypted_records_repository_state
    ON encrypted_records(repository_id, state);

CREATE INDEX idx_encrypted_records_policy
    ON encrypted_records(policy_id);

CREATE INDEX idx_nonce_usage_key_version
    ON nonce_usage(key_version);

CREATE INDEX idx_policy_decisions_record
    ON policy_decisions(record_id, evaluated_at DESC);

INSERT INTO encryption_modes (
    mode,
    provides_confidentiality,
    provides_authentication,
    requires_padding,
    supports_parallel_encryption,
    requires_unique_nonce,
    operational_risk
)
VALUES
(
    'ECB',
    TRUE,
    FALSE,
    TRUE,
    TRUE,
    FALSE,
    'Repeated plaintext blocks can reveal structural relationships.'
),
(
    'CBC',
    TRUE,
    FALSE,
    TRUE,
    FALSE,
    FALSE,
    'Unauthenticated CBC is malleable and can expose padding-oracle risks.'
),
(
    'CTR',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'Nonce reuse can expose relationships between plaintexts.'
),
(
    'GCM',
    TRUE,
    TRUE,
    FALSE,
    TRUE,
    TRUE,
    'Nonce reuse can seriously compromise authenticated encryption.'
),
(
    'CHACHA20_POLY1305',
    TRUE,
    TRUE,
    FALSE,
    TRUE,
    TRUE,
    'Nonce management and key management remain critical.'
);

INSERT INTO encryption_policies (
    policy_name,
    mode,
    integrity_required,
    minimum_key_bits,
    require_unique_nonce,
    allow_legacy_interoperability
)
VALUES
(
    'Legacy CBC Interoperability',
    'CBC',
    FALSE,
    256,
    FALSE,
    TRUE
),
(
    'Internal CTR Confidentiality',
    'CTR',
    FALSE,
    256,
    TRUE,
    FALSE
),
(
    'Financial Records AEAD',
    'GCM',
    TRUE,
    256,
    TRUE,
    FALSE
),
(
    'High Assurance AEAD',
    'CHACHA20_POLY1305',
    TRUE,
    256,
    TRUE,
    FALSE
);

INSERT INTO repositories (
    repository_name,
    data_classification,
    default_policy_id
)
SELECT
    'treasury-records',
    'restricted-financial',
    policy_id
FROM encryption_policies
WHERE policy_name = 'Financial Records AEAD';

INSERT INTO repositories (
    repository_name,
    data_classification,
    default_policy_id
)
SELECT
    'warehouse-records',
    'confidential-operational',
    policy_id
FROM encryption_policies
WHERE policy_name = 'High Assurance AEAD';

INSERT INTO encrypted_records (
    repository_id,
    external_reference,
    mode,
    policy_id,
    state,
    key_version,
    encrypted_payload,
    authentication_tag,
    associated_data,
    encrypted_at,
    authenticated_at
)
SELECT
    r.repository_id,
    'PAY-2026-1007',
    'GCM',
    p.policy_id,
    'AUTHENTICATED',
    7,
    decode('7f8a91ab2211', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to(
        'record-type=payment;classification=restricted',
        'UTF8'
    ),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM repositories r
JOIN encryption_policies p
    ON p.policy_name = 'Financial Records AEAD'
WHERE r.repository_name = 'treasury-records';

INSERT INTO encrypted_records (
    repository_id,
    external_reference,
    mode,
    policy_id,
    state,
    key_version,
    encrypted_payload,
    associated_data,
    encrypted_at
)
SELECT
    r.repository_id,
    'WH-2026-840',
    'CTR',
    p.policy_id,
    'ENCRYPTED',
    4,
    decode('1234567890abcdef', 'hex'),
    convert_to(
        'record-type=inventory;classification=confidential',
        'UTF8'
    ),
    CURRENT_TIMESTAMP
FROM repositories r
JOIN encryption_policies p
    ON p.policy_name = 'Internal CTR Confidentiality'
WHERE r.repository_name = 'warehouse-records';

INSERT INTO nonce_usage (
    record_id,
    key_version,
    nonce
)
SELECT
    record_id,
    key_version,
    decode('0102030405060708090a0b0c', 'hex')
FROM encrypted_records
WHERE external_reference = 'PAY-2026-1007';

INSERT INTO nonce_usage (
    record_id,
    key_version,
    nonce
)
SELECT
    record_id,
    key_version,
    decode('112233445566778899aabbcc', 'hex')
FROM encrypted_records
WHERE external_reference = 'WH-2026-840';

CREATE VIEW encryption_mode_inventory AS
SELECT
    mode,
    provides_confidentiality,
    provides_authentication,
    requires_padding,
    supports_parallel_encryption,
    requires_unique_nonce,
    operational_risk
FROM encryption_modes;

CREATE VIEW authenticated_record_audit AS
SELECT
    er.record_id,
    r.repository_name,
    er.external_reference,
    er.mode,
    er.key_version,
    er.state,
    er.authentication_tag IS NOT NULL AS has_authentication_tag,
    nu.nonce IS NOT NULL AS has_nonce,
    er.created_at,
    er.authenticated_at
FROM encrypted_records er
JOIN repositories r
    ON r.repository_id = er.repository_id
LEFT JOIN nonce_usage nu
    ON nu.record_id = er.record_id
WHERE er.state = 'AUTHENTICATED';

CREATE OR REPLACE FUNCTION validate_encryption_policy(
    requested_mode encryption_mode,
    integrity_required BOOLEAN,
    nonce_available BOOLEAN
)
RETURNS TABLE (
    approved BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    selected_mode encryption_modes%ROWTYPE;
BEGIN
    SELECT *
    INTO selected_mode
    FROM encryption_modes
    WHERE mode = requested_mode;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, 'Unknown encryption mode';
        RETURN;
    END IF;

    IF integrity_required
       AND NOT selected_mode.provides_authentication THEN
        RETURN QUERY
        SELECT
            FALSE,
            'The selected mode does not provide authentication';
        RETURN;
    END IF;

    IF selected_mode.requires_unique_nonce
       AND NOT nonce_available THEN
        RETURN QUERY
        SELECT
            FALSE,
            'A unique nonce is required by the selected mode';
        RETURN;
    END IF;

    RETURN QUERY
    SELECT TRUE, 'Encryption policy accepted';
END;
$$;

CREATE OR REPLACE FUNCTION prevent_invalid_authenticated_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'AUTHENTICATED'
       AND NEW.authentication_tag IS NULL THEN
        RAISE EXCEPTION
            'Authenticated records require an authentication tag';
    END IF;

    IF NEW.mode IN ('GCM', 'CHACHA20_POLY1305')
       AND NEW.state = 'AUTHENTICATED'
       AND NEW.authentication_tag IS NULL THEN
        RAISE EXCEPTION
            'AEAD records require an authentication tag';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER encrypted_record_integrity_guard
BEFORE INSERT OR UPDATE
ON encrypted_records
FOR EACH ROW
EXECUTE FUNCTION prevent_invalid_authenticated_state();

-- Policy evaluation examples.

SELECT *
FROM encryption_mode_inventory
ORDER BY mode;

SELECT *
FROM validate_encryption_policy(
    'GCM',
    TRUE,
    TRUE
);

SELECT *
FROM validate_encryption_policy(
    'CTR',
    TRUE,
    TRUE
);

SELECT *
FROM validate_encryption_policy(
    'GCM',
    TRUE,
    FALSE
);

SELECT
    r.repository_name,
    COUNT(*) AS encrypted_records,
    COUNT(*) FILTER (
        WHERE er.state = 'AUTHENTICATED'
    ) AS authenticated_records
FROM encrypted_records er
JOIN repositories r
    ON r.repository_id = er.repository_id
GROUP BY r.repository_name
ORDER BY r.repository_name;

SELECT
    er.external_reference,
    er.mode,
    er.state,
    er.key_version,
    octet_length(er.encrypted_payload) AS ciphertext_bytes,
    octet_length(nu.nonce) AS nonce_bytes,
    er.authentication_tag IS NOT NULL AS authenticated
FROM encrypted_records er
LEFT JOIN nonce_usage nu
    ON nu.record_id = er.record_id
ORDER BY er.record_id;

-- PostgreSQL's UNIQUE(key_version, nonce) constraint prevents the same nonce
-- from being registered twice for the same key version. The following query
-- exposes any duplicate attempt if imported data bypassed the intended path.
SELECT
    key_version,
    encode(nonce, 'hex') AS nonce_hex,
    COUNT(*) AS usage_count
FROM nonce_usage
GROUP BY key_version, nonce
HAVING COUNT(*) > 1;

-- Demonstrate a transaction for a policy decision.
BEGIN;

INSERT INTO policy_decisions (
    record_id,
    policy_id,
    decision,
    reason
)
SELECT
    er.record_id,
    er.policy_id,
    CASE
        WHEN em.provides_authentication
             AND nu.nonce IS NOT NULL
        THEN 'APPROVED'::decision_state
        ELSE 'REJECTED'::decision_state
    END,
    CASE
        WHEN em.provides_authentication
             AND nu.nonce IS NOT NULL
        THEN 'Authenticated mode with registered nonce'
        ELSE 'Integrity or nonce requirement is not satisfied'
    END
FROM encrypted_records er
JOIN encryption_modes em
    ON em.mode = er.mode
LEFT JOIN nonce_usage nu
    ON nu.record_id = er.record_id
WHERE er.external_reference = 'PAY-2026-1007';

COMMIT;

SELECT
    pd.decision_id,
    er.external_reference,
    p.policy_name,
    pd.decision,
    pd.reason,
    pd.evaluated_at
FROM policy_decisions pd
JOIN encrypted_records er
    ON er.record_id = pd.record_id
JOIN encryption_policies p
    ON p.policy_id = pd.policy_id
ORDER BY pd.evaluated_at DESC;
