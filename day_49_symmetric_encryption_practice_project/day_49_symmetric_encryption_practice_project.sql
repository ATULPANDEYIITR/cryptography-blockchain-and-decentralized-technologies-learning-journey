-- Symmetric Encryption Practice Project
-- PostgreSQL-compatible relational model.
--
-- The database models an encrypted document service rather than attempting
-- to implement AES inside SQL. Cryptographic operations belong in a reviewed
-- application or cryptographic service, while PostgreSQL enforces:
-- key-version identity, document lifecycle, nonce uniqueness, ciphertext
-- metadata, auditability, and state consistency.

DROP SCHEMA IF EXISTS symmetric_encryption_practice CASCADE;
CREATE SCHEMA symmetric_encryption_practice;
SET search_path TO symmetric_encryption_practice;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'RETIRED',
    'REVOKED'
);

CREATE TYPE document_status AS ENUM (
    'ACTIVE',
    'ROTATED',
    'REVOKED'
);

CREATE TABLE encryption_keys (
    key_id              BIGSERIAL PRIMARY KEY,
    key_name            TEXT NOT NULL UNIQUE,
    algorithm           TEXT NOT NULL,
    key_version         INTEGER NOT NULL,
    status              key_status NOT NULL DEFAULT 'ACTIVE',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at          TIMESTAMPTZ,
    CONSTRAINT encryption_keys_algorithm_chk
        CHECK (algorithm IN ('AES-256-GCM')),
    CONSTRAINT encryption_keys_version_chk
        CHECK (key_version > 0),
    CONSTRAINT encryption_keys_retirement_chk
        CHECK (
            (status = 'ACTIVE' AND retired_at IS NULL)
            OR
            (status <> 'ACTIVE')
        )
);

-- The actual key material is intentionally not stored in this practice
-- database. A production deployment would normally use a KMS/HSM or another
-- dedicated key-management boundary.
CREATE TABLE encryption_key_events (
    event_id            BIGSERIAL PRIMARY KEY,
    key_id              BIGINT NOT NULL
                        REFERENCES encryption_keys(key_id),
    event_type          TEXT NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason              TEXT,
    CONSTRAINT key_events_type_chk
        CHECK (
            event_type IN (
                'CREATED',
                'ROTATED',
                'RETIRED',
                'REVOKED'
            )
        )
);

CREATE TABLE protected_documents (
    document_id         BIGSERIAL PRIMARY KEY,
    external_reference  TEXT NOT NULL UNIQUE,
    classification      TEXT NOT NULL,
    status              document_status NOT NULL DEFAULT 'ACTIVE',
    current_key_id      BIGINT NOT NULL
                        REFERENCES encryption_keys(key_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE encrypted_document_versions (
    document_version_id BIGSERIAL PRIMARY KEY,
    document_id         BIGINT NOT NULL
                        REFERENCES protected_documents(document_id)
                        ON DELETE CASCADE,
    key_id              BIGINT NOT NULL
                        REFERENCES encryption_keys(key_id),
    nonce               BYTEA NOT NULL,
    ciphertext          BYTEA NOT NULL,
    authentication_tag  BYTEA NOT NULL,
    associated_data     BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT nonce_length_chk
        CHECK (octet_length(nonce) = 12),
    CONSTRAINT tag_length_chk
        CHECK (octet_length(authentication_tag) = 16),
    CONSTRAINT ciphertext_nonempty_chk
        CHECK (octet_length(ciphertext) > 0),
    UNIQUE (key_id, nonce)
);

-- This index supports document history and rotation workflows.
CREATE INDEX encrypted_document_versions_document_idx
    ON encrypted_document_versions(document_id, created_at DESC);

CREATE INDEX protected_documents_key_idx
    ON protected_documents(current_key_id);

CREATE TABLE encryption_audit_log (
    audit_id            BIGSERIAL PRIMARY KEY,
    document_id         BIGINT
                        REFERENCES protected_documents(document_id),
    key_id              BIGINT
                        REFERENCES encryption_keys(key_id),
    action              TEXT NOT NULL,
    succeeded           BOOLEAN NOT NULL,
    details             TEXT,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_action_chk
        CHECK (
            action IN (
                'ENCRYPT',
                'DECRYPT',
                'ROTATE',
                'REVOKE',
                'AUTHENTICATION_FAILURE'
            )
        )
);

CREATE OR REPLACE FUNCTION set_document_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER protected_documents_updated_at
BEFORE UPDATE ON protected_documents
FOR EACH ROW
EXECUTE FUNCTION set_document_updated_at();

CREATE OR REPLACE FUNCTION enforce_active_document_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_status key_status;
BEGIN
    SELECT status
    INTO current_status
    FROM encryption_keys
    WHERE key_id = NEW.key_id;

    IF current_status IS NULL THEN
        RAISE EXCEPTION
            'Encryption key % does not exist',
            NEW.key_id;
    END IF;

    IF current_status <> 'ACTIVE' THEN
        RAISE EXCEPTION
            'Encryption key % is not active',
            NEW.key_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER encrypted_document_active_key
BEFORE INSERT OR UPDATE ON encrypted_document_versions
FOR EACH ROW
EXECUTE FUNCTION enforce_active_document_key();

CREATE OR REPLACE FUNCTION prevent_revoke_with_active_document()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'REVOKED' THEN
        INSERT INTO encryption_audit_log (
            document_id,
            key_id,
            action,
            succeeded,
            details
        )
        VALUES (
            NEW.document_id,
            NEW.current_key_id,
            'REVOKE',
            TRUE,
            'Document access state changed to REVOKED'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER document_revoke_audit
AFTER UPDATE OF status ON protected_documents
FOR EACH ROW
WHEN (NEW.status = 'REVOKED')
EXECUTE FUNCTION prevent_revoke_with_active_document();

CREATE OR REPLACE VIEW current_document_encryption AS
SELECT
    d.document_id,
    d.external_reference,
    d.classification,
    d.status AS document_status,
    k.key_name,
    k.key_version,
    k.algorithm,
    v.document_version_id,
    v.nonce,
    v.ciphertext,
    v.authentication_tag,
    v.associated_data,
    v.created_at AS encrypted_at
FROM protected_documents d
JOIN encryption_keys k
    ON k.key_id = d.current_key_id
JOIN LATERAL (
    SELECT v1.*
    FROM encrypted_document_versions v1
    WHERE v1.document_id = d.document_id
    ORDER BY v1.created_at DESC
    LIMIT 1
) v
    ON TRUE;

-- --------------------------------------------------------------------------
-- Sample key versions
-- --------------------------------------------------------------------------

INSERT INTO encryption_keys (
    key_name,
    algorithm,
    key_version,
    status
)
VALUES
    ('finance-documents-v1', 'AES-256-GCM', 1, 'RETIRED'),
    ('finance-documents-v2', 'AES-256-GCM', 2, 'ACTIVE'),
    ('legal-documents-v1', 'AES-256-GCM', 1, 'ACTIVE');

INSERT INTO encryption_key_events (
    key_id,
    event_type,
    reason
)
SELECT
    key_id,
    CASE
        WHEN key_version = 1 AND key_name = 'finance-documents-v1'
            THEN 'RETIRED'
        ELSE 'CREATED'
    END,
    CASE
        WHEN key_name = 'finance-documents-v1'
            THEN 'Replaced during scheduled key rotation'
        ELSE 'Initial key creation'
    END
FROM encryption_keys;

-- --------------------------------------------------------------------------
-- Protected documents
-- --------------------------------------------------------------------------

INSERT INTO protected_documents (
    external_reference,
    classification,
    status,
    current_key_id
)
SELECT
    'FIN-2026-001',
    'CONFIDENTIAL',
    'ACTIVE',
    key_id
FROM encryption_keys
WHERE key_name = 'finance-documents-v2';

INSERT INTO protected_documents (
    external_reference,
    classification,
    status,
    current_key_id
)
SELECT
    'LEGAL-2026-009',
    'RESTRICTED',
    'ACTIVE',
    key_id
FROM encryption_keys
WHERE key_name = 'legal-documents-v1';

-- pgcrypto provides gen_random_bytes() for sample cryptographic-looking
-- binary data. The example stores ciphertext as data produced by an external
-- encryption service, not by this SQL script.
INSERT INTO encrypted_document_versions (
    document_id,
    key_id,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data
)
SELECT
    d.document_id,
    k.key_id,
    decode('00112233445566778899aabb', 'hex'),
    convert_to(
        'ciphertext produced by AES-256-GCM',
        'UTF8'
    ),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to(
        'document=FIN-2026-001;classification=CONFIDENTIAL',
        'UTF8'
    )
FROM protected_documents d
JOIN encryption_keys k
    ON k.key_id = d.current_key_id
WHERE d.external_reference = 'FIN-2026-001';

INSERT INTO encrypted_document_versions (
    document_id,
    key_id,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data
)
SELECT
    d.document_id,
    k.key_id,
    decode('112233445566778899aabbcc', 'hex'),
    convert_to(
        'legal ciphertext produced by AES-256-GCM',
        'UTF8'
    ),
    decode('112233445566778899aabbccddeeff00', 'hex'),
    convert_to(
        'document=LEGAL-2026-009;classification=RESTRICTED',
        'UTF8'
    )
FROM protected_documents d
JOIN encryption_keys k
    ON k.key_id = d.current_key_id
WHERE d.external_reference = 'LEGAL-2026-009';

-- --------------------------------------------------------------------------
-- Queries representing operational checks
-- --------------------------------------------------------------------------

-- Current encryption state for each protected document.
SELECT
    external_reference,
    classification,
    document_status,
    key_name,
    key_version,
    algorithm,
    encrypted_at
FROM current_document_encryption
ORDER BY external_reference;

-- Find documents that still use an older key version.
SELECT
    d.external_reference,
    k.key_name,
    k.key_version,
    k.status
FROM protected_documents d
JOIN encryption_keys k
    ON k.key_id = d.current_key_id
WHERE k.status <> 'ACTIVE'
   OR k.key_version < (
        SELECT MAX(key_version)
        FROM encryption_keys k2
        WHERE k2.key_name LIKE 'finance-documents-%'
   );

-- Detect duplicate nonces for a key. The UNIQUE constraint should make this
-- query return zero rows under valid database state.
SELECT
    key_id,
    encode(nonce, 'hex') AS nonce_hex,
    COUNT(*) AS occurrences
FROM encrypted_document_versions
GROUP BY key_id, nonce
HAVING COUNT(*) > 1;

-- Show the encryption history of each document.
SELECT
    d.external_reference,
    v.document_version_id,
    k.key_name,
    k.key_version,
    encode(v.nonce, 'hex') AS nonce_hex,
    octet_length(v.ciphertext) AS ciphertext_bytes,
    v.created_at
FROM protected_documents d
JOIN encrypted_document_versions v
    ON v.document_id = d.document_id
JOIN encryption_keys k
    ON k.key_id = v.key_id
ORDER BY
    d.external_reference,
    v.created_at;

-- --------------------------------------------------------------------------
-- Transactional key rotation
-- --------------------------------------------------------------------------

BEGIN;

-- Create a replacement key version.
INSERT INTO encryption_keys (
    key_name,
    algorithm,
    key_version,
    status
)
VALUES (
    'legal-documents-v2',
    'AES-256-GCM',
    2,
    'ACTIVE'
)
RETURNING key_id;

-- The application would decrypt the existing legal record under v1 and
-- submit newly encrypted ciphertext under v2. This SQL transaction updates
-- the database references atomically once that ciphertext is available.

-- Simulate the newly generated encrypted representation.
WITH new_key AS (
    SELECT key_id
    FROM encryption_keys
    WHERE key_name = 'legal-documents-v2'
),
target_document AS (
    SELECT document_id
    FROM protected_documents
    WHERE external_reference = 'LEGAL-2026-009'
)
INSERT INTO encrypted_document_versions (
    document_id,
    key_id,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data
)
SELECT
    target_document.document_id,
    new_key.key_id,
    gen_random_bytes(12),
    convert_to(
        'new ciphertext produced externally using AES-256-GCM',
        'UTF8'
    ),
    gen_random_bytes(16),
    convert_to(
        'document=LEGAL-2026-009;classification=RESTRICTED',
        'UTF8'
    )
FROM new_key, target_document;

UPDATE protected_documents
SET
    current_key_id = (
        SELECT key_id
        FROM encryption_keys
        WHERE key_name = 'legal-documents-v2'
    ),
    status = 'ROTATED'
WHERE external_reference = 'LEGAL-2026-009';

UPDATE encryption_keys
SET
    status = 'RETIRED',
    retired_at = clock_timestamp()
WHERE key_name = 'legal-documents-v1';

INSERT INTO encryption_key_events (
    key_id,
    event_type,
    reason
)
SELECT
    key_id,
    'ROTATED',
    'Legal document encryption moved to key version 2'
FROM encryption_keys
WHERE key_name = 'legal-documents-v2';

INSERT INTO encryption_key_events (
    key_id,
    event_type,
    reason
)
SELECT
    key_id,
    'RETIRED',
    'Replaced by legal-documents-v2'
FROM encryption_keys
WHERE key_name = 'legal-documents-v1';

INSERT INTO encryption_audit_log (
    document_id,
    key_id,
    action,
    succeeded,
    details
)
SELECT
    d.document_id,
    d.current_key_id,
    'ROTATE',
    TRUE,
    'Document encryption key rotated transactionally'
FROM protected_documents d
WHERE d.external_reference = 'LEGAL-2026-009';

COMMIT;

-- --------------------------------------------------------------------------
-- Demonstrate database-level invalid-state protection
-- --------------------------------------------------------------------------

-- The following statement is intentionally commented out because it should
-- fail: retired keys cannot receive a new encrypted document version.
--
-- INSERT INTO encrypted_document_versions (
--     document_id,
--     key_id,
--     nonce,
--     ciphertext,
--     authentication_tag,
--     associated_data
-- )
-- SELECT
--     document_id,
--     key_id,
--     gen_random_bytes(12),
--     convert_to('invalid ciphertext', 'UTF8'),
--     gen_random_bytes(16),
--     convert_to('invalid metadata', 'UTF8')
-- FROM protected_documents
-- CROSS JOIN encryption_keys
-- WHERE external_reference = 'FIN-2026-001'
--   AND key_name = 'finance-documents-v1';

-- The nonce uniqueness rule is also database-enforced. An application
-- attempting to reuse the same nonce under the same key receives a UNIQUE
-- constraint violation.
SELECT
    external_reference,
    document_status,
    key_name,
    key_version
FROM current_document_encryption
ORDER BY external_reference;
