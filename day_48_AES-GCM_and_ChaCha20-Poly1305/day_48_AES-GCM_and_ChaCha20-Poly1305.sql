-- AES-GCM and ChaCha20-Poly1305
-- PostgreSQL relational model for an enterprise AEAD envelope service.
--
-- PostgreSQL stores AEAD metadata and binary ciphertext. The actual AES-GCM
-- or ChaCha20-Poly1305 operation is intentionally performed by an application
-- cryptographic library rather than by handwritten SQL cryptography.
--
-- The database is responsible for:
--   * algorithm and key-version metadata
--   * nonce/tag/ciphertext storage
--   * tenant and record relationships
--   * uniqueness constraints
--   * key lifecycle state
--   * immutable encrypted-record metadata
--   * auditability
--   * queries needed by encryption/decryption services
--
-- The schema uses bytea for binary cryptographic material and PostgreSQL
-- enums for controlled algorithm and lifecycle values.

DROP SCHEMA IF EXISTS aead_demo CASCADE;
CREATE SCHEMA aead_demo;

SET search_path = aead_demo, public;

CREATE TYPE aead_algorithm AS ENUM (
    'AES-256-GCM',
    'ChaCha20-Poly1305'
);

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'RETIRING',
    'RETIRED',
    'COMPROMISED'
);

CREATE TYPE record_status AS ENUM (
    'ENCRYPTED',
    'DECRYPTED',
    'REJECTED'
);

CREATE TABLE tenants (
    tenant_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_code TEXT NOT NULL UNIQUE,
    tenant_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT tenants_code_format
        CHECK (tenant_code ~ '^[a-z0-9][a-z0-9_-]{2,63}$')
);

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id BIGINT NOT NULL
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE,
    repository_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT repository_environment_check
        CHECK (environment IN ('development', 'staging', 'production')),

    CONSTRAINT repository_name_nonempty
        CHECK (length(trim(repository_name)) > 0),

    UNIQUE (tenant_id, repository_name, environment)
);

CREATE TABLE encryption_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id BIGINT NOT NULL
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE,
    key_version INTEGER NOT NULL,
    algorithm aead_algorithm NOT NULL,
    key_status key_status NOT NULL DEFAULT 'ACTIVE',

    /*
     * The key material itself is deliberately not stored in plaintext here.
     * key_reference identifies an external KMS/HSM-managed key version.
     */
    key_reference TEXT NOT NULL,

    activated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ,

    UNIQUE (tenant_id, key_version),

    CONSTRAINT key_version_positive
        CHECK (key_version > 0),

    CONSTRAINT key_reference_nonempty
        CHECK (length(trim(key_reference)) > 0),

    CONSTRAINT retired_key_has_timestamp
        CHECK (
            key_status NOT IN ('RETIRED', 'COMPROMISED')
            OR retired_at IS NOT NULL
        )
);

CREATE TABLE encrypted_records (
    record_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,

    key_id BIGINT NOT NULL
        REFERENCES encryption_keys(key_id),

    algorithm aead_algorithm NOT NULL,

    /*
     * AES-GCM and ChaCha20-Poly1305 normally use a 96-bit nonce.
     * This schema enforces that deployment profile explicitly.
     */
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    authentication_tag BYTEA NOT NULL,
    associated_data BYTEA NOT NULL DEFAULT ''::bytea,

    plaintext_length BIGINT NOT NULL,
    status record_status NOT NULL DEFAULT 'ENCRYPTED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    authenticated_at TIMESTAMPTZ,

    CONSTRAINT nonce_96_bit
        CHECK (octet_length(nonce) = 12),

    CONSTRAINT authentication_tag_128_bit
        CHECK (octet_length(authentication_tag) = 16),

    CONSTRAINT plaintext_length_nonnegative
        CHECK (plaintext_length >= 0),

    CONSTRAINT algorithm_matches_key
        CHECK (algorithm IS NOT NULL)
);

CREATE TABLE encryption_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    record_id BIGINT NOT NULL
        REFERENCES encrypted_records(record_id)
        ON DELETE CASCADE,

    event_type TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor TEXT NOT NULL,
    detail TEXT,

    CONSTRAINT event_type_allowed
        CHECK (
            event_type IN (
                'ENCRYPTED',
                'DECRYPTED',
                'AUTHENTICATION_FAILED',
                'KEY_ROTATION',
                'REJECTED'
            )
        )
);

CREATE INDEX idx_repositories_tenant
    ON repositories (tenant_id);

CREATE INDEX idx_encryption_keys_tenant_status
    ON encryption_keys (tenant_id, key_status);

CREATE INDEX idx_encrypted_records_repository_created
    ON encrypted_records (repository_id, created_at DESC);

CREATE INDEX idx_encrypted_records_key
    ON encrypted_records (key_id);

CREATE INDEX idx_encryption_events_record_time
    ON encryption_events (record_id, event_time DESC);

INSERT INTO tenants (tenant_code, tenant_name)
VALUES
    ('acme-finance', 'Acme Finance'),
    ('acme-research', 'Acme Research');

INSERT INTO repositories (
    tenant_id,
    repository_name,
    environment
)
SELECT
    tenant_id,
    'settlement-api',
    'production'
FROM tenants
WHERE tenant_code = 'acme-finance';

INSERT INTO repositories (
    tenant_id,
    repository_name,
    environment
)
SELECT
    tenant_id,
    'quant-research',
    'staging'
FROM tenants
WHERE tenant_code = 'acme-research';

INSERT INTO encryption_keys (
    tenant_id,
    key_version,
    algorithm,
    key_status,
    key_reference
)
SELECT
    tenant_id,
    17,
    'AES-256-GCM',
    'RETIRED',
    'kms://acme-finance/aead/key-17'
FROM tenants
WHERE tenant_code = 'acme-finance';

INSERT INTO encryption_keys (
    tenant_id,
    key_version,
    algorithm,
    key_status,
    key_reference
)
SELECT
    tenant_id,
    18,
    'AES-256-GCM',
    'ACTIVE',
    'kms://acme-finance/aead/key-18'
FROM tenants
WHERE tenant_code = 'acme-finance';

INSERT INTO encryption_keys (
    tenant_id,
    key_version,
    algorithm,
    key_status,
    key_reference
)
SELECT
    tenant_id,
    4,
    'ChaCha20-Poly1305',
    'ACTIVE',
    'kms://acme-research/aead/key-4'
FROM tenants
WHERE tenant_code = 'acme-research';

-- These binary values are demonstration envelopes, not production secrets.
INSERT INTO encrypted_records (
    repository_id,
    key_id,
    algorithm,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data,
    plaintext_length
)
SELECT
    r.repository_id,
    k.key_id,
    k.algorithm,
    decode('00112233445566778899aabb', 'hex'),
    decode('aabbccddeeff00112233445566778899', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to(
        'tenant=acme-finance;environment=production;record=manifest',
        'UTF8'
    ),
    16
FROM repositories r
JOIN encryption_keys k
    ON k.tenant_id = (
        SELECT tenant_id
        FROM tenants
        WHERE tenant_code = 'acme-finance'
    )
WHERE r.repository_name = 'settlement-api'
  AND r.environment = 'production'
  AND k.key_version = 18;

INSERT INTO encrypted_records (
    repository_id,
    key_id,
    algorithm,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data,
    plaintext_length
)
SELECT
    r.repository_id,
    k.key_id,
    k.algorithm,
    decode('102132435465768798a9bacb', 'hex'),
    decode('11223344556677889900aabbccddeeff', 'hex'),
    decode('ffeeddccbbaa00998877665544332211', 'hex'),
    convert_to(
        'tenant=acme-research;environment=staging;record=experiment',
        'UTF8'
    ),
    16
FROM repositories r
JOIN encryption_keys k
    ON k.tenant_id = (
        SELECT tenant_id
        FROM tenants
        WHERE tenant_code = 'acme-research'
    )
WHERE r.repository_name = 'quant-research'
  AND r.environment = 'staging'
  AND k.key_version = 4;

INSERT INTO encryption_events (
    record_id,
    event_type,
    actor,
    detail
)
SELECT
    record_id,
    'ENCRYPTED',
    'artifact-service',
    'AEAD envelope created with the active key version'
FROM encrypted_records;

-- Query the current cryptographic inventory.
SELECT
    t.tenant_code,
    k.key_version,
    k.algorithm,
    k.key_status,
    k.key_reference
FROM encryption_keys k
JOIN tenants t
    ON t.tenant_id = k.tenant_id
ORDER BY t.tenant_code, k.key_version;

-- Find records using keys that are no longer active.
SELECT
    er.record_id,
    t.tenant_code,
    er.algorithm,
    k.key_version,
    k.key_status
FROM encrypted_records er
JOIN encryption_keys k
    ON k.key_id = er.key_id
JOIN repositories r
    ON r.repository_id = er.repository_id
JOIN tenants t
    ON t.tenant_id = r.tenant_id
WHERE k.key_status <> 'ACTIVE'
ORDER BY er.record_id;

-- Measure ciphertext volume without exposing plaintext.
SELECT
    t.tenant_code,
    er.algorithm,
    count(*) AS record_count,
    sum(octet_length(er.ciphertext)) AS ciphertext_bytes,
    avg(er.plaintext_length) AS average_plaintext_bytes
FROM encrypted_records er
JOIN repositories r
    ON r.repository_id = er.repository_id
JOIN tenants t
    ON t.tenant_id = r.tenant_id
GROUP BY t.tenant_code, er.algorithm
ORDER BY t.tenant_code, er.algorithm;

-- The application must reject an envelope if its metadata says one algorithm
-- while the referenced key belongs to another algorithm. This query exposes
-- such a state for monitoring.
SELECT
    er.record_id,
    er.algorithm AS record_algorithm,
    k.algorithm AS key_algorithm
FROM encrypted_records er
JOIN encryption_keys k
    ON k.key_id = er.key_id
WHERE er.algorithm <> k.algorithm;

-- A partial unique index ensures that one tenant cannot have two active key
-- versions for the same algorithm. This is a database-level lifecycle rule.
CREATE UNIQUE INDEX uq_one_active_key_per_algorithm
    ON encryption_keys (tenant_id, algorithm)
    WHERE key_status = 'ACTIVE';

-- Key rotation occurs transactionally: the old key becomes retiring and the
-- replacement becomes active. Existing ciphertext remains decryptable with
-- its recorded key version until explicit re-encryption is completed.
BEGIN;

UPDATE encryption_keys
SET
    key_status = 'RETIRING'
WHERE key_version = 18
  AND tenant_id = (
      SELECT tenant_id
      FROM tenants
      WHERE tenant_code = 'acme-finance'
  )
  AND algorithm = 'AES-256-GCM';

INSERT INTO encryption_keys (
    tenant_id,
    key_version,
    algorithm,
    key_status,
    key_reference
)
SELECT
    tenant_id,
    19,
    'AES-256-GCM',
    'ACTIVE',
    'kms://acme-finance/aead/key-19'
FROM tenants
WHERE tenant_code = 'acme-finance';

COMMIT;

-- Authentication failures are kept separate from successful decryption so
-- monitoring can identify repeated tampering or key-management failures.
INSERT INTO encryption_events (
    record_id,
    event_type,
    actor,
    detail
)
SELECT
    record_id,
    'AUTHENTICATION_FAILED',
    'security-monitor',
    'Demonstration event for an invalid authentication tag'
FROM encrypted_records
ORDER BY record_id
LIMIT 1;

SELECT
    er.record_id,
    ee.event_type,
    ee.event_time,
    ee.actor,
    ee.detail
FROM encryption_events ee
JOIN encrypted_records er
    ON er.record_id = ee.record_id
ORDER BY ee.event_time DESC, ee.event_id DESC;

-- Application-level cryptographic validation checklist query.
-- A row returned here needs investigation before the record is trusted.
SELECT
    er.record_id,
    er.algorithm,
    octet_length(er.nonce) AS nonce_bytes,
    octet_length(er.authentication_tag) AS tag_bytes,
    er.plaintext_length,
    k.key_status,
    CASE
        WHEN octet_length(er.nonce) <> 12 THEN 'INVALID_NONCE'
        WHEN octet_length(er.authentication_tag) <> 16 THEN 'INVALID_TAG'
        WHEN er.algorithm <> k.algorithm THEN 'ALGORITHM_KEY_MISMATCH'
        WHEN k.key_status = 'COMPROMISED' THEN 'COMPROMISED_KEY'
        ELSE 'STRUCTURALLY_VALID'
    END AS validation_state
FROM encrypted_records er
JOIN encryption_keys k
    ON k.key_id = er.key_id
ORDER BY er.record_id;
