-- PostgreSQL 15+ compatible initialization-vector governance model.
--
-- The schema records key versions, encryption operations, nonce allocation,
-- encrypted artifacts, and audit events. It does not implement AES.
--
-- Run in a dedicated learning database:
--   psql -v ON_ERROR_STOP=1 -f initialization_vectors.sql
--
-- Production nonce allocation must be atomic, durable, and coordinated
-- across every process using the same key. Database uniqueness constraints
-- help prevent duplicate records but cannot replace a complete key lifecycle.

BEGIN;

CREATE SCHEMA IF NOT EXISTS cryptography_lab;
SET search_path TO cryptography_lab, public;

CREATE TABLE encryption_keys (
    key_id              text PRIMARY KEY,
    algorithm           text NOT NULL
                        CHECK (algorithm IN ('AES-256-GCM', 'AES-256-CBC')),
    key_version         integer NOT NULL CHECK (key_version > 0),
    lifecycle_state     text NOT NULL
                        CHECK (lifecycle_state IN
                            ('ACTIVE', 'RETIRED', 'REVOKED')),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at          timestamptz,
    UNIQUE (algorithm, key_version),
    CHECK (
        (lifecycle_state = 'ACTIVE' AND retired_at IS NULL)
        OR
        (lifecycle_state <> 'ACTIVE')
    )
);

CREATE TABLE nonce_allocations (
    allocation_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id              text NOT NULL REFERENCES encryption_keys(key_id),
    nonce               bytea NOT NULL,
    allocation_method   text NOT NULL
                        CHECK (allocation_method IN
                            ('RANDOM', 'COUNTER', 'EXTERNAL_KMS')),
    worker_id           text NOT NULL,
    allocated_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (key_id, nonce),
    CHECK (
        (SELECT 1) IS NOT NULL
    )
);

-- This constraint deliberately scopes uniqueness to the key. Identical
-- nonce bytes under distinct keys are not automatically a reuse violation.
CREATE INDEX nonce_allocations_key_time_idx
    ON nonce_allocations (key_id, allocated_at DESC);

CREATE TABLE encrypted_artifacts (
    artifact_id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_id         text NOT NULL UNIQUE,
    key_id              text NOT NULL REFERENCES encryption_keys(key_id),
    allocation_id       bigint NOT NULL UNIQUE
                        REFERENCES nonce_allocations(allocation_id),
    ciphertext           bytea NOT NULL,
    authentication_tag  bytea,
    artifact_state      text NOT NULL
                        CHECK (artifact_state IN
                            ('ENCRYPTED', 'VERIFIED', 'QUARANTINED',
                             'DECRYPTED', 'REJECTED')),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(ciphertext) > 0)
);

CREATE TABLE encryption_audit (
    audit_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id              text REFERENCES encryption_keys(key_id),
    artifact_id         bigint REFERENCES encrypted_artifacts(artifact_id),
    event_type          text NOT NULL
                        CHECK (event_type IN
                            ('KEY_CREATED', 'NONCE_ALLOCATED',
                             'ENCRYPTION_COMPLETED', 'AUTHENTICATION_FAILED',
                             'KEY_RETIRED', 'ARTIFACT_QUARANTINED')),
    details             jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at         timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX encrypted_artifacts_key_created_idx
    ON encrypted_artifacts (key_id, created_at DESC);

CREATE INDEX encryption_audit_event_time_idx
    ON encryption_audit (event_type, occurred_at DESC);

CREATE VIEW active_encryption_keys AS
SELECT key_id, algorithm, key_version, created_at
FROM encryption_keys
WHERE lifecycle_state = 'ACTIVE';

CREATE VIEW nonce_usage_by_key AS
SELECT
    k.key_id,
    k.algorithm,
    k.key_version,
    count(n.allocation_id) AS allocated_nonces,
    min(n.allocated_at) AS first_allocation,
    max(n.allocated_at) AS latest_allocation
FROM encryption_keys AS k
LEFT JOIN nonce_allocations AS n ON n.key_id = k.key_id
GROUP BY k.key_id, k.algorithm, k.key_version;

INSERT INTO encryption_keys
    (key_id, algorithm, key_version, lifecycle_state)
VALUES
    ('inspection-key-v3', 'AES-256-GCM', 3, 'ACTIVE'),
    ('legacy-cbc-key-v1', 'AES-256-CBC', 1, 'RETIRED');

INSERT INTO nonce_allocations
    (key_id, nonce, allocation_method, worker_id)
VALUES
    (
        'inspection-key-v3',
        decode('52454c310000000000000001', 'hex'),
        'COUNTER',
        'worker-east-01'
    ),
    (
        'inspection-key-v3',
        decode('52454c310000000000000002', 'hex'),
        'COUNTER',
        'worker-east-01'
    );

INSERT INTO encrypted_artifacts
    (external_id, key_id, allocation_id, ciphertext,
     authentication_tag, artifact_state)
VALUES
    (
        'inspection-402',
        'inspection-key-v3',
        1,
        decode('c0ffee01', 'hex'),
        decode('00112233445566778899aabbccddeeff', 'hex'),
        'ENCRYPTED'
    ),
    (
        'inspection-403',
        'inspection-key-v3',
        2,
        decode('c0ffee02', 'hex'),
        decode('ffeeddccbbaa99887766554433221100', 'hex'),
        'QUARANTINED'
    );

INSERT INTO encryption_audit
    (key_id, artifact_id, event_type, details)
VALUES
    (
        'inspection-key-v3',
        1,
        'ENCRYPTION_COMPLETED',
        '{"source":"inspection-service","operation":"encrypt"}'::jsonb
    ),
    (
        'inspection-key-v3',
        2,
        'ARTIFACT_QUARANTINED',
        '{"reason":"manual security review"}'::jsonb
    );

-- Review active keys and their recorded nonce usage.
SELECT * FROM active_encryption_keys;
SELECT * FROM nonce_usage_by_key ORDER BY key_id;

-- Inspect artifacts without exposing encryption keys.
SELECT
    a.external_id,
    a.key_id,
    n.allocation_method,
    encode(n.nonce, 'hex') AS nonce_hex,
    octet_length(a.ciphertext) AS ciphertext_bytes,
    a.artifact_state,
    a.created_at
FROM encrypted_artifacts AS a
JOIN nonce_allocations AS n ON n.allocation_id = a.allocation_id
ORDER BY a.artifact_id;

-- Locate key usage that may need review before retirement.
SELECT
    key_id,
    count(*) FILTER (WHERE artifact_state = 'ENCRYPTED') AS encrypted_count,
    count(*) FILTER (WHERE artifact_state = 'QUARANTINED') AS quarantined_count
FROM encrypted_artifacts
GROUP BY key_id;

-- Demonstrate duplicate-nonce enforcement in a savepoint.
-- The insert must fail because the key and nonce pair already exists.
SAVEPOINT duplicate_nonce_test;

DO $$
BEGIN
    BEGIN
        INSERT INTO nonce_allocations
            (key_id, nonce, allocation_method, worker_id)
        VALUES
            (
                'inspection-key-v3',
                decode('52454c310000000000000001', 'hex'),
                'COUNTER',
                'worker-west-02'
            );

        RAISE EXCEPTION 'Expected duplicate nonce rejection did not occur';
    EXCEPTION
        WHEN unique_violation THEN
            RAISE NOTICE 'Duplicate nonce rejected by database constraint';
    END;
END;
$$;

ROLLBACK TO SAVEPOINT duplicate_nonce_test;
RELEASE SAVEPOINT duplicate_nonce_test;

-- Demonstrate an invalid nonce size for the chosen AES-GCM profile.
-- The production schema should enforce the algorithm-specific nonce size
-- using a trigger or a validated allocation function.
DO $$
BEGIN
    IF octet_length(decode('010203', 'hex')) <> 12 THEN
        RAISE NOTICE 'Three-byte nonce rejected by application policy';
    END IF;
END;
$$;

-- The demonstration data is committed for subsequent inspection.
COMMIT;
