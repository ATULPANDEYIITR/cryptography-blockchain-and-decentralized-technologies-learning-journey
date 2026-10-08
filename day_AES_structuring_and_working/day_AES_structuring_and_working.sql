-- AES Structure and Working
-- PostgreSQL-compatible relational demonstration.
--
-- The database models an AES-oriented cryptographic processing service.
-- It records algorithm parameters, encryption operations, AES state snapshots,
-- key metadata, authenticated-encryption metadata, and validation results.
--
-- The schema deliberately distinguishes:
--   * AES algorithm structure: block size, key size, rounds, transformations
--   * encryption operations: a concrete request against a key
--   * round traces: the evolving AES state
--   * authenticated application usage: nonce, tag, and associated data
--
-- This script does not store plaintext or raw secret keys.

DROP SCHEMA IF EXISTS aes_lab CASCADE;
CREATE SCHEMA aes_lab;

SET search_path TO aes_lab;

CREATE TABLE aes_algorithm (
    algorithm_code      VARCHAR(20) PRIMARY KEY,
    block_size_bits     INTEGER NOT NULL,
    key_size_bits       INTEGER NOT NULL,
    round_count         INTEGER NOT NULL,
    final_round_has_mix_columns BOOLEAN NOT NULL,
    CONSTRAINT aes_block_size_ck CHECK (block_size_bits = 128),
    CONSTRAINT aes_key_size_ck CHECK (key_size_bits IN (128, 192, 256)),
    CONSTRAINT aes_round_count_ck CHECK (
        (key_size_bits = 128 AND round_count = 10)
        OR
        (key_size_bits = 192 AND round_count = 12)
        OR
        (key_size_bits = 256 AND round_count = 14)
    ),
    CONSTRAINT aes_final_round_ck CHECK (
        final_round_has_mix_columns = FALSE
    )
);

INSERT INTO aes_algorithm (
    algorithm_code,
    block_size_bits,
    key_size_bits,
    round_count,
    final_round_has_mix_columns
)
VALUES
    ('AES-128', 128, 128, 10, FALSE),
    ('AES-192', 128, 192, 12, FALSE),
    ('AES-256', 128, 256, 14, FALSE);

CREATE TABLE key_registry (
    key_id                  BIGSERIAL PRIMARY KEY,
    key_reference           VARCHAR(100) NOT NULL UNIQUE,
    algorithm_code          VARCHAR(20) NOT NULL REFERENCES aes_algorithm(algorithm_code),
    key_version             INTEGER NOT NULL,
    lifecycle_state         VARCHAR(20) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at              TIMESTAMPTZ,
    CONSTRAINT key_version_ck CHECK (key_version > 0),
    CONSTRAINT key_state_ck CHECK (
        lifecycle_state IN ('ACTIVE', 'ROTATING', 'RETIRED', 'REVOKED')
    ),
    CONSTRAINT retired_state_consistency_ck CHECK (
        (lifecycle_state IN ('RETIRED', 'REVOKED') AND retired_at IS NOT NULL)
        OR
        (lifecycle_state IN ('ACTIVE', 'ROTATING') AND retired_at IS NULL)
    )
);

INSERT INTO key_registry (
    key_reference,
    algorithm_code,
    key_version,
    lifecycle_state
)
VALUES
    ('vault://crypto/aes/operations', 'AES-256', 7, 'ACTIVE'),
    ('vault://crypto/aes/archive', 'AES-128', 3, 'ROTATING');

CREATE TABLE encryption_operation (
    operation_id            BIGSERIAL PRIMARY KEY,
    operation_reference     UUID NOT NULL DEFAULT gen_random_uuid(),
    key_id                  BIGINT NOT NULL REFERENCES key_registry(key_id),
    operation_type          VARCHAR(20) NOT NULL,
    status                  VARCHAR(30) NOT NULL,
    plaintext_length_bytes  INTEGER,
    ciphertext_length_bytes INTEGER,
    nonce                   BYTEA,
    authentication_tag      BYTEA,
    associated_data         BYTEA,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at            TIMESTAMPTZ,
    CONSTRAINT operation_type_ck CHECK (
        operation_type IN ('ENCRYPT', 'DECRYPT')
    ),
    CONSTRAINT operation_status_ck CHECK (
        status IN (
            'REQUESTED',
            'COMPLETED',
            'AUTHENTICATION_FAILED',
            'REJECTED'
        )
    ),
    CONSTRAINT plaintext_length_ck CHECK (
        plaintext_length_bytes IS NULL
        OR plaintext_length_bytes >= 0
    ),
    CONSTRAINT ciphertext_length_ck CHECK (
        ciphertext_length_bytes IS NULL
        OR ciphertext_length_bytes >= 0
    ),
    CONSTRAINT gcm_metadata_ck CHECK (
        (
            nonce IS NULL
            AND authentication_tag IS NULL
        )
        OR
        (
            octet_length(nonce) = 12
            AND octet_length(authentication_tag) = 16
        )
    ),
    CONSTRAINT completion_timestamp_ck CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL)
        OR
        (status <> 'COMPLETED')
    )
);

CREATE UNIQUE INDEX encryption_operation_reference_uq
    ON encryption_operation(operation_reference);

CREATE INDEX encryption_operation_key_status_idx
    ON encryption_operation(key_id, status, created_at DESC);

CREATE TABLE aes_round_trace (
    trace_id                BIGSERIAL PRIMARY KEY,
    operation_id            BIGINT NOT NULL REFERENCES encryption_operation(operation_id)
                            ON DELETE CASCADE,
    round_number            INTEGER NOT NULL,
    transformation          VARCHAR(30) NOT NULL,
    state_before            BYTEA,
    state_after             BYTEA NOT NULL,
    CONSTRAINT round_number_ck CHECK (round_number BETWEEN 0 AND 14),
    CONSTRAINT transformation_ck CHECK (
        transformation IN (
            'SUB_BYTES',
            'SHIFT_ROWS',
            'MIX_COLUMNS',
            'ADD_ROUND_KEY'
        )
    ),
    CONSTRAINT state_size_ck CHECK (
        octet_length(state_after) = 16
        AND (
            state_before IS NULL
            OR octet_length(state_before) = 16
        )
    ),
    UNIQUE (operation_id, round_number, transformation)
);

CREATE INDEX aes_round_trace_operation_round_idx
    ON aes_round_trace(operation_id, round_number);

CREATE TABLE validation_event (
    validation_id           BIGSERIAL PRIMARY KEY,
    operation_id            BIGINT REFERENCES encryption_operation(operation_id),
    rule_code               VARCHAR(60) NOT NULL,
    passed                   BOOLEAN NOT NULL,
    detail                  TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX validation_event_operation_idx
    ON validation_event(operation_id, passed);

-- A valid AES operation must reference an active or rotating key.
CREATE OR REPLACE FUNCTION validate_key_for_operation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_state VARCHAR(20);
BEGIN
    SELECT lifecycle_state
    INTO key_state
    FROM key_registry
    WHERE key_id = NEW.key_id;

    IF key_state IS NULL THEN
        RAISE EXCEPTION 'Referenced cryptographic key does not exist';
    END IF;

    IF key_state NOT IN ('ACTIVE', 'ROTATING') THEN
        RAISE EXCEPTION
            'Key % cannot process new encryption operations because it is %',
            NEW.key_id,
            key_state;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER encryption_operation_key_validation
BEFORE INSERT ON encryption_operation
FOR EACH ROW
EXECUTE FUNCTION validate_key_for_operation();

-- The following sample operation uses a fictional state trace.
-- The values are 16-byte AES states represented as binary data.
INSERT INTO encryption_operation (
    key_id,
    operation_type,
    status,
    plaintext_length_bytes,
    ciphertext_length_bytes,
    nonce,
    authentication_tag,
    associated_data,
    completed_at
)
SELECT
    key_id,
    'ENCRYPT',
    'COMPLETED',
    128,
    128,
    decode('00112233445566778899aabb', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to(
        'repository=secure-operations;classification=restricted',
        'UTF8'
    ),
    CURRENT_TIMESTAMP
FROM key_registry
WHERE key_reference = 'vault://crypto/aes/operations';

INSERT INTO validation_event (
    operation_id,
    rule_code,
    passed,
    detail
)
SELECT
    operation_id,
    'AES_BLOCK_SIZE',
    TRUE,
    'AES operates on a fixed 128-bit block.'
FROM encryption_operation
WHERE operation_type = 'ENCRYPT'
ORDER BY operation_id DESC
LIMIT 1;

INSERT INTO validation_event (
    operation_id,
    rule_code,
    passed,
    detail
)
SELECT
    operation_id,
    'GCM_NONCE_LENGTH',
    octet_length(nonce) = 12,
    'GCM application policy requires a 96-bit nonce.'
FROM encryption_operation
WHERE operation_type = 'ENCRYPT'
ORDER BY operation_id DESC
LIMIT 1;

INSERT INTO validation_event (
    operation_id,
    rule_code,
    passed,
    detail
)
SELECT
    operation_id,
    'GCM_TAG_LENGTH',
    octet_length(authentication_tag) = 16,
    'The application policy requires a 128-bit authentication tag.'
FROM encryption_operation
WHERE operation_type = 'ENCRYPT'
ORDER BY operation_id DESC
LIMIT 1;

-- Round 0 demonstrates the initial AddRoundKey transformation.
INSERT INTO aes_round_trace (
    operation_id,
    round_number,
    transformation,
    state_before,
    state_after
)
SELECT
    operation_id,
    0,
    'ADD_ROUND_KEY',
    decode('00112233445566778899aabbccddeeff', 'hex'),
    decode('00102030405060708090a0b0c0d0e0f0', 'hex')
FROM encryption_operation
WHERE operation_type = 'ENCRYPT'
ORDER BY operation_id DESC
LIMIT 1;

-- Round 1 records the four AES transformations.
WITH operation AS (
    SELECT operation_id
    FROM encryption_operation
    WHERE operation_type = 'ENCRYPT'
    ORDER BY operation_id DESC
    LIMIT 1
)
INSERT INTO aes_round_trace (
    operation_id,
    round_number,
    transformation,
    state_before,
    state_after
)
SELECT operation_id, 1, 'SUB_BYTES',
       decode('00102030405060708090a0b0c0d0e0f0', 'hex'),
       decode('63cab7040953d051cd60e0e7ba70e18c', 'hex')
FROM operation
UNION ALL
SELECT operation_id, 1, 'SHIFT_ROWS',
       decode('63cab7040953d051cd60e0e7ba70e18c', 'hex'),
       decode('6353e08c0960e104cd70b751bacad0e7', 'hex')
FROM operation
UNION ALL
SELECT operation_id, 1, 'MIX_COLUMNS',
       decode('6353e08c0960e104cd70b751bacad0e7', 'hex'),
       decode('5f72641557f5bc92f7be3b291db9f91a', 'hex')
FROM operation
UNION ALL
SELECT operation_id, 1, 'ADD_ROUND_KEY',
       decode('5f72641557f5bc92f7be3b291db9f91a', 'hex'),
       decode('89d810e8855ace682d1843d8cb128fe4', 'hex')
FROM operation;

-- A view exposes the relationship between an operation, its AES variant,
-- key lifecycle, and the number of recorded transformations.
CREATE VIEW encryption_operation_summary AS
SELECT
    eo.operation_id,
    eo.operation_reference,
    ar.algorithm_code,
    ar.block_size_bits,
    ar.key_size_bits,
    ar.round_count,
    kr.key_reference,
    kr.key_version,
    kr.lifecycle_state AS key_lifecycle,
    eo.operation_type,
    eo.status,
    eo.plaintext_length_bytes,
    eo.ciphertext_length_bytes,
    octet_length(eo.nonce) AS nonce_bytes,
    octet_length(eo.authentication_tag) AS authentication_tag_bytes,
    COUNT(rt.trace_id) AS recorded_transformations
FROM encryption_operation eo
JOIN key_registry kr
    ON kr.key_id = eo.key_id
JOIN aes_algorithm ar
    ON ar.algorithm_code = kr.algorithm_code
LEFT JOIN aes_round_trace rt
    ON rt.operation_id = eo.operation_id
GROUP BY
    eo.operation_id,
    eo.operation_reference,
    ar.algorithm_code,
    ar.block_size_bits,
    ar.key_size_bits,
    ar.round_count,
    kr.key_reference,
    kr.key_version,
    kr.lifecycle_state,
    eo.operation_type,
    eo.status,
    eo.plaintext_length_bytes,
    eo.ciphertext_length_bytes,
    eo.nonce,
    eo.authentication_tag;

-- Compare the structural parameters of all AES variants.
SELECT
    algorithm_code,
    block_size_bits,
    key_size_bits,
    round_count,
    final_round_has_mix_columns
FROM aes_algorithm
ORDER BY key_size_bits;

-- Inspect the encryption workflow and recorded AES transformations.
SELECT
    s.operation_id,
    s.algorithm_code,
    s.key_size_bits,
    s.round_count,
    s.status,
    s.nonce_bytes,
    s.authentication_tag_bytes,
    s.recorded_transformations
FROM encryption_operation_summary AS s
ORDER BY s.operation_id;

-- Show the transformation sequence for the latest encryption operation.
SELECT
    rt.round_number,
    rt.transformation,
    encode(rt.state_before, 'hex') AS state_before,
    encode(rt.state_after, 'hex') AS state_after
FROM aes_round_trace AS rt
JOIN (
    SELECT operation_id
    FROM encryption_operation
    WHERE operation_type = 'ENCRYPT'
    ORDER BY operation_id DESC
    LIMIT 1
) AS latest
    ON latest.operation_id = rt.operation_id
ORDER BY rt.round_number, rt.transformation;

-- Demonstrate database-level identification of an invalid GCM nonce.
SELECT
    operation_id,
    CASE
        WHEN nonce IS NULL THEN 'NO_NONCE'
        WHEN octet_length(nonce) <> 12 THEN 'INVALID_NONCE_LENGTH'
        ELSE 'VALID_NONCE_LENGTH'
    END AS nonce_validation
FROM encryption_operation;

-- Count successful and failed validation rules by operation.
SELECT
    operation_id,
    COUNT(*) FILTER (WHERE passed) AS passed_rules,
    COUNT(*) FILTER (WHERE NOT passed) AS failed_rules
FROM validation_event
GROUP BY operation_id
ORDER BY operation_id;

-- The following transaction demonstrates key governance:
-- a revoked key cannot be used for a new operation because the trigger
-- rejects the insert before it reaches the table.
BEGIN;

UPDATE key_registry
SET lifecycle_state = 'REVOKED',
    retired_at = CURRENT_TIMESTAMP
WHERE key_reference = 'vault://crypto/aes/archive';

-- This query intentionally exposes the resulting governance state.
SELECT
    key_reference,
    algorithm_code,
    key_version,
    lifecycle_state,
    retired_at
FROM key_registry
WHERE key_reference = 'vault://crypto/aes/archive';

COMMIT;

-- Production note:
-- Raw AES keys and plaintext should not be persisted in this audit model.
-- Key references should point to an appropriate key-management system.
-- AES-GCM nonce uniqueness must be enforced by the application/key lifecycle
-- design; a relational uniqueness constraint can help when every nonce is
-- recorded, but it cannot replace a sound cryptographic nonce strategy.
