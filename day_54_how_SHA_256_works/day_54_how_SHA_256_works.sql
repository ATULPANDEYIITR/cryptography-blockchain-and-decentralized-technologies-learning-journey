-- PostgreSQL SHA-256 learning and verification model.
--
-- Requirements:
--   - PostgreSQL
--   - pgcrypto extension
--
-- The database models SHA-256 as a content-integrity workflow:
-- messages -> canonical byte representation -> SHA-256 digest
--          -> verification -> avalanche comparison -> audit reporting
--
-- pgcrypto provides the production SHA-256 primitive. PostgreSQL does not
-- expose a practical pure-SQL implementation of all 64 SHA-256 rounds as
-- a standard built-in function, so the database focuses on correct storage,
-- validation, verification, indexing, and operational use of the digest.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP SCHEMA IF EXISTS sha256_lab CASCADE;
CREATE SCHEMA sha256_lab;

SET search_path TO sha256_lab, public;

CREATE TYPE digest_algorithm AS ENUM ('SHA-256');

CREATE TYPE verification_status AS ENUM (
    'verified',
    'mismatch',
    'not_checked'
);

CREATE TABLE hash_messages (
    message_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    label TEXT NOT NULL,
    message_text TEXT NOT NULL,
    message_bytes BYTEA NOT NULL,
    algorithm digest_algorithm NOT NULL DEFAULT 'SHA-256',
    digest BYTEA NOT NULL,
    digest_hex TEXT GENERATED ALWAYS AS (encode(digest, 'hex')) STORED,
    byte_length INTEGER GENERATED ALWAYS AS (octet_length(message_bytes)) STORED,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT hash_messages_label_ck
        CHECK (length(btrim(label)) > 0),

    CONSTRAINT hash_messages_digest_length_ck
        CHECK (octet_length(digest) = 32),

    CONSTRAINT hash_messages_encoding_ck
        CHECK (message_bytes = convert_to(message_text, 'UTF8'))
);

CREATE UNIQUE INDEX hash_messages_digest_idx
    ON hash_messages (digest);

CREATE INDEX hash_messages_algorithm_created_idx
    ON hash_messages (algorithm, created_at DESC);

CREATE TABLE verification_runs (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES hash_messages(message_id)
        ON DELETE CASCADE,
    supplied_digest BYTEA,
    status verification_status NOT NULL DEFAULT 'not_checked',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    details TEXT,

    CONSTRAINT verification_supplied_digest_length_ck
        CHECK (
            supplied_digest IS NULL
            OR octet_length(supplied_digest) = 32
        )
);

CREATE INDEX verification_runs_message_idx
    ON verification_runs (message_id, checked_at DESC);

CREATE TABLE avalanche_experiments (
    experiment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    original_message_id BIGINT NOT NULL
        REFERENCES hash_messages(message_id)
        ON DELETE CASCADE,
    modified_message TEXT NOT NULL,
    original_digest BYTEA NOT NULL,
    modified_digest BYTEA NOT NULL,
    differing_bits INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT avalanche_original_digest_ck
        CHECK (octet_length(original_digest) = 32),

    CONSTRAINT avalanche_modified_digest_ck
        CHECK (octet_length(modified_digest) = 32),

    CONSTRAINT avalanche_bit_count_ck
        CHECK (differing_bits BETWEEN 0 AND 256)
);

CREATE OR REPLACE FUNCTION calculate_sha256(input_text TEXT)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT digest(convert_to(input_text, 'UTF8'), 'sha256')
$$;

CREATE OR REPLACE FUNCTION calculate_sha256_hex(input_text TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT encode(calculate_sha256(input_text), 'hex')
$$;

CREATE OR REPLACE FUNCTION verify_sha256(
    input_text TEXT,
    expected_hex TEXT
)
RETURNS verification_status
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    expected BYTEA;
    actual BYTEA;
BEGIN
    IF expected_hex !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION
            'SHA-256 hexadecimal digest must contain exactly 64 hexadecimal characters';
    END IF;

    expected := decode(expected_hex, 'hex');
    actual := calculate_sha256(input_text);

    IF actual = expected THEN
        RETURN 'verified';
    END IF;

    RETURN 'mismatch';
END;
$$;

-- Insert known-answer vectors and realistic content-integrity records.
INSERT INTO hash_messages (
    label,
    message_text,
    message_bytes,
    digest
)
VALUES
(
    'empty-string',
    '',
    convert_to('', 'UTF8'),
    digest(convert_to('', 'UTF8'), 'sha256')
),
(
    'abc',
    'abc',
    convert_to('abc', 'UTF8'),
    digest(convert_to('abc', 'UTF8'), 'sha256')
),
(
    'quick-brown-fox',
    'The quick brown fox jumps over the lazy dog',
    convert_to(
        'The quick brown fox jumps over the lazy dog',
        'UTF8'
    ),
    digest(
        convert_to(
            'The quick brown fox jumps over the lazy dog',
            'UTF8'
        ),
        'sha256'
    )
),
(
    'unicode-content',
    'SHA-256 protects integrity of UTF-8 byte sequences.',
    convert_to(
        'SHA-256 protects integrity of UTF-8 byte sequences.',
        'UTF8'
    ),
    digest(
        convert_to(
            'SHA-256 protects integrity of UTF-8 byte sequences.',
            'UTF8'
        ),
        'sha256'
    )
);

-- Known-answer validation.
DO $$
DECLARE
    actual TEXT;
    expected TEXT :=
        'ba7816bf8f01cfea414140de5dae2223'
        'b00361a396177a9cb410ff61f20015ad';
BEGIN
    actual := calculate_sha256_hex('abc');

    IF actual <> expected THEN
        RAISE EXCEPTION
            'Known-answer test failed: expected %, got %',
            expected,
            actual;
    END IF;
END;
$$;

-- Populate verification records.
INSERT INTO verification_runs (
    message_id,
    supplied_digest,
    status,
    details
)
SELECT
    message_id,
    digest,
    verify_sha256(message_text, digest_hex),
    'Recomputed SHA-256 and compared with stored digest.'
FROM hash_messages;

-- Deliberately create a failed verification.
INSERT INTO verification_runs (
    message_id,
    supplied_digest,
    status,
    details
)
SELECT
    message_id,
    decode(
        repeat('00', 32),
        'hex'
    ),
    verify_sha256(
        message_text,
        repeat('0', 64)
    ),
    'Intentional mismatch used to demonstrate failure handling.'
FROM hash_messages
WHERE label = 'abc';

-- A trigger prevents accidental insertion of an incorrect digest.
CREATE OR REPLACE FUNCTION enforce_sha256_digest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.algorithm <> 'SHA-256' THEN
        RAISE EXCEPTION
            'This table currently supports SHA-256 only';
    END IF;

    IF NEW.digest <> calculate_sha256(NEW.message_text) THEN
        RAISE EXCEPTION
            'Digest does not match message_text for label %',
            NEW.label;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER hash_messages_integrity_trg
BEFORE INSERT OR UPDATE OF message_text, message_bytes, digest, algorithm
ON hash_messages
FOR EACH ROW
EXECUTE FUNCTION enforce_sha256_digest();

-- Demonstrate a valid transactional insertion.
BEGIN;

INSERT INTO hash_messages (
    label,
    message_text,
    message_bytes,
    digest
)
VALUES (
    'transactional-record',
    'This row is committed atomically.',
    convert_to('This row is committed atomically.', 'UTF8'),
    calculate_sha256('This row is committed atomically.')
);

COMMIT;

-- Hamming distance between two 256-bit digests.
-- PostgreSQL bit strings make the bit-level comparison explicit.
CREATE OR REPLACE FUNCTION sha256_hamming_distance(
    first_digest BYTEA,
    second_digest BYTEA
)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT sum(
        length(
            replace(
                ((get_byte(first_digest, i)
                  # get_byte(second_digest, i))::bit(8))::text,
                '0',
                ''
            )
        )
    )::INTEGER
    FROM generate_series(0, 31) AS positions(i)
$$;

-- Generate an avalanche experiment by changing one byte of "security".
WITH original AS (
    SELECT
        'security'::TEXT AS message_text,
        calculate_sha256('security') AS digest
),
modified AS (
    SELECT
        'r' || substring(message_text FROM 2) AS message_text
    FROM original
)
INSERT INTO avalanche_experiments (
    original_message_id,
    modified_message,
    original_digest,
    modified_digest,
    differing_bits
)
SELECT
    hm.message_id,
    modified.message_text,
    original.digest,
    calculate_sha256(modified.message_text),
    sha256_hamming_distance(
        original.digest,
        calculate_sha256(modified.message_text)
    )
FROM original
CROSS JOIN modified
JOIN hash_messages hm
    ON hm.message_text = original.message_text
LIMIT 1;

-- Query 1: digest inventory.
SELECT
    message_id,
    label,
    byte_length,
    algorithm,
    digest_hex,
    created_at
FROM hash_messages
ORDER BY message_id;

-- Query 2: integrity verification results.
SELECT
    vr.verification_id,
    hm.label,
    vr.status,
    vr.details,
    vr.checked_at
FROM verification_runs vr
JOIN hash_messages hm
    ON hm.message_id = vr.message_id
ORDER BY vr.checked_at;

-- Query 3: identify failures.
SELECT
    hm.label,
    vr.status,
    encode(vr.supplied_digest, 'hex') AS supplied_digest,
    hm.digest_hex AS expected_digest
FROM verification_runs vr
JOIN hash_messages hm
    ON hm.message_id = vr.message_id
WHERE vr.status = 'mismatch';

-- Query 4: avalanche effect.
SELECT
    hm.label AS original_message,
    ae.modified_message,
    ae.differing_bits,
    round(ae.differing_bits * 100.0 / 256, 2)
        AS differing_percentage
FROM avalanche_experiments ae
JOIN hash_messages hm
    ON hm.message_id = ae.original_message_id;

-- Query 5: aggregate verification health.
SELECT
    status,
    count(*) AS verification_count
FROM verification_runs
GROUP BY status
ORDER BY status;

-- Query 6: content-addressed lookup.
SELECT
    message_id,
    label,
    message_text
FROM hash_messages
WHERE digest = calculate_sha256(
    'The quick brown fox jumps over the lazy dog'
);

-- Demonstrate a rejected incorrect digest without leaving the transaction dirty.
DO $$
BEGIN
    BEGIN
        INSERT INTO hash_messages (
            label,
            message_text,
            message_bytes,
            digest
        )
        VALUES (
            'invalid-record',
            'This digest is intentionally incorrect.',
            convert_to(
                'This digest is intentionally incorrect.',
                'UTF8'
            ),
            decode(repeat('00', 32), 'hex')
        );
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Expected integrity rejection: %', SQLERRM;
    END;
END;
$$;

-- Design notes:
--
-- 1. BYTEA stores the raw 32-byte digest rather than wasting storage on
--    the 64-character hexadecimal representation.
-- 2. digest_hex is generated for readable reporting and interoperability.
-- 3. The unique digest index supports content-addressed lookups.
-- 4. The trigger prevents application-layer mistakes from becoming
--    persistent integrity violations.
-- 5. convert_to(..., 'UTF8') makes the hashed byte representation explicit.
-- 6. SHA-256 verifies integrity but does not authenticate an untrusted
--    sender. Authentication requires a MAC or digital signature.
-- 7. Raw SHA-256 is not a password-storage construction because it is
--    intentionally fast and therefore suitable for high-rate guessing.

COMMIT;
