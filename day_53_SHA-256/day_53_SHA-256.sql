DROP SCHEMA IF EXISTS sha256_lab CASCADE;
CREATE SCHEMA sha256_lab;
SET search_path = sha256_lab;

-- SHA-256 produces a 256-bit digest, represented here as 64 lowercase
-- hexadecimal characters. PostgreSQL's pgcrypto provides digest() and
-- encode() for production-grade hashing rather than reimplementing SHA-256
-- inside SQL.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE artifact_state AS ENUM (
    'RECEIVED',
    'VERIFIED',
    'REJECTED'
);

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    owner_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    artifact_name TEXT NOT NULL,
    content BYTEA NOT NULL,
    expected_sha256 CHAR(64),
    actual_sha256 CHAR(64),
    state artifact_state NOT NULL DEFAULT 'RECEIVED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMPTZ,

    CONSTRAINT artifact_name_not_blank
        CHECK (length(btrim(artifact_name)) > 0),

    CONSTRAINT expected_sha256_format
        CHECK (
            expected_sha256 IS NULL
            OR expected_sha256 ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT actual_sha256_format
        CHECK (
            actual_sha256 IS NULL
            OR actual_sha256 ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT verification_timestamp_rule
        CHECK (
            (state = 'VERIFIED' AND verified_at IS NOT NULL)
            OR (state <> 'VERIFIED')
        ),

    CONSTRAINT unique_repository_artifact
        UNIQUE (repository_id, artifact_name)
);

CREATE TABLE verification_events (
    verification_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id)
        ON DELETE CASCADE,
    calculated_sha256 CHAR(64) NOT NULL,
    expected_sha256 CHAR(64),
    matched BOOLEAN NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT calculated_sha256_format
        CHECK (calculated_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT event_expected_sha256_format
        CHECK (
            expected_sha256 IS NULL
            OR expected_sha256 ~ '^[0-9a-f]{64}$'
        )
);

CREATE INDEX idx_artifacts_repository_state
    ON artifacts (repository_id, state);

CREATE INDEX idx_verification_events_artifact_time
    ON verification_events (artifact_id, checked_at DESC);

CREATE OR REPLACE FUNCTION calculate_artifact_sha256(
    p_content BYTEA
)
RETURNS CHAR(64)
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT encode(digest(p_content, 'sha256'), 'hex')::CHAR(64);
$$;

CREATE OR REPLACE FUNCTION verify_artifact(
    p_artifact_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_content BYTEA;
    v_expected CHAR(64);
    v_actual CHAR(64);
    v_match BOOLEAN;
BEGIN
    SELECT content, expected_sha256
    INTO v_content, v_expected
    FROM artifacts
    WHERE artifact_id = p_artifact_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Artifact % does not exist', p_artifact_id;
    END IF;

    v_actual := calculate_artifact_sha256(v_content);

    v_match :=
        v_expected IS NOT NULL
        AND v_actual = v_expected;

    INSERT INTO verification_events (
        artifact_id,
        calculated_sha256,
        expected_sha256,
        matched
    )
    VALUES (
        p_artifact_id,
        v_actual,
        v_expected,
        v_match
    );

    UPDATE artifacts
    SET actual_sha256 = v_actual,
        state = CASE
            WHEN v_match THEN 'VERIFIED'::artifact_state
            ELSE 'REJECTED'::artifact_state
        END,
        verified_at = CASE
            WHEN v_match THEN CURRENT_TIMESTAMP
            ELSE NULL
        END
    WHERE artifact_id = p_artifact_id;

    RETURN v_match;
END;
$$;

CREATE OR REPLACE VIEW artifact_integrity_report AS
SELECT
    a.artifact_id,
    r.repository_name,
    a.artifact_name,
    a.state,
    a.expected_sha256,
    a.actual_sha256,
    a.actual_sha256 = a.expected_sha256 AS digest_matches,
    a.created_at,
    a.verified_at
FROM artifacts a
JOIN repositories r
    ON r.repository_id = a.repository_id;

INSERT INTO repositories (repository_name, owner_name)
VALUES
    ('release-platform', 'platform-team'),
    ('research-artifacts', 'research-team');

-- Known SHA-256 value for "hello world".
INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    expected_sha256
)
VALUES (
    (SELECT repository_id
     FROM repositories
     WHERE repository_name = 'release-platform'),
    'release.txt',
    convert_to('hello world', 'UTF8'),
    'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
);

-- This expected digest intentionally belongs to different content and
-- demonstrates rejection after integrity verification.
INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    expected_sha256
)
VALUES (
    (SELECT repository_id
     FROM repositories
     WHERE repository_name = 'release-platform'),
    'tampered.txt',
    convert_to('modified artifact', 'UTF8'),
    'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
);

-- An artifact without a supplied reference digest cannot be verified
-- successfully, even though its actual digest can still be calculated.
INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content
)
VALUES (
    (SELECT repository_id
     FROM repositories
     WHERE repository_name = 'research-artifacts'),
    'unverified.bin',
    decode('00010203040506070809', 'hex')
);

BEGIN;

SELECT verify_artifact(
    (
        SELECT artifact_id
        FROM artifacts
        WHERE artifact_name = 'release.txt'
    )
);

SELECT verify_artifact(
    (
        SELECT artifact_id
        FROM artifacts
        WHERE artifact_name = 'tampered.txt'
    )
);

SELECT verify_artifact(
    (
        SELECT artifact_id
        FROM artifacts
        WHERE artifact_name = 'unverified.bin'
    )
);

COMMIT;

-- Retrieve current integrity state.
SELECT
    artifact_id,
    repository_name,
    artifact_name,
    state,
    expected_sha256,
    actual_sha256,
    digest_matches
FROM artifact_integrity_report
ORDER BY artifact_id;

-- Identify artifacts that were rejected or have never received a matching
-- expected digest.
SELECT
    repository_name,
    artifact_name,
    state,
    expected_sha256,
    actual_sha256
FROM artifact_integrity_report
WHERE state <> 'VERIFIED'
   OR digest_matches IS DISTINCT FROM TRUE
ORDER BY repository_name, artifact_name;

-- Aggregate verification outcomes by repository.
SELECT
    repository_name,
    COUNT(*) AS artifact_count,
    COUNT(*) FILTER (WHERE state = 'VERIFIED') AS verified_count,
    COUNT(*) FILTER (WHERE state = 'REJECTED') AS rejected_count,
    COUNT(*) FILTER (WHERE state = 'RECEIVED') AS received_count
FROM artifact_integrity_report
GROUP BY repository_name
ORDER BY repository_name;

-- Show the verification audit trail.
SELECT
    ve.verification_id,
    a.artifact_name,
    ve.calculated_sha256,
    ve.expected_sha256,
    ve.matched,
    ve.checked_at
FROM verification_events ve
JOIN artifacts a
    ON a.artifact_id = ve.artifact_id
ORDER BY ve.checked_at, ve.verification_id;

-- A CTE can isolate failed integrity checks for reporting pipelines.
WITH failed_integrity AS (
    SELECT
        artifact_id,
        repository_name,
        artifact_name,
        expected_sha256,
        actual_sha256
    FROM artifact_integrity_report
    WHERE digest_matches IS DISTINCT FROM TRUE
)
SELECT *
FROM failed_integrity
ORDER BY repository_name, artifact_name;

-- Demonstrate direct PostgreSQL SHA-256 calculation.
SELECT
    encode(
        digest(convert_to('abc', 'UTF8'), 'sha256'),
        'hex'
    ) AS sha256_of_abc;

-- Demonstrate transaction rollback for an intentionally invalid update.
BEGIN;

UPDATE artifacts
SET expected_sha256 = repeat('0', 63)
WHERE artifact_name = 'release.txt';

-- The CHECK constraint rejects the preceding statement.
-- The transaction remains available for rollback when executed interactively.
ROLLBACK;
