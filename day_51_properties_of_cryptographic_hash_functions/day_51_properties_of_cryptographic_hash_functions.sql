-- PostgreSQL model of cryptographic hash properties.
--
-- The database stores repository artifacts, digest algorithms, integrity
-- observations, hash-chain evidence, and digest-based audit records.
-- pgcrypto provides PostgreSQL's digest() implementation.
--
-- Run with a PostgreSQL role that can CREATE EXTENSION when pgcrypto
-- is not already installed.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS artifact_integrity_report;
DROP FUNCTION IF EXISTS verify_artifact_integrity();
DROP FUNCTION IF EXISTS set_hash_chain_digest();
DROP FUNCTION IF EXISTS prevent_hash_chain_mutation();

DROP TABLE IF EXISTS hash_chain_events CASCADE;
DROP TABLE IF EXISTS integrity_checks CASCADE;
DROP TABLE IF EXISTS repository_artifacts CASCADE;
DROP TABLE IF EXISTS hash_algorithms CASCADE;

CREATE TABLE hash_algorithms (
    algorithm_id smallserial PRIMARY KEY,
    algorithm_name text NOT NULL UNIQUE,
    digest_bits integer NOT NULL CHECK (digest_bits > 0),
    collision_security_bits integer NOT NULL CHECK (collision_security_bits > 0),
    approved boolean NOT NULL DEFAULT true
);

CREATE TABLE repository_artifacts (
    artifact_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_name text NOT NULL,
    branch_name text NOT NULL,
    commit_id text NOT NULL,
    content bytea NOT NULL,
    algorithm_id smallint NOT NULL
        REFERENCES hash_algorithms(algorithm_id),
    content_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT repository_artifact_commit_unique
        UNIQUE (repository_name, branch_name, commit_id),

    CONSTRAINT repository_name_not_blank
        CHECK (length(btrim(repository_name)) > 0),

    CONSTRAINT branch_name_not_blank
        CHECK (length(btrim(branch_name)) > 0),

    CONSTRAINT commit_id_not_blank
        CHECK (length(btrim(commit_id)) > 0)
);

CREATE INDEX repository_artifacts_repository_branch_idx
    ON repository_artifacts(repository_name, branch_name);

CREATE INDEX repository_artifacts_digest_idx
    ON repository_artifacts(algorithm_id, content_digest);

CREATE TABLE integrity_checks (
    check_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id bigint NOT NULL
        REFERENCES repository_artifacts(artifact_id)
        ON DELETE CASCADE,
    observed_digest bytea NOT NULL,
    matched boolean NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    failure_reason text,

    CONSTRAINT integrity_failure_reason_rule
        CHECK (
            (matched AND failure_reason IS NULL)
            OR
            (NOT matched AND failure_reason IS NOT NULL)
        )
);

CREATE INDEX integrity_checks_artifact_time_idx
    ON integrity_checks(artifact_id, checked_at DESC);

CREATE TABLE hash_chain_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sequence_no integer NOT NULL,
    event_type text NOT NULL,
    event_payload jsonb NOT NULL,
    previous_digest bytea NOT NULL,
    current_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT hash_chain_sequence_positive
        CHECK (sequence_no >= 0),

    CONSTRAINT hash_chain_event_type
        CHECK (event_type IN ('COMMIT', 'REVIEW', 'MERGE', 'RELEASE')),

    CONSTRAINT hash_chain_payload_object
        CHECK (jsonb_typeof(event_payload) = 'object'),

    CONSTRAINT hash_chain_sequence_unique
        UNIQUE (sequence_no)
);

INSERT INTO hash_algorithms
    (algorithm_name, digest_bits, collision_security_bits)
VALUES
    ('SHA-256', 256, 128),
    ('SHA3-256', 256, 128);

-- The trigger computes SHA-256 from canonical artifact fields.
CREATE OR REPLACE FUNCTION set_hash_chain_digest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    canonical text;
BEGIN
    canonical :=
        NEW.repository_name || E'\n' ||
        NEW.branch_name || E'\n' ||
        NEW.commit_id || E'\n' ||
        encode(NEW.content, 'hex');

    NEW.content_digest :=
        digest(convert_to(canonical, 'UTF8'), 'sha256');

    RETURN NEW;
END;
$$;

CREATE TRIGGER repository_artifact_digest_trigger
BEFORE INSERT OR UPDATE OF repository_name, branch_name, commit_id, content
ON repository_artifacts
FOR EACH ROW
EXECUTE FUNCTION set_hash_chain_digest();

-- Hash-chain rows represent append-only evidence.
-- Updating or deleting them would invalidate the chain's audit meaning.
CREATE OR REPLACE FUNCTION prevent_hash_chain_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'hash-chain evidence is append-only';
END;
$$;

CREATE TRIGGER hash_chain_immutable_trigger
BEFORE UPDATE OR DELETE
ON hash_chain_events
FOR EACH ROW
EXECUTE FUNCTION prevent_hash_chain_mutation();

-- Verify an artifact against a supplied digest.
CREATE OR REPLACE FUNCTION verify_artifact_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.matched AND NEW.failure_reason IS NOT NULL THEN
        RAISE EXCEPTION
            'matched integrity check cannot have a failure reason';
    END IF;

    IF NOT NEW.matched AND NEW.failure_reason IS NULL THEN
        RAISE EXCEPTION
            'failed integrity check requires a failure reason';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER integrity_check_validation_trigger
BEFORE INSERT OR UPDATE
ON integrity_checks
FOR EACH ROW
EXECUTE FUNCTION verify_artifact_integrity();

INSERT INTO repository_artifacts
    (repository_name, branch_name, commit_id, content, algorithm_id)
SELECT
    'payments-service',
    'main',
    '8f42',
    convert_to('release=2026.10.21;artifact=build-1842', 'UTF8'),
    algorithm_id
FROM hash_algorithms
WHERE algorithm_name = 'SHA-256';

INSERT INTO repository_artifacts
    (repository_name, branch_name, commit_id, content, algorithm_id)
SELECT
    'payments-service',
    'main',
    '19bc',
    convert_to('review=approved;tests=passing', 'UTF8'),
    algorithm_id
FROM hash_algorithms
WHERE algorithm_name = 'SHA-256';

INSERT INTO repository_artifacts
    (repository_name, branch_name, commit_id, content, algorithm_id)
SELECT
    'identity-service',
    'release',
    'a71e',
    convert_to('release=2026.10.21;artifact=build-52', 'UTF8'),
    algorithm_id
FROM hash_algorithms
WHERE algorithm_name = 'SHA3-256';

-- Successful integrity check.
INSERT INTO integrity_checks
    (artifact_id, observed_digest, matched, failure_reason)
SELECT
    artifact_id,
    content_digest,
    true,
    NULL
FROM repository_artifacts
WHERE commit_id = '8f42';

-- Failed integrity check represents a modified artifact.
INSERT INTO integrity_checks
    (artifact_id, observed_digest, matched, failure_reason)
SELECT
    artifact_id,
    digest(convert_to('tampered-content', 'UTF8'), 'sha256'),
    false,
    'observed digest does not match stored artifact digest'
FROM repository_artifacts
WHERE commit_id = '8f42';

-- Build an append-only evidence chain.
WITH first_event AS (
    SELECT
        0 AS sequence_no,
        'COMMIT'::text AS event_type,
        '{"commit":"8f42","branch":"main"}'::jsonb AS event_payload,
        decode(repeat('00', 32), 'hex') AS previous_digest
)
INSERT INTO hash_chain_events
    (sequence_no, event_type, event_payload, previous_digest, current_digest)
SELECT
    sequence_no,
    event_type,
    event_payload,
    previous_digest,
    digest(
        convert_to(
            sequence_no::text || '|' ||
            encode(previous_digest, 'hex') || '|' ||
            event_payload::text,
            'UTF8'
        ),
        'sha256'
    )
FROM first_event;

INSERT INTO hash_chain_events
    (sequence_no, event_type, event_payload, previous_digest, current_digest)
SELECT
    1,
    'REVIEW',
    '{"review":"approved","reviewer":"security-team"}'::jsonb,
    current_digest,
    digest(
        convert_to(
            '1|' ||
            encode(current_digest, 'hex') || '|' ||
            '{"review":"approved","reviewer":"security-team"}'::jsonb::text,
            'UTF8'
        ),
        'sha256'
    )
FROM hash_chain_events
WHERE sequence_no = 0;

INSERT INTO hash_chain_events
    (sequence_no, event_type, event_payload, previous_digest, current_digest)
SELECT
    2,
    'MERGE',
    '{"target":"main","strategy":"squash"}'::jsonb,
    current_digest,
    digest(
        convert_to(
            '2|' ||
            encode(current_digest, 'hex') || '|' ||
            '{"target":"main","strategy":"squash"}'::jsonb::text,
            'UTF8'
        ),
        'sha256'
    )
FROM hash_chain_events
WHERE sequence_no = 1;

CREATE OR REPLACE VIEW artifact_integrity_report AS
SELECT
    a.artifact_id,
    a.repository_name,
    a.branch_name,
    a.commit_id,
    h.algorithm_name,
    h.digest_bits,
    encode(a.content_digest, 'hex') AS expected_digest,
    count(c.check_id) AS checks_performed,
    count(*) FILTER (WHERE c.matched) AS successful_checks,
    count(*) FILTER (WHERE NOT c.matched) AS failed_checks,
    max(c.checked_at) AS last_checked_at
FROM repository_artifacts AS a
JOIN hash_algorithms AS h
    ON h.algorithm_id = a.algorithm_id
LEFT JOIN integrity_checks AS c
    ON c.artifact_id = a.artifact_id
GROUP BY
    a.artifact_id,
    a.repository_name,
    a.branch_name,
    a.commit_id,
    h.algorithm_name,
    h.digest_bits;

-- Retrieval and reporting.
SELECT
    repository_name,
    branch_name,
    commit_id,
    algorithm_name,
    digest_bits,
    expected_digest,
    checks_performed,
    successful_checks,
    failed_checks
FROM artifact_integrity_report
ORDER BY repository_name, commit_id;

-- Detect artifacts with at least one failed integrity check.
SELECT
    a.repository_name,
    a.branch_name,
    a.commit_id,
    c.failure_reason,
    c.checked_at
FROM repository_artifacts AS a
JOIN integrity_checks AS c
    ON c.artifact_id = a.artifact_id
WHERE NOT c.matched
ORDER BY c.checked_at DESC;

-- Validate the append-only chain using a recursive CTE.
WITH RECURSIVE chain AS (
    SELECT
        e.sequence_no,
        e.current_digest,
        true AS valid_link
    FROM hash_chain_events AS e
    WHERE e.sequence_no = 0

    UNION ALL

    SELECT
        next_event.sequence_no,
        next_event.current_digest,
        chain.valid_link
        AND next_event.previous_digest = chain.current_digest
    FROM chain
    JOIN hash_chain_events AS next_event
      ON next_event.sequence_no = chain.sequence_no + 1
)
SELECT
    sequence_no,
    valid_link
FROM chain
ORDER BY sequence_no;

-- Demonstrate digest size and birthday-bound collision reasoning.
SELECT
    algorithm_name,
    digest_bits,
    collision_security_bits,
    round(power(2::numeric, collision_security_bits), 0)
        AS approximate_work_for_generic_collision_search
FROM hash_algorithms
ORDER BY algorithm_name;

-- Transactional example: integrity evidence and artifact insertion are
-- committed together. An exception would roll both operations back.
SAVEPOINT before_audit_transaction;

INSERT INTO repository_artifacts
    (repository_name, branch_name, commit_id, content, algorithm_id)
SELECT
    'audit-service',
    'main',
    'f004',
    convert_to('audit-event=hash-verified', 'UTF8'),
    algorithm_id
FROM hash_algorithms
WHERE algorithm_name = 'SHA-256';

INSERT INTO integrity_checks
    (artifact_id, observed_digest, matched, failure_reason)
SELECT
    artifact_id,
    content_digest,
    true,
    NULL
FROM repository_artifacts
WHERE repository_name = 'audit-service'
  AND commit_id = 'f004';

RELEASE SAVEPOINT before_audit_transaction;

COMMIT;

-- Security note:
-- SHA-256 and SHA3-256 are general-purpose cryptographic hashes.
-- They do not encrypt data and do not authenticate an attacker-controlled
-- message. Passwords require password-specific KDFs such as Argon2id,
-- scrypt, or bcrypt. Authenticity requires HMAC or digital signatures.
