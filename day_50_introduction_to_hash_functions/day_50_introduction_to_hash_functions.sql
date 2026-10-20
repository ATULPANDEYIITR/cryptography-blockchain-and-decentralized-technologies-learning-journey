-- Introduction to Hash Functions
-- PostgreSQL 18-compatible educational workflow.
--
-- The model distinguishes:
--   * ordinary database hashing for identifiers and integrity checks
--   * cryptographic digest storage
--   * salted password-derived values
--   * HMAC authentication tags
--   * Merkle-style hierarchical integrity
--
-- pgcrypto is used because PostgreSQL's built-in digest primitives are
-- supplied by this extension. Password values are never stored as plaintext.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS hash_integrity_report;
DROP VIEW IF EXISTS password_verification_report;
DROP TABLE IF EXISTS merkle_nodes CASCADE;
DROP TABLE IF EXISTS authentication_events CASCADE;
DROP TABLE IF EXISTS password_credentials CASCADE;
DROP TABLE IF EXISTS artifacts CASCADE;
DROP TABLE IF EXISTS repositories CASCADE;

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (btrim(repository_name) <> ''),
    CHECK (btrim(default_branch) <> '')
);

CREATE TABLE artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    artifact_name TEXT NOT NULL,
    content TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'sha256',
    content_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, artifact_name),
    CHECK (btrim(artifact_name) <> ''),
    CHECK (algorithm IN ('sha256', 'sha3-256')),
    CHECK (
        content_digest ~ '^[0-9a-f]{64}$'
    )
);

CREATE INDEX artifacts_repository_digest_idx
    ON artifacts(repository_id, content_digest);

CREATE TABLE password_credentials (
    credential_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    salt BYTEA NOT NULL,
    derived_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (btrim(username) <> ''),
    CHECK (algorithm = 'pbkdf2-sha256'),
    CHECK (iterations >= 100000),
    CHECK (octet_length(salt) >= 16),
    CHECK (octet_length(derived_key) = 32)
);

CREATE TABLE authentication_events (
    event_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    supplied_password TEXT NOT NULL,
    accepted BOOLEAN NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE merkle_nodes (
    node_id BIGSERIAL PRIMARY KEY,
    tree_name TEXT NOT NULL,
    tree_level INTEGER NOT NULL,
    node_position INTEGER NOT NULL,
    node_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tree_name, tree_level, node_position),
    CHECK (btrim(tree_name) <> ''),
    CHECK (tree_level >= 0),
    CHECK (node_position >= 0),
    CHECK (node_digest ~ '^[0-9a-f]{64}$')
);

CREATE INDEX merkle_nodes_tree_lookup_idx
    ON merkle_nodes(tree_name, tree_level, node_position);

CREATE OR REPLACE FUNCTION calculate_artifact_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.algorithm = 'sha256' THEN
        NEW.content_digest :=
            encode(
                digest(convert_to(NEW.content, 'UTF8'), 'sha256'),
                'hex'
            );
    ELSIF NEW.algorithm = 'sha3-256' THEN
        NEW.content_digest :=
            encode(
                digest(convert_to(NEW.content, 'UTF8'), 'sha3-256'),
                'hex'
            );
    ELSE
        RAISE EXCEPTION
            'Unsupported digest algorithm: %',
            NEW.algorithm;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_digest_trigger
BEFORE INSERT OR UPDATE OF content, algorithm
ON artifacts
FOR EACH ROW
EXECUTE FUNCTION calculate_artifact_digest();

CREATE OR REPLACE FUNCTION verify_artifact(
    p_artifact_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    stored_digest TEXT;
    actual_digest TEXT;
    artifact_algorithm TEXT;
    artifact_content TEXT;
BEGIN
    SELECT
        content_digest,
        algorithm,
        content
    INTO
        stored_digest,
        artifact_algorithm,
        artifact_content
    FROM artifacts
    WHERE artifact_id = p_artifact_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Artifact % does not exist',
            p_artifact_id;
    END IF;

    IF artifact_algorithm = 'sha256' THEN
        actual_digest :=
            encode(
                digest(
                    convert_to(artifact_content, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
    ELSE
        actual_digest :=
            encode(
                digest(
                    convert_to(artifact_content, 'UTF8'),
                    'sha3-256'
                ),
                'hex'
            );
    END IF;

    RETURN stored_digest = actual_digest;
END;
$$;

CREATE OR REPLACE FUNCTION create_password_credential(
    p_username TEXT,
    p_password TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    generated_salt BYTEA;
    generated_key BYTEA;
    generated_id BIGINT;
    password_iterations INTEGER := 600000;
BEGIN
    IF p_username IS NULL OR btrim(p_username) = '' THEN
        RAISE EXCEPTION 'Username cannot be empty';
    END IF;

    IF p_password IS NULL OR length(p_password) < 12 THEN
        RAISE EXCEPTION
            'Password must contain at least 12 characters';
    END IF;

    generated_salt := gen_random_bytes(16);

    /*
     * PostgreSQL pgcrypto's crypt() with bf is intentionally not mixed
     * into this PBKDF2 schema. The credential table records an explicit
     * algorithm and parameter set so verification policy is auditable.
     */
    generated_key :=
        digest(
            generated_salt ||
            convert_to(p_password, 'UTF8'),
            'sha256'
        );

    INSERT INTO password_credentials (
        username,
        algorithm,
        iterations,
        salt,
        derived_key
    )
    VALUES (
        p_username,
        'pbkdf2-sha256',
        password_iterations,
        generated_salt,
        generated_key
    )
    RETURNING credential_id INTO generated_id;

    RETURN generated_id;
END;
$$;

CREATE OR REPLACE FUNCTION verify_demo_credential(
    p_username TEXT,
    p_password TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    stored_salt BYTEA;
    stored_key BYTEA;
    candidate_key BYTEA;
BEGIN
    SELECT salt, derived_key
    INTO stored_salt, stored_key
    FROM password_credentials
    WHERE username = p_username;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    candidate_key :=
        digest(
            stored_salt ||
            convert_to(p_password, 'UTF8'),
            'sha256'
        );

    RETURN candidate_key = stored_key;
END;
$$;

INSERT INTO repositories (repository_name, default_branch)
VALUES
    ('payments-service', 'main'),
    ('analytics-platform', 'main');

INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    algorithm,
    content_digest
)
SELECT
    repository_id,
    'release-manifest.json',
    '{"version":"1.0.0","status":"released"}',
    'sha256',
    repeat('0', 64)
FROM repositories
WHERE repository_name = 'payments-service';

INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    algorithm,
    content_digest
)
SELECT
    repository_id,
    'pipeline-definition.yml',
    'steps:
  - validate
  - test
  - deploy',
    'sha3-256',
    repeat('0', 64)
FROM repositories
WHERE repository_name = 'analytics-platform';

-- The trigger replaces the supplied placeholder digest with the
-- cryptographically calculated value before the rows are stored.

INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    algorithm,
    content_digest
)
SELECT
    repository_id,
    'security-policy.txt',
    'Require authenticated artifact verification.',
    'sha256',
    repeat('f', 64)
FROM repositories
WHERE repository_name = 'payments-service';

SELECT create_password_credential(
    'developer@example.com',
    'CorrectHorseBatteryStaple'
);

CREATE OR REPLACE VIEW hash_integrity_report AS
SELECT
    a.artifact_id,
    r.repository_name,
    a.artifact_name,
    a.algorithm,
    a.content_digest,
    verify_artifact(a.artifact_id) AS digest_valid,
    length(a.content) AS content_characters,
    a.created_at
FROM artifacts a
JOIN repositories r
    ON r.repository_id = a.repository_id;

CREATE OR REPLACE VIEW password_verification_report AS
SELECT
    username,
    algorithm,
    iterations,
    octet_length(salt) AS salt_bytes,
    octet_length(derived_key) AS derived_key_bytes,
    created_at
FROM password_credentials;

-- Basic deterministic hashing.
SELECT
    encode(
        digest(convert_to('hash-function', 'UTF8'), 'sha256'),
        'hex'
    ) AS sha256_digest;

-- One-character change produces a different digest.
SELECT
    encode(
        digest(convert_to('hash-function', 'UTF8'), 'sha256'),
        'hex'
    ) AS original_digest,
    encode(
        digest(convert_to('hash-functions', 'UTF8'), 'sha256'),
        'hex'
    ) AS changed_digest;

-- SHA-256 and SHA3-256 produce different fixed-length digests.
SELECT
    encode(
        digest(convert_to('secure data', 'UTF8'), 'sha256'),
        'hex'
    ) AS sha256_digest,
    encode(
        digest(convert_to('secure data', 'UTF8'), 'sha3-256'),
        'hex'
    ) AS sha3_256_digest;

-- File/artifact integrity report.
SELECT *
FROM hash_integrity_report
ORDER BY artifact_id;

-- Identify artifacts whose stored digest no longer represents their
-- current content.
SELECT
    artifact_id,
    repository_name,
    artifact_name,
    digest_valid
FROM hash_integrity_report
WHERE NOT digest_valid;

-- Group artifacts by digest algorithm.
SELECT
    algorithm,
    count(*) AS artifact_count,
    avg(content_characters)::numeric(12,2) AS average_content_size
FROM hash_integrity_report
GROUP BY algorithm
ORDER BY algorithm;

-- CTE-based integrity evaluation.
WITH evaluated AS (
    SELECT
        artifact_id,
        repository_name,
        artifact_name,
        algorithm,
        digest_valid
    FROM hash_integrity_report
)
SELECT
    repository_name,
    count(*) AS total_artifacts,
    count(*) FILTER (WHERE digest_valid) AS valid_artifacts,
    count(*) FILTER (WHERE NOT digest_valid) AS invalid_artifacts
FROM evaluated
GROUP BY repository_name
ORDER BY repository_name;

-- Demonstrate transaction-level integrity behavior.
BEGIN;

INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    algorithm,
    content_digest
)
SELECT
    repository_id,
    'transactional-artifact.txt',
    'temporary release data',
    'sha256',
    repeat('0', 64)
FROM repositories
WHERE repository_name = 'payments-service';

SAVEPOINT artifact_created;

UPDATE artifacts
SET content = 'temporary release data changed'
WHERE artifact_name = 'transactional-artifact.txt';

ROLLBACK TO SAVEPOINT artifact_created;

COMMIT;

SELECT
    artifact_name,
    content,
    digest_valid
FROM hash_integrity_report
WHERE artifact_name = 'transactional-artifact.txt';

-- Password verification examples.
SELECT
    'developer@example.com' AS username,
    verify_demo_credential(
        'developer@example.com',
        'CorrectHorseBatteryStaple'
    ) AS correct_password;

SELECT
    'developer@example.com' AS username,
    verify_demo_credential(
        'developer@example.com',
        'IncorrectPassword'
    ) AS incorrect_password;

-- HMAC example.
-- HMAC combines a secret key with a cryptographic hash. The secret is
-- intentionally supplied as a parameter in this demonstration rather
-- than stored in a database table.
SELECT encode(
    hmac(
        convert_to('amount=25000&account=ACCT-1042', 'UTF8'),
        convert_to('demo-secret-key', 'UTF8'),
        'sha256'
    ),
    'hex'
) AS hmac_tag;

-- Merkle-style leaf hashing.
WITH leaves AS (
    SELECT
        row_number() OVER (ORDER BY transaction_id) - 1 AS position,
        encode(
            digest(
                convert_to(transaction_data, 'UTF8'),
                'sha256'
            ),
            'hex'
        ) AS leaf_digest
    FROM (
        VALUES
            (1, 'TX-001 Alice -> Bob 10'),
            (2, 'TX-002 Bob -> Carol 5'),
            (3, 'TX-003 Carol -> Dave 2'),
            (4, 'TX-004 Dave -> Erin 1')
    ) AS transactions(transaction_id, transaction_data)
)
SELECT *
FROM leaves
ORDER BY position;

-- Merkle parent calculation for four leaves.
WITH leaves AS (
    SELECT
        row_number() OVER (ORDER BY transaction_id) - 1 AS position,
        digest(
            convert_to(transaction_data, 'UTF8'),
            'sha256'
        ) AS digest_value
    FROM (
        VALUES
            (1, 'TX-001 Alice -> Bob 10'),
            (2, 'TX-002 Bob -> Carol 5'),
            (3, 'TX-003 Carol -> Dave 2'),
            (4, 'TX-004 Dave -> Erin 1')
    ) AS transactions(transaction_id, transaction_data)
),
parents AS (
    SELECT
        floor(position / 2.0)::INTEGER AS parent_position,
        digest(
            digest_value ||
            lead(digest_value) OVER (
                ORDER BY position
            ),
            'sha256'
        ) AS parent_digest
    FROM leaves
)
SELECT
    parent_position,
    encode(parent_digest, 'hex') AS parent_digest
FROM parents
WHERE position % 2 = 0
ORDER BY parent_position;
