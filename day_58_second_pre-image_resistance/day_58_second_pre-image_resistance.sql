-- Second-preimage resistance relational laboratory
-- PostgreSQL 14+ compatible.
--
-- The schema separates:
--   artifacts       = fixed messages being protected
--   hash_records    = digest evidence
--   candidates      = attempted alternative messages
--   attack_runs     = controlled search executions
--   security_policies = operational acceptance rules
--
-- The digest values are intentionally small hexadecimal values in sample
-- records so the database can represent an educational experiment.
-- Production applications should use a vetted cryptographic implementation
-- such as SHA-256/SHA-3 rather than database-side toy hashes.

DROP SCHEMA IF EXISTS second_preimage CASCADE;
CREATE SCHEMA second_preimage;

SET search_path = second_preimage, public;

CREATE TYPE artifact_state AS ENUM (
    'REGISTERED',
    'VERIFIED',
    'REJECTED',
    'QUARANTINED'
);

CREATE TYPE attack_state AS ENUM (
    'RUNNING',
    'FOUND',
    'NOT_FOUND',
    'FAILED'
);

CREATE TYPE security_decision AS ENUM (
    'ACCEPT',
    'REJECT',
    'REVIEW_REQUIRED'
);

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    owner_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id),
    artifact_name TEXT NOT NULL,
    content TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    digest_bits INTEGER NOT NULL
        CHECK (digest_bits BETWEEN 1 AND 512),
    state artifact_state NOT NULL DEFAULT 'REGISTERED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, artifact_name)
);

CREATE TABLE hash_records (
    hash_record_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    digest_hex TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (artifact_id, digest_hex)
);

CREATE TABLE attack_runs (
    attack_run_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    digest_bits INTEGER NOT NULL
        CHECK (digest_bits BETWEEN 1 AND 512),
    maximum_attempts BIGINT NOT NULL
        CHECK (maximum_attempts > 0),
    attempts BIGINT NOT NULL DEFAULT 0
        CHECK (attempts >= 0),
    state attack_state NOT NULL DEFAULT 'RUNNING',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    failure_reason TEXT,
    CHECK (
        (state = 'RUNNING' AND completed_at IS NULL)
        OR
        (state <> 'RUNNING' AND completed_at IS NOT NULL)
    )
);

CREATE TABLE candidates (
    candidate_id BIGSERIAL PRIMARY KEY,
    attack_run_id BIGINT NOT NULL
        REFERENCES attack_runs(attack_run_id) ON DELETE CASCADE,
    candidate_content TEXT NOT NULL,
    candidate_digest_hex TEXT NOT NULL,
    is_distinct BOOLEAN NOT NULL,
    matches_target BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(candidate_content) > 0),
    CHECK (is_distinct OR NOT matches_target)
);

CREATE TABLE security_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    minimum_digest_bits INTEGER NOT NULL
        CHECK (minimum_digest_bits > 0),
    require_authenticated_origin BOOLEAN NOT NULL DEFAULT true,
    reject_known_second_preimage BOOLEAN NOT NULL DEFAULT true,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE verification_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    policy_id BIGINT NOT NULL
        REFERENCES security_policies(policy_id),
    digest_bits INTEGER NOT NULL,
    origin_authenticated BOOLEAN NOT NULL,
    second_preimage_found BOOLEAN NOT NULL,
    decision security_decision NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_artifacts_repository_state
    ON artifacts(repository_id, state);

CREATE INDEX idx_attack_runs_artifact_state
    ON attack_runs(artifact_id, state);

CREATE INDEX idx_candidates_matching
    ON candidates(attack_run_id, matches_target)
    WHERE matches_target = true;

CREATE OR REPLACE FUNCTION prevent_identical_candidate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.is_distinct = false AND NEW.matches_target = true THEN
        RAISE EXCEPTION
            'An identical message cannot be classified as a second preimage';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_identical_candidate
BEFORE INSERT OR UPDATE ON candidates
FOR EACH ROW
EXECUTE FUNCTION prevent_identical_candidate();

CREATE OR REPLACE FUNCTION validate_attack_completion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'FOUND' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM candidates c
            WHERE c.attack_run_id = NEW.attack_run_id
              AND c.is_distinct = true
              AND c.matches_target = true
        ) THEN
            RAISE EXCEPTION
                'FOUND attack requires a distinct candidate with matching digest';
        END IF;
    END IF;

    IF NEW.attempts > NEW.maximum_attempts THEN
        RAISE EXCEPTION
            'Attempt count % exceeds configured maximum %',
            NEW.attempts,
            NEW.maximum_attempts;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_attack_completion
BEFORE UPDATE ON attack_runs
FOR EACH ROW
EXECUTE FUNCTION validate_attack_completion();

CREATE OR REPLACE FUNCTION evaluate_security_policy(
    p_digest_bits INTEGER,
    p_origin_authenticated BOOLEAN,
    p_second_preimage_found BOOLEAN,
    p_minimum_digest_bits INTEGER,
    p_require_authenticated_origin BOOLEAN,
    p_reject_known_second_preimage BOOLEAN
)
RETURNS security_decision
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_digest_bits < p_minimum_digest_bits THEN
        RETURN 'REJECT';
    END IF;

    IF p_reject_known_second_preimage
       AND p_second_preimage_found THEN
        RETURN 'REJECT';
    END IF;

    IF p_require_authenticated_origin
       AND NOT p_origin_authenticated THEN
        RETURN 'REVIEW_REQUIRED';
    END IF;

    RETURN 'ACCEPT';
END;
$$;

INSERT INTO repositories (repository_name, owner_name)
VALUES
    ('ledger-service', 'security-engineering'),
    ('release-artifacts', 'platform-engineering');

INSERT INTO artifacts (
    repository_id,
    artifact_name,
    content,
    hash_algorithm,
    digest_bits,
    state
)
VALUES
(
    (SELECT repository_id FROM repositories
     WHERE repository_name = 'ledger-service'),
    'release-4.2.1',
    'ledger-service|release=4.2.1|environment=production',
    'SHA-256',
    256,
    'REGISTERED'
),
(
    (SELECT repository_id FROM repositories
     WHERE repository_name = 'release-artifacts'),
    'laboratory-message',
    'fixed-message-for-16-bit-experiment',
    'SHA-256-TRUNCATED',
    16,
    'REGISTERED'
);

INSERT INTO hash_records (artifact_id, digest_hex)
SELECT artifact_id,
       CASE artifact_name
           WHEN 'release-4.2.1'
               THEN '9a2f7d0d7f7e8e0d'
           WHEN 'laboratory-message'
               THEN '4b7a'
       END
FROM artifacts;

INSERT INTO security_policies (
    policy_name,
    minimum_digest_bits,
    require_authenticated_origin,
    reject_known_second_preimage,
    active
)
VALUES
(
    'production-artifact-policy',
    128,
    true,
    true,
    true
),
(
    'laboratory-policy',
    16,
    false,
    true,
    true
);

-- Transactionally record an attack run and a candidate.
BEGIN;

INSERT INTO attack_runs (
    artifact_id,
    digest_bits,
    maximum_attempts,
    attempts,
    state,
    completed_at
)
SELECT artifact_id,
       digest_bits,
       500000,
       500000,
       'NOT_FOUND',
       now()
FROM artifacts
WHERE artifact_name = 'laboratory-message';

COMMIT;

-- A second-preimage candidate must be distinct from the fixed target.
-- This sample deliberately records a non-matching candidate.
INSERT INTO candidates (
    attack_run_id,
    candidate_content,
    candidate_digest_hex,
    is_distinct,
    matches_target
)
SELECT
    ar.attack_run_id,
    a.content || '|candidate=1',
    'c81e',
    true,
    false
FROM attack_runs ar
JOIN artifacts a ON a.artifact_id = ar.artifact_id
WHERE a.artifact_name = 'laboratory-message';

-- Retrieval: artifact, target digest, and current state.
SELECT
    r.repository_name,
    a.artifact_name,
    a.hash_algorithm,
    a.digest_bits,
    a.state,
    h.digest_hex
FROM artifacts a
JOIN repositories r ON r.repository_id = a.repository_id
LEFT JOIN hash_records h ON h.artifact_id = a.artifact_id
ORDER BY r.repository_name, a.artifact_name;

-- Evaluation: identify whether any run produced a verified
-- second-preimage candidate.
SELECT
    a.artifact_name,
    ar.attack_run_id,
    ar.state,
    ar.attempts,
    EXISTS (
        SELECT 1
        FROM candidates c
        WHERE c.attack_run_id = ar.attack_run_id
          AND c.is_distinct
          AND c.matches_target
    ) AS verified_second_preimage
FROM attack_runs ar
JOIN artifacts a ON a.artifact_id = ar.artifact_id
ORDER BY ar.attack_run_id;

-- Aggregate operational reporting.
SELECT
    a.hash_algorithm,
    a.digest_bits,
    COUNT(*) AS attack_runs,
    COUNT(*) FILTER (WHERE ar.state = 'FOUND') AS found_runs,
    SUM(ar.attempts) AS total_attempts
FROM attack_runs ar
JOIN artifacts a ON a.artifact_id = ar.artifact_id
GROUP BY a.hash_algorithm, a.digest_bits
ORDER BY a.digest_bits;

-- Policy eligibility for every artifact.
SELECT
    a.artifact_name,
    p.policy_name,
    a.digest_bits,
    p.minimum_digest_bits,
    false AS second_preimage_found,
    evaluate_security_policy(
        a.digest_bits,
        false,
        false,
        p.minimum_digest_bits,
        p.require_authenticated_origin,
        p.reject_known_second_preimage
    ) AS eligibility
FROM artifacts a
CROSS JOIN security_policies p
WHERE p.active
ORDER BY a.artifact_name, p.policy_name;

-- Demonstrate a rejected policy decision for an undersized digest.
INSERT INTO verification_decisions (
    artifact_id,
    policy_id,
    digest_bits,
    origin_authenticated,
    second_preimage_found,
    decision
)
SELECT
    a.artifact_id,
    p.policy_id,
    a.digest_bits,
    false,
    false,
    evaluate_security_policy(
        a.digest_bits,
        false,
        false,
        p.minimum_digest_bits,
        p.require_authenticated_origin,
        p.reject_known_second_preimage
    )
FROM artifacts a
JOIN security_policies p
  ON p.policy_name = 'production-artifact-policy'
WHERE a.artifact_name = 'laboratory-message';

-- Reporting view for security operators.
CREATE VIEW artifact_security_report AS
SELECT
    a.artifact_id,
    r.repository_name,
    a.artifact_name,
    a.hash_algorithm,
    a.digest_bits,
    a.state,
    COUNT(DISTINCT ar.attack_run_id) AS attack_runs,
    COUNT(c.candidate_id) FILTER (
        WHERE c.is_distinct AND c.matches_target
    ) AS verified_second_preimages,
    MAX(ar.attempts) AS largest_search_budget
FROM artifacts a
JOIN repositories r
  ON r.repository_id = a.repository_id
LEFT JOIN attack_runs ar
  ON ar.artifact_id = a.artifact_id
LEFT JOIN candidates c
  ON c.attack_run_id = ar.attack_run_id
GROUP BY
    a.artifact_id,
    r.repository_name,
    a.artifact_name,
    a.hash_algorithm,
    a.digest_bits,
    a.state;

SELECT *
FROM artifact_security_report
ORDER BY repository_name, artifact_name;
