-- Key derivation in blockchain and cryptography.
-- PostgreSQL model for wallets, derivation paths, cryptographic keys,
-- repositories, reviews, approvals, status checks, branch protection,
-- and merge eligibility.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP SCHEMA IF EXISTS blockchain_governance CASCADE;
CREATE SCHEMA blockchain_governance;

SET search_path = blockchain_governance, public;

CREATE TYPE kdf_algorithm AS ENUM (
    'PBKDF2-SHA256',
    'SCRYPT',
    'HKDF-SHA256'
);

CREATE TYPE key_purpose AS ENUM (
    'WALLET_SEED',
    'SIGNING',
    'ENCRYPTION',
    'AUDIT'
);

CREATE TYPE repository_visibility AS ENUM (
    'PRIVATE',
    'INTERNAL',
    'PUBLIC'
);

CREATE TYPE pull_request_state AS ENUM (
    'DRAFT',
    'OPEN',
    'MERGED',
    'CLOSED'
);

CREATE TYPE review_state AS ENUM (
    'PENDING',
    'APPROVED',
    'CHANGES_REQUESTED',
    'DISMISSED'
);

CREATE TYPE branch_type AS ENUM (
    'PROTECTED',
    'DEVELOPMENT',
    'FEATURE'
);

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    visibility repository_visibility NOT NULL DEFAULT 'PRIVATE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_name, repository_name),
    CHECK (length(trim(repository_name)) >= 2)
);

CREATE TABLE repository_members (
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    username TEXT NOT NULL,
    role_name TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (repository_id, username),
    CHECK (role_name IN ('OWNER', 'MAINTAINER', 'DEVELOPER', 'REVIEWER'))
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    branch_name TEXT NOT NULL,
    branch_type branch_type NOT NULL,
    head_commit TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, branch_name),
    CHECK (length(trim(branch_name)) > 0),
    CHECK (length(head_commit) >= 7)
);

CREATE TABLE commits (
    commit_id TEXT PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    branch_id BIGINT
        REFERENCES branches(branch_id)
        ON DELETE SET NULL,
    author_name TEXT NOT NULL,
    commit_message TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(trim(commit_id)) >= 7),
    CHECK (length(trim(commit_message)) > 0)
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    title TEXT NOT NULL,
    state pull_request_state NOT NULL DEFAULT 'DRAFT',
    author_name TEXT NOT NULL,
    draft BOOLEAN NOT NULL DEFAULT TRUE,
    merge_conflict BOOLEAN NOT NULL DEFAULT FALSE,
    unresolved_conversations INTEGER NOT NULL DEFAULT 0,
    linear_history BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id),
    CHECK (unresolved_conversations >= 0),
    CHECK (
        (state = 'MERGED' AND merged_at IS NOT NULL)
        OR state <> 'MERGED'
    ),
    CHECK (
        (state = 'CLOSED' AND closed_at IS NOT NULL)
        OR state <> 'CLOSED'
    )
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    commit_id TEXT NOT NULL
        REFERENCES commits(commit_id)
        ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL,
    PRIMARY KEY (pull_request_id, commit_id),
    UNIQUE (pull_request_id, sequence_no),
    CHECK (sequence_no > 0)
);

CREATE TABLE reviewers (
    reviewer_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    username TEXT NOT NULL,
    security_clearance BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, username)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES reviewers(reviewer_id)
        ON DELETE RESTRICT,
    state review_state NOT NULL DEFAULT 'PENDING',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (pull_request_id, reviewer_id)
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES reviews(review_id)
        ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (line_number > 0),
    CHECK (length(trim(body)) > 0)
);

CREATE TABLE status_checks (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    passed BOOLEAN NOT NULL,
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE
        REFERENCES branches(branch_id)
        ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL DEFAULT 1,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    prohibit_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    prohibit_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    prohibit_branch_deletion BOOLEAN NOT NULL DEFAULT TRUE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (required_approvals >= 0)
);

CREATE TABLE required_status_checks (
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policies(policy_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    PRIMARY KEY (policy_id, check_name),
    CHECK (length(trim(check_name)) > 0)
);

CREATE TABLE kdf_operations (
    operation_id BIGSERIAL PRIMARY KEY,
    operation_name TEXT NOT NULL,
    algorithm kdf_algorithm NOT NULL,
    key_purpose key_purpose NOT NULL,
    output_length INTEGER NOT NULL,
    iterations INTEGER,
    memory_cost_kib INTEGER,
    parallelism INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (output_length BETWEEN 16 AND 64),
    CHECK (
        (algorithm = 'PBKDF2-SHA256' AND iterations >= 100000)
        OR algorithm <> 'PBKDF2-SHA256'
    ),
    CHECK (
        (algorithm = 'SCRYPT' AND memory_cost_kib IS NOT NULL)
        OR algorithm <> 'SCRYPT'
    )
);

CREATE TABLE wallet_keys (
    wallet_key_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT
        REFERENCES repositories(repository_id)
        ON DELETE SET NULL,
    operation_id BIGINT NOT NULL
        REFERENCES kdf_operations(operation_id),
    key_purpose key_purpose NOT NULL,
    derivation_path TEXT NOT NULL,
    key_fingerprint BYTEA NOT NULL,
    chain_code_fingerprint BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, key_purpose, derivation_path),
    CHECK (derivation_path ~ '^m(/[0-9]+''?)*$'),
    CHECK (octet_length(key_fingerprint) BETWEEN 8 AND 32)
);

CREATE INDEX idx_branches_repository
    ON branches(repository_id, branch_name);

CREATE INDEX idx_pr_target_state
    ON pull_requests(target_branch_id, state);

CREATE INDEX idx_reviews_pr_state
    ON reviews(pull_request_id, state, stale);

CREATE INDEX idx_status_checks_pr
    ON status_checks(pull_request_id, check_name);

CREATE INDEX idx_review_comments_unresolved
    ON review_comments(review_id)
    WHERE resolved = FALSE;

CREATE OR REPLACE FUNCTION prevent_protected_branch_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.protected AND NEW.head_commit IS DISTINCT FROM OLD.head_commit THEN
        IF EXISTS (
            SELECT 1
            FROM branch_protection_policies p
            WHERE p.branch_id = OLD.branch_id
              AND p.prohibit_direct_push
        ) THEN
            RAISE EXCEPTION
                'direct update of protected branch % is prohibited',
                OLD.branch_name;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protected_branch_mutation
BEFORE UPDATE OF head_commit
ON branches
FOR EACH ROW
EXECUTE FUNCTION prevent_protected_branch_mutation();

CREATE OR REPLACE FUNCTION reject_invalid_review()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    reviewer_active BOOLEAN;
BEGIN
    SELECT active
    INTO reviewer_active
    FROM reviewers
    WHERE reviewer_id = NEW.reviewer_id;

    IF NOT COALESCE(reviewer_active, FALSE) THEN
        RAISE EXCEPTION
            'inactive reviewer cannot submit a review';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_review_reviewer_validation
BEFORE INSERT OR UPDATE
ON reviews
FOR EACH ROW
EXECUTE FUNCTION reject_invalid_review();

CREATE OR REPLACE FUNCTION mark_approvals_stale_after_commit()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE reviews r
    SET stale = TRUE
    WHERE r.pull_request_id IN (
        SELECT pull_request_id
        FROM pull_request_commits
        WHERE commit_id = NEW.commit_id
    )
    AND r.state = 'APPROVED';

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_commit_stales_approvals
AFTER INSERT
ON pull_request_commits
FOR EACH ROW
EXECUTE FUNCTION mark_approvals_stale_after_commit();

CREATE OR REPLACE VIEW merge_eligibility AS
WITH review_summary AS (
    SELECT
        pr.pull_request_id,
        COUNT(*) FILTER (
            WHERE r.state = 'APPROVED'
              AND NOT r.stale
        ) AS valid_approvals
    FROM pull_requests pr
    LEFT JOIN reviews r
        ON r.pull_request_id = pr.pull_request_id
    GROUP BY pr.pull_request_id
),
check_summary AS (
    SELECT
        pr.pull_request_id,
        COUNT(*) FILTER (
            WHERE sc.passed
        ) AS passed_checks,
        COUNT(*) AS total_checks
    FROM pull_requests pr
    LEFT JOIN status_checks sc
        ON sc.pull_request_id = pr.pull_request_id
    GROUP BY pr.pull_request_id
),
required_check_summary AS (
    SELECT
        pr.pull_request_id,
        COUNT(rsc.check_name) AS required_checks,
        COUNT(rsc.check_name) FILTER (
            WHERE sc.passed
        ) AS passed_required_checks
    FROM pull_requests pr
    JOIN branch_protection_policies bpp
        ON bpp.branch_id = pr.target_branch_id
    LEFT JOIN required_status_checks rsc
        ON rsc.policy_id = bpp.policy_id
    LEFT JOIN status_checks sc
        ON sc.pull_request_id = pr.pull_request_id
       AND sc.check_name = rsc.check_name
    GROUP BY pr.pull_request_id
)
SELECT
    pr.pull_request_id,
    pr.title,
    pr.state,
    pr.draft,
    pr.merge_conflict,
    pr.unresolved_conversations,
    pr.linear_history,
    COALESCE(rs.valid_approvals, 0) AS valid_approvals,
    bpp.required_approvals,
    COALESCE(rcs.required_checks, 0) AS required_checks,
    COALESCE(rcs.passed_required_checks, 0) AS passed_required_checks,
    (
        pr.state = 'OPEN'
        AND NOT pr.draft
        AND NOT pr.merge_conflict
        AND pr.unresolved_conversations = 0
        AND (
            NOT bpp.require_linear_history
            OR pr.linear_history
        )
        AND COALESCE(rs.valid_approvals, 0)
            >= bpp.required_approvals
        AND COALESCE(rcs.passed_required_checks, 0)
            = COALESCE(rcs.required_checks, 0)
    ) AS eligible
FROM pull_requests pr
JOIN branch_protection_policies bpp
    ON bpp.branch_id = pr.target_branch_id
LEFT JOIN review_summary rs
    ON rs.pull_request_id = pr.pull_request_id
LEFT JOIN check_summary cs
    ON cs.pull_request_id = pr.pull_request_id
LEFT JOIN required_check_summary rcs
    ON rcs.pull_request_id = pr.pull_request_id;

CREATE OR REPLACE FUNCTION derive_hkdf_sha256(
    input_key_material BYTEA,
    salt BYTEA,
    info BYTEA,
    output_length INTEGER
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    prk BYTEA;
    previous BYTEA := ''::BYTEA;
    output BYTEA := ''::BYTEA;
    counter INTEGER := 1;
BEGIN
    IF input_key_material IS NULL
       OR octet_length(input_key_material) = 0 THEN
        RAISE EXCEPTION 'HKDF input key material must not be empty';
    END IF;

    IF salt IS NULL
       OR octet_length(salt) < 16 THEN
        RAISE EXCEPTION 'HKDF salt must contain at least 16 bytes';
    END IF;

    IF output_length <= 0
       OR output_length > 255 * 32 THEN
        RAISE EXCEPTION 'invalid HKDF output length';
    END IF;

    prk := hmac(input_key_material, salt, 'sha256');

    WHILE octet_length(output) < output_length LOOP
        previous := hmac(
            previous || COALESCE(info, ''::BYTEA)
                || decode(lpad(to_hex(counter), 2, '0'), 'hex'),
            prk,
            'sha256'
        );

        output := output || previous;
        counter := counter + 1;
    END LOOP;

    RETURN substring(output FROM 1 FOR output_length);
END;
$$;

INSERT INTO repositories (
    repository_name,
    owner_name,
    visibility
)
VALUES (
    'blockchain-key-governance',
    'platform-security',
    'PRIVATE'
);

INSERT INTO repository_members (
    repository_id,
    username,
    role_name
)
SELECT
    repository_id,
    username,
    role_name
FROM repositories r
CROSS JOIN (
    VALUES
        ('lead-engineer', 'OWNER'),
        ('security-reviewer', 'REVIEWER'),
        ('cryptography-reviewer', 'REVIEWER'),
        ('developer-a', 'DEVELOPER')
) AS members(username, role_name)
WHERE r.repository_name = 'blockchain-key-governance';

INSERT INTO branches (
    repository_id,
    branch_name,
    branch_type,
    head_commit,
    protected
)
SELECT
    repository_id,
    branch_name,
    branch_type,
    head_commit,
    protected
FROM repositories r
CROSS JOIN (
    VALUES
        ('main', 'PROTECTED'::branch_type, 'c200', TRUE),
        ('develop', 'DEVELOPMENT'::branch_type, 'c190', FALSE),
        ('feature/key-rotation', 'FEATURE'::branch_type, 'c200', FALSE)
) AS b(branch_name, branch_type, head_commit, protected)
WHERE r.repository_name = 'blockchain-key-governance';

INSERT INTO commits (
    commit_id,
    repository_id,
    branch_id,
    author_name,
    commit_message
)
SELECT
    v.commit_id,
    r.repository_id,
    b.branch_id,
    'developer-a',
    v.message
FROM repositories r
JOIN branches b
    ON b.repository_id = r.repository_id
CROSS JOIN (
    VALUES
        ('c198', 'add key rotation policy'),
        ('c199', 'validate KDF parameters'),
        ('c200', 'add cryptographic audit controls')
) AS v(commit_id, message)
WHERE r.repository_name = 'blockchain-key-governance'
  AND b.branch_name = 'feature/key-rotation';

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    title,
    state,
    author_name,
    draft,
    merge_conflict,
    unresolved_conversations,
    linear_history
)
SELECT
    r.repository_id,
    source_branch.branch_id,
    target_branch.branch_id,
    'Harden blockchain key derivation workflow',
    'OPEN',
    'developer-a',
    FALSE,
    FALSE,
    0,
    TRUE
FROM repositories r
JOIN branches source_branch
    ON source_branch.repository_id = r.repository_id
   AND source_branch.branch_name = 'feature/key-rotation'
JOIN branches target_branch
    ON target_branch.repository_id = r.repository_id
   AND target_branch.branch_name = 'main'
WHERE r.repository_name = 'blockchain-key-governance';

INSERT INTO pull_request_commits (
    pull_request_id,
    commit_id,
    sequence_no
)
SELECT
    pr.pull_request_id,
    c.commit_id,
    row_number() OVER (
        ORDER BY c.commit_id
    )
FROM pull_requests pr
JOIN commits c
    ON c.repository_id = pr.repository_id
WHERE pr.title = 'Harden blockchain key derivation workflow';

INSERT INTO reviewers (
    repository_id,
    username,
    security_clearance,
    active
)
SELECT
    repository_id,
    username,
    TRUE,
    TRUE
FROM repositories
CROSS JOIN (
    VALUES
        ('security-reviewer'),
        ('cryptography-reviewer')
) AS r(username)
WHERE repository_name = 'blockchain-key-governance';

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    stale
)
SELECT
    pr.pull_request_id,
    rv.reviewer_id,
    'APPROVED',
    FALSE
FROM pull_requests pr
JOIN reviewers rv
    ON rv.repository_id = pr.repository_id
WHERE pr.title = 'Harden blockchain key derivation workflow'
  AND rv.username IN (
      'security-reviewer',
      'cryptography-reviewer'
  );

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
SELECT
    review_id,
    'key_derivation.py',
    120,
    'Verify that password-derived material is never persisted.',
    TRUE
FROM reviews
WHERE state = 'APPROVED';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    passed,
    completed_at
)
SELECT
    pull_request_id,
    check_name,
    passed,
    now()
FROM pull_requests
CROSS JOIN (
    VALUES
        ('unit-tests', TRUE),
        ('security-scan', TRUE),
        ('policy-check', TRUE)
) AS checks(check_name, passed)
WHERE title = 'Harden blockchain key derivation workflow';

INSERT INTO branch_protection_policies (
    branch_id,
    required_approvals,
    require_conversation_resolution,
    require_linear_history,
    prohibit_direct_push,
    prohibit_force_push,
    prohibit_branch_deletion,
    allow_administrator_bypass
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE
FROM branches
WHERE branch_name = 'main';

INSERT INTO required_status_checks (
    policy_id,
    check_name
)
SELECT
    policy_id,
    check_name
FROM branch_protection_policies
CROSS JOIN (
    VALUES
        ('unit-tests'),
        ('security-scan'),
        ('policy-check')
) AS checks(check_name);

INSERT INTO kdf_operations (
    operation_name,
    algorithm,
    key_purpose,
    output_length,
    iterations
)
VALUES (
    'wallet seed derivation',
    'PBKDF2-SHA256',
    'WALLET_SEED',
    64,
    310000
),
(
    'signing key expansion',
    'HKDF-SHA256',
    'SIGNING',
    32,
    NULL
),
(
    'storage key expansion',
    'HKDF-SHA256',
    'ENCRYPTION',
    32,
    NULL
);

INSERT INTO wallet_keys (
    repository_id,
    operation_id,
    key_purpose,
    derivation_path,
    key_fingerprint,
    chain_code_fingerprint
)
SELECT
    r.repository_id,
    ko.operation_id,
    ko.key_purpose,
    paths.derivation_path,
    digest(
        paths.derivation_path || ':example-key-material',
        'sha256'
    ),
    digest(
        paths.derivation_path || ':example-chain-code',
        'sha256'
    )
FROM repositories r
JOIN kdf_operations ko
    ON ko.key_purpose = 'SIGNING'
CROSS JOIN (
    VALUES
        ('m/44''/0''/0''/0/0'),
        ('m/44''/0''/0''/0/1')
) AS paths(derivation_path)
WHERE r.repository_name = 'blockchain-key-governance';

-- Retrieval: repository and protected branches.
SELECT
    r.repository_name,
    b.branch_name,
    b.protected,
    b.head_commit
FROM repositories r
JOIN branches b
    ON b.repository_id = r.repository_id
ORDER BY b.branch_name;

-- Validation: KDF policy configuration.
SELECT
    operation_name,
    algorithm,
    key_purpose,
    output_length,
    iterations,
    CASE
        WHEN algorithm = 'PBKDF2-SHA256'
             AND iterations >= 100000
        THEN 'VALID'
        WHEN algorithm = 'HKDF-SHA256'
             AND output_length <= 64
        THEN 'VALID'
        ELSE 'REVIEW_REQUIRED'
    END AS configuration_status
FROM kdf_operations;

-- Aggregation: review decisions per Pull Request.
SELECT
    pr.pull_request_id,
    pr.title,
    COUNT(r.review_id) AS total_reviews,
    COUNT(*) FILTER (
        WHERE r.state = 'APPROVED'
          AND NOT r.stale
    ) AS valid_approvals,
    COUNT(*) FILTER (
        WHERE r.state = 'CHANGES_REQUESTED'
    ) AS change_requests
FROM pull_requests pr
LEFT JOIN reviews r
    ON r.pull_request_id = pr.pull_request_id
GROUP BY pr.pull_request_id, pr.title;

-- Evaluation: merge eligibility.
SELECT
    pull_request_id,
    title,
    valid_approvals,
    required_approvals,
    required_checks,
    passed_required_checks,
    eligible
FROM merge_eligibility
ORDER BY pull_request_id;

-- Workflow state report.
SELECT
    state,
    COUNT(*) AS pull_request_count
FROM pull_requests
GROUP BY state
ORDER BY state;

-- Eligibility decision for protected branches.
SELECT
    me.pull_request_id,
    me.title,
    me.eligible,
    CASE
        WHEN me.eligible
        THEN 'MERGE_ALLOWED'
        ELSE 'MERGE_BLOCKED'
    END AS decision
FROM merge_eligibility me;

-- HKDF demonstration using non-secret test material.
-- The database never stores wallet passwords, seed phrases, or private keys.
SELECT encode(
    derive_hkdf_sha256(
        decode(
            '00112233445566778899aabbccddeeff',
            'hex'
        ),
        decode(
            'ffeeddccbbaa99887766554433221100',
            'hex'
        ),
        convert_to('blockchain/signing-key/v1', 'UTF8'),
        32
    ),
    'hex'
) AS derived_demo_key;

-- Transactional workflow:
-- approval state and Pull Request state are changed atomically.
BEGIN;

UPDATE reviews
SET state = 'APPROVED',
    stale = FALSE
WHERE review_id = (
    SELECT MIN(review_id)
    FROM reviews
    WHERE pull_request_id = (
        SELECT pull_request_id
        FROM pull_requests
        WHERE title = 'Harden blockchain key derivation workflow'
    )
);

UPDATE pull_requests
SET state = 'OPEN',
    draft = FALSE
WHERE title = 'Harden blockchain key derivation workflow';

COMMIT;

-- Demonstrate a stale approval after a new Pull Request commit is attached.
-- The trigger marks existing approvals stale, forcing fresh review.
BEGIN;

INSERT INTO commits (
    commit_id,
    repository_id,
    branch_id,
    author_name,
    commit_message
)
SELECT
    'c201',
    repository_id,
    branch_id,
    'developer-a',
    'rotate domain separation labels'
FROM repositories r
JOIN branches b
    ON b.repository_id = r.repository_id
WHERE r.repository_name = 'blockchain-key-governance'
  AND b.branch_name = 'feature/key-rotation';

INSERT INTO pull_request_commits (
    pull_request_id,
    commit_id,
    sequence_no
)
SELECT
    pr.pull_request_id,
    'c201',
    COALESCE(
        MAX(prc.sequence_no),
        0
    ) + 1
FROM pull_requests pr
LEFT JOIN pull_request_commits prc
    ON prc.pull_request_id = pr.pull_request_id
WHERE pr.title = 'Harden blockchain key derivation workflow'
GROUP BY pr.pull_request_id;

COMMIT;

SELECT
    pr.title,
    r.state,
    r.stale
FROM reviews r
JOIN pull_requests pr
    ON pr.pull_request_id = r.pull_request_id
WHERE pr.title = 'Harden blockchain key derivation workflow'
ORDER BY r.review_id;
