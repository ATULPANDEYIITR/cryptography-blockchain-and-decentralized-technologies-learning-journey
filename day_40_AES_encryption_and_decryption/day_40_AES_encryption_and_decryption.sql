-- PostgreSQL-compatible AES governance example.
-- pgcrypto supplies AES functions through the database extension.
-- The example models repositories, branches, pull requests, commits,
-- reviewers, reviews, review comments, status checks, and branch protection.
--
-- AES-GCM is not exposed by pgcrypto's high-level encrypt/decrypt functions.
-- This script therefore demonstrates AES encryption/decryption using
-- pgp_sym_encrypt/pgp_sym_decrypt with AES-256, while keeping governance
-- integrity in relational constraints and transactional operations.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP VIEW IF EXISTS merge_eligibility;
DROP TABLE IF EXISTS review_comments CASCADE;
DROP TABLE IF EXISTS reviews CASCADE;
DROP TABLE IF EXISTS status_checks CASCADE;
DROP TABLE IF EXISTS pull_request_commits CASCADE;
DROP TABLE IF EXISTS pull_requests CASCADE;
DROP TABLE IF EXISTS branch_protection CASCADE;
DROP TABLE IF EXISTS branches CASCADE;
DROP TABLE IF EXISTS reviewers CASCADE;
DROP TABLE IF EXISTS repositories CASCADE;

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_protected BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(repository_id, name)
);

CREATE TABLE reviewers (
    reviewer_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE branch_protection (
    protection_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE
        REFERENCES branches(branch_id)
        ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL DEFAULT 1
        CHECK (required_approvals >= 1),
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE
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
    state TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (state IN (
            'DRAFT',
            'OPEN',
            'CHANGES_REQUESTED',
            'APPROVED',
            'MERGED',
            'CLOSED'
        )),
    is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    head_commit_sha TEXT NOT NULL,
    base_commit_sha TEXT NOT NULL,
    merge_conflict BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id)
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    commit_sha TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pull_request_id, commit_sha)
);

CREATE TABLE status_checks (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('PENDING', 'PASSED', 'FAILED')),
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES reviewers(reviewer_id),
    commit_sha TEXT NOT NULL,
    review_state TEXT NOT NULL
        CHECK (review_state IN ('APPROVED', 'CHANGES_REQUESTED', 'COMMENTED')),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES reviews(review_id)
        ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pull_requests_target
    ON pull_requests(target_branch_id, state);

CREATE INDEX idx_reviews_pr_commit
    ON reviews(pull_request_id, commit_sha, review_state);

CREATE INDEX idx_status_checks_pr_status
    ON status_checks(pull_request_id, status);

CREATE INDEX idx_review_comments_unresolved
    ON review_comments(review_id)
    WHERE resolved = FALSE;

INSERT INTO repositories (name, owner)
VALUES ('security-platform', 'engineering');

INSERT INTO branches (repository_id, name, is_protected)
SELECT repository_id, 'main', TRUE
FROM repositories
WHERE name = 'security-platform';

INSERT INTO branches (repository_id, name, is_protected)
SELECT repository_id, 'feature/encrypted-audit', FALSE
FROM repositories
WHERE name = 'security-platform';

INSERT INTO branch_protection (
    branch_id,
    required_approvals,
    require_status_checks,
    require_conversation_resolution,
    allow_force_push,
    allow_deletion,
    require_linear_history
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TRUE
FROM branches
WHERE name = 'main';

INSERT INTO reviewers (username)
VALUES
    ('reviewer_a'),
    ('reviewer_b'),
    ('reviewer_c');

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    title,
    state,
    is_draft,
    head_commit_sha,
    base_commit_sha
)
SELECT
    r.repository_id,
    source.branch_id,
    target.branch_id,
    'Encrypt repository audit metadata',
    'OPEN',
    FALSE,
    'abc123',
    'base001'
FROM repositories r
JOIN branches source
    ON source.repository_id = r.repository_id
   AND source.name = 'feature/encrypted-audit'
JOIN branches target
    ON target.repository_id = r.repository_id
   AND target.name = 'main'
WHERE r.name = 'security-platform';

INSERT INTO pull_request_commits (pull_request_id, commit_sha)
SELECT pull_request_id, 'abc123'
FROM pull_requests
WHERE title = 'Encrypt repository audit metadata';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    status,
    completed_at
)
SELECT
    pull_request_id,
    'unit-tests',
    'PASSED',
    CURRENT_TIMESTAMP
FROM pull_requests
WHERE title = 'Encrypt repository audit metadata';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    status,
    completed_at
)
SELECT
    pull_request_id,
    'security-scan',
    'PASSED',
    CURRENT_TIMESTAMP
FROM pull_requests
WHERE title = 'Encrypt repository audit metadata';

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    commit_sha,
    review_state
)
SELECT
    p.pull_request_id,
    r.reviewer_id,
    p.head_commit_sha,
    'APPROVED'
FROM pull_requests p
CROSS JOIN reviewers r
WHERE p.title = 'Encrypt repository audit metadata'
  AND r.username IN ('reviewer_a', 'reviewer_b');

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
SELECT
    review_id,
    'src/security/aes_service.java',
    87,
    'Verify that IV reuse cannot occur for the selected AES mode.',
    TRUE
FROM reviews
WHERE review_state = 'APPROVED'
LIMIT 1;

CREATE VIEW merge_eligibility AS
WITH approval_state AS (
    SELECT
        p.pull_request_id,
        COUNT(DISTINCT r.reviewer_id) FILTER (
            WHERE r.review_state = 'APPROVED'
              AND r.commit_sha = p.head_commit_sha
              AND reviewers.active = TRUE
        ) AS valid_approvals,
        BOOL_OR(
            r.review_state = 'CHANGES_REQUESTED'
            AND r.commit_sha = p.head_commit_sha
        ) AS has_changes_requested
    FROM pull_requests p
    LEFT JOIN reviews r
        ON r.pull_request_id = p.pull_request_id
    LEFT JOIN reviewers
        ON reviewers.reviewer_id = r.reviewer_id
    GROUP BY p.pull_request_id
),
check_state AS (
    SELECT
        p.pull_request_id,
        COUNT(*) FILTER (WHERE sc.status = 'FAILED') AS failed_checks,
        COUNT(*) FILTER (WHERE sc.status = 'PENDING') AS pending_checks
    FROM pull_requests p
    LEFT JOIN status_checks sc
        ON sc.pull_request_id = p.pull_request_id
    GROUP BY p.pull_request_id
),
conversation_state AS (
    SELECT
        p.pull_request_id,
        COUNT(rc.comment_id) FILTER (WHERE rc.resolved = FALSE) AS unresolved_comments
    FROM pull_requests p
    LEFT JOIN reviews r
        ON r.pull_request_id = p.pull_request_id
    LEFT JOIN review_comments rc
        ON rc.review_id = r.review_id
    GROUP BY p.pull_request_id
)
SELECT
    p.pull_request_id,
    p.title,
    p.state,
    bp.required_approvals,
    a.valid_approvals,
    a.has_changes_requested,
    c.failed_checks,
    c.pending_checks,
    cs.unresolved_comments,
    p.merge_conflict,
    (
        p.state IN ('OPEN', 'APPROVED')
        AND NOT p.is_draft
        AND target.is_protected
        AND a.valid_approvals >= bp.required_approvals
        AND COALESCE(a.has_changes_requested, FALSE) = FALSE
        AND (
            NOT bp.require_status_checks
            OR (c.failed_checks = 0 AND c.pending_checks = 0)
        )
        AND (
            NOT bp.require_conversation_resolution
            OR cs.unresolved_comments = 0
        )
        AND p.merge_conflict = FALSE
    ) AS merge_allowed
FROM pull_requests p
JOIN branches target
    ON target.branch_id = p.target_branch_id
JOIN branch_protection bp
    ON bp.branch_id = target.branch_id
JOIN approval_state a
    ON a.pull_request_id = p.pull_request_id
JOIN check_state c
    ON c.pull_request_id = p.pull_request_id
JOIN conversation_state cs
    ON cs.pull_request_id = p.pull_request_id;

SELECT *
FROM merge_eligibility;

-- Demonstrate stale approval semantics: the approval is attached to an old
-- commit and therefore does not count toward the current head commit.
INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    commit_sha,
    review_state
)
SELECT
    p.pull_request_id,
    r.reviewer_id,
    'old999',
    'APPROVED'
FROM pull_requests p
JOIN reviewers r ON r.username = 'reviewer_c'
WHERE p.title = 'Encrypt repository audit metadata';

UPDATE pull_requests
SET head_commit_sha = 'new456'
WHERE title = 'Encrypt repository audit metadata';

SELECT
    pull_request_id,
    title,
    valid_approvals,
    required_approvals,
    merge_allowed
FROM merge_eligibility;

-- Transactional merge eligibility check.
BEGIN;

SELECT
    p.pull_request_id,
    p.title,
    me.merge_allowed
FROM pull_requests p
JOIN merge_eligibility me
    ON me.pull_request_id = p.pull_request_id
WHERE p.title = 'Encrypt repository audit metadata'
FOR UPDATE;

-- A production application would perform the merge only after the locked
-- eligibility result is verified. This transaction intentionally leaves the
-- data unchanged for demonstration.
ROLLBACK;

-- AES encryption/decryption using pgcrypto.
-- The passphrase is demonstration data only. Production systems should obtain
-- keys from a dedicated secret-management system rather than storing them in
-- SQL source code.
WITH encrypted AS (
    SELECT pgp_sym_encrypt(
        'Confidential repository governance record',
        'demo-only-passphrase',
        'cipher-algo=aes256'
    ) AS ciphertext
)
SELECT
    encode(ciphertext, 'base64') AS encrypted_value,
    pgp_sym_decrypt(
        ciphertext,
        'demo-only-passphrase'
    ) AS decrypted_value
FROM encrypted;

-- The database cannot infer that a plaintext key is trustworthy merely from
-- the existence of pgp_sym_decrypt. Key lifecycle, access control, rotation,
-- secret storage, audit logging, and authorization remain operational
-- responsibilities outside this demonstration.
