-- DES IN CRYPTOGRAPHY AND BLOCKCHAIN
-- PostgreSQL-compatible relational case study.
--
-- The database models cryptographic metadata and blockchain relationships,
-- while deliberately keeping DES key material outside the database.
--
-- Security boundary:
--   DES       -> historical confidentiality mechanism
--   SHA-256   -> integrity/linking digest
--   signatures/consensus -> blockchain trust model
--   database constraints -> local data integrity
--
-- A production database should not store plaintext cryptographic keys in
-- ordinary relational columns. Key management belongs in a dedicated KMS/HSM
-- or equivalent controlled secret-management system.

DROP SCHEMA IF EXISTS des_blockchain CASCADE;
CREATE SCHEMA des_blockchain;

SET search_path = des_blockchain;

CREATE TYPE transaction_state AS ENUM (
    'PROPOSED',
    'VALIDATED',
    'COMMITTED',
    'REJECTED'
);

CREATE TYPE review_state AS ENUM (
    'PENDING',
    'APPROVED',
    'CHANGES_REQUESTED',
    'DISMISSED'
);

CREATE TYPE check_state AS ENUM (
    'PENDING',
    'SUCCESS',
    'FAILURE'
);

CREATE TYPE merge_strategy AS ENUM (
    'MERGE_COMMIT',
    'SQUASH',
    'REBASE'
);

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_name TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_name, repository_name)
);

CREATE TABLE branches (
    branch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id) ON DELETE CASCADE,
    branch_name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, branch_name)
);

CREATE TABLE contributors (
    contributor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE pull_requests (
    pull_request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id) ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    author_id BIGINT NOT NULL
        REFERENCES contributors(contributor_id),
    title TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('OPEN', 'CLOSED', 'MERGED', 'DRAFT')),
    merge_strategy merge_strategy,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id),
    CHECK (
        (state = 'MERGED' AND merged_at IS NOT NULL)
        OR
        (state <> 'MERGED')
    )
);

CREATE TABLE commits (
    commit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id) ON DELETE CASCADE,
    commit_hash CHAR(40) NOT NULL UNIQUE,
    author_id BIGINT NOT NULL
        REFERENCES contributors(contributor_id),
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (commit_hash ~ '^[0-9a-fA-F]{40}$')
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    commit_id BIGINT NOT NULL
        REFERENCES commits(commit_id) ON DELETE CASCADE,
    PRIMARY KEY (pull_request_id, commit_id)
);

CREATE TABLE reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES contributors(contributor_id),
    state review_state NOT NULL,
    commit_id BIGINT
        REFERENCES commits(commit_id),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    body TEXT,
    UNIQUE (pull_request_id, reviewer_id, submitted_at)
);

CREATE TABLE review_comments (
    comment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES reviews(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE status_checks (
    status_check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    state check_state NOT NULL DEFAULT 'PENDING',
    commit_hash CHAR(40),
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE
        REFERENCES branches(branch_id) ON DELETE CASCADE,
    required_reviews INTEGER NOT NULL DEFAULT 1
        CHECK (required_reviews >= 0),
    dismiss_stale_approvals BOOLEAN NOT NULL DEFAULT TRUE,
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE approval_requirements (
    requirement_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policies(policy_id) ON DELETE CASCADE,
    required_role TEXT NOT NULL,
    minimum_count INTEGER NOT NULL CHECK (minimum_count > 0),
    UNIQUE (policy_id, required_role)
);

CREATE TABLE blockchain_blocks (
    block_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id) ON DELETE CASCADE,
    block_index INTEGER NOT NULL CHECK (block_index >= 0),
    previous_hash CHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    des_ciphertext BYTEA,
    initialization_vector BYTEA,
    payload_mac BYTEA,
    nonce BIGINT NOT NULL DEFAULT 0 CHECK (nonce >= 0),
    block_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, block_index),
    UNIQUE (repository_id, block_hash),
    CHECK (block_hash ~ '^[0-9a-fA-F]{64}$')
);

CREATE INDEX idx_pull_requests_target_state
    ON pull_requests (target_branch_id, state);

CREATE INDEX idx_reviews_pull_request_state
    ON reviews (pull_request_id, state);

CREATE INDEX idx_status_checks_pull_request_state
    ON status_checks (pull_request_id, state);

CREATE INDEX idx_blocks_repository_index
    ON blockchain_blocks (repository_id, block_index);

-- ---------------------------------------------------------------------------
-- Sample repository and branch governance
-- ---------------------------------------------------------------------------

INSERT INTO repositories (
    owner_name,
    repository_name,
    default_branch
)
VALUES (
    'example-org',
    'secure-ledger',
    'main'
);

INSERT INTO branches (
    repository_id,
    branch_name,
    protected
)
SELECT repository_id, branch_name, branch_name = 'main'
FROM repositories
CROSS JOIN (
    VALUES ('main'), ('feature/des-audit'), ('feature/ledger-validation')
) AS branch_names(branch_name);

INSERT INTO contributors (
    username,
    role_name
)
VALUES
    ('alice', 'author'),
    ('bob', 'security-reviewer'),
    ('carol', 'blockchain-reviewer'),
    ('dave', 'maintainer'),
    ('ci-bot', 'automation');

INSERT INTO branch_protection_policies (
    branch_id,
    required_reviews,
    dismiss_stale_approvals,
    require_status_checks,
    require_conversation_resolution,
    restrict_direct_push,
    allow_force_push,
    allow_deletion,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    FALSE
FROM branches
WHERE branch_name = 'main';

INSERT INTO approval_requirements (
    policy_id,
    required_role,
    minimum_count
)
SELECT
    policy_id,
    'security-reviewer',
    1
FROM branch_protection_policies;

INSERT INTO approval_requirements (
    policy_id,
    required_role,
    minimum_count
)
SELECT
    policy_id,
    'blockchain-reviewer',
    1
FROM branch_protection_policies;

-- ---------------------------------------------------------------------------
-- Pull Request, commits, reviews, comments, and checks
-- ---------------------------------------------------------------------------

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    author_id,
    title,
    state
)
SELECT
    r.repository_id,
    source_branch.branch_id,
    target_branch.branch_id,
    author.contributor_id,
    'Protect encrypted ledger records',
    'OPEN'
FROM repositories r
JOIN branches source_branch
    ON source_branch.repository_id = r.repository_id
    AND source_branch.branch_name = 'feature/des-audit'
JOIN branches target_branch
    ON target_branch.repository_id = r.repository_id
    AND target_branch.branch_name = 'main'
JOIN contributors author
    ON author.username = 'alice'
WHERE r.repository_name = 'secure-ledger';

INSERT INTO commits (
    repository_id,
    commit_hash,
    author_id,
    message
)
SELECT
    r.repository_id,
    '1111111111111111111111111111111111111111',
    c.contributor_id,
    'Add encrypted payload metadata'
FROM repositories r
JOIN contributors c ON c.username = 'alice'
WHERE r.repository_name = 'secure-ledger';

INSERT INTO commits (
    repository_id,
    commit_hash,
    author_id,
    message
)
SELECT
    r.repository_id,
    '2222222222222222222222222222222222222222',
    c.contributor_id,
    'Add blockchain validation checks'
FROM repositories r
JOIN contributors c ON c.username = 'alice'
WHERE r.repository_name = 'secure-ledger';

INSERT INTO pull_request_commits (
    pull_request_id,
    commit_id
)
SELECT pr.pull_request_id, c.commit_id
FROM pull_requests pr
JOIN commits c
    ON c.repository_id = pr.repository_id
WHERE pr.title = 'Protect encrypted ledger records';

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_id,
    body
)
SELECT
    pr.pull_request_id,
    reviewer.contributor_id,
    'APPROVED',
    c.commit_id,
    'DES usage is documented as legacy cryptography.'
FROM pull_requests pr
JOIN contributors reviewer
    ON reviewer.username = 'bob'
JOIN commits c
    ON c.commit_hash = '2222222222222222222222222222222222222222';

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_id,
    body
)
SELECT
    pr.pull_request_id,
    reviewer.contributor_id,
    'APPROVED',
    c.commit_id,
    'Blockchain hash linkage is validated.'
FROM pull_requests pr
JOIN contributors reviewer
    ON reviewer.username = 'carol'
JOIN commits c
    ON c.commit_hash = '2222222222222222222222222222222222222222';

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
SELECT
    review_id,
    'crypto/des_legacy.py',
    184,
    'Document why DES is not suitable for new production encryption.',
    TRUE
FROM reviews
WHERE body LIKE 'DES usage%';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    state,
    commit_hash,
    completed_at
)
SELECT
    pull_request_id,
    check_name,
    'SUCCESS',
    '2222222222222222222222222222222222222222',
    now()
FROM pull_requests
CROSS JOIN (
    VALUES ('unit-tests'), ('security-scan'), ('blockchain-integrity')
) AS checks(check_name)
WHERE title = 'Protect encrypted ledger records';

-- ---------------------------------------------------------------------------
-- Approval and protection-policy evaluation
-- ---------------------------------------------------------------------------

CREATE VIEW merge_eligibility AS
WITH latest_reviews AS (
    SELECT DISTINCT ON (r.pull_request_id, r.reviewer_id)
        r.pull_request_id,
        r.reviewer_id,
        r.state,
        r.commit_id,
        r.submitted_at
    FROM reviews r
    ORDER BY
        r.pull_request_id,
        r.reviewer_id,
        r.submitted_at DESC
),
approval_counts AS (
    SELECT
        lr.pull_request_id,
        COUNT(*) FILTER (
            WHERE lr.state = 'APPROVED'
        ) AS approvals,
        COUNT(*) FILTER (
            WHERE lr.state = 'CHANGES_REQUESTED'
        ) AS change_requests
    FROM latest_reviews lr
    GROUP BY lr.pull_request_id
),
check_counts AS (
    SELECT
        sc.pull_request_id,
        COUNT(*) AS total_checks,
        COUNT(*) FILTER (
            WHERE sc.state = 'SUCCESS'
        ) AS successful_checks
    FROM status_checks sc
    GROUP BY sc.pull_request_id
),
unresolved AS (
    SELECT
        r.pull_request_id,
        COUNT(*) FILTER (
            WHERE rc.resolved = FALSE
        ) AS unresolved_comments
    FROM reviews r
    LEFT JOIN review_comments rc
        ON rc.review_id = r.review_id
    GROUP BY r.pull_request_id
)
SELECT
    pr.pull_request_id,
    pr.title,
    bp.required_reviews,
    COALESCE(ac.approvals, 0) AS approvals,
    COALESCE(ac.change_requests, 0) AS change_requests,
    COALESCE(cc.total_checks, 0) AS total_checks,
    COALESCE(cc.successful_checks, 0) AS successful_checks,
    COALESCE(u.unresolved_comments, 0) AS unresolved_comments,
    (
        pr.state = 'OPEN'
        AND COALESCE(ac.approvals, 0) >= bp.required_reviews
        AND COALESCE(ac.change_requests, 0) = 0
        AND (
            NOT bp.require_status_checks
            OR (
                COALESCE(cc.total_checks, 0) > 0
                AND cc.successful_checks = cc.total_checks
            )
        )
        AND (
            NOT bp.require_conversation_resolution
            OR COALESCE(u.unresolved_comments, 0) = 0
        )
    ) AS eligible_to_merge
FROM pull_requests pr
JOIN branch_protection_policies bp
    ON bp.branch_id = pr.target_branch_id
LEFT JOIN approval_counts ac
    ON ac.pull_request_id = pr.pull_request_id
LEFT JOIN check_counts cc
    ON cc.pull_request_id = pr.pull_request_id
LEFT JOIN unresolved u
    ON u.pull_request_id = pr.pull_request_id;

SELECT *
FROM merge_eligibility;

-- ---------------------------------------------------------------------------
-- Blockchain blocks and chain integrity
-- ---------------------------------------------------------------------------

INSERT INTO blockchain_blocks (
    repository_id,
    block_index,
    previous_hash,
    payload,
    des_ciphertext,
    initialization_vector,
    payload_mac,
    nonce,
    block_hash
)
SELECT
    repository_id,
    0,
    repeat('0', 64),
    'Settlement transaction accepted',
    decode('85E813540F0AB405', 'hex'),
    decode('A1A2A3A4A5A6A7A8', 'hex'),
    decode(
        '00112233445566778899AABBCCDDEEFF',
        'hex'
    ),
    17,
    repeat('1', 64)
FROM repositories
WHERE repository_name = 'secure-ledger';

INSERT INTO blockchain_blocks (
    repository_id,
    block_index,
    previous_hash,
    payload,
    des_ciphertext,
    initialization_vector,
    payload_mac,
    nonce,
    block_hash
)
SELECT
    repository_id,
    1,
    repeat('1', 64),
    'Escrow state transitioned to RELEASED',
    decode('1234567890ABCDEF', 'hex'),
    decode('B1B2B3B4B5B6B7B8', 'hex'),
    decode(
        'FFEEDDCCBBAA99887766554433221100',
        'hex'
    ),
    23,
    repeat('2', 64)
FROM repositories
WHERE repository_name = 'secure-ledger';

-- A recursive query follows the previous-hash relationship and exposes
-- broken links. The query does not pretend that PostgreSQL's digest functions
-- replace blockchain consensus; it evaluates relational consistency.
WITH RECURSIVE chain AS (
    SELECT
        b.repository_id,
        b.block_index,
        b.previous_hash,
        b.block_hash,
        0 AS depth
    FROM blockchain_blocks b
    WHERE b.block_index = 0

    UNION ALL

    SELECT
        next_block.repository_id,
        next_block.block_index,
        next_block.previous_hash,
        next_block.block_hash,
        chain.depth + 1
    FROM chain
    JOIN blockchain_blocks next_block
        ON next_block.repository_id = chain.repository_id
        AND next_block.previous_hash = chain.block_hash
)
SELECT *
FROM chain
ORDER BY block_index;

-- ---------------------------------------------------------------------------
-- Edge-case queries
-- ---------------------------------------------------------------------------

-- Finds Pull Requests that have approvals but still have failing checks.
SELECT
    me.pull_request_id,
    me.title,
    me.approvals,
    me.successful_checks,
    me.total_checks
FROM merge_eligibility me
WHERE me.approvals >= me.required_reviews
  AND me.successful_checks < me.total_checks;

-- Finds protected branches where direct pushes are restricted.
SELECT
    r.owner_name,
    r.repository_name,
    b.branch_name,
    bp.restrict_direct_push,
    bp.allow_force_push,
    bp.allow_deletion,
    bp.require_linear_history
FROM repositories r
JOIN branches b
    ON b.repository_id = r.repository_id
JOIN branch_protection_policies bp
    ON bp.branch_id = b.branch_id
WHERE b.protected = TRUE;

-- Shows reviewers whose latest decision is not an approval.
WITH latest AS (
    SELECT DISTINCT ON (pull_request_id, reviewer_id)
        pull_request_id,
        reviewer_id,
        state,
        submitted_at
    FROM reviews
    ORDER BY pull_request_id, reviewer_id, submitted_at DESC
)
SELECT
    pr.title,
    c.username,
    latest.state
FROM latest
JOIN pull_requests pr
    ON pr.pull_request_id = latest.pull_request_id
JOIN contributors c
    ON c.contributor_id = latest.reviewer_id
WHERE latest.state <> 'APPROVED';

-- DES-specific metadata query. Key material is intentionally absent.
SELECT
    repository_name,
    'DES ciphertext is stored only as encrypted payload metadata' AS policy,
    'DES effective key size: 56 bits' AS cryptographic_fact
FROM repositories
WHERE repository_name = 'secure-ledger';

-- Transactional example: a commit and its status update should succeed
-- together or fail together.
BEGIN;

INSERT INTO commits (
    repository_id,
    commit_hash,
    author_id,
    message
)
SELECT
    repository_id,
    '3333333333333333333333333333333333333333',
    contributor_id,
    'Fix encrypted ledger documentation'
FROM repositories
CROSS JOIN contributors
WHERE repository_name = 'secure-ledger'
  AND username = 'alice';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    state,
    commit_hash,
    completed_at
)
SELECT
    pull_request_id,
    'documentation-build',
    'SUCCESS',
    '3333333333333333333333333333333333333333',
    now()
FROM pull_requests
WHERE title = 'Protect encrypted ledger records'
ON CONFLICT (pull_request_id, check_name)
DO UPDATE SET
    state = EXCLUDED.state,
    commit_hash = EXCLUDED.commit_hash,
    completed_at = EXCLUDED.completed_at;

COMMIT;

-- Final eligibility state after the transaction.
SELECT *
FROM merge_eligibility
ORDER BY pull_request_id;
