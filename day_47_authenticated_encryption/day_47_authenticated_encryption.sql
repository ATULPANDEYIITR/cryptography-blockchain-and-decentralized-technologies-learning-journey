-- Authenticated Encryption Repository Governance Data Model
--
-- PostgreSQL-compatible SQL.
--
-- PostgreSQL does not provide a portable built-in AES-GCM application
-- encryption API through ordinary SQL. This schema therefore stores the
-- authenticated-encryption envelope produced by an application or KMS:
-- algorithm, key identity, nonce, ciphertext, authentication tag, and AAD.
--
-- The database enforces structural and governance invariants while the
-- cryptographic operation remains in the application/KMS boundary.

DROP SCHEMA IF EXISTS aead_governance CASCADE;

CREATE SCHEMA aead_governance;

SET search_path = aead_governance, public;

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(repository_name)) > 0),
    CHECK (length(trim(default_branch)) > 0)
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    branch_name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, branch_name),
    CHECK (length(trim(branch_name)) > 0)
);

CREATE TABLE developers (
    developer_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (length(trim(username)) > 0)
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    number INTEGER NOT NULL,
    source_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL
        REFERENCES branches(branch_id),
    state TEXT NOT NULL,
    is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    has_conflicts BOOLEAN NOT NULL DEFAULT FALSE,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMPTZ,
    UNIQUE (repository_id, number),
    CHECK (
        state IN (
            'OPEN',
            'CLOSED',
            'MERGED'
        )
    ),
    CHECK (source_branch_id <> target_branch_id),
    CHECK (
        (state = 'CLOSED' AND closed_at IS NOT NULL)
        OR
        (state <> 'CLOSED')
    )
);

CREATE TABLE commits (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    commit_hash TEXT NOT NULL,
    author_id BIGINT NOT NULL
        REFERENCES developers(developer_id),
    committed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (repository_id, commit_hash),
    CHECK (commit_hash ~ '^[0-9a-fA-F]{7,64}$')
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    commit_id BIGINT NOT NULL
        REFERENCES commits(commit_id)
        ON DELETE CASCADE,
    PRIMARY KEY (pull_request_id, commit_id)
);

CREATE TABLE reviewers (
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    developer_id BIGINT NOT NULL
        REFERENCES developers(developer_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pull_request_id, developer_id)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES developers(developer_id),
    reviewed_commit_id BIGINT NOT NULL
        REFERENCES commits(commit_id),
    state TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        state IN (
            'COMMENTED',
            'CHANGES_REQUESTED',
            'APPROVED',
            'DISMISSED'
        )
    ),
    UNIQUE (
        pull_request_id,
        reviewer_id,
        reviewed_commit_id
    )
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES reviews(review_id)
        ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(file_path)) > 0),
    CHECK (line_number IS NULL OR line_number > 0),
    CHECK (length(trim(body)) > 0)
);

CREATE TABLE status_checks (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    status TEXT NOT NULL,
    commit_id BIGINT NOT NULL
        REFERENCES commits(commit_id),
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name),
    CHECK (
        status IN (
            'PENDING',
            'PASSED',
            'FAILED'
        )
    )
);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE
        REFERENCES branches(branch_id)
        ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL DEFAULT 1,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_merge BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (required_approvals >= 0),
    CHECK (allow_force_push = FALSE),
    CHECK (allow_deletion = FALSE),
    CHECK (restrict_direct_push = TRUE),
    CHECK (restrict_merge = TRUE)
);

CREATE TABLE required_status_checks (
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policies(policy_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    PRIMARY KEY (policy_id, check_name),
    CHECK (length(trim(check_name)) > 0)
);

CREATE TABLE encrypted_artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    artifact_name TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    authentication_tag BYTEA NOT NULL,
    associated_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (repository_id, artifact_name),
    CHECK (algorithm = 'AES-256-GCM'),
    CHECK (length(nonce) = 12),
    CHECK (length(authentication_tag) = 16),
    CHECK (length(ciphertext) > 0),
    CHECK (length(key_id) > 0)
);

CREATE INDEX idx_pull_requests_repository_target
    ON pull_requests(repository_id, target_branch_id, state);

CREATE INDEX idx_reviews_pull_request_state
    ON reviews(pull_request_id, state);

CREATE INDEX idx_review_comments_unresolved
    ON review_comments(review_id)
    WHERE resolved = FALSE;

CREATE INDEX idx_status_checks_pull_request_status
    ON status_checks(pull_request_id, status);

CREATE INDEX idx_encrypted_artifacts_repository
    ON encrypted_artifacts(repository_id);

INSERT INTO repositories (repository_name, default_branch)
VALUES ('platform-security', 'main');

INSERT INTO branches (
    repository_id,
    branch_name,
    protected
)
SELECT repository_id, 'main', TRUE
FROM repositories
WHERE repository_name = 'platform-security';

INSERT INTO branches (
    repository_id,
    branch_name,
    protected
)
SELECT repository_id, 'feature/security-policy', FALSE
FROM repositories
WHERE repository_name = 'platform-security';

INSERT INTO developers (username)
VALUES
    ('security-reviewer'),
    ('platform-reviewer'),
    ('feature-author'),
    ('release-manager');

INSERT INTO branch_protection_policies (
    branch_id,
    required_approvals,
    require_conversation_resolution,
    require_linear_history,
    allow_force_push,
    allow_deletion,
    restrict_direct_push,
    restrict_merge
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE
FROM branches
WHERE branch_name = 'main';

INSERT INTO required_status_checks (
    policy_id,
    check_name
)
SELECT policy_id, check_name
FROM branch_protection_policies,
     (
         VALUES
             ('unit-tests'),
             ('security-scan'),
             ('policy-validation')
     ) AS checks(check_name);

INSERT INTO commits (
    repository_id,
    commit_hash,
    author_id,
    committed_at
)
SELECT
    r.repository_id,
    '0123456789abcdef0123456789abcdef01234567',
    d.developer_id,
    CURRENT_TIMESTAMP
FROM repositories r
JOIN developers d
    ON d.username = 'feature-author'
WHERE r.repository_name = 'platform-security';

INSERT INTO pull_requests (
    repository_id,
    number,
    source_branch_id,
    target_branch_id,
    state,
    is_draft,
    has_conflicts
)
SELECT
    r.repository_id,
    482,
    source.branch_id,
    target.branch_id,
    'OPEN',
    FALSE,
    FALSE
FROM repositories r
JOIN branches source
    ON source.repository_id = r.repository_id
   AND source.branch_name = 'feature/security-policy'
JOIN branches target
    ON target.repository_id = r.repository_id
   AND target.branch_name = 'main'
WHERE r.repository_name = 'platform-security';

INSERT INTO pull_request_commits (
    pull_request_id,
    commit_id
)
SELECT
    pr.pull_request_id,
    c.commit_id
FROM pull_requests pr
JOIN commits c
    ON c.repository_id = pr.repository_id
WHERE pr.number = 482;

INSERT INTO reviewers (
    pull_request_id,
    developer_id
)
SELECT
    pr.pull_request_id,
    d.developer_id
FROM pull_requests pr
CROSS JOIN developers d
WHERE pr.number = 482
  AND d.username IN (
      'security-reviewer',
      'platform-reviewer'
  );

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    reviewed_commit_id,
    state,
    body
)
SELECT
    pr.pull_request_id,
    d.developer_id,
    c.commit_id,
    'APPROVED',
    CASE
        WHEN d.username = 'security-reviewer'
            THEN 'Threat model and encryption boundaries reviewed.'
        ELSE
            'Repository policy behavior reviewed.'
    END
FROM pull_requests pr
JOIN commits c
    ON c.repository_id = pr.repository_id
JOIN developers d
    ON d.username IN (
        'security-reviewer',
        'platform-reviewer'
    )
WHERE pr.number = 482;

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
SELECT
    review_id,
    'branch-protection-policy.json',
    18,
    'Force-push behavior is explicitly disabled.',
    TRUE
FROM reviews
WHERE state = 'APPROVED'
LIMIT 1;

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    status,
    commit_id,
    completed_at
)
SELECT
    pr.pull_request_id,
    checks.check_name,
    'PASSED',
    c.commit_id,
    CURRENT_TIMESTAMP
FROM pull_requests pr
JOIN commits c
    ON c.repository_id = pr.repository_id
CROSS JOIN (
    VALUES
        ('unit-tests'),
        ('security-scan'),
        ('policy-validation')
) AS checks(check_name)
WHERE pr.number = 482;

INSERT INTO encrypted_artifacts (
    repository_id,
    artifact_name,
    algorithm,
    key_id,
    nonce,
    ciphertext,
    authentication_tag,
    associated_data
)
SELECT
    repository_id,
    'branch-protection-policy',
    'AES-256-GCM',
    'repo-key-2026',
    decode('0102030405060708090a0b0c', 'hex'),
    decode('aabbccddeeff00112233445566778899', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to(
        'repository=platform-security;artifact=branch-protection-policy',
        'UTF8'
    )
FROM repositories
WHERE repository_name = 'platform-security';

-- Pull Request-specific query:
-- show the proposed source and protected target branch.
SELECT
    pr.number,
    source.branch_name AS source_branch,
    target.branch_name AS target_branch,
    pr.state,
    pr.is_draft,
    pr.has_conflicts
FROM pull_requests pr
JOIN branches source
    ON source.branch_id = pr.source_branch_id
JOIN branches target
    ON target.branch_id = pr.target_branch_id
WHERE pr.number = 482;

-- Code-review query:
-- expose reviewer decisions without treating comments as approvals.
SELECT
    pr.number,
    d.username AS reviewer,
    r.state AS review_state,
    r.submitted_at
FROM reviews r
JOIN pull_requests pr
    ON pr.pull_request_id = r.pull_request_id
JOIN developers d
    ON d.developer_id = r.reviewer_id
WHERE pr.number = 482
ORDER BY r.submitted_at;

-- Approval query:
-- only APPROVED reviews count toward the approval threshold.
WITH active_approvals AS (
    SELECT
        pull_request_id,
        COUNT(DISTINCT reviewer_id) AS approval_count
    FROM reviews
    WHERE state = 'APPROVED'
    GROUP BY pull_request_id
)
SELECT
    pr.number,
    COALESCE(aa.approval_count, 0) AS approval_count,
    policy.required_approvals,
    COALESCE(aa.approval_count, 0)
        >= policy.required_approvals AS approval_requirement_met
FROM pull_requests pr
JOIN branch_protection_policies policy
    ON policy.branch_id = pr.target_branch_id
LEFT JOIN active_approvals aa
    ON aa.pull_request_id = pr.pull_request_id
WHERE pr.number = 482;

-- Branch-protection query:
-- every required check must have a PASSED result.
WITH required_checks AS (
    SELECT
        pr.pull_request_id,
        required.check_name
    FROM pull_requests pr
    JOIN branch_protection_policies policy
        ON policy.branch_id = pr.target_branch_id
    JOIN required_status_checks required
        ON required.policy_id = policy.policy_id
    WHERE pr.number = 482
),
check_results AS (
    SELECT
        required_checks.pull_request_id,
        required_checks.check_name,
        status_checks.status
    FROM required_checks
    LEFT JOIN status_checks
        ON status_checks.pull_request_id =
               required_checks.pull_request_id
       AND status_checks.check_name =
               required_checks.check_name
)
SELECT
    check_name,
    COALESCE(status, 'MISSING') AS observed_status,
    COALESCE(status = 'PASSED', FALSE) AS satisfied
FROM check_results
ORDER BY check_name;

-- Integrated merge-eligibility evaluation.
WITH approval_state AS (
    SELECT
        pr.pull_request_id,
        COUNT(DISTINCT r.reviewer_id)
            FILTER (WHERE r.state = 'APPROVED') AS approvals,
        COUNT(*)
            FILTER (WHERE r.state = 'CHANGES_REQUESTED')
            AS active_change_requests
    FROM pull_requests pr
    LEFT JOIN reviews r
        ON r.pull_request_id = pr.pull_request_id
    WHERE pr.number = 482
    GROUP BY pr.pull_request_id
),
check_state AS (
    SELECT
        pr.pull_request_id,
        COUNT(required.check_name) AS required_checks,
        COUNT(status.check_name)
            FILTER (WHERE status.status = 'PASSED')
            AS passed_checks
    FROM pull_requests pr
    JOIN branch_protection_policies policy
        ON policy.branch_id = pr.target_branch_id
    JOIN required_status_checks required
        ON required.policy_id = policy.policy_id
    LEFT JOIN status_checks status
        ON status.pull_request_id = pr.pull_request_id
       AND status.check_name = required.check_name
    WHERE pr.number = 482
    GROUP BY pr.pull_request_id
)
SELECT
    pr.number,
    pr.state,
    pr.is_draft,
    pr.has_conflicts,
    approval_state.approvals,
    policy.required_approvals,
    check_state.required_checks,
    check_state.passed_checks,
    (
        pr.state = 'OPEN'
        AND pr.is_draft = FALSE
        AND pr.has_conflicts = FALSE
        AND approval_state.approvals >= policy.required_approvals
        AND approval_state.active_change_requests = 0
        AND check_state.passed_checks = check_state.required_checks
    ) AS merge_eligible
FROM pull_requests pr
JOIN branch_protection_policies policy
    ON policy.branch_id = pr.target_branch_id
JOIN approval_state
    ON approval_state.pull_request_id = pr.pull_request_id
JOIN check_state
    ON check_state.pull_request_id = pr.pull_request_id
WHERE pr.number = 482;

-- Database-level protection test:
-- This statement is intentionally invalid and should be rejected because
-- the policy CHECK constraint prohibits force pushes.
-- Uncomment to observe the constraint:
--
-- UPDATE branch_protection_policies
-- SET allow_force_push = TRUE
-- WHERE branch_id = (
--     SELECT branch_id
--     FROM branches
--     WHERE branch_name = 'main'
-- );

-- Transactional policy update:
-- A review policy and its required checks are changed atomically.
BEGIN;

UPDATE branch_protection_policies
SET required_approvals = 2,
    require_conversation_resolution = TRUE
WHERE branch_id = (
    SELECT branch_id
    FROM branches
    WHERE branch_name = 'main'
);

INSERT INTO required_status_checks (
    policy_id,
    check_name
)
SELECT
    policy_id,
    'dependency-audit'
FROM branch_protection_policies
WHERE branch_id = (
    SELECT branch_id
    FROM branches
    WHERE branch_name = 'main'
)
ON CONFLICT DO NOTHING;

COMMIT;

-- The encrypted artifact record deliberately contains no secret key.
-- key_id identifies which external key-management context should be used.
SELECT
    repository_id,
    artifact_name,
    algorithm,
    key_id,
    octet_length(nonce) AS nonce_bytes,
    octet_length(ciphertext) AS ciphertext_bytes,
    octet_length(authentication_tag) AS tag_bytes,
    convert_from(associated_data, 'UTF8') AS visible_aad
FROM encrypted_artifacts
ORDER BY artifact_id;
