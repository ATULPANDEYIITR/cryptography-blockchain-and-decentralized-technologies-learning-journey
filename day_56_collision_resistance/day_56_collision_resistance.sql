DROP SCHEMA IF EXISTS collision_resistance CASCADE;
CREATE SCHEMA collision_resistance;

SET search_path = collision_resistance, public;

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    branch_name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    head_commit_sha CHAR(64),
    UNIQUE (repository_id, branch_name)
);

CREATE TABLE commits (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    commit_sha CHAR(64) NOT NULL,
    parent_sha CHAR(64),
    message TEXT NOT NULL,
    content_digest CHAR(64) NOT NULL,
    author_name TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, commit_sha),
    UNIQUE (repository_id, content_digest),
    CHECK (commit_sha ~ '^[0-9a-f]{64}$'),
    CHECK (content_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    source_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    head_commit_id BIGINT NOT NULL REFERENCES commits(commit_id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open',
    is_draft BOOLEAN NOT NULL DEFAULT TRUE,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    closed_at TIMESTAMPTZ,
    merged_at TIMESTAMPTZ,
    CHECK (state IN ('open', 'closed', 'merged')),
    CHECK (source_branch_id <> target_branch_id),
    CHECK (
        (state = 'open' AND closed_at IS NULL AND merged_at IS NULL)
        OR
        (state = 'closed' AND closed_at IS NOT NULL AND merged_at IS NULL)
        OR
        (state = 'merged' AND merged_at IS NOT NULL)
    )
);

CREATE TABLE reviewers (
    reviewer_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    username TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, username)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id),
    reviewer_id BIGINT NOT NULL REFERENCES reviewers(reviewer_id),
    state TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    commit_id BIGINT NOT NULL REFERENCES commits(commit_id),
    body TEXT NOT NULL DEFAULT '',
    CHECK (state IN ('commented', 'approved', 'changes_requested', 'dismissed'))
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (line_number > 0)
);

CREATE TABLE status_checks (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id),
    check_name TEXT NOT NULL,
    state TEXT NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK (state IN ('pending', 'passing', 'failing', 'cancelled')),
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branches(branch_id),
    required_approvals INTEGER NOT NULL DEFAULT 0,
    require_passing_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_conversations_resolved BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_direct_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (required_approvals >= 0)
);

CREATE TABLE approval_requirements (
    requirement_id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES branch_protection_policies(policy_id) ON DELETE CASCADE,
    reviewer_role TEXT NOT NULL,
    required_count INTEGER NOT NULL,
    UNIQUE (policy_id, reviewer_role),
    CHECK (required_count > 0)
);

CREATE INDEX idx_pr_target_state
    ON pull_requests(target_branch_id, state);

CREATE INDEX idx_reviews_pr_state
    ON reviews(pull_request_id, state);

CREATE INDEX idx_status_checks_pr_state
    ON status_checks(pull_request_id, state);

CREATE INDEX idx_comments_review_resolved
    ON review_comments(review_id, resolved);

INSERT INTO repositories (repository_name)
VALUES ('collision-resistant-repository');

INSERT INTO branches (
    repository_id,
    branch_name,
    protected
)
VALUES
    (1, 'main', TRUE),
    (1, 'feature/hash-analysis', FALSE);

INSERT INTO commits (
    repository_id,
    commit_sha,
    message,
    content_digest,
    author_name
)
VALUES
(
    1,
    repeat('a', 64),
    'Add collision-resistance analysis',
    repeat('1', 64),
    'developer-a'
),
(
    1,
    repeat('b', 64),
    'Update validation after review',
    repeat('2', 64),
    'developer-a'
);

UPDATE branches
SET head_commit_sha = repeat('a', 64)
WHERE branch_name = 'main';

UPDATE branches
SET head_commit_sha = repeat('b', 64)
WHERE branch_name = 'feature/hash-analysis';

INSERT INTO reviewers (repository_id, username)
VALUES
    (1, 'reviewer-a'),
    (1, 'reviewer-b'),
    (1, 'reviewer-c');

INSERT INTO branch_protection_policies (
    branch_id,
    required_approvals,
    require_passing_checks,
    require_conversations_resolved,
    require_linear_history,
    allow_force_push,
    allow_direct_push,
    allow_administrator_bypass
)
VALUES (
    1,
    2,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    FALSE
);

INSERT INTO approval_requirements (
    policy_id,
    reviewer_role,
    required_count
)
VALUES
    (1, 'maintainer', 1),
    (1, 'security-reviewer', 1);

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    head_commit_id,
    title,
    description,
    state,
    is_draft
)
VALUES (
    1,
    2,
    1,
    2,
    'Evaluate collision resistance of repository digests',
    'Tests cryptographic digest handling and governance controls.',
    'open',
    FALSE
);

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_id,
    body
)
VALUES
    (1, 1, 'approved', 2, 'Digest selection and validation are correct.'),
    (1, 2, 'approved', 2, 'Collision-security assumptions are documented.'),
    (1, 3, 'commented', 2, 'Consider documenting truncated-digest risks.');

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
VALUES
    (3, 'src/hash_policy.py', 42,
     'Truncated hashes must not be used as security identifiers.',
     TRUE);

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    state,
    completed_at
)
VALUES
    (1, 'unit-tests', 'passing', clock_timestamp()),
    (1, 'security-scan', 'passing', clock_timestamp()),
    (1, 'collision-policy-check', 'passing', clock_timestamp());

CREATE OR REPLACE FUNCTION unresolved_conversation_count(
    p_pull_request_id BIGINT
)
RETURNS INTEGER
LANGUAGE SQL
STABLE
AS $$
    SELECT COUNT(*)::INTEGER
    FROM review_comments rc
    JOIN reviews r ON r.review_id = rc.review_id
    WHERE r.pull_request_id = p_pull_request_id
      AND rc.resolved = FALSE;
$$;

CREATE OR REPLACE FUNCTION approval_count(
    p_pull_request_id BIGINT,
    p_head_commit_id BIGINT
)
RETURNS INTEGER
LANGUAGE SQL
STABLE
AS $$
    SELECT COUNT(DISTINCT r.reviewer_id)::INTEGER
    FROM reviews r
    JOIN reviewers rv ON rv.reviewer_id = r.reviewer_id
    WHERE r.pull_request_id = p_pull_request_id
      AND r.commit_id = p_head_commit_id
      AND rv.active = TRUE
      AND r.state = 'approved';
$$;

CREATE OR REPLACE FUNCTION passing_check_count(
    p_pull_request_id BIGINT
)
RETURNS INTEGER
LANGUAGE SQL
STABLE
AS $$
    SELECT COUNT(*)::INTEGER
    FROM status_checks
    WHERE pull_request_id = p_pull_request_id
      AND state = 'passing';
$$;

CREATE OR REPLACE FUNCTION failing_check_count(
    p_pull_request_id BIGINT
)
RETURNS INTEGER
LANGUAGE SQL
STABLE
AS $$
    SELECT COUNT(*)::INTEGER
    FROM status_checks
    WHERE pull_request_id = p_pull_request_id
      AND state = 'failing';
$$;

CREATE OR REPLACE FUNCTION merge_eligibility(
    p_pull_request_id BIGINT
)
RETURNS TABLE (
    eligible BOOLEAN,
    approval_requirement_met BOOLEAN,
    checks_requirement_met BOOLEAN,
    conversation_requirement_met BOOLEAN,
    branch_protection_active BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_pr pull_requests%ROWTYPE;
    v_policy branch_protection_policies%ROWTYPE;
    v_approvals INTEGER;
    v_unresolved INTEGER;
    v_passing INTEGER;
    v_failing INTEGER;
BEGIN
    SELECT *
    INTO v_pr
    FROM pull_requests
    WHERE pull_request_id = p_pull_request_id;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, FALSE, FALSE, FALSE, FALSE,
               'Pull Request does not exist';
        RETURN;
    END IF;

    SELECT bpp.*
    INTO v_policy
    FROM branch_protection_policies bpp
    JOIN branches b ON b.branch_id = bpp.branch_id
    WHERE b.branch_id = v_pr.target_branch_id;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT
            v_pr.state = 'open',
            TRUE,
            TRUE,
            TRUE,
            FALSE,
            CASE
                WHEN v_pr.state = 'open'
                THEN 'No branch protection policy is configured'
                ELSE 'Pull Request is not open'
            END;
        RETURN;
    END IF;

    v_approvals :=
        approval_count(p_pull_request_id, v_pr.head_commit_id);

    v_unresolved :=
        unresolved_conversation_count(p_pull_request_id);

    v_passing :=
        passing_check_count(p_pull_request_id);

    v_failing :=
        failing_check_count(p_pull_request_id);

    RETURN QUERY
    SELECT
        v_pr.state = 'open'
        AND v_approvals >= v_policy.required_approvals
        AND (
            NOT v_policy.require_passing_checks
            OR (v_failing = 0 AND v_passing > 0)
        )
        AND (
            NOT v_policy.require_conversations_resolved
            OR v_unresolved = 0
        ),
        v_approvals >= v_policy.required_approvals,
        (
            NOT v_policy.require_passing_checks
            OR (v_failing = 0 AND v_passing > 0)
        ),
        (
            NOT v_policy.require_conversations_resolved
            OR v_unresolved = 0
        ),
        TRUE,
        CASE
            WHEN v_pr.state <> 'open'
                THEN 'Pull Request is not open'
            WHEN v_approvals < v_policy.required_approvals
                THEN 'Required approvals are missing'
            WHEN v_policy.require_passing_checks
                 AND (v_failing > 0 OR v_passing = 0)
                THEN 'Required status checks are not passing'
            WHEN v_policy.require_conversations_resolved
                 AND v_unresolved > 0
                THEN 'Unresolved review conversations remain'
            ELSE 'All configured merge conditions are satisfied'
        END;
END;
$$;

CREATE OR REPLACE FUNCTION prevent_direct_protected_branch_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.protected AND NEW.head_commit_sha IS DISTINCT FROM OLD.head_commit_sha THEN
        RAISE EXCEPTION
            'Direct branch-head changes are prohibited for protected branches';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protected_branch_head
BEFORE UPDATE OF head_commit_sha ON branches
FOR EACH ROW
EXECUTE FUNCTION prevent_direct_protected_branch_update();

CREATE OR REPLACE FUNCTION refresh_stale_approvals()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.head_commit_id IS DISTINCT FROM OLD.head_commit_id THEN
        UPDATE reviews
        SET state = 'dismissed'
        WHERE pull_request_id = NEW.pull_request_id
          AND state = 'approved'
          AND commit_id <> NEW.head_commit_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_refresh_stale_approvals
AFTER UPDATE OF head_commit_id ON pull_requests
FOR EACH ROW
EXECUTE FUNCTION refresh_stale_approvals();

-- Retrieval: identify commits and their cryptographic content digests.
SELECT
    commit_id,
    commit_sha,
    message,
    content_digest,
    author_name
FROM commits
ORDER BY commit_id;

-- Validation: detect duplicate content digests within a repository.
SELECT
    repository_id,
    content_digest,
    COUNT(*) AS occurrence_count
FROM commits
GROUP BY repository_id, content_digest
HAVING COUNT(*) > 1;

-- Review reporting: current review decisions.
SELECT
    pr.pull_request_id,
    rv.username,
    r.state,
    r.commit_id,
    r.submitted_at
FROM pull_requests pr
JOIN reviews r
    ON r.pull_request_id = pr.pull_request_id
JOIN reviewers rv
    ON rv.reviewer_id = r.reviewer_id
ORDER BY pr.pull_request_id, r.submitted_at;

-- Status reporting.
SELECT
    pr.pull_request_id,
    sc.check_name,
    sc.state
FROM pull_requests pr
JOIN status_checks sc
    ON sc.pull_request_id = pr.pull_request_id
ORDER BY pr.pull_request_id, sc.check_name;

-- Collision-resistance-oriented digest statistics.
SELECT
    COUNT(*) AS total_commits,
    COUNT(DISTINCT content_digest) AS distinct_content_digests,
    COUNT(*) - COUNT(DISTINCT content_digest) AS duplicate_digest_count
FROM commits;

-- Full merge-eligibility evaluation.
SELECT *
FROM merge_eligibility(1);

-- Transactional merge workflow.
BEGIN;

SELECT *
FROM merge_eligibility(1)
FOR UPDATE;

UPDATE pull_requests
SET state = 'merged',
    merged_at = clock_timestamp()
WHERE pull_request_id = 1
  AND state = 'open'
  AND (SELECT eligible FROM merge_eligibility(1));

COMMIT;

-- The following query exposes the final workflow state.
SELECT
    pull_request_id,
    state,
    is_draft,
    opened_at,
    merged_at
FROM pull_requests
WHERE pull_request_id = 1;
