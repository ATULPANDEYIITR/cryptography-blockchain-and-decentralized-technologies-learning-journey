DROP SCHEMA IF EXISTS birthday_hash_lab CASCADE;
CREATE SCHEMA birthday_hash_lab;
SET search_path TO birthday_hash_lab, public;

-- The relational model separates repository state, proposed changes,
-- review decisions, automated checks, and branch-level enforcement.

CREATE TYPE repository_visibility AS ENUM ('PRIVATE', 'INTERNAL', 'PUBLIC');
CREATE TYPE branch_type AS ENUM ('PROTECTED', 'UNPROTECTED');
CREATE TYPE pr_state AS ENUM ('DRAFT', 'OPEN', 'CHANGES_REQUESTED', 'MERGED', 'CLOSED');
CREATE TYPE review_state AS ENUM ('APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED');
CREATE TYPE check_state AS ENUM ('PASS', 'FAIL', 'PENDING');
CREATE TYPE comment_state AS ENUM ('OPEN', 'RESOLVED');
CREATE TYPE merge_strategy AS ENUM ('MERGE_COMMIT', 'SQUASH', 'REBASE');
CREATE TYPE decision_state AS ENUM ('ELIGIBLE', 'BLOCKED', 'MERGED');

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    visibility repository_visibility NOT NULL DEFAULT 'PRIVATE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (owner_name, name),
    CHECK (length(trim(name)) >= 2)
);

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_administrator BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (username ~ '^[A-Za-z0-9_.-]{2,64}$')
);

CREATE TABLE repository_members (
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_name TEXT NOT NULL CHECK (role_name IN ('OWNER', 'MAINTAINER', 'DEVELOPER', 'REVIEWER')),
    PRIMARY KEY (repository_id, user_id)
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    branch_kind branch_type NOT NULL DEFAULT 'UNPROTECTED',
    head_commit_sha CHAR(64),
    UNIQUE (repository_id, name),
    CHECK (name <> '')
);

CREATE TABLE commits (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    sha CHAR(64) NOT NULL UNIQUE,
    author_id BIGINT NOT NULL REFERENCES users(user_id),
    parent_sha CHAR(64),
    message TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (sha ~ '^[0-9a-f]{64}$'),
    CHECK (length(trim(message)) > 0)
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    author_id BIGINT NOT NULL REFERENCES users(user_id),
    state pr_state NOT NULL DEFAULT 'DRAFT',
    title TEXT NOT NULL,
    base_head_sha CHAR(64) NOT NULL,
    source_head_sha CHAR(64) NOT NULL,
    is_synchronized BOOLEAN NOT NULL DEFAULT FALSE,
    has_merge_conflict BOOLEAN NOT NULL DEFAULT FALSE,
    merge_strategy merge_strategy,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id),
    CHECK (length(trim(title)) > 0)
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    commit_id BIGINT NOT NULL REFERENCES commits(commit_id),
    commit_order INTEGER NOT NULL,
    PRIMARY KEY (pull_request_id, commit_id),
    UNIQUE (pull_request_id, commit_order),
    CHECK (commit_order > 0)
);

CREATE TABLE reviewers (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(user_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pull_request_id, user_id)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES users(user_id),
    state review_state NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    commit_sha CHAR(64) NOT NULL,
    dismissed_at TIMESTAMPTZ,
    CHECK (
        (state = 'DISMISSED' AND dismissed_at IS NOT NULL)
        OR
        (state <> 'DISMISSED')
    )
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id) ON DELETE CASCADE,
    author_id BIGINT NOT NULL REFERENCES users(user_id),
    file_path TEXT NOT NULL,
    line_number INTEGER,
    body TEXT NOT NULL,
    state comment_state NOT NULL DEFAULT 'OPEN',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    CHECK (length(trim(file_path)) > 0),
    CHECK (length(trim(body)) > 0),
    CHECK (line_number IS NULL OR line_number > 0),
    CHECK (
        (state = 'RESOLVED' AND resolved_at IS NOT NULL)
        OR
        (state = 'OPEN')
    )
);

CREATE TABLE status_checks (
    check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    state check_state NOT NULL,
    commit_sha CHAR(64) NOT NULL,
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name, commit_sha)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branches(branch_id) ON DELETE CASCADE,
    required_reviews INTEGER NOT NULL DEFAULT 1,
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_conversations_resolved BOOLEAN NOT NULL DEFAULT TRUE,
    allow_direct_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_branch_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (required_reviews >= 0)
);

CREATE TABLE approval_requirements (
    requirement_id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES branch_protection_policies(policy_id) ON DELETE CASCADE,
    reviewer_role TEXT,
    required_count INTEGER NOT NULL,
    UNIQUE (policy_id, reviewer_role),
    CHECK (required_count > 0)
);

CREATE TABLE merge_eligibility (
    eligibility_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    decision decision_state NOT NULL,
    reason TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pr_repository_state
    ON pull_requests(repository_id, state);

CREATE INDEX idx_reviews_pr_reviewer_time
    ON reviews(pull_request_id, reviewer_id, submitted_at DESC);

CREATE INDEX idx_status_checks_pr_state
    ON status_checks(pull_request_id, state);

CREATE INDEX idx_comments_review_state
    ON review_comments(review_id, state);

CREATE OR REPLACE FUNCTION prevent_invalid_review_reviewer()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM reviewers r
        WHERE r.pull_request_id = NEW.pull_request_id
          AND r.user_id = NEW.reviewer_id
    ) THEN
        RAISE EXCEPTION
            'Reviewer % is not assigned to pull request %',
            NEW.reviewer_id, NEW.pull_request_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_review_reviewer
BEFORE INSERT ON reviews
FOR EACH ROW
EXECUTE FUNCTION prevent_invalid_review_reviewer();

CREATE OR REPLACE FUNCTION evaluate_merge_eligibility(p_pr BIGINT)
RETURNS TABLE (
    decision decision_state,
    reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    target_branch BIGINT;
    required_reviews INTEGER;
    require_checks BOOLEAN;
    require_conversations BOOLEAN;
    linear_required BOOLEAN;
    approvals INTEGER;
    unresolved_comments INTEGER;
    failed_checks INTEGER;
    pending_checks INTEGER;
    pr_state_value pr_state;
    synchronized BOOLEAN;
    conflict BOOLEAN;
BEGIN
    SELECT
        pr.target_branch_id,
        pr.state,
        pr.is_synchronized,
        pr.has_merge_conflict,
        bp.required_reviews,
        bp.require_status_checks,
        bp.require_conversations_resolved,
        bp.require_linear_history
    INTO
        target_branch,
        pr_state_value,
        synchronized,
        conflict,
        required_reviews,
        require_checks,
        require_conversations,
        linear_required
    FROM pull_requests pr
    JOIN branches b
      ON b.branch_id = pr.target_branch_id
    LEFT JOIN branch_protection_policies bp
      ON bp.branch_id = b.branch_id
    WHERE pr.pull_request_id = p_pr;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Pull Request does not exist';
        RETURN;
    END IF;

    required_reviews := COALESCE(required_reviews, 0);
    require_checks := COALESCE(require_checks, FALSE);
    require_conversations := COALESCE(require_conversations, FALSE);
    linear_required := COALESCE(linear_required, FALSE);

    IF pr_state_value IN ('DRAFT', 'CLOSED', 'MERGED') THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Pull Request state cannot be merged';
        RETURN;
    END IF;

    IF NOT synchronized THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Source branch is not synchronized with target';
        RETURN;
    END IF;

    IF conflict THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Merge conflict must be resolved';
        RETURN;
    END IF;

    SELECT count(DISTINCT reviewer_id)
    INTO approvals
    FROM (
        SELECT DISTINCT ON (reviewer_id)
            reviewer_id,
            state
        FROM reviews
        WHERE pull_request_id = p_pr
        ORDER BY reviewer_id, submitted_at DESC, review_id DESC
    ) latest
    WHERE latest.state = 'APPROVED';

    IF EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (reviewer_id)
                reviewer_id,
                state
            FROM reviews
            WHERE pull_request_id = p_pr
            ORDER BY reviewer_id, submitted_at DESC, review_id DESC
        ) latest
        WHERE latest.state = 'CHANGES_REQUESTED'
    ) THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Latest reviewer decision requests changes';
        RETURN;
    END IF;

    IF approvals < required_reviews THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state,
            format('Only %s of %s required approvals are current',
                   approvals, required_reviews);
        RETURN;
    END IF;

    SELECT count(*)
    INTO unresolved_comments
    FROM review_comments rc
    JOIN reviews r ON r.review_id = rc.review_id
    WHERE r.pull_request_id = p_pr
      AND rc.state = 'OPEN';

    IF require_conversations AND unresolved_comments > 0 THEN
        RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Unresolved review conversations remain';
        RETURN;
    END IF;

    SELECT
        count(*) FILTER (WHERE state = 'FAIL'),
        count(*) FILTER (WHERE state = 'PENDING')
    INTO failed_checks, pending_checks
    FROM status_checks
    WHERE pull_request_id = p_pr;

    IF require_checks THEN
        IF failed_checks > 0 THEN
            RETURN QUERY SELECT 'BLOCKED'::decision_state, 'One or more required checks failed';
            RETURN;
        END IF;

        IF pending_checks > 0 THEN
            RETURN QUERY SELECT 'BLOCKED'::decision_state, 'One or more required checks are pending';
            RETURN;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM status_checks WHERE pull_request_id = p_pr
        ) THEN
            RETURN QUERY SELECT 'BLOCKED'::decision_state, 'Required status checks have not executed';
            RETURN;
        END IF;
    END IF;

    IF linear_required THEN
        -- This example records linear-history enforcement at policy level.
        -- A production Git integration would validate the actual commit graph.
        IF EXISTS (
            SELECT 1
            FROM pull_requests
            WHERE pull_request_id = p_pr
              AND source_head_sha = base_head_sha
        ) THEN
            RETURN QUERY SELECT 'BLOCKED'::decision_state,
                'Source and target heads are unexpectedly identical';
            RETURN;
        END IF;
    END IF;

    RETURN QUERY SELECT 'ELIGIBLE'::decision_state, 'All merge requirements satisfied';
END;
$$;

CREATE OR REPLACE FUNCTION record_merge_decision()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    d decision_state;
BEGIN
    SELECT decision
    INTO d
    FROM evaluate_merge_eligibility(NEW.pull_request_id);

    IF d = 'ELIGIBLE' AND NEW.state = 'MERGED' THEN
        NEW.merged_at := COALESCE(NEW.merged_at, CURRENT_TIMESTAMP);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_merge_decision
BEFORE UPDATE OF state ON pull_requests
FOR EACH ROW
EXECUTE FUNCTION record_merge_decision();

INSERT INTO repositories (name, owner_name, visibility)
VALUES
    ('cryptographic-platform', 'security-team', 'PRIVATE'),
    ('hash-research', 'research-team', 'INTERNAL');

INSERT INTO users (username, is_active, is_administrator)
VALUES
    ('alice', TRUE, FALSE),
    ('bob', TRUE, FALSE),
    ('carol', TRUE, FALSE),
    ('dave', TRUE, FALSE),
    ('root-admin', TRUE, TRUE);

INSERT INTO repository_members (repository_id, user_id, role_name)
SELECT r.repository_id, u.user_id, x.role_name
FROM repositories r
JOIN (
    VALUES
        ('alice', 'MAINTAINER'),
        ('bob', 'REVIEWER'),
        ('carol', 'REVIEWER'),
        ('dave', 'DEVELOPER')
) AS x(username, role_name) ON TRUE
JOIN users u ON u.username = x.username
WHERE r.name = 'cryptographic-platform';

INSERT INTO branches (repository_id, name, branch_kind, head_commit_sha)
SELECT repository_id, 'main', 'PROTECTED',
       'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FROM repositories
WHERE name = 'cryptographic-platform';

INSERT INTO branches (repository_id, name, branch_kind, head_commit_sha)
SELECT repository_id, 'feature/hash-audit', 'UNPROTECTED',
       'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
FROM repositories
WHERE name = 'cryptographic-platform';

INSERT INTO branches (repository_id, name, branch_kind, head_commit_sha)
SELECT repository_id, 'feature/blocked', 'UNPROTECTED',
       'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
FROM repositories
WHERE name = 'cryptographic-platform';

INSERT INTO branch_protection_policies (
    branch_id,
    required_reviews,
    require_status_checks,
    require_conversations_resolved,
    allow_direct_push,
    allow_force_push,
    allow_branch_deletion,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    FALSE
FROM branches
WHERE name = 'main';

INSERT INTO approval_requirements (policy_id, reviewer_role, required_count)
SELECT policy_id, 'REVIEWER', 2
FROM branch_protection_policies
JOIN branches USING (branch_id)
WHERE branches.name = 'main';

INSERT INTO commits (repository_id, sha, author_id, message)
SELECT
    r.repository_id,
    x.sha,
    u.user_id,
    x.message
FROM repositories r
CROSS JOIN (
    VALUES
    ('1111111111111111111111111111111111111111111111111111111111111111',
     'Implement collision-analysis service'),
    ('2222222222222222222222222222222222222222222222222222222222222222',
     'Add hash truncation validation'),
    ('3333333333333333333333333333333333333333333333333333333333333333',
     'Add security policy tests')
) AS x(sha, message)
JOIN users u ON u.username = 'dave'
WHERE r.name = 'cryptographic-platform';

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    author_id,
    state,
    title,
    base_head_sha,
    source_head_sha,
    is_synchronized,
    has_merge_conflict
)
SELECT
    r.repository_id,
    sb.branch_id,
    tb.branch_id,
    u.user_id,
    'OPEN',
    'Evaluate birthday-collision security',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    TRUE,
    FALSE
FROM repositories r
JOIN branches sb ON sb.repository_id = r.repository_id
JOIN branches tb ON tb.repository_id = r.repository_id
JOIN users u ON u.username = 'dave'
WHERE r.name = 'cryptographic-platform'
  AND sb.name = 'feature/hash-audit'
  AND tb.name = 'main';

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    author_id,
    state,
    title,
    base_head_sha,
    source_head_sha,
    is_synchronized,
    has_merge_conflict
)
SELECT
    r.repository_id,
    sb.branch_id,
    tb.branch_id,
    u.user_id,
    'OPEN',
    'Blocked collision-policy change',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    TRUE,
    TRUE
FROM repositories r
JOIN branches sb ON sb.repository_id = r.repository_id
JOIN branches tb ON tb.repository_id = r.repository_id
JOIN users u ON u.username = 'dave'
WHERE r.name = 'cryptographic-platform'
  AND sb.name = 'feature/blocked'
  AND tb.name = 'main';

INSERT INTO pull_request_commits (pull_request_id, commit_id, commit_order)
SELECT
    pr.pull_request_id,
    c.commit_id,
    row_number() OVER (ORDER BY c.commit_id)
FROM pull_requests pr
JOIN commits c ON c.repository_id = pr.repository_id
WHERE pr.title = 'Evaluate birthday-collision security';

INSERT INTO reviewers (pull_request_id, user_id)
SELECT pr.pull_request_id, u.user_id
FROM pull_requests pr
CROSS JOIN users u
WHERE pr.title = 'Evaluate birthday-collision security'
  AND u.username IN ('bob', 'carol');

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_sha
)
SELECT
    pr.pull_request_id,
    u.user_id,
    'APPROVED',
    pr.source_head_sha
FROM pull_requests pr
JOIN users u ON u.username IN ('bob', 'carol')
WHERE pr.title = 'Evaluate birthday-collision security';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    state,
    commit_sha,
    completed_at
)
SELECT
    pr.pull_request_id,
    x.check_name,
    'PASS',
    pr.source_head_sha,
    CURRENT_TIMESTAMP
FROM pull_requests pr
CROSS JOIN (
    VALUES ('unit-tests'), ('security-scan'), ('static-analysis')
) AS x(check_name)
WHERE pr.title = 'Evaluate birthday-collision security';

INSERT INTO review_comments (
    review_id,
    author_id,
    file_path,
    line_number,
    body,
    state
)
SELECT
    rv.review_id,
    u.user_id,
    'hash_policy.py',
    42,
    'Clarify why digest truncation reduces collision security.',
    'RESOLVED'
FROM reviews rv
JOIN pull_requests pr ON pr.pull_request_id = rv.pull_request_id
JOIN users u ON u.username = 'bob'
WHERE pr.title = 'Evaluate birthday-collision security'
LIMIT 1;

-- Retrieval: current review decisions.
SELECT
    pr.pull_request_id,
    pr.title,
    u.username AS author,
    pr.state,
    pr.is_synchronized,
    pr.has_merge_conflict
FROM pull_requests pr
JOIN users u ON u.user_id = pr.author_id
ORDER BY pr.pull_request_id;

-- Evaluation: exact merge-eligibility decision.
SELECT *
FROM evaluate_merge_eligibility(
    (
        SELECT pull_request_id
        FROM pull_requests
        WHERE title = 'Evaluate birthday-collision security'
    )
);

-- Failure case: the conflicted PR must remain blocked.
SELECT *
FROM evaluate_merge_eligibility(
    (
        SELECT pull_request_id
        FROM pull_requests
        WHERE title = 'Blocked collision-policy change'
    )
);

-- Approval reporting: use the latest review from each reviewer.
WITH latest_reviews AS (
    SELECT DISTINCT ON (pull_request_id, reviewer_id)
        pull_request_id,
        reviewer_id,
        state,
        submitted_at
    FROM reviews
    ORDER BY pull_request_id, reviewer_id, submitted_at DESC, review_id DESC
)
SELECT
    pr.pull_request_id,
    pr.title,
    count(*) FILTER (WHERE lr.state = 'APPROVED') AS current_approvals,
    count(*) FILTER (WHERE lr.state = 'CHANGES_REQUESTED') AS change_requests
FROM pull_requests pr
LEFT JOIN latest_reviews lr
    ON lr.pull_request_id = pr.pull_request_id
GROUP BY pr.pull_request_id, pr.title
ORDER BY pr.pull_request_id;

-- Status aggregation.
SELECT
    pr.pull_request_id,
    sc.check_name,
    sc.state,
    sc.commit_sha
FROM pull_requests pr
JOIN status_checks sc ON sc.pull_request_id = pr.pull_request_id
ORDER BY pr.pull_request_id, sc.check_name;

-- Repository governance report.
SELECT
    r.name AS repository,
    b.name AS branch,
    bp.required_reviews,
    bp.require_status_checks,
    bp.require_conversations_resolved,
    bp.allow_direct_push,
    bp.allow_force_push,
    bp.allow_branch_deletion,
    bp.require_linear_history,
    bp.allow_administrator_bypass
FROM repositories r
JOIN branches b ON b.repository_id = r.repository_id
JOIN branch_protection_policies bp ON bp.branch_id = b.branch_id
ORDER BY r.name, b.name;

-- Birthday-problem calculation for a 365-outcome space.
WITH RECURSIVE collision AS (
    SELECT
        1::numeric AS i,
        1::numeric AS probability_no_collision
    UNION ALL
    SELECT
        i + 1,
        probability_no_collision * (365 - i) / 365
    FROM collision
    WHERE i < 23
)
SELECT
    23 AS samples,
    1 - probability_no_collision AS collision_probability
FROM collision
WHERE i = 23;

-- Generic birthday approximation:
-- P(collision) ≈ 1 - exp(-k(k-1)/(2N)).
SELECT
    23 AS samples,
    365 AS space_size,
    1 - exp(
        -(23.0 * 22.0) / (2.0 * 365.0)
    ) AS approximate_collision_probability;

-- A k-bit hash has approximately k/2 bits of generic collision security.
SELECT
    bits,
    bits / 2.0 AS approximate_collision_security_bits
FROM (
    VALUES (64), (128), (160), (256)
) AS hashes(bits);

-- Transactional workflow example. A merge is allowed only after an
-- eligibility decision is recorded and the Pull Request is currently eligible.
BEGIN;

DO $$
DECLARE
    v_pr BIGINT;
    v_decision decision_state;
    v_reason TEXT;
BEGIN
    SELECT pull_request_id
    INTO v_pr
    FROM pull_requests
    WHERE title = 'Evaluate birthday-collision security'
    FOR UPDATE;

    SELECT decision, reason
    INTO v_decision, v_reason
    FROM evaluate_merge_eligibility(v_pr);

    INSERT INTO merge_eligibility (pull_request_id, decision, reason)
    VALUES (v_pr, v_decision, v_reason);

    IF v_decision <> 'ELIGIBLE' THEN
        RAISE EXCEPTION 'Merge blocked: %', v_reason;
    END IF;

    UPDATE pull_requests
    SET state = 'MERGED',
        merge_strategy = 'SQUASH',
        merged_at = CURRENT_TIMESTAMP
    WHERE pull_request_id = v_pr;
END $$;

COMMIT;

-- Final workflow state.
SELECT
    pull_request_id,
    title,
    state,
    merge_strategy,
    merged_at
FROM pull_requests
WHERE title = 'Evaluate birthday-collision security';
