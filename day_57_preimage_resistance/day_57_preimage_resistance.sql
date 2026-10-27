-- Preimage resistance relational model.
--
-- The schema separates:
--   repository change proposal
--   branch and commit state
--   review decisions
--   review comments and conversations
--   automated status checks
--   approval policy
--   branch protection
--   cryptographic artifact digests
--   merge eligibility
--
-- SHA-256 is supplied as trusted digest evidence by the application layer.
-- PostgreSQL stores and compares the resulting digest. This avoids pretending
-- that the database's generic digest functions alone provide application
-- authentication or a secure password-storage design.

DROP SCHEMA IF EXISTS preimage_resistance CASCADE;
CREATE SCHEMA preimage_resistance;

SET search_path TO preimage_resistance, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE pull_request_state AS ENUM (
    'draft',
    'open',
    'closed',
    'merged'
);

CREATE TYPE review_state AS ENUM (
    'commented',
    'changes_requested',
    'approved',
    'dismissed'
);

CREATE TYPE check_state AS ENUM (
    'pending',
    'passing',
    'failing'
);

CREATE TYPE conversation_state AS ENUM (
    'open',
    'resolved'
);

CREATE TABLE repository (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(trim(name)) >= 2)
);

CREATE TABLE repository_user (
    user_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (length(trim(username)) >= 2),
    CHECK (length(trim(display_name)) >= 2)
);

CREATE TABLE branch (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repository(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, name),
    CHECK (length(trim(name)) >= 1)
);

CREATE TABLE commit_record (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repository(repository_id) ON DELETE CASCADE,
    branch_id BIGINT NOT NULL
        REFERENCES branch(branch_id),
    commit_hash TEXT NOT NULL UNIQUE,
    message TEXT NOT NULL,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    parent_commit_id BIGINT REFERENCES commit_record(commit_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(commit_hash) >= 7),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX idx_commit_branch_created
    ON commit_record(branch_id, created_at DESC);

CREATE TABLE pull_request (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repository(repository_id) ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL
        REFERENCES branch(branch_id),
    target_branch_id BIGINT NOT NULL
        REFERENCES branch(branch_id),
    head_commit_id BIGINT NOT NULL
        REFERENCES commit_record(commit_id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state pull_request_state NOT NULL DEFAULT 'draft',
    draft BOOLEAN NOT NULL DEFAULT TRUE,
    base_synchronized BOOLEAN NOT NULL DEFAULT FALSE,
    created_by BIGINT NOT NULL
        REFERENCES repository_user(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id),
    CHECK (
        (state = 'merged' AND merged_at IS NOT NULL)
        OR state <> 'merged'
    ),
    CHECK (
        (state = 'closed' AND closed_at IS NOT NULL)
        OR state <> 'closed'
    )
);

CREATE INDEX idx_pull_request_target_state
    ON pull_request(target_branch_id, state);

CREATE INDEX idx_pull_request_head
    ON pull_request(head_commit_id);

CREATE TABLE review (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES repository_user(user_id),
    state review_state NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    stale BOOLEAN NOT NULL DEFAULT FALSE,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_review_pr_state
    ON review(pull_request_id, state);

CREATE TABLE review_comment (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES review(review_id) ON DELETE CASCADE,
    author_id BIGINT NOT NULL
        REFERENCES repository_user(user_id),
    file_path TEXT NOT NULL,
    line_number INTEGER,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(trim(body)) > 0),
    CHECK (line_number IS NULL OR line_number > 0)
);

CREATE TABLE conversation (
    conversation_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    review_comment_id BIGINT
        REFERENCES review_comment(comment_id) ON DELETE SET NULL,
    state conversation_state NOT NULL DEFAULT 'open',
    resolved_by BIGINT REFERENCES repository_user(user_id),
    resolved_at TIMESTAMPTZ,
    CHECK (
        (state = 'resolved' AND resolved_by IS NOT NULL AND resolved_at IS NOT NULL)
        OR state = 'open'
    )
);

CREATE INDEX idx_conversation_pr_state
    ON conversation(pull_request_id, state);

CREATE TABLE status_check (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    state check_state NOT NULL DEFAULT 'pending',
    observed_commit_id BIGINT
        REFERENCES commit_record(commit_id),
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE INDEX idx_status_check_pr_state
    ON status_check(pull_request_id, state);

CREATE TABLE branch_protection_policy (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE
        REFERENCES branch(branch_id) ON DELETE CASCADE,
    require_pull_request BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_deletion BOOLEAN NOT NULL DEFAULT TRUE,
    require_resolved_conversations BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE approval_requirement (
    approval_requirement_id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policy(policy_id) ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL,
    require_distinct_reviewers BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (policy_id),
    CHECK (required_approvals >= 0)
);

CREATE TABLE eligible_reviewer (
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policy(policy_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL
        REFERENCES repository_user(user_id),
    PRIMARY KEY (policy_id, reviewer_id)
);

CREATE TABLE required_status_check (
    policy_id BIGINT NOT NULL
        REFERENCES branch_protection_policy(policy_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    PRIMARY KEY (policy_id, check_name),
    CHECK (length(trim(check_name)) > 0)
);

CREATE TABLE merge_record (
    merge_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL UNIQUE
        REFERENCES pull_request(pull_request_id),
    merged_by BIGINT NOT NULL
        REFERENCES repository_user(user_id),
    merge_strategy TEXT NOT NULL,
    merged_commit_hash TEXT NOT NULL,
    merged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (merge_strategy IN ('merge_commit', 'squash', 'rebase')),
    CHECK (length(trim(merged_commit_hash)) >= 7)
);

CREATE TABLE integrity_verification (
    verification_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL
        REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    commit_id BIGINT NOT NULL
        REFERENCES commit_record(commit_id),
    algorithm TEXT NOT NULL DEFAULT 'SHA-256',
    expected_digest TEXT NOT NULL,
    observed_digest TEXT NOT NULL,
    verified BOOLEAN NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (algorithm = 'SHA-256'),
    CHECK (expected_digest ~ '^[0-9a-f]{64}$'),
    CHECK (observed_digest ~ '^[0-9a-f]{64}$')
);

-- Digest values are represented as SHA-256 hexadecimal strings.
-- pgcrypto.digest() is used to verify stored commit content.
CREATE OR REPLACE FUNCTION verify_commit_digest(
    p_commit_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT encode(digest(content, 'sha256'), 'hex') = content_sha256
    FROM commit_record
    WHERE commit_id = p_commit_id;
$$;

-- Prevent direct marking of a pull request as merged unless a merge record
-- exists. The merge record itself is inserted only after eligibility checks.
CREATE OR REPLACE FUNCTION enforce_merged_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'merged' THEN
        IF NEW.merged_at IS NULL THEN
            NEW.merged_at := now();
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM merge_record
            WHERE pull_request_id = NEW.pull_request_id
        ) THEN
            RAISE EXCEPTION
                'Pull request % cannot enter merged state without merge record',
                NEW.pull_request_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_merged_state
BEFORE UPDATE ON pull_request
FOR EACH ROW
EXECUTE FUNCTION enforce_merged_state();

-- Prevent approvals from inactive reviewers.
CREATE OR REPLACE FUNCTION enforce_reviewer_activity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    reviewer_active BOOLEAN;
BEGIN
    SELECT active
    INTO reviewer_active
    FROM repository_user
    WHERE user_id = NEW.reviewer_id;

    IF NEW.state = 'approved' AND COALESCE(reviewer_active, FALSE) = FALSE THEN
        RAISE EXCEPTION
            'Inactive or unknown reviewer % cannot submit an approval',
            NEW.reviewer_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_reviewer_activity
BEFORE INSERT OR UPDATE ON review
FOR EACH ROW
EXECUTE FUNCTION enforce_reviewer_activity();

INSERT INTO repository (name)
VALUES ('security-platform');

INSERT INTO repository_user (username, display_name, active)
VALUES
    ('alice', 'Alice Reviewer', TRUE),
    ('bob', 'Bob Reviewer', TRUE),
    ('carol', 'Carol Reviewer', TRUE),
    ('disabled-reviewer', 'Disabled Reviewer', FALSE);

INSERT INTO branch (repository_id, name, protected)
SELECT repository_id, 'main', TRUE
FROM repository
WHERE name = 'security-platform';

INSERT INTO branch (repository_id, name, protected)
SELECT repository_id, 'feature/preimage', FALSE
FROM repository
WHERE name = 'security-platform';

INSERT INTO commit_record (
    repository_id,
    branch_id,
    commit_hash,
    message,
    content,
    content_sha256
)
SELECT
    r.repository_id,
    b.branch_id,
    'a1b2c3d4e5f6',
    'Add digest verification policy',
    'branch protection requires two approvals',
    encode(
        digest('branch protection requires two approvals', 'sha256'),
        'hex'
    )
FROM repository r
JOIN branch b
    ON b.repository_id = r.repository_id
WHERE r.name = 'security-platform'
  AND b.name = 'feature/preimage';

INSERT INTO branch_protection_policy (
    branch_id,
    require_pull_request,
    restrict_direct_push,
    restrict_force_push,
    restrict_deletion,
    require_resolved_conversations,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    branch_id,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE
FROM branch
WHERE name = 'main';

INSERT INTO approval_requirement (
    policy_id,
    required_approvals,
    require_distinct_reviewers
)
SELECT policy_id, 2, TRUE
FROM branch_protection_policy;

INSERT INTO eligible_reviewer (policy_id, reviewer_id)
SELECT
    p.policy_id,
    u.user_id
FROM branch_protection_policy p
CROSS JOIN repository_user u
WHERE u.username IN ('alice', 'bob', 'carol');

INSERT INTO required_status_check (policy_id, check_name)
SELECT policy_id, 'unit-tests'
FROM branch_protection_policy
UNION ALL
SELECT policy_id, 'security-scan'
FROM branch_protection_policy;

INSERT INTO pull_request (
    repository_id,
    source_branch_id,
    target_branch_id,
    head_commit_id,
    title,
    description,
    state,
    draft,
    base_synchronized,
    created_by
)
SELECT
    r.repository_id,
    source.branch_id,
    target.branch_id,
    c.commit_id,
    'Verify repository artifact before merge',
    'Use a trusted SHA-256 digest to verify the proposed commit content.',
    'open',
    FALSE,
    TRUE,
    u.user_id
FROM repository r
JOIN branch source
    ON source.repository_id = r.repository_id
   AND source.name = 'feature/preimage'
JOIN branch target
    ON target.repository_id = r.repository_id
   AND target.name = 'main'
JOIN commit_record c
    ON c.commit_hash = 'a1b2c3d4e5f6'
JOIN repository_user u
    ON u.username = 'alice'
WHERE r.name = 'security-platform';

INSERT INTO review (
    pull_request_id,
    reviewer_id,
    state,
    body,
    stale
)
SELECT
    pr.pull_request_id,
    u.user_id,
    'approved',
    'Digest verification is explicit and independently testable.',
    FALSE
FROM pull_request pr
JOIN repository_user u ON u.username = 'alice'
WHERE pr.title = 'Verify repository artifact before merge';

INSERT INTO review (
    pull_request_id,
    reviewer_id,
    state,
    body,
    stale
)
SELECT
    pr.pull_request_id,
    u.user_id,
    'approved',
    'Integrity evidence is separated from repository governance.',
    FALSE
FROM pull_request pr
JOIN repository_user u ON u.username = 'bob'
WHERE pr.title = 'Verify repository artifact before merge';

INSERT INTO review (
    pull_request_id,
    reviewer_id,
    state,
    body,
    stale
)
SELECT
    pr.pull_request_id,
    u.user_id,
    'commented',
    'Consider documenting the trust boundary around the expected digest.',
    FALSE
FROM pull_request pr
JOIN repository_user u ON u.username = 'carol'
WHERE pr.title = 'Verify repository artifact before merge';

INSERT INTO review_comment (
    review_id,
    author_id,
    file_path,
    line_number,
    body
)
SELECT
    rv.review_id,
    u.user_id,
    'src/integrity.txt',
    12,
    'The digest verifies content but does not authenticate its source.'
FROM review rv
JOIN repository_user u ON u.username = 'carol'
WHERE rv.state = 'commented';

INSERT INTO conversation (
    pull_request_id,
    review_comment_id,
    state
)
SELECT
    pr.pull_request_id,
    rc.comment_id,
    'open'
FROM pull_request pr
JOIN review_comment rc
    ON rc.file_path = 'src/integrity.txt'
WHERE pr.title = 'Verify repository artifact before merge';

INSERT INTO status_check (
    pull_request_id,
    check_name,
    state,
    observed_commit_id,
    completed_at
)
SELECT
    pr.pull_request_id,
    'unit-tests',
    'passing',
    pr.head_commit_id,
    now()
FROM pull_request pr;

INSERT INTO status_check (
    pull_request_id,
    check_name,
    state,
    observed_commit_id,
    completed_at
)
SELECT
    pr.pull_request_id,
    'security-scan',
    'passing',
    pr.head_commit_id,
    now()
FROM pull_request pr;

-- Resolve the review conversation.
UPDATE conversation
SET
    state = 'resolved',
    resolved_by = (
        SELECT user_id
        FROM repository_user
        WHERE username = 'alice'
    ),
    resolved_at = now()
WHERE conversation_id = (
    SELECT min(conversation_id)
    FROM conversation
);

-- Record cryptographic verification.
INSERT INTO integrity_verification (
    pull_request_id,
    commit_id,
    expected_digest,
    observed_digest,
    verified
)
SELECT
    pr.pull_request_id,
    c.commit_id,
    c.content_sha256,
    encode(digest(c.content, 'sha256'), 'hex'),
    c.content_sha256 = encode(digest(c.content, 'sha256'), 'hex')
FROM pull_request pr
JOIN commit_record c
    ON c.commit_id = pr.head_commit_id;

-- View: current valid approvals.
CREATE OR REPLACE VIEW valid_approval_counts AS
SELECT
    pr.pull_request_id,
    pr.target_branch_id,
    COUNT(DISTINCT rv.reviewer_id) AS valid_approvals
FROM pull_request pr
JOIN review rv
    ON rv.pull_request_id = pr.pull_request_id
JOIN branch_protection_policy bp
    ON bp.branch_id = pr.target_branch_id
JOIN eligible_reviewer er
    ON er.policy_id = bp.policy_id
   AND er.reviewer_id = rv.reviewer_id
JOIN repository_user u
    ON u.user_id = rv.reviewer_id
WHERE rv.state = 'approved'
  AND rv.stale = FALSE
  AND u.active = TRUE
GROUP BY pr.pull_request_id, pr.target_branch_id;

-- View: unresolved conversation counts.
CREATE OR REPLACE VIEW unresolved_conversation_counts AS
SELECT
    pr.pull_request_id,
    COUNT(c.conversation_id) AS unresolved_conversations
FROM pull_request pr
LEFT JOIN conversation c
    ON c.pull_request_id = pr.pull_request_id
   AND c.state = 'open'
GROUP BY pr.pull_request_id;

-- View: required status-check failures.
CREATE OR REPLACE VIEW status_policy_results AS
SELECT
    pr.pull_request_id,
    COUNT(rsc.check_name) AS required_checks,
    COUNT(sc.status_check_id)
        FILTER (WHERE sc.state = 'passing') AS passing_required_checks
FROM pull_request pr
JOIN branch_protection_policy bp
    ON bp.branch_id = pr.target_branch_id
JOIN required_status_check rsc
    ON rsc.policy_id = bp.policy_id
LEFT JOIN status_check sc
    ON sc.pull_request_id = pr.pull_request_id
   AND sc.check_name = rsc.check_name
GROUP BY pr.pull_request_id;

-- Comprehensive merge-eligibility report.
WITH policy AS (
    SELECT
        bp.branch_id,
        bp.require_resolved_conversations,
        ar.required_approvals
    FROM branch_protection_policy bp
    JOIN approval_requirement ar
        ON ar.policy_id = bp.policy_id
),
approval AS (
    SELECT
        pull_request_id,
        valid_approvals
    FROM valid_approval_counts
),
conversation AS (
    SELECT
        pull_request_id,
        unresolved_conversations
    FROM unresolved_conversation_counts
),
checks AS (
    SELECT
        pull_request_id,
        required_checks,
        passing_required_checks
    FROM status_policy_results
),
integrity AS (
    SELECT
        pull_request_id,
        BOOL_AND(verified) AS integrity_valid
    FROM integrity_verification
    GROUP BY pull_request_id
)
SELECT
    pr.pull_request_id,
    pr.title,
    pr.state,
    COALESCE(a.valid_approvals, 0) AS valid_approvals,
    p.required_approvals,
    COALESCE(c.unresolved_conversations, 0) AS unresolved_conversations,
    COALESCE(s.required_checks, 0) AS required_checks,
    COALESCE(s.passing_required_checks, 0) AS passing_required_checks,
    COALESCE(i.integrity_valid, FALSE) AS integrity_valid,
    (
        pr.state = 'open'
        AND pr.base_synchronized
        AND COALESCE(a.valid_approvals, 0) >= p.required_approvals
        AND (
            NOT p.require_resolved_conversations
            OR COALESCE(c.unresolved_conversations, 0) = 0
        )
        AND COALESCE(s.required_checks, 0)
            = COALESCE(s.passing_required_checks, 0)
        AND COALESCE(i.integrity_valid, FALSE)
    ) AS merge_eligible
FROM pull_request pr
JOIN policy p
    ON p.branch_id = pr.target_branch_id
LEFT JOIN approval a
    ON a.pull_request_id = pr.pull_request_id
LEFT JOIN conversation c
    ON c.pull_request_id = pr.pull_request_id
LEFT JOIN checks s
    ON s.pull_request_id = pr.pull_request_id
LEFT JOIN integrity i
    ON i.pull_request_id = pr.pull_request_id
ORDER BY pr.pull_request_id;

-- Aggregation: review outcomes by state.
SELECT
    rv.state,
    COUNT(*) AS review_count
FROM review rv
GROUP BY rv.state
ORDER BY rv.state;

-- Validation: find commits whose stored digest does not match their content.
SELECT
    commit_id,
    commit_hash,
    verify_commit_digest(commit_id) AS digest_valid
FROM commit_record
WHERE NOT verify_commit_digest(commit_id);

-- Validation: identify stale approvals that must not satisfy current policy.
SELECT
    pr.pull_request_id,
    rv.review_id,
    u.username,
    rv.state,
    rv.stale
FROM review rv
JOIN pull_request pr
    ON pr.pull_request_id = rv.pull_request_id
JOIN repository_user u
    ON u.user_id = rv.reviewer_id
WHERE rv.state = 'approved'
  AND rv.stale = TRUE;

-- Transactional merge demonstration.
-- The transaction rechecks eligibility immediately before recording the merge.
BEGIN;

WITH eligibility AS (
    SELECT
        pr.pull_request_id,
        pr.head_commit_id,
        pr.target_branch_id,
        pr.state,
        pr.base_synchronized,
        COALESCE(v.valid_approvals, 0) AS approvals,
        COALESCE(u.unresolved_conversations, 0) AS unresolved,
        COALESCE(s.required_checks, 0) AS required_checks,
        COALESCE(s.passing_required_checks, 0) AS passing_checks,
        COALESCE(i.integrity_valid, FALSE) AS integrity_valid,
        ar.required_approvals,
        bp.require_resolved_conversations
    FROM pull_request pr
    JOIN branch_protection_policy bp
        ON bp.branch_id = pr.target_branch_id
    JOIN approval_requirement ar
        ON ar.policy_id = bp.policy_id
    LEFT JOIN valid_approval_counts v
        ON v.pull_request_id = pr.pull_request_id
    LEFT JOIN unresolved_conversation_counts u
        ON u.pull_request_id = pr.pull_request_id
    LEFT JOIN status_policy_results s
        ON s.pull_request_id = pr.pull_request_id
    LEFT JOIN (
        SELECT
            pull_request_id,
            BOOL_AND(verified) AS integrity_valid
        FROM integrity_verification
        GROUP BY pull_request_id
    ) i
        ON i.pull_request_id = pr.pull_request_id
    WHERE pr.pull_request_id = (
        SELECT min(pull_request_id)
        FROM pull_request
        WHERE state = 'open'
    )
),
eligible AS (
    SELECT *
    FROM eligibility
    WHERE state = 'open'
      AND base_synchronized
      AND approvals >= required_approvals
      AND (
          NOT require_resolved_conversations
          OR unresolved = 0
      )
      AND required_checks = passing_checks
      AND integrity_valid
)
INSERT INTO merge_record (
    pull_request_id,
    merged_by,
    merge_strategy,
    merged_commit_hash
)
SELECT
    e.pull_request_id,
    (
        SELECT user_id
        FROM repository_user
        WHERE username = 'alice'
    ),
    'squash',
    c.commit_hash
FROM eligible e
JOIN commit_record c
    ON c.commit_id = e.head_commit_id;

-- The trigger requires the merge record to exist before state becomes merged.
UPDATE pull_request pr
SET
    state = 'merged',
    draft = FALSE,
    merged_at = now()
WHERE pr.pull_request_id IN (
    SELECT pull_request_id
    FROM merge_record
)
AND pr.state = 'open';

COMMIT;

-- Final state report.
SELECT
    pr.pull_request_id,
    pr.title,
    pr.state,
    mr.merge_strategy,
    mr.merged_commit_hash,
    mr.merged_at
FROM pull_request pr
LEFT JOIN merge_record mr
    ON mr.pull_request_id = pr.pull_request_id
ORDER BY pr.pull_request_id;
