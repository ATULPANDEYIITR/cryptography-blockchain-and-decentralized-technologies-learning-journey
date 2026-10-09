-- PostgreSQL: AES key inventory, key schedule metadata, and rotation governance.
-- The database stores key references and metadata, never raw AES key bytes.
-- Cryptographic operations should run in a trusted cryptographic service.

BEGIN;

CREATE SCHEMA IF NOT EXISTS cryptography_lab;

CREATE TABLE cryptography_lab.repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    CHECK (length(trim(repository_name)) > 0),
    CHECK (length(trim(default_branch)) > 0)
);

CREATE TABLE cryptography_lab.aes_key_profiles (
    profile_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    algorithm_name TEXT NOT NULL UNIQUE,
    key_bytes SMALLINT NOT NULL UNIQUE,
    rounds SMALLINT NOT NULL,
    block_bytes SMALLINT NOT NULL DEFAULT 16,
    round_key_count SMALLINT GENERATED ALWAYS AS (rounds + 1) STORED,
    security_status TEXT NOT NULL DEFAULT 'approved',
    CONSTRAINT valid_aes_profile CHECK (
        (key_bytes = 16 AND rounds = 10)
        OR (key_bytes = 24 AND rounds = 12)
        OR (key_bytes = 32 AND rounds = 14)
    ),
    CONSTRAINT valid_block_size CHECK (block_bytes = 16),
    CONSTRAINT valid_security_status CHECK (
        security_status IN ('approved', 'deprecated', 'disabled')
    )
);

INSERT INTO cryptography_lab.aes_key_profiles
    (algorithm_name, key_bytes, rounds, security_status)
VALUES
    ('AES-128', 16, 10, 'approved'),
    ('AES-192', 24, 12, 'approved'),
    ('AES-256', 32, 14, 'approved')
ON CONFLICT (algorithm_name) DO UPDATE
SET key_bytes = EXCLUDED.key_bytes,
    rounds = EXCLUDED.rounds,
    security_status = EXCLUDED.security_status;

CREATE TABLE cryptography_lab.key_registry (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id BIGINT NOT NULL
        REFERENCES cryptography_lab.repositories(repository_id),
    profile_id SMALLINT NOT NULL
        REFERENCES cryptography_lab.aes_key_profiles(profile_id),
    external_key_reference TEXT NOT NULL UNIQUE,
    key_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    key_status TEXT NOT NULL DEFAULT 'pending',
    created_by TEXT NOT NULL,
    CONSTRAINT positive_key_version CHECK (key_version > 0),
    CONSTRAINT valid_key_status CHECK (
        key_status IN ('pending', 'active', 'retiring', 'retired', 'revoked')
    ),
    CONSTRAINT valid_key_lifecycle CHECK (
        retired_at IS NULL OR activated_at IS NULL OR retired_at >= activated_at
    ),
    CONSTRAINT valid_activation CHECK (
        key_status NOT IN ('active', 'retiring', 'retired')
        OR activated_at IS NOT NULL
    ),
    CONSTRAINT valid_retirement CHECK (
        key_status NOT IN ('retired', 'revoked') OR retired_at IS NOT NULL
    ),
    UNIQUE (repository_id, key_version)
);

CREATE UNIQUE INDEX one_active_key_per_repository
ON cryptography_lab.key_registry(repository_id)
WHERE key_status = 'active';

CREATE INDEX key_registry_status_created_idx
ON cryptography_lab.key_registry(key_status, created_at DESC);

CREATE TABLE cryptography_lab.key_rotation_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES cryptography_lab.repositories(repository_id),
    old_key_id UUID REFERENCES cryptography_lab.key_registry(key_id),
    new_key_id UUID NOT NULL REFERENCES cryptography_lab.key_registry(key_id),
    initiated_by TEXT NOT NULL,
    rotation_reason TEXT NOT NULL,
    event_status TEXT NOT NULL DEFAULT 'requested',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT valid_rotation_status CHECK (
        event_status IN ('requested', 'approved', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT different_rotation_keys CHECK (
        old_key_id IS NULL OR old_key_id <> new_key_id
    ),
    CONSTRAINT completed_rotation_has_timestamp CHECK (
        event_status <> 'completed' OR completed_at IS NOT NULL
    )
);

CREATE TABLE cryptography_lab.rotation_approvals (
    approval_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id BIGINT NOT NULL
        REFERENCES cryptography_lab.key_rotation_events(event_id),
    reviewer_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT valid_rotation_decision CHECK (
        decision IN ('approved', 'rejected', 'commented')
    ),
    UNIQUE (event_id, reviewer_id)
);

CREATE TABLE cryptography_lab.rotation_checks (
    check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id BIGINT NOT NULL
        REFERENCES cryptography_lab.key_rotation_events(event_id),
    check_name TEXT NOT NULL,
    check_status TEXT NOT NULL DEFAULT 'pending',
    executed_at TIMESTAMPTZ,
    CONSTRAINT valid_check_status CHECK (
        check_status IN ('pending', 'passed', 'failed')
    ),
    UNIQUE (event_id, check_name)
);

-- Keep key lifecycle transitions in the database consistent.
CREATE OR REPLACE FUNCTION cryptography_lab.validate_key_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.key_status IN ('retired', 'revoked')
           AND NEW.key_status <> OLD.key_status THEN
            RAISE EXCEPTION
                'Terminal key state % cannot transition to %',
                OLD.key_status, NEW.key_status;
        END IF;

        IF NEW.key_status = 'active' AND NEW.activated_at IS NULL THEN
            NEW.activated_at := now();
        END IF;

        IF NEW.key_status IN ('retired', 'revoked')
           AND NEW.retired_at IS NULL THEN
            NEW.retired_at := now();
        END IF;

        IF NEW.repository_id <> OLD.repository_id
           OR NEW.profile_id <> OLD.profile_id
           OR NEW.key_version <> OLD.key_version
           OR NEW.external_key_reference <> OLD.external_key_reference THEN
            RAISE EXCEPTION
                'Key identity and cryptographic profile are immutable';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER key_transition_guard
BEFORE UPDATE ON cryptography_lab.key_registry
FOR EACH ROW
EXECUTE FUNCTION cryptography_lab.validate_key_transition();

-- A rotation can complete only when approvals and required checks pass.
CREATE OR REPLACE FUNCTION cryptography_lab.complete_key_rotation(
    requested_event_id BIGINT,
    required_approvals INTEGER DEFAULT 2
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rotation cryptography_lab.key_rotation_events%ROWTYPE;
    approval_count INTEGER;
    failed_or_pending_checks INTEGER;
BEGIN
    IF required_approvals < 1 THEN
        RAISE EXCEPTION 'At least one rotation approval is required';
    END IF;

    SELECT *
    INTO rotation
    FROM cryptography_lab.key_rotation_events
    WHERE event_id = requested_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Rotation event % does not exist', requested_event_id;
    END IF;

    IF rotation.event_status NOT IN ('requested', 'approved') THEN
        RAISE EXCEPTION
            'Rotation event % cannot complete from state %',
            requested_event_id, rotation.event_status;
    END IF;

    SELECT count(*)
    INTO approval_count
    FROM cryptography_lab.rotation_approvals
    WHERE event_id = requested_event_id
      AND decision = 'approved'
      AND reviewer_id <> rotation.initiated_by;

    IF approval_count < required_approvals THEN
        RAISE EXCEPTION
            'Rotation requires % independent approvals; found %',
            required_approvals, approval_count;
    END IF;

    SELECT count(*)
    INTO failed_or_pending_checks
    FROM cryptography_lab.rotation_checks
    WHERE event_id = requested_event_id
      AND check_status <> 'passed';

    IF failed_or_pending_checks > 0 THEN
        RAISE EXCEPTION 'Rotation has pending or failed verification checks';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM cryptography_lab.key_registry
        WHERE key_id = rotation.new_key_id
          AND repository_id = rotation.repository_id
          AND key_status = 'pending'
    ) THEN
        RAISE EXCEPTION 'Replacement key must be pending and belong to repository';
    END IF;

    IF rotation.old_key_id IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM cryptography_lab.key_registry
           WHERE key_id = rotation.old_key_id
             AND repository_id = rotation.repository_id
             AND key_status = 'active'
       ) THEN
        RAISE EXCEPTION 'Old key must be active before rotation';
    END IF;

    -- The unique partial index prevents two active keys during concurrent
    -- rotations. FOR UPDATE serializes this event, but applications should
    -- still handle transaction conflicts and retry only safe operations.
    IF rotation.old_key_id IS NOT NULL THEN
        UPDATE cryptography_lab.key_registry
        SET key_status = 'retired',
            retired_at = now()
        WHERE key_id = rotation.old_key_id;
    END IF;

    UPDATE cryptography_lab.key_registry
    SET key_status = 'active',
        activated_at = now()
    WHERE key_id = rotation.new_key_id;

    UPDATE cryptography_lab.key_rotation_events
    SET event_status = 'completed',
        completed_at = now()
    WHERE event_id = requested_event_id;
END;
$$;

INSERT INTO cryptography_lab.repositories (repository_name, default_branch)
VALUES ('payments-api', 'main')
ON CONFLICT (repository_name) DO NOTHING;

-- Sample lifecycle: pending replacement key, independent approvals, checks,
-- and a completed rotation executed within a single transaction.
DO $$
DECLARE
    repo_id BIGINT;
    aes256_id SMALLINT;
    old_key UUID;
    new_key UUID;
    event_id BIGINT;
BEGIN
    SELECT repository_id INTO repo_id
    FROM cryptography_lab.repositories
    WHERE repository_name = 'payments-api';

    SELECT profile_id INTO aes256_id
    FROM cryptography_lab.aes_key_profiles
    WHERE algorithm_name = 'AES-256';

    SELECT key_id INTO old_key
    FROM cryptography_lab.key_registry
    WHERE repository_id = repo_id
      AND key_version = 1;

    IF old_key IS NULL THEN
        INSERT INTO cryptography_lab.key_registry (
            repository_id, profile_id, external_key_reference,
            key_version, activated_at, key_status, created_by
        )
        VALUES (
            repo_id, aes256_id, 'kms://payments-api/key-v1',
            1, now(), 'active', 'security-service'
        )
        RETURNING key_id INTO old_key;
    END IF;

    SELECT key_id INTO new_key
    FROM cryptography_lab.key_registry
    WHERE repository_id = repo_id
      AND key_version = 2;

    IF new_key IS NULL THEN
        INSERT INTO cryptography_lab.key_registry (
            repository_id, profile_id, external_key_reference,
            key_version, key_status, created_by
        )
        VALUES (
            repo_id, aes256_id, 'kms://payments-api/key-v2',
            2, 'pending', 'security-service'
        )
        RETURNING key_id INTO new_key;
    END IF;

    INSERT INTO cryptography_lab.key_rotation_events (
        repository_id, old_key_id, new_key_id,
        initiated_by, rotation_reason, event_status
    )
    VALUES (
        repo_id, old_key, new_key,
        'security-service', 'Scheduled key rotation', 'requested'
    )
    RETURNING cryptography_lab.key_rotation_events.event_id INTO event_id;

    INSERT INTO cryptography_lab.rotation_approvals (
        event_id, reviewer_id, decision
    )
    VALUES
        (event_id, 'security-reviewer-a', 'approved'),
        (event_id, 'security-reviewer-b', 'approved');

    INSERT INTO cryptography_lab.rotation_checks (
        event_id, check_name, check_status, executed_at
    )
    VALUES
        (event_id, 'key-material-available', 'passed', now()),
        (event_id, 'consumer-compatibility', 'passed', now()),
        (event_id, 'audit-record-written', 'passed', now());

    PERFORM cryptography_lab.complete_key_rotation(event_id, 2);
END;
$$;

CREATE VIEW cryptography_lab.key_inventory AS
SELECT
    r.repository_name,
    k.key_version,
    p.algorithm_name,
    p.key_bytes * 8 AS key_bits,
    p.rounds,
    p.round_key_count,
    k.key_status,
    k.created_at,
    k.activated_at,
    k.retired_at,
    k.external_key_reference
FROM cryptography_lab.key_registry AS k
JOIN cryptography_lab.repositories AS r
    ON r.repository_id = k.repository_id
JOIN cryptography_lab.aes_key_profiles AS p
    ON p.profile_id = k.profile_id;

-- Inventory query: AES key sizes and round counts are profile metadata.
SELECT *
FROM cryptography_lab.key_inventory
ORDER BY repository_name, key_version;

-- Rotation audit: distinguish incomplete, failed, and completed operations.
SELECT
    r.repository_name,
    e.event_id,
    e.event_status,
    e.rotation_reason,
    e.created_at,
    e.completed_at,
    count(DISTINCT a.approval_id)
        FILTER (WHERE a.decision = 'approved') AS approvals,
    count(DISTINCT c.check_id)
        FILTER (WHERE c.check_status = 'passed') AS passed_checks,
    count(DISTINCT c.check_id)
        FILTER (WHERE c.check_status <> 'passed') AS unresolved_checks
FROM cryptography_lab.key_rotation_events AS e
JOIN cryptography_lab.repositories AS r
    ON r.repository_id = e.repository_id
LEFT JOIN cryptography_lab.rotation_approvals AS a
    ON a.event_id = e.event_id
LEFT JOIN cryptography_lab.rotation_checks AS c
    ON c.event_id = e.event_id
GROUP BY
    r.repository_name, e.event_id, e.event_status,
    e.rotation_reason, e.created_at, e.completed_at
ORDER BY e.created_at DESC;

-- Expected integrity failure: AES-192 must have 12 rounds.
-- Uncomment to verify CHECK constraint enforcement:
-- INSERT INTO cryptography_lab.aes_key_profiles
--     (algorithm_name, key_bytes, rounds)
-- VALUES ('INVALID-AES', 24, 10);

COMMIT;
