-- PostgreSQL Nonce Governance Database
--
-- This schema models nonce lifecycle management for a service that protects
-- application messages with an AEAD construction.
--
-- The database enforces:
--   * key-scoped nonce uniqueness
--   * valid nonce lengths
--   * session counters
--   * replay windows
--   * message states
--   * nonce allocation transactions
--   * auditability of allocation and rejection events
--
-- Cryptographic encryption itself remains outside the relational layer.
-- PostgreSQL stores the protocol metadata required to manage nonce safety.

DROP SCHEMA IF EXISTS nonce_governance CASCADE;

CREATE SCHEMA nonce_governance;

SET search_path TO nonce_governance, public;

-- -------------------------------------------------------------------------
-- Cryptographic keys
-- -------------------------------------------------------------------------

CREATE TABLE cryptographic_keys (
    key_id              BIGSERIAL PRIMARY KEY,
    key_name            TEXT NOT NULL UNIQUE,
    algorithm           TEXT NOT NULL,
    nonce_bytes         INTEGER NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at          TIMESTAMPTZ,

    CONSTRAINT cryptographic_keys_algorithm_check
        CHECK (algorithm IN (
            'AES-128-GCM',
            'AES-256-GCM',
            'CHACHA20-POLY1305'
        )),

    CONSTRAINT cryptographic_keys_nonce_size_check
        CHECK (nonce_bytes > 0 AND nonce_bytes <= 64),

    CONSTRAINT cryptographic_keys_status_check
        CHECK (status IN ('ACTIVE', 'RETIRED')),

    CONSTRAINT cryptographic_keys_retirement_check
        CHECK (
            (status = 'ACTIVE' AND retired_at IS NULL)
            OR
            (status = 'RETIRED' AND retired_at IS NOT NULL)
        )
);

-- -------------------------------------------------------------------------
-- Sessions
-- -------------------------------------------------------------------------

CREATE TABLE sessions (
    session_id          BIGSERIAL PRIMARY KEY,
    session_name        TEXT NOT NULL UNIQUE,
    key_id              BIGINT NOT NULL REFERENCES cryptographic_keys(key_id),
    session_namespace   BIGINT NOT NULL,
    next_counter        BIGINT NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'OPEN',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at           TIMESTAMPTZ,

    CONSTRAINT sessions_namespace_check
        CHECK (session_namespace >= 0),

    CONSTRAINT sessions_counter_check
        CHECK (next_counter >= 0),

    CONSTRAINT sessions_status_check
        CHECK (status IN ('OPEN', 'CLOSED')),

    CONSTRAINT sessions_closure_check
        CHECK (
            (status = 'OPEN' AND closed_at IS NULL)
            OR
            (status = 'CLOSED' AND closed_at IS NOT NULL)
        )
);

CREATE INDEX idx_sessions_key_status
    ON sessions (key_id, status);

-- -------------------------------------------------------------------------
-- Protocol messages
-- -------------------------------------------------------------------------

CREATE TABLE messages (
    message_id          BIGSERIAL PRIMARY KEY,
    session_id          BIGINT NOT NULL REFERENCES sessions(session_id),
    key_id              BIGINT NOT NULL REFERENCES cryptographic_keys(key_id),
    sequence_number     BIGINT NOT NULL,
    nonce               BYTEA NOT NULL,
    ciphertext          BYTEA NOT NULL,
    authentication_tag  BYTEA NOT NULL,
    associated_data     BYTEA,
    state               TEXT NOT NULL DEFAULT 'CREATED',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at         TIMESTAMPTZ,
    rejected_reason     TEXT,

    CONSTRAINT messages_sequence_check
        CHECK (sequence_number >= 0),

    CONSTRAINT messages_nonce_nonempty_check
        CHECK (octet_length(nonce) > 0),

    CONSTRAINT messages_ciphertext_check
        CHECK (octet_length(ciphertext) > 0),

    CONSTRAINT messages_tag_check
        CHECK (octet_length(authentication_tag) > 0),

    CONSTRAINT messages_state_check
        CHECK (
            state IN (
                'CREATED',
                'ACCEPTED',
                'REJECTED_REPLAY',
                'REJECTED_NONCE',
                'REJECTED_POLICY'
            )
        ),

    CONSTRAINT messages_acceptance_time_check
        CHECK (
            (state = 'ACCEPTED' AND accepted_at IS NOT NULL)
            OR
            (state <> 'ACCEPTED')
        )
);

-- The same nonce/key pair must never appear twice in the message table.
-- This is the central database-level uniqueness invariant.
CREATE UNIQUE INDEX ux_messages_key_nonce
    ON messages (key_id, nonce);

CREATE INDEX idx_messages_session_sequence
    ON messages (session_id, sequence_number);

CREATE INDEX idx_messages_state_created
    ON messages (state, created_at);

-- -------------------------------------------------------------------------
-- Replay windows
-- -------------------------------------------------------------------------

CREATE TABLE replay_windows (
    session_id          BIGINT PRIMARY KEY REFERENCES sessions(session_id),
    highest_sequence    BIGINT NOT NULL DEFAULT -1,
    window_size         INTEGER NOT NULL DEFAULT 64,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT replay_windows_highest_check
        CHECK (highest_sequence >= -1),

    CONSTRAINT replay_windows_size_check
        CHECK (window_size > 0)
);

-- -------------------------------------------------------------------------
-- Nonce allocation audit
-- -------------------------------------------------------------------------

CREATE TABLE nonce_allocations (
    allocation_id       BIGSERIAL PRIMARY KEY,
    session_id          BIGINT NOT NULL REFERENCES sessions(session_id),
    key_id              BIGINT NOT NULL REFERENCES cryptographic_keys(key_id),
    counter_value       BIGINT NOT NULL,
    nonce               BYTEA NOT NULL,
    allocated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT nonce_allocations_counter_check
        CHECK (counter_value >= 0),

    CONSTRAINT nonce_allocations_nonce_check
        CHECK (octet_length(nonce) > 0),

    CONSTRAINT nonce_allocations_unique_counter
        UNIQUE (session_id, counter_value)
);

CREATE UNIQUE INDEX ux_nonce_allocations_key_nonce
    ON nonce_allocations (key_id, nonce);

CREATE INDEX idx_nonce_allocations_session
    ON nonce_allocations (session_id, counter_value);

-- -------------------------------------------------------------------------
-- Review/audit events for nonce lifecycle decisions
-- -------------------------------------------------------------------------

CREATE TABLE nonce_events (
    event_id            BIGSERIAL PRIMARY KEY,
    message_id          BIGINT REFERENCES messages(message_id),
    event_type          TEXT NOT NULL,
    event_detail        TEXT NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT nonce_events_type_check
        CHECK (
            event_type IN (
                'ALLOCATED',
                'ACCEPTED',
                'REPLAY_REJECTED',
                'NONCE_REUSE_REJECTED',
                'POLICY_REJECTED'
            )
        )
);

CREATE INDEX idx_nonce_events_message_time
    ON nonce_events (message_id, event_time);

-- -------------------------------------------------------------------------
-- Atomic counter allocation
-- -------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION allocate_nonce_counter(
    p_session_id BIGINT
)
RETURNS TABLE (
    allocated_counter BIGINT,
    allocated_nonce BYTEA
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id BIGINT;
    v_namespace BIGINT;
    v_counter BIGINT;
    v_nonce BYTEA;
    v_nonce_bytes INTEGER;
BEGIN
    /*
     * FOR UPDATE serializes concurrent allocations for the same session.
     * Without row locking, two transactions could read the same counter
     * before either transaction updates it.
     */
    SELECT
        s.key_id,
        s.session_namespace,
        s.next_counter,
        k.nonce_bytes
    INTO
        v_key_id,
        v_namespace,
        v_counter,
        v_nonce_bytes
    FROM sessions s
    JOIN cryptographic_keys k
      ON k.key_id = s.key_id
    WHERE s.session_id = p_session_id
      AND s.status = 'OPEN'
      AND k.status = 'ACTIVE'
    FOR UPDATE OF s;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Session % is missing, closed, or its key is inactive',
            p_session_id;
    END IF;

    IF v_counter = 9223372036854775807 THEN
        RAISE EXCEPTION
            'Nonce counter exhausted for session %',
            p_session_id;
    END IF;

    /*
     * The structured nonce contains the session namespace followed by the
     * counter. The construction must match the protocol specification.
     */
    v_nonce :=
        decode(
            lpad(
                to_hex(v_namespace),
                16,
                '0'
            )
            ||
            lpad(
                to_hex(v_counter),
                16,
                '0'
            ),
            'hex'
        );

    IF octet_length(v_nonce) <> v_nonce_bytes THEN
        RAISE EXCEPTION
            'Constructed nonce length % does not match key policy %',
            octet_length(v_nonce),
            v_nonce_bytes;
    END IF;

    UPDATE sessions
    SET next_counter = next_counter + 1
    WHERE session_id = p_session_id;

    INSERT INTO nonce_allocations (
        session_id,
        key_id,
        counter_value,
        nonce
    )
    VALUES (
        p_session_id,
        v_key_id,
        v_counter,
        v_nonce
    );

    RETURN QUERY
    SELECT v_counter, v_nonce;
END;
$$;

-- -------------------------------------------------------------------------
-- Message acceptance procedure
-- -------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION accept_message(
    p_session_id BIGINT,
    p_key_id BIGINT,
    p_sequence_number BIGINT,
    p_nonce BYTEA,
    p_ciphertext BYTEA,
    p_authentication_tag BYTEA,
    p_associated_data BYTEA DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_message_id BIGINT;
    v_expected_nonce_bytes INTEGER;
    v_current_highest BIGINT;
    v_window_size INTEGER;
BEGIN
    IF p_sequence_number < 0 THEN
        RAISE EXCEPTION 'Sequence number cannot be negative';
    END IF;

    IF p_ciphertext IS NULL
       OR octet_length(p_ciphertext) = 0 THEN
        RAISE EXCEPTION 'Ciphertext cannot be empty';
    END IF;

    IF p_authentication_tag IS NULL
       OR octet_length(p_authentication_tag) = 0 THEN
        RAISE EXCEPTION 'Authentication tag cannot be empty';
    END IF;

    SELECT nonce_bytes
    INTO v_expected_nonce_bytes
    FROM cryptographic_keys
    WHERE key_id = p_key_id
      AND status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Key % is missing or inactive',
            p_key_id;
    END IF;

    IF octet_length(p_nonce) <> v_expected_nonce_bytes THEN
        RAISE EXCEPTION
            'Nonce length % violates key policy %',
            octet_length(p_nonce),
            v_expected_nonce_bytes;
    END IF;

    /*
     * Lock the replay-window row before changing the highest sequence.
     * This prevents concurrent receivers from making contradictory
     * decisions about the same session's replay state.
     */
    SELECT
        highest_sequence,
        window_size
    INTO
        v_current_highest,
        v_window_size
    FROM replay_windows
    WHERE session_id = p_session_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Replay window does not exist for session %',
            p_session_id;
    END IF;

    IF v_current_highest >= 0
       AND p_sequence_number < v_current_highest - v_window_size + 1 THEN

        INSERT INTO messages (
            session_id,
            key_id,
            sequence_number,
            nonce,
            ciphertext,
            authentication_tag,
            associated_data,
            state,
            rejected_reason
        )
        VALUES (
            p_session_id,
            p_key_id,
            p_sequence_number,
            p_nonce,
            p_ciphertext,
            p_authentication_tag,
            p_associated_data,
            'REJECTED_REPLAY',
            'Sequence is outside the replay window'
        )
        RETURNING message_id INTO v_message_id;

        INSERT INTO nonce_events (
            message_id,
            event_type,
            event_detail
        )
        VALUES (
            v_message_id,
            'REPLAY_REJECTED',
            'Sequence number was outside the accepted replay window'
        );

        RETURN v_message_id;
    END IF;

    /*
     * The unique key/nonce index is the final database-level defense
     * against reuse. An application-level check alone is insufficient
     * because two concurrent transactions can race.
     */
    BEGIN
        INSERT INTO messages (
            session_id,
            key_id,
            sequence_number,
            nonce,
            ciphertext,
            authentication_tag,
            associated_data,
            state,
            accepted_at
        )
        VALUES (
            p_session_id,
            p_key_id,
            p_sequence_number,
            p_nonce,
            p_ciphertext,
            p_authentication_tag,
            p_associated_data,
            'ACCEPTED',
            CURRENT_TIMESTAMP
        )
        RETURNING message_id INTO v_message_id;

    EXCEPTION
        WHEN unique_violation THEN

            INSERT INTO messages (
                session_id,
                key_id,
                sequence_number,
                nonce,
                ciphertext,
                authentication_tag,
                associated_data,
                state,
                rejected_reason
            )
            VALUES (
                p_session_id,
                p_key_id,
                p_sequence_number,
                p_nonce,
                p_ciphertext,
                p_authentication_tag,
                p_associated_data,
                'REJECTED_NONCE',
                'Nonce already used with this key'
            )
            RETURNING message_id INTO v_message_id;

            INSERT INTO nonce_events (
                message_id,
                event_type,
                event_detail
            )
            VALUES (
                v_message_id,
                'NONCE_REUSE_REJECTED',
                'Unique key/nonce constraint prevented reuse'
            );

            RETURN v_message_id;
    END;

    IF p_sequence_number > v_current_highest THEN
        UPDATE replay_windows
        SET
            highest_sequence = p_sequence_number,
            updated_at = CURRENT_TIMESTAMP
        WHERE session_id = p_session_id;
    END IF;

    INSERT INTO nonce_events (
        message_id,
        event_type,
        event_detail
    )
    VALUES (
        v_message_id,
        'ACCEPTED',
        'Message passed nonce and replay policy'
    );

    RETURN v_message_id;
END;
$$;

-- -------------------------------------------------------------------------
-- Seed cryptographic keys
-- -------------------------------------------------------------------------

INSERT INTO cryptographic_keys (
    key_name,
    algorithm,
    nonce_bytes
)
VALUES
    ('repository-aead-2026', 'AES-256-GCM', 12),
    ('service-aead-2026', 'CHACHA20-POLY1305', 12);

-- -------------------------------------------------------------------------
-- Seed sessions
-- -------------------------------------------------------------------------

INSERT INTO sessions (
    session_name,
    key_id,
    session_namespace
)
SELECT
    'repository-session-alpha',
    key_id,
    1001
FROM cryptographic_keys
WHERE key_name = 'repository-aead-2026';

INSERT INTO replay_windows (
    session_id,
    highest_sequence,
    window_size
)
SELECT
    session_id,
    -1,
    64
FROM sessions
WHERE session_name = 'repository-session-alpha';

-- -------------------------------------------------------------------------
-- Allocate deterministic nonces transactionally
-- -------------------------------------------------------------------------

BEGIN;

SELECT *
FROM allocate_nonce_counter(
    (
        SELECT session_id
        FROM sessions
        WHERE session_name = 'repository-session-alpha'
    )
);

SELECT *
FROM allocate_nonce_counter(
    (
        SELECT session_id
        FROM sessions
        WHERE session_name = 'repository-session-alpha'
    )
);

COMMIT;

-- -------------------------------------------------------------------------
-- Inspect allocated nonce state
-- -------------------------------------------------------------------------

SELECT
    na.allocation_id,
    s.session_name,
    ck.key_name,
    na.counter_value,
    encode(na.nonce, 'hex') AS nonce_hex,
    na.allocated_at
FROM nonce_allocations na
JOIN sessions s
  ON s.session_id = na.session_id
JOIN cryptographic_keys ck
  ON ck.key_id = na.key_id
ORDER BY na.allocation_id;

-- -------------------------------------------------------------------------
-- Accept a realistic message
-- -------------------------------------------------------------------------

WITH allocated AS (
    SELECT
        session_id,
        key_id,
        nonce
    FROM nonce_allocations
    ORDER BY allocation_id
    LIMIT 1
)
SELECT accept_message(
    allocated.session_id,
    allocated.key_id,
    1,
    allocated.nonce,
    decode('746573742d63697068657274657874', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    convert_to('protocol=v1', 'UTF8')
)
FROM allocated;

-- -------------------------------------------------------------------------
-- Demonstrate database-level nonce reuse prevention
-- -------------------------------------------------------------------------

WITH allocated AS (
    SELECT
        session_id,
        key_id,
        nonce
    FROM nonce_allocations
    ORDER BY allocation_id
    LIMIT 1
)
SELECT accept_message(
    allocated.session_id,
    allocated.key_id,
    2,
    allocated.nonce,
    decode('7265757365642d6e6f6e6365', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    NULL
)
FROM allocated;

-- -------------------------------------------------------------------------
-- Demonstrate replay rejection
-- -------------------------------------------------------------------------

WITH allocated AS (
    SELECT
        session_id,
        key_id,
        nonce
    FROM nonce_allocations
    ORDER BY allocation_id
    LIMIT 1
)
SELECT accept_message(
    allocated.session_id,
    allocated.key_id,
    -1,
    (
        SELECT nonce
        FROM nonce_allocations
        ORDER BY allocation_id DESC
        LIMIT 1
    ),
    decode('7265706c6179', 'hex'),
    decode('00112233445566778899aabbccddeeff', 'hex'),
    NULL
)
FROM allocated;

-- -------------------------------------------------------------------------
-- Governance reports
-- -------------------------------------------------------------------------

SELECT
    state,
    COUNT(*) AS message_count
FROM messages
GROUP BY state
ORDER BY state;

SELECT
    ck.key_name,
    COUNT(*) AS unique_nonce_count
FROM nonce_allocations na
JOIN cryptographic_keys ck
  ON ck.key_id = na.key_id
GROUP BY ck.key_name
ORDER BY ck.key_name;

SELECT
    ne.event_type,
    COUNT(*) AS event_count
FROM nonce_events ne
GROUP BY ne.event_type
ORDER BY ne.event_type;

-- -------------------------------------------------------------------------
-- Detect suspicious repeated sequence numbers
-- -------------------------------------------------------------------------

SELECT
    session_id,
    sequence_number,
    COUNT(*) AS occurrences
FROM messages
GROUP BY session_id, sequence_number
HAVING COUNT(*) > 1
ORDER BY occurrences DESC;

-- -------------------------------------------------------------------------
-- Demonstrate key lifecycle enforcement
-- -------------------------------------------------------------------------

UPDATE cryptographic_keys
SET
    status = 'RETIRED',
    retired_at = CURRENT_TIMESTAMP
WHERE key_name = 'service-aead-2026';

-- A retired key is excluded by allocate_nonce_counter and accept_message.
SELECT
    key_name,
    algorithm,
    nonce_bytes,
    status,
    created_at,
    retired_at
FROM cryptographic_keys
ORDER BY key_id;
