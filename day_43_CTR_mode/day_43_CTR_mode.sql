-- PostgreSQL: CTR mode operation ledger and authenticated-transfer controls.
--
-- This schema records key identities, counter allocations, transfer metadata,
-- and verification results. It does not implement AES in SQL. Encryption
-- belongs in a vetted application cryptographic library.
--
-- CTR confidentiality depends on unique counter blocks for every message
-- encrypted under the same key. A repeated counter block repeats keystream.
-- Database controls can coordinate allocation, but key material must not
-- be stored in this ledger.

BEGIN;

DROP VIEW IF EXISTS ctr_transfer_audit;
DROP TABLE IF EXISTS transfer_events CASCADE;
DROP TABLE IF EXISTS encrypted_transfers CASCADE;
DROP TABLE IF EXISTS counter_allocations CASCADE;
DROP TABLE IF EXISTS crypto_keys CASCADE;

CREATE TABLE crypto_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_name TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('AES-128-CTR', 'AES-192-CTR', 'AES-256-CTR')),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'retired', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    UNIQUE (key_name, key_version),
    CHECK (
        (status = 'active' AND retired_at IS NULL)
        OR status <> 'active'
    )
);

CREATE TABLE counter_allocations (
    allocation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_id BIGINT NOT NULL REFERENCES crypto_keys(key_id),
    nonce_prefix BYTEA NOT NULL CHECK (octet_length(nonce_prefix) > 0),
    initial_counter NUMERIC(39, 0) NOT NULL
        CHECK (
            initial_counter >= 0
            AND initial_counter < 340282366920938463463374607431768211456
        ),
    counter_block_count BIGINT NOT NULL CHECK (counter_block_count > 0),
    allocated_to TEXT NOT NULL CHECK (length(trim(allocated_to)) > 0),
    allocated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (key_id, nonce_prefix, initial_counter)
);

-- This constraint prevents duplicate starting values. The allocation service
-- must also prevent overlapping counter ranges for a shared nonce prefix.
CREATE INDEX idx_counter_allocations_key_time
    ON counter_allocations (key_id, allocated_at DESC);

CREATE TABLE encrypted_transfers (
    transfer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_reference TEXT NOT NULL UNIQUE,
    key_id BIGINT NOT NULL REFERENCES crypto_keys(key_id),
    allocation_id BIGINT NOT NULL UNIQUE
        REFERENCES counter_allocations(allocation_id),
    source_service TEXT NOT NULL CHECK (length(trim(source_service)) > 0),
    target_service TEXT NOT NULL CHECK (length(trim(target_service)) > 0),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    ciphertext_length BIGINT NOT NULL CHECK (ciphertext_length >= 0),
    mode TEXT NOT NULL DEFAULT 'CTR'
        CHECK (mode IN ('CTR')),
    authentication_mode TEXT NOT NULL
        CHECK (authentication_mode IN ('none', 'external')),
    state TEXT NOT NULL DEFAULT 'created'
        CHECK (state IN ('created', 'encrypted', 'delivered', 'verified', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    CHECK (plaintext_length = ciphertext_length),
    CHECK (
        (state IN ('created', 'encrypted') AND verified_at IS NULL)
        OR state IN ('delivered', 'verified', 'rejected')
    ),
    CHECK (
        (state = 'verified' AND verified_at IS NOT NULL)
        OR state <> 'verified'
    )
);

CREATE INDEX idx_transfers_state_created
    ON encrypted_transfers (state, created_at DESC);

CREATE INDEX idx_transfers_key
    ON encrypted_transfers (key_id, created_at DESC);

CREATE TABLE transfer_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    transfer_id BIGINT NOT NULL REFERENCES encrypted_transfers(transfer_id),
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'created', 'encrypted', 'delivered', 'verified',
            'rejected', 'counter_conflict', 'authentication_failure'
        )
    ),
    event_detail TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_transfer_events_history
    ON transfer_events (transfer_id, occurred_at);

CREATE OR REPLACE FUNCTION record_transfer_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO transfer_events (transfer_id, event_type, event_detail)
        VALUES (NEW.transfer_id, NEW.state, 'Initial transfer state');
        RETURN NEW;
    END IF;

    IF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO transfer_events (transfer_id, event_type, event_detail)
        VALUES (
            NEW.transfer_id,
            NEW.state,
            format('State changed from %s to %s', OLD.state, NEW.state)
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transfer_state_history
AFTER INSERT OR UPDATE OF state ON encrypted_transfers
FOR EACH ROW
EXECUTE FUNCTION record_transfer_event();

CREATE OR REPLACE FUNCTION enforce_transfer_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.key_id <> OLD.key_id
       OR NEW.allocation_id <> OLD.allocation_id THEN
        RAISE EXCEPTION
            'Key identity and counter allocation are immutable after creation';
    END IF;

    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.state = 'created' AND NEW.state = 'encrypted')
        OR (OLD.state = 'encrypted' AND NEW.state = 'delivered')
        OR (OLD.state = 'delivered' AND NEW.state IN ('verified', 'rejected'))
    ) THEN
        RAISE EXCEPTION
            'Invalid transfer state transition: % -> %', OLD.state, NEW.state;
    END IF;

    IF NEW.state = 'delivered' AND NEW.delivered_at IS NULL THEN
        NEW.delivered_at := now();
    END IF;

    IF NEW.state IN ('verified', 'rejected') AND NEW.verified_at IS NULL THEN
        NEW.verified_at := now();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_transfer_transition
BEFORE UPDATE ON encrypted_transfers
FOR EACH ROW
EXECUTE FUNCTION enforce_transfer_transition();

CREATE VIEW ctr_transfer_audit AS
SELECT
    t.transfer_id,
    t.external_reference,
    k.key_name,
    k.key_version,
    k.algorithm,
    t.source_service,
    t.target_service,
    t.plaintext_length,
    t.ciphertext_length,
    t.authentication_mode,
    t.state,
    a.nonce_prefix,
    a.initial_counter,
    a.counter_block_count,
    a.allocated_to,
    t.created_at,
    t.verified_at
FROM encrypted_transfers t
JOIN crypto_keys k ON k.key_id = t.key_id
JOIN counter_allocations a ON a.allocation_id = t.allocation_id;

INSERT INTO crypto_keys (key_name, algorithm, key_version)
VALUES
    ('inspection-transport', 'AES-256-CTR', 1),
    ('archive-transport', 'AES-128-CTR', 3);

-- The nonce prefix is public metadata, not a secret. Its uniqueness and
-- the counter range must be managed for each key.
INSERT INTO counter_allocations
    (key_id, nonce_prefix, initial_counter, counter_block_count, allocated_to)
VALUES
    (1, decode('a1b2c3d4', 'hex'), 1000, 8, 'inspection-service'),
    (1, decode('a1b2c3d4', 'hex'), 1008, 4, 'inspection-service'),
    (2, decode('01020304', 'hex'), 1000, 6, 'archive-service');

INSERT INTO encrypted_transfers (
    external_reference,
    key_id,
    allocation_id,
    source_service,
    target_service,
    plaintext_length,
    ciphertext_length,
    authentication_mode,
    state
)
VALUES
    (
        'INS-2026-1001', 1, 1,
        'inspection-service', 'central-records',
        512, 512, 'external', 'created'
    ),
    (
        'INS-2026-1002', 1, 2,
        'inspection-service', 'central-records',
        256, 256, 'external', 'created'
    ),
    (
        'ARC-2026-0021', 2, 3,
        'archive-service', 'cold-storage',
        1024, 1024, 'none', 'created'
    );

-- The allocation identifier is unique per transfer. Applications should
-- allocate counter ranges transactionally and reject overlapping ranges
-- for the same key and nonce prefix.
UPDATE encrypted_transfers
SET state = 'encrypted'
WHERE external_reference IN ('INS-2026-1001', 'INS-2026-1002');

UPDATE encrypted_transfers
SET state = 'delivered'
WHERE external_reference = 'INS-2026-1001';

UPDATE encrypted_transfers
SET state = 'verified'
WHERE external_reference = 'INS-2026-1001';

-- Audit status by key and authentication mode. CTR records with no external
-- authentication are flagged because successful decryption cannot prove
-- that ciphertext has not been altered.
SELECT
    key_name,
    authentication_mode,
    state,
    COUNT(*) AS transfer_count,
    SUM(ciphertext_length) AS ciphertext_bytes
FROM ctr_transfer_audit
GROUP BY key_name, authentication_mode, state
ORDER BY key_name, authentication_mode, state;

SELECT
    external_reference,
    state,
    authentication_mode,
    CASE
        WHEN authentication_mode = 'none'
            THEN 'Confidentiality only; integrity is not verified'
        WHEN state <> 'verified'
            THEN 'External authentication must be confirmed'
        ELSE 'Application reports verification'
    END AS security_assessment
FROM ctr_transfer_audit
ORDER BY external_reference;

-- Show state-transition evidence.
SELECT
    t.external_reference,
    e.event_type,
    e.event_detail,
    e.occurred_at
FROM transfer_events e
JOIN encrypted_transfers t ON t.transfer_id = e.transfer_id
ORDER BY t.external_reference, e.occurred_at, e.event_id;

-- Database constraint demonstration: the following statement would fail
-- because ciphertext length must equal plaintext length in CTR mode.
-- Uncomment to test inside a transaction:
-- UPDATE encrypted_transfers
-- SET ciphertext_length = plaintext_length + 1
-- WHERE external_reference = 'INS-2026-1001';

-- Invalid transitions are rejected by the trigger.
-- Uncomment to test:
-- UPDATE encrypted_transfers
-- SET state = 'created'
-- WHERE external_reference = 'INS-2026-1001';

COMMIT;
