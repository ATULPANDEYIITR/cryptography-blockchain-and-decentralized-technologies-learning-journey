/*
 * ECDH IN BLOCKCHAIN
 * PostgreSQL relational implementation
 *
 * Models:
 * - Blockchain networks
 * - Repositories of wallet identities
 * - Wallet public-key registration
 * - ECDH sessions
 * - Session commitments
 * - Blockchain transactions
 * - Blocks
 * - Transaction inclusion
 * - Cryptographic audit records
 * - Replay protection
 * - Key lifecycle and revocation
 *
 * Requires PostgreSQL with pgcrypto installed.
 *
 * IMPORTANT:
 * PostgreSQL stores public keys and commitments, never private
 * ECDH keys or raw shared secrets.
 *
 * ECDH arithmetic and secure-channel key derivation are performed
 * by the participating applications.
 */

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS ecdh_chain;

SET search_path TO ecdh_chain, public;

-- ============================================================
-- 1. Domain types
-- ============================================================

CREATE TYPE wallet_status AS ENUM (
    'ACTIVE',
    'SUSPENDED',
    'REVOKED'
);

CREATE TYPE session_status AS ENUM (
    'INITIATED',
    'ESTABLISHED',
    'EXPIRED',
    'FAILED',
    'REVOKED'
);

CREATE TYPE transaction_status AS ENUM (
    'PENDING',
    'INCLUDED',
    'REJECTED'
);

CREATE TYPE block_status AS ENUM (
    'PROPOSED',
    'VALIDATED',
    'FINALIZED',
    'REJECTED'
);

CREATE TYPE key_algorithm AS ENUM (
    'SECP256K1',
    'SECP256R1'
);

-- ============================================================
-- 2. Blockchain networks
-- ============================================================

CREATE TABLE blockchain_networks (
    network_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    network_name VARCHAR(100) NOT NULL UNIQUE,
    chain_identifier VARCHAR(100) NOT NULL UNIQUE,
    consensus_mechanism VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(trim(network_name)) > 0)
);

-- ============================================================
-- 3. Wallet identities
-- ============================================================

CREATE TABLE wallets (
    wallet_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    network_id BIGINT NOT NULL
        REFERENCES blockchain_networks(network_id),
    wallet_address VARCHAR(100) NOT NULL,
    public_key BYTEA NOT NULL,
    key_algorithm key_algorithm NOT NULL,
    key_fingerprint CHAR(64) NOT NULL,
    status wallet_status NOT NULL DEFAULT 'ACTIVE',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,

    UNIQUE (network_id, wallet_address),
    UNIQUE (network_id, key_fingerprint),

    CHECK (length(wallet_address) >= 10),
    CHECK (octet_length(public_key) > 0),
    CHECK (key_fingerprint ~ '^[a-f0-9]{64}$'),
    CHECK (
        (status = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (status <> 'REVOKED' AND revoked_at IS NULL)
    )
);

CREATE INDEX idx_wallet_active
ON wallets(network_id, wallet_address)
WHERE status = 'ACTIVE';

-- ============================================================
-- 4. ECDH sessions
-- ============================================================

CREATE TABLE ecdh_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    network_id BIGINT NOT NULL
        REFERENCES blockchain_networks(network_id),

    initiator_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    responder_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    algorithm key_algorithm NOT NULL,

    session_nonce BYTEA NOT NULL,

    context_hash CHAR(64) NOT NULL,

    channel_commitment CHAR(64),

    status session_status NOT NULL DEFAULT 'INITIATED',

    initiated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    established_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ NOT NULL,

    failure_reason TEXT,

    CHECK (initiator_wallet_id <> responder_wallet_id),
    CHECK (octet_length(session_nonce) >= 16),
    CHECK (context_hash ~ '^[a-f0-9]{64}$'),
    CHECK (
        channel_commitment IS NULL
        OR channel_commitment ~ '^[a-f0-9]{64}$'
    ),
    CHECK (expires_at > initiated_at),
    CHECK (
        (status = 'ESTABLISHED'
            AND established_at IS NOT NULL
            AND channel_commitment IS NOT NULL)
        OR
        (status <> 'ESTABLISHED'
            AND established_at IS NULL
            AND channel_commitment IS NULL)
    )
);

CREATE INDEX idx_sessions_participants
ON ecdh_sessions(
    initiator_wallet_id,
    responder_wallet_id,
    initiated_at DESC
);

CREATE INDEX idx_sessions_expiration
ON ecdh_sessions(expires_at)
WHERE status IN ('INITIATED', 'ESTABLISHED');

-- ============================================================
-- 5. ECDH session transition validation
-- ============================================================

CREATE OR REPLACE FUNCTION validate_ecdh_session()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    initiator_status wallet_status;
    responder_status wallet_status;
    initiator_network BIGINT;
    responder_network BIGINT;
BEGIN
    SELECT status, network_id
    INTO initiator_status, initiator_network
    FROM wallets
    WHERE wallet_id = NEW.initiator_wallet_id;

    SELECT status, network_id
    INTO responder_status, responder_network
    FROM wallets
    WHERE wallet_id = NEW.responder_wallet_id;

    IF initiator_status IS NULL OR responder_status IS NULL THEN
        RAISE EXCEPTION 'Unknown ECDH participant';
    END IF;

    IF initiator_status <> 'ACTIVE'
       OR responder_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Both wallets must be active';
    END IF;

    IF initiator_network <> NEW.network_id
       OR responder_network <> NEW.network_id THEN
        RAISE EXCEPTION 'Wallets must belong to the session network';
    END IF;

    IF NEW.status = 'ESTABLISHED' THEN
        IF NEW.channel_commitment IS NULL THEN
            RAISE EXCEPTION 'Established session requires commitment';
        END IF;

        IF NEW.established_at IS NULL THEN
            RAISE EXCEPTION 'Established session requires timestamp';
        END IF;

        IF NEW.expires_at <= now() THEN
            RAISE EXCEPTION 'Expired session cannot be established';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_ecdh_session
BEFORE INSERT OR UPDATE ON ecdh_sessions
FOR EACH ROW
EXECUTE FUNCTION validate_ecdh_session();

-- ============================================================
-- 6. Blockchain blocks
-- ============================================================

CREATE TABLE blocks (
    block_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    network_id BIGINT NOT NULL
        REFERENCES blockchain_networks(network_id),

    block_height BIGINT NOT NULL,

    previous_hash CHAR(64),

    block_hash CHAR(64) NOT NULL,

    transaction_root CHAR(64),

    status block_status NOT NULL DEFAULT 'PROPOSED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    finalized_at TIMESTAMPTZ,

    UNIQUE (network_id, block_height),
    UNIQUE (network_id, block_hash),

    CHECK (block_height >= 0),
    CHECK (block_hash ~ '^[a-f0-9]{64}$'),
    CHECK (
        previous_hash IS NULL
        OR previous_hash ~ '^[a-f0-9]{64}$'
    ),
    CHECK (
        transaction_root IS NULL
        OR transaction_root ~ '^[a-f0-9]{64}$'
    )
);

CREATE INDEX idx_blocks_network_height
ON blocks(network_id, block_height DESC);

-- ============================================================
-- 7. Blockchain transactions
-- ============================================================

CREATE TABLE blockchain_transactions (
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    network_id BIGINT NOT NULL
        REFERENCES blockchain_networks(network_id),

    sender_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    recipient_wallet_id BIGINT NOT NULL
        REFERENCES wallets(wallet_id),

    session_id UUID
        REFERENCES ecdh_sessions(session_id),

    transaction_nonce BIGINT NOT NULL,

    amount NUMERIC(30, 8) NOT NULL,

    channel_commitment CHAR(64) NOT NULL,

    transaction_hash CHAR(64) NOT NULL,

    status transaction_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (sender_wallet_id <> recipient_wallet_id),
    CHECK (transaction_nonce >= 0),
    CHECK (amount > 0),
    CHECK (channel_commitment ~ '^[a-f0-9]{64}$'),
    CHECK (transaction_hash ~ '^[a-f0-9]{64}$'),

    UNIQUE (
        network_id,
        sender_wallet_id,
        transaction_nonce
    ),

    UNIQUE (network_id, transaction_hash)
);

CREATE INDEX idx_transactions_sender
ON blockchain_transactions(
    network_id,
    sender_wallet_id,
    created_at DESC
);

CREATE INDEX idx_transactions_recipient
ON blockchain_transactions(
    network_id,
    recipient_wallet_id,
    created_at DESC
);

CREATE INDEX idx_transactions_pending
ON blockchain_transactions(network_id, created_at)
WHERE status = 'PENDING';

-- ============================================================
-- 8. Transaction inclusion
-- ============================================================

CREATE TABLE block_transactions (
    block_id BIGINT NOT NULL
        REFERENCES blocks(block_id),

    transaction_id UUID NOT NULL
        REFERENCES blockchain_transactions(transaction_id),

    transaction_position INTEGER NOT NULL,

    PRIMARY KEY (block_id, transaction_id),

    UNIQUE (block_id, transaction_position),

    CHECK (transaction_position >= 0)
);

-- ============================================================
-- 9. ECDH security audit
-- ============================================================

CREATE TABLE ecdh_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID
        REFERENCES ecdh_sessions(session_id),

    wallet_id BIGINT
        REFERENCES wallets(wallet_id),

    event_type VARCHAR(50) NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (length(trim(event_type)) > 0)
);

CREATE INDEX idx_ecdh_audit_session
ON ecdh_audit(session_id, event_timestamp DESC);

CREATE INDEX idx_ecdh_audit_type
ON ecdh_audit(event_type, event_timestamp DESC);

-- ============================================================
-- 10. Transaction consistency validation
-- ============================================================

CREATE OR REPLACE FUNCTION validate_transaction()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    sender_status wallet_status;
    recipient_status wallet_status;
    sender_network BIGINT;
    recipient_network BIGINT;
    session_record ecdh_sessions%ROWTYPE;
BEGIN
    SELECT status, network_id
    INTO sender_status, sender_network
    FROM wallets
    WHERE wallet_id = NEW.sender_wallet_id;

    SELECT status, network_id
    INTO recipient_status, recipient_network
    FROM wallets
    WHERE wallet_id = NEW.recipient_wallet_id;

    IF sender_status <> 'ACTIVE'
       OR recipient_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Both wallets must be active';
    END IF;

    IF sender_network <> NEW.network_id
       OR recipient_network <> NEW.network_id THEN
        RAISE EXCEPTION 'Transaction network mismatch';
    END IF;

    IF NEW.session_id IS NOT NULL THEN
        SELECT *
        INTO session_record
        FROM ecdh_sessions
        WHERE session_id = NEW.session_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Unknown ECDH session';
        END IF;

        IF session_record.status <> 'ESTABLISHED' THEN
            RAISE EXCEPTION 'ECDH session is not established';
        END IF;

        IF session_record.expires_at <= now() THEN
            RAISE EXCEPTION 'ECDH session has expired';
        END IF;

        IF session_record.channel_commitment
           <> NEW.channel_commitment THEN
            RAISE EXCEPTION 'Channel commitment mismatch';
        END IF;

        IF NOT (
            (
                session_record.initiator_wallet_id =
                    NEW.sender_wallet_id
                AND session_record.responder_wallet_id =
                    NEW.recipient_wallet_id
            )
            OR
            (
                session_record.responder_wallet_id =
                    NEW.sender_wallet_id
                AND session_record.initiator_wallet_id =
                    NEW.recipient_wallet_id
            )
        ) THEN
            RAISE EXCEPTION 'Transaction participants mismatch';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_transaction
BEFORE INSERT ON blockchain_transactions
FOR EACH ROW
EXECUTE FUNCTION validate_transaction();

-- ============================================================
-- 11. Transaction inclusion processing
-- ============================================================

CREATE OR REPLACE FUNCTION include_transaction(
    p_block_id BIGINT,
    p_transaction_id UUID,
    p_position INTEGER
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    block_record blocks%ROWTYPE;
    transaction_record blockchain_transactions%ROWTYPE;
BEGIN
    SELECT *
    INTO block_record
    FROM blocks
    WHERE block_id = p_block_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block does not exist';
    END IF;

    IF block_record.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'Block is not open for transactions';
    END IF;

    SELECT *
    INTO transaction_record
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction does not exist';
    END IF;

    IF transaction_record.status <> 'PENDING' THEN
        RAISE EXCEPTION 'Transaction is not pending';
    END IF;

    IF transaction_record.network_id <> block_record.network_id THEN
        RAISE EXCEPTION 'Network mismatch';
    END IF;

    IF p_position < 0 THEN
        RAISE EXCEPTION 'Invalid transaction position';
    END IF;

    INSERT INTO block_transactions(
        block_id,
        transaction_id,
        transaction_position
    )
    VALUES (
        p_block_id,
        p_transaction_id,
        p_position
    );

    UPDATE blockchain_transactions
    SET status = 'INCLUDED'
    WHERE transaction_id = p_transaction_id;

END;
$$;

-- ============================================================
-- 12. Block validation
-- ============================================================

CREATE OR REPLACE FUNCTION validate_block(
    p_block_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    current_block blocks%ROWTYPE;
    previous_block blocks%ROWTYPE;
    included_count BIGINT;
    expected_root TEXT;
BEGIN
    SELECT *
    INTO current_block
    FROM blocks
    WHERE block_id = p_block_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block does not exist';
    END IF;

    IF current_block.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'Block cannot be validated in current state';
    END IF;

    IF current_block.block_height > 0 THEN
        SELECT *
        INTO previous_block
        FROM blocks
        WHERE network_id = current_block.network_id
          AND block_height = current_block.block_height - 1;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Previous block is missing';
        END IF;

        IF current_block.previous_hash <> previous_block.block_hash THEN
            RAISE EXCEPTION 'Previous block hash mismatch';
        END IF;
    ELSE
        IF current_block.previous_hash IS NOT NULL THEN
            RAISE EXCEPTION 'Genesis block must not have a previous hash';
        END IF;
    END IF;

    SELECT count(*)
    INTO included_count
    FROM block_transactions
    WHERE block_id = p_block_id;

    SELECT encode(
        digest(
            COALESCE(
                string_agg(
                    transaction_hash,
                    '' ORDER BY bt.transaction_position
                ),
                ''
            ),
            'sha256'
        ),
        'hex'
    )
    INTO expected_root
    FROM block_transactions bt
    JOIN blockchain_transactions tx
      ON tx.transaction_id = bt.transaction_id
    WHERE bt.block_id = p_block_id;

    IF current_block.transaction_root IS DISTINCT FROM expected_root THEN
        RAISE EXCEPTION 'Transaction root mismatch';
    END IF;

    UPDATE blocks
    SET status = 'VALIDATED'
    WHERE block_id = p_block_id;

    RETURN TRUE;
END;
$$;

-- ============================================================
-- 13. Finalization
-- ============================================================

CREATE OR REPLACE FUNCTION finalize_block(
    p_block_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE blocks
    SET status = 'FINALIZED',
        finalized_at = now()
    WHERE block_id = p_block_id
      AND status = 'VALIDATED';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Only validated blocks can be finalized';
    END IF;
END;
$$;

-- ============================================================
-- 14. Reporting views
-- ============================================================

CREATE VIEW wallet_security_report AS
SELECT
    w.wallet_id,
    w.wallet_address,
    w.key_algorithm,
    w.status,
    w.registered_at,
    count(DISTINCT s.session_id) AS total_sessions,
    count(DISTINCT t.transaction_id) AS total_transactions
FROM wallets w
LEFT JOIN ecdh_sessions s
    ON w.wallet_id IN (
        s.initiator_wallet_id,
        s.responder_wallet_id
    )
LEFT JOIN blockchain_transactions t
    ON w.wallet_id IN (
        t.sender_wallet_id,
        t.recipient_wallet_id
    )
GROUP BY
    w.wallet_id,
    w.wallet_address,
    w.key_algorithm,
    w.status,
    w.registered_at;

CREATE VIEW blockchain_transaction_report AS
SELECT
    n.network_name,
    tx.transaction_id,
    sender.wallet_address AS sender,
    recipient.wallet_address AS recipient,
    tx.amount,
    tx.transaction_nonce,
    tx.status,
    tx.created_at,
    s.status AS ecdh_session_status
FROM blockchain_transactions tx
JOIN blockchain_networks n
    ON n.network_id = tx.network_id
JOIN wallets sender
    ON sender.wallet_id = tx.sender_wallet_id
JOIN wallets recipient
    ON recipient.wallet_id = tx.recipient_wallet_id
LEFT JOIN ecdh_sessions s
    ON s.session_id = tx.session_id;

-- ============================================================
-- 15. Eligibility evaluation
-- ============================================================

CREATE OR REPLACE FUNCTION check_ecdh_eligibility(
    p_session_id UUID
)
RETURNS TABLE (
    eligible BOOLEAN,
    reason TEXT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        (
            s.status = 'ESTABLISHED'
            AND s.expires_at > now()
            AND a.status = 'ACTIVE'
            AND b.status = 'ACTIVE'
            AND s.channel_commitment IS NOT NULL
        ) AS eligible,

        CASE
            WHEN s.session_id IS NULL
                THEN 'Session not found'
            WHEN s.status <> 'ESTABLISHED'
                THEN 'Session is not established'
            WHEN s.expires_at <= now()
                THEN 'Session expired'
            WHEN a.status <> 'ACTIVE'
                THEN 'Initiator wallet inactive'
            WHEN b.status <> 'ACTIVE'
                THEN 'Responder wallet inactive'
            ELSE 'ECDH session eligible'
        END AS reason

    FROM ecdh_sessions s
    JOIN wallets a
      ON a.wallet_id = s.initiator_wallet_id
    JOIN wallets b
      ON b.wallet_id = s.responder_wallet_id
    WHERE s.session_id = p_session_id;
$$;

-- ============================================================
-- 16. Sample data
-- ============================================================

INSERT INTO blockchain_networks(
    network_name,
    chain_identifier,
    consensus_mechanism
)
VALUES
(
    'Enterprise Demonstration Chain',
    'enterprise-ecdh-001',
    'Proof of Authority'
),
(
    'Private Research Chain',
    'research-ecdh-002',
    'Permissioned BFT'
);

INSERT INTO wallets(
    network_id,
    wallet_address,
    public_key,
    key_algorithm,
    key_fingerprint
)
VALUES
(
    1,
    '0xALICE00000000000000000000000000000001',
    decode(repeat('11', 33), 'hex'),
    'SECP256K1',
    encode(digest(decode(repeat('11', 33), 'hex'), 'sha256'), 'hex')
),
(
    1,
    '0xBOB00000000000000000000000000000000002',
    decode(repeat('22', 33), 'hex'),
    'SECP256K1',
    encode(digest(decode(repeat('22', 33), 'hex'), 'sha256'), 'hex')
),
(
    1,
    '0xCHARLIE00000000000000000000000000000003',
    decode(repeat('33', 33), 'hex'),
    'SECP256K1',
    encode(digest(decode(repeat('33', 33), 'hex'), 'sha256'), 'hex')
);

-- The sample public-key bytes are illustrative records.
-- They are not asserted to be valid curve points.

INSERT INTO ecdh_sessions(
    session_id,
    network_id,
    initiator_wallet_id,
    responder_wallet_id,
    algorithm,
    session_nonce,
    context_hash,
    status,
    expires_at
)
VALUES
(
    '11111111-1111-1111-1111-111111111111',
    1,
    1,
    2,
    'SECP256K1',
    gen_random_bytes(32),
    encode(digest('alice-bob-context', 'sha256'), 'hex'),
    'INITIATED',
    now() + interval '1 hour'
),
(
    '22222222-2222-2222-2222-222222222222',
    1,
    2,
    3,
    'SECP256K1',
    gen_random_bytes(32),
    encode(digest('bob-charlie-context', 'sha256'), 'hex'),
    'INITIATED',
    now() + interval '1 hour'
);

UPDATE ecdh_sessions
SET status = 'ESTABLISHED',
    established_at = now(),
    channel_commitment =
        encode(digest('alice-bob-channel', 'sha256'), 'hex')
WHERE session_id =
    '11111111-1111-1111-1111-111111111111';

UPDATE ecdh_sessions
SET status = 'FAILED',
    failure_reason = 'Peer authentication failed'
WHERE session_id =
    '22222222-2222-2222-2222-222222222222';

INSERT INTO ecdh_audit(
    session_id,
    wallet_id,
    event_type,
    event_details
)
VALUES
(
    '11111111-1111-1111-1111-111111111111',
    1,
    'ECDH_ESTABLISHED',
    '{"algorithm":"secp256k1","kdf":"HKDF-SHA256"}'
),
(
    '22222222-2222-2222-2222-222222222222',
    2,
    'ECDH_FAILED',
    '{"reason":"peer_authentication_failed"}'
);

INSERT INTO blockchain_transactions(
    transaction_id,
    network_id,
    sender_wallet_id,
    recipient_wallet_id,
    session_id,
    transaction_nonce,
    amount,
    channel_commitment,
    transaction_hash
)
VALUES
(
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    1,
    1,
    2,
    '11111111-1111-1111-1111-111111111111',
    0,
    100.00,
    (
        SELECT channel_commitment
        FROM ecdh_sessions
        WHERE session_id =
            '11111111-1111-1111-1111-111111111111'
    ),
    encode(digest('transaction-alice-bob-001', 'sha256'), 'hex')
);

-- ============================================================
-- 17. Block creation and transaction inclusion
-- ============================================================

INSERT INTO blocks(
    network_id,
    block_height,
    previous_hash,
    block_hash,
    transaction_root,
    status
)
VALUES
(
    1,
    0,
    NULL,
    encode(digest('genesis-enterprise-ecdh', 'sha256'), 'hex'),
    encode(digest('', 'sha256'), 'hex'),
    'FINALIZED'
),
(
    1,
    1,
    (
        SELECT block_hash
        FROM blocks
        WHERE network_id = 1
          AND block_height = 0
    ),
    encode(digest('block-enterprise-001', 'sha256'), 'hex'),
    (
        SELECT encode(
            digest(transaction_hash, 'sha256'),
            'hex'
        )
        FROM blockchain_transactions
        WHERE transaction_id =
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    ),
    'PROPOSED'
);

-- The inclusion operation and validation are atomic.
DO $$
DECLARE
    target_block BIGINT;
BEGIN
    SELECT block_id
    INTO target_block
    FROM blocks
    WHERE network_id = 1
      AND block_height = 1;

    PERFORM include_transaction(
        target_block,
        'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        0
    );

    PERFORM validate_block(target_block);

    PERFORM finalize_block(target_block);
END;
$$;

COMMIT;

-- ============================================================
-- 18. Retrieval queries
-- ============================================================

SELECT *
FROM wallets
ORDER BY wallet_id;

SELECT *
FROM ecdh_sessions
ORDER BY initiated_at DESC;

SELECT *
FROM blockchain_transaction_report
ORDER BY created_at DESC;

-- ============================================================
-- 19. ECDH eligibility evaluation
-- ============================================================

SELECT *
FROM check_ecdh_eligibility(
    '11111111-1111-1111-1111-111111111111'
);

SELECT *
FROM check_ecdh_eligibility(
    '22222222-2222-2222-2222-222222222222'
);

-- ============================================================
-- 20. Aggregation and reporting
-- ============================================================

SELECT
    status,
    count(*) AS session_count
FROM ecdh_sessions
GROUP BY status
ORDER BY status;

SELECT
    key_algorithm,
    status,
    count(*) AS wallet_count
FROM wallets
GROUP BY key_algorithm, status
ORDER BY key_algorithm, status;

SELECT
    network_id,
    status,
    count(*) AS transaction_count,
    sum(amount) AS total_amount
FROM blockchain_transactions
GROUP BY network_id, status;

SELECT *
FROM wallet_security_report
ORDER BY wallet_id;

-- ============================================================
-- 21. CTE-based transaction analytics
-- ============================================================

WITH transaction_activity AS (
    SELECT
        sender_wallet_id AS wallet_id,
        amount
    FROM blockchain_transactions

    UNION ALL

    SELECT
        recipient_wallet_id AS wallet_id,
        amount
    FROM blockchain_transactions
),
wallet_totals AS (
    SELECT
        wallet_id,
        count(*) AS activity_count,
        sum(amount) AS activity_volume
    FROM transaction_activity
    GROUP BY wallet_id
)
SELECT
    w.wallet_address,
    COALESCE(t.activity_count, 0) AS activity_count,
    COALESCE(t.activity_volume, 0) AS activity_volume
FROM wallets w
LEFT JOIN wallet_totals t
    ON t.wallet_id = w.wallet_id
ORDER BY activity_volume DESC;

-- ============================================================
-- 22. Replay and integrity validation
-- ============================================================

SELECT
    network_id,
    sender_wallet_id,
    transaction_nonce,
    count(*) AS duplicate_count
FROM blockchain_transactions
GROUP BY
    network_id,
    sender_wallet_id,
    transaction_nonce
HAVING count(*) > 1;

SELECT
    block_height,
    status,
    previous_hash,
    block_hash
FROM blocks
WHERE network_id = 1
ORDER BY block_height;

-- ============================================================
-- 23. Invalid-operation demonstrations
-- ============================================================

-- Each example is isolated in an exception-handling block.
-- Expected failures do not abort the remaining demonstration.

DO $$
BEGIN
    BEGIN
        INSERT INTO blockchain_transactions(
            network_id,
            sender_wallet_id,
            recipient_wallet_id,
            transaction_nonce,
            amount,
            channel_commitment,
            transaction_hash
        )
        VALUES (
            1, 1, 2, 0, 50,
            repeat('a', 64),
            encode(digest('replay-attempt', 'sha256'), 'hex')
        );

        RAISE EXCEPTION 'Replay validation unexpectedly passed';

    EXCEPTION
        WHEN unique_violation THEN
            RAISE NOTICE 'Replay rejected by unique nonce constraint';
        WHEN OTHERS THEN
            RAISE NOTICE 'Invalid transaction rejected: %', SQLERRM;
    END;

    BEGIN
        UPDATE wallets
        SET status = 'REVOKED',
            revoked_at = now()
        WHERE wallet_id = 1;

        RAISE NOTICE 'Wallet revoked for lifecycle demonstration';

    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Wallet update failed: %', SQLERRM;
    END;
END;
$$;

-- ============================================================
-- 24. Operational security queries
-- ============================================================

-- Identify established sessions nearing expiration.
SELECT
    session_id,
    expires_at
FROM ecdh_sessions
WHERE status = 'ESTABLISHED'
  AND expires_at < now() + interval '15 minutes'
ORDER BY expires_at;

-- Identify failed sessions.
SELECT
    session_id,
    failure_reason,
    initiated_at
FROM ecdh_sessions
WHERE status = 'FAILED'
ORDER BY initiated_at DESC;

-- Identify wallet transactions involving inactive identities.
SELECT
    tx.transaction_id,
    tx.status,
    w.wallet_address,
    w.status AS wallet_status
FROM blockchain_transactions tx
JOIN wallets w
    ON w.wallet_id IN (
        tx.sender_wallet_id,
        tx.recipient_wallet_id
    )
WHERE w.status <> 'ACTIVE';

-- Inspect security events.
SELECT
    event_type,
    count(*) AS event_count
FROM ecdh_audit
GROUP BY event_type
ORDER BY event_count DESC;
