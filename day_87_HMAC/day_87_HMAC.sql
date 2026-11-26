/*
=================================================================
HMAC-SHA256 AND BLOCKCHAIN AUTHENTICATION
PostgreSQL 15+

Requirements:
    PostgreSQL
    pgcrypto extension

Demonstrates:
    1. HMAC-SHA256 using pgcrypto.
    2. Key identifiers and lifecycle management.
    3. Authenticated blockchain transactions.
    4. Canonical transaction serialization.
    5. Transaction replay protection.
    6. Block hash chaining.
    7. Status and integrity verification.
    8. Key rotation.
    9. Views, triggers, functions and reporting.
    10. Transactional block commitment.

IMPORTANT:
This is an educational database model.
Production HMAC secrets should be held outside the database
in a KMS or HSM. Do not expose secret material to ordinary
application roles.
=================================================================
*/

BEGIN;

-- ============================================================
-- 1. EXTENSIONS AND SCHEMA
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS blockchain_security;

SET search_path TO blockchain_security, public;

-- ============================================================
-- 2. ENUMERATED DOMAIN TYPES
-- ============================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'RETIRED',
    'REVOKED'
);

CREATE TYPE transaction_status AS ENUM (
    'CREATED',
    'AUTHENTICATED',
    'PENDING',
    'COMMITTED',
    'REJECTED'
);

CREATE TYPE block_status AS ENUM (
    'VALID',
    'INVALID'
);

CREATE TYPE check_status AS ENUM (
    'PASSED',
    'FAILED',
    'PENDING'
);

-- ============================================================
-- 3. KEY REGISTRY
-- ============================================================

CREATE TABLE cryptographic_keys (
    key_id VARCHAR(100) PRIMARY KEY,

    -- Demonstration only. Production secrets belong in a KMS.
    secret_key BYTEA NOT NULL,

    algorithm VARCHAR(30) NOT NULL DEFAULT 'HMAC-SHA256',

    status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    retired_at TIMESTAMPTZ,

    CONSTRAINT valid_hmac_algorithm
        CHECK (algorithm = 'HMAC-SHA256'),

    CONSTRAINT minimum_key_length
        CHECK (octet_length(secret_key) >= 32),

    CONSTRAINT valid_retirement_state
        CHECK (
            (status = 'ACTIVE' AND retired_at IS NULL)
            OR
            (status <> 'ACTIVE' AND retired_at IS NOT NULL)
        )
);

CREATE INDEX idx_keys_status
    ON cryptographic_keys(status);

-- ============================================================
-- 4. ACCOUNTS
-- ============================================================

CREATE TABLE accounts (
    account_id VARCHAR(100) PRIMARY KEY,

    display_name VARCHAR(150) NOT NULL,

    key_id VARCHAR(100) NOT NULL
        REFERENCES cryptographic_keys(key_id),

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT nonempty_account_name
        CHECK (length(trim(display_name)) > 0)
);

CREATE INDEX idx_accounts_key
    ON accounts(key_id);

-- ============================================================
-- 5. BLOCKCHAIN BLOCKS
-- ============================================================

CREATE TABLE blocks (
    block_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    block_height BIGINT NOT NULL UNIQUE,

    previous_hash CHAR(64) NOT NULL,

    block_hash CHAR(64) NOT NULL UNIQUE,

    block_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    transaction_count INTEGER NOT NULL DEFAULT 0,

    status block_status NOT NULL DEFAULT 'VALID',

    CONSTRAINT valid_block_height
        CHECK (block_height >= 0),

    CONSTRAINT valid_transaction_count
        CHECK (transaction_count >= 0)
);

CREATE INDEX idx_blocks_timestamp
    ON blocks(block_timestamp DESC);

-- ============================================================
-- 6. TRANSACTIONS
-- ============================================================

CREATE TABLE transactions (
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    sender_id VARCHAR(100) NOT NULL
        REFERENCES accounts(account_id),

    receiver_id VARCHAR(100) NOT NULL
        REFERENCES accounts(account_id),

    amount BIGINT NOT NULL,

    nonce BIGINT NOT NULL,

    key_id VARCHAR(100) NOT NULL
        REFERENCES cryptographic_keys(key_id),

    transaction_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    canonical_payload BYTEA NOT NULL,

    hmac_signature CHAR(64) NOT NULL,

    status transaction_status NOT NULL DEFAULT 'CREATED',

    block_id BIGINT
        REFERENCES blocks(block_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT positive_transaction_amount
        CHECK (amount > 0),

    CONSTRAINT nonnegative_nonce
        CHECK (nonce >= 0),

    CONSTRAINT distinct_accounts
        CHECK (sender_id <> receiver_id),

    CONSTRAINT valid_hmac_format
        CHECK (hmac_signature ~ '^[0-9a-f]{64}$'),

    CONSTRAINT valid_transaction_commitment
        CHECK (
            (status = 'COMMITTED' AND block_id IS NOT NULL)
            OR
            (status <> 'COMMITTED' AND block_id IS NULL)
        )
);

-- A sender cannot commit the same nonce twice.
CREATE UNIQUE INDEX uq_committed_sender_nonce
    ON transactions(sender_id, nonce)
    WHERE status = 'COMMITTED';

CREATE UNIQUE INDEX uq_transaction_block_membership
    ON transactions(transaction_id, block_id)
    WHERE block_id IS NOT NULL;

CREATE INDEX idx_transactions_sender
    ON transactions(sender_id, transaction_timestamp DESC);

CREATE INDEX idx_transactions_receiver
    ON transactions(receiver_id, transaction_timestamp DESC);

CREATE INDEX idx_transactions_status
    ON transactions(status);

CREATE INDEX idx_transactions_block
    ON transactions(block_id)
    WHERE block_id IS NOT NULL;

-- ============================================================
-- 7. AUDIT EVENTS
-- ============================================================

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_type VARCHAR(100) NOT NULL,

    entity_type VARCHAR(50) NOT NULL,

    entity_id VARCHAR(150),

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_audit_time
    ON security_audit(created_at DESC);

CREATE INDEX idx_security_audit_type
    ON security_audit(event_type);

-- ============================================================
-- 8. CANONICAL SERIALIZATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION canonical_transaction_payload(
    p_transaction_id UUID,
    p_sender_id VARCHAR,
    p_receiver_id VARCHAR,
    p_amount BIGINT,
    p_nonce BIGINT,
    p_timestamp TIMESTAMPTZ,
    p_key_id VARCHAR
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT convert_to(
        jsonb_build_object(
            'transaction_id', p_transaction_id::TEXT,
            'sender_id', p_sender_id,
            'receiver_id', p_receiver_id,
            'amount', p_amount,
            'nonce', p_nonce,
            'timestamp',
                to_char(
                    p_timestamp AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US'
                ) || 'Z',
            'key_id', p_key_id
        )::TEXT,
        'UTF8'
    );
$$;

-- JSONB produces deterministic key ordering in PostgreSQL.
-- All signing systems must implement exactly the same encoding.

-- ============================================================
-- 9. HMAC GENERATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION generate_transaction_hmac(
    p_payload BYTEA,
    p_key_id VARCHAR
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = blockchain_security, public
AS $$
DECLARE
    v_secret BYTEA;
    v_status key_status;
    v_signature BYTEA;
BEGIN
    SELECT secret_key, status
    INTO v_secret, v_status
    FROM cryptographic_keys
    WHERE key_id = p_key_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown key identifier: %', p_key_id;
    END IF;

    IF v_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Key is not active for signing';
    END IF;

    v_signature := hmac(
        p_payload,
        v_secret,
        'sha256'
    );

    RETURN encode(v_signature, 'hex');
END;
$$;

-- ============================================================
-- 10. HMAC VERIFICATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION verify_transaction_hmac(
    p_payload BYTEA,
    p_key_id VARCHAR,
    p_signature TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = blockchain_security, public
AS $$
DECLARE
    v_secret BYTEA;
    v_status key_status;
    v_expected TEXT;
BEGIN
    IF p_signature IS NULL
       OR p_signature !~ '^[0-9a-f]{64}$' THEN
        RETURN FALSE;
    END IF;

    SELECT secret_key, status
    INTO v_secret, v_status
    FROM cryptographic_keys
    WHERE key_id = p_key_id;

    IF NOT FOUND OR v_status = 'REVOKED' THEN
        RETURN FALSE;
    END IF;

    v_expected := encode(
        hmac(p_payload, v_secret, 'sha256'),
        'hex'
    );

    -- Application-level constant-time verification should
    -- also be used where the database is not the trusted boundary.
    RETURN v_expected = p_signature;
END;
$$;

-- ============================================================
-- 11. TRANSACTION INTEGRITY TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION enforce_transaction_integrity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_expected BYTEA;
    v_sender_active BOOLEAN;
    v_receiver_active BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.status = 'COMMITTED' THEN
            RAISE EXCEPTION
                'Committed transaction records are immutable';
        END IF;

        IF (
            NEW.transaction_id,
            NEW.sender_id,
            NEW.receiver_id,
            NEW.amount,
            NEW.nonce,
            NEW.key_id,
            NEW.transaction_timestamp,
            NEW.canonical_payload,
            NEW.hmac_signature
        ) IS DISTINCT FROM (
            OLD.transaction_id,
            OLD.sender_id,
            OLD.receiver_id,
            OLD.amount,
            OLD.nonce,
            OLD.key_id,
            OLD.transaction_timestamp,
            OLD.canonical_payload,
            OLD.hmac_signature
        ) THEN
            RAISE EXCEPTION
                'Transaction payload cannot be modified after insertion';
        END IF;
    END IF;

    IF NEW.status IN ('AUTHENTICATED', 'PENDING', 'COMMITTED') THEN

        v_expected := canonical_transaction_payload(
            NEW.transaction_id,
            NEW.sender_id,
            NEW.receiver_id,
            NEW.amount,
            NEW.nonce,
            NEW.transaction_timestamp,
            NEW.key_id
        );

        IF NEW.canonical_payload <> v_expected THEN
            RAISE EXCEPTION
                'Canonical transaction payload mismatch';
        END IF;

        IF NOT verify_transaction_hmac(
            NEW.canonical_payload,
            NEW.key_id,
            NEW.hmac_signature
        ) THEN
            RAISE EXCEPTION
                'Transaction HMAC verification failed';
        END IF;

        SELECT active
        INTO v_sender_active
        FROM accounts
        WHERE account_id = NEW.sender_id;

        SELECT active
        INTO v_receiver_active
        FROM accounts
        WHERE account_id = NEW.receiver_id;

        IF NOT COALESCE(v_sender_active, FALSE)
           OR NOT COALESCE(v_receiver_active, FALSE) THEN
            RAISE EXCEPTION 'Inactive account';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_integrity
BEFORE INSERT OR UPDATE
ON transactions
FOR EACH ROW
EXECUTE FUNCTION enforce_transaction_integrity();

-- ============================================================
-- 12. BLOCK HASH FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION calculate_block_hash(
    p_height BIGINT,
    p_previous_hash CHAR(64),
    p_timestamp TIMESTAMPTZ,
    p_transactions JSONB
)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT encode(
        digest(
            convert_to(
                jsonb_build_object(
                    'height', p_height,
                    'previous_hash', p_previous_hash,
                    'timestamp',
                        to_char(
                            p_timestamp AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US'
                        ) || 'Z',
                    'transactions', p_transactions
                )::TEXT,
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    );
$$;

-- ============================================================
-- 13. BLOCK CREATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE commit_pending_transactions()
LANGUAGE plpgsql
AS $$
DECLARE
    v_height BIGINT;
    v_previous_hash CHAR(64);
    v_timestamp TIMESTAMPTZ;
    v_block_id BIGINT;
    v_transactions JSONB;
    v_hash TEXT;
    v_count INTEGER;
BEGIN
    -- Serialize block creation to prevent competing writers.
    LOCK TABLE blocks IN EXCLUSIVE MODE;

    SELECT COUNT(*)
    INTO v_count
    FROM transactions
    WHERE status = 'PENDING';

    IF v_count = 0 THEN
        RAISE EXCEPTION 'No pending transactions';
    END IF;

    -- Revalidate all transactions before commitment.
    IF EXISTS (
        SELECT 1
        FROM transactions t
        WHERE t.status = 'PENDING'
          AND NOT verify_transaction_hmac(
              t.canonical_payload,
              t.key_id,
              t.hmac_signature
          )
    ) THEN
        RAISE EXCEPTION
            'At least one pending transaction has an invalid HMAC';
    END IF;

    -- Detect duplicate sender nonces within the pending batch.
    IF EXISTS (
        SELECT sender_id, nonce
        FROM transactions
        WHERE status = 'PENDING'
        GROUP BY sender_id, nonce
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'Duplicate pending nonce';
    END IF;

    -- Detect conflicts with previously committed nonces.
    IF EXISTS (
        SELECT 1
        FROM transactions pending
        JOIN transactions committed
          ON committed.sender_id = pending.sender_id
         AND committed.nonce = pending.nonce
         AND committed.status = 'COMMITTED'
        WHERE pending.status = 'PENDING'
    ) THEN
        RAISE EXCEPTION 'Committed nonce conflict';
    END IF;

    SELECT COALESCE(MAX(block_height) + 1, 0)
    INTO v_height
    FROM blocks;

    SELECT COALESCE(
        (
            SELECT block_hash
            FROM blocks
            ORDER BY block_height DESC
            LIMIT 1
        ),
        repeat('0', 64)
    )
    INTO v_previous_hash;

    v_timestamp := clock_timestamp();

    SELECT jsonb_agg(
        jsonb_build_object(
            'transaction_id', transaction_id,
            'sender_id', sender_id,
            'receiver_id', receiver_id,
            'amount', amount,
            'nonce', nonce,
            'key_id', key_id,
            'signature', hmac_signature,
            'payload', encode(canonical_payload, 'hex')
        )
        ORDER BY transaction_id
    )
    INTO v_transactions
    FROM transactions
    WHERE status = 'PENDING';

    v_hash := calculate_block_hash(
        v_height,
        v_previous_hash,
        v_timestamp,
        v_transactions
    );

    INSERT INTO blocks (
        block_height,
        previous_hash,
        block_hash,
        block_timestamp,
        transaction_count
    )
    VALUES (
        v_height,
        v_previous_hash,
        v_hash,
        v_timestamp,
        v_count
    )
    RETURNING block_id INTO v_block_id;

    UPDATE transactions
    SET
        status = 'COMMITTED',
        block_id = v_block_id
    WHERE status = 'PENDING';

    INSERT INTO security_audit (
        event_type,
        entity_type,
        entity_id,
        event_details
    )
    VALUES (
        'BLOCK_COMMITTED',
        'BLOCK',
        v_block_id::TEXT,
        jsonb_build_object(
            'height', v_height,
            'transaction_count', v_count,
            'hash', v_hash
        )
    );

    RAISE NOTICE
        'Block % committed with % transactions',
        v_height,
        v_count;
END;
$$;

-- ============================================================
-- 14. BLOCKCHAIN VALIDATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_blockchain()
RETURNS TABLE (
    checked_height BIGINT,
    valid BOOLEAN,
    validation_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_block RECORD;
    v_previous CHAR(64) := repeat('0', 64);
    v_expected TEXT;
    v_payload JSONB;
BEGIN
    FOR v_block IN
        SELECT *
        FROM blocks
        ORDER BY block_height
    LOOP

        IF v_block.block_height = 0
           AND v_block.previous_hash <> repeat('0', 64) THEN

            RETURN QUERY SELECT
                v_block.block_height,
                FALSE,
                'Invalid genesis block reference'::TEXT;

            RETURN;
        END IF;

        IF v_block.previous_hash <> v_previous THEN
            RETURN QUERY SELECT
                v_block.block_height,
                FALSE,
                'Previous block hash mismatch'::TEXT;

            RETURN;
        END IF;

        SELECT jsonb_agg(
            jsonb_build_object(
                'transaction_id', transaction_id,
                'sender_id', sender_id,
                'receiver_id', receiver_id,
                'amount', amount,
                'nonce', nonce,
                'key_id', key_id,
                'signature', hmac_signature,
                'payload', encode(canonical_payload, 'hex')
            )
            ORDER BY transaction_id
        )
        INTO v_payload
        FROM transactions
        WHERE block_id = v_block.block_id;

        IF v_payload IS NULL THEN
            v_payload := '[]'::JSONB;
        END IF;

        IF jsonb_array_length(v_payload)
           <> v_block.transaction_count THEN

            RETURN QUERY SELECT
                v_block.block_height,
                FALSE,
                'Transaction count mismatch'::TEXT;

            RETURN;
        END IF;

        v_expected := calculate_block_hash(
            v_block.block_height,
            v_block.previous_hash,
            v_block.block_timestamp,
            v_payload
        );

        IF v_expected <> v_block.block_hash THEN
            RETURN QUERY SELECT
                v_block.block_height,
                FALSE,
                'Block hash mismatch'::TEXT;

            RETURN;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM transactions t
            WHERE t.block_id = v_block.block_id
              AND NOT verify_transaction_hmac(
                  t.canonical_payload,
                  t.key_id,
                  t.hmac_signature
              )
        ) THEN
            RETURN QUERY SELECT
                v_block.block_height,
                FALSE,
                'Transaction authentication failure'::TEXT;

            RETURN;
        END IF;

        v_previous := v_block.block_hash;

        RETURN QUERY SELECT
            v_block.block_height,
            TRUE,
            'Block integrity verified'::TEXT;
    END LOOP;
END;
$$;

-- ============================================================
-- 15. ACCOUNT BALANCE VIEW
-- ============================================================

CREATE OR REPLACE VIEW account_balances AS
SELECT
    a.account_id,
    a.display_name,

    COALESCE(
        SUM(
            CASE
                WHEN t.receiver_id = a.account_id
                    THEN t.amount
                WHEN t.sender_id = a.account_id
                    THEN -t.amount
                ELSE 0
            END
        ),
        0
    ) AS balance

FROM accounts a

LEFT JOIN transactions t
    ON (
        t.sender_id = a.account_id
        OR t.receiver_id = a.account_id
    )
    AND t.status = 'COMMITTED'

GROUP BY
    a.account_id,
    a.display_name;

-- ============================================================
-- 16. TRANSACTION REPORTING VIEW
-- ============================================================

CREATE OR REPLACE VIEW transaction_report AS
SELECT
    t.transaction_id,
    t.sender_id,
    sender.display_name AS sender_name,
    t.receiver_id,
    receiver.display_name AS receiver_name,
    t.amount,
    t.nonce,
    t.key_id,
    k.status AS key_status,
    t.status AS transaction_status,
    b.block_height,
    b.block_hash,
    t.transaction_timestamp

FROM transactions t

JOIN accounts sender
    ON sender.account_id = t.sender_id

JOIN accounts receiver
    ON receiver.account_id = t.receiver_id

JOIN cryptographic_keys k
    ON k.key_id = t.key_id

LEFT JOIN blocks b
    ON b.block_id = t.block_id;

-- ============================================================
-- 17. KEY ROTATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE rotate_key(
    p_old_key_id VARCHAR,
    p_new_key_id VARCHAR,
    p_new_secret BYTEA
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF octet_length(p_new_secret) < 32 THEN
        RAISE EXCEPTION
            'New HMAC key must contain at least 32 bytes';
    END IF;

    UPDATE cryptographic_keys
    SET
        status = 'RETIRED',
        retired_at = NOW()
    WHERE key_id = p_old_key_id
      AND status = 'ACTIVE';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Old key does not exist or is not active';
    END IF;

    INSERT INTO cryptographic_keys (
        key_id,
        secret_key,
        algorithm,
        status
    )
    VALUES (
        p_new_key_id,
        p_new_secret,
        'HMAC-SHA256',
        'ACTIVE'
    );

    INSERT INTO security_audit (
        event_type,
        entity_type,
        entity_id,
        event_details
    )
    VALUES (
        'KEY_ROTATED',
        'CRYPTOGRAPHIC_KEY',
        p_new_key_id,
        jsonb_build_object(
            'previous_key_id', p_old_key_id,
            'new_key_id', p_new_key_id
        )
    );
END;
$$;

-- ============================================================
-- 18. SEED DATA
-- ============================================================

INSERT INTO cryptographic_keys (
    key_id,
    secret_key,
    status
)
VALUES
(
    'wallet-key-v1',
    decode(repeat('42', 32), 'hex'),
    'ACTIVE'
),
(
    'wallet-key-retired',
    decode(repeat('33', 32), 'hex'),
    'RETIRED'
);

UPDATE cryptographic_keys
SET retired_at = NOW()
WHERE key_id = 'wallet-key-retired';

INSERT INTO accounts (
    account_id,
    display_name,
    key_id
)
VALUES
('ALICE', 'Alice Account', 'wallet-key-v1'),
('BOB', 'Bob Account', 'wallet-key-v1'),
('CHARLIE', 'Charlie Account', 'wallet-key-v1'),
('DAVID', 'David Account', 'wallet-key-v1');

-- ============================================================
-- 19. SAMPLE AUTHENTICATED TRANSACTION
-- ============================================================

DO $$
DECLARE
    v_id UUID := gen_random_uuid();
    v_sender VARCHAR := 'ALICE';
    v_receiver VARCHAR := 'BOB';
    v_amount BIGINT := 500;
    v_nonce BIGINT := 1;
    v_key_id VARCHAR := 'wallet-key-v1';
    v_timestamp TIMESTAMPTZ := NOW();
    v_payload BYTEA;
    v_signature TEXT;
BEGIN
    v_payload := canonical_transaction_payload(
        v_id,
        v_sender,
        v_receiver,
        v_amount,
        v_nonce,
        v_timestamp,
        v_key_id
    );

    v_signature := generate_transaction_hmac(
        v_payload,
        v_key_id
    );

    INSERT INTO transactions (
        transaction_id,
        sender_id,
        receiver_id,
        amount,
        nonce,
        key_id,
        transaction_timestamp,
        canonical_payload,
        hmac_signature,
        status
    )
    VALUES (
        v_id,
        v_sender,
        v_receiver,
        v_amount,
        v_nonce,
        v_key_id,
        v_timestamp,
        v_payload,
        v_signature,
        'PENDING'
    );

    RAISE NOTICE 'Authenticated transaction inserted: %', v_id;
END;
$$;

-- ============================================================
-- 20. SECOND SAMPLE TRANSACTION
-- ============================================================

DO $$
DECLARE
    v_id UUID := gen_random_uuid();
    v_sender VARCHAR := 'BOB';
    v_receiver VARCHAR := 'CHARLIE';
    v_amount BIGINT := 150;
    v_nonce BIGINT := 1;
    v_key_id VARCHAR := 'wallet-key-v1';
    v_timestamp TIMESTAMPTZ := NOW();
    v_payload BYTEA;
    v_signature TEXT;
BEGIN
    v_payload := canonical_transaction_payload(
        v_id,
        v_sender,
        v_receiver,
        v_amount,
        v_nonce,
        v_timestamp,
        v_key_id
    );

    v_signature := generate_transaction_hmac(
        v_payload,
        v_key_id
    );

    INSERT INTO transactions (
        transaction_id,
        sender_id,
        receiver_id,
        amount,
        nonce,
        key_id,
        transaction_timestamp,
        canonical_payload,
        hmac_signature,
        status
    )
    VALUES (
        v_id,
        v_sender,
        v_receiver,
        v_amount,
        v_nonce,
        v_key_id,
        v_timestamp,
        v_payload,
        v_signature,
        'PENDING'
    );
END;
$$;

-- ============================================================
-- 21. TRANSACTIONAL BLOCK COMMITMENT
-- ============================================================

SAVEPOINT before_block_commit;

CALL commit_pending_transactions();

-- If block processing fails, the transaction can be rolled back.
RELEASE SAVEPOINT before_block_commit;

COMMIT;

-- ============================================================
-- 22. RETRIEVAL QUERIES
-- ============================================================

-- All transactions.
SELECT *
FROM transaction_report
ORDER BY transaction_timestamp DESC;

-- Transactions belonging to a particular sender.
SELECT *
FROM transaction_report
WHERE sender_id = 'ALICE';

-- Committed transactions.
SELECT *
FROM transactions
WHERE status = 'COMMITTED';

-- Block history.
SELECT
    block_height,
    previous_hash,
    block_hash,
    transaction_count,
    block_timestamp
FROM blocks
ORDER BY block_height;

-- ============================================================
-- 23. HMAC VALIDATION
-- ============================================================

SELECT
    transaction_id,
    verify_transaction_hmac(
        canonical_payload,
        key_id,
        hmac_signature
    ) AS hmac_valid
FROM transactions;

-- ============================================================
-- 24. REPLAY DETECTION REPORT
-- ============================================================

SELECT
    sender_id,
    nonce,
    COUNT(*) AS transaction_count,
    COUNT(*) FILTER (
        WHERE status = 'COMMITTED'
    ) AS committed_count
FROM transactions
GROUP BY sender_id, nonce
HAVING COUNT(*) > 1;

-- ============================================================
-- 25. BLOCKCHAIN INTEGRITY REPORT
-- ============================================================

SELECT *
FROM validate_blockchain()
ORDER BY checked_height;

-- ============================================================
-- 26. ACCOUNT AGGREGATION
-- ============================================================

SELECT
    account_id,
    display_name,
    balance
FROM account_balances
ORDER BY balance DESC;

-- ============================================================
-- 27. TRANSACTION VOLUME REPORT
-- ============================================================

SELECT
    date_trunc('day', transaction_timestamp) AS transaction_day,
    COUNT(*) AS transaction_count,
    SUM(amount) AS total_amount,
    COUNT(*) FILTER (
        WHERE status = 'COMMITTED'
    ) AS committed_transactions,
    COUNT(*) FILTER (
        WHERE status = 'REJECTED'
    ) AS rejected_transactions
FROM transactions
GROUP BY date_trunc('day', transaction_timestamp)
ORDER BY transaction_day DESC;

-- ============================================================
-- 28. KEY USAGE REPORT
-- ============================================================

SELECT
    k.key_id,
    k.algorithm,
    k.status,
    COUNT(t.transaction_id) AS transaction_count
FROM cryptographic_keys k
LEFT JOIN transactions t
    ON t.key_id = k.key_id
GROUP BY
    k.key_id,
    k.algorithm,
    k.status
ORDER BY transaction_count DESC;

-- ============================================================
-- 29. ELIGIBILITY QUERY
-- ============================================================

SELECT
    t.transaction_id,

    CASE
        WHEN t.status <> 'PENDING'
            THEN 'NOT_PENDING'

        WHEN NOT verify_transaction_hmac(
            t.canonical_payload,
            t.key_id,
            t.hmac_signature
        )
            THEN 'INVALID_HMAC'

        WHEN k.status <> 'ACTIVE'
            THEN 'INACTIVE_KEY'

        WHEN NOT sender.active
            THEN 'INACTIVE_SENDER'

        WHEN NOT receiver.active
            THEN 'INACTIVE_RECEIVER'

        ELSE 'ELIGIBLE_FOR_BLOCK'
    END AS eligibility_status

FROM transactions t

JOIN cryptographic_keys k
    ON k.key_id = t.key_id

JOIN accounts sender
    ON sender.account_id = t.sender_id

JOIN accounts receiver
    ON receiver.account_id = t.receiver_id;

-- ============================================================
-- 30. SECURITY AND OPERATIONAL NOTES
-- ============================================================

/*
Production controls:

1. Do not expose cryptographic_keys.secret_key to application
   users or reporting roles.

2. Store secrets in an external KMS or HSM.

3. Restrict execution of SECURITY DEFINER functions.

4. Revoke unnecessary schema and table privileges.

5. Use application-side constant-time tag verification.

6. Apply canonical serialization consistently across systems.

7. Keep retired keys available only for historical verification
   until the applicable retention period expires.

8. Revocation should invalidate signatures according to an
   explicit security policy.

9. A database hash chain is not a distributed consensus protocol.

10. HMAC authentication does not provide non-repudiation because
    every holder of a shared secret can create valid tags.

11. Database transactions provide atomicity but do not provide
    proof of independent blockchain consensus.

12. Balance validation and sufficient-funds enforcement must
    be added before treating this ledger as a payment system.

13. Protect audit records against privileged modification.

14. Use appropriate role separation and encrypted connections.
*/
