-- ============================================================
-- MAC IN CRYPTOGRAPHY AND BLOCKCHAIN
-- PostgreSQL 15+
--
-- Requirements:
--   CREATE EXTENSION pgcrypto;
--
-- Capabilities:
--   HMAC-SHA256
--   Cryptographic key registry
--   Message authentication
--   Transaction authentication
--   Replay protection
--   Blockchain block management
--   Hash-linked integrity validation
--   Authentication policies
--   Transaction processing
--   Audit reporting
--
-- IMPORTANT:
-- Database-held demonstration keys are not a production
-- secret-management solution. Production keys belong in an
-- external KMS or HSM.
-- ============================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS mac_chain;

SET search_path TO mac_chain, public;

-- ============================================================
-- 1. ENUMERATIONS
-- ============================================================

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE transaction_status AS ENUM (
    'PENDING',
    'AUTHENTICATED',
    'REJECTED',
    'COMMITTED'
);

CREATE TYPE block_status AS ENUM (
    'PROPOSED',
    'VALIDATED',
    'COMMITTED',
    'INVALID'
);

CREATE TYPE authentication_status AS ENUM (
    'SUCCESS',
    'FAILURE',
    'REPLAY_BLOCKED',
    'KEY_REJECTED'
);

-- ============================================================
-- 2. REPOSITORY-STYLE NODE REGISTRY
-- ============================================================

CREATE TABLE nodes (
    node_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    node_name VARCHAR(100) NOT NULL UNIQUE,

    public_identifier VARCHAR(150) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- ============================================================
-- 3. CRYPTOGRAPHIC KEY REGISTRY
-- ============================================================

CREATE TABLE cryptographic_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    node_id UUID NOT NULL REFERENCES nodes(node_id),

    key_name VARCHAR(100) NOT NULL,

    algorithm VARCHAR(30) NOT NULL DEFAULT 'HMAC-SHA256',

    -- Demonstration only. Use an external KMS/HSM in production.
    secret_key BYTEA NOT NULL,

    status key_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ,

    UNIQUE(node_id, key_name),

    CONSTRAINT valid_algorithm
        CHECK (algorithm = 'HMAC-SHA256'),

    CONSTRAINT minimum_key_length
        CHECK (octet_length(secret_key) >= 32),

    CONSTRAINT valid_expiry
        CHECK (
            expires_at IS NULL
            OR expires_at > created_at
        )
);

CREATE INDEX idx_keys_node_status
ON cryptographic_keys(node_id, status);

-- ============================================================
-- 4. MESSAGE AUTHENTICATION
-- ============================================================

CREATE TABLE authenticated_messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    sender_node UUID NOT NULL REFERENCES nodes(node_id),

    receiver_node UUID NOT NULL REFERENCES nodes(node_id),

    key_id UUID NOT NULL REFERENCES cryptographic_keys(key_id),

    payload JSONB NOT NULL,

    nonce UUID NOT NULL DEFAULT gen_random_uuid(),

    message_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    mac BYTEA NOT NULL,

    verification_status authentication_status
        NOT NULL DEFAULT 'SUCCESS',

    CONSTRAINT valid_message_mac
        CHECK (octet_length(mac) = 32),

    CONSTRAINT different_message_participants
        CHECK (sender_node <> receiver_node),

    UNIQUE(sender_node, nonce)
);

CREATE INDEX idx_messages_sender_timestamp
ON authenticated_messages(sender_node, message_timestamp DESC);

CREATE INDEX idx_messages_receiver_timestamp
ON authenticated_messages(receiver_node, message_timestamp DESC);

-- ============================================================
-- 5. TRANSACTIONS
-- ============================================================

CREATE TABLE blockchain_transactions (
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    sender_node UUID NOT NULL REFERENCES nodes(node_id),

    receiver_node UUID NOT NULL REFERENCES nodes(node_id),

    key_id UUID NOT NULL REFERENCES cryptographic_keys(key_id),

    amount NUMERIC(24, 8) NOT NULL,

    nonce BIGINT NOT NULL,

    transaction_payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    mac BYTEA,

    status transaction_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    authenticated_at TIMESTAMPTZ,

    committed_at TIMESTAMPTZ,

    CONSTRAINT positive_transaction_amount
        CHECK (amount > 0),

    CONSTRAINT valid_transaction_nonce
        CHECK (nonce >= 0),

    CONSTRAINT different_transaction_participants
        CHECK (sender_node <> receiver_node),

    CONSTRAINT valid_transaction_mac
        CHECK (
            mac IS NULL
            OR octet_length(mac) = 32
        ),

    UNIQUE(sender_node, nonce)
);

CREATE INDEX idx_transactions_status_created
ON blockchain_transactions(status, created_at);

CREATE INDEX idx_transactions_sender
ON blockchain_transactions(sender_node, nonce);

-- ============================================================
-- 6. BLOCKCHAIN BLOCKS
-- ============================================================

CREATE TABLE blockchain_blocks (
    block_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    block_index BIGINT NOT NULL UNIQUE,

    previous_hash BYTEA NOT NULL,

    block_hash BYTEA NOT NULL,

    status block_status NOT NULL DEFAULT 'PROPOSED',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    committed_at TIMESTAMPTZ,

    CONSTRAINT valid_previous_hash
        CHECK (octet_length(previous_hash) = 32),

    CONSTRAINT valid_block_hash
        CHECK (octet_length(block_hash) = 32),

    CONSTRAINT valid_block_index
        CHECK (block_index >= 0)
);

CREATE INDEX idx_blocks_status_index
ON blockchain_blocks(status, block_index DESC);

-- ============================================================
-- 7. BLOCK TRANSACTION RELATIONSHIP
-- ============================================================

CREATE TABLE block_transactions (
    block_id BIGINT NOT NULL
        REFERENCES blockchain_blocks(block_id),

    transaction_id UUID NOT NULL
        REFERENCES blockchain_transactions(transaction_id),

    transaction_position INTEGER NOT NULL,

    PRIMARY KEY(block_id, transaction_id),

    UNIQUE(block_id, transaction_position),

    -- A transaction may be committed only once.
    UNIQUE(transaction_id),

    CHECK(transaction_position >= 0)
);

CREATE INDEX idx_block_transactions_transaction
ON block_transactions(transaction_id);

-- ============================================================
-- 8. AUTHENTICATION AUDIT
-- ============================================================

CREATE TABLE authentication_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    transaction_id UUID
        REFERENCES blockchain_transactions(transaction_id),

    message_id UUID
        REFERENCES authenticated_messages(message_id),

    key_id UUID
        REFERENCES cryptographic_keys(key_id),

    event_status authentication_status NOT NULL,

    failure_reason TEXT,

    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_audit_reference
        CHECK (
            transaction_id IS NOT NULL
            OR message_id IS NOT NULL
        )
);

CREATE INDEX idx_authentication_audit_timestamp
ON authentication_audit(event_timestamp DESC);

CREATE INDEX idx_authentication_audit_status
ON authentication_audit(event_status, event_timestamp DESC);

-- ============================================================
-- 9. REPLAY PROTECTION
-- ============================================================

CREATE TABLE processed_nonces (
    nonce_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    sender_node UUID NOT NULL REFERENCES nodes(node_id),

    nonce BIGINT NOT NULL,

    transaction_id UUID
        REFERENCES blockchain_transactions(transaction_id),

    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(sender_node, nonce)
);

-- ============================================================
-- 10. KEY VALIDATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_mac_key(
    p_key_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_status key_status;
    v_expiry TIMESTAMPTZ;
    v_node_active BOOLEAN;
BEGIN

    SELECT
        k.status,
        k.expires_at,
        n.is_active
    INTO
        v_status,
        v_expiry,
        v_node_active
    FROM cryptographic_keys k
    JOIN nodes n ON n.node_id = k.node_id
    WHERE k.key_id = p_key_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF v_status <> 'ACTIVE' THEN
        RETURN FALSE;
    END IF;

    IF v_expiry IS NOT NULL AND v_expiry <= NOW() THEN
        RETURN FALSE;
    END IF;

    IF NOT v_node_active THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$;

-- ============================================================
-- 11. CANONICAL TRANSACTION SERIALIZATION
-- ============================================================

CREATE OR REPLACE FUNCTION transaction_canonical_bytes(
    p_transaction_id UUID
)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result TEXT;
BEGIN

    SELECT jsonb_build_object(
        'transaction_id', transaction_id,
        'sender_node', sender_node,
        'receiver_node', receiver_node,
        'amount', amount,
        'nonce', nonce,
        'key_id', key_id,
        'payload', transaction_payload
    )::TEXT
    INTO v_result
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found';
    END IF;

    RETURN convert_to(v_result, 'UTF8');
END;
$$;

-- ============================================================
-- 12. HMAC GENERATION
-- ============================================================

CREATE OR REPLACE FUNCTION generate_transaction_mac(
    p_transaction_id UUID
)
RETURNS BYTEA
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_key_id UUID;
    v_secret BYTEA;
    v_message BYTEA;
    v_mac BYTEA;
BEGIN

    SELECT key_id
    INTO v_key_id
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found';
    END IF;

    IF NOT validate_mac_key(v_key_id) THEN
        RAISE EXCEPTION 'Cryptographic key is inactive or expired';
    END IF;

    SELECT secret_key
    INTO v_secret
    FROM cryptographic_keys
    WHERE key_id = v_key_id;

    v_message := transaction_canonical_bytes(
        p_transaction_id
    );

    v_mac := public.hmac(
        v_message,
        v_secret,
        'sha256'
    );

    RETURN v_mac;
END;
$$;

-- ============================================================
-- 13. HMAC VERIFICATION
-- ============================================================

CREATE OR REPLACE FUNCTION verify_transaction_mac(
    p_transaction_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_key_id UUID;
    v_secret BYTEA;
    v_supplied BYTEA;
    v_expected BYTEA;
BEGIN

    SELECT key_id, mac
    INTO v_key_id, v_supplied
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id;

    IF NOT FOUND OR v_supplied IS NULL THEN
        RETURN FALSE;
    END IF;

    IF NOT validate_mac_key(v_key_id) THEN
        RETURN FALSE;
    END IF;

    SELECT secret_key
    INTO v_secret
    FROM cryptographic_keys
    WHERE key_id = v_key_id;

    v_expected := public.hmac(
        transaction_canonical_bytes(p_transaction_id),
        v_secret,
        'sha256'
    );

    -- Bytea equality is not a guaranteed constant-time comparison.
    -- This function is for controlled database demonstration.
    RETURN v_expected = v_supplied;
END;
$$;

-- ============================================================
-- 14. TRANSACTION AUTHENTICATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE authenticate_transaction(
    p_transaction_id UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_mac BYTEA;
    v_sender UUID;
    v_nonce BIGINT;
BEGIN

    SELECT sender_node, nonce
    INTO v_sender, v_nonce
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction does not exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM processed_nonces
        WHERE sender_node = v_sender
          AND nonce = v_nonce
    ) THEN

        INSERT INTO authentication_audit (
            transaction_id,
            event_status,
            failure_reason
        )
        VALUES (
            p_transaction_id,
            'REPLAY_BLOCKED',
            'Nonce has already been processed'
        );

        RAISE EXCEPTION 'Replay detected';
    END IF;

    v_mac := generate_transaction_mac(
        p_transaction_id
    );

    UPDATE blockchain_transactions
    SET mac = v_mac,
        status = 'AUTHENTICATED',
        authenticated_at = NOW()
    WHERE transaction_id = p_transaction_id
      AND status = 'PENDING';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction is not pending';
    END IF;

    INSERT INTO processed_nonces (
        sender_node,
        nonce,
        transaction_id
    )
    VALUES (
        v_sender,
        v_nonce,
        p_transaction_id
    );

    INSERT INTO authentication_audit (
        transaction_id,
        event_status
    )
    VALUES (
        p_transaction_id,
        'SUCCESS'
    );

END;
$$;

-- ============================================================
-- 15. BLOCK HASH GENERATION
-- ============================================================

CREATE OR REPLACE FUNCTION calculate_block_hash(
    p_block_id BIGINT
)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_content TEXT;
BEGIN

    SELECT
        b.block_index::TEXT
        || '|'
        || encode(b.previous_hash, 'hex')
        || '|'
        || COALESCE(
            string_agg(
                t.transaction_id::TEXT
                || ':'
                || encode(t.mac, 'hex'),
                '|'
                ORDER BY bt.transaction_position
            ),
            ''
        )
    INTO v_content
    FROM blockchain_blocks b
    LEFT JOIN block_transactions bt
        ON bt.block_id = b.block_id
    LEFT JOIN blockchain_transactions t
        ON t.transaction_id = bt.transaction_id
    WHERE b.block_id = p_block_id
    GROUP BY b.block_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block does not exist';
    END IF;

    RETURN public.digest(
        convert_to(v_content, 'UTF8'),
        'sha256'
    );
END;
$$;

-- ============================================================
-- 16. BLOCK INTEGRITY VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_blockchain()
RETURNS TABLE (
    checked_block BIGINT,
    integrity_valid BOOLEAN,
    validation_reason TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_block RECORD;
    v_previous_hash BYTEA;
BEGIN

    v_previous_hash := decode(repeat('00', 32), 'hex');

    FOR v_block IN
        SELECT *
        FROM blockchain_blocks
        ORDER BY block_index
    LOOP

        IF v_block.previous_hash <> v_previous_hash THEN

            checked_block := v_block.block_index;
            integrity_valid := FALSE;
            validation_reason := 'Previous block hash mismatch';

            RETURN NEXT;
            RETURN;
        END IF;

        IF v_block.block_hash <>
            calculate_block_hash(v_block.block_id) THEN

            checked_block := v_block.block_index;
            integrity_valid := FALSE;
            validation_reason := 'Block hash mismatch';

            RETURN NEXT;
            RETURN;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM block_transactions bt
            JOIN blockchain_transactions t
                ON t.transaction_id = bt.transaction_id
            WHERE bt.block_id = v_block.block_id
              AND (
                  t.status <> 'COMMITTED'
                  OR NOT verify_transaction_mac(t.transaction_id)
              )
        ) THEN

            checked_block := v_block.block_index;
            integrity_valid := FALSE;
            validation_reason := 'Transaction authentication failure';

            RETURN NEXT;
            RETURN;
        END IF;

        v_previous_hash := v_block.block_hash;

        checked_block := v_block.block_index;
        integrity_valid := TRUE;
        validation_reason := 'Integrity verified';

        RETURN NEXT;

    END LOOP;
END;
$$;

-- ============================================================
-- 17. COMMIT BLOCK PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE commit_block(
    p_block_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_block RECORD;
BEGIN

    SELECT *
    INTO v_block
    FROM blockchain_blocks
    WHERE block_id = p_block_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block does not exist';
    END IF;

    IF v_block.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'Block is not in proposed state';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM block_transactions
        WHERE block_id = p_block_id
    ) THEN
        RAISE EXCEPTION 'Cannot commit an empty block';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM block_transactions bt
        JOIN blockchain_transactions t
            ON t.transaction_id = bt.transaction_id
        WHERE bt.block_id = p_block_id
          AND (
              t.status <> 'AUTHENTICATED'
              OR NOT verify_transaction_mac(t.transaction_id)
          )
    ) THEN
        RAISE EXCEPTION 'Block contains invalid transactions';
    END IF;

    UPDATE blockchain_blocks
    SET block_hash = calculate_block_hash(p_block_id),
        status = 'VALIDATED'
    WHERE block_id = p_block_id;

    UPDATE blockchain_transactions t
    SET status = 'COMMITTED',
        committed_at = NOW()
    FROM block_transactions bt
    WHERE bt.block_id = p_block_id
      AND bt.transaction_id = t.transaction_id;

    UPDATE blockchain_blocks
    SET status = 'COMMITTED',
        committed_at = NOW()
    WHERE block_id = p_block_id;

END;
$$;

-- ============================================================
-- 18. DEMONSTRATION DATA
-- ============================================================

INSERT INTO nodes (
    node_name,
    public_identifier
)
VALUES
    ('Node Alpha', 'NODE-ALPHA-001'),
    ('Node Beta', 'NODE-BETA-001'),
    ('Node Gamma', 'NODE-GAMMA-001');

-- Demonstration key material only.
INSERT INTO cryptographic_keys (
    node_id,
    key_name,
    algorithm,
    secret_key
)
SELECT
    node_id,
    'primary-hmac-key',
    'HMAC-SHA256',
    decode(
        repeat(
            CASE
                WHEN node_name = 'Node Alpha' THEN '11'
                WHEN node_name = 'Node Beta' THEN '22'
                ELSE '33'
            END,
            32
        ),
        'hex'
    )
FROM nodes;

-- ============================================================
-- 19. SAMPLE TRANSACTIONS
-- ============================================================

INSERT INTO blockchain_transactions (
    sender_node,
    receiver_node,
    key_id,
    amount,
    nonce,
    transaction_payload
)
SELECT
    sender.node_id,
    receiver.node_id,
    k.key_id,
    125.50000000,
    1001,
    '{"asset":"TOKEN","purpose":"payment"}'::jsonb
FROM nodes sender
JOIN nodes receiver
    ON receiver.node_name = 'Node Beta'
JOIN cryptographic_keys k
    ON k.node_id = sender.node_id
WHERE sender.node_name = 'Node Alpha';

INSERT INTO blockchain_transactions (
    sender_node,
    receiver_node,
    key_id,
    amount,
    nonce,
    transaction_payload
)
SELECT
    sender.node_id,
    receiver.node_id,
    k.key_id,
    250.00000000,
    1002,
    '{"asset":"TOKEN","purpose":"settlement"}'::jsonb
FROM nodes sender
JOIN nodes receiver
    ON receiver.node_name = 'Node Gamma'
JOIN cryptographic_keys k
    ON k.node_id = sender.node_id
WHERE sender.node_name = 'Node Alpha';

-- Invalid transaction example: zero amount is rejected by CHECK.
-- This statement is intentionally excluded from the executable
-- transaction sequence because the constraint must remain enforced.

-- ============================================================
-- 20. AUTHENTICATION WORKFLOW
-- ============================================================

DO $$
DECLARE
    v_transaction UUID;
BEGIN

    FOR v_transaction IN
        SELECT transaction_id
        FROM blockchain_transactions
        WHERE status = 'PENDING'
        ORDER BY created_at, transaction_id
    LOOP

        CALL authenticate_transaction(v_transaction);

    END LOOP;

END;
$$;

-- ============================================================
-- 21. BLOCK CREATION
-- ============================================================

DO $$
DECLARE
    v_block_id BIGINT;
BEGIN

    INSERT INTO blockchain_blocks (
        block_index,
        previous_hash,
        block_hash,
        status
    )
    VALUES (
        0,
        decode(repeat('00', 32), 'hex'),
        decode(repeat('00', 32), 'hex'),
        'PROPOSED'
    )
    RETURNING block_id INTO v_block_id;

    INSERT INTO block_transactions (
        block_id,
        transaction_id,
        transaction_position
    )
    SELECT
        v_block_id,
        transaction_id,
        row_number() OVER (
            ORDER BY created_at, transaction_id
        ) - 1
    FROM blockchain_transactions
    WHERE status = 'AUTHENTICATED';

    CALL commit_block(v_block_id);

END;
$$;

-- ============================================================
-- 22. VIEWS
-- ============================================================

CREATE OR REPLACE VIEW transaction_authentication_report AS
SELECT
    t.transaction_id,
    sender.node_name AS sender,
    receiver.node_name AS receiver,
    t.amount,
    t.nonce,
    t.status,
    t.authenticated_at,
    t.committed_at,
    encode(t.mac, 'hex') AS mac_hex,
    validate_mac_key(t.key_id) AS key_active,
    CASE
        WHEN t.mac IS NULL THEN FALSE
        ELSE verify_transaction_mac(t.transaction_id)
    END AS mac_valid
FROM blockchain_transactions t
JOIN nodes sender
    ON sender.node_id = t.sender_node
JOIN nodes receiver
    ON receiver.node_id = t.receiver_node;

CREATE OR REPLACE VIEW block_integrity_report AS
SELECT
    b.block_id,
    b.block_index,
    b.status,
    encode(b.previous_hash, 'hex') AS previous_hash,
    encode(b.block_hash, 'hex') AS block_hash,
    COUNT(bt.transaction_id) AS transaction_count,
    b.created_at,
    b.committed_at
FROM blockchain_blocks b
LEFT JOIN block_transactions bt
    ON bt.block_id = b.block_id
GROUP BY b.block_id;

-- ============================================================
-- 23. REPORTING AND EVALUATION
-- ============================================================

-- Transaction retrieval and MAC verification.
SELECT *
FROM transaction_authentication_report
ORDER BY authenticated_at;

-- Blockchain block report.
SELECT *
FROM block_integrity_report
ORDER BY block_index;

-- Full-chain integrity.
SELECT *
FROM validate_blockchain();

-- Authentication success and failure aggregation.
SELECT
    event_status,
    COUNT(*) AS event_count
FROM authentication_audit
GROUP BY event_status
ORDER BY event_count DESC;

-- Transaction volume by sender.
SELECT
    n.node_name,
    COUNT(t.transaction_id) AS transaction_count,
    COALESCE(SUM(t.amount), 0) AS total_amount
FROM nodes n
LEFT JOIN blockchain_transactions t
    ON t.sender_node = n.node_id
GROUP BY n.node_id, n.node_name
ORDER BY total_amount DESC;

-- Key lifecycle monitoring.
SELECT
    k.key_name,
    n.node_name,
    k.status,
    k.created_at,
    k.expires_at,
    validate_mac_key(k.key_id) AS eligible_for_authentication
FROM cryptographic_keys k
JOIN nodes n ON n.node_id = k.node_id;

-- ============================================================
-- 24. POLICY VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION transaction_is_eligible(
    p_transaction_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_status transaction_status;
    v_key_id UUID;
BEGIN

    SELECT status, key_id
    INTO v_status, v_key_id
    FROM blockchain_transactions
    WHERE transaction_id = p_transaction_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    RETURN
        v_status = 'AUTHENTICATED'
        AND validate_mac_key(v_key_id)
        AND verify_transaction_mac(p_transaction_id);
END;
$$;

-- Eligible transaction report.
SELECT
    transaction_id,
    transaction_is_eligible(transaction_id) AS eligible
FROM blockchain_transactions;

-- ============================================================
-- 25. KEY REVOCATION DEMONSTRATION
-- ============================================================

-- Revoke a key only after considering dependent transactions.
-- Revoked keys cannot authenticate or validate transactions.

-- UPDATE cryptographic_keys
-- SET status = 'REVOKED'
-- WHERE key_name = 'primary-hmac-key'
--   AND key_id = (
--       SELECT key_id
--       FROM cryptographic_keys
--       ORDER BY created_at
--       LIMIT 1
--   );

-- ============================================================
-- 26. DATABASE SECURITY NOTES
-- ============================================================

-- Production deployment should:
-- 1. Move key material to an external KMS/HSM.
-- 2. Restrict direct access to cryptographic_keys.
-- 3. Grant transaction authentication only to trusted roles.
-- 4. Prevent unauthorized modification of committed records.
-- 5. Use immutable audit storage.
-- 6. Define key rotation and revocation procedures.
-- 7. Use serializable transactions or appropriate row locking
--    for concurrent nonce processing.
-- 8. Use an audited constant-time verification implementation
--    at the trusted application boundary.
--
-- HMAC proves authenticity only to parties sharing the secret.
-- It does not provide public verifiability or non-repudiation.
-- Blockchain SHA-256 links detect changes but do not provide
-- authorization by themselves.

COMMIT;
