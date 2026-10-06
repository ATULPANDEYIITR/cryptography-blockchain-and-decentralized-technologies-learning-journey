-- PostgreSQL-compatible demonstration:
-- Why DES became outdated and how an enterprise cryptography inventory
-- can identify DES and 3DES dependencies during migration.

DROP SCHEMA IF EXISTS des_migration_demo CASCADE;
CREATE SCHEMA des_migration_demo;
SET search_path TO des_migration_demo;

CREATE TYPE algorithm_family AS ENUM (
    'DES',
    '3DES',
    'AES'
);

CREATE TYPE deployment_status AS ENUM (
    'NEW',
    'LEGACY',
    'MIGRATING',
    'RETIRED'
);

CREATE TYPE security_classification AS ENUM (
    'PROHIBITED',
    'LEGACY_ONLY',
    'APPROVED'
);

CREATE TABLE cryptographic_algorithms (
    algorithm_id BIGSERIAL PRIMARY KEY,
    algorithm_name VARCHAR(40) NOT NULL UNIQUE,
    family algorithm_family NOT NULL,
    effective_key_bits INTEGER NOT NULL CHECK (effective_key_bits > 0),
    block_bits INTEGER NOT NULL CHECK (block_bits > 0),
    classification security_classification NOT NULL,
    reason TEXT NOT NULL,
    CHECK (
        algorithm_name <> 'DES'
        OR (effective_key_bits = 56 AND block_bits = 64)
    ),
    CHECK (
        algorithm_name <> '3DES'
        OR block_bits = 64
    )
);

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name VARCHAR(120) NOT NULL UNIQUE,
    owning_team VARCHAR(120) NOT NULL,
    environment VARCHAR(30) NOT NULL,
    deployment_status deployment_status NOT NULL
);

CREATE TABLE encryption_assets (
    asset_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL
        REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    asset_name VARCHAR(150) NOT NULL,
    algorithm_id BIGINT NOT NULL
        REFERENCES cryptographic_algorithms(algorithm_id),
    data_classification VARCHAR(40) NOT NULL,
    estimated_bytes_per_day BIGINT NOT NULL
        CHECK (estimated_bytes_per_day >= 0),
    production_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, asset_name)
);

CREATE TABLE migration_events (
    migration_event_id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL
        REFERENCES encryption_assets(asset_id)
        ON DELETE CASCADE,
    previous_algorithm_id BIGINT
        REFERENCES cryptographic_algorithms(algorithm_id),
    target_algorithm_id BIGINT
        REFERENCES cryptographic_algorithms(algorithm_id),
    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_note TEXT NOT NULL
);

CREATE TABLE security_findings (
    finding_id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL
        REFERENCES encryption_assets(asset_id)
        ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    finding_code VARCHAR(60) NOT NULL,
    finding_text TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE
);

-- DES has a 56-bit effective key and a 64-bit block.
-- 3DES improves key strength but retains the 64-bit block.
-- AES uses a 128-bit block and larger key options.
INSERT INTO cryptographic_algorithms
    (algorithm_name, family, effective_key_bits, block_bits, classification, reason)
VALUES
    (
        'DES',
        'DES',
        56,
        64,
        'PROHIBITED',
        'The 56-bit effective key space is no longer adequate against modern exhaustive search.'
    ),
    (
        '3DES',
        '3DES',
        112,
        64,
        'LEGACY_ONLY',
        '3DES extends DES-era compatibility but retains the 64-bit block and higher processing cost.'
    ),
    (
        'AES-128',
        'AES',
        128,
        128,
        'APPROVED',
        'AES-128 provides a modern 128-bit block and substantially larger key space.'
    ),
    (
        'AES-256',
        'AES',
        256,
        128,
        'APPROVED',
        'AES-256 provides a large key space with a 128-bit block.'
    );

INSERT INTO repositories
    (repository_name, owning_team, environment, deployment_status)
VALUES
    ('legacy-payment-gateway', 'Payments Platform', 'production', 'LEGACY'),
    ('customer-records', 'Data Platform', 'production', 'MIGRATING'),
    ('analytics-archive', 'Analytics', 'production', 'LEGACY'),
    ('new-account-service', 'Identity Platform', 'production', 'NEW');

INSERT INTO encryption_assets
    (
        repository_id,
        asset_name,
        algorithm_id,
        data_classification,
        estimated_bytes_per_day,
        production_enabled
    )
SELECT
    r.repository_id,
    x.asset_name,
    a.algorithm_id,
    x.data_classification,
    x.estimated_bytes_per_day,
    x.production_enabled
FROM (
    VALUES
        (
            'legacy-payment-gateway',
            'card-compatibility-records',
            '3DES',
            'regulated',
            20::BIGINT * 1024 * 1024 * 1024,
            TRUE
        ),
        (
            'customer-records',
            'customer-database-backup',
            'DES',
            'confidential',
            400::BIGINT * 1024 * 1024 * 1024,
            TRUE
        ),
        (
            'analytics-archive',
            'historical-archive',
            'DES',
            'internal',
            100::BIGINT * 1024 * 1024 * 1024,
            TRUE
        ),
        (
            'new-account-service',
            'customer-secrets',
            'AES-256',
            'restricted',
            50::BIGINT * 1024 * 1024 * 1024,
            TRUE
        )
) AS x(
    repository_name,
    asset_name,
    algorithm_name,
    data_classification,
    estimated_bytes_per_day,
    production_enabled
)
JOIN repositories r
    ON r.repository_name = x.repository_name
JOIN cryptographic_algorithms a
    ON a.algorithm_name = x.algorithm_name;

-- An index supports inventory queries that search for assets using a
-- prohibited or legacy-only cryptographic algorithm.
CREATE INDEX idx_encryption_assets_algorithm
    ON encryption_assets(algorithm_id);

CREATE INDEX idx_security_findings_unresolved
    ON security_findings(asset_id)
    WHERE resolved = FALSE;

CREATE INDEX idx_migration_events_asset_time
    ON migration_events(asset_id, event_time DESC);

-- Detect assets that violate the organization's algorithm policy.
INSERT INTO security_findings
    (asset_id, severity, finding_code, finding_text)
SELECT
    ea.asset_id,
    CASE
        WHEN ca.algorithm_name = 'DES' THEN 'CRITICAL'
        ELSE 'HIGH'
    END,
    CASE
        WHEN ca.algorithm_name = 'DES'
            THEN 'DES_EFFECTIVE_KEY_TOO_SMALL'
        ELSE 'LEGACY_64_BIT_BLOCK_CIPHER'
    END,
    CASE
        WHEN ca.algorithm_name = 'DES'
            THEN 'DES uses a 56-bit effective key and is prohibited for modern protection.'
        ELSE '3DES retains a 64-bit block and is permitted only for controlled legacy compatibility.'
    END
FROM encryption_assets ea
JOIN cryptographic_algorithms ca
    ON ca.algorithm_id = ea.algorithm_id
WHERE ca.classification IN ('PROHIBITED', 'LEGACY_ONLY');

-- Inventory report showing why an asset is flagged.
SELECT
    r.repository_name,
    ea.asset_name,
    ca.algorithm_name,
    ca.effective_key_bits,
    ca.block_bits,
    ca.classification,
    ea.estimated_bytes_per_day,
    sf.severity,
    sf.finding_code
FROM encryption_assets ea
JOIN repositories r
    ON r.repository_id = ea.repository_id
JOIN cryptographic_algorithms ca
    ON ca.algorithm_id = ea.algorithm_id
LEFT JOIN security_findings sf
    ON sf.asset_id = ea.asset_id
   AND sf.resolved = FALSE
ORDER BY
    CASE sf.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    r.repository_name;

-- Compare the design characteristics without treating key size and block
-- size as interchangeable security properties.
SELECT
    algorithm_name,
    effective_key_bits,
    block_bits,
    classification,
    CASE
        WHEN effective_key_bits <= 56
            THEN 'Key space is the primary modern weakness.'
        WHEN block_bits = 64
            THEN 'Key strength improved, but the small block remains a limitation.'
        ELSE 'Modern block and key dimensions.'
    END AS engineering_interpretation
FROM cryptographic_algorithms
ORDER BY effective_key_bits;

-- Identify high-volume legacy encryption. A 64-bit block cipher has a much
-- smaller birthday-bound data scale than a 128-bit block cipher.
SELECT
    r.repository_name,
    ea.asset_name,
    ca.algorithm_name,
    ea.estimated_bytes_per_day
FROM encryption_assets ea
JOIN repositories r
    ON r.repository_id = ea.repository_id
JOIN cryptographic_algorithms ca
    ON ca.algorithm_id = ea.algorithm_id
WHERE ca.block_bits = 64
ORDER BY ea.estimated_bytes_per_day DESC;

-- A migration is recorded transactionally so the inventory and migration
-- history change together.
BEGIN;

WITH source_asset AS (
    SELECT
        ea.asset_id,
        ea.algorithm_id AS old_algorithm_id,
        target.algorithm_id AS new_algorithm_id
    FROM encryption_assets ea
    JOIN repositories r
        ON r.repository_id = ea.repository_id
    JOIN cryptographic_algorithms target
        ON target.algorithm_name = 'AES-256'
    WHERE r.repository_name = 'customer-records'
      AND ea.asset_name = 'customer-database-backup'
)
INSERT INTO migration_events
    (asset_id, previous_algorithm_id, target_algorithm_id, event_note)
SELECT
    asset_id,
    old_algorithm_id,
    new_algorithm_id,
    'Migrated from DES to AES-256 because DES is prohibited and the 64-bit block is unsuitable for the target workload.'
FROM source_asset;

UPDATE encryption_assets ea
SET algorithm_id = target.algorithm_id
FROM repositories r,
     cryptographic_algorithms target
WHERE ea.repository_id = r.repository_id
  AND target.algorithm_name = 'AES-256'
  AND r.repository_name = 'customer-records'
  AND ea.asset_name = 'customer-database-backup';

UPDATE security_findings sf
SET resolved = TRUE
FROM encryption_assets ea
JOIN repositories r
    ON r.repository_id = ea.repository_id
WHERE sf.asset_id = ea.asset_id
  AND r.repository_name = 'customer-records'
  AND ea.asset_name = 'customer-database-backup';

COMMIT;

-- Verify that the migrated asset now uses an approved modern algorithm.
SELECT
    r.repository_name,
    ea.asset_name,
    ca.algorithm_name,
    ca.classification,
    ca.effective_key_bits,
    ca.block_bits,
    me.event_time,
    me.event_note
FROM encryption_assets ea
JOIN repositories r
    ON r.repository_id = ea.repository_id
JOIN cryptographic_algorithms ca
    ON ca.algorithm_id = ea.algorithm_id
LEFT JOIN migration_events me
    ON me.asset_id = ea.asset_id
WHERE r.repository_name = 'customer-records'
  AND ea.asset_name = 'customer-database-backup'
ORDER BY me.event_time DESC NULLS LAST;

-- Policy query: find any production asset still using a prohibited algorithm.
SELECT
    r.repository_name,
    ea.asset_name,
    ca.algorithm_name
FROM encryption_assets ea
JOIN repositories r
    ON r.repository_id = ea.repository_id
JOIN cryptographic_algorithms ca
    ON ca.algorithm_id = ea.algorithm_id
WHERE ea.production_enabled = TRUE
  AND ca.classification = 'PROHIBITED';

-- A clean result from the previous query means the DES migration has removed
-- all production assets classified as prohibited.
