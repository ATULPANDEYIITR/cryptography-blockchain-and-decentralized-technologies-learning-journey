/*
 * ELLIPTIC CURVES AND POINTS
 * PostgreSQL relational implementation
 *
 * Models:
 * - Finite fields
 * - Elliptic curve configurations
 * - Curve points
 * - Point membership validation
 * - Point operations
 * - Scalar multiplication
 * - Point orders
 * - Group validation
 * - Operation auditing
 * - Reproducible computational experiments
 *
 * Curve equation:
 * y^2 = x^3 + ax + b (mod p)
 *
 * This implementation restricts p to 1,000,000.
 * This keeps intermediate BIGINT multiplication safe.
 *
 * Execute using PostgreSQL 14 or later.
 */

BEGIN;

CREATE SCHEMA IF NOT EXISTS elliptic;
SET search_path TO elliptic, public;

-- ============================================================
-- 1. DOMAIN TYPES
-- ============================================================

CREATE TYPE point_kind AS ENUM (
    'FINITE',
    'INFINITY'
);

CREATE TYPE operation_kind AS ENUM (
    'ADDITION',
    'DOUBLING',
    'NEGATION',
    'SCALAR_MULTIPLICATION'
);

CREATE TYPE experiment_status AS ENUM (
    'CREATED',
    'RUNNING',
    'COMPLETED',
    'FAILED'
);

-- ============================================================
-- 2. FINITE-FIELD CONFIGURATION
-- ============================================================

CREATE TABLE curves (
    curve_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_name VARCHAR(100) NOT NULL UNIQUE,

    field_prime BIGINT NOT NULL,

    coefficient_a BIGINT NOT NULL,

    coefficient_b BIGINT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_field_prime
        CHECK (field_prime BETWEEN 2 AND 1000000),

    CONSTRAINT normalized_a
        CHECK (
            coefficient_a >= 0
            AND coefficient_a < field_prime
        ),

    CONSTRAINT normalized_b
        CHECK (
            coefficient_b >= 0
            AND coefficient_b < field_prime
        )
);

-- ============================================================
-- 3. BASIC NUMBER-THEORETIC FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.is_prime(n BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    divisor BIGINT := 3;
BEGIN
    IF n < 2 THEN
        RETURN FALSE;
    END IF;

    IF n IN (2, 3) THEN
        RETURN TRUE;
    END IF;

    IF n % 2 = 0 THEN
        RETURN FALSE;
    END IF;

    WHILE divisor <= n / divisor LOOP
        IF n % divisor = 0 THEN
            RETURN FALSE;
        END IF;

        divisor := divisor + 2;
    END LOOP;

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION elliptic.mod_inverse(
    value BIGINT,
    modulus BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    old_r BIGINT;
    r BIGINT;
    old_s BIGINT := 1;
    s BIGINT := 0;
    quotient BIGINT;
    next_r BIGINT;
    next_s BIGINT;
BEGIN
    IF modulus < 2 THEN
        RAISE EXCEPTION 'Invalid modulus';
    END IF;

    old_r := ((value % modulus) + modulus) % modulus;
    r := modulus;

    IF old_r = 0 THEN
        RAISE EXCEPTION 'Zero has no modular inverse';
    END IF;

    WHILE r <> 0 LOOP
        quotient := old_r / r;

        next_r := old_r - quotient * r;
        old_r := r;
        r := next_r;

        next_s := old_s - quotient * s;
        old_s := s;
        s := next_s;
    END LOOP;

    IF old_r <> 1 THEN
        RAISE EXCEPTION 'Value is not invertible';
    END IF;

    RETURN ((old_s % modulus) + modulus) % modulus;
END;
$$;

-- ============================================================
-- 4. CURVE VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.validate_curve()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    discriminant BIGINT;
BEGIN
    IF NOT elliptic.is_prime(NEW.field_prime) THEN
        RAISE EXCEPTION
            'Field modulus % is not prime',
            NEW.field_prime;
    END IF;

    discriminant := (
        4 * POWER(NEW.coefficient_a::NUMERIC, 3)
        + 27 * POWER(NEW.coefficient_b::NUMERIC, 2)
    )::BIGINT % NEW.field_prime;

    IF discriminant = 0 THEN
        RAISE EXCEPTION
            'Singular elliptic curves are not allowed';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER validate_curve_before_write
BEFORE INSERT OR UPDATE ON elliptic.curves
FOR EACH ROW
EXECUTE FUNCTION elliptic.validate_curve();

-- ============================================================
-- 5. POINTS
-- ============================================================

CREATE TABLE curve_points (
    point_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL
        REFERENCES curves(curve_id)
        ON DELETE CASCADE,

    point_type point_kind NOT NULL DEFAULT 'FINITE',

    x_coordinate BIGINT,

    y_coordinate BIGINT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT point_coordinate_state
        CHECK (
            (
                point_type = 'INFINITY'
                AND x_coordinate IS NULL
                AND y_coordinate IS NULL
            )
            OR
            (
                point_type = 'FINITE'
                AND x_coordinate IS NOT NULL
                AND y_coordinate IS NOT NULL
            )
        ),

    CONSTRAINT unique_point
        UNIQUE (
            curve_id,
            point_type,
            x_coordinate,
            y_coordinate
        )
);

CREATE INDEX idx_points_curve
ON curve_points(curve_id);

CREATE INDEX idx_points_coordinates
ON curve_points(curve_id, x_coordinate, y_coordinate)
WHERE point_type = 'FINITE';

-- ============================================================
-- 6. POINT MEMBERSHIP
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.point_is_valid(
    p_curve_id BIGINT,
    p_x BIGINT,
    p_y BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    curve_record RECORD;
    lhs BIGINT;
    rhs BIGINT;
BEGIN
    SELECT field_prime, coefficient_a, coefficient_b
    INTO curve_record
    FROM elliptic.curves
    WHERE curve_id = p_curve_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF p_x IS NULL OR p_y IS NULL THEN
        RETURN FALSE;
    END IF;

    IF (
        p_x < 0 OR p_x >= curve_record.field_prime
        OR p_y < 0 OR p_y >= curve_record.field_prime
    ) THEN
        RETURN FALSE;
    END IF;

    lhs := (p_y::NUMERIC * p_y)::BIGINT
        % curve_record.field_prime;

    rhs := (
        POWER(p_x::NUMERIC, 3)
        + curve_record.coefficient_a::NUMERIC * p_x
        + curve_record.coefficient_b
    )::BIGINT % curve_record.field_prime;

    RETURN lhs = rhs;
END;
$$;

CREATE OR REPLACE FUNCTION elliptic.validate_point()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.point_type = 'FINITE' THEN
        IF NOT elliptic.point_is_valid(
            NEW.curve_id,
            NEW.x_coordinate,
            NEW.y_coordinate
        ) THEN
            RAISE EXCEPTION
                'Invalid point coordinates (%, %) for curve %',
                NEW.x_coordinate,
                NEW.y_coordinate,
                NEW.curve_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER validate_point_before_write
BEFORE INSERT OR UPDATE ON elliptic.curve_points
FOR EACH ROW
EXECUTE FUNCTION elliptic.validate_point();

-- ============================================================
-- 7. OPERATION AUDIT
-- ============================================================

CREATE TABLE point_operations (
    operation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL
        REFERENCES curves(curve_id),

    operation_type operation_kind NOT NULL,

    left_point_id BIGINT
        REFERENCES curve_points(point_id),

    right_point_id BIGINT
        REFERENCES curve_points(point_id),

    scalar_value BIGINT,

    result_point_id BIGINT
        REFERENCES curve_points(point_id),

    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    execution_metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX idx_operations_curve_time
ON point_operations(curve_id, executed_at DESC);

-- ============================================================
-- 8. GROUP EXPERIMENTS
-- ============================================================

CREATE TABLE experiments (
    experiment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    curve_id BIGINT NOT NULL
        REFERENCES curves(curve_id),

    experiment_name VARCHAR(150) NOT NULL,

    status experiment_status NOT NULL DEFAULT 'CREATED',

    expected_group_size BIGINT,

    measured_group_size BIGINT,

    started_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT nonnegative_group_sizes
        CHECK (
            (expected_group_size IS NULL OR expected_group_size > 0)
            AND
            (measured_group_size IS NULL OR measured_group_size > 0)
        ),

    CONSTRAINT experiment_timestamps
        CHECK (
            completed_at IS NULL
            OR started_at IS NULL
            OR completed_at >= started_at
        ),

    UNIQUE(curve_id, experiment_name)
);

CREATE INDEX idx_experiments_status
ON experiments(status, created_at DESC);

-- ============================================================
-- 9. GROUP MEMBERSHIP FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.point_add(
    p_curve_id BIGINT,
    x1 BIGINT,
    y1 BIGINT,
    x2 BIGINT,
    y2 BIGINT
)
RETURNS TABLE (
    result_x BIGINT,
    result_y BIGINT,
    is_infinity BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    curve_record RECORD;
    slope BIGINT;
    numerator BIGINT;
    denominator BIGINT;
    x3 BIGINT;
    y3 BIGINT;
BEGIN
    SELECT field_prime, coefficient_a, coefficient_b
    INTO curve_record
    FROM elliptic.curves
    WHERE curve_id = p_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown curve';
    END IF;

    IF NOT elliptic.point_is_valid(p_curve_id, x1, y1)
       OR NOT elliptic.point_is_valid(p_curve_id, x2, y2) THEN
        RAISE EXCEPTION 'Invalid input point';
    END IF;

    -- P + (-P) = O.
    IF x1 = x2
       AND ((y1 + y2) % curve_record.field_prime) = 0 THEN
        RETURN QUERY SELECT NULL::BIGINT, NULL::BIGINT, TRUE;
        RETURN;
    END IF;

    IF x1 = x2 AND y1 = y2 THEN
        IF y1 = 0 THEN
            RETURN QUERY SELECT NULL::BIGINT, NULL::BIGINT, TRUE;
            RETURN;
        END IF;

        numerator := (
            3 * POWER(x1::NUMERIC, 2)
            + curve_record.coefficient_a
        )::BIGINT;

        denominator := 2 * y1;
    ELSE
        numerator := y2 - y1;
        denominator := x2 - x1;
    END IF;

    slope := (
        numerator::NUMERIC
        * elliptic.mod_inverse(
            denominator,
            curve_record.field_prime
        )
    )::BIGINT % curve_record.field_prime;

    x3 := (
        POWER(slope::NUMERIC, 2)
        - x1 - x2
    )::BIGINT % curve_record.field_prime;

    x3 := (x3 + curve_record.field_prime)
        % curve_record.field_prime;

    y3 := (
        slope::NUMERIC * (x1 - x3) - y1
    )::BIGINT % curve_record.field_prime;

    y3 := (y3 + curve_record.field_prime)
        % curve_record.field_prime;

    IF NOT elliptic.point_is_valid(p_curve_id, x3, y3) THEN
        RAISE EXCEPTION 'Computed point failed validation';
    END IF;

    RETURN QUERY SELECT x3, y3, FALSE;
END;
$$;

-- ============================================================
-- 10. SCALAR MULTIPLICATION
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.scalar_multiply(
    p_curve_id BIGINT,
    scalar BIGINT,
    x BIGINT,
    y BIGINT
)
RETURNS TABLE (
    result_x BIGINT,
    result_y BIGINT,
    is_infinity BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    k BIGINT;
    current_x BIGINT := x;
    current_y BIGINT := y;
    accumulator_x BIGINT;
    accumulator_y BIGINT;
    accumulator_infinity BOOLEAN := TRUE;
    current_infinity BOOLEAN := FALSE;
    temporary RECORD;
BEGIN
    IF NOT elliptic.point_is_valid(p_curve_id, x, y) THEN
        RAISE EXCEPTION 'Invalid generator point';
    END IF;

    IF scalar < 0 THEN
        RAISE EXCEPTION
            'Negative scalar is not supported by this SQL function';
    END IF;

    k := scalar;

    WHILE k > 0 LOOP
        IF k % 2 = 1 THEN
            IF accumulator_infinity THEN
                accumulator_x := current_x;
                accumulator_y := current_y;
                accumulator_infinity := current_infinity;
            ELSE
                SELECT *
                INTO temporary
                FROM elliptic.point_add(
                    p_curve_id,
                    accumulator_x,
                    accumulator_y,
                    current_x,
                    current_y
                );

                accumulator_x := temporary.result_x;
                accumulator_y := temporary.result_y;
                accumulator_infinity := temporary.is_infinity;
            END IF;
        END IF;

        k := k / 2;

        IF k > 0 THEN
            SELECT *
            INTO temporary
            FROM elliptic.point_add(
                p_curve_id,
                current_x,
                current_y,
                current_x,
                current_y
            );

            current_x := temporary.result_x;
            current_y := temporary.result_y;
            current_infinity := temporary.is_infinity;

            IF current_infinity THEN
                -- Doubling the identity remains the identity.
                current_x := NULL;
                current_y := NULL;
            END IF;
        END IF;
    END LOOP;

    RETURN QUERY
    SELECT
        accumulator_x,
        accumulator_y,
        accumulator_infinity;
END;
$$;

-- ============================================================
-- 11. POINT ORDER
-- ============================================================

CREATE OR REPLACE FUNCTION elliptic.point_order(
    p_curve_id BIGINT,
    x BIGINT,
    y BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    curve_record RECORD;
    current_x BIGINT := x;
    current_y BIGINT := y;
    result RECORD;
    order_value BIGINT := 0;
    bound_value BIGINT;
    root_value BIGINT;
BEGIN
    SELECT field_prime
    INTO curve_record
    FROM elliptic.curves
    WHERE curve_id = p_curve_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown curve';
    END IF;

    IF NOT elliptic.point_is_valid(p_curve_id, x, y) THEN
        RAISE EXCEPTION 'Invalid point';
    END IF;

    root_value := CEIL(SQRT(curve_record.field_prime::NUMERIC));
    bound_value := curve_record.field_prime + 1 + 2 * root_value;

    LOOP
        order_value := order_value + 1;

        SELECT *
        INTO result
        FROM elliptic.point_add(
            p_curve_id,
            current_x,
            current_y,
            x,
            y
        );

        IF result.is_infinity THEN
            RETURN order_value;
        END IF;

        current_x := result.result_x;
        current_y := result.result_y;

        IF order_value >= bound_value THEN
            RAISE EXCEPTION 'Point order search exceeded Hasse bound';
        END IF;
    END LOOP;
END;
$$;

-- ============================================================
-- 12. GROUP VALIDATION VIEW
-- ============================================================

CREATE OR REPLACE VIEW curve_point_inventory AS
SELECT
    c.curve_id,
    c.curve_name,
    c.field_prime,
    c.coefficient_a,
    c.coefficient_b,
    COUNT(p.point_id) FILTER (
        WHERE p.point_type = 'FINITE'
    ) AS affine_point_count,
    COUNT(p.point_id) FILTER (
        WHERE p.point_type = 'INFINITY'
    ) AS infinity_point_count
FROM curves c
LEFT JOIN curve_points p
    ON p.curve_id = c.curve_id
GROUP BY
    c.curve_id,
    c.curve_name,
    c.field_prime,
    c.coefficient_a,
    c.coefficient_b;

-- ============================================================
-- 13. SAMPLE CURVE
-- ============================================================

INSERT INTO curves (
    curve_name,
    field_prime,
    coefficient_a,
    coefficient_b
)
VALUES (
    'educational_curve_97',
    97,
    2,
    3
);

-- ============================================================
-- 14. SAMPLE POINTS
-- ============================================================

INSERT INTO curve_points (
    curve_id,
    point_type,
    x_coordinate,
    y_coordinate
)
SELECT
    curve_id,
    'INFINITY',
    NULL,
    NULL
FROM curves
WHERE curve_name = 'educational_curve_97';

INSERT INTO curve_points (
    curve_id,
    point_type,
    x_coordinate,
    y_coordinate
)
SELECT
    curve_id,
    'FINITE',
    3,
    6
FROM curves
WHERE curve_name = 'educational_curve_97';

INSERT INTO curve_points (
    curve_id,
    point_type,
    x_coordinate,
    y_coordinate
)
SELECT
    curve_id,
    'FINITE',
    3,
    91
FROM curves
WHERE curve_name = 'educational_curve_97';

-- ============================================================
-- 15. SAMPLE EXPERIMENT
-- ============================================================

INSERT INTO experiments (
    curve_id,
    experiment_name,
    status,
    expected_group_size,
    started_at
)
SELECT
    curve_id,
    'finite_field_group_analysis',
    'RUNNING',
    NULL,
    CURRENT_TIMESTAMP
FROM curves
WHERE curve_name = 'educational_curve_97';

-- ============================================================
-- 16. RETRIEVAL
-- ============================================================

SELECT
    c.curve_name,
    c.field_prime,
    c.coefficient_a,
    c.coefficient_b,
    p.point_type,
    p.x_coordinate,
    p.y_coordinate
FROM curves c
JOIN curve_points p
    ON p.curve_id = c.curve_id
ORDER BY p.point_id;

-- ============================================================
-- 17. VALIDATION
-- ============================================================

SELECT
    point_id,
    x_coordinate,
    y_coordinate,
    elliptic.point_is_valid(
        curve_id,
        x_coordinate,
        y_coordinate
    ) AS is_valid
FROM curve_points
WHERE point_type = 'FINITE';

-- ============================================================
-- 18. GROUP OPERATIONS
-- ============================================================

SELECT *
FROM elliptic.point_add(
    (
        SELECT curve_id
        FROM curves
        WHERE curve_name = 'educational_curve_97'
    ),
    3,
    6,
    3,
    6
);

-- ============================================================
-- 19. SCALAR MULTIPLICATION
-- ============================================================

SELECT *
FROM elliptic.scalar_multiply(
    (
        SELECT curve_id
        FROM curves
        WHERE curve_name = 'educational_curve_97'
    ),
    3,
    3,
    6
);

-- ============================================================
-- 20. POINT ORDER
-- ============================================================

SELECT elliptic.point_order(
    (
        SELECT curve_id
        FROM curves
        WHERE curve_name = 'educational_curve_97'
    ),
    3,
    6
) AS generator_order;

-- ============================================================
-- 21. AGGREGATION AND REPORTING
-- ============================================================

SELECT *
FROM curve_point_inventory;

SELECT
    curve_id,
    COUNT(*) AS recorded_operations,
    COUNT(*) FILTER (
        WHERE operation_type = 'ADDITION'
    ) AS additions,
    COUNT(*) FILTER (
        WHERE operation_type = 'DOUBLING'
    ) AS doublings,
    COUNT(*) FILTER (
        WHERE operation_type = 'SCALAR_MULTIPLICATION'
    ) AS scalar_multiplications
FROM point_operations
GROUP BY curve_id;

-- ============================================================
-- 22. INVALID-CASE VALIDATION
-- ============================================================

DO $$
DECLARE
    test_curve_id BIGINT;
    rejected BOOLEAN := FALSE;
BEGIN
    SELECT curve_id
    INTO test_curve_id
    FROM elliptic.curves
    WHERE curve_name = 'educational_curve_97';

    BEGIN
        INSERT INTO elliptic.curve_points (
            curve_id,
            point_type,
            x_coordinate,
            y_coordinate
        )
        VALUES (
            test_curve_id,
            'FINITE',
            10,
            10
        );

    EXCEPTION WHEN OTHERS THEN
        rejected := TRUE;
        RAISE NOTICE 'Invalid point correctly rejected: %', SQLERRM;
    END;

    IF NOT rejected THEN
        RAISE EXCEPTION 'Invalid point was unexpectedly accepted';
    END IF;
END;
$$;

-- ============================================================
-- 23. EXPERIMENT COMPLETION
-- ============================================================

UPDATE experiments
SET
    status = 'COMPLETED',
    measured_group_size = (
        SELECT COUNT(*)
        FROM (
            SELECT
                x_coordinate,
                y_coordinate
            FROM curve_points
            WHERE curve_id = experiments.curve_id
              AND point_type = 'FINITE'
        ) AS recorded_points
    ) + 1,
    completed_at = CURRENT_TIMESTAMP
WHERE experiment_name = 'finite_field_group_analysis';

SELECT
    experiment_name,
    status,
    expected_group_size,
    measured_group_size,
    started_at,
    completed_at
FROM experiments;

-- ============================================================
-- 24. TRANSACTION VALIDATION
-- ============================================================

SAVEPOINT before_test_record;

-- This valid operation demonstrates transactional persistence.
INSERT INTO experiments (
    curve_id,
    experiment_name,
    status
)
SELECT
    curve_id,
    'transactional_validation_run',
    'CREATED'
FROM curves
WHERE curve_name = 'educational_curve_97';

-- Retain the experiment record.
RELEASE SAVEPOINT before_test_record;

COMMIT;

-- ============================================================
-- 25. ADDITIONAL REPORTING QUERIES
-- ============================================================

SELECT
    c.curve_name,
    c.field_prime,
    COUNT(p.point_id) AS stored_points
FROM curves c
LEFT JOIN curve_points p
    ON p.curve_id = c.curve_id
GROUP BY c.curve_id, c.curve_name, c.field_prime;

SELECT
    e.experiment_name,
    e.status,
    e.measured_group_size,
    c.curve_name
FROM experiments e
JOIN curves c
    ON c.curve_id = e.curve_id
ORDER BY e.created_at DESC;

-- Verify all recorded finite points.
SELECT
    p.point_id,
    p.x_coordinate,
    p.y_coordinate,
    c.curve_name
FROM curve_points p
JOIN curves c
    ON c.curve_id = p.curve_id
WHERE p.point_type = 'FINITE'
  AND NOT elliptic.point_is_valid(
      p.curve_id,
      p.x_coordinate,
      p.y_coordinate
  );

-- An empty result means all stored finite points are valid.
