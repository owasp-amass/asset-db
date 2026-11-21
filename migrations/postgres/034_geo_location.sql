-- +migrate Up

-- ============================================================================
-- OWASP Amass: GeoLocation table native for asset type (PostgreSQL 13+)
--
-- A geographic position (WGS 84): latitude and longitude in decimal degrees,
-- identified by the position rounded to six decimal places,
-- "<latitude>,<longitude>". Altitude and uncertainty describe observations:
-- altitude takes the latest known value, and uncertainty keeps the smallest
-- radius observed, since the best sighting of a point is the one to trust.
-- ============================================================================

INSERT INTO public.entity_type_lu(name) VALUES ('geolocation') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS public.geolocation (
    id          bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    created_at  timestamp without time zone NOT NULL DEFAULT now(),
    updated_at  timestamp without time zone NOT NULL DEFAULT now(),
    unique_id   text NOT NULL UNIQUE,
    latitude    double precision NOT NULL,
    longitude   double precision NOT NULL,
    altitude    double precision,
    uncertainty double precision
);
CREATE INDEX IF NOT EXISTS idx_geolocation_updated_at_id_desc ON public.geolocation (updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_geolocation_lat_lon ON public.geolocation (latitude, longitude);

-- A revisit within one enumeration that changes nothing writes nothing.
CREATE TRIGGER touch_guard BEFORE UPDATE ON public.geolocation
FOR EACH ROW EXECUTE FUNCTION public.touch_guard();

-- Upsert a GeoLocation AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := NULLIF(_rec->>'unique_id', '');

    -- 1) Upsert into geolocation.
    v_row := public.geolocation_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'geolocation'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.geolocation'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_upsert(
    _unique_id   text,
    _latitude    double precision,
    _longitude   double precision,
    _altitude    double precision DEFAULT NULL,
    _uncertainty double precision DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _latitude IS NULL OR _longitude IS NULL THEN
        RAISE EXCEPTION 'geolocation_upsert requires non-NULL unique_id, latitude and longitude';
    END IF;

    INSERT INTO public.geolocation (
        unique_id, latitude, longitude, altitude, uncertainty
    ) VALUES (
        _unique_id, _latitude, _longitude, _altitude, _uncertainty
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        altitude    = COALESCE(EXCLUDED.altitude, geolocation.altitude),
        -- LEAST ignores NULLs: the smallest radius observed is kept
        uncertainty = LEAST(EXCLUDED.uncertainty, geolocation.uncertainty),
        updated_at  = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.geolocation WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
BEGIN
    RETURN public.geolocation_upsert(
        NULLIF(_rec->>'unique_id', ''),
        (_rec->>'latitude')::double precision,
        (_rec->>'longitude')::double precision,
        (_rec->>'altitude')::double precision,
        (_rec->>'uncertainty')::double precision
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_get_by_id(_row_id bigint)
RETURNS public.geolocation
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.geolocation
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: unique_id, latitude, longitude
-- Requires at least one supported filter to be present.
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id   bigint,
    id          bigint,
    created_at  timestamp without time zone,
    updated_at  timestamp without time zone,
    unique_id   text,
    latitude    double precision,
    longitude   double precision,
    altitude    double precision,
    uncertainty double precision
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id text             := NULLIF(_filters->>'unique_id', '');
    v_latitude  double precision := NULLIF(_filters->>'latitude', '')::double precision;
    v_longitude double precision := NULLIF(_filters->>'longitude', '')::double precision;
    v_limit     integer          := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_unique_id IS NULL AND v_latitude IS NULL AND v_longitude IS NULL THEN
        RAISE EXCEPTION 'geolocation_find_by_content requires at least one filter';
    END IF;

    RETURN QUERY
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.latitude,
        a.longitude,
        a.altitude,
        a.uncertainty
    FROM public.geolocation a
    JOIN public.entity e ON e.table_name = 'public.geolocation'::citext AND e.row_id = a.id
    WHERE
        (v_unique_id IS NULL OR a.unique_id = v_unique_id)
    AND (v_latitude  IS NULL OR a.latitude  = v_latitude)
    AND (v_longitude IS NULL OR a.longitude = v_longitude)
    AND (_since      IS NULL OR a.updated_at >= _since)
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT v_limit; -- LIMIT NULL is unlimited
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.geolocation_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id   bigint,
    id          bigint,
    created_at  timestamp without time zone,
    updated_at  timestamp without time zone,
    unique_id   text,
    latitude    double precision,
    longitude   double precision,
    altitude    double precision,
    uncertainty double precision
)
LANGUAGE plpgsql
STABLE
AS $fn$
BEGIN
    RETURN QUERY
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.latitude,
        a.longitude,
        a.altitude,
        a.uncertainty
    FROM public.geolocation a
    JOIN public.entity e ON e.table_name = 'public.geolocation'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT NULLIF(_limit, 0); -- LIMIT NULL is unlimited
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.geolocation_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.geolocation_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.geolocation_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.geolocation_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.geolocation_upsert(text, double precision, double precision, double precision, double precision);
DROP FUNCTION IF EXISTS public.geolocation_upsert_entity_json(jsonb);

DROP TRIGGER IF EXISTS touch_guard ON public.geolocation;
DROP INDEX IF EXISTS idx_geolocation_lat_lon;
DROP INDEX IF EXISTS idx_geolocation_updated_at_id_desc;
DROP TABLE IF EXISTS public.geolocation;

DELETE FROM public.entity_type_lu WHERE name = 'geolocation';
