-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Location Table native for asset type
-- ============================================================================


CREATE TABLE IF NOT EXISTS public.location (
  id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at      timestamp without time zone NOT NULL DEFAULT now(),
  updated_at      timestamp without time zone NOT NULL DEFAULT now(),
  city            text NOT NULL,
  unit            text,
  street_address  text NOT NULL UNIQUE,
  country         text NOT NULL,
  building        text,
  province        text,
  locality        text,
  postal_code     text,
  street_name     text,
  building_number text,
  attrs           jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_location_created_at ON public.location (created_at);
CREATE INDEX IF NOT EXISTS idx_location_updated_at ON public.location (updated_at);
CREATE INDEX IF NOT EXISTS idx_location_building ON public.location (building);
CREATE INDEX IF NOT EXISTS idx_location_building_number ON public.location (building_number);
CREATE INDEX IF NOT EXISTS idx_location_province ON public.location (province);
CREATE INDEX IF NOT EXISTS idx_location_street_name ON public.location (street_name);
CREATE INDEX IF NOT EXISTS idx_location_unit ON public.location (unit);
CREATE INDEX IF NOT EXISTS idx_location_locality ON public.location (locality);
CREATE INDEX IF NOT EXISTS idx_location_city ON public.location (city);
CREATE INDEX IF NOT EXISTS idx_location_country ON public.location (country);
CREATE INDEX IF NOT EXISTS idx_location_postal_code ON public.location (postal_code);

-- Upsert a Location AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_addr text;
    v_row  bigint;
BEGIN
    v_addr := NULLIF(_rec->>'address', '');

    -- 1) Upsert into location.
    v_row := public.location_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'location'::citext,
        _natural_key := v_addr::citext,
        _table_name  := 'public.location'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by street_address (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert(
    _street_address  text,
    _city            text,
    _country         text,
    _unit            text DEFAULT NULL,
    _building        text DEFAULT NULL,
    _province        text DEFAULT NULL,
    _locality        text DEFAULT NULL,
    _postal_code     text DEFAULT NULL,
    _street_name     text DEFAULT NULL,
    _building_number text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _street_address IS NULL OR _city IS NULL OR _country IS NULL THEN
        RAISE EXCEPTION 'location_upsert requires non-NULL street_address, city and country';
    END IF;

    INSERT INTO public.location (
        street_address, city, country, unit, building, province,
        locality, postal_code, street_name, building_number, attrs
    ) VALUES (
        _street_address, _city, _country, _unit, _building, _province, 
        _locality, _postal_code, _street_name, _building_number, _attrs
    )
    ON CONFLICT (street_address) DO UPDATE
    SET
        city            = COALESCE(EXCLUDED.city,            location.city),
        country         = COALESCE(EXCLUDED.country,         location.country),
        unit            = COALESCE(EXCLUDED.unit,            location.unit),
        building        = COALESCE(EXCLUDED.building,        location.building),
        province        = COALESCE(EXCLUDED.province,        location.province),
        locality        = COALESCE(EXCLUDED.locality,        location.locality),
        postal_code     = COALESCE(EXCLUDED.postal_code,     location.postal_code),
        street_name     = COALESCE(EXCLUDED.street_name,     location.street_name),
        building_number = COALESCE(EXCLUDED.building_number, location.building_number),
        attrs           = location.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_street_address  text;
    v_city            text;
    v_country         text;
    v_unit            text;
    v_building        text;
    v_province        text;
    v_locality        text;
    v_postal_code     text;
    v_street_name     text;
    v_building_number text;
    v_po_box          text;
    v_gln             text;
    v_attrs           jsonb;
BEGIN
    v_street_address  := NULLIF(_rec->>'address', '');
    v_city            := NULLIF(_rec->>'city', '');
    v_country         := NULLIF(_rec->>'country', '');
    v_unit            := NULLIF(_rec->>'unit', '');
    v_building        := NULLIF(_rec->>'building', '');
    v_province        := NULLIF(_rec->>'province', '');
    v_locality        := NULLIF(_rec->>'locality', '');
    v_postal_code     := NULLIF(_rec->>'postal_code', '');
    v_street_name     := NULLIF(_rec->>'street_name', '');
    v_building_number := NULLIF(_rec->>'building_number', '');
    v_po_box          := NULLIF(_rec->>'po_box', '');
    v_gln             := NULLIF(_rec->>'gln', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'po_box', v_po_box,
            'gln',    v_gln
        )
    ) || '{}'::jsonb;

    RETURN public.location_upsert(
        v_street_address,
        v_city,
        v_country,
        v_unit,
        v_building,
        v_province,
        v_locality,
        v_postal_code,
        v_street_name,
        v_building_number,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_by_id(_row_id bigint)
RETURNS public.location
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.location
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: street_address (or address), city, country, unit, building,
-- province, locality, postal_code, street_name, building_number
-- Requires at least one supported filter to be present.
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    -- Support both "street_address" and legacy "address"
    v_street_address  text := NULLIF(_filters->>'address', '');
    v_city            text := NULLIF(_filters->>'city', '');
    v_country         text := NULLIF(_filters->>'country', '');
    v_unit            text := NULLIF(_filters->>'unit', '');
    v_building        text := NULLIF(_filters->>'building', '');
    v_province        text := NULLIF(_filters->>'province', '');
    v_locality        text := NULLIF(_filters->>'locality', '');
    v_postal_code     text := NULLIF(_filters->>'postal_code', '');
    v_street_name     text := NULLIF(_filters->>'street_name', '');
    v_building_number text := NULLIF(_filters->>'building_number', '');
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    -- Require at least one supported filter
    IF v_street_address IS NULL
       AND v_city IS NULL
       AND v_country IS NULL
       AND v_unit IS NULL
       AND v_building IS NULL
       AND v_province IS NULL
       AND v_locality IS NULL
       AND v_postal_code IS NULL
       AND v_street_name IS NULL
       AND v_building_number IS NULL THEN
        RAISE EXCEPTION 'location_find_by_content requires at least one filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.location_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.location_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.location_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.location_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.location_upsert(
    text, text, text, text, text, text, text, text, text, text, jsonb
);
DROP FUNCTION IF EXISTS public.location_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_location_postal_code;
DROP INDEX IF EXISTS idx_location_country;
DROP INDEX IF EXISTS idx_location_city;
DROP INDEX IF EXISTS idx_location_locality;
DROP INDEX IF EXISTS idx_location_unit;
DROP INDEX IF EXISTS idx_location_street_name;
DROP INDEX IF EXISTS idx_location_province;
DROP INDEX IF EXISTS idx_location_building_number;
DROP INDEX IF EXISTS idx_location_building;
DROP INDEX IF EXISTS idx_location_updated_at;
DROP INDEX IF EXISTS idx_location_created_at;
DROP TABLE IF EXISTS public.location;