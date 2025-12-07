-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Location Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.location (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  city text NOT NULL,
  unit text,
  street_address text NOT NULL UNIQUE,
  country text NOT NULL,
  building text,
  province text,
  locality text,
  postal_code text,
  street_name text,
  building_number text
);
CREATE INDEX IF NOT EXISTS idx_location_created_at
  ON public.location(created_at);
CREATE INDEX IF NOT EXISTS idx_location_updated_at
  ON public.location(updated_at);
CREATE INDEX IF NOT EXISTS idx_location_building
  ON public.location(building);
CREATE INDEX IF NOT EXISTS idx_location_building_number
  ON public.location(building_number);
CREATE INDEX IF NOT EXISTS idx_location_province
  ON public.location(province);
CREATE INDEX IF NOT EXISTS idx_location_street_name
  ON public.location(street_name);
CREATE INDEX IF NOT EXISTS idx_location_unit
  ON public.location(unit);
CREATE INDEX IF NOT EXISTS idx_location_locality
  ON public.location(locality);
CREATE INDEX IF NOT EXISTS idx_location_city
  ON public.location(city);
CREATE INDEX IF NOT EXISTS idx_location_country
  ON public.location(country);
CREATE INDEX IF NOT EXISTS idx_location_postal_code
  ON public.location(postal_code);

-- Upsert by street_address (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert(
    _street_address text,
    _city           text,
    _country        text,
    _unit           text DEFAULT NULL,
    _building       text DEFAULT NULL,
    _province       text DEFAULT NULL,
    _locality       text DEFAULT NULL,
    _postal_code    text DEFAULT NULL,
    _street_name    text DEFAULT NULL,
    _building_number text DEFAULT NULL
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
        street_address,
        city,
        country,
        unit,
        building,
        province,
        locality,
        postal_code,
        street_name,
        building_number
    ) VALUES (
        _street_address,
        _city,
        _country,
        _unit,
        _building,
        _province,
        _locality,
        _postal_code,
        _street_name,
        _building_number
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
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   street_address, city, country, unit, building, province, locality,
--   postal_code, street_name, building_number
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_street_address text;
    v_city           text;
    v_country        text;
    v_unit           text;
    v_building       text;
    v_province       text;
    v_locality       text;
    v_postal_code    text;
    v_street_name    text;
    v_building_number text;
BEGIN
    v_street_address  := _rec->>'street_address';
    v_city            := _rec->>'city';
    v_country         := _rec->>'country';
    v_unit            := NULLIF(_rec->>'unit', '');
    v_building        := NULLIF(_rec->>'building', '');
    v_province        := NULLIF(_rec->>'province', '');
    v_locality        := NULLIF(_rec->>'locality', '');
    v_postal_code     := NULLIF(_rec->>'postal_code', '');
    v_street_name     := NULLIF(_rec->>'street_name', '');
    v_building_number := NULLIF(_rec->>'building_number', '');

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
        v_building_number
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by street_address (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_id_by_street_address(
    _street_address text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.location
    WHERE street_address = _street_address
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by street_address
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_by_street_address(
    _street_address text
) RETURNS public.location
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.location
    WHERE street_address = _street_address
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by postal_code (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_find_by_postal_code(
    _postal_code text
) RETURNS SETOF public.location
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.location
    WHERE (CASE
             WHEN strpos(_postal_code, '%') > 0 OR strpos(_postal_code, '_') > 0
               THEN postal_code ILIKE _postal_code
             ELSE postal_code = _postal_code
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.location
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.location
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Location AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_entity(
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
    _extra_attrs     jsonb  DEFAULT '{}'::jsonb,          -- for caller-provided extra attributes
    _etype_name      citext DEFAULT 'location'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.location%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _street_address IS NULL OR _city IS NULL OR _country IS NULL THEN
        RAISE EXCEPTION 'location_upsert_entity requires non-NULL street_address, city and country';
    END IF;

    -- 1) Upsert into location by street_address.
    INSERT INTO public.location (
        street_address,
        city,
        country,
        unit,
        building,
        province,
        locality,
        postal_code,
        street_name,
        building_number
    ) VALUES (
        _street_address,
        _city,
        _country,
        _unit,
        _building,
        _province,
        _locality,
        _postal_code,
        _street_name,
        _building_number
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
        updated_at      = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the location plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'street_address',  v_row.street_address,
            'city',            v_row.city,
            'country',         v_row.country,
            'unit',            v_row.unit,
            'building',        v_row.building,
            'province',        v_row.province,
            'locality',        v_row.locality,
            'postal_code',     v_row.postal_code,
            'street_name',     v_row.street_name,
            'building_number', v_row.building_number
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using street_address as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                       -- e.g. 'location'
        _natural_key := v_row.street_address::citext,      -- canonical key
        _table_name  := 'location'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map street_address -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_entity_id_by_street_address(
    _street_address text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.location l
    JOIN public.entity e
      ON e.table_name = 'location'
     AND e.row_id     = l.id
    WHERE l.street_address = _street_address
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Location by street_address
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_with_entity_by_street_address(
    _street_address text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    location_row public.location
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        l
    FROM public.location l
    JOIN public.entity e
      ON e.table_name = 'location'
     AND e.row_id     = l.id
    WHERE l.street_address = _street_address
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.location_upsert(text, 
    text, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public.location_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.location_get_id_by_street_address(text);
DROP FUNCTION IF EXISTS public.location_get_by_street_address(text);
DROP FUNCTION IF EXISTS public.location_find_by_postal_code(text);
DROP FUNCTION IF EXISTS public.location_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.location_upsert_entity(text, text,
    text, text, text, text, text, text, text, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.location_get_entity_id_by_street_address(text);
DROP FUNCTION IF EXISTS public.location_get_with_entity_by_street_address(text);

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