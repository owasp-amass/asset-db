-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Phone Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.phone (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  raw_number text NOT NULL,
  e164 text NOT NULL UNIQUE,
  number_type text,
  country_code integer,
  country_abbrev text
);
CREATE INDEX IF NOT EXISTS idx_phone_created_at
  ON public.phone(created_at);
CREATE INDEX IF NOT EXISTS idx_phone_updated_at
  ON public.phone(updated_at);
CREATE INDEX IF NOT EXISTS idx_phone_raw
  ON public.phone(raw_number);
CREATE INDEX IF NOT EXISTS idx_phone_number_type
  ON public.phone(number_type);
CREATE INDEX IF NOT EXISTS idx_phone_country_code
  ON public.phone(country_code);
CREATE INDEX IF NOT EXISTS idx_phone_country_abbrev
  ON public.phone(country_abbrev);

-- Upsert by e164 (scalar params). Returns the row id.
-- Note: raw_number will fall back to e164 if not provided.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert(
    _e164           text,
    _raw_number     text DEFAULT NULL,
    _number_type    text DEFAULT NULL,
    _country_code   integer DEFAULT NULL,
    _country_abbrev text DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _e164 IS NULL THEN
        RAISE EXCEPTION 'phone_upsert requires non-NULL e164';
    END IF;

    INSERT INTO public.phone (
        raw_number,
        e164,
        number_type,
        country_code,
        country_abbrev
    ) VALUES (
        COALESCE(_raw_number, _e164),
        _e164,
        _number_type,
        _country_code,
        _country_abbrev
    )
    ON CONFLICT (e164) DO UPDATE
    SET
        raw_number     = COALESCE(EXCLUDED.raw_number,     phone.raw_number),
        number_type    = COALESCE(EXCLUDED.number_type,    phone.number_type),
        country_code   = COALESCE(EXCLUDED.country_code,   phone.country_code),
        country_abbrev = COALESCE(EXCLUDED.country_abbrev, phone.country_abbrev),
        updated_at     = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Accepts keys:
--   e164, raw_number, number_type, country_code, country_abbrev
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_e164           text;
    v_raw_number     text;
    v_number_type    text;
    v_country_code   integer;
    v_country_abbrev text;
BEGIN
    v_e164           := _rec->>'e164';
    v_raw_number     := NULLIF(_rec->>'raw_number', '');
    v_number_type    := NULLIF(_rec->>'number_type', '');
    v_country_abbrev := NULLIF(_rec->>'country_abbrev', '');

    IF _rec ? 'country_code' THEN
        v_country_code := NULLIF(_rec->>'country_code', '')::integer;
    ELSE
        v_country_code := NULL;
    END IF;

    RETURN public.phone_upsert(
        v_e164,
        v_raw_number,
        v_number_type,
        v_country_code,
        v_country_abbrev
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by e164 (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_get_id_by_e164(
    _e164 text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.phone
    WHERE e164 = _e164
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by e164
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_get_by_e164(
    _e164 text
) RETURNS public.phone
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.phone
    WHERE e164 = _e164
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by raw_number (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_find_by_raw_number(
    _raw_number text
) RETURNS SETOF public.phone
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.phone
    WHERE (CASE
             WHEN strpos(_raw_number, '%') > 0 OR strpos(_raw_number, '_') > 0
               THEN raw_number ILIKE _raw_number
             ELSE raw_number = _raw_number
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.phone
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.phone
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Phone AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert_entity(
    _e164           text,
    _raw_number     text DEFAULT NULL,
    _number_type    text DEFAULT NULL,
    _country_code   integer DEFAULT NULL,
    _country_abbrev text DEFAULT NULL,
    _extra_attrs    jsonb  DEFAULT '{}'::jsonb,        -- caller-provided extra attrs
    _etype_name     citext DEFAULT 'phone'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.phone%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _e164 IS NULL THEN
        RAISE EXCEPTION 'phone_upsert_entity requires non-NULL e164';
    END IF;

    -- 1) Upsert into phone by e164.
    INSERT INTO public.phone (
        raw_number,
        e164,
        number_type,
        country_code,
        country_abbrev
    ) VALUES (
        COALESCE(_raw_number, _e164),
        _e164,
        _number_type,
        _country_code,
        _country_abbrev
    )
    ON CONFLICT (e164) DO UPDATE
    SET
        raw_number     = COALESCE(EXCLUDED.raw_number,     phone.raw_number),
        number_type    = COALESCE(EXCLUDED.number_type,    phone.number_type),
        country_code   = COALESCE(EXCLUDED.country_code,   phone.country_code),
        country_abbrev = COALESCE(EXCLUDED.country_abbrev, phone.country_abbrev),
        updated_at     = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the phone plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw_number',     v_row.raw_number,
            'e164',           v_row.e164,
            'number_type',    v_row.number_type,
            'country_code',   v_row.country_code,
            'country_abbrev', v_row.country_abbrev
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using e164 as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                -- e.g. 'phone'
        _natural_key := v_row.e164::citext,         -- canonical key
        _table_name  := 'phone'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map e164 -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_get_entity_id_by_e164(
    _e164 text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.phone p
    JOIN public.entity e
      ON e.table_name = 'phone'
     AND e.row_id     = p.id
    WHERE p.e164 = _e164
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Phone by e164
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_get_with_entity_by_e164(
    _e164 text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    phone_row    public.phone
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        p
    FROM public.phone p
    JOIN public.entity e
      ON e.table_name = 'phone'
     AND e.row_id     = p.id
    WHERE p.e164 = _e164
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.phone_upsert(text, text, text, integer, text);
DROP FUNCTION IF EXISTS public.phone_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.phone_get_id_by_e164(text);
DROP FUNCTION IF EXISTS public.phone_get_by_e164(text);
DROP FUNCTION IF EXISTS public.phone_find_by_raw_number(text);
DROP FUNCTION IF EXISTS public.phone_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.phone_upsert_entity(text, text, text, integer, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.phone_get_entity_id_by_e164(text);
DROP FUNCTION IF EXISTS public.phone_get_with_entity_by_e164(text);

DROP INDEX IF EXISTS idx_phone_country_abbrev;
DROP INDEX IF EXISTS idx_phone_country_code;
DROP INDEX IF EXISTS idx_phone_number_type;
DROP INDEX IF EXISTS idx_phone_raw;
DROP INDEX IF EXISTS idx_phone_updated_at;
DROP INDEX IF EXISTS idx_phone_created_at;
DROP TABLE IF EXISTS public.phone;