-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- FQDN Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.fqdn (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  fqdn citext NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_fqdn_created_at
  ON public.fqdn(created_at);
CREATE INDEX IF NOT EXISTS idx_fqdn_updated_at
  ON public.fqdn(updated_at);

-- Upsert by FQDN (scalar param). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert(
    _fqdn text
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _fqdn IS NULL THEN
        RAISE EXCEPTION 'fqdn_upsert requires non-NULL fqdn';
    END IF;

    INSERT INTO public.fqdn (
        fqdn
    ) VALUES (
        lower(_fqdn)
    )
    ON CONFLICT (fqdn) DO UPDATE
    SET
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts key: fqdn. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_fqdn text;
BEGIN
    v_fqdn := _rec->>'fqdn';

    RETURN public.fqdn_upsert(v_fqdn);
END
$fn$;
-- +migrate StatementEnd

-- Get the id by fqdn (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_get_id_by_fqdn(
    _fqdn text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.fqdn
    WHERE fqdn = lower(_fqdn)::citext
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by fqdn
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_get_by_fqdn(
    _fqdn text
) RETURNS public.fqdn
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fqdn
    WHERE fqdn = lower(_fqdn)::citext
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.fqdn
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.fqdn
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an FQDN AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert_entity(
    _fqdn        text,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,       -- for caller-provided extra attributes
    _etype_name  citext DEFAULT 'fqdn'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.fqdn%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _fqdn IS NULL THEN
        RAISE EXCEPTION 'fqdn_upsert_entity requires non-NULL fqdn';
    END IF;

    -- 1) Upsert into fqdn by fqdn.
    INSERT INTO public.fqdn (
        fqdn
    ) VALUES (
        lower(_fqdn)
    )
    ON CONFLICT (fqdn) DO UPDATE
    SET
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the fqdn plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'fqdn', v_row.fqdn
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                 -- e.g. 'fqdn'
        _natural_key := v_row.fqdn::citext,          -- canonical key
        _table_name  := 'fqdn'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map fqdn -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_get_entity_id_by_fqdn(
    _fqdn text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.fqdn f
    JOIN public.entity e
      ON e.table_name = 'fqdn'
     AND e.row_id     = f.id
    WHERE f.fqdn = lower(_fqdn)::citext
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+FQDN by fqdn
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_get_with_entity_by_fqdn(
    _fqdn text
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    fqdn_row     public.fqdn
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        f
    FROM public.fqdn f
    JOIN public.entity e
      ON e.table_name = 'fqdn'
     AND e.row_id     = f.id
    WHERE f.fqdn = lower(_fqdn)::citext
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.fqdn_upsert(text);
DROP FUNCTION IF EXISTS public.fqdn_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.fqdn_get_id_by_fqdn(text);
DROP FUNCTION IF EXISTS public.fqdn_get_by_fqdn(text);
DROP FUNCTION IF EXISTS public.fqdn_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.fqdn_upsert_entity(text, jsonb, citext);
DROP FUNCTION IF EXISTS public.fqdn_get_entity_id_by_fqdn(text);
DROP FUNCTION IF EXISTS public.fqdn_get_with_entity_by_fqdn(text);

DROP INDEX IF EXISTS idx_fqdn_updated_at;
DROP INDEX IF EXISTS idx_fqdn_created_at;
DROP TABLE IF EXISTS public.fqdn;