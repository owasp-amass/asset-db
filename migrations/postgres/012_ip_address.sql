-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPAddress Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipaddress (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  ip_version text NOT NULL,
  ip_address inet NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_ipaddress_created_at
  ON public.ipaddress(created_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_updated_at
  ON public.ipaddress(updated_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_ip_version
  ON public.ipaddress(ip_version);

-- Upsert by IP address (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert(
    _ip_address inet,
    _ip_version text
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _ip_address IS NULL OR _ip_version IS NULL THEN
        RAISE EXCEPTION 'ipaddress_upsert requires non-NULL ip_address and ip_version';
    END IF;

    INSERT INTO public.ipaddress (
        ip_version,
        ip_address
    ) VALUES (
        _ip_version,
        _ip_address
    )
    ON CONFLICT (ip_address) DO UPDATE
    SET
        ip_version = COALESCE(EXCLUDED.ip_version, ipaddress.ip_version),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: ip_address, ip_version.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_ip_address inet;
    v_ip_version text;
BEGIN
    v_ip_address := NULLIF(_rec->>'ip_address', '')::inet;
    v_ip_version := NULLIF(_rec->>'ip_version', '');

    RETURN public.ipaddress_upsert(
        v_ip_address,
        v_ip_version
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by IP address (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_get_id_by_ip(
    _ip_address inet
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.ipaddress
    WHERE ip_address = _ip_address
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by IP address
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_get_by_ip(
    _ip_address inet
) RETURNS public.ipaddress
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipaddress
    WHERE ip_address = _ip_address
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.ipaddress
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.ipaddress
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert an IPAddress AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert_entity(
    _ip_address  inet,
    _ip_version  text,
    _extra_attrs jsonb  DEFAULT '{}'::jsonb,        -- for caller-provided extra attributes
    _etype_name  citext DEFAULT 'ipaddress'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.ipaddress%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _ip_address IS NULL OR _ip_version IS NULL THEN
        RAISE EXCEPTION 'ipaddress_upsert_entity requires non-NULL ip_address and ip_version';
    END IF;

    -- 1) Upsert into ipaddress by ip_address.
    INSERT INTO public.ipaddress (
        ip_version,
        ip_address
    ) VALUES (
        _ip_version,
        _ip_address
    )
    ON CONFLICT (ip_address) DO UPDATE
    SET
        ip_version = COALESCE(EXCLUDED.ip_version, ipaddress.ip_version),
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the ipaddress plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'ip_address', v_row.ip_address::text,
            'ip_version', v_row.ip_version
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert).
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                      -- e.g. 'ipaddress'
        _natural_key := v_row.ip_address::text::citext,   -- canonical key: textual IP
        _table_name  := 'ipaddress'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map IP address -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_get_entity_id_by_ip(
    _ip_address inet
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.ipaddress a
    JOIN public.entity e
      ON e.table_name = 'ipaddress'
     AND e.row_id     = a.id
    WHERE a.ip_address = _ip_address
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+IPAddress by IP address
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_get_with_entity_by_ip(
    _ip_address inet
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    ip_row       public.ipaddress
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        a
    FROM public.ipaddress a
    JOIN public.entity e
      ON e.table_name = 'ipaddress'
     AND e.row_id     = a.id
    WHERE a.ip_address = _ip_address
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.ipaddress_upsert(inet, text);
DROP FUNCTION IF EXISTS public.ipaddress_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.ipaddress_get_id_by_ip(inet);
DROP FUNCTION IF EXISTS public.ipaddress_get_by_ip(inet);
DROP FUNCTION IF EXISTS public.ipaddress_updated_since(timestamp without time zone);

DROP FUNCTION IF EXISTS public.ipaddress_upsert_entity(inet, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.ipaddress_get_entity_id_by_ip(inet);
DROP FUNCTION IF EXISTS public.ipaddress_get_with_entity_by_ip(inet);

DROP INDEX IF EXISTS idx_ipaddress_ip_version;
DROP INDEX IF EXISTS idx_ipaddress_updated_at;
DROP INDEX IF EXISTS idx_ipaddress_created_at;
DROP TABLE IF EXISTS public.ipaddress;