-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- Netblock Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.netblock (
  id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone NOT NULL DEFAULT now(),
  netblock_cidr cidr NOT NULL UNIQUE,
  ip_version text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_netblock_created_at
  ON public.netblock(created_at);
CREATE INDEX IF NOT EXISTS idx_netblock_updated_at
  ON public.netblock(updated_at);
CREATE INDEX IF NOT EXISTS idx_netblock_ip_version
  ON public.netblock(ip_version);

-- Upsert by netblock_cidr (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert(
    _netblock_cidr cidr,
    _ip_version    text
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _netblock_cidr IS NULL OR _ip_version IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL netblock_cidr and ip_version';
    END IF;

    INSERT INTO public.netblock (
        netblock_cidr,
        ip_version
    ) VALUES (
        _netblock_cidr,
        _ip_version
    )
    ON CONFLICT (netblock_cidr) DO UPDATE
    SET
        ip_version = COALESCE(EXCLUDED.ip_version, netblock.ip_version),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: netblock_cidr, ip_version. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_netblock_cidr cidr;
    v_ip_version    text;
BEGIN
    v_netblock_cidr := NULLIF(_rec->>'netblock_cidr', '')::cidr;
    v_ip_version    := NULLIF(_rec->>'ip_version', '');

    RETURN public.netblock_upsert(
        v_netblock_cidr,
        v_ip_version
    );
END
$fn$;
-- +migrate StatementEnd

-- Get the id by netblock_cidr (NULL if not found)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_get_id_by_cidr(
    _netblock_cidr cidr
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT id
    FROM public.netblock
    WHERE netblock_cidr = _netblock_cidr
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Return the full row by netblock_cidr
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_get_by_cidr(
    _netblock_cidr cidr
) RETURNS public.netblock
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.netblock
    WHERE netblock_cidr = _netblock_cidr
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Search by ip_version (exact or ILIKE pattern if caller includes %/_)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_find_by_ip_version(
    _ip_version text
) RETURNS SETOF public.netblock
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.netblock
    WHERE (CASE
             WHEN strpos(_ip_version, '%') > 0 OR strpos(_ip_version, '_') > 0
               THEN ip_version ILIKE _ip_version
             ELSE ip_version = _ip_version
           END)
    ORDER BY updated_at DESC, id DESC;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.netblock
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.netblock
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

-- Upsert a Netblock AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert_entity(
    _netblock_cidr cidr,
    _ip_version    text,
    _extra_attrs   jsonb  DEFAULT '{}'::jsonb,        -- for caller-provided extra attributes
    _etype_name    citext DEFAULT 'netblock'::citext
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row       public.netblock%ROWTYPE;
    v_entity_id bigint;
    v_attrs     jsonb;
BEGIN
    IF _netblock_cidr IS NULL OR _ip_version IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert_entity requires non-NULL netblock_cidr and ip_version';
    END IF;

    -- 1) Upsert into netblock by netblock_cidr.
    INSERT INTO public.netblock (
        netblock_cidr,
        ip_version
    ) VALUES (
        _netblock_cidr,
        _ip_version
    )
    ON CONFLICT (netblock_cidr) DO UPDATE
    SET
        ip_version = COALESCE(EXCLUDED.ip_version, netblock.ip_version),
        updated_at = now()
    RETURNING * INTO v_row;

    -- 2) Build attrs from the netblock plus any caller-supplied extras.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'netblock_cidr', v_row.netblock_cidr::text,
            'ip_version',    v_row.ip_version
        )
    ) || COALESCE(_extra_attrs, '{}'::jsonb);

    -- 3) Upsert into entity via the generic helper (entity_upsert),
    -- using netblock_cidr as the natural key.
    v_entity_id := public.entity_upsert(
        _etype_name  := _etype_name,                         -- e.g. 'netblock'
        _natural_key := v_row.netblock_cidr::text::citext,   -- canonical key: CIDR string
        _table_name  := 'netblock'::citext,
        _row_id      := v_row.id,
        _attrs       := v_attrs
    );

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Map netblock_cidr -> entity_id (if present)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_get_entity_id_by_cidr(
    _netblock_cidr cidr
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.entity_id
    FROM public.netblock n
    JOIN public.entity e
      ON e.table_name = 'netblock'
     AND e.row_id     = n.id
    WHERE n.netblock_cidr = _netblock_cidr
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get Entity+Netblock by netblock_cidr
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_get_with_entity_by_cidr(
    _netblock_cidr cidr
) RETURNS TABLE (
    entity_id    bigint,
    etype_id     smallint,
    natural_key  citext,
    entity_attrs jsonb,
    netblock_row public.netblock
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        e.etype_id,
        e.natural_key,
        e.attrs,
        n
    FROM public.netblock n
    JOIN public.entity e
      ON e.table_name = 'netblock'
     AND e.row_id     = n.id
    WHERE n.netblock_cidr = _netblock_cidr
    ORDER BY e.entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.netblock_upsert(cidr, text);
DROP FUNCTION IF EXISTS public.netblock_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.netblock_get_id_by_cidr(cidr);
DROP FUNCTION IF EXISTS public.netblock_get_by_cidr(cidr);
DROP FUNCTION IF EXISTS public.netblock_find_by_ip_version(text);
DROP FUNCTION IF EXISTS public.netblock_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.netblock_upsert_entity(cidr, text, jsonb, citext);
DROP FUNCTION IF EXISTS public.netblock_get_entity_id_by_cidr(cidr);
DROP FUNCTION IF EXISTS public.netblock_get_with_entity_by_cidr(cidr);

DROP INDEX IF EXISTS idx_netblock_ip_version;
DROP INDEX IF EXISTS idx_netblock_updated_at;
DROP INDEX IF EXISTS idx_netblock_created_at;
DROP TABLE IF EXISTS public.netblock;