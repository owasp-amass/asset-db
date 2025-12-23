-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- AutnumRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.autnumrecord (
  id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at   timestamp without time zone NOT NULL DEFAULT now(),
  updated_at   timestamp without time zone NOT NULL DEFAULT now(),
  handle       text NOT NULL UNIQUE,
  asn          integer NOT NULL UNIQUE,
  record_name  text,
  whois_server citext,
  attrs        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_created_at ON public.autnumrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_updated_at ON public.autnumrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_name ON public.autnumrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_whois_server ON public.autnumrecord (whois_server);

-- Upsert an AutnumRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row    bigint;
    v_handle text;
BEGIN
    v_handle := NULLIF(_rec->>'handle', '');

    -- 1) Upsert into autnumrecord.
    v_row := public.autnumrecord_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'autnumrecord'::citext,
        _natural_key := v_handle::citext,
        _table_name  := 'public.autnumrecord'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by handle/asn (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert(
    _handle       text,
    _asn          integer,
    _record_name  text DEFAULT NULL,
    _whois_server citext DEFAULT NULL,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id_handle bigint;
    v_id_asn    bigint;
    v_id        bigint;
BEGIN
    IF _handle IS NULL OR _asn IS NULL THEN
        RAISE EXCEPTION 'autnumrecord_upsert requires non-NULL handle and asn';
    END IF;

    -- Try to find existing rows (lock if present to avoid races during merge)
    SELECT id INTO v_id_handle
    FROM public.autnumrecord
    WHERE handle = _handle
    FOR UPDATE SKIP LOCKED;

    SELECT id INTO v_id_asn
    FROM public.autnumrecord
    WHERE asn = _asn
    FOR UPDATE SKIP LOCKED;

    IF v_id_handle IS NOT NULL AND v_id_asn IS NOT NULL AND v_id_handle <> v_id_asn THEN
        -- Merge: keep the handle-owned row; drop the other after ensuring values land on keeper.
        -- Update the handle row first with all incoming fields (including the ASN).
        UPDATE public.autnumrecord
        SET
            asn           = _asn,
            record_name   = COALESCE(_record_name,  record_name),
            whois_server  = COALESCE(_whois_server, whois_server),
            attrs         = attrs || COALESCE(_attrs, '{}'::jsonb),
            updated_at    = now()
        WHERE id = v_id_handle;

        -- Safe to delete the asn-only row (no declared FK references in the schema).
        DELETE FROM public.autnumrecord WHERE id = v_id_asn;

        v_id := v_id_handle;

    ELSIF v_id_handle IS NOT NULL OR v_id_asn IS NOT NULL THEN
        -- Update the existing row (by whichever matched)
        v_id := COALESCE(v_id_handle, v_id_asn);

        UPDATE public.autnumrecord
        SET
            handle        = _handle, -- keep the canonical handle in sync too
            asn           = _asn,
            record_name   = COALESCE(_record_name,  record_name),
            whois_server  = COALESCE(_whois_server, whois_server),
            attrs         = attrs || COALESCE(_attrs, '{}'::jsonb),
            updated_at    = now()
        WHERE id = v_id;

    ELSE
        -- Insert fresh row
        INSERT INTO public.autnumrecord(
            handle, asn, record_name, whois_server, attrs
        ) VALUES (
            _handle, _asn, _record_name, _whois_server, _attrs
        )
        RETURNING id INTO v_id;

    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Accepts keys: handle, asn, record_name, record_status,
-- created_date, updated_date, whois_server. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_raw           text;
    v_handle        text;
    v_asn           integer;
    v_record_name   text;
    v_record_status text;
    v_created_date  timestamp without time zone;
    v_updated_date  timestamp without time zone;
    v_whois_server  citext;
    v_attrs         jsonb;
BEGIN
    v_raw           := NULLIF(_rec->>'raw', '');
    v_handle        := NULLIF(_rec->>'handle', '');
    v_asn           := NULLIF(_rec->>'asn', '')::integer;
    v_record_name   := (_rec->>'name');
    v_record_status := NULLIF(_rec->>'status', '');
    v_created_date  := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date  := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_whois_server  := (_rec->>'whois_server')::citext;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw',          v_raw,
            'status',       v_record_status,
            'created_date', v_created_date,
            'updated_date', v_updated_date
        )
    ) || '{}'::jsonb;

    RETURN public.autnumrecord_upsert(
        v_handle,
        v_asn,
        v_record_name,
        v_whois_server,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_get_by_id(_row_id bigint)
RETURNS public.autnumrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.autnumrecord
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: handle, number (asn), name (record_name), whois_server
-- Requires at least one supported filter to be present.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    handle       text,
    asn          integer,
    record_name  text,
    whois_server citext,
    attrs        jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_handle       text    := NULLIF(_filters->>'handle', '');
    v_asn          integer := NULLIF(_filters->>'number', '')::integer;
    v_record_name  text    := NULLIF(_filters->>'name', '');
    v_whois_server citext  := NULLIF(_filters->>'whois_server', '')::citext;
    v_limit        integer := NULLIF(_limit, 0);
BEGIN
    IF v_handle IS NULL AND v_asn IS NULL AND v_record_name IS NULL AND v_whois_server IS NULL THEN
        RAISE EXCEPTION 'autnumrecord_find_by_content requires at least one supported filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.handle,
            a.asn,
            a.record_name,
            a.whois_server,
            a.attrs
        FROM public.autnumrecord a
        JOIN public.entity e ON e.table_name = 'public.autnumrecord'::citext AND e.row_id = a.id
        WHERE
            -- require at least one supported filter
            (v_handle IS NOT NULL OR v_asn IS NOT NULL OR v_record_name IS NOT NULL OR v_whois_server IS NOT NULL)
          AND (v_handle       IS NULL OR a.handle       = v_handle)
          AND (v_asn          IS NULL OR a.asn          = v_asn)
          AND (v_record_name  IS NULL OR a.record_name  = v_record_name)
          AND (v_whois_server IS NULL OR a.whois_server = v_whois_server)
          AND ( _since        IS NULL OR a.updated_at   >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.handle,
            a.asn,
            a.record_name,
            a.whois_server,
            a.attrs
        FROM public.autnumrecord a
        JOIN public.entity e ON e.table_name = 'public.autnumrecord'::citext AND e.row_id = a.id
        WHERE
            -- require at least one supported filter
            (v_handle IS NOT NULL OR v_asn IS NOT NULL OR v_record_name IS NOT NULL OR v_whois_server IS NOT NULL)
          AND (v_handle       IS NULL OR a.handle       = v_handle)
          AND (v_asn          IS NULL OR a.asn          = v_asn)
          AND (v_record_name  IS NULL OR a.record_name  = v_record_name)
          AND (v_whois_server IS NULL OR a.whois_server = v_whois_server)
          AND ( _since        IS NULL OR a.updated_at   >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autnumrecord_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id    bigint,
    id           bigint,
    created_at   timestamp without time zone,
    updated_at   timestamp without time zone,
    handle       text,
    asn          integer,
    record_name  text,
    whois_server citext,
    attrs        jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0);
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.handle,
            a.asn,
            a.record_name,
            a.whois_server,
            a.attrs
        FROM public.autnumrecord a
        JOIN public.entity e ON e.table_name = 'public.autnumrecord'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.handle,
            a.asn,
            a.record_name,
            a.whois_server,
            a.attrs
        FROM public.autnumrecord a
        JOIN public.entity e ON e.table_name = 'public.autnumrecord'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.autnumrecord_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.autnumrecord_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.autnumrecord_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.autnumrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.autnumrecord_upsert(text, text, integer, citext, jsonb);
DROP FUNCTION IF EXISTS public.autnumrecord_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_autnumrecord_whois_server;
DROP INDEX IF EXISTS idx_autnumrecord_name;
DROP INDEX IF EXISTS idx_autnumrecord_updated_at;
DROP INDEX IF EXISTS idx_autnumrecord_created_at;
DROP TABLE IF EXISTS public.autnumrecord;