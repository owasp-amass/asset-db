-- +migrate Up

-- ============================================================================
-- OWASP Amass: High-performance SCHEMA (PostgreSQL 13+)
-- IPNetRecord Table native for asset type
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.ipnetrecord (
  id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at    timestamp without time zone NOT NULL DEFAULT now(),
  updated_at    timestamp without time zone NOT NULL DEFAULT now(),
  record_cidr   cidr NOT NULL UNIQUE,
  record_name   text NOT NULL,
  handle        text NOT NULL UNIQUE,
  whois_server  citext,
  parent_handle text,
  start_address inet,
  end_address   inet,
  attrs         jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_created_at ON public.ipnetrecord (created_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_updated_at ON public.ipnetrecord (updated_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_name ON public.ipnetrecord (record_name);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_start_address ON public.ipnetrecord (start_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_end_address ON public.ipnetrecord (end_address);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_whois_server ON public.ipnetrecord (whois_server);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_parent_handle ON public.ipnetrecord (parent_handle);

-- Upsert an IPNetRecord AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row    bigint;
    v_handle text;
BEGIN
    v_handle := (_rec->>'handle');

    -- 1) Upsert into ipnetrecord by handle.
    v_row := public.ipnetrecord_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'ipnetrecord'::citext,
        _natural_key := v_handle::citext,
        _table_name  := 'public.ipnetrecord'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by record_cidr / handle, with merge semantics similar to autnumrecord_upsert.
-- Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert(
    _record_cidr   cidr,
    _record_name   text,
    _handle        text,
    _whois_server  citext DEFAULT NULL,
    _parent_handle text DEFAULT NULL,
    _start_address inet DEFAULT NULL,
    _end_address   inet DEFAULT NULL,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id_cidr   bigint;
    v_id_handle bigint;
    v_id        bigint;
BEGIN
    IF _record_cidr IS NULL OR _record_name IS NULL OR _handle IS NULL THEN
        RAISE EXCEPTION 'ipnetrecord_upsert requires non-NULL record_cidr, record_name, handle';
    END IF;

    -- Lock rows if present to avoid races while merging.
    SELECT id INTO v_id_cidr
    FROM public.ipnetrecord
    WHERE record_cidr = _record_cidr
    FOR UPDATE SKIP LOCKED;

    SELECT id INTO v_id_handle
    FROM public.ipnetrecord
    WHERE handle = _handle
    FOR UPDATE SKIP LOCKED;

    IF v_id_cidr IS NOT NULL AND v_id_handle IS NOT NULL AND v_id_cidr <> v_id_handle THEN
        -- Merge: keep the handle-owned row; drop the other after updating it with incoming fields.
        UPDATE public.ipnetrecord
        SET
            record_cidr   = _record_cidr,
            record_name   = COALESCE(_record_name,   record_name),
            whois_server  = COALESCE(_whois_server,  whois_server),
            parent_handle = COALESCE(_parent_handle, parent_handle),
            start_address = COALESCE(_start_address, start_address),
            end_address   = COALESCE(_end_address,   end_address),
            attrs         = ipnetrecord.attrs || COALESCE(_attrs, '{}'::jsonb),
            updated_at    = now()
        WHERE id = v_id_handle;

        DELETE FROM public.ipnetrecord WHERE id = v_id_cidr;

        v_id := v_id_handle;

    ELSIF v_id_cidr IS NOT NULL OR v_id_handle IS NOT NULL THEN
        -- Update whichever existing row we found.
        v_id := COALESCE(v_id_cidr, v_id_handle);

        UPDATE public.ipnetrecord
        SET
            record_cidr   = _record_cidr,
            record_name   = COALESCE(_record_name,   record_name),
            handle        = _handle,
            whois_server  = COALESCE(_whois_server,  whois_server),
            parent_handle = COALESCE(_parent_handle, parent_handle),
            start_address = COALESCE(_start_address, start_address),
            end_address   = COALESCE(_end_address,   end_address),
            attrs         = ipnetrecord.attrs || COALESCE(_attrs, '{}'::jsonb),
            updated_at    = now()
        WHERE id = v_id;

    ELSE
        -- Insert new row.
        INSERT INTO public.ipnetrecord (
            record_cidr, record_name, handle, whois_server, parent_handle, start_address, end_address, attrs
        ) VALUES (
            _record_cidr, _record_name, _handle, _whois_server, _parent_handle, _start_address, _end_address, _attrs
        )
        RETURNING id INTO v_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant.
-- Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_record_cidr   cidr;
    v_record_name   text;
    v_ip_version    text;
    v_handle        text;
    v_method        text;
    v_record_status text[];
    v_created_date  timestamp without time zone;
    v_updated_date  timestamp without time zone;
    v_whois_server  citext;
    v_parent_handle text;
    v_start_address inet;
    v_end_address   inet;
    v_country       text;
    v_raw           text;
    v_attrs         jsonb;
BEGIN
    v_record_cidr   := NULLIF(_rec->>'cidr', '')::cidr;
    v_record_name   := NULLIF(_rec->>'name', '');
    v_ip_version    := NULLIF(_rec->>'type', '');
    v_handle        := NULLIF(_rec->>'handle', '');
    v_method        := NULLIF(_rec->>'method', '');
    v_created_date  := NULLIF(_rec->>'created_date', '')::timestamp;
    v_updated_date  := NULLIF(_rec->>'updated_date', '')::timestamp;
    v_whois_server  := NULLIF(_rec->>'whois_server', '');
    v_parent_handle := NULLIF(_rec->>'parent_handle', '');
    v_start_address := NULLIF(_rec->>'start_address', '')::inet;
    v_end_address   := NULLIF(_rec->>'end_address', '')::inet;
    v_country       := NULLIF(_rec->>'country', '');
    v_raw           := NULLIF(_rec->>'raw', '');

    IF _rec ? 'status' THEN
        SELECT array_agg(elem::text)
        INTO v_record_status
        FROM jsonb_array_elements_text(_rec->'status') AS elem;
    ELSE
        v_record_status := NULL;
    END IF;

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'raw',          v_raw,
            'type',         v_ip_version,
            'method',       v_method,
            'status',       v_record_status,
            'created_date', v_created_date,
            'updated_date', v_updated_date,
            'country',      v_country
        )
    ) || '{}'::jsonb;

    RETURN public.ipnetrecord_upsert(
        v_record_cidr,
        v_record_name,
        v_handle,
        v_whois_server,
        v_parent_handle,
        v_start_address,
        v_end_address,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_get_by_id(_row_id bigint)
RETURNS public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, record_cidr, record_name, handle, whois_server, parent_handle, start_address, end_address, attrs
    FROM public.ipnetrecord
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_updated_since(
    _ts timestamp without time zone
) RETURNS SETOF public.ipnetrecord
LANGUAGE sql
STABLE
AS $fn$
    SELECT id, created_at, updated_at, record_cidr, record_name, handle, whois_server, parent_handle, start_address, end_address, attrs
    FROM public.ipnetrecord
    WHERE updated_at >= _ts
    ORDER BY updated_at ASC, id ASC;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.ipnetrecord_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.ipnetrecord_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.ipnetrecord_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.ipnetrecord_upsert(
    cidr, text, text, citext, text, inet, inet, jsonb
);
DROP FUNCTION IF EXISTS public.ipnetrecord_upsert_entity_json(jsonb);

DROP INDEX IF EXISTS idx_ipnetrecord_parent_handle;
DROP INDEX IF EXISTS idx_ipnetrecord_whois_server;
DROP INDEX IF EXISTS idx_ipnetrecord_end_address;
DROP INDEX IF EXISTS idx_ipnetrecord_start_address;
DROP INDEX IF EXISTS idx_ipnetrecord_name;
DROP INDEX IF EXISTS idx_ipnetrecord_updated_at;
DROP INDEX IF EXISTS idx_ipnetrecord_created_at;
DROP TABLE IF EXISTS public.ipnetrecord;