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
    SELECT *
    FROM public.ipnetrecord
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_find_by_content(
    _filters jsonb, 
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT 0
) RETURNS SETOF TABLE (
    entity_id     bigint,
    id            bigint,
    created_at    timestamp without time zone,
    updated_at    timestamp without time zone,
    record_cidr   cidr,
    record_name   text,
    handle        text,
    whois_server  citext,
    parent_handle text,
    start_address inet,
    end_address   inet,
    attrs         jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_record_cidr   cidr;
    v_record_name   text;
    v_handle        text;
    v_whois_server  citext;
    v_parent_handle text;
    v_start_address inet;
    v_end_address   inet;
    v_count         integer := 0;
    v_params        text[]  := array[]::text[];
    v_sql           text;
BEGIN
    v_sql := $Q$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.record_cidr,
        a.record_name,
        a.handle,
        a.whois_server,
        a.parent_handle,
        a.start_address,
        a.end_address,
        a.attrs
    FROM public.ipnetrecord a
    JOIN public.entity e ON e.table_name = 'public.ipnetrecord'::citext AND e.row_id = a.id WHERE TRUE$Q$;

    -- 1) Extract filters from JSONB
    v_record_cidr   := NULLIF(_filters->>'cidr', '')::cidr;
    v_record_name   := NULLIF(_filters->>'name', '');
    v_handle        := NULLIF(_filters->>'handle', '');
    v_whois_server  := NULLIF(_filters->>'whois_server', '')::citext;
    v_parent_handle := NULLIF(_filters->>'parent_handle', '');
    v_start_address := NULLIF(_filters->>'start_address', '')::inet;
    v_end_address   := NULLIF(_filters->>'end_address', '')::inet;

    -- 2) Build the params array from the filters
    IF v_record_cidr IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_record_cidr::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.record_cidr', v_count);
    END IF;

    IF v_record_name IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_record_name);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.record_name', v_count);
    END IF;

    IF v_handle IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_handle);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.handle', v_count);
    END IF;

    IF v_whois_server IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_whois_server::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.whois_server', v_count);
    END IF;

    IF v_parent_handle IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_parent_handle);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.parent_handle', v_count);
    END IF;

    IF v_start_address IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_start_address::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.start_address', v_count);
    END IF;

    IF v_end_address IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, v_end_address::text);
        v_sql    := v_sql || format(' AND %I = $%s', 'a.end_address', v_count);
    END IF;

    IF v_count = 0 THEN
        RAISE EXCEPTION 'ipnetrecord_find_by_content requires at least one filter';
    END IF;

    IF _since IS NOT NULL THEN
        v_count  := v_count + 1;
        v_params := array_append(v_params, _since::text);
        v_sql    := v_sql || format(' AND %I >= $%s', 'a.updated_at', v_count);
    END IF;

    -- 3) Add the ORDER BY clause
    v_sql := v_sql || ' ORDER BY a.updated_at DESC, a.id DESC';

    IF _limit > 0 THEN
        v_sql := v_sql || format(' LIMIT %s', _limit);
    END IF;

    -- 4) Execute dynamic SQL and return results
    CASE v_count
        WHEN 1 THEN RETURN QUERY EXECUTE v_sql USING v_params[1];
        WHEN 2 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2];
        WHEN 3 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3];
        WHEN 4 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4];
        WHEN 5 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5];
        WHEN 6 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5], v_params[6];
        WHEN 7 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5], v_params[6], v_params[7];
        WHEN 8 THEN RETURN QUERY EXECUTE v_sql USING v_params[1], v_params[2], v_params[3], v_params[4], v_params[5], v_params[6], v_params[7], v_params[8];
    END CASE;

    RETURN;
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipnetrecord_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id     bigint,
    id            bigint,
    created_at    timestamp without time zone,
    updated_at    timestamp without time zone,
    record_cidr   cidr,
    record_name   text,
    handle        text,
    whois_server  citext,
    parent_handle text,
    start_address inet,
    end_address   inet,
    attrs         jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.record_cidr,
        a.record_name,
        a.handle,
        a.whois_server,
        a.parent_handle,
        a.start_address,
        a.end_address,
        a.attrs
    FROM public.ipnetrecord a
    JOIN public.entity e ON e.table_name = 'public.ipnetrecord'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT _limit;
$fn$;
-- +migrate StatementEnd

COMMIT;

-- +migrate Down

DROP FUNCTION IF EXISTS public.ipnetrecord_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.ipnetrecord_find_by_content(jsonb, timestamp without time zone);
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