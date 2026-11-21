-- +migrate Up

-- ============================================================================
-- OWASP Amass: StorageBucket table native for asset type (PostgreSQL 13+)
--
-- An object-storage bucket (Amazon S3, Google Cloud Storage, Azure Blob),
-- identified by "<service>:<bucket>" within its provider's global namespace.
-- bucket_exists and is_public hold the latest observation: a bucket can be
-- deleted (becoming claimable) or made private, so a later sighting replaces
-- them rather than merging.
-- ============================================================================

INSERT INTO public.entity_type_lu(name) VALUES ('storagebucket') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS public.storagebucket (
    id            bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    created_at    timestamp without time zone NOT NULL DEFAULT now(),
    updated_at    timestamp without time zone NOT NULL DEFAULT now(),
    unique_id     text NOT NULL UNIQUE,
    bucket_name   text NOT NULL,
    provider      text,
    service       text,
    bucket_exists boolean NOT NULL DEFAULT false,
    is_public     boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_storagebucket_updated_at_id_desc ON public.storagebucket (updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_storagebucket_bucket_name ON public.storagebucket (bucket_name);
CREATE INDEX IF NOT EXISTS idx_storagebucket_provider ON public.storagebucket (provider);

-- A revisit within one enumeration that changes nothing writes nothing.
CREATE TRIGGER touch_guard BEFORE UPDATE ON public.storagebucket
FOR EACH ROW EXECUTE FUNCTION public.touch_guard();

-- Upsert a StorageBucket AND its corresponding Entity.
-- Returns the entity_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_upsert_entity_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_unique_id text;
    v_row       bigint;
BEGIN
    v_unique_id := NULLIF(_rec->>'unique_id', '');

    -- 1) Upsert into storagebucket.
    v_row := public.storagebucket_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'storagebucket'::citext,
        _natural_key := v_unique_id::citext,
        _table_name  := 'public.storagebucket'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- Upsert by unique_id (scalar params). Returns the row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_upsert(
    _unique_id   text,
    _bucket_name text,
    _provider    text DEFAULT NULL,
    _service     text DEFAULT NULL,
    _exists      boolean DEFAULT false,
    _public      boolean DEFAULT false
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _bucket_name IS NULL THEN
        RAISE EXCEPTION 'storagebucket_upsert requires non-NULL unique_id and bucket_name';
    END IF;

    INSERT INTO public.storagebucket (
        unique_id, bucket_name, provider, service, bucket_exists, is_public
    ) VALUES (
        _unique_id, _bucket_name, _provider, _service,
        COALESCE(_exists, false), COALESCE(_public, false)
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        bucket_name   = EXCLUDED.bucket_name,
        provider      = COALESCE(EXCLUDED.provider, storagebucket.provider),
        service       = COALESCE(EXCLUDED.service,  storagebucket.service),
        bucket_exists = EXCLUDED.bucket_exists,
        is_public     = EXCLUDED.is_public,
        updated_at    = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.storagebucket WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- JSONB upsert variant. Returns row id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
BEGIN
    RETURN public.storagebucket_upsert(
        NULLIF(_rec->>'unique_id', ''),
        NULLIF(_rec->>'bucket_name', ''),
        NULLIF(_rec->>'provider', ''),
        NULLIF(_rec->>'service', ''),
        COALESCE((_rec->>'exists')::boolean, false),
        COALESCE((_rec->>'public')::boolean, false)
    );
END
$fn$;
-- +migrate StatementEnd

-- Return the full row by id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_get_by_id(_row_id bigint)
RETURNS public.storagebucket
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.storagebucket
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Rows matching the provided filters and since timestamp
-- Supported keys in _filters: unique_id, bucket_name, provider, service, exists, public
-- Requires at least one supported filter to be present.
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id     bigint,
    id            bigint,
    created_at    timestamp without time zone,
    updated_at    timestamp without time zone,
    unique_id     text,
    bucket_name   text,
    provider      text,
    service       text,
    bucket_exists boolean,
    is_public     boolean
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_unique_id   text    := NULLIF(_filters->>'unique_id', '');
    v_bucket_name text    := NULLIF(_filters->>'bucket_name', '');
    v_provider    text    := NULLIF(_filters->>'provider', '');
    v_service     text    := NULLIF(_filters->>'service', '');
    v_exists      boolean := CASE WHEN _filters ? 'exists'
                                  THEN NULLIF(_filters->>'exists', '')::boolean END;
    v_public      boolean := CASE WHEN _filters ? 'public'
                                  THEN NULLIF(_filters->>'public', '')::boolean END;
    v_limit       integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_unique_id IS NULL AND v_bucket_name IS NULL AND v_provider IS NULL
       AND v_service IS NULL AND v_exists IS NULL AND v_public IS NULL THEN
        RAISE EXCEPTION 'storagebucket_find_by_content requires at least one filter';
    END IF;

    RETURN QUERY
    SELECT
        e.entity_id,
        a.id,
        a.created_at,
        a.updated_at,
        a.unique_id,
        a.bucket_name,
        a.provider,
        a.service,
        a.bucket_exists,
        a.is_public
    FROM public.storagebucket a
    JOIN public.entity e ON e.table_name = 'public.storagebucket'::citext AND e.row_id = a.id
    WHERE
        (v_unique_id   IS NULL OR a.unique_id     = v_unique_id)
    AND (v_bucket_name IS NULL OR a.bucket_name   = v_bucket_name)
    AND (v_provider    IS NULL OR a.provider      = v_provider)
    AND (v_service     IS NULL OR a.service       = v_service)
    AND (v_exists      IS NULL OR a.bucket_exists = v_exists)
    AND (v_public      IS NULL OR a.is_public     = v_public)
    AND (_since        IS NULL OR a.updated_at   >= _since)
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT v_limit; -- LIMIT NULL is unlimited
END
$fn$;
-- +migrate StatementEnd

-- Rows updated since a given timestamp
-- _limit = NULL means unlimited (0 is treated as unlimited as well)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.storagebucket_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id     bigint,
    id            bigint,
    created_at    timestamp without time zone,
    updated_at    timestamp without time zone,
    unique_id     text,
    bucket_name   text,
    provider      text,
    service       text,
    bucket_exists boolean,
    is_public     boolean
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
        a.bucket_name,
        a.provider,
        a.service,
        a.bucket_exists,
        a.is_public
    FROM public.storagebucket a
    JOIN public.entity e ON e.table_name = 'public.storagebucket'::citext AND e.row_id = a.id
    WHERE a.updated_at >= _since
    ORDER BY a.updated_at DESC, a.id DESC
    LIMIT NULLIF(_limit, 0); -- LIMIT NULL is unlimited
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.storagebucket_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.storagebucket_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.storagebucket_get_by_id(bigint);

DROP FUNCTION IF EXISTS public.storagebucket_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.storagebucket_upsert(text, text, text, text, boolean, boolean);
DROP FUNCTION IF EXISTS public.storagebucket_upsert_entity_json(jsonb);

DROP TRIGGER IF EXISTS touch_guard ON public.storagebucket;
DROP INDEX IF EXISTS idx_storagebucket_provider;
DROP INDEX IF EXISTS idx_storagebucket_bucket_name;
DROP INDEX IF EXISTS idx_storagebucket_updated_at_id_desc;
DROP TABLE IF EXISTS public.storagebucket;

DELETE FROM public.entity_type_lu WHERE name = 'storagebucket';
