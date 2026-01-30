-- +migrate Up

-- ============================================================================
-- OWASP Amass: Graph helper functions for edges and tags (PostgreSQL 13+)
-- ============================================================================


-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.null_safe_attrs(p jsonb)
RETURNS jsonb 
LANGUAGE sql 
IMMUTABLE 
AS $fn$
  SELECT COALESCE(p, '{}'::jsonb);
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_entity_type_id(p_name text)
RETURNS smallint 
LANGUAGE sql 
IMMUTABLE 
AS $fn$
  SELECT id FROM public.entity_type_lu WHERE name = p_name;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_edge_type_id(p_name text)
RETURNS smallint 
LANGUAGE sql 
IMMUTABLE 
AS $fn$
  SELECT id FROM public.edge_type_lu WHERE name = p_name;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- ENTITY UPSERT + HELPERS
-- ---------------------------------------------------------------------------

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_upsert(
    _etype_name  citext,
    _natural_key citext,
    _table_name  citext,
    _row_id      bigint
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_etype_id  smallint;
    v_entity_id bigint;
BEGIN
    IF _etype_name IS NULL OR _natural_key IS NULL OR _table_name IS NULL OR _row_id IS NULL THEN
        RAISE EXCEPTION 'entity_upsert requires non-NULL etype_name, natural_key, table_name, row_id';
    END IF;

    SELECT id INTO v_etype_id
    FROM public.entity_type_lu
    WHERE name = _etype_name::text;

    IF v_etype_id IS NULL THEN
        RAISE EXCEPTION 'entity_type_lu has no entry for name=%', _etype_name;
    END IF;

    INSERT INTO public.entity (
        etype_id, natural_key, table_name, row_id
    )
    VALUES (
        v_etype_id, lower(_natural_key)::citext, lower(_table_name)::citext, _row_id
    )
    ON CONFLICT (etype_id, row_id) DO UPDATE
    SET
        natural_key = EXCLUDED.natural_key,
        updated_at  = now()
    RETURNING entity_id INTO v_entity_id;

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- Simple helper: get an entity table row by entity_id
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_get_by_id(_entity_id bigint)
RETURNS TABLE (
    etype_name  citext,
    etype_id    smallint,
    natural_key citext,
    table_name  citext,
    row_id      bigint
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT et.name       AS etype_name,
           e.etype_id,
           e.natural_key,
           e.table_name,
           e.row_id
    FROM public.entity e
    JOIN public.entity_type_lu et
        ON e.etype_id = et.id
    WHERE entity_id = _entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- EDGE UPSERT + HELPERS
-- ---------------------------------------------------------------------------

-- Upsert an edge by edge-type-name, from/to entity IDs, and label.
-- Returns edge_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_upsert(
    _etype_name     text,
    _label          text,
    _from_entity_id bigint,
    _to_entity_id   bigint,
    _content        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_etype_id smallint;
    v_edge_id  bigint;
    v_content  jsonb;
BEGIN
    IF _from_entity_id IS NULL OR _to_entity_id IS NULL THEN
        RAISE EXCEPTION 'edge_upsert requires non-NULL from_entity_id and to_entity_id';
    END IF;

    IF _from_entity_id = _to_entity_id THEN
        RAISE EXCEPTION 'edge_upsert requires from_entity_id <> to_entity_id';
    END IF;

    IF _etype_name IS NULL OR btrim(_etype_name) = '' THEN
        RAISE EXCEPTION 'edge_upsert requires non-NULL etype_name';
    END IF;

    SELECT id INTO v_etype_id
    FROM public.edge_type_lu
    WHERE name = lower(_etype_name);

    IF v_etype_id IS NULL THEN
        RAISE EXCEPTION 'edge_type_lu has no entry for name=%', _etype_name;
    END IF;

    v_content := jsonb_strip_nulls(COALESCE(_content, '{}'::jsonb));

    INSERT INTO public.edge (
        etype_id, label, from_entity_id, to_entity_id, content
    )
    VALUES (
        v_etype_id, lower(_label)::citext, _from_entity_id, _to_entity_id, v_content
    )
    ON CONFLICT (etype_id, from_entity_id, to_entity_id, label) DO UPDATE
    SET
        content    = public.edge.content || v_content,
        updated_at = now()
    RETURNING edge_id INTO v_edge_id;

    RETURN v_edge_id;
END
$fn$;
-- +migrate StatementEnd

-- Get edge_id for a given edge-type-name, label and endpoints (if exists)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_get_id(
    _etype_name     text,
    _label          text,
    _from_entity_id bigint,
    _to_entity_id   bigint
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT e.edge_id
    FROM public.edge e
    JOIN public.edge_type_lu et 
        ON e.etype_id = et.id
    WHERE et.name          = _etype_name
      AND e.label          = lower(_label)::citext
      AND e.from_entity_id = _from_entity_id
      AND e.to_entity_id   = _to_entity_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Edges updated since a given timestamp (simple utility)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edges_updated_since(
    _since timestamp without time zone
) RETURNS SETOF public.edge
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.edge
    WHERE updated_at >= _since
    ORDER BY updated_at DESC, edge_id ASC;
$fn$;
-- +migrate StatementEnd

-- Edges matching the provided direction/labels and optional since timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edges_for_entity(
    _entity_id bigint,
    _direction text DEFAULT 'both',
    _since     timestamp without time zone DEFAULT NULL,
    _labels    text[] DEFAULT NULL
) RETURNS TABLE (
    edge_id        bigint,
    created_at     timestamp without time zone,
    updated_at     timestamp without time zone,
    etype_name     text,
    from_entity_id bigint,
    to_entity_id   bigint,
    label          citext,
    content        jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        e.edge_id,
        e.created_at,
        e.updated_at,
        te.name AS etype_name,
        e.from_entity_id,
        e.to_entity_id,
        e.label,
        e.content
    FROM public.edge e
    JOIN public.edge_type_lu te
      ON te.id = e.etype_id
    WHERE
        (
            (lower(_direction) = 'out'  AND e.from_entity_id = _entity_id)
         OR (lower(_direction) = 'in'   AND e.to_entity_id   = _entity_id)
         OR (lower(_direction) = 'both' AND (e.from_entity_id = _entity_id OR e.to_entity_id = _entity_id))
        )
      AND (_since  IS NULL OR e.updated_at >= _since)
      AND (_labels IS NULL OR e.label = ANY(_labels))
    ORDER BY e.updated_at DESC, e.edge_id DESC;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- ENTITY TAG HELPERS
-- ---------------------------------------------------------------------------

-- Upsert an entity tag (by entity_id / tag-type-name / property_name / property_value).
-- Returns tag_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_tag_upsert(
    _entity_id      bigint,
    _ttype_name     text,
    _property_name  text,
    _property_value text,
    _content        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_ttype_id smallint;
    v_tag_id   bigint;
BEGIN
    IF _entity_id IS NULL THEN
        RAISE EXCEPTION 'entity_tag_upsert requires non-NULL entity_id';
    END IF;
    IF _ttype_name IS NULL OR btrim(_ttype_name) = '' THEN
        RAISE EXCEPTION 'entity_tag_upsert requires non-NULL ttype_name';
    END IF;
    IF _property_name IS NULL OR _property_value IS NULL THEN
        RAISE EXCEPTION 'entity_tag_upsert requires non-NULL property_name and property_value';
    END IF;

    SELECT id INTO v_ttype_id
    FROM public.tag_type_lu
    WHERE name = lower(_ttype_name);

    IF v_ttype_id IS NULL THEN
        RAISE EXCEPTION 'tag_type_lu has no entry for name=%', _ttype_name;
    END IF;

    INSERT INTO public.entity_tag (
        entity_id, ttype_id, property_name, property_value, content
    )
    VALUES (
        _entity_id, v_ttype_id, _property_name, _property_value, COALESCE(_content, '{}'::jsonb)
    )
    ON CONFLICT (entity_id, ttype_id, property_name, property_value) DO UPDATE
    SET
        content    = CASE
                       WHEN public.entity_tag.content IS DISTINCT FROM COALESCE(EXCLUDED.content, '{}'::jsonb)
                         THEN public.entity_tag.content || EXCLUDED.content
                       ELSE public.entity_tag.content
                     END,
        updated_at = now()
    RETURNING tag_id INTO v_tag_id;

    RETURN v_tag_id;
END
$fn$;
-- +migrate StatementEnd

-- Get entity tag by tag ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_entity_tag_by_id(_tag_id bigint)
RETURNS TABLE (
    tag_id     bigint,
    entity_id  bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT 
        et.tag_id, 
        et.entity_id, 
        et.created_at, 
        et.updated_at, 
        tt.name AS ttype_name, 
        et.content
    FROM public.entity_tag et
    JOIN public.tag_type_lu tt ON tt.id = et.ttype_id
    WHERE et.tag_id = _tag_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get tags for an entity with optional updated-since and property_name filters
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_get_tags(
    _entity_id bigint,
    _since     timestamp without time zone DEFAULT NULL,
    _names     text[] DEFAULT NULL
) RETURNS TABLE (
    tag_id     bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        et.tag_id,
        et.created_at,
        et.updated_at,
        tt.name AS ttype_name,
        et.content
    FROM public.entity_tag et
    JOIN public.tag_type_lu tt ON tt.id = et.ttype_id
    WHERE et.entity_id = _entity_id
      AND (_since IS NULL OR et.updated_at >= _since)
      AND (_names IS NULL OR et.property_name = ANY(_names))
    ORDER BY et.updated_at DESC;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- EDGE TAG HELPERS
-- ---------------------------------------------------------------------------

-- Upsert an entity tag (by entity_id / tag-type-name / property_name / property_value).
-- Returns tag_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_tag_upsert(
    _edge_id        bigint,
    _ttype_name     text,
    _property_name  text,
    _property_value text,
    _content        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_ttype_id smallint;
    v_tag_id   bigint;
BEGIN
    IF _edge_id IS NULL THEN
        RAISE EXCEPTION 'edge_tag_upsert requires non-NULL edge_id';
    END IF;
   IF _ttype_name IS NULL OR btrim(_ttype_name) = '' THEN
        RAISE EXCEPTION 'edge_tag_upsert requires non-NULL ttype_name';
    END IF;
    IF _property_name IS NULL OR _property_value IS NULL THEN
        RAISE EXCEPTION 'edge_tag_upsert requires non-NULL property_name and property_value';
    END IF;

    SELECT id INTO v_ttype_id
    FROM public.tag_type_lu
    WHERE name = lower(_ttype_name);

    IF v_ttype_id IS NULL THEN
        RAISE EXCEPTION 'tag_type_lu has no entry for name=%', _ttype_name;
    END IF;

    INSERT INTO public.edge_tag (
        edge_id, ttype_id, property_name, property_value, content
    )
    VALUES (
        _edge_id, v_ttype_id, _property_name, _property_value, COALESCE(_content, '{}'::jsonb)
    )
    ON CONFLICT (edge_id, ttype_id, property_name, property_value) DO UPDATE
    SET
        content    = CASE
                       WHEN public.edge_tag.content IS DISTINCT FROM COALESCE(EXCLUDED.content, '{}'::jsonb)
                         THEN public.edge_tag.content || EXCLUDED.content
                       ELSE public.edge_tag.content
                     END,
        updated_at = now()
    RETURNING tag_id INTO v_tag_id;

    RETURN v_tag_id;
END
$fn$;
-- +migrate StatementEnd

-- Get edge tag by tag ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_edge_tag_by_id(_tag_id bigint)
RETURNS TABLE (
    tag_id     bigint,
    edge_id    bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT 
        et.tag_id,
        et.edge_id,
        et.created_at,
        et.updated_at,
        tt.name AS ttype_name,
        et.content
    FROM public.edge_tag et
    JOIN public.tag_type_lu tt ON tt.id = et.ttype_id
    WHERE et.tag_id = _tag_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get tags for an edge with optional updated-since and property_name filters
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_get_tags(
    _edge_id bigint,
    _since   timestamp without time zone DEFAULT NULL,
    _names   text[] DEFAULT NULL
) RETURNS TABLE (
    tag_id     bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        et.tag_id,
        et.created_at,
        et.updated_at,
        tt.name AS ttype_name,
        et.content
    FROM public.edge_tag et
    JOIN public.tag_type_lu tt ON tt.id = et.ttype_id
    WHERE et.edge_id = _edge_id
      AND (_since IS NULL OR et.updated_at >= _since)
      AND (_names IS NULL OR et.property_name = ANY(_names))
    ORDER BY et.updated_at DESC;
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.edge_tag_map_get_tag_id(bigint);
DROP FUNCTION IF EXISTS public.edge_get_tags(bigint, timestamp without time zone, text[]);
DROP FUNCTION IF EXISTS public.get_edge_tag_map_by_id(bigint);
DROP FUNCTION IF EXISTS public.edge_tag_map_upsert(bigint, text, text, text, jsonb);

DROP FUNCTION IF EXISTS public.entity_tag_map_get_tag_id(bigint);
DROP FUNCTION IF EXISTS public.entity_get_tags(bigint, timestamp without time zone, text[]);
DROP FUNCTION IF EXISTS public.get_entity_tag_map_by_id(bigint);
DROP FUNCTION IF EXISTS public.entity_tag_map_upsert(bigint, text, text, text, jsonb);

DROP FUNCTION IF EXISTS public.tag_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.tag_get_id(text, text, text);
DROP FUNCTION IF EXISTS public.tag_upsert(text, text, text, jsonb);

DROP FUNCTION IF EXISTS public.edges_for_entity(bigint, text, timestamp without time zone, text[]);
DROP FUNCTION IF EXISTS public.edges_updated_since(timestamp without time zone);
DROP FUNCTION IF EXISTS public.edge_get_id(text, text, bigint, bigint);
DROP FUNCTION IF EXISTS public.edge_upsert(text, text, bigint, bigint, jsonb);

DROP FUNCTION IF EXISTS public.entity_get_by_id(bigint);
DROP FUNCTION IF EXISTS public.entity_upsert(citext, citext, citext, bigint);

DROP FUNCTION IF EXISTS public.get_edge_type_id(text);
DROP FUNCTION IF EXISTS public.get_entity_type_id(text);
DROP FUNCTION IF EXISTS public.null_safe_attrs(jsonb);