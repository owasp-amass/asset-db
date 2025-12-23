-- +migrate Up

-- ============================================================================
-- OWASP Amass: Graph helper functions for edges and tags (PostgreSQL 13+)
-- ============================================================================

BEGIN;

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
    WHERE name = _etype_name::text
    LIMIT 1;

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
    WHERE name = _etype_name
    LIMIT 1;

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
-- TAG UPSERT + HELPERS
-- ---------------------------------------------------------------------------

-- Upsert a tag (by tag-type-name / property_name / property_value).
-- Returns tag_id.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tag_upsert(
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
    IF _ttype_name IS NULL OR btrim(_ttype_name) = '' THEN
        RAISE EXCEPTION 'tag_upsert requires non-NULL ttype_name';
    END IF;
    IF _property_name IS NULL OR _property_value IS NULL THEN
        RAISE EXCEPTION 'tag_upsert requires non-NULL property_name and property_value';
    END IF;

    SELECT id INTO v_ttype_id
    FROM public.tag_type_lu
    WHERE name = _ttype_name
    LIMIT 1;

    IF v_ttype_id IS NULL THEN
        RAISE EXCEPTION 'tag_type_lu has no entry for name=%', _ttype_name;
    END IF;

    INSERT INTO public.tag (
        ttype_id, property_name, property_value, content
    )
    VALUES (
        v_ttype_id, _property_name, _property_value, COALESCE(_content, '{}'::jsonb)
    )
    ON CONFLICT (ttype_id, property_name, property_value) DO UPDATE
    SET
        content    = CASE
                       WHEN public.tag.content IS DISTINCT FROM COALESCE(EXCLUDED.content, '{}'::jsonb)
                         THEN public.tag.content || EXCLUDED.content
                       ELSE public.tag.content
                     END,
        updated_at = now()
    RETURNING tag_id INTO v_tag_id;

    RETURN v_tag_id;
END
$fn$;
-- +migrate StatementEnd

-- Get an existing tag_id by tag-type-name and property (NULL if missing)
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tag_get_id(
    _ttype_name     text,
    _property_name  text,
    _property_value text
) RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT t.tag_id
    FROM public.tag t
    JOIN public.tag_type_lu tt
        ON t.ttype_id = tt.id
    WHERE tt.name          = _ttype_name
      AND t.property_name  = _property_name
      AND t.property_value = _property_value
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Tags updated since a given timestamp
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tag_updated_since(
    _since timestamp without time zone
) RETURNS SETOF public.tag
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.tag
    WHERE updated_at >= _since
    ORDER BY updated_at DESC, tag_id ASC;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- ENTITY ↔ TAG MAPPING HELPERS
-- ---------------------------------------------------------------------------

-- Ensure a tag exists and map it to an entity.
-- Returns (tag_id, map_id).
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_tag_map_upsert(
    _entity_id      bigint,
    _ttype_name     text,
    _property_name  text,
    _property_value text,
    _content        jsonb DEFAULT '{}'::jsonb
) RETURNS TABLE (
    tag_id bigint,
    map_id bigint
)
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_tag_id bigint;
BEGIN
    IF _entity_id IS NULL THEN
        RAISE EXCEPTION 'entity_tag_map_upsert requires non-NULL entity_id';
    END IF;

    v_tag_id := public.tag_upsert(
        _ttype_name,
        _property_name,
        _property_value,
        COALESCE(_content, '{}'::jsonb)
    );

    RETURN QUERY
    INSERT INTO public.entity_tag_map AS m (entity_id, tag_id)
    VALUES (_entity_id, v_tag_id)
    ON CONFLICT (entity_id, tag_id) DO UPDATE
      SET updated_at = now()
    RETURNING m.tag_id, m.map_id;
END
$fn$;
-- +migrate StatementEnd

-- Get entity tag mapping by mapping ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_entity_tag_map_by_id(_map_id bigint)
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
        tg.tag_id, 
        m.entity_id, 
        m.created_at, 
        m.updated_at, 
        tt.name AS ttype_name, 
        tg.content
    FROM public.entity_tag_map m
    JOIN public.tag tg ON tg.tag_id = m.tag_id
    JOIN public.tag_type_lu tt ON tt.id = tg.ttype_id
    WHERE m.map_id = _map_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get tag mappings for an entity with optional updated-since and property_name filters
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_get_tags(
    _entity_id bigint,
    _since     timestamp without time zone DEFAULT NULL,
    _names     text[] DEFAULT NULL
) RETURNS TABLE (
    tag_id     bigint,
    map_id     bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        tg.tag_id,
        m.map_id,
        m.created_at,
        m.updated_at,
        tt.name AS ttype_name,
        tg.content
    FROM public.entity_tag_map m
    JOIN public.tag tg
      ON tg.tag_id = m.tag_id
    JOIN public.tag_type_lu tt
      ON tt.id = tg.ttype_id
    WHERE m.entity_id = _entity_id
      AND (_since IS NULL OR m.updated_at >= _since)
      AND (_names IS NULL OR tg.property_name = ANY(_names))
    ORDER BY m.updated_at DESC, m.map_id DESC;
$fn$;
-- +migrate StatementEnd

-- Get the tag ID for the provided entity map ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.entity_tag_map_get_tag_id(_map_id bigint)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT tg.tag_id
    FROM public.entity_tag_map m
    JOIN public.tag tg ON tg.tag_id = m.tag_id
    WHERE m.map_id = _map_id
    ORDER BY m.updated_at DESC, m.map_id DESC
    LIMIT 1;
$fn$;
-- +migrate StatementEnd


-- ---------------------------------------------------------------------------
-- EDGE ↔ TAG MAPPING HELPERS
-- ---------------------------------------------------------------------------

-- Ensure a tag exists and map it to an edge.
-- Returns (tag_id, map_id).
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_tag_map_upsert(
    _edge_id        bigint,
    _ttype_name     text,
    _property_name  text,
    _property_value text,
    _content        jsonb DEFAULT '{}'::jsonb
) RETURNS TABLE (
    tag_id bigint,
    map_id bigint
)
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_tag_id bigint;
BEGIN
    IF _edge_id IS NULL THEN
        RAISE EXCEPTION 'edge_tag_map_upsert requires non-NULL edge_id';
    END IF;

    v_tag_id := public.tag_upsert(
        _ttype_name,
        _property_name,
        _property_value,
        COALESCE(_content, '{}'::jsonb)
    );

    RETURN QUERY
    INSERT INTO public.edge_tag_map AS m (edge_id, tag_id)
    VALUES (_edge_id, v_tag_id)
    ON CONFLICT (edge_id, tag_id) DO UPDATE
      SET updated_at = now()
    RETURNING m.tag_id, m.map_id;
END
$fn$;
-- +migrate StatementEnd

-- Get edge tag mapping by mapping ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.get_edge_tag_map_by_id(_map_id bigint)
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
        tg.tag_id, 
        m.edge_id, 
        m.created_at, 
        m.updated_at, 
        tt.name AS ttype_name, 
        tg.content
    FROM public.edge_tag_map m
    JOIN public.tag tg ON tg.tag_id = m.tag_id
    JOIN public.tag_type_lu tt ON tt.id = tg.ttype_id
    WHERE m.map_id = _map_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- Get tag mappings for an edge with optional updated-since and property_name filters
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_get_tags(
    _edge_id bigint,
    _since   timestamp without time zone DEFAULT NULL,
    _names   text[] DEFAULT NULL
) RETURNS TABLE (
    tag_id     bigint,
    map_id     bigint,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ttype_name text,
    content    jsonb
)
LANGUAGE sql
STABLE
AS $fn$
    SELECT
        tg.tag_id,
        m.map_id,
        m.created_at,
        m.updated_at,
        tt.name AS ttype_name,
        tg.content
    FROM public.edge_tag_map m
    JOIN public.tag tg
      ON tg.tag_id = m.tag_id
    JOIN public.tag_type_lu tt
      ON tt.id = tg.ttype_id
    WHERE m.edge_id = _edge_id
      AND (_since IS NULL OR m.updated_at >= _since)
      AND (_names IS NULL OR tg.property_name = ANY(_names))
    ORDER BY m.updated_at DESC, m.map_id DESC;
$fn$;
-- +migrate StatementEnd

-- Get the tag ID for the provided edge map ID
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_tag_map_get_tag_id(_map_id bigint)
RETURNS bigint
LANGUAGE sql
STABLE
AS $fn$
    SELECT tg.tag_id
    FROM public.edge_tag_map m
    JOIN public.tag tg ON tg.tag_id = m.tag_id
    WHERE m.map_id = _map_id
    ORDER BY m.updated_at DESC, m.map_id DESC
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

COMMIT;

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