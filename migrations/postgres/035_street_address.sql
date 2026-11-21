-- +migrate Up

-- ============================================================================
-- OWASP Amass: the Location asset type is renamed StreetAddress (PostgreSQL)
--
-- Open Asset Model renamed Location to StreetAddress, since a position on the
-- Earth is now its own type (GeoLocation). Stored addresses keep their entity
-- IDs, edges and properties: the table, its indexes and functions are renamed,
-- the entity type name becomes 'streetaddress', and each entity row points at
-- the renamed table. The plain address relations become one label,
-- street_address (ContactRecord and Organization "location", Person
-- "address"); the role labels hq_address and legal_address are unchanged.
-- ============================================================================

ALTER TABLE public.location RENAME TO streetaddress;
UPDATE public.entity_type_lu SET name = 'streetaddress' WHERE name = 'location';
UPDATE public.entity SET table_name = 'public.streetaddress' WHERE table_name = 'public.location';

-- the relation's label is held in the column and in the stored relation
UPDATE public.edge e
SET label   = 'street_address',
    content = CASE WHEN e.content ? 'label'
                   THEN jsonb_set(e.content, '{label}', '"street_address"') ELSE e.content END
FROM public.entity d
JOIN public.entity_type_lu dt ON dt.id = d.etype_id
WHERE e.to_entity_id = d.entity_id AND dt.name = 'streetaddress' AND e.label IN ('location', 'address');

-- +migrate StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT indexname FROM pg_indexes
             WHERE schemaname = 'public' AND tablename = 'streetaddress' AND indexname LIKE 'idx\_location\_%'
    LOOP
        EXECUTE format('ALTER INDEX public.%I RENAME TO %I', r.indexname,
                       'idx_streetaddress_' || substr(r.indexname, length('idx_location_') + 1));
    END LOOP;
END
$$;
-- +migrate StatementEnd

DROP FUNCTION IF EXISTS public.location_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.location_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.location_get_by_id(bigint);
DROP FUNCTION IF EXISTS public.location_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.location_upsert(text, text, text, text, text, text, text, text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.location_upsert_entity_json(jsonb);

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_get_by_id(_row_id bigint)
RETURNS public.streetaddress
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.streetaddress
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_upsert(
    _street_address  text,
    _city            text,
    _country         text,
    _unit            text DEFAULT NULL,
    _building        text DEFAULT NULL,
    _province        text DEFAULT NULL,
    _locality        text DEFAULT NULL,
    _postal_code     text DEFAULT NULL,
    _street_name     text DEFAULT NULL,
    _building_number text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _street_address IS NULL OR _city IS NULL OR _country IS NULL THEN
        RAISE EXCEPTION 'streetaddress_upsert requires non-NULL street_address, city and country';
    END IF;

    INSERT INTO public.streetaddress (
        street_address, city, country, unit, building, province,
        locality, postal_code, street_name, building_number, attrs
    ) VALUES (
        _street_address, _city, _country, _unit, _building, _province, 
        _locality, _postal_code, _street_name, _building_number, _attrs
    )
    ON CONFLICT (street_address) DO UPDATE
    SET
        city            = COALESCE(EXCLUDED.city,            streetaddress.city),
        country         = COALESCE(EXCLUDED.country,         streetaddress.country),
        unit            = COALESCE(EXCLUDED.unit,            streetaddress.unit),
        building        = COALESCE(EXCLUDED.building,        streetaddress.building),
        province        = COALESCE(EXCLUDED.province,        streetaddress.province),
        locality        = COALESCE(EXCLUDED.locality,        streetaddress.locality),
        postal_code     = COALESCE(EXCLUDED.postal_code,     streetaddress.postal_code),
        street_name     = COALESCE(EXCLUDED.street_name,     streetaddress.street_name),
        building_number = COALESCE(EXCLUDED.building_number, streetaddress.building_number),
        attrs           = streetaddress.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.streetaddress WHERE street_address = _street_address;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_street_address  text;
    v_city            text;
    v_country         text;
    v_unit            text;
    v_building        text;
    v_province        text;
    v_locality        text;
    v_postal_code     text;
    v_street_name     text;
    v_building_number text;
    v_po_box          text;
    v_gln             integer;
    v_attrs           jsonb;
BEGIN
    v_street_address  := NULLIF(_rec->>'address', '');
    v_city            := NULLIF(_rec->>'city', '');
    v_country         := NULLIF(_rec->>'country', '');
    v_unit            := NULLIF(_rec->>'unit', '');
    v_building        := NULLIF(_rec->>'building', '');
    v_province        := NULLIF(_rec->>'province', '');
    v_locality        := NULLIF(_rec->>'locality', '');
    v_postal_code     := NULLIF(_rec->>'postal_code', '');
    v_street_name     := NULLIF(_rec->>'street_name', '');
    v_building_number := NULLIF(_rec->>'building_number', '');
    v_po_box          := NULLIF(_rec->>'po_box', '');
    v_gln             := NULLIF(_rec->>'gln', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'po_box', v_po_box,
            'gln',    v_gln
        )
    ) || '{}'::jsonb;

    RETURN public.streetaddress_upsert(
        v_street_address,
        v_city,
        v_country,
        v_unit,
        v_building,
        v_province,
        v_locality,
        v_postal_code,
        v_street_name,
        v_building_number,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_addr text;
    v_row  bigint;
BEGIN
    v_addr := NULLIF(_rec->>'address', '');

    -- 1) Upsert into streetaddress.
    v_row := public.streetaddress_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'streetaddress'::citext,
        _natural_key := v_addr::citext,
        _table_name  := 'public.streetaddress'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    -- Support both "street_address" and legacy "address"
    v_street_address  text := NULLIF(_filters->>'address', '');
    v_city            text := NULLIF(_filters->>'city', '');
    v_country         text := NULLIF(_filters->>'country', '');
    v_unit            text := NULLIF(_filters->>'unit', '');
    v_building        text := NULLIF(_filters->>'building', '');
    v_province        text := NULLIF(_filters->>'province', '');
    v_locality        text := NULLIF(_filters->>'locality', '');
    v_postal_code     text := NULLIF(_filters->>'postal_code', '');
    v_street_name     text := NULLIF(_filters->>'street_name', '');
    v_building_number text := NULLIF(_filters->>'building_number', '');
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    -- Require at least one supported filter
    IF v_street_address IS NULL
       AND v_city IS NULL
       AND v_country IS NULL
       AND v_unit IS NULL
       AND v_building IS NULL
       AND v_province IS NULL
       AND v_locality IS NULL
       AND v_postal_code IS NULL
       AND v_street_name IS NULL
       AND v_building_number IS NULL THEN
        RAISE EXCEPTION 'streetaddress_find_by_content requires at least one filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.streetaddress a
        JOIN public.entity e ON e.table_name = 'public.streetaddress'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.streetaddress a
        JOIN public.entity e ON e.table_name = 'public.streetaddress'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.streetaddress_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.streetaddress a
        JOIN public.entity e ON e.table_name = 'public.streetaddress'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.streetaddress a
        JOIN public.entity e ON e.table_name = 'public.streetaddress'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd


-- +migrate Down

DROP FUNCTION IF EXISTS public.streetaddress_updated_since(timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.streetaddress_find_by_content(jsonb, timestamp without time zone, integer);
DROP FUNCTION IF EXISTS public.streetaddress_get_by_id(bigint);
DROP FUNCTION IF EXISTS public.streetaddress_upsert_json(jsonb);
DROP FUNCTION IF EXISTS public.streetaddress_upsert(text, text, text, text, text, text, text, text, text, text, jsonb);
DROP FUNCTION IF EXISTS public.streetaddress_upsert_entity_json(jsonb);

-- a Person's address edge was "address"; the others were "location"
UPDATE public.edge e
SET label   = CASE WHEN st.name = 'person' THEN 'address' ELSE 'location' END,
    content = CASE WHEN e.content ? 'label'
                   THEN jsonb_set(e.content, '{label}',
                                  to_jsonb(CASE WHEN st.name = 'person' THEN 'address' ELSE 'location' END))
                   ELSE e.content END
FROM public.entity d
JOIN public.entity_type_lu dt ON dt.id = d.etype_id,
     public.entity s
JOIN public.entity_type_lu st ON st.id = s.etype_id
WHERE e.to_entity_id = d.entity_id AND e.from_entity_id = s.entity_id
  AND dt.name = 'streetaddress' AND e.label = 'street_address';

ALTER TABLE public.streetaddress RENAME TO location;
UPDATE public.entity_type_lu SET name = 'location' WHERE name = 'streetaddress';
UPDATE public.entity SET table_name = 'public.location' WHERE table_name = 'public.streetaddress';

-- +migrate StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT indexname FROM pg_indexes
             WHERE schemaname = 'public' AND tablename = 'location' AND indexname LIKE 'idx\_streetaddress\_%'
    LOOP
        EXECUTE format('ALTER INDEX public.%I RENAME TO %I', r.indexname,
                       'idx_location_' || substr(r.indexname, length('idx_streetaddress_') + 1));
    END LOOP;
END
$$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_get_by_id(_row_id bigint)
RETURNS public.location
LANGUAGE sql
STABLE
AS $fn$
    SELECT *
    FROM public.location
    WHERE id = _row_id
    LIMIT 1;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert(
    _street_address  text,
    _city            text,
    _country         text,
    _unit            text DEFAULT NULL,
    _building        text DEFAULT NULL,
    _province        text DEFAULT NULL,
    _locality        text DEFAULT NULL,
    _postal_code     text DEFAULT NULL,
    _street_name     text DEFAULT NULL,
    _building_number text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _street_address IS NULL OR _city IS NULL OR _country IS NULL THEN
        RAISE EXCEPTION 'location_upsert requires non-NULL street_address, city and country';
    END IF;

    INSERT INTO public.location (
        street_address, city, country, unit, building, province,
        locality, postal_code, street_name, building_number, attrs
    ) VALUES (
        _street_address, _city, _country, _unit, _building, _province, 
        _locality, _postal_code, _street_name, _building_number, _attrs
    )
    ON CONFLICT (street_address) DO UPDATE
    SET
        city            = COALESCE(EXCLUDED.city,            location.city),
        country         = COALESCE(EXCLUDED.country,         location.country),
        unit            = COALESCE(EXCLUDED.unit,            location.unit),
        building        = COALESCE(EXCLUDED.building,        location.building),
        province        = COALESCE(EXCLUDED.province,        location.province),
        locality        = COALESCE(EXCLUDED.locality,        location.locality),
        postal_code     = COALESCE(EXCLUDED.postal_code,     location.postal_code),
        street_name     = COALESCE(EXCLUDED.street_name,     location.street_name),
        building_number = COALESCE(EXCLUDED.building_number, location.building_number),
        attrs           = location.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.location WHERE street_address = _street_address;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_json(_rec jsonb)
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_street_address  text;
    v_city            text;
    v_country         text;
    v_unit            text;
    v_building        text;
    v_province        text;
    v_locality        text;
    v_postal_code     text;
    v_street_name     text;
    v_building_number text;
    v_po_box          text;
    v_gln             integer;
    v_attrs           jsonb;
BEGIN
    v_street_address  := NULLIF(_rec->>'address', '');
    v_city            := NULLIF(_rec->>'city', '');
    v_country         := NULLIF(_rec->>'country', '');
    v_unit            := NULLIF(_rec->>'unit', '');
    v_building        := NULLIF(_rec->>'building', '');
    v_province        := NULLIF(_rec->>'province', '');
    v_locality        := NULLIF(_rec->>'locality', '');
    v_postal_code     := NULLIF(_rec->>'postal_code', '');
    v_street_name     := NULLIF(_rec->>'street_name', '');
    v_building_number := NULLIF(_rec->>'building_number', '');
    v_po_box          := NULLIF(_rec->>'po_box', '');
    v_gln             := NULLIF(_rec->>'gln', '');

    -- Build attrs from the appropriate fields.
    v_attrs := jsonb_strip_nulls(
        jsonb_build_object(
            'po_box', v_po_box,
            'gln',    v_gln
        )
    ) || '{}'::jsonb;

    RETURN public.location_upsert(
        v_street_address,
        v_city,
        v_country,
        v_unit,
        v_building,
        v_province,
        v_locality,
        v_postal_code,
        v_street_name,
        v_building_number,
        v_attrs
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_upsert_entity_json(_rec jsonb) 
RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_addr text;
    v_row  bigint;
BEGIN
    v_addr := NULLIF(_rec->>'address', '');

    -- 1) Upsert into location.
    v_row := public.location_upsert_json(_rec);

    -- 2) Upsert into entity via the generic helper.
    RETURN public.entity_upsert(
        _etype_name  := 'location'::citext,
        _natural_key := v_addr::citext,
        _table_name  := 'public.location'::citext,
        _row_id      := v_row
    );
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_find_by_content(
    _filters jsonb,
    _since   timestamp without time zone DEFAULT NULL,
    _limit   integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    -- Support both "street_address" and legacy "address"
    v_street_address  text := NULLIF(_filters->>'address', '');
    v_city            text := NULLIF(_filters->>'city', '');
    v_country         text := NULLIF(_filters->>'country', '');
    v_unit            text := NULLIF(_filters->>'unit', '');
    v_building        text := NULLIF(_filters->>'building', '');
    v_province        text := NULLIF(_filters->>'province', '');
    v_locality        text := NULLIF(_filters->>'locality', '');
    v_postal_code     text := NULLIF(_filters->>'postal_code', '');
    v_street_name     text := NULLIF(_filters->>'street_name', '');
    v_building_number text := NULLIF(_filters->>'building_number', '');
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    -- Require at least one supported filter
    IF v_street_address IS NULL
       AND v_city IS NULL
       AND v_country IS NULL
       AND v_unit IS NULL
       AND v_building IS NULL
       AND v_province IS NULL
       AND v_locality IS NULL
       AND v_postal_code IS NULL
       AND v_street_name IS NULL
       AND v_building_number IS NULL THEN
        RAISE EXCEPTION 'location_find_by_content requires at least one filter';
    END IF;

    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE
            (v_street_address  IS NULL OR a.street_address  = v_street_address)
        AND (v_city            IS NULL OR a.city            = v_city)
        AND (v_country         IS NULL OR a.country         = v_country)
        AND (v_unit            IS NULL OR a.unit            = v_unit)
        AND (v_building        IS NULL OR a.building        = v_building)
        AND (v_province        IS NULL OR a.province        = v_province)
        AND (v_locality        IS NULL OR a.locality        = v_locality)
        AND (v_postal_code     IS NULL OR a.postal_code     = v_postal_code)
        AND (v_street_name     IS NULL OR a.street_name     = v_street_name)
        AND (v_building_number IS NULL OR a.building_number = v_building_number)
        AND (_since            IS NULL OR a.updated_at      >= _since)
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.location_updated_since(
    _since timestamp without time zone,
    _limit integer DEFAULT NULL
) RETURNS TABLE (
    entity_id       bigint,
    id              bigint,
    created_at      timestamp without time zone,
    updated_at      timestamp without time zone,
    street_address  text,
    city            text,
    country         text,
    unit            text,
    building        text,
    province        text,
    locality        text,
    postal_code     text,
    street_name     text,
    building_number text,
    attrs           jsonb
)
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
    v_limit integer := NULLIF(_limit, 0); -- treat 0 as unlimited
BEGIN
    IF v_limit IS NULL THEN
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC;
    ELSE
        RETURN QUERY
        SELECT
            e.entity_id,
            a.id,
            a.created_at,
            a.updated_at,
            a.street_address,
            a.city,
            a.country,
            a.unit,
            a.building,
            a.province,
            a.locality,
            a.postal_code,
            a.street_name,
            a.building_number,
            a.attrs
        FROM public.location a
        JOIN public.entity e ON e.table_name = 'public.location'::citext AND e.row_id = a.id
        WHERE a.updated_at >= _since
        ORDER BY a.updated_at DESC, a.id DESC
        LIMIT v_limit;
    END IF;
END
$fn$;
-- +migrate StatementEnd
