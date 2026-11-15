-- +migrate Up

-- ============================================================================
-- OWASP Amass: leaner writes and indexed label lookups (PostgreSQL 13+)
--
-- * Indexes no query uses, or that another index covers, are dropped (on the
--   graph tables they took two to three times the space of the rows).
-- * Within one enumeration, a row seen again with nothing new is left as it
--   is for touch_window() (touch_guard), so a revisit writes no new row
--   version and no index entry. The writer names the enumeration's start in
--   the amass.seen_since setting: a row last seen before it always records
--   the sighting, so updated_at never falls before the run that saw the row.
--   Without the setting, every sighting is recorded, as before.
-- * Edges are found by (entity, label) indexes; labels compare as citext.
-- * Tag uniqueness uses a SHA-256 of the value, so values longer than a
--   B-tree entry (about 2.7 KB) can be stored.
-- * A source tag is one row per source: the confidence lives in its content.
-- * DNS edges are distinct per record type.
-- No table, column or data type of the Open Asset Model changes.
-- ============================================================================

-- --- Helpers -----------------------------------------------------------------
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.touch_window() RETURNS interval
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$ SELECT interval '5 minutes' $fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tag_value_key(text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $fn$ SELECT sha256(convert_to($1, 'UTF8')) $fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tag_stored_value(_ttype_name text, _value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
    SELECT CASE WHEN lower(_ttype_name) = 'sourceproperty' THEN '' ELSE _value END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.edge_record_type(_content jsonb) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$ SELECT COALESCE(_content #>> '{header,rr_type}', '') $fn$;
-- +migrate StatementEnd

-- touch_guard skips an update that changes nothing but updated_at, when the
-- row was already seen in this enumeration (at or after amass.seen_since)
-- and within touch_window(). Its arguments are JSON paths into
-- the row to leave out of the comparison: generated columns (not computed
-- yet in a BEFORE trigger) and values that change on every observation, such
-- as the remaining TTL a resolver reports.
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.touch_guard() RETURNS trigger
LANGUAGE plpgsql AS $fn$
DECLARE
    v_since text;
    v_seen  timestamp without time zone;
    v_new   jsonb;
    v_old   jsonb;
    v_path  text;
BEGIN
    v_since := NULLIF(current_setting('amass.seen_since', true), '');
    IF v_since IS NULL OR OLD.updated_at < v_since::timestamp
       OR OLD.updated_at < localtimestamp - public.touch_window() THEN
        RETURN NEW;
    END IF;

    IF TG_NARGS = 0 THEN
        -- compare the rows as they are, but for when they were last seen
        v_seen := NEW.updated_at;
        NEW.updated_at := OLD.updated_at;
        IF NEW IS NOT DISTINCT FROM OLD THEN
            RETURN NULL;
        END IF;

        NEW.updated_at := v_seen;
        RETURN NEW;
    END IF;

    v_new := to_jsonb(NEW) - 'updated_at';
    v_old := to_jsonb(OLD) - 'updated_at';
    FOREACH v_path IN ARRAY TG_ARGV LOOP
        v_new := v_new #- v_path::text[];
        v_old := v_old #- v_path::text[];
    END LOOP;

    IF v_new = v_old THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END
$fn$;
-- +migrate StatementEnd

-- --- One source tag per source ------------------------------------------------
-- Keep the most recent row of each source, first seen at the earliest.
WITH src AS (SELECT id FROM public.tag_type_lu WHERE name = 'sourceproperty'),
ranked AS (
    SELECT t.tag_id,
           row_number() OVER w AS rn,
           min(t.created_at) OVER (PARTITION BY t.entity_id, t.property_name) AS first_seen
    FROM public.entity_tag t, src
    WHERE t.ttype_id = src.id
    WINDOW w AS (PARTITION BY t.entity_id, t.property_name ORDER BY t.updated_at DESC, t.tag_id DESC)
),
gone AS (DELETE FROM public.entity_tag t USING ranked r WHERE t.tag_id = r.tag_id AND r.rn > 1)
UPDATE public.entity_tag t SET property_value = '', created_at = r.first_seen
FROM ranked r WHERE t.tag_id = r.tag_id AND r.rn = 1;

WITH src AS (SELECT id FROM public.tag_type_lu WHERE name = 'sourceproperty'),
ranked AS (
    SELECT t.tag_id,
           row_number() OVER w AS rn,
           min(t.created_at) OVER (PARTITION BY t.edge_id, t.property_name) AS first_seen
    FROM public.edge_tag t, src
    WHERE t.ttype_id = src.id
    WINDOW w AS (PARTITION BY t.edge_id, t.property_name ORDER BY t.updated_at DESC, t.tag_id DESC)
),
gone AS (DELETE FROM public.edge_tag t USING ranked r WHERE t.tag_id = r.tag_id AND r.rn > 1)
UPDATE public.edge_tag t SET property_value = '', created_at = r.first_seen
FROM ranked r WHERE t.tag_id = r.tag_id AND r.rn = 1;

-- --- Indexes -------------------------------------------------------------------
DROP INDEX IF EXISTS public.idx_entity_created_at;
DROP INDEX IF EXISTS public.idx_entity_updated_at;
DROP INDEX IF EXISTS public.idx_edge_created_at;
DROP INDEX IF EXISTS public.idx_edge_updated_at;
DROP INDEX IF EXISTS public.idx_edge_etype;
DROP INDEX IF EXISTS public.gin_edge_content;
DROP INDEX IF EXISTS public.idx_edge_from_id;
DROP INDEX IF EXISTS public.idx_edge_to_id;
DROP INDEX IF EXISTS public.idx_edge_from;
DROP INDEX IF EXISTS public.idx_edge_to;
DROP INDEX IF EXISTS public.idx_entity_tag_created_at;
DROP INDEX IF EXISTS public.idx_entity_tag_updated_at;
DROP INDEX IF EXISTS public.idx_entity_tag_entity_updated;
DROP INDEX IF EXISTS public.idx_entity_tag_entity_id;
DROP INDEX IF EXISTS public.idx_entity_tag_ttype_id;
DROP INDEX IF EXISTS public.idx_entity_tag_property_name;
DROP INDEX IF EXISTS public.idx_entity_tag_tt_name;
DROP INDEX IF EXISTS public.idx_entity_tag_property_name_value;
DROP INDEX IF EXISTS public.idx_entity_tag_ttype_name_value;
DROP INDEX IF EXISTS public.gin_entity_tag_content;
DROP INDEX IF EXISTS public.idx_edge_tag_created_at;
DROP INDEX IF EXISTS public.idx_edge_tag_updated_at;
DROP INDEX IF EXISTS public.idx_edge_tag_edge_updated;
DROP INDEX IF EXISTS public.idx_edge_tag_edge_id;
DROP INDEX IF EXISTS public.idx_edge_tag_ttype_id;
DROP INDEX IF EXISTS public.idx_edge_tag_property_name;
DROP INDEX IF EXISTS public.idx_edge_tag_tt_name;
DROP INDEX IF EXISTS public.idx_edge_tag_property_name_value;
DROP INDEX IF EXISTS public.idx_edge_tag_ttype_name_value;
DROP INDEX IF EXISTS public.gin_edge_tag_content;
DROP INDEX IF EXISTS public.idx_account_created_at;
DROP INDEX IF EXISTS public.idx_autnumrecord_created_at;
DROP INDEX IF EXISTS public.idx_autonomoussystem_created_at;
DROP INDEX IF EXISTS public.idx_contactrecord_created_at;
DROP INDEX IF EXISTS public.idx_domainrecord_created_at;
DROP INDEX IF EXISTS public.idx_file_created_at;
DROP INDEX IF EXISTS public.idx_fqdn_created_at;
DROP INDEX IF EXISTS public.idx_fundstransfer_created_at;
DROP INDEX IF EXISTS public.idx_identifier_created_at;
DROP INDEX IF EXISTS public.idx_ipaddress_created_at;
DROP INDEX IF EXISTS public.idx_ipnetrecord_created_at;
DROP INDEX IF EXISTS public.idx_location_created_at;
DROP INDEX IF EXISTS public.idx_netblock_created_at;
DROP INDEX IF EXISTS public.idx_organization_created_at;
DROP INDEX IF EXISTS public.idx_person_created_at;
DROP INDEX IF EXISTS public.idx_phone_created_at;
DROP INDEX IF EXISTS public.idx_product_created_at;
DROP INDEX IF EXISTS public.idx_productrelease_created_at;
DROP INDEX IF EXISTS public.idx_service_created_at;
DROP INDEX IF EXISTS public.idx_tlscertificate_created_at;
DROP INDEX IF EXISTS public.idx_url_created_at;

ALTER TABLE public.entity DROP CONSTRAINT entity_table_name_row_id_key;
ALTER TABLE public.entity DROP CONSTRAINT entity_etype_id_row_id_key;
-- row_id first: the type tables' finds join on (table_name, row_id), and a
-- row_id is shared by at most one row per type
ALTER TABLE public.entity ADD CONSTRAINT entity_row_id_etype_id_key UNIQUE (row_id, etype_id);

ALTER TABLE public.edge DROP CONSTRAINT edge_etype_id_from_entity_id_to_entity_id_label_key;
CREATE UNIQUE INDEX edge_identity_uidx
  ON public.edge (from_entity_id, label, etype_id, to_entity_id, public.edge_record_type(content));
CREATE INDEX edge_to_label_idx ON public.edge (to_entity_id, label);

ALTER TABLE public.entity_tag DROP CONSTRAINT entity_tag_entity_id_ttype_id_property_name_property_value_key;
CREATE UNIQUE INDEX entity_tag_identity_uidx
  ON public.entity_tag (entity_id, ttype_id, property_name, public.tag_value_key(property_value));
CREATE INDEX entity_tag_value_idx ON public.entity_tag (property_name, public.tag_value_key(property_value));

ALTER TABLE public.edge_tag DROP CONSTRAINT edge_tag_edge_id_ttype_id_property_name_property_value_key;
CREATE UNIQUE INDEX edge_tag_identity_uidx
  ON public.edge_tag (edge_id, ttype_id, property_name, public.tag_value_key(property_value));

-- room on each page for a row's next version
ALTER TABLE public.entity SET (fillfactor = 90);
ALTER TABLE public.edge SET (fillfactor = 90);
ALTER TABLE public.entity_tag SET (fillfactor = 90);
ALTER TABLE public.edge_tag SET (fillfactor = 90);

-- --- Upserts -------------------------------------------------------------------
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

    -- the touch guard kept the row unchanged: return its id
    IF v_entity_id IS NULL THEN
        SELECT entity_id INTO v_entity_id FROM public.entity WHERE row_id = _row_id AND etype_id = v_etype_id;
    END IF;

    RETURN v_entity_id;
END
$fn$;
-- +migrate StatementEnd

-- An edge is identified by its endpoints, label and relation type, and for
-- DNS relations by the record type as well: a name can hold records of two
-- types that point at the same name (NS and CNAME), each its own edge.
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
    ON CONFLICT (from_entity_id, label, etype_id, to_entity_id, public.edge_record_type(content)) DO UPDATE
    SET
        content    = public.edge.content || v_content,
        updated_at = now()
    RETURNING edge_id INTO v_edge_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_edge_id IS NULL THEN
        SELECT edge_id INTO v_edge_id FROM public.edge
        WHERE from_entity_id = _from_entity_id AND label = lower(_label)::citext AND etype_id = v_etype_id
          AND to_entity_id = _to_entity_id AND public.edge_record_type(content) = public.edge_record_type(v_content);
    END IF;

    RETURN v_edge_id;
END
$fn$;
-- +migrate StatementEnd

-- A source tag is one row per source: its value (the confidence) is kept in
-- the content, which the latest observation updates, not in the key.
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
    v_value    text;
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

    v_value := public.tag_stored_value(_ttype_name, _property_value);
    INSERT INTO public.entity_tag (
        entity_id, ttype_id, property_name, property_value, content
    )
    VALUES (
        _entity_id, v_ttype_id, _property_name, v_value, COALESCE(_content, '{}'::jsonb)
    )
    ON CONFLICT (entity_id, ttype_id, property_name, public.tag_value_key(property_value)) DO UPDATE
    SET
        content    = CASE
                       WHEN public.entity_tag.content IS DISTINCT FROM COALESCE(EXCLUDED.content, '{}'::jsonb)
                         THEN public.entity_tag.content || EXCLUDED.content
                       ELSE public.entity_tag.content
                     END,
        updated_at = now()
    RETURNING tag_id INTO v_tag_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_tag_id IS NULL THEN
        SELECT tag_id INTO v_tag_id FROM public.entity_tag
        WHERE entity_id = _entity_id AND ttype_id = v_ttype_id AND property_name = _property_name
          AND public.tag_value_key(property_value) = public.tag_value_key(v_value);
    END IF;

    RETURN v_tag_id;
END
$fn$;
-- +migrate StatementEnd

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
    v_value    text;
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

    v_value := public.tag_stored_value(_ttype_name, _property_value);
    INSERT INTO public.edge_tag (
        edge_id, ttype_id, property_name, property_value, content
    )
    VALUES (
        _edge_id, v_ttype_id, _property_name, v_value, COALESCE(_content, '{}'::jsonb)
    )
    ON CONFLICT (edge_id, ttype_id, property_name, public.tag_value_key(property_value)) DO UPDATE
    SET
        content    = CASE
                       WHEN public.edge_tag.content IS DISTINCT FROM COALESCE(EXCLUDED.content, '{}'::jsonb)
                         THEN public.edge_tag.content || EXCLUDED.content
                       ELSE public.edge_tag.content
                     END,
        updated_at = now()
    RETURNING tag_id INTO v_tag_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_tag_id IS NULL THEN
        SELECT tag_id INTO v_tag_id FROM public.edge_tag
        WHERE edge_id = _edge_id AND ttype_id = v_ttype_id AND property_name = _property_name
          AND public.tag_value_key(property_value) = public.tag_value_key(v_value);
    END IF;

    RETURN v_tag_id;
END
$fn$;
-- +migrate StatementEnd

-- Labels are compared as citext, so the (entity, label) indexes serve them.
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
      AND (_labels IS NULL OR e.label = ANY(_labels::citext[]))
    ORDER BY e.updated_at DESC, e.edge_id DESC;
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert(
    _unique_id      text,
    _account_type   text,
    _username       text DEFAULT NULL,
    _account_number text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _account_type IS NULL THEN
        RAISE EXCEPTION 'account_upsert requires non-NULL unique_id and account_type';
    END IF;

    INSERT INTO public.account (
        unique_id, account_type, username, account_number, attrs
    ) VALUES (
        _unique_id, _account_type, _username, _account_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        account_type   = COALESCE(EXCLUDED.account_type,   account.account_type),
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        attrs          = account.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at     = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.account WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert(
    _asn   integer,
    _attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _asn IS NULL THEN
        RAISE EXCEPTION 'autonomoussystem_upsert requires non-NULL asn';
    END IF;

    INSERT INTO public.autonomoussystem (
        asn, attrs
    ) VALUES (
        _asn, _attrs
    )
    ON CONFLICT (asn) DO UPDATE
    SET
        attrs      = autonomoussystem.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.autonomoussystem WHERE asn = _asn;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert(
    _discovered_at text,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _discovered_at IS NULL THEN
        RAISE EXCEPTION 'contactrecord_upsert requires non-NULL discovered_at';
    END IF;

    INSERT INTO public.contactrecord (
        discovered_at, attrs
    ) VALUES (
        _discovered_at, _attrs
    )
    ON CONFLICT (discovered_at) DO UPDATE
    SET
        attrs      = contactrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.contactrecord WHERE discovered_at = _discovered_at;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert(
    _domain         text,
    _record_name    text,
    _punycode       text DEFAULT NULL,
    _extension      text DEFAULT NULL,
    _whois_server   citext DEFAULT NULL,
    _object_id      text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _domain IS NULL THEN
        RAISE EXCEPTION 'domainrecord_upsert requires non-NULL domain';
    END IF;

    INSERT INTO public.domainrecord (
        domain, record_name, punycode, extension, whois_server, object_id, attrs
    ) VALUES (
        _domain, _record_name, _punycode, _extension, _whois_server, _object_id, _attrs
    )
    ON CONFLICT (domain) DO UPDATE
    SET
        record_name     = COALESCE(EXCLUDED.record_name,  domainrecord.record_name),
        punycode        = COALESCE(EXCLUDED.punycode,     domainrecord.punycode),
        extension       = COALESCE(EXCLUDED.extension,    domainrecord.extension),
        whois_server    = COALESCE(EXCLUDED.whois_server, domainrecord.whois_server),
        object_id       = COALESCE(EXCLUDED.object_id,    domainrecord.object_id),
        attrs           = domainrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.domainrecord WHERE domain = _domain;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert(
    _file_url  text,
    _basename  text DEFAULT NULL,
    _file_type text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _file_url IS NULL THEN
        RAISE EXCEPTION 'file_upsert requires non-NULL file_url';
    END IF;

    INSERT INTO public.file (
        file_url, basename, file_type, attrs
    ) VALUES (
        _file_url, _basename, _file_type, _attrs
    )
    ON CONFLICT (file_url) DO UPDATE
    SET
        basename   = COALESCE(EXCLUDED.basename,  file.basename),
        file_type  = COALESCE(EXCLUDED.file_type, file.file_type),
        attrs      = file.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.file WHERE file_url = _file_url;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert(
    _fqdn  text,
    _attrs jsonb DEFAULT '{}'::jsonb
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
        fqdn, attrs
    ) VALUES (
        lower(_fqdn)::citext, _attrs
    )
    ON CONFLICT (fqdn) DO UPDATE
    SET
        attrs      = fqdn.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.fqdn WHERE fqdn = lower(_fqdn)::citext;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert(
    _unique_id        text,
    _amount           numeric,
    _reference_number text DEFAULT NULL,
    _attrs            jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _amount IS NULL THEN
        RAISE EXCEPTION 'fundstransfer_upsert requires non-NULL unique_id and amount';
    END IF;

    INSERT INTO public.fundstransfer (
        unique_id, amount, reference_number, attrs
    ) VALUES (
        _unique_id, _amount, _reference_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        amount           = EXCLUDED.amount,
        reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
        attrs            = fundstransfer.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at       = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.fundstransfer WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert(
    _unique_id text,
    _id_value  text,
    _id_type   text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _id_value IS NULL OR _id_type IS NULL THEN
        RAISE EXCEPTION 'identifier_upsert requires non-NULL unique_id, id_value, and id_type';
    END IF;

    INSERT INTO public.identifier (
        unique_id, id_value, id_type, attrs
    ) VALUES (
        _unique_id, _id_value, _id_type, _attrs
    )
    ON CONFLICT (id_value, id_type) DO UPDATE
    SET
        unique_id  = EXCLUDED.unique_id,
        attrs      = identifier.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.identifier WHERE id_value = _id_value AND id_type = _id_type;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert(
    _ip_address inet,
    _attrs      jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _ip_address IS NULL THEN
        RAISE EXCEPTION 'ipaddress_upsert requires non-NULL ip_address';
    END IF;
    IF NOT (_attrs ? 'type') THEN
        RAISE EXCEPTION 'ipaddress_upsert requires attrs to contain key "type"';
    END IF;

    INSERT INTO public.ipaddress (
        ip_address, attrs
    ) VALUES (
        _ip_address, _attrs
    )
    ON CONFLICT (ip_address) DO UPDATE
    SET
        attrs      = ipaddress.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.ipaddress WHERE ip_address = _ip_address;
    END IF;

    RETURN v_id;
END
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
CREATE OR REPLACE FUNCTION public.netblock_upsert(
    _netblock_cidr cidr,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _netblock_cidr IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL netblock_cidr';
    END IF;
    IF NOT (_attrs ? 'type') OR (_attrs->>'type') IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL ip_version';
    END IF;

    INSERT INTO public.netblock (
        netblock_cidr, attrs
    ) VALUES (
        _netblock_cidr, _attrs
    )
    ON CONFLICT (netblock_cidr) DO UPDATE
    SET
        attrs      = netblock.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.netblock WHERE netblock_cidr = _netblock_cidr;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert(
    _unique_id       text,
    _org_name        text,
    _legal_name      text DEFAULT NULL,
    _jurisdiction    text DEFAULT NULL,
    _registration_id text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _org_name IS NULL THEN
        RAISE EXCEPTION 'organization_upsert requires non-NULL unique_id and org_name';
    END IF;

    INSERT INTO public.organization (
        unique_id, org_name, legal_name, jurisdiction, registration_id, attrs
    ) VALUES (
        _unique_id, _org_name, _legal_name, _jurisdiction, _registration_id, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        org_name        = COALESCE(EXCLUDED.org_name,        organization.org_name),
        legal_name      = COALESCE(EXCLUDED.legal_name,      organization.legal_name),
        jurisdiction    = COALESCE(EXCLUDED.jurisdiction,    organization.jurisdiction),
        registration_id = COALESCE(EXCLUDED.registration_id, organization.registration_id),
        attrs           = organization.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.organization WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert(
    _unique_id   text,
    _full_name   text DEFAULT NULL,
    _first_name  text DEFAULT NULL,
    _family_name text DEFAULT NULL,
    _attrs       jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'person_upsert requires non-NULL unique_id';
    END IF;

    INSERT INTO public.person (
        unique_id, full_name, first_name, family_name, attrs
    ) VALUES (
        _unique_id, _full_name, _first_name, _family_name, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
        first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
        family_name = COALESCE(EXCLUDED.family_name, person.family_name),
        attrs       = person.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at  = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.person WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert(
    _e164         text,
    _country_code integer DEFAULT NULL,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _e164 IS NULL THEN
        RAISE EXCEPTION 'phone_upsert requires non-NULL e164';
    END IF;

    INSERT INTO public.phone (
        e164, country_code, attrs
    ) VALUES (
        _e164, _country_code, _attrs
    )
    ON CONFLICT (e164) DO UPDATE
    SET
        country_code = COALESCE(EXCLUDED.country_code, phone.country_code),
        attrs        = phone.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.phone WHERE e164 = _e164;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert(
    _unique_id    text,
    _product_name text,
    _product_type text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _product_name IS NULL OR _product_type IS NULL THEN
        RAISE EXCEPTION 'product_upsert requires non-NULL unique_id, product_name, and product_type';
    END IF;

    INSERT INTO public.product (
        unique_id, product_name, product_type, attrs
    ) VALUES (
        _unique_id, _product_name, _product_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        product_name = COALESCE(EXCLUDED.product_name, product.product_name),
        product_type = COALESCE(EXCLUDED.product_type, product.product_type),
        attrs        = product.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.product WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert(
    _release_name text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _release_name IS NULL THEN
        RAISE EXCEPTION 'productrelease_upsert requires non-NULL release_name';
    END IF;

    INSERT INTO public.productrelease (
        release_name, attrs
    ) VALUES (
        _release_name, _attrs
    )
    ON CONFLICT (release_name) DO UPDATE
    SET
        attrs        = productrelease.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.productrelease WHERE release_name = _release_name;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert(
    _unique_id    text,
    _service_type text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _service_type IS NULL THEN
        RAISE EXCEPTION 'service_upsert requires non-NULL unique_id and service_type';
    END IF;

    INSERT INTO public.service (
        unique_id, service_type, attrs
    ) VALUES (
        _unique_id, _service_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        service_type = COALESCE(EXCLUDED.service_type,  service.service_type),
        attrs        = service.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.service WHERE unique_id = _unique_id;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number       text,
    _subject_common_name text,
    _attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL serial_number';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, COALESCE(_subject_common_name, ''), _attrs
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        subject_common_name = COALESCE(NULLIF(EXCLUDED.subject_common_name, ''), tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.tlscertificate WHERE serial_number = _serial_number;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert(
    _raw_url text,
    _scheme  text DEFAULT NULL,
    _attrs   jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _raw_url IS NULL OR _scheme IS NULL OR NOT (_attrs ? 'host') THEN
        RAISE EXCEPTION 'url_upsert requires non-NULL raw_url and scheme and host';
    END IF;

    INSERT INTO public.url (
        raw_url, scheme, attrs
    ) VALUES (
        _raw_url, _scheme, _attrs
    )
    ON CONFLICT (raw_url) DO UPDATE
    SET
        scheme     = COALESCE(EXCLUDED.scheme, url.scheme),
        attrs      = url.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    -- the touch guard kept the row unchanged: return its id
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM public.url WHERE raw_url = _raw_url;
    END IF;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd


-- --- Touch guards on every table that records when a row was last seen --------
-- +migrate StatementBegin
DO $do$
DECLARE
    t      record;
    v_args text;
BEGIN
    FOR t IN
        SELECT c.relname,
               (SELECT string_agg(quote_literal('{' || a.attname || '}'), ', ')
                FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attgenerated <> '' AND NOT a.attisdropped) AS gen
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'updated_at'
                      AND NOT a.attisdropped)
    LOOP
        v_args := t.gen;
        IF t.relname IN ('edge', 'entity_tag') THEN
            v_args := concat_ws(', ', v_args, quote_literal('{content,header,ttl}'));
        END IF;
        EXECUTE format('CREATE TRIGGER touch_guard BEFORE UPDATE ON public.%I FOR EACH ROW '
                       'EXECUTE FUNCTION public.touch_guard(%s)', t.relname, COALESCE(v_args, ''));
    END LOOP;
END
$do$;
-- +migrate StatementEnd

-- +migrate Down

-- +migrate StatementBegin
DO $do$
DECLARE
    t record;
BEGIN
    FOR t IN SELECT tgrelid::regclass AS rel FROM pg_trigger WHERE tgname = 'touch_guard' LOOP
        EXECUTE format('DROP TRIGGER touch_guard ON %s', t.rel);
    END LOOP;
END
$do$;
-- +migrate StatementEnd

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

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.account_upsert(
    _unique_id      text,
    _account_type   text,
    _username       text DEFAULT NULL,
    _account_number text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _account_type IS NULL THEN
        RAISE EXCEPTION 'account_upsert requires non-NULL unique_id and account_type';
    END IF;

    INSERT INTO public.account (
        unique_id, account_type, username, account_number, attrs
    ) VALUES (
        _unique_id, _account_type, _username, _account_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        account_type   = COALESCE(EXCLUDED.account_type,   account.account_type),
        username       = COALESCE(EXCLUDED.username,       account.username),
        account_number = COALESCE(EXCLUDED.account_number, account.account_number),
        attrs          = account.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at     = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.autonomoussystem_upsert(
    _asn   integer,
    _attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _asn IS NULL THEN
        RAISE EXCEPTION 'autonomoussystem_upsert requires non-NULL asn';
    END IF;

    INSERT INTO public.autonomoussystem (
        asn, attrs
    ) VALUES (
        _asn, _attrs
    )
    ON CONFLICT (asn) DO UPDATE
    SET
        attrs      = autonomoussystem.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.contactrecord_upsert(
    _discovered_at text,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _discovered_at IS NULL THEN
        RAISE EXCEPTION 'contactrecord_upsert requires non-NULL discovered_at';
    END IF;

    INSERT INTO public.contactrecord (
        discovered_at, attrs
    ) VALUES (
        _discovered_at, _attrs
    )
    ON CONFLICT (discovered_at) DO UPDATE
    SET
        attrs      = contactrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.domainrecord_upsert(
    _domain         text,
    _record_name    text,
    _punycode       text DEFAULT NULL,
    _extension      text DEFAULT NULL,
    _whois_server   citext DEFAULT NULL,
    _object_id      text DEFAULT NULL,
    _attrs          jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _domain IS NULL THEN
        RAISE EXCEPTION 'domainrecord_upsert requires non-NULL domain';
    END IF;

    INSERT INTO public.domainrecord (
        domain, record_name, punycode, extension, whois_server, object_id, attrs
    ) VALUES (
        _domain, _record_name, _punycode, _extension, _whois_server, _object_id, _attrs
    )
    ON CONFLICT (domain) DO UPDATE
    SET
        record_name     = COALESCE(EXCLUDED.record_name,  domainrecord.record_name),
        punycode        = COALESCE(EXCLUDED.punycode,     domainrecord.punycode),
        extension       = COALESCE(EXCLUDED.extension,    domainrecord.extension),
        whois_server    = COALESCE(EXCLUDED.whois_server, domainrecord.whois_server),
        object_id       = COALESCE(EXCLUDED.object_id,    domainrecord.object_id),
        attrs           = domainrecord.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.file_upsert(
    _file_url  text,
    _basename  text DEFAULT NULL,
    _file_type text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _file_url IS NULL THEN
        RAISE EXCEPTION 'file_upsert requires non-NULL file_url';
    END IF;

    INSERT INTO public.file (
        file_url, basename, file_type, attrs
    ) VALUES (
        _file_url, _basename, _file_type, _attrs
    )
    ON CONFLICT (file_url) DO UPDATE
    SET
        basename   = COALESCE(EXCLUDED.basename,  file.basename),
        file_type  = COALESCE(EXCLUDED.file_type, file.file_type),
        attrs      = file.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fqdn_upsert(
    _fqdn  text,
    _attrs jsonb DEFAULT '{}'::jsonb
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
        fqdn, attrs
    ) VALUES (
        lower(_fqdn)::citext, _attrs
    )
    ON CONFLICT (fqdn) DO UPDATE
    SET
        attrs      = fqdn.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.fundstransfer_upsert(
    _unique_id        text,
    _amount           numeric,
    _reference_number text DEFAULT NULL,
    _attrs            jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _amount IS NULL THEN
        RAISE EXCEPTION 'fundstransfer_upsert requires non-NULL unique_id and amount';
    END IF;

    INSERT INTO public.fundstransfer (
        unique_id, amount, reference_number, attrs
    ) VALUES (
        _unique_id, _amount, _reference_number, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        amount           = EXCLUDED.amount,
        reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
        attrs            = fundstransfer.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at       = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.identifier_upsert(
    _unique_id text,
    _id_value  text,
    _id_type   text DEFAULT NULL,
    _attrs     jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _id_value IS NULL OR _id_type IS NULL THEN
        RAISE EXCEPTION 'identifier_upsert requires non-NULL unique_id, id_value, and id_type';
    END IF;

    INSERT INTO public.identifier (
        unique_id, id_value, id_type, attrs
    ) VALUES (
        _unique_id, _id_value, _id_type, _attrs
    )
    ON CONFLICT (id_value, id_type) DO UPDATE
    SET
        unique_id  = EXCLUDED.unique_id,
        attrs      = identifier.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.ipaddress_upsert(
    _ip_address inet,
    _attrs      jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _ip_address IS NULL THEN
        RAISE EXCEPTION 'ipaddress_upsert requires non-NULL ip_address';
    END IF;
    IF NOT (_attrs ? 'type') THEN
        RAISE EXCEPTION 'ipaddress_upsert requires attrs to contain key "type"';
    END IF;

    INSERT INTO public.ipaddress (
        ip_address, attrs
    ) VALUES (
        _ip_address, _attrs
    )
    ON CONFLICT (ip_address) DO UPDATE
    SET
        attrs      = ipaddress.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
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

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.netblock_upsert(
    _netblock_cidr cidr,
    _attrs         jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _netblock_cidr IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL netblock_cidr';
    END IF;
    IF NOT (_attrs ? 'type') OR (_attrs->>'type') IS NULL THEN
        RAISE EXCEPTION 'netblock_upsert requires non-NULL ip_version';
    END IF;

    INSERT INTO public.netblock (
        netblock_cidr, attrs
    ) VALUES (
        _netblock_cidr, _attrs
    )
    ON CONFLICT (netblock_cidr) DO UPDATE
    SET
        attrs      = netblock.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.organization_upsert(
    _unique_id       text,
    _org_name        text,
    _legal_name      text DEFAULT NULL,
    _jurisdiction    text DEFAULT NULL,
    _registration_id text DEFAULT NULL,
    _attrs           jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _org_name IS NULL THEN
        RAISE EXCEPTION 'organization_upsert requires non-NULL unique_id and org_name';
    END IF;

    INSERT INTO public.organization (
        unique_id, org_name, legal_name, jurisdiction, registration_id, attrs
    ) VALUES (
        _unique_id, _org_name, _legal_name, _jurisdiction, _registration_id, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        org_name        = COALESCE(EXCLUDED.org_name,        organization.org_name),
        legal_name      = COALESCE(EXCLUDED.legal_name,      organization.legal_name),
        jurisdiction    = COALESCE(EXCLUDED.jurisdiction,    organization.jurisdiction),
        registration_id = COALESCE(EXCLUDED.registration_id, organization.registration_id),
        attrs           = organization.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at      = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.person_upsert(
    _unique_id   text,
    _full_name   text DEFAULT NULL,
    _first_name  text DEFAULT NULL,
    _family_name text DEFAULT NULL,
    _attrs       jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL THEN
        RAISE EXCEPTION 'person_upsert requires non-NULL unique_id';
    END IF;

    INSERT INTO public.person (
        unique_id, full_name, first_name, family_name, attrs
    ) VALUES (
        _unique_id, _full_name, _first_name, _family_name, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
        first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
        family_name = COALESCE(EXCLUDED.family_name, person.family_name),
        attrs       = person.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at  = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.phone_upsert(
    _e164         text,
    _country_code integer DEFAULT NULL,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _e164 IS NULL THEN
        RAISE EXCEPTION 'phone_upsert requires non-NULL e164';
    END IF;

    INSERT INTO public.phone (
        e164, country_code, attrs
    ) VALUES (
        _e164, _country_code, _attrs
    )
    ON CONFLICT (e164) DO UPDATE
    SET
        country_code = COALESCE(EXCLUDED.country_code, phone.country_code),
        attrs        = phone.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.product_upsert(
    _unique_id    text,
    _product_name text,
    _product_type text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _product_name IS NULL OR _product_type IS NULL THEN
        RAISE EXCEPTION 'product_upsert requires non-NULL unique_id, product_name, and product_type';
    END IF;

    INSERT INTO public.product (
        unique_id, product_name, product_type, attrs
    ) VALUES (
        _unique_id, _product_name, _product_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        product_name = COALESCE(EXCLUDED.product_name, product.product_name),
        product_type = COALESCE(EXCLUDED.product_type, product.product_type),
        attrs        = product.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.productrelease_upsert(
    _release_name text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _release_name IS NULL THEN
        RAISE EXCEPTION 'productrelease_upsert requires non-NULL release_name';
    END IF;

    INSERT INTO public.productrelease (
        release_name, attrs
    ) VALUES (
        _release_name, _attrs
    )
    ON CONFLICT (release_name) DO UPDATE
    SET
        attrs        = productrelease.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.service_upsert(
    _unique_id    text,
    _service_type text,
    _attrs        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _unique_id IS NULL OR _service_type IS NULL THEN
        RAISE EXCEPTION 'service_upsert requires non-NULL unique_id and service_type';
    END IF;

    INSERT INTO public.service (
        unique_id, service_type, attrs
    ) VALUES (
        _unique_id, _service_type, _attrs
    )
    ON CONFLICT (unique_id) DO UPDATE
    SET
        service_type = COALESCE(EXCLUDED.service_type,  service.service_type),
        attrs        = service.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at   = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.tlscertificate_upsert(
    _serial_number       text,
    _subject_common_name text,
    _attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _serial_number IS NULL THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL serial_number';
    END IF;

    IF NOT (_attrs ? 'not_before') OR NOT (_attrs ? 'not_after') THEN
        RAISE EXCEPTION 'tlscertificate_upsert requires non-NULL not_before and not_after';
    END IF;

    INSERT INTO public.tlscertificate (
        serial_number, subject_common_name, attrs
    ) VALUES (
        _serial_number, COALESCE(_subject_common_name, ''), _attrs
    )
    ON CONFLICT (serial_number) DO UPDATE
    SET
        subject_common_name = COALESCE(NULLIF(EXCLUDED.subject_common_name, ''), tlscertificate.subject_common_name),
        attrs               = tlscertificate.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at          = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION public.url_upsert(
    _raw_url text,
    _scheme  text DEFAULT NULL,
    _attrs   jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_id bigint;
BEGIN
    IF _raw_url IS NULL OR _scheme IS NULL OR NOT (_attrs ? 'host') THEN
        RAISE EXCEPTION 'url_upsert requires non-NULL raw_url and scheme and host';
    END IF;

    INSERT INTO public.url (
        raw_url, scheme, attrs
    ) VALUES (
        _raw_url, _scheme, _attrs
    )
    ON CONFLICT (raw_url) DO UPDATE
    SET
        scheme     = COALESCE(EXCLUDED.scheme, url.scheme),
        attrs      = url.attrs || COALESCE(EXCLUDED.attrs, '{}'::jsonb),
        updated_at = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END
$fn$;
-- +migrate StatementEnd


ALTER TABLE public.entity RESET (fillfactor);
ALTER TABLE public.edge RESET (fillfactor);
ALTER TABLE public.entity_tag RESET (fillfactor);
ALTER TABLE public.edge_tag RESET (fillfactor);

DROP INDEX IF EXISTS public.edge_tag_identity_uidx;
DROP INDEX IF EXISTS public.entity_tag_value_idx;
DROP INDEX IF EXISTS public.entity_tag_identity_uidx;
DROP INDEX IF EXISTS public.edge_to_label_idx;
DROP INDEX IF EXISTS public.edge_identity_uidx;
ALTER TABLE public.entity DROP CONSTRAINT IF EXISTS entity_row_id_etype_id_key;

-- source tags hold their confidence again; duplicates merged by Up stay merged
UPDATE public.entity_tag SET property_value = COALESCE(content->>'confidence', '')
WHERE ttype_id = (SELECT id FROM public.tag_type_lu WHERE name = 'sourceproperty');
UPDATE public.edge_tag SET property_value = COALESCE(content->>'confidence', '')
WHERE ttype_id = (SELECT id FROM public.tag_type_lu WHERE name = 'sourceproperty');

ALTER TABLE public.entity ADD CONSTRAINT entity_etype_id_row_id_key UNIQUE (etype_id, row_id);
ALTER TABLE public.entity ADD CONSTRAINT entity_table_name_row_id_key UNIQUE (table_name, row_id);
ALTER TABLE public.edge ADD CONSTRAINT edge_etype_id_from_entity_id_to_entity_id_label_key
  UNIQUE (etype_id, from_entity_id, to_entity_id, label);
ALTER TABLE public.entity_tag ADD CONSTRAINT entity_tag_entity_id_ttype_id_property_name_property_value_key
  UNIQUE (entity_id, ttype_id, property_name, property_value);
ALTER TABLE public.edge_tag ADD CONSTRAINT edge_tag_edge_id_ttype_id_property_name_property_value_key
  UNIQUE (edge_id, ttype_id, property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_entity_created_at ON public.entity USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_updated_at ON public.entity USING btree (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_created_at ON public.edge USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_updated_at ON public.edge USING btree (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_etype ON public.edge USING btree (etype_id);
CREATE INDEX IF NOT EXISTS gin_edge_content ON public.edge USING gin (content jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_edge_from_id ON public.edge USING btree (from_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_to_id ON public.edge USING btree (to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_from ON public.edge USING btree (from_entity_id, etype_id, to_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_to ON public.edge USING btree (to_entity_id, etype_id, from_entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_created_at ON public.entity_tag USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_updated_at ON public.entity_tag USING btree (updated_at);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_updated ON public.entity_tag USING btree (entity_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_entity_tag_entity_id ON public.entity_tag USING btree (entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_id ON public.entity_tag USING btree (ttype_id);
CREATE INDEX IF NOT EXISTS idx_entity_tag_property_name ON public.entity_tag USING btree (property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_tt_name ON public.entity_tag USING btree (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_entity_tag_property_name_value ON public.entity_tag USING btree (property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_entity_tag_ttype_name_value ON public.entity_tag USING btree (ttype_id, property_name, property_value);
CREATE INDEX IF NOT EXISTS gin_entity_tag_content ON public.entity_tag USING gin (content jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_edge_tag_created_at ON public.edge_tag USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_updated_at ON public.edge_tag USING btree (updated_at);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_updated ON public.edge_tag USING btree (edge_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_edge_tag_edge_id ON public.edge_tag USING btree (edge_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_id ON public.edge_tag USING btree (ttype_id);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name ON public.edge_tag USING btree (property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_tt_name ON public.edge_tag USING btree (ttype_id, property_name);
CREATE INDEX IF NOT EXISTS idx_edge_tag_property_name_value ON public.edge_tag USING btree (property_name, property_value);
CREATE INDEX IF NOT EXISTS idx_edge_tag_ttype_name_value ON public.edge_tag USING btree (ttype_id, property_name, property_value);
CREATE INDEX IF NOT EXISTS gin_edge_tag_content ON public.edge_tag USING gin (content jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_account_created_at ON public.account USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_autnumrecord_created_at ON public.autnumrecord USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_autonomoussystem_created_at ON public.autonomoussystem USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_contactrecord_created_at ON public.contactrecord USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_domainrecord_created_at ON public.domainrecord USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_file_created_at ON public.file USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_fqdn_created_at ON public.fqdn USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_fundstransfer_created_at ON public.fundstransfer USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_identifier_created_at ON public.identifier USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_ipaddress_created_at ON public.ipaddress USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_ipnetrecord_created_at ON public.ipnetrecord USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_location_created_at ON public.location USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_netblock_created_at ON public.netblock USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_organization_created_at ON public.organization USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_person_created_at ON public.person USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_phone_created_at ON public.phone USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_product_created_at ON public.product USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_productrelease_created_at ON public.productrelease USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_service_created_at ON public.service USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_tlscertificate_created_at ON public.tlscertificate USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_url_created_at ON public.url USING btree (created_at);

DROP FUNCTION IF EXISTS public.touch_guard();
DROP FUNCTION IF EXISTS public.edge_record_type(jsonb);
DROP FUNCTION IF EXISTS public.tag_stored_value(text, text);
DROP FUNCTION IF EXISTS public.tag_value_key(text);
DROP FUNCTION IF EXISTS public.touch_window();
