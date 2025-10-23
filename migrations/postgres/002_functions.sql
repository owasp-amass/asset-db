-- +migrate Up

-- ============================================================================
-- OWASP Amass: FUNCTIONS (PostgreSQL 13+)
-- - No-op-aware UPSERTs (avoid bloat)
-- - Helpers for type ids, entities/edges/tags
-- - Per-asset UPSERTs (return canonical entity_id)
-- ============================================================================

BEGIN;

-- --- Utility: null-safe attrs -----------------------------------------------
CREATE OR REPLACE FUNCTION public.null_safe_attrs(p jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT COALESCE(p, '{}'::jsonb)
$$;

-- --- Helpers to get (or create) type ids ------------------------------------
CREATE OR REPLACE FUNCTION public.get_entity_type_id(p_name text)
RETURNS smallint LANGUAGE plpgsql AS $$
DECLARE v_id smallint;
BEGIN
  SELECT id INTO v_id FROM public.entity_type_lu WHERE name = p_name;
  IF v_id IS NULL THEN
    INSERT INTO public.entity_type_lu(name) VALUES (p_name) RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END$$;

CREATE OR REPLACE FUNCTION public.get_edge_type_id(p_name text)
RETURNS smallint LANGUAGE plpgsql AS $$
DECLARE v_id smallint;
BEGIN
  SELECT id INTO v_id FROM public.edge_type_lu WHERE name = p_name;
  IF v_id IS NULL THEN
    INSERT INTO public.edge_type_lu(name) VALUES (p_name) RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END$$;

-- --- Core UPSERT helper: entity + ref (by type name) ------------------------
CREATE OR REPLACE FUNCTION public.upsert_entity_and_ref(
  p_type_name     text,
  p_display_value text,
  p_attrs         jsonb,
  p_table_name    text,
  p_row_id        integer
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  v_type_id smallint := public.get_entity_type_id(p_type_name);
  v_entity_id bigint;
BEGIN
  INSERT INTO public.entities(type_id, display_value, attrs)
  VALUES (v_type_id, p_display_value, COALESCE(p_attrs,'{}'::jsonb))
  ON CONFLICT (type_id, display_value)
  DO UPDATE SET
    attrs = CASE
              WHEN public.entities.attrs IS DISTINCT FROM public.entities.attrs || EXCLUDED.attrs
              THEN public.entities.attrs || EXCLUDED.attrs
              ELSE public.entities.attrs
            END,
    updated_at = CASE
                  WHEN public.entities.attrs IS DISTINCT FROM public.entities.attrs || EXCLUDED.attrs
                  THEN CURRENT_TIMESTAMP
                  ELSE public.entities.updated_at
                END
  WHERE public.entities.attrs IS DISTINCT FROM public.entities.attrs || EXCLUDED.attrs
  RETURNING entity_id INTO v_entity_id;

  IF v_entity_id IS NULL THEN
    SELECT entity_id INTO v_entity_id
    FROM public.entities
    WHERE type_id = v_type_id AND display_value = p_display_value;
  END IF;

  INSERT INTO public.entity_ref(entity_id, table_name, row_id)
  VALUES (v_entity_id, p_table_name, p_row_id)
  ON CONFLICT (table_name, row_id)
  DO UPDATE SET
    entity_id  = EXCLUDED.entity_id,
    updated_at = CURRENT_TIMESTAMP
  WHERE public.entity_ref.entity_id IS DISTINCT FROM EXCLUDED.entity_id;

  RETURN v_entity_id;
END$$;

-- --- Edge helper (no-op aware), type by name --------------------------------
CREATE OR REPLACE FUNCTION public.ensure_edge(
  p_etype_name     text,
  p_from_entity_id bigint,
  p_to_entity_id   bigint,
  p_content        jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  v_edge_id bigint;
  v_etype_id smallint := public.get_edge_type_id(p_etype_name);
BEGIN
  INSERT INTO public.edges(etype_id, from_entity_id, to_entity_id, content)
  VALUES (v_etype_id, p_from_entity_id, p_to_entity_id, COALESCE(p_content,'{}'::jsonb))
  ON CONFLICT (etype_id, from_entity_id, to_entity_id)
  DO UPDATE SET
    content = CASE
                WHEN public.edges.content IS DISTINCT FROM public.edges.content || EXCLUDED.content
                THEN public.edges.content || EXCLUDED.content
                ELSE public.edges.content
              END,
    updated_at = CASE
                   WHEN public.edges.content IS DISTINCT FROM public.edges.content || EXCLUDED.content
                   THEN CURRENT_TIMESTAMP
                   ELSE public.edges.updated_at
                 END
  WHERE public.edges.content IS DISTINCT FROM public.edges.content || EXCLUDED.content
  RETURNING edge_id INTO v_edge_id;

  IF v_edge_id IS NULL THEN
    SELECT edge_id INTO v_edge_id
    FROM public.edges
    WHERE etype_id = v_etype_id AND from_entity_id = p_from_entity_id AND to_entity_id = p_to_entity_id;
  END IF;

  RETURN v_edge_id;
END$$;

-- --- Tag helpers -------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.upsert_tag(
  p_namespace text,
  p_name      text,
  p_value     text DEFAULT NULL,
  p_meta      jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE v_tag_id bigint;
BEGIN
  INSERT INTO public.tags(namespace, name, value, meta)
  VALUES (COALESCE(p_namespace,'default'), p_name, p_value, COALESCE(p_meta,'{}'::jsonb))
  ON CONFLICT (namespace, name, COALESCE(value,'∅'))
  DO UPDATE SET
    meta = CASE
             WHEN public.tags.meta IS DISTINCT FROM public.tags.meta || EXCLUDED.meta
             THEN public.tags.meta || EXCLUDED.meta
             ELSE public.tags.meta
           END,
    updated_at = CASE
                   WHEN public.tags.meta IS DISTINCT FROM public.tags.meta || EXCLUDED.meta
                   THEN CURRENT_TIMESTAMP
                   ELSE public.tags.updated_at
                 END
  WHERE public.tags.meta IS DISTINCT FROM public.tags.meta || EXCLUDED.meta
  RETURNING tag_id INTO v_tag_id;

  IF v_tag_id IS NULL THEN
    SELECT tag_id INTO v_tag_id
    FROM public.tags
    WHERE namespace = COALESCE(p_namespace,'default')
      AND name = p_name
      AND COALESCE(value,'∅') = COALESCE(p_value,'∅');
  END IF;

  RETURN v_tag_id;
END$$;

CREATE OR REPLACE FUNCTION public.tag_entity(
  p_entity_id bigint,
  p_namespace text,
  p_name      text,
  p_value     text DEFAULT NULL,
  p_details   jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE v_tag_id bigint; v_id bigint;
BEGIN
  v_tag_id := public.upsert_tag(p_namespace, p_name, p_value, '{}'::jsonb);

  INSERT INTO public.entity_tag_map(entity_id, tag_id, details)
  VALUES (p_entity_id, v_tag_id, COALESCE(p_details,'{}'::jsonb))
  ON CONFLICT (entity_id, tag_id)
  DO UPDATE SET
    details = CASE
                WHEN public.entity_tag_map.details IS DISTINCT FROM public.entity_tag_map.details || EXCLUDED.details
                THEN public.entity_tag_map.details || EXCLUDED.details
                ELSE public.entity_tag_map.details
              END,
    updated_at = CASE
                   WHEN public.entity_tag_map.details IS DISTINCT FROM public.entity_tag_map.details || EXCLUDED.details
                   THEN CURRENT_TIMESTAMP
                   ELSE public.entity_tag_map.updated_at
                 END
  WHERE public.entity_tag_map.details IS DISTINCT FROM public.entity_tag_map.details || EXCLUDED.details
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT id INTO v_id FROM public.entity_tag_map WHERE entity_id = p_entity_id AND tag_id = v_tag_id;
  END IF;

  RETURN v_id;
END$$;

CREATE OR REPLACE FUNCTION public.tag_edge(
  p_edge_id  bigint,
  p_namespace text,
  p_name      text,
  p_value     text DEFAULT NULL,
  p_details   jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE v_tag_id bigint; v_id bigint;
BEGIN
  v_tag_id := public.upsert_tag(p_namespace, p_name, p_value, '{}'::jsonb);

  INSERT INTO public.edge_tag_map(edge_id, tag_id, details)
  VALUES (p_edge_id, v_tag_id, COALESCE(p_details,'{}'::jsonb))
  ON CONFLICT (edge_id, tag_id)
  DO UPDATE SET
    details = CASE
                WHEN public.edge_tag_map.details IS DISTINCT FROM public.edge_tag_map.details || EXCLUDED.details
                THEN public.edge_tag_map.details || EXCLUDED.details
                ELSE public.edge_tag_map.details
              END,
    updated_at = CASE
                   WHEN public.edge_tag_map.details IS DISTINCT FROM public.edge_tag_map.details || EXCLUDED.details
                   THEN CURRENT_TIMESTAMP
                   ELSE public.edge_tag_map.updated_at
                 END
  WHERE public.edge_tag_map.details IS DISTINCT FROM public.edge_tag_map.details || EXCLUDED.details
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT id INTO v_id FROM public.edge_tag_map WHERE edge_id = p_edge_id AND tag_id = v_tag_id;
  END IF;

  RETURN v_id;
END$$;

-- --- Asset UPSERTs (no-op aware, return entity_id) --------------------------

-- Account
CREATE OR REPLACE FUNCTION public.upsert_account(
  p_unique_id text,
  p_account_type text,
  p_username text DEFAULT NULL,
  p_account_number text DEFAULT NULL,
  p_balance numeric DEFAULT NULL,
  p_active boolean DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.account(unique_id, account_type, username, account_number, balance, active)
  VALUES (p_unique_id, p_account_type, p_username, p_account_number, p_balance, p_active)
  ON CONFLICT (unique_id) DO UPDATE SET
    account_type   = COALESCE(EXCLUDED.account_type,   account.account_type),
    username       = COALESCE(EXCLUDED.username,       account.username),
    account_number = COALESCE(EXCLUDED.account_number, account.account_number),
    balance        = COALESCE(EXCLUDED.balance,        account.balance),
    active         = COALESCE(EXCLUDED.active,         account.active),
    updated_at     = CASE WHEN
        (EXCLUDED.account_type IS DISTINCT FROM account.account_type) OR
        (EXCLUDED.username     IS DISTINCT FROM account.username) OR
        (EXCLUDED.account_number IS DISTINCT FROM account.account_number) OR
        (EXCLUDED.balance      IS DISTINCT FROM account.balance) OR
        (EXCLUDED.active       IS DISTINCT FROM account.active)
      THEN CURRENT_TIMESTAMP ELSE account.updated_at END
  WHERE (EXCLUDED.account_type IS DISTINCT FROM account.account_type) OR
        (EXCLUDED.username     IS DISTINCT FROM account.username) OR
        (EXCLUDED.account_number IS DISTINCT FROM account.account_number) OR
        (EXCLUDED.balance      IS DISTINCT FROM account.balance) OR
        (EXCLUDED.active       IS DISTINCT FROM account.active)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.account WHERE unique_id = p_unique_id; END IF;

  v_entity_id := public.upsert_entity_and_ref('account', p_unique_id, public.null_safe_attrs(p_attrs), 'account', v_id);
  RETURN v_entity_id;
END$$;

-- Autnum Record
CREATE OR REPLACE FUNCTION public.upsert_autnumrecord(
  p_handle text,
  p_asn integer,
  p_record_name text DEFAULT NULL,
  p_record_status text DEFAULT NULL,
  p_created_date timestamp without time zone DEFAULT NULL,
  p_updated_date timestamp without time zone DEFAULT NULL,
  p_whois_server text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.autnumrecord(handle, asn, record_name, record_status, created_date, updated_date, whois_server)
  VALUES (p_handle, p_asn, p_record_name, p_record_status, p_created_date, p_updated_date, p_whois_server)
  ON CONFLICT (handle) DO UPDATE SET
    asn           = COALESCE(EXCLUDED.asn,           autnumrecord.asn),
    record_name   = COALESCE(EXCLUDED.record_name,   autnumrecord.record_name),
    record_status = COALESCE(EXCLUDED.record_status, autnumrecord.record_status),
    created_date  = COALESCE(EXCLUDED.created_date,  autnumrecord.created_date),
    updated_date  = COALESCE(EXCLUDED.updated_date,  autnumrecord.updated_date),
    whois_server  = COALESCE(EXCLUDED.whois_server,  autnumrecord.whois_server),
    updated_at    = CASE WHEN
      (EXCLUDED.asn IS DISTINCT FROM autnumrecord.asn) OR
      (EXCLUDED.record_name IS DISTINCT FROM autnumrecord.record_name) OR
      (EXCLUDED.record_status IS DISTINCT FROM autnumrecord.record_status) OR
      (EXCLUDED.created_date IS DISTINCT FROM autnumrecord.created_date) OR
      (EXCLUDED.updated_date IS DISTINCT FROM autnumrecord.updated_date) OR
      (EXCLUDED.whois_server IS DISTINCT FROM autnumrecord.whois_server)
    THEN CURRENT_TIMESTAMP ELSE autnumrecord.updated_at END
  WHERE (EXCLUDED.asn IS DISTINCT FROM autnumrecord.asn) OR
        (EXCLUDED.record_name IS DISTINCT FROM autnumrecord.record_name) OR
        (EXCLUDED.record_status IS DISTINCT FROM autnumrecord.record_status) OR
        (EXCLUDED.created_date IS DISTINCT FROM autnumrecord.created_date) OR
        (EXCLUDED.updated_date IS DISTINCT FROM autnumrecord.updated_date) OR
        (EXCLUDED.whois_server IS DISTINCT FROM autnumrecord.whois_server)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.autnumrecord WHERE handle = p_handle; END IF;

  v_entity_id := public.upsert_entity_and_ref('autnumrecord', p_handle, public.null_safe_attrs(p_attrs), 'autnumrecord', v_id);
  RETURN v_entity_id;
END$$;

-- Autonomous System
CREATE OR REPLACE FUNCTION public.upsert_autonomoussystem(
  p_asn integer,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint; v_disp text;
BEGIN
  INSERT INTO public.autonomoussystem(asn)
  VALUES (p_asn)
  ON CONFLICT (asn) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.autonomoussystem WHERE asn = p_asn; END IF;

  v_disp := 'AS' || p_asn::text;
  v_entity_id := public.upsert_entity_and_ref('autonomoussystem', v_disp, public.null_safe_attrs(p_attrs), 'autonomoussystem', v_id);
  RETURN v_entity_id;
END$$;

-- Contact Record
CREATE OR REPLACE FUNCTION public.upsert_contactrecord(
  p_discovered_at text,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.contactrecord(discovered_at)
  VALUES (p_discovered_at)
  ON CONFLICT (discovered_at) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.contactrecord WHERE discovered_at = p_discovered_at; END IF;

  v_entity_id := public.upsert_entity_and_ref('contactrecord', p_discovered_at, public.null_safe_attrs(p_attrs), 'contactrecord', v_id);
  RETURN v_entity_id;
END$$;

-- Domain Record
CREATE OR REPLACE FUNCTION public.upsert_domainrecord(
  p_domain citext,
  p_record_name text,
  p_raw_record text DEFAULT NULL,
  p_record_status text[] DEFAULT NULL,
  p_punycode text DEFAULT NULL,
  p_extension text DEFAULT NULL,
  p_created_date timestamp without time zone DEFAULT NULL,
  p_updated_date timestamp without time zone DEFAULT NULL,
  p_expiration_date timestamp without time zone DEFAULT NULL,
  p_whois_server text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.domainrecord(domain, record_name, raw_record, record_status, punycode, extension,
                                  created_date, updated_date, expiration_date, whois_server)
  VALUES (p_domain, p_record_name, p_raw_record, p_record_status, p_punycode, p_extension,
          p_created_date, p_updated_date, p_expiration_date, p_whois_server)
  ON CONFLICT (domain) DO UPDATE SET
    record_name    = COALESCE(EXCLUDED.record_name,    domainrecord.record_name),
    raw_record     = COALESCE(EXCLUDED.raw_record,     domainrecord.raw_record),
    record_status  = COALESCE(EXCLUDED.record_status,  domainrecord.record_status),
    punycode       = COALESCE(EXCLUDED.punycode,       domainrecord.punycode),
    extension      = COALESCE(EXCLUDED.extension,      domainrecord.extension),
    created_date   = COALESCE(EXCLUDED.created_date,   domainrecord.created_date),
    updated_date   = COALESCE(EXCLUDED.updated_date,   domainrecord.updated_date),
    expiration_date= COALESCE(EXCLUDED.expiration_date,domainrecord.expiration_date),
    whois_server   = COALESCE(EXCLUDED.whois_server,   domainrecord.whois_server),
    updated_at     = CASE WHEN
      (EXCLUDED.record_name IS DISTINCT FROM domainrecord.record_name) OR
      (EXCLUDED.raw_record IS DISTINCT FROM domainrecord.raw_record) OR
      (EXCLUDED.record_status IS DISTINCT FROM domainrecord.record_status) OR
      (EXCLUDED.punycode IS DISTINCT FROM domainrecord.punycode) OR
      (EXCLUDED.extension IS DISTINCT FROM domainrecord.extension) OR
      (EXCLUDED.created_date IS DISTINCT FROM domainrecord.created_date) OR
      (EXCLUDED.updated_date IS DISTINCT FROM domainrecord.updated_date) OR
      (EXCLUDED.expiration_date IS DISTINCT FROM domainrecord.expiration_date) OR
      (EXCLUDED.whois_server IS DISTINCT FROM domainrecord.whois_server)
    THEN CURRENT_TIMESTAMP ELSE domainrecord.updated_at END
  WHERE (EXCLUDED.record_name IS DISTINCT FROM domainrecord.record_name) OR
        (EXCLUDED.raw_record IS DISTINCT FROM domainrecord.raw_record) OR
        (EXCLUDED.record_status IS DISTINCT FROM domainrecord.record_status) OR
        (EXCLUDED.punycode IS DISTINCT FROM domainrecord.punycode) OR
        (EXCLUDED.extension IS DISTINCT FROM domainrecord.extension) OR
        (EXCLUDED.created_date IS DISTINCT FROM domainrecord.created_date) OR
        (EXCLUDED.updated_date IS DISTINCT FROM domainrecord.updated_date) OR
        (EXCLUDED.expiration_date IS DISTINCT FROM domainrecord.expiration_date) OR
        (EXCLUDED.whois_server IS DISTINCT FROM domainrecord.whois_server)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.domainrecord WHERE domain = p_domain; END IF;

  v_entity_id := public.upsert_entity_and_ref('domainrecord', p_domain::text, public.null_safe_attrs(p_attrs), 'domainrecord', v_id);
  RETURN v_entity_id;
END$$;

-- File
CREATE OR REPLACE FUNCTION public.upsert_file(
  p_file_url text,
  p_basename text DEFAULT NULL,
  p_file_type text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.file(file_url, basename, file_type)
  VALUES (p_file_url, p_basename, p_file_type)
  ON CONFLICT (file_url) DO UPDATE SET
    basename   = COALESCE(EXCLUDED.basename,  file.basename),
    file_type  = COALESCE(EXCLUDED.file_type, file.file_type),
    updated_at = CASE WHEN
      (EXCLUDED.basename IS DISTINCT FROM file.basename) OR
      (EXCLUDED.file_type IS DISTINCT FROM file.file_type)
    THEN CURRENT_TIMESTAMP ELSE file.updated_at END
  WHERE (EXCLUDED.basename IS DISTINCT FROM file.basename) OR
        (EXCLUDED.file_type IS DISTINCT FROM file.file_type)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.file WHERE file_url = p_file_url; END IF;

  v_entity_id := public.upsert_entity_and_ref('file', p_file_url, public.null_safe_attrs(p_attrs), 'file', v_id);
  RETURN v_entity_id;
END$$;

-- FQDN
CREATE OR REPLACE FUNCTION public.upsert_fqdn(
  p_fqdn citext,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.fqdn(fqdn)
  VALUES (p_fqdn)
  ON CONFLICT (fqdn) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.fqdn WHERE fqdn = p_fqdn; END IF;

  v_entity_id := public.upsert_entity_and_ref('fqdn', p_fqdn::text, public.null_safe_attrs(p_attrs), 'fqdn', v_id);
  RETURN v_entity_id;
END$$;

-- Funds Transfer
CREATE OR REPLACE FUNCTION public.upsert_fundstransfer(
  p_unique_id text,
  p_amount numeric,
  p_reference_number text DEFAULT NULL,
  p_currency text DEFAULT NULL,
  p_transfer_method text DEFAULT NULL,
  p_exchange_date timestamp without time zone DEFAULT NULL,
  p_exchange_rate numeric DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.fundstransfer(unique_id, amount, reference_number, currency, transfer_method,
                                   exchange_date, exchange_rate)
  VALUES (p_unique_id, p_amount, p_reference_number, p_currency, p_transfer_method,
          p_exchange_date, p_exchange_rate)
  ON CONFLICT (unique_id) DO UPDATE SET
    amount           = COALESCE(EXCLUDED.amount,           fundstransfer.amount),
    reference_number = COALESCE(EXCLUDED.reference_number, fundstransfer.reference_number),
    currency         = COALESCE(EXCLUDED.currency,         fundstransfer.currency),
    transfer_method  = COALESCE(EXCLUDED.transfer_method,  fundstransfer.transfer_method),
    exchange_date    = COALESCE(EXCLUDED.exchange_date,    fundstransfer.exchange_date),
    exchange_rate    = COALESCE(EXCLUDED.exchange_rate,    fundstransfer.exchange_rate),
    updated_at       = CASE WHEN
      (EXCLUDED.amount IS DISTINCT FROM fundstransfer.amount) OR
      (EXCLUDED.reference_number IS DISTINCT FROM fundstransfer.reference_number) OR
      (EXCLUDED.currency IS DISTINCT FROM fundstransfer.currency) OR
      (EXCLUDED.transfer_method IS DISTINCT FROM fundstransfer.transfer_method) OR
      (EXCLUDED.exchange_date IS DISTINCT FROM fundstransfer.exchange_date) OR
      (EXCLUDED.exchange_rate IS DISTINCT FROM fundstransfer.exchange_rate)
    THEN CURRENT_TIMESTAMP ELSE fundstransfer.updated_at END
  WHERE (EXCLUDED.amount IS DISTINCT FROM fundstransfer.amount) OR
        (EXCLUDED.reference_number IS DISTINCT FROM fundstransfer.reference_number) OR
        (EXCLUDED.currency IS DISTINCT FROM fundstransfer.currency) OR
        (EXCLUDED.transfer_method IS DISTINCT FROM fundstransfer.transfer_method) OR
        (EXCLUDED.exchange_date IS DISTINCT FROM fundstransfer.exchange_date) OR
        (EXCLUDED.exchange_rate IS DISTINCT FROM fundstransfer.exchange_rate)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.fundstransfer WHERE unique_id = p_unique_id; END IF;

  v_entity_id := public.upsert_entity_and_ref('fundstransfer', p_unique_id, public.null_safe_attrs(p_attrs), 'fundstransfer', v_id);
  RETURN v_entity_id;
END$$;

-- Identifier
CREATE OR REPLACE FUNCTION public.upsert_identifier(
  p_id_type text,
  p_unique_id text,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.identifier(id_type, unique_id)
  VALUES (p_id_type, p_unique_id)
  ON CONFLICT (unique_id) DO UPDATE SET
    id_type = COALESCE(EXCLUDED.id_type, identifier.id_type),
    updated_at = CASE WHEN (EXCLUDED.id_type IS DISTINCT FROM identifier.id_type)
                THEN CURRENT_TIMESTAMP ELSE identifier.updated_at END
  WHERE (EXCLUDED.id_type IS DISTINCT FROM identifier.id_type)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.identifier WHERE unique_id = p_unique_id; END IF;

  v_entity_id := public.upsert_entity_and_ref('identifier', p_unique_id, public.null_safe_attrs(p_attrs), 'identifier', v_id);
  RETURN v_entity_id;
END$$;

-- IP Address
CREATE OR REPLACE FUNCTION public.upsert_ipaddress(
  p_ip_version text,
  p_ip_address inet,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.ipaddress(ip_version, ip_address)
  VALUES (p_ip_version, p_ip_address)
  ON CONFLICT (ip_address) DO UPDATE SET
    ip_version = COALESCE(EXCLUDED.ip_version, ipaddress.ip_version),
    updated_at = CASE WHEN (EXCLUDED.ip_version IS DISTINCT FROM ipaddress.ip_version)
                THEN CURRENT_TIMESTAMP ELSE ipaddress.updated_at END
  WHERE (EXCLUDED.ip_version IS DISTINCT FROM ipaddress.ip_version)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.ipaddress WHERE ip_address = p_ip_address; END IF;

  v_entity_id := public.upsert_entity_and_ref('ipaddress', p_ip_address::text, public.null_safe_attrs(p_attrs), 'ipaddress', v_id);
  RETURN v_entity_id;
END$$;

-- IP Network Record
CREATE OR REPLACE FUNCTION public.upsert_ipnetrecord(
  p_record_cidr cidr,
  p_record_name text,
  p_ip_version text,
  p_handle text,
  p_method text DEFAULT NULL,
  p_record_status text[] DEFAULT NULL,
  p_created_date timestamp without time zone DEFAULT NULL,
  p_updated_date timestamp without time zone DEFAULT NULL,
  p_whois_server text DEFAULT NULL,
  p_parent_handle text DEFAULT NULL,
  p_start_address inet DEFAULT NULL,
  p_end_address inet DEFAULT NULL,
  p_country text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.ipnetrecord(
    record_cidr, record_name, ip_version, handle, method, record_status,
    created_date, updated_date, whois_server, parent_handle, start_address, end_address, country
  ) VALUES (
    p_record_cidr, p_record_name, p_ip_version, p_handle, p_method, p_record_status,
    p_created_date, p_updated_date, p_whois_server, p_parent_handle, p_start_address, p_end_address, p_country
  )
  ON CONFLICT (record_cidr) DO UPDATE SET
    record_name   = COALESCE(EXCLUDED.record_name,   ipnetrecord.record_name),
    ip_version    = COALESCE(EXCLUDED.ip_version,    ipnetrecord.ip_version),
    handle        = COALESCE(EXCLUDED.handle,        ipnetrecord.handle),
    method        = COALESCE(EXCLUDED.method,        ipnetrecord.method),
    record_status = COALESCE(EXCLUDED.record_status, ipnetrecord.record_status),
    created_date  = COALESCE(EXCLUDED.created_date,  ipnetrecord.created_date),
    updated_date  = COALESCE(EXCLUDED.updated_date,  ipnetrecord.updated_date),
    whois_server  = COALESCE(EXCLUDED.whois_server,  ipnetrecord.whois_server),
    parent_handle = COALESCE(EXCLUDED.parent_handle, ipnetrecord.parent_handle),
    start_address = COALESCE(EXCLUDED.start_address, ipnetrecord.start_address),
    end_address   = COALESCE(EXCLUDED.end_address,   ipnetrecord.end_address),
    country       = COALESCE(EXCLUDED.country,       ipnetrecord.country),
    updated_at    = CASE WHEN
      (EXCLUDED.record_name IS DISTINCT FROM ipnetrecord.record_name) OR
      (EXCLUDED.ip_version  IS DISTINCT FROM ipnetrecord.ip_version)  OR
      (EXCLUDED.handle      IS DISTINCT FROM ipnetrecord.handle)      OR
      (EXCLUDED.method      IS DISTINCT FROM ipnetrecord.method)      OR
      (EXCLUDED.record_status IS DISTINCT FROM ipnetrecord.record_status) OR
      (EXCLUDED.created_date IS DISTINCT FROM ipnetrecord.created_date) OR
      (EXCLUDED.updated_date IS DISTINCT FROM ipnetrecord.updated_date) OR
      (EXCLUDED.whois_server IS DISTINCT FROM ipnetrecord.whois_server) OR
      (EXCLUDED.parent_handle IS DISTINCT FROM ipnetrecord.parent_handle) OR
      (EXCLUDED.start_address IS DISTINCT FROM ipnetrecord.start_address) OR
      (EXCLUDED.end_address IS DISTINCT FROM ipnetrecord.end_address) OR
      (EXCLUDED.country IS DISTINCT FROM ipnetrecord.country)
    THEN CURRENT_TIMESTAMP ELSE ipnetrecord.updated_at END
  WHERE (EXCLUDED.record_name IS DISTINCT FROM ipnetrecord.record_name) OR
        (EXCLUDED.ip_version  IS DISTINCT FROM ipnetrecord.ip_version)  OR
        (EXCLUDED.handle      IS DISTINCT FROM ipnetrecord.handle)      OR
        (EXCLUDED.method      IS DISTINCT FROM ipnetrecord.method)      OR
        (EXCLUDED.record_status IS DISTINCT FROM ipnetrecord.record_status) OR
        (EXCLUDED.created_date IS DISTINCT FROM ipnetrecord.created_date) OR
        (EXCLUDED.updated_date IS DISTINCT FROM ipnetrecord.updated_date) OR
        (EXCLUDED.whois_server IS DISTINCT FROM ipnetrecord.whois_server) OR
        (EXCLUDED.parent_handle IS DISTINCT FROM ipnetrecord.parent_handle) OR
        (EXCLUDED.start_address IS DISTINCT FROM ipnetrecord.start_address) OR
        (EXCLUDED.end_address IS DISTINCT FROM ipnetrecord.end_address) OR
        (EXCLUDED.country IS DISTINCT FROM ipnetrecord.country)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT id INTO v_id FROM public.ipnetrecord WHERE record_cidr = p_record_cidr OR handle = p_handle LIMIT 1;
  END IF;

  v_entity_id := public.upsert_entity_and_ref('ipnetrecord', p_record_cidr::text, public.null_safe_attrs(p_attrs), 'ipnetrecord', v_id);
  RETURN v_entity_id;
END$$;

-- Location
CREATE OR REPLACE FUNCTION public.upsert_location(
  p_city text,
  p_street_address text,
  p_country text,
  p_unit text DEFAULT NULL,
  p_building text DEFAULT NULL,
  p_province text DEFAULT NULL,
  p_locality text DEFAULT NULL,
  p_postal_code text DEFAULT NULL,
  p_street_name text DEFAULT NULL,
  p_building_number text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.location(city, street_address, country, unit, building, province,
                              locality, postal_code, street_name, building_number)
  VALUES (p_city, p_street_address, p_country, p_unit, p_building, p_province,
          p_locality, p_postal_code, p_street_name, p_building_number)
  ON CONFLICT (street_address) DO UPDATE SET
    city            = COALESCE(EXCLUDED.city,            location.city),
    country         = COALESCE(EXCLUDED.country,         location.country),
    unit            = COALESCE(EXCLUDED.unit,            location.unit),
    building        = COALESCE(EXCLUDED.building,        location.building),
    province        = COALESCE(EXCLUDED.province,        location.province),
    locality        = COALESCE(EXCLUDED.locality,        location.locality),
    postal_code     = COALESCE(EXCLUDED.postal_code,     location.postal_code),
    street_name     = COALESCE(EXCLUDED.street_name,     location.street_name),
    building_number = COALESCE(EXCLUDED.building_number, location.building_number),
    updated_at      = CASE WHEN
      (EXCLUDED.city IS DISTINCT FROM location.city) OR
      (EXCLUDED.country IS DISTINCT FROM location.country) OR
      (EXCLUDED.unit IS DISTINCT FROM location.unit) OR
      (EXCLUDED.building IS DISTINCT FROM location.building) OR
      (EXCLUDED.province IS DISTINCT FROM location.province) OR
      (EXCLUDED.locality IS DISTINCT FROM location.locality) OR
      (EXCLUDED.postal_code IS DISTINCT FROM location.postal_code) OR
      (EXCLUDED.street_name IS DISTINCT FROM location.street_name) OR
      (EXCLUDED.building_number IS DISTINCT FROM location.building_number)
    THEN CURRENT_TIMESTAMP ELSE location.updated_at END
  WHERE (EXCLUDED.city IS DISTINCT FROM location.city) OR
        (EXCLUDED.country IS DISTINCT FROM location.country) OR
        (EXCLUDED.unit IS DISTINCT FROM location.unit) OR
        (EXCLUDED.building IS DISTINCT FROM location.building) OR
        (EXCLUDED.province IS DISTINCT FROM location.province) OR
        (EXCLUDED.locality IS DISTINCT FROM location.locality) OR
        (EXCLUDED.postal_code IS DISTINCT FROM location.postal_code) OR
        (EXCLUDED.street_name IS DISTINCT FROM location.street_name) OR
        (EXCLUDED.building_number IS DISTINCT FROM location.building_number)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.location WHERE street_address = p_street_address; END IF;

  v_entity_id := public.upsert_entity_and_ref('location', p_street_address, public.null_safe_attrs(p_attrs), 'location', v_id);
  RETURN v_entity_id;
END$$;

-- Netblock
CREATE OR REPLACE FUNCTION public.upsert_netblock(
  p_netblock_cidr cidr,
  p_ip_version text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.netblock(netblock_cidr, ip_version)
  VALUES (p_netblock_cidr, p_ip_version)
  ON CONFLICT (netblock_cidr) DO UPDATE SET
    ip_version = COALESCE(EXCLUDED.ip_version, netblock.ip_version),
    updated_at = CASE WHEN (EXCLUDED.ip_version IS DISTINCT FROM netblock.ip_version)
                THEN CURRENT_TIMESTAMP ELSE netblock.updated_at END
  WHERE (EXCLUDED.ip_version IS DISTINCT FROM netblock.ip_version)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.netblock WHERE netblock_cidr = p_netblock_cidr; END IF;

  v_entity_id := public.upsert_entity_and_ref('netblock', p_netblock_cidr::text, public.null_safe_attrs(p_attrs), 'netblock', v_id);
  RETURN v_entity_id;
END$$;

-- Organization
CREATE OR REPLACE FUNCTION public.upsert_organization(
  p_unique_id text,
  p_legal_name text,
  p_org_name text DEFAULT NULL,
  p_active boolean DEFAULT NULL,
  p_jurisdiction text DEFAULT NULL,
  p_founding_date timestamp without time zone DEFAULT NULL,
  p_registration_id text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint; v_display text;
BEGIN
  INSERT INTO public.organization(unique_id, legal_name, org_name, active, jurisdiction, founding_date, registration_id)
  VALUES (p_unique_id, p_legal_name, p_org_name, p_active, p_jurisdiction, p_founding_date, p_registration_id)
  ON CONFLICT (unique_id) DO UPDATE SET
    legal_name     = COALESCE(EXCLUDED.legal_name,     organization.legal_name),
    org_name       = COALESCE(EXCLUDED.org_name,       organization.org_name),
    active         = COALESCE(EXCLUDED.active,         organization.active),
    jurisdiction   = COALESCE(EXCLUDED.jurisdiction,   organization.jurisdiction),
    founding_date  = COALESCE(EXCLUDED.founding_date,  organization.founding_date),
    registration_id= COALESCE(EXCLUDED.registration_id,organization.registration_id),
    updated_at     = CASE WHEN
      (EXCLUDED.legal_name IS DISTINCT FROM organization.legal_name) OR
      (EXCLUDED.org_name IS DISTINCT FROM organization.org_name) OR
      (EXCLUDED.active IS DISTINCT FROM organization.active) OR
      (EXCLUDED.jurisdiction IS DISTINCT FROM organization.jurisdiction) OR
      (EXCLUDED.founding_date IS DISTINCT FROM organization.founding_date) OR
      (EXCLUDED.registration_id IS DISTINCT FROM organization.registration_id)
    THEN CURRENT_TIMESTAMP ELSE organization.updated_at END
  WHERE (EXCLUDED.legal_name IS DISTINCT FROM organization.legal_name) OR
        (EXCLUDED.org_name IS DISTINCT FROM organization.org_name) OR
        (EXCLUDED.active IS DISTINCT FROM organization.active) OR
        (EXCLUDED.jurisdiction IS DISTINCT FROM organization.jurisdiction) OR
        (EXCLUDED.founding_date IS DISTINCT FROM organization.founding_date) OR
        (EXCLUDED.registration_id IS DISTINCT FROM organization.registration_id)
  RETURNING id, legal_name INTO v_id, v_display;

  IF v_id IS NULL THEN SELECT id, legal_name INTO v_id, v_display FROM public.organization WHERE unique_id = p_unique_id; END IF;

  v_display := COALESCE(v_display, p_unique_id);
  v_entity_id := public.upsert_entity_and_ref('organization', v_display, public.null_safe_attrs(p_attrs), 'organization', v_id);
  RETURN v_entity_id;
END$$;

-- Person
CREATE OR REPLACE FUNCTION public.upsert_person(
  p_unique_id text,
  p_full_name text DEFAULT NULL,
  p_first_name text DEFAULT NULL,
  p_family_name text DEFAULT NULL,
  p_middle_name text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint; v_display text;
BEGIN
  INSERT INTO public.person(unique_id, full_name, first_name, family_name, middle_name)
  VALUES (p_unique_id, p_full_name, p_first_name, p_family_name, p_middle_name)
  ON CONFLICT (unique_id) DO UPDATE SET
    full_name   = COALESCE(EXCLUDED.full_name,   person.full_name),
    first_name  = COALESCE(EXCLUDED.first_name,  person.first_name),
    family_name = COALESCE(EXCLUDED.family_name, person.family_name),
    middle_name = COALESCE(EXCLUDED.middle_name, person.middle_name),
    updated_at  = CASE WHEN
      (EXCLUDED.full_name IS DISTINCT FROM person.full_name) OR
      (EXCLUDED.first_name IS DISTINCT FROM person.first_name) OR
      (EXCLUDED.family_name IS DISTINCT FROM person.family_name) OR
      (EXCLUDED.middle_name IS DISTINCT FROM person.middle_name)
    THEN CURRENT_TIMESTAMP ELSE person.updated_at END
  WHERE (EXCLUDED.full_name IS DISTINCT FROM person.full_name) OR
        (EXCLUDED.first_name IS DISTINCT FROM person.first_name) OR
        (EXCLUDED.family_name IS DISTINCT FROM person.family_name) OR
        (EXCLUDED.middle_name IS DISTINCT FROM person.middle_name)
  RETURNING id, full_name INTO v_id, v_display;

  IF v_id IS NULL THEN SELECT id, full_name INTO v_id, v_display FROM public.person WHERE unique_id = p_unique_id; END IF;

  v_display := COALESCE(v_display, p_unique_id);
  v_entity_id := public.upsert_entity_and_ref('person', v_display, public.null_safe_attrs(p_attrs), 'person', v_id);
  RETURN v_entity_id;
END$$;

-- Phone
CREATE OR REPLACE FUNCTION public.upsert_phone(
  p_raw_number text,
  p_e164 text,
  p_number_type text DEFAULT NULL,
  p_country_code integer DEFAULT NULL,
  p_country_abbrev text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.phone(raw_number, e164, number_type, country_code, country_abbrev)
  VALUES (p_raw_number, p_e164, p_number_type, p_country_code, p_country_abbrev)
  ON CONFLICT (e164) DO UPDATE SET
    raw_number     = COALESCE(EXCLUDED.raw_number,     phone.raw_number),
    number_type    = COALESCE(EXCLUDED.number_type,    phone.number_type),
    country_code   = COALESCE(EXCLUDED.country_code,   phone.country_code),
    country_abbrev = COALESCE(EXCLUDED.country_abbrev, phone.country_abbrev),
    updated_at     = CASE WHEN
      (EXCLUDED.raw_number IS DISTINCT FROM phone.raw_number) OR
      (EXCLUDED.number_type IS DISTINCT FROM phone.number_type) OR
      (EXCLUDED.country_code IS DISTINCT FROM phone.country_code) OR
      (EXCLUDED.country_abbrev IS DISTINCT FROM phone.country_abbrev)
    THEN CURRENT_TIMESTAMP ELSE phone.updated_at END
  WHERE (EXCLUDED.raw_number IS DISTINCT FROM phone.raw_number) OR
        (EXCLUDED.number_type IS DISTINCT FROM phone.number_type) OR
        (EXCLUDED.country_code IS DISTINCT FROM phone.country_code) OR
        (EXCLUDED.country_abbrev IS DISTINCT FROM phone.country_abbrev)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.phone WHERE e164 = p_e164; END IF;

  v_entity_id := public.upsert_entity_and_ref('phone', p_e164, public.null_safe_attrs(p_attrs), 'phone', v_id);
  RETURN v_entity_id;
END$$;

-- Product
CREATE OR REPLACE FUNCTION public.upsert_product(
  p_unique_id text,
  p_product_name text,
  p_product_type text DEFAULT NULL,
  p_category text DEFAULT NULL,
  p_product_description text DEFAULT NULL,
  p_country_of_origin text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint; v_display text;
BEGIN
  INSERT INTO public.product(unique_id, product_name, product_type, category, product_description, country_of_origin)
  VALUES (p_unique_id, p_product_name, p_product_type, p_category, p_product_description, p_country_of_origin)
  ON CONFLICT (unique_id) DO UPDATE SET
    product_name        = COALESCE(EXCLUDED.product_name,        product.product_name),
    product_type        = COALESCE(EXCLUDED.product_type,        product.product_type),
    category            = COALESCE(EXCLUDED.category,            product.category),
    product_description = COALESCE(EXCLUDED.product_description, product.product_description),
    country_of_origin   = COALESCE(EXCLUDED.country_of_origin,   product.country_of_origin),
    updated_at          = CASE WHEN
      (EXCLUDED.product_name IS DISTINCT FROM product.product_name) OR
      (EXCLUDED.product_type IS DISTINCT FROM product.product_type) OR
      (EXCLUDED.category IS DISTINCT FROM product.category) OR
      (EXCLUDED.product_description IS DISTINCT FROM product.product_description) OR
      (EXCLUDED.country_of_origin IS DISTINCT FROM product.country_of_origin)
    THEN CURRENT_TIMESTAMP ELSE product.updated_at END
  WHERE (EXCLUDED.product_name IS DISTINCT FROM product.product_name) OR
        (EXCLUDED.product_type IS DISTINCT FROM product.product_type) OR
        (EXCLUDED.category IS DISTINCT FROM product.category) OR
        (EXCLUDED.product_description IS DISTINCT FROM product.product_description) OR
        (EXCLUDED.country_of_origin IS DISTINCT FROM product.country_of_origin)
  RETURNING id, product_name INTO v_id, v_display;

  IF v_id IS NULL THEN SELECT id, product_name INTO v_id, v_display FROM public.product WHERE unique_id = p_unique_id; END IF;

  v_display := COALESCE(v_display, p_unique_id);
  v_entity_id := public.upsert_entity_and_ref('product', v_display, public.null_safe_attrs(p_attrs), 'product', v_id);
  RETURN v_entity_id;
END$$;

-- Product Release
CREATE OR REPLACE FUNCTION public.upsert_productrelease(
  p_release_name text,
  p_release_date timestamp without time zone DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.productrelease(release_name, release_date)
  VALUES (p_release_name, p_release_date)
  ON CONFLICT (release_name) DO UPDATE SET
    release_date = COALESCE(EXCLUDED.release_date, productrelease.release_date),
    updated_at   = CASE WHEN (EXCLUDED.release_date IS DISTINCT FROM productrelease.release_date)
                  THEN CURRENT_TIMESTAMP ELSE productrelease.updated_at END
  WHERE (EXCLUDED.release_date IS DISTINCT FROM productrelease.release_date)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.productrelease WHERE release_name = p_release_name; END IF;

  v_entity_id := public.upsert_entity_and_ref('productrelease', p_release_name, public.null_safe_attrs(p_attrs), 'productrelease', v_id);
  RETURN v_entity_id;
END$$;

-- Service
CREATE OR REPLACE FUNCTION public.upsert_service(
  p_unique_id text,
  p_service_type text,
  p_output_data text DEFAULT NULL,
  p_output_length integer DEFAULT NULL,
  p_attributes jsonb DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.service(unique_id, service_type, output_data, output_length, attributes)
  VALUES (p_unique_id, p_service_type, p_output_data, p_output_length, p_attributes)
  ON CONFLICT (unique_id) DO UPDATE SET
    service_type = COALESCE(EXCLUDED.service_type, service.service_type),
    output_data  = COALESCE(EXCLUDED.output_data,  service.output_data),
    output_length= COALESCE(EXCLUDED.output_length,service.output_length),
    attributes   = COALESCE(EXCLUDED.attributes,   service.attributes),
    updated_at   = CASE WHEN
      (EXCLUDED.service_type IS DISTINCT FROM service.service_type) OR
      (EXCLUDED.output_data IS DISTINCT FROM service.output_data) OR
      (EXCLUDED.output_length IS DISTINCT FROM service.output_length) OR
      (EXCLUDED.attributes IS DISTINCT FROM service.attributes)
    THEN CURRENT_TIMESTAMP ELSE service.updated_at END
  WHERE (EXCLUDED.service_type IS DISTINCT FROM service.service_type) OR
        (EXCLUDED.output_data IS DISTINCT FROM service.output_data) OR
        (EXCLUDED.output_length IS DISTINCT FROM service.output_length) OR
        (EXCLUDED.attributes IS DISTINCT FROM service.attributes)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.service WHERE unique_id = p_unique_id; END IF;

  v_entity_id := public.upsert_entity_and_ref('service', p_unique_id, public.null_safe_attrs(p_attrs), 'service', v_id);
  RETURN v_entity_id;
END$$;

-- TLS Certificate
CREATE OR REPLACE FUNCTION public.upsert_tlscertificate(
  p_serial_number       text,
  p_subject_common_name text,
  p_is_ca               boolean DEFAULT NULL,
  p_tls_version         integer DEFAULT NULL,
  p_key_usage           text DEFAULT NULL,
  p_ext_key_usage       text DEFAULT NULL,
  p_not_before          timestamp without time zone DEFAULT NULL,
  p_not_after           timestamp without time zone DEFAULT NULL,
  p_subject_key_id      text DEFAULT NULL,
  p_authority_key_id    text DEFAULT NULL,
  p_issuer_common_name  text DEFAULT NULL,
  p_signature_algorithm text DEFAULT NULL,
  p_public_key_algorithm text DEFAULT NULL,
  p_crl_distribution_points text DEFAULT NULL,
  p_attrs               jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.tlscertificate(
    serial_number, subject_common_name, is_ca, tls_version, key_usage, ext_key_usage,
    not_before, not_after, subject_key_id, authority_key_id, issuer_common_name,
    signature_algorithm, public_key_algorithm, crl_distribution_points
  ) VALUES (
    p_serial_number, p_subject_common_name, p_is_ca, p_tls_version, p_key_usage, p_ext_key_usage,
    p_not_before, p_not_after, p_subject_key_id, p_authority_key_id, p_issuer_common_name,
    p_signature_algorithm, p_public_key_algorithm, p_crl_distribution_points
  )
  ON CONFLICT (serial_number) DO UPDATE SET
    subject_common_name   = COALESCE(EXCLUDED.subject_common_name,   tlscertificate.subject_common_name),
    is_ca                 = COALESCE(EXCLUDED.is_ca,                 tlscertificate.is_ca),
    tls_version           = COALESCE(EXCLUDED.tls_version,           tlscertificate.tls_version),
    key_usage             = COALESCE(EXCLUDED.key_usage,             tlscertificate.key_usage),
    ext_key_usage         = COALESCE(EXCLUDED.ext_key_usage,         tlscertificate.ext_key_usage),
    not_before            = COALESCE(EXCLUDED.not_before,            tlscertificate.not_before),
    not_after             = COALESCE(EXCLUDED.not_after,             tlscertificate.not_after),
    subject_key_id        = COALESCE(EXCLUDED.subject_key_id,        tlscertificate.subject_key_id),
    authority_key_id      = COALESCE(EXCLUDED.authority_key_id,      tlscertificate.authority_key_id),
    issuer_common_name    = COALESCE(EXCLUDED.issuer_common_name,    tlscertificate.issuer_common_name),
    signature_algorithm   = COALESCE(EXCLUDED.signature_algorithm,   tlscertificate.signature_algorithm),
    public_key_algorithm  = COALESCE(EXCLUDED.public_key_algorithm,  tlscertificate.public_key_algorithm),
    crl_distribution_points=COALESCE(EXCLUDED.crl_distribution_points,tlscertificate.crl_distribution_points),
    updated_at            = CASE WHEN
      (EXCLUDED.subject_common_name IS DISTINCT FROM tlscertificate.subject_common_name) OR
      (EXCLUDED.is_ca IS DISTINCT FROM tlscertificate.is_ca) OR
      (EXCLUDED.tls_version IS DISTINCT FROM tlscertificate.tls_version) OR
      (EXCLUDED.key_usage IS DISTINCT FROM tlscertificate.key_usage) OR
      (EXCLUDED.ext_key_usage IS DISTINCT FROM tlscertificate.ext_key_usage) OR
      (EXCLUDED.not_before IS DISTINCT FROM tlscertificate.not_before) OR
      (EXCLUDED.not_after IS DISTINCT FROM tlscertificate.not_after) OR
      (EXCLUDED.subject_key_id IS DISTINCT FROM tlscertificate.subject_key_id) OR
      (EXCLUDED.authority_key_id IS DISTINCT FROM tlscertificate.authority_key_id) OR
      (EXCLUDED.issuer_common_name IS DISTINCT FROM tlscertificate.issuer_common_name) OR
      (EXCLUDED.signature_algorithm IS DISTINCT FROM tlscertificate.signature_algorithm) OR
      (EXCLUDED.public_key_algorithm IS DISTINCT FROM tlscertificate.public_key_algorithm) OR
      (EXCLUDED.crl_distribution_points IS DISTINCT FROM tlscertificate.crl_distribution_points)
    THEN CURRENT_TIMESTAMP ELSE tlscertificate.updated_at END
  WHERE (EXCLUDED.subject_common_name IS DISTINCT FROM tlscertificate.subject_common_name) OR
        (EXCLUDED.is_ca IS DISTINCT FROM tlscertificate.is_ca) OR
        (EXCLUDED.tls_version IS DISTINCT FROM tlscertificate.tls_version) OR
        (EXCLUDED.key_usage IS DISTINCT FROM tlscertificate.key_usage) OR
        (EXCLUDED.ext_key_usage IS DISTINCT FROM tlscertificate.ext_key_usage) OR
        (EXCLUDED.not_before IS DISTINCT FROM tlscertificate.not_before) OR
        (EXCLUDED.not_after IS DISTINCT FROM tlscertificate.not_after) OR
        (EXCLUDED.subject_key_id IS DISTINCT FROM tlscertificate.subject_key_id) OR
        (EXCLUDED.authority_key_id IS DISTINCT FROM tlscertificate.authority_key_id) OR
        (EXCLUDED.issuer_common_name IS DISTINCT FROM tlscertificate.issuer_common_name) OR
        (EXCLUDED.signature_algorithm IS DISTINCT FROM tlscertificate.signature_algorithm) OR
        (EXCLUDED.public_key_algorithm IS DISTINCT FROM tlscertificate.public_key_algorithm) OR
        (EXCLUDED.crl_distribution_points IS DISTINCT FROM tlscertificate.crl_distribution_points)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.tlscertificate WHERE serial_number = p_serial_number; END IF;

  v_entity_id := public.upsert_entity_and_ref('tlscertificate', p_serial_number, public.null_safe_attrs(p_attrs), 'tlscertificate', v_id);
  RETURN v_entity_id;
END$$;

-- URL
CREATE OR REPLACE FUNCTION public.upsert_url(
  p_raw_url text,
  p_host citext,
  p_url_path text DEFAULT NULL,
  p_port integer DEFAULT NULL,
  p_scheme text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE v_id integer; v_entity_id bigint;
BEGIN
  INSERT INTO public.url(raw_url, host, url_path, port, scheme)
  VALUES (p_raw_url, p_host, p_url_path, p_port, p_scheme)
  ON CONFLICT (raw_url) DO UPDATE SET
    host       = COALESCE(EXCLUDED.host,       url.host),
    url_path   = COALESCE(EXCLUDED.url_path,   url.url_path),
    port       = COALESCE(EXCLUDED.port,       url.port),
    scheme     = COALESCE(EXCLUDED.scheme,     url.scheme),
    updated_at = CASE WHEN
      (EXCLUDED.host IS DISTINCT FROM url.host) OR
      (EXCLUDED.url_path IS DISTINCT FROM url.url_path) OR
      (EXCLUDED.port IS DISTINCT FROM url.port) OR
      (EXCLUDED.scheme IS DISTINCT FROM url.scheme)
    THEN CURRENT_TIMESTAMP ELSE url.updated_at END
  WHERE (EXCLUDED.host IS DISTINCT FROM url.host) OR
        (EXCLUDED.url_path IS DISTINCT FROM url.url_path) OR
        (EXCLUDED.port IS DISTINCT FROM url.port) OR
        (EXCLUDED.scheme IS DISTINCT FROM url.scheme)
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.url WHERE raw_url = p_raw_url; END IF;

  v_entity_id := public.upsert_entity_and_ref('url', p_raw_url, public.null_safe_attrs(p_attrs), 'url', v_id);
  RETURN v_entity_id;
END$$;

COMMIT;

-- ============================================================================
-- Usage examples
-- SELECT public.upsert_fqdn('login.example.com');
-- SELECT public.upsert_ipaddress('IPv4', '203.0.113.7');
-- WITH e1 AS (SELECT public.upsert_fqdn('login.example.com') id),
--      e2 AS (SELECT public.upsert_ipaddress('IPv4','203.0.113.7') id)
-- SELECT public.ensure_edge('dns_record', (SELECT id FROM e1), (SELECT id FROM e2), '{"rr":"A"}');
-- ============================================================================

-- +migrate Down

DROP FUNCTION IF EXISTS public.upsert_url(
  p_raw_url text,
  p_host citext,
  p_url_path text DEFAULT NULL,
  p_port integer DEFAULT NULL,
  p_scheme text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_tlscertificate(
  p_serial_number       text,
  p_subject_common_name text,
  p_is_ca               boolean DEFAULT NULL,
  p_tls_version         integer DEFAULT NULL,
  p_key_usage           text DEFAULT NULL,
  p_ext_key_usage       text DEFAULT NULL,
  p_not_before          timestamp without time zone DEFAULT NULL,
  p_not_after           timestamp without time zone DEFAULT NULL,
  p_subject_key_id      text DEFAULT NULL,
  p_authority_key_id    text DEFAULT NULL,
  p_issuer_common_name  text DEFAULT NULL,
  p_signature_algorithm text DEFAULT NULL,
  p_public_key_algorithm text DEFAULT NULL,
  p_crl_distribution_points text DEFAULT NULL,
  p_attrs               jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_service(
  p_unique_id text,
  p_service_type text,
  p_output_data text DEFAULT NULL,
  p_output_length integer DEFAULT NULL,
  p_attributes jsonb DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_productrelease(
  p_release_name text,
  p_release_date timestamp without time zone DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_product(
  p_unique_id text,
  p_product_name text,
  p_product_type text DEFAULT NULL,
  p_category text DEFAULT NULL,
  p_product_description text DEFAULT NULL,
  p_country_of_origin text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_phone(
  p_raw_number text,
  p_e164 text,
  p_number_type text DEFAULT NULL,
  p_country_code integer DEFAULT NULL,
  p_country_abbrev text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_person(
  p_unique_id text,
  p_full_name text DEFAULT NULL,
  p_first_name text DEFAULT NULL,
  p_family_name text DEFAULT NULL,
  p_middle_name text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_organization(
  p_unique_id text,
  p_legal_name text,
  p_org_name text DEFAULT NULL,
  p_active boolean DEFAULT NULL,
  p_jurisdiction text DEFAULT NULL,
  p_founding_date timestamp without time zone DEFAULT NULL,
  p_registration_id text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_netblock(
  p_netblock_cidr cidr,
  p_ip_version text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_location(
  p_city text,
  p_street_address text,
  p_country text,
  p_unit text DEFAULT NULL,
  p_building text DEFAULT NULL,
  p_province text DEFAULT NULL,
  p_locality text DEFAULT NULL,
  p_postal_code text DEFAULT NULL,
  p_street_name text DEFAULT NULL,
  p_building_number text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_ipnetrecord(
  p_record_cidr cidr,
  p_record_name text,
  p_ip_version text,
  p_handle text,
  p_method text DEFAULT NULL,
  p_record_status text[] DEFAULT NULL,
  p_created_date timestamp without time zone DEFAULT NULL,
  p_updated_date timestamp without time zone DEFAULT NULL,
  p_whois_server text DEFAULT NULL,
  p_parent_handle text DEFAULT NULL,
  p_start_address inet DEFAULT NULL,
  p_end_address inet DEFAULT NULL,
  p_country text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_ipaddress(
  p_ip_version text,
  p_ip_address inet,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_identifier(
  p_identifier_type text,
  p_identifier_value text,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_fundstransfer(
  p_transaction_id text,
  p_amount numeric DEFAULT NULL,
  p_currency text DEFAULT NULL,
  p_sender text DEFAULT NULL,
  p_receiver text DEFAULT NULL,
  p_transaction_date timestamp without time zone DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_fqdn(
  p_fqdn citext,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_file(
  p_file_hash text,
  p_hash_type text,
  p_file_name text DEFAULT NULL,
  p_file_size integer DEFAULT NULL,
  p_mime_type text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_domainrecord(
  p_record_name text,
  p_record_type text,
  p_record_value text,
  p_ttl integer DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_contactrecord(
  p_contact_type text,
  p_contact_value text,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_autonomoussystem(
  p_asn integer,
  p_as_name text DEFAULT NULL,
  p_country text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_autnumrecord(
  p_asn integer,
  p_record_name text,
  p_record_type text,
  p_record_value text,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_account(
  p_account_id text,
  p_account_type text DEFAULT NULL,
  p_platform text DEFAULT NULL,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.tag_edge(
  p_edge_id bigint,
  p_tag_key text,
  p_tag_value text
);

DROP FUNCTION IF EXISTS public.tag_entity(
  p_entity_id bigint,
  p_tag_key text,
  p_tag_value text
);

DROP FUNCTION IF EXISTS public.upsert_tag(
  p_tag_key text,
  p_tag_value text
);

DROP FUNCTION IF EXISTS public.ensure_edge(
  p_edge_type text,
  p_from_entity_id bigint,
  p_to_entity_id bigint,
  p_attrs jsonb DEFAULT '{}'::jsonb
);

DROP FUNCTION IF EXISTS public.upsert_entity_and_ref(
  p_entity_type text,
  p_display text,
  p_attrs jsonb DEFAULT '{}'::jsonb,
  p_table_name text,
  p_table_id integer
);

DROP FUNCTION IF EXISTS public.get_entity_type_id(
  p_entity_type text
);

DROP FUNCTION IF EXISTS public.null_safe_attrs(
  p_attrs jsonb
);