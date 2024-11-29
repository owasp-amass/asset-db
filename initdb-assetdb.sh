#!/bin/bash
set -e

# add single quotes around the Amass password
export TEMPPASS="'$AMASS_PASSWORD'"

# create the Amass user and asset-db database within PostgreSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    \getenv assetdb AMASS_DB
    \getenv username AMASS_USER
    \getenv password TEMPPASS
    CREATE DATABASE :assetdb;
    ALTER DATABASE :assetdb SET timezone TO 'UTC';
    CREATE USER :username WITH PASSWORD :password;
EOSQL

# within the new asset-db, install the trigram matching 
# extension and grant privileges to the Amass user
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$AMASS_DB" <<-EOSQL
    \getenv username AMASS_USER
    CREATE EXTENSION pg_trgm SCHEMA public;
	GRANT USAGE ON SCHEMA public TO :username;
    GRANT CREATE ON SCHEMA public TO :username;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO :username;

    CREATE OR REPLACE FUNCTION names_to_addrs(TEXT, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE) RETURNS TABLE(fqdn TEXT, ip_addr TEXT) AS \$BODY\$ 
    DECLARE
        _name TEXT;
        _names TEXT[];
        _var_r RECORD;
        _to TIMESTAMP;
        _from TIMESTAMP;
    BEGIN
        _to = \$3;
        _from = \$2;
        _names = string_to_array(\$1, ',');

        FOR _var_r IN (
            SELECT srvs.content->>'name' AS "name", ips.content->>'address' AS "addr" 
            FROM ((((entities AS fqdns 
            INNER JOIN edges AS r1 ON fqdns.entity_id = r1.from_entity_id) 
            INNER JOIN entities AS srvs ON r1.to_entity_id = srvs.entity_id) 
            INNER JOIN edges AS r2 ON srvs.entity_id = r2.from_entity_id) 
            INNER JOIN entities AS ips ON r2.to_entity_id = ips.entity_id) 
            WHERE fqdns.etype = 'FQDN' AND srvs.etype = 'FQDN' AND ips.etype = 'IPAddress' 
            AND r1.etype IN ('PrefDNSRelation', 'SRVDNSRelation') AND r1.content->>'label' = 'dns_record' 
            AND r1.content->'header'->'rr_type' IN ('33', '2', '15') 
            AND r2.etype = 'BasicDNSRelation' AND r2.content->>'label' = 'dns_record' 
            AND r2.content->'header'->'rr_type' IN ('1', '28') 
            AND r1.updated_at >= _from AND r1.updated_at <= _to AND r2.updated_at >= _from 
            AND r2.updated_at <= _to AND fqdns.content->>'name' = ANY(_names)
        ) LOOP fqdn = _var_r.name;
            ip_addr = _var_r.addr;
            _names = array_remove(_names, _var_r.name);
            RETURN NEXT;
        END LOOP;

        FOR _var_r IN (
            SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
            FROM ((entities AS fqdns 
            INNER JOIN edges ON fqdns.entity_id = edges.from_entity_id) 
            INNER JOIN entities AS ips ON edges.to_entity_id = ips.entity_id) 
            WHERE fqdns.etype = 'FQDN' AND ips.etype = 'IPAddress' 
            AND edges.etype = 'BasicDNSRelation' AND edges.content->>'label' = 'dns_record' 
            AND edges.content->'header'->'rr_type' IN ('1', '28') AND edges.updated_at >= _from 
            AND edges.updated_at <= _to AND fqdns.content->>'name' = ANY(_names)
        ) LOOP fqdn = _var_r.name;
            ip_addr = _var_r.addr;
            _names = array_remove(_names, _var_r.name);
            RETURN NEXT;
        END LOOP;

        FOREACH _name IN ARRAY _names LOOP
            FOR _var_r IN (
                WITH RECURSIVE traverse_cname(_fqdn) AS ( 
                VALUES(_name) 
                UNION 
                SELECT cnames.content->>'name' FROM ((entities AS fqdns 
                INNER JOIN edges ON fqdns.entity_id = edges.from_entity_id) 
                INNER JOIN entities AS cnames ON edges.to_entity_id = cnames.entity_id), traverse_cname 
                WHERE fqdns.etype = 'FQDN' AND cnames.etype = 'FQDN' 
                AND edges.updated_at >= _from AND edges.updated_at <= _to 
                AND edges.etype = 'BasicDNSRelation' AND edges.content->>'label' = 'dns_record' 
                AND edges.content->'header'->'rr_type' = '5' 
                AND fqdns.content->>'name' = traverse_cname._fqdn) 
                SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
                FROM ((entities AS fqdns INNER JOIN edges ON fqdns.entity_id = edges.from_entity_id) 
                INNER JOIN entities AS ips ON edges.to_entity_id = ips.entity_id) 
                WHERE fqdns.etype = 'FQDN' AND ips.etype = 'IPAddress' 
                AND edges.updated_at >= _from AND edges.updated_at <= _to 
                AND edges.etype = 'BasicDNSRelation' AND edges.content->>'label' = 'dns_record' 
                AND edges.content->'header'->'rr_type' IN ('1', '28') 
                AND fqdns.content->>'name' IN (SELECT _fqdn FROM traverse_cname)
            ) LOOP fqdn = _name;
                ip_addr = _var_r.addr;
                RETURN NEXT;
            END LOOP;
        END LOOP;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;
EOSQL
