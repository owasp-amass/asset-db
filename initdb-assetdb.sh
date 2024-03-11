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
    CREATE DATABASE ip2location OWNER :username;
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
            FROM ((((assets AS fqdns INNER JOIN relations AS r1 ON fqdns.id = r1.from_asset_id) 
            INNER JOIN assets AS srvs ON r1.to_asset_id = srvs.id) INNER JOIN relations AS r2 ON srvs.id = 
            r2.from_asset_id) INNER JOIN assets AS ips ON r2.to_asset_id = ips.id) 
            WHERE fqdns.type = 'FQDN' AND srvs.type = 'FQDN' AND ips.type = 'IPAddress' 
            AND r1.type IN ('srv_record','ns_record','mx_record') AND r2.type IN ('a_record','aaaa_record') 
            AND r1.last_seen >= _from AND r1.last_seen <= _to AND r2.last_seen >= _from AND r2.last_seen <= _to 
            AND fqdns.content->>'name' = ANY(_names)
        ) LOOP fqdn = _var_r.name;
            ip_addr = _var_r.addr;
            _names = array_remove(_names, _var_r.name);
            RETURN NEXT;
        END LOOP;

        FOR _var_r IN (
            SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
            FROM ((assets AS fqdns 
            INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
            INNER JOIN assets AS ips ON relations.to_asset_id = ips.id) 
            WHERE fqdns.type = 'FQDN' AND ips.type = 'IPAddress' 
            AND relations.type IN ('a_record', 'aaaa_record') 
            AND relations.last_seen >= _from AND relations.last_seen <= _to 
            AND fqdns.content->>'name' = ANY(_names)
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
                SELECT cnames.content->>'name' FROM ((assets AS fqdns 
                INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
                INNER JOIN assets AS cnames ON relations.to_asset_id = cnames.id), traverse_cname 
                WHERE fqdns.type = 'FQDN' AND cnames.type = 'FQDN' 
                AND relations.last_seen >= _from AND relations.last_seen <= _to 
                AND relations.type = 'cname_record' AND fqdns.content->>'name' = traverse_cname._fqdn) 
                SELECT fqdns.content->>'name' AS "name", ips.content->>'address' AS "addr" 
                FROM ((assets AS fqdns INNER JOIN relations ON fqdns.id = relations.from_asset_id) 
                INNER JOIN assets AS ips ON relations.to_asset_id = ips.id) 
                WHERE fqdns.type = 'FQDN' AND ips.type = 'IPAddress' 
                AND relations.last_seen >= _from AND relations.last_seen <= _to 
                AND relations.type IN ('a_record', 'aaaa_record') 
                AND fqdns.content->>'name' IN (SELECT _fqdn FROM traverse_cname)
            ) LOOP fqdn = _name;
                ip_addr = _var_r.addr;
                RETURN NEXT;
            END LOOP;
        END LOOP;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;
EOSQL

# create the table and support routines within the ip2location database
PGPASSWORD=$AMASS_PASSWORD psql -v ON_ERROR_STOP=1 --username "$AMASS_USER" --dbname ip2location <<-EOSQL
    CREATE OR REPLACE FUNCTION batch_ip_geo(TEXT) RETURNS TABLE(ip_addr TEXT, city VARCHAR(128), latitude VARCHAR(20), longitude VARCHAR(20)) AS \$BODY\$ 
    DECLARE
        _ip TEXT;
        _ips TEXT[];
        _var_r RECORD;
    BEGIN
        _ips = string_to_array(\$1, ',');

        FOREACH _ip IN ARRAY _ips LOOP 
            FOR _var_r IN (
                WITH addr(ip_addr) AS (VALUES (_ip))
                SELECT addr.ip_addr AS addr, geo.city_name AS "city", 
                geo.latitude AS "lat", geo.longitude AS "long" 
                FROM (SELECT ip_geo.city_name, ip_geo.latitude, ip_geo.longitude 
                FROM ip_geo WHERE inet_to_num(_ip::inet) >= ip_from AND country_code != '-' 
                ORDER BY ip_from DESC LIMIT 1) AS geo 
                JOIN addr ON 1=1
            ) LOOP ip_addr = _var_r.addr;
                city = _var_r.city;
                latitude = _var_r.lat;
                longitude = _var_r.long;
                RETURN NEXT;
            END LOOP;
        END LOOP;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;

    CREATE OR REPLACE FUNCTION ipv6_to_num(inet) RETURNS DECIMAL(39,0) AS \$BODY\$ 
    DECLARE
        _groups TEXT[];
        _weight DECIMAL(39,0);
        _ipnum DECIMAL(39,0) = 0;
    BEGIN
        _groups = string_to_array(expand_ipv6(\$1), ':');

        FOR i in 1..8 LOOP
            _weight = 1;

            IF i < 8 THEN
                _weight = 65536 ^ (8 - i);
            END IF;

            _ipnum = _ipnum + (hex_to_bigint(_groups[i]) * _weight);
        END LOOP;

        RETURN _ipnum;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;

    CREATE OR REPLACE FUNCTION inet_to_num(inet) RETURNS DECIMAL(39,0) AS \$BODY\$ 
        SELECT \$1 - '0.0.0.0'::inet WHERE family(\$1) = 4 
        UNION ALL
        SELECT ipv6_to_num(\$1) WHERE family(\$1) = 6
        UNION ALL
        SELECT 0 WHERE family(\$1) != 4 AND family(\$1) != 6
    \$BODY\$ LANGUAGE sql IMMUTABLE STRICT;

    CREATE OR REPLACE FUNCTION expand_ipv6(inet) RETURNS TEXT AS \$BODY\$ 
    DECLARE
        _len1 INT;
        _len2 INT;
        _addr TEXT;
        _missing INT;
        _sides TEXT[];
        _groups1 TEXT[];
        _groups2 TEXT[];
    BEGIN
        _addr = host(\$1);
        _sides = string_to_array(_addr, '::');

        IF cardinality(_sides) = 2 THEN
            _groups1 = string_to_array(_sides[1], ':');
            _groups2 = string_to_array(_sides[2], ':');
            _len1 = cardinality(_groups1);
            _len2 = cardinality(_groups2);
            _missing = (8 - _len1) - _len2;

            IF _len1 > 0 THEN
                _sides[1] = _sides[1] || ':';
            END IF;

            FOR i in 1.._missing LOOP
                _sides[1] = _sides[1] || '0';
                IF i < _missing THEN
                    _sides[1] = _sides[1] || ':';
                END IF;
            END LOOP;

            IF _len2 > 0 THEN
                _sides[1] = _sides[1] || ':' || _sides[2];
            END IF;

            _addr = _sides[1];
        END IF;

        RETURN _addr;
    END
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;

    CREATE OR REPLACE FUNCTION hex_to_bigint(hexval varchar) RETURNS BIGINT AS \$BODY\$
    DECLARE
        result BIGINT;
    BEGIN
        EXECUTE 'SELECT x' || quote_literal(hexval) || '::bigint' INTO result;
        RETURN result;
    END;
    \$BODY\$ LANGUAGE plpgsql IMMUTABLE STRICT;

    CREATE TABLE ip_geo (
        ip_from DECIMAL(39,0) NOT NULL,
        ip_to DECIMAL(39,0) NOT NULL,
        country_code CHAR(2) NOT NULL,
        country_name VARCHAR(64) NOT NULL,
        region_name VARCHAR(128) NOT NULL,
        city_name VARCHAR(128) NOT NULL,
        latitude VARCHAR(20) NOT NULL,
        longitude VARCHAR(20) NOT NULL,
        zip_code VARCHAR(30) NULL DEFAULT NULL,
        time_zone VARCHAR(8) NULL DEFAULT NULL,
        CONSTRAINT idx_key PRIMARY KEY (ip_to)
    );
EOSQL