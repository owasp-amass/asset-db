
-- +migrate Up

alter table assets alter column created_at TYPE TIMESTAMP without time zone;
alter table assets alter column last_seen TYPE TIMESTAMP without time zone;
alter table relations alter column created_at TYPE TIMESTAMP without time zone;
alter table relations alter column last_seen TYPE TIMESTAMP without time zone;

-- +migrate Down

alter table assets alter column created_at TYPE TIMESTAMP with time zone;
alter table assets alter column last_seen TYPE TIMESTAMP with time zone;
alter table relations alter column created_at TYPE TIMESTAMP with time zone;
alter table relations alter column last_seen TYPE TIMESTAMP with time zone;
