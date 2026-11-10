-- +migrate Up

-- Indexes for repository.ValueFinder: certificates sharing a key identifier.
CREATE INDEX IF NOT EXISTS idx_tlscertificate_subject_key_id
  ON tlscertificate (json_extract(attrs, '$.subject_key_id'));
CREATE INDEX IF NOT EXISTS idx_tlscertificate_authority_key_id
  ON tlscertificate (json_extract(attrs, '$.authority_key_id'));

-- +migrate Down

DROP INDEX IF EXISTS idx_tlscertificate_authority_key_id;
DROP INDEX IF EXISTS idx_tlscertificate_subject_key_id;
