# Semantic and provenance evaluation fixture (disposable only)

The `semantic/` directory contains a deliberately small **synthetic**
OAM fixture, separate from the original AI fixture.

- 11 assets: four organizations, three FQDNs and four URLs.
- 10 OAM-valid simple relations: subsidiary, website, and domain.
- 11 property records with distinct source-tag coverage and
  unattributed metadata.
- Two distinct URL -> FQDN pathways reach `tech.acme.example` and
  two distinct organization -> URL -> FQDN pathways trace back to
  Acme Technologies Ltd.
- Acme Holdings is the parent of Acme Technologies and Acme Europe;
  Northwind is disconnected and must not be inferred as an owner.
- One domain / website route has a single source tag on each edge;
  the alternate route has two named source tags on each. This tests
  relative source-tag completeness, **not verified independence**.
- The parent -> subsidiary edge has two named source tags.
  The sibling edge has only one.
- The Northwind website edge has a generic property, explicitly
  *without* a source identity.

All domains use reserved `.example` names; no external DNS or scanning
occurs during fixture creation. No files contain real organizations'
identifiers, source records, or credentials.

## Validate and create a disposable SQLite fixture

```bash
cd /path/to/asset-db
go test ./internal/aitestfixture -run '^TestSemantic' -v -count=1

ROOT=$(mktemp -d /tmp/amass-ai-semantic.XXXXXX)
go run ./cmd/ai-fixture-seed \
  -fixture ./testdata/ai/semantic \
  -sqlite "$ROOT/semantic-fixture.db" \
  -confirm-disposable
```

The seeder refuses an existing SQLite file. The chosen path must
be new, must end in `.db`, and cannot contain `asset.db`. Never
point it at production or your existing Amass test database.

To use the result as an Amass `-dir` local database, copy the
closed SQLite DB into the *same new disposable directory*:

```bash
cp "$ROOT/semantic-fixture.db" "$ROOT/asset.db"
```

Then run `amass ai -dir "$ROOT" ... ask` from a sibling Amass
feature-branch checkout. See
`amass/docs/ai/SEMANTIC_EVIDENCE.md` for exact commands,
expected results, and JSON inspection.

Source tag names such as `synthetic-dns-a` and
`synthetic-dns-b` are only fixture labels. Different labels do
not demonstrate that their upstream datasets are independent.
