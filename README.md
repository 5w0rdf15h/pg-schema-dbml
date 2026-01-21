# pg-schema-dbml — PostgreSQL schema export to DBML

Export a PostgreSQL schema (no data) to **DBML** for **dbdiagram.io** and database documentation.

## Problem

You want a clean database diagram or schema documentation, but the tools usually fall into one of these buckets:

- require a Python driver or extra dependencies
- dump raw SQL and expect you to parse/clean it
- break on real-world Postgres schemas (arrays, `character varying`, odd identifiers, partial indexes)
- produce unstable output that’s hard to diff in Git

This project is for the boring but important job: **reliable PostgreSQL schema export** to a format that diagram tools understand.

## What this tool does

- connects to PostgreSQL using the native `psql` CLI
- reads schema metadata from `pg_catalog` (no SQL parsing)
- writes a deterministic **DBML** file:
  - tables + columns
  - primary keys (including composite)
  - foreign keys (including composite)
  - unique constraints and basic indexes
  - enums
  - nullability and defaults
- includes notes when something can’t be represented cleanly in DBML

## Why this exists (and when it’s better than alternatives)

- **No Python dependencies.** Standard library only. Works anywhere `psql` works.
- **No fragile DDL parsing.** It queries Postgres catalogs directly.
- **dbdiagram.io-compatible output.** Normalizes Postgres type spellings and edge cases that commonly break rendering.
- **Stable diffs.** Output is sorted consistently so schema changes review well in PRs.

If you already use an ORM and like its schema tools, stick with those. If you want a small, reliable export step for documentation/diagrams, this is a good fit.

## Features

- ✅ Standard library only (no `psycopg`, no pip installs)
- ✅ Uses `psql` + `COPY TO STDOUT` (handles large schemas)
- ✅ Multiple schemas: `--schema public --schema billing`
- ✅ Optional view export: `--include-views`
- ✅ Deterministic output ordering
- ✅ dbdiagram.io compatibility:
  - `character varying` → `varchar`
  - array types (`varchar(64)[]`) rendered safely
  - problematic/unicode/punctuation column names sanitized, with original preserved in notes
- ✅ Clear error messages, non-zero exit codes
- ✅ Doesn’t log secrets (password via env var name or `.pgpass`)

## Installation

Zero install if you already have Python and Postgres client tools.

Requirements:
- Python 3.9+
- `psql` available in `PATH`

Copy the script into your repo:

```bash
curl -L -o pg_schema_to_dbml.py https://raw.githubusercontent.com/5w0rdf15h/pg-schema-dbml/main/pg_schema_to_dbml.py
chmod +x pg_schema_to_dbml.py
````

> Tip: prefer `.pgpass` for local development, or use `--password-env` for CI.

## Usage

### Using host/port/db/user

Password must be provided via env var name (or `.pgpass`):

```bash
export PG_PASSWORD='your_password'

python pg_schema_to_dbml.py \
  --host localhost --port 5432 --db mydb --user myuser \
  --password-env PG_PASSWORD \
  --schema public \
  --out docs/schema.dbml
```

### Using a DSN

If `--dsn` is set, it overrides host/port/db/user:

```bash
export PG_PASSWORD='your_password'

python pg_schema_to_dbml.py \
  --dsn "postgresql://myuser@localhost:5432/mydb?sslmode=require" \
  --password-env PG_PASSWORD \
  --schema public \
  --out docs/schema.dbml
```

### Multiple schemas

```bash
python pg_schema_to_dbml.py \
  --dsn "postgresql://myuser@localhost:5432/mydb" \
  --schema public \
  --schema billing \
  --out docs/schema.dbml
```

### Include views

```bash
python pg_schema_to_dbml.py \
  --dsn "postgresql://myuser@localhost:5432/mydb" \
  --schema public \
  --include-views \
  --out docs/schema.dbml
```

## Output example

```dbml
Table public.students_student {
  id uuid [pk, not null]
  full_name varchar(128)

  // Postgres arrays are represented safely for dbdiagram.io
  crm_client_ids varchar(64) [not null, note: "ARRAY"]

  Indexes {
    (id) [unique]
  }
}

Ref: public.students_student.school_id > public.schools.id
```

## Common use cases

* **Generate a database diagram** in dbdiagram.io from a live PostgreSQL schema
* **Schema export in CI** to keep architecture docs in sync with migrations
* **Schema documentation** alongside backend code (docs-as-code)
* **Database architecture reviews**: stable diffs in PRs when tables/constraints change
* **Feeding schema structure to other tooling** that accepts DBML

## Using DBML with modern AI systems

This tool produces DBML that is intentionally **machine-friendly**.  
That matters today not only for diagram tools, but also for how modern LLMs
(ChatGPT, Claude, Gemini, z.ai, local models) reason about databases and generate code.

### High-level assessment

The generated `.dbml` file works extremely well as a **structural input** for AI,
but it should not be treated as the **only source of truth**.

Think of it as a *structural substrate*, not a full semantic description of your domain.

### What AI models do very well with this output

Modern LLMs read DBML surprisingly effectively:

- Build a reliable mental graph of tables and relationships
- Infer cardinality and ownership from PK/FK structure
- Detect one-to-many and many-to-many patterns
- Generate:
  - ORM models (Django, SQLAlchemy, Prisma-style)
  - Pydantic / DTO schemas
  - CRUD endpoints
  - Join logic and dependency-aware ordering

For AI-assisted code generation, DBML is often **cleaner and more reliable**
than large collections of SQL migrations.

### Where DBML alone is not enough

What AI **cannot** infer from schema alone:

- Business meaning of tables and fields
- Why certain relationships exist
- Lifecycle semantics (active / archived / soft-deleted)
- Whether something is a business enum, technical enum, or workflow state
- Which tables are core domain vs supporting or audit-only

This is not a limitation of this tool — it’s a limitation of structural schemas in general.


### Recommended pattern for AI-assisted development

The most effective setup is to **combine DBML with lightweight semantic context**:

```
docs/contracts/db/
├── schema.dbml              # structural truth (this tool)
├── schema.sql               # actual DDL
├── schema.summary.md        # short per-table summaries
└── schema.semantic.md       # domain meaning and invariants
````

Even minimal additions dramatically improve AI reasoning quality.

Example:

```dbml
Table public.accounts {
  status_id integer [not null, note: "FSM: new → active → suspended → archived"]
}
````

LLMs reliably read `note:` fields and use them during reasoning and code generation.

### Bottom line

* As a **technical schema**: excellent
* As input for **AI-assisted code generation**: very strong
* As a standalone **domain explanation**: intentionally incomplete

This tool focuses on producing a **clean, stable, machine-readable structure**.
Semantic meaning belongs in adjacent documentation — not embedded into SQL or migrations.

## Limitations / non-goals

This is intentionally not a full database reverse-engineering suite.

* Not a SQL DDL parser
* Not a migration tool
* Does not export data
* Expression/partial indexes are preserved as notes when they can’t be represented as DBML index blocks
* Some PostgreSQL-specific type details may be simplified for diagram compatibility (kept as notes where relevant)

## Contributing

Issues and PRs are welcome — especially for:

* more edge-case coverage on PostgreSQL types
* better representation of advanced indexes/constraints in DBML
* real schema examples that currently fail dbdiagram.io parsing

Please keep the “no third-party Python dependencies” constraint.
