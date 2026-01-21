#!/usr/bin/env python3
"""
pg_schema_to_dbml.py — Dump PostgreSQL schema to DBML (dbdiagram.io style)

How it works (high level)
- Uses the native `psql` CLI (no Python DB drivers; standard library only).
- Runs set-based catalog queries (pg_catalog) and streams results via `COPY (...) TO STDOUT WITH CSV`.
- Builds an in-memory model (schemas/enums/tables/columns/constraints/indexes), then writes deterministic DBML.
- Normalizes common PostgreSQL type spellings to DBML-friendly aliases (e.g., character varying -> varchar).

Usage examples
  # Using discrete connection params (password via env var name or .pgpass)
  python pg_schema_to_dbml.py \
    --host localhost --port 5432 --db mydb --user myuser \
    --password-env PG_PASSWORD \
    --schema public \
    --out docs/contracts/db/schema.dbml

  # Multiple schemas
  python pg_schema_to_dbml.py \
    --host localhost --port 5432 --db mydb --user myuser \
    --password-env PG_PASSWORD \
    --schema public --schema billing \
    --out schema.dbml

  # DSN overrides host/port/db/user
  python pg_schema_to_dbml.py \
    --dsn "postgresql://user@host:5432/dbname?sslmode=require" \
    --password-env PG_PASSWORD \
    --schema public \
    --include-views \
    --out schema.dbml

Notes
- Password must NOT be provided as a CLI value. Use --password-env NAME (reads os.environ[NAME]) or rely on .pgpass.
- By default, system schemas (pg_catalog, information_schema, etc.) are excluded unless explicitly requested via --schema.
- Views are excluded by default; add --include-views to include (as tables with Note).
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


SYSTEM_SCHEMAS = {
    "pg_catalog",
    "information_schema",
    "pg_toast",
    "pg_temp_1",
    "pg_toast_temp_1",
}
# Also exclude common extension/internal schemas unless explicitly requested
DEFAULT_EXCLUDE_SCHEMA_PREFIXES = ("pg_",)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def die(msg: str, code: int = 2) -> "NoReturn":
    eprint(msg)
    raise SystemExit(code)


def safe_env_with_password(password_env_name: Optional[str]) -> Dict[str, str]:
    """
    Return a subprocess env dict that sets PGPASSWORD if password_env_name is provided and exists.
    Never prints the password or the env var value.
    """
    env = dict(os.environ)
    if password_env_name:
        if password_env_name not in os.environ:
            die(
                f"ERROR: --password-env was set to '{password_env_name}', but that env var is not present.\n"
                f"       Either set it (export {password_env_name}=...) or omit --password-env and rely on .pgpass.",
                2,
            )
        # psql honors PGPASSWORD
        env["PGPASSWORD"] = os.environ[password_env_name]
    return env


def which_or_die(exe: str) -> str:
    path = shutil.which(exe)
    if not path:
        die(
            f"ERROR: Required executable '{exe}' not found on PATH.\n"
            f"       Please install PostgreSQL client tools (psql) and ensure it's available in PATH.",
            127,
        )
    return path


def sql_string_literal(s: str) -> str:
    # Safe for embedding schema names into SQL literals.
    return "'" + s.replace("'", "''") + "'"


def csv_copy_sql(select_sql: str) -> str:
    # Ensure a single statement for ON_ERROR_STOP.
    return f"COPY (\n{select_sql}\n) TO STDOUT WITH (FORMAT csv, HEADER false)"


def run_psql_copy(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    sql: str,
    env: Dict[str, str],
) -> List[List[str]]:
    """
    Execute a psql COPY-to-STDOUT CSV query and return rows (each row is list of strings).
    """
    # -X no .psqlrc, -v ON_ERROR_STOP for failing on errors, -q quiet
    cmd = [
        psql_path,
        "-X",
        "--no-psqlrc",
        "-v",
        "ON_ERROR_STOP=1",
        "-q",
        *conn_args,
        "-c",
        sql,
    ]

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as ex:
        die(f"ERROR: Failed to execute psql: {ex}", 127)

    if proc.returncode != 0:
        # Do not print secrets; stderr may include connection info but not password.
        err = proc.stderr.strip() or "(no stderr output)"
        die(f"ERROR: psql failed (exit {proc.returncode}).\n{err}", proc.returncode)

    out = proc.stdout
    rows: List[List[str]] = []
    # COPY CSV uses standard CSV rules; values can contain commas/quotes/newlines safely.
    reader = csv.reader(out.splitlines())
    for row in reader:
        rows.append(row)
    return rows


def build_conn_args(
    *,
    dsn: Optional[str],
    host: Optional[str],
    port: Optional[int],
    db: Optional[str],
    user: Optional[str],
) -> List[str]:
    args: List[str] = []
    if dsn:
        # psql: --dbname can be a connstring/DSN URL
        args += ["--dbname", dsn]
        return args
    if host:
        args += ["--host", host]
    if port:
        args += ["--port", str(port)]
    if db:
        args += ["--dbname", db]
    if user:
        args += ["--username", user]
    return args


_DBML_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def dbml_ident(name: str) -> str:
    """
    DBML identifiers are safest unquoted when lowercase snake_case. Otherwise, use backticks.
    """
    if _DBML_IDENT_RE.match(name):
        return name
    return "`" + name.replace("`", "``") + "`"


def dbml_fq(schema: str, name: str) -> str:
    return f"{dbml_ident(schema)}.{dbml_ident(name)}"


# dbdiagram.io's parser is stricter than "DBML in general" for identifiers:
# even backticked names can fail when they contain punctuation like ';' or some unicode.
# To ensure rendering, we sanitize column names into ASCII snake_case identifiers and
# preserve the original PostgreSQL name as a Note.
_SAN_RE_NON_ALNUM = re.compile(r"[^A-Za-z0-9_]+")
_SAN_RE_MULTI_UNDERSCORE = re.compile(r"_+")


def _stable_suffix(name: str) -> str:
    # Stable short suffix for uniqueness; avoids importing hashlib for very large schemas?
    # (hashlib is stdlib; use it anyway for stability)
    import hashlib
    h = hashlib.sha1(name.encode("utf-8", errors="surrogatepass")).hexdigest()
    return h[:8]


def sanitize_dbml_column_name(original: str, used: set[str]) -> str:
    """
    Convert an arbitrary PostgreSQL identifier to a dbdiagram-safe DBML identifier.

    Rules:
      - ASCII only: [a-z_][a-z0-9_]*
      - Replace non-alnum with underscores, collapse underscores, lowercase.
      - If result is empty or starts with digit, prefix with 'col_' + stable hash.
      - Ensure uniqueness within the table (append _2, _3... deterministically).
    """
    s = original.strip()
    base = _SAN_RE_NON_ALNUM.sub("_", s)
    base = _SAN_RE_MULTI_UNDERSCORE.sub("_", base).strip("_").lower()

    if not base or base[0].isdigit():
        base = f"col_{_stable_suffix(original)}"
    if base == "_":
        base = f"col_{_stable_suffix(original)}"

    cand = base
    i = 2
    while cand in used:
        cand = f"{base}_{i}"
        i += 1
    used.add(cand)
    return cand


def sanitize_columns_for_dbdiagram(
    tables: Dict[Tuple[str, str], "Table"],
    fks: List["ForeignKey"],
) -> List["ForeignKey"]:
    """
    Mutates tables/columns/index definitions to use sanitized column names.

    Returns updated FK list with columns renamed on both sides to match sanitized names.

    We preserve original names in Column.orig_name and add a column note:
      "PG COLUMN: <original>"
    """
    # Build per-table mapping from original -> sanitized (only when needed, but always map deterministically)
    mapping: Dict[Tuple[str, str], Dict[str, str]] = {}

    for key, t in tables.items():
        used: set[str] = set()
        m: Dict[str, str] = {}
        # First pass: pick names, ensuring uniqueness even if originals collide under sanitization.
        for col in t.columns:
            orig = col.orig_name
            safe = sanitize_dbml_column_name(orig, used)
            m[orig] = safe
        mapping[key] = m

        # Apply to columns
        for col in t.columns:
            safe = m.get(col.orig_name, col.name)
            if safe != col.orig_name:
                col.notes.append(f"PG COLUMN: {col.orig_name}")
            col.name = safe

        # Apply to PK and uniques
        t.pk_cols = [m.get(c, c) for c in t.pk_cols]
        for u in t.uniques:
            u.columns = [m.get(c, c) for c in u.columns]

        # Apply to indexes
        for idx in t.indexes:
            if idx.columns:
                idx.columns = [m.get(c, c) for c in idx.columns]

    # Apply to FKs (source and destination mappings)
    new_fks: List[ForeignKey] = []
    for fk in fks:
        src_key = (fk.schema, fk.table)
        dst_key = (fk.ref_schema, fk.ref_table)
        src_map = mapping.get(src_key, {})
        dst_map = mapping.get(dst_key, {})
        new_fks.append(
            ForeignKey(
                schema=fk.schema,
                table=fk.table,
                name=fk.name,
                columns=[src_map.get(c, c) for c in fk.columns],
                ref_schema=fk.ref_schema,
                ref_table=fk.ref_table,
                ref_columns=[dst_map.get(c, c) for c in fk.ref_columns],
                on_delete=fk.on_delete,
                on_update=fk.on_update,
            )
        )

    return new_fks


def dbml_str(s: str) -> str:
    """
    DBML string for note-like fields: "..." with basic escaping.
    """
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\n", "\\n")
    return f'"{s}"'


def dbml_default_expr(expr: str) -> str:
    """
    DBML default field supports backticked expressions.
    """
    expr = expr.strip()
    return "`" + expr.replace("`", "``") + "`"


def decode_action(code: str) -> str:
    # pg_constraint.confdeltype/confupdtype
    mapping = {
        "a": "no action",
        "r": "restrict",
        "c": "cascade",
        "n": "set null",
        "d": "set default",
    }
    return mapping.get(code, "no action")


@dataclass(frozen=True)
class EnumValue:
    label: str
    sort_order: float


@dataclass
class EnumType:
    schema: str
    name: str
    values: List[EnumValue] = field(default_factory=list)


@dataclass
class Column:
    orig_name: str
    name: str
    data_type: str  # raw PG format_type
    not_null: bool
    default_expr: Optional[str]
    comment: Optional[str]
    identity: str  # '', 'a', 'd' (always/by default)
    generated: str  # '', 's' (stored)
    pk: bool = False
    unique: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class IndexDef:
    name: str
    columns: Optional[List[str]]  # None when expression/unsupported
    unique: bool
    note: Optional[str] = None


@dataclass
class UniqueConstraint:
    name: str
    columns: List[str]


@dataclass
class Table:
    schema: str
    name: str
    relkind: str  # r/p/v/m
    comment: Optional[str]
    columns: List[Column] = field(default_factory=list)
    pk_cols: List[str] = field(default_factory=list)
    uniques: List[UniqueConstraint] = field(default_factory=list)
    indexes: List[IndexDef] = field(default_factory=list)
    table_notes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ForeignKey:
    schema: str
    table: str
    name: str
    columns: List[str]
    ref_schema: str
    ref_table: str
    ref_columns: List[str]
    on_delete: str
    on_update: str


def selected_schema_predicate(schemas: List[str]) -> str:
    lits = ", ".join(sql_string_literal(s) for s in schemas)
    return f"ns.nspname IN ({lits})"


def fetch_tables(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
    include_views: bool,
) -> Dict[Tuple[str, str], Table]:
    relkinds = ["r", "p"]
    if include_views:
        relkinds += ["v", "m"]

    relkind_lits = ", ".join(sql_string_literal(k) for k in relkinds)
    pred = selected_schema_predicate(schemas)

    sql = csv_copy_sql(
        f"""
        SELECT
          ns.nspname,
          c.relname,
          c.relkind,
          obj_description(c.oid, 'pg_class') AS comment
        FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE {pred}
          AND c.relkind IN ({relkind_lits})
        ORDER BY ns.nspname, c.relname
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)

    tables: Dict[Tuple[str, str], Table] = {}
    for r in rows:
        schema, relname, relkind, comment = (r + ["", "", "", ""])[:4]
        key = (schema, relname)
        t = Table(schema=schema, name=relname, relkind=relkind, comment=comment or None)
        if relkind == "v":
            t.table_notes.append("VIEW")
        elif relkind == "m":
            t.table_notes.append("MATERIALIZED VIEW")
        tables[key] = t
    return tables


def fetch_columns(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
    include_views: bool,
) -> Dict[Tuple[str, str], List[Column]]:
    relkinds = ["r", "p"]
    if include_views:
        relkinds += ["v", "m"]

    relkind_lits = ", ".join(sql_string_literal(k) for k in relkinds)
    pred = selected_schema_predicate(schemas)

    sql = csv_copy_sql(
        f"""
        SELECT
          ns.nspname,
          c.relname,
          a.attnum::text,
          a.attname,
          format_type(a.atttypid, a.atttypmod) AS data_type,
          CASE WHEN a.attnotnull THEN 't' ELSE 'f' END AS not_null,
          COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '') AS default_expr,
          COALESCE(a.attidentity, '') AS identity,
          COALESCE(a.attgenerated, '') AS generated,
          COALESCE(col_description(a.attrelid, a.attnum), '') AS comment
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE {pred}
          AND c.relkind IN ({relkind_lits})
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY ns.nspname, c.relname, a.attnum
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)

    by_table: Dict[Tuple[str, str], List[Column]] = {}
    for r in rows:
        schema, relname, _attnum, attname, data_type, not_null_s, default_expr, identity, generated, comment = (
            (r + [""] * 10)[:10]
        )
        col = Column(
            orig_name=attname,
            name=attname,
            data_type=data_type,
            not_null=(not_null_s == "t"),
            default_expr=(default_expr if default_expr else None),
            comment=(comment if comment else None),
            identity=identity,
            generated=generated,
        )
        if identity:
            col.notes.append("IDENTITY")
        if generated:
            # For generated stored columns, pg_attrdef expression is in default_expr
            if col.default_expr:
                col.notes.append(f"GENERATED ALWAYS AS ({col.default_expr}) STORED")
                # Avoid rendering as DBML default (semantically different)
                col.default_expr = None
            else:
                col.notes.append("GENERATED COLUMN")
        by_table.setdefault((schema, relname), []).append(col)
    return by_table


def fetch_primary_and_unique_constraints(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
) -> Tuple[Dict[Tuple[str, str], List[str]], Dict[Tuple[str, str], List[UniqueConstraint]]]:
    pred = selected_schema_predicate(schemas)

    sql = csv_copy_sql(
        f"""
        WITH cons AS (
          SELECT
            con.conrelid,
            ns.nspname,
            c.relname,
            con.conname,
            con.contype,
            con.conkey
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace ns ON ns.oid = c.relnamespace
          WHERE {pred}
            AND con.contype IN ('p', 'u')
        ),
        expanded AS (
          SELECT
            conrelid,
            nspname,
            relname,
            conname,
            contype,
            k.attnum,
            k.ord
          FROM cons
          JOIN LATERAL unnest(cons.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
        )
        SELECT
          e.nspname,
          e.relname,
          e.conname,
          e.contype,
          string_agg(a.attname, ',' ORDER BY e.ord) AS cols
        FROM expanded e
        JOIN pg_attribute a ON a.attrelid = e.conrelid AND a.attnum = e.attnum
        GROUP BY e.nspname, e.relname, e.conname, e.contype
        ORDER BY e.nspname, e.relname, e.contype, e.conname
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)

    pk_by_table: Dict[Tuple[str, str], List[str]] = {}
    uniq_by_table: Dict[Tuple[str, str], List[UniqueConstraint]] = {}
    for r in rows:
        schema, relname, conname, contype, cols_csv = (r + [""] * 5)[:5]
        cols = [c for c in cols_csv.split(",") if c]
        key = (schema, relname)
        if contype == "p":
            pk_by_table[key] = cols
        elif contype == "u":
            uniq_by_table.setdefault(key, []).append(UniqueConstraint(name=conname, columns=cols))
    for key in uniq_by_table:
        uniq_by_table[key].sort(key=lambda u: (len(u.columns), u.columns, u.name))
    return pk_by_table, uniq_by_table


def fetch_foreign_keys(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
) -> List[ForeignKey]:
    pred = selected_schema_predicate(schemas)

    sql = csv_copy_sql(
        f"""
        WITH fks AS (
          SELECT
            con.oid AS conoid,
            con.conname,
            con.conrelid,
            con.confrelid,
            con.conkey,
            con.confkey,
            con.confdeltype,
            con.confupdtype
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace ns ON ns.oid = c.relnamespace
          WHERE {pred}
            AND con.contype = 'f'
        ),
        src AS (
          SELECT
            f.conoid,
            f.conname,
            f.conrelid,
            ns.nspname AS src_schema,
            c.relname AS src_table,
            k.attnum,
            k.ord,
            f.confrelid,
            f.confdeltype,
            f.confupdtype
          FROM fks f
          JOIN pg_class c ON c.oid = f.conrelid
          JOIN pg_namespace ns ON ns.oid = c.relnamespace
          JOIN LATERAL unnest(f.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
        ),
        dst AS (
          SELECT
            f.conoid,
            k.attnum,
            k.ord
          FROM fks f
          JOIN LATERAL unnest(f.confkey) WITH ORDINALITY AS k(attnum, ord) ON true
        )
        SELECT
          s.src_schema,
          s.src_table,
          s.conname,
          string_agg(sa.attname, ',' ORDER BY s.ord) AS src_cols,
          dns.nspname AS dst_schema,
          dc.relname AS dst_table,
          string_agg(da.attname, ',' ORDER BY d.ord) AS dst_cols,
          s.confdeltype,
          s.confupdtype
        FROM src s
        JOIN pg_attribute sa ON sa.attrelid = s.conrelid AND sa.attnum = s.attnum
        JOIN pg_class dc ON dc.oid = s.confrelid
        JOIN pg_namespace dns ON dns.oid = dc.relnamespace
        JOIN dst d ON d.conoid = s.conoid AND d.ord = s.ord
        JOIN pg_attribute da ON da.attrelid = s.confrelid AND da.attnum = d.attnum
        GROUP BY
          s.src_schema, s.src_table, s.conname,
          dns.nspname, dc.relname,
          s.confdeltype, s.confupdtype
        ORDER BY s.src_schema, s.src_table, s.conname
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)

    out: List[ForeignKey] = []
    for r in rows:
        (
            src_schema,
            src_table,
            conname,
            src_cols_csv,
            dst_schema,
            dst_table,
            dst_cols_csv,
            confdeltype,
            confupdtype,
        ) = (r + [""] * 9)[:9]
        out.append(
            ForeignKey(
                schema=src_schema,
                table=src_table,
                name=conname,
                columns=[c for c in src_cols_csv.split(",") if c],
                ref_schema=dst_schema,
                ref_table=dst_table,
                ref_columns=[c for c in dst_cols_csv.split(",") if c],
                on_delete=decode_action(confdeltype),
                on_update=decode_action(confupdtype),
            )
        )
    return out


def fetch_enums(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
) -> Dict[Tuple[str, str], EnumType]:
    pred = selected_schema_predicate(schemas)
    sql = csv_copy_sql(
        f"""
        SELECT
          ns.nspname,
          t.typname,
          e.enumlabel,
          e.enumsortorder::text
        FROM pg_type t
        JOIN pg_namespace ns ON ns.oid = t.typnamespace
        JOIN pg_enum e ON e.enumtypid = t.oid
        WHERE {pred}
          AND t.typtype = 'e'
        ORDER BY ns.nspname, t.typname, e.enumsortorder
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)
    enums: Dict[Tuple[str, str], EnumType] = {}
    for r in rows:
        schema, typname, label, sort_s = (r + ["", "", "", "0"])[:4]
        key = (schema, typname)
        et = enums.get(key)
        if not et:
            et = EnumType(schema=schema, name=typname)
            enums[key] = et
        try:
            sort = float(sort_s)
        except ValueError:
            sort = float(len(et.values))
        et.values.append(EnumValue(label=label, sort_order=sort))
    return enums


def fetch_indexes(
    *,
    psql_path: str,
    conn_args: Sequence[str],
    env: Dict[str, str],
    schemas: List[str],
    include_views: bool,
) -> Dict[Tuple[str, str], List[IndexDef]]:
    relkinds = ["r", "p"]
    if include_views:
        relkinds += ["v", "m"]
    relkind_lits = ", ".join(sql_string_literal(k) for k in relkinds)
    pred = selected_schema_predicate(schemas)

    sql = csv_copy_sql(
        f"""
        WITH idx AS (
          SELECT
            ns.nspname AS schema,
            tbl.oid AS tbloid,
            tbl.relname AS table_name,
            ic.relname AS index_name,
            i.indisunique,
            i.indisprimary,
            i.indisvalid,
            i.indpred IS NOT NULL AS is_partial,
            i.indexprs IS NOT NULL AS has_expr,
            i.indkey,
            pg_get_indexdef(i.indexrelid) AS indexdef
          FROM pg_index i
          JOIN pg_class ic ON ic.oid = i.indexrelid
          JOIN pg_class tbl ON tbl.oid = i.indrelid
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
          WHERE {pred}
            AND tbl.relkind IN ({relkind_lits})
        ),
        expanded AS (
          SELECT
            schema, tbloid, table_name, index_name, indisunique, indisprimary, indisvalid, is_partial, has_expr, indexdef,
            k.attnum, k.ord
          FROM idx
          JOIN LATERAL unnest(idx.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
        )
        SELECT
          e.schema,
          e.table_name,
          e.index_name,
          CASE WHEN e.indisunique THEN 't' ELSE 'f' END AS is_unique,
          CASE WHEN e.indisprimary THEN 't' ELSE 'f' END AS is_primary,
          CASE WHEN e.indisvalid THEN 't' ELSE 'f' END AS is_valid,
          CASE WHEN e.is_partial THEN 't' ELSE 'f' END AS is_partial,
          CASE WHEN e.has_expr THEN 't' ELSE 'f' END AS has_expr,
          COALESCE(string_agg(a.attname, ',' ORDER BY e.ord) FILTER (WHERE e.attnum > 0), '') AS cols,
          e.indexdef
        FROM expanded e
        LEFT JOIN pg_attribute a ON a.attrelid = e.tbloid AND a.attnum = e.attnum
        GROUP BY
          e.schema, e.table_name, e.index_name,
          e.indisunique, e.indisprimary, e.indisvalid, e.is_partial, e.has_expr, e.indexdef
        ORDER BY e.schema, e.table_name, e.index_name
        """
    )
    rows = run_psql_copy(psql_path=psql_path, conn_args=conn_args, sql=sql, env=env)

    by_table: Dict[Tuple[str, str], List[IndexDef]] = {}
    for r in rows:
        schema, table, idx_name, is_unique, is_primary, is_valid, is_partial, has_expr, cols_csv, indexdef = (
            (r + [""] * 10)[:10]
        )
        if is_primary == "t":
            continue

        note_parts: List[str] = []
        if is_valid != "t":
            note_parts.append("INVALID INDEX")
        if is_partial == "t":
            note_parts.append("PARTIAL INDEX")
        if has_expr == "t":
            note_parts.append("EXPRESSION INDEX")

        cols = [c for c in cols_csv.split(",") if c] if cols_csv else []
        if has_expr == "t" or not cols:
            idx = IndexDef(
                name=idx_name,
                columns=None,
                unique=(is_unique == "t"),
                note="; ".join(note_parts + [f"DEF: {indexdef}"]).strip(),
            )
        else:
            idx = IndexDef(
                name=idx_name,
                columns=cols,
                unique=(is_unique == "t"),
                note="; ".join(note_parts).strip() or None,
            )

        by_table.setdefault((schema, table), []).append(idx)

    for key in by_table:
        by_table[key].sort(key=lambda i: (0 if i.unique else 1, i.columns or [], i.name))
    return by_table


def apply_constraints_and_indexes(
    tables: Dict[Tuple[str, str], "Table"],
    columns_by_table: Dict[Tuple[str, str], List["Column"]],
    pk_by_table: Dict[Tuple[str, str], List[str]],
    uniq_by_table: Dict[Tuple[str, str], List["UniqueConstraint"]],
    idx_by_table: Dict[Tuple[str, str], List["IndexDef"]],
) -> None:
    for key, t in tables.items():
        t.columns = columns_by_table.get(key, [])
        t.pk_cols = pk_by_table.get(key, [])
        t.uniques = uniq_by_table.get(key, [])
        t.indexes = idx_by_table.get(key, [])

        pk_set = set(t.pk_cols)
        single_unique_cols: set[str] = {u.columns[0] for u in t.uniques if len(u.columns) == 1}

        for c in t.columns:
            if c.name in pk_set:
                c.pk = True
            if c.name in single_unique_cols:
                c.unique = True

            if c.comment:
                c.notes.append(f"COMMENT: {c.comment}")

        if t.comment:
            t.table_notes.append(f"COMMENT: {t.comment}")

        for idx in t.indexes:
            if idx.note and (idx.columns is None):
                t.table_notes.append(f"INDEX {idx.name}: {idx.note}")
            elif idx.note and idx.columns is not None:
                t.table_notes.append(f"INDEX {idx.name}: {idx.note}")


def normalize_schemas(requested: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for s in requested:
        if s not in seen:
            seen.add(s)
            out.append(s)
    out.sort()
    return out


def should_warn_system_schemas(schemas: List[str]) -> bool:
    return any(s in SYSTEM_SCHEMAS or s.startswith(DEFAULT_EXCLUDE_SCHEMA_PREFIXES) for s in schemas)


_TYPE_PREFIX_REPLACEMENTS: List[Tuple[re.Pattern[str], str]] = [
    # Most important for dbdiagram.io compatibility: "character varying" -> "varchar"
    (re.compile(r"^character\s+varying\b", re.IGNORECASE), "varchar"),
    (re.compile(r"^character\b", re.IGNORECASE), "char"),
    (re.compile(r"^timestamp\s+without\s+time\s+zone\b", re.IGNORECASE), "timestamp"),
    (re.compile(r"^timestamp\s+with\s+time\s+zone\b", re.IGNORECASE), "timestamp"),  # keep simple for dbdiagram
    (re.compile(r"^time\s+without\s+time\s+zone\b", re.IGNORECASE), "time"),
    (re.compile(r"^time\s+with\s+time\s+zone\b", re.IGNORECASE), "time"),
    (re.compile(r"^double\s+precision\b", re.IGNORECASE), "double"),
    (re.compile(r"^boolean\b", re.IGNORECASE), "bool"),
    # jsonb isn't always recognized; "json" tends to be accepted.
    (re.compile(r"^jsonb\b", re.IGNORECASE), "json"),
]


def normalize_dbml_type(raw_pg_type: str) -> Tuple[str, Optional[str]]:
    """
    Normalize PostgreSQL's format_type output to a DBML-friendly type string.

    dbdiagram.io's DBML parser is strict: type tokens must not contain spaces.
    We therefore map common multi-word PostgreSQL types to DBML-friendly aliases and,
    as a fallback, replace remaining spaces with underscores while preserving the
    original PostgreSQL spelling as a Note (so nothing is silently lost).

    Returns (type_string, extra_note)
      - type_string: the DBML type token (no spaces)
      - extra_note: optional note to preserve lost fidelity (e.g., "WITH TIME ZONE", original PG spelling)
    """
    t = " ".join(raw_pg_type.strip().split())
    if not t:
        return t, None

    original = t
    extra_notes: List[str] = []

    # Arrays in Postgres are rendered with [] suffix (e.g., varchar(64)[]).
    # dbdiagram.io interprets [] as the settings list, so types must not contain '[' or ']'.
    # We strip array brackets and preserve dimensionality as a note.
    dims = 0
    while t.endswith("[]"):
        t = t[:-2]
        dims += 1
    if dims:
        extra_notes.append(f"ARRAY{'[' + str(dims) + ']' if dims > 1 else ''}")

    lower = t.lower()

    # Preserve timezone-ness as note if we map to plain timestamp/time
    if lower.startswith("timestamp with time zone"):
        extra_notes.append("WITH TIME ZONE")
    elif lower.startswith("time with time zone"):
        extra_notes.append("WITH TIME ZONE")

    # Apply prefix replacements (case-insensitive), keeping any suffix like "(100)" or "[]"
    for pat, repl in _TYPE_PREFIX_REPLACEMENTS:
        if pat.search(t):
            t = pat.sub(repl, t)
            break

    # Normalize spacing around modifiers
    t = t.replace("varchar (", "varchar(").replace("char (", "char(")

    # If type still contains spaces, DBML parsers will likely choke.
    # Convert spaces to underscores and add the original spelling as a note.
    if " " in t:
        t = t.replace(" ", "_")
        extra_notes.append(f"PG TYPE: {original}")

    return t, ("; ".join(extra_notes) if extra_notes else None)


def dbml_type_from_pg(col: Column) -> str:
    """
    DBML generally tolerates many type strings, but dbdiagram.io is picky.
    We normalize known problematic PostgreSQL spellings (notably 'character varying').
    """
    normalized, extra_note = normalize_dbml_type(col.data_type)
    if extra_note:
        # Add as note on column to avoid losing semantics.
        col.notes.append(extra_note)
    return normalized


def render_dbml(
    enums: Dict[Tuple[str, str], EnumType],
    tables: Dict[Tuple[str, str], Table],
    fks: List[ForeignKey],
) -> str:
    lines: List[str] = []
    lines.append("// Generated by pg_schema_to_dbml.py")
    lines.append("")

    for (schema, name) in sorted(enums.keys(), key=lambda k: (k[0], k[1])):
        et = enums[(schema, name)]
        lines.append(f"Enum {dbml_fq(et.schema, et.name)} {{")
        for v in sorted(et.values, key=lambda x: x.sort_order):
            lines.append(f"  {dbml_str(v.label)}")
        lines.append("}")
        lines.append("")

    for key in sorted(tables.keys(), key=lambda k: (k[0], k[1])):
        t = tables[key]
        lines.append(f"Table {dbml_fq(t.schema, t.name)} {{")

        for c in t.columns:
            attrs: List[str] = []
            if c.pk:
                attrs.append("pk")
            if c.not_null:
                attrs.append("not null")
            if c.unique:
                attrs.append("unique")
            if c.default_expr:
                attrs.append(f"default: {dbml_default_expr(c.default_expr)}")
            if c.notes:
                attrs.append(f"note: {dbml_str('; '.join(c.notes))}")

            attrs_s = ""
            if attrs:
                attrs_s = " [" + ", ".join(attrs) + "]"

            lines.append(f"  {dbml_ident(c.name)} {dbml_type_from_pg(c)}{attrs_s}")

        index_entries: List[Tuple[List[str], bool]] = []
        for u in t.uniques:
            if len(u.columns) >= 2:
                index_entries.append((u.columns, True))
        for idx in t.indexes:
            if idx.columns:
                index_entries.append((idx.columns, idx.unique))

        dedup: Dict[Tuple[Tuple[str, ...], bool], None] = {}
        index_entries2: List[Tuple[List[str], bool]] = []
        for cols, uniq in index_entries:
            k = (tuple(cols), bool(uniq))
            if k in dedup:
                continue
            dedup[k] = None
            index_entries2.append((cols, uniq))
        index_entries2.sort(key=lambda x: (0 if x[1] else 1, x[0]))

        if index_entries2:
            lines.append("")
            lines.append("  Indexes {")
            for cols, uniq in index_entries2:
                cols_s = ", ".join(dbml_ident(c) for c in cols)
                if uniq:
                    lines.append(f"    ({cols_s}) [unique]")
                else:
                    lines.append(f"    ({cols_s})")
            lines.append("  }")

        if t.table_notes:
            note = "; ".join(t.table_notes)
            lines.append("")
            lines.append(f"  Note: {dbml_str(note)}")

        lines.append("}")
        lines.append("")

    fks_sorted = sorted(
        fks,
        key=lambda fk: (
            fk.schema,
            fk.table,
            fk.name,
            fk.columns,
            fk.ref_schema,
            fk.ref_table,
            fk.ref_columns,
        ),
    )
    for fk in fks_sorted:
        if len(fk.columns) == 1 and len(fk.ref_columns) == 1:
            lhs = f"{dbml_fq(fk.schema, fk.table)}.{dbml_ident(fk.columns[0])}"
            rhs = f"{dbml_fq(fk.ref_schema, fk.ref_table)}.{dbml_ident(fk.ref_columns[0])}"
        else:
            lhs_cols = ", ".join(dbml_ident(c) for c in fk.columns)
            rhs_cols = ", ".join(dbml_ident(c) for c in fk.ref_columns)
            lhs = f"{dbml_fq(fk.schema, fk.table)}.({lhs_cols})"
            rhs = f"{dbml_fq(fk.ref_schema, fk.ref_table)}.({rhs_cols})"

        opts: List[str] = []
        if fk.on_delete:
            opts.append(f"delete: {fk.on_delete}")
        if fk.on_update:
            opts.append(f"update: {fk.on_update}")
        opt_s = ""
        if opts:
            opt_s = " [" + ", ".join(opts) + "]"
        lines.append(f"Ref: {lhs} > {rhs}{opt_s}")

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="pg_schema_to_dbml.py",
        description="Dump PostgreSQL schema (catalog queries via psql) to DBML (dbdiagram.io style).",
    )

    conn = p.add_argument_group("connection")
    conn.add_argument("--dsn", help="PostgreSQL DSN/URL. If provided, overrides --host/--port/--db/--user.")
    conn.add_argument("--host", help="PostgreSQL host")
    conn.add_argument("--port", type=int, default=5432, help="PostgreSQL port (default: 5432)")
    conn.add_argument("--db", help="Database name")
    conn.add_argument("--user", help="Database user")
    conn.add_argument(
        "--password-env",
        help="Name of environment variable containing password (sets PGPASSWORD for psql). "
        "If omitted, relies on .pgpass or other libpq methods.",
    )

    sel = p.add_argument_group("selection")
    sel.add_argument(
        "--schema",
        action="append",
        required=True,
        help="Schema to include. Can be provided multiple times: --schema public --schema billing",
    )
    sel.add_argument(
        "--include-views",
        action="store_true",
        help="Include views/materialized views (rendered as tables with Note).",
    )

    out = p.add_argument_group("output")
    out.add_argument("--out", required=True, help="Output DBML file path")

    return p.parse_args(argv)


def validate_args(ns: argparse.Namespace) -> None:
    if ns.dsn:
        return
    missing = [k for k in ("host", "db", "user") if not getattr(ns, k)]
    if missing:
        die(
            "ERROR: Missing required connection params without --dsn: "
            + ", ".join(f"--{m}" for m in missing),
            2,
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = parse_args(argv)
    validate_args(ns)

    psql_path = which_or_die("psql")
    env = safe_env_with_password(ns.password_env)

    schemas = normalize_schemas(list(ns.schema or []))
    if not schemas:
        die("ERROR: At least one --schema is required.", 2)

    if should_warn_system_schemas(schemas):
        eprint(
            "WARNING: You requested one or more system/extension schemas (e.g., pg_catalog / pg_*). "
            "This may include internal objects."
        )

    conn_args = build_conn_args(dsn=ns.dsn, host=ns.host, port=ns.port, db=ns.db, user=ns.user)

    tables = fetch_tables(psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas, include_views=ns.include_views)
    if not tables:
        die("ERROR: No tables found for the selected schema(s).", 3)

    columns_by_table = fetch_columns(
        psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas, include_views=ns.include_views
    )
    pk_by_table, uniq_by_table = fetch_primary_and_unique_constraints(
        psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas
    )
    fks = fetch_foreign_keys(psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas)
    enums = fetch_enums(psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas)
    idx_by_table = fetch_indexes(
        psql_path=psql_path, conn_args=conn_args, env=env, schemas=schemas, include_views=ns.include_views
    )

    apply_constraints_and_indexes(tables, columns_by_table, pk_by_table, uniq_by_table, idx_by_table)

    # Sanitize column identifiers for dbdiagram.io compatibility (punctuation/unicode can break parsing)
    fks = sanitize_columns_for_dbdiagram(tables, fks)

    dbml = render_dbml(enums, tables, fks)

    out_path = Path(ns.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        out_path.write_text(dbml, encoding="utf-8", errors="strict")
    except OSError as ex:
        die(f"ERROR: Failed to write output file '{out_path}': {ex}", 1)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(141)

# -----------------------------------------------------------------------------
# Minimal manual test plan
#
# 1) Preconditions
#    - Ensure `psql` is installed and on PATH: psql --version
#    - Ensure you can connect using either .pgpass or env var.
#
# 2) dbdiagram.io compatibility check for varchar
#    - Create a test table with varchar:
#        CREATE TABLE public.t (a character varying(100) NOT NULL);
#    - Run export and confirm output uses "varchar(100)" (not "character varying(100)").
#
# 3) Basic schema export
#    export PG_PASSWORD='...'
#    python pg_schema_to_dbml.py --host localhost --port 5432 --db mydb --user myuser \
#      --password-env PG_PASSWORD --schema public --out /tmp/schema.dbml
#
# 4) Views included
#    python pg_schema_to_dbml.py --dsn "postgresql://user@localhost:5432/mydb" \
#      --password-env PG_PASSWORD --schema public --include-views --out /tmp/schema_views.dbml
#
# 5) Edge cases
#    - Composite PK, composite FK
#    - Enum type + enum columns
#    - Identity column
#    - Generated stored column (note should capture expression; no misleading default:)
#    - Expression/partial index (should appear as Table Note)
#
# 6) Error handling
#    - Unset password env var but pass --password-env -> should error without printing secret
#    - Wrong host/port -> clear psql error, non-zero exit
# -----------------------------------------------------------------------------
