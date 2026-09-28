# -*- coding: utf-8 -*-
"""SQLite / PostgreSQL 양쪽을 쓰는 얇은 계층.

ADR-003 은 "DDL 을 PostgreSQL 호환으로 유지하고 동시 쓰기 주체가 둘 이상 생기면
전환한다" 였다. 웹앱이 붙고 PostgreSQL 을 쓸 수 있게 되었으므로 이제 둘 다 지원한다.

  sqlite:  파일 경로 또는 `sqlite:///경로`   — 단일 사용자·폐쇄망·테스트
  postgres: `postgresql://user:pw@host:port/db` — 표 27 의 기본

**append-only 는 두 엔진 모두에서 강제한다.** SQLite 는 트리거의 RAISE(ABORT),
PostgreSQL 은 트리거 함수의 RAISE EXCEPTION 이다. 주석으로만 지킨 규칙은
지켜지지 않는다.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence

PG_PREFIXES = ("postgresql://", "postgres://")


def is_postgres(dsn: str) -> bool:
    return str(dsn).startswith(PG_PREFIXES)


class Row(dict):
    """sqlite3.Row 와 psycopg dict_row 를 같은 모양으로 쓴다."""
    def __getitem__(self, k):
        if isinstance(k, int):
            return list(self.values())[k]
        return dict.__getitem__(self, k)


class Conn:
    """`?` 자리표시자 하나로 두 엔진을 다 쓴다."""

    def __init__(self, dsn: str):
        self.dsn = str(dsn)
        self.pg = is_postgres(self.dsn)
        if self.pg:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise SystemExit(
                    "PostgreSQL 을 쓰려면 psycopg 가 필요합니다:  "
                    "python -m pip install -e \".[web]\"   "
                    "(SQLite 로 쓰려면 --db data/otai.db)  (%s)" % exc)
            self._c = psycopg.connect(self.dsn, autocommit=True, row_factory=dict_row)
        else:
            path = self.dsn[len("sqlite:///"):] if self.dsn.startswith("sqlite:///") else self.dsn
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._c = sqlite3.connect(path, check_same_thread=False)
            self._c.row_factory = sqlite3.Row

    # ---- 실행 -----------------------------------------------------------
    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def execute(self, sql: str, args: Sequence = ()):
        cur = self._c.cursor()
        cur.execute(self._sql(sql), tuple(args))
        return cur

    def query(self, sql: str, args: Sequence = ()) -> List[Row]:
        cur = self.execute(sql, args)
        try:
            rows = cur.fetchall()
        except Exception:
            return []
        return [Row(r) if self.pg else Row({k: r[k] for k in r.keys()}) for r in rows]

    def one(self, sql: str, args: Sequence = ()) -> Optional[Row]:
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def insert_returning_id(self, sql: str, args: Sequence, table: str) -> int:
        if self.pg:
            cur = self.execute(sql.rstrip().rstrip(";") + " RETURNING id", args)
            r = cur.fetchone()
            return r["id"] if r else 0
        cur = self.execute(sql, args)
        self.commit()
        return cur.lastrowid

    def script(self, sql: str):
        if self.pg:
            self._c.execute(sql)
        else:
            self._c.executescript(sql)
        self.commit()

    def commit(self):
        if not self.pg:
            self._c.commit()

    def close(self):
        self._c.close()

    # ---- 오류 판별 ------------------------------------------------------
    @property
    def integrity_error(self):
        """append-only 위반을 잡을 때 쓰는 예외 타입."""
        if self.pg:
            import psycopg
            return (psycopg.errors.RaiseException, psycopg.errors.IntegrityError)
        return (sqlite3.IntegrityError,)


# --------------------------------------------------------------------------
# DDL 방언
# --------------------------------------------------------------------------
def pk(conn: Conn) -> str:
    return "BIGSERIAL PRIMARY KEY" if conn.pg else "INTEGER PRIMARY KEY"


_TRIGGER_RE = re.compile(
    r"CREATE TRIGGER IF NOT EXISTS (\w+)\s*"
    r"BEFORE (UPDATE|DELETE) ON (\w+)\s*"
    r"BEGIN SELECT RAISE\(ABORT,\s*'([^']*)'\s*\);\s*END;",
    re.I | re.S)


def translate_ddl(conn: Conn, ddl: str) -> str:
    """SQLite 로 쓴 DDL 을 PostgreSQL 로 옮긴다.

    append-only 트리거가 핵심이다 — 옮기다 빠뜨리면 불변 규칙 3 이 조용히 사라진다.
    """
    if not conn.pg:
        return ddl

    triggers = _TRIGGER_RE.findall(ddl)
    body = _TRIGGER_RE.sub("", ddl)

    body = body.replace("INTEGER PRIMARY KEY", "BIGSERIAL PRIMARY KEY")
    body = re.sub(r"\bTEXT PRIMARY KEY\b", "TEXT PRIMARY KEY", body)
    body = re.sub(r"--[^\n]*", "", body)          # 주석 제거 (psycopg 다중문 안전)

    out = [body]
    for name, event, table, msg in triggers:
        fn = "fn_" + name
        out.append("""
CREATE OR REPLACE FUNCTION {fn}() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION '{msg}'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS {name} ON {table};
CREATE TRIGGER {name} BEFORE {event} ON {table}
FOR EACH ROW EXECUTE FUNCTION {fn}();
""".format(fn=fn, name=name, table=table, event=event.upper(),
           msg=msg.replace("'", "''")))
    return "\n".join(out)
