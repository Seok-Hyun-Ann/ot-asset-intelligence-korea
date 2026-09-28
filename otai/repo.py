# -*- coding: utf-8 -*-
"""자산 저장소 — 여러 자산을 등록하고 목록으로 관리한다.

기획서 5장의 입력 단위는 장치 한 줄이 아니라
**Factory → Site/Area → Zone/Cell → Asset → Component** 계층이다.
지금까지는 자산이 픽스처 파일로만 존재했다. 웹앱에는 저장소가 필요하다.

관측은 여전히 **append-only** 다 (불변 규칙 3). 자산의 '현재 값' 은 저장된 것이
아니라 관측들에서 계산한 뷰이고, 자산 행은 그 뷰의 캐시일 뿐이다.

저장소는 `otai/db.py` 의 `Conn` 을 통해 SQLite 와 PostgreSQL 을 모두 쓴다 (ADR-027).
웹앱은 PostgreSQL 이 기본이고 CLI 는 SQLite 다. 두 엔진에서 목록·패싯·완성도가
같은 결과를 내는지는 `tests/test_postgres_backend.py` 가 확인한다.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .safeio import bounded_json_load
from .db import Conn, translate_ddl
from .model import Asset, asset_from_dict

SCHEMA = """
CREATE TABLE IF NOT EXISTS zone (
    zone_id     TEXT PRIMARY KEY,
    factory     TEXT NOT NULL,
    name        TEXT NOT NULL,
    purdue_level REAL,
    criticality TEXT
);

CREATE TABLE IF NOT EXISTS asset_row (
    asset_id      TEXT PRIMARY KEY,
    asset_type    TEXT NOT NULL,
    factory       TEXT,
    zone_id       TEXT,
    body_json     TEXT NOT NULL,      -- 부록 C 형식 원문
    created_as_of TEXT NOT NULL,
    updated_as_of TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_asset_zone ON asset_row (factory, zone_id);
CREATE INDEX IF NOT EXISTS ix_asset_type ON asset_row (asset_type);

"""

# 식별 완성도 L0~L5 (표 8) — 자산 목록의 핵심 열이다
LEVELS = [
    ("L5", lambda b: bool((b.get("operations") or {}).get("next_maintenance_window")
                          or (b.get("operations") or {}).get("safety_criticality"))
                     and bool(b.get("network"))),
    ("L4", lambda b: bool(b.get("network"))),
    ("L3", lambda b: any((c.get("version") or {}).get("raw")
                         for c in b.get("components") or [])),
    ("L2", lambda b: bool((b.get("identity") or {}).get("model_raw")
                          or (b.get("identity") or {}).get("order_number"))),
    ("L1", lambda b: bool((b.get("identity") or {}).get("vendor_raw"))),
    ("L0", lambda b: bool(b.get("asset_type"))),
]


def completeness(body: dict) -> str:
    """이 자산이 어느 단계까지 채워졌는가 (표 8)."""
    for name, test in LEVELS:
        try:
            if test(body):
                return name
        except Exception:
            continue
    return "L0"


class Repo:
    def __init__(self, dsn):
        self.dsn = str(dsn)
        self.conn = Conn(self.dsn)
        self.conn.script(translate_ddl(self.conn, SCHEMA))

    @property
    def backend(self) -> str:
        return "postgresql" if self.conn.pg else "sqlite"

    # ---- 쓰기 -------------------------------------------------------------
    def put(self, body: dict, as_of: str) -> str:
        aid = body["asset_id"]
        loc = body.get("location") or {}
        row = self.conn.one("SELECT created_as_of FROM asset_row WHERE asset_id=?", (aid,))
        created = row["created_as_of"] if row else as_of
        self.conn.execute(
            "INSERT INTO asset_row (asset_id, asset_type, factory, zone_id, body_json,"
            " created_as_of, updated_as_of) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(asset_id) DO UPDATE SET asset_type=excluded.asset_type,"
            " factory=excluded.factory, zone_id=excluded.zone_id,"
            " body_json=excluded.body_json, updated_as_of=excluded.updated_as_of",
            (aid, body.get("asset_type") or "unknown", loc.get("factory"), loc.get("zone"),
             json.dumps(body, ensure_ascii=False, sort_keys=True), created, as_of))
        if loc.get("zone"):
            self.conn.execute(
                "INSERT INTO zone (zone_id, factory, name) VALUES (?,?,?)"
                " ON CONFLICT (zone_id) DO NOTHING",
                (loc["zone"], loc.get("factory") or "", loc["zone"]))
        self.conn.commit()
        return aid

    def delete(self, asset_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM asset_row WHERE asset_id=?", (asset_id,))
        self.conn.commit()
        return (cur.rowcount or 0) > 0

    def import_dir(self, directory, as_of: str) -> int:
        n = 0
        for p in sorted(Path(directory).glob("*.json")):
            try:
                self.put(bounded_json_load(p), as_of)
                n += 1
            except Exception:
                continue
        return n

    # ---- 읽기 -------------------------------------------------------------
    def body(self, asset_id: str) -> Optional[dict]:
        r = self.conn.one("SELECT body_json FROM asset_row WHERE asset_id=?", (asset_id,))
        return json.loads(r["body_json"]) if r else None

    def asset(self, asset_id: str) -> Optional[Asset]:
        b = self.body(asset_id)
        return None if b is None else asset_from_dict(b)

    def list(self, factory=None, zone=None, asset_type=None,
             level=None, q=None) -> List[dict]:
        sql = "SELECT * FROM asset_row WHERE 1=1"
        args: List = []
        if factory:
            sql += " AND factory = ?"; args.append(factory)
        if zone:
            sql += " AND zone_id = ?"; args.append(zone)
        if asset_type:
            sql += " AND asset_type = ?"; args.append(asset_type)
        if q:
            sql += " AND (asset_id LIKE ? OR body_json LIKE ?)"
            args += ["%" + q + "%", "%" + q + "%"]
        out = []
        for r in self.conn.query(sql + " ORDER BY asset_id", args):
            b = json.loads(r["body_json"])
            lv = completeness(b)
            if level and lv != level:
                continue
            ident = b.get("identity") or {}
            out.append({
                "asset_id": r["asset_id"],
                "asset_type": r["asset_type"],
                "factory": r["factory"], "zone": r["zone_id"],
                "level": lv,
                "vendor": ident.get("vendor_raw"),
                "model": ident.get("model_raw") or ident.get("family_raw"),
                "firmware": next((c.get("version", {}).get("raw")
                                  for c in b.get("components") or []
                                  if (c.get("version") or {}).get("raw")), None),
                "lifecycle": b.get("lifecycle_status"),
                "safety": (b.get("operations") or {}).get("safety_criticality"),
                "updated_as_of": r["updated_as_of"],
                # 합성 자산은 스스로 그렇다고 선언한다 (ADR-013 과 같은 규칙)
                "synthetic": bool(b.get("synthetic")),
            })
        return out

    def facets(self) -> Dict[str, List[str]]:
        def col(name):
            return sorted({r[name] for r in self.conn.query(
                "SELECT DISTINCT %s FROM asset_row WHERE %s IS NOT NULL" % (name, name))
                if r[name]})
        levels = sorted({completeness(json.loads(r["body_json"]))
                         for r in self.conn.query("SELECT body_json FROM asset_row")})
        return {"factory": col("factory"), "zone": col("zone_id"),
                "asset_type": col("asset_type"), "level": levels}

    def count(self) -> int:
        r = self.conn.one("SELECT COUNT(*) AS c FROM asset_row")
        return int(r["c"]) if r else 0

    def close(self):
        self.conn.close()
