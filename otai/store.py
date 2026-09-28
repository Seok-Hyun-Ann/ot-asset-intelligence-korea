# -*- coding: utf-8 -*-
"""Append-only 저장소 (슬라이스 1e).

불변 규칙 3: assertion 은 추가만 한다. 새 값이 기존 값을 덮어쓰지 않는다.
그 규칙을 주석이 아니라 **DB 트리거로 강제**한다 — UPDATE/DELETE 가 실패한다.

ADR-003: 슬라이스 1 은 SQLite 였고 DDL 만 PostgreSQL 호환으로 유지했다.
웹앱이 붙으면서 전환 조건이 충족되어 이제 `otai/db.py` 를 통해 **둘 다** 쓴다.
append-only 트리거도 함께 옮겨진다 — SQLite 는 `RAISE(ABORT)`,
PostgreSQL 은 트리거 함수의 `RAISE EXCEPTION` 이다 (`translate_ddl`).

**wall-clock 을 읽지 않는다.** 기록 시각이 필요하면 호출자가 넘긴다
(판정의 as_of). 머신 시계를 읽는 순간 재현성 게이트가 깨진다.
"""
from __future__ import annotations

import json
from typing import List, Optional

from .applicability import Decision
from .db import Conn, Row, translate_ddl

SCHEMA = """
CREATE TABLE IF NOT EXISTS assertion (
    id           INTEGER PRIMARY KEY,
    asset_id     TEXT NOT NULL,
    predicate    TEXT NOT NULL,
    object       TEXT,
    source       TEXT,
    method       TEXT,
    observed_at  TEXT,
    evidence_id  TEXT,
    as_of        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decision (
    id             INTEGER PRIMARY KEY,
    asset_id       TEXT NOT NULL,
    advisory_id    TEXT NOT NULL,
    as_of          TEXT NOT NULL,
    status         TEXT NOT NULL,
    rule_version   TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    input_hash     TEXT NOT NULL,
    card_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event (
    id                  INTEGER PRIMARY KEY,
    as_of               TEXT NOT NULL,
    actor               TEXT NOT NULL,
    -- 인증되지 않은 주장을 인증된 사실처럼 기록하면 감사 로그가 감사 가치를 잃는다.
    -- 슬라이스 4 에는 인증이 없으므로 기본값은 0 이다 (ADR-019).
    actor_authenticated INTEGER NOT NULL DEFAULT 0,
    action              TEXT NOT NULL,
    subject             TEXT,
    detail_json         TEXT,
    correlation_id      TEXT
);

CREATE TABLE IF NOT EXISTS exception (
    id               INTEGER PRIMARY KEY,
    asset_id         TEXT NOT NULL,
    advisory_id      TEXT NOT NULL,
    bucket_accepted  TEXT NOT NULL,
    reason           TEXT NOT NULL,
    approver         TEXT NOT NULL,
    granted_as_of    TEXT NOT NULL,
    expires_as_of    TEXT NOT NULL,
    reevaluate_on    TEXT
);

CREATE TABLE IF NOT EXISTS identity_link (
    id            INTEGER PRIMARY KEY,
    event         TEXT NOT NULL,          -- merge | split
    from_asset_id TEXT NOT NULL,
    to_asset_id   TEXT NOT NULL,
    approver      TEXT NOT NULL,
    as_of         TEXT NOT NULL,
    reason        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_link_from ON identity_link (from_asset_id);
CREATE INDEX IF NOT EXISTS ix_link_to ON identity_link (to_asset_id);
CREATE INDEX IF NOT EXISTS ix_decision_lookup ON decision (asset_id, advisory_id, as_of);
CREATE INDEX IF NOT EXISTS ix_event_action ON event (action, as_of);
CREATE INDEX IF NOT EXISTS ix_exception_lookup ON exception (asset_id, advisory_id);
CREATE INDEX IF NOT EXISTS ix_assertion_subject ON assertion (asset_id, predicate);

-- 불변 규칙 3 을 저장 계층에서 강제한다
CREATE TRIGGER IF NOT EXISTS assertion_is_append_only_update
BEFORE UPDATE ON assertion
BEGIN SELECT RAISE(ABORT, 'assertion 은 append-only 입니다. 새 assertion 을 추가하세요.'); END;

CREATE TRIGGER IF NOT EXISTS assertion_is_append_only_delete
BEFORE DELETE ON assertion
BEGIN SELECT RAISE(ABORT, 'assertion 은 append-only 입니다.'); END;

CREATE TRIGGER IF NOT EXISTS decision_is_append_only_update
BEFORE UPDATE ON decision
BEGIN SELECT RAISE(ABORT, 'decision 은 append-only 입니다. 새 판정을 추가하세요.'); END;

CREATE TRIGGER IF NOT EXISTS decision_is_append_only_delete
BEFORE DELETE ON decision
BEGIN SELECT RAISE(ABORT, 'decision 은 append-only 입니다.'); END;

CREATE TRIGGER IF NOT EXISTS event_is_append_only_update
BEFORE UPDATE ON event
BEGIN SELECT RAISE(ABORT, '감사 이벤트는 append-only 입니다.'); END;

CREATE TRIGGER IF NOT EXISTS event_is_append_only_delete
BEFORE DELETE ON event
BEGIN SELECT RAISE(ABORT, '감사 이벤트는 append-only 입니다. 삭제할 수 없습니다.'); END;

CREATE TRIGGER IF NOT EXISTS exception_is_append_only_update
BEFORE UPDATE ON exception
BEGIN SELECT RAISE(ABORT, '예외는 append-only 입니다. 철회하려면 만료된 새 예외를 추가하세요.'); END;

CREATE TRIGGER IF NOT EXISTS exception_is_append_only_delete
BEFORE DELETE ON exception
BEGIN SELECT RAISE(ABORT, '예외는 append-only 입니다.'); END;

CREATE TRIGGER IF NOT EXISTS link_is_append_only_update
BEFORE UPDATE ON identity_link
BEGIN SELECT RAISE(ABORT, '계보는 append-only 입니다. 되돌리려면 반대 방향 링크를 추가하세요.'); END;

CREATE TRIGGER IF NOT EXISTS link_is_append_only_delete
BEFORE DELETE ON identity_link
BEGIN SELECT RAISE(ABORT, '계보는 append-only 입니다.'); END;
"""

# 감사 대상 행위 (FR-GOV-002). 새 행위를 추가하면 여기에 등록한다.
ACTIONS = (
    "decision_recorded", "bundle_exported", "bundle_verified", "bundle_rejected",
    "bundle_applied", "bundle_rolled_back", "import_dry_run", "import_applied",
    "exception_granted", "queue_rendered", "identity_merged", "identity_split",
    "policy_approved", "policy_rolled_back", "sources_compared",
    "demo_assets_purged",
    # 프로젝트 파일 (ADR-038). 읽기도 기록한다 — 어떤 파일이 언제 들어왔는지가
    # 계보의 시작점이고, 그 해시가 거기서 나온 모든 값의 출처가 된다.
    "project_file_scanned", "project_file_applied",
    # 캡처 (ADR-039). 어떤 파일이 언제 들어왔는지가 토폴로지 계보의 시작점이다.
    "capture_scanned", "capture_applied",
)


class Store:
    def __init__(self, dsn):
        self.dsn = str(dsn)
        self.conn = Conn(self.dsn)
        self.conn.script(translate_ddl(self.conn, SCHEMA))

    @property
    def backend(self) -> str:
        return "postgresql" if self.conn.pg else "sqlite"

    @property
    def path(self) -> str:      # 이전 이름 유지 (SQLite 경로를 쓰던 호출부)
        return self.dsn

    # ---- 쓰기 -------------------------------------------------------------
    def append_assertion(self, asset_id, predicate, object_, as_of,
                         source=None, method=None, observed_at=None, evidence_id=None) -> int:
        return self.conn.insert_returning_id(
            "INSERT INTO assertion (asset_id, predicate, object, source, method,"
            " observed_at, evidence_id, as_of) VALUES (?,?,?,?,?,?,?,?)",
            (asset_id, predicate, object_, source, method, observed_at, evidence_id, as_of),
            "assertion")

    # ---- 감사 (FR-GOV-002) ----------------------------------------------
    def log(self, action: str, *, as_of: str, actor: str = "unknown",
            actor_authenticated: bool = False, subject: str = None,
            detail: dict = None, correlation_id: str = None) -> int:
        """감사 이벤트를 남긴다. 삭제·수정 불가 (트리거로 강제).

        `actor_authenticated` 는 슬라이스 4 에서 항상 False 다 — 인증이 없기
        때문이다. 슬라이스 5 에서 OIDC 가 붙으면 True 가 되고, 과거 기록은
        여전히 "그때는 인증이 없었다" 를 정확히 말한다 (ADR-019).
        """
        if action not in ACTIONS:
            raise ValueError("등록되지 않은 감사 행위: %r" % action)
        return self.conn.insert_returning_id(
            "INSERT INTO event (as_of, actor, actor_authenticated, action, subject,"
            " detail_json, correlation_id) VALUES (?,?,?,?,?,?,?)",
            (as_of, actor, 1 if actor_authenticated else 0, action, subject,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True), correlation_id),
            "event")

    def events(self, action: str = None) -> List[Row]:
        sql, args = "SELECT * FROM event", []
        if action:
            sql += " WHERE action = ?"
            args.append(action)
        return self.conn.query(sql + " ORDER BY id", args)

    # ---- 예외 (FR-ACT-001) ----------------------------------------------
    def grant_exception(self, asset_id: str, advisory_id: str, *, reason: str,
                        approver: str, granted_as_of: str, expires_as_of: str,
                        bucket_accepted: str = "P4", reevaluate_on: str = None) -> int:
        rowid = self.conn.insert_returning_id(
            "INSERT INTO exception (asset_id, advisory_id, bucket_accepted, reason,"
            " approver, granted_as_of, expires_as_of, reevaluate_on)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (asset_id, advisory_id, bucket_accepted, reason, approver,
             granted_as_of, expires_as_of, reevaluate_on),
            "exception")
        self.log("exception_granted", as_of=granted_as_of, actor=approver,
                 subject="%s/%s" % (asset_id, advisory_id),
                 detail={"reason": reason, "expires_as_of": expires_as_of})
        return rowid

    def active_exception(self, asset_id: str, advisory_id: str, as_of: str):
        """as_of 시점에 유효한 예외. 만료된 것은 돌려주지 않는다."""
        rows = self.conn.query(
            "SELECT * FROM exception WHERE asset_id = ? AND advisory_id = ?"
            " ORDER BY id DESC", (asset_id, advisory_id))
        for r in rows:
            if r["granted_as_of"] <= as_of < r["expires_as_of"]:
                return r
        return None

    # ---- 정체성 계보 (FR-ID-003) -----------------------------------------
    def merge_identity(self, from_asset_id: str, into_asset_id: str, *,
                       approver: str, as_of: str, reason: str) -> int:
        """자산을 병합한다. **과거 판정을 다시 쓰지 않는다.**

        ADR-025: 병합은 링크를 추가할 뿐이고 decision 행은 원래 asset_id 로 남는다.
        과거를 새 id 로 재계산하면 append-only 불변 규칙을 정면으로 위반한다.
        조회는 `history(..., include_lineage=True)` 가 두 계보를 합쳐 보여준다.
        """
        if not approver:
            raise ValueError("병합에는 승인자가 필요합니다 (FR-ID-003)")
        rowid = self.conn.insert_returning_id(
            "INSERT INTO identity_link (event, from_asset_id, to_asset_id, approver,"
            " as_of, reason) VALUES ('merge',?,?,?,?,?)",
            (from_asset_id, into_asset_id, approver, as_of, reason), "identity_link")
        self.log("identity_merged", as_of=as_of, actor=approver,
                 subject="%s→%s" % (from_asset_id, into_asset_id),
                 detail={"reason": reason})
        return rowid

    def split_identity(self, asset_id: str, into_asset_id: str, *,
                       approver: str, as_of: str, reason: str) -> int:
        if not approver:
            raise ValueError("분리에는 승인자가 필요합니다 (FR-ID-003)")
        rowid = self.conn.insert_returning_id(
            "INSERT INTO identity_link (event, from_asset_id, to_asset_id, approver,"
            " as_of, reason) VALUES ('split',?,?,?,?,?)",
            (asset_id, into_asset_id, approver, as_of, reason), "identity_link")
        self.log("identity_split", as_of=as_of, actor=approver,
                 subject="%s→%s" % (asset_id, into_asset_id),
                 detail={"reason": reason})
        return rowid

    def lineage(self, asset_id: str, as_of: str = "9999-12-31") -> List[str]:
        """as_of 시점까지의 링크로 연결된 자산 id 전체 (양방향 추이 폐포)."""
        rows = self.conn.query(
            "SELECT from_asset_id, to_asset_id FROM identity_link WHERE as_of <= ?",
            (as_of,))
        adj = {}
        for r in rows:
            adj.setdefault(r["from_asset_id"], set()).add(r["to_asset_id"])
            adj.setdefault(r["to_asset_id"], set()).add(r["from_asset_id"])
        seen, stack = {asset_id}, [asset_id]
        while stack:
            cur = stack.pop()
            for nxt in adj.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return sorted(seen)

    def record(self, d: Decision) -> int:
        return self.conn.insert_returning_id(
            "INSERT INTO decision (asset_id, advisory_id, as_of, status, rule_version,"
            " parser_version, input_hash, card_json) VALUES (?,?,?,?,?,?,?,?)",
            (
                d.asset_id,
                str(d.evidence["advisory_id"]),
                d.as_of,
                d.status,
                d.rule_version,
                d.parser_version,
                d.input_hash,
                d.canonical_json(),
            ),
            "decision")

    # ---- 읽기 -------------------------------------------------------------
    def history(self, asset_id: str, advisory_id: Optional[str] = None,
                include_lineage: bool = False, as_of: str = "9999-12-31") -> List[Row]:
        """판정 이력. `include_lineage` 면 병합·분리로 연결된 자산까지 합친다.

        각 행은 원래 asset_id 를 그대로 갖는다 — 계보를 합쳐 보여줄 뿐 다시 쓰지 않는다.
        """
        ids = self.lineage(asset_id, as_of) if include_lineage else [asset_id]
        placeholders = ",".join("?" * len(ids))
        sql = "SELECT * FROM decision WHERE asset_id IN (%s)" % placeholders
        args = list(ids)
        if advisory_id:
            sql += " AND advisory_id = ?"
            args.append(advisory_id)
        return self.conn.query(sql + " ORDER BY id", args)

    def assertions(self, asset_id: str) -> List[Row]:
        return self.conn.query(
            "SELECT * FROM assertion WHERE asset_id = ? ORDER BY id", (asset_id,))

    def current_value(self, asset_id: str, predicate: str) -> Optional[str]:
        """현재 값은 저장된 것이 아니라 **계산한 뷰**다 (불변 규칙 3).

        슬라이스 1 규칙: observed_at 이 가장 최근인 assertion. 권위·확신도까지
        반영한 완전한 뷰는 슬라이스 2 에서 소스 권위(표 13)와 함께 붙인다.
        """
        rows = [r for r in self.assertions(asset_id) if r["predicate"] == predicate]
        if not rows:
            return None
        rows.sort(key=lambda r: (r["observed_at"] or "", r["id"]))
        return rows[-1]["object"]

    def close(self):
        self.conn.close()
