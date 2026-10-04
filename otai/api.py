# -*- coding: utf-8 -*-
"""REST API — 표 29 의 초기 인터페이스.

기획서 표 27 의 Application API 자리다. 판정·우선순위·경로 계산은 전부 기존
엔진(`otai/*`)을 그대로 부른다 — API 는 얇은 껍데기이고 규칙을 다시 쓰지 않는다.

인증이 없다 (슬라이스 5 보류). 그래서 **127.0.0.1 에만 바인딩한다.**
감사 로그의 actor 는 여전히 인증되지 않은 주장이다 (ADR-019).
"""
from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .applicability import PHRASES, decide_applicability
from .ask import apply_answer, next_question
from .attack import EDGE_TYPE_TECHNIQUES, find_bundle, load_attack
from .csaf import load_advisory
from .csvimport import apply_report, build_report
from .db import is_postgres
from .exposure import find as find_exposure
from .identity import could_match, index_advisory
from .kev import find_snapshot, load_kev
from .lifecycle import from_advisory as lifecycle_from_advisory
from .lifecycle import from_asset as lifecycle_from_asset
from .lifecycle import resolve as lifecycle_resolve
from .logic import Tri
from .paths import blocking_candidates, evaluate_reachability, find_paths
from .policy import DEFAULT_POLICY, active_policy, preview as policy_preview
from .priority import BUCKET_ORDER, BUCKET_PHRASES, LENS_PRESETS, evaluate_priority, sort_queue
from .repo import Repo, completeness
from .safeio import MAX_JSON_BYTES, UnsafeInput, check_json_bounds
from .capture import scan_capture, to_topology as capture_topology
from .projectfile import (build_vocabulary, devices as project_devices,
                          scan_file, to_asset as project_asset)
from .timeline import (ORDER as CHANGE_ORDER, diff as timeline_diff, known_at,
                       kev_at, summarize as change_counts, visible_at)
from .sources import (UNVERIFIED, compare_cvss, compare_products, link_advisories,
                      provenance_table, publisher_role)
from .store import Store
from .topology import load_topology

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
DIST = WEB / "dist"          # Vite 빌드 결과 (frontend/ → npm run build)

CTX: Dict[str, Any] = {}


def audit_dsn(db: str) -> str:
    """감사 저장소의 DSN.

    PostgreSQL 이면 **같은 데이터베이스**를 쓴다 — 테이블 이름이 겹치지 않고
    (`asset_row/zone` vs `assertion/decision/event/exception/identity_link`),
    무엇보다 감사 로그가 자산과 다른 곳에 흩어지면 계보가 끊긴다 (불변 규칙 5).
    SQLite 일 때만 파일을 나눈다 — 한 파일에 두 스키마를 넣던 기존 동작 유지.
    """
    return db if is_postgres(db) else str(db).replace(".db", "-audit.db")


class BoundedBody:
    """요청 본문을 `safeio` 한계 안에서만 들여보낸다 (ADR-041 · ADR-044).

    `body: dict = Body(...)` 는 **FastAPI 가 먼저 파싱한다** — 우리 코드가 돌기
    전이라 `MAX_JSON_BYTES` · `MAX_JSON_DEPTH` 가 전부 건너뛰어졌다. 그런데
    `POST /api/assets` 는 append-only 저장소에 바로 쓰고, 이 서버에는 인증도
    CSRF 토큰도 없다(127.0.0.1 전용이라는 고지뿐이다).

    `otai/server.py` 의 단순한 입력 서버는 이미 본문을 묶고 있었다 — FastAPI
    계층만 물려받지 못했다.

    **핸들러를 async 로 바꾸지 않는다.** 바꾸면 동기 DB 쓰기가 스레드풀이 아니라
    이벤트 루프에서 돌아 스윕 스레드와 함께 서버를 멈춘다. 그래서 ASGI 층에서
    본문을 모아 검사하고 **그대로 다시 흘려보낸다** — 지금 라우트와 앞으로
    추가될 라우트가 모두 덮인다.
    """

    #: 본문을 볼 메서드. GET·HEAD 는 본문이 없다.
    METHODS = ("POST", "PUT", "PATCH")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") not in self.METHODS:
            return await self.app(scope, receive, send)

        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                # 더 읽지 않는다. 읽어들이는 것 자체가 비용이다.
                return await self._reject(
                    send, 413, "본문 크기 %d바이트 초과 (상한 %d)"
                    % (total, MAX_JSON_BYTES))
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        raw = b"".join(chunks)

        if raw:
            try:
                check_json_bounds(raw, name=scope.get("path", "<body>"))
            except UnsafeInput as exc:
                return await self._reject(send, 400, str(exc))

        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": raw, "more_body": False}

        return await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send, status, detail):
        payload = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                (b"content-length", str(len(payload)).encode())]})
        await send({"type": "http.response.body", "body": payload})


def build_app(*, db: str, advisory_paths: List[Path], as_of: str,
              topology: Optional[Path], kev_path: Optional[Path]) -> FastAPI:
    db = str(db)
    repo = Repo(db)
    store = Store(audit_dsn(db))
    advisories = [load_advisory(p) for p in advisory_paths]
    # 자산 × 권고문 전부를 매 요청마다 판정할 수는 없다 (212만 쌍). 색인으로 거른다.
    indexes = [index_advisory(a) for a in advisories]
    snap = kev_path or find_snapshot()
    kev = load_kev(snap) if snap else None
    topo = load_topology(topology) if topology else None
    bundle = find_bundle()
    attack = load_attack(bundle) if bundle else None

    CTX.update(repo=repo, store=store, advisories=advisories, kev=kev, topo=topo,
               attack=attack, as_of=as_of, policy=active_policy(ROOT / "data"))

    # 기준 시점에 **알려져 있던 것만** (ADR-037). 스윕 스레드가 `_at` 보다 먼저
    # 뜨므로 빌드 때 한 번 만들어 둔다. 배제는 `false` 일 때만 한다.
    BASE_VIS = visible_at(advisories, indexes, as_of)
    BASE_KEV = kev_at(kev, as_of)

    # 소스가 '얼마나 큰가' 와 '우리 범위에서 얼마나 쓰이나' 는 다른 수다.
    # 둘을 같이 보여주지 않으면 카탈로그 크기가 우리 커버리지로 읽힌다.
    _all_cves = set()
    for _a in advisories:
        _all_cves |= {v.cve for v in _a.vulnerabilities if v.cve}
    _kev_overlap = len(_all_cves & set(kev.cve_ids)) if kev else 0
    _mapped_techniques = sorted({t for tids in EDGE_TYPE_TECHNIQUES.values() for t in tids})
    # 권위를 확인하지 못한 발행처가 몇 곳인가. 조용히 넘어가면 안 되는 수다 (ADR-024).
    _unverified_pubs = sorted({a.publisher_name for a in advisories
                               if publisher_role(a)[0] == UNVERIFIED})
    _unverified_advs = sum(1 for a in advisories if publisher_role(a)[0] == UNVERIFIED)

    # 행동 큐는 전수 계산이 필요하다. 요청 때 돌리면 수십 초 걸리므로 시작할 때
    # 배경에서 한 번 돌리고 결과를 들고 있는다. 큐 요청은 그것을 기다린다.
    sweep: Dict[str, Any] = {
        "state": "준비 중", "done": 0, "total": 0, "pairs": 0, "skipped": 0,
        "evaluated": 0, "no_match": 0, "rows": [], "error": None, "seconds": 0.0,
        # 표 4: 노출·구성 위험은 자산 단위이고 권고문과 무관하다
        "exposures": [], "questions": [],
    }
    sweep_ready = threading.Event()

    def run_sweep() -> None:
        import time as _t
        t0 = _t.perf_counter()
        try:
            listing = repo.list()
            sweep["total"] = len(listing)
            rows, pairs, skipped, evaluated, no_match = [], 0, 0, 0, 0
            exposures, questions = [], []
            sweep["not_yet_published"] = len(advisories) - len(BASE_VIS)
            for i, row in enumerate(listing):
                sweep["done"] = i + 1
                a = repo.asset(row["asset_id"])
                if a is None:
                    continue
                # 표 4 의 노출·구성 위험 — 권고문이 없어도 존재한다
                ex, qs = find_exposure(a, topology=topo, as_of=as_of)
                for f in ex:
                    exposures.append((row, f))
                questions.extend(qs)
                for adv, ix, _k in BASE_VIS:
                    pairs += 1
                    if not could_match(a, ix):
                        skipped += 1
                        continue
                    evaluated += 1
                    d = decide_applicability(a, adv, as_of=as_of)
                    if d.status == "no_known_match":
                        no_match += 1
                        continue
                    rows.append((row, a, d, adv))
            # 같은 사실이 CVE 쪽 H02 의 근거로도 쓰였으면 서로를 가리키게 한다
            h02_assets = {r["asset_id"] for r, _a, d, _adv in rows
                          if "H02" in _priority_rules(_a, d)}
            exposures = [(r, replace(f, also_raises_cve=(r["asset_id"] in h02_assets)))
                         for r, f in exposures]
            sweep.update(rows=rows, pairs=pairs, skipped=skipped, evaluated=evaluated,
                         no_match=no_match, state="완료",
                         exposures=exposures, questions=questions,
                         seconds=round(_t.perf_counter() - t0, 1))
        except Exception as exc:                      # 실패해도 서버는 살아 있어야 한다
            sweep.update(state="실패", error=str(exc)[:300])
        finally:
            sweep_ready.set()

    threading.Thread(target=run_sweep, name="otai-sweep", daemon=True).start()

    app = FastAPI(title="OT 자산 취약점 관리", docs_url="/api/docs", redoc_url=None)
    app.add_middleware(BoundedBody)

    # ---------------------------------------------------------------- 공통
    def _adv(advisory_id: str):
        for a in advisories:
            if a.advisory_id == advisory_id:
                return a
        raise HTTPException(404, "권고문을 찾지 못했습니다: %s" % advisory_id)

    def _asset(asset_id: str):
        a = repo.asset(asset_id)
        if a is None:
            raise HTTPException(404, "자산을 찾지 못했습니다: %s" % asset_id)
        return a

    _at_cache: Dict[str, Tuple[list, object]] = {}

    def _at(as_of_v: str):
        """그 시점에 알려져 있던 권고문과 KEV (ADR-037).

        **`false` 일 때만 뺀다.** 날짜를 모르는 문서는 남는다 — 모르는 것을
        배제하면 영향받는 항목이 조용히 사라진다 (불변 규칙 2 의 시간 축 판).
        1,300건을 매 요청 훑지 않도록 시점별로 한 번만 만든다.
        """
        hit = _at_cache.get(as_of_v)
        if hit is None:
            hit = (visible_at(advisories, indexes, as_of_v), kev_at(kev, as_of_v))
            _at_cache[as_of_v] = hit
        return hit
    _at_cache[as_of] = (BASE_VIS, BASE_KEV)

    def _findings(asset, as_of_v: str, lens="default", use_topo=True):
        """판정 결과. 가망 없는 권고문은 건너뛴다 (ADR-030).

        건너뛴 쌍은 `no_known_match` 로 확정이므로 결과가 달라지지 않는다.
        몇 건을 건너뛰었는지는 `_scanned` 로 따로 셀 수 있다 — 화면에서 '나머지는
        안전' 이 아니라 '나머지는 대상 제품이 아님' 이라고 정확히 말하기 위해서다.
        """
        vis, kv = _at(as_of_v)
        out = []
        for adv, ix, _k in vis:
            if not could_match(asset, ix):
                continue
            d = decide_applicability(asset, adv, as_of=as_of_v)
            it = evaluate_priority(d, asset, kev=kv,
                                   topology=topo if use_topo else None,
                                   lens=lens, policy=CTX["policy"],
                                   lifecycle=_lifecycle(asset, adv))
            out.append((d, it, adv))
        return out

    def _lifecycle(asset, adv):
        """표 13: 제조사 EOL/EOS 가 1차, 자산의 현장 기록이 보조.

        권고문이 이 제품에 대해 `no_fix_planned` 를 선언했으면 사용자가
        'supported' 라고 적었어도 제조사가 이긴다.
        """
        role = publisher_role(adv)[0]
        ids = [p.product_id for p in adv.products]
        return lifecycle_resolve(
            [lifecycle_from_asset(asset.lifecycle_status)]
            + lifecycle_from_advisory(adv, ids, role=role))

    def _priority_rules(asset, d) -> Tuple[str, ...]:
        it = evaluate_priority(d, asset, kev=BASE_KEV, topology=topo,
                               policy=CTX["policy"])
        return tuple(it.fired_rules)

    def _scanned(asset, as_of_v: Optional[str] = None) -> Dict[str, int]:
        """몇 건을 보고 몇 건을 왜 건너뛰었는지.

        '아직 안 나온 문서' 와 '이 장비 얘기가 아닌 문서' 는 다른 사실이다.
        합쳐 세면 과거 시점에서 "이 문서들이 다루는 제품이 이 장비가 아닙니다"
        라는 화면 설명이 거짓이 된다.
        """
        vis, _kv = _at(as_of_v or CTX["as_of"])
        n = sum(1 for _a, ix, _k in vis if could_match(asset, ix))
        return {"total": len(advisories), "considered": n,
                "not_yet_published": len(advisories) - len(vis),
                "excluded": len(vis) - n}

    def _known_json(adv, as_of_v: str) -> Dict:
        k = known_at(adv, as_of_v)
        return {"existed": k.existed.name.lower(), "reason": k.reason,
                "revision_uncertain": k.revision_uncertain,
                "initial_release_date": k.initial, "current_release_date": k.current}

    def _finding_json(d, it, adv):
        return {
            "advisory_id": adv.advisory_id, "advisory_title": adv.title,
            # 그 시점에 이 문서가 알려져 있었는가 (ADR-037). 과거 `as_of` 로 부르면
            # 개정본만 들고 있는 항목이 그렇지 않은 것과 구별돼야 한다.
            "known_at": _known_json(adv, it.as_of),
            "publisher": adv.publisher_name,
            "status": d.status, "phrase": d.phrase_ko,
            "identity_level": d.identity_level,
            "identity_confidence": round(d.identity_confidence, 2),
            "bucket": it.bucket, "bucket_phrase": it.bucket_phrase,
            "floor_if_confirmed": it.floor_if_confirmed,
            "fired_rules": it.fired_rules,
            "pending": [{"rule": p.rule_id, "floor": p.floor_if_confirmed,
                         "missing": p.missing, "question": p.question}
                        for p in it.pending_escalations],
            "rationale": it.rationale,
            "conditions": d.decisive_conditions,
            "fields": d.fields,
            "next_question": d.next_best_question,
            "cves": list(d.cves[:20]), "n_cves": len(d.cves),
            "kev_cves": it.kev_cves,
            "max_cvss": d.max_cvss, "cvss_vector": d.cvss_vector,
            "raw_expression": d.evidence.get("raw_expression"),
            "advisory_sha256": d.evidence.get("advisory_sha256"),
            "input_hash": d.input_hash, "as_of": d.as_of,
            "rule_version": d.rule_version, "policy_version": it.policy_version,
            "lens_score": round(it.lens_score, 3),
        }

    # ---------------------------------------------------------------- 맥락
    @app.get("/api/context")
    def context():
        return {
            "as_of": CTX["as_of"],
            "advisories": [{"id": a.advisory_id, "title": a.title,
                            "publisher": a.publisher_name,
                            "products": len(a.products),
                            "cves": len({v.cve for v in a.vulnerabilities if v.cve})}
                           for a in advisories],
            "kev": kev.catalog_version if kev else None,
            "attack": attack.version if attack else None,
            "topology": topo.source_path if topo else None,
            "topology_synthetic": bool(topo and topo.provenance.get("synthetic")),
            "topology_warning": topo.provenance.get("warning") if topo else None,
            "policy": CTX["policy"].version,
            "lens_presets": LENS_PRESETS,
            "buckets": BUCKET_PHRASES, "bucket_order": BUCKET_ORDER,
            "phrases": PHRASES,
            "assets": repo.count(),
            # 사용자의 실제 장비가 하나라도 있는가. 없으면 화면이 그렇게 말해야 한다 —
            # 예시 데이터를 실제 인벤토리로 오해하는 것이 이 제품에서 가장 나쁜 오해다.
            "assets_demo": sum(1 for r in repo.list() if r.get("synthetic")),
            "authenticated": False,
            "backend": repo.backend,
        }

    # ---------------------------------------------------------------- 자산
    @app.get("/api/assets")
    def list_assets(factory: str = None, zone: str = None, asset_type: str = None,
                    level: str = None, q: str = None, limit: int = 0):
        rows = repo.list(factory, zone, asset_type, level, q)
        total = len(rows)
        # 고르개처럼 몇 건만 필요한 화면은 limit 을 준다. 총계는 그대로 알려준다 —
        # 몇 건 중 몇 건인지 말하지 않으면 사용자가 전부라고 오해한다.
        if limit and limit > 0:
            rows = rows[:limit]
        return {"items": rows, "total": total, "facets": repo.facets()}

    @app.post("/api/assets")
    def create_asset(body: dict = Body(...)):
        if not body.get("asset_id"):
            raise HTTPException(400, "asset_id 가 필요합니다")
        repo.put(body, CTX["as_of"])
        store.log("import_applied", as_of=CTX["as_of"], actor="web",
                  subject=body["asset_id"], detail={"via": "POST /api/assets"})
        return {"asset_id": body["asset_id"], "level": completeness(body)}

    @app.get("/api/assets/{asset_id}")
    def get_asset(asset_id: str):
        b = repo.body(asset_id)
        if b is None:
            raise HTTPException(404, "자산을 찾지 못했습니다")
        return {"body": b, "level": completeness(b)}

    @app.post("/api/assets/purge-demo")
    def purge_demo():
        """예시 자산을 전부 지운다. 사용자가 넣은 자산은 건드리지 않는다."""
        gone = [r["asset_id"] for r in repo.list() if r.get("synthetic")]
        for aid in gone:
            repo.delete(aid)
        store.log("demo_assets_purged", as_of=CTX["as_of"], actor="web",
                  detail={"count": len(gone)})
        # 저장소가 바뀌었으니 전수 계산 결과는 더 이상 맞지 않는다.
        sweep.update(rows=[], pairs=0, skipped=0, evaluated=0, no_match=0,
                     total=repo.count(), state="다시 계산 필요", seconds=0.0)
        return {"deleted": len(gone), "remaining": repo.count(),
                "note": "행동 큐를 다시 채우려면 서버를 다시 시작하세요."}

    @app.delete("/api/assets/{asset_id}")
    def del_asset(asset_id: str):
        if not repo.delete(asset_id):
            raise HTTPException(404, "자산을 찾지 못했습니다")
        return {"deleted": asset_id}

    @app.post("/api/assets/{asset_id}/observations")
    def add_observation(asset_id: str, body: dict = Body(...)):
        """관측을 추가한다. 덮어쓰지 않고 자산 본문을 갱신하며 assertion 을 남긴다."""
        asset = _asset(asset_id)
        field, value = body.get("field"), body.get("value")
        if not field:
            raise HTTPException(400, "field 가 필요합니다")
        updated = apply_answer(asset, field, value, CTX["as_of"])
        cur = repo.body(asset_id) or {}
        merged = _asset_to_body(updated, cur)
        repo.put(merged, CTX["as_of"])
        store.append_assertion(asset_id, field, str(value), as_of=CTX["as_of"],
                               source="web", method="manual")
        return {"body": merged, "level": completeness(merged)}

    @app.get("/api/assets/{asset_id}/findings")
    def findings(asset_id: str, as_of: str = None, lens: str = "default",
                 topology: bool = True):
        asset = _asset(asset_id)
        aov = as_of or CTX["as_of"]
        rows = [_finding_json(d, it, adv) for d, it, adv in
                _findings(asset, aov, lens, topology)]
        order = {"affected_confirmed": 0, "affected_likely": 1, "candidate": 2,
                 "insufficient_information": 3, "conflicting_evidence": 4, "stale": 5,
                 "no_known_match": 6, "not_affected_confirmed": 7, "fixed": 8}
        rows.sort(key=lambda r: (order.get(r["status"], 9), r["advisory_id"]))
        vis, _kv = _at(aov)
        q = next_question(asset, [a for a, _i, _k in vis], aov)
        # 수명주기는 권고문마다 근거가 다를 수 있다 — 가장 강한 것을 대표로 싣는다
        lv_best = None
        for adv, ix, _k in vis:
            if not could_match(asset, ix):
                continue
            v = _lifecycle(asset, adv)
            if lv_best is None or (v.vendor_confirmed and not lv_best.vendor_confirmed):
                lv_best = v
        # CISA 자산 인벤토리 고우선 속성 (ADR-042). 없으면 미상으로 보인다.
        _net = asset.network
        return {"findings": rows, "scanned": _scanned(asset, aov),
                "addresses": [{"ip": a.ip, "mac": a.mac, "hostname": a.hostname,
                               "vlan": a.vlan, "method": a.method,
                               "observed_at": a.observed_at}
                              for a in _net.addresses],
                "lifecycle": None if lv_best is None else {
                    "state": lv_best.state,
                    "vendor_confirmed": lv_best.vendor_confirmed,
                    "conflicting": lv_best.conflicting,
                    "reason": lv_best.reason,
                    "claims": [{"state": c.state, "source": c.source_id,
                                "role": c.source_role, "basis": c.basis,
                                "structured": c.structured}
                               for c in lv_best.claims]},
                "question": None if q is None else {
                    "field": q.field, "label": q.label, "help": q.help,
                    "kind": q.kind, "options": q.options, "why": q.why,
                    "skippable": q.skippable}}

    # ---------------------------------------------------------------- 마인드맵
    @app.get("/api/assets/{asset_id}/mindmap")
    def mindmap(asset_id: str, as_of: str = None):
        """그림 5 — 자산 중심 방사형. 축 7개: 식별·구성요소·취약점·경로·공정영향·조치·증거."""
        asset = _asset(asset_id)
        aov = as_of or CTX["as_of"]
        body = repo.body(asset_id) or {}
        rows = _findings(asset, aov)

        nodes = [{"id": "root", "label": asset_id, "kind": "root"}]
        edges = []

        def branch(bid, label, kind, state="observed"):
            nodes.append({"id": bid, "label": label, "kind": kind})
            edges.append({"source": "root", "target": bid, "state": state})

        def leaf(bid, lid, label, state="observed", detail=""):
            nodes.append({"id": lid, "label": label, "kind": "leaf",
                          "state": state, "detail": detail})
            edges.append({"source": bid, "target": lid, "state": state})

        ident = body.get("identity") or {}
        branch("identity", "식별", "identity",
               "observed" if ident.get("model_raw") else "unknown")
        for k, lab in (("vendor_raw", "제조사"), ("family_raw", "제품군"),
                       ("model_raw", "모델"), ("order_number", "주문번호")):
            leaf("identity", "id_" + k, "%s %s" % (lab, ident.get(k) or "미상"),
                 "observed" if ident.get(k) else "unknown")

        branch("components", "구성요소", "components",
               "observed" if body.get("components") else "unknown")
        for i, c in enumerate(body.get("components") or []):
            v = (c.get("version") or {}).get("raw")
            leaf("components", "c%d" % i, "%s %s" % (c.get("type", "?"), v or "버전 미상"),
                 "observed" if v else "unknown", c.get("evidence_id") or "")

        affected = [r for r in rows if r[0].status in
                    ("affected_confirmed", "affected_likely", "candidate")]
        branch("vulns", "취약점", "vulns", "observed" if affected else "unknown")
        for d, it, adv in rows:
            st = ("observed" if d.status == "affected_confirmed"
                  else "inferred" if d.status in ("affected_likely", "candidate")
                  else "unknown" if d.status in ("insufficient_information", "stale")
                  else "settled")
            leaf("vulns", "v_" + adv.advisory_id, "%s %s" % (adv.advisory_id, d.phrase_ko),
                 st, ", ".join(d.cves[:3]))

        reach = evaluate_reachability(topo, asset_id, as_of=aov) if topo else None
        # 삼진 값은 `is` 로 비교한다. `.value == "true"` 는 `Tri.__bool__` 가드를
        # 지나쳐 문자열을 보는 것이고, 타입이 바뀌면 조용히 거짓이 된다 — 그리고
        # 여기서 거짓은 안전하지 않은 방향이다.
        rstate = ("observed" if reach and reach.verdict is Tri.TRUE
                  else "inferred" if reach and reach.verdict is Tri.UNKNOWN
                  else "unknown")
        branch("paths", "공격 경로", "paths", rstate)
        if reach:
            leaf("paths", "p_verdict", "도달성 %s" % reach.verdict.value, rstate, reach.reason)
            for i, p in enumerate((reach.confirmed_paths or reach.unconfirmed_paths)[:4]):
                leaf("paths", "p%d" % i, "%d홉 · 확신도 %.2f" % (len(p.hops), p.confidence),
                     "observed" if p.is_confirmed else "inferred", " → ".join(p.nodes))

        ops = body.get("operations") or {}
        branch("impact", "공정 영향", "impact",
               "observed" if ops.get("safety_criticality") else "unknown")
        leaf("impact", "i_safety", "안전 중요도 %s" % (ops.get("safety_criticality") or "미상"),
             "observed" if ops.get("safety_criticality") else "unknown")
        leaf("impact", "i_life", "수명주기 %s" % (body.get("lifecycle_status") or "미상"),
             "observed" if body.get("lifecycle_status") else "unknown")

        branch("action", "조치", "action")
        for d, it, adv in rows:
            if it.bucket == "P4":
                continue
            leaf("action", "a_" + adv.advisory_id,
                 "%s %s" % (it.bucket, BUCKET_PHRASES.get(it.bucket, "")),
                 "observed" if it.fired_rules else "inferred",
                 ", ".join(it.fired_rules) or (it.floor_if_confirmed or ""))

        branch("evidence", "증거", "evidence")
        seen = set()
        for d, it, adv in rows:
            sha = str(d.evidence.get("advisory_sha256") or "")[:12]
            if sha and sha not in seen:
                seen.add(sha)
                leaf("evidence", "e_" + sha, "%s %s…" % (adv.advisory_id, sha),
                     "observed", str(d.evidence.get("current_release_date") or ""))
        for c in body.get("components") or []:
            if c.get("evidence_id"):
                leaf("evidence", "ev_" + c["evidence_id"], c["evidence_id"], "observed",
                     c.get("observed_at") or "")

        return {"nodes": nodes, "edges": edges,
                "legend": {"observed": "확인", "inferred": "추론",
                           "unknown": "정보 부족", "settled": "해당 없음"}}

    # ---------------------------------------------------------------- 취약점
    @app.get("/api/vulnerabilities/{advisory_id}")
    def vulnerability(advisory_id: str, asset_id: str = None, as_of: str = None):
        adv = _adv(advisory_id)
        aov = as_of or CTX["as_of"]
        out: Dict[str, Any] = {
            "advisory_id": adv.advisory_id, "title": adv.title,
            "publisher": adv.publisher_name, "publisher_category": adv.publisher_category,
            "released_at": adv.current_release_date, "sha256": adv.sha256,
            "products": len(adv.products),
            "vulnerabilities": [],
        }
        for v in adv.vulnerabilities[:60]:
            score, vector = v.cvss()
            out["vulnerabilities"].append({
                "cve": v.cve, "cvss": score, "vector": vector,
                "kev": bool(kev and v.cve in kev.cve_ids),
                "status": list(v.product_status),
                "remediations": [{"category": r.get("category"),
                                  "details": (r.get("details") or "")[:300],
                                  "url": r.get("url")} for r in v.remediations[:3]],
            })
        if asset_id:
            asset = _asset(asset_id)
            d = decide_applicability(asset, adv, as_of=aov)
            it = evaluate_priority(d, asset, kev=_at(aov)[1], topology=topo,
                                   policy=CTX["policy"],
                                   lifecycle=_lifecycle(asset, adv))
            out["finding"] = _finding_json(d, it, adv)
            out["known_at"] = _known_json(adv, aov)
        return out

    def _exposure_json(row, f) -> Dict[str, Any]:
        return {
            "kind": f.kind, "code": f.code, "asset_id": f.asset_id,
            "zone": row["zone"], "factory": row["factory"], "level": row["level"],
            "title": f.title, "why": f.why, "what_to_do": f.what_to_do,
            "bucket": f.bucket, "floor_if_confirmed": f.floor_if_confirmed,
            "checks": [{"name": c.name, "value": str(c.value.name).lower(),
                        "evidence": c.evidence} for c in f.checks],
            "missing": list(f.missing),
            "evidence": list(f.evidence),
            "cwe": f.cwe,
            "also_raises_cve": f.also_raises_cve,
        }

    @app.get("/api/exposures")
    def exposures(asset_id: str = None):
        """표 4 의 노출·구성 위험. 권고문과 무관하게 존재한다."""
        sweep_ready.wait(timeout=600)
        rows = [(r, f) for r, f in sweep["exposures"]
                if not asset_id or r["asset_id"] == asset_id]
        order = {"P0": 0, "P?": 1, "P1": 2, "P2": 3, "P3": 4, "P4": 5}
        rows.sort(key=lambda x: (order.get(x[1].bucket, 9), x[0]["asset_id"]))
        counts: Dict[str, int] = {}
        for _r, f in rows:
            counts[f.bucket] = counts.get(f.bucket, 0) + 1
        return {
            "items": [_exposure_json(r, f) for r, f in rows],
            "counts": counts,
            "questions": [{"asset_id": q.asset_id, "field": q.field,
                           "ask": q.ask, "why": q.why}
                          for q in sweep["questions"]
                          if not asset_id or q.asset_id == asset_id][:200],
            "total_questions": len(sweep["questions"]),
        }

    # ---------------------------------------------------------------- 행동 큐
    # ------------------------------------------------------------ 시간 축
    _diff_cache: Dict[Tuple[str, str, str], Dict] = {}

    def _rows_at(as_of_v: str):
        """그 시점 기준 전수 판정. 비교에 쓸 최소 필드만 만든다.

        버킷과 상태만 담는다 — 렌즈 점수를 담으면 부동소수 잡음이 '등급 변경'
        으로 둔갑한다. 등급은 사실이고 점수는 같은 등급 안의 정렬일 뿐이다.
        """
        vis, kv = _at(as_of_v)
        out, fog = [], []
        for row in repo.list():
            a = repo.asset(row["asset_id"])
            if a is None:
                continue
            for adv, ix, k in vis:
                if not could_match(a, ix):
                    continue
                d = decide_applicability(a, adv, as_of=as_of_v)
                if d.status == "no_known_match":
                    continue
                it = evaluate_priority(d, a, kev=kv, topology=topo,
                                       policy=CTX["policy"],
                                       lifecycle=_lifecycle(a, adv))
                out.append({"asset_id": row["asset_id"], "advisory_id": adv.advisory_id,
                            "bucket": it.bucket, "status": d.status,
                            "zone": row.get("zone"), "title": adv.title})
                if not k.certain:
                    fog.append((row["asset_id"], adv.advisory_id))
        return out, fog

    #: 종류마다 몇 건까지 실어 보내는가. 전체를 그냥 자르면 이름순으로 잘려서
    #: 뒤쪽 자산이 통째로 사라지고, 화면에서 종류를 골라도 빈 목록이 나온다.
    PER_KIND = 120

    def _sample(changes):
        """종류별로 골고루 담는다. 급한 것(P0·P1)이 먼저 오도록 정렬한다."""
        rank = {"P0": 0, "P?": 1, "P1": 2, "P2": 3, "P3": 4, "P4": 5}
        out, seen = [], {k: 0 for k in CHANGE_ORDER}
        for c in sorted(changes, key=lambda c: (rank.get(c.after or c.before, 9),
                                                c.asset_id, c.advisory_id)):
            if seen.get(c.kind, 0) >= PER_KIND:
                continue
            seen[c.kind] = seen.get(c.kind, 0) + 1
            out.append(c)
        return out

    @app.get("/api/timeline/diff")
    def timeline_compare(before: str, after: str = None):
        """두 시점 사이에 무엇이 달라졌는가.

        **자산은 고정이다.** 합성 자산의 관측 시각을 과거로 고쳐 쓰지 않기 때문에
        (없는 역사를 지어내는 것이다) 앞 시점 열은 '그때의 현장' 이 아니라
        **'그 시점에 알려져 있던 권고문으로 오늘의 자산을 다시 판정한 것'** 이다.
        화면이 이 문장을 그대로 말한다.

        두 번 전수 계산하므로 느리다. 시작할 때 돌리지 않고 눌렀을 때만 돈다.
        정책이 바뀌면 결과가 달라지므로 캐시 키에 정책 버전을 넣는다.
        """
        aft = after or CTX["as_of"]
        if before > aft:
            raise HTTPException(400, "앞 시점이 뒤 시점보다 늦습니다")
        key = (before, aft, CTX["policy"].version)
        hit = _diff_cache.get(key)
        if hit is not None:
            return hit
        import time as _t
        t0 = _t.perf_counter()
        rows_a, fog_a = _rows_at(before)
        rows_b, fog_b = _rows_at(aft)
        changes = timeline_diff(rows_a, rows_b, uncertain=set(fog_a) | set(fog_b))
        counts = change_counts(changes)
        vis_a, vis_b = _at(before)[0], _at(aft)[0]
        out = {
            "before": before, "after": aft,
            "order": list(CHANGE_ORDER), "counts": counts,
            "advisories": {"before": len(vis_a), "after": len(vis_b),
                           "total": len(advisories)},
            "kev": {"before": len(_at(before)[1].entries) if _at(before)[1] else 0,
                    "after": len(_at(aft)[1].entries) if _at(aft)[1] else 0},
            "uncertain_advisories": sum(1 for _a, _i, k in vis_a if not k.certain),
            "rows": {"before": len(rows_a), "after": len(rows_b)},
            "changes": [{"kind": c.kind, "asset_id": c.asset_id,
                         "advisory_id": c.advisory_id, "before": c.before,
                         "after": c.after, "before_status": c.before_status,
                         "after_status": c.after_status, "why": c.why}
                        for c in _sample(changes)],
            "truncated": max(0, len(changes) - len(_sample(changes))),
            "caveat": "자산은 두 시점 모두 현재 상태입니다. 관측 시각을 과거로 "
                      "고쳐 쓰지 않기 때문에, 앞 시점 열은 '그때의 현장' 이 아니라 "
                      "'그 시점에 알려져 있던 권고문으로 지금의 자산을 다시 판정한 "
                      "것' 입니다.",
            "seconds": round(_t.perf_counter() - t0, 1),
            "policy_version": CTX["policy"].version,
        }
        _diff_cache[key] = out
        return out

    @app.get("/api/actions")
    def actions(bucket: str = None, lens: str = "default", zone: str = None,
                as_of: str = None, topology: bool = True):
        # 적용성 판정은 스윕이 이미 끝냈다. 여기서는 관점(lens)과 경로 반영만
        # 다시 계산한다 — 그 둘은 값이 싸고 요청마다 달라진다.
        sweep_ready.wait(timeout=600)
        if sweep["state"] == "실패":
            raise HTTPException(503, "전수 계산에 실패했습니다: %s" % sweep["error"])
        items = []
        for row, asset, d, adv in sweep["rows"]:
            if zone and row["zone"] != zone:
                continue
            it = evaluate_priority(d, asset, kev=BASE_KEV,
                                   topology=topo if topology else None,
                                   lens=lens, policy=CTX["policy"],
                                   lifecycle=_lifecycle(asset, adv))
            items.append((it, _finding_json(d, it, adv), row))
        ordered = sort_queue([i for i, _, _ in items])
        by_id = {(f["advisory_id"], it.asset_id): (f, r) for it, f, r in items}
        out = []
        for it in ordered:
            key = (it.advisory_id, it.asset_id)
            if key not in by_id:
                continue
            f, r = by_id[key]
            if bucket and it.bucket != bucket:
                continue
            out.append({**f, "asset_id": it.asset_id, "zone": r["zone"],
                        "factory": r["factory"], "level": r["level"]})
        counts: Dict[str, int] = {}
        for it in ordered:
            counts[it.bucket] = counts.get(it.bucket, 0) + 1
        return {"items": out, "counts": counts, "scanned": {
            "assets": sweep["total"], "advisories": len(advisories),
            "pairs": sweep["pairs"], "excluded": sweep["skipped"],
            "evaluated": sweep["evaluated"], "no_match": sweep["no_match"],
            "findings": len(sweep["rows"]), "seconds": sweep["seconds"]}}

    # ---------------------------------------------------------------- 경로
    @app.get("/api/graphs/attack-paths")
    def attack_paths(asset_id: str, as_of: str = None):
        if topo is None:
            return {"available": False, "reason": "토폴로지가 로드되지 않았습니다"}
        aov = as_of or CTX["as_of"]
        node = topo.node_for_asset(asset_id)
        if node is None:
            return {"available": False,
                    "reason": "이 자산은 토폴로지에 없습니다 — 도달 불가로 단정하지 않고 미상으로 둡니다"}
        paths = find_paths(topo, node.node_id, as_of=aov)
        blocks = blocking_candidates(topo, [node.node_id], as_of=aov, top=5)
        return {
            "available": True, "node": node.node_id, "label": node.label,
            "warning": topo.provenance.get("warning"),
            "graph": {
                "nodes": [{"id": n.node_id, "label": n.label, "zone": n.zone,
                           "level": n.purdue_level, "type": n.node_type,
                           "entry": n.is_entry_point, "critical": n.is_critical}
                          for n in sorted(topo.nodes.values(), key=lambda x: x.node_id)],
                "edges": [{"id": e.key, "source": e.src, "target": e.dst,
                           "label": e.label, "state": e.status,
                           "techniques": [t.technique_id for t in attack.for_edge(e)]
                                         if attack else []}
                          for e in sorted(topo.edges, key=lambda x: x.key)],
            },
            "paths": [{"status": p.status, "confidence": p.confidence,
                       "nodes": list(p.nodes), "edges": list(p.edge_keys),
                       "weakest": p.weakest.key if p.weakest else None,
                       "hops": [{"src": h.edge.src, "dst": h.edge.dst,
                                 "label": h.edge.label, "state": h.edge.status,
                                 "caps": sorted(h.caps_after)} for h in p.hops]}
                      for p in paths],
            "blocks": [{"edge": b.edge.key, "cut": b.paths_cut,
                        "legit": b.legitimate_flows_broken,
                        "remaining": b.paths_remaining} for b in blocks],
        }

    # ---------------------------------------------------------------- 증거 비교
    # link_advisories 는 1,303건을 훑는다. 요청마다 다시 하지 않는다.
    _groups: List[Any] = []

    def _linked():
        if not _groups:
            _groups.extend(g for g in link_advisories(advisories)
                           if len(g.advisories) >= 2)
        return _groups

    def _group_summary(gid: int, g) -> Dict[str, Any]:
        comps = compare_products(g)
        cv = compare_cvss(g)
        prov = provenance_table(g)
        cves = list(g.cves)
        return {
            "id": gid,
            "publishers": sorted({p["publisher"] for p in prov}),
            "advisories": [p["advisory_id"] for p in prov],
            "n_advisories": len(prov),
            "n_cves": len(cves),
            "cves_head": cves[:4],
            "n_products": len(comps),
            "n_conflict": sum(1 for c in comps if c.conflicting),
            "n_multivalued": sum(1 for c in comps
                                 if c.multivalued and not c.conflicting),
            "n_disjoint": sum(1 for c in comps if c.disjoint),
            "n_undecidable": sum(1 for c in comps if c.undecidable),
            "cvss": None if cv is None else {
                "value": cv.current.value, "source": cv.current.source_id,
                "role": cv.current.source_role, "conflicting": cv.conflicting},
        }
    @app.get("/api/evidence/compare")
    def evidence_compare():
        """묶음 **목록**만. 충돌이 많은 것부터 — 사람이 볼 이유가 거기 있다."""
        rows = [_group_summary(i, g) for i, g in enumerate(_linked())]
        rows.sort(key=lambda r: (-r["n_conflict"], -r["n_products"], r["id"]))
        return {
            "groups": rows,
            "totals": {
                "groups": len(rows),
                "advisories": len(advisories),
                "conflicts": sum(r["n_conflict"] for r in rows),
                "multivalued": sum(r["n_multivalued"] for r in rows),
                "disjoint": sum(r["n_disjoint"] for r in rows),
                "undecidable": sum(r["n_undecidable"] for r in rows),
                "products": sum(r["n_products"] for r in rows),
                "with_conflict": sum(1 for r in rows if r["n_conflict"]),
            },
        }

    @app.get("/api/evidence/compare/{gid}")
    def evidence_group(gid: int, limit: int = 40):
        """묶음 하나의 상세. 제품 대조는 **충돌부터** 보여준다."""
        groups = _linked()
        if gid < 0 or gid >= len(groups):
            raise HTTPException(404, "그런 묶음이 없습니다")
        g = groups[gid]
        comps = compare_products(g)
        comps = sorted(comps, key=lambda c: (not c.conflicting,
                                             not c.undecidable, c.key))
        out = _group_summary(gid, g)
        out["provenance"] = provenance_table(g)
        out["cves"] = list(g.cves)[:200]
        out["products"] = [{
            "key": c.key,
            "current": c.views["version_range"].current.value,
            "source": c.views["version_range"].current.source_id,
            "role": c.views["version_range"].current.source_role,
            "reason": c.views["version_range"].reason,
            "corroborated": list(c.views["version_range"].corroborated_by),
            "dissenting": [{"value": d.value, "source": d.source_id}
                           for d in c.views["version_range"].dissenting],
            "conflicting": c.conflicting,
            "multivalued": c.multivalued,
            "disjoint": c.disjoint,
            "undecidable": c.undecidable,
            # 실제로 부딪히는 값 쌍만. '채택' 하나만 보이면 논쟁과 무관한 값이 나온다.
            "disputed": [{"a": p[0], "a_src": p[1], "b": p[2], "b_src": p[3]}
                         for p in c.views["version_range"].disputed[:4]],
        } for c in comps[:limit]]
        return out

    # ---------------------------------------------------------------- 정책 렌즈
    @app.post("/api/decisions/preview")
    def decisions_preview(body: dict = Body(default={})):
        lens_a = body.get("lens_a", "default")
        lens_b = body.get("lens_b", "security")
        aov = body.get("as_of") or CTX["as_of"]

        # 적용성 판정은 스윕이 이미 끝냈다. 렌즈마다 다시 돌면 규모에서 18초씩 더 든다.
        # 여기서 다시 계산하는 것은 **우선순위뿐**이고, 그게 이 화면의 요점이다 —
        # 렌즈를 바꿔도 버킷이 안 움직인다는 것을 보이는 것.
        sweep_ready.wait(timeout=600)
        if sweep["state"] == "실패":
            raise HTTPException(503, "전수 계산에 실패했습니다: %s" % sweep["error"])

        def rank(lens):
            items = [evaluate_priority(d, asset, kev=BASE_KEV, topology=topo,
                                       lens=lens, policy=CTX["policy"],
                                       lifecycle=_lifecycle(asset, adv))
                     for _, asset, d, adv in sweep["rows"]]
            return [{"asset_id": i.asset_id, "advisory": i.advisory_id,
                     "bucket": i.bucket, "score": round(i.lens_score, 3)}
                    for i in sort_queue(items)]

        a, b = rank(lens_a), rank(lens_b)
        pos_a = {(r["asset_id"], r["advisory"]): i for i, r in enumerate(a)}
        moved = []
        for i, r in enumerate(b):
            k = (r["asset_id"], r["advisory"])
            if k in pos_a and pos_a[k] != i:
                moved.append({**r, "from": pos_a[k], "to": i})
        return {"lens_a": lens_a, "lens_b": lens_b, "a": a, "b": b,
                "moved": moved,
                "bucket_changed": [r for r in b
                                   if any(x["asset_id"] == r["asset_id"]
                                          and x["advisory"] == r["advisory"]
                                          and x["bucket"] != r["bucket"] for x in a)],
                "presets": LENS_PRESETS}

    # ---------------------------------------------------------------- 온보딩
    # ---------------------------------------------------- 프로젝트 파일 (ADR-038)
    # 사전은 권고문에서 만든다. 저쪽 도구의 스키마를 모르므로, 우리가 아는
    # 식별자와 맞추는 방향으로 읽는다. 사전은 한 번만 만든다.
    _vocab = {"v": None}

    def _vocabulary():
        if _vocab["v"] is None:
            _vocab["v"] = build_vocabulary(advisories)
        return _vocab["v"]

    MAX_UPLOAD = 48 * 1024 * 1024

    MAX_CAPTURE_UPLOAD = 96 * 1024 * 1024

    @app.post("/api/topology/capture")
    def topology_from_capture(body: dict = Body(...)):
        """캡처 파일에서 토폴로지를 만든다.

        **장비에 붙지 않고 네트워크에 아무것도 보내지 않는다** (불변 규칙 6).
        저장은 하지 않는다 — 만든 토폴로지를 돌려주고, 사용자가 내려받아
        레벨·구역을 채운 뒤 `--topology` 로 쓴다.
        """
        import base64
        import tempfile

        name = str(body.get("filename") or "capture.pcap")
        try:
            raw = base64.b64decode(body.get("content_base64") or "", validate=True)
        except Exception:
            raise HTTPException(400, "파일 내용을 읽지 못했습니다 (base64 아님)")
        if not raw:
            raise HTTPException(400, "빈 파일입니다")
        if len(raw) > MAX_CAPTURE_UPLOAD:
            raise HTTPException(
                413, "파일이 %d MB 를 넘습니다. 구간을 잘라서 올려 주세요."
                     % (MAX_CAPTURE_UPLOAD // (1024 * 1024)))

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "upload.pcap"
            f.write_bytes(raw)
            # 관측 시각은 **캡처 안의 첫 패킷 시각**이다 (ADR-038 에서 고친 것과 같다).
            scan = scan_capture(f)
            doc = capture_topology(scan)

        store.log("capture_scanned", as_of=CTX["as_of"], actor="web",
                  detail={"file": name, "sha256": scan.sha256,
                          "packets": scan.packets, "nodes": len(doc["nodes"]),
                          "edges": len(doc["edges"])})
        prov = doc["provenance"]
        return {
            "filename": name, "sha256": scan.sha256,
            "packets": scan.packets, "window": prov["window"],
            "counters": scan.counters, "warnings": scan.warnings,
            "nodes": doc["nodes"], "edges": doc["edges"],
            "note": prov["note"],
            "topology": doc,
            "known_ports": sorted({e["protocol"] for e in doc["edges"] if e["protocol"]}),
        }

    @app.post("/api/assets/project-file")
    def project_file(body: dict = Body(...)):
        """엔지니어링 프로젝트 파일을 읽어 무엇을 알아봤는지 돌려준다.

        **장비에 붙지 않는다** — 사용자가 준 파일만 읽는다 (불변 규칙 6).
        **기본은 dry-run.** `apply` 를 줘야 자산이 만들어진다 (추측 금지).
        """
        import base64
        import tempfile

        name = str(body.get("filename") or "project.xml")
        raw_b64 = body.get("content_base64") or ""
        try:
            raw = base64.b64decode(raw_b64, validate=True)
        except Exception:
            raise HTTPException(400, "파일 내용을 읽지 못했습니다 (base64 아님)")
        if not raw:
            raise HTTPException(400, "빈 파일입니다")
        if len(raw) > MAX_UPLOAD:
            raise HTTPException(
                413, "파일이 %d MB 를 넘습니다. 하드웨어 구성만 내보내 주세요."
                     % (MAX_UPLOAD // (1024 * 1024)))

        suffix = Path(name).suffix or ".xml"
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / ("upload" + suffix)
            f.write_bytes(raw)
            # 관측 시각은 **브라우저가 보낸 원본 파일의 시각**이다. 임시 파일의
            # mtime 은 방금이라 그걸 쓰면 없는 관측을 기록하게 된다 (ADR-038).
            ms = body.get("last_modified_ms")
            when = None
            if isinstance(ms, (int, float)) and ms > 0:
                import datetime as _dt
                when = _dt.datetime.fromtimestamp(
                    ms / 1000.0, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            scan = scan_file(f, _vocabulary(), workdir=tmp, mtime=when)
            found = project_devices(scan)
            existing = {r["asset_id"] for r in repo.list()}
            rows, created = [], 0
            for d in found:
                aid = d.suggested_asset_id()
                dup = aid in existing
                rows.append({
                    "asset_id": aid, "order_number": d.order_number,
                    "known_as": d.known_as, "vendor": d.vendor,
                    "version": d.version, "ambiguous": d.ambiguous,
                    "version_candidates": [v.value for v in d.versions],
                    "member": d.member, "path": d.path, "model": d.model,
                    "name": d.name, "same_model_count": d.same_model_count,
                    "action": "duplicate" if dup else "create",
                })
            if body.get("apply"):
                picked = set(body.get("pick") or [r["asset_id"] for r in rows])
                for d, row in zip(found, rows):
                    if row["action"] != "create" or row["asset_id"] not in picked:
                        continue
                    repo.put(project_asset(d, scan), CTX["as_of"])
                    created += 1
                store.log("project_file_applied", as_of=CTX["as_of"], actor="web",
                          detail={"file": name, "sha256": scan.sha256,
                                  "created": created})
            else:
                store.log("project_file_scanned", as_of=CTX["as_of"], actor="web",
                          detail={"file": name, "sha256": scan.sha256,
                                  "devices": len(found)})
            return {
                "filename": name, "sha256": scan.sha256,
                "file_mtime": scan.file_mtime,
                "members_read": scan.members_read, "elements": scan.elements,
                "summary": scan.summary(), "warnings": scan.warnings,
                "refused": scan.refused[:20],
                "vocabulary": dict(zip(("order_numbers", "product_names", "vendors"),
                                       _vocabulary().size)),
                "devices": rows, "applied": bool(body.get("apply")),
                "created": created,
                # 화면이 이 문장을 그대로 싣는다. 버전이 '확인' 으로 보이면 안 된다.
                "version_caveat":
                    "프로젝트 파일의 펌웨어는 **설정값**입니다. 장비에서 읽은 값이 "
                    "아니므로 '확인' 으로 쓰지 않고, 실제 버전을 확인할 때까지 "
                    "'가능성 높음' 또는 '정보 부족' 으로 둡니다.",
            }

    @app.post("/api/assets/import")
    def import_csv(body: dict = Body(...)):
        """CSV 를 미리보기 하거나 적용한다 (FR-ASSET-003). 기본은 dry-run."""
        text = body.get("csv") or ""
        apply_it = bool(body.get("apply"))
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False,
                                         encoding="utf-8") as f:
            f.write(text)
            tmp = f.name
        try:
            rep = build_report(tmp, body.get("mapping"),
                               existing_ids=[r["asset_id"] for r in repo.list()])
        except UnsafeInput as exc:
            raise HTTPException(400, str(exc))
        finally:
            Path(tmp).unlink(missing_ok=True)

        result = {
            "rows": rep.rows, "created": rep.created, "duplicates": rep.duplicates,
            "errors": rep.errors, "unmapped": rep.unmapped_headers,
            "mapping": rep.mapping, "sanitized": rep.sanitized_count,
            "applied": False,
            "preview": [{"line": r.line, "asset_id": r.asset_id, "action": r.action,
                         "message": r.message, "asset": r.asset} for r in rep.results],
        }
        if apply_it:
            n = 0
            for r in rep.results:
                if r.action == "create" and r.asset:
                    repo.put(r.asset, CTX["as_of"])
                    n += 1
            store.log("import_applied", as_of=CTX["as_of"], actor="web",
                      detail={"created": n})
            result["applied"] = True
            result["created"] = n
        else:
            store.log("import_dry_run", as_of=CTX["as_of"], actor="web",
                      detail={"rows": rep.rows})
        return result

    # ---------------------------------------------------------------- 운영 콘솔
    @app.get("/api/ops")
    def ops():
        kevp = find_snapshot()
        return {
            "sources": [
                {"name": "CSAF 권고문", "count": len(advisories), "unit": "건",
                 "detail": "발행처 %d곳 · 대상 제품 %s개 · 고유 CVE %s개"
                           % (len({a.publisher_name for a in advisories}),
                              "{:,}".format(sum(len(a.products) for a in advisories)),
                              "{:,}".format(len(_all_cves))),
                 "used": len(advisories) - _unverified_advs,
                 "used_label": "그중 발행처 권위를 확인한 것",
                 "extra": (("권위 미확인 %d건 · 발행처 %d곳: %s — 값은 보여주되 "
                            "검증된 출처를 이기지 못합니다."
                            % (_unverified_advs, len(_unverified_pubs),
                               ", ".join(_unverified_pubs[:4])))
                           if _unverified_advs else
                           "모든 발행처를 KNOWN_PUBLISHERS 표로 판단했습니다."),
                 "ok": bool(advisories)},

                {"name": "CISA KEV", "count": len(kev.cve_ids) if kev else 0,
                 "unit": "개",
                 "detail": ("카탈로그 %s — CISA 가 실제 악용을 확인한 CVE 전체입니다"
                            % kev.catalog_version) if kev else "미로드",
                 "used": _kev_overlap,
                 "used_label": "그중 우리 권고문 범위와 겹치는 CVE",
                 "extra": "겹친다고 해서 전부 발견이 되는 것은 아닙니다 — "
                          "그 권고문에 해당하는 자산이 있어야 큐에 뜹니다.",
                 "ok": bool(kev)},

                {"name": "ATT&CK ICS", "count": len(attack.techniques) if attack else 0,
                 "unit": "기법",
                 "detail": ("v%s 고정 · 번들에서 색인한 ICS 기법 (폐기 항목 제외)"
                            % attack.version) if attack else "미로드",
                 "used": len(_mapped_techniques) if attack else 0,
                 "used_label": "그중 엣지 타입에 매핑한 기법",
                 "extra": ("매핑: %s. 나머지는 참조용입니다 — 근거 없이 기법을 "
                           "붙이지 않습니다 (표 32)." % ", ".join(_mapped_techniques))
                          if attack else None,
                 "ok": bool(attack)},

                {"name": "토폴로지", "count": len(topo.nodes) if topo else 0,
                 "unit": "노드",
                 "detail": ("엣지 %d개%s" % (len(topo.edges),
                            " · 합성 — 실제 공장 관측이 아닙니다"
                            if topo.provenance.get("synthetic") else ""))
                           if topo else "미로드",
                 "used": len(topo.nodes) if topo else 0,
                 "used_label": "경로 계산에 씁니다",
                 "ok": bool(topo)},
            ],
            "versions": {"policy": CTX["policy"].version,
                         "parser": advisories[0].parser_version if advisories else "-"},
            "assets": repo.count(),
            "sweep": {"state": sweep["state"], "done": sweep["done"],
                      "total": sweep["total"], "pairs": sweep["pairs"],
                      "excluded": sweep["skipped"], "evaluated": sweep["evaluated"],
                      "findings": len(sweep["rows"]), "seconds": sweep["seconds"],
                      "kev_findings": sum(
                          1 for _r, _a, d, _adv in sweep["rows"]
                          if kev and any(c in kev.cve_ids for c in d.cves))},
            "audit": [{"id": r["id"], "as_of": r["as_of"], "action": r["action"],
                       "actor": r["actor"],
                       "authenticated": bool(r["actor_authenticated"]),
                       "subject": r["subject"]}
                      for r in store.events()[-40:]][::-1],
            "authenticated": False,
            "backend": repo.backend,
        }

    # ---------------------------------------------------------------- 정적
    # 기본은 Vite 빌드 결과(`web/dist`)다. 경로는 해시 라우팅이라 서버에
    # catch-all 이 필요 없다 — `/ui/#/asset/plc-01` 은 그냥 `/ui/index.html` 이다.
    # 외부 자원은 여전히 0개다: 번들은 전부 로컬에서 만들어 함께 배포한다.
    if DIST.exists():
        app.mount("/ui", StaticFiles(directory=str(DIST), html=True), name="ui")
    else:
        # 빌드가 없으면 /ui 는 404 였다 — README 를 보고 온 사람이 첫 화면에서 막힌다.
        # 폴백(UMD) 화면이 있는 / 로 보낸다. 해시 경로는 그대로 살아남는다.
        @app.get("/ui")
        @app.get("/ui/")
        @app.get("/ui/{path:path}")
        def ui_fallback(path: str = ""):
            return RedirectResponse("/")

    # UMD 판(빌드 없이 도는 폴백)은 /legacy 로 남긴다.
    if (WEB / "vendor").exists():
        app.mount("/vendor", StaticFiles(directory=str(WEB / "vendor")), name="vendor")

    @app.get("/")
    def index():
        if DIST.exists():
            return RedirectResponse("/ui/")
        return FileResponse(str(WEB / "index.html"))

    @app.get("/legacy")
    def legacy():
        return FileResponse(str(WEB / "index.html"))

    @app.get("/app.js")
    def appjs():
        return FileResponse(str(WEB / "app.js"), media_type="application/javascript")

    @app.get("/app.css")
    def appcss():
        return FileResponse(str(WEB / "app.css"), media_type="text/css")

    return app


def _asset_to_body(asset, base: dict) -> dict:
    """Asset 객체를 부록 C 형식 본문으로 되돌린다."""
    b = dict(base)
    b["asset_id"] = asset.asset_id
    b["asset_type"] = asset.asset_type or b.get("asset_type") or "unknown"
    ident = {k: v for k, v in {
        "vendor_raw": asset.identity.vendor_raw,
        "family_raw": asset.identity.family_raw,
        "model_raw": asset.identity.model_raw,
        "order_number": asset.identity.order_number}.items() if v}
    b["identity"] = ident
    b["components"] = [{
        "type": c.type,
        "version": ({"raw": c.version_raw} if c.version_raw else {"state": "unknown"}),
        "observed_at": c.observed_at, "method": c.method, "evidence_id": c.evidence_id}
        for c in asset.components]
    b["operations"] = asset.operations or {}
    if asset.lifecycle_status:
        b["lifecycle_status"] = asset.lifecycle_status
    if asset.network.declared:
        b["network"] = {
            "services": [{"protocol": p.protocol, "port": p.port, "role": p.role,
                          "encrypted": p.encrypted} for p in asset.network.protocols],
            "remote_access": asset.network.remote_access}
    return b
