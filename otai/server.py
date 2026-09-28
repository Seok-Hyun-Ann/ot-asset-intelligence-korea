# -*- coding: utf-8 -*-
"""로컬 입력 서버 — 사용자가 직접 장치를 넣고 판정을 받는다.

    python -m otai ask

**추가 의존성 없음.** 표준 라이브러리 http.server 만 쓴다.
**127.0.0.1 에만 바인딩한다.** 인증이 없으므로 외부에 열지 않는다 (슬라이스 5 보류 사항).

정적 UI(`scripts/build_ui.py`)와 역할이 다르다:
  정적 UI   미리 계산한 조합을 보는 것. 폐쇄망 반입·발표용.
  이 서버   **사용자가 아는 것만 넣고** 실제 엔진이 판정과 다음 질문을 돌려주는 것.
            기획서 UC01·FR-ASSET-001·FR-NBQ-001 의 핵심 루프다.
"""
from __future__ import annotations

import json
import re
import sys
import threading
import webbrowser
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import List

from .applicability import decide_applicability
from .ask import apply_answer, next_question
from .csaf import load_advisory
from .kev import find_snapshot, load_kev
from .model import Asset, Identity
from .priority import evaluate_priority
from .topology import load_topology

STATE = {"advisories": [], "kev": None, "topo": None, "as_of": "2026-09-11",
         "outdir": Path("fixtures/assets")}


def blank_asset(asset_id="new-asset") -> Asset:
    return Asset(asset_id=asset_id, asset_type="", identity=Identity(None, None, None, None),
                 components=(), location={}, operations={})


def asset_from_json(d: dict) -> Asset:
    a = blank_asset(d.get("asset_id") or "new-asset")
    for field, value in (d.get("answers") or {}).items():
        a = apply_answer(a, field, value, STATE["as_of"])
    return a


def judge(asset: Asset) -> dict:
    as_of = STATE["as_of"]
    out = []
    for adv in STATE["advisories"]:
        d = decide_applicability(asset, adv, as_of=as_of)
        it = evaluate_priority(d, asset, kev=STATE["kev"], topology=STATE["topo"])
        out.append({
            "advisory": adv.advisory_id,
            "title": adv.title,
            "publisher": adv.publisher_name,
            "status": d.status, "phrase": d.phrase_ko,
            "identity": d.identity_level, "confidence": round(d.identity_confidence, 2),
            "bucket": it.bucket, "bucket_phrase": it.bucket_phrase,
            "floor": it.floor_if_confirmed,
            "fired": it.fired_rules,
            "pending": [{"rule": p.rule_id, "floor": p.floor_if_confirmed,
                         "missing": p.missing} for p in it.pending_escalations],
            "conditions": d.decisive_conditions,
            "fields": d.fields,
            "question": d.next_best_question,
            "raw_expression": d.evidence.get("raw_expression"),
            "advisory_sha": str(d.evidence.get("advisory_sha256"))[:16],
            "input_hash": d.input_hash[:16],
            "kev": it.kev_cves,
            "n_cves": len(d.cves),
        })
    order = {"affected_confirmed": 0, "affected_likely": 1, "candidate": 2,
             "insufficient_information": 3, "conflicting_evidence": 4, "stale": 5,
             "no_known_match": 6, "not_affected_confirmed": 7, "fixed": 8}
    out.sort(key=lambda r: (order.get(r["status"], 9), r["advisory"]))

    q = next_question(asset, STATE["advisories"], as_of)
    return {
        "as_of": as_of,
        "judgments": out,
        "question": None if q is None else {
            "field": q.field, "label": q.label, "help": q.help, "kind": q.kind,
            "options": q.options, "why": q.why, "skippable": q.skippable},
        "known": {
            "asset_type": asset.asset_type or None,
            "vendor": asset.identity.vendor_raw,
            "model": asset.identity.model_raw,
            "order_number": asset.identity.order_number,
            "firmware": next((c.version_raw for c in asset.components if c.version_raw), None),
            "safety": (asset.operations or {}).get("safety_criticality"),
            "lifecycle": asset.lifecycle_status,
            "network": asset.network.declared,
        },
    }


_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def save_asset(asset: Asset) -> str:
    """입력한 자산을 픽스처 파일로 남긴다 — CLI·테스트로 그대로 흘러간다."""
    aid = asset.asset_id
    if not _SAFE_ID.match(aid):
        raise ValueError("자산 id 는 영문·숫자·.-_ 만, 64자 이내입니다")
    out = STATE["outdir"]
    out.mkdir(parents=True, exist_ok=True)
    body = {
        "asset_id": aid,
        "asset_type": asset.asset_type or "unknown",
        "identity": {k: v for k, v in {
            "vendor_raw": asset.identity.vendor_raw,
            "family_raw": asset.identity.family_raw,
            "model_raw": asset.identity.model_raw,
            "order_number": asset.identity.order_number}.items() if v},
        "components": [{
            "type": c.type,
            "version": ({"raw": c.version_raw} if c.version_raw else {"state": "unknown"}),
            "observed_at": c.observed_at, "method": c.method,
            "evidence_id": c.evidence_id} for c in asset.components],
        "operations": asset.operations or {},
    }
    if asset.lifecycle_status:
        body["lifecycle_status"] = asset.lifecycle_status
    if asset.network.declared:
        body["network"] = {
            "services": [{"protocol": p.protocol, "port": p.port,
                          "role": p.role, "encrypted": p.encrypted}
                         for p in asset.network.protocols],
            "remote_access": asset.network.remote_access,
        }
    path = out / (aid + ".json")
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return str(path)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # 콘솔을 조용하게

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            from .askpage import PAGE
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/context":
            self._send(200, json.dumps({
                "as_of": STATE["as_of"],
                "advisories": [{"id": a.advisory_id, "title": a.title,
                                "publisher": a.publisher_name} for a in STATE["advisories"]],
                "kev": STATE["kev"].catalog_version if STATE["kev"] else None,
                "topology": STATE["topo"].source_path if STATE["topo"] else None,
            }, ensure_ascii=False))
        else:
            self._send(404, json.dumps({"error": "없는 경로입니다"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1 << 20:
            return self._send(413, json.dumps({"error": "입력이 너무 큽니다"}))
        try:
            payload = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception as exc:
            return self._send(400, json.dumps({"error": "JSON 을 읽을 수 없습니다: %s" % exc},
                                              ensure_ascii=False))
        try:
            asset = asset_from_json(payload)
            if self.path == "/judge":
                self._send(200, json.dumps(judge(asset), ensure_ascii=False))
            elif self.path == "/save":
                self._send(200, json.dumps({"path": save_asset(asset)}, ensure_ascii=False))
            else:
                self._send(404, json.dumps({"error": "없는 경로입니다"}, ensure_ascii=False))
        except ValueError as exc:
            self._send(400, json.dumps({"error": str(exc)}, ensure_ascii=False))
        except Exception as exc:                       # noqa: BLE001
            self._send(500, json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)},
                                       ensure_ascii=False))


def serve(advisories: List[Path], as_of: str, port: int = 8765,
          topology: Path = None, outdir: Path = None, open_browser: bool = True) -> int:
    STATE["advisories"] = [load_advisory(p) for p in advisories]
    STATE["as_of"] = as_of
    snap = find_snapshot()
    STATE["kev"] = load_kev(snap) if snap else None
    STATE["topo"] = load_topology(topology) if topology else None
    if outdir:
        STATE["outdir"] = Path(outdir)

    srv = HTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d/" % port
    sys.stdout.write("장치 입력 서버가 떴습니다 — %s\n" % url)
    sys.stdout.write("  권고문 %d건 · KEV %s · 기준 시점 %s\n"
                     % (len(STATE["advisories"]),
                        STATE["kev"].catalog_version if STATE["kev"] else "미로드", as_of))
    sys.stdout.write("  127.0.0.1 에만 열려 있습니다. 인증이 없으므로 외부에 노출하지 마세요.\n")
    sys.stdout.write("  멈추려면 Ctrl+C\n")
    sys.stdout.flush()
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\n서버를 멈췄습니다.\n")
    finally:
        srv.server_close()
    return 0
