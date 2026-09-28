# -*- coding: utf-8 -*-
"""대화형 UI 생성 — 자기완결 HTML 한 개.

    python scripts/build_ui.py            # → out/ui/index.html
    python scripts/build_ui.py --open     # 만들고 브라우저로 열기

**서버가 없다.** 조합을 미리 계산해 JSON 으로 심고, 브라우저에서 선택만 한다.
그래서 폐쇄망에서 파일 하나만 복사하면 그대로 동작한다 (NFR-OFF-001).

ADR-016 정정: "JS 0줄" 은 과한 조문이었다. 실제 제약은 두 가지다 —
**비결정적 레이아웃 금지**(바이트 동일 게이트)와 **외부 자원 금지**(폐쇄망).
인라인 JS 로 *표시*를 바꾸는 것은 둘 다 어기지 않는다. 계산은 여전히 파이썬이
하고, JS 는 이미 계산된 것을 고르고 정렬할 뿐이다.

렌즈 가중치만은 브라우저에서 다시 계산한다 — 가중치를 아무리 움직여도
**버킷이 절대 안 움직인다**는 불변량을 눈으로 보여주기 위해서다.
"""
from __future__ import annotations

import argparse
import html
import io
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from otai.applicability import PHRASES, decide_applicability      # noqa: E402
from otai.attack import find_bundle, load_attack                  # noqa: E402
from otai.csaf import load_advisory                               # noqa: E402
from otai.kev import find_snapshot, load_kev                      # noqa: E402
from otai.model import load_asset                                 # noqa: E402
from otai.paths import blocking_candidates, find_paths            # noqa: E402
from otai.priority import (BUCKET_ORDER, BUCKET_PHRASES,          # noqa: E402
                           LENS_DIMENSIONS, LENS_PRESETS, evaluate_priority)
from otai.render import render_svg                                # noqa: E402
from otai.sources import (compare_products, link_advisories,      # noqa: E402
                          provenance_table)
from otai.topology import load_topology                           # noqa: E402

# 9개 상태는 임의의 라벨이 아니라 **확신도 축 위의 세 그룹**이다.
# 화면이 그 구조를 드러내야 읽을 수 있다 (NFR-UX-001: 3분 내 설명).
#
# 라벨은 부록 B 의 정본 문구를 그대로 쓰고, 평문 설명을 아래에 덧붙인다.
# 라벨을 바꾸면 안 되지만, 설명 없이 두는 것도 안 된다.
STATE_INFO = {
    # ── 해당함 · 조치가 필요하다 ──────────────────────────────────
    "affected_confirmed": {
        "group": "해당함", "rank": 1, "tone": "alarm",
        "plain": "이 장비가 이 취약점에 해당합니다. 제품·버전·구성이 모두 맞습니다.",
        "next": "조치 등급을 정하고 실행하세요.",
    },
    "affected_likely": {
        "group": "해당함", "rank": 2, "tone": "alarm",
        "plain": "제품은 맞는데 버전이나 구성 일부를 추론했습니다.",
        "next": "정확한 모델·버전을 확인하면 확정됩니다.",
    },
    "candidate": {
        "group": "해당함", "rank": 3, "tone": "caution",
        "plain": "제품군까지만 맞습니다. 같은 시리즈라는 것만 아는 상태입니다.",
        "next": "정확한 모델을 확인하세요. 해당 여부가 갈립니다.",
    },
    # ── 판단 보류 · 더 알아야 한다 ────────────────────────────────
    "insufficient_information": {
        "group": "판단 보류", "rank": 4, "tone": "caution",
        "plain": "판정에 필요한 값이 없습니다. 대개 펌웨어 버전입니다.",
        "next": "빠진 값을 확인하세요. 카드에 무엇이 없는지 적혀 있습니다.",
    },
    "conflicting_evidence": {
        "group": "판단 보류", "rank": 5, "tone": "caution",
        "plain": "출처끼리 말이 다릅니다. 자동으로 한쪽을 고르지 않습니다.",
        "next": "두 주장을 비교하고 사람이 판단하세요.",
    },
    "stale": {
        "group": "판단 보류", "rank": 6, "tone": "caution",
        "plain": "관측이 너무 오래됐습니다. 값은 있지만 믿고 확정할 수 없습니다.",
        "next": "다시 관측하세요.",
    },
    "no_known_match": {
        "group": "판단 보류", "rank": 7, "tone": "caution",
        "plain": "이 권고문의 대상 목록에 없습니다. 안전하다는 뜻이 아닙니다.",
        "next": "다른 권고문은 따로 확인해야 합니다.",
    },
    # ── 해당 없음 · 종결할 수 있다 ────────────────────────────────
    "not_affected_confirmed": {
        "group": "해당 없음", "rank": 8, "tone": "settled",
        "plain": "근거를 갖고 해당하지 않습니다. 버전이 영향 범위 밖입니다.",
        "next": "종결. 권고문이 개정되면 다시 봅니다.",
    },
    "fixed": {
        "group": "해당 없음", "rank": 9, "tone": "settled",
        "plain": "패치했고 그 증거가 있습니다.",
        "next": "종결. 되돌아가지 않았는지만 모니터합니다.",
    },
}

GROUPS = [
    ("해당함", "조치가 필요합니다", "alarm"),
    ("판단 보류", "더 알아야 합니다", "caution"),
    ("해당 없음", "종결할 수 있습니다", "settled"),
]

# 좁은 칸(행 왼쪽)과 넓은 곳(카드)에서 쓰는 말이 다르다.
# 한 문자열을 두 곳에 우겨넣으면 어느 한쪽이 반드시 어색해진다.
BUCKET_SHORT = {
    "P0": "지금",
    "P?": "확인 먼저",
    "P1": "창 밖에",
    "P2": "다음 창에",
    "P3": "모니터",
    "P4": "종결",
}

BUCKET_INFO = {
    "P0": "지금 격리하거나 비상 검토",
    "P?": "전제조건이 미상이라 막힌 P0/P1 — 확인이 먼저입니다",
    "P1": "정기 정비 창 밖에서 조치",
    "P2": "다음 정비 창에 조치",
    "P3": "확인하거나 모니터",
    "P4": "해당 없음·수용·종결",
}

ASSETS = ROOT / "fixtures" / "assets"
CSAF = ROOT / "data" / "csaf"
TOPO = ROOT / "fixtures" / "topology" / "purdue-62443-reference.json"
OUT = ROOT / "out" / "ui"

# 미리 계산할 시점들 — 정보가 늘면서 결론이 움직이는 것을 보이려면 여럿이 필요하다
AS_OF_CHOICES = ["2026-08-01", "2026-08-22", "2026-09-09"]


def esc(s):
    return html.escape(str(s if s is not None else ""))


def build_records(assets, advisories, topo, kev):
    """(자산 × 권고 × 시점 × 토폴로지 유무) 전 조합을 미리 계산한다."""
    records = []
    for a in assets:
        for adv in advisories:
            for as_of in AS_OF_CHOICES:
                d = decide_applicability(a, adv, as_of=as_of)
                for topo_on in (False, True):
                    it = evaluate_priority(d, a, kev=kev,
                                           topology=topo if topo_on else None)
                    records.append({
                        "asset": a.asset_id,
                        "advisory": adv.advisory_id,
                        "as_of": as_of,
                        "topo": topo_on,
                        "status": d.status,
                        "phrase": d.phrase_ko,
                        "identity": d.identity_level,
                        "confidence": round(d.identity_confidence, 2),
                        "bucket": it.bucket,
                        "bucket_phrase": it.bucket_phrase,
                        "floor": it.floor_if_confirmed,
                        "fired": it.fired_rules,
                        "pending": [{"rule": p.rule_id, "floor": p.floor_if_confirmed,
                                     "missing": p.missing, "question": p.question}
                                    for p in it.pending_escalations],
                        "rationale": it.rationale,
                        "conditions": d.decisive_conditions,
                        "fields": d.fields,
                        "question": d.next_best_question,
                        "kev": it.kev_cves,
                        "cves": d.cves[:8],
                        "n_cves": len(d.cves),
                        "signals": {k: round(v, 4) for k, v in it.signals.items()},
                        "raw_expression": d.evidence.get("raw_expression"),
                        "advisory_sha": str(d.evidence.get("advisory_sha256"))[:16],
                        "input_hash": d.input_hash[:16],
                        "policy": it.policy_version,
                        "rule_version": d.rule_version,
                    })
    return records


def build_paths(topo):
    out = {}
    for node in topo.nodes.values():
        if node.asset_id is None:
            continue
        paths = find_paths(topo, node.node_id, as_of="2026-09-09")
        blocks = blocking_candidates(topo, [node.node_id], as_of="2026-09-09", top=5)
        out[node.asset_id] = {
            "node": node.node_id,
            "label": node.label,
            "paths": [{
                "status": p.status,
                "confidence": round(p.confidence, 3),
                "nodes": list(p.nodes),
                "edges": list(p.edge_keys),
                "weakest": p.weakest.key if p.weakest else None,
                "hops": [{"src": h.edge.src, "dst": h.edge.dst, "label": h.edge.label,
                          "status": h.edge.status, "caps": sorted(h.caps_after)}
                         for h in p.hops],
            } for p in paths],
            "blocks": [{"edge": b.edge.key, "cut": b.paths_cut,
                        "legit": b.legitimate_flows_broken,
                        "remaining": b.paths_remaining} for b in blocks],
        }
    return out


def build_sources(advisories):
    groups = []
    for g in link_advisories(advisories):
        if len(g.advisories) < 2:
            continue
        comps = compare_products(g)
        groups.append({
            "cves": list(g.cves),
            "provenance": provenance_table(g),
            "n_products": len(comps),
            "n_conflict": sum(1 for c in comps if c.conflicting),
            "samples": [{
                "key": c.key,
                "value": c.views["version_range"].current.value,
                "source": c.views["version_range"].current.source_id,
                "role": c.views["version_range"].current.source_role,
                "corroborated": list(c.views["version_range"].corroborated_by),
                "conflicting": c.conflicting,
            } for c in comps[:40]],
        })
    return groups


CSS = """
/* 디아조 청사진 — 도면 종이, 프러시안 블루 선, 검사 도장의 붉은색 하나.
   대시보드 팔레트가 아니라 문서 팔레트다. 채도는 판정에만 쓴다. */
:root{
  --paper:#EFEDE7; --card:#FBFAF7; --sink:#E6E3DB;
  --line:#17365D; --line2:#40618C;
  --ink:#1A1C1E; --faded:#77808A; --rule:#C6C2B8; --hair:#DEDAD1;
  --stamp:#A31C1F;     /* 검사 도장 — 해당함 · P0 에만 */
  --pending:#8A6800;   /* 판단 보류 */
  --settled:#2C5C43;   /* 해당 없음 */
  --serif:Batang,'Times New Roman',serif;
  --sans:'Malgun Gothic','Segoe UI',sans-serif;
  --mono:Consolas,'Courier New',monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  font-size:13px;line-height:1.6}
:focus-visible{outline:2px solid var(--line);outline-offset:2px}

/* ── 표제란 (도면 title block) ────────────────────────────── */
.tb{border-top:5px solid var(--line);background:var(--card);
  border-bottom:1px solid var(--rule)}
.tb-in{max-width:1420px;margin:0 auto;padding:0 26px;display:flex;flex-wrap:wrap;
  align-items:stretch;gap:0}
.tb .brand{padding:13px 22px 12px 0;border-right:1px solid var(--hair);margin-right:20px}
.tb .brand b{display:block;font-family:var(--serif);font-size:19px;font-weight:700;
  letter-spacing:-.01em;line-height:1.15;color:var(--line)}
.tb .brand span{display:block;font-size:10.5px;color:var(--faded);margin-top:2px}
.fld{padding:11px 18px 10px 0;display:flex;flex-direction:column;justify-content:center}
.fld>label{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faded);
  font-weight:700;margin-bottom:3px}
.fld select{border:0;border-bottom:1px solid var(--rule);background:0;padding:2px 16px 2px 0;
  font-family:var(--mono);font-size:12.5px;color:var(--ink);cursor:pointer;
  appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--line2) 50%),
  linear-gradient(135deg,var(--line2) 50%,transparent 50%);
  background-position:calc(100% - 5px) 9px,calc(100% - 1px) 9px;
  background-size:4px 4px,4px 4px;background-repeat:no-repeat}
.fld select:hover{border-bottom-color:var(--line)}
.chk{display:flex;align-items:center;gap:7px;padding:11px 18px 10px 0;cursor:pointer}
.chk input{margin:0;accent-color:var(--line)}
.chk span{font-size:12px}
.stampinfo{margin-left:auto;padding:12px 0;text-align:right;font-family:var(--mono);
  font-size:10.5px;color:var(--faded);line-height:1.5;align-self:center}

/* ── 색인 ─────────────────────────────────────────────────── */
.nav{background:var(--card);border-bottom:1px solid var(--rule)}
.nav-in{max-width:1420px;margin:0 auto;padding:0 26px;display:flex;gap:0}
.tab{border:0;background:0;padding:9px 17px;font-family:var(--sans);font-size:12.5px;
  color:var(--faded);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab:hover{color:var(--line)}
.tab.on{color:var(--line);font-weight:700;border-bottom-color:var(--line)}

.sheet{max-width:1420px;margin:0 auto;padding:30px 26px 70px}

/* ── 영웅: 확신이 끝나는 지점 ─────────────────────────────── */
.thesis{font-family:var(--serif);font-size:34px;line-height:1.34;font-weight:700;
  color:var(--line);letter-spacing:-.015em;margin:0 0 4px;max-width:19em}
.thesis em{font-style:normal;color:var(--stamp)}
.thesis.calm em{color:var(--settled)}
.sub{font-size:13px;color:var(--faded);margin-bottom:22px;max-width:52em}

.band{display:flex;align-items:stretch;border:1px solid var(--line);background:var(--card);
  overflow:hidden}
.seg{border:0;padding:9px 13px;display:block;cursor:pointer;font-family:var(--sans);
  text-align:left;color:#fff;flex-basis:0;min-width:96px;overflow:hidden;
  transition:flex-grow .22s ease}
.seg+.seg{border-left:1px solid var(--card)}
.seg .n{display:block;font-family:var(--mono);font-size:20px;font-weight:700;line-height:1.1}
.seg .l{display:block;font-size:11px;margin-top:3px;opacity:.92;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
.seg.sv0{background:var(--stamp)} .seg.sv1{background:var(--pending)} .seg.sv2{background:var(--settled)}
.seg.empty{flex-grow:0!important;min-width:0;padding:0;width:0}
.seg:hover .l{opacity:1}

.ticks{display:flex;margin-top:1px}
.tg{display:flex;gap:1px;padding-right:1px;flex-basis:0;min-width:0}
.tick{border:1px solid var(--hair);border-top:0;background:var(--card);padding:6px 9px 7px;
  cursor:pointer;font-family:var(--sans);text-align:left;flex:1;min-width:0;
  transition:background .15s}
.tick:hover{background:var(--sink)}
.tick.on{background:var(--sink);box-shadow:inset 0 2px 0 var(--line)}
.tick.zero{opacity:.4}
.tick .n{font-family:var(--mono);font-size:13px;font-weight:700}
.tick .l{font-size:10px;color:var(--faded);white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.t0 .n{color:var(--stamp)} .t1 .n{color:var(--pending)} .t2 .n{color:var(--settled)}
.filterbar{margin-top:11px;padding:9px 13px;background:var(--card);
  border-left:3px solid var(--line);font-size:12.5px}
.filterbar b{font-family:var(--serif);font-size:15px}
.filterbar a{color:var(--line);margin-left:9px}

/* ── 관점 ─────────────────────────────────────────────────── */
.lens{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:26px 0 6px;
  padding:11px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}
.lens>.lb{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faded);
  font-weight:700}
.wsl{display:flex;align-items:center;gap:6px}
.wsl b{font-size:11px;font-weight:400;color:var(--faded);min-width:26px}
.wsl input{width:64px;accent-color:var(--line)}
.wsl output{font-family:var(--mono);font-size:10.5px;color:var(--faded);min-width:18px}
.pre{display:flex;gap:6px;margin-left:auto}
.pre button{border:1px solid var(--rule);background:var(--card);padding:4px 12px;
  font-family:var(--sans);font-size:11.5px;cursor:pointer;color:var(--faded)}
.pre button:hover{border-color:var(--line);color:var(--line)}
.lensnote{font-size:11.5px;color:var(--faded);margin-bottom:20px}

/* ── 판정 항목 (성적서 한 줄) ─────────────────────────────── */
.recs{border-top:1px solid var(--rule)}
.rec{display:grid;grid-template-columns:88px 1fr 296px 54px;gap:20px;padding:15px 4px 16px;
  border-bottom:1px solid var(--hair);cursor:pointer;align-items:start}
.rec:hover{background:var(--card)}
.rec.on{background:var(--card);box-shadow:inset 3px 0 0 var(--line)}
.mark{font-family:var(--mono);font-size:22px;font-weight:700;line-height:1;letter-spacing:-.03em}
.mark small{display:block;font-family:var(--sans);font-size:10px;font-weight:400;
  color:var(--faded);margin-top:4px;letter-spacing:0}
.k0 .mark{color:var(--stamp)} .k1 .mark{color:var(--pending)} .k2 .mark{color:var(--settled)}
.tagno{font-family:var(--mono);font-size:12px;color:var(--faded);letter-spacing:.02em}
.verdict{font-family:var(--serif);font-size:19px;font-weight:700;line-height:1.3;
  margin:1px 0 3px;letter-spacing:-.01em}
.k0 .verdict{color:var(--stamp)} .k1 .verdict{color:var(--pending)} .k2 .verdict{color:var(--settled)}
.verdict code{font-family:var(--mono);font-size:10.5px;font-weight:400;color:var(--faded);
  margin-left:7px;letter-spacing:0}
.say{font-size:12.5px;color:#454b52;max-width:46em}
.rule{font-size:12px;text-align:left}
.rule .hi{font-family:var(--mono);font-weight:700;color:var(--line)}
.rule .sub2{color:var(--faded);font-size:11.5px;margin-top:3px;line-height:1.5}
.wt{font-family:var(--mono);font-size:12.5px;color:var(--faded);text-align:right}
.empty{padding:34px 0;color:var(--faded);font-size:13px}

/* ── 문서 요소 ───────────────────────────────────────────── */
h3{font-family:var(--sans);font-size:9.5px;font-weight:700;letter-spacing:.18em;
  text-transform:uppercase;color:var(--faded);margin:30px 0 10px;
  padding-bottom:6px;border-bottom:1px solid var(--rule)}
h3:first-child{margin-top:0}
.docttl{font-family:var(--serif);font-size:26px;font-weight:700;color:var(--line);
  line-height:1.25;margin:0 0 3px;letter-spacing:-.015em}
.docsub{font-size:12.5px;color:var(--faded);margin-bottom:22px}
table{border-collapse:collapse;width:100%;font-size:12.5px;background:var(--card)}
th,td{border:1px solid var(--hair);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--sink);font-weight:700;font-size:9.5px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--faded)}
.m{font-family:var(--mono);font-size:11.5px}
.k{color:var(--faded);font-size:11.5px}
.callout{border-left:3px solid var(--pending);background:var(--card);padding:11px 14px;
  margin:12px 0;font-size:12.5px}
.callout.ok{border-left-color:var(--settled)}
.callout.hot{border-left-color:var(--stamp)}
.callout .big{font-family:var(--serif);font-size:20px;font-weight:700;display:block;
  margin-bottom:5px}
ul{margin:7px 0;padding-left:19px}li{margin:4px 0}
.cols2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
select.wide{width:100%;padding:7px 9px;border:1px solid var(--rule);background:var(--card);
  font-family:var(--mono);font-size:12px;margin-bottom:12px}
svg{max-width:100%;height:auto;border:1px solid var(--rule);background:var(--card)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media (max-width:980px){
  .thesis{font-size:25px}
  .rec{grid-template-columns:70px 1fr;gap:13px}
  .rule,.wt{grid-column:2}.wt{text-align:left}
  .cols2{grid-template-columns:1fr}
  .stampinfo{margin-left:0;text-align:left;width:100%;padding-bottom:11px}
  .band{height:auto;flex-wrap:wrap}.seg{min-width:33%;padding:10px 12px}
  .ticks{flex-wrap:wrap}.tg{flex:1 1 100%}
}
"""

JS = r"""
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const D=DATA, ORD=D.bucket_order, SI=D.state_info, GRP=D.groups.map(g=>g[0]);
let W=Object.assign({},D.lens_presets['default']), TAB='rec', FILTER=null;

const ctl=()=>({asset:$('#asset').value,adv:$('#adv').value,asOf:$('#asof').value,topo:$('#topo').checked});
const recs=()=>{const c=ctl();return D.records.filter(r=>r.advisory===c.adv&&r.as_of===c.asOf&&r.topo===c.topo);};
const cur=()=>recs().find(r=>r.asset===ctl().asset);
const score=r=>D.dims.reduce((s,d)=>s+(W[d]||0)*(r.signals[d]||0),0);
const gi=st=>GRP.indexOf(SI[st].group);
const esc=t=>String(t??'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));

function sortQ(rs){return rs.slice().sort((a,b)=>{
  const d=ORD[a.bucket]-ORD[b.bucket]; if(d)return d;
  const f=(ORD[a.floor]??99)-(ORD[b.floor]??99); if(f)return f;
  const s=score(b)-score(a); if(Math.abs(s)>1e-9)return s;
  return a.asset<b.asset?-1:1;});}

/* ── 영웅 + 시그니처: 확신 띠 ────────────────────────────────
   폭이 건수에 비례한다. 어디서 확신이 끊기는지가 숫자가 아니라 형태로 보인다. */
function hero(all){
  const byG=[0,0,0], byS={};
  all.forEach(r=>{byG[gi(r.status)]++; byS[r.status]=(byS[r.status]||0)+1;});
  const total=all.length, unsure=byG[1];

  let h='';
  if(unsure) h+=`<p class="thesis">${total}건 중 <em>${unsure}건</em>은<br>아직 답할 수 없습니다.</p>
    <p class="sub">모르는 것을 아는 것처럼 답하지 않습니다. 무엇을 물어야 답할 수 있는지는 아래 각 항목에 적혀 있습니다.</p>`;
  else h+=`<p class="thesis calm">${total}건 모두<br><em>답할 수 있습니다.</em></p>
    <p class="sub">이 권고문 범위 안에서는 판단을 보류한 항목이 없습니다.</p>`;

  h+='<div class="band">';
  D.groups.forEach(([g,sub,_],i)=>{
    h+=`<button class="seg sv${i}${byG[i]?'':' empty'}" style="flex-grow:${byG[i]||0}"
        onclick="filtG(${i})" aria-label="${g} ${byG[i]}건">
        <span class="n">${byG[i]}</span><span class="l">${g} · ${sub}</span></button>`;
  });
  h+='</div><div class="ticks">';
  const order=Object.keys(SI).sort((a,b)=>SI[a].rank-SI[b].rank);
  D.groups.forEach(([g],i)=>{
    const ks=order.filter(k=>SI[k].group===g);
    h+=`<div class="tg" style="flex-grow:${byG[i]||0};flex-basis:0">`;
    ks.forEach(k=>{const c=byS[k]||0;
      h+=`<button class="tick t${i}${FILTER===k?' on':''}${c?'':' zero'}" onclick="filt('${k}')"
          title="${esc(SI[k].plain)}"><span class="n">${c}</span>
          <span class="l">${D.phrases[k]}</span></button>`;});
    h+='</div>';
  });
  h+='</div>';
  if(FILTER) h+=`<div class="filterbar"><b>${D.phrases[FILTER]}</b> ${esc(SI[FILTER].plain)}
    <br><span class="k">다음 행동 — ${esc(SI[FILTER].next)}</span>
    <a href="#" onclick="filt(null);return false">전체 보기</a></div>`;
  return h;
}

function renderRecs(){
  const all=recs(), rs=sortQ(FILTER?all.filter(r=>r.status===FILTER):all), c=ctl();
  let h=hero(all);

  h+='<div class="lens"><span class="lb">보는 관점</span>';
  D.dims.forEach(d=>{h+=`<span class="wsl"><b>${d}</b>
    <input type="range" id="w_${d}" min="0" max="3" step="0.1" value="${W[d]}" aria-label="${d} 가중치">
    <output>${W[d].toFixed(1)}</output></span>`;});
  h+=`<span class="pre"><button onclick="preset('default')">기본</button>
      <button onclick="preset('ops')">운영</button>
      <button onclick="preset('security')">보안</button></span></div>`;
  h+=`<p class="lensnote">관점을 바꿔도 조치 등급은 움직이지 않습니다. 같은 등급 안에서 무엇을 먼저 볼지만 바뀝니다.
      ${c.topo?'':'· 위 <b>경로 반영</b>을 켜면 도달성이 확정되면서 보류된 등급이 정해집니다.'}</p>`;

  h+='<div class="recs">';
  for(const r of rs){
    const i=SI[r.status], g=gi(r.status);
    let act=r.fired.length?`<span class="hi">${r.fired.join(' · ')}</span> 발화`
          :(r.bucket==='P?'?`확정되면 최소 <span class="hi">${r.floor}</span>`:'<span class="k">강제규칙 없음</span>');
    let sub=r.pending.length
      ? `<div class="sub2">${r.pending.map(p=>`${p.rule} → ${p.floor} · ${p.missing.join(', ')} 미확인`).join('<br>')}</div>`
      : (r.kev.length?`<div class="sub2">KEV 등재 ${r.kev.join(', ')}</div>`:'');
    h+=`<div class="rec k${g}${r.asset===c.asset?' on':''}" onclick="pick('${r.asset}')"
         tabindex="0" onkeydown="if(event.key==='Enter'){pick('${r.asset}')}">
      <div class="mark">${r.bucket}<small>${esc(D.bucket_short[r.bucket]||'')}</small></div>
      <div><div class="tagno">${r.asset}</div>
        <div class="verdict">${r.phrase}<code>${r.status}</code></div>
        <div class="say">${esc(i.plain)}</div></div>
      <div class="rule">${act}${sub}</div>
      <div class="wt">${score(r).toFixed(2)}</div></div>`;
  }
  h+='</div>';
  if(!rs.length) h+='<p class="empty">이 상태에 해당하는 자산이 없습니다. 위 띠에서 다른 칸을 누르거나 전체 보기로 돌아가세요.</p>';
  return h;
}

function renderCard(){
  const r=cur(); if(!r) return '<p class="empty">이 조합에 해당하는 판정이 없습니다.</p>';
  const i=SI[r.status], g=gi(r.status);
  let h=`<p class="docttl">${r.phrase}</p>
    <p class="docsub"><span class="m">${r.asset}</span> · ${r.status} · 기준 시점 ${r.as_of}</p>`;
  h+=`<div class="callout ${g===2?'ok':g===0?'hot':''}">${esc(i.plain)}
      <br><b>다음 행동</b> — ${esc(i.next)}
      <br><span class="k">조치 등급 <b class="m">${r.bucket}</b> ${esc(D.bucket_info[r.bucket]||'')}
      ${r.identity?` · 제품 식별 ${r.identity} (확신 ${r.confidence})`:''}</span></div>`;
  h+='<h3>이 결론을 만든 조건</h3><ul>'+r.conditions.map(c=>`<li>${esc(c)}</li>`).join('')+'</ul>';
  h+='<div class="cols2"><div><h3>대조 결과</h3><table>';
  for(const [k,lab] of [['matched','일치'],['mismatched','불일치'],['missing','빠진 값']])
    h+=`<tr><th style="width:74px">${lab}</th><td class="m">${(r.fields[k]||[]).map(esc).join('<br>')||'—'}</td></tr>`;
  h+='</table></div><div><h3>근거</h3><table>';
  h+=`<tr><th style="width:118px">영향 범위 원문</th><td class="m">${esc(r.raw_expression??'—')}</td></tr>`;
  h+=`<tr><th>권고 원문 해시</th><td class="m">${r.advisory_sha}…</td></tr>`;
  h+=`<tr><th>적용 CVE</th><td class="m">${r.n_cves}건${r.kev.length?` · KEV ${r.kev.join(', ')}`:''}</td></tr>`;
  h+=`<tr><th>재현 해시</th><td class="m">${r.input_hash}…</td></tr></table></div></div>`;
  if(r.question) h+=`<h3>다음에 확인할 것</h3><div class="callout">${esc(r.question)}</div>`;
  if(r.pending.length){
    h+='<h3>보류된 강제규칙</h3><table><tr><th>규칙</th><th>확정되면</th><th>막고 있는 것</th></tr>';
    for(const p of r.pending) h+=`<tr><td class="m">${p.rule}</td><td class="m">${p.floor}</td><td>${p.missing.map(esc).join(', ')}</td></tr>`;
    h+='</table>';
  }
  h+='<h3>등급을 정한 이유</h3><ul>'+r.rationale.map(x=>`<li>${esc(x)}</li>`).join('')+'</ul>';
  return h;
}

function renderPaths(){
  const c=ctl(), p=D.paths[c.asset];
  if(!p) return `<p class="docttl">이 자산은 토폴로지에 없습니다</p>
    <div class="callout">도달 불가로 단정하지 않고 <b>미상</b>으로 둡니다.
    모르는 것을 아는 것처럼 답하지 않습니다.</div>`;
  let h=`<p class="docttl">${p.label}</p><p class="docsub">어디까지 도달하는가</p>`;
  h+=`<div class="callout">${esc(D.topo_warning)}</div>`;
  h+='<h3>경로 선택 — 실선은 확인된 통신, 점선은 추론</h3>';
  h+='<select class="wide" id="pathsel" onchange="draw()">';
  p.paths.forEach((x,i)=>{h+=`<option value="${i}">[${x.status}] 확신도 ${x.confidence} · ${x.hops.length}홉 · ${x.nodes.join(' → ')}</option>`;});
  h+='</select><div id="svgbox"></div><div id="hops"></div>';
  h+='<h3>차단 후보</h3><p class="k">점수 대신 정수 두 개로 비교합니다 — 몇 개를 끊고 무엇을 희생하는지.</p>';
  h+='<table><tr><th>끊을 구간</th><th>사라지는 공격 경로</th><th>영향받는 정상 통신</th><th>남는 경로</th></tr>';
  for(const b of p.blocks) h+=`<tr><td class="m">${b.edge}</td><td class="m">${b.cut}</td><td class="m">${b.legit}</td><td class="m">${b.remaining}</td></tr>`;
  return h+'</table>';
}

function draw(){
  const p=D.paths[ctl().asset]; if(!p) return;
  const path=p.paths[+($('#pathsel')?.value||0)], box=$('#svgbox'); if(!box) return;
  box.innerHTML=D.svg;
  const on=new Set(path.edges), nodes=new Set(path.nodes);
  box.querySelectorAll('g.edge').forEach(g=>{
    const m=(g.querySelector('title')?.textContent||'').match(/^(\S+) → (\S+)/); if(!m) return;
    if([...on].some(k=>k.startsWith(m[1]+'->'+m[2]+':'))){
      const pa=g.querySelector('path');pa.setAttribute('stroke','#A31C1F');pa.setAttribute('stroke-width','3.4');}
  });
  box.querySelectorAll('g.node').forEach(g=>{
    const t=g.querySelector('title')?.textContent||'';
    if([...nodes].some(n=>D.node_labels[n]&&t.startsWith(D.node_labels[n]))){
      const r=g.querySelector('rect');r.setAttribute('stroke','#A31C1F');r.setAttribute('stroke-width','2.6');}
  });
  $('#hops').innerHTML='<h3>공격자가 무엇을 얻어 가는가</h3><table><tr><th>구간</th><th>근거</th><th>이 구간을 지나면 얻는 것</th></tr>'+
    path.hops.map(h=>`<tr><td class="m">${h.src} → ${h.dst}<div class="k">${h.label}</div></td>
      <td>${h.status==='observed'?'확인됨':h.status==='inferred'?'추론':'정보 부족'}</td>
      <td class="m">${h.caps.join(', ')}</td></tr>`).join('')+
    `</table><p class="k">가장 약한 구간 <span class="m">${path.weakest||'—'}</span> 이 경로 전체의 확신도를 결정합니다.</p>`;
}

function renderSources(){
  if(!D.sources.length) return '<p class="empty">연결된 소스 쌍이 없습니다.</p>';
  let h='';
  for(const g of D.sources){
    h+=`<p class="docttl">같은 취약점을 두 곳이 말하고 있습니다</p>
        <p class="docsub">${g.cves.join(', ')}</p>`;
    h+='<table><tr><th>권고</th><th>발행처</th><th>스스로 밝힌 역할</th><th>우리가 판단한 역할</th><th>시점</th></tr>';
    for(const r of g.provenance) h+=`<tr><td class="m">${r.advisory_id}</td><td>${esc(r.publisher)}</td>
      <td class="m">${r.declared_category}</td><td><b>${r.role}</b><div class="k">${r.role_basis}</div></td>
      <td class="m">${(r.released_at||'').slice(0,10)}</td></tr>`;
    h+='</table>';
    h+=`<div class="callout ${g.n_conflict?'hot':'ok'}">제품 <b>${g.n_products}</b>건 대조 · 값이 다른 것 <b>${g.n_conflict}</b>건.
        ${g.n_conflict?'다른 값은 지우지 않고 둘 다 보관합니다.':
        '한쪽이 다른 쪽 문서를 그대로 재발행하기 때문에 값이 같습니다. 그래도 두 주장을 모두 보관하고, 화면의 값은 필드별 권위로 계산합니다 — 덮어쓰지 않습니다.'}</div>`;
    h+='<h3>제품별 대조</h3><table><tr><th>제품</th><th>화면에 쓰는 값</th><th>채택한 곳</th><th>같은 값을 말한 곳</th></tr>';
    for(const s of g.samples) h+=`<tr><td class="m">${s.key}</td><td class="m">${s.value}</td>
      <td>${s.source} <span class="k">${s.role}</span></td><td class="k">${s.corroborated.join(', ')||'—'}</td></tr>`;
    h+='</table>';
  }
  return h;
}

function renderClaims(){
  let h=`<p class="docttl">무엇을 주장하고, 무엇을 주장하지 않는가</p>
    <p class="docsub">정답이 바깥에서 객관적으로 주어지는 것만 정확도를 주장합니다</p>`;
  h+='<table><tr><th>단계</th><th>테스트</th><th>주장 유형</th><th>개수</th></tr>';
  for(const r of D.claims) h+=`<tr><td class="m">${r.slice}</td><td class="m">${r.file}</td>
    <td>${r.kind==='정확도'?'<b style="color:var(--stamp)">정확도 주장</b>':esc(r.kind)}</td><td class="m">${r.n}</td></tr>`;
  h+='</table>';
  h+=`<div class="callout ok">정확도를 주장하는 둘 — <b>적용성 판정</b>(정답이 권고문에서 나옴)과
      <b>적대적 입력 거부</b>("거부되어야 한다"는 논쟁 여지가 없음).</div>`;
  h+=`<div class="callout">우선순위와 경로 탐지의 <b>정확도는 주장하지 않습니다</b>.
      현장 전문가 합의 골드셋이 없고, 토폴로지가 100% 합성이기 때문입니다.
      검증은 규칙이 조건대로 발화하는지, 불변량이 지켜지는지, 시나리오가 재현되는지까지입니다.</div>`;
  return h;
}

function pick(a){$('#asset').value=a;render();}
function filt(k){FILTER=(k===FILTER)?null:k;render();}
function filtG(i){
  const g=D.groups[i][0], ks=Object.keys(SI).filter(k=>SI[k].group===g);
  const now=recs().filter(r=>ks.includes(r.status));
  FILTER=(FILTER&&ks.includes(FILTER))?null:(now[0]?now[0].status:null);
  render();
}
function setTab(t){TAB=t;render();}
function render(){
  $$('.tab').forEach(b=>b.classList.toggle('on',b.dataset.t===TAB));
  $('#sheet').innerHTML={rec:renderRecs,card:renderCard,paths:renderPaths,
                         sources:renderSources,claims:renderClaims}[TAB]();
  if(TAB==='paths')draw();
  if(TAB==='rec')D.dims.forEach(d=>{
    const el=$('#w_'+CSS.escape(d)); if(!el) return;
    el.addEventListener('input',e=>{W[d]=+e.target.value;render();});
  });
  const c=ctl();
  $('#stamp').innerHTML=`규칙 ${D.rule_version} · 정책 ${D.policy_version}<br>KEV ${D.kev||'미로드'} · 경로 ${c.topo?'반영':'미반영'}`;
}
function preset(n){W=Object.assign({},D.lens_presets[n]);render();}
window.addEventListener('DOMContentLoaded',()=>{
  ['asset','adv','asof','topo'].forEach(id=>$('#'+id).addEventListener('change',render));
  render();
});
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--open", action="store_true", dest="do_open")
    args = ap.parse_args()

    assets = [load_asset(p) for p in sorted(ASSETS.glob("*.json"))]
    advisories = [load_advisory(p) for p in sorted(CSAF.rglob("*.json"))]
    topo = load_topology(TOPO)
    snap = find_snapshot(ROOT / "data" / "kev")
    kev = load_kev(snap) if snap else None

    claims = []
    vm = ROOT / "docs" / "VERIFICATION.md"
    if vm.exists():
        for line in vm.read_text(encoding="utf-8").splitlines():
            if line.startswith("| ") and "`tests/" in line:
                c = [x.strip() for x in line.strip("|").split("|")]
                claims.append({"slice": c[0], "file": c[1].strip("`"),
                               "kind": c[2].replace("*", ""), "n": c[3]})

    records = build_records(assets, advisories, topo, kev)
    data = {
        "records": records,
        "paths": build_paths(topo),
        "sources": build_sources(advisories),
        "claims": claims,
        "dims": list(LENS_DIMENSIONS),
        "lens_presets": LENS_PRESETS,
        "bucket_order": BUCKET_ORDER,
        "bucket_phrases": BUCKET_PHRASES,
        "svg": render_svg(topo),
        "node_labels": {n.node_id: n.label for n in topo.nodes.values()},
        "topo_warning": topo.provenance.get("warning", ""),
        "kev": kev.catalog_version if kev else None,
        "state_info": STATE_INFO,
        "groups": GROUPS,
        "bucket_info": BUCKET_INFO,
        "bucket_short": BUCKET_SHORT,
        "rule_version": records[0]["rule_version"] if records else "-",
        "policy_version": records[0]["policy"] if records else "-",
        "phrases": PHRASES,
    }

    asset_ids = sorted({r["asset"] for r in data["records"]})
    adv_ids = sorted({r["advisory"] for r in data["records"]})

    opts = lambda xs, sel=None: "".join(
        '<option%s>%s</option>' % (" selected" if x == sel else "", esc(x)) for x in xs)


    doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>판정 기록 — OT 자산 취약점</title><style>{CSS}</style></head><body>

<div class="tb"><div class="tb-in">
  <div class="brand"><b>판정 기록</b><span>OT 자산 취약점</span></div>
  <div class="fld"><label for="asset">자산</label><select id="asset">{opts(asset_ids)}</select></div>
  <div class="fld"><label for="adv">권고문</label><select id="adv">{opts(adv_ids)}</select></div>
  <div class="fld"><label for="asof">기준 시점</label>
    <select id="asof">{opts(AS_OF_CHOICES, AS_OF_CHOICES[-1])}</select></div>
  <label class="chk" for="topo"><input type="checkbox" id="topo"><span>경로 반영</span></label>
  <div class="stampinfo" id="stamp"></div>
</div></div>

<div class="nav"><div class="nav-in">
  <button class="tab" data-t="rec" onclick="setTab('rec')">판정</button>
  <button class="tab" data-t="card" onclick="setTab('card')">근거</button>
  <button class="tab" data-t="paths" onclick="setTab('paths')">경로</button>
  <button class="tab" data-t="sources" onclick="setTab('sources')">출처</button>
  <button class="tab" data-t="claims" onclick="setTab('claims')">검증</button>
</div></div>

<main class="sheet" id="sheet"></main>

<script>const DATA={json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))};</script>
<script>{JS}</script>
</body></html>
"""

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "index.html"
    path.write_text(doc, encoding="utf-8")
    size = len(doc.encode("utf-8"))
    print("생성: %s  (%.1f KB · 조합 %d개 · 경로 %d자산)"
          % (path, size / 1024, len(data["records"]), len(data["paths"])))
    print("브라우저로 여세요. 서버가 필요 없고 외부 자원도 받지 않습니다.")
    if args.do_open:
        import webbrowser
        webbrowser.open(path.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
