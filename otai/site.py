# -*- coding: utf-8 -*-
"""사이트 프로파일 — 자산대장의 `구역` 을 그래프로 (ADR-050).

**문제**: 엑셀로 설비 800대를 넣어도 토폴로지에는 노드가 하나도 안 생긴다.
`capture.py` 는 캡처가 있어야 노드를 만들고, 자산대장의 `location.zone` 은
목록 패싯일 뿐 그래프가 아니었다. 그래서 `_reaches_critical` 이 **"이 자산이
토폴로지에 없습니다"** 로 UNKNOWN 을 내고 H01~H03 이 막혀 **첫 화면이 `P?` 로
찬다.** 엔진은 옳게 동작하는데 현업자는 "아무것도 못 말하네" 로 읽는다.

**이 모듈이 하는 일**: 현업자가 아는 것을 받아 자산을 그래프 안에 **존재하게**
만든다. 아는 것은 둘이다 —

| | 현업자가 아는가 | 우리가 받는 것 |
|---|---|---|
| 구역 이름 | 예 (대장에 적혀 있다) | 자산대장의 `location.zone` |
| 구역의 Purdue 레벨·안전 중요도 | 예 | `zones[]` 선언 |
| 구역 **사이**의 연결 | 안다/모른다가 섞인다 | `conduits[]` 선언, 상태를 함께 |
| 그 연결로 무슨 능력을 얻는가 | 대개 모른다 | 비워 둔다 — **지어내지 않는다** |

**기본값은 아무것도 확정하지 않는다.** 만들어지는 엣지는 `inferred`·`unknown`
이므로 골격만으로는 도달성이 TRUE 가 되지 않는다 (ADR-014). 골격의 값은 '확정'
이 아니라 **'무엇을 확인하면 확정되는지 이름을 대는 것'** 이다 — `P?` 의 이유가
"자산이 그래프에 없다" 에서 **"이 세 구간이 미확인이다"** 로 바뀌고, 막는 엣지를
이름으로 지목한다.

**확정까지 가려면 사람이 둘 다 선언해야 한다.** 구역 **사이**는
`conduits[].status = "observed"`, 구역 **안쪽**은
`zones[].internal_reachability = "flat_observed"`. 하나만 하면 미상으로 남는다 —
처음에는 안쪽 선언을 만들지 않아서 **모든 연결을 확인해도 영원히 미상인 막다른
길**이었고, 실측에서 그것을 잡았다.

안전 중요가 **아닌** 구역의 자산은 H02 가 `FALSE` 로 확정되어 `P?` 를 떠난다
(`priority._reaches_critical`). 다만 실측에서 보면 **골격만으로 `P?` 건수가 줄지는
않는다** — 줄어드는 것은 '왜 막혔는지 모른다' 쪽이다. 과장하지 말 것.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .safeio import UnsafeInput, bounded_json_load
from .topology import INFERRED, OBSERVED, UNKNOWN

#: 구역 노드 이름의 접두. 자산 id 와 섞이지 않게 둔다.
ZONE_PREFIX = "zone:"

MAX_ZONES = 500
MAX_CONDUITS = 2000

#: 구역 사이 연결의 상태. `observed` 는 **사람이 명시적으로 적을 때만** 쓴다 —
#: "방화벽 규칙을 눈으로 확인했다" 같은 근거가 있어야 한다.
CONDUIT_STATUS = (UNKNOWN, INFERRED, OBSERVED)


#: 구역 **안쪽**이 서로 닿는지. 기본은 '모른다'.
#:
#: 이게 없으면 골격이 **막다른 길**이 된다 — 구역 간 연결을 전부 `observed` 로
#: 올려도 `구역 → 자산` 엣지가 `inferred` 라서 도달성이 영원히 미상이다. 실제로
#: 그렇게 만들었다가 실측에서 잡았다 (ADR-050).
#:
#: `flat_observed` 는 **사람이 확인했다는 선언**이다: "이 구역은 관리 안 되는
#: 스위치 한 대로 평평하고, 안쪽끼리는 서로 닿는 것을 확인했다." 현장에서 흔한
#: 사실이고, 그걸 적을 수 있어야 골격이 확정까지 간다.
INTERNAL_UNKNOWN = "unknown"
INTERNAL_FLAT_OBSERVED = "flat_observed"
INTERNAL_REACHABILITY = (INTERNAL_UNKNOWN, INTERNAL_FLAT_OBSERVED)


@dataclass(frozen=True)
class Zone:
    name: str
    purdue_level: Optional[float] = None
    is_critical: bool = False
    is_entry_point: bool = False
    factory: Optional[str] = None
    note: Optional[str] = None
    #: 구역 안쪽 도달성. `flat_observed` 면 `구역 → 자산` 엣지가 관측이 된다.
    internal_reachability: str = INTERNAL_UNKNOWN

    @property
    def node_id(self) -> str:
        return ZONE_PREFIX + self.name


@dataclass(frozen=True)
class Conduit:
    src: str                      # 구역 이름
    dst: str
    status: str = UNKNOWN
    protocol: Optional[str] = None
    port: Optional[int] = None
    grants: Tuple[str, ...] = ()
    legitimate: bool = False
    note: Optional[str] = None


@dataclass(frozen=True)
class Site:
    name: str
    zones: Tuple[Zone, ...]
    conduits: Tuple[Conduit, ...]
    sha256: str
    source: str
    note: Optional[str] = None
    #: 연결 목록이 **완전한가.** 기본은 아니다 — 사람은 아는 것만 적는다.
    #:
    #: 이게 없으면 도구가 '닿지 않는다'(FALSE)고 말한다. 구역 간 연결을 모르는
    #: 채 골격을 만든 사람에게는 거짓이고, 서식에 "비워 두면 격리된 것처럼
    #: 보이지만 격리됐다는 뜻이 아닙니다" 라고 적어 둔 바로 그 오독이다.
    #: `true` 로 두는 것은 **"연결을 전부 열거했다"는 사람의 책임 선언**이다.
    conduits_complete: bool = False

    def zone(self, name: str) -> Optional[Zone]:
        for z in self.zones:
            if z.name == name:
                return z
        return None


def load_site(path) -> Site:
    """사이트 프로파일을 읽는다. 외부 파일이므로 `safeio` 를 거친다 (ADR-041)."""
    p = Path(path)
    doc = bounded_json_load(p)
    raw_zones = doc.get("zones") or []
    raw_conduits = doc.get("conduits") or []
    if not isinstance(raw_zones, list) or not isinstance(raw_conduits, list):
        raise UnsafeInput("zones 와 conduits 는 목록이어야 합니다", p.name)
    if len(raw_zones) > MAX_ZONES:
        raise UnsafeInput("구역 %d개 > 상한 %d" % (len(raw_zones), MAX_ZONES), p.name)
    if len(raw_conduits) > MAX_CONDUITS:
        raise UnsafeInput("연결 %d개 > 상한 %d" % (len(raw_conduits), MAX_CONDUITS),
                          p.name)

    zones = []
    seen = set()
    for i, z in enumerate(raw_zones, 1):
        if not isinstance(z, dict) or not (z.get("name") or "").strip():
            raise UnsafeInput("%d번째 구역에 name 이 없습니다" % i, p.name)
        name = z["name"].strip()
        if name in seen:
            raise UnsafeInput("구역 이름이 겹칩니다: %s" % name, p.name)
        seen.add(name)
        lvl = z.get("purdue_level")
        internal = (z.get("internal_reachability") or INTERNAL_UNKNOWN).strip()
        if internal not in INTERNAL_REACHABILITY:
            raise UnsafeInput(
                "internal_reachability 는 %s 중 하나여야 합니다 (받은 것: %s)"
                % (" · ".join(INTERNAL_REACHABILITY), internal), p.name)
        zones.append(Zone(
            name=name,
            purdue_level=None if lvl is None else float(lvl),
            is_critical=bool(z.get("is_critical")),
            is_entry_point=bool(z.get("is_entry_point")),
            factory=z.get("factory"), note=z.get("note"),
            internal_reachability=internal))

    conduits = []
    for i, c in enumerate(raw_conduits, 1):
        if not isinstance(c, dict):
            raise UnsafeInput("%d번째 연결이 객체가 아닙니다" % i, p.name)
        src, dst = (c.get("from") or "").strip(), (c.get("to") or "").strip()
        if not src or not dst:
            raise UnsafeInput("%d번째 연결에 from·to 가 없습니다" % i, p.name)
        for side in (src, dst):
            if side not in seen:
                raise UnsafeInput(
                    "연결이 선언되지 않은 구역을 가리킵니다: %s (선언된 구역: %s)"
                    % (side, ", ".join(sorted(seen))), p.name)
        status = (c.get("status") or UNKNOWN).strip()
        if status not in CONDUIT_STATUS:
            raise UnsafeInput(
                "연결 상태는 %s 중 하나여야 합니다 (받은 것: %s)"
                % (" · ".join(CONDUIT_STATUS), status), p.name)
        port = c.get("port")
        conduits.append(Conduit(
            src=src, dst=dst, status=status, protocol=c.get("protocol"),
            port=None if port is None else int(port),
            grants=tuple(c.get("grants") or ()),
            legitimate=bool(c.get("legitimate")), note=c.get("note")))

    meta = doc.get("site") or {}
    return Site(name=meta.get("name") or p.stem, zones=tuple(zones),
                conduits=tuple(conduits),
                sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                source=p.name, note=meta.get("note"),
                conduits_complete=bool(meta.get("conduits_complete")))


@dataclass
class BuildResult:
    zones_used: List[str] = field(default_factory=list)
    #: 대장에 구역이 적혀 있는데 프로파일에 **선언되지 않은** 구역
    undeclared_zones: Dict[str, int] = field(default_factory=dict)
    #: 구역이 비어 있는 자산 — 그래프에 넣지 않는다
    without_zone: List[str] = field(default_factory=list)
    assets_placed: int = 0
    levels_missing: List[str] = field(default_factory=list)


def _zone_of(body: dict) -> str:
    return str(((body.get("location") or {}).get("zone") or "")).strip()


def from_assets(bodies: Sequence[dict], site: Site) -> Tuple[dict, BuildResult]:
    """자산대장 + 사이트 프로파일 → 토폴로지 골격.

    노드는 **구역 노드 + 자산 노드**다. 자산마다 구역과 직접 엣지를 그으면
    800대 × 50대 짜리 폭발이 나므로, 구역을 노드로 두고 자산을 그 아래 단다.
    경로는 `진입 구역 → … → 대상 구역 → 자산` 이라 홉 수가 작게 유지된다.
    """
    res = BuildResult()
    nodes: List[dict] = []
    edges: List[dict] = []

    by_zone: Dict[str, List[dict]] = {}
    for body in bodies:
        name = _zone_of(body)
        aid = str(body.get("asset_id") or "")
        if not name:
            res.without_zone.append(aid)
            continue
        z = site.zone(name)
        if z is None:
            res.undeclared_zones[name] = res.undeclared_zones.get(name, 0) + 1
            continue
        by_zone.setdefault(name, []).append(body)

    for z in site.zones:
        members = by_zone.get(z.name) or []
        if not members:
            continue           # 자산이 없는 구역은 노드로 만들지 않는다
        res.zones_used.append(z.name)
        if z.purdue_level is None:
            res.levels_missing.append(z.name)
        nodes.append({
            "node_id": z.node_id, "label": z.name, "node_type": "zone",
            "zone": z.name, "purdue_level": z.purdue_level,
            # `Node.is_critical` 은 `safety_criticality == "high"` 에서 파생된다
            # (topology.py). `is_critical` 키를 쓰면 로더가 읽지 않아 **조용히
            # 전부 비중요**가 되고, H02 가 발화하지 않는다.
            "safety_criticality": "high" if z.is_critical else "low",
            "is_entry_point": z.is_entry_point,
            "evidence": {"source": "site_profile", "declared_by": "site_profile",
                         "site_sha256": site.sha256, "assets": len(members),
                         "note": z.note or ""},
        })
        for body in members:
            aid = str(body.get("asset_id") or "")
            ident = body.get("identity") or {}
            nodes.append({
                "node_id": aid, "asset_id": aid,
                "label": str(body.get("label") or aid),
                "node_type": str(body.get("asset_type") or "") or "asset",
                "zone": z.name, "purdue_level": z.purdue_level,
                # 안전 중요도는 **자산이 말한 것이 우선**이고, 없으면 구역을 따른다
                "safety_criticality": "high" if _critical(body, z) else "low",
                "evidence": {"source": "asset_register",
                             "declared_by": "site_profile",
                             "site_sha256": site.sha256,
                             "vendor": ident.get("vendor_raw") or "",
                             "note": "자산대장이 이 설비를 '%s' 구역으로 "
                                     "선언했습니다" % z.name},
            })
            # 구역 안에 있으면 닿는가. 기본은 **추론**이다 — 같은 구역이라고
            # 서로 닿는 것은 아니다(내부 분할·호스트 방화벽이 있을 수 있다).
            # 사람이 `flat_observed` 로 확인했다고 적으면 관측이 된다 (ADR-050).
            flat = z.internal_reachability == INTERNAL_FLAT_OBSERVED
            edges.append({
                "src": z.node_id, "dst": aid, "edge_type": "can_reach",
                "status": OBSERVED if flat else INFERRED, "legitimate": True,
                "evidence": {
                    "source": "site_profile", "declared_by": "site_profile",
                    "confidence": 1.0 if flat else 0.5,
                    "note": ("이 구역은 평평하고 안쪽끼리 닿는 것을 **사람이 "
                             "확인했다**고 선언했습니다 "
                             "(internal_reachability=flat_observed)") if flat else
                            ("같은 구역 안이라 닿는다고 **가정**한 것입니다 — "
                             "관측이 아닙니다. 확인했다면 구역에 "
                             "internal_reachability=flat_observed 를 적어 주세요"),
                },
            })
            res.assets_placed += 1

    live = set(res.zones_used)
    for c in site.conduits:
        if c.src not in live or c.dst not in live:
            continue           # 양쪽에 자산이 있어야 의미가 있다
        edges.append({
            "src": ZONE_PREFIX + c.src, "dst": ZONE_PREFIX + c.dst,
            "edge_type": "can_reach", "status": c.status,
            "protocol": c.protocol, "port": c.port,
            # **능력을 지어내지 않는다.** 사람이 적은 것만 싣는다 (R06).
            "grants": list(c.grants),
            "legitimate": c.legitimate,
            "evidence": {"source": "site_profile", "declared_by": "site_profile",
                         "site_sha256": site.sha256, "confidence": 0.5,
                         "note": c.note or "사이트 프로파일이 선언한 구역 간 연결"},
        })

    doc = {
        "nodes": nodes, "edges": edges,
        "provenance": {
            "source": "site_profile",
            "synthetic": False,
            "site": site.name, "site_source": site.source,
            "site_sha256": site.sha256,
            "zones": len(res.zones_used), "assets": res.assets_placed,
            # **엣지 부재를 '없음' 으로 읽지 못하게 한다** (ADR-050).
            # 사람이 "연결을 전부 열거했다" 고 선언할 때만 끈다.
            "edges_may_be_incomplete": not site.conduits_complete,
            "incomplete_reason":
                None if site.conduits_complete else
                "사이트 프로파일은 **아는 연결만** 적은 것입니다 (conduits_complete "
                "가 선언되지 않았습니다)",
            "conduits_complete": site.conduits_complete,
            "note": "자산대장의 구역 선언으로 만든 **골격**입니다. 기본 엣지는 "
                    "`inferred`·`unknown` 이고 관측이 아니므로 그대로는 도달성이 "
                    "확정되지 않습니다 (ADR-014/050). 확정까지 가려면 **둘 다** "
                    "사람이 확인해 선언해야 합니다 — 구역 간 연결에 "
                    "status=observed, 평평한 구역에 "
                    "internal_reachability=flat_observed.",
            "what_is_declared": "구역·Purdue 레벨·안전 중요도·구역 간 연결은 사람이 "
                                "선언한 값입니다. 자산의 소속 구역은 자산대장이 "
                                "말한 것입니다. **관측된 통신은 하나도 없습니다.**",
        },
    }
    return doc, res


def _critical(body: dict, z: Zone) -> bool:
    """안전 중요도 — 자산이 말한 것이 구역보다 세다.

    대장에 `operations.safety_criticality` 가 있으면 그것을 쓴다. 구역 기본값으로
    덮으면 "이 설비만 안전 핵심" 이라고 적은 사람의 말이 사라진다.
    """
    sc = str(((body.get("operations") or {}).get("safety_criticality") or "")).lower()
    if sc in ("high", "상", "높음"):
        return True
    if sc in ("low", "none", "하", "낮음", "없음"):
        return False
    return z.is_critical


def template(bodies: Sequence[dict]) -> dict:
    """대장에 보이는 구역으로 **빈 프로파일 서식**을 만든다.

    레벨을 추측해서 채워 주지 않는다 — 추측이 사실로 굳는다 (ADR-047 과 같은 규칙).
    연결(`conduits`)은 비워 둔다. 무엇이 무엇에 닿는지는 우리가 알 길이 없다.
    """
    counts: Dict[str, int] = {}
    factories: Dict[str, str] = {}
    for body in bodies:
        name = _zone_of(body)
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        f = str(((body.get("location") or {}).get("factory") or "")).strip()
        if f:
            factories.setdefault(name, f)
    zones = [{"name": n, "factory": factories.get(n, ""), "purdue_level": None,
              "is_critical": False, "is_entry_point": False,
              "internal_reachability": "unknown",
              "note": "설비 %d대가 이 구역에 있습니다 — Purdue 레벨과 안전 "
                      "중요도를 적어 주세요" % c}
             for n, c in sorted(counts.items(), key=lambda kv: -kv[1])]
    return {
        "_설명": [
            "사이트 프로파일 서식입니다. 자산대장의 '구역' 열에서 뽑았습니다.",
            "Purdue: 0 물리공정 · 1 기본제어 · 2 감시제어 · 3 운영 · 4 기업망 · 5 외부",
            "밖에서 들어오는 구역에 is_entry_point: true 를 주세요. 하나도 없으면",
            "도달성이 미상으로 남습니다 — '닿지 않는다' 가 아닙니다 (ADR-045).",
            "안전 중요가 **아닌** 구역은 is_critical 을 false 로 두세요 — 그 구역의",
            "설비는 H02 가 '해당 없음' 으로 확정되어 '확인 필요(P?)' 를 떠납니다.",
            "conduits 는 구역 사이 연결입니다. 비워 두면 구역이 서로 격리된 것처럼",
            "보이지만 **격리됐다는 뜻이 아닙니다** — 아는 것만 적고, 눈으로 확인한",
            "구간만 status: observed 로 올리세요. 기본은 unknown 입니다.",
            "구역 안쪽이 평평해서 서로 닿는 것을 확인했다면 그 구역에",
            "internal_reachability: flat_observed 를 적어 주세요. 그것까지 "
            "선언해야",
            "도달성이 확정까지 갑니다 — 둘 중 하나라도 미상이면 미상으로 남습니다.",
            "conduits 를 **전부** 열거했다면 site.conduits_complete 를 true 로 두세요.",
            "그때까지는 경로를 못 찾아도 '닿지 않는다' 가 아니라 '미상' 입니다 —",
            "아는 것만 적었을 수 있기 때문입니다.",
        ],
        "site": {"name": "", "note": "", "conduits_complete": False},
        "zones": zones,
        "conduits": [
            {"from": "", "to": "", "status": "unknown", "protocol": "", "port": None,
             "legitimate": True,
             "note": "예: 사무망 → 가공라인. 아는 연결만 적으세요"}
        ] if len(zones) > 1 else [],
    }
