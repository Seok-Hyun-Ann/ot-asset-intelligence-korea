# -*- coding: utf-8 -*-
"""권고문·KEV·ATT&CK 을 내려받는다.

    python scripts/fetch_advisories.py            # 골드셋용 최소 세트
    python scripts/fetch_advisories.py --bulk     # + CISA OT CSAF 약 1,300건

CISA (공공 도메인)   → data/csaf/cisa/<연도>/
Siemens (TLP:WHITE)  → data/csaf/siemens/

라이선스 주의 (ADR-005 / R12): CISA CSAF 는 공공 도메인이라 저장소에 함께 둔다.
Siemens TLP:WHITE 는 *공유*를 허용하는 표시이지 재배포 허가가 아니므로 커밋하지
않고 이 스크립트로 각자 받는다. 슬라이스 4(서명 번들 배포) 전에 확정할 사항이다.
"""
from __future__ import annotations

import hashlib
import io as _io
import sys
import urllib.request
from pathlib import Path

# 윈도우 기본 콘솔(cp949)에서 한국어와 em-dash 가 깨지지 않도록 고정
if hasattr(sys.stdout, "buffer"):
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from otai.safeio import bounded_json_loads          # noqa: E402

SOURCES = [
    (
        "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-036-02.json",
        ROOT / "data" / "csaf" / "cisa" / "2026" / "icsa-26-036-02.json",
        "CISA / Mitsubishi Electric MELSEC iQ-R — 자유 문자열 범위 '<=48'",
    ),
    (
        "https://cert-portal.siemens.com/productcert/csaf/ssa-019113.json",
        ROOT / "data" / "csaf" / "siemens" / "ssa-019113.json",
        "Siemens / SIMATIC S7-1500 — vers: URI 범위 + model_numbers",
    ),
]


def fetch(url: str, dest: Path, note: str) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            body = r.read()
    except Exception as exc:
        print("  실패 %s\n    %s" % (dest.name, exc))
        return False
    dest.write_bytes(body)
    print("  %s  %d bytes  sha256=%s" % (dest.name, len(body), hashlib.sha256(body).hexdigest()[:16]))
    print("    %s" % note)
    return True


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> bool:
    """KEV 는 catalogVersion 별 스냅샷 디렉터리에 넣는다.

    매일 바뀌므로 오늘의 KEV 로 과거 판정을 재현하면 안 된다 (ADR-009).
    카탈로그 버전과 sha256 이 우선순위 판정의 input_hash 에 들어간다.
    """
    import json
    try:
        with urllib.request.urlopen(KEV_URL, timeout=120) as r:
            body = r.read()
    except Exception as exc:
        print("  실패 KEV")
        print("    %s" % exc)
        return False
    # 인터넷에서 바로 온 바이트다 — 파일로 쓰기 전에 한계를 본다 (ADR-041).
    doc = bounded_json_loads(body, name="KEV")
    ver = doc.get("catalogVersion", "unknown")
    dest = ROOT / "data" / "kev" / ver / "known_exploited_vulnerabilities.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    print("  KEV %s  %d건  sha256=%s"
          % (ver, len(doc.get("vulnerabilities", [])), hashlib.sha256(body).hexdigest()[:16]))
    print("    스냅샷 data/kev/%s/ — 버전별로 쌓이며 덮어쓰지 않는다" % ver)
    return True


ATTACK_VERSION = "19.2"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/ics-attack/ics-attack-%s.json" % ATTACK_VERSION)


def fetch_attack() -> bool:
    """ATT&CK ICS STIX 를 **버전 고정**해 받는다 (표 14).

    릴리스마다 기법이 revoke·재편되므로 최신을 자동 추종하면 매핑이 조용히 깨진다 —
    실제로 v19 에서 T0855 가 revoked 되고 T1692.001 로 대체되었다.
    """
    dest = ROOT / "data" / "attack" / ("ics-attack-%s.json" % ATTACK_VERSION)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(ATTACK_URL, timeout=180) as r:
            body = r.read()
    except Exception as exc:
        print("  실패 ATT&CK")
        print("    %s" % exc)
        return False
    dest.write_bytes(body)
    print("  ATT&CK ICS v%s  %d bytes  sha256=%s"
          % (ATTACK_VERSION, len(body), hashlib.sha256(body).hexdigest()[:16]))
    print("    버전 고정 — 자동 최신 추종 금지 (표 14)")
    return True


# --------------------------------------------------------------------------
# 대량 수집 (ADR-030)
# --------------------------------------------------------------------------
# 파일 하나씩 HTTP 로 받으면 1,300건에 수십 분 걸리고 rate limit 에 걸린다.
# blob 을 미루는 sparse 얕은 클론이면 14MB 로 끝난다.
BULK_REPO = "https://github.com/cisagov/CSAF.git"
BULK_REF = "develop"          # fetch() 의 raw URL 과 같은 ref 여야 한다
BULK_PATH = "csaf_files/OT/white"
BULK_YEARS = ("2024", "2025", "2026")


def fetch_bulk(years=BULK_YEARS) -> bool:
    """CISA OT CSAF 를 연도 단위로 받아 data/csaf/cisa/<연도>/ 에 넣는다.

    **이미 있는 파일은 덮어쓰지 않는다.** 받아둔 파일은 고정된 스냅샷이고,
    판정은 그 내용 해시와 함께 재현되어야 한다 (불변 규칙 4·5). 상류가 같은
    권고문을 재포맷해도 우리 기준선은 움직이지 않는다.
    """
    import shutil
    import subprocess

    work = ROOT / ".toolchain" / "csaf-repo"
    if not (work / ".git").exists():
        work.parent.mkdir(parents=True, exist_ok=True)
        print("  얕은 sparse 클론 (%s)" % BULK_REPO)
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
             "--branch", BULK_REF, BULK_REPO, str(work)],
            capture_output=True, text=True)
        if rc.returncode:
            print("  실패: %s" % (rc.stderr or rc.stdout)[-300:])
            print("    git 이 없으면 이 단계는 건너뛰어도 됩니다 — 기본 권고문 2건으로도 돕니다.")
            return False
        subprocess.run(["git", "-C", str(work), "sparse-checkout", "set", BULK_PATH],
                       capture_output=True, text=True)
    else:
        subprocess.run(["git", "-C", str(work), "fetch", "--depth", "1", "origin", BULK_REF],
                       capture_output=True, text=True)
        subprocess.run(["git", "-C", str(work), "checkout", "-q", "FETCH_HEAD"],
                       capture_output=True, text=True)

    src = work / BULK_PATH
    dst = ROOT / "data" / "csaf" / "cisa"
    added = kept = 0
    for year in years:
        d = src / year
        if not d.is_dir():
            print("  %s 없음 — 건너뜁니다" % year)
            continue
        for f in sorted(d.glob("*.json")):
            out = dst / year / f.name
            out.parent.mkdir(parents=True, exist_ok=True)
            if out.exists():
                kept += 1          # 고정 스냅샷은 그대로 둔다
                continue
            shutil.copy2(f, out)
            added += 1
    total = len(list(dst.rglob("*.json")))
    size = sum(x.stat().st_size for x in dst.rglob("*.json")) / 1e6
    print("  추가 %d건 · 기존 유지 %d건 → 총 %d건 (%.0f MB)"
          % (added, kept, total, size))
    print("    CISA CSAF 는 공공 도메인이라 저장소에 함께 둘 수 있습니다 (ADR-005).")
    return True


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bulk", action="store_true",
                    help="CISA OT CSAF 를 연도 단위로 대량 수집한다 (약 1,300건 · 40MB)")
    ap.add_argument("--years", nargs="+", default=list(BULK_YEARS),
                    help="--bulk 로 받을 연도 (기본 2024 2025 2026)")
    a = ap.parse_args()

    print("권고문 수집 (원문 그대로 저장, 해시는 판정의 근거가 된다)")
    results = [fetch(*s) for s in SOURCES]
    if a.bulk:
        results.append(fetch_bulk(a.years))
    results.append(fetch_kev())
    results.append(fetch_attack())
    if not all(results):
        print("\n일부 수집에 실패했습니다. 오프라인이면 기존 파일이 그대로 쓰입니다.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
