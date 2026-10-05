# -*- coding: utf-8 -*-
"""공개 ICS 캡처를 받아온다 (ADR-048).

    python scripts/fetch_pcap.py

**왜 필요한가.** 이 프로젝트는 토폴로지가 100% 합성이라는 이유로 경로 탐지
정확도를 주장하지 않았다 (ADR-013). 공개된 **실제 ICS 트래픽**을 넣으면 그 한계의
일부가 사라진다 — 엣지가 관측에서 나온다.

**받는 것**: 4SICS 2015 GeekLounge 캡처. 스웨덴 ICS 보안 컨퍼런스(현 CS3Sthlm)가
전시용으로 꾸린 랩에서 뜬 트래픽이다. Siemens S7-1200 · DirectLogic 205 ·
Beckhoff CX1010 · RUGGEDCOM · Moxa · Allen-Bradley · Advantech 같은 **실제 장비**가
S7(102) · Modbus/TCP(502) · DNP3(20000) 로 오간다.

**저장소에 커밋하지 않는다.** 25~200MB 이고 우리 저작물이 아니다 — Siemens
권고문과 같은 취급이다 (`.gitignore`). 대신 이 스크립트로 언제든 다시 받는다.

**출처 표기.** Netresec 는 재배포·교육 사용 시 CS3Sthlm 을 밝히고 원 페이지를
링크해 달라고 적어 두었다. 파생물(토폴로지 픽스처)의 provenance 에 그 사실을 담고,
README 의 데이터 출처 표에도 싣는다.

**이것은 공장이 아니다.** 컨퍼런스 시연 랩이고, 게스트 WiFi 트래픽이 섞여 있다.
'실제 장비의 실제 트래픽' 이라는 것까지만 주장한다.
"""
from __future__ import annotations

import hashlib
import io as _io
import sys
import urllib.request
from pathlib import Path

if hasattr(sys.stdout, "buffer"):
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "pcap"

PAGE = "https://www.netresec.com/?page=PCAP4SICS"
CREDIT = ("4SICS/CS3Sthlm ICS lab capture — Netresec 가 공개. 재배포·교육 사용 시 "
          "CS3Sthlm 을 밝혀 달라는 요청이 있다. " + PAGE)

#: (파일명, URL, 설명). 해시는 받은 뒤 찍어 준다 — 우리가 만든 값이 아니므로
#: 미리 박아 두면 상대가 파일을 갱신했을 때 거짓으로 실패한다.
SOURCES = [
    ("4SICS-GeekLounge-151020.pcap",
     "https://share.netresec.com/s/xYj2qCNbsLEAd6M/download/4SICS-GeekLounge-151020.pcap",
     "1일차 25MB — 장비 10대, S7comm 이 또렷하다. 먼저 이것부터 써 보세요"),
    ("4SICS-GeekLounge-151021.pcap",
     "https://share.netresec.com/s/camL59aoxbCRyyZ/download/4SICS-GeekLounge-151021.pcap",
     "2일차 134MB"),
    ("4SICS-GeekLounge-151022.pcap",
     "https://share.netresec.com/s/gw6Y2QzJHqDD5pr/download/4SICS-GeekLounge-151022.pcap",
     "3일차 200MB — 가장 활동이 많다"),
]


def fetch(name: str, url: str, note: str, *, only_first: bool) -> bool:
    dest = DEST / name
    if dest.exists():
        raw = dest.read_bytes()
        print("  이미 있음 %s  %.1fMB  sha256=%s"
              % (name, len(raw) / 1048576, hashlib.sha256(raw).hexdigest()[:16]))
        return True
    if only_first and name != SOURCES[0][0]:
        print("  건너뜀   %s  (%s) — `--all` 로 전부 받습니다" % (name, note))
        return True
    print("  받는 중   %s  (%s)" % (name, note))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "otai/fetch_pcap"})
        with urllib.request.urlopen(req, timeout=300) as r:
            raw = r.read()
    except Exception as exc:
        print("    실패: %s" % exc)
        print("    브라우저로 받아 %s 에 두셔도 됩니다: %s" % (DEST, PAGE))
        return False
    DEST.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    print("    %.1fMB  sha256=%s" % (len(raw) / 1048576,
                                     hashlib.sha256(raw).hexdigest()))
    return True


def main() -> int:
    only_first = "--all" not in sys.argv
    print("공개 ICS 캡처 — 4SICS 2015 GeekLounge")
    print("  " + CREDIT)
    print()
    ok = all(fetch(n, u, d, only_first=only_first) for n, u, d in SOURCES)
    print()
    print("다음 단계 — 캡처에서 토폴로지를 만듭니다 (장비에 접속하지 않습니다)")
    print("  python -m otai capture --file data/pcap/%s \\" % SOURCES[0][0])
    print("    --zones fixtures/topology/4sics-zones.json \\")
    print("    --as-of 2026-10-05 --out out/4sics.json")
    print()
    print("  `--zones` 없이 돌리면 Purdue 레벨이 미상으로 남고 도달성이 확정되지")
    print("  않습니다. `--zones-template z.json` 으로 서식을 받아 채우셔도 됩니다.")
    print()
    print("  **캡처는 시간 창입니다.** 여기 없는 경로가 없다는 뜻이 아니고,")
    print("  도달성은 그래서 FALSE 가 아니라 미상으로 남습니다 (ADR-048).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
