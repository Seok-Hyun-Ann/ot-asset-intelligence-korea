# 제3자 구성요소 고지 (Third-Party Notices)

이 저장소에 **직접 포함된** 제3자 구성요소와 그 라이선스입니다. Python 의존성
(`pyproject.toml`)은 포함하지 않고 설치 시 각자 받으므로 여기 적지 않습니다 —
다만 `psycopg` 는 LGPL-3.0 이며, 이 프로젝트는 그것을 수정하지 않고 동적으로
import 만 하므로 어느 라이선스로 배포해도 무방합니다.

| 구성요소 | 버전 | 라이선스 | 위치 | 용도 |
|---|---|---|---|---|
| React | 18.3.1 | MIT | `web/vendor/react.js` (UMD) · `frontend/` 의존성 | 화면 |
| React DOM | 18.3.1 | MIT | `web/vendor/react-dom.js` (UMD) | 화면 |
| Cytoscape.js | 3.34.3 | MIT | `web/vendor/cytoscape.js` (UMD) · `frontend/` 의존성 | 마인드맵·공격 경로 그래프 |
| htm | — | MIT | `web/vendor/htm.js` | 빌드 없이 도는 폴백 화면의 템플릿 |
| Pretendard Variable | — | SIL OFL 1.1 | `frontend/src/fonts/` | 화면 글꼴 (라이선스 원문 동봉) |

`web/vendor/` 의 UMD 판은 `frontend/` 를 빌드하지 않아도(node 가 없는 폐쇄망에서도)
화면이 뜨게 하는 안전망입니다. React·React DOM·Cytoscape 파일은 원문의 라이선스
헤더를 그대로 담고 있습니다. htm 은 배포판에 헤더가 없어 아래에 원문 고지를 둡니다.

## 데이터

| 소스 | 라이선스 | 저장소 포함 |
|---|---|---|
| [CISA ICS Advisories (CSAF)](https://github.com/cisagov/CSAF) | 미국 정부 저작물 — 공공 도메인 | 골드셋 앵커 2건만 (`data/csaf/cisa/2026/`). 나머지는 `scripts/fetch_advisories.py --bulk` |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 미국 정부 저작물 — 공공 도메인 | 스냅샷 1건 (`data/kev/`) |
| Siemens ProductCERT CSAF | TLP:WHITE — 재배포 허가 미확인 | **포함하지 않음.** 각자 받는다 |
| [MITRE ATT&CK for ICS](https://github.com/mitre-attack/attack-stix-data) | MITRE 이용 약관 (출처 표기) | **포함하지 않음** (4MB). 각자 받는다 |

---

## MIT License — htm

Copyright (c) 2018 Jason Miller

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## MIT License — React, React DOM (Meta Platforms, Inc.) · Cytoscape.js (The Cytoscape Consortium)

각 파일 머리의 `@license` 헤더에 원문 고지가 있습니다. 조건은 위 MIT 본문과 같습니다.

## SIL Open Font License 1.1 — Pretendard

`frontend/src/fonts/Pretendard-LICENSE.txt` 에 원문이 있습니다.
