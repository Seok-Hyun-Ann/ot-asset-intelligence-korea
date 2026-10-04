<div align="center">

# OT Asset Intelligence

### OT 자산 취약점·공격 경로 관리 플랫폼

**모르는 것은 모른다고 답하는** 스마트 팩토리 OT 보안 의사결정 도구
*Evidence-graded vulnerability applicability and attack-path management for OT assets — on-premises, air-gapped first.*

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-React%2018-009688?logo=fastapi&logoColor=white)](frontend/)
[![Air-gapped](https://img.shields.io/badge/air--gapped-first-informational)](#데이터-출처)

<img src="docs/screenshots/01-actions.png" alt="할 일 화면 — 위험 점수가 아니라 해야 할 일이 기본 화면" width="900">

</div>

---

불완전한 현장 자산 정보를 입력받아 **실제 적용 가능한 취약점**을 증거 수준별로 판별하고,
공격 경로를 계산하며, 생산 안전과 정비 여건을 반영한 조치 순서를 제시합니다.
범용 CVE 검색기와 OT NDR **사이**에 위치합니다.

핵심 산출물은 CVE 목록이 아니라 **각 결론의 근거와 다음 행동**입니다.

```
                         ┌─ 정보가 늘면서 결론이 움직인다 ─┐
제품군만 안다      →  후보 (candidate)
버전 확보          →  적용 확인 · P?          도달성 미상이라 강제규칙 보류
토폴로지 확보      →  P0                       H02 발화
차단 후보 적용     →  경로 소멸
패치 증거 확보     →  수정 확인 · P4
```

## 왜 이 도구인가

| | |
|---|---|
| **False safe 0건** | 영향받는 장비를 "안전" 으로 표시하는 것이 최악의 오류입니다. `no_known_match` 는 어디서도 안전으로 렌더링하지 않고, "대상이 아니다" 옆에는 항상 "안전하다는 뜻이 아닙니다" 가 붙습니다. |
| **삼진 논리** | 모든 조건은 `true / false / unknown` 입니다. `unknown` 을 `false` 로 붕괴시키지 않습니다 — `Tri` 를 `bool()` 로 캐스팅하면 **예외가 납니다.** 판단이 막힌 항목은 낮은 순위가 아니라 `P?`(막힌 P0/P1)입니다. |
| **재현성 100%** | 모든 판정은 `as_of` + 규칙 버전 + 입력 해시와 함께 저장됩니다. `otai/` 안에 wall-clock 이 없고, 같은 입력은 **바이트 동일** 출력을 냅니다. 과거 시점 판정은 그 시점에 알려져 있던 권고문·KEV 로만 다시 계산합니다. |
| **보안을 모르는 사람 기준** | 화면 문구는 전문 용어 없이, 모든 발견에 "지금 뭘 하면 되나" 가 붙습니다. 등급 배지를 누르면 **왜 그 등급인지**를 그 항목에 대해 설명합니다. |

<div align="center">
<table><tr>
<td><img src="docs/screenshots/02-asset.png" alt="자산 상세 — 왜 P? 인지 그 자리에서 설명" width="440"></td>
<td><img src="docs/screenshots/03-changes.png" alt="무엇이 달라졌나 — 두 시점 비교" width="440"></td>
</tr><tr>
<td align="center"><sub>자산 상세 — 배지를 누르면 왜 그 등급인지, 무엇을 확인하면 되는지</sub></td>
<td align="center"><sub>무엇이 달라졌나 — 그 시점에 알려져 있던 것만으로 다시 판정</sub></td>
</tr></table>
<sub>화면의 자산은 전부 <b>합성</b>입니다 — 제조사·제품명·버전 표기는 실제 권고문 원문이지만 장비 자체는 실재하지 않습니다. 화면이 그 사실을 계속 알립니다.</sub>
</div>

## 5분 안에 시작하기

```bash
git clone https://github.com/Seok-Hyun-Ann/ot-asset-intelligence-korea.git && cd ot-asset-intelligence-korea
python -m pip install -e ".[web]"          # Python 3.11+ · 웹앱 의존성까지
python scripts/fetch_advisories.py         # 권고문·KEV·ATT&CK 수집 (인터넷 필요, 1회)
python -m otai web --db data/otai.db --seed fixtures/assets
#   → http://127.0.0.1:8000/   (frontend/ 를 빌드하면 /ui/ 의 정식 화면, 아니면 같은 자리의 폴백 화면)
```

이 경로는 **SQLite** 라 추가 설치가 없습니다. 운영 기본값인 PostgreSQL 은 [아래](#웹앱)에 있습니다.
저장소에는 골드셋 권고문 2건과 KEV 스냅샷만 들어 있고, 나머지 데이터는 위 스크립트가 받아옵니다.

```bash
python -m otai ask                         # 장치 하나를 대화형으로 넣어보기
python scripts/demo.py                     # 전 과정 시연 → out/demo/
```

## 어떻게 동작하나

```mermaid
flowchart LR
    A["수집<br/>CSAF · KEV · CSV<br/>프로젝트 파일 · PCAP"] --> B["정규화<br/>버전 문법 2종 · 별칭<br/>필드별 소스 권위"]
    B --> C["적용성<br/>삼진 논리 · VEX<br/>9개 상태"]
    C --> D["경로<br/>능력 상태 전이<br/>observed / inferred / unknown"]
    D --> E["우선순위<br/>강제규칙 H01~H05<br/>P0 → P? → P1 → P2 → P3 → P4"]
    E --> F["행동 큐<br/>근거 + 다음 행동"]
```

- **수집**은 장비에 접속하지 않습니다. 사용자가 준 파일(CSV · 엔지니어링 프로젝트 · 캡처)과 공개 피드만 읽습니다.
- **적용성**은 결정적 규칙 모듈입니다. 버전 비교·영향 확정·P0~P4 결정에 LLM 이 관여하지 않습니다.
- **경로**는 최단 거리가 아니라 공격자가 얻어가는 **능력**(`network < credentials < code_exec < control_write`)의 전이로 평가합니다.
- **우선순위**의 강제규칙은 사용자 관점(렌즈)·정책·예외 승인으로 **내릴 수 없습니다.** 렌즈는 같은 등급 안의 순서만 바꿉니다.

## 웹앱

```bash
# 1) 저장소 — PostgreSQL 이 기본입니다. OTAI_DB 환경변수로 DSN 을 지정하세요.
export OTAI_DB="postgresql://user:pass@127.0.0.1:5433/otai"   # 기본값은 개발용(otai:otai)입니다

# 2) 화면 — 한 번 빌드합니다. node 가 없으면 web/vendor 의 UMD 판으로 자동 폴백합니다.
cd frontend && npm install && npm run build && cd ..

# 3) 실행
python -m otai web --seed fixtures/assets
```

| 화면 | 하는 일 |
|---|---|
| **할 일** | 기본 화면. 위험 점수가 아니라 **해야 할 일** 하나. `P0 → P? → P1 → P2 → P3 → P4` |
| 자산 목록 | 공장·구역·종류·**식별 완성도(L0~L5)** 로 걸러 봅니다 |
| 자산 가져오기 | 엔지니어링 프로젝트 파일 · **캡처(pcap)** · CSV — 셋 다 미리보기가 기본 |
| 무엇이 달라졌나 | 지난 어느 날과 기준 시점을 견줍니다 — 새로 생김 · 등급 변경 · 사라짐 · **비교 불가** |
| 자산 상세 | 아는 것을 표로 보고, **다음에 확인할 것 하나**에 답해 판정을 움직입니다 |
| 취약점 | CVE·CVSS·KEV·수정 정보와 일치/불일치/빠진 값 |
| 마인드맵 | 자산을 가운데 두고 일곱 축 (식별·구성요소·취약점·경로·공정영향·조치·증거) |
| 공격 경로 | 진입점에서 이 자산까지. 공격자가 얻어가는 능력과 **차단 후보** |
| 출처 대조 | 같은 취약점을 여러 곳이 말할 때 **덮어쓰지 않고** 모두 보관 |
| 관점 바꿔보기 | 렌즈를 바꿔도 **조치 등급은 안 움직인다**는 것을 눈으로 |
| 운영 콘솔 | 소스 상태·규칙 버전·감사 이벤트 |

> **`127.0.0.1` 에만 열립니다. 인증이 없으므로 외부에 노출하지 마세요.** 화면 상단 경고 띠가 그 사실을 계속
> 알리고, 감사 로그의 `actor` 는 인증되지 않은 주장으로 기록됩니다. PostgreSQL 이 안 떠 있으면 SQLite 로
> 조용히 내려가지 않고 **크게 실패합니다** — 감사 기록이 갈라지면 계보가 끊기기 때문입니다.

## 현장 파일에서 시작하기 — 장비에 접속하지 않습니다

세 가지 파일을 **사용자가 주면** 읽습니다. 네트워크에 아무것도 보내지 않습니다. 셋 다 기본은 dry-run 이고
사람이 고른 것만 적용됩니다.

```bash
# 엔지니어링 프로젝트 파일 (AutomationML · XML · 압축) → 자산 후보
#   권고문에서 뽑은 주문번호 1,028개와 맞춥니다 — 도구의 스키마를 추측하지 않습니다.
#   펌웨어는 '설정값' 으로만 들어가고, 그것만으로 '확인' 에 도달하지 않습니다.
python -m otai project --file plant.aml --advisory data/csaf --as-of 2026-09-11
python -m otai project --file plant.aml --advisory data/csaf --as-of 2026-09-11 --apply --out fixtures/assets

# 캡처 파일 (pcap · pcapng) → 관측된 토폴로지
#   실제로 오간 통신만 observed 엣지가 됩니다. 캡처는 시간 창이라 안 보인 것을 '없다' 로 만들지 않습니다.
#   Purdue 레벨·구역은 패킷에 없어 비워 두고 사람이 채웁니다.
python -m otai capture --file line3.pcap --as-of 2026-09-11 --out out/topology.json

# CSV → 자산
python -m otai import --csv fixtures/csv/assets-sample.csv --out out/assets --as-of 2026-09-11
```

### 장치 하나를 직접 넣어보기

```bash
python -m otai ask
```

아무것도 모르는 상태에서 시작해 아는 것만 답하면, 답할 때마다 실제 엔진이 다시 판정하고 **다음에 물어볼 것 하나**를 돌려줍니다.

```
장치 종류?      → PLC                  판정: 정보 부족
제조사?         → Mitsubishi Electric  판정: 정보 부족
모델/제품군?    → MELSEC iQ-R Series   판정: 후보
펌웨어?         → 48                   판정: 적용 가능성 높음   ← 제품군까지만 알아서
  (정확한 모델을 넣으면)               판정: 적용 확인
  (49 를 넣으면)                       판정: 비영향 확인
```

**모르면 「확인 불가」를 누르세요.** 빈칸을 기본값으로 채우지 않습니다 — 미상으로 남습니다.

<details>
<summary><b>개별 명령</b> — 판정 카드 · 행동 큐 · 공격 경로 · 소스 비교 · 폐쇄망 번들</summary>

```bash
# 적용성 판정 — 자산 1건 + 권고문 1건 → 판정 카드
python -m otai decide --asset fixtures/assets/melsec-iqr-fw48.json \
  --advisory data/csaf/cisa/2026/icsa-26-036-02.json --as-of 2026-09-11

# 행동 큐 — P0 → P? → P1 → P2 → P3 → P4 (토폴로지가 있으면 P? 가 확정됩니다)
python -m otai queue --assets fixtures/assets \
  --advisory data/csaf/cisa/2026/icsa-26-036-02.json --as-of 2026-09-11 --lens ops \
  --topology fixtures/topology/purdue-62443-reference.json

# 공격 경로와 차단 후보
python -m otai paths --topology fixtures/topology/purdue-62443-reference.json \
  --target melsec-iqr-fw48 --as-of 2026-09-11

# 다중 소스 비교 — 필드별 권위, 충돌 보존
python -m otai sources --advisory data/csaf/cisa/2026/icsa-26-036-02.json data/csaf/cisa/2026/icsa-26-071-04.json
#   (fetch_advisories.py 를 돌렸다면 Siemens 원문과도 비교할 수 있습니다: data/csaf/siemens/ssa-019113.json)

# 폐쇄망 번들 — Ed25519 서명 · 파일별 해시 · 매니페스트에 없는 멤버 거부
python -m otai keygen --out keys/
python -m otai bundle-export --include "csaf/a.json=data/csaf/cisa/2026/icsa-26-036-02.json" \
  --out b.zip --key keys/signing.key --as-of 2026-09-11
python -m otai bundle-verify --bundle b.zip --pub keys/signing.pub --as-of 2026-09-11

# 서버 없이 보는 단일 HTML (미리 계산한 조합 · 외부 자원 0개)
python scripts/build_ui.py --open
```

`python -m otai --help` 로 전체 명령을 볼 수 있습니다.

</details>

## 규모 (2026-09-11 실측)

```bash
python scripts/fetch_advisories.py --bulk                    # CISA OT CSAF 대량 수집
python scripts/make_assets.py --apply --vendors 400 --per-vendor 1
python scripts/inventory.py --db data/otai.db                # 지금 무엇을 몇 개 들고 있는지
```

| | 수 |
|---|---:|
| 권고문 (CISA OT CSAF) | 1,306건 |
| 고유 CVE | 5,769개 |
| 대상 제품 항목 | 10,381개 |
| 제조사 | 367종 |
| 자산 (합성, 실제 제품 식별자에 앵커) | 1,360개 |
| 대조한 쌍 | 1,776,160 |
| 그중 사전 필터가 거른 것 | 1,728,388 (97.3%) |
| 실제 판정 | 47,772쌍 |
| KEV 등재 CVE (우리 범위 안) | 54건 |

사전 필터가 틀리면 그게 곧 false safe 이므로 **177만 쌍 전부**를 돌려 건너뛴 쌍이 정말 `no_known_match`
인지 확인했습니다 — 위반 0건. 무엇을 어떻게 검증했는지는 [`docs/VERIFICATION.md`](docs/VERIFICATION.md) 에 있습니다.

## 설계에서 양보하지 않은 것

| 규칙 | 이유 |
|---|---|
| **False safe 0건** | 영향 대상을 "안전" 으로 표시하는 것이 최악의 오류. `no_known_match` 는 절대 안전으로 렌더링하지 않음 |
| **삼진 논리** | `unknown` 을 `false` 로 붕괴시키지 않음. 버전 미상을 `0` 으로 치환하지 않음 |
| **추론 ≠ 확정** | 도달성은 **모든 엣지가 관측된** 경로에서만 확정. 토폴로지에 없는 자산은 `unknown` 이지 도달 불가가 아님 |
| **덮어쓰기 금지** | 모든 주장을 보존하고 '현재 값' 은 권위·시점으로 **계산**. DB 트리거가 UPDATE/DELETE 를 차단 |
| **재현성** | `otai/` 안에 wall-clock 없음. 시간은 `as_of` · `observed_at` 으로만. 같은 입력은 바이트 동일 출력 |
| **안전 하한** | 렌즈 가중치도 정책 파일도 예외 승인도 **강제규칙이 발화한 항목을 내리지 못함** |
| **현장 안전** | 능동 스캔 없음. 사용자가 준 파일만 읽고, 신뢰할 수 없는 바이트는 전부 `otai/safeio.py` 를 거침 |
| **LLM 경계** | 버전 비교 · 적용성 확정 · P0~P4 결정에 LLM 이 관여하지 않음. 전부 결정적 규칙 모듈 |

## 표준 점검 항목에 근거를 댑니다 — 준수 판정은 하지 않습니다

이미 내린 자산별 판정이 **어느 점검 항목의 근거가 되는지** 이어 줍니다.
표준 2종, 항목 280개를 싣고 그중 **20개**에 기계가 만든 근거를 댑니다.

| 표준 | 항목 | 근거를 대는 것 | 매핑 표 |
|---|:--:|:--:|---|
| KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 2026 · `06. 제어시스템` | 51 | **9** | [`data/controls/kisa-2026-ics.json`](data/controls/kisa-2026-ics.json) |
| NIST SP 800-82 Rev.3 `부록 F — OT Overlay` (SP 800-53 Rev.5 재단) | 229 | **11** | [`data/controls/nist-800-82r3-ot-overlay.json`](data/controls/nist-800-82r3-ot-overlay.json) |

답할 수 없는 **260개를 그대로 싣습니다.** 우리가 답하는 것만 보여주면 안내서가 아니라
홍보물이 됩니다.

| 상태 | 뜻 |
|---|---|
| **근거 있음** | 이 항목에 댈 기계 판독 가능한 근거를 냈습니다 |
| **근거 없음** | 낼 수 있는 항목인데 아직 근거가 없습니다. **미달이라는 뜻이 아닙니다** |
| **도구가 답할 수 없음** | 정책·절차·물리·교육 항목입니다. **통과도 미달도 아닙니다** |

**「양호」·「취약」·「준수」라고 말하지 않습니다.** 취약점 분석·평가는 정보통신기반
보호법에 따라 자격을 갖춘 평가기관이 수행합니다. 그 어휘를 쓰면 할 수 없는 법적
주장을 하는 것입니다. 답하지 않는 것도 항목마다 적습니다 — 예를 들어 NIST `RA-5`
(Vulnerability Monitoring **and Scanning**)에서 모니터링 쪽은 답하고 **스캐닝은 하지
않습니다.** 능동 질의는 현장 안전 때문에 금지입니다.

표준 **원문은 저장소에 없습니다.** 매핑 표에는 항목 코드·분류명과 매핑 사유를 담고,
KISA 는 우리가 쓴 한 줄 요약(본문은 재배포 금지), NIST 는 근거가 된 **짧은 원문 인용**을
함께 싣습니다(미국 정부 저작물). 자세히는 [ADR-043 · ADR-044](docs/DECISIONS.md).

```bash
python -m otai controls \
  --asset    fixtures/assets/melsec-iqr-fw48.json \
  --advisory data/csaf/cisa/2026 \
  --topology fixtures/topology/purdue-62443-reference.json \
  --as-of    2026-09-11        # --standard kisa|nist · --all · --json
```

`--topology` 를 주지 않으면 도달성은 **미상으로 남습니다** — '분리됐다' 가 아닙니다.
웹 화면 연결은 아직 없습니다 ([`docs/GAP_ANALYSIS.md`](docs/GAP_ANALYSIS.md) 의 (h)).

## 무엇을 주장하고 무엇을 주장하지 않는가

**이 구분이 이 프로젝트의 핵심입니다.** 상세는 [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

- **정확도를 주장하는 것** — 적용성 판정과 적대적 입력 거부. 정답이 외부에서 객관적으로 주어집니다
  (권고문에서 파생 / "거부되어야 한다" 는 논쟁 여지 없음).
- **주장하지 않는 것** — 우선순위와 경로 탐지의 정확도. 전문가 합의 골드셋이 없고 토폴로지가 100% 합성이기
  때문입니다. 자산도 전부 합성이며 화면이 그 사실을 계속 알립니다.

알려진 한계: 인증·RBAC 미구현(로컬 전용) · NVD·EPSS 의도적 미구현 · 프로토콜 식별 대화(CIP·S7) 미해석 ·
실제 현장 데이터로 검증하지 못함.

## 데이터 출처

| 소스 | 용도 | 저장소 포함 |
|---|---|---|
| [CISA CSAF](https://github.com/cisagov/CSAF) | ICS 권고문 (조정기관) | 골드셋 2건 — 공공 도메인. 나머지는 스크립트로 수집 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 실제 악용 | 스냅샷 1건 — 공공 도메인 |
| [Siemens ProductCERT](https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json) | 벤더 권고문 | ✗ TLP:WHITE 재배포 미확인 |
| [ATT&CK for ICS](https://github.com/mitre-attack/attack-stix-data) | 기법 분류 (v19.2 고정) | ✗ 4MB |
| [NIST SP 800-82r3](https://doi.org/10.6028/NIST.SP.800-82r3) | OT Overlay 통제 매핑 | 매핑 표만 — 원문 PDF 는 공개 URL 에서 받습니다 |
| [KISA 상세가이드 2026](https://www.krcert.or.kr/) | 제어시스템 점검항목 매핑 | 매핑 표만 — 원문은 재배포 금지 |

`scripts/fetch_advisories.py` 가 전부 받아옵니다. 토폴로지는 **합성**이며 Purdue + IEC 62443 구조를 따릅니다.

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/SPEC_v1.0.md`](docs/SPEC_v1.0.md) | 상세 기획서 (22장 + 부록, 표 52개) — 모든 설계의 1차 근거 |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | ADR 44개 — 무엇을 왜 그렇게 정했고, 무엇을 기각했고, 무엇이 한계인가 |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | 검증 매트릭스 — 무엇을 어떤 근거로 검증했는가 |
| [`docs/GAP_ANALYSIS.md`](docs/GAP_ANALYSIS.md) | 비슷한 공개 도구들과의 격차 — 무엇이 없고 어떻게 붙이는가 |

성능: `python scripts/bench_paths.py` 로 직접 측정합니다. 실측값은 [`docs/DECISIONS.md`](docs/DECISIONS.md) 의 ADR-015 표에 있습니다 — 10만 엣지 5홉 질의가 기준(5초) 안쪽입니다.

## 기여

이슈와 PR 을 환영합니다. 규칙을 바꿀 때는 `docs/DECISIONS.md` 에 ADR 로 이유를 남깁니다 — 특히
**"안전" 쪽으로 새는 경로**를 만들지 않았는지가 기준입니다.

> **테스트 묶음(`tests/`)과 검증 스크립트(`scripts/check_*.py`·`verify_matrix.py`)는 이 저장소에
> 배포하지 않습니다.** 실행에 필요한 파일만 올리기로 했기 때문입니다. 그래서 내려받은 뒤
> `pytest` 를 돌릴 것은 없고, `docs/VERIFICATION.md` 와 ADR 에 적힌 테스트 이름은 **무엇을 어떤
> 근거로 검증했는지에 대한 기록**이지 내려받은 트리에서 실행할 수 있는 대상이 아닙니다.
> PR 을 주실 때는 재현 절차를 본문에 적어 주세요 — 어떤 입력에서 무엇이 달라지는지가
> 테스트 파일보다 중요합니다.

## 라이선스

[`LICENSE`](LICENSE) · 포함된 제3자 구성요소와 데이터의 라이선스는 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 에 있습니다.
