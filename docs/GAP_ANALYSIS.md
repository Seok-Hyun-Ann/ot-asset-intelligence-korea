# 격차 분석 — 비슷한 도구들에 있고 우리에게 없는 것

*실측일 2026-10-03 · 비교 대상은 **실제로 확인한 것만** 적는다. 이름만 들어본 도구는 넣지 않았다.*

이 문서는 세 가지에 답한다.

1. 비슷한 공개 도구들에 있는데 우리에게 없는 것은 무엇인가
2. 그것을 어떻게 붙일 수 있는가 — **어느 모듈을 늘리는 일인가**
3. 다른 보안 표준 문서들을 종합해 결합할 수 있는가

---

## 0. 먼저, 비교 대상이 하지 않는 것

가치를 부풀리지 않기 위해 먼저 적는다. 아래 넷은 조사한 공개 도구에서 보지 못했다.

| 우리가 하는 것 | 왜 드문가 |
|---|---|
| **삼진 논리 적용성** — `unknown` 을 `false` 로 붕괴시키지 않음 | 대부분 "취약/비취약" 이진값이라 판정 못 한 것이 비취약 쪽에 섞인다 |
| **`P?` 가 일급 상태** — 낮은 순위가 아니라 **막힌 P0/P1** | 점수 하나로 줄 세우면 "판단 불가" 가 사라진다 |
| **`as_of` 재현** — 그 시점에 알려져 있던 권고문·KEV 로만 다시 판정 | 대개 현재 피드로 과거를 다시 읽는다 |
| **False safe 0건을 설계 제약으로** | "안전" 표현 금지가 코드·화면·테스트에 걸려 있다 |

이건 **다르게 만든 것**이지 더 많이 만든 것이 아니다. 아래는 전부 **덜 만든 것**이다.

---

## 1. CISA 자산 인벤토리 기준 대조 — 14개 중 12개  *(2026-10-03 ADR-042 로 9 → 12)*

미국 CISA 가 2025년에 낸 [*Foundations for OT Cybersecurity: Asset Inventory Guidance*](https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators)
는 OT 자산 인벤토리가 **먼저 모아야 할 고우선 속성 14개**를 지정한다. 우리 자산 스키마
(`otai/model.py`)가 그것을 담을 수 있는지 실측했다.

| CISA 고우선 속성 | 담는가 | 어디에 |
|---|:--:|---|
| Active/supported communication protocols | ✅ | `Network.protocols[].protocol` |
| Asset criticality | ✅ | `operations.safety_criticality` |
| Asset number | ✅ | `Asset.asset_id` |
| Asset Role/Type | ✅ | `Asset.asset_type` |
| Hostname | ⚠️ | `NetworkAddress.hostname` — 스키마는 있으나 **자동 수집원이 없다** (CSV 로만) |
| IP address | ✅ | `NetworkAddress.ip` — 캡처·CSV (ADR-042) |
| **Logging** | ❌ | — 구성·점검 사실이라 넣지 않았다 (ADR-042) |
| MAC address | ✅ | `NetworkAddress.mac` — 캡처·CSV (ADR-042) |
| Manufacturer | ✅ | `Identity.vendor_raw` |
| Model | ✅ | `Identity.model_raw` |
| Operating system | ⚠️ | `Component.type` 로 표현은 되나 전용 필드가 없다 |
| Physical location/address | ⚠️ | `location.factory/zone` — 논리 구역이지 물리 주소가 아니다 |
| Ports/services | ✅ | `Network.protocols[].port` |
| **User accounts** | ❌ | — 구성·점검 사실이라 넣지 않았다 (ADR-042) |

중간 우선순위에서는 `Firmware/Software Version` ✅, `VLAN` ✅(ADR-042),
`Department/Owner` ❌, `Serial Number` ❌.

### ~~이 중 셋은 "없어서" 가 아니라 "뽑아 놓고 버려서" 다~~ → **닫았다 (ADR-042)**

`otai/capture.py` 는 PCAP 에서 이것들을 실제로 뽑는다. 합성 캡처 한 개로 확인:

```
캡처가 실제로 뽑은 것 →  IP: 10.20.3.11 · MAC: 00:1B:1B:AA:BB:CC · 제조사: Siemens · VLAN: (해당 캡처엔 없음)
```

`to_topology()` 가 이 값들을 **토폴로지 노드에만** 싣고 자산에는 담을 필드가 없었다.
**ADR-042 에서 닫았다** — `NetworkAddress` 를 추가하고, `otai capture --topology` 가
**토폴로지가 `asset_id` 를 선언한 장비에만** 주소를 제안한다(추측으로 잇지 않는다).
못 이은 주소는 숫자로 말하고, 기본은 dry-run 이다.

---

## 2. 공개 도구 세 곳과의 비교

이름만 많이 적는 대신, **실제로 확인한 셋**만 본다.

### 2.1 Dependency-Track — SBOM 을 먹고 VEX 를 뱉는다

[OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/) 은 SBOM(CycloneDX)을
입력으로 받아 구성요소별 취약점을 계속 추적하고, 판단 결과를 **CycloneDX VEX 로 내보낸다.**

| | 그쪽 | 우리 |
|---|---|---|
| SBOM 입력 (CycloneDX/SPDX) | ✅ | ❌ — 기획서(표 15)에만 있다 |
| VEX **소비** | ✅ | ✅ CSAF VEX 를 `applicability.py` 가 읽는다 |
| VEX **생산** | ✅ | ❌ |

**왜 중요한가.** 미국 EO 14028 과 EU CRA 이후 OT 제조사가 장비에 SBOM 을 동봉하기
시작했다. 우리는 "제품 식별" 을 주문번호·제품명 문자열로 하는데, SBOM 이 있으면
**장비 안의 구성요소(OS·런타임·웹서버·라이브러리)까지** 내려간다. 기획서가 요구한
`Asset → Component → Installed Product` 계층이 그제야 실제 데이터로 채워진다.

**VEX 생산이 더 흥미롭다.** 우리의 9개 상태는 이미 VEX 의 네 상태
(`affected` / `not_affected` / `fixed` / `under_investigation`)로 **손실 없이 사상된다** —
오히려 우리 쪽이 더 세분화돼 있다. 판정 근거(`decisive_conditions`)와 해시가 이미
있으므로, VEX 문서를 내보내면 **다른 도구가 우리 판단을 받아 쓸 수 있다.** 지금은
우리 판단이 우리 화면 안에만 있다.

### 2.2 Malcolm / ICSNPP — 현장은 PCAP 이 아니라 Zeek 로그를 갖고 있다

[Malcolm](https://www.cisa.gov/resources-tools/services/malcolm) 은 CISA 와 아이다호 국립연구소가
만든 OT 네트워크 분석 도구다. 핵심은 [ICSNPP](https://github.com/cisagov/icsnpp) — Zeek 용
**ICS 프로토콜 파서 14종**(BACnet, BSAP, C12.22, EtherCAT, EtherNet/IP·CIP, GE-SRTP, Genisys,
HART-IP, Omron FINS, OPC UA, PROFINET IO CM, ROC-Plus, S7comm + DNP3·Modbus 확장),
BSD-3-Clause.

| | 그쪽 | 우리 |
|---|---|---|
| 프로토콜 식별 | 애플리케이션 계층까지 (Modbus 함수 코드, 레지스터 주소까지) | 포트 번호로만 |
| 입력 | PCAP **과 Zeek 로그** | PCAP 만 |
| 장비 식별 | 프로토콜 대화에서 | MAC OUI 로만 (ADR-039) |

**왜 중요한가.** 현장에 Malcolm 이나 Zeek 센서가 이미 있는 경우가 많다. 그쪽은
**몇 주치 로그**를 들고 있는데 우리는 사용자에게 PCAP 파일을 달라고 한다. ICSNPP 의
`modbus.log` · `s7comm.log` 를 읽으면 **우리가 ADR-039 에서 "다음 판" 으로 미룬
프로토콜 식별 대화 해석을 직접 하지 않고도** 얻을 수 있다 — 그쪽이 이미 파싱해 뒀다.
그리고 캡처의 시간 창 한계도 완화된다(며칠치 로그 vs 10분 캡처).

### 2.3 CSET — 표준 질의응답을 데이터로

CISA 의 CSET(Cyber Security Evaluation Tool)은 IEC 62443 · NIST 800-82 · NERC CIP 등의
요구사항을 **질문지로 만들어** 조직의 준수 상태를 평가한다.

| | 그쪽 | 우리 |
|---|---|---|
| 표준 통제 항목 매핑 | ✅ 여러 표준 | ⚠️ **2종** — KISA 제어시스템 51 · NIST 800-82r3 OT Overlay 229 |
| 자산별 근거와 연결 | ❌ (조직 수준 질의응답) | ✅ 항목마다 자산별 근거 (ADR-043/044) |

**왜 중요한가, 그리고 왜 그대로 베끼면 안 되는가.** 처음 전수 검색했을 때
`62443` 은 토폴로지 픽스처 이름과 ADR 에만 있고, `800-82` 는 문서에만, **`NERC`·`CSF`·
`D3FEND`·`CAPEC`·`OSCAL` 은 한 글자도 없었다.** 감사·규제 대응이 필요한 조직에는 이게
도입 거부 사유가 된다. 그래서 둘을 넣었다 — KISA 제어시스템(ADR-043)과 NIST
800-82r3 OT Overlay(ADR-044). `62443`·`NERC`·`CSF`·`OSCAL` 은 아직 없다.

다만 CSET 은 **조직이 스스로 답하는 질문지**다. 우리의 강점은 반대쪽 — **자산별 증거**다.
베낄 것은 질문지가 아니라 **매핑**이다: 우리가 이미 내리는 판정이 어느 통제 항목의
근거가 되는지.

---

## 3. 표준 문서를 결합할 수 있는가 — 어디에 붙는지로 답한다

"종합적으로 결합" 은 문서를 많이 읽는 일이 아니라 **코드의 어느 지점에 사상되는가**를
정하는 일이다. 붙을 자리가 없는 문서는 결합되지 않는다.

| 문서 | 코드의 어디에 붙나 | 지금 상태 |
|---|---|---|
| **CISA KEV** | `H01` 의 전제조건 | ✅ 구현 (`otai/kev.py`, `dateAdded` 시점 필터까지) |
| **ATT&CK for ICS** | 엣지 타입 → 기법 | ✅ 구현. 단 3개 기법만 매핑 (근거 없는 귀속 금지, 표 32) |
| **IEC 62443 Zone/Conduit** | 토폴로지 모델 그 자체 | ⚠️ 구조는 이미 일치. **명시적 선언이 없다** |
| **CISA 자산 인벤토리 지침** | `Asset` 스키마 | ⚠️ 14개 중 12개 — ADR-042 로 9→12 (§1) |
| **SSVC** | 버킷 유도 근거 | ❌ 기획서만. 아래 참조 |
| **CSAF VEX** | 입력은 ✅, 출력은 ❌ | 절반 |
| **CycloneDX/SPDX SBOM** | `Component` 채우기 | ❌ |
| **D3FEND** | **차단 후보**(`paths.blocking_candidates`)의 어휘 | ❌ |
| **NIST SP 800-82r3 OT Overlay** | 판정 → 통제 근거 | ⚠️ **읽고 매핑했다** — 229개 중 11개에 근거를 댄다 (ADR-044) |
| **NIST CSF / NERC CIP** | 판정 → 통제 항목 매핑 | ❌ |
| **OSCAL** | 위 매핑을 기계가 읽는 형식으로 내보낼 때 | ❌ (매핑이 생긴 뒤의 일) |
| **KISA 제어시스템 점검항목 (2026년판)** | 판정 → 점검항목 근거 | ⚠️ **읽고 매핑했다** — 51개 중 9개에 근거를 댄다 (ADR-043) |
| **IEC 62443-3-3 요구사항(SR)** | 위와 같은 자리 — 표 하나를 더하는 일 | ❌ 다음 (근거는 이미 종류별로 모여 있다) |

### SSVC 가 특히 아깝다 — 이미 가진 것으로 거의 채워진다

CISA 의 [SSVC](https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc)
는 다섯 가지 결정점으로 `Track / Track* / Attend / Act` 를 정한다. 우리가 이미 갖고 있는 값과 대보면:

| SSVC 결정점 | 우리에게 있는 것 |
|---|---|
| Exploitation (악용 상태) | ✅ KEV 등재 여부 |
| Technical impact | ✅ CVSS 벡터 (`capability.py` 가 이미 파싱) |
| Automatable | ✅ CVSS 벡터 (AV/AC/PR/UI) |
| Mission prevalence | ⚠️ 자산 수는 알지만 공정 중요도와 연결이 약하다 |
| Public well-being impact | ✅ `operations.safety_criticality` |

즉 **데이터는 거의 다 있고 결정 트리만 없다.** 다만 우리 P0~P4 를 SSVC 로 **대체하면
안 된다** — 강제규칙(H01~H05)의 안전 하한이 SSVC 보다 강하다. SSVC 는 **설명 축**으로
붙여야 한다: "이 항목은 SSVC 로 `Act` 이고, 우리 규칙으로도 P0 다" 처럼.

### 패치할 수 없을 때 — 외부 근거가 우리 설계를 뒷받침한다

Huff 외, [*I Can't Patch My OT Systems!*](https://arxiv.org/abs/2510.06951) (2025) 는 KEV 전체를
분석해 **13% 만이 벤더 우회·완화책을 담고 있다**고 보고한다. OT 는 패치가 어려운데
공개 데이터가 대안을 거의 주지 않는다는 뜻이다.

우리는 이미 **"답이 패치가 아니라 보상 통제"** 를 설계에 넣었다(`exposure.py` 의
`what_to_do`, `paths.blocking_candidates`). 그러나 그 보상 통제는 **우리가 쓴 한국어
문장**이지 표준 어휘가 아니다. **D3FEND** 를 붙이면 "방화벽에서 쓰기 명령을 제한" 이
식별자 있는 방어 기법이 되고, 다른 도구·보고서와 맞춰진다.

---

## 4. 붙이는 순서 — (false safe 관련성 × 품) 기준

| 순위 | 할 일 | 어느 모듈을 늘리나 | 품 |
|:--:|---|---|---|
| ~~a~~ | ~~IP·MAC·호스트명·VLAN 을 `Asset` 에 + 캡처→자산 다리~~ → **완료 (ADR-042)** | `model.py` · `capture.py` · `csvimport.py` | — |
| **b** | **SBOM 입력** (CycloneDX → `Component`) | 새 `otai/sbom.py`, `safeio` 경유 | 중간 |
| **c** | **VEX 출력** (9상태 → CSAF VEX / OpenVEX) | `applicability.Decision` 에 내보내기 | 중간 |
| ~~d~~ | ~~Zeek 로그 입력~~ → **완료 (ADR-051).** ICSNPP 로그 8종을 읽고 `cip_identity`·`bacnet_discovery` 에서 **관측 식별**을 얻는다. 남은 로그 8종은 열 이름을 확인하면 한 줄씩 더하는 일 | `otai/zeeklog.py` | — |
| **e** | **SSVC 설명 축** | `priority.py` 에 병기 (대체 아님) | 작음 |
| ~~f~~ | ~~통제 항목 매핑~~ → **KISA 제어시스템(ADR-043) + NIST 800-82r3 OT Overlay(ADR-044) 완료.** 62443-3-3 · CSF · NERC CIP 는 남음. **화면 연결은 (h)** | `data/controls/` · `otai/controls.py` | — |
| **g** | **D3FEND 어휘**를 차단 후보에 | `paths.py` · `terms.ts` | 중간 |
| ~~h~~ | ~~점검 항목 근거를 CLI 로~~ → **`otai controls` + `otai report` 완료** (ADR-049). 남은 것은 **웹 화면의 보고서 버튼** | `api.py` · 표 25 | — |
| **i** | **현장 반입** — 엑셀·CP949·매핑 프로파일·담당자 (ADR-046) 완료. 남은 것은 **웹 화면의 매핑 편집**(API 는 이미 받는다) | `screens.tsx` | 작음 |
| **j** | **자산대장의 `구역` 열에서 골격 토폴로지 생성** — 지금은 캡처가 있어야 노드가 생긴다. xlsx 로 들어온 800대가 그래프 안에 존재하게 만드는 일 | `zonemap.py` · `csvimport.py` | 중간 |

**(a) 를 먼저 하는 이유**: 측정된 격차이고, 데이터가 이미 수집되고 있으며, CISA 기준의
세 항목을 한 번에 채우고, `capture.py` 가 만든 토폴로지와 자산 목록이 **같은 장비를
가리키게** 된다(지금은 IP 로 만든 노드와 주문번호로 만든 자산이 서로를 모른다).

### 각각이 지켜야 할 기존 제약

- **(b) SBOM**: 외부 파일이므로 `safeio` 를 거친다. SBOM 의 버전은 **제조사 선언**이지
  현장 관측이 아니다 — ADR-038 의 `CLAIMED_METHODS` 와 같은 취급을 받아야 한다.
- **(c) VEX 출력**: `no_known_match` 를 VEX `not_affected` 로 내보내면 **그 순간
  false safe 를 외부에 퍼뜨린다.** 확정된 것만 내보내고 나머지는 생략해야 한다.
- **(d) Zeek**: 로그는 캡처보다 긴 시간 창이지만 여전히 **창**이다. "안 보였다 = 없다"
  금지는 그대로 (ADR-039).
- **(f) 통제 매핑**: 표준 원문은 대개 재배포 불가다. **통제 ID 와 우리 판정의 링크만**
  저장하고 본문은 담지 않는다.

---

## 5. 하지 않기로 한 것 (격차가 아니라 선택)

| 항목 | 왜 |
|---|---|
| **EPSS · NVD** | ADR-022. KEV/EPSS 는 정렬 신호이지 적용성 입력이 아니다 |
| **능동 스캔** | 불변 규칙 6. 현장 안전이 기능보다 앞선다 |
| **LLM 판정** | 표 32. 버전 비교·영향 확정·P0~P4 에 관여 금지 |
| **정확도 주장** | ADR-008/013. 전문가 골드셋도 실제 토폴로지도 없다 |

---

## 6. 이 문서의 한계

- ~~KISA 기준 문서를 읽지 않았다~~ → **읽고 매핑했다 (ADR-043).** 2026년판의
  `06. 제어시스템` 장(C-01~C-51)을 `data/controls/kisa-2026-ics.json` 에 사상했다.
  51개 중 **9개**에만 근거를 댄다 — 나머지 42개는 정책·절차·물리·교육이라 도구가
  답할 수 없고, 그 사실을 표에 그대로 싣는다.
- ~~NIST SP 800-82 는 Rev.3 영문 원문이 필요하다~~ → **받아서 매핑했다 (ADR-044).**
  부록 F(OT Overlay) 의 통제 229개를 `data/controls/nist-800-82r3-ot-overlay.json` 에
  사상했고 **11개**에 근거를 댄다. Rev.2 한글 번역본은 쓰지 않았다 — 2023-09-28 에
  폐기된 판이고(통제 ID 가 800-53 Rev.4 기준이다), 번역본은 KISA 저작권이라 재배포할
  수 없다. Rev.3 영문은 미국 정부 저작물이라 짧은 인용까지 싣는다.
- **통제 보강(enhancement)과 기준선 선정은 하지 않는다.** 오버레이는 통제마다
  LOW/MOD/HIGH 기준선과 `AC-4(21)` 같은 보강을 말하는데, 그 선정은 조직의 일이다.
  우리는 상위 통제 단위로만 답하고 `severity` 를 비워 둔다 — 없는 값을 지어내지 않는다.
- 비교 대상을 **셋으로 좁혔다.** 이름만 아는 도구를 늘리는 것보다 실제로 확인한 것을
  정확히 적는 쪽을 골랐다.
- 여기 적은 우리 쪽 수치는 전부 이 저장소 코드에서 실측했다. 검증 방법은
  [`VERIFICATION.md`](VERIFICATION.md) 에 있다.

---

**출처**
[CISA · OT 자산 인벤토리 지침](https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators) ·
[CISA/INL · Malcolm](https://www.cisa.gov/resources-tools/services/malcolm) ·
[cisagov/icsnpp](https://github.com/cisagov/icsnpp) ·
[CISA · SSVC](https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc) ·
[OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/) ·
[Huff 외 · I Can't Patch My OT Systems!](https://arxiv.org/abs/2510.06951) ·
[KISA 보호나라](https://krcert.or.kr/)
