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

## 1. CISA 자산 인벤토리 기준 대조 — 14개 중 9개

미국 CISA 가 2025년에 낸 [*Foundations for OT Cybersecurity: Asset Inventory Guidance*](https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators)
는 OT 자산 인벤토리가 **먼저 모아야 할 고우선 속성 14개**를 지정한다. 우리 자산 스키마
(`otai/model.py`)가 그것을 담을 수 있는지 실측했다.

| CISA 고우선 속성 | 담는가 | 어디에 |
|---|:--:|---|
| Active/supported communication protocols | ✅ | `Network.protocols[].protocol` |
| Asset criticality | ✅ | `operations.safety_criticality` |
| Asset number | ✅ | `Asset.asset_id` |
| Asset Role/Type | ✅ | `Asset.asset_type` |
| **Hostname** | ❌ | — |
| **IP address** | ❌ | — |
| **Logging** | ❌ | — |
| **MAC address** | ❌ | — |
| Manufacturer | ✅ | `Identity.vendor_raw` |
| Model | ✅ | `Identity.model_raw` |
| Operating system | ⚠️ | `Component.type` 로 표현은 되나 전용 필드가 없다 |
| Physical location/address | ⚠️ | `location.factory/zone` — 논리 구역이지 물리 주소가 아니다 |
| Ports/services | ✅ | `Network.protocols[].port` |
| **User accounts** | ❌ | — |

중간 우선순위에서는 `Firmware/Software Version` ✅, **`VLAN` ❌**, `Department/Owner` ❌,
`Serial Number` ❌.

### 이 중 셋은 "없어서" 가 아니라 **"뽑아 놓고 버려서"** 다

`otai/capture.py` 는 PCAP 에서 이것들을 실제로 뽑는다. 합성 캡처 한 개로 확인:

```
캡처가 실제로 뽑은 것 →  IP: 10.20.3.11 · MAC: 00:1B:1B:AA:BB:CC · 제조사: Siemens · VLAN: (해당 캡처엔 없음)
```

그런데 `to_topology()` 가 이 값들을 **토폴로지 노드에만** 싣는다. 자산 쪽에는
`Asset` 에 담을 필드가 없어서 들어가지 못한다. 즉 **수집은 되는데 자산 인벤토리에
반영되지 않는다.** 가장 작고 가장 확실한 격차다.

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
| 표준 통제 항목 매핑 | ✅ 여러 표준 | ❌ 전무 |
| 자산별 근거와 연결 | ❌ (조직 수준 질의응답) | — |

**왜 중요한가, 그리고 왜 그대로 베끼면 안 되는가.** 우리 코드 전수 검색 결과:
`62443` 은 토폴로지 픽스처 이름과 ADR 에만 있고, `800-82` 는 문서에만, **`NERC`·`CSF`·
`D3FEND`·`CAPEC`·`OSCAL` 은 한 글자도 없다.** 감사·규제 대응이 필요한 조직에는 이게
도입 거부 사유가 된다.

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
| **CISA 자산 인벤토리 지침** | `Asset` 스키마 | ⚠️ 14개 중 9개 (§1) |
| **SSVC** | 버킷 유도 근거 | ❌ 기획서만. 아래 참조 |
| **CSAF VEX** | 입력은 ✅, 출력은 ❌ | 절반 |
| **CycloneDX/SPDX SBOM** | `Component` 채우기 | ❌ |
| **D3FEND** | **차단 후보**(`paths.blocking_candidates`)의 어휘 | ❌ |
| **NIST 800-82 / CSF / NERC CIP** | 판정 → 통제 항목 매핑 | ❌ |
| **OSCAL** | 위 매핑을 기계가 읽는 형식으로 내보낼 때 | ❌ (매핑이 생긴 뒤의 일) |
| **KISA 주요정보통신기반시설 취약점 분석·평가 기준** | 국내 규제 대응 계층 | ❌ **그리고 아직 읽지 않았다** |

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
| **a** | **IP·MAC·호스트명·VLAN 을 `Asset` 에** + 캡처→자산 다리 | `model.py` · `capture.py` | 작음 |
| **b** | **SBOM 입력** (CycloneDX → `Component`) | 새 `otai/sbom.py`, `safeio` 경유 | 중간 |
| **c** | **VEX 출력** (9상태 → CSAF VEX / OpenVEX) | `applicability.Decision` 에 내보내기 | 중간 |
| **d** | **Zeek 로그 입력** (ICSNPP `*.log` → 토폴로지·프로토콜) | `capture.py` 와 같은 모양의 `otai/zeeklog.py` | 중간 |
| **e** | **SSVC 설명 축** | `priority.py` 에 병기 (대체 아님) | 작음 |
| **f** | **통제 항목 매핑** (62443 / 800-82 / KISA) | 새 `data/controls/*.json` + 판정 ↔ 통제 링크 | 큼 |
| **g** | **D3FEND 어휘**를 차단 후보에 | `paths.py` · `terms.ts` | 중간 |

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

- **KISA 기준 문서를 읽지 않았다.** [KISA 보호나라](https://krcert.or.kr/)에 「주요정보통신기반시설
  기술적 취약점 분석·평가 방법 상세가이드」가 있다는 것만 확인했다. 국내 규제 계층을
  설계하려면 원문을 받아 읽어야 한다 — 읽기 전에는 무엇이 사상되는지 말할 수 없다.
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
