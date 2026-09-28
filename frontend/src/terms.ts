/* 통제 어휘 → 사람 말.
 *
 * 표 10 의 한국어 UI 문구(`label`)는 기획서가 고정한 값이라 바꾸지 않는다.
 * 바꾸는 것은 **그 옆에 영문 코드를 그대로 노출하던 것**이다. 화면에는 `plain`
 * (무슨 뜻인지)과 `why`(왜 그렇게 판단했는지)를 쓰고, 코드는 '자세히' 안으로 넣는다.
 *
 * `no_known_match` 의 `plain` 을 고칠 때는 주의할 것 — 절대 '안전' 으로 읽히면
 * 안 된다 (부록 B, 불변 규칙 1).
 */
import type {Bucket, Status} from './types';

export interface Term {
  label: string;
  plain: string;   // 무슨 일인가
  why: string;     // 그래서 뭐가 위험한가
  todo?: string;   // 지금 뭘 하면 되나 — 보안을 모르는 사람이 실제로 읽는 줄
}

export const STATUS: Record<Status, Term> = {
  affected_confirmed: {
    label: '적용 확인',
    plain: '이 장비가 영향을 받습니다',
    why: '제품·버전·구성 조건이 모두 현장 증거와 맞습니다.',
    todo: '이 장비를 지금 조치 대상으로 올리세요. 제조사가 낸 수정본이 있으면 다음 정비 때 올리고, 그때까지는 이 장비로 들어오는 길을 막아 두세요.',
  },
  affected_likely: {
    label: '적용 가능성 높음',
    plain: '영향받을 가능성이 높습니다',
    why: '제품은 확실히 맞고, 버전이나 조건 일부는 추론입니다.',
    todo: '정확한 모델명이나 펌웨어 번호를 확인하세요. 그 값 하나로 ’해당함’ 과 ’해당 없음’ 이 갈립니다.',
  },
  candidate: {
    label: '후보',
    plain: '아직 후보입니다',
    why: '제품군까지만 맞아 확정할 수 없습니다. 정확한 모델을 알면 갈립니다.',
    todo: '장비 명판이나 설정 화면에서 정확한 모델명을 확인해 입력하세요.',
  },
  insufficient_information: {
    label: '정보 부족',
    plain: '판단할 값이 없습니다',
    why: '핵심 값 하나가 비어 있습니다. 그것만 채우면 결론이 납니다.',
    todo: '화면이 물어보는 값 하나만 채우세요. 그러면 바로 결론이 납니다.',
  },
  conflicting_evidence: {
    label: '근거 충돌',
    plain: '출처마다 말이 다릅니다',
    why: '사람이 봐야 합니다. 한쪽을 골라 결론 내리지 않았습니다.',
    todo: '담당자가 직접 확인해야 합니다. 두 출처가 다르게 말하고 있어 자동으로 정하지 않았습니다.',
  },
  stale: {
    label: '정보 오래됨',
    plain: '관측이 너무 오래됐습니다',
    why: '다시 확인하기 전에는 확정하지 않습니다.',
    todo: '장비를 다시 확인해 최신 값을 입력하세요. 지금 값은 너무 오래돼 믿을 수 없습니다.',
  },
  no_known_match: {
    label: '현재 일치 항목 없음',
    plain: '지금 가진 범위에서 못 찾았습니다',
    // 안전이 아니다. 이 문장을 줄이지 말 것.
    why: '안전하다는 뜻이 아닙니다. 불러온 권고문 안에 일치가 없을 뿐입니다.',
    todo: '지금은 할 일이 없습니다. 다만 안전하다는 뜻이 아니라, 불러온 문서 안에 이 장비 이야기가 없다는 뜻입니다.',
  },
  not_affected_confirmed: {
    label: '비영향 확인',
    plain: '영향받지 않습니다',
    why: '제조사 VEX 또는 버전 조건으로 확인했습니다.',
    todo: '할 일이 없습니다. 근거와 확인 시점을 기록해 두면 나중에 같은 질문을 다시 받지 않습니다.',
  },
  fixed: {
    label: '수정 확인',
    plain: '이미 고쳐졌습니다',
    why: '수정 버전이 설치된 증거가 있습니다.',
    todo: '할 일이 없습니다. 다음 점검 때 이 버전이 그대로인지만 확인하세요.',
  },
};

export const BUCKET: Record<Bucket, Term> = {
  'P0': {label: '지금', plain: '지금 격리하거나 비상 검토',
         why: '활성 악용이거나 제어·안전 경로에 직접 닿습니다.'},
  'P?': {label: '확인 먼저', plain: '판단이 막혀 있습니다',
         why: '낮은 우선순위가 아닙니다. 전제 하나만 확인하면 최고 등급으로 올라갑니다.'},
  'P1': {label: '정기 창 밖에', plain: '정기 정비를 기다리지 말고 조치',
         why: '영향과 도달성이 높거나, 악용 사례·지원 종료가 걸려 있습니다.'},
  'P2': {label: '다음 정비 창에', plain: '다음 정비 때 처리',
         why: '적용은 확인됐지만 보상 통제가 있어 당장은 아닙니다.'},
  'P3': {label: '확인·관찰', plain: '확인하거나 지켜보기',
         why: '후보이거나 정보가 부족하거나 도달성이 낮습니다.'},
  'P4': {label: '종결', plain: '종결해도 됩니다',
         why: '비영향·수정 확인이거나 승인된 위험 수용입니다.'},
};

/** 표 18 식별 사다리 — 'Composite' 같은 낱말을 그대로 두지 않는다. */
export const IDENTITY: Record<string, string> = {
  Exact: '주문번호까지 똑같습니다',
  Deterministic: '제조사와 모델이 정확히 맞습니다',
  Composite: '제품군은 맞는데 정확한 모델을 아직 모릅니다',
  Fuzzy: '이름이 비슷해서 추정한 것입니다 — 사람이 확인해야 합니다',
  Inferred: '가능성만 있습니다',
};

/** 표 23 강제 상황 규칙 — 화면에는 코드 대신 이 문장을 쓴다. */
export const RULES: Record<string, string> = {
  H01: '실제 공격에 쓰이고 있는 취약점인데, 밖에서 이 장비까지 길이 열려 있습니다',
  H02: '비밀번호 없이 원격에서 이 장비의 값을 바꿀 수 있고, 그 길이 중요한 설비까지 닿습니다',
  H03: '제조사가 가장 위험하다고 매긴 결함이고, 사람이 다칠 수 있는 설비이며, 사무망 쪽에서 닿습니다',
  H04: '제조사 지원이 끝난 장비가 밖에서 들어오는 통로에 있는데, 버전도 모릅니다',
  H05: '출처마다 말이 다른데, 틀렸을 때 사람이 다칠 수 있는 설비입니다',
};

/** 표 8 식별 완성도. */
export const LEVEL: Record<string, string> = {
  L0: '장치 종류만',
  L1: '제조사까지',
  L2: '정확한 모델까지',
  L3: '펌웨어 버전까지',
  L4: '망 구성까지',
  L5: '공정·정비 조건까지',
};

/** 구성요소 종류 (부록 C). `controller_firmware` 를 그대로 보여주지 않는다. */
export const COMPONENT: Record<string, string> = {
  controller_firmware: '제어기 펌웨어',
  cpu_firmware: 'CPU 펌웨어',
  comm_module_firmware: '통신 모듈 펌웨어',
  os: '운영체제',
  runtime: '런타임',
  web_server: '웹 서버',
  database: '데이터베이스',
  application: '응용 프로그램',
  hmi_software: 'HMI 소프트웨어',
  engineering_software: '엔지니어링 소프트웨어',
};
export const componentText = (k: string) =>
  COMPONENT[k] ?? k.replace(/_/g, ' ');

/** 값이 없다 = 아직 모른다. 이 제품에서 '없음' 과 '모름' 은 같은 칸에 오지 않는다.
 *  빈칸이나 대시로 두면 '해당 없음' 으로 읽힌다 — 불변 규칙 2 가 막는 바로 그 붕괴다. */
export const UNKNOWN = '미상';

/** 장치 종류. 판정에는 쓰이지 않고 목록 필터와 라벨에만 쓰인다.
 *  제품명이 종류를 말하지 않으면 `unknown` 이고, 그건 정직한 답이다. */
export const ASSET_TYPE: Record<string, string> = {
  unknown: '미상',
  PLC: 'PLC (제어기)',
  RTU: 'RTU (원격 단말)',
  HMI: 'HMI (조작 화면)',
  Drive: '드라이브·인버터',
  NetworkDevice: '네트워크 장비',
  Camera: '카메라',
  Software: '소프트웨어',
  ProtectionRelay: '보호 계전기',
  EVCharger: '충전기',
  AccessControl: '출입 통제',
  Sensor: '센서·계측',
  WebService: '웹 서비스',
};
export const typeText = (k: string | null | undefined) =>
  (k ? ASSET_TYPE[k] ?? k : UNKNOWN);

/** 수명주기 (부록 C). H04 의 전제라 정확히 보여야 한다. */
export const LIFECYCLE: Record<string, string> = {
  supported: '지원 중',
  end_of_life: '지원 종료',
  end_of_sale: '판매 종료',
  end_of_support: '지원 종료',
  unknown: UNKNOWN,
};
export const lifecycleText = (k: string | null | undefined) =>
  (k ? LIFECYCLE[k] ?? k : UNKNOWN);

/** 강제규칙이 확인하는 전제조건 — 화면용 이름.
 *
 * 엔진은 `유효 경로` 같은 짧은 식별자를 쓴다 (규칙표·테스트·근거 기록이 그 이름을
 * 쓴다). 화면에는 **무엇을 확인해야 하는지가 그대로 읽히는 문장**을 쓴다.
 */
export const PRECONDITION: Record<string, string> = {
  '적용성': '이 취약점이 이 장비에 해당하는지',
  '실제 악용(KEV)': '실제로 공격에 쓰이고 있는지',
  '유효 경로': '밖에서 이 장비까지 길이 열려 있는지',
  '무인증 원격 쓰기': '비밀번호 없이 원격에서 값을 바꿀 수 있는지',
  '중요 자산 도달': '그 길이 중요한 설비까지 닿는지',
  '외부 상위 Zone 도달': '사무망 쪽에서 닿을 수 있는지',
  '공정 안전 영향': '사람이 다칠 수 있는 설비인지',
  '벤더 Critical': '제조사가 가장 위험하다고 매겼는지',
  '수명주기 종료': '제조사 지원이 끝났는지',
  '원격접속 경계': '밖에서 들어오는 접속 통로인지',
  '버전 미상': '버전을 아직 모르는지',
  '소스 충돌': '출처마다 말이 다른지',
};
export const preconditionText = (k: string) => PRECONDITION[k] ?? k;

/** 색 이외의 구분 수단 (NFR-A11Y-001). 확신도 3축의 글리프. */
export const GLYPH = ['●', '◐', '○'] as const;

export const ruleText = (code: string) => RULES[code] ?? code;
export const identityText = (lv: string | null) => (lv ? IDENTITY[lv] ?? lv : null);

/** 프로토콜 → 사람 말 (ADR-040).
 *
 * `s7comm` 은 이 분야 사람이 아니면 아무 뜻이 없다. 엔진 이름(`exposure.py` 의
 * `CONTROL_PROTOCOLS`)은 그대로 두고 화면용 이름만 여기 둔다 — `PRECONDITION`
 * 과 같은 방식이다 (ADR-035).
 *
 * `control: true` 는 **공정 제어 명령을 실어 나르는** 것이다. 이게 평문으로
 * 열려 있으면 노출 위험이 된다.
 */
export interface Proto { label: string; what: string; control?: boolean }

export const PROTOCOL: Record<string, Proto> = {
  modbus_tcp: {label: 'Modbus TCP', what: '가장 널리 쓰이는 산업 제어 통신', control: true},
  modbus: {label: 'Modbus', what: '산업 제어 통신', control: true},
  s7comm: {label: 'Siemens S7', what: 'Siemens PLC 를 읽고 쓰는 통신', control: true},
  s7comm_plus: {label: 'Siemens S7 (신형)', what: 'Siemens 최신 PLC 통신', control: true},
  dnp3: {label: 'DNP3', what: '전력·수처리 원격 감시 제어', control: true},
  iec104: {label: 'IEC 104', what: '전력 계통 원격 감시 제어', control: true},
  iec61850_mms: {label: 'IEC 61850 MMS', what: '변전소 자동화 통신', control: true},
  iec61850_goose: {label: 'IEC 61850 GOOSE', what: '변전소 보호 계전 신호', control: true},
  ethernet_ip: {label: 'EtherNet/IP', what: 'Rockwell 계열 제어 통신', control: true},
  ethernet_ip_io: {label: 'EtherNet/IP 실시간 I/O', what: '주기적 입출력 전송', control: true},
  cip: {label: 'CIP', what: 'EtherNet/IP 가 싣고 다니는 제어 명령', control: true},
  profinet: {label: 'PROFINET', what: 'Siemens 계열 현장 기기 제어', control: true},
  profinet_io: {label: 'PROFINET IO', what: 'Siemens 계열 입출력 전송', control: true},
  profibus: {label: 'PROFIBUS', what: '현장 기기 직렬 제어', control: true},
  bacnet: {label: 'BACnet', what: '건물 설비(공조·조명) 제어', control: true},
  bacnet_ip: {label: 'BACnet/IP', what: '건물 설비 제어', control: true},
  opc_ua: {label: 'OPC UA', what: '설비와 상위 시스템 사이 표준 데이터 교환', control: true},
  opc_da: {label: 'OPC DA (구형)', what: '윈도우 기반 구형 설비 데이터 교환', control: true},
  ethercat: {label: 'EtherCAT', what: '고속 모션 제어', control: true},
  powerlink: {label: 'POWERLINK', what: '고속 모션 제어', control: true},
  sercos: {label: 'SERCOS', what: '서보·모션 제어', control: true},
  modbus_rtu: {label: 'Modbus RTU', what: '직렬 방식 산업 제어 통신', control: true},
  fl_net: {label: 'FL-net', what: '일본 공장 자동화 제어망', control: true},
  cspv4: {label: 'KV CSPv4', what: 'Keyence PLC 통신', control: true},
  hart_ip: {label: 'HART-IP', what: '계장 기기 설정·진단', control: true},
  fins: {label: 'FINS', what: 'Omron PLC 통신', control: true},
  slmp: {label: 'SLMP', what: 'Mitsubishi PLC 통신', control: true},
  melsec: {label: 'MELSEC', what: 'Mitsubishi PLC 통신', control: true},
  cclink: {label: 'CC-Link', what: 'Mitsubishi 현장 기기 네트워크', control: true},
  // 제어가 아닌 것 — 여기 있다고 노출 위험이 되지는 않는다
  snmp: {label: 'SNMP', what: '장비 상태 조회·관리'},
  ntp: {label: 'NTP', what: '시각 맞추기'},
  dns: {label: 'DNS', what: '이름 조회'},
  dhcp: {label: 'DHCP', what: 'IP 주소 자동 배정'},
  http: {label: 'HTTP', what: '웹 화면 (암호화 없음)'},
  https: {label: 'HTTPS', what: '웹 화면 (암호화됨)'},
  ssh: {label: 'SSH', what: '원격 접속 (암호화됨)'},
  telnet: {label: 'Telnet', what: '원격 접속 (암호화 없음)'},
  ftp: {label: 'FTP', what: '파일 전송 (암호화 없음)'},
  smb: {label: 'SMB', what: '윈도우 파일 공유'},
  rdp: {label: 'RDP', what: '윈도우 원격 데스크톱'},
  vnc: {label: 'VNC', what: '화면 원격 조작'},
};

/** 화면에 쓸 이름. 모르는 프로토콜은 **원문 그대로** 둔다 — 지어내지 않는다. */
export const protocolText = (p: string | null | undefined): string =>
  p ? (PROTOCOL[p]?.label ?? p) : UNKNOWN;

/** 무엇에 쓰는 통신인지 한 마디. 모르면 빈 문자열. */
export const protocolWhat = (p: string | null | undefined): string =>
  (p && PROTOCOL[p]?.what) || '';
