/* 서버 응답의 타입. 표 29 API 와 1:1 로 맞춘다.
 * 판정 규칙은 서버에만 있다 — 여기서 다시 쓰지 않고 모양만 선언한다. */

export type Status =
  | 'affected_confirmed' | 'affected_likely' | 'candidate'
  | 'insufficient_information' | 'conflicting_evidence' | 'stale' | 'no_known_match'
  | 'not_affected_confirmed' | 'fixed';

export type Bucket = 'P0' | 'P?' | 'P1' | 'P2' | 'P3' | 'P4';
export type EdgeState = 'observed' | 'inferred' | 'unknown' | 'settled';

export interface Pending {
  rule: string;
  floor: Bucket;
  missing: string[];
  question: string;
}

export interface Finding {
  advisory_id: string;
  advisory_title: string;
  publisher: string;
  status: Status;
  phrase: string;
  identity_level: string | null;
  identity_confidence: number;
  bucket: Bucket;
  bucket_phrase: string;
  floor_if_confirmed: Bucket | null;
  fired_rules: string[];
  pending: Pending[];
  rationale: string[];
  conditions: string[];
  fields: {matched: string[]; mismatched: string[]; missing: string[]};
  next_question: string | null;
  cves: string[];
  n_cves: number;
  kev_cves: string[];
  max_cvss: number | null;
  cvss_vector: string | null;
  raw_expression: string | null;
  advisory_sha256: string;
  input_hash: string;
  as_of: string;
  rule_version: string;
  policy_version: string;
  lens_score: number;
  /** /api/actions 에서만 채워진다 */
  asset_id?: string;
  zone?: string | null;
  factory?: string | null;
  level?: string;
}

/** 표 4 의 노출·구성 위험. CVE 와 달리 권고문이 없어도 존재한다. */
export interface Exposure {
  kind: string;
  code: string;
  asset_id: string;
  zone: string | null;
  factory: string | null;
  level: string;
  title: string;
  why: string;
  what_to_do: string;
  bucket: Bucket;
  floor_if_confirmed: Bucket | null;
  checks: {name: string; value: string; evidence: string}[];
  missing: string[];
  evidence: string[];
  cwe: string | null;
  also_raises_cve: boolean;
}
export interface ExposureResp {
  items: Exposure[];
  counts: Record<string, number>;
  questions: {asset_id: string; field: string; ask: string; why: string}[];
  total_questions: number;
}

export interface Question {
  field: string;
  label: string;
  help: string;
  kind: 'text' | 'select' | 'choice' | 'network';
  options: {v: string; t: string}[];
  why: string;
  skippable: boolean;
}

export interface AssetRow {
  asset_id: string;
  asset_type: string;
  factory: string | null;
  zone: string | null;
  level: string;
  vendor: string | null;
  model: string | null;
  firmware: string | null;
  lifecycle: string | null;
  safety: string | null;
  updated_as_of: string;
  /** 합성 자산인가 (fixtures/assets-scale). 실제 인벤토리와 구분한다 */
  synthetic?: boolean;
}

/** 자산의 주소 하나. CISA 자산 인벤토리 고우선 속성 (ADR-042).
 *  값이 아니라 **관측**이라 출처(method)와 시점이 함께 간다. */
export interface NetAddress {
  ip: string | null;
  mac: string | null;
  hostname: string | null;
  vlan: number | null;
  method: string | null;
  observed_at: string | null;
}

/** 대조 규모 — '나머지는 안전' 이 아니라 '나머지는 대상 제품이 아님' 을 말하기 위한 값 */
export interface Scanned {
  total: number; considered: number; excluded: number;
}
export interface QueueScan {
  assets: number; advisories: number; pairs: number; excluded: number;
  evaluated: number; no_match: number; findings: number; seconds: number;
}

/** 수명주기 — 표 13: 제조사가 1차, 현장 기록이 보조 */
export interface LifecycleView {
  state: string;
  vendor_confirmed: boolean;
  conflicting: boolean;
  reason: string;
  claims: {state: string; source: string; role: string; basis: string;
           structured: boolean}[];
}

export interface Facets {
  factory: string[]; zone: string[]; asset_type: string[]; level: string[];
}

export interface Ctx {
  as_of: string;
  advisories: {id: string; title: string; publisher: string; products: number; cves: number}[];
  kev: string | null;
  attack: string | null;
  topology: string | null;
  topology_synthetic: boolean;
  topology_warning: string | null;
  policy: string;
  lens_presets: Record<string, Record<string, number>>;
  buckets: Record<string, string>;
  bucket_order: Record<string, number>;
  phrases: Record<string, string>;
  assets: number;
  /** 그중 예시 데이터. assets 와 같으면 사용자의 실제 장비가 하나도 없다. */
  assets_demo: number;
  authenticated: boolean;
  backend: string;
}

export interface MindNode {
  id: string; label: string; kind: string; state?: EdgeState; detail?: string;
}
export interface MindEdge { source: string; target: string; state: EdgeState; }
export interface MindMap { nodes: MindNode[]; edges: MindEdge[]; legend: Record<string, string>; }

export interface Hop {
  src: string; dst: string; label: string; state: EdgeState; caps: string[];
}
export interface AttackPath {
  status: 'confirmed' | 'inferred' | 'unknown';
  confidence: number; nodes: string[]; edges: string[];
  weakest: string | null; hops: Hop[];
}
export interface PathsResp {
  available: boolean; reason?: string; node?: string; label?: string; warning?: string;
  graph?: {
    nodes: {id: string; label: string; zone: string; level: number; type: string;
            entry: boolean; critical: boolean}[];
    edges: {id: string; source: string; target: string; label: string;
            state: EdgeState; techniques: string[]}[];
  };
  paths?: AttackPath[];
  blocks?: {edge: string; cut: number; legit: number; remaining: number}[];
}

export interface ImportReport {
  rows: number; created: number; duplicates: number; errors: number;
  unmapped: string[]; mapping: Record<string, string>; sanitized: number;
  applied: boolean;
  preview: {line: number; asset_id: string | null; action: string;
            message: string; asset: unknown}[];
}

/** 출처 대조 — 같은 취약점을 말하는 권고문 묶음 */
export interface SourceGroup {
  id: number;
  publishers: string[];
  advisories: string[];
  n_advisories: number;
  n_cves: number;
  cves_head: string[];
  n_products: number;
  n_conflict: number;
  n_multivalued: number;
  n_disjoint: number;
  n_undecidable: number;
  cvss: {value: unknown; source: string; role: string; conflicting: boolean} | null;
}
export interface GroupDetail extends SourceGroup {
  provenance: {advisory_id: string; publisher: string; declared_category: string;
               role: string; role_basis: string; released_at: string | null}[];
  cves: string[];
  products: {key: string; current: string; source: string; role: string; reason: string;
             corroborated: string[]; dissenting: {value: string; source: string}[];
             conflicting: boolean; multivalued: boolean; disjoint: boolean;
             undecidable: boolean;
             disputed: {a: string; a_src: string; b: string; b_src: string}[]}[];
}
export interface EvidenceResp {
  groups: SourceGroup[];
  totals: {groups: number; advisories: number; conflicts: number;
           multivalued: number; disjoint: number; undecidable: number;
           products: number; with_conflict: number};
}

export interface OpsResp {
  sources: {
    name: string; count: number; unit: string; detail: string; ok: boolean;
    /** 카탈로그 크기와 별개로 **우리 범위에서 실제로 쓰이는 수** */
    used: number; used_label: string; extra?: string | null;
  }[];
  sweep: {state: string; done: number; total: number; pairs: number;
          excluded: number; evaluated: number; findings: number; seconds: number;
          kev_findings?: number};
  versions: {policy: string; parser: string};
  assets: number;
  audit: {id: number; as_of: string; action: string; actor: string;
          authenticated: boolean; subject: string | null}[];
  authenticated: boolean;
  backend: string;
}
