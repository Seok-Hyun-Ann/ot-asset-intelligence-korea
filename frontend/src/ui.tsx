/* 화면 전체가 공유하는 조각들. */
import {useState} from 'react';
import {BUCKET, GLYPH, STATUS, identityText, preconditionText, ruleText}
  from './terms';
import type {Exposure, Finding, QueueScan, Status} from './types';

export const TONE0: Status[] = ['affected_confirmed', 'affected_likely'];
export const TONE2: Status[] = ['not_affected_confirmed', 'fixed'];
export const tone = (s: Status): 0 | 1 | 2 =>
  TONE0.includes(s) ? 0 : TONE2.includes(s) ? 2 : 1;

export const GROUPS: [string, string][] = [
  ['해당함', '조치가 필요합니다'],
  ['판단 보류', '더 알아야 합니다'],
  ['해당 없음', '종결할 수 있습니다'],
];
export const GROUP_OF: Record<Status, 0 | 1 | 2> = {
  affected_confirmed: 0, affected_likely: 0, candidate: 0,
  insufficient_information: 1, conflicting_evidence: 1, stale: 1, no_known_match: 1,
  not_affected_confirmed: 2, fixed: 2,
};

export const Err = ({e}: {e: Error | null}) =>
  e ? <div className="err">{e.message}</div> : null;

export const Spin = ({what = '불러오는 중'}: {what?: string}) =>
  <p className="spin">{what}…</p>;

/** 확신도 계기 — 폭이 곧 건수다. */
export function Band({counts, total, note}:
    {counts: Partial<Record<Status, number>>; total: number; note?: string}) {
  const g: [number, number, number] = [0, 0, 0];
  (Object.entries(counts) as [Status, number][])
    .forEach(([k, n]) => { g[GROUP_OF[k] ?? 1] += n; });
  return (
    <div>
      <div className="band">
        {GROUPS.map(([name, sub], i) => (
          <div key={name} className={`seg sv${i}`} title={sub}>
            <span className="n">{g[i]}</span>
            <span className="l">{GLYPH[i]} {name} · {sub}</span>
          </div>
        ))}
      </div>
      <p className="k">전체 {total}건 — 왼쪽으로 갈수록 해당할 가능성이 높고,
        오른쪽으로 갈수록 확실히 아닙니다.{note ? ' ' + note : ''}</p>
    </div>
  );
}

/** 아직 확인하지 못한 전제들. 규칙마다 겹치므로 중복을 없앤다. */
export function missingOf(f: Finding): string {
  const seen = new Set<string>();
  f.pending.forEach(p => p.missing.forEach(m => seen.add(preconditionText(m))));
  const all = [...seen];
  // 넷을 다 이으면 한 줄이 폭발한다. 셋 이상이면 개수로 말하고 목록은 옆 칸에 둔다.
  if (all.length > 2) return `${all[0]} 등 ${all.length}가지`;
  return all.join(', ');
}

/** 확인해야 할 것 전부 — 옆 칸에 목록으로 편다 */
export function missingList(f: Finding): string[] {
  const seen = new Set<string>();
  f.pending.forEach(p => p.missing.forEach(m => seen.add(preconditionText(m))));
  return [...seen];
}

/** 이 판정을 만든 이유 한 줄. 코드(H02, Composite) 대신 문장을 쓴다. */
export function reasonOf(f: Finding): string {
  if (f.fired_rules.length) return ruleText(f.fired_rules[0]!);
  // 서버의 `question` 은 "유효 경로 을(를) 확인하면 H01 이(가) 발화해…" 처럼
  // 조사 자리표시자와 규칙 코드가 들어 있다. 화면에서는 쓰지 않는다.
  if (f.bucket === 'P?' && f.pending.length) {
    return `${missingOf(f)}만 확인하면 ${f.floor_if_confirmed} 로 올라갑니다`;
  }
  return identityText(f.identity_level) ?? (f.conditions[0] ?? '');
}

/** 지금 이것 하나 — 조치할 수 있는 항목만 온다. `P?` 는 여기 오지 않는다. */
export function FocusCard({f, rank, total, onOpen}:
    {f: Finding; rank: number; total: number; onOpen: () => void}) {
  const b = BUCKET[f.bucket], s = STATUS[f.status];
  return (
    <div className="focus">
      <div className="eyebrow">
        지금 이것 하나
        <span className="of">· 조치 대상 {total}건 중 {rank}번째</span>
      </div>
      <h4>{b.plain}</h4>
      <div className="who">{f.asset_id}</div>
      <p className="because">{reasonOf(f)}</p>
      <p className="detail">{s.plain} — {s.why}</p>
      <div className="facts">
        <span className="fact">{f.bucket} {b.label}</span>
        <span className="fact">{s.label}</span>
        {f.kev_cves.length > 0 &&
          <span className="fact kev">실제 악용 사례 있음 · {f.kev_cves[0]}</span>}
        {f.max_cvss != null && <span className="fact">CVSS {f.max_cvss}</span>}
        {f.n_cves > 0 && <span className="fact">CVE {f.n_cves}건</span>}
      </div>
      <div className="btnrow">
        <button onClick={onOpen}>이 자산 열기 →</button>
      </div>
    </div>
  );
}

/** 확인만 하면 등급이 오르는 것들 — `P?` 전용. 막힌 것이지 낮은 게 아니다.
 *
 * 우선순위는 (자산 × 권고문) 쌍마다 평가되는데, 막고 있는 전제는 자산의 성질인
 * 경우가 많다 (도달성·수명주기). 그래서 규모가 커지면 같은 문장이 권고문 수만큼
 * 반복된다. **감추지 않고 한 줄로 묶어 몇 건인지 함께 적는다.**
 */
const BLOCKED_PAGE = 40;

interface Group { key: string; f: Finding; n: number; score: number; }

function groupBlocked(items: Finding[]): Group[] {
  const by = new Map<string, Group>();
  items.forEach(f => {
    const key = `${f.asset_id}|${missingOf(f)}|${f.floor_if_confirmed}`;
    const g = by.get(key);
    if (g) {
      g.n += 1;
      g.score = Math.max(g.score, f.lens_score);
    } else {
      by.set(key, {key, f, n: 1, score: f.lens_score});
    }
  });
  return [...by.values()].sort((a, b) => b.score - a.score);
}

export function BlockedPanel({items, onOpen}:
    {items: Finding[]; onOpen: (f: Finding) => void}) {
  if (!items.length) return null;
  const groups = groupBlocked(items);
  return (
    <div className="card">
      <h3 style={{margin: '0 0 4px'}}>
        확인하면 등급이 오르는 것 {groups.length.toLocaleString()}건
        {groups.length !== items.length &&
          <span className="k" style={{fontWeight: 400}}>
            {' '}· 권고문 {items.length.toLocaleString()}건에 걸쳐 있습니다
          </span>}
      </h3>
      <p className="k" style={{margin: '0 0 12px'}}>
        낮은 우선순위가 아닙니다. 전제 하나를 몰라 판단이 막혀 있을 뿐입니다.
      </p>
      {groups.slice(0, BLOCKED_PAGE).map(({key, f, n}) => (
        <div key={key} className="rec"
             onClick={() => onOpen(f)} tabIndex={0}
             onKeyDown={e => e.key === 'Enter' && onOpen(f)}>
          <div className="mark t1">확인<small>{f.floor_if_confirmed} 후보</small></div>
          <div>
            <div className="tag">{f.asset_id}
              {n > 1 && <span className="k"> · 권고문 {n}건에서 동일</span>}</div>
            <div className="v"><span className="g">◐</span>{missingOf(f)}를 확인하면 됩니다</div>
            <div className="say">확인되면 {ruleText(f.pending[0]?.rule ?? '')}</div>
          </div>
          <div className="why">
            <span className="hi">확인되면 {f.floor_if_confirmed}</span>
            {missingList(f).length > 2 && (
              <div className="s2">{missingList(f).map(m => (
                <div key={m}>· {m}</div>))}</div>)}
            {f.kev_cves.length > 0 && <div className="s2">실제 악용 사례 있음</div>}
            {f.max_cvss != null && <div className="s2">CVSS {f.max_cvss}</div>}
          </div>
          <div className="wt">{f.lens_score}</div>
        </div>
      ))}
      {groups.length > BLOCKED_PAGE && (
        <p className="k" style={{marginTop: 10}}>
          {groups.length.toLocaleString()}건 중 {BLOCKED_PAGE}건만 표시합니다.
        </p>)}
    </div>
  );
}

/** 왜 이 등급인지를 **이 항목에 대해** 말한다. 일반론이 아니다. */
function whyThisBucket(f: Finding): string {
  const b = BUCKET[f.bucket];
  if (f.bucket === 'P?') {
    const what = missingOf(f);
    return `이미 “${STATUS[f.status].plain}” 로 확정됐습니다. 그런데 ${what}를 몰라서 ` +
      `등급이 여기서 멈췄습니다. 그것만 확인하면 ${f.floor_if_confirmed} 로 올라갑니다. ` +
      `모르는 것을 “해당 없음” 으로 처리하지 않기 때문에 기다리는 중입니다.`;
  }
  if (f.status === 'no_known_match') {
    return '이 권고문이 다루는 제품 목록에 이 장비가 없습니다. 그래서 더 볼 것이 ' +
      '없습니다 — 안전하다는 뜻이 아니라, 이 문서가 이 장비 이야기가 아니라는 뜻입니다.';
  }
  if (f.fired_rules.length) {
    return `${ruleText(f.fired_rules[0]!)} — 그래서 등급이 올라갔습니다. ${b.why}`;
  }
  return b.why;
}

/** 배지를 누르면 펼쳐지는 설명. 눈이 이미 가 있는 곳에 답을 둔다. */
function WhyPanel({f}: {f: Finding}) {
  const b = BUCKET[f.bucket], s = STATUS[f.status];
  const ident = identityText(f.identity_level);
  return (
    <div className="whybox">
      <dl>
        <dt>{f.bucket} 는 무슨 뜻인가</dt>
        <dd>{b.plain}. {b.why}</dd>
        <dt>왜 이 항목이 {f.bucket} 인가</dt>
        <dd>{whyThisBucket(f)}</dd>
        <dt>이 장비가 맞다고 어떻게 판단했나</dt>
        <dd>{ident ?? '이 권고문의 제품 목록과 맞춰보지 못했습니다.'}</dd>
        {s.todo && <><dt>지금 뭘 하면 되나</dt><dd>{s.todo}</dd></>}
      </dl>
      <p className="k">
        판정 시점 {f.as_of} · 규칙 {f.rule_version}
        {f.advisory_sha256 && ` · 원문 ${f.advisory_sha256.slice(0, 12)}…`}
      </p>
    </div>
  );
}

export function FindingRow({f, onOpen, selected}:
    {f: Finding; onOpen?: () => void; selected?: boolean}) {
  const t = tone(f.status);
  const [why, setWhy] = useState(false);
  const b = BUCKET[f.bucket], s = STATUS[f.status];
  return (
    <div className={`rec${selected ? ' on' : ''}${why ? ' open' : ''}`} onClick={onOpen}
         tabIndex={0} onKeyDown={e => e.key === 'Enter' && onOpen?.()}>
      <button className={`mark t${t} ask`} aria-expanded={why}
              title={`${f.bucket} 가 무슨 뜻인지, 왜 이 등급인지 보기`}
              onClick={e => { e.stopPropagation(); setWhy(!why); }}>
        {f.bucket}
        <small>{b.label}</small>
        <span className="q">{why ? '설명 닫기' : '이게 무슨 뜻인가요?'}</span>
      </button>
      <div>
        <div className="tag">{f.asset_id ?? f.advisory_id}</div>
        <div className={`v t${t}`}><span className="g">{GLYPH[t]}</span>{s.plain}</div>
        <div className="say">{reasonOf(f)}</div>
        {s.todo && <div className="todo">→ {s.todo}</div>}
      </div>
      <div className="why">
        <span>{s.why}</span>
        {f.kev_cves.length > 0 &&
          <div className="s2 t0">실제 악용 사례 {f.kev_cves.length}건</div>}
        {f.fired_rules.includes('H02') && (
          <div className="s2">이 장비가 암호 없이 명령을 받는 것이 등급을 올렸습니다 —
            아래 <b>장비가 놓인 방식</b>에 따로 있습니다</div>)}
        {f.max_cvss != null && f.n_cves > 0 &&
          <div className="s2">CVE {f.n_cves}건 · 최고 CVSS {f.max_cvss}</div>}
        {f.pending.length > 0 &&
          <div className="s2">{missingOf(f)} 확인하면 {f.floor_if_confirmed}</div>}
      </div>
      <div className="wt">{f.lens_score}</div>
      {why && <WhyPanel f={f}/>}
    </div>
  );
}

/** 대조 규모. 큰 수가 '안전' 으로 읽히지 않게 문장으로 쓴다. */
export function Scale({s}: {s?: QueueScan}) {
  if (!s) return null;
  const n = (v: number) => v.toLocaleString();
  return (
    <p className="k" style={{marginTop: 10}}>
      자산 {n(s.assets)}개 × 권고문 {n(s.advisories)}건 = {n(s.pairs)}쌍을 대조했습니다.
      그중 {n(s.excluded)}쌍은 제조사·모델이 달라 대상이 아니었고,
      {' '}{n(s.evaluated)}쌍을 실제로 판정해 {n(s.findings)}건이 남았습니다
      {s.seconds ? ` (${s.seconds}초)` : ''}.
      {' '}대상이 아니라는 것은 <b>안전하다는 뜻이 아닙니다</b> — 이 범위의 권고문에
      해당 제품이 없다는 뜻입니다.
    </p>
  );
}


/** 표 4 의 노출·구성 위험 한 줄.
 *
 * CVE 와 나란히 놓되 **다른 것**임을 말한다 — CVE 는 고칠 수 있고 이건 대개 못 고친다.
 * 그래서 '패치' 가 아니라 '주변을 막는' 답이 붙는다.
 */
export function ExposureRow({e, onOpen}: {e: Exposure; onOpen?: () => void}) {
  const t = e.bucket === 'P3' || e.bucket === 'P4' ? 1 : 0;
  return (
    <div className="rec exposure" onClick={onOpen} tabIndex={0}
         onKeyDown={ev => ev.key === 'Enter' && onOpen?.()}>
      <div className={`mark t${t}`}>{e.bucket}
        <small>{e.kind === 'exposure' ? '통신 방식' : '설정'}</small></div>
      <div>
        <div className="tag">{e.asset_id}
          {e.also_raises_cve && <span className="k"> · 위 취약점 등급도 이것 때문입니다</span>}
        </div>
        <div className={`v t${t}`}><span className="g">●</span>{e.title}</div>
        <div className="say">{e.why}</div>
        <div className="todo">→ {e.what_to_do}</div>
      </div>
      <div className="why">
        {e.checks.map(c => (
          <div key={c.name}>
            {c.value === 'true' ? '○ ' : c.value === 'false' ? '× ' : '? '}
            {c.name}
          </div>))}
        {e.floor_if_confirmed && (
          <div className="s2">확인되면 {e.floor_if_confirmed}</div>)}
      </div>
      <div className="wt k">{e.cwe ?? ''}</div>
    </div>
  );
}
