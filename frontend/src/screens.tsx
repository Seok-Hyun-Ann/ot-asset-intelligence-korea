/* 표 25 의 화면 10개. 판정은 전부 서버가 계산하고 여기서는 보여주기만 한다. */
import {useEffect, useMemo, useRef, useState} from 'react';
import cytoscape from 'cytoscape';
import {api, post, useApi} from './api';
import {Band, BlockedPanel, Err, ExposureRow, FindingRow, FocusCard, Scale, Spin,
        tone} from './ui';
import {BUCKET, LEVEL, STATUS, UNKNOWN, componentText, identityText,
        lifecycleText, protocolText, protocolWhat, typeText} from './terms';
import {StartGuide, useStartGuide} from './start';
import type {
  AssetRow, Bucket, Ctx, Facets, Finding, ImportReport, MindMap, OpsResp,
  EvidenceResp, Exposure, ExposureResp, GroupDetail, LifecycleView, PathsResp,
  QueueScan, Question, Scanned, Status,
} from './types';

export interface Route { screen: string; asset?: string; advisory?: string; }
export interface Props { ctx: Ctx; route: Route; go: (s: string, e?: Partial<Route>) => void; }

/* 캔버스에는 CSS 가 닿지 않는다. 색과 글꼴을 여기서 직접 준다. */
/* Cytoscape 는 따옴표가 들어간 font-family 목록을 거부한다 (콘솔에 invalid 경고).
   캔버스 텍스트라 CSS 가 닿지 않으므로 여기서 따옴표 없이 준다. */
const FONT = "Pretendard Variable, Pretendard, Malgun Gothic, sans-serif";
const C = {
  deck: '#131A22', deck2: '#1B242E', rule: '#31404F',
  txt: '#DCE4EE', dim: '#93A4B6', faint: '#6E8095',
  act: '#FF6A5E', hold: '#FFB627', clear: '#34C79B', signal: '#5B9CFF',
};
const STATE_COLOR: Record<string, string> = {
  observed: C.signal, inferred: C.hold, unknown: C.faint, settled: C.clear,
};

/** Cytoscape 인스턴스를 컴포넌트 수명에 맞춰 만들고 지운다. */
function useCytoscape(build: (el: HTMLDivElement) => cytoscape.Core | null, deps: unknown[]) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const cy = build(ref.current);
    return () => {
      (cy as unknown as {_offResize?: () => void})?._offResize?.();
      cy?.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return ref;
}

/** 자산을 아직 고르지 않은 화면에서 쓰는 고르개.
 *
 * 전에는 "자산을 먼저 고르세요" 한 줄이었다. 열 개 메뉴 중 넷이 그렇게 끝났다 —
 * 처음 온 사람에게는 그게 곧 막다른 길이다. 그 자리에서 고를 수 있게 한다. */
function PickAsset({go, to, title, lead}:
    {go: Props['go']; to: string; title: string; lead: string}) {
  const [q, setQ] = useState('');
  const {data} = useApi<{items: AssetRow[]; total: number}>(
    '/api/assets?limit=12' + (q ? '&q=' + encodeURIComponent(q) : ''), [q]);
  const rows = data?.items ?? [];
  return (
    <div>
      <h2>{title}</h2>
      <p className="lead">{lead}</p>
      <div className="f" style={{maxWidth: 460}}>
        <label htmlFor="pick">어느 자산을 볼까요</label>
        <input id="pick" type="search" value={q} autoFocus
               placeholder="자산 id · 모델 · 제조사로 찾기"
               onChange={e => setQ(e.target.value)}/>
      </div>
      {!data ? <Spin/> : rows.length ? (
        <div className="scroll"><table className="assets">
          <thead><tr><th>자산</th><th>완성도</th><th>제조사</th><th>모델</th></tr></thead>
          <tbody>{rows.map(a => (
            <tr key={a.asset_id} className="click"
                onClick={() => go(to, {asset: a.asset_id})}>
              <td className="m">{a.asset_id}</td>
              <td><span className="pill lv" title={LEVEL[a.level] ?? ''}>{a.level}</span></td>
              <td>{a.vendor ?? <span className="k">{UNKNOWN}</span>}</td>
              <td>{a.model ?? <span className="k">{UNKNOWN}</span>}</td>
            </tr>))}</tbody></table></div>
      ) : <p className="empty">찾는 자산이 없습니다. 조건을 지우거나
            <b> 자산 가져오기</b>에서 등록하세요.</p>}
      {data && data.total > rows.length &&
        <p className="k" style={{marginTop: 10}}>
          {data.total.toLocaleString()}건 중 {rows.length}건을 보여줍니다 —
          이름을 입력해 좁히세요.</p>}
    </div>
  );
}

/* ── 1. 온보딩·가져오기 ───────────────────────────────────── */
/** 엔지니어링 도구에서 내보낸 파일을 읽는다. 장비에는 붙지 않는다. */
function ProjectFile() {
  const [scan, setScan] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState<string | null>(null);
  const [raw, setRaw] = useState<string | null>(null);
  const [pick, setPick] = useState<Set<string>>(new Set());
  const [when, setWhen] = useState<number | null>(null);

  const read = (f: File) => {
    setErr(null); setScan(null); setName(f.name);
    const r = new FileReader();
    r.onload = () => {
      const b64 = String(r.result).split(',')[1] ?? '';
      setRaw(b64);
      // 파일이 **언제 저장됐는지**를 함께 보낸다. 서버가 임시 파일의 시각을 읽으면
      // 2023년 프로젝트가 오늘 관측된 것으로 기록된다 (ADR-038).
      setWhen(f.lastModified || null);
      void send(f.name, b64, false, undefined, f.lastModified || null);
    };
    r.onerror = () => setErr(new Error('파일을 읽지 못했습니다'));
    r.readAsDataURL(f);
  };

  const send = async (filename: string, b64: string, apply: boolean,
                      picked?: string[], ms?: number | null) => {
    setBusy(true); setErr(null);
    try {
      const d: any = await post('/api/assets/project-file',
        {filename, content_base64: b64, apply, pick: picked,
         last_modified_ms: ms ?? when});
      setScan(d);
      if (!apply) {
        setPick(new Set(d.devices.filter((x: any) => x.action === 'create')
          .map((x: any) => x.asset_id)));
      }
    } catch (e) { setErr(e as Error); }
    finally { setBusy(false); }
  };

  const toggle = (id: string) => {
    const n = new Set(pick);
    if (n.has(id)) n.delete(id); else n.add(id);
    setPick(n);
  };
  const newOnes = scan ? scan.devices.filter((x: any) => x.action === 'create') : [];

  return (
    <div>
      <div className="f">
        <label htmlFor="pf">엔지니어링 도구에서 내보낸 파일</label>
        <input id="pf" type="file" accept=".aml,.xml,.amlx,.caex,.zip,.zap16,.zap17,.zap18,.zap19"
               onChange={e => { const f = e.target.files?.[0]; if (f) read(f); }}/>
      </div>
      <p className="k">TIA Portal 은 <b>AutomationML(.aml)</b> 로, 다른 도구는 XML 로
        내보내면 읽을 수 있습니다. 도구의 독자 형식(.ap18 · .gx3)은 내부 구조가
        공개되어 있지 않아 읽지 못합니다 — 그럴 때는 그렇게 말해 드립니다.
        <b> 장비에는 접속하지 않습니다.</b> 주신 파일만 읽습니다.</p>
      <Err e={err}/>
      {busy && <Spin what="파일을 읽는 중"/>}
      {scan && (
        <div>
          <div className={`callout ${newOnes.length ? '' : 'hot'}`}>
            <span className="big">{newOnes.length
              ? `알아본 장비 ${scan.devices.length}대 — 이 중 ${newOnes.length}대가 새 자산입니다`
              : '아는 제품을 찾지 못했습니다'}</span>
            {scan.filename} · 원문 해시 {scan.sha256.slice(0, 12)}…
            {scan.members_read > 1 && ` · 파일 ${scan.members_read}개`}
            {scan.file_mtime && ` · 이 파일이 저장된 때 ${scan.file_mtime.slice(0, 10)}`}
            {` · 권고문에서 만든 목록 ${scan.vocabulary.order_numbers.toLocaleString()}개와 맞춰봤습니다`}
          </div>
          {scan.warnings.map((w: string, i: number) =>
            <p key={i} className="k">{w}</p>)}
          {scan.refused.length > 0 && (
            <p className="k">안전하지 않아 읽지 않은 파일 {scan.refused.length}개:{' '}
              {scan.refused.slice(0, 3).join(' · ')}</p>)}
          {scan.devices.length > 0 && (
            <>
              <div className="scroll" style={{marginTop: 12}}>
                <table><thead><tr>
                  <th></th><th>이름</th><th>주문번호</th><th>모델</th><th>제조사</th>
                  <th>펌웨어(설정값)</th><th>어디서</th><th></th>
                </tr></thead>
                {/* 키는 유일한 asset_id 다. 같은 모델 5대의 키가 같으면 체크박스
                    하나가 다섯 개를 한꺼번에 켜고, React 가 행을 섞는다. */}
                <tbody>{scan.devices.map((d: any) => (
                  <tr key={d.asset_id}>
                    <td>{d.action === 'create'
                      ? <input type="checkbox" checked={pick.has(d.asset_id)}
                               onChange={() => toggle(d.asset_id)}/>
                      : <span className="k">이미 있음</span>}</td>
                    <td>{d.name
                      ? <span className="m">{d.name}</span>
                      : <span className="k">이름 없음</span>}
                      {d.same_model_count > 1 && <div className="k">
                        같은 모델 {d.same_model_count}대 — 이름으로 구분</div>}</td>
                    <td className="m">{d.order_number}</td>
                    <td>{d.model || UNKNOWN}</td>
                    <td>{d.vendor || UNKNOWN}</td>
                    <td className="m">{d.ambiguous
                      ? <span className="k">여럿({d.version_candidates.join(', ')}) — 고르지 않음</span>
                      : (d.version || UNKNOWN)}</td>
                    <td className="k">{d.member || scan.filename}</td>
                    <td className="k">{d.path.split('/').slice(-2).join('/')}</td>
                  </tr>))}</tbody></table>
              </div>
              <div className="callout">
                <span className="big">펌웨어는 <b>설정값</b>입니다</span>
                {scan.version_caveat.replace(/\*\*/g, '')}
              </div>
              <div className="btnrow">
                <button disabled={busy || !pick.size || scan.applied}
                        onClick={() => raw && name
                          && send(name, raw, true, [...pick])}>
                  {scan.applied
                    ? `${scan.created}대를 등록했습니다`
                    : `고른 ${pick.size}대 등록`}</button>
                {!scan.applied && <span className="k">
                  아직 아무것도 쓰지 않았습니다.</span>}
              </div>
            </>)}
        </div>)}
    </div>
  );
}

/** 캡처에서 토폴로지. 장비에 붙지 않고, 주신 파일만 읽습니다. */
function CaptureFile() {
  const [scan, setScan] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);

  const read = (f: File) => {
    setErr(null); setScan(null); setBusy(true);
    const r = new FileReader();
    r.onload = async () => {
      try {
        setScan(await post('/api/topology/capture', {
          filename: f.name, content_base64: String(r.result).split(',')[1] ?? '',
        }));
      } catch (e) { setErr(e as Error); }
      finally { setBusy(false); }
    };
    r.onerror = () => { setErr(new Error('파일을 읽지 못했습니다')); setBusy(false); };
    r.readAsDataURL(f);
  };

  const save = () => {
    const blob = new Blob([JSON.stringify(scan.topology, null, 1)],
                          {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'topology-from-capture.json';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div>
      <div className="f">
        <label htmlFor="cap">캡처 파일 (pcap · pcapng)</label>
        <input id="cap" type="file" accept=".pcap,.pcapng,.cap"
               onChange={e => { const f = e.target.files?.[0]; if (f) read(f); }}/>
      </div>
      <p className="k">스위치의 미러 포트(SPAN)나 TAP 에서 뜬 캡처를 주세요.
        <b> 장비에 접속하지 않고 망에 아무것도 보내지 않습니다</b> — 주신 파일만 읽습니다.
        캡처에 운영 정보가 들어 있으니 이 화면은 이 컴퓨터 밖으로 나가지 않습니다.</p>
      <Err e={err}/>
      {busy && <Spin what="패킷을 읽는 중"/>}
      {scan && (
        <div>
          <div className={`callout ${scan.edges.length ? '' : 'hot'}`}>
            <span className="big">{scan.edges.length
              ? `장비 ${scan.nodes.length}대 · 실제로 오간 통신 ${scan.edges.length}개`
              : 'IPv4 통신을 찾지 못했습니다'}</span>
            {scan.filename} · 패킷 {scan.packets.toLocaleString()}개 · 원문 해시{' '}
            {scan.sha256.slice(0, 12)}…
            {scan.window[0] && ` · 관측 창 ${scan.window[0].slice(0, 16).replace('T', ' ')} ~ ${(scan.window[1] || '').slice(11, 16)}`}
          </div>
          {scan.warnings.map((w: string, i: number) => <p key={i} className="k">{w}</p>)}
          {Object.keys(scan.counters).length > 0 && (
            <p className="k">못 읽은 패킷:{' '}
              {Object.entries(scan.counters).map(([k, v]) => `${k} ${v}개`).join(' · ')}</p>)}

          {scan.nodes.length > 0 && <>
            <h3>찾은 장비</h3>
            <div className="scroll"><table><thead><tr>
              <th>주소</th><th>제조사(추정)</th><th>종류(추정)</th><th>패킷</th>
            </tr></thead><tbody>{scan.nodes.map((n: any) => (
              <tr key={n.node_id}>
                <td className="m">{n.node_id}</td>
                <td>{n.vendor_hint
                  ? <>{n.vendor_hint} <span className="k">· 랜카드 기준</span></>
                  : (n.evidence?.mac_ambiguous
                      ? <span className="k">라우터 너머라 알 수 없음</span>
                      : UNKNOWN)}</td>
                <td>{n.evidence?.type_hint
                  ? <><b>{n.evidence.type_hint}</b>{' '}
                      <span className="k">인 듯 — {n.evidence.type_hint_reason}</span></>
                  : UNKNOWN}</td>
                <td className="m right">{(n.evidence?.packets ?? 0).toLocaleString()}</td>
              </tr>))}</tbody></table></div>

            <h3>오간 통신</h3>
            <div className="scroll"><table><thead><tr>
              <th>보낸 쪽</th><th>받은 쪽</th><th>무슨 통신</th><th>패킷</th><th></th>
            </tr></thead><tbody>{scan.edges.map((e: any, i: number) => (
              <tr key={i}>
                <td className="m">{e.src}</td>
                <td className="m">{e.dst}</td>
                <td>{e.protocol
                  ? <><b>{protocolText(e.protocol)}</b>{' '}
                      <span className="k">:{e.port}
                        {protocolWhat(e.protocol) && ` · ${protocolWhat(e.protocol)}`}</span></>
                  : <span className="k">미상 :{e.port}
                      {e.evidence.sport_protocol
                        && ` (보낸 쪽 포트는 ${e.evidence.sport_protocol})`}</span>}</td>
                <td className="m right">{e.evidence.packets.toLocaleString()}</td>
                <td className="k">{e.evidence.direction_known ? '' : '방향 미상'}</td>
              </tr>))}</tbody></table></div>

            {/* 여기가 핵심이다. 안 보인 것을 없다고 읽으면 경로 판정이 거짓이 된다. */}
            <div className="callout hot">
              <span className="big">이건 <b>그 시간 동안 보인 것</b>입니다</span>
              {scan.note}
            </div>
            <div className="btnrow">
              <button onClick={save}>토폴로지 파일로 내려받기</button>
              <span className="k">레벨·구역을 채운 뒤 서버를 시작할 때
                <span className="m"> --topology</span> 로 지정하세요.</span>
            </div>
          </>}
        </div>)}
    </div>
  );
}

export function Onboard({ctx, go}: Props) {
  const [csv, setCsv] = useState(
    '자산id,제조사,모델,펌웨어,공장,구역,안전중요도,수명주기\n' +
    'plc-line3-01,Mitsubishi Electric,MELSEC iQ-R Series R08PCPU,48,Factory-A,Cell-L3,high,supported\n' +
    'plc-line3-02,Mitsubishi Electric,MELSEC iQ-R Series R08PCPU,,Factory-A,Cell-L3,high,supported\n');
  const [rep, setRep] = useState<ImportReport | null>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [purged, setPurged] = useState<number | null>(null);
  // 손으로 쓰는 것보다 도구에서 내보낸 파일이 정확하다 — 그쪽을 먼저 보여준다.
  const [how, setHow] = useState<'file' | 'pcap' | 'csv'>('file');
  const run = async (apply: boolean) => {
    setErr(null);
    try { setRep(await post<ImportReport>('/api/assets/import', {csv, apply})); }
    catch (e) { setErr(e as Error); }
  };
  return (
    <div>
      <h2>자산 가져오기</h2>
      <p className="lead">아는 것만 있으면 됩니다. 빈 칸은 미상으로 들어가고, 매핑하지 못한
        열은 버리되 무엇을 버렸는지 알려줍니다. <b>먼저 미리보기</b> 하고 확인한 뒤 적용하세요.</p>
      {ctx.assets_demo > 0 && (
        <div className="callout">
          <span className="big">지금 등록된 {ctx.assets.toLocaleString()}개 중{' '}
            {ctx.assets_demo.toLocaleString()}개는 예시입니다</span>
          제가 만든 예시 자산입니다 — 제조사·제품명·버전 표기는 실제 권고문에서
          가져왔지만 장비 자체는 실재하지 않습니다. 내 장비만 보시려면 지우세요.
          {purged !== null
            ? <div className="btnrow"><span className="k">
                예시 {purged.toLocaleString()}개를 지웠습니다. 행동 큐를 다시 채우려면
                서버를 다시 시작하세요.</span></div>
            : <div className="btnrow">
                <button className="ghost" onClick={async () => {
                  setErr(null);
                  try {
                    const r = await post<{deleted: number}>('/api/assets/purge-demo', {});
                    setPurged(r.deleted);
                  } catch (e) { setErr(e as Error); }
                }}>예시 자산 {ctx.assets_demo.toLocaleString()}개 지우기</button>
              </div>}
        </div>)}
      <div className="btnrow" style={{margin: '4px 0 14px'}}>
        {([['file', '도구에서 내보낸 파일'], ['pcap', '캡처 파일'],
           ['csv', 'CSV 붙여넣기']] as const).map(
          ([k, label]) => (
            <button key={k} className={'pick' + (how === k ? ' on' : '')}
                    onClick={() => setHow(k)}>{label}</button>))}
      </div>
      {how === 'file' && <ProjectFile/>}
      {how === 'pcap' && <CaptureFile/>}
      {how === 'csv' && <div className="split">
        <div>
          <div className="f">
            <label htmlFor="csv">CSV 붙여넣기</label>
            <textarea id="csv" value={csv} onChange={e => setCsv(e.target.value)}/>
          </div>
          <div className="btnrow">
            <button onClick={() => run(false)}>미리보기</button>
            <button className="ghost" disabled={!rep || !rep.created || rep.applied}
                    onClick={() => run(true)}>
              {rep && rep.created ? `${rep.created}건 적용` : '적용'}</button>
          </div>
          <Err e={err}/>
        </div>
        <div>
          {!rep ? <p className="empty">왼쪽에 CSV 를 넣고 미리보기를 누르세요.</p> : (
            <div>
              <div className={`callout ${rep.applied ? 'ok' : ''}`}>
                <span className="big">{rep.applied
                  ? `${rep.created}건을 등록했습니다`
                  : '미리보기 — 아직 아무것도 쓰지 않았습니다'}</span>
                행 {rep.rows} · 생성 대상 {rep.created} · 중복 {rep.duplicates} · 오류 {rep.errors}
                {rep.sanitized > 0 && <><br/>수식 인젝션 무해화 {rep.sanitized}칸</>}
                {rep.unmapped.length > 0 && <><br/>매핑하지 못한 열 (추측하지 않고 버립니다):{' '}
                  <span className="m">{rep.unmapped.join(', ')}</span></>}
              </div>
              {rep.applied && <div className="btnrow">
                <button onClick={() => go('assets')}>자산 목록으로</button></div>}
              <h3>행별 결과</h3>
              <table><thead><tr><th>행</th><th>자산</th><th>결과</th><th>메시지</th></tr></thead>
                <tbody>{rep.preview.map(r => (
                  <tr key={r.line}><td className="m">{r.line}</td>
                    <td className="m">{r.asset_id ?? '—'}</td>
                    <td>{r.action === 'create' ? '생성'
                      : r.action === 'duplicate' ? '중복' : '오류'}</td>
                    <td className="k">{r.message}</td></tr>))}</tbody></table>
              <h3>인식한 열 매핑</h3>
              <table><tbody>{Object.entries(rep.mapping).map(([h, f]) => (
                <tr key={h}><th style={{width: 160}}>{h}</th>
                  <td className="m">{f}</td></tr>))}</tbody></table>
            </div>
          )}
        </div>
      </div>}
    </div>
  );
}

/* ── 2. 행동 큐 ───────────────────────────────────────────── */
const ACTIONABLE: Bucket[] = ['P0', 'P1', 'P2'];

// 큐도 브라우저가 그리는 만큼만 그린다. 정렬이 이미 급한 순서라 위에서 자르는 것이
// 안전하다. 몇 건 중 몇 건인지는 항상 함께 말한다.
const QUEUE_PAGE = 100;

export function Actions({ctx, go}: Props) {
  const [lens, setLens] = useState('default');
  const [topo, setTopo] = useState(true);
  const [bucket, setBucket] = useState<Bucket | null>(null);
  const guide = useStartGuide();
  const {data, error} = useApi<{items: Finding[]; counts: Record<Bucket, number>;
                               scanned: QueueScan}>(
    `/api/actions?lens=${lens}&topology=${topo}`, [lens, topo]);
  const {data: exp} = useApi<ExposureResp>('/api/exposures');

  const all = data?.items ?? [];
  const counts: Partial<Record<Status, number>> = {};
  all.forEach(i => { counts[i.status] = (counts[i.status] ?? 0) + 1; });

  // 초점 카드에는 **지금 할 수 있는 것**만 온다. `P?` 는 조치가 아니라 질문이므로
  // 아래 '확인하면 등급이 오르는 것' 으로 따로 간다 — 막힌 것을 하라고 시키지 않는다.
  const todo = all.filter(f => ACTIONABLE.includes(f.bucket));
  const blocked = all.filter(f => f.bucket === 'P?');
  const focus = todo[0];
  const rest = bucket ? all.filter(f => f.bucket === bucket)
                      : all.filter(f => f !== focus && f.bucket !== 'P?');

  return (
    <div>
      <h2>지금 해야 할 일</h2>
      <p className="lead">위험 점수가 아니라 <b>해야 할 일</b>이 기본 화면입니다.
        맨 위 하나만 처리하면 됩니다. 나머지는 아래에 순서대로 있습니다.</p>
      {/* 등급 표는 접히지 않는다. 사용자가 P? 를 처음 보는 곳이 여기다. */}
      <div className="key">
        {(['P0', 'P?', 'P1', 'P2', 'P3', 'P4'] as Bucket[]).map(k => (
          <span key={k} className={'keyitem' + (k === 'P?' ? ' hi' : '')}
                title={BUCKET[k].why}>
            <b>{k}</b> {BUCKET[k].plain}
          </span>))}
        <span className="k">배지를 누르면 <b>왜 그 등급인지</b> 이 항목에 대해 설명합니다.</span>
      </div>
      <Err e={error}/>
      {guide.open && (
        <StartGuide ctx={ctx} todo={todo.length}
                    blocked={blocked.length} counting={!data}
                    onClose={guide.close} go={go}/>)}
      {!data ? <Spin what="자산과 권고문을 전부 대조하는 중 — 처음 한 번은 시간이 걸립니다"/> : (
        <div>
          {focus
            ? <FocusCard f={focus} rank={1} total={todo.length}
                         onOpen={() => go('asset', {asset: focus.asset_id})}/>
            : <div className="callout ok"><span className="big">지금 당장 할 일은 없습니다</span>
                조치가 필요한 항목이 없습니다. 아래에서 확인할 것들을 보세요.</div>}

          <BlockedPanel items={blocked} onOpen={f => go('asset', {asset: f.asset_id})}/>

          {exp && exp.items.length > 0 && (
            <div className="card">
              <h3 style={{margin: '0 0 4px'}}>
                장비가 놓인 방식 때문에 생기는 위험 {exp.items.length.toLocaleString()}건</h3>
              <p className="k" style={{margin: '0 0 12px'}}>
                위쪽 항목은 <b>고칠 수 있는 결함</b>입니다 — 제조사가 수정본을 냅니다.
                여기 있는 것은 <b>장비를 어떻게 놓았는지</b>의 문제라 펌웨어를 올려도
                없어지지 않습니다. 대신 <b>주변을 막아서</b> 해결합니다.
              </p>
              {exp.items.slice(0, 20).map((e, i) => (
                <ExposureRow key={`${e.asset_id}-${e.code}-${i}`} e={e}
                             onOpen={() => go('asset', {asset: e.asset_id})}/>))}
              {exp.items.length > 20 && (
                <p className="k" style={{marginTop: 10}}>
                  {exp.items.length.toLocaleString()}건 중 20건만 표시합니다.</p>)}
              {exp.total_questions > 0 && (
                <p className="k" style={{marginTop: 10}}>
                  통신 정보를 아직 모르는 장비가 {exp.total_questions.toLocaleString()}대
                  있습니다 — <b>안전하다는 뜻이 아니라 판단할 수 없다는 뜻입니다.</b>
                </p>)}
            </div>)}

          <h3>전체 현황</h3>
          <Band counts={counts} total={all.length}/>
          <Scale s={data.scanned}/>

          <div className="btnrow" style={{marginBottom: 6}}>
            <span className="k" style={{marginRight: 4}}>관점</span>
            {Object.keys(ctx.lens_presets).map(l => (
              <button key={l} className={lens === l ? 'on' : 'ghost'}
                      onClick={() => setLens(l)}>{l}</button>))}
            <button className={topo ? 'on' : 'ghost'} onClick={() => setTopo(!topo)}>
              경로 반영 {topo ? '켬' : '끔'}</button>
            {(Object.keys(data.counts) as Bucket[]).map(b => (
              <button key={b} className={bucket === b ? 'on' : 'ghost'}
                      onClick={() => setBucket(bucket === b ? null : b)}>
                {b} {data.counts[b]}</button>))}
          </div>

          <div style={{marginTop: 14}}>
            {rest.length ? rest.slice(0, QUEUE_PAGE).map((f, i) => (
              <FindingRow key={`${f.asset_id}-${f.advisory_id}-${i}`} f={f}
                          onOpen={() => go('asset', {asset: f.asset_id})}/>
            )) : <p className="empty">이 조건에 해당하는 항목이 없습니다.</p>}
            {rest.length > QUEUE_PAGE && (
              <p className="k" style={{marginTop: 12}}>
                {rest.length.toLocaleString()}건 중 급한 순서로 {QUEUE_PAGE}건만
                표시합니다. 위 등급 단추로 좁혀서 보세요.
              </p>)}
          </div>
          <p className="k" style={{marginTop: 14}}>관점을 바꿔도 조치 등급은 움직이지 않습니다.
            같은 등급 안에서 무엇을 먼저 볼지만 바뀝니다.</p>
        </div>
      )}
    </div>
  );
}

/* ── 3. 자산 목록 ─────────────────────────────────────────── */
type Filters = {q: string} & Record<keyof Facets, string>;

/* 렌더 본문 안에 두면 매 입력마다 컴포넌트 타입이 새로 생겨 select 가 다시 마운트되고
   포커스가 날아간다. 바깥에 둔다. */
function Sel({k, label, f, setF, fac}: {
  k: keyof Facets; label: string; f: Filters;
  setF: (v: Filters) => void; fac: Facets;
}) {
  return (
    <div className="f"><label htmlFor={k}>{label}</label>
      <select id={k} value={f[k]} onChange={e => setF({...f, [k]: e.target.value})}>
        <option value="">전체</option>
        {fac[k].map(v => (
          <option key={v} value={v}>
            {k === 'asset_type' ? typeText(v) : k === 'level' ? `${v} · ${LEVEL[v] ?? ''}` : v}
          </option>))}
      </select></div>
  );
}

const NO_FILTER: Filters = {q: '', factory: '', zone: '', asset_type: '', level: ''};

// 표는 브라우저가 그리는 만큼만 그린다. 1,000행을 한 번에 그리면 화면이 멈춘다.
// 감추는 것이 아니라 **몇 건 중 몇 건인지 항상 함께 말한다**.
const PAGE = 200;

export function AssetList({go}: Props) {
  const [f, setF] = useState<Filters>(NO_FILTER);
  const qs = Object.entries(f).filter(([, v]) => v)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const {data, error} = useApi<{items: AssetRow[]; facets: Facets}>(
    '/api/assets' + (qs ? '?' + qs : ''), [qs]);
  const fac: Facets = data?.facets ?? {factory: [], zone: [], asset_type: [], level: []};
  const sel = {f, setF, fac};
  return (
    <div>
      <h2>자산 목록</h2>
      <p className="lead">식별이 어디까지 채워졌는지가 <b>L0~L5</b> 로 보입니다.
        {Object.entries(LEVEL).map(([k, v], i) =>
          <span key={k}>{i ? ' · ' : ' '}<b>{k}</b> {v}</span>)}
        <br/><b>미상</b>은 빈칸이 아니라 <b>아직 모른다</b>는 뜻입니다 — 없다는 뜻이
        아닙니다. <b>종류 미상</b>은 권고문의 제품명이 장치 종류를 말하지 않아서이고,
        판정에는 쓰이지 않습니다.</p>
      <div className="split3">
        <div className="card">
          <div className="f"><label htmlFor="q">검색</label>
            <input id="q" type="search" value={f.q} placeholder="자산 id · 모델 · 제조사"
                   onChange={e => setF({...f, q: e.target.value})}/></div>
          <Sel k="factory" label="공장" {...sel}/><Sel k="zone" label="구역" {...sel}/>
          <Sel k="asset_type" label="장치 종류" {...sel}/>
          <Sel k="level" label="식별 완성도" {...sel}/>
          <div className="btnrow"><button className="ghost"
            onClick={() => setF(NO_FILTER)}>조건 지우기</button></div>
        </div>
        <div>
          <Err e={error}/>
          {!data ? <Spin/> : (
            <div>
              <p className="k">
                {data.items.length.toLocaleString()}건
                {data.items.length > PAGE &&
                  <> — 위에서 {PAGE}건만 표시합니다. 왼쪽 조건으로 좁히세요.</>}
              </p>
              <div className="scroll"><table className="assets"><thead><tr>
                <th>자산</th><th>완성도</th><th>종류</th><th>제조사</th>
                <th>모델</th><th>펌웨어</th><th>구역</th><th>수명주기</th></tr></thead>
                <tbody>{data.items.slice(0, PAGE).map(a => (
                  <tr key={a.asset_id} className="click"
                      onClick={() => go('asset', {asset: a.asset_id})}>
                    <td className="m">{a.asset_id}
                      {a.synthetic && <span className="pill demo" style={{marginLeft: 6}}
                            title="제가 만든 예시 자산입니다. 실제 장비가 아닙니다.">예시</span>}
                    </td>
                    <td><span className="pill lv" title={LEVEL[a.level] ?? ''}>
                      {a.level}</span></td>
                    <td>{typeText(a.asset_type)}</td>
                    <td>{a.vendor ?? <span className="k">{UNKNOWN}</span>}</td>
                    <td>{a.model
                      ? <span className="m">{a.model}</span>
                      : <span className="k">{UNKNOWN}</span>}</td>
                    <td>{a.firmware
                      ? <span className="m">{a.firmware}</span>
                      : <span className="k">{UNKNOWN}</span>}</td>
                    <td>{a.zone
                      ? <span className="m">{a.zone}</span>
                      : <span className="k">{UNKNOWN}</span>}</td>
                    <td>{a.lifecycle
                      ? lifecycleText(a.lifecycle)
                      : <span className="k">{UNKNOWN}</span>}</td>
                  </tr>))}</tbody></table></div>
              {!data.items.length &&
                <p className="empty">조건에 맞는 자산이 없습니다.
                  <b> 가져오기</b> 에서 CSV 로 등록할 수 있습니다.</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── 4. 자산 상세 ─────────────────────────────────────────── */
export function AssetDetail({route, go}: Props) {
  const id = route.asset;
  const [ans, setAns] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<Error | null>(null);
  const [tick, setTick] = useState(0);
  const body = useApi<{body: Record<string, any>; level: string}>(
    id ? `/api/assets/${id}` : null, [tick]);
  const ex = useApi<ExposureResp>(id ? `/api/exposures?asset_id=${id}` : null, [id]);
  const fd = useApi<{findings: Finding[]; question: Question | null;
                     scanned: Scanned; lifecycle: LifecycleView | null}>(
    id ? `/api/assets/${id}/findings` : null, [tick]);
  if (!id) return <PickAsset go={go} to="asset" title="자산 상세"
    lead="자산 하나를 열면 지금까지 아는 것, 그 자산에 대한 판정, 다음에 확인할 것 하나가 함께 나옵니다."/>;

  const q = fd.data?.question ?? null;
  const answer = async (value: string) => {
    if (!q) return;
    setBusy(true); setErr(null);
    try {
      await post(`/api/assets/${id}/observations`, {field: q.field, value});
      setAns(''); setTick(t => t + 1);
    } catch (e) { setErr(e as Error); } finally { setBusy(false); }
  };

  const b = body.data?.body ?? {};
  const ident = (b.identity ?? {}) as Record<string, string>;
  const rows: [string, string | undefined][] = [
    ['장치 종류', typeText(b.asset_type)], ['제조사', ident.vendor_raw], ['제품군', ident.family_raw],
    ['모델', ident.model_raw], ['주문번호', ident.order_number],
    ['수명주기', b.lifecycle_status ? lifecycleText(b.lifecycle_status) : undefined], ['안전 중요도', (b.operations ?? {}).safety_criticality],
  ];
  return (
    <div>
      <h2>{id}</h2>
      <p className="lead">값 옆에 <b>출처와 시점</b>이 붙습니다. 모르는 값은 채우지 않고 미상으로 둡니다.</p>
      <Err e={err ?? body.error ?? fd.error}/>
      <div className="split">
        <div>
          {q ? (
            <div className="card">
              <h3 style={{marginTop: 0}}>다음에 확인할 것</h3>
              <div className="v" style={{marginBottom: 6}}>{q.label}</div>
              <p className="k">{q.help}</p>
              <div className="callout">{q.why}</div>
              {q.kind === 'select' || q.kind === 'choice' ? (
                <select value={ans} onChange={e => setAns(e.target.value)}>
                  {q.options.map(o => <option key={o.v} value={o.v}>{o.t}</option>)}
                </select>
              ) : (
                <input type="text" value={ans} placeholder="아는 대로 적으세요"
                       onChange={e => setAns(e.target.value)}
                       onKeyDown={e => e.key === 'Enter' && answer(ans)}/>
              )}
              <div className="btnrow">
                <button disabled={busy}
                        onClick={() => answer(ans || q.options[0]?.v || '')}>답하기</button>
                {q.skippable && <button className="ghost" disabled={busy}
                  onClick={() => answer('')}>확인 불가</button>}
              </div>
            </div>
          ) : <div className="card"><p className="k">더 물을 것이 없습니다.</p></div>}

          <div className="card">
            <h3 style={{marginTop: 0}}>지금까지 아는 것{' '}
              {body.data && <span className="pill lv">
                {body.data.level} · {LEVEL[body.data.level] ?? ''}</span>}</h3>
            {!body.data ? <Spin/> : (
              <table><tbody>
                {rows.map(([k, v]) => (
                  <tr key={k}><th style={{width: 92}}>{k}</th>
                    <td>{v ? <span className="m">{v}</span>
                           : <span className="k">{UNKNOWN}</span>}</td></tr>))}
                {(b.components ?? []).map((c: any, i: number) => (
                  <tr key={'c' + i}><th>{componentText(c.type)}</th>
                    <td>{c.version?.raw
                          ? <span className="m">{c.version.raw}</span>
                          : <span className="k">버전 미상</span>}
                      {/* 설정값을 '확인' 이라고 쓰면 안 된다 — 판정은 막아 놓고
                          화면만 확정처럼 말하면 사람이 그걸 믿는다 (ADR-038). */}
                      {c.method === 'project_file' &&
                        <div className="k"><b>설정값</b> — 프로젝트 파일에 적힌 값이고
                          장비에서 읽은 값이 아닙니다</div>}
                      {c.observed_at &&
                        <div className="k">{String(c.observed_at).slice(0, 10)}
                          {c.method === 'project_file' ? ' 파일 기준' : '에 확인'}
                          {c.method === 'manual' ? ' · 사람이 입력'
                            : c.method === 'project_file' ? ' · 프로젝트 파일'
                            : ' · ' + c.method}</div>}
                    </td></tr>))}
              </tbody></table>
            )}
            {fd.data?.lifecycle && fd.data.lifecycle.state !== 'unknown' && (
              <div className={'callout ' + (fd.data.lifecycle.vendor_confirmed
                ? 'hot' : '')} style={{marginTop: 12}}>
                <span className="big">
                  {fd.data.lifecycle.state === 'end_of_life' ? '지원 종료' : '지원 중'}
                  {fd.data.lifecycle.vendor_confirmed
                    ? ' — 제조사가 확인' : ' — 현장 기록만'}</span>
                {fd.data.lifecycle.reason}
                <details style={{marginTop: 8}}>
                  <summary className="k" style={{cursor: 'pointer'}}>
                    근거 {fd.data.lifecycle.claims.length}건</summary>
                  {fd.data.lifecycle.claims.map((cl, i) => (
                    <div key={i} className="k" style={{marginTop: 6}}>
                      <b>{cl.role === 'field' ? '현장 기록'
                        : cl.role === 'vendor' ? '제조사' : '조정기관'}</b>
                      {' · '}{cl.source}
                      {!cl.structured && ' · 문장에서 읽음'}
                      <div>{cl.basis}</div>
                    </div>))}
                </details>
              </div>)}
            <div className="btnrow">
              <button className="ghost" onClick={() => go('mindmap', {asset: id})}>마인드맵</button>
              <button className="ghost" onClick={() => go('paths', {asset: id})}>공격 경로</button>
            </div>
          </div>
        </div>
        <div>
          {ex.data && ex.data.items.length > 0 && (
            <div style={{marginBottom: 20}}>
              <h3 style={{marginTop: 0}}>장비가 놓인 방식 때문에 생기는 위험</h3>
              {ex.data.items.map((e: Exposure, i: number) => (
                <ExposureRow key={i} e={e}/>))}
            </div>)}
          <h3 style={{marginTop: ex.data?.items.length ? undefined : 0}}>
            이 자산에 대한 판정</h3>
          {!fd.data ? <Spin what="계산 중"/> : <>
            {fd.data.scanned && (
              <p className="k" style={{margin: '0 0 12px'}}>
                권고문 {fd.data.scanned.total.toLocaleString()}건 중{' '}
                <b>{fd.data.scanned.considered}건</b>을 판정했습니다.
                나머지 {fd.data.scanned.excluded.toLocaleString()}건은 제조사·모델이
                이 장비와 무관해 대상 자체가 아닙니다 — <b>안전하다는 뜻이 아닙니다.</b>
              </p>)}
            {(() => {
              // 대부분은 '이 장비 얘기가 아님' 이다. 그걸 다 펼치면 정작 중요한 몇 건이
              // 묻힌다 — 실측 396건 중 390건이 그랬다. 접어두되 **숫자는 남긴다.**
              const real = fd.data.findings.filter(f => f.status !== 'no_known_match');
              const none = fd.data.findings.filter(f => f.status === 'no_known_match');
              return (
                <>
                  {real.length
                    ? real.map(f => (
                        <FindingRow key={f.advisory_id} f={f}
                                    onOpen={() => go('vuln', {asset: id, advisory: f.advisory_id})}/>))
                    : <p className="empty">판단 대상인 권고문이 없습니다.
                        모델이나 버전을 채우면 달라집니다.</p>}
                  {none.length > 0 && (
                    <details className="folded">
                      <summary>
                        이 장비 얘기가 아닌 권고문 {none.length.toLocaleString()}건
                        <span className="k"> — 안전하다는 뜻이 아니라, 이 문서들이 다루는
                          제품이 이 장비가 아니라는 뜻입니다</span>
                      </summary>
                      {none.slice(0, 30).map(f => (
                        <div key={f.advisory_id} className="k folded-row">
                          <span className="m">{f.advisory_id}</span> · {f.publisher}
                        </div>))}
                      {none.length > 30 && (
                        <div className="k folded-row">… 외 {(none.length - 30).toLocaleString()}건</div>)}
                    </details>)}
                </>
              );
            })()}
          </>}
        </div>
      </div>
    </div>
  );
}

/* ── 5. 취약점 상세 ───────────────────────────────────────── */
export function VulnDetail({route, go}: Props) {
  const {advisory, asset} = route;
  const {data, error} = useApi<any>(
    advisory ? `/api/vulnerabilities/${advisory}${asset ? `?asset_id=${asset}` : ''}` : null,
    [advisory, asset]);
  if (!advisory) return <PickAsset go={go} to="asset" title="취약점 상세"
    lead="취약점은 자산에서 출발합니다. 자산을 고르면 그 자산에 걸린 권고문 목록이 나오고, 거기서 하나를 누르면 이 화면이 열립니다."/>;
  const f: Finding | undefined = data?.finding;
  return (
    <div>
      <Err e={error}/>
      {!data ? <Spin/> : (
        <div>
          <h2>{data.advisory_id}</h2>
          <p className="lead">{data.title} · {data.publisher} ·
            개정 {String(data.released_at ?? '').slice(0, 10)}</p>
          {f && (
            <>
              <div className={`callout ${tone(f.status) === 2 ? 'ok'
                : tone(f.status) === 0 ? 'hot' : ''}`}>
                <span className="big">{asset} — {STATUS[f.status].plain}</span>
                {STATUS[f.status].why}
                {identityText(f.identity_level) &&
                  <div>· 제품 식별: {identityText(f.identity_level)}</div>}
                {f.conditions.map((c, i) => <div key={i}>· {c}</div>)}
              </div>
              <details style={{margin: '10px 0'}}>
                <summary className="k" style={{cursor: 'pointer'}}>통제 어휘와 원문 값</summary>
                <table style={{marginTop: 8}}><tbody>
                  <tr><th style={{width: 130}}>상태 코드</th>
                    <td className="m">{f.status} · {STATUS[f.status].label}</td></tr>
                  <tr><th>식별 수준</th><td className="m">{f.identity_level ?? '—'}</td></tr>
                  <tr><th>발화 규칙</th><td className="m">{f.fired_rules.join(', ') || '없음'}</td></tr>
                  <tr><th>원문 범위 표현</th><td className="m">{f.raw_expression ?? '—'}</td></tr>
                  <tr><th>규칙·정책 버전</th>
                    <td className="m">{f.rule_version} · {f.policy_version}</td></tr>
                  <tr><th>입력 해시</th><td className="m">{f.input_hash}</td></tr>
                </tbody></table>
              </details>
              <h3>일치·불일치·빠진 값</h3>
              <table><tbody>
                {([['matched', '일치'], ['mismatched', '불일치'],
                   ['missing', '빠진 값']] as const).map(([k, lab]) => (
                  <tr key={k}><th style={{width: 84}}>{lab}</th>
                    <td className="m">{f.fields[k].join(' · ') || '—'}</td></tr>))}
              </tbody></table>
            </>
          )}
          <h3>이 권고문의 취약점</h3>
          <table><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>상태</th>
            <th>수정·완화</th></tr></thead>
            <tbody>{data.vulnerabilities.map((v: any) => (
              <tr key={v.cve}>
                <td className="m">{v.cve}</td>
                <td className="m">{v.cvss ?? '—'}<div className="k">{v.vector}</div></td>
                <td>{v.kev ? <b className="t0">등재</b> : <span className="k">없음</span>}</td>
                <td className="m">{v.status.join(', ')}</td>
                <td className="k">{v.remediations.map((r: any, i: number) => (
                  <div key={i}>{r.category} — {r.details}</div>))}</td>
              </tr>))}</tbody></table>
          <p className="k">원문 해시 <span className="m">{String(data.sha256).slice(0, 24)}…</span>
            {' '}· 대상 제품 {data.products}건</p>
        </div>
      )}
    </div>
  );
}

/* ── 6. 마인드맵 (그림 5) ─────────────────────────────────── */
export function MindMapView({route, go}: Props) {
  const id = route.asset;
  const {data, error} = useApi<MindMap>(id ? `/api/assets/${id}/mindmap` : null, [id]);
  const ref = useCytoscape(el => {
    if (!data) return null;
    const cy = cytoscape({
      container: el,
      elements: [
        ...data.nodes.map(n => ({data: {...n, state: n.state ?? 'observed'}})),
        ...data.edges.map((e, i) => ({data: {id: `e${i}`, ...e}})),
      ],
      style: [
        {selector: 'node', style: {
          label: 'data(label)', 'font-family': FONT, 'font-size': '13px',
          'font-weight': 500, 'text-wrap': 'wrap', 'text-max-width': '150px', color: C.dim,
          'background-color': C.deck2, 'border-width': 1, 'border-color': C.rule,
          shape: 'round-rectangle', padding: '11px',
          width: 'label', height: 'label', 'text-valign': 'center'}},
        {selector: 'node[kind="root"]', style: {
          'background-color': C.signal, color: '#06101F', 'font-size': '15px',
          'font-weight': 700, 'border-width': 0, padding: '22px', shape: 'ellipse'}},
        {selector: 'node[kind!="leaf"][kind!="root"]', style: {
          'background-color': C.deck, 'font-weight': 700, 'border-color': C.signal,
          color: C.txt, 'font-size': '14px', 'border-width': 1.6}},
        {selector: 'node[state="unknown"]', style: {color: C.faint, 'border-style': 'dotted'}},
        {selector: 'edge', style: {width: 1.6, 'curve-style': 'bezier', 'line-color': C.rule}},
        ...(['inferred', 'unknown', 'settled'] as const).map(s => ({
          selector: `edge[state="${s}"]`,
          style: {'line-color': STATE_COLOR[s],
                  'line-style': (s === 'settled' ? 'solid' : s === 'inferred'
                    ? 'dashed' : 'dotted') as cytoscape.Css.LineStyle},
        })),
      ],
      layout: {name: 'concentric', minNodeSpacing: 58, padding: 30, spacingFactor: 1.1,
               concentric: (n: any) => n.data('kind') === 'root' ? 3
                 : n.data('kind') === 'leaf' ? 1 : 2,
               levelWidth: () => 1} as cytoscape.LayoutOptions,
      minZoom: 0.45, maxZoom: 2.5, wheelSensitivity: 0.2,
    });
    (el as unknown as {_cy: unknown})._cy = cy;
    el.dataset.nodes = String(cy.nodes().length);
    return cy;
  }, [data]);
  if (!id) return <PickAsset go={go} to="mindmap" title="마인드맵"
    lead="자산 하나를 가운데 두고 식별·구성요소·취약점·경로·공정 영향·조치·증거를 한눈에 펼칩니다."/>;
  return (
    <div>
      <h2>{id} — 아는 것 전부</h2>
      <p className="lead">자산을 가운데 두고 <b>식별 · 구성요소 · 취약점 · 공격 경로 ·
        공정 영향 · 조치 · 증거</b> 일곱 축으로 펼칩니다. 탐색용 화면입니다.</p>
      <Err e={error}/>
      {!data && <Spin what="그리는 중"/>}
      <div ref={ref} className="cy tall"/>
      <div className="legend">
        <span><i/>확인</span><span><i className="d"/>추론</span>
        <span><i className="g"/>정보 부족</span>
        <span>가운데가 자산, 한 겹 밖이 축, 바깥이 값입니다.</span>
      </div>
      <div className="btnrow">
        <button className="ghost" onClick={() => go('asset', {asset: id})}>자산 상세로</button>
      </div>
    </div>
  );
}

/* ── 7. 공격 경로 ─────────────────────────────────────────── */
/* Purdue 레벨 = 행. 이 도메인은 원래 층 구조이고 공격은 위(기업망)에서
   아래(현장)로 내려온다. 레벨을 행으로 고정하면 좌표가 결정적이고 — 흩어놓는
   레이아웃과 달리 — 글자가 읽힌다. ADR-016 이 SVG 에서 택한 것과 같은 이유다. */
/** Purdue 참조 모델의 층 이름 (IEC 62443). 숫자만 보여주면 뜻이 없다. */
const PURDUE: Record<number, string> = {
  5: '기업망', 4: '사업장 IT', 3: '운영 관리', 2: '감시 제어', 1: '제어', 0: '현장 장치',
};

const ROW_H = 108;
const COL_W = 210;

function purdueRows(nodes: {id: string; level: number}[]) {
  const levels = [...new Set(nodes.map(n => n.level))].sort((a, b) => b - a);
  const perRow = new Map<number, string[]>();
  nodes.forEach(n => {
    const r = levels.indexOf(n.level);
    perRow.set(r, [...(perRow.get(r) ?? []), n.id]);
  });
  const pos = new Map<string, {x: number; y: number}>();
  perRow.forEach((ids, r) => {
    ids.forEach((nid, i) => {
      pos.set(nid, {x: (i - (ids.length - 1) / 2) * COL_W, y: r * ROW_H});
    });
  });
  return {levels, pos, height: levels.length * ROW_H};
}

export function Paths({route, go}: Props) {
  const id = route.asset;
  const [sel, setSel] = useState(0);
  // 레일 눈금은 fit 이후의 **실제 렌더 좌표**에서 읽는다. 미리 계산한 값을 쓰면
  // 확대 배율이 바뀌는 순간 층 이름과 노드가 어긋난다.
  const [railY, setRailY] = useState<{lv: number; y: number}[]>([]);
  const {data, error} = useApi<PathsResp>(
    id ? `/api/graphs/attack-paths?asset_id=${id}` : null, [id]);
  useEffect(() => setSel(0), [id]);
  const rows = useMemo(
    () => (data?.graph ? purdueRows(data.graph.nodes) : null), [data]);
  const ref = useCytoscape(el => {
    if (!data?.available || !data.graph || !rows) return null;
    const path = data.paths?.[sel];
    const on = new Set(path?.edges ?? []);
    const pn = new Set(path?.nodes ?? []);
    const graph = data.graph;
    const cy = cytoscape({
      container: el,
      elements: [
        ...data.graph.nodes.map(n => ({
          data: {id: n.id, label: `${n.label}\n${n.zone}`, hot: pn.has(n.id) ? 1 : 0,
                 entry: n.entry ? 1 : 0}})),
        ...data.graph.edges.map(e => ({data: {
          id: e.id, source: e.source, target: e.target, label: e.label,
          state: e.state, hot: on.has(e.id) ? 1 : 0}})),
      ],
      style: [
        {selector: 'node', style: {
          label: 'data(label)', 'font-family': FONT, 'font-size': '13px',
          'font-weight': 500, 'text-wrap': 'wrap', color: C.dim,
          'background-color': C.deck2, 'border-width': 1,
          'border-color': C.rule, shape: 'round-rectangle', padding: '12px',
          width: 'label', height: 'label', 'text-valign': 'center'}},
        {selector: 'node[entry=1]', style: {'border-color': C.hold, 'border-style': 'dashed'}},
        {selector: 'node[hot=1]', style: {
          'border-color': C.act, 'border-width': 2.2, 'border-style': 'solid',
          'background-color': '#2A1614', color: C.txt}},
        {selector: 'edge', style: {
          width: 1.3, 'curve-style': 'bezier', 'line-color': C.rule,
          'target-arrow-shape': 'triangle', 'target-arrow-color': C.rule,
          'arrow-scale': 0.8, label: 'data(label)', 'font-size': '10px',
          'font-family': FONT, color: C.faint, 'text-rotation': 'autorotate'}},
        {selector: 'edge[state="inferred"]', style: {'line-style': 'dashed', 'line-color': C.hold}},
        {selector: 'edge[state="unknown"]', style: {'line-style': 'dotted', 'line-color': C.faint}},
        {selector: 'edge[hot=1]', style: {
          'line-color': C.act, width: 2.8, 'target-arrow-color': C.act}},
      ],
      // 좌표는 layout.positions 로 준다. elements[].position 으로 주면
      // width:'label' 과 맞물려 첫 페인트가 어긋난다 (노드 대부분이 안 그려졌다).
      layout: {name: 'breadthfirst', directed: true, spacingFactor: 1.15,
               padding: 20} as cytoscape.LayoutOptions,
      // 층 다이어그램이다. 사용자가 끌어서 흐트러뜨리면 레일과 어긋난다.
      boxSelectionEnabled: false, autoungrabify: true, wheelSensitivity: 0.2,
    });
    // layout:'preset' 으로 좌표를 주면 cytoscape 3.30 이 노드 대부분을 칠하지 않는다
    // (width:'label' 과 맞물리는 문제). breadthfirst 로 정상 렌더한 뒤 좌표만 옮긴다.
    const place = () => {
      cy.batch(() => {
        cy.nodes().forEach(n => {
          const q = rows.pos.get(n.id());
          if (q) n.position(q);
        });
      });
      cy.fit(undefined, 26);
      const next = rows.levels.map(lv => ({
        lv,
        y: Math.round(cy.getElementById(graph.nodes.find(n => n.level === lv)!.id)
             .renderedPosition().y),
      }));
      // 같은 값이면 setState 를 건너뛴다 — ResizeObserver 와 물려 루프가 된다.
      setRailY(prev => (prev.length === next.length &&
        prev.every((r, i) => r.y === next[i]!.y && r.lv === next[i]!.lv) ? prev : next));
    };
    (el as unknown as {_cy: unknown})._cy = cy;
    cy.ready(() => {
      place();
      el.dataset.nodes = String(cy.nodes().length);
    });
    // flex 레이아웃이 확정되기 전에 만들어지면 fit 이 빗나간다. 크기가 잡히면 다시 맞춘다.
    const ro = new ResizeObserver(() => { cy.resize(); place(); });
    ro.observe(el);
    (cy as unknown as {_offResize: () => void})._offResize = () => ro.disconnect();
    return cy;
  }, [data, sel]);
  if (!id) return <PickAsset go={go} to="paths" title="공격 경로"
    lead="진입점에서 이 자산까지 어떻게 닿는지, 공격자가 무엇을 얻어 가는지, 어디를 끊으면 되는지 봅니다."/>;
  return (
    <div>
      <h2>공격 경로</h2>
      <Err e={error}/>
      {!data ? <Spin what="계산 중"/> : !data.available ? (
        <div className="callout"><span className="big">{data.reason}</span>
          모르는 것을 아는 것처럼 답하지 않습니다.</div>
      ) : (
        <div>
          <p className="lead">{data.label} — 진입점에서 여기까지 어떻게 닿는가</p>
          <div className="callout">{data.warning}</div>
          <div className="f"><label htmlFor="ps">경로 선택</label>
            <select id="ps" value={sel} onChange={e => setSel(Number(e.target.value))}>
              {data.paths?.map((p, i) => (
                <option key={i} value={i}>
                  {p.status === 'confirmed' ? '전 구간 확인됨'
                    : p.status === 'inferred' ? '일부 추론' : '정보 부족'}
                  {' · '}{p.hops.length}홉 · {p.nodes.join(' → ')}
                </option>))}
            </select></div>
          <div className="stack" style={{marginTop: 12}}>
            <div className="levels">
              {railY.map(({lv, y}) => (
                <div key={lv} className="lvrow" style={{top: y + 'px'}}>
                  <b>L{lv % 1 === 0 ? lv : lv.toFixed(1)}</b>
                  <span>{PURDUE[Math.floor(lv)] ?? ''}</span>
                </div>))}
            </div>
            <div ref={ref} className="cy tall" style={{flex: 1, minWidth: 0}}/>
          </div>
          <p className="k" style={{marginTop: 8}}>
            층은 Purdue 참조 모델입니다 — 위가 기업망, 아래가 현장 장치.
            공격은 위에서 아래로 내려옵니다.</p>
          <div className="legend">
            <span><i/>확인된 통신</span><span><i className="d"/>추론</span>
            <span><i className="g"/>정보 부족</span>
            <span>도달성은 <b>모든 구간이 확인된</b> 경로에서만 확정됩니다.</span>
          </div>
          <div className="grid2" style={{marginTop: 18}}>
            <div><h3>공격자가 얻어 가는 것</h3>
              <table><thead><tr><th>구간</th><th>근거</th><th>얻는 것</th></tr></thead>
                <tbody>{(data.paths?.[sel]?.hops ?? []).map((h, i) => (
                  <tr key={i}><td className="m">{h.src} → {h.dst}
                    <div className="k">{h.label}</div></td>
                    <td>{h.state === 'observed' ? '확인됨'
                      : h.state === 'inferred' ? '추론' : '정보 부족'}</td>
                    <td className="m">{h.caps.join(', ')}</td></tr>))}</tbody></table></div>
            <div><h3>차단 후보</h3>
              <p className="k">점수 대신 정수 두 개 — 몇 개를 끊고 무엇을 희생하는지.</p>
              <table><thead><tr><th>끊을 구간</th><th>사라지는 경로</th>
                <th>영향받는 정상 통신</th></tr></thead>
                <tbody>{(data.blocks ?? []).map(b => (
                  <tr key={b.edge}><td className="m">{b.edge}</td>
                    <td className="m">{b.cut}</td><td className="m">{b.legit}</td></tr>))}
                </tbody></table></div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── 8. 증거 비교 ─────────────────────────────────────────── */
/* 권고문 1,303건이면 묶음이 58개다. 전부 펼치면 CVE 나열 12만 자가 된다 —
   실제로 그랬다. 목록에서 고르고 하나만 펼치는 구조로 바꾼다.
   정렬은 **충돌이 많은 것부터** — 사람이 볼 이유가 거기 있다. */
export function Evidence() {
  const [sel, setSel] = useState<number | null>(null);
  const {data, error} = useApi<EvidenceResp>('/api/evidence/compare');
  const {data: one} = useApi<GroupDetail>(
    sel === null ? null : `/api/evidence/compare/${sel}`, [sel]);

  useEffect(() => {
    if (sel === null && data?.groups.length) setSel(data.groups[0]!.id);
  }, [data, sel]);

  return (
    <div>
      <h2>출처 대조</h2>
      <p className="lead">같은 취약점을 여러 곳이 말할 때 <b>덮어쓰지 않습니다.</b>
        모든 주장을 보관하고, 화면의 값은 필드별 권위로 계산합니다.</p>
      <Err e={error}/>
      {!data ? <Spin what="권고문을 연결하는 중"/> : (
        <div>
          <div className="stats">
            <div className="stat"><b>{data.totals.groups}</b><span>연결된 묶음</span></div>
            <div className="stat"><b>{data.totals.advisories.toLocaleString()}</b>
              <span>권고문 전체</span></div>
            <div className="stat"><b>{data.totals.products.toLocaleString()}</b>
              <span>대조한 제품</span></div>
            <div className={'stat' + (data.totals.conflicts ? ' hot' : ' ok')}>
              <b>{data.totals.conflicts}</b><span>진짜 충돌</span></div>
            <div className="stat"><b>{data.totals.multivalued}</b>
              <span>한 출처가 범위 여럿</span></div>
          </div>
          <p className="k">
            <b>값이 여럿이라고 충돌이 아닙니다.</b> 충돌은 <b>서로 다른 출처</b>가
            <b> 겹치는 범위</b>에 대해 다르게 말할 때입니다 (7.2). 한 권고문이 같은
            제품에 범위를 여럿 적는 것은 흔하고 정상입니다
            ({data.totals.multivalued.toLocaleString()}건).
            {data.totals.disjoint > 0 &&
              ` 범위가 겹치지 않는 서로 다른 분기 ${data.totals.disjoint}건도 모순이 아닙니다.`}
            {data.totals.undecidable > 0 &&
              ` 범위를 파싱하지 못해 겹침을 판단할 수 없는 것 ${data.totals.undecidable}건은
                충돌로 단정하지 않고 사람 확인 대상으로 둡니다.`}
            {' '}묶음은 <b>CVE 교집합</b>으로 만듭니다 (ADR-024).
          </p>

          <div className="split" style={{marginTop: 20}}>
            <div>
              <h3 style={{marginTop: 0}}>묶음 {data.totals.groups}개</h3>
              <p className="k" style={{margin: '0 0 10px'}}>충돌이 많은 순서입니다.</p>
              <div className="picklist">
                {data.groups.map(g => (
                  <button key={g.id} className={'pick' + (g.id === sel ? ' on' : '')}
                          onClick={() => setSel(g.id)}>
                    <span className="ttl">{g.publishers.join(' · ')}</span>
                    <span className="sub">
                      CVE {g.n_cves.toLocaleString()} · 제품 {g.n_products} ·
                      권고문 {g.n_advisories}
                    </span>
                    <span className={'badge' + (g.n_conflict ? ' hot' : ' ok')}>
                      {g.n_conflict ? `충돌 ${g.n_conflict}` : '일치'}
                    </span>
                  </button>))}
              </div>
            </div>

            <div>
              {!one ? <Spin/> : (
                <div>
                  <h3 style={{marginTop: 0}}>
                    {one.publishers.join(' · ')} — 무엇이 같고 무엇이 다른가</h3>
                  <div className={`callout ${one.n_conflict ? 'hot' : 'ok'}`}>
                    <span className="big">제품 {one.n_products}건 대조 ·
                      진짜 충돌 {one.n_conflict}건</span>
                    {one.n_conflict
                      ? '서로 다른 출처가 겹치는 범위를 다르게 말합니다. 다른 값도 지우지 않고 함께 보관합니다 — 결론은 사람이 냅니다.'
                      : '출처 간 모순은 없습니다. 그래도 모든 주장을 보관합니다.'}
                    {one.n_multivalued > 0 &&
                      ` 한 출처가 범위를 여럿 말한 제품 ${one.n_multivalued}건은 충돌이 아닙니다.`}
                  </div>

                  <h3>이 묶음의 권고문</h3>
                  <div className="scroll"><table>
                    <thead><tr><th>권고</th><th>발행처</th><th>스스로 밝힌 역할</th>
                      <th>우리가 판단한 역할</th><th>개정</th></tr></thead>
                    <tbody>{one.provenance.map(p => (
                      <tr key={p.advisory_id}>
                        <td className="m">{p.advisory_id}</td>
                        <td>{p.publisher}</td>
                        <td className="m k">{p.declared_category}</td>
                        <td>{p.role === 'unverified'
                          ? <b className="t1">권위 미확인</b>
                          : <b>{p.role === 'vendor' ? '제조사'
                              : p.role === 'coordinator' ? '조정기관'
                              : p.role === 'cna' ? 'CNA' : p.role}</b>}
                          <div className="k">{p.role_basis}</div></td>
                        <td className="m">{String(p.released_at ?? '').slice(0, 10)}</td>
                      </tr>))}</tbody></table></div>

                  <h3>공통 CVE {one.n_cves.toLocaleString()}건</h3>
                  <p className="k m">{one.cves.slice(0, 24).join(', ')}
                    {one.n_cves > 24 && ` … 외 ${(one.n_cves - 24).toLocaleString()}건`}</p>

                  <h3>제품별 대조 {one.n_conflict > 0 && '— 값이 다른 것부터'}</h3>
                  <div className="scroll"><table>
                    <thead><tr><th>제품</th><th>상태</th><th>화면에 쓰는 값</th>
                      <th>부딪히는 값</th></tr></thead>
                    <tbody>{one.products.map(p => (
                      <tr key={p.key} className={p.conflicting ? 'row-hot' : ''}>
                        <td className="m">{p.key}</td>
                        <td>{p.conflicting ? <b className="t0">충돌</b>
                          : p.undecidable ? <span className="t1">판단 보류</span>
                          : p.disjoint ? <span className="k">다른 분기</span>
                          : p.multivalued ? <span className="k">범위 여럿</span>
                          : <span className="t2">일치</span>}</td>
                        <td className="m">{p.current}
                          <div className="k">{p.source} · {p.role}</div></td>
                        <td className="k">
                          {p.disputed.length ? p.disputed.map((d, i) => (
                            <div key={i} className="m">
                              {d.a} <span className="k">({d.a_src})</span><br/>
                              {d.b} <span className="k">({d.b_src})</span>
                            </div>))
                            : p.dissenting.length
                              ? <span className="m">{p.dissenting.map(x =>
                                  x.value).slice(0, 3).join(' · ')}</span>
                              : '—'}
                        </td>
                      </tr>))}</tbody></table></div>
                  {one.n_products > one.products.length && (
                    <p className="k">{one.n_products}건 중 {one.products.length}건을
                      보여줍니다 — 충돌이 있는 것을 먼저 실었습니다.</p>)}
                </div>)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── 9. 정책 렌즈 ─────────────────────────────────────────── */
const LENS_PAGE = 60;

export function Lens({ctx}: Props) {
  const [a, setA] = useState('default');
  const [b, setB] = useState('security');
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const run = async () => {
    setData(null); setErr(null);
    try { setData(await post('/api/decisions/preview', {lens_a: a, lens_b: b})); }
    catch (e) { setErr(e as Error); }
  };
  useEffect(() => { void run(); }, []);
  return (
    <div>
      <h2>관점 바꿔보기</h2>
      <p className="lead">가중치를 바꾸면 <b>같은 등급 안의 순서만</b> 바뀝니다.
        조치 등급은 절대 움직이지 않습니다 — 그게 안전 하한입니다.</p>
      <div className="btnrow" style={{marginBottom: 14}}>
        {([['A', a, setA], ['B', b, setB]] as const).map(([side, val, set]) => (
          <span key={side} style={{marginRight: 14}}>
            <span className="k">{side} </span>
            <select style={{width: 'auto', display: 'inline-block'}} value={val}
                    onChange={e => set(e.target.value)}>
              {Object.keys(ctx.lens_presets).map(l => <option key={l} value={l}>{l}</option>)}
            </select></span>))}
        <button onClick={run}>비교</button>
      </div>
      <Err e={err}/>
      {!data ? <Spin what="계산 중"/> : (
        <div>
          <div className={`callout ${data.bucket_changed.length ? 'hot' : 'ok'}`}>
            <span className="big">{data.bucket_changed.length
              ? `등급이 바뀐 항목 ${data.bucket_changed.length}건 — 규칙 위반입니다`
              : '등급이 바뀐 항목 없음'}</span>
            순서만 바뀐 항목 {data.moved.length}건. 관점은 정렬만 바꾸고 등급은 못 바꿉니다.
          </div>
          <div className="grid2">
            {([['a', data.lens_a], ['b', data.lens_b]] as const).map(([key, name]) => (
              <div key={key}><h3>{name}</h3>
                <div className="scroll"><table>
                  <thead><tr><th>#</th><th>등급</th><th>자산</th><th>점수</th>
                  {key === 'b' && <th>이동</th>}</tr></thead>
                  <tbody>{data[key].slice(0, LENS_PAGE).map((r: any, i: number) => {
                    const mv = data.moved.find((m: any) =>
                      m.asset_id === r.asset_id && m.advisory === r.advisory);
                    return (
                      <tr key={i}><td className="m">{i + 1}</td>
                        <td className="m">{r.bucket}</td><td className="m">{r.asset_id}</td>
                        <td className="m right">{r.score}</td>
                        {key === 'b' && <td className="m">
                          {mv ? `${mv.from + 1}→${mv.to + 1}` : ''}</td>}
                      </tr>);
                  })}</tbody></table></div>
                {data[key].length > LENS_PAGE && (
                  <p className="k">{data[key].length.toLocaleString()}건 중
                    위에서 {LENS_PAGE}건만 표시합니다.</p>)}
              </div>))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── 11. 무엇이 달라졌나 (두 시점 비교) ───────────────────── */

/** 두 시점 비교는 전수 계산 두 번이라 느리다. 눌렀을 때만 돈다. */
const T_EARLY = '2026-02-01';

const CHANGE_TONE: Record<string, string> = {
  '새로 생김': 'hot', '등급 변경': 'warn', '사라짐': 'ok', '비교 불가': 'ask',
};
/** 상태 코드는 서버가 주는 문자열이다. 모르는 값이 와도 화면이 깨지지 않게 한다. */
const statusLabel = (s: string): string =>
  (STATUS as Record<string, {label: string}>)[s]?.label ?? s;

const CHANGE_LEAD: Record<string, string> = {
  '새로 생김': '그 뒤에 나온 권고문이 내 장비에 걸린 것',
  '등급 변경': '같은 문서인데 해야 할 일의 급이 달라진 것',
  '사라짐': '앞 시점에는 있었는데 지금 목록에 없는 것 — 고쳐졌다는 뜻이 아닙니다',
  '비교 불가': '두 시점을 견줄 수 없는 것 — 변화가 없다는 뜻이 아닙니다',
};

export function Changes({go}: Props) {
  const [before, setBefore] = useState(T_EARLY);
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const [pick, setPick] = useState<string | null>(null);
  const run = async () => {
    setData(null); setErr(null); setBusy(true);
    try { setData(await api(`/api/timeline/diff?before=${before}`)); }
    catch (e) { setErr(e as Error); }
    finally { setBusy(false); }
  };
  const shown = data && (data.changes as any[]).filter(
    (c: any) => !pick || c.kind === pick);
  return (
    <div>
      <h2>무엇이 달라졌나</h2>
      <p className="lead">지난 어느 날과 <b>기준 시점</b>을 견줍니다. 그날 이후 새로
        나온 권고문이 내 장비에 걸렸는지, 이미 있던 것의 급이 올라갔는지를 봅니다.</p>
      <div className="btnrow" style={{marginBottom: 14}}>
        <span className="k">기준일&nbsp;</span>
        <input type="date" value={before} max={data?.after ?? undefined}
               style={{width: 'auto', display: 'inline-block'}}
               onChange={e => setBefore(e.target.value)}/>
        <button onClick={run} disabled={busy}>
          {busy ? '계산 중 — 40초쯤 걸립니다' : '견주기'}</button>
      </div>
      <Err e={err}/>
      {busy && <Spin what="두 시점을 각각 전수 판정 중"/>}
      {data && (
        <div>
          <div className="stats">
            {(data.order as string[]).map(k => (
              <button key={k} title={CHANGE_LEAD[k]}
                      className={`stat pick ${CHANGE_TONE[k]}` + (pick === k ? ' on' : '')}
                      onClick={() => setPick(pick === k ? null : k)}>
                <b>{data.counts[k].toLocaleString()}</b>
                <span>{k}</span>
                <span className="why">{CHANGE_LEAD[k]}</span>
              </button>))}
          </div>
          <div className="callout">
            <span className="big">{data.before} → {data.after}</span>
            그날 나와 있던 권고문 {data.advisories.before.toLocaleString()}건,
            {data.after} 기준 {data.advisories.after.toLocaleString()}건.
            악용이 알려진 CVE 도 그날 기준({data.kev.before.toLocaleString()}건)으로
            맞췄습니다 — 그때 몰랐던 악용으로 등급을 올리지 않습니다.
          </div>
          <p className="k">{data.caveat}</p>
          {data.uncertain_advisories > 0 && (
            <p className="k">그날 있었지만 그 뒤 고쳐진 문서가{' '}
              {data.uncertain_advisories.toLocaleString()}건 있습니다. 우리가 가진
              사본은 고쳐진 쪽이라 그 문서들은 <b>비교 불가</b>로 둡니다.</p>)}
          <div className="scroll" style={{marginTop: 12}}>
            <table><thead><tr>
              <th>무슨 일</th><th>장비</th><th>권고문</th>
              <th>{data.before}</th><th>{data.after}</th>
            </tr></thead>
            <tbody>{shown.map((c: any, i: number) => (
              <tr key={i} className="clickable" title={c.why}
                  onClick={() => go('vuln', {asset: c.asset_id, advisory: c.advisory_id})}>
                <td><span className={`chip t${CHANGE_TONE[c.kind]}`}>{c.kind}</span></td>
                <td className="m">{c.asset_id}</td>
                <td className="m">{c.advisory_id}</td>
                <td className="m">{c.before ?? '없었음'}</td>
                <td className="m">{c.after ?? '없음'}
                  {c.before === c.after && c.before_status !== c.after_status
                    && <span className="k"> ({statusLabel(c.before_status)} →{' '}
                      {statusLabel(c.after_status)})</span>}</td>
              </tr>))}</tbody></table>
          </div>
          {shown.length === 0 && <p className="k">{pick} 에 해당하는 항목이 없습니다.</p>}
          <p className="k">
            {data.truncated > 0 && `변화 ${(data.changes.length + data.truncated).toLocaleString()}건 중 종류마다 급한 것부터 추려 ${data.changes.length.toLocaleString()}건을 보여줍니다. `}
            {data.seconds}초 걸렸습니다. 같은 두 날짜를 다시 누르면 바로 나옵니다.</p>
        </div>)}
    </div>
  );
}

/* ── 10. 운영 콘솔 ────────────────────────────────────────── */
export function Ops() {
  const {data, error} = useApi<OpsResp>('/api/ops');
  const sw = data?.sweep;
  return (
    <div>
      <h2>운영 콘솔</h2>
      <p className="lead">소스가 살아 있는지, 무슨 버전으로 판정했는지, 누가 무엇을 했는지.</p>
      <Err e={error}/>
      {!data ? <Spin/> : (
        <div>
          <h3 style={{marginTop: 0}}>소스 상태</h3>
          <p className="k" style={{margin: '0 0 10px'}}>
            큰 수는 <b>카탈로그 크기</b>이고, 그 아래가 <b>우리 범위에서 실제로 쓰이는 수</b>
            입니다. 둘은 다릅니다.</p>
          <div className="cards">
            {data.sources.map(s => (
              <div key={s.name} className={'card src' + (s.ok ? '' : ' down')}>
                <div className="hd">
                  <span className={'dot ' + (s.ok ? 'ok' : 'down')}/>
                  {s.name}
                  <span className="st">{s.ok ? '정상' : '미로드'}</span>
                </div>
                <b>{s.count.toLocaleString()}<em>{s.unit}</em></b>
                <span className="k">{s.detail}</span>
                {s.used !== s.count && (
                  <div className="used">
                    <b>{s.used.toLocaleString()}</b>
                    <span>{s.used_label}</span>
                    {s.name === 'CISA KEV' && sw?.kev_findings != null && (
                      <span>→ 실제 발견에 붙은 것 {sw.kev_findings.toLocaleString()}건</span>)}
                  </div>)}
                {s.extra && <span className="k xtra">{s.extra}</span>}
              </div>))}
          </div>

          <h3>전수 계산</h3>
          {sw && sw.state !== '완료' ? (
            <div className="callout">
              <span className="big">{sw.state === '실패'
                ? '전수 계산에 실패했습니다'
                : `계산 중 — 자산 ${sw.done.toLocaleString()} / ${sw.total.toLocaleString()}`}</span>
              시작할 때 한 번만 돕니다. 끝나면 여기에 숫자가 채워지고 할 일 화면이 열립니다.
            </div>
          ) : (
          <div className="stats">
            <div className="stat"><b>{(sw?.pairs ?? 0).toLocaleString()}</b>
              <span>대조한 쌍</span></div>
            <div className="stat"><b>{(sw?.excluded ?? 0).toLocaleString()}</b>
              <span>대상 아님</span></div>
            <div className="stat"><b>{(sw?.evaluated ?? 0).toLocaleString()}</b>
              <span>실제 판정</span></div>
            <div className="stat hot"><b>{(sw?.findings ?? 0).toLocaleString()}</b>
              <span>남은 발견</span></div>
            <div className="stat"><b>{sw?.seconds ? `${sw.seconds}초` : '—'}</b>
              <span>계산 시간</span></div>
          </div>)}
          <p className="k">‘대상 아님’ 은 제조사·모델이 달라 이 권고문의 대상이 아니라는
            뜻입니다 — <b>안전하다는 뜻이 아닙니다.</b></p>

          <h3>버전</h3>
          <div className="cards">
            <div className="card src"><div className="hd">정책</div>
              <b className="m sm">{data.versions.policy}</b>
              <span className="k">내용 해시로 버전을 만듭니다</span></div>
            <div className="card src"><div className="hd">파서</div>
              <b className="m sm">{data.versions.parser}</b>
              <span className="k">파싱 결과를 재생성할 수 있습니다</span></div>
            <div className="card src"><div className="hd">저장소</div>
              <b className="sm">{data.backend}</b>
              <span className="k">등록 자산 {data.assets.toLocaleString()}개</span></div>
          </div>

          <h3>감사 이벤트</h3>
          <div className="callout">인증이 아직 없습니다. 그래서 <b>actor 는 인증되지 않은
            주장</b>으로 기록됩니다 — 인증된 사실처럼 적지 않습니다.</div>
          {data.audit.length ? (
            <div className="scroll"><table>
              <thead><tr><th>#</th><th>시점</th><th>행위</th><th>actor</th>
                <th>인증됨</th><th>대상</th></tr></thead>
              <tbody>{data.audit.map(e => (
                <tr key={e.id}><td className="m">{e.id}</td><td className="m">{e.as_of}</td>
                  <td className="m">{e.action}</td><td className="m">{e.actor}</td>
                  <td>{e.authenticated ? '예' : <span className="k">아니오</span>}</td>
                  <td className="k">{e.subject}</td></tr>))}</tbody></table></div>
          ) : <p className="empty">아직 기록된 이벤트가 없습니다. 자산을 가져오거나
                예외를 승인하면 여기에 남습니다.</p>}
        </div>
      )}
    </div>
  );
}
