/* OT 자산 취약점 관리 — 표 25 의 화면 10개.
 *
 * React 18 UMD + htm (JSX 대신 태그 템플릿). node 가 없어 빌드 단계를 두지 않았다.
 * 판정·우선순위·경로는 전부 서버의 엔진이 계산한다 — 여기서 규칙을 다시 쓰지 않는다.
 */
const {useState, useEffect, useRef, useCallback} = React;
const html = htm.bind(React.createElement);
const root = ReactDOM.createRoot(document.getElementById('root'));

const TONE0 = ['affected_confirmed', 'affected_likely'];
const TONE2 = ['not_affected_confirmed', 'fixed'];
const tone = s => TONE0.includes(s) ? 0 : (TONE2.includes(s) ? 2 : 1);
const GROUPS = [['해당함', '조치가 필요합니다'], ['판단 보류', '더 알아야 합니다'],
                ['해당 없음', '종결할 수 있습니다']];
const GROUP_OF = {
  affected_confirmed: 0, affected_likely: 0, candidate: 0,
  insufficient_information: 1, conflicting_evidence: 1, stale: 1, no_known_match: 1,
  not_affected_confirmed: 2, fixed: 2,
};
const BUCKET_SHORT = {P0: '지금', 'P?': '확인 먼저', P1: '창 밖에', P2: '다음 창에',
                      P3: '모니터', P4: '종결'};

async function api(path, opts) {
  const r = await fetch(path, opts);
  const t = await r.text();
  let d; try { d = JSON.parse(t); } catch (e) { d = {detail: t}; }
  if (!r.ok) throw new Error(d.detail || ('요청이 실패했습니다 (' + r.status + ')'));
  return d;
}
const post = (p, body) => api(p, {method: 'POST', headers: {'Content-Type': 'application/json'},
                                  body: JSON.stringify(body)});

/* ── 공통 조각 ─────────────────────────────────────────────── */
const Err = ({e}) => e ? html`<div class="err">${String(e.message || e)}</div>` : null;

function Band({counts, total, onPick, active}) {
  const g = [0, 0, 0];
  Object.entries(counts || {}).forEach(([k, n]) => { g[GROUP_OF[k] ?? 1] += n; });
  return html`<div>
    <div class="band">${GROUPS.map((grp, i) => html`
      <button key=${i} class=${'seg sv' + i} style=${{flexGrow: g[i] || 0.001}}
        onClick=${() => onPick && onPick(i)} title=${grp[1]}>
        <span class="n">${g[i]}</span><span class="l">${grp[0]} · ${grp[1]}</span>
      </button>`)}
    </div>
    <p class="k">전체 ${total}건 — 왼쪽으로 갈수록 해당할 가능성이 높고,
      오른쪽으로 갈수록 확실히 아닙니다.${active ? ' · 지금 ' + active + ' 만 봅니다.' : ''}</p>
  </div>`;
}

function Finding({f, phrases, onOpen}) {
  const t = tone(f.status);
  return html`<div class=${'rec' + (f._on ? ' on' : '')} onClick=${() => onOpen && onOpen(f)}>
    <div class=${'mark t' + t}>${f.bucket}<small>${BUCKET_SHORT[f.bucket] || ''}</small></div>
    <div>
      <div class="tag">${f.asset_id || f.advisory_id}</div>
      <div class=${'v t' + t}>${f.phrase} <span class="k m">${f.status}</span></div>
      <div class="say">${(f.conditions || [])[0] || ''}</div>
    </div>
    <div class="why">
      ${f.fired_rules && f.fired_rules.length
        ? html`<span class="hi">${f.fired_rules.join(' · ')}</span> 발화`
        : (f.bucket === 'P?' ? html`확정되면 최소 <span class="hi">${f.floor_if_confirmed}</span>`
                             : html`<span class="k">강제규칙 없음</span>`)}
      ${(f.pending || []).length ? html`<div class="s2">${f.pending.map(p =>
        html`${p.rule} → ${p.floor} · ${p.missing.join(', ')} 미확인<br/>`)}</div>` : null}
      ${(f.kev_cves || []).length ? html`<div class="s2">KEV ${f.kev_cves.join(', ')}</div>` : null}
    </div>
    <div class="wt">${f.lens_score ?? ''}</div>
  </div>`;
}

/* ── 1. 온보딩·가져오기 ────────────────────────────────────── */
function Onboard({ctx, go}) {
  const [csv, setCsv] = useState(
    '자산id,제조사,모델,펌웨어,공장,구역,안전중요도,수명주기\n' +
    'plc-line3-01,Mitsubishi Electric,MELSEC iQ-R Series R08PCPU,48,Factory-A,Cell-L3,high,supported\n' +
    'plc-line3-02,Mitsubishi Electric,MELSEC iQ-R Series R08PCPU,,Factory-A,Cell-L3,high,supported\n');
  const [rep, setRep] = useState(null); const [err, setErr] = useState(null);
  const run = async (apply) => {
    setErr(null);
    try { setRep(await post('/api/assets/import', {csv, apply})); }
    catch (e) { setErr(e); }
  };
  return html`<div>
    <h2>자산 가져오기</h2>
    <p class="lead">아는 것만 있으면 됩니다. 빈 칸은 미상으로 들어가고, 매핑하지 못한 열은
      버리되 무엇을 버렸는지 알려줍니다. <b>먼저 미리보기</b> 하고 확인한 뒤에 적용하세요.</p>
    <div class="split">
      <div>
        <div class="f"><label>CSV 붙여넣기</label>
          <textarea value=${csv} onChange=${e => setCsv(e.target.value)}></textarea></div>
        <div class="btnrow">
          <button onClick=${() => run(false)}>미리보기</button>
          <button class="ghost" disabled=${!rep || !rep.created}
            onClick=${() => run(true)}>${rep && rep.created ? rep.created + '건 적용' : '적용'}</button>
        </div>
        <${Err} e=${err}/>
      </div>
      <div>
        ${!rep ? html`<p class="empty">왼쪽에 CSV 를 넣고 미리보기를 누르세요.</p>` : html`<div>
          <div class=${'callout ' + (rep.applied ? 'ok' : '')}>
            <span class="big">${rep.applied ? rep.created + '건을 등록했습니다'
                                            : '미리보기 — 아직 아무것도 쓰지 않았습니다'}</span>
            행 ${rep.rows} · 생성 대상 ${rep.created} · 중복 ${rep.duplicates} · 오류 ${rep.errors}
            ${rep.sanitized ? html`<br/>수식 인젝션 무해화 ${rep.sanitized}칸` : null}
            ${rep.unmapped.length ? html`<br/>매핑하지 못한 열 (추측하지 않고 버립니다):
              <span class="m">${rep.unmapped.join(', ')}</span>` : null}
          </div>
          ${rep.applied ? html`<div class="btnrow">
            <button onClick=${() => go('assets')}>자산 목록으로</button></div>` : null}
          <h3>행별 결과</h3>
          <table><thead><tr><th>행</th><th>자산</th><th>결과</th><th>메시지</th></tr></thead>
          <tbody>${rep.preview.map(r => html`<tr key=${r.line}>
            <td class="m">${r.line}</td><td class="m">${r.asset_id || '—'}</td>
            <td>${r.action === 'create' ? '생성' : r.action === 'duplicate' ? '중복' : '오류'}</td>
            <td class="k">${r.message}</td></tr>`)}</tbody></table>
          <h3>인식한 열 매핑</h3>
          <table><tbody>${Object.entries(rep.mapping).map(([h, f]) =>
            html`<tr key=${h}><th style=${{width: '160px'}}>${h}</th>
              <td class="m">${f}</td></tr>`)}</tbody></table>
        </div>`}
      </div>
    </div>
  </div>`;
}

/* ── 2. 행동 큐 ────────────────────────────────────────────── */
function Actions({ctx, go}) {
  const [lens, setLens] = useState('default');
  const [topo, setTopo] = useState(true);
  const [bucket, setBucket] = useState(null);
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  useEffect(() => {
    setD(null);
    api(`/api/actions?lens=${lens}&topology=${topo}`).then(setD).catch(setErr);
  }, [lens, topo]);
  const items = d ? (bucket ? d.items.filter(i => i.bucket === bucket) : d.items) : [];
  const counts = {}; (d ? d.items : []).forEach(i => counts[i.status] = (counts[i.status] || 0) + 1);
  return html`<div>
    <h2>지금 해야 할 일</h2>
    <p class="lead">위험 점수가 아니라 <b>해야 할 일</b>이 기본 화면입니다.
      정렬은 P0 → P? → P1 → P2 → P3 → P4.
      <b>P?</b> 는 낮은 우선순위가 아니라 전제조건을 몰라 <b>막힌 P0/P1</b> 입니다.</p>
    <div class="btnrow" style=${{marginBottom: '14px'}}>
      ${Object.keys(ctx.lens_presets).map(l => html`<button key=${l}
        class=${lens === l ? 'on' : 'ghost'} onClick=${() => setLens(l)}>${l}</button>`)}
      <button class=${topo ? 'on' : 'ghost'} onClick=${() => setTopo(!topo)}>
        경로 반영 ${topo ? '켬' : '끔'}</button>
      ${d && Object.keys(d.counts).map(b => html`<button key=${b}
        class=${bucket === b ? 'on' : 'ghost'}
        onClick=${() => setBucket(bucket === b ? null : b)}>${b} ${d.counts[b]}</button>`)}
    </div>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">계산 중…</p>` : html`<div>
      <${Band} counts=${counts} total=${d.items.length}/>
      <div style=${{marginTop: '16px'}}>
        ${items.length ? items.map((f, i) => html`<${Finding} key=${i} f=${f}
          onOpen=${() => go('asset', {asset: f.asset_id})}/>`)
          : html`<p class="empty">이 조건에 해당하는 항목이 없습니다.</p>`}
      </div>
      <p class="k" style=${{marginTop: '14px'}}>관점(렌즈)을 바꿔도 조치 등급은 움직이지 않습니다.
        같은 등급 안에서 무엇을 먼저 볼지만 바뀝니다.</p>
    </div>`}
  </div>`;
}

/* ── 3. 자산 목록 ──────────────────────────────────────────── */
function AssetList({go}) {
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  const [f, setF] = useState({q: '', factory: '', zone: '', asset_type: '', level: ''});
  const load = useCallback(() => {
    const qs = Object.entries(f).filter(([, v]) => v).map(([k, v]) =>
      `${k}=${encodeURIComponent(v)}`).join('&');
    api('/api/assets' + (qs ? '?' + qs : '')).then(setD).catch(setErr);
  }, [f]);
  useEffect(load, [load]);
  const fac = d ? d.facets : {factory: [], zone: [], asset_type: [], level: []};
  const sel = (k, label) => html`<div class="f"><label>${label}</label>
    <select value=${f[k]} onChange=${e => setF({...f, [k]: e.target.value})}>
      <option value="">전체</option>
      ${(fac[k] || []).map(v => html`<option key=${v} value=${v}>${v}</option>`)}
    </select></div>`;
  return html`<div>
    <h2>자산 목록</h2>
    <p class="lead">식별이 어디까지 채워졌는지가 <b>L0~L5</b> 로 보입니다.
      L0 는 장치 종류만, L5 는 공정·정비 조건까지 아는 상태입니다.</p>
    <div class="split3">
      <div class="card">
        <div class="f"><label>검색</label>
          <input type="search" value=${f.q} placeholder="자산 id · 모델 · 제조사"
            onChange=${e => setF({...f, q: e.target.value})}/></div>
        ${sel('factory', '공장')} ${sel('zone', '구역')}
        ${sel('asset_type', '장치 종류')} ${sel('level', '식별 완성도')}
        <div class="btnrow"><button class="ghost"
          onClick=${() => setF({q: '', factory: '', zone: '', asset_type: '', level: ''})}>
          조건 지우기</button></div>
      </div>
      <div>
        <${Err} e=${err}/>
        ${!d ? html`<p class="spin">불러오는 중…</p>` : html`<div>
          <p class="k">${d.items.length}건</p>
          <table><thead><tr><th>자산</th><th>완성도</th><th>종류</th><th>제조사</th>
            <th>모델</th><th>펌웨어</th><th>구역</th><th>수명주기</th></tr></thead>
          <tbody>${d.items.map(a => html`<tr key=${a.asset_id} class="click"
            onClick=${() => go('asset', {asset: a.asset_id})}>
            <td class="m">${a.asset_id}</td>
            <td><span class="pill lv">${a.level}</span></td>
            <td>${a.asset_type}</td><td>${a.vendor || '—'}</td>
            <td class="m">${a.model || '—'}</td>
            <td class="m">${a.firmware || html`<span class="k">미상</span>`}</td>
            <td class="m">${a.zone || '—'}</td>
            <td>${a.lifecycle || html`<span class="k">미상</span>`}</td></tr>`)}</tbody></table>
          ${!d.items.length ? html`<p class="empty">조건에 맞는 자산이 없습니다.
            위 <b>가져오기</b> 에서 CSV 로 등록할 수 있습니다.</p>` : null}
        </div>`}
      </div>
    </div>
  </div>`;
}

/* ── 4. 자산 상세 ──────────────────────────────────────────── */
function AssetDetail({ctx, route, go}) {
  const id = route.asset;
  const [body, setBody] = useState(null);
  const [fd, setFd] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [ans, setAns] = useState('');
  const load = useCallback(() => {
    if (!id) return;
    api(`/api/assets/${id}`).then(r => setBody(r)).catch(setErr);
    api(`/api/assets/${id}/findings`).then(setFd).catch(setErr);
  }, [id]);
  useEffect(load, [load]);
  if (!id) return html`<p class="empty">자산을 먼저 고르세요.</p>`;

  const answer = async (value) => {
    setBusy(true); setErr(null);
    try {
      await post(`/api/assets/${id}/observations`, {field: fd.question.field, value});
      setAns(''); load();
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  const q = fd && fd.question;
  return html`<div>
    <h2>${id}</h2>
    <p class="lead">값 옆에 <b>출처와 시점</b>이 붙습니다. 모르는 값은 채우지 않고 미상으로 둡니다.</p>
    <${Err} e=${err}/>
    <div class="split">
      <div>
        ${q ? html`<div class="card">
          <h3 style=${{marginTop: 0}}>다음에 확인할 것</h3>
          <div class="v" style=${{marginBottom: '6px'}}>${q.label}</div>
          <p class="k">${q.help}</p>
          <div class="callout">${q.why}</div>
          ${q.kind === 'select' || q.kind === 'choice'
            ? html`<select value=${ans} onChange=${e => setAns(e.target.value)}>
                ${q.options.map(o => html`<option key=${o.v} value=${o.v}>${o.t}</option>`)}
              </select>`
            : html`<input type="text" value=${ans} placeholder="아는 대로 적으세요"
                onChange=${e => setAns(e.target.value)}
                onKeyDown=${e => e.key === 'Enter' && answer(ans)}/>`}
          <div class="btnrow">
            <button disabled=${busy} onClick=${() => answer(ans || (q.options[0]||{}).v || '')}>답하기</button>
            ${q.skippable ? html`<button class="ghost" disabled=${busy}
              onClick=${() => answer('')}>확인 불가</button>` : null}
          </div>
        </div>` : html`<div class="card"><p class="k">더 물을 것이 없습니다.</p></div>`}

        <div class="card">
          <h3 style=${{marginTop: 0}}>지금까지 아는 것
            ${body ? html` <span class="pill lv">${body.level}</span>` : null}</h3>
          ${body ? html`<table><tbody>
            ${[['장치 종류', body.body.asset_type],
               ['제조사', (body.body.identity || {}).vendor_raw],
               ['제품군', (body.body.identity || {}).family_raw],
               ['모델', (body.body.identity || {}).model_raw],
               ['주문번호', (body.body.identity || {}).order_number],
               ['수명주기', body.body.lifecycle_status],
               ['안전 중요도', (body.body.operations || {}).safety_criticality]].map(([k, v]) =>
              html`<tr key=${k}><th style=${{width: '92px'}}>${k}</th>
                <td class="m">${v || html`<span class="k">아직 모름</span>`}</td></tr>`)}
            ${(body.body.components || []).map((c, i) => html`<tr key=${'c' + i}>
              <th>${c.type}</th><td class="m">${(c.version || {}).raw
                || html`<span class="k">버전 미상</span>`}
              ${c.observed_at ? html`<div class="k">${c.observed_at.slice(0,10)} · ${c.method || ''}</div>` : null}
              </td></tr>`)}
          </tbody></table>` : html`<p class="spin">…</p>`}
          <div class="btnrow">
            <button class="ghost" onClick=${() => go('mindmap', {asset: id})}>마인드맵</button>
            <button class="ghost" onClick=${() => go('paths', {asset: id})}>공격 경로</button>
          </div>
        </div>
      </div>

      <div>
        <h3 style=${{marginTop: 0}}>이 자산에 대한 판정</h3>
        ${!fd ? html`<p class="spin">계산 중…</p>`
          : fd.findings.map(f => html`<${Finding} key=${f.advisory_id} f=${f}
              onOpen=${() => go('vuln', {asset: id, advisory: f.advisory_id})}/>`)}
      </div>
    </div>
  </div>`;
}

/* ── 5. 취약점 상세 ────────────────────────────────────────── */
function VulnDetail({route, go}) {
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  const adv = route.advisory;
  useEffect(() => {
    if (!adv) return;
    setD(null);
    api(`/api/vulnerabilities/${adv}` + (route.asset ? `?asset_id=${route.asset}` : ''))
      .then(setD).catch(setErr);
  }, [adv, route.asset]);
  if (!adv) return html`<p class="empty">권고문을 먼저 고르세요.</p>`;
  const f = d && d.finding;
  return html`<div>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">불러오는 중…</p>` : html`<div>
      <h2>${d.advisory_id}</h2>
      <p class="lead">${d.title} · ${d.publisher} · 개정 ${(d.released_at || '').slice(0, 10)}</p>
      ${f ? html`<div class=${'callout ' + (tone(f.status) === 2 ? 'ok' : tone(f.status) === 0 ? 'hot' : '')}>
        <span class="big">${route.asset} — ${f.phrase}</span>
        ${(f.conditions || []).map((c, i) => html`<div key=${i}>· ${c}</div>`)}
      </div>
      <h3>일치·불일치·빠진 값</h3>
      <table><tbody>${[['matched', '일치'], ['mismatched', '불일치'], ['missing', '빠진 값']].map(
        ([k, lab]) => html`<tr key=${k}><th style=${{width: '84px'}}>${lab}</th>
          <td class="m">${(f.fields[k] || []).join(' · ') || '—'}</td></tr>`)}
      </tbody></table>` : null}
      <h3>이 권고문의 취약점</h3>
      <table><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>상태</th><th>수정·완화</th></tr></thead>
      <tbody>${d.vulnerabilities.map(v => html`<tr key=${v.cve}>
        <td class="m">${v.cve}</td>
        <td class="m">${v.cvss ?? '—'}<div class="k">${v.vector || ''}</div></td>
        <td>${v.kev ? html`<b class="t0">등재</b>` : html`<span class="k">없음</span>`}</td>
        <td class="m">${v.status.join(', ')}</td>
        <td class="k">${v.remediations.map((r, i) =>
          html`<div key=${i}>${r.category} — ${r.details}</div>`)}</td></tr>`)}
      </tbody></table>
      <p class="k">원문 해시 <span class="m">${d.sha256.slice(0, 24)}…</span> · 대상 제품 ${d.products}건</p>
    </div>`}
  </div>`;
}

/* ── 6. 마인드맵 (그림 5) ──────────────────────────────────── */
const STATE_COLOR = {observed: '#17365D', inferred: '#8A6800',
                     unknown: '#9AA1A8', settled: '#2C5C43'};
function useCy(ref, build, deps) {
  useEffect(() => {
    if (!ref.current) return;
    const cy = build(ref.current);
    return () => cy && cy.destroy();
  }, deps);
}

function MindMap({route, go}) {
  const id = route.asset;
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  const box = useRef(null);
  useEffect(() => {
    if (!id) return; setD(null);
    api(`/api/assets/${id}/mindmap`).then(setD).catch(setErr);
  }, [id]);
  useCy(box, el => {
    if (!d) return null;
    return cytoscape({
      container: el,
      elements: [
        ...d.nodes.map(n => ({data: {id: n.id, label: n.label, kind: n.kind,
                                     state: n.state || 'observed', detail: n.detail || ''}})),
        ...d.edges.map((e, i) => ({data: {id: 'e' + i, source: e.source, target: e.target,
                                          state: e.state}})),
      ],
      style: [
        {selector: 'node', style: {
          'label': 'data(label)', 'font-family': 'Malgun Gothic', 'font-size': '13px',
          'text-wrap': 'wrap', 'text-max-width': '150px', 'color': '#1A1C1E',
          'background-color': '#FBFAF7', 'border-width': 1.4, 'border-color': '#C6C2B8',
          'shape': 'round-rectangle', 'padding': '10px',
          'width': 'label', 'height': 'label', 'text-valign': 'center'}},
        {selector: 'node[kind="root"]', style: {
          'background-color': '#17365D', 'color': '#fff', 'font-size': '14px',
          'font-weight': 'bold', 'border-width': 0, 'padding': '20px', 'shape': 'ellipse'}},
        {selector: 'node[kind!="leaf"][kind!="root"]', style: {
          'background-color': '#E6E3DB', 'font-weight': 'bold', 'border-color': '#17365D',
          'font-size': '14px', 'border-width': 2}},
        {selector: 'node[state="unknown"]', style: {'color': '#77808A', 'border-style': 'dotted'}},
        {selector: 'edge', style: {
          'width': 1.8, 'curve-style': 'bezier', 'line-color': '#17365D',
          'target-arrow-shape': 'none'}},
        {selector: 'edge[state="inferred"]', style: {'line-style': 'dashed', 'line-color': '#8A6800'}},
        {selector: 'edge[state="unknown"]', style: {'line-style': 'dotted', 'line-color': '#9AA1A8'}},
        {selector: 'edge[state="settled"]', style: {'line-color': '#2C5C43'}},
      ],
      layout: {name: 'concentric', concentric: n => n.data('kind') === 'root' ? 3
                 : (n.data('kind') === 'leaf' ? 1 : 2),
               levelWidth: () => 1, minNodeSpacing: 58, padding: 30,
               spacingFactor: 1.1},
      minZoom: 0.45, maxZoom: 2.5, wheelSensitivity: 0.2,
    });
  }, [d]);
  if (!id) return html`<p class="empty">자산을 먼저 고르세요.</p>`;
  return html`<div>
    <h2>${id} — 아는 것 전부</h2>
    <p class="lead">자산을 가운데 두고 <b>식별 · 구성요소 · 취약점 · 공격 경로 · 공정 영향 ·
      조치 · 증거</b> 일곱 축으로 펼칩니다. 탐색용 화면입니다.</p>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">그리는 중…</p>` : null}
    <div ref=${box} class="cy tall"></div>
    <div class="legend">
      <span><i></i>확인</span><span><i class="d"></i>추론</span>
      <span><i class="g"></i>정보 부족</span>
      <span>가운데가 자산, 한 겹 밖이 축, 바깥이 값입니다.</span>
    </div>
    <div class="btnrow"><button class="ghost" onClick=${() => go('asset', {asset: id})}>
      자산 상세로</button></div>
  </div>`;
}

/* ── 7. 공격 경로 ──────────────────────────────────────────── */
function Paths({route, go}) {
  const id = route.asset;
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  const [sel, setSel] = useState(0);
  const box = useRef(null);
  useEffect(() => {
    if (!id) return; setD(null); setSel(0);
    api(`/api/graphs/attack-paths?asset_id=${id}`).then(setD).catch(setErr);
  }, [id]);
  useCy(box, el => {
    if (!d || !d.available) return null;
    const path = d.paths[sel];
    const on = new Set(path ? path.edges : []), pn = new Set(path ? path.nodes : []);
    return cytoscape({
      container: el,
      elements: [
        ...d.graph.nodes.map(n => ({data: {id: n.id, label: n.label + '\n' + n.zone,
          level: n.level, hot: pn.has(n.id) ? 1 : 0, entry: n.entry ? 1 : 0}})),
        ...d.graph.edges.map(e => ({data: {id: e.id, source: e.source, target: e.target,
          label: e.label, state: e.state, hot: on.has(e.id) ? 1 : 0}})),
      ],
      style: [
        {selector: 'node', style: {'label': 'data(label)', 'font-family': 'Malgun Gothic',
          'font-size': '12px', 'text-wrap': 'wrap', 'background-color': '#FBFAF7',
          'border-width': 1.2, 'border-color': '#C6C2B8', 'shape': 'round-rectangle',
          'padding': '10px', 'width': 'label', 'height': 'label', 'text-valign': 'center'}},
        {selector: 'node[entry=1]', style: {'background-color': '#F4E3E3'}},
        {selector: 'node[hot=1]', style: {'border-color': '#A31C1F', 'border-width': 2.4}},
        {selector: 'edge', style: {'width': 1.4, 'curve-style': 'bezier',
          'line-color': '#40618C', 'target-arrow-shape': 'triangle',
          'target-arrow-color': '#40618C', 'arrow-scale': .8,
          'label': 'data(label)', 'font-size': '10px', 'color': '#77808A',
          'text-rotation': 'autorotate'}},
        {selector: 'edge[state="inferred"]', style: {'line-style': 'dashed', 'line-color': '#8A6800'}},
        {selector: 'edge[state="unknown"]', style: {'line-style': 'dotted', 'line-color': '#9AA1A8'}},
        {selector: 'edge[hot=1]', style: {'line-color': '#A31C1F', 'width': 3.2,
          'target-arrow-color': '#A31C1F'}},
      ],
      layout: {name: 'breadthfirst', directed: true, spacingFactor: 1.15, padding: 20,
               roots: d.graph.nodes.filter(n => n.entry).map(n => n.id)},
      wheelSensitivity: 0.2,
    });
  }, [d, sel]);
  if (!id) return html`<p class="empty">자산을 먼저 고르세요.</p>`;
  return html`<div>
    <h2>공격 경로</h2>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">계산 중…</p>` : !d.available
      ? html`<div class="callout"><span class="big">${d.reason}</span>
          모르는 것을 아는 것처럼 답하지 않습니다.</div>`
      : html`<div>
        <p class="lead">${d.label} — 진입점에서 여기까지 어떻게 닿는가</p>
        <div class="callout">${d.warning}</div>
        <div class="f"><label>경로 선택</label>
          <select value=${sel} onChange=${e => setSel(+e.target.value)}>
            ${d.paths.map((p, i) => html`<option key=${i} value=${i}>
              [${p.status}] 확신도 ${p.confidence} · ${p.hops.length}홉 · ${p.nodes.join(' → ')}
            </option>`)}
          </select></div>
        <div ref=${box} class="cy" style=${{marginTop: '12px'}}></div>
        <div class="legend"><span><i></i>확인된 통신</span><span><i class="d"></i>추론</span>
          <span><i class="g"></i>정보 부족</span>
          <span>도달성은 <b>모든 구간이 확인된</b> 경로에서만 확정됩니다.</span></div>
        <div class="grid2" style=${{marginTop: '18px'}}>
          <div><h3>공격자가 얻어 가는 것</h3>
            <table><thead><tr><th>구간</th><th>근거</th><th>얻는 것</th></tr></thead>
            <tbody>${(d.paths[sel] || {hops: []}).hops.map((h, i) => html`<tr key=${i}>
              <td class="m">${h.src} → ${h.dst}<div class="k">${h.label}</div></td>
              <td>${h.state === 'observed' ? '확인됨' : h.state === 'inferred' ? '추론' : '정보 부족'}</td>
              <td class="m">${h.caps.join(', ')}</td></tr>`)}</tbody></table></div>
          <div><h3>차단 후보</h3>
            <p class="k">점수 대신 정수 두 개 — 몇 개를 끊고 무엇을 희생하는지.</p>
            <table><thead><tr><th>끊을 구간</th><th>사라지는 경로</th><th>영향받는 정상 통신</th></tr></thead>
            <tbody>${d.blocks.map(b => html`<tr key=${b.edge}>
              <td class="m">${b.edge}</td><td class="m">${b.cut}</td>
              <td class="m">${b.legit}</td></tr>`)}</tbody></table></div>
        </div>
      </div>`}
  </div>`;
}

/* ── 8. 증거 비교 ──────────────────────────────────────────── */
function Evidence() {
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  useEffect(() => { api('/api/evidence/compare').then(setD).catch(setErr); }, []);
  return html`<div>
    <h2>출처 대조</h2>
    <p class="lead">같은 취약점을 여러 곳이 말할 때 <b>덮어쓰지 않습니다.</b>
      모든 주장을 보관하고, 화면의 값은 필드별 권위로 계산합니다.</p>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">불러오는 중…</p>`
      : !d.groups.length ? html`<p class="empty">연결된 소스 쌍이 없습니다.</p>`
      : d.groups.map((g, gi) => html`<div key=${gi}>
        <h3>${g.cves.join(', ')}</h3>
        <table><thead><tr><th>권고</th><th>발행처</th><th>스스로 밝힌 역할</th>
          <th>우리가 판단한 역할</th><th>개정 시점</th></tr></thead>
        <tbody>${g.provenance.map(p => html`<tr key=${p.advisory_id}>
          <td class="m">${p.advisory_id}</td><td>${p.publisher}</td>
          <td class="m">${p.declared_category}</td>
          <td><b>${p.role}</b><div class="k">${p.role_basis}</div></td>
          <td class="m">${(p.released_at || '').slice(0, 10)}</td></tr>`)}</tbody></table>
        <div class=${'callout ' + (g.n_conflict ? 'hot' : 'ok')}>
          제품 ${g.n_products}건 대조 · 값이 다른 것 <b>${g.n_conflict}</b>건.
          ${g.n_conflict ? ' 다른 값도 지우지 않고 함께 보관합니다.'
            : ' 한쪽이 다른 쪽 문서를 재발행하기 때문에 값이 같습니다. 그래도 두 주장을 모두 보관합니다.'}
        </div>
        <table><thead><tr><th>제품</th><th>화면에 쓰는 값</th><th>채택한 곳</th>
          <th>같은 값을 말한 곳</th><th>다른 값</th></tr></thead>
        <tbody>${g.products.slice(0, 25).map(p => html`<tr key=${p.key}>
          <td class="m">${p.key}</td><td class="m">${p.current}</td>
          <td>${p.source} <span class="k">${p.role}</span></td>
          <td class="k">${p.corroborated.join(', ') || '—'}</td>
          <td class="k">${p.dissenting.map(x => x.value + ' (' + x.source + ')').join(', ') || '—'}</td>
        </tr>`)}</tbody></table>
      </div>`)}
  </div>`;
}

/* ── 9. 정책 렌즈 ──────────────────────────────────────────── */
function Lens({ctx}) {
  const [a, setA] = useState('default'); const [b, setB] = useState('security');
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  const run = () => { setD(null); post('/api/decisions/preview', {lens_a: a, lens_b: b})
    .then(setD).catch(setErr); };
  useEffect(run, []);
  return html`<div>
    <h2>관점 바꿔보기</h2>
    <p class="lead">가중치를 바꾸면 <b>같은 등급 안의 순서만</b> 바뀝니다.
      조치 등급은 절대 움직이지 않습니다 — 그게 안전 하한입니다.</p>
    <div class="btnrow" style=${{marginBottom: '14px'}}>
      ${['A', 'B'].map((side, i) => html`<span key=${side} style=${{marginRight: '14px'}}>
        <span class="k">${side} </span>
        <select style=${{width: 'auto', display: 'inline-block'}}
          value=${i ? b : a} onChange=${e => (i ? setB : setA)(e.target.value)}>
          ${Object.keys(ctx.lens_presets).map(l => html`<option key=${l} value=${l}>${l}</option>`)}
        </select></span>`)}
      <button onClick=${run}>비교</button>
    </div>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">계산 중…</p>` : html`<div>
      <div class=${'callout ' + (d.bucket_changed.length ? 'hot' : 'ok')}>
        <span class="big">${d.bucket_changed.length
          ? '등급이 바뀐 항목 ' + d.bucket_changed.length + '건 — 규칙 위반입니다'
          : '등급이 바뀐 항목 없음'}</span>
        순서만 바뀐 항목 ${d.moved.length}건. 관점은 정렬만 바꾸고 등급은 못 바꿉니다.
      </div>
      <div class="grid2">
        <div><h3>${d.lens_a}</h3>
          <table><thead><tr><th>#</th><th>등급</th><th>자산</th><th>점수</th></tr></thead>
          <tbody>${d.a.map((r, i) => html`<tr key=${i}><td class="m">${i + 1}</td>
            <td class="m">${r.bucket}</td><td class="m">${r.asset_id}</td>
            <td class="m right">${r.score}</td></tr>`)}</tbody></table></div>
        <div><h3>${d.lens_b}</h3>
          <table><thead><tr><th>#</th><th>등급</th><th>자산</th><th>점수</th><th>이동</th></tr></thead>
          <tbody>${d.b.map((r, i) => {
            const mv = d.moved.find(m => m.asset_id === r.asset_id && m.advisory === r.advisory);
            return html`<tr key=${i}><td class="m">${i + 1}</td>
              <td class="m">${r.bucket}</td><td class="m">${r.asset_id}</td>
              <td class="m right">${r.score}</td>
              <td class="m">${mv ? (mv.from + 1) + '→' + (mv.to + 1) : ''}</td></tr>`;
          })}</tbody></table></div>
      </div>
    </div>`}
  </div>`;
}

/* ── 10. 운영 콘솔 ─────────────────────────────────────────── */
function Ops() {
  const [d, setD] = useState(null); const [err, setErr] = useState(null);
  useEffect(() => { api('/api/ops').then(setD).catch(setErr); }, []);
  return html`<div>
    <h2>운영 콘솔</h2>
    <p class="lead">소스가 살아 있는지, 무슨 버전으로 판정했는지, 누가 무엇을 했는지.</p>
    <${Err} e=${err}/>
    ${!d ? html`<p class="spin">불러오는 중…</p>` : html`<div>
      <h3>소스 상태</h3>
      <table><thead><tr><th>소스</th><th>건수</th><th>상세</th><th>상태</th></tr></thead>
      <tbody>${d.sources.map(s => html`<tr key=${s.name}>
        <td>${s.name}</td><td class="m">${s.count}</td><td class="k">${s.detail}</td>
        <td>${s.ok ? html`<span class="t2">정상</span>` : html`<span class="t1">미로드</span>`}</td>
      </tr>`)}</tbody></table>
      <h3>버전</h3>
      <table><tbody>
        <tr><th style=${{width: '120px'}}>정책</th><td class="m">${d.versions.policy}</td></tr>
        <tr><th>파서</th><td class="m">${d.versions.parser}</td></tr>
        <tr><th>등록 자산</th><td class="m">${d.assets}건</td></tr>
      </tbody></table>
      <h3>감사 이벤트</h3>
      <div class="callout">인증이 아직 없습니다. 그래서 <b>actor 는 인증되지 않은 주장</b>으로
        기록됩니다 — 인증된 사실처럼 적지 않습니다.</div>
      <table><thead><tr><th>#</th><th>시점</th><th>행위</th><th>actor</th>
        <th>인증됨</th><th>대상</th></tr></thead>
      <tbody>${d.audit.map(e => html`<tr key=${e.id}>
        <td class="m">${e.id}</td><td class="m">${e.as_of}</td><td class="m">${e.action}</td>
        <td class="m">${e.actor}</td>
        <td>${e.authenticated ? '예' : html`<span class="k">아니오</span>`}</td>
        <td class="k">${e.subject || ''}</td></tr>`)}</tbody></table>
      ${!d.audit.length ? html`<p class="empty">아직 기록된 이벤트가 없습니다.</p>` : null}
    </div>`}
  </div>`;
}

/* ── 셸 ────────────────────────────────────────────────────── */
const SCREENS = [
  ['actions', '할 일', Actions], ['assets', '자산 목록', AssetList],
  ['asset', '자산 상세', AssetDetail], ['vuln', '취약점', VulnDetail],
  ['mindmap', '마인드맵', MindMap], ['paths', '공격 경로', Paths],
  ['evidence', '출처 대조', Evidence], ['lens', '관점', Lens],
  ['onboard', '가져오기', Onboard], ['ops', '운영 콘솔', Ops],
];

function App() {
  const [ctx, setCtx] = useState(null);
  const [err, setErr] = useState(null);
  const [route, setRoute] = useState({screen: 'actions'});
  useEffect(() => { api('/api/context').then(setCtx).catch(setErr); }, []);
  const go = (screen, extra) => setRoute({...route, ...(extra || {}), screen});
  if (err) return html`<div class="sheet"><${Err} e=${err}/></div>`;
  if (!ctx) return html`<div class="sheet"><p class="spin">불러오는 중…</p></div>`;
  const Cur = (SCREENS.find(s => s[0] === route.screen) || SCREENS[0])[2];
  return html`<div>
    <div class="tb"><div class="tb-in">
      <b>OT 자산 취약점 관리</b>
      <span class="sub">모르는 것은 모른다고 답합니다</span>
      <div class="r">권고문 ${ctx.advisories.length}건 · 자산 ${ctx.assets}건 · KEV ${ctx.kev || '미로드'}<br/>
        기준 시점 ${ctx.as_of} · 정책 ${ctx.policy}</div>
    </div></div>
    ${!ctx.authenticated ? html`<div class="warnbar">
      인증이 없는 로컬 실행입니다. 127.0.0.1 에만 열려 있으며 외부에 노출하면 안 됩니다.
      ${ctx.topology_synthetic ? ' · 토폴로지는 합성입니다.' : ''}
    </div>` : null}
    <div class="nav"><div class="nav-in">
      ${SCREENS.map(([k, label]) => html`<button key=${k}
        class=${'tab' + (route.screen === k ? ' on' : '')}
        onClick=${() => go(k)}>${label}</button>`)}
    </div></div>
    <div class="sheet"><${Cur} ctx=${ctx} route=${route} go=${go}/></div>
  </div>`;
}

root.render(html`<${App}/>`);
