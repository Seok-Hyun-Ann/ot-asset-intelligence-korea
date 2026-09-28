# -*- coding: utf-8 -*-
"""장치 입력 화면. `otai/server.py` 가 그대로 내보낸다.

정적 UI 와 같은 시각 언어를 쓴다 — 디아조 청사진 팔레트, 판정 문구는 바탕체.
다른 점은 **여기서는 사용자가 값을 넣는다**는 것이다.
"""

PAGE = r"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>장치 입력 — 판정 기록</title>
<style>
:root{--paper:#EFEDE7;--card:#FBFAF7;--sink:#E6E3DB;--line:#17365D;--line2:#40618C;
 --ink:#1A1C1E;--faded:#77808A;--rule:#C6C2B8;--hair:#DEDAD1;--stamp:#A31C1F;
 --pending:#8A6800;--settled:#2C5C43;
 --serif:Batang,'Times New Roman',serif;--sans:'Malgun Gothic','Segoe UI',sans-serif;
 --mono:Consolas,'Courier New',monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:13px;line-height:1.6}
:focus-visible{outline:2px solid var(--line);outline-offset:2px}
.tb{border-top:5px solid var(--line);background:var(--card);border-bottom:1px solid var(--rule)}
.tb-in{max-width:1180px;margin:0 auto;padding:13px 26px;display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
.tb b{font-family:var(--serif);font-size:19px;color:var(--line)}
.tb span{font-size:11px;color:var(--faded)}
.tb .r{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--faded);text-align:right}
.sheet{max-width:1180px;margin:0 auto;padding:28px 26px 80px;display:grid;
 grid-template-columns:400px 1fr;gap:30px;align-items:start}
h2{font-family:var(--sans);font-size:9.5px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
 color:var(--faded);margin:0 0 11px;padding-bottom:6px;border-bottom:1px solid var(--rule)}
h2.mt{margin-top:30px}
.ask{background:var(--card);border:1px solid var(--rule);border-left:4px solid var(--line);padding:18px 20px}
.q{font-family:var(--serif);font-size:23px;font-weight:700;color:var(--line);line-height:1.3;margin:0 0 6px}
.qh{font-size:12px;color:var(--faded);margin-bottom:12px}
.why{font-size:12px;background:var(--sink);padding:9px 12px;margin-bottom:14px;border-left:2px solid var(--line2)}
input[type=text],select{width:100%;padding:9px 10px;border:1px solid var(--rule);background:#fff;
 font-family:var(--mono);font-size:13.5px;color:var(--ink)}
input[type=text]:focus,select:focus{border-color:var(--line)}
.opts{display:flex;flex-direction:column;gap:6px}
.opt{display:flex;align-items:flex-start;gap:8px;padding:9px 11px;border:1px solid var(--rule);
 background:#fff;cursor:pointer;font-size:12.5px}
.opt:hover{border-color:var(--line)}
.opt input{margin:2px 0 0}
.row{display:flex;gap:8px;margin-top:13px}
button{border:1px solid var(--line);background:var(--line);color:#fff;padding:9px 20px;
 font-family:var(--sans);font-size:13px;cursor:pointer}
button:hover{background:var(--line2);border-color:var(--line2)}
button.ghost{background:0;color:var(--faded);border-color:var(--rule)}
button.ghost:hover{color:var(--line);border-color:var(--line);background:0}
.known{margin-top:22px}
.known table{width:100%;border-collapse:collapse;font-size:12px;background:var(--card)}
.known th,.known td{border:1px solid var(--hair);padding:5px 9px;text-align:left}
.known th{width:96px;color:var(--faded);font-weight:400;font-size:11px}
.known td{font-family:var(--mono);font-size:11.5px}
.known td.no{color:var(--faded);font-family:var(--sans)}
.j{background:var(--card);border:1px solid var(--rule);padding:15px 18px;margin-bottom:9px;
 border-left:4px solid var(--rule)}
.j.s0{border-left-color:var(--stamp)}.j.s1{border-left-color:var(--pending)}
.j.s2{border-left-color:var(--settled)}
.j .hd{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap}
.j .v{font-family:var(--serif);font-size:20px;font-weight:700;line-height:1.25}
.s0 .v{color:var(--stamp)}.s1 .v{color:var(--pending)}.s2 .v{color:var(--settled)}
.j .code{font-family:var(--mono);font-size:10.5px;color:var(--faded)}
.j .bk{margin-left:auto;font-family:var(--mono);font-size:17px;font-weight:700}
.s0 .bk{color:var(--stamp)}.s1 .bk{color:var(--pending)}.s2 .bk{color:var(--settled)}
.j .adv{font-family:var(--mono);font-size:11px;color:var(--faded);margin-top:3px}
.j ul{margin:9px 0 0;padding-left:18px;font-size:12.5px}
.j li{margin:3px 0}
.j .meta{margin-top:9px;padding-top:8px;border-top:1px solid var(--hair);
 font-family:var(--mono);font-size:10.5px;color:var(--faded)}
.done{background:var(--card);border:1px solid var(--rule);border-left:4px solid var(--settled);
 padding:18px 20px}
.done .q{color:var(--settled)}
.hint{font-size:12px;color:var(--faded);margin-top:12px}
.err{background:#FBF0F0;border-left:3px solid var(--stamp);padding:10px 13px;margin-bottom:12px;font-size:12.5px}
.trail{font-size:11.5px;color:var(--faded);margin-top:9px}
.trail b{color:var(--ink);font-weight:400}
@media (max-width:900px){.sheet{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>

<div class="tb"><div class="tb-in">
  <b>장치 입력</b><span>아는 것만 넣으면 나머지를 물어봅니다</span>
  <div class="r" id="ctx"></div>
</div></div>

<div class="sheet">
  <div>
    <h2>지금 물어볼 것</h2>
    <div id="ask"></div>
    <div class="known"><h2 class="mt">지금까지 아는 것</h2><div id="known"></div>
      <div class="row"><button class="ghost" onclick="reset()">처음부터</button>
        <button class="ghost" onclick="save()">자산 파일로 저장</button></div>
      <div class="hint" id="saved"></div>
    </div>
  </div>
  <div>
    <h2>판정</h2>
    <div id="out"></div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s);
const esc=t=>String(t??'').replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
let A={asset_id:'new-asset',answers:{}}, TRAIL=[];
const S0=['affected_confirmed','affected_likely'],
      S2=['not_affected_confirmed','fixed'];
const tone=s=>S0.includes(s)?0:(S2.includes(s)?2:1);

fetch('/context').then(r=>r.json()).then(c=>{
  $('#ctx').innerHTML=`권고문 ${c.advisories.length}건 · KEV ${c.kev||'미로드'}<br>기준 시점 ${c.as_of}`;
});

async function judge(){
  const r=await fetch('/judge',{method:'POST',headers:{'Content-Type':'application/json'},
                               body:JSON.stringify(A)});
  const d=await r.json();
  if(d.error){$('#ask').innerHTML=`<div class="err">${esc(d.error)}</div>`;return;}
  renderAsk(d); renderKnown(d.known); renderOut(d);
}

function renderAsk(d){
  const q=d.question;
  if(!q){
    $('#ask').innerHTML=`<div class="done"><p class="q">더 물을 것이 없습니다</p>
      <p class="qh">아는 값으로 답할 수 있는 것은 모두 답했습니다.
      오른쪽 판정에서 남은 항목의 근거를 확인하세요.</p></div>`;
    return;
  }
  let ctrl='';
  if(q.kind==='text') ctrl=`<input type="text" id="ans" autocomplete="off"
      placeholder="아는 대로 적으세요" onkeydown="if(event.key==='Enter')answer()">`;
  else if(q.kind==='select')
    ctrl=`<select id="ans">${q.options.map(o=>`<option value="${esc(o.v)}">${esc(o.t)}</option>`).join('')}</select>`;
  else if(q.kind==='choice')
    ctrl=`<div class="opts">${q.options.map((o,i)=>`<label class="opt">
      <input type="radio" name="ans" value="${esc(o.v)}"${i===0?' checked':''}>
      <span>${esc(o.t)}</span></label>`).join('')}</div>`;
  else if(q.kind==='network')
    ctrl=`<div class="opts">
      <label class="opt"><input type="checkbox" id="n_remote"><span>원격에서 접속할 수 있습니다 (VPN·원격 유지보수)</span></label>
      <label class="opt"><input type="checkbox" id="n_modbus"><span>Modbus TCP 502 를 평문으로 열어두고 있습니다</span></label></div>`;

  $('#ask').innerHTML=`<div class="ask">
    <p class="q">${esc(q.label)}</p>
    <p class="qh">${esc(q.help)}</p>
    <div class="why">${esc(q.why)}</div>
    ${ctrl}
    <div class="row"><button onclick="answer()">답하기</button>
    ${q.skippable?`<button class="ghost" onclick="skip('${esc(q.field)}')">확인 불가</button>`:''}</div>
  </div>`;
  const el=$('#ans'); if(el&&el.focus) el.focus();
}

function readAnswer(field){
  const q=document.querySelector('#ask');
  if($('#n_remote')||$('#n_modbus'))
    return {remote:$('#n_remote').checked, modbus_plain:$('#n_modbus').checked};
  const radio=q.querySelector('input[name=ans]:checked');
  if(radio) return radio.value;
  const el=$('#ans'); return el?el.value:'';
}

function answer(){
  const f=$('#ask').querySelector('.q'); if(!f) return;
  const field=CURFIELD; if(!field) return;
  A.answers[field]=readAnswer(field); judge();
}
function skip(field){ A.answers[field]=''; judge(); }
function reset(){ A={asset_id:'new-asset',answers:{}}; TRAIL=[]; $('#saved').textContent=''; judge(); }

let CURFIELD=null;
const _renderAsk=renderAsk;
renderAsk=function(d){ CURFIELD=d.question?d.question.field:null; _renderAsk(d); };

function renderKnown(k){
  const rows=[['장치 종류',k.asset_type],['제조사',k.vendor],['모델',k.model],
    ['주문번호',k.order_number],['펌웨어',k.firmware],['안전 중요도',k.safety],
    ['수명주기',k.lifecycle],['네트워크',k.network?'입력됨':null]];
  $('#known').innerHTML='<table>'+rows.map(([a,b])=>
    `<tr><th>${a}</th>${b?`<td>${esc(b)}</td>`:'<td class="no">아직 모름</td>'}</tr>`).join('')+'</table>';
}

function renderOut(d){
  const js=d.judgments;
  const hot=js.filter(j=>tone(j.status)===0).length,
        mid=js.filter(j=>tone(j.status)===1).length;
  let h=`<p class="trail">권고문 ${js.length}건 대조 — <b>해당함 ${hot}</b> · <b>판단 보류 ${mid}</b> · 해당 없음 ${js.length-hot-mid}</p>`;
  for(const j of js){
    const t=tone(j.status);
    h+=`<div class="j s${t}">
      <div class="hd"><span class="v">${esc(j.phrase)}</span>
        <span class="code">${j.status}</span>
        <span class="bk">${j.bucket}</span></div>
      <div class="adv">${j.advisory} · ${esc(j.title)}</div>
      <ul>${j.conditions.map(c=>`<li>${esc(c)}</li>`).join('')}</ul>`;
    if(j.pending.length) h+=`<ul>${j.pending.map(p=>
      `<li>강제규칙 ${p.rule} 보류 — 확정되면 최소 ${p.floor} (${p.missing.map(esc).join(', ')} 미확인)</li>`).join('')}</ul>`;
    if(j.fired.length) h+=`<ul><li>강제규칙 ${j.fired.join(', ')} 발화</li></ul>`;
    h+=`<div class="meta">영향 범위 ${esc(j.raw_expression??'—')} · CVE ${j.n_cves}건`
      +`${j.kev.length?' · KEV '+j.kev.join(', '):''} · 원문 ${j.advisory_sha}… · 재현 ${j.input_hash}…</div></div>`;
  }
  $('#out').innerHTML=h;
}

async function save(){
  const id=prompt('저장할 자산 id 를 적으세요 (영문·숫자·.-_)','my-plc-01');
  if(!id) return;
  A.asset_id=id;
  const r=await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},
                               body:JSON.stringify(A)});
  const d=await r.json();
  $('#saved').innerHTML=d.error?`<span style="color:var(--stamp)">${esc(d.error)}</span>`
    :`저장했습니다 — <span style="font-family:var(--mono)">${esc(d.path)}</span><br>
      이제 <span style="font-family:var(--mono)">otai queue</span> 와 테스트에서 그대로 쓰입니다.`;
}

judge();
</script></body></html>
"""
