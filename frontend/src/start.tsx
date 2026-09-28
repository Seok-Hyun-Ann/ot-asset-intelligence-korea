/* 처음 온 사람을 위한 안내.
 *
 * 기본 홈은 여전히 행동 큐다 (위험 점수 대시보드가 아니라 '해야 할 일'이 첫 화면이라는
 * 것이 이 제품의 전제다). 그래서 별도 시작 화면으로 데려가지 않고, 큐 위에 접을 수
 * 있는 띠로 얹는다. 한 번 닫으면 다시 뜨지 않는다.
 *
 * 안내는 "무엇을 할 수 있다" 가 아니라 **"지금 무엇이 준비됐고 다음에 무엇을 하면
 * 되는지"** 를 말한다 — 셋업 체크리스트 관행.
 */
import {useEffect, useState} from 'react';
import {BUCKET, LEVEL, STATUS} from './terms';
import type {Ctx} from './types';

const KEY = 'otai.start.dismissed';

function readDismissed(): boolean {
  try { return localStorage.getItem(KEY) === '1'; } catch { return false; }
}

export function useStartGuide() {
  const [open, setOpen] = useState(false);
  useEffect(() => { setOpen(!readDismissed()); }, []);
  const close = () => {
    try { localStorage.setItem(KEY, '1'); } catch { /* 사생활 보호 모드 */ }
    setOpen(false);
  };
  return {open, close, reopen: () => setOpen(true)};
}

interface Props {
  ctx: Ctx;
  todo: number;
  blocked: number;
  /** 아직 전수 계산 중인가. 세기 전에 '없습니다' 라고 말하면 안 된다. */
  counting: boolean;
  onClose: () => void;
  go: (screen: string) => void;
}

export function StartGuide({ctx, todo, blocked, counting, onClose, go}: Props) {
  const [terms, setTerms] = useState(false);
  const steps: {done: boolean; label: string; detail: string;
                cta?: {t: string; to: string}}[] = [
    {
      done: ctx.advisories.length > 0,
      label: `권고문 ${ctx.advisories.length.toLocaleString()}건을 불러왔습니다`,
      detail: '제조사·CISA 가 낸 실제 공개 문서입니다. 여기서 CVE 와 영향 범위가 나옵니다.',
    },
    {
      done: ctx.assets > ctx.assets_demo,
      label: ctx.assets_demo === ctx.assets
        ? `등록된 ${ctx.assets.toLocaleString()}개는 전부 예시입니다 — 내 장비는 아직 없습니다`
        : `자산 ${ctx.assets.toLocaleString()}개가 등록돼 있습니다`
          + (ctx.assets_demo ? ` (예시 ${ctx.assets_demo.toLocaleString()}개 포함)` : ''),
      detail: '내 장치를 넣으려면 CSV 를 붙여넣으면 됩니다. 아는 것만 채워도 됩니다.',
      cta: {t: '자산 가져오기', to: 'onboard'},
    },
    {
      done: !counting && (todo > 0 || blocked > 0),
      label: counting
        ? '지금 자산과 권고문을 대조하는 중입니다'
        : todo
          ? `지금 조치할 일이 ${todo}건, 확인하면 등급이 오르는 것이 ${blocked}건입니다`
          : '조치할 일이 없습니다',
      detail: counting
        ? '처음 한 번만 걸립니다. 끝나면 아래에 급한 순서로 나옵니다.'
        : '맨 위 카드 하나만 처리하면 됩니다. 나머지는 급한 순서로 아래에 있습니다.',
    },
  ];

  return (
    <div className="start">
      <div className="start-head">
        <div>
          <h3>처음이시라면 — 이 도구는 이렇게 씁니다</h3>
          <p>내 장치 정보가 <b>불완전한 상태에서도</b> 어떤 취약점이 실제로 해당하는지
            가려내고, 무엇을 먼저 할지 순서를 매깁니다.
            <b> 모르는 것은 모른다고 답합니다</b> — 빈칸을 추측으로 채우지 않습니다.</p>
        </div>
        <button className="x" onClick={onClose} aria-label="안내 닫기">닫기</button>
      </div>

      <ol className="steps">
        {steps.map((s, i) => (
          <li key={i} className={s.done ? 'done' : ''}>
            <span className="dot" aria-hidden>{s.done ? '✓' : i + 1}</span>
            <div>
              <b>{s.label}</b>
              <span>{s.detail}</span>
              {s.cta && (
                <button className="link" onClick={() => go(s.cta!.to)}>
                  {s.cta.t} →</button>)}
            </div>
          </li>
        ))}
      </ol>

      <div className="start-foot">
        <div className="paths">
          <b>어디서 시작할까요</b>
          <button className="link" onClick={() => go('assets')}>
            자산 목록에서 내 장비 찾아보기 →</button>
          <button className="link" onClick={() => go('onboard')}>
            CSV 로 내 장치 넣어보기 →</button>
          <button className="link" onClick={() => go('lens')}>
            관점을 바꿔도 등급이 안 변하는지 확인하기 →</button>
        </div>
        <button className="link" onClick={() => setTerms(!terms)}>
          {terms ? '용어 접기' : '나오는 용어 뜻 보기'} {terms ? '▲' : '▼'}</button>
      </div>

      {terms && (
        <div className="glossary">
          <div>
            <h6>조치 등급</h6>
            {(Object.keys(BUCKET) as (keyof typeof BUCKET)[]).map(b => (
              <p key={b}><code>{b}</code> <b>{BUCKET[b].label}</b> — {BUCKET[b].plain}</p>))}
          </div>
          <div>
            <h6>판정 상태</h6>
            {(Object.keys(STATUS) as (keyof typeof STATUS)[]).map(s => (
              <p key={s}><b>{STATUS[s].label}</b> — {STATUS[s].plain}</p>))}
          </div>
          <div>
            <h6>식별 완성도</h6>
            {Object.entries(LEVEL).map(([k, v]) => (
              <p key={k}><code>{k}</code> {v}</p>))}
            <p className="note">
              <b>미상</b>은 빈칸이 아니라 <b>아직 모른다</b>는 뜻입니다.
              모르는 값을 0 이나 '아니오' 로 바꾸지 않습니다.
            </p>
          </div>
        </div>
      )}

      {ctx.assets_demo > 0 && (
        <p className="note">
          지금 등록된 자산 {ctx.assets.toLocaleString()}개 중 {ctx.assets_demo.toLocaleString()}개는
          <b> 예시</b>입니다 — 제조사·제품명·버전 표기는 실제 권고문에서 가져왔지만
          장비 자체와 배치·통신은 만든 것입니다. 목록에 <b>예시</b> 배지가 붙습니다.
          내 장비를 넣으면 그것만 남기고 예시는 지울 수 있습니다.
        </p>
      )}
    </div>
  );
}
