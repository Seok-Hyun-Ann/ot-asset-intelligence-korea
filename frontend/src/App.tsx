/* 셸 — 표 25 의 화면 10개를 묶는다.
 *
 * 화면 10개를 한 줄로 늘어놓으면 어디에 뭐가 있는지 알 수 없다. 하는 일로 묶는다:
 * **작업**(지금 할 일) · **분석**(왜 그런지 파고들기) · **근거**(무엇을 믿고 있는지).
 *
 * 경로는 해시로 쓴다. 서버에 catch-all 을 두지 않아도 `#/asset/plc-line3-01` 을
 * 새로고침·북마크할 수 있고, 폐쇄망에서 정적 파일만 복사해도 그대로 동작한다.
 */
import {useEffect, useState} from 'react';
import {useApi} from './api';
import {Err} from './ui';
import type {Ctx} from './types';
import type {Props, Route} from './screens';
import {
  Actions, AssetDetail, AssetList, Changes, Evidence, Lens, MindMapView, Onboard,
  Ops, Paths, VulnDetail,
} from './screens';

type Screen = React.ComponentType<Props>;
interface Item { key: string; label: string; comp: Screen; }

const SECTIONS: {title: string; hint: string; items: Item[]}[] = [
  {title: '내 자산', hint: '무엇이 있고 무엇을 해야 하나', items: [
    {key: 'actions', label: '할 일', comp: Actions},
    {key: 'assets', label: '자산 목록', comp: AssetList},
    {key: 'onboard', label: '자산 가져오기', comp: Onboard},
    {key: 'changes', label: '무엇이 달라졌나', comp: Changes},
  ]},
  {title: '분석', hint: '왜 그런 판정인지 파고들기', items: [
    {key: 'asset', label: '자산 상세', comp: AssetDetail},
    {key: 'vuln', label: '취약점', comp: VulnDetail},
    {key: 'mindmap', label: '마인드맵', comp: MindMapView},
    {key: 'paths', label: '공격 경로', comp: Paths},
  ]},
  {title: '검증·운영', hint: '무엇을 믿고 있는지 확인', items: [
    {key: 'evidence', label: '출처 대조', comp: Evidence},
    {key: 'lens', label: '관점 바꿔보기', comp: Lens},
    {key: 'ops', label: '운영 콘솔', comp: Ops},
  ]},
];
const ITEMS = SECTIONS.flatMap(s => s.items);
const NAMES = ITEMS.map(i => i.key);

/** `#/vuln/plc-01/icsa-26-036-02` → {screen, asset, advisory} */
export function parseHash(hash: string): Route {
  const parts = hash.replace('#', '').split('/').filter(Boolean).map(decodeURIComponent);
  const screen = parts[0] && NAMES.includes(parts[0]) ? parts[0] : 'actions';
  return {screen, asset: parts[1], advisory: parts[2]};
}

export function toHash(r: Route): string {
  const parts = [r.screen];
  if (r.asset) parts.push(r.asset);
  if (r.asset && r.advisory) parts.push(r.advisory);
  return '#/' + parts.map(encodeURIComponent).join('/');
}

export default function App() {
  const {data: ctx, error} = useApi<Ctx>('/api/context');
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));

  // 뒤로가기가 동작해야 한다 — 주소창이 정본이고 상태는 그것을 따라간다.
  useEffect(() => {
    const onHash = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const go = (screen: string, extra?: Partial<Route>) => {
    const next: Route = {...route, ...(extra ?? {}), screen};
    window.location.hash = toHash(next);
    setRoute(next);
  };

  if (error) return <div className="sheet"><Err e={error}/></div>;
  if (!ctx) return <div className="sheet"><p className="spin">불러오는 중…</p></div>;

  const cur = ITEMS.find(i => i.key === route.screen) ?? ITEMS[0]!;
  const Cur = cur.comp;
  return (
    <div className="shell">
      <div className="rail">
        <div className="brand">
          <b>OT 자산 취약점 관리</b>
          <span>모르는 것은 모른다고 답합니다</span>
        </div>
        <div className="nav">
          {SECTIONS.map(sec => (
            <div key={sec.title}>
              <h6>{sec.title}<span>{sec.hint}</span></h6>
              {sec.items.map(it => (
                <button key={it.key}
                        className={'tab' + (route.screen === it.key ? ' on' : '')}
                        onClick={() => go(it.key)}>
                  <span className="ic"/>{it.label}
                  {it.key === 'assets' && <span className="ct">{ctx.assets}</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div className="main">
        <div className="tb">
          <b>{cur.label}</b>
          {route.asset && <span className="sub">{route.asset}</span>}
          <div className="r">
            <span>기준 시점 <em>{ctx.as_of}</em></span>
            <span>권고문 <em>{ctx.advisories.length}</em></span>
            <span>KEV <em>{ctx.kev ?? '미로드'}</em></span>
            <span>저장소 <em>{ctx.backend}</em></span>
          </div>
        </div>
        {ctx.assets > 0 && ctx.assets_demo === ctx.assets && (
          <div className="demobar">
            지금 등록된 자산 {ctx.assets.toLocaleString()}개는 <b>전부 예시</b>입니다 —
            사용자의 실제 장비가 아닙니다. 아래 판정은 그 예시에 대한 것입니다.
            <button className="go" onClick={() => go('onboard')}>
              내 장비 넣기 →</button>
          </div>)}
        {!ctx.authenticated && (
          <div className="warnbar">
            인증이 없는 로컬 실행입니다. 127.0.0.1 에만 열려 있으며 외부에 노출하면 안 됩니다.
            {ctx.topology_synthetic ? ' 토폴로지는 합성입니다.' : ''}
          </div>
        )}
        <div className="sheet"><Cur ctx={ctx} route={route} go={go}/></div>
      </div>
    </div>
  );
}
