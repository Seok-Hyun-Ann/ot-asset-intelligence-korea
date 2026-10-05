# -*- coding: utf-8 -*-
"""보고서를 인쇄용 HTML 로 (ADR-049).

**PDF 라이브러리를 넣지 않는다.** `reportlab`·`weasyprint` 는 무겁고 폐쇄망 반입에
플랫폼 wheel 이 필요하다. 브라우저의 '인쇄 → PDF 로 저장' 이 같은 일을 하고
의존성이 **0개**다. `render.py` 가 이미 그 방식으로 자기완결 HTML 을 낸다.

**외부 자원 0개.** 글꼴·스크립트·이미지를 가져오지 않는다 — 폐쇄망에서 파일 하나만
복사하면 열린다 (불변 규칙 9).

**시계를 읽지 않는다.** 표지에 기준 시점만 있고 생성 시각이 없다. 같은 입력이면
바이트 동일한 HTML 이 나온다.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .controls import SCOPE_KO
from .priority import BUCKET_ORDER, BUCKET_PHRASES
from .report import Report

_CSS = """
:root { --ink:#14181f; --mute:#5b6472; --line:#d7dce3; --head:#0f3a52;
        --warn:#fff4e5; --warnline:#e0a33a; }
* { box-sizing:border-box; }
body { margin:0; font:11pt/1.55 "Malgun Gothic","맑은 고딕",system-ui,sans-serif;
       color:var(--ink); background:#fff; }
.page { max-width:190mm; margin:0 auto; padding:14mm 12mm; }
h1 { font-size:20pt; margin:0 0 2mm; letter-spacing:-.4pt; }
h2 { font-size:13pt; margin:9mm 0 3mm; padding-bottom:1.5mm;
     border-bottom:2px solid var(--head); }
h3 { font-size:11pt; margin:5mm 0 2mm; color:var(--head); }
.sub { color:var(--mute); margin:0 0 6mm; }
table { width:100%; border-collapse:collapse; font-size:8.5pt; margin:2mm 0 4mm; }
th { background:var(--head); color:#fff; text-align:left; font-weight:600;
     padding:1.6mm 2mm; }
td { padding:1.4mm 2mm; border-bottom:1px solid var(--line);
     vertical-align:top; word-break:break-word; }
tr:nth-child(even) td { background:#f7f9fb; }
.meta { font-size:9.5pt; }
.meta td:first-child { width:38mm; font-weight:600; color:var(--mute); }
.warn { background:var(--warn); border-left:3px solid var(--warnline);
        padding:3mm 4mm; margin:3mm 0; font-size:9.5pt; }
.claim { font-size:9pt; color:var(--mute); }
.claim li { margin:1.2mm 0; }
.b { display:inline-block; min-width:9mm; padding:.4mm 1.6mm; border-radius:2px;
     font-weight:700; font-size:8pt; text-align:center; border:1.5px solid; }
.P0{color:#8a1c1c;border-color:#8a1c1c} .Pq{color:#8a5a00;border-color:#8a5a00}
.P1{color:#8a5a00;border-color:#8a5a00} .P2{color:#1d4f73;border-color:#1d4f73}
.P3{color:#4a5563;border-color:#4a5563} .P4{color:#2c6b43;border-color:#2c6b43}
.n { text-align:right; font-variant-numeric:tabular-nums; }
.empty { color:var(--mute); font-style:italic; padding:3mm 0; }
@media print {
  .page { max-width:none; padding:0; }
  h2 { page-break-after:avoid; } tr { page-break-inside:avoid; }
  thead { display:table-header-group; }
}
"""


def _esc(v) -> str:
    s = "" if v is None else str(v)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _badge(bucket: str) -> str:
    cls = "Pq" if bucket == "P?" else _esc(bucket)
    return '<span class="b %s">%s</span>' % (cls, _esc(bucket))


def _table(headers: Sequence[str], rows: Sequence[Sequence], *,
           numeric=(), empty="해당 없음") -> str:
    if not rows:
        return '<p class="empty">%s</p>' % _esc(empty)
    L = ["<table><thead><tr>"]
    L += ["<th>%s</th>" % _esc(h) for h in headers]
    L.append("</tr></thead><tbody>")
    for r in rows:
        L.append("<tr>")
        for i, c in enumerate(r):
            cls = ' class="n"' if i in numeric else ""
            L.append("<td%s>%s</td>" % (cls, c if isinstance(c, _Raw) else _esc(c)))
        L.append("</tr>")
    L.append("</tbody></table>")
    return "".join(L)


class _Raw(str):
    """이미 HTML 로 만든 조각 — 다시 이스케이프하지 않는다."""


def render(rep: Report, *, limit: int = 400) -> str:
    L = ['<meta charset="utf-8">',
         "<title>OT 자산 보고서 %s</title>" % _esc(rep.as_of),
         "<style>%s</style>" % _CSS, '<div class="page">',
         "<h1>OT 자산 취약점·공격 경로 보고서</h1>",
         '<p class="sub">기준 시점 %s · 규칙 %s</p>'
         % (_esc(rep.as_of), _esc(rep.policy_version))]

    L.append(_table(["", ""], [
        ("기준 시점", rep.as_of),
        ("규칙 버전", rep.policy_version),
        ("KEV 스냅샷", rep.kev_snapshot or "미로드"),
        ("권고문", "%d건" % rep.advisories),
        ("토폴로지", "%s%s" % (rep.topology_source or "없음",
                             " (합성)" if rep.topology_synthetic
                             else " (캡처에서 관측)" if rep.topology_synthetic is False
                             else "")),
        ("자산", "%d대" % len(rep.assets)),
    ]))
    L.append('<p class="sub">이 보고서에는 <b>생성 시각이 없습니다.</b> 기준 시점만 '
             '있고, 같은 입력이면 같은 파일이 나옵니다 — 해시를 맞춰 재현을 '
             '확인할 수 있습니다.</p>')

    if rep.synthetic_assets:
        L.append('<div class="warn"><b>합성 자산 %d대가 포함되어 있습니다.</b> '
                 '실재하지 않는 장비이며, 실제 인벤토리로 오인하지 마세요.</div>'
                 % rep.synthetic_assets)

    L.append("<h2>할 일</h2>")
    order = sorted(rep.buckets, key=lambda b: BUCKET_ORDER.get(b, 99))
    L.append(_table(["등급", "뜻", "건수"],
                    [(_Raw(_badge(b)), BUCKET_PHRASES.get(b, ""),
                      "%d" % rep.buckets[b]) for b in order], numeric=(2,)))
    L.append(_table(["등급", "자산", "설비명", "담당자", "판정", "강제규칙",
                     "KEV", "막고 있는 것"],
                    [(_Raw(_badge(a.bucket)), a.asset_id, a.label, a.owner,
                      a.status_ko, a.fired_rules, a.kev, a.blocked_by)
                     for a in rep.actions[:limit]],
                    empty="해당하는 권고문이 없습니다 — 안전하다는 뜻이 아닙니다"))
    if len(rep.actions) > limit:
        L.append('<p class="sub">%d건 중 %d건만 실었습니다. 전체는 엑셀 보고서에 '
                 '있습니다.</p>' % (len(rep.actions), limit))

    L.append("<h2>통신 방식 위험</h2>")
    L.append('<p class="sub">권고문 없이 <b>자산이 놓인 방식만</b> 보고 나온 '
             '것입니다. 패치로는 대개 없앨 수 없습니다.</p>')
    L.append(_table(["자산", "설비명", "무슨 일인가", "지금 뭘 하면 되나", "등급"],
                    [(e.asset_id, e.label, e.title, e.what_to_do,
                      _Raw(_badge(e.bucket))) for e in rep.exposures[:limit]]))

    if rep.coverage:
        L.append("<h2>제조사 커버리지</h2>")
        L.append('<p class="sub">우리 자산의 제조사가 <b>공개 권고문에 몇 번 '
                 '나오는가</b>입니다. 권고문이 없는 제조사는 CVE 축이 비는데, '
                 '그것은 <b>안전하다는 뜻이 아닙니다.</b></p>')
        L.append(_table(["제조사", "우리 자산", "공개 권고문", "그래서"],
                        [(c.vendor, "%d대" % c.our_assets, "%d건" % c.advisories,
                          c.verdict.replace("**", "")) for c in rep.coverage],
                        numeric=(1, 2)))

    if rep.controls:
        L.append("<h2>점검 항목 근거</h2>")
        L.append('<div class="warn"><b>준수 여부 판정이 아닙니다.</b> 이 표는 평가에 '
                 '<b>낼 수 있는 근거</b>를 모은 것입니다. 취약점 분석·평가는 '
                 '정보통신기반 보호법에 따라 자격을 갖춘 평가기관이 수행합니다.</div>')
        by_std: dict = {}
        for c in rep.controls:
            by_std.setdefault(c.standard, []).append(c)
        for std, rows in sorted(by_std.items()):
            # `our_scope` 는 한국어다 (`SCOPE_KO`) — 영문 `"none"` 과 비교하면
            # 전부 '답할 수 있음' 이 되어 280개를 다 싣는다.
            answerable = [c for c in rows if c.our_scope != SCOPE_KO["none"]]
            L.append("<h3>%s</h3>" % _esc(std))
            L.append('<p class="sub">항목 %d개 중 <b>%d개</b>에 근거를 댑니다. '
                     '나머지 %d개는 정책·절차·물리·교육이라 도구가 답할 수 '
                     '없습니다 — <b>통과도 미달도 아닙니다.</b></p>'
                     % (len(rows), len(answerable), len(rows) - len(answerable)))
            L.append(_table(["항목", "이름", "중요도", "근거 있음", "근거 없음"],
                            [(c.code, c.name or c.note[:60], c.severity,
                              "%d대" % c.present, "%d대" % c.absent)
                             for c in answerable], numeric=(3, 4)))

    L.append("<h2>이 보고서가 주장하지 않는 것</h2>")
    L.append('<ul class="claim">')
    for d in rep.disclaimers:
        L.append("<li>%s</li>" % _esc(d).replace("**", ""))
    L.append("</ul>")
    L.append("</div>")
    return "\n".join(L) + "\n"


def write(rep: Report, path, **kw) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # **줄바꿈을 LF 로 고정한다.** 기본값으로 쓰면 윈도우에서 CRLF 가 되어
    # 리눅스에서 다시 돌린 감사인과 해시가 달라진다 — 재현의 요점이 사라진다.
    # **줄바꿈을 LF 로 고정한다.** 기본값으로 쓰면 윈도우에서 CRLF 가 되어
    # 리눅스에서 다시 돌린 감사인과 해시가 달라진다 — 재현의 요점이 사라진다.
    path.write_text(render(rep, **kw), encoding="utf-8", newline="\n")
    return path


def write_csv(rep: Report, path) -> Path:
    """할 일을 평탄한 CSV 로 — Jira·Redmine 에 그대로 올릴 수 있게.

    티켓 시스템 연동을 만들지 않는다. 감사가 그렇게 권했고 맞다 — CSV 수동
    임포트로 버티고, 쓸모가 증명된 뒤에 붙이면 된다.
    """
    import csv as _csv
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # BOM 을 붙인다 — 한국 Excel 이 UTF-8 CSV 를 그래야 제대로 연다
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["등급", "뜻", "자산", "설비명", "담당자", "구역", "제조사",
                    "모델", "권고문", "판정", "강제규칙", "KEV", "확정 시 최소",
                    "막고 있는 것", "근거", "기준 시점", "규칙 버전"])
        for a in rep.actions:
            w.writerow([a.bucket, a.bucket_phrase, a.asset_id, a.label, a.owner,
                        a.zone, a.vendor, a.model, a.advisory_id, a.status_ko,
                        a.fired_rules, a.kev, a.floor_if_confirmed, a.blocked_by,
                        a.rationale, rep.as_of, rep.policy_version])
    return path
