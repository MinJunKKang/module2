import json as _json

from llm.mitre_crawler import cross_validate_candidates


INTRO_TEXT = """
이 리포트는 웹 해킹부터 내부 시스템 이동, 그리고 데이터 탈취까지 이어지는 공격 과정을 쉽게 이해할 수 있도록 정리한 문서입니다.

먼저, 공격자가 어떤 방식으로 시스템을 공격했는지를 분석하기 위해
MITRE ATT&CK이라는 기준을 사용합니다.
이는 실제 해커들이 사용하는 공격 방법들을 정리해 놓은 일종의 공격 메뉴얼이라고 보면 됩니다.

또한, 단순히 공격을 나열하는 것이 아니라
시스템이 어떤 구조를 가지고 있고, 어디에서 문제가 발생할 수 있는지를 분석하기 위해
Threat Modeling(위협 모델링)을 함께 활용합니다.
이는 시스템을 하나의 지도처럼 그려보고, 어디가 공격에 취약한지 미리 찾아보는 방법입니다.

이 문서는 보안 지식이 많지 않은 사용자도 이해할 수 있도록
어려운 용어 대신 쉬운 설명을 먼저 제공하고,

- 공격이 어떤 단계로 진행되었는지
- 각 단계에서 어떤 공격 기법이 사용되었는지
- 시스템 구조상 어떤 부분이 위험한지

를 순서대로 보여줍니다.

이를 통해 사용자는 단순히 결과를 보는 것이 아니라
“어떻게 공격이 이루어졌고, 왜 위험한지”를 자연스럽게 이해할 수 있도록 돕습니다.
"""

MITRE_EASY_TEXT = """
MITRE ATT&CK는 실제 공격자들이 어떤 방식으로 침투하고, 권한을 넓히고, 정보를 훔쳐 가는지를 정리해 둔
'공격 행동 사전' 같은 프레임워크입니다.

쉽게 말하면,
- 공격자가 왜 이 행동을 하는지 = 전술(Tactic)
- 공격자가 어떻게 수행하는지 = 기술(Technique)
- 그 기술을 더 구체적으로 나눈 것 = 서브기술(Sub-technique)

예를 들어 'SSH로 다른 서버에 접속했다'는 행동도 ATT&CK 기준으로 보면
'원격 서비스 이용' 또는 'SSH를 통한 내부 이동' 같은 표준 이름으로 설명할 수 있습니다.
"""

WHY_MAPPING_TEXT = """
ATT&CK 매핑을 하면 좋은 점은 다음과 같습니다.

1. 공격 흐름을 표준 기술 이름으로 설명할 수 있습니다.
2. 팀원 간에 같은 기준으로 공격 단계를 해석할 수 있습니다.
3. 탐지 규칙, 대응 방안, 보고서 작성을 표준 용어로 연결할 수 있습니다.
4. 하나의 단계에 대해 후보 TTP를 비교하며 더 적절한 기술을 선정할 수 있습니다.

즉, ATT&CK 매핑은 단순 라벨링이 아니라 공격을 구조적으로 이해하는 출발점입니다.
"""

STAGE_DEFS = [
    {
        "stage": "1단계: 웹쉘 업로드",
        "flow": "Attacker → DVWA upload endpoint → shell.php 업로드 및 실행",
        "candidate_ttps": ["T1505.003", "T1190", "T1105"],
        "reason": "웹쉘 자체는 Web Shell이 가장 직접적이고, 공개 웹 애플리케이션 악용 관점에서는 T1190도 함께 검토할 수 있습니다.",
    },
    {
        "stage": "2단계: 계정정보 탈취",
        "flow": "WebShell → config.txt 열람 → plaintext credentials 확보",
        "candidate_ttps": ["T1552.001", "T1552", "T1005"],
        "reason": "설정 파일 내 평문 계정정보라면 Credentials In Files가 가장 직접적이고, 상위 기법 T1552와 로컬 데이터 수집 관점의 T1005도 후보가 됩니다.",
    },
    {
        "stage": "3단계: Lateral Movement",
        "flow": "탈취한 계정정보 사용 → SSH 로그인 → ServerB 접근",
        "candidate_ttps": ["T1021.004", "T1078", "T1021"],
        "reason": "SSH 자체는 T1021.004가 가장 직접적이고, 정상 계정 악용 측면에서는 T1078, 상위 원격 서비스 범주로는 T1021도 후보가 됩니다.",
    },
    {
        "stage": "4단계: DB 데이터 탈취",
        "flow": "ServerB SSH 세션 → MySQL 접근 → USIM 데이터 조회/수집",
        "candidate_ttps": ["T1213.006", "T1005"],
        "reason": "데이터베이스 직접 수집이면 Databases가 더 직접적이고, 로컬 시스템 데이터 수집 관점에서는 T1005도 함께 검토할 수 있습니다.",
    },
]


def build_report_data():
    rows = []

    for item in STAGE_DEFS:
        validated = cross_validate_candidates(
            stage_text=item["stage"],
            flow_text=item["flow"],
            candidate_ids=item["candidate_ttps"],
        )
        primary = validated[0] if validated else None

        rows.append({
            "stage": item["stage"],
            "flow": item["flow"],
            "reason": item["reason"],
            "validated_ttps": validated,
            "primary_ttp_id": primary["id"] if primary else "-",
            "primary_ttp_name": primary["name"] if primary else "-",
            "primary_ttp_summary_ko": primary["summary_ko"] if primary else "-",
        })

    return rows


def build_candidate_mapping_html(rows) -> str:
    """
    후보군 전체 매핑 및 교차검증을 인터랙티브 HTML로 생성합니다.
    - 단계 탭: 4개 공격 단계 전환
    - 카드 뷰: 후보 TTP를 순위 카드 + 점수 바로 표시
    - 차트 뷰: 1차/2차/최종 점수를 그루핑 바 차트로 비교
    """
    import json as _json

    stages_data = []
    for row in rows:
        candidates = []
        for c in row["validated_ttps"]:
            candidates.append({
                "id":       c["id"],
                "name":     c["name"],
                "summary":  c["summary_ko"],
                "rule":     c["rule_score"],
                "cross":    c["cross_check_score"],
                "final":    c["final_score"],
                "verified": c.get("index_verified", False),
                "url":      c.get("url", ""),
            })
        stages_data.append({
            "name":       row["stage"],
            "flow":       row["flow"],
            "reason":     row["reason"],
            "candidates": candidates,
        })

    stages_json = _json.dumps(stages_data, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: Arial, Helvetica, sans-serif; background: white; font-size: 14px; color: #111827; }}

.stage-tabs {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; padding: 16px 0 0; }}
.stage-tab {{
  display: flex; align-items: center; gap: 8px;
  padding: 9px 18px; border-radius: 10px; font-size: 13px; font-weight: 600;
  border: 1px solid #e5e7eb; background: #f9fafb; color: #6b7280; cursor: pointer;
  transition: all .15s;
}}
.stage-tab:hover {{ background: #f1f5f9; border-color: #d1d5db; }}
.stage-tab.active {{ background: #1e40af; color: #fff; border-color: #1e40af; }}
.stage-num {{
  width: 22px; height: 22px; border-radius: 50%; background: rgba(255,255,255,0.25);
  display: inline-flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; flex-shrink: 0;
}}
.stage-tab:not(.active) .stage-num {{
  background: #e5e7eb; color: #6b7280;
}}

.view-toggle {{ display: flex; gap: 6px; margin-bottom: 16px; }}
.view-btn {{
  padding: 7px 16px; border-radius: 7px; font-size: 13px; font-weight: 600;
  border: 1px solid #e5e7eb; background: white; color: #6b7280; cursor: pointer;
  transition: all .15s;
}}
.view-btn:hover {{ background: #f9fafb; }}
.view-btn.active {{ background: #f1f5f9; color: #111827; border-color: #9ca3af; }}

.stage-summary {{
  display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
  padding: 10px 16px; background: #f8fafc; border-radius: 8px;
  font-size: 13px; color: #6b7280; margin-bottom: 16px;
  border: 1px solid #e5e7eb;
}}
.flow-sep {{ color: #d1d5db; }}

.candidate-card {{
  border: 1px solid #e5e7eb; border-radius: 12px; background: white;
  padding: 18px 20px; margin-bottom: 12px; position: relative;
}}
.candidate-card.rank-0 {{ border-left: 4px solid #1e40af; }}
.candidate-card.rank-1 {{ border-left: 3px solid #9ca3af; }}
.candidate-card.rank-2 {{ border-left: 3px solid #d1d5db; }}

.card-top {{ display: flex; gap: 12px; align-items: flex-start; margin-bottom: 14px; }}
.rank-badge {{
  width: 34px; height: 34px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; font-weight: 700;
}}
.rank-0 .rank-badge {{ background: #dbeafe; color: #1e40af; font-size: 16px; }}
.rank-1 .rank-badge {{ background: #f3f4f6; color: #6b7280; }}
.rank-2 .rank-badge {{ background: #f3f4f6; color: #9ca3af; }}

.ttp-id {{
  font-size: 13px; font-weight: 700; color: #1e40af;
  background: #eff6ff; padding: 3px 9px; border-radius: 5px;
  font-family: 'Courier New', monospace;
}}
.top-badge {{
  font-size: 11px; font-weight: 700; color: #1e40af;
  background: #dbeafe; padding: 3px 10px; border-radius: 99px;
}}
.ttp-name {{ font-size: 15px; font-weight: 700; color: #111827; margin: 5px 0 4px; }}
.ttp-desc {{ font-size: 13px; color: #6b7280; line-height: 1.6; }}

.score-row {{ display: flex; align-items: center; gap: 8px; margin-top: 14px; flex-wrap: wrap; }}
.score-block {{
  display: flex; flex-direction: column; align-items: center;
  background: #f9fafb; border-radius: 8px; padding: 8px 14px; min-width: 70px;
}}
.score-label {{ font-size: 11px; color: #9ca3af; margin-bottom: 3px; }}
.score-val {{ font-size: 22px; font-weight: 700; color: #111827; }}
.score-op {{ font-size: 18px; color: #d1d5db; }}
.score-final {{ background: #dbeafe; }}
.score-final .score-val {{ color: #1e40af; }}
.score-final .score-label {{ color: #60a5fa; }}

.mini-bars {{ flex: 1; min-width: 140px; display: flex; flex-direction: column; gap: 6px; }}
.mini-bar-row {{ display: flex; align-items: center; gap: 8px; }}
.mini-bar-lbl {{ font-size: 12px; color: #9ca3af; width: 28px; }}
.mini-bar-track {{ flex: 1; height: 7px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }}
.mini-bar-fill {{ height: 100%; border-radius: 4px; }}

.verified-tag {{
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 12px; color: #166534; background: #dcfce7;
  padding: 4px 10px; border-radius: 99px; margin-top: 10px;
}}
.ttp-link {{
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 12px; color: #2563eb; margin-top: 6px; margin-left: 10px;
  text-decoration: none;
}}
.ttp-link:hover {{ text-decoration: underline; }}

.chart-legend {{ display: flex; gap: 16px; font-size: 12px; color: #6b7280; margin-bottom: 16px; flex-wrap: wrap; }}
.legend-dot {{ width: 11px; height: 11px; border-radius: 2px; display: inline-block; margin-right: 5px; }}

.chart-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }}
.chart-id {{ font-family: monospace; font-size: 12px; width: 94px; flex-shrink: 0; text-align: right; }}
.chart-bars-col {{ flex: 1; display: flex; flex-direction: column; gap: 4px; }}
.chart-bar-row {{ display: flex; align-items: center; gap: 8px; }}
.chart-bar-lbl {{ font-size: 11px; width: 30px; flex-shrink: 0; }}
.chart-bar-track {{ flex: 1; height: 10px; background: #f1f5f9; border-radius: 5px; overflow: hidden; }}
.chart-bar-fill {{ height: 100%; border-radius: 5px; }}
.chart-bar-val {{ font-size: 12px; color: #6b7280; width: 24px; text-align: right; flex-shrink: 0; }}
.chart-total {{ font-size: 15px; font-weight: 700; color: #1e40af; width: 40px; text-align: right; flex-shrink: 0; }}

.reason-box {{
  margin-top: 16px; padding: 12px 16px; background: #f8fafc;
  border-radius: 8px; border: 1px solid #e5e7eb;
  font-size: 13px; color: #6b7280; line-height: 1.7;
}}
.reason-box strong {{ color: #374151; }}
</style>
</head>
<body>

<div id="app"></div>

<script>
const STAGES = {stages_json};
const MAX_SCORE = 20;

let curStage = 0;
let curView = 'cards';

function esc(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function flowHTML(flow) {{
  return flow.split('→').map(p => esc(p.trim())).join(
    ' <span class="flow-sep">→</span> '
  );
}}

function renderTabs() {{
  return STAGES.map((s, i) => `
    <button class="stage-tab ${{i===curStage?'active':''}}" onclick="setStage(${{i}})">
      <span class="stage-num">${{i+1}}</span>
      ${{esc(s.name.replace(/^[0-9]+단계:[ \t]*/, ''))}}
    </button>`).join('');
}}

function renderSummary(s) {{
  return `<span style="font-weight:700;color:#374151;margin-right:4px;">공격 흐름</span>
    ${{flowHTML(s.flow)}}`;
}}

function renderCards(s) {{
  return s.candidates.map((c, i) => {{
    const ruleW  = Math.round(c.rule  / MAX_SCORE * 100);
    const crossW = Math.round(c.cross / MAX_SCORE * 100);
    const isTop  = i === 0;
    return `
    <div class="candidate-card rank-${{i}}">
      <div class="card-top">
        <div class="rank-badge">${{isTop ? '★' : i+1}}</div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:3px;">
            <span class="ttp-id">${{esc(c.id)}}</span>
            ${{isTop ? '<span class="top-badge">대표 선정</span>' : ''}}
          </div>
          <div class="ttp-name">${{esc(c.name)}}</div>
          <div class="ttp-desc">${{esc(c.summary)}}</div>
        </div>
      </div>
      <div class="score-row">
        <div class="score-block">
          <span class="score-label">1차 점수</span>
          <span class="score-val">${{c.rule}}</span>
        </div>
        <span class="score-op">+</span>
        <div class="score-block">
          <span class="score-label">2차 점수</span>
          <span class="score-val">${{c.cross}}</span>
        </div>
        <span class="score-op">=</span>
        <div class="score-block score-final">
          <span class="score-label">최종</span>
          <span class="score-val">${{c.final}}</span>
        </div>
        <div class="mini-bars">
          <div class="mini-bar-row">
            <span class="mini-bar-lbl" style="color:#3b82f6;">1차</span>
            <div class="mini-bar-track">
              <div class="mini-bar-fill" style="width:${{ruleW}}%;background:#3b82f6;"></div>
            </div>
          </div>
          <div class="mini-bar-row">
            <span class="mini-bar-lbl" style="color:#8b5cf6;">2차</span>
            <div class="mini-bar-track">
              <div class="mini-bar-fill" style="width:${{crossW}}%;background:#8b5cf6;"></div>
            </div>
          </div>
        </div>
      </div>
      ${{c.verified ? '<div class="verified-tag">&#10003; ATT&CK Enterprise 인덱스 교차검증 확인</div>' : ''}}
      ${{c.url ? `<a class="ttp-link" href="${{esc(c.url)}}" target="_blank">&#8599; ATT&CK 원문 보기</a>` : ''}}
    </div>`;
  }}).join('');
}}

function renderChart(s) {{
  const sorted = [...s.candidates].sort((a,b) => b.final - a.final);
  const legend = `
    <div class="chart-legend">
      <span><span class="legend-dot" style="background:#3b82f6;"></span>1차 점수 (키워드 매칭)</span>
      <span><span class="legend-dot" style="background:#8b5cf6;"></span>2차 점수 (교차검증)</span>
      <span><span class="legend-dot" style="background:#1e40af;"></span>최종 합산</span>
    </div>`;

  const rows = sorted.map((c, i) => {{
    const ruleW  = Math.round(c.rule  / MAX_SCORE * 100);
    const crossW = Math.round(c.cross / MAX_SCORE * 100);
    const finalW = Math.round(c.final / MAX_SCORE * 100);
    const isTop  = i === 0;
    return `
    <div class="chart-row" style="opacity:${{isTop ? 1 : 0.72}};">
      <div class="chart-id" style="${{isTop ? 'color:#1e40af;font-weight:700;' : 'color:#6b7280;'}}">
        ${{esc(c.id)}}
      </div>
      <div class="chart-bars-col">
        <div class="chart-bar-row">
          <span class="chart-bar-lbl" style="color:#3b82f6;">1차</span>
          <div class="chart-bar-track">
            <div class="chart-bar-fill" style="width:${{ruleW}}%;background:#3b82f6;"></div>
          </div>
          <span class="chart-bar-val">${{c.rule}}</span>
        </div>
        <div class="chart-bar-row">
          <span class="chart-bar-lbl" style="color:#8b5cf6;">2차</span>
          <div class="chart-bar-track">
            <div class="chart-bar-fill" style="width:${{crossW}}%;background:#8b5cf6;"></div>
          </div>
          <span class="chart-bar-val">${{c.cross}}</span>
        </div>
        <div class="chart-bar-row">
          <span class="chart-bar-lbl" style="color:#1e40af;font-weight:700;">합산</span>
          <div class="chart-bar-track">
            <div class="chart-bar-fill" style="width:${{finalW}}%;background:#1e40af;"></div>
          </div>
          <span class="chart-bar-val" style="font-weight:700;color:#1e40af;">${{c.final}}</span>
        </div>
      </div>
      <span class="chart-total">${{c.final}}</span>
      ${{isTop ? '<span style="font-size:10px;background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:99px;font-weight:700;white-space:nowrap;">대표</span>' : ''}}
    </div>`;
  }}).join('');

  const reason = `
    <div class="reason-box">
      <strong>선정 이유 —</strong> ${{esc(s.reason)}}
    </div>`;

  return legend + rows + reason;
}}

function notifyHeight() {{
  const h = document.body.scrollHeight;
  window.parent.postMessage({{type: 'streamlit:setFrameHeight', height: h + 24}}, '*');
}}

function render() {{
  const s = STAGES[curStage];
  const html = `
    <div class="stage-tabs">${{renderTabs()}}</div>
    <div class="stage-summary">${{renderSummary(s)}}</div>
    <div class="view-toggle">
      <button class="view-btn ${{curView==='cards'?'active':''}}" onclick="setView('cards')">카드 뷰</button>
      <button class="view-btn ${{curView==='chart'?'active':''}}" onclick="setView('chart')">점수 비교 차트</button>
    </div>
    <div id="content">
      ${{curView === 'cards' ? renderCards(s) : renderChart(s)}}
    </div>`;
  document.getElementById('app').innerHTML = html;
  setTimeout(notifyHeight, 50);
}}

function setStage(i) {{ curStage = i; render(); }}
function setView(v)  {{ curView  = v; render(); }}

render();
window.addEventListener('load', notifyHeight);
</script>
</body>
</html>"""
    return html


def build_mitre_summary_html(rows) -> str:
    """
    MITRE ATT&CK 분석 파트 마무리 정리 카드를 HTML로 생성합니다.
    - 공격 흐름 타임라인: 단계별 대표 TTP를 화살표로 연결
    - 분석 결과 요약: 전술/기법 분류, 주요 인사이트 3가지
    - Threat Modeling 연계 안내
    """
    import json as _json

    # 단계별 대표 TTP 정보 추출
    stage_items = []
    tactic_map = {
        "T1505.003": ("지속성", "Persistence"),
        "T1190":     ("초기 침투", "Initial Access"),
        "T1105":     ("명령·제어", "C2"),
        "T1552.001": ("자격증명 접근", "Credential Access"),
        "T1552":     ("자격증명 접근", "Credential Access"),
        "T1005":     ("수집", "Collection"),
        "T1021.004": ("내부 이동", "Lateral Movement"),
        "T1021":     ("내부 이동", "Lateral Movement"),
        "T1078":     ("초기 침투 / 권한유지", "Defense Evasion"),
        "T1213.006": ("수집", "Collection"),
    }
    tactic_colors = {
        "초기 침투":       ("#dc2626", "#fee2e2"),
        "지속성":          ("#d97706", "#fef9c3"),
        "자격증명 접근":   ("#7c3aed", "#ede9fe"),
        "내부 이동":       ("#0369a1", "#e0f2fe"),
        "수집":            ("#166534", "#dcfce7"),
        "명령·제어":       ("#be185d", "#fce7f3"),
        "초기 침투 / 권한유지": ("#b45309", "#fef3c7"),
    }

    for row in rows:
        tid  = row["primary_ttp_id"]
        name = row["primary_ttp_name"]
        ko   = row["primary_ttp_summary_ko"]
        tactic_ko, _ = tactic_map.get(tid, ("기타", "Other"))
        t_color, t_bg = tactic_colors.get(tactic_ko, ("#374151", "#f3f4f6"))
        stage_items.append({
            "stage": row["stage"],
            "tid": tid,
            "name": name,
            "ko": ko,
            "tactic": tactic_ko,
            "t_color": t_color,
            "t_bg": t_bg,
        })

    # 전술 집합
    tactics = list(dict.fromkeys(s["tactic"] for s in stage_items))
    tactic_pills = "".join(
        f'<span style="background:{tactic_colors.get(t,("","#f3f4f6"))[1]};'
        f'color:{tactic_colors.get(t,("#374151",""))[0]};'
        f'font-size:12px;font-weight:700;padding:4px 12px;border-radius:99px;">{t}</span>'
        for t in tactics
    )

    # 타임라인 카드
    timeline_cards = ""
    for i, s in enumerate(stage_items):
        arrow = (
            f'<div style="display:flex;align-items:center;justify-content:center;'
            f'color:#d1d5db;font-size:20px;font-weight:700;padding:0 2px;">→</div>'
            if i < len(stage_items) - 1 else ""
        )
        stage_num = i + 1
        timeline_cards += f"""
        <div style="flex:1;min-width:0;">
          <div style="border:1px solid #e5e7eb;border-radius:10px;background:white;
                      padding:14px 16px;border-top:3px solid {s['t_color']};">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px;">
              <span style="width:22px;height:22px;border-radius:50%;
                           background:{s['t_bg']};color:{s['t_color']};
                           font-size:11px;font-weight:700;display:inline-flex;
                           align-items:center;justify-content:center;flex-shrink:0;">{stage_num}</span>
              <span style="font-size:10px;font-weight:700;color:{s['t_color']};
                           background:{s['t_bg']};padding:2px 8px;border-radius:99px;">{s['tactic']}</span>
            </div>
            <div style="font-family:'Courier New',monospace;font-size:12px;
                        font-weight:700;color:{s['t_color']};margin-bottom:4px;">{s['tid']}</div>
            <div style="font-size:13px;font-weight:700;color:#111827;
                        margin-bottom:4px;line-height:1.4;">{s['name']}</div>
            <div style="font-size:12px;color:#6b7280;line-height:1.5;">{s['ko']}</div>
          </div>
        </div>
        {arrow}"""

    # 주요 인사이트
    insights = [
        ("단계적 침투 구조",
         "이번 공격은 단일 취약점 하나로 끝나지 않고 웹쉘 → 계정 탈취 → 내부 이동 → 데이터 수집으로 "
         "이어지는 연쇄 공격 체인을 형성했습니다. 각 단계가 이전 단계의 성공을 전제로 설계되어 있어 "
         "초기 단계 차단이 전체 피해를 막는 데 결정적입니다."),
        ("내부망 신뢰 과다 부여",
         "ServerA에서 ServerB로의 SSH 접근이 무제한 허용된 것이 내부 이동을 가능하게 했습니다. "
         "탈취한 계정 하나만으로 코어망 진입이 가능한 구조는 네트워크 세그멘테이션과 "
         "최소권한 원칙 미적용을 보여줍니다."),
        ("데이터 보호 통제 부재",
         "2,696만 건의 USIM 데이터가 평문으로 저장되어 있어 단순 DB 접근만으로 "
         "전체 데이터를 즉시 탈취할 수 있었습니다. 암호화·감사로그·대량 조회 탐지 중 "
         "어느 것도 작동하지 않았습니다."),
    ]

    insight_cards = ""
    icons  = ["🔗", "🌐", "🗄️"]
    colors = [("#1e40af", "#eff6ff"), ("#7c3aed", "#f5f3ff"), ("#dc2626", "#fff1f2")]
    for (title, desc), icon, (tc, bc) in zip(insights, icons, colors):
        insight_cards += f"""
        <div style="flex:1;min-width:220px;border:1px solid #e5e7eb;border-radius:10px;
                    background:{bc};padding:16px 18px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
            <span style="font-size:18px;">{icon}</span>
            <span style="font-size:13px;font-weight:700;color:{tc};">{title}</span>
          </div>
          <p style="font-size:13px;color:#374151;line-height:1.7;margin:0;">{desc}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: Arial, Helvetica, sans-serif; background: white; font-size: 14px; }}
</style>
</head>
<body style="padding: 4px 0 8px;">

  <div style="border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:16px;">
    <div style="background:#1e293b;padding:14px 20px;display:flex;
                align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
      <div>
        <div style="font-size:11px;font-weight:700;color:#94a3b8;
                    letter-spacing:2px;margin-bottom:4px;">MITRE ATT&CK 분석 결과</div>
        <div style="font-size:17px;font-weight:700;color:white;">
          총 {len(stage_items)}개 단계 · {len(stage_items)}개 대표 TTP 선정
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">{tactic_pills}</div>
    </div>

    <div style="padding:18px 20px;background:#f8fafc;">
      <div style="font-size:12px;font-weight:700;color:#6b7280;
                  letter-spacing:1px;margin-bottom:14px;">공격 체인 타임라인</div>
      <div style="display:flex;align-items:stretch;gap:6px;flex-wrap:nowrap;overflow-x:auto;">
        {timeline_cards}
      </div>
    </div>
  </div>

  <div>
    <div style="font-size:12px;font-weight:700;color:#6b7280;
                letter-spacing:1px;margin-bottom:12px;">주요 인사이트</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;">
      {insight_cards}
    </div>
  </div>

</body></html>"""
    return html