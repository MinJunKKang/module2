import streamlit as st
import plotly.graph_objects as go
from config import MISSIONS

# ============================
# 공격 흐름 데이터
# ============================
ATTACK_FLOW = [
    {
        "step": "01",
        "title": "웹쉘 업로드",
        "attck": "T1190",
        "desc": "파일 업로드 취약점 악용\nshell.php 업로드 → OS 명령 실행",
        "color": "#dc2626",
    },
    {
        "step": "02",
        "title": "계정정보 탈취",
        "attck": "T1552",
        "desc": "설정 파일 평문 계정정보 획득\nServerB IP / USER / PASS 탈취",
        "color": "#ea580c",
    },
    {
        "step": "03",
        "title": "Lateral Movement",
        "attck": "T1021",
        "desc": "탈취 계정으로 내부망 SSH 접속\nServerA → ServerB 이동",
        "color": "#d97706",
    },
    {
        "step": "04",
        "title": "DB 데이터 탈취",
        "attck": "T1005",
        "desc": "유심 DB 전체 덤프\n2,696만 건 / 9.82GB 유출",
        "color": "#7c3aed",
    },
]

ANALYSIS_DATA = [
    {
        "단계": "웹쉘 업로드",
        "ATTCK": "T1190 — Exploit Public-Facing Application",
        "STRIDE": "Tampering / Elevation of Privilege",
        "DREAD": {"피해규모": 8, "재현가능성": 9, "악용가능성": 9, "영향받는사용자": 7, "발견가능성": 6},
        "대응방안": "업로드 파일 확장자 화이트리스트 검증, 업로드 디렉토리 실행 권한 제거, WAF 룰 적용, 파일 타입 서버사이드 재검증",
    },
    {
        "단계": "계정정보 탈취",
        "ATTCK": "T1552 — Unsecured Credentials",
        "STRIDE": "Information Disclosure",
        "DREAD": {"피해규모": 9, "재현가능성": 8, "악용가능성": 9, "영향받는사용자": 8, "발견가능성": 5},
        "대응방안": "Secrets Manager / Vault 사용, 설정 파일 암호화, 최소 권한 원칙 적용, 하드코딩 금지 정책 수립",
    },
    {
        "단계": "Lateral Movement",
        "ATTCK": "T1021 — Remote Services (SSH)",
        "STRIDE": "Spoofing / Elevation of Privilege",
        "DREAD": {"피해규모": 9, "재현가능성": 7, "악용가능성": 8, "영향받는사용자": 9, "발견가능성": 5},
        "대응방안": "내부망 네트워크 세그멘테이션 적용, SSH MFA 강제화, 취약 패스워드 정책 강화, Zero Trust 아키텍처 도입",
    },
    {
        "단계": "DB 데이터 탈취",
        "ATTCK": "T1005 — Data from Local System",
        "STRIDE": "Information Disclosure",
        "DREAD": {"피해규모": 10, "재현가능성": 7, "악용가능성": 8, "영향받는사용자": 10, "발견가능성": 4},
        "대응방안": "DB 컬럼 레벨 암호화 (Ki/OPc), 대용량 덤프 이상 감지 알람, DB 접근 감사 로그 활성화, HSM 기반 키 관리",
    },
]


def render_flow_chart():
    """공격 흐름 단계도 (Plotly)"""
    fig = go.Figure()

    n = len(ATTACK_FLOW)
    x_positions = [i * 2.5 for i in range(n)]

    # 화살표 (단계 사이 연결선)
    for i in range(n - 1):
        fig.add_annotation(
            x=x_positions[i + 1] - 0.2, y=0.5,
            ax=x_positions[i] + 0.2, ay=0.5,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True,
            arrowhead=2, arrowsize=1.5, arrowwidth=2,
            arrowcolor="#94a3b8",
        )

    # 각 단계 박스
    for i, stage in enumerate(ATTACK_FLOW):
        x = x_positions[i]
        # 박스 배경
        fig.add_shape(
            type="rect",
            x0=x - 0.9, y0=0.05, x1=x + 0.9, y1=0.95,
            fillcolor=stage["color"] + "22",
            line=dict(color=stage["color"], width=2),
            layer="below",
        )
        # 단계 번호
        fig.add_annotation(
            x=x, y=0.82, text=f"STAGE {stage['step']}",
            font=dict(size=11, color=stage["color"], family="monospace"),
            showarrow=False,
        )
        # 제목
        fig.add_annotation(
            x=x, y=0.65, text=f"<b>{stage['title']}</b>",
            font=dict(size=13, color="#1a1a2e"),
            showarrow=False,
        )
        # ATT&CK 태그
        fig.add_annotation(
            x=x, y=0.5, text=stage["attck"],
            font=dict(size=11, color=stage["color"], family="monospace"),
            showarrow=False,
        )
        # 설명
        fig.add_annotation(
            x=x, y=0.28,
            text=stage["desc"].replace("\n", "<br>"),
            font=dict(size=10, color="#4a5568"),
            showarrow=False,
            align="center",
        )

    fig.update_layout(
        xaxis=dict(visible=False, range=[-1, x_positions[-1] + 1]),
        yaxis=dict(visible=False, range=[0, 1]),
        plot_bgcolor="#ffffff",
        paper_bgcolor="#ffffff",
        margin=dict(l=20, r=20, t=20, b=20),
        height=220,
    )
    return fig


def render_radar_chart():
    """DREAD 레이더 차트"""
    cats = ["피해규모", "재현가능성", "악용가능성", "영향받는사용자", "발견가능성"]
    colors = ["#dc2626", "#ea580c", "#d97706", "#7c3aed"]
    fig = go.Figure()
    for i, s in enumerate(ANALYSIS_DATA):
        vals = [s["DREAD"][c] for c in cats]
        vals.append(vals[0])
        fig.add_trace(go.Scatterpolar(
            r=vals, theta=cats + [cats[0]],
            fill="toself", name=s["단계"],
            line=dict(color=colors[i], width=2),
            fillcolor=colors[i] + "33",
        ))
    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 10], gridcolor="#e2e8f0", color="#718096"),
            angularaxis=dict(gridcolor="#e2e8f0", color="#1a1a2e"),
            bgcolor="#ffffff",
        ),
        paper_bgcolor="#ffffff",
        showlegend=True,
        legend=dict(font=dict(color="#1a1a2e", size=12)),
        margin=dict(l=40, r=40, t=40, b=40),
        height=380,
    )
    return fig


def build_report_html():
    """최종 보고서 HTML 문자열 생성"""
    rows = ""
    for s in ANALYSIS_DATA:
        total = sum(s["DREAD"].values())
        dread_str = " / ".join(f"{k}:{v}" for k, v in s["DREAD"].items())
        rows += f"""
        <tr>
            <td>{s['단계']}</td>
            <td style="font-family:monospace;font-size:12px;">{s['ATTCK']}</td>
            <td>{s['STRIDE']}</td>
            <td style="text-align:center;font-weight:700;color:#dc2626;">{total}/50</td>
            <td style="font-size:12px;">{s['대응방안']}</td>
        </tr>"""

    completed = sum(st.session_state.completed.values())

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<style>
  body {{ font-family: 'Malgun Gothic', sans-serif; padding: 40px; color: #1a1a2e; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }}
  h2 {{ color: #2563eb; margin-top: 32px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th {{ background: #1a1a2e; color: #fff; padding: 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; }}
  .red {{ background:#fee2e2; color:#dc2626; }}
  .blue {{ background:#dbeafe; color:#2563eb; }}
  .summary {{ background:#f1f5f9; border-left:4px solid #2563eb; padding:16px; margin:16px 0; border-radius:4px; }}
</style>
</head>
<body>
<h1>🔐 SKT 침해사고 모의훈련 최종 보고서</h1>
<div class="summary">
  <b>훈련 완료율:</b> {completed}/{len(MISSIONS)} 미션 완료 &nbsp;|&nbsp;
  <b>공격 시나리오:</b> 4단계 완료 &nbsp;|&nbsp;
  <b>분석 프레임워크:</b> MITRE ATT&CK / STRIDE / DREAD
</div>

<h2>① 공격 흐름 요약</h2>
<table>
  <tr><th>단계</th><th>ATT&CK</th><th>STRIDE</th><th>DREAD 합산</th><th>대응방안</th></tr>
  {rows}
</table>

<h2>② 주요 취약점</h2>
<ul>
  <li>파일 업로드 확장자 검증 없음 → 웹쉘 실행 가능</li>
  <li>설정 파일 평문 계정정보 저장 → 내부망 계정 탈취</li>
  <li>내부망 SSH 무제한 허용 + 취약 패스워드 → Lateral Movement</li>
  <li>DB 민감 데이터(Ki) 평문 저장 → 유심 복제 가능</li>
</ul>

<h2>③ 핵심 대응 방안</h2>
<ul>
  <li>업로드 파일 확장자 화이트리스트 + 실행 권한 제거</li>
  <li>AWS Secrets Manager / HashiCorp Vault 도입</li>
  <li>내부망 네트워크 세그멘테이션 + Zero Trust 적용</li>
  <li>DB 컬럼 레벨 암호화 (AES-256) + HSM 키 관리</li>
  <li>LLM 기반 웹쉘 탐지 시스템 도입</li>
</ul>
</body>
</html>"""


def render():
    st.markdown("""<div style="color:#2563eb;font-size:13px;font-weight:700;
        letter-spacing:2px;padding:14px 0 6px 0;">📊 INCIDENT ANALYSIS REPORT — ATT&CK / STRIDE / DREAD</div>""",
        unsafe_allow_html=True)

    completed_count = sum(1 for k, _, t in MISSIONS if t == "attack" and st.session_state.completed[k])

    if completed_count < 4:
        st.warning(f"공격 시나리오 4단계를 모두 완료해야 리포트를 생성할 수 있습니다. (현재 {completed_count}/4)")
        st.progress(completed_count / 4)
        return

    st.success("공격 시나리오 완료! 분석 리포트를 확인하세요.")

    # 공격 흐름 단계도
    st.markdown("### 🔴 공격 흐름 단계도")
    st.plotly_chart(render_flow_chart(), use_container_width=True)

    # ATT&CK / STRIDE 테이블 + DREAD 레이더
    st.markdown("### 🎯 ATT&CK / STRIDE / DREAD 분석")
    c1, c2 = st.columns([1, 1], gap="large")
    with c1:
        st.table({
            "단계":   [d["단계"]  for d in ANALYSIS_DATA],
            "ATT&CK": [d["ATTCK"] for d in ANALYSIS_DATA],
            "STRIDE": [d["STRIDE"] for d in ANALYSIS_DATA],
        })
    with c2:
        st.plotly_chart(render_radar_chart(), use_container_width=True)

    # 단계별 대응 방안
    st.markdown("### 🛡️ 단계별 대응 방안")
    for s in ANALYSIS_DATA:
        total = sum(s["DREAD"].values())
        with st.expander(f"  {s['단계']}  —  {s['ATTCK']}"):
            st.markdown(f"""<div style="font-size:14px;color:#718096;margin-bottom:8px;">
                DREAD 합산 위험도: <span style="color:#dc2626;font-size:18px;font-weight:700;">{total}</span>/50
            </div>""", unsafe_allow_html=True)
            st.write(s["대응방안"])

    # 최종 보고서 다운로드
    st.markdown("### 📄 최종 보고서 출력")
    st.download_button(
        label="⬇️  HTML 보고서 다운로드",
        data=build_report_html().encode("utf-8"),
        file_name="SKT_침해사고_모의훈련_보고서.html",
        mime="text/html",
        use_container_width=True,
    )