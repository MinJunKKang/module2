import textwrap
import streamlit as st
import streamlit.components.v1 as components
from config import MISSIONS

from llm.mitre_pipeline import (
    INTRO_TEXT,
    MITRE_EASY_TEXT,
    WHY_MAPPING_TEXT,
    build_report_data,
    build_candidate_mapping_html,
    build_mitre_summary_html,
)

from llm.threat_modeling_pipeline import (
    THREAT_MODELING_TEXT,
    DFD_TEXT,
    STRIDE_TEXT,
    DREAD_TEXT,
    SECURITY_REQ_TEXT,
    build_dfd_graph,
    build_stride_heatmap_html,
    build_dread_cards_html,
    build_dread_bar_chart,
    build_dread_radar,
    build_security_requirements_df,
    build_security_requirement_details,
)


def get_completed_attack_count(missions, completed_state):
    return sum(
        1 for name, _, mission_type in missions
        if mission_type == "attack" and completed_state[name]
    )


def estimate_table_height(row_count: int, base: int = 64, row_px: int = 44, max_height: int = 1400) -> int:
    height = base + (row_count + 1) * row_px
    return min(max(height, 180), max_height)


def render_html_table(
    df,
    col_widths=None,
    height=None,
    allow_horizontal_scroll=False,
    allow_vertical_scroll=False,
    max_table_height_px=None,
):
    html_table = df.to_html(index=False, escape=False)

    if height is None:
        height = estimate_table_height(len(df))

    width_css = ""
    if col_widths:
        width_rules = []
        for idx, width in enumerate(col_widths, start=1):
            width_rules.append(
                f"""
                th:nth-child({idx}), td:nth-child({idx}) {{
                    width: {width};
                }}
                """
            )
        width_css = "\n".join(width_rules)

    wrapper_overflow_x = "auto" if allow_horizontal_scroll else "visible"
    wrapper_overflow_y = "auto" if allow_vertical_scroll else "visible"
    table_layout = "fixed" if not allow_horizontal_scroll else "auto"
    min_width = "1400px" if allow_horizontal_scroll else "100%"

    inner_wrapper_style = ""
    if max_table_height_px:
        inner_wrapper_style = f"max-height:{max_table_height_px}px; overflow-y:auto;"

    html_block = textwrap.dedent(f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: white;
        }}

        .outer-table-wrapper {{
            width: 100%;
            overflow-x: {wrapper_overflow_x};
            overflow-y: {wrapper_overflow_y};
        }}

        .inner-table-wrapper {{
            {inner_wrapper_style}
        }}

        table {{
            width: 100%;
            min-width: {min_width};
            border-collapse: collapse;
            table-layout: {table_layout};
            font-size: 14px;
        }}

        th, td {{
            border: 1px solid #e5e7eb;
            padding: 10px 12px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
            white-space: normal;
            line-height: 1.6;
        }}

        th {{
            background: #f8fafc;
            font-weight: 700;
            position: sticky;
            top: 0;
            z-index: 2;
        }}

        a {{
            color: #2563eb;
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        {width_css}
    </style>
    </head>
    <body>
        <div class="outer-table-wrapper">
            <div class="inner-table-wrapper">
                {html_table}
            </div>
        </div>
    </body>
    </html>
    """)

    components.html(html_block, height=height, scrolling=False)


def render_report_header():
    st.markdown(
        """
<div style="color:#2563eb;font-size:13px;font-weight:700;letter-spacing:2px;padding:14px 0 6px 0;">
📊 INCIDENT ANALYSIS REPORT — MITRE ATT&CK + THREAT MODELING
</div>
""",
        unsafe_allow_html=True,
    )


def render_intro_section():
    st.markdown("### 🧾 분석 리포트")
    st.info(INTRO_TEXT.strip())


def render_mitre_explainer():
    st.markdown("### 🎯 MITRE ATT&CK란?")
    st.markdown(MITRE_EASY_TEXT.strip())

    st.markdown("### ✅ ATT&CK 매핑을 하면 뭐가 좋을까?")
    st.markdown(WHY_MAPPING_TEXT.strip())


def render_candidate_mapping(rows):

    score_guide_html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, Helvetica, sans-serif; background: white; }
.wrap { display: flex; align-items: stretch; gap: 0; border: 1px solid #e5e7eb; border-radius: 10px; overflow: hidden; }
.col { flex: 1; padding: 14px 16px; }
.col + .col { border-left: 1px solid #e5e7eb; }
.col-1 { background: #eff6ff; }
.col-2 { background: #f5f3ff; }
.col-3 { background: #f0fdf4; }
.col-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.step-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 99px; white-space: nowrap; }
.s1 { background: #dbeafe; color: #1e40af; }
.s2 { background: #ede9fe; color: #6d28d9; }
.s3 { background: #dcfce7; color: #166534; }
.col-title { font-size: 13px; font-weight: 700; color: #111827; }
.tier-row { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }
.tier-label { font-size: 11px; color: #6b7280; width: 52px; flex-shrink: 0; }
.tier-bar-wrap { flex: 1; height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; }
.tier-bar { height: 100%; border-radius: 3px; }
.tier-val { font-size: 11px; font-weight: 600; width: 44px; text-align: right; flex-shrink: 0; }
.b1 { background: #3b82f6; }
.b2 { background: #7c3aed; }
.b3 { background: #16a34a; }
.v1 { color: #1e40af; }
.v2 { color: #6d28d9; }
.v3 { color: #166534; }
.col-desc { font-size: 11px; color: #6b7280; margin-top: 8px; line-height: 1.5; }
.eq { display: flex; align-items: center; justify-content: center; font-size: 18px; color: #d1d5db; font-weight: 700; flex-shrink: 0; padding: 0 2px; align-self: center; }
</style></head><body>
<div class="wrap">
  <div class="col col-1">
    <div class="col-head">
      <span class="step-badge s1">1차 점수</span>
      <span class="col-title">키워드 매칭</span>
    </div>
    <div class="tier-row"><span class="tier-label">직접 일치</span><div class="tier-bar-wrap"><div class="tier-bar b1" style="width:100%"></div></div><span class="tier-val v1">+5~10</span></div>
    <div class="tier-row"><span class="tier-label">부분 관련</span><div class="tier-bar-wrap"><div class="tier-bar b1" style="width:50%"></div></div><span class="tier-val v1">+2~4</span></div>
    <div class="tier-row"><span class="tier-label">간접/보조</span><div class="tier-bar-wrap"><div class="tier-bar b1" style="width:20%"></div></div><span class="tier-val v1">+0~2</span></div>
    <p class="col-desc">공격 시나리오 텍스트와 TTP 키워드 간 직접 연관성 평가</p>
  </div>
  <div class="eq">+</div>
  <div class="col col-2">
    <div class="col-head">
      <span class="step-badge s2">2차 점수</span>
      <span class="col-title">교차 검증</span>
    </div>
    <div class="tier-row"><span class="tier-label">명확 일치</span><div class="tier-bar-wrap"><div class="tier-bar b2" style="width:100%"></div></div><span class="tier-val v2">+2~4</span></div>
    <div class="tier-row"><span class="tier-label">일부 일치</span><div class="tier-bar-wrap"><div class="tier-bar b2" style="width:50%"></div></div><span class="tier-val v2">+1~2</span></div>
    <div class="tier-row"><span class="tier-label">관련성 낮음</span><div class="tier-bar-wrap"><div class="tier-bar b2" style="width:0%"></div></div><span class="tier-val v2">+0</span></div>
    <p class="col-desc">MITRE 공식 기술 설명 텍스트 및 Enterprise 인덱스 기반 검증</p>
  </div>
  <div class="eq">=</div>
  <div class="col col-3">
    <div class="col-head">
      <span class="step-badge s3">최종 점수</span>
      <span class="col-title">1차 + 2차 합산</span>
    </div>
    <div class="tier-row"><span class="tier-label">높을수록</span><div class="tier-bar-wrap"><div class="tier-bar b3" style="width:100%"></div></div><span class="tier-val v3">대표 선정</span></div>
    <div class="tier-row"><span class="tier-label">중간</span><div class="tier-bar-wrap"><div class="tier-bar b3" style="width:55%"></div></div><span class="tier-val v3">후보 유지</span></div>
    <div class="tier-row"><span class="tier-label">낮을수록</span><div class="tier-bar-wrap"><div class="tier-bar b3" style="width:20%"></div></div><span class="tier-val v3">하위 순위</span></div>
    <p class="col-desc">가장 높은 점수의 TTP를 해당 단계 대표 기법으로 선정</p>
  </div>
</div>
</body></html>"""
    components.html(score_guide_html, height=160, scrolling=False)

    st.divider()

    mapping_html = build_candidate_mapping_html(rows)
    max_candidates = max((len(row["validated_ttps"]) for row in rows), default=3)
    dynamic_height = 60 + 52 + 44 + max_candidates * 215 + 40
    components.html(mapping_html, height=dynamic_height, scrolling=True)


def render_mapping_section(rows):
    st.markdown("### 🗺️ 단계별 ATT&CK 매핑")
    st.caption(
        "각 단계마다 여러 TTP 후보를 함께 제시하고, "
        "1차 키워드 점수와 2차 교차검증 점수를 합산해 대표 기법을 선정합니다."
    )
    render_candidate_mapping(rows)

    summary_html = build_mitre_summary_html(rows)
    # 타임라인(~260) + 인사이트 3열(~190) + 연계 안내(~90) + 헤더(~70)
    components.html(summary_html, height=500, scrolling=False)


def render_threat_modeling_flow():
    flow_html = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, Helvetica, sans-serif; background: white; padding: 4px 0 8px; }
.flow { display: flex; align-items: stretch; gap: 0; }
.step {
    flex: 1; border-radius: 14px; padding: 20px 18px;
    display: flex; flex-direction: column; gap: 6px;
}
.step-1 { background: #eef4ff; border: 1px solid #d7e3ff; }
.step-2 { background: #f5f3ff; border: 1px solid #ddd6fe; }
.step-3 { background: #fff7ed; border: 1px solid #fed7aa; }
.step-4 { background: #ecfdf5; border: 1px solid #bbf7d0; }
.step-num {
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
}
.c1 { color: #2563eb; } .c2 { color: #7c3aed; }
.c3 { color: #ea580c; } .c4 { color: #059669; }
.step-title { font-size: 22px; font-weight: 800; color: #111827; }
.step-tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 2px; }
.tag {
    font-size: 11px; font-weight: 600; padding: 2px 8px;
    border-radius: 99px; white-space: nowrap;
}
.t1 { background: #dbeafe; color: #1e40af; }
.t2 { background: #ede9fe; color: #6d28d9; }
.t3 { background: #ffedd5; color: #c2410c; }
.t4 { background: #d1fae5; color: #065f46; }
.step-desc { font-size: 13px; color: #4b5563; line-height: 1.6; margin-top: 4px; }
.arrow {
    display: flex; align-items: center; justify-content: center;
    padding: 0 10px; font-size: 22px; color: #cbd5e1;
    flex-shrink: 0;
}
</style>
</head>
<body>
<div class="flow">

  <div class="step step-1">
    <div class="step-num c1">STEP 1</div>
    <div class="step-title">DFD</div>
    <div class="step-tags">
      <span class="tag t1">데이터 흐름</span>
      <span class="tag t1">시스템 구조</span>
    </div>
    <div class="step-desc">시스템 안에서 데이터가 어디를 지나는지 그림으로 파악</div>
  </div>

  <div class="arrow">→</div>

  <div class="step step-2">
    <div class="step-num c2">STEP 2</div>
    <div class="step-title">STRIDE</div>
    <div class="step-tags">
      <span class="tag t2">6가지 위협 유형</span>
      <span class="tag t2">위협 식별</span>
    </div>
    <div class="step-desc">각 구성 요소에서 발생 가능한 위협을 유형별로 분류</div>
  </div>

  <div class="arrow">→</div>

  <div class="step step-3">
    <div class="step-num c3">STEP 3</div>
    <div class="step-title">DREAD</div>
    <div class="step-tags">
      <span class="tag t3">위험도 점수화</span>
      <span class="tag t3">우선순위</span>
    </div>
    <div class="step-desc">위협마다 5가지 항목을 점수로 평가해 대응 순서 결정</div>
  </div>

  <div class="arrow">→</div>

  <div class="step step-4">
    <div class="step-num c4">STEP 4</div>
    <div class="step-title">보안명세서</div>
    <div class="step-tags">
      <span class="tag t4">요구사항 도출</span>
      <span class="tag t4">구현 가이드</span>
    </div>
    <div class="step-desc">위협별 보안 목표·요구사항·검증 방법을 문서로 정리</div>
  </div>

</div>
</body></html>"""
    components.html(flow_html, height=180, scrolling=False)


def render_threat_modeling_intro():
    st.markdown("### 🛡️ Threat Modeling이란?")
    st.markdown(THREAT_MODELING_TEXT.strip())
    render_threat_modeling_flow()


def render_dfd_section():
    st.markdown("### 1) DFD")
    st.markdown(DFD_TEXT.strip())
    st.graphviz_chart(build_dfd_graph(), use_container_width=True)


# ============================================================
# STRIDE 히트맵 렌더러 (신규)
# ============================================================

def render_stride_section():
    st.markdown("### 2) STRIDE 위협 식별")
    st.markdown(STRIDE_TEXT.strip())

    # 히트맵 HTML 렌더링
    heatmap_html = build_stride_heatmap_html()
    # 행 수에 맞게 높이 계산: 헤더(70) + 행당 약 75px
    row_count = 4
    height = 70 + row_count * 80 + 70  # 헤더 + 행들 + 범례
    components.html(heatmap_html, height=height, scrolling=False)


# ============================================================
# DREAD 렌더러 (신규: 카드 + 바 차트 + 레이더)
# ============================================================

def render_dread_section():
    st.markdown("### 3) DREAD 위험도 평가")
    st.markdown(DREAD_TEXT.strip())

    # --- 카드 그리드 ---
    st.markdown("### 📋 단계별 항목 점수")
    cards_html = build_dread_cards_html()
    # 카드 2열 × 2행, 카드 하나 약 185px + 여백
    components.html(cards_html, height=420, scrolling=False)

    st.divider()

    # --- 바 차트 + 레이더 나란히 ---
    st.markdown("### 📊 DREAD 총점 순위 및 항목 비교")
    col_bar, col_radar = st.columns([1, 1.1], gap="large")

    with col_bar:
        st.caption("🔴 Critical (42+)  🟡 High (35–41)  🟢 Medium (~34)")
        st.plotly_chart(
            build_dread_bar_chart(),
            use_container_width=True,
            config={"displayModeBar": False},
        )

    with col_radar:
        st.caption("단계별 5개 항목 분포 비교 — 넓을수록 전방위 위협")
        st.plotly_chart(
            build_dread_radar(),
            use_container_width=True,
            config={"displayModeBar": False},
        )


# ============================================================
# 보안 요구사항 명세 렌더러
# ============================================================

def render_security_requirements_section():
    st.markdown("### 4) 보안 요구사항 명세서")
    st.markdown(SECURITY_REQ_TEXT.strip())

    summary_df = build_security_requirements_df()

    render_html_table(
        summary_df,
        col_widths=["18%", "18%", "44%", "10%"],
        height=360,
        allow_horizontal_scroll=False,
        allow_vertical_scroll=True,
        max_table_height_px=320,
    )

    st.markdown("### 📝 단계별 상세 명세")
    details = build_security_requirement_details()

    priority_color = {"Critical": "#dc2626", "High": "#d97706", "Medium": "#16a34a"}

    for item in details:
        p_color = priority_color.get(item["우선순위"], "#6b7280")
        with st.expander(f"{item['단계']} — 보안 요구사항 상세"):
            # 요약 메트릭 카드
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("**요구사항 ID**", item["요구사항 ID"])
            m2.metric("**DREAD 총점**", f"{item['DREAD 총점']}/50")
            m3.metric("**우선순위**", item["우선순위"])
            m4.metric("**관련 STRIDE**", item["관련 위협"].split(",")[0].strip())

            st.markdown(f"**보호 대상 자산:** {item['자산']}")
            st.divider()

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**🎯 보안 목표**")
                st.info(item["보안 목표"])

                st.markdown("**📋 보안 요구사항**")
                st.write(item["보안 요구사항"])

            with c2:
                st.markdown("**🔧 구현 가이드**")
                st.write(item["구현 가이드"])

                st.markdown("**✅ 검증 방법**")
                st.write(item["검증 방법"])


def render_threat_modeling_section():
    render_threat_modeling_intro()
    st.divider()

    render_dfd_section()
    st.divider()

    render_stride_section()
    st.divider()

    render_dread_section()
    st.divider()

    render_security_requirements_section()


def render_report_tab(missions=None):
    if missions is None:
        missions = MISSIONS

    render_report_header()

    completed_count = get_completed_attack_count(missions, st.session_state.completed)

    if completed_count < 4:
        st.warning(
            f"공격 시나리오 4단계를 모두 완료해야 리포트를 생성할 수 있습니다. (현재 {completed_count}/4)"
        )
        st.progress(completed_count / 4)
        return

    st.success("공격 시나리오 완료! 분석 리포트를 생성하세요.")

    if st.button("🤖 분석 리포트 생성"):
        with st.spinner("MITRE ATT&CK 및 Threat Modeling 분석 생성 중..."):
            rows = build_report_data()

            render_intro_section()
            st.divider()

            render_mitre_explainer()
            st.divider()

            render_mapping_section(rows)
            st.divider()

            render_threat_modeling_section()


def render():
    render_report_tab()