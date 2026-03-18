import streamlit as st
import plotly.graph_objects as go
from config import MISSIONS
from llm.report_generator import generate_report

ATTACK_STAGES = [
    "웹쉘 업로드 (T1190)",
    "평문 계정정보 탈취 (T1552)",
    "SSH Lateral Movement (T1021)",
    "DB 데이터 탈취 (T1005)",
]


def render():
    st.markdown("""<div style="color:#2563eb;font-size:13px;font-weight:700;
        letter-spacing:2px;padding:14px 0 6px 0;">📊 INCIDENT ANALYSIS REPORT — ATT&CK / STRIDE / DREAD</div>""",
        unsafe_allow_html=True)

    completed_count = sum(1 for k, _, t in MISSIONS if t == "attack" and st.session_state.completed[k])

    if completed_count < 4:
        st.warning(f"공격 시나리오 4단계를 모두 완료해야 리포트를 생성할 수 있습니다. (현재 {completed_count}/4)")
        st.progress(completed_count / 4)
        return

    st.success("공격 시나리오 완료! LLM 기반 보안 분석 리포트를 생성하세요.")
    if st.button("🤖  LLM 분석 리포트 생성"):
        with st.spinner("ATT&CK 매핑 / STRIDE 분류 / DREAD 위험도 산정 중..."):
            try:
                result = generate_report(ATTACK_STAGES)

                c1, c2 = st.columns([1, 1], gap="large")
                with c1:
                    st.subheader("🎯 ATT&CK / STRIDE 매핑")
                    st.table({
                        "단계":   [d["단계"]  for d in result["단계별분석"]],
                        "ATT&CK": [d["ATTCK"] for d in result["단계별분석"]],
                        "STRIDE": [d["STRIDE"] for d in result["단계별분석"]],
                    })
                with c2:
                    st.subheader("📡 DREAD 위험도 레이더")
                    cats = ["피해규모", "재현가능성", "악용가능성", "영향받는사용자", "발견가능성"]
                    colors = ["#ff3e3e", "#ffd600", "#ff8800", "#00cfff"]
                    fig = go.Figure()
                    for i, s in enumerate(result["단계별분석"]):
                        vals = [int(s["DREAD"].get(c, 5)) for c in cats]
                        vals.append(vals[0])
                        fig.add_trace(go.Scatterpolar(
                            r=vals, theta=cats + [cats[0]],
                            fill='toself', name=s["단계"],
                            line=dict(color=colors[i % len(colors)], width=2),
                        ))
                    fig.update_layout(
                        polar=dict(
                            radialaxis=dict(visible=True, range=[0, 10], gridcolor="#e2e8f0", color="#718096"),
                            angularaxis=dict(gridcolor="#e2e8f0", color="#1a1a2e"),
                            bgcolor="#ffffff",
                        ),
                        paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                        showlegend=True, legend=dict(font=dict(color="#1a1a2e", size=13)),
                        margin=dict(l=40, r=40, t=40, b=40),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                st.subheader("🛡️ 단계별 대응 방안")
                for s in result["단계별분석"]:
                    with st.expander(f"  {s['단계']}  —  {s['ATTCK']}"):
                        total = sum(int(v) for v in s["DREAD"].values())
                        st.markdown(f"""<div style="font-size:14px;color:#718096;margin-bottom:8px;">
                            DREAD 합산 위험도: <span style="color:#dc2626;font-size:18px;font-weight:700;">{total}</span>/50
                        </div>""", unsafe_allow_html=True)
                        st.write(s["대응방안"])
            except Exception as e:
                st.error(f"리포트 생성 오류: {e}")