import streamlit as st
from components import STYLES
from config import MISSIONS, SERVER_A_IP, SERVER_B_IP
from tabs import attack_tab, defense_tab, report_tab
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="SKT 침해사고 체험 플랫폼",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(STYLES, unsafe_allow_html=True)

# ============================
# 세션 초기화
# ============================
if "completed" not in st.session_state:
    st.session_state.completed = {k: False for k, _, __ in MISSIONS}

# ============================
# 사이드바
# ============================
with st.sidebar:
    st.markdown("""
<div style="padding:20px 0 12px 0;">
    <div style="color:#718096;font-size:12px;font-weight:600;letter-spacing:2px;margin-bottom:6px;">MISSION BOARD</div>
    <div style="color:#1a1a2e;font-size:22px;font-weight:700;">진행 현황</div>
</div>
<hr style="border-color:#e2e8f0;margin:8px 0 14px 0;">
""", unsafe_allow_html=True)

    attack_done = sum(1 for k, _, t in MISSIONS if t == "attack" and st.session_state.completed[k])
    defend_done = sum(1 for k, _, t in MISSIONS if t == "defense" and st.session_state.completed[k])
    st.markdown(f"""
<div style="font-size:14px;color:#718096;margin-bottom:14px;">
    🗡️ 공격 {attack_done}/4 &nbsp;|&nbsp; 🛡️ 방어 {defend_done}/3
</div>
""", unsafe_allow_html=True)

    for mission, tag, mtype in MISSIONS:
        done = st.session_state.completed[mission]
        is_attack = mtype == "attack"
        bg     = ("#f0fdf4" if done else "#fff5f5") if is_attack else ("#eff6ff" if done else "#f8fafc")
        border = ("#86efac" if done else "#fca5a5") if is_attack else ("#93c5fd" if done else "#e2e8f0")
        text_color = ("#166534" if done else "#991b1b") if is_attack else ("#1e40af" if done else "#4a5568")
        tag_color  = "#dc2626" if is_attack else "#2563eb"
        icon = "✅" if done else ("🔴" if is_attack else "🔵")
        st.markdown(f"""
<div style="display:flex;justify-content:space-between;align-items:center;
     padding:10px 12px;margin-bottom:6px;border:1.5px solid {border};
     border-radius:8px;background:{bg};">
    <span style="font-size:14px;font-weight:600;color:{text_color};">{icon} {mission}</span>
    <span style="font-size:11px;color:{tag_color};font-weight:700;">{tag}</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("<hr style='border-color:#e2e8f0;margin:14px 0;'>", unsafe_allow_html=True)
    progress = sum(st.session_state.completed.values()) / len(MISSIONS)
    st.progress(progress)
    st.markdown(f"""
<div style="font-size:14px;color:#718096;text-align:right;margin-top:6px;font-weight:600;">
    전체 진행률: {int(progress * 100)}%
</div>
""", unsafe_allow_html=True)
    st.markdown("")
    if st.button("⟳  환경 초기화", use_container_width=True):
        st.session_state.completed = {k: False for k, _, __ in MISSIONS}
        st.rerun()

# ============================
# 헤더
# ============================
st.markdown(f"""
<div style="padding:32px 0 24px 0;border-bottom:3px solid #e2e8f0;margin-bottom:28px;">
    <div style="color:#2563eb;font-size:12px;font-weight:700;letter-spacing:3px;margin-bottom:10px;">
        CYBER SECURITY TRAINING PLATFORM — SIMULATION MODE
    </div>
    <h1 style="font-size:36px;font-weight:800;color:#1a1a2e;margin:0;line-height:1.2;">
        SKT 침해사고 &nbsp;<span style="color:#dc2626;">공격</span> &amp; <span style="color:#2563eb;">방어</span>&nbsp; 체험 플랫폼
    </h1>
    <div style="color:#718096;font-size:14px;margin-top:10px;">
        Target: <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">{SERVER_A_IP}</code> (ServerA)
        &nbsp;→&nbsp;
        <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">{SERVER_B_IP}</code> (ServerB)
        &nbsp;|&nbsp; ⚠️ 시뮬레이션 환경 — 실제 서버 연결 없음
    </div>
</div>
""", unsafe_allow_html=True)

# ============================
# 탭
# ============================
tab1, tab2, tab3 = st.tabs(["  🗡️  공격 시나리오  ", "  🛡️  방어 시나리오  ", "  📊  분석 리포트  "])

with tab1:
    attack_tab.render()

with tab2:
    defense_tab.render()

with tab3:
    report_tab.render()