import os
import streamlit as st

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "images")

MAPPING = [
    {
        "num": "①",
        "skt": "초기 침투 — 시스템 관리망 서버 A/B 감염",
        "dfd": "공격자 → 서버 A 웹쉘 업로드",
        "stage": "STAGE 01 — 웹쉘 업로드 (T1190)",
        "color": "#dc2626",
    },
    {
        "num": "②",
        "skt": "추가 거점 확보 — 고객 관리망 서버 감염",
        "dfd": "서버 A → config.txt 계정정보 열람",
        "stage": "STAGE 02 — 계정정보 탈취 (T1552)",
        "color": "#ea580c",
    },
    {
        "num": "③",
        "skt": "정보 유출 — 코어망 HSS 서버 접근 및 유심정보 유출",
        "dfd": "서버 A → SSH → 서버 B → USIM DB 조회/덤프",
        "stage": "STAGE 03~04 — Lateral Movement + DB 탈취 (T1021/T1005)",
        "color": "#7c3aed",
    },
]


def render():
    st.markdown("""
<div style="padding:32px 0 24px 0;border-bottom:3px solid #e2e8f0;margin-bottom:28px;">
    <div style="color:#dc2626;font-size:12px;font-weight:700;letter-spacing:3px;margin-bottom:10px;">
        2025 SKT USIM DATA BREACH — INCIDENT ANALYSIS
    </div>
    <h1 style="font-size:32px;font-weight:800;color:#1a1a2e;margin:0 0 10px 0;">
        SKT 침해사고 개요 및 실습 매핑
    </h1>
    <p style="color:#718096;font-size:15px;margin:0;">
        2025년 4월 발생한 SKT USIM 데이터 유출 사건의 공격 흐름을 분석하고,
        본 플랫폼의 실습 시나리오가 실제 사건의 어느 단계에 해당하는지 확인합니다.
    </p>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="display:flex;gap:16px;margin-bottom:28px;flex-wrap:wrap;">
    <div style="flex:1;min-width:160px;background:#fff5f5;border:1.5px solid #fca5a5;border-radius:10px;padding:16px 18px;">
        <div style="font-size:11px;font-weight:700;color:#dc2626;letter-spacing:1px;margin-bottom:6px;">피해 규모</div>
        <div style="font-size:22px;font-weight:800;color:#1a1a2e;">2,696만 건</div>
        <div style="font-size:13px;color:#718096;margin-top:4px;">9.82GB 유심정보 유출</div>
    </div>
    <div style="flex:1;min-width:160px;background:#fff5f5;border:1.5px solid #fca5a5;border-radius:10px;padding:16px 18px;">
        <div style="font-size:11px;font-weight:700;color:#dc2626;letter-spacing:1px;margin-bottom:6px;">공격 방법</div>
        <div style="font-size:21px;font-weight:800;color:#1a1a2e;">Lateral Movement</div>
        <div style="font-size:13px;color:#718096;margin-top:4px;">내부망 침투 → DB 탈취</div>
    </div>
    <div style="flex:1;min-width:160px;background:#fff5f5;border:1.5px solid #fca5a5;border-radius:10px;padding:16px 18px;">
        <div style="font-size:11px;font-weight:700;color:#dc2626;letter-spacing:1px;margin-bottom:6px;">유출 정보</div>
        <div style="font-size:22px;font-weight:800;color:#1a1a2e;">ICCID / Ki</div>
        <div style="font-size:13px;color:#718096;margin-top:4px;">유심 복제 가능 핵심값 포함</div>
    </div>
    <div style="flex:1;min-width:160px;background:#eff6ff;border:1.5px solid #93c5fd;border-radius:10px;padding:16px 18px;">
        <div style="font-size:11px;font-weight:700;color:#2563eb;letter-spacing:1px;margin-bottom:6px;">실습 단계</div>
        <div style="font-size:22px;font-weight:800;color:#1a1a2e;">4단계 공격</div>
        <div style="font-size:13px;color:#718096;margin-top:4px;">+ 3단계 방어 실습</div>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="font-size:15px;font-weight:700;color:#2563eb;letter-spacing:2px;margin-bottom:16px;">
    🔍 사고 원인 분석 이미지 vs 구현 DFD 매핑
</div>
""", unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1], gap="large")
    with c1:
        st.markdown("<div style='font-size:15px;font-weight:700;color:#dc2626;margin-bottom:8px;'>📌 SKT 공식 사고 원인 분석</div>", unsafe_allow_html=True)
        st.image(os.path.join(BASE_DIR, "skt_original.png"), use_container_width=True)
    with c2:
        st.markdown("<div style='font-size:15px;font-weight:700;color:#2563eb;margin-bottom:8px;'>📌 실습 흐름도</div>", unsafe_allow_html=True)
        st.image(os.path.join(BASE_DIR, "dfd.png"), use_container_width=True)

    st.markdown("<div style='margin-top:24px;margin-bottom:16px;font-size:15px;font-weight:700;color:#2563eb;letter-spacing:2px;'>🔗 단계별 매핑 및 실습 연결</div>", unsafe_allow_html=True)

    for m in MAPPING:
        st.markdown(f"""
<div style="display:flex;align-items:flex-start;gap:16px;padding:18px 20px;
     margin-bottom:10px;border:1.5px solid #e2e8f0;border-left:5px solid {m['color']};
     border-radius:8px;background:#ffffff;">
    <div style="font-size:32px;font-weight:800;color:{m['color']};min-width:36px;">{m['num']}</div>
    <div style="flex:1;">
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px;">
            <span style="background:#fff5f5;color:#dc2626;font-size:13px;font-weight:700;
                         padding:4px 12px;border-radius:99px;">SKT 원본</span>
            <span style="font-size:16px;color:#1a1a2e;font-weight:700;">{m['skt']}</span>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px;">
            <span style="background:#eff6ff;color:#2563eb;font-size:13px;font-weight:700;
                         padding:4px 12px;border-radius:99px;">실습흐름</span>
            <span style="font-size:16px;color:#1a1a2e;font-weight:700;">{m['dfd']}</span>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <span style="background:#f5f3ff;color:#7c3aed;font-size:13px;font-weight:700;
                         padding:4px 12px;border-radius:99px;">실습 단계</span>
            <span style="font-size:15px;color:#4a5568;font-weight:600;">{m['stage']}</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)