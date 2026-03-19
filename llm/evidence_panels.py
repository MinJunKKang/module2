import streamlit as st


# ─────────────────────────────────────────────────────────────────
# 공통 헬퍼
# ─────────────────────────────────────────────────────────────────

def _badge(text: str, color: str, bg: str) -> str:
    """인라인 배지 HTML 반환 (st.markdown unsafe_allow_html 용)"""
    return (
        f'<span style="background:{bg};color:{color};font-size:11px;font-weight:700;'
        f'padding:2px 9px;border-radius:99px;">{text}</span>'
    )


def _src_badge() -> str:
    return _badge("출처", "#5b21b6", "#ede9fe")


def _crt_badge() -> str:
    return _badge("기준", "#92400e", "#fef3c7")


def _why_badge() -> str:
    return _badge("근거", "#1d4ed8", "#dbeafe")


def _section_divider(icon: str, label: str):
    """각 evidence 블록 위에 표시되는 얇은 구분 레이블"""
    st.markdown(
        f"<div style='font-size:12px;color:#9ca3af;margin:10px 0 2px;'>"
        f"{icon} <b style='color:#6b7280;'>{label}</b></div>",
        unsafe_allow_html=True,
    )


def _row(title: str, desc: str):
    """출처·근거 항목 한 행 렌더링"""
    st.markdown(f"**{title}**")
    st.caption(desc)


def _criteria_table(rows: list[tuple]):
    """
    기준표 렌더링
    rows: [(등급_html, 조건, 대응), ...]
    """
    import streamlit.components.v1 as components

    thead = "<tr><th>등급</th><th>조건</th><th>대응 방향</th></tr>"
    tbody = ""
    for grade_html, cond, action in rows:
        tbody += f"<tr><td>{grade_html}</td><td>{cond}</td><td>{action}</td></tr>"

    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<style>
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:transparent; }}
table {{ width:100%; border-collapse:collapse; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; font-size:12px; }}
th {{ background:#f8fafc; font-weight:700; padding:7px 10px; border-bottom:1px solid #e5e7eb; text-align:left; color:#374151; }}
td {{ padding:7px 10px; border-bottom:1px solid #f1f5f9; vertical-align:top; color:#374151; line-height:1.5; }}
tr:last-child td {{ border-bottom:none; }}
</style>
</head><body>
<table><thead>{thead}</thead><tbody>{tbody}</tbody></table>
<script>
  function notifyHeight() {{
    var h = document.body.scrollHeight;
    window.parent.postMessage({{type:"streamlit:setFrameHeight", height: h + 8}}, "*");
  }}
  window.addEventListener("load", notifyHeight);
  window.addEventListener("resize", notifyHeight);
  setTimeout(notifyHeight, 100);
</script>
</body></html>"""
    row_h = 52
    height = 44 + len(rows) * row_h
    components.html(html, height=height, scrolling=False)


def _trace_table(rows: list[tuple]):
    """
    추적성 흐름 테이블
    rows: [(stride_text, dread_text, req_text), ...]
    """
    import streamlit.components.v1 as components

    cards = ""
    for stride, dread, req in rows:
        cards += f"""
<div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;
            padding:8px 10px;background:#f8fafc;border:1px solid #e5e7eb;
            border-radius:8px;margin-bottom:6px;">
  <span style="background:#dbeafe;color:#1e40af;font-size:11px;font-weight:600;
               padding:4px 10px;border-radius:6px;line-height:1.4;white-space:nowrap;">{stride}</span>
  <span style="color:#9ca3af;font-size:14px;font-weight:700;">→</span>
  <span style="background:#fef3c7;color:#92400e;font-size:11px;font-weight:600;
               padding:4px 10px;border-radius:6px;line-height:1.4;white-space:nowrap;">{dread}</span>
  <span style="color:#9ca3af;font-size:14px;font-weight:700;">→</span>
  <span style="background:#d1fae5;color:#065f46;font-size:11px;font-weight:600;
               padding:4px 10px;border-radius:6px;line-height:1.4;white-space:nowrap;">{req}</span>
</div>"""

    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<style>* {{ box-sizing:border-box; margin:0; padding:0; }} body {{ background:transparent; }}</style>
</head><body>{cards}
<script>
  function notifyHeight() {{
    var h = document.body.scrollHeight;
    window.parent.postMessage({{type:"streamlit:setFrameHeight", height: h + 8}}, "*");
  }}
  window.addEventListener("load", notifyHeight);
  window.addEventListener("resize", notifyHeight);
  setTimeout(notifyHeight, 100);
</script>
</body></html>"""
    height = len(rows) * 70
    components.html(html, height=height, scrolling=False)


# ═══════════════════════════════════════════════════════════════
# 1) DFD 근거 패널
# ═══════════════════════════════════════════════════════════════

def render_dfd_evidence():
    _section_divider("📌", "DFD 분석 출처 · 기준 · 근거")

    with st.expander("📚 출처 — 참조 프레임워크"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(_src_badge() + "&nbsp; **Microsoft Threat Modeling Tool — DFD 표기법**",
                        unsafe_allow_html=True)
            st.caption("프로세스(원), 외부 엔티티(사각형), 데이터 저장소(평행선), 데이터 흐름(화살표) 4요소 표기 방식 적용")
        with c2:
            st.markdown(_src_badge() + "&nbsp; **OWASP Threat Modeling Cheat Sheet**",
                        unsafe_allow_html=True)
            st.caption("공격자 진입점(entry point) 식별 및 신뢰 경계(trust boundary) 구분 기준 적용")

    with st.expander("📐 기준 — 다이어그램 작성 기준"):
        st.markdown(_crt_badge() + "&nbsp; **DFD Level 1 수준으로 작성**",
                    unsafe_allow_html=True)
        st.caption("개별 함수·코드가 아닌 서비스·컴포넌트 단위로 추상화 — 공격 경로 흐름 파악에 필요한 최소 단위 유지")

        st.markdown(_crt_badge() + "&nbsp; **신뢰 경계: 외부 인터넷 ↔ 서버 A ↔ 서버 B ↔ DB**",
                    unsafe_allow_html=True)
        st.caption("각 경계 횡단 지점이 위협 식별(STRIDE) 대상 — 경계를 넘는 데이터 흐름마다 위협 검토 수행")

        st.markdown(_crt_badge() + "&nbsp; **공격자를 외부 엔티티로 명시 포함**",
                    unsafe_allow_html=True)
        st.caption("정상 사용자와 공격자를 별도 엔티티로 구분하여 의도적 위협 흐름과 정상 흐름을 시각적으로 분리")

    with st.expander("🔎 근거 — 이 시나리오에서 이 DFD가 나온 이유"):
        st.markdown(_why_badge() + "&nbsp; **웹쉘 업로드 → config.txt 열람 → SSH 접근 → DB 조회의 4단계 공격 흐름이 단일 데이터 흐름으로 연결됨**",
                    unsafe_allow_html=True)
        st.caption("각 화살표가 다음 공격 단계의 전제 조건이 되므로, 흐름 단절 지점이 곧 방어 제어 포인트")

        st.markdown(_why_badge() + "&nbsp; **config.txt와 USIM Database를 데이터 저장소로 별도 표기**",
                    unsafe_allow_html=True)
        st.caption("공격 목표 자산(고가치 데이터)을 흐름 위에 명시해 어느 저장소가 최종 탈취 대상인지 즉시 식별 가능하게 함")


# ═══════════════════════════════════════════════════════════════
# 2) STRIDE 근거 패널
# ═══════════════════════════════════════════════════════════════

def render_stride_evidence():
    _section_divider("📌", "STRIDE 분석 출처 · 기준 · 근거")

    with st.expander("📚 출처 — 참조 프레임워크"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(_src_badge() + "&nbsp; **Microsoft STRIDE Threat Model**",
                        unsafe_allow_html=True)
            st.caption("Loren Kohnfelder & Praerit Garg (1999) — 신분 위조·데이터 변조·행위 부인·정보 유출·서비스 거부·권한 상승의 6개 위협 유형 분류 체계 적용")
        with c2:
            st.markdown(_src_badge() + "&nbsp; **OWASP Threat Modeling — STRIDE per Element**",
                        unsafe_allow_html=True)
            st.caption("DFD 각 요소 유형(프로세스·데이터 흐름·저장소·외부 엔티티)마다 적용 가능한 위협 유형이 다름 — 이 기준으로 해당없음(N) 판정")

    with st.expander("📐 기준 — 고위험 / 중위험 / 해당없음 판정 기준"):
        _criteria_table([
            ('<strong style="color:#dc2626;">고위험</strong>',
             "해당 공격 단계에서 직접 발현 가능하고, DREAD 개별 항목 점수 7점 이상이며 핵심 공격 메커니즘과 직결",
             "즉각 대응 필요 — 보안 요구사항으로 반드시 전환"),
            ('<strong style="color:#d97706;">중위험</strong>',
             "이 단계에서 간접적으로 발생하거나, 공격자가 추가 조건 달성 시 발현 가능한 위협",
             "모니터링 및 탐지 정책 적용 권고"),
            ('<strong style="color:#6b7280;">해당없음</strong>',
             "STRIDE per Element 기준으로 해당 DFD 요소 유형에서 발현 불가, 또는 현재 시나리오와 무관",
             "현재 범위 외 — 시나리오 확장 시 재검토"),
        ])

    with st.expander("🔎 근거 — 단계별 주요 판정 근거"):
        items = [
            ("1단계 웹쉘 업로드 — 데이터 변조(고위험), 권한 상승(고위험)",
             "파일 업로드 기능으로 서버에 악성 파일을 직접 심을 수 있어 데이터 변조 위협이 직접 발현됩니다. "
             "심어진 웹쉘이 실행되면 웹서버 프로세스 권한으로 시스템 명령을 실행할 수 있어 권한 상승으로 이어집니다."),
            ("2단계 계정정보 탈취 — 정보 유출(고위험)",
             "config.txt는 STRIDE 분석에서 데이터 저장소로 분류됩니다. OWASP STRIDE per Element 방법론에 따르면 "
             "데이터 저장소의 핵심 위협은 정보 유출이며, 자격증명이 평문으로 저장되어 있어 위협이 즉시 발현됩니다."),
            ("3단계 SSH 내부 이동 — 신분 위조(고위험), 권한 상승(고위험)",
             "탈취한 정상 계정으로 SSH에 로그인하면 시스템은 공격자와 정상 사용자를 구별할 수 없습니다. "
             "다른 사람의 신분으로 인증하는 행위가 신분 위조에 해당하며, 내부 서버 접근 권한까지 확보되므로 권한 상승도 함께 고위험으로 판정했습니다."),
            ("4단계 DB 데이터 탈취 — 행위 부인(고위험), 정보 유출(고위험)",
             "감사 로그가 미흡하면 공격자가 어떤 데이터를 조회했는지 사후 추적이 불가합니다. "
             "행위 부인 위협이 고위험으로 발현되며, USIM 가입자 정보 등 민감 고객정보의 직접 유출로 정보 유출 역시 고위험으로 판정했습니다."),
        ]
        for title, desc in items:
            st.markdown(_why_badge() + f"&nbsp; **{title}**", unsafe_allow_html=True)
            st.caption(desc)
            st.divider()


# ═══════════════════════════════════════════════════════════════
# 3) DREAD 근거 패널
# ═══════════════════════════════════════════════════════════════

def render_dread_evidence():
    _section_divider("📌", "DREAD 분석 출처 · 기준 · 근거")

    with st.expander("📚 출처 — 참조 프레임워크"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(_src_badge() + "&nbsp; **Microsoft DREAD Risk Rating Model**",
                        unsafe_allow_html=True)
            st.caption("피해 규모·재현 가능성·악용 용이성·영향 사용자·발견 가능성 5개 항목으로 위협 위험도를 정량 평가 — Microsoft SDL(Security Development Lifecycle)에서 사용")
        with c2:
            st.markdown(_src_badge() + "&nbsp; **OWASP Risk Rating Methodology**",
                        unsafe_allow_html=True)
            st.caption("위협 요인 × 취약점 × 비즈니스 영향 구조를 DREAD 항목 평가 시 참조 — 특히 영향 사용자(Affected Users) 범위 산정에 적용")

    with st.expander("📐 기준 — 항목별 점수 구간 및 등급 기준"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**항목별 점수 구간 (1~10점)**")
            _criteria_table([
                ('<strong style="color:#dc2626;">7 ~ 10점</strong>',
                 "높음 — 실현 가능성 높고 피해 범위 광범위",
                 "공개 익스플로잇 존재, 인증 불필요, 전체 서비스 영향"),
                ('<strong style="color:#d97706;">4 ~ 6점</strong>',
                 "중간 — 조건부 실현 또는 제한적 피해",
                 "일부 기술 지식 필요, 내부 사용자 일부에만 영향"),
                ('<strong style="color:#059669;">1 ~ 3점</strong>',
                 "낮음 — 실현 어렵거나 피해 최소",
                 "고도 전문지식 필요, 단일 사용자·세션에만 영향"),
            ])
        with c2:
            st.markdown("**총점 등급 기준 (50점 만점)**")
            _criteria_table([
                ('<strong style="color:#dc2626;">Critical</strong>',
                 "42점 이상",
                 "즉각 대응 필요 — 방치 시 시스템 전체 침해로 이어질 수 있음"),
                ('<strong style="color:#d97706;">High</strong>',
                 "35 ~ 41점",
                 "1주 내 조치 권고 — 탐지·모니터링과 병행해 보안 통제 신속 적용"),
                ('<strong style="color:#059669;">Medium</strong>',
                 "34점 이하",
                 "정기 검토 수준 — 환경 변화 시 재평가 필요"),
            ])

    with st.expander("🔎 근거 — 단계별 주요 점수 판단 근거"):
        score_items = [
            ("1단계 웹쉘 업로드", "39/50", "High",
             [("피해 규모", "9점", "웹쉘 실행 성공 시 서버 전체 제어권 탈취 가능"),
              ("재현 가능성", "8점", "공개된 웹쉘 업로드 도구로 반복 재현 용이"),
              ("발견 가능성", "7점", "업로드 기능 노출 여부는 크롤러·버그바운티로 발견 가능")]),
            ("2단계 계정정보 탈취", "42/50", "Critical",
             [("악용 용이성", "9점", "웹쉘 획득 후 파일 열람만으로 즉시 자격증명 확보 — 별도 기술 불필요"),
              ("재현 가능성", "9점", "파일 위치·이름을 알면 언제든 재실행 가능"),
              ("발견 가능성", "8점", "config.txt 등 예측 가능한 파일명")]),
            ("3단계 SSH 내부 이동", "38/50", "High",
             [("피해 규모", "9점", "내부 서버 접근으로 공격 범위 확장"),
              ("발견 가능성", "6점", "내부 네트워크 구조 사전 파악 필요 — 다른 단계 대비 발견 난도 높음")]),
            ("4단계 DB 데이터 탈취", "41/50", "High",
             [("피해 규모", "10점", "USIM 가입자 정보 등 최고 민감도 개인정보 유출"),
              ("영향 사용자", "10점", "DB 내 전체 가입자 영향"),
              ("발견 가능성", "6점", "DB 서버 위치는 내부 접근 후에야 식별 가능")]),
        ]

        grade_color = {"Critical": "#dc2626", "High": "#d97706", "Medium": "#16a34a"}

        for stage, score, grade, details in score_items:
            g_color = grade_color.get(grade, "#6b7280")
            st.markdown(
                f"**{stage}** &nbsp;"
                f'<span style="background:{g_color};color:white;font-size:11px;'
                f'font-weight:700;padding:2px 9px;border-radius:99px;">'
                f'{score} · {grade}</span>',
                unsafe_allow_html=True,
            )
            cols = st.columns(len(details))
            for col, (item_name, item_score, item_reason) in zip(cols, details):
                col.metric(item_name, item_score)
                col.caption(item_reason)
            st.divider()


# ═══════════════════════════════════════════════════════════════
# 4) 보안 요구사항 명세 근거 패널
# ═══════════════════════════════════════════════════════════════

def render_security_evidence():
    _section_divider("📌", "보안 요구사항 명세 출처 · 기준 · 근거")

    with st.expander("📚 출처 — 구현 가이드 및 검증 방법 참조 프레임워크"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(_src_badge() + "&nbsp; **OWASP Top 10 (2021) & OWASP ASVS**",
                        unsafe_allow_html=True)
            st.caption("A03 Injection · A04 Insecure Design · A07 Identification and Authentication Failures 항목을 SEC-REQ-001~003 구현 가이드에 반영")

            st.markdown(_src_badge() + "&nbsp; **NIST SP 800-53 Rev.5**",
                        unsafe_allow_html=True)
            st.caption("AC(접근 통제)·AU(감사 및 책임추적)·SC(시스템 통신 보호) 계열 통제 항목을 SEC-REQ-003(SSH 접근 제어) · SEC-REQ-004(DB 감사 로그) 요구사항에 적용")
        with c2:
            st.markdown(_src_badge() + "&nbsp; **CIS Controls v8 — IG2 수준**",
                        unsafe_allow_html=True)
            st.caption("Control 3(데이터 보호) · Control 5(계정 관리) · Control 8(감사 로그 관리)를 SEC-REQ-002(자격증명 관리) · SEC-REQ-004(DB 접근 감사)에 반영")

            st.markdown(_src_badge() + "&nbsp; **MITRE ATT&CK Mitigations — M1017 · M1026 · M1027 · M1030**",
                        unsafe_allow_html=True)
            st.caption("각 TTP에 대응하는 공식 완화 기법(Mitigation)을 구현 가이드의 기술적 통제 방향으로 활용")

    with st.expander("📐 기준 — 요구사항 도출 기준"):
        st.markdown(_crt_badge() + "&nbsp; **STRIDE 고위험 판정 위협만 보안 요구사항으로 필수 전환, 중위험은 모니터링 권고 수준 반영**",
                    unsafe_allow_html=True)
        st.caption("해당없음 판정 위협은 현재 명세서 범위에서 제외 — 시나리오 확장 시 재검토 대상")

        st.markdown(_crt_badge() + "&nbsp; **DREAD Critical(42점+)은 우선순위 Critical, High(35~41점)는 High로 직접 연결**",
                    unsafe_allow_html=True)
        st.caption("점수가 아닌 등급 기준으로 대응 시급성 결정 — 총점 1~2점 차이로 우선순위가 바뀌는 오류 방지")

        st.markdown(_crt_badge() + "&nbsp; **보안 목표 → 요구사항 → 구현 가이드 → 검증 방법의 4단 연결 구조 적용**",
                    unsafe_allow_html=True)
        st.caption('"왜 이 통제가 필요한가(목표) → 무엇을 해야 하는가(요구사항) → 어떻게 하는가(가이드) → 어떻게 확인하는가(검증)"으로 연결')

    with st.expander("🔎 근거 — 위협 → 요구사항 추적성 (Traceability)"):
        _trace_table([
            ("데이터 변조 (고위험)<br>권한 상승 (고위험)", "위험도 39/50<br>High", "SEC-REQ-001<br>파일 업로드 통제"),
            ("정보 유출 (고위험)",                        "위험도 42/50<br>Critical", "SEC-REQ-002<br>자격증명 암호화 관리"),
            ("신분 위조 (고위험)<br>권한 상승 (고위험)",  "위험도 38/50<br>High", "SEC-REQ-003<br>SSH 접근 제어·MFA"),
            ("행위 부인 (고위험)<br>정보 유출 (고위험)",  "위험도 41/50<br>High", "SEC-REQ-004<br>DB 암호화·감사 로그"),
        ])