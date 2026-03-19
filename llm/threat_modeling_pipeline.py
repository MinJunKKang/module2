import pandas as pd
import plotly.graph_objects as go
from graphviz import Digraph


THREAT_MODELING_TEXT = """
Threat Modeling은 시스템을 공격자의 시각에서 미리 살펴보며
'어디가 위험한지', '어떤 방식으로 공격될 수 있는지', '무엇을 먼저 막아야 하는지'를 정리하는 과정입니다.

쉽게 말하면,
- 시스템 구조를 먼저 그려 보고
- 각 지점에서 발생 가능한 위협을 찾고
- 위험도를 평가한 뒤
- 필요한 보안 요구사항을 도출하는 과정입니다.
"""

DFD_TEXT = """
DFD(Data Flow Diagram)는 시스템 안에서 데이터가 어디서 들어오고, 어디를 지나고, 어디에 저장되는지를
그림으로 나타낸 것입니다. 공격자가 어떤 경로로 중요한 데이터에 도달했는지 시각적으로 이해하는 데 도움이 됩니다.
"""

STRIDE_TEXT = """
STRIDE는 시스템에서 발생할 수 있는 위협을 6가지 유형으로 분류하는 방법입니다.

- S: Spoofing (신분 위조) — 다른 사람인 척 속이는 행위
- T: Tampering (변조) — 데이터나 파일을 몰래 바꾸는 행위
- R: Repudiation (부인) — 자신이 한 행동을 증거 없이 부인하는 행위
- I: Information Disclosure (정보 유출) — 허가 없이 정보를 빼가는 행위
- D: Denial of Service (서비스 거부) — 시스템을 마비시키는 행위
- E: Elevation of Privilege (권한 상승) — 허가되지 않은 더 높은 권한을 획득하는 행위

아래 히트맵에서 각 공격 단계별로 어떤 위협이 발생했는지 한눈에 확인할 수 있습니다.
"""

DREAD_TEXT = """
DREAD는 위협의 위험도를 5가지 기준으로 점수화해 우선순위를 정하는 방법입니다.

- D (Damage): 공격이 성공했을 때 피해 규모
- R (Reproducibility): 같은 공격을 반복해서 실행하기 쉬운 정도
- E (Exploitability): 공격자가 실제로 공격을 실행하기 쉬운 정도
- A (Affected Users): 피해를 받는 사용자 수
- D (Discoverability): 공격자가 취약점을 발견하기 쉬운 정도

각 항목은 1~10점으로 평가하며, 점수가 높을수록 우선적으로 대응해야 합니다.
"""

SECURITY_REQ_TEXT = """
보안 요구사항 명세서는 식별된 위협을 줄이기 위해
어떤 통제를 적용해야 하는지를 구조적으로 정리한 결과물입니다.
"""

THREAT_ROWS = [
    {
        "단계": "1단계: 웹쉘 업로드",
        "DFD 요소": "서버 A (웹 서버)",
        "자산": "업로드 엔드포인트 / 웹 애플리케이션",
        "데이터 흐름": "Attacker → Web Server",
        # STRIDE: 각 유형별 존재 여부 (H=고위험, M=중위험, N=없음)
        "stride_S": "N",
        "stride_T": "H",
        "stride_R": "N",
        "stride_I": "M",
        "stride_D": "M",
        "stride_E": "H",
        "STRIDE 유형": "Tampering, Elevation of Privilege",
        "STRIDE 설명": "업로드 기능을 악용해 서버 파일을 변조하고, 실행 가능한 웹쉘을 통해 추가 명령 실행 및 권한 확대의 발판을 마련할 수 있음",
        "Damage": 9,
        "Reproducibility": 8,
        "Exploitability": 8,
        "Affected Users": 7,
        "Discoverability": 7,
        "우선순위": "High",
        "요구사항 ID": "SEC-REQ-001",
        "보안 목표": "파일 업로드 기능을 통한 악성 스크립트 반입과 서버 측 실행을 차단한다.",
        "보안 요구사항": "파일 업로드 시 허용 확장자 화이트리스트, MIME 타입 검증, 저장 디렉터리 실행 권한 제거, 업로드 파일 악성 여부 검사, WAF 기반 업로드 공격 탐지 정책을 적용해야 한다.",
        "구현 가이드": "웹 루트와 업로드 디렉터리를 분리하고, Apache/Nginx에서 업로드 경로의 스크립트 실행을 금지한다. 업로드 직후 AV 또는 YARA 검사와 파일 무결성 검사를 수행한다.",
        "검증 방법": "php, phtml, jsp 등 실행 가능한 파일 업로드 차단 테스트, Content-Type 우회 테스트, 업로드 디렉터리 직접 실행 테스트, WAF 탐지 로그 확인",
    },
    {
        "단계": "2단계: 계정정보 탈취",
        "DFD 요소": "설정 파일(config.txt)",
        "자산": "계정정보 / 설정 파일",
        "데이터 흐름": "WebShell → config.txt",
        "stride_S": "N",
        "stride_T": "N",
        "stride_R": "M",
        "stride_I": "H",
        "stride_D": "N",
        "stride_E": "M",
        "STRIDE 유형": "Information Disclosure",
        "STRIDE 설명": "설정 파일에 저장된 평문 자격증명이 노출되어 이후 원격 접속과 시스템 확장 공격에 사용될 수 있음",
        "Damage": 8,
        "Reproducibility": 9,
        "Exploitability": 9,
        "Affected Users": 8,
        "Discoverability": 8,
        "우선순위": "Critical",
        "요구사항 ID": "SEC-REQ-002",
        "보안 목표": "설정 파일이나 코드 저장소에 평문 자격증명이 남지 않도록 하고, 자격증명 노출 시 피해를 최소화한다.",
        "보안 요구사항": "비밀번호와 API Key 등 민감 자격정보는 평문 저장을 금지하고 Vault 또는 KMS 기반 비밀관리 체계를 사용해야 한다. 설정 파일 접근권한은 최소화하고 민감정보 정적 스캔을 정기 수행해야 한다.",
        "구현 가이드": "환경변수/비밀관리 솔루션으로 자격증명을 분리하고, Git pre-commit secret scan, 서버 측 파일 권한 600 제한, 자격정보 주기적 교체, MFA 적용을 병행한다.",
        "검증 방법": "설정 파일 평문 비밀번호 존재 여부 점검, secret scanning 도구 실행 결과 확인, 비밀관리 솔루션 연동 테스트, 노출 계정 교체 이력 확인",
    },
    {
        "단계": "3단계: SSH Lateral Movement",
        "DFD 요소": "서버 B SSH 서비스",
        "자산": "SSH 서비스 / 내부 서버 접근 권한",
        "데이터 흐름": "ServerA → SSH → ServerB",
        "stride_S": "H",
        "stride_T": "N",
        "stride_R": "M",
        "stride_I": "M",
        "stride_D": "N",
        "stride_E": "H",
        "STRIDE 유형": "Spoofing, Elevation of Privilege",
        "STRIDE 설명": "탈취한 계정정보를 정상 사용자 계정처럼 사용해 내부 서버에 접근하고 추가 권한을 확보할 수 있음",
        "Damage": 9,
        "Reproducibility": 8,
        "Exploitability": 7,
        "Affected Users": 8,
        "Discoverability": 6,
        "우선순위": "High",
        "요구사항 ID": "SEC-REQ-003",
        "보안 목표": "내부 서버 간 원격 접속을 최소화하고, 탈취 계정만으로 내부 이동이 가능하지 않도록 통제한다.",
        "보안 요구사항": "SSH 직접 접속은 관리망 또는 Bastion Host 경유로 제한하고, MFA 또는 강한 키 기반 인증을 적용해야 한다. 서버 간 접근 제어, 내부망 세분화, 비정상 로그인 탐지 정책을 운영해야 한다.",
        "구현 가이드": "보안그룹/방화벽에서 SSH 허용 소스 제한, Bastion Host 도입, PAM/SSHD MFA 연동, 비정상 시간대 로그인 탐지, 계정별 명령어 로깅과 세션 감사 적용",
        "검증 방법": "허용되지 않은 소스 IP의 SSH 접속 차단 확인, Bastion 우회 접속 시도, MFA 우회 여부 점검, SSH 감사 로그와 비정상 로그인 알림 테스트",
    },
    {
        "단계": "4단계: DB 데이터 탈취",
        "DFD 요소": "ServerB → MySQL → USIM Database",
        "자산": "USIM 데이터 / 고객정보",
        "데이터 흐름": "SSH Session → DB Query",
        "stride_S": "N",
        "stride_T": "N",
        "stride_R": "H",
        "stride_I": "H",
        "stride_D": "M",
        "stride_E": "N",
        "STRIDE 유형": "Information Disclosure, Repudiation",
        "STRIDE 설명": "DB 직접 조회를 통해 민감 고객정보가 유출될 수 있으며, 로그가 미흡하면 누가 어떤 데이터를 조회했는지 추적하기 어려울 수 있음",
        "Damage": 10,
        "Reproducibility": 8,
        "Exploitability": 7,
        "Affected Users": 10,
        "Discoverability": 6,
        "우선순위": "Critical",
        "요구사항 ID": "SEC-REQ-004",
        "보안 목표": "민감 데이터에 대한 직접 조회와 대량 추출을 제한하고, 모든 데이터 접근을 추적 가능하게 유지한다.",
        "보안 요구사항": "DB 계정은 최소권한 원칙으로 분리하고, 민감 컬럼 암호화와 대량 조회 탐지 정책을 적용해야 한다. 감사 로그는 위변조 방지 상태로 보관하고 데이터 조회 행위를 추적해야 한다.",
        "구현 가이드": "읽기/쓰기/관리자 계정 분리, 컬럼 단위 암호화, SQL Firewall 또는 DAM 적용, 대량 SELECT/EXPORT 탐지 룰 구성, 중앙 로그 저장소로 감사 로그 전송",
        "검증 방법": "과도한 SELECT 및 dump 시도 탐지, 비인가 계정의 테이블 접근 차단, 감사 로그 위변조 방지 확인, 민감 컬럼 복호화 권한 테스트",
    },
]


def build_dfd_graph():
    dot = Digraph()
    dot.attr(rankdir="LR", bgcolor="white", pad="0.3")
    dot.attr("node", shape="box", style="rounded,filled", color="#c7ddff", fillcolor="#eef5ff", fontname="Helvetica")
    dot.attr("edge", color="#111827", penwidth="1.4", fontname="Helvetica")

    dot.node("user", "정상 사용자")
    dot.node("attacker", "공격자")
    dot.node("web", "서버 A\n웹 서버 / 업로드 엔드포인트")
    dot.node("config", "config.txt\n계정정보 파일")
    dot.node("ssh", "서버 B\nSSH 서비스")
    dot.node("db", "USIM Database")

    dot.edge("user", "web", "정상 요청")
    dot.edge("attacker", "web", "웹쉘 업로드")
    dot.edge("web", "config", "계정정보 열람")
    dot.edge("web", "ssh", "탈취 계정으로 SSH 접근")
    dot.edge("ssh", "db", "DB 조회 / 데이터 수집")

    return dot


def build_stride_heatmap_html() -> str:
    """
    STRIDE 히트맵을 인터랙티브 HTML로 생성합니다.
    H=고위험(빨강), M=중위험(노랑), N=해당없음(회색)
    각 셀에 마우스를 올리면 위협 설명 툴팁이 표시됩니다.
    """
    stride_keys = ["stride_S", "stride_T", "stride_R", "stride_I", "stride_D", "stride_E"]
    stride_labels = [
        ("S", "신분 위조", "다른 사람인 척 속이는 행위"),
        ("T", "데이터 변조", "파일·데이터를 몰래 바꾸는 행위"),
        ("R", "행위 부인", "자신의 행동을 부인하는 행위"),
        ("I", "정보 유출", "허가 없이 정보를 빼가는 행위"),
        ("D", "서비스 거부", "시스템을 마비시키는 행위"),
        ("E", "권한 상승", "더 높은 권한을 획득하는 행위"),
    ]

    level_config = {
        "H": {"bg": "#fee2e2", "border": "#f87171", "text": "#991b1b", "label": "고위험", "dot": "#ef4444"},
        "M": {"bg": "#fef9c3", "border": "#fbbf24", "text": "#92400e", "label": "중위험", "dot": "#f59e0b"},
        "N": {"bg": "#f8fafc", "border": "#e2e8f0", "text": "#94a3b8", "label": "—",     "dot": "#e2e8f0"},
    }

    # 헤더 컬럼
    header_cells = ""
    for letter, name, desc in stride_labels:
        header_cells += f"""
        <th style="text-align:center;padding:10px 6px;background:#f8fafc;
                   border:1px solid #e5e7eb;font-size:13px;min-width:90px;">
            <div style="font-size:18px;font-weight:800;color:#1e40af;">{letter}</div>
            <div style="font-size:11px;font-weight:600;color:#374151;margin-top:2px;">{name}</div>
            <div style="font-size:10px;color:#9ca3af;margin-top:1px;font-weight:400;">{desc}</div>
        </th>"""

    # 데이터 행
    body_rows = ""
    for row in THREAT_ROWS:
        # 단계 레이블 색상
        priority = row["우선순위"]
        stage_bg = "#fff1f2" if priority == "Critical" else "#fffbeb" if priority == "High" else "#f0fdf4"
        stage_border = "#fca5a5" if priority == "Critical" else "#fde68a" if priority == "High" else "#86efac"
        stage_text = "#991b1b" if priority == "Critical" else "#92400e" if priority == "High" else "#166534"
        priority_badge_bg = "#dc2626" if priority == "Critical" else "#d97706" if priority == "High" else "#16a34a"

        stage_cell = f"""
        <td style="padding:10px 12px;border:1px solid #e5e7eb;background:{stage_bg};
                   border-left:3px solid {stage_border};min-width:160px;">
            <div style="font-size:13px;font-weight:700;color:{stage_text};">{row['단계']}</div>
            <div style="font-size:11px;color:#6b7280;margin-top:3px;">{row['DFD 요소']}</div>
            <span style="display:inline-block;margin-top:5px;background:{priority_badge_bg};
                         color:white;font-size:10px;font-weight:700;
                         padding:2px 7px;border-radius:99px;">{priority}</span>
        </td>"""

        threat_cells = ""
        for key in stride_keys:
            level = row.get(key, "N")
            cfg = level_config[level]
            tooltip_text = row["STRIDE 설명"] if level != "N" else "해당 위협 없음"
            threat_cells += f"""
            <td style="text-align:center;padding:8px 6px;border:1px solid #e5e7eb;background:{cfg['bg']};"
                title="{tooltip_text}">
                <div style="width:28px;height:28px;border-radius:50%;
                            background:{cfg['dot']};margin:0 auto 4px;
                            display:flex;align-items:center;justify-content:center;">
                    <span style="color:white;font-size:11px;font-weight:700;">
                        {'!' if level == 'H' else '△' if level == 'M' else '—'}
                    </span>
                </div>
                <div style="font-size:10px;font-weight:600;color:{cfg['text']};">{cfg['label']}</div>
            </td>"""

        body_rows += f"<tr>{stage_cell}{threat_cells}</tr>"

    # 범례
    legend_html = """
    <div style="display:flex;gap:20px;align-items:center;margin-top:12px;
                padding:10px 14px;background:#f8fafc;border-radius:8px;
                border:1px solid #e5e7eb;flex-wrap:wrap;">
        <span style="font-size:12px;font-weight:700;color:#374151;">범례</span>
        <span style="display:flex;align-items:center;gap:6px;font-size:12px;color:#374151;">
            <span style="width:16px;height:16px;border-radius:50%;background:#ef4444;
                         display:inline-flex;align-items:center;justify-content:center;
                         color:white;font-size:9px;font-weight:700;">!</span>
            고위험 — 즉각 대응 필요
        </span>
        <span style="display:flex;align-items:center;gap:6px;font-size:12px;color:#374151;">
            <span style="width:16px;height:16px;border-radius:50%;background:#f59e0b;
                         display:inline-flex;align-items:center;justify-content:center;
                         color:white;font-size:9px;font-weight:700;">△</span>
            중위험 — 모니터링 필요
        </span>
        <span style="display:flex;align-items:center;gap:6px;font-size:12px;color:#374151;">
            <span style="width:16px;height:16px;border-radius:50%;background:#e2e8f0;
                         display:inline-flex;align-items:center;justify-content:center;
                         color:#9ca3af;font-size:9px;font-weight:700;">—</span>
            해당없음
        </span>
        <span style="font-size:11px;color:#9ca3af;margin-left:auto;">
            💡 각 셀에 마우스를 올리면 위협 설명이 표시됩니다
        </span>
    </div>"""

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8">
    <style>
        body {{ margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:white; }}
        table {{ border-collapse:collapse;width:100%; }}
        tr:hover td {{ filter:brightness(0.97); }}
    </style>
    </head>
    <body>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th style="text-align:left;padding:10px 12px;background:#f8fafc;
                                   border:1px solid #e5e7eb;font-size:13px;min-width:160px;">
                            공격 단계
                        </th>
                        {header_cells}
                    </tr>
                </thead>
                <tbody>{body_rows}</tbody>
            </table>
        </div>
        {legend_html}
    </body>
    </html>
    """
    return html


def build_dread_df():
    df = pd.DataFrame([
        {
            "단계": row["단계"],
            "Damage": row["Damage"],
            "Reproducibility": row["Reproducibility"],
            "Exploitability": row["Exploitability"],
            "Affected Users": row["Affected Users"],
            "Discoverability": row["Discoverability"],
        }
        for row in THREAT_ROWS
    ])
    df["총점"] = df[["Damage", "Reproducibility", "Exploitability", "Affected Users", "Discoverability"]].sum(axis=1)
    return df


def build_dread_cards_html() -> str:
    """
    DREAD 카드 그리드: 각 공격 단계별로 5개 항목을 가로 바로 시각화합니다.
    총점과 위험 등급을 뱃지로 표시합니다.
    """
    dread_dims = [
        ("Damage",          "D", "피해 규모",     "#ef4444"),
        ("Reproducibility", "R", "재현 가능성",   "#f97316"),
        ("Exploitability",  "E", "악용 용이성",   "#eab308"),
        ("Affected Users",  "A", "영향 사용자",   "#8b5cf6"),
        ("Discoverability", "D","발견 가능성",   "#3b82f6"),
    ]

    def score_badge(total):
        if total >= 42:
            return "#dc2626", "white", "Critical"
        elif total >= 35:
            return "#d97706", "white", "High"
        else:
            return "#16a34a", "white", "Medium"

    cards_html = ""
    for row in THREAT_ROWS:
        total = sum(row[d[0]] for d in dread_dims)
        badge_bg, badge_text, badge_label = score_badge(total)

        bars_html = ""
        for key, short, name, color in dread_dims:
            val = row[key]
            pct = val * 10
            bars_html += f"""
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:7px;">
                <span style="width:14px;height:14px;border-radius:3px;background:{color};
                             display:inline-flex;align-items:center;justify-content:center;
                             color:white;font-size:9px;font-weight:700;flex-shrink:0;">{short}</span>
                <span style="font-size:12px;color:#6b7280;width:76px;flex-shrink:0;">{name}</span>
                <div style="flex:1;height:7px;background:#f1f5f9;border-radius:4px;overflow:hidden;">
                    <div style="width:{pct}%;height:100%;background:{color};border-radius:4px;
                                transition:width 0.6s ease;"></div>
                </div>
                <span style="font-size:12px;font-weight:700;color:#374151;width:18px;
                             text-align:right;flex-shrink:0;">{val}</span>
            </div>"""

        cards_html += f"""
        <div style="background:white;border:1px solid #e5e7eb;border-radius:12px;
                    padding:16px 18px;box-shadow:none;">
            <div style="font-size:13px;font-weight:700;color:#111827;margin-bottom:4px;
                        line-height:1.4;">{row['단계']}</div>
            <div style="margin-bottom:12px;">
                <span style="background:{badge_bg};color:{badge_text};font-size:11px;
                             font-weight:700;padding:3px 9px;border-radius:99px;">
                    DREAD {total}/50 — {badge_label}
                </span>
            </div>
            {bars_html}
        </div>"""

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8">
    <style>
        body {{ margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:white; }}
        .grid {{ display:grid;grid-template-columns:repeat(2,1fr);gap:12px; }}
        @media (max-width:600px) {{ .grid {{ grid-template-columns:1fr; }} }}
    </style>
    </head>
    <body>
        <div class="grid">{cards_html}</div>
    </body>
    </html>
    """
    return html


def build_dread_bar_chart() -> go.Figure:
    """
    DREAD 총점 세로 선 그래프.
    단계별 총점을 세로축으로 배치하고 꺾은선으로 연결.
    점수 구간에 따라 마커 색상이 다르게 표시됩니다.
    """
    df = build_dread_df()

    # 공격 순서대로 (1→4단계)
    df = df.reset_index(drop=True)

    def marker_color(total):
        if total >= 42:
            return "#ef4444"
        elif total >= 35:
            return "#f59e0b"
        return "#22c55e"

    colors = [marker_color(v) for v in df["총점"]]

    # x축 라벨 축약
    labels = [s.replace("SSH Lateral Movement", "SSH Lateral\nMovement") for s in df["단계"]]

    fig = go.Figure()

    # 위험 구간 배경 (shape 대신 filled scatter로)
    fig.add_hrect(y0=42, y1=52, fillcolor="#fee2e2", opacity=0.3, line_width=0, layer="below")
    fig.add_hrect(y0=35, y1=42, fillcolor="#fef9c3", opacity=0.4, line_width=0, layer="below")

    # 선 + 마커
    fig.add_trace(go.Scatter(
        x=labels,
        y=df["총점"],
        mode="lines+markers+text",
        line=dict(color="#94a3b8", width=2, dash="dot"),
        marker=dict(
            color=colors,
            size=14,
            line=dict(color="white", width=2),
        ),
        text=[f"{v}" for v in df["총점"]],
        textposition="top center",
        textfont=dict(size=12, color="#374151"),
    ))

    # 위험 구간 레이블
    fig.add_annotation(x=labels[-1], y=47, text="Critical", showarrow=False,
                       font=dict(size=10, color="#ef4444"), xanchor="right")
    fig.add_annotation(x=labels[-1], y=38.5, text="High", showarrow=False,
                       font=dict(size=10, color="#f59e0b"), xanchor="right")

    fig.update_layout(
        xaxis=dict(
            tickfont=dict(size=11, color="#374151"),
            showgrid=False,
            zeroline=False,
        ),
        yaxis=dict(
            range=[0, 52],
            showgrid=True,
            gridcolor="#f1f5f9",
            zeroline=False,
            tickfont=dict(size=11, color="#6b7280"),
            title=dict(text="DREAD 총점", font=dict(size=11, color="#9ca3af")),
        ),
        plot_bgcolor="white",
        paper_bgcolor="white",
        margin=dict(l=10, r=20, t=30, b=10),
        height=280,
        showlegend=False,
    )

    return fig


def build_dread_radar() -> go.Figure:
    """레이더 차트 — 단계별 DREAD 5개 항목 비교"""
    df = build_dread_df()
    categories = ["Damage", "Reproducibility", "Exploitability", "Affected Users", "Discoverability"]
    colors = ["#ef4444", "#f59e0b", "#3b82f6", "#10b981"]

    fig = go.Figure()

    for idx, row in df.iterrows():
        values = [row[c] for c in categories]
        values.append(values[0])

        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories + [categories[0]],
            fill="toself",
            name=row["단계"],
            line=dict(color=colors[idx % len(colors)], width=2),
            fillcolor=colors[idx % len(colors)],
            opacity=0.15,
        ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 10], tickfont=dict(size=10)),
            angularaxis=dict(tickfont=dict(size=11)),
        ),
        showlegend=True,
        legend=dict(
            font=dict(size=11),
            orientation="h",
            y=-0.15,
        ),
        margin=dict(l=40, r=40, t=20, b=60),
        height=320,
        paper_bgcolor="white",
        plot_bgcolor="white",
    )

    return fig


def build_security_requirements_df():
    return pd.DataFrame([
        {
            "단계": row["단계"],
            "관련 위협": row["STRIDE 유형"],
            "보안 요구사항": row["보안 요구사항"],
            "우선순위": row["우선순위"],
        }
        for row in THREAT_ROWS
    ])


def build_security_requirement_details():
    dread_df = build_dread_df()
    dread_map = dict(zip(dread_df["단계"], dread_df["총점"]))

    details = []
    for row in THREAT_ROWS:
        details.append({
            "단계": row["단계"],
            "요구사항 ID": row["요구사항 ID"],
            "관련 위협": row["STRIDE 유형"],
            "자산": row["자산"],
            "DREAD 총점": dread_map.get(row["단계"], 0),
            "우선순위": row["우선순위"],
            "보안 목표": row["보안 목표"],
            "보안 요구사항": row["보안 요구사항"],
            "구현 가이드": row["구현 가이드"],
            "검증 방법": row["검증 방법"],
        })
    return details