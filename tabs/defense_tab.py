import re
import streamlit as st
from components import fake_terminal, section_header, defense_box
from config import RD1, RD3, DEFENSE_VIDEOS


def to_embed_url(url):
    if "youtu.be/" in url:
        video_id = url.split("youtu.be/")[1].split("?")[0]
    elif "v=" in url:
        video_id = url.split("v=")[1].split("&")[0]
    else:
        return None
    return f"https://www.youtube.com/embed/{video_id}"


def video_player(key):
    url = DEFENSE_VIDEOS.get(key, "")
    if url:
        embed = to_embed_url(url)
        st.components.v1.iframe(embed, height=400)
    else:
        st.markdown('''
<div style="background:#f8fafc;border:2px dashed #e2e8f0;border-radius:8px;
     padding:20px;text-align:center;color:#94a3b8;font-size:13px;">
    🎬 영상 준비 중 — config.py의 DEFENSE_VIDEOS에 유튜브 링크를 넣어주세요
</div>
''', unsafe_allow_html=True)

# ============================
# 웹쉘 탐지 규칙 (LLM 없이)
# ============================
WEBSHELL_RULES = [
    {
        "pattern": r"system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "score": 95,
        "reason": "외부 입력값을 system() 함수에 직접 전달 — OS 명령 실행 가능",
        "evidence": "system($_GET[...]) 패턴 탐지",
    },
    {
        "pattern": r"exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "score": 95,
        "reason": "외부 입력값을 exec() 함수에 직접 전달 — 임의 명령 실행 가능",
        "evidence": "exec($_GET[...]) 패턴 탐지",
    },
    {
        "pattern": r"passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "score": 90,
        "reason": "passthru()를 통한 외부 명령 실행 시도",
        "evidence": "passthru($_GET[...]) 패턴 탐지",
    },
    {
        "pattern": r"shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "score": 90,
        "reason": "shell_exec()를 통한 외부 명령 실행 시도",
        "evidence": "shell_exec($_GET[...]) 패턴 탐지",
    },
    {
        "pattern": r"base64_decode\s*\(.+\)\s*\(",
        "score": 85,
        "reason": "base64 디코딩 후 즉시 함수 호출 — 난독화 웹쉘 패턴",
        "evidence": "base64_decode(...)(...) 난독화 패턴 탐지",
    },
    {
        "pattern": r"\$[a-zA-Z_]+\s*=\s*base64_decode",
        "score": 75,
        "reason": "base64 디코딩 결과를 변수에 저장 후 함수로 사용 — 난독화 의심",
        "evidence": "$var = base64_decode(...) 패턴 탐지",
    },
    {
        "pattern": r"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "score": 98,
        "reason": "외부 입력값을 eval()로 직접 실행 — 가장 위험한 웹쉘 패턴",
        "evidence": "eval($_GET[...]) 패턴 탐지",
    },
    {
        "pattern": r"eval\s*\(.*(base64_decode|gzinflate|str_rot13)",
        "score": 90,
        "reason": "인코딩된 코드를 eval()로 실행 — 난독화 웹쉘",
        "evidence": "eval(decode(...)) 난독화 패턴 탐지",
    },
    {
        "pattern": r"preg_replace\s*\(.+/e",
        "score": 85,
        "reason": "/e 플래그를 이용한 코드 실행 시도",
        "evidence": "preg_replace /e 패턴 탐지",
    },
]

SAMPLE_CODES = {
    "일반 웹쉘": "<?php system($_GET['cmd']); ?>",
    "난독화 웹쉘": "<?php $a=base64_decode('c3lzdGVt');$a($_GET['c']); ?>",
    "eval 웹쉘": "<?php eval($_GET['code']); ?>",
    "정상 PHP": '<?php echo "Hello, World!"; ?>',
}


def analyze_webshell(code: str) -> dict:
    """규칙 기반 웹쉘 탐지 — LLM 없이 동작"""
    matched = []
    max_score = 0

    for rule in WEBSHELL_RULES:
        if re.search(rule["pattern"], code, re.IGNORECASE):
            matched.append(rule)
            if rule["score"] > max_score:
                max_score = rule["score"]

    if matched:
        return {
            "판정": "악성",
            "위험도": max_score,
            "이유": matched[0]["reason"],
            "근거": [r["evidence"] for r in matched],
        }
    else:
        return {
            "판정": "정상",
            "위험도": 5,
            "이유": "알려진 웹쉘 패턴이 탐지되지 않았습니다.",
            "근거": ["system/exec/eval 등 위험 함수 미탐지", "외부 입력값 직접 실행 패턴 없음"],
        }


def render():
    st.markdown("""<div style="color:#2563eb;font-size:13px;font-weight:700;
        letter-spacing:2px;padding:14px 0 6px 0;">🛡️ DEFENSE SCENARIO — 3 COUNTERMEASURES</div>""",
        unsafe_allow_html=True)
    st.info("💡 각 공격 단계의 취약점에 대응하는 방어 조치를 직접 적용해보세요.")

    # DEF 01
    with st.expander("  [ DEF 01 ]  계정정보 암호화 — Credential Encryption at Rest", expanded=True):
        section_header("📹 교육 영상", "#00cfff")
        video_player("d1")
        st.markdown("")
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("DEFENSE BRIEF", "#00cfff")
            st.markdown("""
**목표:** 평문 저장된 계정정보를 AES-256 암호화하여
웹쉘로 읽어도 내용을 알 수 없게 만드세요.

**방어 원리:**
`server_info.txt`를 OpenSSL AES-256으로 암호화 후 원본 삭제.
공격자가 웹쉘로 `.enc` 파일을 읽어도
암호화된 바이너리만 보여 계정정보 획득 불가.
→ **Lateral Movement 원천 차단**

**📌 실습 순서:**
```bash
ls /var/www/html/dvwa/config/
sudo openssl enc -aes-256-cbc -pbkdf2 -in /var/www/html/dvwa/config/server_info.txt -out /var/www/html/dvwa/config/server_info.enc -k secretkey123
sudo rm /var/www/html/dvwa/config/server_info.txt
cat /var/www/html/dvwa/config/server_info.enc
```
""")
            defense_box([
                "파일 읽기 → 암호화 바이너리만 노출",
                "Lateral Movement 불가",
                "추가 권장: AWS Secrets Manager 사용",
            ])
        with c2:
            section_header("TERMINAL — www-data@ServerA", "#00cfff")
            fake_terminal("d1", RD1, host="ServerA", user="www-data")
            if st.button("✅  DEF 01 완료", key="btn5", use_container_width=True):
                st.session_state.completed["방어1: 계정정보 암호화"] = True
                st.success("DEF 01 CLEAR — Lateral Movement 차단")

    # DEF 02
    with st.expander("  [ DEF 02 ]  웹쉘 탐지 — Rule-based Webshell Detection"):
        section_header("📹 교육 영상", "#00cfff")
        video_player("d2")
        st.markdown("")
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("DEFENSE BRIEF", "#00cfff")
            st.markdown("""
**목표:** PHP 코드를 직접 입력하고 웹쉘 여부를 탐지하세요.

**방어 원리:**
정규식 기반 패턴 매칭으로 위험 함수 탐지.
`system()`, `exec()`, `eval()`, `base64_decode()` 등
웹쉘에서 자주 사용되는 패턴을 분석합니다.

**테스트해볼 코드 예시:**
```php
<?php system($_GET['cmd']); ?>
<?php $a=base64_decode('c3lzdGVt');$a($_GET['c']); ?>
<?php eval($_GET['code']); ?>
<?php echo "Hello, World!"; ?>
```
""")

            # 샘플 버튼
            section_header("빠른 샘플 선택", "#00cfff")
            cols = st.columns(4)
            for i, (label, code) in enumerate(SAMPLE_CODES.items()):
                if cols[i].button(label, key=f"sample_{i}", use_container_width=True):
                    st.session_state["def02_code"] = code

            # 코드 입력창
            st.markdown("")
            code_input = st.text_area(
                "PHP 코드 입력",
                value=st.session_state.get("def02_code", ""),
                height=120,
                placeholder="<?php ... ?>",
                label_visibility="collapsed",
            )

            if st.button("🔍  웹쉘 분석 실행", use_container_width=True, key="btn_analyze"):
                if code_input.strip():
                    st.session_state["def02_result"] = analyze_webshell(code_input)
                    st.session_state["def02_analyzed_code"] = code_input

        with c2:
            section_header("분석 결과", "#00cfff")

            if "def02_result" in st.session_state:
                result = st.session_state["def02_result"]
                code_shown = st.session_state.get("def02_analyzed_code", "")

                # 분석한 코드 표시
                st.code(code_shown, language="php")

                # 판정 배너
                if result["판정"] == "악성":
                    st.error(f"🚨 악성 웹쉘 탐지 — 위험도: {result['위험도']}/100")
                else:
                    st.success(f"✅ 정상 파일 — 위험도: {result['위험도']}/100")

                # 위험도 프로그레스바
                st.progress(result["위험도"] / 100)

                # 분석 이유
                st.markdown(f"""
<div style="background:#f8fafc;border:2px solid #e2e8f0;border-radius:8px;padding:14px;margin-top:10px;">
    <div style="font-size:13px;font-weight:700;color:#2d3748;margin-bottom:8px;">📋 분석 결과</div>
    <div style="font-size:14px;color:#4a5568;margin-bottom:10px;">{result['이유']}</div>
    <div style="font-size:12px;font-weight:700;color:#718096;margin-bottom:6px;">탐지 근거</div>
    {"".join(f'<div style="font-size:13px;color:#2563eb;padding:2px 0;">→ {e}</div>' for e in result['근거'])}
</div>
""", unsafe_allow_html=True)

                if st.button("✅  DEF 02 완료", key="btn6", use_container_width=True):
                    st.session_state.completed["방어2: 웹쉘 탐지"] = True
                    st.success("DEF 02 CLEAR — 웹쉘 탐지 성공")
            else:
                st.markdown("""
<div style="background:#f8fafc;border:2px dashed #e2e8f0;border-radius:8px;
     padding:40px;text-align:center;color:#94a3b8;font-size:14px;">
    왼쪽에서 코드를 입력하고<br>분석 실행 버튼을 눌러주세요
</div>
""", unsafe_allow_html=True)

            # 탐지 방법 비교표
            st.markdown("")
            section_header("탐지 방법 비교", "#2563eb")
            st.markdown("""
<div style="background:#eff6ff;border:2px solid #93c5fd;border-radius:8px;padding:18px;">
    <table style="width:100%;border-collapse:collapse;">
        <tr>
            <th style="color:#718096;text-align:left;padding:8px;border-bottom:2px solid #e2e8f0;font-size:14px;">방법</th>
            <th style="color:#718096;text-align:center;padding:8px;border-bottom:2px solid #e2e8f0;font-size:14px;">일반 웹쉘</th>
            <th style="color:#718096;text-align:center;padding:8px;border-bottom:2px solid #e2e8f0;font-size:14px;">난독화 웹쉘</th>
        </tr>
        <tr>
            <td style="color:#2d3748;padding:10px 8px;font-size:14px;">시그니처 기반 (AV)</td>
            <td style="color:#16a34a;text-align:center;font-size:16px;font-weight:700;">✓ 탐지</td>
            <td style="color:#dc2626;text-align:center;font-size:16px;font-weight:700;">✗ 미탐</td>
        </tr>
        <tr>
            <td style="color:#2d3748;padding:10px 8px;font-size:14px;">규칙 기반 (현재)</td>
            <td style="color:#16a34a;text-align:center;font-size:16px;font-weight:700;">✓ 탐지</td>
            <td style="color:#d97706;text-align:center;font-size:16px;font-weight:700;">△ 일부</td>
        </tr>
        <tr>
            <td style="color:#2563eb;padding:10px 8px;font-size:14px;font-weight:700;">LLM 분석</td>
            <td style="color:#16a34a;text-align:center;font-size:16px;font-weight:700;">✓ 탐지</td>
            <td style="color:#16a34a;text-align:center;font-size:16px;font-weight:700;">✓ 탐지</td>
        </tr>
    </table>
</div>
""", unsafe_allow_html=True)

    # DEF 03
    with st.expander("  [ DEF 03 ]  DB 암호화 — AES Encryption at Rest"):
        section_header("📹 교육 영상", "#00cfff")
        video_player("d3")
        st.markdown("")
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("DEFENSE BRIEF", "#00cfff")
            st.markdown("""
**목표:** DB의 Ki값을 AES 암호화하여
데이터를 탈취해도 유심 복제가 불가능하게 하세요.

**방어 원리:**
Ki값을 MySQL `AES_ENCRYPT`로 암호화 저장.
공격자가 DB 전체를 덤프해도
암호키 없이는 Ki 원본 복호화 불가 → 유심 복제 불가.

**📌 실습 순서:**
```sql
mysql -u dbadmin -p1234 simdb
SELECT * FROM usim LIMIT 3;
UPDATE usim SET Ki = HEX(AES_ENCRYPT(Ki, 'supersecretkey'));
SELECT * FROM usim;
```
""")
            defense_box([
                "Ki 탈취 → 암호화된 HEX값만 획득",
                "유심 복제 불가 → 통신 도감청 차단",
                "추가 권장: 컬럼 레벨 암호화 + HSM 사용",
            ])
        with c2:
            section_header("TERMINAL — dbadmin@ServerB", "#00cfff")
            fake_terminal("d3", RD3, host="ServerB", user="dbadmin")
            if st.button("✅  DEF 03 완료", key="btn7", use_container_width=True):
                st.session_state.completed["방어3: DB 암호화"] = True
                st.success("DEF 03 CLEAR — 데이터 탈취해도 Ki 복호화 불가")