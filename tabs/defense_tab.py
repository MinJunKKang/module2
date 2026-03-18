import streamlit as st
from components import fake_terminal, section_header, defense_box
from config import RD1, RD3


def render():
    st.markdown("""<div style="color:#2563eb;font-size:13px;font-weight:700;
        letter-spacing:2px;padding:14px 0 6px 0;">🛡️ DEFENSE SCENARIO — 3 COUNTERMEASURES</div>""",
        unsafe_allow_html=True)
    st.info("💡 각 공격 단계의 취약점에 대응하는 방어 조치를 직접 적용해보세요.")

    # DEF 01
    with st.expander("  [ DEF 01 ]  계정정보 암호화 — Credential Encryption at Rest", expanded=True):
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
    with st.expander("  [ DEF 02 ]  웹쉘 탐지 — LLM-based Webshell Detection"):
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("DEFENSE BRIEF", "#00cfff")
            st.markdown("""
**목표:** 업로드된 PHP 파일이 웹쉘인지 LLM으로 탐지하세요.

**방어 원리:**
기존 시그니처 기반 도구(AV, WAF)는
**난독화 웹쉘**을 탐지하지 못합니다.
LLM은 코드 **의미**를 이해하므로 난독화 여부와
관계없이 악성 코드를 탐지할 수 있습니다.

**테스트용 예시:**

일반 웹쉘:
```php
<?php system($_GET['cmd']); ?>
```

난독화 웹쉘:
```php
<?php $a=base64_decode('c3lzdGVt');$a($_GET['c']); ?>
```

정상 PHP:
```php
<?php echo "Hello, World!"; ?>
```
""")
            uploaded_file = st.file_uploader("📎 PHP 파일 업로드", type=["php"], label_visibility="collapsed")
            if uploaded_file:
                code = uploaded_file.read().decode("utf-8")
                st.code(code, language="php")
                if st.button("🤖  LLM 분석 실행", use_container_width=True):
                    st.info("🔧 LLM 분석 기능은 준비 중입니다.")
        with c2:
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
            <td style="color:#2d3748;padding:10px 8px;font-size:14px;">규칙 기반 (WAF)</td>
            <td style="color:#d97706;text-align:center;font-size:16px;font-weight:700;">△ 일부</td>
            <td style="color:#dc2626;text-align:center;font-size:16px;font-weight:700;">✗ 미탐</td>
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