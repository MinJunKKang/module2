from openai import OpenAI
import streamlit as st

from llm.threat_modeling_pipeline import THREAT_ROWS

MODEL = "gpt-4o-mini"

_client = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        import os
        from dotenv import load_dotenv
        load_dotenv()
        _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return _client


def _call_gpt(system: str, user: str) -> str:
    try:
        resp = _get_client().chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            temperature=0.4,
            max_tokens=700,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"⚠️ GPT 해설 생성 중 오류가 발생했습니다: {e}"


# ── 공통 시스템 프롬프트 ───────────────────────────────────────────────────────

_SYSTEM = (
    "당신은 보안 교육 플랫폼의 해설 작가입니다. "
    "보안 지식이 없는 일반인도 이해할 수 있도록 친근하고 명확하게 설명하세요. "
    "전문 용어는 괄호 안에 간단한 부연을 달아주세요. "
    "마크다운 사용 가능. 응답은 반드시 한국어로 작성하세요."
)


# ── 섹션별 해설 생성 함수 ─────────────────────────────────────────────────────

@st.cache_data(show_spinner=False, ttl=3600)
def generate_dfd_commentary() -> str:
    """DFD 다이어그램 해설 — 공격 흐름과 신뢰 경계를 쉽게 설명"""
    flows = "\n".join(
        f"- {row['단계']}: {row['데이터 흐름']}"
        for row in THREAT_ROWS
    )
    user = f"""아래는 침해사고 시나리오의 데이터 흐름(DFD) 정보입니다.

공격 흐름:
{flows}

다음 내용을 3~4문장으로 해설해주세요:
1. 이 DFD가 보여주는 전체 공격 경로의 흐름
2. 공격자가 어떤 경로로 최종 목표(DB)에 도달했는지
3. 각 화살표(데이터 흐름)가 방어 관점에서 왜 중요한지

응답 형식:
각 항목을 아래처럼 작성해주세요.

**[항목 제목]**
설명 문장 (2문장 이내). 빈 줄로 항목을 구분하세요."""
    return _call_gpt(_SYSTEM, user)


@st.cache_data(show_spinner=False, ttl=3600)
def generate_stride_commentary() -> str:
    """STRIDE 히트맵 해설 — 위협 유형별 의미를 쉽게 풀어 설명"""
    stride_summary = "\n".join(
        f"- {row['단계']}: {row['STRIDE 유형']} → {row['STRIDE 설명']}"
        for row in THREAT_ROWS
    )
    user = f"""아래는 각 공격 단계별 STRIDE 위협 분석 결과입니다.

{stride_summary}

다음 내용을 3~4문장으로 해설해주세요:
1. 이번 시나리오에서 가장 많이 나타난 위협 유형과 그 이유
2. 고위험으로 분류된 위협이 실제로 어떤 피해를 일으킬 수 있는지
3. 비전문가가 히트맵을 보고 핵심을 파악하는 방법

응답 형식:
각 항목을 아래처럼 작성해주세요.

**[항목 제목]**
설명 문장 (2문장 이내). 빈 줄로 항목을 구분하세요."""
    return _call_gpt(_SYSTEM, user)


@st.cache_data(show_spinner=False, ttl=3600)
def generate_dread_commentary() -> str:
    """DREAD 점수 해설 — 점수의 의미와 우선순위를 쉽게 설명"""
    dread_summary = "\n".join(
        f"- {row['단계']}: D={row['Damage']} R={row['Reproducibility']} "
        f"E={row['Exploitability']} A={row['Affected Users']} "
        f"D2={row['Discoverability']} / 우선순위={row['우선순위']}"
        for row in THREAT_ROWS
    )
    total_scores = {
        row['단계']: row['Damage'] + row['Reproducibility'] +
                     row['Exploitability'] + row['Affected Users'] +
                     row['Discoverability']
        for row in THREAT_ROWS
    }
    highest = max(total_scores, key=total_scores.get)

    user = f"""아래는 각 공격 단계별 DREAD 위험도 점수입니다 (각 항목 1~10점, 총점 50점 만점).

{dread_summary}

가장 높은 총점 단계: {highest} ({total_scores[highest]}/50)

다음 내용을 3~4문장으로 해설해주세요:
1. 어떤 단계가 가장 위험하고 왜 그런지
2. DREAD 점수가 실무에서 어떤 의사결정에 활용되는지
3. 이 점수를 바탕으로 가장 먼저 대응해야 할 것

응답 형식:
각 항목을 아래처럼 작성해주세요.

**[항목 제목]**
설명 문장 (2문장 이내). 빈 줄로 항목을 구분하세요."""
    return _call_gpt(_SYSTEM, user)


@st.cache_data(show_spinner=False, ttl=3600)
def generate_security_req_commentary() -> str:
    """보안 요구사항 명세 해설 — 요구사항이 왜 필요한지 맥락 설명"""
    req_summary = "\n".join(
        f"- {row['단계']} ({row['요구사항 ID']}): {row['보안 목표']}"
        for row in THREAT_ROWS
    )
    critical_stages = [
        row['단계'] for row in THREAT_ROWS if row['우선순위'] == 'Critical'
    ]

    user = f"""아래는 각 공격 단계별 보안 요구사항 명세 요약입니다.

{req_summary}

Critical 우선순위 단계: {', '.join(critical_stages) if critical_stages else '없음'}

다음 내용을 3~4문장으로 해설해주세요:
1. 이 보안 요구사항들이 앞서 식별한 STRIDE 위협을 어떻게 해소하는지
2. Critical 단계를 가장 먼저 처리해야 하는 이유
3. 보안 요구사항 명세가 단순 대응책 목록과 다른 점

응답 형식:
각 항목을 아래처럼 작성해주세요.

**[항목 제목]**
설명 문장 (2문장 이내). 빈 줄로 항목을 구분하세요."""
    return _call_gpt(_SYSTEM, user)