from functools import lru_cache
import requests
from bs4 import BeautifulSoup

ATTACK_BASE = "https://attack.mitre.org/techniques"
ENTERPRISE_INDEX_URL = "https://attack.mitre.org/techniques/enterprise/"

TECHNIQUE_URLS = {
    "T1190": f"{ATTACK_BASE}/T1190/",
    "T1505.003": f"{ATTACK_BASE}/T1505/003/",
    "T1105": f"{ATTACK_BASE}/T1105/",
    "T1552": f"{ATTACK_BASE}/T1552/",
    "T1552.001": f"{ATTACK_BASE}/T1552/001/",
    "T1005": f"{ATTACK_BASE}/T1005/",
    "T1021": f"{ATTACK_BASE}/T1021/",
    "T1021.004": f"{ATTACK_BASE}/T1021/004/",
    "T1078": f"{ATTACK_BASE}/T1078/",
    "T1213.006": f"{ATTACK_BASE}/T1213/006/",
}

KOR_SUMMARY_MAP = {
    "T1190": "인터넷에 노출된 웹 애플리케이션이나 서비스의 취약점을 악용해 처음 침투하는 기법",
    "T1505.003": "웹 서버에 웹쉘을 올려 명령 실행과 지속적 접근 거점으로 사용하는 기법",
    "T1105": "공격에 필요한 도구나 파일을 외부에서 내부 시스템으로 가져오는 기법",
    "T1552": "안전하지 않게 저장된 자격증명을 찾아 획득하는 상위 기법",
    "T1552.001": "설정 파일이나 텍스트 파일 등에 저장된 평문 자격증명을 수집하는 기법",
    "T1005": "로컬 시스템에 있는 파일, 설정, 데이터 등을 수집하는 기법",
    "T1021": "원격 연결 서비스를 이용해 다른 시스템으로 접근하는 상위 기법",
    "T1021.004": "SSH를 통해 다른 시스템에 원격 접속하고 내부 이동을 수행하는 기법",
    "T1078": "정상 계정을 악용해 합법 사용자처럼 인증하고 시스템에 접근하는 기법",
    "T1213.006": "데이터베이스에서 공격 가치가 있는 정보를 수집하는 기법",
}

KEYWORDS_MAP = {
    "T1190": ["web", "upload", "public", "exploit", "취약점", "업로드", "dvwa"],
    "T1505.003": ["webshell", "shell", "shell.php", "웹쉘"],
    "T1105": ["upload", "file", "transfer", "tool", "전송"],
    "T1552": ["credential", "password", "config", "plaintext", "자격증명", "계정정보"],
    "T1552.001": ["config.txt", "file", "plaintext", "credential", "설정 파일", "평문"],
    "T1005": ["local", "file", "mysql", "db", "database", "data", "usim", "데이터"],
    "T1021": ["remote", "service", "ssh", "lateral", "movement", "원격"],
    "T1021.004": ["ssh", "serverb", "lateral", "movement"],
    "T1078": ["valid", "account", "credential", "login", "계정", "인증"],
    "T1213.006": ["database", "mysql", "db", "repository", "데이터베이스"],
}


def _headers():
    return {"User-Agent": "Mozilla/5.0"}


@lru_cache(maxsize=1)
def fetch_enterprise_index_text() -> str:
    try:
        response = requests.get(ENTERPRISE_INDEX_URL, headers=_headers(), timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.get_text(" ", strip=True)
    except Exception:
        return ""


@lru_cache(maxsize=32)
def crawl_attack_technique(technique_id: str) -> dict:
    url = TECHNIQUE_URLS.get(technique_id, "")
    default = {
        "id": technique_id,
        "name": technique_id,
        "summary_en": "설명을 가져오지 못했습니다.",
        "summary_ko": KOR_SUMMARY_MAP.get(technique_id, "설명을 가져오지 못했습니다."),
        "url": url,
        "index_verified": False,
    }

    if not url:
        return default

    try:
        response = requests.get(url, headers=_headers(), timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        title = technique_id
        summary_en = ""

        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(" ", strip=True)

        desc = soup.find("div", class_="description-body")
        if desc:
            p = desc.find("p")
            if p:
                summary_en = p.get_text(" ", strip=True)

        if not summary_en:
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc:
                summary_en = meta_desc.get("content", "").strip()

        index_text = fetch_enterprise_index_text()
        index_verified = technique_id in index_text

        return {
            "id": technique_id,
            "name": title,
            "summary_en": summary_en or default["summary_en"],
            "summary_ko": KOR_SUMMARY_MAP.get(technique_id, summary_en or default["summary_en"]),
            "url": url,
            "index_verified": index_verified,
        }
    except Exception:
        return default


def score_candidate(stage_text: str, flow_text: str, technique_id: str) -> int:
    haystack = f"{stage_text} {flow_text}".lower()
    score = 0

    for keyword in KEYWORDS_MAP.get(technique_id, []):
        if keyword.lower() in haystack:
            score += 2

    if "웹쉘" in stage_text and technique_id == "T1505.003":
        score += 3
    if "업로드" in stage_text and technique_id == "T1190":
        score += 2
    if "계정정보" in stage_text and technique_id in ["T1552", "T1552.001"]:
        score += 3
    if "Lateral Movement" in stage_text and technique_id in ["T1021", "T1021.004", "T1078"]:
        score += 3
    if "DB" in stage_text and technique_id in ["T1005", "T1213.006"]:
        score += 3

    return score


def cross_validate_candidates(stage_text: str, flow_text: str, candidate_ids: list[str]) -> list[dict]:
    """
    1차: 단계/데이터 흐름 키워드 규칙 점수
    2차: 공식 ATT&CK 설명 텍스트 및 Enterprise 인덱스 존재 여부 교차검증
    """
    validated = []

    for technique_id in candidate_ids:
        technique = crawl_attack_technique(technique_id)
        rule_score = score_candidate(stage_text, flow_text, technique_id)

        overlap_score = 0
        summary_blob = f"{technique['name']} {technique['summary_en']} {technique['summary_ko']}".lower()

        for token in flow_text.lower().replace("→", " ").replace("/", " ").split():
            cleaned = token.strip(".,:;()[]{}")
            if cleaned and cleaned in summary_blob:
                overlap_score += 1

        source_score = 2 if technique["index_verified"] else 0
        final_score = rule_score + overlap_score + source_score

        validated.append({
            **technique,
            "rule_score": rule_score,
            "cross_check_score": overlap_score + source_score,
            "final_score": final_score,
            "cross_check_detail": (
                "기술 페이지 설명 일치 + Enterprise 인덱스 확인"
                if technique["index_verified"]
                else "기술 페이지 설명 일치"
            ),
        })

    validated.sort(key=lambda item: item["final_score"], reverse=True)
    return validated