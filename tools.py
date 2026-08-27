from langchain_core.tools import tool
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
import re


@tool(parse_docstring=True)
def EmailParserTool(email_text: str) -> str:
    """이메일 원문에서 피싱 분석에 필요한 정보를 추출합니다.

    Args:
        email_text: 분석할 이메일 원문입니다.

    Returns:
        발신자, 수신자, 제목, 본문, URL, 첨부파일 및 피싱 의심 키워드 분석 결과입니다.
    """
    try:
        msg = Parser(policy=policy.default).parsestr(email_text)
        sender = msg.get("From", "정보 없음")
        recipient = msg.get("To", "정보 없음")
        subject = msg.get("Subject", "정보 없음")

        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        content = part.get_content()
                        if "\\u" in content:
                            try:
                                content = content.encode("utf-8").decode("unicode_escape")
                            except Exception:
                                pass
                        if content:
                            body_parts.append(content)
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_content()
                if "\\u" in body:
                    try:
                        body = body.encode("utf-8").decode("unicode_escape")
                    except Exception:
                        pass
                if body:
                    body_parts.append(body)
            except Exception:
                pass

        body = "\n".join(body_parts).strip() or email_text
        urls = re.findall(r'''https?://[^\s<>"'\)\]]+''', body)
        attachments = []
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)

        suspicious_keywords = [
            "긴급", "즉시", "계정 정지", "계정이 잠겼", "비밀번호", "인증", "로그인", "결제", "송금",
            "보안 경고", "urgent", "verify", "verification", "password", "account suspended", "login",
            "payment", "security alert"
        ]
        search_text = f"{subject}\n{body}".lower()
        found_keywords = [keyword for keyword in suspicious_keywords if keyword.lower() in search_text]

        result = f"""
[EmailParserTool 분석 결과]

발신자: {sender}
수신자: {recipient}
제목: {subject}

본문:
{body[:3000]}

추출된 URL:
{chr(10).join(urls) if urls else "없음"}

첨부파일:
{chr(10).join(attachments) if attachments else "없음"}

피싱 의심 키워드:
{", ".join(found_keywords) if found_keywords else "탐지되지 않음"}

URL 개수: {len(urls)}
첨부파일 개수: {len(attachments)}
"""
        return result.strip()
    except Exception as e:
        return f"EmailParserTool 실행 실패: {str(e)}"


@tool(parse_docstring=True)
def URLSecurityCheckTool(url: str) -> str:
    """URL의 위험도를 간단히 검사합니다.

    Args:
        url: 검사할 URL 문자열입니다.

    Returns:
        URL 위험도 검사 결과 문자열입니다.
    """
    try:
        target = url.strip()
        if not target:
            return "실패: URL이 비어 있습니다."

        parsed = urlparse(target if target.startswith(("http://", "https://")) else f"http://{target}")
        host = (parsed.netloc or parsed.path).lower()

        score = 0
        signals = []
        if parsed.scheme not in {"http", "https"}:
            score += 10
            signals.append("비정상적인 스킴")
        if "@" in host:
            score += 20
            signals.append("@ 포함 URL")
        if len(host) > 30:
            score += 5
            signals.append("과도하게 긴 호스트명")
        if host.count("-") >= 3:
            score += 5
            signals.append("하이픈 과다 사용")

        suspicious_domains = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}
        if any(host.endswith(domain) or domain in host for domain in suspicious_domains):
            score += 20
            signals.append("단축 URL 또는 위험 도메인")
        if re.search(r"[\u4e00-\u9fff]", host):
            score += 10
            signals.append("유니코드/한자 도메인 의심")
        if any(ext in target.lower() for ext in [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs"]):
            score += 15
            signals.append("실행 파일형 경로 포함")

        verdict = "안전" if score < 15 else "의심" if score < 35 else "악성"
        return "\n".join([
            f"URL: {target}",
            f"판정: {verdict}",
            f"위험 점수: {score}/100",
            f"감지 신호: {', '.join(signals) if signals else '없음'}",
        ])
    except Exception as e:
        return f"실패: {str(e)}"


@tool(parse_docstring=True)
def DomainLookupTool(domain: str) -> str:
    """발신자 도메인의 기본 특성을 분석합니다.

    Args:
        domain: 분석할 도메인 문자열입니다.

    Returns:
        도메인 분석 결과 문자열입니다.
    """
    try:
        value = domain.strip().lower()
        if not value:
            return "실패: 도메인이 비어 있습니다."
        if "@" in value:
            value = value.split("@", 1)[1]

        score = 0
        signals = []
        if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", value):
            score += 20
            signals.append("도메인 형식 비정상")
        if value.startswith("xn--") or ".xn--" in value:
            score += 10
            signals.append("Punycode 사용")
        if value.count(".") >= 3:
            score += 5
            signals.append("서브도메인 다수")

        suspicious_tlds = {"tk", "top", "xyz", "ru", "cc"}
        tld = value.rsplit(".", 1)[-1] if "." in value else ""
        if tld in suspicious_tlds:
            score += 10
            signals.append("위험 가능 TLD")

        verdict = "안전" if score < 10 else "의심" if score < 25 else "악성"
        return "\n".join([
            f"도메인: {value}",
            f"판정: {verdict}",
            f"위험 점수: {score}/100",
            f"감지 신호: {', '.join(signals) if signals else '없음'}",
        ])
    except Exception as e:
        return f"실패: {str(e)}"


@tool(parse_docstring=True)
def ThreatIntelligenceSearchTool(query: str) -> str:
    """과거 피싱 사례 및 위협 인텔리전스 관련 키워드를 검색형으로 요약합니다.

    Args:
        query: 검색할 문자열 또는 IOC 관련 요약 정보입니다.

    Returns:
        위협 인텔리전스 요약 문자열입니다.
    """
    try:
        text = query.strip().lower()
        if not text:
            return "실패: 검색어가 비어 있습니다."

        keywords = [
            "phishing", "malware", "credential theft", "ioc", "known bad",
            "피싱", "악성", "자격 증명 탈취", "위협", "도메인", "url"
        ]
        hits = [kw for kw in keywords if kw in text]

        score = 0
        if hits:
            score += 30
        if any(term in text for term in ["urgent", "verify", "계정", "비밀번호", "결제"]):
            score += 10

        verdict = "안전" if score < 10 else "의심" if score < 25 else "악성"
        return "\n".join([
            f"검색어: {query}",
            f"판정: {verdict}",
            f"매칭 키워드: {', '.join(hits) if hits else '없음'}",
            f"참고 점수: {score}/100",
            "참고: 실제 외부 TI API 연동 전 기본 휴리스틱 결과입니다.",
        ])
    except Exception as e:
        return f"실패: {str(e)}"


@tool(parse_docstring=True)
def RiskScoreTool(
    email_text: str,
    urls: str | None = None,
    sender_email: str | None = None,
    sender_domain: str | None = None,
    attachment_info: str | None = None,
    historical_context: str | None = None,
) -> str:
    """이메일, URL, 발신자, 첨부파일, 과거 사례를 종합하여 위험도를 산정합니다.

    Args:
        email_text: 이메일 본문 및 헤더를 포함한 전체 텍스트입니다.
        urls: 추출되었거나 검사할 URL 목록 문자열입니다.
        sender_email: 발신자 이메일 주소입니다.
        sender_domain: 발신자 도메인입니다.
        attachment_info: 첨부파일 관련 정보입니다.
        historical_context: 과거 피싱 사례 또는 위협 인텔리전스 요약입니다.

    Returns:
        최종 판정과 점수가 포함된 문자열입니다.
    """
    try:
        text = email_text or ""
        lower_text = text.lower()
        score = 0
        signals = []

        if any(k in lower_text for k in ["긴급", "즉시", "verify", "urgent", "계정 정지", "비밀번호", "로그인"]):
            score += 15
            signals.append("긴급/인증 유도 문구")

        extracted_urls = []
        if urls:
            extracted_urls = [u.strip() for u in re.split(r"[\n,;\s]+", urls) if u.strip()]
        else:
            extracted_urls = re.findall(r'''https?://[^\s<>"]+|www\.[^\s<>"]+''', text, re.IGNORECASE)

        for u in extracted_urls:
            parsed = urlparse(u if u.startswith(("http://", "https://")) else f"http://{u}")
            host = (parsed.netloc or parsed.path).lower()
            if "@" in host:
                score += 20
                signals.append("URL 내 @ 포함")
            if len(host) > 30:
                score += 5
            if host.count("-") >= 3:
                score += 5
            if any(tld in host for tld in [".tk", ".top", ".xyz", ".ru"]):
                score += 10

        if sender_email:
            m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$", sender_email.strip())
            if m:
                email_domain = m.group(1).lower()
                if sender_domain and sender_domain.lower() != email_domain:
                    score += 20
                    signals.append("발신자 도메인 불일치")
            else:
                score += 5
                signals.append("발신자 이메일 형식 비정상")

        if attachment_info:
            attachment_lower = attachment_info.lower()
            dangerous = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".docm", ".xlsm", ".pptm"]
            if any(ext in attachment_lower for ext in dangerous):
                score += 25
                signals.append("위험 첨부파일 확장자")

        if historical_context:
            hist_lower = historical_context.lower()
            if any(k in hist_lower for k in ["phishing", "malware", "ioc", "악성", "피싱"]):
                score += 30
                signals.append("과거 위협 사례 연관")

        verdict = "안전" if score < 20 else "의심" if score < 50 else "악성"
        return "\n".join([
            f"최종 판정: {verdict}",
            f"위험 점수: {score}/100",
            f"감지 신호: {', '.join(signals) if signals else '없음'}",
            f"URL 수: {len(extracted_urls)}",
        ])
    except Exception as e:
        return f"실패: {str(e)}"


CUSTOM_TOOLS = [
    EmailParserTool,
    URLSecurityCheckTool,
    DomainLookupTool,
    ThreatIntelligenceSearchTool,
    RiskScoreTool,
]

email_parser_tool = EmailParserTool
url_security_check_tool = URLSecurityCheckTool
domain_lookup_tool = DomainLookupTool
threat_intelligence_search_tool = ThreatIntelligenceSearchTool
risk_score_tool = RiskScoreTool
