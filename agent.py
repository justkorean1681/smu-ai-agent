from langchain.agents import create_agent
from tools import CUSTOM_TOOLS
from middleware import (
    rate_limiter_middleware,
    pii_input_masking_middleware,
    prompt_injection_filter_middleware,
    pii_masking_middleware,
    skill_lifecycle_middleware,
    SkillMiddleware,
)


def create_phishing_analysis_agent():
    system_prompt = """당신은 의심스러운 이메일을 분석하고 피싱 여부를 판단하는 AI Agent입니다.

아래 도구를 활용하여 이메일을 종합적으로 분석하세요:
- EmailParserTool: 이메일 원문에서 발신자, 수신자, 제목, 본문, URL, 첨부파일, 의심 키워드를 추출합니다.
- URLSecurityCheckTool: 추출된 URL의 위험도를 검사합니다.
- DomainLookupTool: 발신자 도메인의 형식, 하위도메인, TLD 등을 분석합니다.
- ThreatIntelligenceSearchTool: 과거 피싱 사례 및 위협 인텔리전스 연관성을 확인합니다.
- RiskScoreTool: 모든 정보를 종합하여 최종 판정을 수행합니다.
- PhishingAnalyzerSkill: 이메일 분석 요청을 받으면 가장 먼저 호출하는 진입점으로, 이후 따라야 할 도구 호출 순서를 반환합니다.
- load_skill: 판정 기준표/보고서 형식 등 전문 절차를 필요할 때 로드합니다.

분석 절차:
1. PhishingAnalyzerSkill을 호출하여 분석 파이프라인을 시작하고, 반환된 순서를 따릅니다.
2. EmailParserTool로 이메일 원문을 구조화합니다.
3. 추출된 각 URL은 URLSecurityCheckTool로 검사합니다.
4. 발신자 이메일 또는 도메인은 DomainLookupTool로 확인합니다.
5. 의심 키워드, 첨부파일, 과거 사례는 ThreatIntelligenceSearchTool과 RiskScoreTool에 반영합니다.
6. 최종 판정 전에 load_skill('phishing-triage')로 판정 기준과 보고서 형식을 로드하고, 그 기준을 그대로 적용합니다.
7. 최종적으로 안전 / 의심 / 악성 중 하나로 판정하고 근거를 요약합니다.

응답 형식:
- 분석 요약
- 주요 의심 신호
- 개별 도구 결과 요약
- 최종 판정: 안전 / 의심 / 악성
- 필요 시 권고 조치

모든 응답은 한글로 작성하세요."""

    agent_executor = create_agent(
        model="gpt-5.4-mini",
        tools=CUSTOM_TOOLS,
        system_prompt=system_prompt,
        # 미들웨어 실행 순서:
        # 1. rate_limiter_middleware          - Agent 실행 전, 과도한 요청부터 차단 (Denial of Wallet 방지)
        # 2. pii_input_masking_middleware     - 모델 최초 호출 전, 사용자 원본 메시지(이메일 원문)의
        #                                        개인정보를 마스킹 → LLM은 애초에 raw PII를 보지 못함
        # 5. skill_lifecycle_middleware       - 'Skill'로 끝나는 메타 도구 호출의 시작/종료를 로깅
        # 6. SkillMiddleware                  - 모델 호출 직전, 시스템 프롬프트에 스킬 목록 주입
        #                                        (상세 내용은 load_skill 호출 시에만 로드)
        # 3. prompt_injection_filter_middleware - EmailParserTool 결과에서 인젝션 시도를 탐지/무력화
        # 4. pii_masking_middleware           - EmailParserTool 결과에도 추가로 마스킹 적용 (이중 방어)
        middleware=[
            rate_limiter_middleware,
            pii_input_masking_middleware,
            prompt_injection_filter_middleware,
            pii_masking_middleware,
            skill_lifecycle_middleware,
            SkillMiddleware(),
        ],
    )

    return agent_executor


agent = create_phishing_analysis_agent()