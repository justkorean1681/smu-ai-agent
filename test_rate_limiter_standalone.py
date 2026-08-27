"""
Rate Limiter 단독 테스트 (LLM/Agent 호출 없이 미들웨어 로직만 검증)

middleware.py의 rate_limiter_middleware를 직접 호출해서
실제 OpenAI API 비용 없이 슬라이딩 윈도우 로직만 빠르게 확인합니다.

주의: @before_agent로 감싼 함수는 일반 함수가 아니라 AgentMiddleware
객체가 되므로, rate_limiter_middleware(state, runtime)이 아니라
rate_limiter_middleware.before_agent(state, runtime) 형태로 호출해야 합니다.

실행 전 middleware.py에서 아래 값을 테스트용으로 낮춰두는 걸 권장합니다:
    _RATE_LIMIT_WINDOW_SECONDS = 60   # 1분
    _RATE_LIMIT_MAX_REQUESTS = 3      # 3건

실행:
    python test_rate_limiter_standalone.py
"""

from middleware import rate_limiter_middleware, _RATE_LIMIT_MAX_REQUESTS, _RATE_LIMIT_WINDOW_SECONDS


class FakeRuntime:
    """runtime.context / runtime.config 를 흉내내는 더미 객체"""
    def __init__(self, user_id: str = "test-user-1"):
        self.context = {"user_id": user_id}
        self.config = {"configurable": {"user_id": user_id}}


def main():
    print(f"설정: WINDOW={_RATE_LIMIT_WINDOW_SECONDS}초, MAX_REQUESTS={_RATE_LIMIT_MAX_REQUESTS}건\n")

    fake_state = {"messages": []}
    fake_runtime = FakeRuntime(user_id="test-user-1")

    total_calls = _RATE_LIMIT_MAX_REQUESTS + 3  # 제한보다 살짝 넘게 호출

    for i in range(1, total_calls + 1):
        # @before_agent로 감싼 함수는 AgentMiddleware 객체이므로
        # .before_agent(state, runtime)으로 실제 로직을 호출합니다.
        result = rate_limiter_middleware.before_agent(fake_state, fake_runtime)

        if result is None:
            print(f"[{i:02d}] ✅ 통과")
        else:
            msg = result["messages"][0].content
            print(f"[{i:02d}] 🚫 차단 -> {msg}")


if __name__ == "__main__":
    main()
