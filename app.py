import re

import streamlit as st
from dotenv import load_dotenv

from agent import agent
from middleware_tests import run_all_middleware_tests

load_dotenv()

OCEAN_CSS = """
<style>
.stApp {
    background: linear-gradient(180deg, #e0f7fa 0%, #b2ebf2 30%, #4dd0e1 65%, #00838f 100%);
    background-attachment: fixed;
    background-size: 100% 100vh;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #01579b 0%, #003c5f 100%);
}
[data-testid="stSidebar"] * {
    color: #e0f7fa !important;
}
[data-testid="stSidebar"] button {
    background: rgba(255,255,255,0.08) !important;
    border: 1px solid rgba(255,255,255,0.25) !important;
}
[data-testid="stSidebar"] button:hover {
    background: rgba(255,255,255,0.2) !important;
    border-color: #4dd0e1 !important;
}
[data-testid="stChatMessage"] {
    border-radius: 14px;
    border-left: 4px solid transparent;
    background: rgba(255,255,255,0.4);
    backdrop-filter: blur(6px);
    -webkit-backdrop-filter: blur(6px);
    padding: 0.6em 0.9em;
    margin-bottom: 0.7em;
    box-shadow: 0 1px 4px rgba(0,60,90,0.1);
}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) {
    border-left-color: #ff8f00;
}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]) {
    border-left-color: #00838f;
}
[data-testid="stChatMessageContent"] * {
    color: #012a3a !important;
}
[data-testid="stChatMessageAvatarUser"],
[data-testid="stChatMessageAvatarAssistant"] {
    background: rgba(255,255,255,0.5) !important;
}
[data-testid="stBottom"], [data-testid="stBottomBlockContainer"] {
    background: transparent !important;
}
[data-testid="stChatInput"] {
    background: rgba(255,255,255,0.4) !important;
    backdrop-filter: blur(6px);
    -webkit-backdrop-filter: blur(6px);
    border-radius: 14px !important;
    border: 1px solid rgba(255,255,255,0.5) !important;
    box-shadow: 0 1px 4px rgba(0,60,90,0.1);
}
[data-testid="stChatInputTextArea"] {
    color: #012a3a !important;
}
[data-testid="stChatInputTextArea"]::placeholder {
    color: #01323d !important;
    opacity: 0.6;
}
h1, h2, h3 { color: #003c5f !important; }
[data-testid="stCaptionContainer"] { color: #01323d !important; }
.wave-divider {
    text-align: center;
    letter-spacing: 6px;
    opacity: 0.6;
    margin: 0.2em 0 1em 0;
}
</style>
"""

VERDICT_STYLE = {
    "안전": ("🐠", "success", "안전한 바다입니다. 낚싯바늘 없음."),
    "의심": ("🎣", "warning", "낚싯바늘 냄새가 납니다. 조심해서 다루세요."),
    "악성": ("🦈", "error", "상어 출현! 절대 클릭하지 마세요."),
}


def load_samples(path: str = "sample_email.md") -> list[dict]:
    with open(path, encoding="utf-8") as f:
        text = f.read()

    pattern = re.compile(r"^\d+[.)]\s*(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(text))

    samples = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        title = m.group(1).strip()
        body = text[start:end].strip()
        samples.append({"title": title, "text": body})
    return samples


def render_verdict(answer: str):
    m = re.search(r"최종 판정:\s*(안전|의심|악성)", answer)
    if not m:
        return
    emoji, kind, note = VERDICT_STYLE[m.group(1)]
    getattr(st, kind)(f"{emoji} **{m.group(1)}** — {note}")


def run_analysis(email_text: str):
    st.session_state.messages.append({"role": "user", "content": email_text})
    with st.spinner("🐬 요원이 그물을 던지는 중..."):
        result = agent.invoke({"messages": [("user", email_text)]})
        answer = result["messages"][-1].content
    st.session_state.messages.append({"role": "assistant", "content": answer})


SAMPLES = load_samples()

st.set_page_config(page_title="피싱 낚시 탐지대", page_icon="🎣", layout="wide")
st.markdown(OCEAN_CSS, unsafe_allow_html=True)

st.title("🎣 피싱 낚시 탐지대")
st.caption("수상한 메일이 왔다면, 낚인 건지 아닌지 여기서 건져보세요 🌊")
st.markdown('<div class="wave-divider">〜〜〜 🐟 🐠 🐬 🦈 🐟 〜〜〜</div>', unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = []

with st.sidebar:
    st.subheader("🧰 미끼 상자 (샘플 메일)")
    st.caption("클릭하면 바로 분석돼요")
    for i, sample in enumerate(SAMPLES):
        if st.button(f"🐟 {sample['title']}", key=f"sample_{i}", use_container_width=True):
            run_analysis(sample["text"])
            st.rerun()
    st.divider()
    if st.button("🌊 그물 비우기 (대화 초기화)", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.divider()
    st.subheader("🧪 미들웨어 테스트")
    st.caption("LLM 호출 없이 middleware.py의 각 미들웨어 로직만 검증합니다")
    if st.button("테스트 실행", use_container_width=True):
        with st.spinner("미들웨어 테스트 실행 중..."):
            st.session_state.middleware_test_results = run_all_middleware_tests()

    results = st.session_state.get("middleware_test_results")
    if results:
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        if passed == total:
            st.success(f"✅ 전체 {total}개 미들웨어 통과")
        else:
            st.error(f"❌ {total - passed}/{total}개 미들웨어 실패")

        for r in results:
            icon = "✅" if r.passed else "❌"
            with st.expander(f"{icon} {r.name}", expanded=not r.passed):
                st.caption(r.description)
                if r.error:
                    st.error(f"테스트 실행 중 예외 발생: {r.error}")
                for c in r.checks:
                    line = f"{'✅' if c.passed else '❌'} {c.label}"
                    if c.detail:
                        line += f"  \n　　({c.detail})"
                    st.markdown(line)

for msg in st.session_state.messages:
    with st.chat_message(msg["role"], avatar="📧" if msg["role"] == "user" else "🐬"):
        st.markdown(msg["content"])
        if msg["role"] == "assistant":
            render_verdict(msg["content"])

email_text = st.chat_input("여기에 수상한 이메일을 던져보세요 🎣")
if email_text:
    run_analysis(email_text)
    st.rerun()
