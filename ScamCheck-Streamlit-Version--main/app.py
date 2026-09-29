import base64
import streamlit as st

import llm
import rules

st.set_page_config(page_title="ScamCheck", page_icon="🛡️", layout="centered")

# ---------- light styling ----------
st.markdown(
    """
<style>
.block-container {max-width: 760px; padding-top: 2rem;}
.meter-wrap {background:#e9ecef; border-radius:999px; height:18px; overflow:hidden;}
.meter-fill {height:100%; border-radius:999px;}
.verdict {font-size:1.6rem; font-weight:700; margin:0.6rem 0 0.1rem 0;}
.flag {border-left:5px solid; padding:0.5rem 0.9rem; margin:0.5rem 0;
       background:rgba(128,128,128,0.08); border-radius:0 8px 8px 0;}
.flag b {display:block;}
.small {opacity:0.75; font-size:0.9rem;}
</style>
""",
    unsafe_allow_html=True,
)

SAMPLES = {
    "Fake internship": (
        "Congratulations! You have been selected for a work from home internship at Google India. "
        "Earn Rs 5000 per day. Pay a registration fee of Rs 999 immediately to confirm your seat. "
        "Only 5 seats left! Register: http://google-intern-hiring.xyz/apply"
    ),
    "KYC threat": (
        "Dear customer, your SBI account will be blocked within 24 hours. "
        "Update your KYC now: http://sbi-kyc-update.top/login and share the OTP you receive."
    ),
    "Real college event": (
        "HACK'N'TECH Internal Hackathon 11.0 on 28 September 2026, 8 AM to 8 PM, CB-105. "
        "Register: https://forms.gle/jVcrS2nNFCtZfvSt8?utm_source=chatgpt.com"
    ),
}

# ---------- header ----------
st.title("🛡️ ScamCheck")
st.caption("Paste any WhatsApp forward, SMS or email, or upload a screenshot. Get a risk score in seconds.")

if "text" not in st.session_state:
    st.session_state.text = ""

if "messages" not in st.session_state:
    st.session_state.messages = []

cols = st.columns(len(SAMPLES))
for col, (label, sample) in zip(cols, SAMPLES.items()):
    if col.button(label, use_container_width=True):
        st.session_state.text = sample

text = st.text_area("Message to check", key="text", height=170,
                    placeholder="Paste the suspicious message here...")
screenshot = st.file_uploader("Upload screenshot", type=["png", "jpg", "jpeg"])

# ---------- AI & Language settings ----------
use_ai = False
lang = "English"

if llm.available():
    c1, c2 = st.columns([1.5, 1])
    with c1:
        use_ai = st.toggle("Add AI second opinion", value=True)
    with c2:
        if use_ai:
            selected_lang = st.selectbox(
                "Summary Language",
                [
                    "English", "Hindi", "Hinglish", "Bengali", "Tamil", 
                    "Telugu", "Marathi", "Gujarati", "Kannada", "Malayalam", 
                    "Spanish", "French", "German", "Other (Type custom)"
                ],
                label_visibility="collapsed"
            )
            if selected_lang == "Other (Type custom)":
                lang = st.text_input("Custom Language", value="Punjabi", label_visibility="collapsed")
            else:
                lang = selected_lang
else:
    st.caption("AI second opinion is off (no API key found). Rule-based checks are still active.")

go = st.button("Check message", type="primary", use_container_width=True)

# ---------- analysis ----------
if go:
    if not text.strip() and not screenshot:
        st.warning("Paste a message or upload a screenshot first.")
        st.stop()

    st.session_state.messages = []

    image_b64 = None
    if screenshot:
        image_b64 = base64.b64encode(screenshot.getvalue()).decode("utf-8")

    score, flags, urls = rules.analyze(text) if text.strip() else (0, [], [])
    
    if text.strip():
        label, advice = rules.verdict(score)
        color = "#2e9e5b" if score < 30 else ("#e0a100" if score < 60 else "#d64545")

        st.markdown(f"<div class='verdict' style='color:{color}'>{label} · {score}/100</div>",
                    unsafe_allow_html=True)
        st.markdown(
            f"<div class='meter-wrap'><div class='meter-fill' style='width:{max(score,3)}%;background:{color}'></div></div>",
            unsafe_allow_html=True,
        )
        st.write(advice)

        if flags:
            st.subheader("Why (Rule Engine)")
            for f in flags:
                c = "#d64545" if f["points"] >= 20 else ("#e0a100" if f["points"] > 0 else "#7a8a99")
                st.markdown(
                    f"<div class='flag' style='border-color:{c}'><b>{f['title']}</b>"
                    f"<span class='small'>{f['detail']}</span></div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("No rule-based red flags found.")

        if urls:
            with st.expander(f"Links found ({len(urls)})"):
                for u in urls:
                    st.code(u, language=None)

    # AI second opinion
    if use_ai:
        with st.spinner(f"Getting AI second opinion in {lang}..."):
            summary = "; ".join(f["title"] for f in flags) if flags else ""
            ai = llm.analyze_with_llm(text, summary, image_b64, lang)

        st.subheader("AI second opinion")
        if "error" in ai:
            st.info("AI check unavailable right now. The rule-based result above still applies.")
            st.caption(ai["error"][:200])
        else:
            st.write(f"**Verdict:** {ai.get('verdict')} ({ai.get('confidence')}% confident)")
            st.write(f"**Type:** {ai.get('scam_type')}")
            if ai.get("red_flags"):
                st.write("**Red flags**")
                for r in ai["red_flags"]:
                    st.write(f"- {r}")
            if ai.get("what_to_do"):
                st.write("**What to do**")
                for r in ai["what_to_do"]:
                    st.write(f"- {r}")
            
            summary_text = ai.get("summary") or ai.get("summary_hindi")
            if summary_text:
                st.info(f"**Summary ({lang}):**\n\n{summary_text}")

            context_prompt = (
                f"The user scanned a message. Scanned Text: '{text}'. "
                f"Rule Engine Score: {score}/100. "
                f"AI Verdict: {ai.get('verdict')}, Scam Type: {ai.get('scam_type')}. "
                f"Red Flags: {', '.join(ai.get('red_flags', []))}. "
                f"Recommended Actions: {', '.join(ai.get('what_to_do', []))}."
            )
            st.session_state.messages.append({"role": "system", "content": context_prompt})

# ---------- Follow-Up Chat Interface ----------
if st.session_state.messages:
    st.divider()
    st.subheader("💬 Ask Follow-Up Questions")
    st.caption("Ask anything about this message (e.g., 'What should I do if I already clicked the link?')")

    for msg in st.session_state.messages:
        if msg["role"] in ["user", "assistant"]:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])

    if user_question := st.chat_input("Type your question here..."):
        with st.chat_message("user"):
            st.write(user_question)
        
        st.session_state.messages.append({"role": "user", "content": user_question})

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                reply = llm.chat_followup(st.session_state.messages, lang)
                st.write(reply)
        
        st.session_state.messages.append({"role": "assistant", "content": reply})

st.divider()
st.caption("ScamCheck gives guidance, not a guarantee. When in doubt, verify with the official source.")