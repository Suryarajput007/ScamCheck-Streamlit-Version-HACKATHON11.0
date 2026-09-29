"""
llm.py - optional AI second opinion with Vision, Dynamic Language, Strict JSON, & Follow-up Chat support.
"""
import json
import os
import urllib.error
import urllib.request

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "qwen/qwen3.8-27b"

XAI_URL = "https://api.x.ai/v1/chat/completions"
DEFAULT_XAI_MODEL = "grok-4.3"


def build_system_prompt(lang: str = "English") -> str:
    return f"""You are a scam-detection assistant for students.
Analyse the message or screenshot provided. Reply with ONLY a JSON object, no markdown fences:
{{
  "verdict": "scam" | "suspicious" | "likely_safe",
  "confidence": <integer 0-100>,
  "scam_type": "<short label, e.g. fake internship, KYC phishing, task scam, lottery, or none>",
  "red_flags": ["<short reason>", ...],
  "what_to_do": ["<short action>", ...],
  "summary": "<2 short sentences explaining the analysis and verdict. Translate this summary into {lang}>"
}}
Be concise. Do not invent facts about the sender. If unsure, say suspicious."""


def provider():
    if os.environ.get("GROQ_API_KEY", "").strip():
        return "groq"
    if os.environ.get("XAI_API_KEY", "").strip():
        return "xai"
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "anthropic"
    return None


def available() -> bool:
    return provider() is not None


def _parse_json(raw: str):
    raw = raw.replace("```json", "").replace("```", "").strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end != -1:
        raw = raw[start:end + 1]
    return json.loads(raw)


def _call_openai_compatible(url: str, key: str, model: str, user_text: str, image_b64: str = None, lang: str = "English"):
    if image_b64:
        user_content = [
            {"type": "text", "text": user_text or "Please analyze this uploaded screenshot for scam indicators."},
            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}}
        ]
    else:
        user_content = user_text

    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": build_system_prompt(lang)},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"}
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamCheck/1.0",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _call_groq(user_text: str, image_b64: str = None, lang: str = "English"):
    key = os.environ["GROQ_API_KEY"].strip()
    model = os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL).strip()
    return _call_openai_compatible(GROQ_URL, key, model, user_text, image_b64, lang)


def _call_xai(user_text: str, image_b64: str = None, lang: str = "English"):
    key = os.environ["XAI_API_KEY"].strip()
    model = os.environ.get("XAI_MODEL", DEFAULT_XAI_MODEL).strip()
    return _call_openai_compatible(XAI_URL, key, model, user_text, image_b64, lang)


def _call_anthropic(user_text: str, image_b64: str = None, lang: str = "English"):
    import anthropic
    client = anthropic.Anthropic()
    content = []
    if image_b64:
        content.append({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}
        })
    content.append({"type": "text", "text": user_text or "Analyze this image for scam indicators."})
    
    resp = client.messages.create(
        model="claude-3-5-sonnet-20240620", max_tokens=700, system=build_system_prompt(lang),
        messages=[{"role": "user", "content": content}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")


_CALLERS = {"groq": _call_groq, "xai": _call_xai, "anthropic": _call_anthropic}


def analyze_with_llm(text: str, rule_summary: str = "", image_b64: str = None, lang: str = "English"):
    user = f'Message to analyse:\n"""\n{text}\n"""' if text else ""
    if rule_summary:
        user += f"\n\nAutomatic checks already found: {rule_summary}"
    p = provider()
    if p is None:
        return {"error": "No API key set."}
    try:
        raw = _CALLERS[p](user, image_b64, lang)
        return _parse_json(raw)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")[:200]
        return {"error": f"HTTP {e.code}: {detail}"}
    except Exception as e:
        return {"error": str(e)}


def chat_followup(messages: list, lang: str = "English") -> str:
    """Handles follow-up chat turns using the conversation history."""
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        return "AI chat is currently unavailable (No API key found)."

    model = os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL).strip()

    sys_instruction = {
        "role": "system",
        "content": f"You are a helpful cyber-safety advisor assisting a student. Respond concisely in {lang}. Give practical advice."
    }
    full_thread = [sys_instruction] + messages

    body = json.dumps({
        "model": model,
        "messages": full_thread,
        "temperature": 0.5,
    }).encode("utf-8")

    req = urllib.request.Request(
        GROQ_URL, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamCheck/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Could not get response: {str(e)}"