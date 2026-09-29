"""
rules.py - rule-based scam checks. Works offline, no API key needed.

Each check returns a list of "flags". A flag is a dict:
    {"points": int, "title": str, "detail": str}
The final score is the sum of points, capped at 100.
"""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s)\]>]+|www\.[^\s)\]>]+)", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly",
}
RISKY_TLDS = {".xyz", ".top", ".click", ".shop", ".site", ".online", ".vip", ".icu", ".buzz", ".live"}
BRANDS = ["google", "amazon", "paytm", "phonepe", "sbi", "hdfc", "icici",
          "flipkart", "naukri", "linkedin", "whatsapp", "irctc", "aadhaar", "epfo",
          "instagram", "facebook", "aktu", "ccsu", "infosys", "wipro"]

# (regex, points, title, detail)
TEXT_RULES = [
    (r"registration fee|processing fee|security deposit|refundable deposit|pay (rs|₹|inr)|training fee|kit fee",
     30, "Asks you to pay money",
     "Real internships and jobs do not charge candidates. Any 'fee' to get selected is a classic scam."),
    (r"(share|send|give|tell|forward|enter|reply|provide).{0,30}(otp|cvv|pin\b|password)|(otp|cvv).{0,20}(to us|to me|here)|card number|net ?banking password",
     35, "Asks for OTP / card / PIN",
     "No genuine organisation asks for your OTP, PIN or CVV over chat."),
    (r"urgent|immediately|last chance|hurry|expires? (today|soon|in)|only \d+ (seats|slots)|limited seats|act now|within 24 hours?",
     15, "Creates false urgency",
     "Scammers rush you so you don't have time to verify."),
    (r"you (have )?(won|been selected|are selected)|congratulations|lucky (draw|winner)|prize|lottery|cashback",
     20, "'You won / you're selected' bait",
     "Unexpected winnings or selections without any application are a red flag."),
    (r"work from home|earn (up to |upto )?(rs|₹)?\s?\d[\d,]*\s?(per|/)\s?(day|week|hour|task|video|like)|part[- ]time.*(earn|income)|no experience (needed|required)",
     20, "Too-good-to-be-true earning offer",
     "High pay for easy work with no experience is a common task-scam pattern."),
    (r"like (and )?subscribe|complete (simple )?tasks?|rate (products|hotels)|telegram",
     20, "Task / Telegram scam pattern",
     "Fake 'task jobs' usually move you to Telegram and ask for deposits later."),
    (r"kyc|account (will be )?(blocked|suspended|closed)|verify your (account|details)|update (your )?(pan|aadhaar|kyc)",
     25, "Fake KYC / account-blocked threat",
     "Banks and wallets don't threaten to block accounts through chat links."),
    (r"forward (this )?to (\d+|10|5|all)|share (this )?with (\d+|10|5|all)|send to \d+ (friends|groups|contacts)",
     10, "Chain-forward request",
     "Messages that beg you to forward them widely are usually hoaxes."),
    (r"scholarship.*(apply|link|click)|free (laptop|ipad|iphone|recharge|data)",
     15, "Free-gift / scholarship bait",
     "Check the official government or university portal directly, not a forwarded link."),
    (r"whatsapp (me|number)|contact (us )?on whatsapp|dm (me|us) (for|to)",
     8, "Pushes conversation to private chat",
     "Legitimate recruiters use official emails or portals."),
    (r"pay\s+(the\s+|a\s+)?(late\s+|exam\s+|form\s+|processing\s+|registration\s+)?(fee|fine|penalty)|fine of (rs|₹)",
     20, "Asks you to pay a fee or fine",
     "Check fees only on the official college portal, never through a link in a message."),
    (r"yojana|govt\.?\s+(is\s+)?(giving|distributing|providing)|government\s+(is\s+)?(giving|distributing|providing)",
     15, "Claims to be a government scheme",
     "Real schemes are announced on official .gov.in sites. Verify there before applying."),
    (r"copyright (violation|infringement|claim|strike)|(account|page|profile).{0,30}(disabled|restricted|suspended|hacked|deleted|violat)|appeal (form|now)",
     25, "Fake account-violation threat",
     "Social media platforms don't ask you to verify through links sent in DMs or messages."),
    (r"\d+(\.\d+)?\s?lpa|package (of )?(rs\.?|₹)?\s?\d|off[- ]campus (drive|hiring)|direct (joining|selection)|no interview",
     15, "Attractive job offer with big package",
     "Check the company's official careers page. Real companies don't recruit through random links."),
]


def extract_urls(text: str):
    return URL_RE.findall(text)


def _host(url: str) -> str:
    if not url.lower().startswith("http"):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def check_url(url: str):
    flags = []
    host = _host(url)
    if not host:
        return flags
    parsed = urlparse(url if url.lower().startswith("http") else "http://" + url)

    if host in SHORTENERS:
        flags.append({"points": 20, "title": "Shortened link",
                      "detail": f"{host} hides the real destination. Expand it before opening."})
    if any(host.endswith(t) for t in RISKY_TLDS):
        flags.append({"points": 15, "title": "Unusual domain ending",
                      "detail": f"{host} uses an ending often seen in throwaway scam sites."})
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append({"points": 25, "title": "Link uses a raw IP address",
                      "detail": "Real organisations use proper domain names."})
    if host.count("-") >= 2:
        flags.append({"points": 10, "title": "Many hyphens in domain",
                      "detail": f"{host} looks like a lookalike domain."})
    if parsed.scheme == "http":
        flags.append({"points": 8, "title": "Link is not HTTPS",
                      "detail": "Never enter personal details on a non-HTTPS page."})
    if "xn--" in host:
        flags.append({"points": 25, "title": "Lookalike (punycode) domain",
                      "detail": "This domain may use lookalike characters to imitate a real site."})

    # brand name in a domain that is not the brand's own
    for b in BRANDS:
        if b in host and not re.search(rf"(^|\.){b}\.(com|in|co\.in|org|gov\.in|net|ac\.in|edu\.in|nic\.in)$", host):
            flags.append({"points": 25, "title": f"Imitates '{b}'",
                          "detail": f"{host} contains '{b}' but is not the official domain."})
            break

    if "utm_source=chatgpt" in url.lower():
        flags.append({"points": 0, "title": "Link copied from a ChatGPT answer",
                      "detail": "Harmless tracking tag, but confirm the link with the organiser."})
    return flags


def analyze(text: str):
    """Return (score 0-100, flags, urls)."""
    flags = []
    lowered = text.lower()
    # A warning like "never share your OTP" is safety advice, not a scam ask.
    lowered = re.sub(r"(do not|don't|dont|never|not to)\s+(share|give|tell|send|reveal)[^.\n]{0,40}", " ", lowered)

    for pattern, points, title, detail in TEXT_RULES:
        if re.search(pattern, lowered):
            flags.append({"points": points, "title": title, "detail": detail})

    urls = extract_urls(text)
    for u in urls:
        flags.extend(check_url(u))

    # any link + any pressure/money flag is worse than either alone
    if urls and any(f["points"] >= 15 for f in flags):
        flags.append({"points": 10, "title": "Link combined with pressure or money ask",
                      "detail": "A link plus urgency or a payment request is the typical scam recipe."})

    score = min(100, sum(f["points"] for f in flags))
    flags.sort(key=lambda f: f["points"], reverse=True)
    return score, flags, urls


def verdict(score: int):
    if score >= 60:
        return "High risk", "Do not click, pay, or share anything. Block and report."
    if score >= 30:
        return "Suspicious", "Verify through an official website or a person you know before acting."
    if score >= 10:
        return "Some warning signs", "Probably fine, but double-check the sender and the link."
    return "No obvious red flags", "Still verify links with the sender before entering personal data."
