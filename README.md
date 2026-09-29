# 🛡️ ScamCheck

**ScamCheck** is an AI-powered, hybrid cyber-safety web application built to help students instantly detect scam messages, fraudulent internship offers, phishing links, fake university notices, and account threats across WhatsApp forwards, SMS, emails, and screenshots.

---

## ✨ Key Features

- **⚡ Hybrid Verification Engine:** Combines an ultra-fast offline rule engine (regex & domain pattern matching) with an LLM-powered second opinion.
- **👁️ Vision AI (Screenshot Analysis):** Upload screenshots of suspicious WhatsApp messages, posters, or payment receipts for visual OCR and fraud evaluation.
- **🌐 Multi-Language Support:** Automatically translates safety advice and analysis summaries into any chosen regional or global language (English, Hindi, Hinglish, Tamil, Telugu, Spanish, etc.).
- **💬 Interactive Follow-Up Chat:** Context-aware chat assistant allows users to ask immediate follow-up questions after an evaluation (e.g., *"What should I do if I already clicked the link?"*).
- **🚩 Rule-Based Scoring Engine:** Works completely offline to screen for urgency keywords, fee requests, fake scholarship schemes, raw IP links, and lookalike domains.
- **🛡️ Guaranteed JSON Structure:** Uses structured schema enforcement to ensure consistent data extraction without interface parsing errors.

---

## 🛠️ Tech Stack

- **Frontend / Framework:** [Streamlit](https://streamlit.io/)
- **LLM / Vision Provider:** [Groq API](https://groq.com/) (`qwen/qwen3.8-27b`)
- **Backend & Logic:** Python 3.10+, `urllib`, `base64`, `re`, `json`

---

## 📁 Repository Structure

```text
scamcheck/
├── app.py              # Streamlit UI, user input controls, and Chat state
├── llm.py              # Groq API integration, Vision encoding, & prompt templates
├── rules.py            # Offline regex rules & domain verification logic
├── requirements.txt    # Python package dependencies
├── .gitignore          # File exclusions (prevents API key exposure)
└── README.md           # Project documentation

## 👥 Team

ScamCheck was collaboratively developed by:

- **SURYA RAJPUT**
- **HIMANK SINGHAL**

Built together as a hackathon project. 🚀
