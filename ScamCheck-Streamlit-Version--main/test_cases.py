"""
test_cases.py - score many messages at once.

Run:  python test_cases.py

HOW TO USE
1. Add messages to the TESTS list below.
2. Each test is ("scam" or "safe", "the message text").
3. Run the script. Lines marked WRONG are the ones to fix in rules.py.
"""
import rules

# "scam" should score 30 or more. "safe" should score under 30.
TESTS = [
    # ---- scams (replace/add real ones from your WhatsApp) ----
    ("scam", "Congratulations! You are selected for work from home job. Earn Rs 3000 per day. Pay Rs 500 registration fee. Join: https://bit.ly/3abcXyz"),
    ("scam", "Dear customer your SBI account will be blocked today. Update KYC at http://sbi-update.top/kyc and share OTP"),
    ("scam", "Like and subscribe to YouTube videos and earn Rs 200 per task. Join our Telegram group now"),
    ("scam", "Free laptop scholarship for students! Click link and apply within 24 hours: http://free-laptop-scheme.xyz"),
    ("scam", "You have won a lucky draw prize of Rs 25 lakh. Pay processing fee to claim."),
    ("scam", "Dear Student, You are selected for NSP National Scholarship Rs. 50,000. Complete verification in 2 hours: https://nsp-scholarship-portal.in Apply fee Rs 299 onlyUGC Alert: Your scholarship will lapse. Update your bank details for DBT payment: https://ugc-scholarship-verify.com"),
    ("scam", "Congratulations! Selected for Amazon / Google Virtual Internship. Stipend Rs. 15,000/month. Pay Rs 499 as offer letter fee on this link to confirm. - HR TeamEarn Rs 2000 daily by simple data entry. Best for students. No investment. Join Telegram: t.me/earn4students"),
    ("scam", "AKTU / CCSU Notice: Your exam form is incomplete. Pay late fee Rs 1200 before 9 PM today else admit card will not be issued: https://aktu-form-update.xyzYour college fees payment failed. Your admission will be cancelled. Pay immediately here: bit.ly/fee-pay-urgent"),
    ("scam", "TCS / Infosys off-campus drive for 2026 batch. Package 8 LPA. Register with Rs 999. Last date today! Link: https://tcs-campus-hiring.net"),
    ("scam", "Free Laptop Yojana 2026: UP Govt is giving free laptops to all students. Register with Aadhar here: https://upfreelaptop-yojana.com"),
    ("safe", "Get all AKTU PYQs + solved notes for Rs 99 only. 5000+ stude..."),
    ("scam", "Your Instagram account has copyright violation. Verify as student creator within 12 hours: https://instagram-verify-blue.com Else account will be deleted."),

    # ---- genuine messages (replace/add real ones) ----
    ("safe", "Your OTP for HDFC Bank login is 482913. Do not share it with anyone. - HDFC Bank"),
    ("safe", "Reminder: Internal exam tomorrow at 10 AM in CB-105. Please bring your ID card."),
    ("safe", "Hey are we meeting at the library at 4?"),
    ("safe", "Registration for the coding contest closes today at 5 PM. Register here: https://forms.gle/abc123"),
    ("safe", "Hackathon on 28 September, 8 AM to 8 PM. Register: https://forms.gle/jVcrS2nNFCtZfvSt8?utm_source=chatgpt.com"),
    ("safe", "Your Amazon order has been shipped and will arrive tomorrow. Track: https://www.amazon.in/orders"),
    ("safe", "*Dear Students,* This is to inform All BCA 2nd and 3rd year students have been allotted to respective Internship In-charges for internship-related activities. The list of students along with their respective Internship In-charges is being shared for your refrence. Kindly check the list carefully and identify your allotted Internship In-charge. For any internship-related work, discussion, or guidance, you are required to meet/contact your allotted Internship In-charge only between 04:00 PM and 05:00 PM. All students are requested to follow the allotted faculty coordination strictly and cooperate in ensuring the smooth completion of the internship-related activities."),
    ("safe", "Dear Students, The One-Word Question Bank for Unit 1 and Unit 2 has been uploaded on your ERP. Please check your ERP and go through the questions for your preparation."),
    ("safe", "MY Bharat Quiz – Weekend Reminder The weekend quiz is now available on the MY Bharat Portal. 🕙 Join the quiz and contribute to your State’s progress on the MY Bharat State-wise Quiz Leaderboard. Regards, Team MY Bharat"),
    
]


def main():
    wrong = 0
    print(f"{'EXPECT':<7}{'SCORE':<7}{'RESULT':<8}MESSAGE")
    print("-" * 90)
    for expected, msg in TESTS:
        score, flags, _ = rules.analyze(msg)
        flagged = score >= 30
        ok = flagged if expected == "scam" else not flagged
        status = "ok" if ok else "WRONG"
        if not ok:
            wrong += 1
        print(f"{expected:<7}{score:<7}{status:<8}{msg[:60]!r}")
        if not ok:
            for f in flags:
                print(f"{'':>22}-> +{f['points']} {f['title']}")
    print("-" * 90)
    print(f"{len(TESTS) - wrong}/{len(TESTS)} correct")


if __name__ == "__main__":
    main()
