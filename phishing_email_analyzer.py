import streamlit as st
import os
import email
import re
import hashlib
import tempfile
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse
import tldextract

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

PHISHING_KEYWORDS = [
    "verify", "reset", "update", "login", "security alert", "account suspended",
    "confirm", "urgent", "password", "click", "bank", "invoice", "payment",
    "limited access", "locked", "unauthorized", "violation", "alert",
    "final notice", "secure your account", "recover access", "credentials",
    "dangerous", "warning", "verify your info", "your account", "deactivate"
]

SUSPICIOUS_DOMAINS = [
    r"bit\.ly", r"tinyurl\.com", r"g00gle", r"paypa1", r"micros0ft",
    r"update-info.*", r"cloud-secure.*", r"secure-mail.*", r"fast-login.*",
    r"banksecure.*", r"auth-center.*", r"account-update.*"
]

TRIGGER_HEADERS = ["X-Priority", "X-MSMail-Priority", "Precedence", "List-Unsubscribe"]

st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")
st.title("📧 Phishing Email Detection & Deep Analysis Tool")

uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    with open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = email.message_from_file(f)

    headers = dict(msg.items())
    body = ""
    attachments = []
    links = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not part.get_filename():
                body += part.get_payload(decode=True).decode(errors='ignore')
            elif part.get_filename():
                attachments.append(part)
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    links = re.findall(r'https?://[\w./\-]+', body)

    phishing_score = 0
    reasons = []

    # Keyword scan
    hits = [kw for kw in PHISHING_KEYWORDS if kw in body.lower()]
    if hits:
        reasons.append(f"🔴 Keywords matched: {', '.join(hits[:5])}")
        phishing_score += len(hits) * 3

    # Suspicious domains and shorteners
    for link in links:
        domain = tldextract.extract(link).domain.lower()
        for pattern in SUSPICIOUS_DOMAINS:
            if re.search(pattern, link.lower()):
                reasons.append(f"🔴 Suspicious link: {link}")
                phishing_score += 4
        if domain in ["bit", "tinyurl"] or domain.isnumeric() or any(c.isdigit() for c in domain):
            reasons.append(f"⚠️ Shortened or fake domain used: {domain}")
            phishing_score += 3

    # Sender mismatch
    if "Return-Path" in headers and "From" in headers:
        if headers["Return-Path"].strip().lower() != headers["From"].strip().lower():
            reasons.append("🔴 Header mismatch: Return-Path != From")
            phishing_score += 3

    # Spam headers
    for h in TRIGGER_HEADERS:
        if h in headers:
            reasons.append(f"⚠️ Suspicious header: {h}")
            phishing_score += 2

    # SPF/DKIM failure
    auth_results = headers.get("Authentication-Results", "").lower()
    if any(x in auth_results for x in ["spf=fail", "spf=none", "dkim=fail", "dkim=none"]):
        reasons.append("🔴 SPF/DKIM authentication failed or missing")
        phishing_score += 4

    # VirusTotal attachment scan
    if VT_API_KEY and attachments:
        for attachment in attachments:
            filename = attachment.get_filename()
            payload = attachment.get_payload(decode=True)
            file_hash = hashlib.sha256(payload).hexdigest()
            try:
                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": VT_API_KEY}
                )
                if vt_response.status_code == 200:
                    data = vt_response.json()
                    mal_count = data['data']['attributes']['last_analysis_stats']['malicious']
                    if mal_count > 0:
                        reasons.append(f"🔴 Attachment {filename} flagged by VirusTotal")
                        phishing_score += 5
            except:
                st.warning(f"⚠️ VirusTotal lookup failed for {filename}")

    # Risk label
    st.subheader("📊 Final Analysis")
    if phishing_score >= 7:
        st.error("🚨 HIGH RISK: Likely phishing!")
    elif phishing_score >= 4:
        st.warning("⚠️ MEDIUM RISK: Suspicious elements found")
    else:
        st.success("✅ LOW RISK: No major signs, but always be cautious")

    st.markdown("---")
    st.subheader("🛡️ Indicators Found")
    if reasons:
        for r in reasons:
            st.markdown(f"- {r}")
    else:
        st.markdown("- No major phishing indicators found.")

    st.subheader("📬 Email Metadata")
    st.text_area("From", headers.get("From", "N/A"), height=70)
    st.text_area("Subject", headers.get("Subject", "N/A"), height=70)
    st.text_area("Body Preview", body[:1000] + ("..." if len(body) > 1000 else ""), height=300)

    if links:
        st.subheader("🔗 Links Extracted")
        for link in links:
            st.markdown(f"- [{link}]({link})")

    if attachments:
        st.subheader("📎 Attachments")
        for att in attachments:
            st.markdown(f"- {att.get_filename()}")

    # Risk percent normalization and visual
    risk_percent = min(int((phishing_score / 15) * 100), 100)
    st.progress(risk_percent)

    if risk_percent >= 70:
        st.error(f"🚨 Normalized Risk Score: {risk_percent}%")
    elif risk_percent >= 30:
        st.warning(f"⚠️ Normalized Risk Score: {risk_percent}%")
    else:
        st.success(f"✅ Normalized Risk Score: {risk_percent}%")

    st.info(f"🧠 Final Score (raw): {phishing_score}")
