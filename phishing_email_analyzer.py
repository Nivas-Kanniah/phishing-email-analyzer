import streamlit as st
import email
import re
import base64
import os
import requests
import unicodedata
from fpdf import FPDF
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv

# Load VirusTotal API key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Set Streamlit page config
st.set_page_config(page_title="Phishing Email Analyzer", layout="centered")

# 🔲 Theme toggle
theme = st.sidebar.radio("🌗 Theme", ["Light", "Dark"])
if theme == "Dark":
    st.markdown("""
        <style>
        body { background-color: #111; color: white; }
        .stApp { background-color: #111; }
        </style>
    """, unsafe_allow_html=True)

# 🚩 Keywords often found in phishing
PHISHING_KEYWORDS = [
    "urgent", "verify", "account", "suspend", "limited", "unauthorized",
    "security alert", "click here", "confirm", "password", "login", "update"
]

# 🧽 Sanitize text for PDF
def sanitize_text(text):
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

# 🧾 PDF export
def generate_pdf_report(from_addr, subject, score, reasons, verdict):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Phishing Email Analysis Report", ln=True, align="C")
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"From: {sanitize_text(from_addr)}", ln=True)
    pdf.cell(200, 10, txt=f"Subject: {sanitize_text(subject)}", ln=True)
    pdf.cell(200, 10, txt=f"Score: {score}%", ln=True)
    pdf.cell(200, 10, txt=f"Verdict: {sanitize_text(verdict)}", ln=True)

    pdf.ln(10)
    clean_reasons = [sanitize_text(r) for r in reasons]
    pdf.multi_cell(0, 10, txt="Reasons:\n" + "\n".join(clean_reasons))

    pdf.output("report.pdf")

    with open("report.pdf", "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="report.pdf">📄 Download Analysis PDF</a>'
        st.markdown(href, unsafe_allow_html=True)

# 🧠 Scoring function
def analyze_email(headers, body):
    score = 0
    reasons = []

    # Check for suspicious headers
    if headers.get("Return-Path") and headers.get("From"):
        if headers.get("Return-Path") != headers.get("From"):
            score += 3
            reasons.append("🔴 Sender mismatch: Return-Path and From header differ")

    # Keyword checks in subject or body
    text_to_check = f"{headers.get('Subject', '')} {body}".lower()
    for word in PHISHING_KEYWORDS:
        if word in text_to_check:
            score += 1
            reasons.append(f"⚠️ Found keyword: '{word}'")

    # VirusTotal scanning score
    if VT_API_KEY:
        attachments = [part for part in headers.walk() if part.get_content_disposition() == 'attachment']
        for att in attachments:
            content = att.get_payload(decode=True)
            r = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers={'x-apikey': VT_API_KEY},
                files={'file': (att.get_filename(), content)}
            )
            if r.status_code == 200:
                result = r.json()
                score += 3
                reasons.append("🦠 VirusTotal: File flagged as suspicious")
            break  # limit to 1 attachment

    return min(score, 15), reasons

# 📬 Email parser
def parse_email(uploaded_file):
    msg = BytesParser(policy=policy.default).parse(uploaded_file)
    headers = msg
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    return headers, body

# 🚀 Main UI
st.title("📧 Phishing Email Detection & Deep Analysis Tool")
uploaded_file = st.file_uploader("Upload an .eml file to analyze", type=["eml"])

if uploaded_file:
    headers, body = parse_email(uploaded_file)
    score, reasons = analyze_email(headers, body)
    risk_percent = min(int((score / 15) * 100), 100)

    st.subheader("📊 Analysis Result")
    if risk_percent >= 70:
        st.error(f"❌ High Risk: Likely a phishing email")
        verdict = "High Risk"
    elif risk_percent >= 40:
        st.warning("⚠️ Medium Risk: Suspicious elements found")
        verdict = "Medium Risk"
    else:
        st.success("✅ Low Risk: Looks safe (but always verify manually)")
        verdict = "Low Risk"

    st.markdown(f"**🧠 Risk Score: {risk_percent}%**")
    st.progress(risk_percent)

    st.subheader("🛡️ Reasons Detected")
    for r in reasons:
        st.markdown(r)

    st.subheader("📬 Email Details")
    st.text_area("From", headers.get("From", "N/A"), height=70)
    st.text_area("Subject", headers.get("Subject", "N/A"), height=70)
    st.text_area("Email Body (Plain Text)", body, height=200)

    # Generate PDF Report
    generate_pdf_report(
        from_addr=headers.get("From", "N/A"),
        subject=headers.get("Subject", "N/A"),
        score=risk_percent,
        reasons=reasons,
        verdict=verdict
    )
