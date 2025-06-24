# 📧 Phishing Email Analyzer

A Streamlit-based tool to detect and analyze phishing emails from `.eml` files. Uses custom scoring logic, VirusTotal API, and email header analysis.

## 🔍 Features
- Detect phishing keywords, spoofed domains, spam headers
- VirusTotal API support for attachments
- Normalized phishing score (0–100%)
- Simple drag & drop UI with Streamlit

## 🛠 How to Run

1. Install dependencies:
pip install -r requirements.txt

2. Set your VirusTotal API key in a `.env` file:
VT_API_KEY=your_api_key_here

3. Run the tool:
streamlit run phishing_email_analyzer.py

## 📁 Upload `.eml` files to test
- Export sample emails from Gmail or Outlook
