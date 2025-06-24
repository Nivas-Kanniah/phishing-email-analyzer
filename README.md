# 📧 Phishing Email Analyzer

A **Streamlit-based** tool to detect and deeply analyze phishing emails from `.eml` files.  
Uses custom scoring logic, **VirusTotal API**, and advanced email header inspection.

---

## 🔍 Features

- 🧠 Detect phishing keywords, spoofed domains, suspicious links, and spam headers  
- 🛡️ VirusTotal API support for scanning attachments  
- 📊 Normalized phishing risk score (0–100%) with a visual indicator  
- 💬 Human-readable reasons behind each detection  
- 🧾 Optional PDF export of analysis results  
- 🌗 Dark/Light theme toggle  
- 🖱️ Simple drag & drop UI powered by Streamlit  
- 📁 **Works best with `.eml` files** containing plain text or HTML bodies  
- ✅ **Designed as a strong first-level phishing detection tool** — always manually verify borderline results

---

## 🚀 How to Run Locally

**1. 📦 Install dependencies:**  
`pip install -r requirements.txt`

**2. 🔐 Set your VirusTotal API key in a `.env` file:**  
`VT_API_KEY=your_api_key_here`  
*(Get your key here: https://www.virustotal.com/gui/user/apikey)*

**3. ▶️ Run the tool:**  
`streamlit run phishing_email_analyzer.py`

---

## 📁 Upload `.eml` Files to Test

- Export emails from **Gmail** or **Outlook**
- Drag & drop them into the web app to analyze

---

## 🌐 Live Demo

Try it online (no install needed):  
🔗 [https://phishing-email-analyzer-python.streamlit.app](https://phishing-email-analyzer-python.streamlit.app)

---

## 🤝 Contributions

- Pull requests, issues, and feedback are welcome  
- Star ⭐ the project if it helped you!  
- Want to improve detection logic or UI? Fork and send a PR!

---

## 📜 License

This project is licensed under the **MIT License**.  
Feel free to use, modify, and share responsibly.
