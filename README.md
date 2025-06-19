# ⚔️ ADVANCE XSS SCANNER

![XSS](https://img.shields.io/badge/XSS-Scanner-red?style=for-the-badge&logo=python)
![Python](https://img.shields.io/badge/Made%20With-Python-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-Research-green?style=for-the-badge&logo=hackthebox)

A powerful and intelligent **Cross-Site Scripting (XSS) vulnerability scanner** built in Python. Designed for ethical hackers, bug bounty hunters, and security researchers to automate and simplify the detection of XSS attack vectors in web applications.

---

## 🚀 Features

- ✅ Supports **Reflected**, **Stored**, and **DOM-Based** XSS detection
- ✅ **Crawling support** for deep scanning
- ✅ Easy-to-use CLI with verbose output
- ✅ Detailed scan reports and logging

---

## 📂 Project Structure

```bash
advance-xss-scanner/
├── scanner.py
├── crawler.py
├── payloads/
│   └── xss_payloads.txt
├── reports/
│   └── scan_report.html
├── README.md
└── requirements.txt

##Installation
git clone https://github.com/manja7304/ADVANCE-XSS-SCANNER.git
cd ADVANCE-XSS-SCANNER
python3 -m venv venv
source venv/bin/activate  # For Linux/macOS
# venv\Scripts\activate   # For Windows
pip install -r requirements.txt

##Usage
python scanner.py
