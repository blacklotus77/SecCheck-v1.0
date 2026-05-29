SecCheck v1.0
Web Security Scanner - Check SSL certificates, HTTP security headers, and generate PDF reports.

SecCheck is a Flask web app that scans any website for basic security issues. Built for clients who need quick security audits without complex tools.

FEATURES:
- SSL Certificate Check: Expiry date, issuer, validity status
- Security Headers Scan: Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- PDF Report Export: Download scan results as professional PDF
- Clean Web UI: Simple input to instant results

TECH-STACK:
- Backend: Python, Flask
- SSL Check: Python ssl + socket modules
- Headers: Python requests library
- PDF: ReportLab
- Frontend: HTML5, CSS3, Jinja2 templates

INSTALLATION AND RUN LOCALLY:
1. Clone repo: git clone https://github.com/blacklotus77/SecCheck.git
2. Go to folder: cd SecCheck
3. Install dependencies: pip install -r http://requirements.txt
4. Run app: python http://app.py
5. Open http://127.0.0.1:5000 in browser

http://REQUIREMENTS.TXT:
Flask==3.0.0
requests==2.31.0
reportlab==4.0.7
cryptography==41.0.7

HOW IT WORKS:
1. User enters target URL
2. App connects via SSL and grabs certificate details
3. App fetches HTTP headers and checks for security best practices
4. Results displayed plus option to download PDF report

AUTHOR:
blacklotus77
First cybersecurity project - feedback welcome

LICENSE:
MIT License - free to use and modify

NOTE FOR CLIENTS:
This v1.0 checks SSL plus headers only. Port scanning removed for safe public deployment.
