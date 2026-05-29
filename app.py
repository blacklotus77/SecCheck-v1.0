from flask import Flask, render_template, request, send_file
import socket
import ssl
from datetime import datetime
import requests
from fpdf import FPDF
import tempfile
import re 

app = Flask(__name__)

COMMON_PORTS =[21, 22, 25, 80, 443, 8080, 3360]

def scan_ports(domain):
    open_ports = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.utcnow()).days
                return days_left
    except:
        return "Error - No SSL or site unreachable"


def check_http_security(domain):
    headers_to_check = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]

    headers = {}
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        for header in headers_to_check:
            headers[header] = response.headers.get(header, 'Missing')
    except:
        for header in headers_to_check:
            headers[header] = 'Error - Site unreachable'[header]

    return headers


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        if domain.startswith('http'):
            domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        ports = scan_ports(domain)
        ssl_days = check_ssl_expiry(domain)
        headers = check_http_security(domain)

        return render_template('results.html',
                             domain=domain,
                             ports=ports,
                             ssl_days=ssl_days,
                             headers=headers)
    return render_template('index.html')

@app.route('/check', methods=['GET', 'POST'])
def check():
    return index()

@app.route('/download_pdf')
def download_pdf():
    domain = request.args.get('domain')
    ports = scan_ports(domain)
    ssl_days = check_ssl_expiry(domain)
    headers = check_http_security(domain)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SecCheck Security Report", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Domain: {domain}", ln=True)
    pdf.cell(200, 10, txt=f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt=f"SSL Certificate: {ssl_days} days remaining", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Open Ports:", ln=True)
    pdf.set_font("Arial", size=12)
    if ports:
        for p in ports:
            pdf.cell(200, 10, txt=f" Port {p} - OPEN", ln=True)
    else:
        pdf.cell(200, 10, txt=" No common ports open", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Security Headers:", ln=True)
    pdf.set_font("Arial", size=12)
    for h, status in headers.items():
        pdf.cell(200, 10, txt=f" {h}: {status}", ln=True)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp.name)
    return send_file(tmp.name, as_attachment=True, download_name=f'SecCheck_{domain}.pdf')

if __name__ == '__main__':
    app.run(debug=True)
