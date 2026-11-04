SentinelShield – Web Security Monitoring System

About

SentinelShield is a Python Flask-based educational web security monitoring project. It inspects HTTP requests, detects suspicious patterns, tracks excessive requests and generates security alerts.

Features

- HTTP request inspection
- Suspicious pattern detection
- Severity classification (Low, Medium, High)
- IP-based time-window rate limiting
- Security event logging
- Automatic alert generation
- Security dashboard
- Security activity chart

Technologies

- Python
- Flask
- HTML
- CSS
- JavaScript
- Chart.js
- JSONL

Installation

Install Flask:

pip install -r requirements.txt

Run the application:

python app.py

Open your browser:

http://127.0.0.1:5000

Learning Outcomes

This project helped me learn about HTTP requests, basic web security monitoring, pattern matching, severity levels, rate limiting, logging and dashboard development.

Limitations

SentinelShield is an educational prototype. Its detection rules are basic and may produce false positives or miss suspicious requests. It is not a production-ready Web Application Firewall.