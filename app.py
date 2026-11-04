from flask import Flask, request, render_template_string
from datetime import datetime
import json
import os
import time

app = Flask(__name__)

LOG_FILE = "security_logs.jsonl"
REPORT_FILE = "security_report.jsonl"
ALERT_FILE = "security_alerts.jsonl"
REQUEST_LIMIT = 5
TIME_WINDOW = 10
request_times = {}

def save_log(data, status, matched_pattern, severity, decision):
    log_entry = {
        "time": str(datetime.now()),
        "method": data["method"],
        "path": data["path"],
        "ip": data["ip"],
        "user_agent": data["user_agent"],
        "query": data["query"],
        "status": status,
        "pattern": matched_pattern,
        "severity": severity,
        "decision": decision
    }

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        json.dump(log_entry, file)
        file.write("\n")


def inspect_request():
    data = {
        "method": request.method,
        "path": request.path,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "query": request.args.to_dict()
    }

    return data

def check_rate_limit(ip):
    now = time.time()
    if ip not in request_times:
        request_times[ip] = []
    request_times[ip] = [
        t for t in request_times[ip]
        if now - t < TIME_WINDOW
    ]
    request_times[ip].append(now)

    if len(request_times[ip]) > REQUEST_LIMIT:
        return True
    return False

def detect_suspicious(query):
    suspicious_patterns = {
        "select": "MEDIUM",
        "<script>": "HIGH",
        "../": "HIGH",
        "union": "HIGH",
        "admin": "MEDIUM"
    }

    severity_level = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3
    }

    query_lower = str(query).lower()

    highest_severity = "LOW"
    matched_pattern = None

    for pattern, severity in suspicious_patterns.items():

        if pattern.lower() in query_lower:

            if severity_level[severity] > severity_level[highest_severity]:
                highest_severity = severity
                matched_pattern = pattern

            elif matched_pattern is None:
                matched_pattern = pattern
                highest_severity = severity

    if matched_pattern is not None:
        return "SUSPICIOUS", matched_pattern, highest_severity

    return "NORMAL", None, "LOW"

    #         return "SUSPICIOUS",pattern, severity
    # return "NORMAL", None, "LOW"


def save_report(data, status, matched_pattern, severity, decision):

    report = {
        "time": str(datetime.now()),
        "method": data["method"],
        "path": data["path"],
        "ip": data["ip"],
        "user_agent": data["user_agent"],
        "query": data["query"],
        "status": status,
        "matched_pattern": matched_pattern,
        "severity": severity,
        "decision": decision
    }

    with open(REPORT_FILE, "a", encoding="utf-8") as file:
        json.dump(report, file)
        file.write("\n")

def generate_alert(data, matched_pattern, severity):
    if matched_pattern == "RATE_LIMIT_EXCEEDED":
        message = "Excessive requests detected from this ip"
        decision = "RATE_LIMITED"
    else:
        message = "Suspicious request detected"
        decision = "FLAGGED"

    alert = {
        "time": str(datetime.now()),
        "ip": data["ip"],
        "path": data["path"],
        "pattern": matched_pattern,
        "severity": severity,
        "decision": decision,
        "message": message
    }
    with open(ALERT_FILE,"a",encoding="utf-8")as file:
        json.dump(alert,file)
        file.write("\n")


@app.route("/")
def home():

    return """
    <html>
    <head>
        <title>SentinelShield</title>
    </head>

    <body>
        <h1>Welcome to SentinelShield</h1>

        <hr>

        <p>
            SentinelShield is a simple web security monitoring lab.
        </p>

        <p>
            It detects suspicious request patterns and records security events.
        </p>

        <hr>

        <p>
            <a href="/about">About</a>
        </p>

        <p>
            <a href="/dashboard">Security Dashboard</a>
        </p>

        <p>
            <a href="/logs">View Security Logs</a>
        </p>

        <p>
            Try the inspection page:
            <a href="/inspect?q=hello">Inspect Request</a>
        </p>

    </body>
    </html>
    """


@app.route("/about")
def about():

    return """
    <html>
    <head>
        <title>SentinelShield Lab</title>
    </head>

    <body>

        <h1>SentinelShield Security Lab</h1>

        <hr>

        <p>
            SentinelShield is a simple Flask-based security monitoring project.
        </p>

        <p>
            It detects suspicious request patterns and records security events.
        </p>

        <hr>

        <a href="/">Back to Home</a>

    </body>
    </html>
    """


@app.route("/search")
def search():

    query = request.args.get("q", "")

    return render_template_string("""
    <html>
    <body>

        <h1>Search</h1>

        <p>You searched for: {{query}}</p>

        <a href="/">Back to Home</a>

    </body>
    </html>
    """, query=query)


@app.route("/inspect")
def inspect():

    data = inspect_request()

    query = request.args.get("q", "")

    status, matched_pattern, severity = detect_suspicious(query)

    abusive_traffic = check_rate_limit(data["ip"])

    if status == "SUSPICIOUS":
        detection_status = "SUSPICIOUS"
        decision = "FLAGGED"
        report_status = "SUSPICIOUS"

    elif abusive_traffic:
        detection_status = "RATE_LIMITED"
        decision = "RATE_LIMITED"
        report_status = "RATE_LIMITED"
    else:
        detection_status = "NORMAL"
        decision = "ALLOWED"
        report_status = "NORMAL"

    save_log(
        data,
        detection_status,
        matched_pattern,
        severity,
        decision
    )
    save_report(
        data,
        report_status,
        matched_pattern,
        severity,
        decision
    )

    if status == "SUSPICIOUS":
        generate_alert(
            data,
            matched_pattern,
            severity
    )

    if abusive_traffic:
        generate_alert(
            data,
            "RATE_LIMIT_EXCEEDED",
            "MEDIUM"
    )

    return render_template_string("""
    <html>

    <head>
        <title>SentinelShield Security Dashboard</title>

        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f4f7;
                margin: 40px;
            }

            .container {
                max-width: 700px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 8px gray;
            }

            h1 {
                text-align: center;
            }

            .suspicious {
                color: red;
                font-weight: bold;
            }

            .normal {
                color: green;
                font-weight: bold;
            }

            a {
                text-decoration: none;
            }
        </style>

    </head>

    <body>

        <div class="container">

            <h1>SentinelShield Security Dashboard</h1>

            <hr>

            <p>
                <strong>Method:</strong> {{ data["method"] }}
            </p>

            <p>
                <strong>Path:</strong> {{ data["path"] }}
            </p>

            <p>
                <strong>IP Address:</strong> {{ data["ip"] }}
            </p>

            <p>
                <strong>User-Agent:</strong> {{ data["user_agent"] }}
            </p>

            <p>
                <strong>Query:</strong> {{ data["query"] }}
            </p>

            <p>
                <strong>Detection Status:</strong>
                {{ status }}
            </p>

            <p>
                <strong>Matched Pattern:</strong>
                {{ matched_pattern }}
            </p>

            <p>
                <strong>Severity:</strong>
                {{ severity }}
            </p>

            <p>
                <strong>Decision:</strong>
                {{ decision }}
            </p>

            <p>
                <strong>Detection Result:</strong>
                {{ detection_status }}
            </p>

            <hr>

            <a href="/dashboard">Go to Dashboard</a>

            <br><br>

            <a href="/logs">View Logs</a>

        </div>

    </body>

    </html>
    """,
    data=data,
    status=status,
    matched_pattern=matched_pattern,
    severity=severity,
    decision=decision,
    detection_status=detection_status
    )


@app.route("/dashboard")
def dashboard():

    total = 0
    suspicious = 0
    normal = 0
    rate_limited = 0
    flagged = 0
    allowed = 0
    high = 0
    medium = 0
    low = 0

    latest_events = []

    try:

        with open(REPORT_FILE, "r", encoding="utf-8") as file:

            for line in file:

                if not line.strip():
                    continue

                report = json.loads(line)
                latest_events.append(report)

                total += 1

                if report.get("status") == "SUSPICIOUS":
                    suspicious += 1
                elif report.get("status") == "RATE_LIMITED":
                    rate_limited += 1
                else:
                    normal += 1

                if report.get("decision") == "FLAGGED":
                    flagged += 1
                elif report.get("decision") == "ALLOWED":
                    allowed += 1

                severity = report.get("severity", "LOW")

                if severity == "HIGH":
                    high += 1
                elif severity == "MEDIUM":
                    medium += 1
                else:
                    low += 1

        latest_events = latest_events[-5:]
        latest_events.reverse()

    except FileNotFoundError:
        pass

    return render_template_string("""
    <html>

    <head>
        <title>SentinelShield Dashboard</title>

        <style>

            body {
                font-family: Arial, sans-serif;
                background-color: #f2f4f7;
                margin: 40px;
            }

            h1 {
                text-align: center;
            }

            .container {
                display: flex;
                justify-content: center;
                gap: 20px;
                flex-wrap: wrap;
                margin-top: 30px;
            }

            .card {
                background: white;
                padding: 25px;
                width: 180px;
                text-align: center;
                border-radius: 10px;
                box-shadow: 0 2px 8px gray;
            }

            .number {
                font-size: 32px;
                font-weight: bold;
            }

        </style>

    </head>

    <body>

        <h1>SentinelShield Security Dashboard</h1>

        <div class="container">

            <div class="card">
                <h3>Total Requests</h3>
                <div class="number">{{ total }}</div>
            </div>

            <div class="card">
                <h3>Suspicious</h3>
                <div class="number">{{ suspicious }}</div>
            </div>

            <div class="card">
                <h3>Normal</h3>
                <div class="number">{{ normal }}</div>
            </div>

            <div class="card">
                <h3>High Severity</h3>
                <div class="number">{{ high }}</div>
            </div>

            <div class="card">
                <h3>Medium Severity</h3>
                <div class="number">{{ medium }}</div>
            </div>

            <div class="card">
                <h3>Low Severity</h3>
                <div class="number">{{ low }}</div>
            </div>

            <div class="card">
                <h3>Rate Limited</h3>
                <div class="number">{{ rate_limited }}</div>
            </div>

            <div class="card">
                <h3>Flagged</h3>
                <div class="number">{{ flagged }}</div>
            </div>

            <div class="card">
                <h3>Allowed</h3>
                <div class="number">{{ allowed }}</div>
            </div>
        </div>

        <h2>Security Activity</h2>

        <div style="max-width: 600px; margin: auto;">
            <canvas id="securityChart"></canvas>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <script>
            const ctx = document.getElementById("securityChart");

            new Chart(ctx, {
                type: "bar",
                data: {
                    labels: ["Normal", "Suspicious", "Rate Limited"],
                    datasets: [{
                        label: "Number of Requests",
                        data: [
                            {{ normal }},
                            {{ suspicious }},
                            {{ rate_limited }}
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        </script>

        <h2>Latest Security Events</h2>

        <table style="width:100%; border-collapse:collapse; background:white;">

            <tr>
                <th style="border:1px solid #ccc; padding:8px;">Time</th>
                <th style="border:1px solid #ccc; padding:8px;">IP</th>
                <th style="border:1px solid #ccc; padding:8px;">Status</th>
                <th style="border:1px solid #ccc; padding:8px;">Pattern</th>
                <th style="border:1px solid #ccc; padding:8px;">Severity</th>
                <th style="border:1px solid #ccc; padding:8px;">Decision</th>
            </tr>

            {% for event in latest_events %}

            <tr>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("time", "") }}
                </td>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("ip", "") }}
                </td>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("status", "") }}
                </td>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("matched_pattern", "") }}
                </td>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("severity", "") }}
                </td>

                <td style="border:1px solid #ccc; padding:8px;">
                    {{ event.get("decision", "") }}
                </td>

            </tr>

            {% endfor %}

        </table>


        <br><br>

        <center>
            <a href="/logs">View Security Logs</a>
            |
            <a href="/alerts">View Security Alerts</a>
            |
            <a href="/">Home</a>
        </center>

    </body>

    </html>
    """,
    total=total,
    suspicious=suspicious,
    normal=normal,
    rate_limited=rate_limited,
    flagged=flagged,
    allowed=allowed,
    high=high,
    medium=medium,
    low=low,
    latest_events=latest_events
    )


@app.route("/logs")
def logs():

    logs_data = []

    try:

        with open(LOG_FILE, "r", encoding="utf-8") as file:

            for line in file:

                if line.strip():
                    logs_data.append(json.loads(line))

    except FileNotFoundError:
        pass

    logs_data.reverse()

    return render_template_string("""
    <html>

    <head>
        <title>SentinelShield Security Logs</title>

        <style>

            body {
                font-family: Arial, sans-serif;
                background-color: #f2f4f7;
                margin: 40px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
            }

            th, td {
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
            }

            th {
                background-color: #eee;
            }

            .HIGH {
                font-weight: bold;
            }

        </style>

    </head>

    <body>

        <h1>SentinelShield Security Logs</h1>

        {% if logs_data %}

        <table>

            <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Path</th>
                <th>IP</th>
                <th>Query</th>
                <th>Status</th>
                <th>Pattern</th>
                <th>Severity</th>
                <th>Decision</th>
            </tr>

            {% for log in logs_data %}

            <tr>

                <td>{{ log["time"] }}</td>
                <td>{{ log["method"] }}</td>
                <td>{{ log["path"] }}</td>
                <td>{{ log["ip"] }}</td>
                <td>{{ log["query"] }}</td>
                <td>{{ log["status"] }}</td>
                <td>{{ log["pattern"] }}</td>
                <td class="{{ log["severity"] }}">
                    {{ log["severity"] }}
                <td>{{log.get('decision','N/A')}}</td>
                </td>

            </tr>

            {% endfor %}

        </table>

        {% else %}

        <p>No security logs found.</p>

        {% endif %}

        <br>

        <a href="/dashboard">Dashboard</a>
        |
        <a href="/">Home</a>

    </body>

    </html>
    """, logs_data=logs_data)

@app.route("/alerts")
def alerts():

    alerts_data = []

    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as file:

            for line in file:

                if line.strip():
                    alerts_data.append(json.loads(line))

    except FileNotFoundError:
        pass

    alerts_data.reverse()

    return render_template_string("""
    <html>

    <head>
        <title>SentinelShield Alerts</title>

        <style>

            body {
                font-family: Arial, sans-serif;
                background-color: #f2f4f7;
                margin: 40px;
            }

            h1 {
                text-align: center;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
            }

            th, td {
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
            }

            th {
                background-color: #eee;
            }

        </style>

    </head>

    <body>

        <h1>SentinelShield Security Alerts</h1>

        {% if alerts_data %}

        <table>

            <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>Path</th>
                <th>Pattern</th>
                <th>Severity</th>
                <th>Decision</th>
                <th>Message</th>
            </tr>

            {% for alert in alerts_data %}

            <tr>

                <td>{{ alert.get("time", "") }}</td>

                <td>{{ alert.get("ip", "") }}</td>

                <td>{{ alert.get("path", "") }}</td>

                <td>{{ alert.get("pattern", "") }}</td>

                <td>{{ alert.get("severity", "") }}</td>

                <td>{{ alert.get("decision", "") }}</td>

                <td>{{ alert.get("message", "") }}</td>

            </tr>

            {% endfor %}

        </table>

        {% else %}

        <p>No security alerts found.</p>

        {% endif %}

        <br>

        <a href="/dashboard">Dashboard</a>
        |
        <a href="/logs">Security Logs</a>
        |
        <a href="/">Home</a>

    </body>

    </html>
    """, alerts_data=alerts_data)


if __name__ == "__main__":
    app.run(debug=True)