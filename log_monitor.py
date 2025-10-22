#!/usr/bin/env python3
"""
log_monitor.py
Journalctl-based monitor for Kali:
- Detects Failed SSH attempts
- Detects SUDO events
- Detects Unauthorized Access (Accepted password by non-whitelisted users)
- Sends alerts via Email / Slack / Telegram if env vars set
- Logs alerts to /var/log/security_alerts.log (for ELK/Filebeat ingestion)
"""

import os, re, subprocess, time

# ------- Patterns -------
PAT_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
PAT_ACCEPT = re.compile(r"Accepted password for (\S+) from (\S+) port")   # successful login
PAT_SUDO = re.compile(r"\bsudo\b|session opened for user root|COMMAND=")

# ------- Config from env -------
WHITELIST = os.getenv("MON_WHITELIST", "").split(",") if os.getenv("MON_WHITELIST") else []
WHITELIST = [u.strip() for u in WHITELIST if u.strip()]

# Email (SMTP) settings
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM")
EMAIL_TO = os.getenv("ALERT_EMAIL_TO")

# Telegram
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT  = os.getenv("TG_CHAT")

# Slack
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

# ------- Log to file (for ELK) -------
LOG_FILE = "/var/log/security_alerts.log"

def log_alert_to_file(message):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(message + "\n")
    except Exception as e:
        print("Failed to write log:", e)

# ------- Notification helpers -------
def send_email(subject, body):
    if not (SMTP_USER and SMTP_PASS and EMAIL_FROM and EMAIL_TO):
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
    except Exception as e:
        print("Email failed:", e)

def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT):
        return
    try:
        import requests
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TG_CHAT, "text": text}, timeout=8)
    except Exception as e:
        print("Telegram failed:", e)

def send_slack(text):
    if not SLACK_WEBHOOK:
        return
    try:
        import requests
        requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=8)
    except Exception as e:
        print("Slack failed:", e)

def alert(title, body):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    out = f"[{ts}] ALERT: {title} | {body}"
    print(out)

    # ---- NEW: log alert for Filebeat ----
    log_alert_to_file(out)

    # Notify external channels
    try: send_email(title, body)
    except Exception: pass
    try: send_telegram(f"{title}\n{body}")
    except Exception: pass
    try: send_slack(f"{title}\n{body}")
    except Exception: pass

# ------- Journal streaming -------
def stream_journal(unit=None):
    cmd = ["journalctl", "-f", "-o", "short"]
    if unit:
        cmd = ["journalctl", "-u", unit, "-f", "-o", "short"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in p.stdout:
            yield line.rstrip("\n")
    except KeyboardInterrupt:
        p.terminate()
        raise

# ------- Processing -------
def process_line(line):
    m = PAT_FAIL.search(line)
    if m:
        user, ip = m.group(1), m.group(2)
        alert("Failed SSH attempt", f"user={user} ip={ip} | {line}")
        return

    m2 = PAT_ACCEPT.search(line)
    if m2:
        user, ip = m2.group(1), m2.group(2)
        if WHITELIST:
            if user not in WHITELIST:
                alert("Unauthorized Access (non-whitelisted user)", f"user={user} ip={ip} | {line}")
            else:
                print(f"[info] Authorized login by {user} from {ip}")
        else:
            print(f"[info] Successful login: {user} from {ip}")
        return

    if PAT_SUDO.search(line):
        if "session opened for user root" in line or "COMMAND=" in line or "authentication failure" in line or "sudo:" in line:
            alert("SUDO event", line)
        else:
            print("SUDO(info):", line)

# ------- Main -------
def main():
    print("Starting journalctl monitor. Press Ctrl+C to stop.")
    unit = None
    for ln in stream_journal(unit):
        process_line(ln)

if __name__ == "__main__":
    main()
