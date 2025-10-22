# Log Monitoring and Alerting System

This project monitors system logs on a Linux machine and detects suspicious activities such as:
- Failed SSH login attempts  
- Privilege escalation (sudo usage)  
- Unauthorized successful logins  

Whenever any of these events are detected, the system sends real-time alerts through:
- **Telegram**
- **Slack**
- **Email**

It also logs the alerts to `/var/log/security_alerts.log`, which is then forwarded to **Elasticsearch** and visualized in **Kibana** using **Filebeat**.

---

## ⚙️ Files in this project

| File / Folder | Description |
|----------------|-------------|
| `log_monitor.py` | Main Python script that checks logs and sends alerts |
| `filebeat.yml` | Filebeat configuration to send logs to Elasticsearch |
| `screenshots/` | Contains screenshots of alerts and Kibana dashboards |
| `Log_Monitoring_Report.docx` | Final report document |
| `README.md` | This file – project overview and setup guide |

---

## 🚀 How it works

1. The Python script (`log_monitor.py`) continuously monitors log files for suspicious activity.  
2. When an event is detected:
   - It writes a message to `/var/log/security_alerts.log`.
   - Sends alerts through Telegram, Slack, or Email (using your configured API keys).
3. Filebeat reads this log file and sends the alerts to Elasticsearch.
4. Kibana displays the data visually on dashboards.

---

## 🧰 Tools and Technologies Used

- 🧩 Filebeat – Collects and forwards system logs.
- 📦 Elasticsearch – Stores and indexes logs.
- 📊 Kibana – Visualizes and builds dashboards.
- 🐍 Python – Custom script for alerting and monitoring.
- 🔔 Slack / Telegram / Email API – Sends real-time notifications.

---

## 🖼️ Screenshots

- Kibana Dashboard Visualization
- Telegram Alert Example
- Email Notification Example
- Slack Alert Example


## 👨‍💻 How to Run (Simple Version🧩 Filebeat – Collects and forwards system logs.

1. Make sure you have Python and Filebeat installed.  
2. Configure your alert credentials inside the Python script or environment variables.  
3. Start Filebeat:
   ```bash
   sudo filebeat setup
   sudo systemctl start filebeat
## yaml file is included 

## Run the monitoring script:
#included 
sudo python3 log_monitor.py

# Generate some failed login attempts and check your Telegram, Slack, or Email for alerts.



#  Open Kibana to visualize alerts.

#  go through report for more

## 🚀 Future Improvements

- Add real-time dashboard refresh automation.

- Extend detection rules for network anomalies.

- Integrate with SIEM platforms for centralized analysis.
