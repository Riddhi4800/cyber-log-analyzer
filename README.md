# cyber-log-analyzer
Cybersecurity Log Analysis &amp; Real-Time Monitoring System

**Overview**
This project is a Python-based cybersecurity system that analyzes web logs to detect suspicious activities such as brute-force attacks, high traffic (DDoS), and sensitive endpoint access.

** Features**
- Log parsing and analysis using Python
- Detection of:
  - Failed login attempts
  - High traffic anomalies
  - Sensitive endpoint access
- Real-time API using Flask
- Power BI dashboard for visualization

** Technologies Used**
- Python
- Pandas
- Flask
- Power BI

** How it Works**
1. Logs are analyzed using `analyzer.py`
2. Results are stored in `analyzed_logs.csv`
3. Flask API serves real-time data (`/logs`, `/alerts`)
4. Power BI visualizes cybersecurity insights


python analyzer.py
python app.py
