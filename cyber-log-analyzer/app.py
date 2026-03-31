from flask import Flask, jsonify
import pandas as pd

app = Flask(__name__)

# Route 1: Get all logs
@app.route("/logs")
def get_logs():
    df = pd.read_csv("analyzed_logs.csv")
    return jsonify(df.to_dict(orient="records"))

# Route 2: Get alerts only
@app.route("/alerts")
def get_alerts():
    df = pd.read_csv("analyzed_logs.csv")
    alerts = df[
        (df["High_Traffic"] == True) |
        (df["Failed_Login"] == True) |
        (df["Sensitive_Access"] == True)
    ]
    return jsonify(alerts.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(debug=True)