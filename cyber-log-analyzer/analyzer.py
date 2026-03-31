import pandas as pd
import re

data = []

with open("logs.txt", "r") as file:
    for line in file:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(.*?)"\s(\d+)', line)
        if match:
            ip = match.group(1)
            timestamp = match.group(2)
            request = match.group(3)
            status = int(match.group(4))

            data.append([ip, timestamp, request, status])

df = pd.DataFrame(data, columns=["IP", "Timestamp", "Request", "Status"])

print("\nAll Logs:")
print(df)

# Brute Force Detection
failed = df[df["Status"] == 401]

failed_counts = failed["IP"].value_counts()

print("\n🚨 Brute Force Attack Detected:")
for ip, count in failed_counts.items():
    if count > 3:
        print(f"IP {ip} has {count} failed login attempts")


# High Traffic Detection
request_counts = df["IP"].value_counts()

print("\n🚨 High Traffic (Possible DDoS):")
for ip, count in request_counts.items():
    if count > 5:
        print(f"IP {ip} made {count} requests")

# Detect sensitive access
sensitive = df[df["Request"].str.contains("admin|config", case=False)]
print("\nSensitive Access:")
print(sensitive[["IP", "Request"]])

print("\n📊 --- SECURITY SUMMARY ---")
print(f"Total Requests: {len(df)}")
print(f"Unique IPs: {df['IP'].nunique()}")
print(f"Failed Login Attempts: {len(failed)}")


# Add detection flags
df["Failed_Login"] = df["Status"] == 401

df["Sensitive_Access"] = df["Request"].str.lower().apply(
    lambda x: any(k in x for k in ["admin", "config", "login"])
)

# Count requests per IP
ip_counts = df["IP"].value_counts()
df["Request_Count"] = df["IP"].map(ip_counts)

# High traffic flag
df["High_Traffic"] = df["Request_Count"] > 3

df["Login_Status"] = df["Failed_Login"].apply(
    lambda x: "Failed Login" if x else "Successful/Other"
)

# Export
df.to_csv("analyzed_logs.csv", index=False)