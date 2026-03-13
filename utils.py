import pandas as pd


SUSPICIOUS_EMAIL_KEYWORDS = [
    "urgent", "invoice", "reset your password", "action required", "expires today"
]

SUSPICIOUS_ATTACHMENTS = [".docm", ".exe", ".zip", ".js"]
SUSPICIOUS_PROCESSES = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]
UNUSUAL_COUNTRIES = ["RU", "CN", "KP", "IR"]


def load_data():
    auth = pd.read_csv("data/auth_logs.csv", parse_dates=["timestamp"])
    email = pd.read_csv("data/email_reports.csv", parse_dates=["timestamp"])
    endpoint = pd.read_csv("data/endpoint_logs.csv", parse_dates=["timestamp"])
    return auth, email, endpoint


def score_email_row(row):
    score = 0
    reasons = []

    text = f"{row['subject']} {row['body']}".lower()
    if any(k in text for k in SUSPICIOUS_EMAIL_KEYWORDS):
        score += 2
        reasons.append("Suspicious email wording")

    attachment = str(row["attachment"]).lower()
    if any(attachment.endswith(ext) for ext in SUSPICIOUS_ATTACHMENTS):
        score += 3
        reasons.append("Dangerous attachment type")

    sender = str(row["sender"]).lower()
    if "micros0ft" in sender or "okta-login-alert" in sender:
        score += 2
        reasons.append("Potential spoofed sender domain")

    return score, reasons


def score_auth_events(auth_df_user):
    score = 0
    reasons = []

    failed = (auth_df_user["status"] == "failed").sum()
    if failed >= 3:
        score += 2
        reasons.append("Burst of failed logins")

    success_after_fail = (
        failed >= 3 and (auth_df_user["status"] == "success").any()
    )
    if success_after_fail:
        score += 3
        reasons.append("Successful login after multiple failures")

    if auth_df_user["country"].isin(UNUSUAL_COUNTRIES).any():
        score += 2
        reasons.append("Login from unusual country")

    return score, reasons


def score_endpoint_events(endpoint_df_user):
    score = 0
    reasons = []

    processes = endpoint_df_user["process_name"].astype(str).str.lower().tolist()
    files = endpoint_df_user["file_name"].astype(str).str.lower().tolist()

    if any(p in SUSPICIOUS_PROCESSES for p in processes):
        score += 3
        reasons.append("Suspicious script/command execution")

    if any(str(f).endswith(".docm") for f in files):
        score += 2
        reasons.append("Macro-enabled document opened")

    return score, reasons


def severity_from_score(score):
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def build_incidents(auth, email, endpoint):
    incidents = []

    for _, email_row in email.iterrows():
        user = email_row["user"]
        t0 = email_row["timestamp"]
        t1 = t0 + pd.Timedelta(minutes=30)

        auth_slice = auth[(auth["user"] == user) & (auth["timestamp"] >= t0) & (auth["timestamp"] <= t1)]
        endpoint_slice = endpoint[(endpoint["user"] == user) & (endpoint["timestamp"] >= t0) & (endpoint["timestamp"] <= t1)]

        email_score, email_reasons = score_email_row(email_row)
        auth_score, auth_reasons = score_auth_events(auth_slice) if not auth_slice.empty else (0, [])
        endpoint_score, endpoint_reasons = score_endpoint_events(endpoint_slice) if not endpoint_slice.empty else (0, [])

        total_score = email_score + auth_score + endpoint_score
        severity = severity_from_score(total_score)

        timeline = []

        timeline.append({
            "timestamp": email_row["timestamp"],
            "source": "email",
            "event": f"Reported email: {email_row['subject']}"
        })

        for _, row in auth_slice.iterrows():
            timeline.append({
                "timestamp": row["timestamp"],
                "source": "auth",
                "event": f"{row['action']} / {row['status']} from {row['ip']} ({row['country']})"
            })

        for _, row in endpoint_slice.iterrows():
            timeline.append({
                "timestamp": row["timestamp"],
                "source": "endpoint",
                "event": f"{row['process_name']} {row['action']} {row['file_name']}"
            })

        timeline = sorted(timeline, key=lambda x: x["timestamp"])

        incidents.append({
            "incident_id": f"INC-{email_row['ticket_id']}",
            "user": user,
            "ticket_id": email_row["ticket_id"],
            "score": total_score,
            "severity": severity,
            "reasons": email_reasons + auth_reasons + endpoint_reasons,
            "timeline": timeline,
            "raw_email": email_row.to_dict(),
            "auth_events": auth_slice.to_dict(orient="records"),
            "endpoint_events": endpoint_slice.to_dict(orient="records"),
        })

    return incidents