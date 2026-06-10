import boto3
import json
import gzip
from datetime import datetime, timedelta, timezone

# ---- CONFIG ----
REGION = "eu-north-1"
ACCOUNT_ID = "025277631090"
BUCKET_NAME = "aws-cloudtrail-logs-025277631090-b5253acd"
LOG_REGIONS = ["eu-north-1", "us-east-1"]  # us-east-1 captures IAM events
HOURS_BACK = 24

# ---- DETECTION RULES ----

SUSPICIOUS_EVENTS = {
    "StopLogging":          ("CRITICAL", "CloudTrail logging disabled — attacker covering tracks"),
    "DeleteTrail":          ("CRITICAL", "CloudTrail trail deleted — audit log destruction"),
    "ConsoleLoginWithoutMFA": ("CRITICAL", "Root or IAM login without MFA"),
    "CreateAccessKey":      ("HIGH",     "New access key created — possible credential theft"),
    "AttachUserPolicy":     ("HIGH",     "Policy attached to user — possible privilege escalation"),
    "PutUserPolicy":        ("HIGH",     "Inline policy added to user — possible privilege escalation"),
    "AuthorizeSecurityGroup": ("MEDIUM", "Security group rule added — firewall change"),
    "AssumeRole":           ("LOW",      "Role assumed — review if source is unexpected"),
}

WHITELISTED_SOURCES = [
    "resource-explorer-2.amazonaws.com",
    "aws-resource-explorer-2.amazonaws.com",
    "config.amazonaws.com",
    "cloudtrail.amazonaws.com",
]


def get_cloudtrail_events(bucket_name, regions, date):
    """Read CloudTrail logs directly from S3"""
    s3 = boto3.client("s3", region_name=REGION)
    events = []

    for region in regions:
        prefix = f"AWSLogs/{ACCOUNT_ID}/CloudTrail/{region}/{date.strftime('%Y/%m/%d')}/"

        try:
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            files = response.get("Contents", [])

            for file in files:
                key = file["Key"]
                obj = s3.get_object(Bucket=bucket_name, Key=key)

                with gzip.GzipFile(fileobj=obj["Body"]) as f:
                    log_data = json.load(f)
                    events.extend(log_data.get("Records", []))
        except Exception as e:
            print(f"  Warning: could not read {region} logs — {e}")

    return events


def analyze_events(events):
    """Check events against detection rules"""

    findings = []

    for event in events:
        event_name = event.get("eventName", "")
        username = event.get("userIdentity", {}).get(
            "userName",
            event.get("userIdentity", {}).get("type", "Unknown")
            )
        event_time = event.get("eventTime", "")
        source_ip = event.get("sourceIPAddress", "Unknown")

        # Skip known safe AWS service sources
        if source_ip in WHITELISTED_SOURCES:
            continue

        if event_name in SUSPICIOUS_EVENTS:
            severity, description = SUSPICIOUS_EVENTS[event_name]

            findings.append({
                "event": event_name,
                "description": description,
                "user": username,
                "time": event_time,
                "source_ip": source_ip,
                "severity": severity
            })

    return findings


def save_findings(findings):
    """Write findings to the findings folder"""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = f"findings/findings_{timestamp}"

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Findings saved to {output_path}")
    return output_path


def main():
    print(f"Pulling CloudTrail events from the last {HOURS_BACK} hours...")
    today = datetime.now(timezone.utc)

    all_events = []
    dates_to_check = [today, today - timedelta(days=1)]  # today and yesterday

    for date in dates_to_check:
        print(f"  Checking logs for {date.strftime('%Y-%m-%d')}...")
        events = get_cloudtrail_events(BUCKET_NAME, LOG_REGIONS, date)
        all_events.extend(events)

    print(f"Found {len(all_events)} events. Analyzing...")

    findings = analyze_events(all_events)

    if findings:
        print(f"\n⚠️  {len(findings)} suspicious event(s) detected:")
        for f in findings:
            print(f"\n  [{f['severity']}] {f['event']}")
            print(f"  → {f['description']}")
            print(f"  → User: {f['user']} | IP: {f['source_ip']} | Time: {f['time']}")
        save_findings(findings)

    else:
        print("✅ No suspicious events detected.")


if __name__ == "__main__":
    main()
