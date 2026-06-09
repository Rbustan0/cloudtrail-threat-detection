import boto3
import json
from datetime import datetime, timedelta, timezone
from dateutil import parser

# ---- CONFIG ----

REGION = "eu-north-1" # Change to your AWS region
HOURS_BACK = 24

# ---- DETECTION RULES ----

SUSPICIOUS_EVENTS = [
    "ConsoleLoginWithoutMFA",
    "StopLogging",
    "DeleteTrail",
    "PutBucketPolicy",  # S3 bucket policy changes
    "AuthorizeSecurityGroup",  # Firewall rule changes
    "CreateAccessKey",
    "AttachUserPolicy",  # Privilege escalation attempt
    "AssumeRole"  # Role assumption - lateral movement indicator
]

WHITELISTED_SOURCES = [
    "resource-explorer-2.amazonaws.com",
    "aws-resource-explorer-2.amazonaws.com",
    "config.amazonaws.com",
    "cloudtrail.amazonaws.com",
]


def get_cloudtrail_events(region, hours_back):
    """Pull recent CloudTrail events"""

    client = boto3.client("cloudtrail", region_name=region)
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    events = []
    kwargs = {
        "StartTime": start_time,
        "EndTime": datetime.now(timezone.utc),
        "MaxResults": 50
    }

    while True:
        response = client.lookup_events(**kwargs)
        events.extend(response.get("Events", []))
        next_token = response.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token

    return events


def analyze_events(events):
    """Check events against detection rules"""

    findings = []

    for event in events:
        event_name = event.get("EventName", "")
        username = event.get("Username", "Unknown")
        event_time = event.get("EventTime", "")
        cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))
        source_ip = cloud_trail_event.get("sourceIPAddress", "Unknown")

        # Skip known safe AWS service sources
        if source_ip in WHITELISTED_SOURCES:
            continue

        if event_name in SUSPICIOUS_EVENTS:
            findings.append({
                "event": event_name,
                "user": username,
                "time": str(event_time),
                "source_ip": source_ip,
                "severity": "HIGH"
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

    events = get_cloudtrail_events(REGION, HOURS_BACK)
    print(f"Found {len(events)} events. Analyzing...")

    findings = analyze_events(events)

    if findings:
        print(f"\n⚠️  {len(findings)} suspicious event(s) detected:")
        for f in findings:
            print(f"  [{f['severity']}] {f['event']} by {f['user']} from {f['source_ip']} at {f['time']}")
        save_findings(findings)
    else:
        print("✅ No suspicious events detected.")


if __name__ == "__main__":
    main()
