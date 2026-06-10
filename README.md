# CloudTrail Threat Detection

A Python tool that analyzes AWS CloudTrail logs for suspicious activity. Built as part of my transition into cloud security — the goal was to understand how threat detection actually works under the hood, not just point a tool at something and read the output.

---

## Overview

The script reads CloudTrail log files directly from S3 and flags events that match known attack patterns — things like access keys being created unexpectedly, someone disabling audit logging, or a user suddenly getting admin permissions they didn't have before.

Each finding gets a severity level and a plain description of why it's suspicious.

---

## Why S3 and Not the CloudTrail API?

I started with the API approach and kept getting empty results even though the events were definitely happening. After some digging, turns out IAM is a global service that always logs to `us-east-1` in S3 regardless of your primary region — so regional API queries just miss them entirely.

Reading directly from S3 is also how real detection pipelines work (Splunk, Datadog, AWS Security Hub all ingest from the same source), so it made more sense to build it the right way from the start.

---

## Detection Rules

| Severity | Event | What It Could Mean |
|----------|-------|-------------------|
| CRITICAL | `StopLogging` | Someone disabled CloudTrail — classic attacker move to cover tracks |
| CRITICAL | `DeleteTrail` | Audit log destroyed entirely |
| CRITICAL | `ConsoleLoginWithoutMFA` | Login with no second factor |
| HIGH | `CreateAccessKey` | New credentials created — possible persistent access attempt |
| HIGH | `AttachUserPolicy` | Admin permissions attached to a user — privilege escalation |
| HIGH | `PutUserPolicy` | Same as above via inline policy |
| MEDIUM | `AuthorizeSecurityGroup` | Firewall rule added |
| LOW | `AssumeRole` | Role assumption — worth reviewing if the source is unexpected |

Known AWS internal services (like Resource Explorer) are whitelisted so they don't flood the output with false positives.

---

## Sample Output

This is from a real run against my AWS account after simulating three attack scenarios:

```
Pulling CloudTrail events from the last 24 hours...
  Checking logs for 2026-06-10...
  Checking logs for 2026-06-09...
Found 700 events. Analyzing...

⚠️  4 suspicious event(s) detected:

  [HIGH] AttachUserPolicy
  → Policy attached to user — possible privilege escalation
  → User: Root | IP: 84.228.168.22 | Time: 2026-06-10T08:53:59Z

  [CRITICAL] StopLogging
  → CloudTrail logging disabled — attacker covering tracks
  → User: Root | IP: 87.71.26.1 | Time: 2026-06-09T14:16:14Z

  [HIGH] CreateAccessKey
  → New access key created — possible credential theft
  → User: Root | IP: 87.71.26.1 | Time: 2026-06-09T09:43:49Z

  [HIGH] CreateAccessKey
  → New access key created — possible credential theft
  → User: Root | IP: 87.71.26.1 | Time: 2026-06-09T09:45:00Z

Findings saved to findings/findings_20260610_090401.json
```

The two `CreateAccessKey` events and the `StopLogging` were deliberate simulations. The `AttachUserPolicy` was me attaching `AdministratorAccess` to a temporary test user to confirm the privilege escalation detection worked. All three were caught.

---

## How to Run It

### Prerequisites
- Python 3.9+
- AWS CLI configured (`aws configure`)
- An IAM user or role with `cloudtrail:LookupEvents`, `s3:GetObject`, and `s3:ListBucket` permissions

### Setup

```bash
git clone https://github.com/Rbustan0/cloudtrail-threat-detection.git
cd cloudtrail-threat-detection
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Open `detect.py` and update the config section at the top:

```python
REGION = "eu-north-1"           # Your primary AWS region
ACCOUNT_ID = "YOUR_ACCOUNT_ID"  # Your 12-digit AWS account ID
BUCKET_NAME = "YOUR_BUCKET"     # Your CloudTrail S3 bucket name
LOG_REGIONS = ["eu-north-1", "us-east-1"]  # us-east-1 needed for IAM events
HOURS_BACK = 24                 # How far back to look
```

### Run

```bash
python3 detect.py
```

Findings are saved as timestamped JSON files in the `findings/` folder.

---

## False Positive Handling

First run returned 49 `AssumeRole` alerts — all from AWS's Resource Explorer doing routine scans. Added a whitelist for known internal AWS service sources to filter those out. In a real environment you'd tune this further based on your specific account's normal activity patterns.

---

## Potential Improvements

- SNS or Slack alerting so findings don't just sit in a JSON file
- Lambda deployment so it runs on a schedule automatically
- Athena integration for querying across longer time windows
- Deduplication so the same event doesn't fire multiple times across runs