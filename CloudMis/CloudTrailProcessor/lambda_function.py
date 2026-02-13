import json, gzip, logging
from io import BytesIO
import boto3, botocore

s3 = boto3.client("s3")
logger = logging.getLogger()
logger.setLevel("INFO")

# ========= HARD-CODED CONFIG (no env vars) =========
SOURCE_BUCKET = "aakash-cloudtrail-logs-2025"
SOURCE_PREFIX = "AWSLogs/465983269375/CloudTrail/"
DEST_BUCKET   = "cloudmis-appdatabucket-a9lvm55gbddg"   # from your stack output
DEST_PREFIX   = "reports/"                               # keep "reports/"
# ===================================================

# --- Severity & CVSS mapping (simple, extensible) ---
SEV_TO_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

EVENT_RULES = {
    # S3 public access / policy changes
    "PutBucketPolicy":            {"issue": "S3 bucket policy changed", "severity": "high"},
    "PutBucketAcl":               {"issue": "S3 bucket ACL changed", "severity": "high"},
    "PutBucketPublicAccessBlock": {"issue": "S3 public access block changed", "severity": "high"},
    "DeleteBucketPolicy":         {"issue": "S3 bucket policy removed", "severity": "critical"},
    # IAM risky changes
    "CreateUser":                 {"issue": "IAM user created", "severity": "medium"},
    "CreateAccessKey":            {"issue": "New access key created", "severity": "high"},
    "AttachUserPolicy":           {"issue": "User policy attached", "severity": "high"},
    "PutUserPolicy":              {"issue": "Inline user policy added", "severity": "high"},
    "AttachRolePolicy":           {"issue": "Role policy attached", "severity": "high"},
    "PutRolePolicy":              {"issue": "Inline role policy added", "severity": "high"},
    # CloudTrail / GuardDuty switches
    "StopLogging":                {"issue": "CloudTrail logging stopped", "severity": "critical"},
    "UpdateDetector":             {"issue": "GuardDuty config changed", "severity": "high"},
}

def cvss_for_severity(sev: str) -> float:
    return SEV_TO_CVSS.get((sev or "").lower(), 5.0)

def guess_resource_id(ev: dict):
    """Return (resource_id, arn)."""
    arn = None
    for r in ev.get("resources", []) or []:
        if isinstance(r, dict):
            arn = r.get("ARN") or arn
            if "ARN" in r:
                break
    if not arn:
        arn = (ev.get("userIdentity") or {}).get("arn")

    resource_id = None
    req = ev.get("requestParameters") or {}
    for k in ("bucketName", "roleName", "userName", "groupName"):
        if k in req:
            resource_id = req.get(k)
            break
    if not resource_id and arn:
        resource_id = arn.split("/")[-1].split(":")[-1]
    return resource_id, arn

def rule_for_event(event_name: str):
    rule = EVENT_RULES.get(event_name)
    if rule:
        return rule["issue"], rule["severity"]
    return event_name, "medium"

def list_objects(bucket: str, prefix: str):
    if not bucket:
        raise ValueError("list_objects(): 'bucket' is empty/None")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix or ""):
        for obj in page.get("Contents", []):
            yield obj["Key"]

def jsonl_key(base_key: str, event_date: str, region: str) -> str:
    base_name = base_key.split("/")[-1].replace(".json.gz", ".jsonl")
    return f"{DEST_PREFIX}date={event_date}/region={region}/{base_name}"

def process_one_gzip(obj_key: str) -> int:
    if not obj_key.endswith(".gz"):
        return 0
    try:
        raw = s3.get_object(Bucket=SOURCE_BUCKET, Key=obj_key)["Body"].read()
    except botocore.exceptions.ClientError as e:
        logger.error(f"[GetObject ERROR] {obj_key}: {e}")
        return 0

    try:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as gz:
            payload = gz.read()
        data = json.loads(payload)
    except Exception as e:
        logger.error(f"[GZIP/JSON ERROR] {obj_key}: {e}")
        return 0

    records = data.get("Records", []) or []
    if not records:
        logger.info(f"[NO RECORDS] {obj_key}")
        return 0

    # Extract date/region from key: .../CloudTrail/<region>/<yyyy>/<mm>/<dd>/...
    parts = obj_key.split("/")
    region = "unknown-region"
    event_date = "1970-01-01"
    try:
        idx = parts.index("CloudTrail")
        region = parts[idx + 1]
        yyyy, mm, dd = parts[idx + 2], parts[idx + 3], parts[idx + 4]
        event_date = f"{yyyy}-{mm}-{dd}"
    except Exception:
        pass

    out_lines = []
    for ev in records:
        timestamp = ev.get("eventTime")
        event_name = ev.get("eventName", "UnknownEvent")
        issue, severity = rule_for_event(event_name)
        cvss = cvss_for_severity(severity)
        resource_id, arn = guess_resource_id(ev)

        out_record = {
            "timestamp": timestamp,
            "event_type": event_name,
            "issue": issue,
            "resource_id": resource_id,
            "severity": severity,
            "cvss_score": cvss,
            "arn": arn,
            "aws_region": ev.get("awsRegion"),
            "source_ip": ev.get("sourceIPAddress"),
            "user": (ev.get("userIdentity") or {}).get("arn") or (ev.get("userIdentity") or {}).get("userName"),
        }
        out_lines.append(json.dumps(out_record, separators=(",", ":"), ensure_ascii=False))

    out_body = ("\n".join(out_lines)).encode("utf-8")
    out_key = jsonl_key(obj_key, event_date, region)

    try:
        s3.put_object(Bucket=DEST_BUCKET, Key=out_key, Body=out_body)
        logger.info(f"[WROTE] {DEST_BUCKET}/{out_key} ({len(records)} events)")
    except botocore.exceptions.ClientError as e:
        logger.error(f"[PutObject ERROR] {DEST_BUCKET}/{out_key}: {e}")
        return 0

    return len(records)

def lambda_handler(event, context):
    logger.info(f"[START] Using SOURCE_BUCKET={SOURCE_BUCKET}, SOURCE_PREFIX={SOURCE_PREFIX}")
    if not SOURCE_BUCKET or not DEST_BUCKET:
        raise RuntimeError(f"Buckets not set correctly. SOURCE_BUCKET={SOURCE_BUCKET!r}, DEST_BUCKET={DEST_BUCKET!r}")
    total = 0
    for key in list_objects(SOURCE_BUCKET, SOURCE_PREFIX):
        total += process_one_gzip(key)
    logger.info(f"[SUMMARY] Total events written: {total}")
    return {"status": "ok", "events_written": total}
