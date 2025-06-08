import argparse
import re
import json
from pathlib import Path
import pandas as pd

# ─────────────  Global knobs  ─────────────
RARE_IP_THRESHOLD = 5
RARE_COUNTRIES = {"CN", "RU", "IR", "KP"}
Z_BURST = 3                       # mean + Z·σ hour spike
# ------------------------------------------

# == Combined ATT&CK-style catalogue ======================================
#   key: API name  (supports '*' wildcard at the end)
#   val: (ATT&CK-ish category, numeric risk 1-4  →  info/low/med/high)
CATALOGUE = {
    # -------------- Defence-Evasion
    "DeleteTrail":                ("Defense Evasion", 4),
    "StopLogging":                ("Defense Evasion", 4),
    "UpdateTrail":                ("Defense Evasion", 4),
    "PutEventSelectors":          ("Defense Evasion", 4),
    "DeleteBucketPolicy":         ("Defense Evasion", 4),
    "DeleteBucketEncryption":     ("Defense Evasion", 4),
    "DisableKey":                 ("Defense Evasion", 4),
    "ScheduleKeyDeletion":        ("Defense Evasion", 4),
    "DeactivateMFADevice":        ("Defense Evasion", 4),
    "DeleteMFADevice":            ("Defense Evasion", 4),

    # -------------- Priv-Esc / Persistence
    "AttachUserPolicy":           ("Privilege Escalation", 4),
    "AttachRolePolicy":           ("Privilege Escalation", 4),
    "PutUserPolicy":              ("Privilege Escalation", 4),
    "PutRolePolicy":              ("Privilege Escalation", 4),
    "CreatePolicy":               ("Privilege Escalation", 4),
    "CreatePolicyVersion":        ("Privilege Escalation", 4),
    "UpdateAssumeRolePolicy":     ("Privilege Escalation", 4),
    "AddUserToGroup":             ("Privilege Escalation", 3),
    "CreateAccessKey":            ("Persistence", 3),
    "CreateLoginProfile":         ("Persistence", 3),
    "DeleteLoginProfile":         ("Persistence", 3),
    "UpdateLoginProfile":         ("Persistence", 3),
    "CreateUser":                 ("Persistence", 2),

    # -------------- Lambda persistence
    "UpdateFunctionCode*":        ("Persistence",           4),

    # -------------- Credential access
    "GetSecretValue":             ("Credential Access", 3),
    "GetParameter":               ("Credential Access", 3),
    "GetParameterHistory":        ("Credential Access", 3),
    "GetParameters":              ("Credential Access", 3),
    "GetPasswordData":            ("Credential Access", 4),

    # -------------- Discovery (wildcards)
    "List*":                      ("Discovery", 1),
    "Get*":                       ("Discovery", 1),
    "Describe*":                  ("Discovery", 1),
    "GetAccountAuthorizationDetails": ("Discovery", 3),

    # -------------- Exfil / Network
    "PutObject":                  ("Exfiltration", 3),
    "CreateSnapshot":             ("Exfiltration", 2),
    "ShareSnapshot":              ("Exfiltration", 3),
    "ModifySnapshotAttribute":    ("Exfiltration", 3),
    "AuthorizeSecurityGroupIngress": ("Lateral/Backdoor", 2),
    "AuthorizeSecurityGroupEgress":  ("Lateral/Backdoor", 2),
    "PutBucketLifecycle":            ("Defense Evasion", 3),
    "PutSubscriptionFilter":         ("Exfiltration", 3),

    # -------------- Impact
    "DeleteBucket":               ("Impact", 4),
    "DeleteObject":               ("Impact", 3),
    "TerminateInstances":         ("Impact", 4),
    "StopInstances":              ("Impact", 3),
    "DeleteDBInstance":           ("Impact", 4),
}

NUM2TXT = {1: "info", 2: "low", 3: "medium", 4: "high"}
TXT_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

# compile wildcard patterns once
WILDCARD = [(re.compile(f"^{k.replace('*', '.*')}$"), v)
            for k, v in CATALOGUE.items() if "*" in k]

EXPECTED = [c.rstrip("_null") for c in (
    "EventTime_null EventName_null UserAgent_null IP_null EventSource_null "
    "userIdentity_Type_null userIdentity_ARN_null userIdentity_userName_null "
    "ErrorCode_null ErrorMessage_null IP_Country_null readOnly_null "
    "requestParameters_null responseElements_null").split()]

# ───────────────────────── Load CSV ─────────────────────────

def load_csv(paths):
    df = pd.concat([pd.read_csv(p, dtype=str, keep_default_na=False) for p in paths],
                   ignore_index=True)
    df.columns = [c.rstrip("_null") for c in df.columns]
    missing = [c for c in EXPECTED if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")
    df["EventTime"] = (pd.to_datetime(df["EventTime"], utc=True, errors="coerce")
                         .dt.tz_localize(None))       # UTC, tz-naïve for Excel
    return df

# ─────────────────────── Classification ──────────────────

def lookup(api):
    if api in CATALOGUE:
        cat, n = CATALOGUE[api]
        return cat, NUM2TXT[n]
    for pat, (cat, n) in WILDCARD:
        if pat.match(api):
            return cat, NUM2TXT[n]
    return "Other", "low"

def rare_tbl(df):
    vc = df["IP"].value_counts(dropna=False)
    return {ip: (n < RARE_IP_THRESHOLD) for ip, n in vc.items()}

def bump(a, b): return a if TXT_ORDER[a] >= TXT_ORDER[b] else b

def classify(row, rare):
    cat, sev = lookup(row["EventName"])
    reasons = [row["EventName"]]

    if rare.get(row["IP"]):                 # rare IP
        sev = bump(sev, "medium")
        reasons.append("RareIP")
    if row.get("IP_Country") in RARE_COUNTRIES:
        sev = bump(sev, "medium")
        reasons.append("ForeignIP")
    if row["ErrorCode"]:
        sev = bump(sev, "medium")
        reasons.append("Error")

    # open SG rule escalation
    if (row["EventName"].startswith("AuthorizeSecurityGroup")
            and "0.0.0.0/0" in row.get("requestParameters", "")):
        sev = bump(sev, "medium")
        reasons.append("OpenSG")

    # short PutBucketLifecycle escalation
    if (row["EventName"] == "PutBucketLifecycle"
            and re.search(r'"Expiration(?:In)?Days"\s*:\s*([0-2])', row["requestParameters"])):
        sev = "high"
        reasons.append("ShortLifecycle")

    row["category"] = cat
    return sev, ";".join(reasons)

# ──────────────────  AWS-recommended IR queries (P1)  ──────────────────

def aws_ir_queries(df: pd.DataFrame) -> pd.DataFrame:
    frames = []

    frames.append(df[df["EventName"].isin(["StopLogging", "DeleteTrail"])]
                  .assign(ir_query="LogTampering"))

    sg = df["EventName"].str.contains("SecurityGroup", case=False, na=False) | \
        df["requestParameters"].str.contains("sg-", na=False)
    frames.append(df[sg].assign(ir_query="NetworkACL_SG"))

    fail_login = (df["EventName"] == "ConsoleLogin") & (df["ErrorCode"] != "")
    frames.append(df[fail_login].assign(ir_query="FailedConsoleLogin"))

    frames.append(df[df["userIdentity_Type"] == "Root"]
                  .assign(ir_query="RootUsage"))

    # 6 – Anonymous S3 GetObject
    anon = (df["EventName"] == "GetObject") & \
           (df["userIdentity_ARN"] == "") & \
           (df["userIdentity_Type"] == "AWSService")
    frames.append(df[anon].assign(ir_query="AnonS3GetObject"))

    # 7 – Bucket deletions
    frames.append(df[df["EventName"] == "DeleteBucket"]
                  .assign(ir_query="DeleteBucket"))

    # 8 – IAM policy changes
    iam_evts = ["AttachUserPolicy", "AttachRolePolicy",
                "PutUserPolicy", "CreatePolicyVersion",
                "CreatePolicy", "PutRolePolicy"]
    frames.append(df[df["EventName"].isin(iam_evts)]
                  .assign(ir_query="IAMPolicyChange"))

    # 9 – KMS tampering
    kms = df["EventName"].isin(["DisableKey", "ScheduleKeyDeletion"])
    frames.append(df[kms].assign(ir_query="KMSTamper"))

    # 10 – Lambda code updates
    frames.append(df[df["EventName"].str.startswith("UpdateFunctionCode")]
                  .assign(ir_query="LambdaCodeUpdate"))

    return pd.concat(frames, ignore_index=True).drop_duplicates()

# ────────────────── AWS-recommended IR queries (P2): Top recurring ErrorCodes (own sheet) ──────────────────

def top_errors(df: pd.DataFrame, n: int = 25) -> pd.DataFrame:
    return (df[df["ErrorCode"] != ""]
            .groupby(["EventName", "ErrorCode"])
            .size()
            .rename("events")
            .reset_index()
            .sort_values("events", ascending=False)
            .head(n))
# ─────────────────────── pivots ──────────────────────────

def pivots(df):
    out = {}
    df["hour"] = df["EventTime"].dt.floor("H")
    hourly = df.groupby("hour").size().rename("events").reset_index()
    out["Hourly_Timeline"] = hourly

    μ, σ = hourly["events"].mean(), hourly["events"].std()
    thr = μ + Z_BURST * σ
    out["Burst_Highlights"] = hourly[hourly["events"] >= thr]\
        .assign(threshold=thr, sigma=σ)

    ip_group = df.groupby("IP")
    ip_stats = (ip_group
                .agg(events=("EventName", "size"),
                     first_seen=("EventTime", "min"),
                     last_seen=("EventTime", "max"))
                .reset_index())

    # most-common country per IP
    ip_stats["country"] = (
        ip_group["IP_Country"]
        .agg(lambda s: s.mode().iat[0] if not s.mode().empty else "")
        .values
    )

    out["IP_Stats"] = ip_stats

    out["User_Stats"] = (df.groupby("userIdentity_userName")
                         .agg(events=("EventName", "size"),
                              first=("EventTime", "min"),
                              last=("EventTime", "max"))
                         .reset_index())
    out["EventName_Counts"] = (df["EventName"].value_counts()
                               .rename_axis("EventName")
                               .reset_index(name="events"))
    return out

# ─────────────────────── workbook ────────────────────────

def write_xlsx(df, out):
    with pd.ExcelWriter(out, engine="openpyxl") as xls:
        df.to_excel(xls, "Raw_Logs", index=False)
        df[df.severity.isin(["medium", "high"])]\
            .to_excel(xls, "Suspicious_Events", index=False)

        for name, frame in pivots(df).items():
            frame.to_excel(xls, name[:31], index=False)

        # AWS IR queries (minus TopErrors)
        aws_ir_queries(df).to_excel(xls, "IR_AWS_Recommended", index=False)

        # NEW: Top recurring errors sheet
        top_errors(df).to_excel(xls, "IR_TopErrors", index=False)

# ─────────────────────── CLI ─────────────────────────────
import sys            # NEW

def build_parser() -> argparse.ArgumentParser:
    """Return a fully-configured argument parser."""
    ap = argparse.ArgumentParser(
        prog="cloudtrail_triage",
        description="CloudTrail DFIR triage → Excel",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("-i", "--input", metavar="FILE", nargs="+", type=Path,
                     help="One or more CloudTrail CSV files")
    grp.add_argument("-d", "--directory", metavar="DIR", type=Path,
                     help="Directory that contains CloudTrail CSV files")
    ap.add_argument("-o", "--output", metavar="FILE", type=Path,
                    default=Path("cloudtrail_triage.xlsx"),
                    help="Destination Excel workbook")
    return ap

def main() -> None:
    parser = build_parser()

    # If the script is launched with no arguments, show help and exit.
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Gather input paths from -i and/or -d
    paths = []
    if args.input:
        paths.extend(args.input)
    if args.directory:
        paths.extend(sorted(args.directory.glob("*.csv")))

    if not paths:
        parser.error("No CSV files found — check -i / -d arguments.")

    df = load_csv(paths)
    rare = rare_tbl(df)
    df["severity"], df["why_flagged"] = zip(
        *df.apply(lambda r: classify(r, rare), axis=1)
    )

    write_xlsx(df, args.output)
    print(f"[+] Workbook written → {args.output.resolve()}")

if __name__ == "__main__":
    main()
