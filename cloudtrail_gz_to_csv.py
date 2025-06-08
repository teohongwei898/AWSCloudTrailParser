#!/usr/bin/env python3
"""
cloudtrail_gz_to_csv.py  –  Convert AWS CloudTrail *.json.gz objects to CSV.

Usage examples
--------------
# convert one local file
python cloudtrail_gz_to_csv.py \
       -i 111122223333_CloudTrail_us-east-2_20150801T0210Z_*.json.gz \
       -o cloudtrail_2015-08-01.csv

# convert an entire date prefix on S3
python cloudtrail_gz_to_csv.py \
       -i s3://my-trail-bucket/AWSLogs/111122223333/CloudTrail/us-east-2/2025/06/08/ \
       -o 2025-06-08_cloudtrail.csv
"""
import argparse
import gzip
import json
import sys
import re
from pathlib import Path
from typing import Iterable, Dict, Union, List

try:
    import boto3
    from botocore.exceptions import ClientError
except ModuleNotFoundError:
    boto3 = None  # only needed for s3:// inputs

# -------------------------------------------------------------------
CSV_FIELDS = [
    "EventTime", "EventName", "UserAgent", "IP", "EventSource",
    "userIdentity_Type", "userIdentity_ARN", "userIdentity_userName",
    "ErrorCode", "ErrorMessage", "IP_Country", "readOnly",
    "requestParameters", "responseElements",
]
S3_RE = re.compile(r"^s3://([^/]+)/(.+)$")

# -------------------------------------------------------------------


def iter_s3_objects(uri: str) -> Iterable[bytes]:
    """Yield decompressed bytes for every *.json.gz object under an S3 key/prefix."""
    if boto3 is None:
        raise RuntimeError(
            "boto3 is required for s3:// sources (pip install boto3)")
    bucket, key = S3_RE.match(uri).groups()
    s3 = boto3.resource("s3")
    bucket_obj = s3.Bucket(bucket)

    # if key ends with ".json.gz" treat as single object; else iterate prefix
    objs = [key] if key.endswith(".json.gz") else \
        (o.key for o in bucket_obj.objects.filter(Prefix=key))
    for obj_key in objs:
        if not obj_key.endswith(".json.gz"):
            continue
        buf = bucket_obj.Object(obj_key).get()["Body"].read()
        yield gzip.decompress(buf)


def iter_local_files(path_str: str) -> Iterable[bytes]:
    """Yield decompressed bytes for every matching local *.json.gz file."""
    paths = Path().glob(path_str) if "*" in path_str else [Path(path_str)]
    for p in paths:
        if p.is_dir():
            for child in p.rglob("*.json.gz"):
                yield gzip.open(child, "rb").read()
        elif p.suffix == ".gz":
            yield gzip.open(p, "rb").read()


def iterate_inputs(inputs: List[str]) -> Iterable[bytes]:
    """Dispatch input sources to local / s3 iterators."""
    for spec in inputs:
        if S3_RE.match(spec):
            yield from iter_s3_objects(spec)
        else:
            yield from iter_local_files(spec)

# -------------------------------------------------------------------


def flatten(record: Dict) -> Dict[str, Union[str, None]]:
    """Extract and normalise the fields our downstream parser expects."""
    ui = record.get("userIdentity", {})
    out = {
        "EventTime":      record.get("eventTime"),
        "EventName":      record.get("eventName"),
        "UserAgent":      record.get("userAgent", ""),
        "IP":             record.get("sourceIPAddress", ""),
        "EventSource":    record.get("eventSource", ""),
        "userIdentity_Type":      ui.get("type", ""),
        "userIdentity_ARN":       ui.get("arn", ""),
        "userIdentity_userName":  ui.get("userName", ""),
        "ErrorCode":      record.get("errorCode", ""),
        "ErrorMessage":   record.get("errorMessage", ""),
        "IP_Country":     "",  # CloudTrail raw does not include geo
        "readOnly":       str(record.get("readOnly", "")),
        # serialise request/response JSON blobs for triage readability
        "requestParameters":  json.dumps(record.get("requestParameters", {}),
                                         ensure_ascii=False),
        "responseElements":   json.dumps(record.get("responseElements", {}),
                                         ensure_ascii=False),
    }
    # normalise None → empty string
    return {k: ("" if v is None else v) for k, v in out.items()}

# -------------------------------------------------------------------


def write_csv(records: Iterable[Dict[str, str]], out_path: Path):
    import csv
    out_fh = sys.stdout if out_path == Path(
        "-") else open(out_path, "w", newline="", encoding="utf-8")
    with out_fh as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)

# -------------------------------------------------------------------


def parse_args():
    ap = argparse.ArgumentParser(
        description="Convert CloudTrail *.json.gz to CSV")
    ap.add_argument("-i", "--input", nargs="+", required=True,
                    help="Local glob, directory, file, or s3:// URI(s)")
    ap.add_argument("-o", "--output", default="-",
                    help="CSV file to write (default: stdout). Use '-' for stdout.")
    return ap.parse_args()


def main():
    args = parse_args()
    flat_records = (flatten(json.loads(blob)["Records"][idx])
                    for blob in iterate_inputs(args.input)
                    for idx in range(len(json.loads(blob)["Records"])))
    write_csv(flat_records, Path(args.output))


if __name__ == "__main__":
    main()
