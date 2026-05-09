#!/usr/bin/env python3
"""
oci_audit_parser.py  —  OCI Audit Log Parser
=============================================
Handles the double-encoded JSON structure produced by OCI Logging:
  results[].data  →  JSON string  →  { datetime, logContent: { data:{...}, id, type, time, ... } }

Outputs:
  • NDJSON  (--format ndjson)  — flat records ready for SIEM / Delta Lake ingestion
  • CSV     (--format csv)     — spreadsheet-friendly
  • Pretty  (--format pretty)  — human-readable table to stdout

Usage:
  python3 oci_audit_parser.py  Audit_Logs.json
  python3 oci_audit_parser.py  Audit_Logs.json  --format csv    -o events.csv
  python3 oci_audit_parser.py  Audit_Logs.json  --format ndjson -o events.ndjson
  python3 oci_audit_parser.py  Audit_Logs.json  --format pretty
  python3 oci_audit_parser.py  Audit_Logs.json  --filter-event GetUser
  python3 oci_audit_parser.py  Audit_Logs.json  --filter-status 4
"""

import json
import csv
import sys
import argparse
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Fields that contain raw credential material — strip before output ─────────
REDACT_KEYS = {"credentials", "Authorization", "authorization", "signature"}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def safe_json_loads(value: Any) -> Any:
    """Return parsed JSON if value is a non-empty string, else return as-is."""
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    return value


def flatten(obj: Any, prefix: str = "", sep: str = ".") -> dict:
    """
    Recursively flatten a nested dict/list into dot-notation keys.
    Lists are serialised as compact JSON strings (preserves array data
    without exploding cardinality).
    """
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, dict):
                items.update(flatten(v, new_key, sep))
            elif isinstance(v, list):
                items[new_key] = json.dumps(v, separators=(",", ":"))
            else:
                items[new_key] = v
    else:
        items[prefix] = obj
    return items


def redact(obj: Any) -> Any:
    """Deep-copy a structure, replacing sensitive values with '[REDACTED]'."""
    if isinstance(obj, dict):
        return {
            k: "[REDACTED]" if k in REDACT_KEYS else redact(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(i) for i in obj]
    return obj


def ms_to_iso(ms: Any) -> str:
    """Convert epoch-milliseconds integer to ISO-8601 UTC string."""
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return str(ms)


# ─────────────────────────────────────────────────────────────────────────────
# Core parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_record(raw_data_str: str) -> dict | None:
    """
    Parse one results[].data string through the two layers of JSON encoding
    and return a clean, flat SIEM-ready dict.

    Schema (your actual logs):
      raw_data_str  →  { datetime, logContent: { data:{...}, id, type, time,
                          source, specversion, dataschema,
                          oracle: { compartmentid, ingestedtime, loggroupid, tenantid } } }
    """
    # ── Layer 1: outer string → dict ─────────────────────────────────────────
    try:
        outer = json.loads(raw_data_str)
    except (json.JSONDecodeError, TypeError) as exc:
        print(f"[WARN] outer json.loads failed: {exc}", file=sys.stderr)
        return None

    datetime_ms = outer.get("datetime")
    log_content = outer.get("logContent", {})

    # ── CloudEvents envelope fields ───────────────────────────────────────────
    envelope = {
        "ce_id":          log_content.get("id"),
        "ce_type":        log_content.get("type"),
        "ce_source":      log_content.get("source"),
        "ce_time":        log_content.get("time"),
        "ce_specversion": log_content.get("specversion"),
        "ce_dataschema":  log_content.get("dataschema"),
        "ingested_ms":    datetime_ms,
        "ingested_iso":   ms_to_iso(datetime_ms),
    }

    # ── oracle.* metadata ─────────────────────────────────────────────────────
    oracle_meta = log_content.get("oracle", {}) or {}
    envelope.update({
        "oracle_compartmentid": oracle_meta.get("compartmentid"),
        "oracle_tenantid":      oracle_meta.get("tenantid"),
        "oracle_loggroupid":    oracle_meta.get("loggroupid"),
        "oracle_ingestedtime":  oracle_meta.get("ingestedtime"),
    })

    # ── data block — the actual audit event ──────────────────────────────────
    data = log_content.get("data", {}) or {}

    # Top-level scalar fields
    event_fields = {
        "eventName":        data.get("eventName"),
        "message":          data.get("message"),
        "compartmentId":    data.get("compartmentId"),
        "compartmentName":  data.get("compartmentName"),
        "availabilityDomain": data.get("availabilityDomain"),
        "resourceId":       data.get("resourceId"),
        "eventGroupingId":  data.get("eventGroupingId"),
    }

    # identity sub-object (redact credentials)
    identity = redact(data.get("identity", {}) or {})
    id_fields = {
        "identity_principalId":   identity.get("principalId"),
        "identity_principalName": identity.get("principalName"),
        "identity_ipAddress":     identity.get("ipAddress"),
        "identity_userAgent":     identity.get("userAgent"),
        "identity_authType":      identity.get("authType"),
        "identity_callerId":      identity.get("callerId"),
        "identity_callerName":    identity.get("callerName"),
        "identity_tenantId":      identity.get("tenantId"),
    }

    # request sub-object (strip auth headers)
    request = redact(data.get("request", {}) or {})
    req_headers = request.get("headers", {}) or {}
    req_fields = {
        "request_id":         request.get("id"),
        "request_action":     request.get("action"),
        "request_path":       request.get("path"),
        "request_parameters": json.dumps(request.get("parameters") or {}, separators=(",", ":")),
        "request_opcRequestId": (req_headers.get("opc-request-id") or
                                  req_headers.get("Opc-Request-Id") or [""])[0]
                                if isinstance(req_headers.get("opc-request-id") or
                                               req_headers.get("Opc-Request-Id"), list)
                                else req_headers.get("opc-request-id") or
                                     req_headers.get("Opc-Request-Id"),
    }

    # response sub-object
    response = data.get("response", {}) or {}
    resp_fields = {
        "response_status":       response.get("status"),
        "response_responseTime": response.get("responseTime"),
        "response_message":      response.get("message"),
        "response_payload":      json.dumps(response.get("payload") or {}, separators=(",", ":")),
    }

    # additionalDetails — varies by service, flatten whatever is there
    additional = data.get("additionalDetails", {}) or {}
    add_fields = {f"additionalDetails_{k}": v for k, v in (additional.items() if isinstance(additional, dict) else {})}

    # tags
    tag_fields = {
        "definedTags":  json.dumps(data.get("definedTags") or {}, separators=(",", ":")),
        "freeformTags": json.dumps(data.get("freeformTags") or {}, separators=(",", ":")),
    }

    # stateChange
    state = data.get("stateChange") or {}
    state_fields = {
        "stateChange_current":  json.dumps(state.get("current"), separators=(",", ":")) if state else "null",
        "stateChange_previous": json.dumps(state.get("previous"), separators=(",", ":")) if state else "null",
    }

    # ── Assemble final flat record ────────────────────────────────────────────
    record = {}
    record.update(envelope)
    record.update(event_fields)
    record.update(id_fields)
    record.update(req_fields)
    record.update(resp_fields)
    record.update(add_fields)
    record.update(tag_fields)
    record.update(state_fields)

    return record


def parse_file(path: str) -> tuple[list[dict], dict]:
    """
    Load an OCI audit log export file and return (records, summary).
    Handles both:
      • Standard export:  {"results": [{"data": "<json_str>"}, ...], "summary": {...}}
      • NDJSON stream:    one JSON object per line
    """
    text = Path(path).read_text(encoding="utf-8")

    # Try standard export format first
    try:
        root = json.loads(text)
        if isinstance(root, dict) and "results" in root:
            summary = root.get("summary", {})
            results = root["results"]
            records = []
            errors = 0
            for i, item in enumerate(results):
                raw = item.get("data")
                if raw is None:
                    print(f"[WARN] result[{i}] has no 'data' key — skipping", file=sys.stderr)
                    errors += 1
                    continue
                record = parse_record(raw)
                if record:
                    records.append(record)
                else:
                    errors += 1
            summary["parse_errors"] = errors
            return records, summary
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON (one record per line)
    records = []
    errors = 0
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            raw = item.get("data", line)
            record = parse_record(raw if isinstance(raw, str) else json.dumps(raw))
            if record:
                records.append(record)
            else:
                errors += 1
        except json.JSONDecodeError as exc:
            print(f"[WARN] line {i} JSON error: {exc}", file=sys.stderr)
            errors += 1

    return records, {"resultCount": len(records), "parse_errors": errors}


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

def write_ndjson(records: list[dict], out) -> None:
    for rec in records:
        out.write(json.dumps(rec, default=str) + "\n")


def write_csv(records: list[dict], out) -> None:
    if not records:
        return
    # Union of all keys across records (order: keys from first record first)
    all_keys = list(dict.fromkeys(k for rec in records for k in rec))
    writer = csv.DictWriter(out, fieldnames=all_keys, extrasaction="ignore",
                             lineterminator="\n")
    writer.writeheader()
    for rec in records:
        writer.writerow({k: ("" if v is None else v) for k, v in rec.items()})


def write_pretty(records: list[dict]) -> None:
    """Print a human-readable summary table to stdout."""
    COL = {
        "ce_time":                22,
        "eventName":              36,
        "identity_principalName": 24,
        "identity_ipAddress":     16,
        "request_action":          6,
        "request_path":           42,
        "response_status":         6,
    }
    header = "  ".join(f"{h:<{w}}" for h, w in COL.items())
    sep    = "  ".join("-" * w for w in COL.values())
    print(f"\n{'OCI Audit Events':^{len(header)}}")
    print(sep)
    print(header)
    print(sep)
    for rec in records:
        row = "  ".join(
            f"{str(rec.get(h, '') or '')[:w]:<{w}}"
            for h, w in COL.items()
        )
        print(row)
    print(sep)
    print(f"\nTotal events: {len(records)}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Filters
# ─────────────────────────────────────────────────────────────────────────────

def apply_filters(records: list[dict], args: argparse.Namespace) -> list[dict]:
    if args.filter_event:
        records = [r for r in records
                   if (r.get("eventName") or "").lower() == args.filter_event.lower()
                   or args.filter_event.lower() in (r.get("ce_type") or "").lower()]
    if args.filter_principal:
        records = [r for r in records
                   if args.filter_principal.lower() in
                      (r.get("identity_principalName") or "").lower()]
    if args.filter_status:
        records = [r for r in records
                   if str(r.get("response_status") or "").startswith(str(args.filter_status))]
    if args.filter_service:
        records = [r for r in records
                   if args.filter_service.lower() in (r.get("ce_type") or "").lower()]
    return records


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse OCI Audit Log JSON exports into flat SIEM-ready records.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("input", help="Path to OCI audit log JSON file")
    p.add_argument("-f", "--format", choices=["ndjson", "csv", "pretty"],
                   default="pretty", help="Output format (default: pretty)")
    p.add_argument("-o", "--output", default=None,
                   help="Output file path (default: stdout)")

    # Filters
    p.add_argument("--filter-event",     metavar="EVENT",
                   help="Keep only events matching this eventName (e.g. GetUser)")
    p.add_argument("--filter-principal", metavar="NAME",
                   help="Keep only events by this principal (substring match)")
    p.add_argument("--filter-status",    metavar="CODE",
                   help="Keep only events whose HTTP status starts with CODE (e.g. 4 for 4xx)")
    p.add_argument("--filter-service",   metavar="SVC",
                   help="Keep only events matching this service (e.g. objectstorage)")

    p.add_argument("--stats", action="store_true",
                   help="Print event-type frequency summary after processing")
    return p


def main():
    args = build_parser().parse_args()

    print(f"[INFO] Loading {args.input} ...", file=sys.stderr)
    records, summary = parse_file(args.input)
    print(f"[INFO] Parsed {len(records)} records  |  summary: {summary}", file=sys.stderr)

    records = apply_filters(records, args)
    print(f"[INFO] After filters: {len(records)} records", file=sys.stderr)

    if args.stats:
        from collections import Counter
        counts = Counter(r.get("eventName") or r.get("ce_type", "unknown") for r in records)
        print("\n── Event frequency ──────────────────────────────", file=sys.stderr)
        for event, count in counts.most_common():
            print(f"  {count:>5}  {event}", file=sys.stderr)
        print("─────────────────────────────────────────────────\n", file=sys.stderr)

    # ── Write output ──────────────────────────────────────────────────────────
    if args.format == "pretty":
        write_pretty(records)
        return

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            if args.format == "ndjson":
                write_ndjson(records, fh)
            else:
                write_csv(records, fh)
        print(f"[INFO] Wrote {args.output}", file=sys.stderr)
    else:
        buf = io.StringIO()
        if args.format == "ndjson":
            write_ndjson(records, buf)
        else:
            write_csv(records, buf)
        print(buf.getvalue())


if __name__ == "__main__":
    main()
