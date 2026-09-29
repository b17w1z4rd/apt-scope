import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from .intel import actor_list, hunt, load, timestamp


def write(report, directory):
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    def safe(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("`", "'")
    def defang(value):
        return safe(value).replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")
    lines = ["# APT Scope", "", "Actor: " + safe(report["actor"]["name"]), "", "Candidate infrastructure; attribution and liveness require review.", "",
             "| Type | Defanged value | Stale only | Shared association |", "| --- | --- | --- | --- |"]
    for row in report["candidates"]:
        lines.append(f"| {row['type']} | {defang(row['value'])} | {row['stale_only']} | {row['shared_association']} |")
    lines.extend(["", *["- " + s for s in report["limitations"]], "", "Evidence paths, references and markings are in report.json.", ""])
    for name, body in (("report.json", json.dumps(report, indent=2)+"\n"), ("report.md", "\n".join(lines))):
        with os.fdopen(os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(body)


def main():
    parser = argparse.ArgumentParser(description="APT infrastructure candidates from attributed STIX intelligence")
    sub = parser.add_subparsers(dest="command", required=True)
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("config")
    refresh_parser.add_argument("--out", default="cache")
    actors = sub.add_parser("actors")
    actors.add_argument("--bundle", action="append", required=True)
    scan = sub.add_parser("hunt")
    scan.add_argument("actor")
    scan.add_argument("--bundle", action="append", required=True)
    scan.add_argument("--out", default="reports/latest")
    scan.add_argument("--max-age-days", type=int, default=180)
    scan.add_argument("--as-of")
    args = parser.parse_args()
    try:
        if args.command == "refresh":
            from .feeds import refresh
            result = refresh(args.config, args.out)
            print(json.dumps(result, indent=2))
            return 0 if result["complete"] else 2
        if args.command == "actors":
            print(json.dumps(actor_list(load(args.bundle)[0]), indent=2))
            return 0
        report = hunt(args.bundle, args.actor, timestamp(args.as_of) if args.as_of else None, args.max_age_days)
        write(report, args.out)
        print(json.dumps({"actor": report["actor"], "candidates": report["candidate_count"],
                          "unsupported_patterns": report["unsupported_patterns"], "warnings": report["warnings"]}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Unable to complete: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
