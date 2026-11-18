"""
File Integrity Monitor (FIM) — tripwire-style checker.

Hashes every file under a target directory with SHA-256, stores a baseline,
then lets you re-check the directory later to detect:
  - modified files (hash changed)
  - new files (not in baseline)
  - deleted files (in baseline, missing now)

Usage:
    python integrity_checker.py init  <directory> [--baseline baseline.json]
    python integrity_checker.py check <directory> [--baseline baseline.json]

Exit code on `check`: 0 if nothing changed, 1 if any change was detected
(useful for wiring this into a cron job or CI pipeline that alerts on
non-zero exit).
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


def hash_file(path, chunk_size=65536):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_directory(directory):
    """Returns {relative_path: sha256_hash} for every file under directory."""
    hashes = {}
    for root, _dirs, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, directory)
            try:
                hashes[rel_path] = hash_file(full_path)
            except (PermissionError, FileNotFoundError) as e:
                print(f"  [warn] skipped {rel_path}: {e}", file=sys.stderr)
    return hashes


def cmd_init(args):
    directory = args.directory
    hashes = scan_directory(directory)
    baseline = {
        "directory": os.path.abspath(directory),
        "created": datetime.now(timezone.utc).isoformat(),
        "files": hashes,
    }
    with open(args.baseline, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"Baseline created: {len(hashes)} files recorded -> {args.baseline}")


def cmd_check(args):
    if not os.path.exists(args.baseline):
        print(f"No baseline found at {args.baseline}. Run 'init' first.", file=sys.stderr)
        sys.exit(2)

    with open(args.baseline) as f:
        baseline = json.load(f)

    old_hashes = baseline["files"]
    new_hashes = scan_directory(args.directory)

    old_paths = set(old_hashes)
    new_paths = set(new_hashes)

    modified = sorted(p for p in old_paths & new_paths if old_hashes[p] != new_hashes[p])
    added = sorted(new_paths - old_paths)
    deleted = sorted(old_paths - new_paths)

    print(f"Checked against baseline from {baseline.get('created', 'unknown')}")
    print(f"Directory: {args.directory}\n")

    if not (modified or added or deleted):
        print("No changes detected. All files match the baseline.")
        sys.exit(0)

    if modified:
        print(f"MODIFIED ({len(modified)}):")
        for p in modified:
            print(f"  ~ {p}")
    if added:
        print(f"NEW ({len(added)}):")
        for p in added:
            print(f"  + {p}")
    if deleted:
        print(f"DELETED ({len(deleted)}):")
        for p in deleted:
            print(f"  - {p}")

    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="SHA-256 file integrity monitor.")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="Create a baseline for a directory.")
    init_parser.add_argument("directory")
    init_parser.add_argument("--baseline", default="baseline.json")
    init_parser.set_defaults(func=cmd_init)

    check_parser = sub.add_parser("check", help="Check a directory against its baseline.")
    check_parser.add_argument("directory")
    check_parser.add_argument("--baseline", default="baseline.json")
    check_parser.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
