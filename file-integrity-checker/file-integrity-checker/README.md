# File Integrity Checker (Tripwire-style FIM)

A small SHA-256-based file integrity monitor. Records a hash "baseline" of a
directory, then later re-checks it to detect modified, new, or deleted
files — the same core idea behind tools like Tripwire, AIDE, and the file
integrity monitoring (FIM) modules in commercial EDR products.

## Why this matters

If malware drops a new binary, modifies a config file, or replaces a system
file with a backdoored version, a FIM tool is one of the few ways you'd
actually notice — especially for changes that don't trigger an AV signature.
It's also used defensively in compliance contexts (PCI-DSS, for example,
requires FIM on in-scope systems).

## Usage

```bash
# Create a baseline of a directory
python integrity_checker.py init demo

# ... later, after files may have changed ...
python integrity_checker.py check demo
```

By default the baseline is saved to `baseline.json` in the current
directory; override with `--baseline path/to/file.json` if you want to keep
baselines for multiple directories.

## Demo walkthrough

The `demo/` folder ships with three sample files. To see the tool catch a
change:

```bash
python integrity_checker.py init demo --baseline demo_baseline.json

# simulate an attacker/accidental change:
echo "unauthorized change" >> demo/notes.txt
rm demo/old_report.txt
echo "dropped payload" > demo/new_file.txt

python integrity_checker.py check demo --baseline demo_baseline.json
```

Expected output:

```
MODIFIED (1):
  ~ notes.txt
NEW (1):
  + new_file.txt
DELETED (1):
  - old_report.txt
```

The process also exits with status code `1` when changes are found (`0` if
clean), so it can be wired into a cron job or CI step that alerts on
non-zero exit — e.g. `integrity_checker.py check /etc || send_alert.sh`.

## How it works

- `scan_directory()` walks the target directory and computes a SHA-256 hash
  of every file's contents.
- `init` saves that map (`path -> hash`) as a JSON baseline, along with a
  timestamp.
- `check` recomputes the current hashes and diffs them against the
  baseline's `path -> hash` map using simple set operations to classify
  changes as modified / new / deleted.

## Limitations & possible extensions (good "future work" material)

- No protection for the baseline file itself — if an attacker can modify
  `baseline.json`, they can hide their tracks. A real implementation would
  sign the baseline or store it somewhere read-only to the monitored host.
- No real-time monitoring — this is a point-in-time snapshot/diff, not a
  live watcher. Extending it with `watchdog` (Python) or `inotify` (Linux)
  would make it event-driven.
- No alerting integration — exit code is there, but wiring it to email/Slack
  webhooks would make it operational.
- Only tracks content hash, not metadata like permissions or ownership,
  which attackers sometimes change without touching file contents.

## Suggested screenshots for your write-up
1. `init` output showing the baseline being created.
2. The three change types shown in `demo/` (modify, add, delete).
3. `check` output flagging all three.
4. `echo $?` after a clean run (0) vs a run with changes (1).
