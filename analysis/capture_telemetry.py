"""
capture_telemetry.py — polls a running threat-engine instance's API and
writes captured alerts + periodic stats snapshots to CSV, for the offline
analysis in analyze_alerts.py / analysis.ipynb.

This is the data-analyst layer's actual data source: real output from the
real engine (running against the in-sandbox simulator's injected attack
patterns), not synthetic data invented for the analysis.

Usage:
    python3 capture_telemetry.py --duration 60 --base http://localhost:8080 --token dev-token-change-me
"""
import argparse
import csv
import time
import urllib.request
import json


def fetch_json(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--token", default="dev-token-change-me")
    ap.add_argument("--duration", type=int, default=60, help="seconds to poll for")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--alerts-out", default="alerts.csv")
    ap.add_argument("--stats-out", default="stats_timeseries.csv")
    args = ap.parse_args()

    seen_ids = set()
    alert_rows = []
    stats_rows = []

    end = time.time() + args.duration
    while time.time() < end:
        t0 = time.time()
        try:
            stats = fetch_json(f"{args.base}/stats", args.token)
            stats_rows.append({"poll_time": t0, **stats})

            alerts = fetch_json(f"{args.base}/alerts?limit=2000", args.token)
            for a in alerts:
                key = (a["id"], a["detector"], a["rule_name"], a["timestamp_ms"])
                if key not in seen_ids:
                    seen_ids.add(key)
                    alert_rows.append(a)
        except Exception as e:
            print("poll error:", e)
        time.sleep(max(0.0, args.interval - (time.time() - t0)))

    if alert_rows:
        with open(args.alerts_out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(alert_rows[0].keys()))
            w.writeheader()
            w.writerows(alert_rows)
    if stats_rows:
        with open(args.stats_out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(stats_rows[0].keys()))
            w.writeheader()
            w.writerows(stats_rows)

    print(f"captured {len(alert_rows)} unique alerts, {len(stats_rows)} stats snapshots")


if __name__ == "__main__":
    main()
