"""
analyze_alerts.py — the data-analyst deliverable: takes captured telemetry
(alerts.csv, stats_timeseries.csv from capture_telemetry.py) and produces:
  1. Throughput analysis (events/sec over the capture window)
  2. Alert severity distribution
  3. Alert volume by detector (signature vs anomaly vs CEP)
  4. A simple false-positive-rate discussion grounded in what the rules
     actually check for, since this capture has no independent ground-truth
     labels to compute a true FP rate against (see FINDINGS.md for why that
     matters and what a real deployment would add: a labeled dataset).

Run after capture_telemetry.py, from the analysis/ directory:
    python3 analyze_alerts.py
Outputs PNG charts into analysis/charts/.
"""
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

CHART_DIR = "charts"
os.makedirs(CHART_DIR, exist_ok=True)


def load():
    alerts = pd.read_csv("alerts.csv")
    stats = pd.read_csv("stats_timeseries.csv")
    alerts["ts"] = pd.to_datetime(alerts["timestamp_ms"], unit="ms")
    stats["ts"] = pd.to_datetime(stats["poll_time"], unit="s")
    return alerts, stats


def throughput_chart(stats):
    stats = stats.sort_values("poll_time").reset_index(drop=True)
    stats["d_events"] = stats["events_processed"].diff()
    stats["d_time"] = stats["poll_time"].diff()
    stats["events_per_sec"] = stats["d_events"] / stats["d_time"]

    fig, ax = plt.subplots(figsize=(9, 3.5))
    ax.plot(stats["ts"], stats["events_per_sec"], color="#2a9d8f", linewidth=1.6)
    ax.set_title("Sustained ingestion throughput during capture window")
    ax.set_ylabel("events / sec")
    ax.set_xlabel("time")
    fig.tight_layout()
    fig.savefig(f"{CHART_DIR}/throughput.png", dpi=140)
    plt.close(fig)

    return {
        "mean_eps": stats["events_per_sec"].mean(),
        "p50_eps": stats["events_per_sec"].median(),
        "p99_eps": stats["events_per_sec"].quantile(0.99),
        "max_eps": stats["events_per_sec"].max(),
        "total_dropped": int(stats["events_dropped"].iloc[-1]) if len(stats) else 0,
    }


def severity_chart(alerts):
    order = ["Critical", "High", "Medium", "Low"]
    counts = alerts["severity"].value_counts().reindex(order).fillna(0)
    colors = {"Critical": "#e63946", "High": "#f4a261", "Medium": "#e9c46a", "Low": "#457b9d"}

    fig, ax = plt.subplots(figsize=(5, 3.5))
    ax.bar(counts.index, counts.values, color=[colors[s] for s in counts.index])
    ax.set_title("Alerts by severity")
    ax.set_ylabel("count")
    fig.tight_layout()
    fig.savefig(f"{CHART_DIR}/severity_distribution.png", dpi=140)
    plt.close(fig)
    return counts.to_dict()


def detector_chart(alerts):
    counts = alerts["detector"].value_counts()
    fig, ax = plt.subplots(figsize=(5, 3.5))
    ax.bar(counts.index, counts.values, color="#264653")
    ax.set_title("Alerts by detector")
    ax.set_ylabel("count")
    fig.tight_layout()
    fig.savefig(f"{CHART_DIR}/detector_distribution.png", dpi=140)
    plt.close(fig)
    return counts.to_dict()


def rule_breakdown(alerts):
    return alerts.groupby(["detector", "rule_name"]).size().sort_values(ascending=False)


def main():
    alerts, stats = load()
    tp = throughput_chart(stats)
    sev = severity_chart(alerts)
    det = detector_chart(alerts)
    rules = rule_breakdown(alerts)

    print("=== Throughput ===")
    for k, v in tp.items():
        print(f"  {k}: {v:.1f}" if isinstance(v, float) else f"  {k}: {v}")

    print("\n=== Severity distribution ===")
    for k, v in sev.items():
        print(f"  {k}: {int(v)}")

    print("\n=== Detector distribution ===")
    for k, v in det.items():
        print(f"  {k}: {v}")

    print("\n=== Per-rule breakdown ===")
    print(rules.to_string())

    print(f"\nCharts written to {CHART_DIR}/")


if __name__ == "__main__":
    main()
