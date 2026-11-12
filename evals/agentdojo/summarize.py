"""Print a Markdown table from evals/results/agentdojo-*.json.

    evals/agentdojo/.venv/bin/python evals/agentdojo/summarize.py

Tables in the docs are pasted from this output, never typed by hand.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "results"


def pct(part: int | None, whole: int | None) -> str:
    if not whole or part is None:
        return "n/a"
    return f"{100 * part / whole:.1f}% ({part}/{whole})"


def guard_label(g: dict) -> str:
    if g["mode"] == "off":
        return "off"
    parts = []
    if g["mode"] in ("policy", "both"):
        parts.append("policy: " + ("per-task (oracle)" if g["policy_kind"] == "task" else "suite allow-list"))
    if g["mode"] in ("scan", "both"):
        parts.append("scan: " + g["scan"] + (f" ({g['judge_model']})" if g.get("judge_model") else ""))
    return "; ".join(parts)


def main() -> None:
    rows = []
    for path in sorted(RESULTS.glob("agentdojo-*.json")):
        r = json.loads(path.read_text())
        t, agent = r["totals"], r["agent"]
        benign, attack = t.get("benign", {}), t.get("under_attack", {})
        medians = [s["latency"]["added_ms_median"] for s in r["suites"].values() if s["latency"].get("calls")]
        p95s = [s["latency"]["added_ms_p95"] for s in r["suites"].values() if s["latency"].get("calls")]
        scripted = agent["type"] != "llm"
        rows.append(
            [
                (agent["model"] or "none (scripted)") + ("" if r.get("scope", "full benchmark") == "full benchmark" else " — " + ", ".join(r["suites"]) + f" ({benign.get('tasks', 0)} tasks, {attack.get('pairs', 0)} pairs)"),
                guard_label(r["guard"]),
                pct(benign.get("utility"), benign.get("tasks")),
                pct(attack.get("utility"), attack.get("pairs")),
                "not measurable" if scripted else pct(attack.get("attack_successes"), attack.get("pairs")),
                pct(attack.get("injected_results_quarantined"), attack.get("injected_results")),
                pct(benign.get("quarantined_calls"), benign.get("tool_calls")),
                pct(benign.get("denied_calls"), benign.get("tool_calls")),
                f"{statistics.median(medians):.3f} / {max(p95s):.3f}" if medians else "n/a",
                r["date_utc"][:10] + ("" if r["complete_run"] else " (partial)" if r.get("finished", True) else " (UNFINISHED)"),
                path.name,
            ]
        )

    header = [
        "Agent model", "Guard", "Benign utility", "Utility under attack", "Attack success",
        "Injected results quarantined", "Benign results quarantined", "Benign calls denied",
        "Added ms per call (median of suite medians / worst suite p95)", "Date", "File",
    ]  # fmt: skip
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for row in rows:
        print("| " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
