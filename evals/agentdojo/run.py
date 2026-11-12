"""Run AgentDojo with every tool call routed through MCP Guard.

Examples (from the repository root; PY=evals/agentdojo/.venv/bin/python):

    # Plumbing check and gateway-side measurements; no model, no cost.
    $PY evals/agentdojo/run.py --agent ground-truth --guard both

    # A model as the agent. Bring your own; nothing is bundled or hosted.
    $PY evals/agentdojo/run.py --agent llm --provider google    --model gemini-3.6-flash --guard off
    $PY evals/agentdojo/run.py --agent llm --provider ollama    --model qwen3.5:4b       --guard off
    $PY evals/agentdojo/run.py --agent llm --provider anthropic --model <model id>       --guard off
    $PY evals/agentdojo/run.py --agent llm --provider openai    --model <model id>       --guard off

Credentials are read by each provider's own SDK from its usual environment
variable (GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY). This script
never reads, prints or stores them. Ollama needs none.

A run that stops (rate limit, daily quota, Ctrl-C) can be continued:

    $PY evals/agentdojo/run.py --resume evals/agentdojo/runs/<run id>

Each run writes one JSON file under evals/results/. Every number quoted
anywhere else must come from such a file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from agentdojo import models as agentdojo_models
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suites

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement

from bridge import BridgeServer, GatewayClient, GatewayGroundTruth, GatewayToolsExecutor, squash

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
GUARD_MODES = ("off", "policy", "scan", "both")
START_DIR = Path.cwd()  # where the command was typed; relative --resume paths are relative to this


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False).stdout.strip()


def build_gateway(out_dir: Path) -> Path:
    binary = out_dir / "mcpguard"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/mcpguard"], cwd=ROOT, check=True)
    return binary


# --------------------------------------------------------------------------
# Policies
# --------------------------------------------------------------------------


def task_token(suite_name: str, task_id: str) -> str:
    """A fixed, public test token. The gateway only ever sees its hash."""
    return f"agentdojo-{suite_name}-{task_id}-not-a-secret"


def write_policy(path: Path, suite, suite_name: str, kind: str) -> dict[str, list[str]]:
    """Writes the policy for one suite and returns {agent name: allowed tools}.

    kind "suite": one identity per task, each allowed every tool in the suite.
        This is what a deployment that simply allow-lists a server's tools has.
    kind "task": one identity per task, allowed only the tools that task's
        ground-truth solution uses. This is least privilege with perfect
        foresight -- an ORACLE upper bound on what tool allow-listing can do,
        not something a real operator could write in advance.
    """
    all_tools = sorted(f.name for f in suite.tools)
    allowed: dict[str, list[str]] = {}
    for task_id, task in suite.user_tasks.items():
        if kind == "task":
            env = task.init_environment(suite.load_and_inject_default_environment({}))
            tools = sorted({call.function for call in task.ground_truth(env)})
        else:
            tools = all_tools
        allowed[task_id] = tools

    lines = ["version: 1", "agents:"]
    for task_id, tools in allowed.items():
        lines += [
            f"  - name: {task_id}",
            f"    token_sha256: {sha256_hex(task_token(suite_name, task_id))}",
            "    servers:",
            f"      {suite_name}:",
        ]
        if tools:
            lines.append("        tools:")
            lines += [f"          {tool}: {{}}" for tool in tools]
        else:
            lines[-1] += " {}"
    path.write_text("\n".join(lines) + "\n")
    return allowed


# --------------------------------------------------------------------------
# Gateway process
# --------------------------------------------------------------------------


class Gateway:
    def __init__(self, binary: Path, run_dir: Path, suite_name: str, upstream: str, args, policy: Path | None):
        self.port = free_port()
        self.audit_db = run_dir / f"audit-{suite_name}.db"
        self.log_path = run_dir / f"gateway-{suite_name}.log"
        self.flags = ["-listen", f"127.0.0.1:{self.port}", "-upstream", f"{suite_name}={upstream}",
                      "-audit-db", str(self.audit_db)]  # fmt: skip
        self.flags += ["-policy", str(policy)] if policy else ["-insecure-allow-all"]
        if args.guard in ("scan", "both"):
            self.flags += ["-scan", args.scan]
            if "judge" in args.scan:
                self.flags += ["-judge-model", args.judge_model]
        else:
            self.flags += ["-scan", "off"]
        self.binary = binary
        self.endpoint = f"http://127.0.0.1:{self.port}/{suite_name}/mcp"
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        self._log = self.log_path.open("w")
        self._proc = subprocess.Popen([str(self.binary), *self.flags], stdout=self._log, stderr=self._log)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"gateway exited at startup; see {self.log_path}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("gateway did not become healthy")

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(timeout=10)
            self._log.close()

    def audit_records(self) -> list[dict]:
        out = subprocess.run([str(self.binary), "audit", "export", "-db", str(self.audit_db)],
                             capture_output=True, text=True, check=True)  # fmt: skip
        return [json.loads(line)["record"] for line in out.stdout.splitlines() if line.strip()]


def latency_stats(records: list[dict]) -> dict:
    """Time the gateway itself added to each forwarded tool call:
    total time minus time in the MCP server minus time waiting for a human.
    Scanning (rules and judge) counts as added time."""
    added, scan = [], []
    for r in records:
        if r.get("rpc_method") != "tools/call" or not r.get("upstream_us"):
            continue
        added.append((r["duration_us"] - r["upstream_us"] - r.get("approval_wait_us", 0)) / 1000)
        if r.get("scanned"):
            scan.append(r.get("scan_us", 0) / 1000)
    if not added:
        return {"calls": 0}
    added.sort()
    return {
        "calls": len(added),
        "added_ms_median": round(statistics.median(added), 3),
        "added_ms_p95": round(added[min(len(added) - 1, int(len(added) * 0.95))], 3),
        "added_ms_mean": round(statistics.fmean(added), 3),
        "scan_ms_median": round(statistics.median(scan), 3) if scan else None,
    }


# --------------------------------------------------------------------------
# Running tasks
# --------------------------------------------------------------------------


PROVIDERS = ("google", "ollama", "anthropic", "openai")
PROSE_NAMES = {"google": "Gemini", "anthropic": "Claude", "openai": "GPT-4", "ollama": "AI assistant"}


class QuotaExhausted(RuntimeError):
    """The provider kept refusing requests; stop and resume later."""


def is_rate_limit(error: Exception) -> bool:
    code = getattr(error, "status_code", None) or getattr(error, "code", None)
    text = f"{type(error).__name__} {error}".lower()
    return code == 429 or "resource_exhausted" in text or "ratelimit" in text or "rate limit" in text or "quota" in text


class ThrottledLLM(BasePipelineElement):
    """Wraps a model element with a requests-per-minute cap and patient
    retries on rate-limit errors, so free tiers and small quotas are usable."""

    def __init__(self, llm: BasePipelineElement, rpm: float, max_retries: int) -> None:
        self.llm = llm
        self.name = getattr(llm, "name", None)
        self.interval = 60.0 / rpm if rpm > 0 else 0.0
        self.max_retries = max_retries
        self.requests = 0
        self.rate_limited = 0
        self._last = 0.0

    def query(self, query, runtime, env=None, messages=(), extra_args={}):
        for attempt in range(self.max_retries + 1):
            wait = self._last + self.interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.requests += 1
            try:
                return self.llm.query(query, runtime, env, messages, extra_args)
            except Exception as e:
                if not is_rate_limit(e):
                    raise
                self.rate_limited += 1
                if attempt == self.max_retries:
                    raise QuotaExhausted(str(e)[:300]) from e
                delay = min(300, 15 * 2**attempt)
                print(f"    rate limited; waiting {delay}s (attempt {attempt + 1}/{self.max_retries})", flush=True)
                time.sleep(delay)
        raise AssertionError("unreachable")


def make_llm(args) -> ThrottledLLM:
    """Builds the model element for the chosen provider. Paid providers bill
    the account behind the key in the environment; Ollama runs locally."""
    if args.provider == "google":
        from agentdojo.agent_pipeline import GoogleLLM
        from google import genai

        # A plain client uses an AI Studio key from GEMINI_API_KEY or
        # GOOGLE_API_KEY (AgentDojo's own default is Vertex AI instead).
        llm = GoogleLLM(args.model, genai.Client())
    elif args.provider == "anthropic":
        import anthropic
        from agentdojo.agent_pipeline import AnthropicLLM

        # Current Claude models reject sampling parameters; send none.
        llm = AnthropicLLM(anthropic.Anthropic(), args.model, temperature=None, max_tokens=args.max_tokens)
    elif args.provider in ("openai", "ollama"):
        import openai
        from agentdojo.agent_pipeline import OpenAILLM

        if args.provider == "ollama":
            # Ollama serves an OpenAI-compatible API locally; the key is a
            # placeholder the client library insists on, not a credential.
            client = openai.OpenAI(base_url=args.base_url or "http://127.0.0.1:11434/v1", api_key="ollama")
        else:
            client = openai.OpenAI(base_url=args.base_url) if args.base_url else openai.OpenAI()
        llm = OpenAILLM(client, args.model)
    else:
        raise SystemExit(f"unsupported provider {args.provider!r}")
    return ThrottledLLM(llm, args.rpm, args.max_retries)


def call_counts(calls) -> dict:
    injected = [c for c in calls if c.result_injected]
    return {
        "tool_calls": len(calls),
        "denied_calls": sum(c.denied for c in calls),
        "quarantined_calls": sum(c.quarantined for c in calls),
        "injected_results": len(injected),
        "injected_results_quarantined": sum(c.quarantined for c in injected),
    }


COUNT_KEYS = ("tool_calls", "denied_calls", "quarantined_calls", "injected_results", "injected_results_quarantined")


def sum_counts(rows: list[dict]) -> dict:
    return {k: sum(r[k] for r in rows) for k in COUNT_KEYS}


def rate(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def run_suite(suite_name: str, suite, args, binary: Path, run_dir: Path) -> dict:
    """Runs one suite, appending each finished task to a progress file so an
    interrupted run can be resumed without repeating (or re-paying for) work."""
    progress_path = run_dir / f"progress-{suite_name}.jsonl"
    done: list[dict] = []
    if progress_path.exists():
        done = [json.loads(line) for line in progress_path.read_text().splitlines() if line.strip()]
    finished = {(r["user_task"], r["injection_task"]) for r in done}

    bridge = BridgeServer()
    bridge.start()
    policy_path = None
    if args.guard in ("policy", "both"):
        policy_path = run_dir / f"policy-{suite_name}.yaml"
        write_policy(policy_path, suite, suite_name, args.policy_kind)
    gateway = Gateway(binary, run_dir, suite_name, bridge.url, args, policy_path)
    gateway.start()

    client = GatewayClient(gateway.endpoint)
    executor = GatewayToolsExecutor(client, bridge.state)
    llm = make_llm(args) if args.agent == "llm" else None

    def pipeline_for(task):
        if llm is None:
            pipeline = AgentPipeline([GatewayGroundTruth(task, executor)])
            pipeline.name = "ground-truth"
        else:
            loop = ToolsExecutionLoop([executor, llm])
            pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm, loop])
            pipeline.name = args.model
        return pipeline

    user_tasks = list(suite.user_tasks.items())
    if args.user_tasks:
        user_tasks = [(i, t) for i, t in user_tasks if i in args.user_tasks]
    if args.limit:
        user_tasks = user_tasks[: args.limit]
    injection_tasks = list(suite.injection_tasks.items())
    if args.injection_tasks:
        injection_tasks = [(i, t) for i, t in injection_tasks if i in args.injection_tasks]
    if args.injection_limit:
        injection_tasks = injection_tasks[: args.injection_limit]

    planned = [(tid, task, None, None) for tid, task in user_tasks]
    if args.attack != "none":
        planned += [(tid, task, iid, inj) for tid, task in user_tasks for iid, inj in injection_tasks]
    attack = load_attack(args.attack, suite, pipeline_for(user_tasks[0][1])) if args.attack != "none" else None

    stopped = None
    try:
        with progress_path.open("a") as progress:
            for task_id, task, inj_id, inj_task in planned:
                if (task_id, inj_id) in finished:
                    continue
                client.token = task_token(suite_name, task_id)
                injections = attack.attack(task, inj_task) if inj_task is not None else {}
                bridge.state.injections = tuple(squash(v) for v in injections.values())
                first, started = len(executor.calls), time.monotonic()
                error = None
                try:
                    utility, security = suite.run_task_with_pipeline(pipeline_for(task), task, inj_task, injections)
                except QuotaExhausted:
                    raise
                except Exception as e:  # a model or tool failure counts against the run, visibly
                    if llm is None:
                        raise
                    utility, security, error = False, False, f"{type(e).__name__}: {e}"[:300]
                row = {
                    "user_task": task_id,
                    "injection_task": inj_id,
                    "utility": bool(utility),
                    # True means the injection goal was achieved (AgentDojo's "security" value).
                    "attack_succeeded": bool(security) if inj_id is not None else None,
                    "error": error,
                    "seconds": round(time.monotonic() - started, 2),
                    **call_counts(executor.calls[first:]),
                }
                progress.write(json.dumps(row) + "\n")
                progress.flush()
                done.append(row)
                kind = "benign" if inj_id is None else inj_id
                outcome = f"utility={row['utility']}" + ("" if inj_id is None else f" attack_succeeded={row['attack_succeeded']}")
                if llm is not None or inj_id is None:
                    print(f"  {suite_name} {task_id} {kind}: {outcome}" + (f" ERROR {error}" if error else ""), flush=True)
    except (QuotaExhausted, KeyboardInterrupt) as e:
        stopped = "interrupted by user" if isinstance(e, KeyboardInterrupt) else f"provider quota exhausted: {e}"
    finally:
        gateway.stop()
        bridge.stop()

    result: dict = {"user_tasks": len(user_tasks), "gateway_flags": gateway.flags[4:],
                    "planned": len(planned), "completed": len(done), "stopped": stopped}  # fmt: skip
    benign = [r for r in done if r["injection_task"] is None]
    attacked = [r for r in done if r["injection_task"] is not None]
    if benign:
        ok = sum(r["utility"] for r in benign)
        result["benign"] = {"tasks": len(benign), "utility": ok, "utility_rate": rate(ok, len(benign)),
                            "errors": sum(r["error"] is not None for r in benign), **sum_counts(benign)}  # fmt: skip
    if attacked:
        ok, hit = sum(r["utility"] for r in attacked), sum(r["attack_succeeded"] for r in attacked)
        result["under_attack"] = {"pairs": len(attacked), "utility": ok, "utility_rate": rate(ok, len(attacked)),
                                  "attack_successes": hit, "attack_success_rate": rate(hit, len(attacked)),
                                  "errors": sum(r["error"] is not None for r in attacked), **sum_counts(attacked)}  # fmt: skip
    if llm is not None:
        result["model_requests_this_session"] = llm.requests
        result["rate_limit_hits_this_session"] = llm.rate_limited

    records = gateway.audit_records()
    result["latency"] = latency_stats(records)
    result["audit_records"] = len(records)
    result["per_task"] = done
    return result


def totals(suites: dict) -> dict:
    out: dict = {}
    for section, keys in (
        ("benign", ("tasks", "utility", "errors", "tool_calls", "denied_calls", "quarantined_calls")),
        ("under_attack", ("pairs", "utility", "attack_successes", "errors", "tool_calls", "denied_calls",
                          "quarantined_calls", "injected_results", "injected_results_quarantined")),  # fmt: skip
    ):
        present = [s[section] for s in suites.values() if section in s]
        if not present:
            continue
        agg = {k: sum(s[k] for s in present) for k in keys}
        n = agg["tasks"] if section == "benign" else agg["pairs"]
        agg["utility_rate"] = rate(agg["utility"], n)
        if section == "benign":
            agg["false_quarantine_rate"] = rate(agg["quarantined_calls"], agg["tool_calls"])
        else:
            agg["attack_success_rate"] = rate(agg["attack_successes"], n)
            agg["injected_result_quarantine_rate"] = rate(agg["injected_results_quarantined"], agg["injected_results"])
        out[section] = agg
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--resume", type=Path, help="continue the run in this directory with its original settings")
    p.add_argument("--agent", choices=("ground-truth", "llm"))
    p.add_argument("--guard", choices=GUARD_MODES, help="off: gateway passes everything; policy; scan; both")
    p.add_argument("--scan", default="rules", choices=("rules", "judge", "rules+judge"))
    p.add_argument("--judge-model", default="claude-opus-5-5")
    p.add_argument("--policy-kind", default="suite", choices=("suite", "task"),
                   help="suite: allow every tool in the suite; task: ORACLE per-task least privilege")  # fmt: skip
    p.add_argument("--suites", nargs="*", default=None, help="default: all four")
    p.add_argument("--benchmark-version", default="v1.2.2")
    p.add_argument("--attack", default="important_instructions", help='AgentDojo attack name, or "none"')
    p.add_argument("--provider", choices=PROVIDERS)
    p.add_argument("--model")
    p.add_argument("--base-url", help="OpenAI-compatible endpoint (ollama default: http://127.0.0.1:11434/v1)")
    p.add_argument("--model-prose-name",
                   help="how the attack text addresses the model; default depends on the provider")  # fmt: skip
    p.add_argument("--max-tokens", type=int, default=4096)
    p.add_argument("--rpm", type=float, default=0, help="cap on model requests per minute (0 = no cap)")
    p.add_argument("--max-retries", type=int, default=6, help="retries on a rate-limit error before stopping")
    p.add_argument("--user-tasks", nargs="*")
    p.add_argument("--injection-tasks", nargs="*")
    p.add_argument("--limit", type=int, help="only the first N user tasks per suite")
    p.add_argument("--injection-limit", type=int, help="only the first N injection tasks per suite")
    p.add_argument("--label", default="", help="suffix for the results file name")
    args = p.parse_args(argv)

    if args.resume:
        args.resume = (START_DIR / args.resume).resolve()
        if not (args.resume / "args.json").exists():
            p.error(f"{args.resume} is not a run directory (no args.json)")
        saved = json.loads((args.resume / "args.json").read_text())
        resumed = argparse.Namespace(**saved)
        resumed.resume = args.resume
        return resumed
    if not args.agent or not args.guard:
        p.error("--agent and --guard are required (or use --resume)")
    if args.agent == "llm" and not (args.provider and args.model):
        p.error("--agent llm needs --provider and --model")
    if not args.model_prose_name:
        args.model_prose_name = PROSE_NAMES.get(args.provider or "", "Claude")
    return args


def main() -> None:
    args = parse_args(sys.argv[1:])

    # The attack addresses the model by name; teach AgentDojo names it lacks.
    pipeline_name = args.model if args.agent == "llm" else "ground-truth"
    agentdojo_models.MODEL_NAMES.setdefault(pipeline_name, args.model_prose_name)

    if args.resume:
        run_dir = args.resume.resolve()
        started = json.loads((run_dir / "args.json").read_text())["started_utc"]
    else:
        started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        run_dir = HERE / "runs" / started.replace("-", "").replace(":", "").replace("+0000", "Z")
        run_dir.mkdir(parents=True)
        saved = {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items() if k != "resume"}
        (run_dir / "args.json").write_text(json.dumps({
            **saved, "started_utc": started, "argv": sys.argv[1:],
            # The gateway binary is built now, so record the source it was built from now.
            "guard_commit": git("rev-parse", "HEAD"), "guard_dirty": bool(git("status", "--porcelain")),
        }, indent=2))  # fmt: skip
    args.started_utc = started
    meta = json.loads((run_dir / "args.json").read_text())
    argv = meta["argv"]
    binary = build_gateway(run_dir)

    all_suites = get_suites(args.benchmark_version)
    names = args.suites or list(all_suites)
    suites = {}
    for name in names:
        print(f"suite {name}", flush=True)
        suites[name] = run_suite(name, all_suites[name], args, binary, run_dir)
        if suites[name]["stopped"]:
            break

    stopped = next((s["stopped"] for s in suites.values() if s["stopped"]), None)
    finished = stopped is None and len(suites) == len(names)
    full_scope = not (args.limit or args.injection_limit or args.user_tasks or args.injection_tasks or args.suites)
    report = {
        "schema": 2,
        "benchmark": "AgentDojo",
        "agentdojo_version": importlib.metadata.version("agentdojo"),
        "benchmark_version": args.benchmark_version,
        "date_utc": started,
        "written_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "complete_run": finished and full_scope,
        "finished": finished,
        "stopped": stopped,
        "scope": "full benchmark" if full_scope else "subset (see command)",
        "agent": {
            "type": args.agent,
            "provider": args.provider,
            "model": args.model,
            "base_url": args.base_url,
            "note": None if args.agent == "llm" else (
                "Scripted agent with no model: it replays each task's ground-truth tool calls and ignores "
                "tool results. It cannot be attacked, so attack_success_rate here is NOT a measure of the "
                "gateway. Use this run for plumbing, denials, quarantine rates and latency only."
            ),
        },
        "attack": {"name": args.attack, "model_prose_name": args.model_prose_name},
        "guard": {
            "mode": args.guard,
            "scan": args.scan if args.guard in ("scan", "both") else "off",
            "judge_model": args.judge_model if args.guard in ("scan", "both") and "judge" in args.scan else None,
            "policy_kind": args.policy_kind if args.guard in ("policy", "both") else None,
            "commit": meta.get("guard_commit") or git("rev-parse", "HEAD"),
            "uncommitted_changes": meta.get("guard_dirty", bool(git("status", "--porcelain"))),
        },
        "bridge": "evals/agentdojo/bridge.py (AgentDojo tools served over MCP Streamable HTTP, JSON responses)",
        "command": "run.py " + " ".join(argv),
        "run_dir": str(run_dir.relative_to(ROOT)),
        "totals": totals(suites),
        "suites": suites,
    }

    results_dir = ROOT / "evals" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    model = (args.model or "ground-truth").replace("/", "_").replace(":", "_")
    label = f"-{args.label}" if args.label else ""
    out = results_dir / f"agentdojo-{run_dir.name}-{model}-guard-{args.guard}{label}.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["totals"], indent=2))
    print(f"wrote {out.relative_to(ROOT)}")
    if stopped:
        print(f"STOPPED: {stopped}\nresume with: run.py --resume {run_dir.relative_to(ROOT)}")
        raise SystemExit(2)


if __name__ == "__main__":
    os.chdir(HERE)
    main()
