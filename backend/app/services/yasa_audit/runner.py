"""Glue between the entry-first audit pipeline and DeepAudit's task system.

The pipeline itself is synchronous (threads + blocking HTTP). DeepAudit calls these helpers through
asyncio.to_thread and emits task events between stages. `to_deepaudit_findings` maps pipeline
findings to the dict shape that agent_tasks._save_findings understands.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .config import AuditConfig
from .pipeline import run

REPORTED = ("confirmed", "likely")

# CWE -> (DeepAudit vulnerability_type, default severity)
CWE_MAP: dict[str, tuple[str, str]] = {
    "CWE-89": ("sql_injection", "high"),
    "CWE-943": ("nosql_injection", "high"),
    "CWE-79": ("xss", "medium"),
    "CWE-78": ("command_injection", "critical"),
    "CWE-77": ("command_injection", "critical"),
    "CWE-94": ("code_injection", "critical"),
    "CWE-95": ("code_injection", "critical"),
    "CWE-22": ("path_traversal", "high"),
    "CWE-23": ("path_traversal", "high"),
    "CWE-73": ("path_traversal", "high"),
    "CWE-918": ("ssrf", "high"),
    "CWE-611": ("xxe", "high"),
    "CWE-502": ("deserialization", "critical"),
    "CWE-601": ("business_logic", "medium"),
    "CWE-1321": ("code_injection", "high"),
    "CWE-347": ("auth_bypass", "high"),
    "CWE-287": ("auth_bypass", "high"),
    "CWE-306": ("auth_bypass", "high"),
    "CWE-862": ("auth_bypass", "high"),
    "CWE-863": ("auth_bypass", "high"),
    "CWE-284": ("auth_bypass", "high"),
    "CWE-285": ("auth_bypass", "high"),
    "CWE-639": ("idor", "high"),
    "CWE-200": ("sensitive_data_exposure", "medium"),
    "CWE-538": ("sensitive_data_exposure", "medium"),
    "CWE-548": ("sensitive_data_exposure", "medium"),
    "CWE-552": ("sensitive_data_exposure", "medium"),
    "CWE-798": ("hardcoded_secret", "high"),
    "CWE-327": ("weak_crypto", "medium"),
    "CWE-328": ("weak_crypto", "medium"),
}
LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


def check_tools(cfg: AuditConfig) -> list[str]:
    """Names of missing executables (empty when the pipeline can run)."""
    missing = []
    for name, path in (("YASAMCP_BIN", cfg.yasamcp_bin), ("YASA_RG_BIN", cfg.rg_bin)):
        if not (Path(path).is_file() or shutil.which(path)):
            missing.append(f"{name}={path}")
    return missing


def init_navigation(cfg: AuditConfig, root: Path, timeout_s: int = 600, stop=None) -> None:
    """Bound the whole navigation process tree, including native engine children.

    `stop` (a callable) ends init early without error: the task starts its stages as soon as
    codegraph's index is written and stops the slower YASA call-graph step when the stages finish.
    """
    command = [cfg.yasamcp_bin, "init", str(root), "--no-progress", "-b", cfg.yasamcp_tools_dir]
    log_path = root / ".yasa" / "navigation-init.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    t_end = time.time() + timeout_s
    with log_path.open("w") as log:
        with subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                              start_new_session=True) as process:
            code = None
            while code is None:
                try:
                    code = process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    stopped = bool(stop and stop())
                    if not stopped and time.time() < t_end:
                        continue
                    # Killing only the CLI leaves its YASA/codegraph children running indefinitely.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    if stopped:
                        return
                    raise RuntimeError(f"yasa-mcp init timed out after {timeout_s}s; navigation process "
                                       f"group stopped; log: {log_path}") from None
    if code:
        raise RuntimeError(f"yasa-mcp init exited with code {code}; log: {log_path}")


def run_entry_audit(cfg: AuditConfig, root: Path, out: Path, deploy: str, product: str, start: float,
                    deadline: float) -> dict:
    """Route reconnaissance, then one review per entry. Returns metrics plus the raw findings."""
    m = run(cfg, root, out, deploy, product, start, deadline)
    data = json.loads((out / "review" / "findings.json").read_text())
    return {**m, "findings": data["findings"], "not_reviewed": data.get("not_reviewed", []),
            "tokens": m["total_tokens"]}


def _describe(f: dict) -> str:
    parts = [f"[yasa_audit/entry review] verdict: {f.get('verdict')}"]
    if f.get("documented_intent"):
        di = f["documented_intent"]
        di = di if isinstance(di, dict) else (di or [{}])[0]
        parts.append(f"Documented as intended by the project: {di.get('file')}:{di.get('line')} \"{di.get('quote')}\"")
    if f.get("issue"):
        parts.append(f"Root cause {f['issue']}: {f.get('root_cause') or '(see linked finding)'}")
    for key, label in (("impact", "Impact"), ("entry", "Entry"), ("required_privilege", "Required privilege"),
                       ("source", "Source"), ("sanitizers", "Guards/sanitizers"), ("handler", "Handler")):
        if f.get(key):
            parts.append(f"{label}: {f[key]}")
    if f.get("hops"):
        parts.append("Path:\n" + "\n".join(f"  {i + 1}. {h}" for i, h in enumerate(f["hops"])))
    return "\n".join(parts)


def to_deepaudit_findings(findings: list[dict]) -> list[dict]:
    """Reported findings in agent_tasks._save_findings' input shape.

    'confirmed' is a static LLM verdict, not an execution, so it maps to confidence rather than to
    is_verified. Severity drops one step for 'likely' and for admin-only issues; issues that need
    operator / CLI access are low.
    """
    out, seen = [], set()
    for f in findings:
        if f.get("verdict") not in REPORTED:
            continue
        cwe = (f.get("cwe") or "").upper().replace(" ", "")
        key = (f.get("sink_file"), f.get("sink_line"), cwe)
        if key in seen:
            continue
        seen.add(key)
        vtype, sev = CWE_MAP.get(cwe, ("other", "medium"))
        if f.get("verdict") == "likely":
            sev = LOWER[sev]
        if f.get("documented_intent"):
            sev = "low"
        elif f.get("required_privilege") in ("privileged", "admin"):
            sev = LOWER[sev]
        elif f.get("required_privilege") == "operator_or_cli":
            sev = "low"
        line = f.get("sink_line")
        out.append({
            "title": f"{f.get('vuln_type') or vtype} ({cwe or 'CWE-?'})",
            "vulnerability_type": vtype,
            "severity": sev,
            "file_path": f.get("sink_file"),
            "line_start": int(line) if str(line or "").isdigit() else None,
            "description": _describe(f),
            "confidence": 0.85 if f.get("verdict") == "confirmed" else 0.6,
            "cwe_id": cwe or None,
            "verification_method": "yasa_audit entry review (static, not executed)",
        })
    return out
