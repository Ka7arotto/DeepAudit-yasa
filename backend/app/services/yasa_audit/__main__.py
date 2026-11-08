"""Command line entry point.

    python -m app.services.yasa_audit init   <project>             # build the yasa-mcp navigation cache
    python -m app.services.yasa_audit recon  <project> --out DIR   # route reconnaissance only
    python -m app.services.yasa_audit run    <project> --out DIR   # recon (reused if DIR/recon exists) + review

LLM settings come from DeepAudit's LLM_BASE_URL / LLM_API_KEY / LLM_MODEL environment variables.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from .config import AuditConfig
from .pipeline import recon, run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.services.yasa_audit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "recon", "run"):
        p = sub.add_parser(name)
        p.add_argument("project", type=Path)
        if name != "init":
            p.add_argument("--out", type=Path, required=True)
            p.add_argument("--deploy", default="", help="deployment context, e.g. 'Linux, nginx, PHP 8.3'")
            p.add_argument("--product", default="",
                           help="product context: roles, what is public by design, what input is trusted")
            p.add_argument("--workers", type=int, default=6)
            p.add_argument("--time-budget", type=float, default=30.0,
                           help="wall-clock budget in minutes (default 30); unreviewed entries are listed")
    args = ap.parse_args(argv)
    cfg = AuditConfig()
    root = args.project.resolve()

    if args.cmd == "init":
        return subprocess.run([cfg.yasamcp_bin, "init", str(root), "--no-progress",
                               "-b", cfg.yasamcp_tools_dir]).returncode

    cfg.workers = args.workers
    cfg.time_budget_s = int(args.time_budget * 60)
    start = time.time()
    if args.cmd == "recon":
        result = recon(cfg, root, args.out / "recon", args.deploy, args.product, start + cfg.time_budget_s)
    else:
        result = run(cfg, root, args.out, args.deploy, args.product, start, start + cfg.time_budget_s)
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
