"""Entry-first audit: route reconnaissance, then one review per entry point.

recon  : an agent works out how requests reach code in THIS project (directory layout, codegraph's route
         evidence, navigation tools), writes extractor programs that enumerate every entry, and checks
         them (handlers resolve to code, sampled entries read correctly, request-reading code is reachable
         from some entry). Output: entries.json.
review : each entry (entries sharing one handler are one unit) is reviewed in a fresh context: what it
         does, who can call it, its access-control verdict, risks plausible for that function, each traced
         to a confirmed path or rejected. Reviewers share verified project facts. No later re-review.
"""

from __future__ import annotations

import collections
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .agent_loop import run_agent
from .config import AuditConfig
from .discovery import codegraph_db, codegraph_routes, snapshot_codegraph
from .llm import LLM
from .prompts import recon_prompt, review_prompt
from .toolbox import FactBook, Toolbox, tool_schemas

MIN_UNIT_S = 60  # do not start a unit with less time left than this
SKIP_PARTS = {"node_modules", ".git", ".yasa", ".codegraph", "vendor", "venv", ".venv", "__pycache__"}
EXPOSURE_RANK = {"public": 0, "unknown": 1, "authenticated": 2, "privileged": 3}
PEERS_MAX = 12


def _schedule(units: list, work, workers: int, deadline: float | None,
              stop=None) -> tuple[list[dict], list]:
    """Run work(i, unit) for units in order with a thread pool. Units that would start with less
    than MIN_UNIT_S left before the deadline are skipped and returned separately."""
    skipped: list = []
    lock = threading.Lock()

    def guarded(i_unit: tuple[int, object]) -> dict | None:
        i, unit = i_unit
        if (stop and stop()) or (deadline is not None and time.time() > deadline - MIN_UNIT_S):
            with lock:
                skipped.append(unit)
            return None
        try:
            return work(i, unit)
        except Exception as e:  # keep the batch going
            return {"findings": [], "cards": [], "prompt_tokens": 0, "completion_tokens": 0,
                    "cached_tokens": 0, "steps": 0, "error": f"{type(e).__name__}: {e}"}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        results = [r for r in ex.map(guarded, enumerate(units)) if r is not None]
    return results, skipped


def _metrics(llm: LLM, extra: dict) -> dict:
    u = llm.usage
    return {"prompt_tokens": u.prompt, "completion_tokens": u.completion, "cached_tokens": u.cached,
            "reasoning_tokens": u.reasoning, "llm_calls": u.calls, **extra}


def _ext_counts(root: Path) -> list[tuple[str, int]]:
    c: collections.Counter = collections.Counter()
    for _d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP_PARTS and not x.startswith(".")]
        c.update(os.path.splitext(f)[1] or f for f in fs)
    return c.most_common(15)


# ----------------------------------------------------------------- recon

def recon(cfg: AuditConfig, root: Path, out: Path, deploy: str = "", product: str = "",
          deadline: float | None = None) -> dict:
    """The recon agent decides the attack surface. Writes entries.json and recon.json to out."""
    out.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_codegraph(root, out)
    except Exception:
        pass
    tb = Toolbox(cfg, root, out, unit="recon")
    llm = LLM(cfg)
    user = (f"Files by extension (vendored and VCS directories left out): {_ext_counts(root)}\n\n"
            f"Top-level layout:\n{tb.list_dir('.', 2)}\n\n"
            f"codegraph route evidence:\n{tb.codegraph_routes(limit=25)}")
    no_extractor_yet = (lambda steps, t: steps >= cfg.recon_budget // 2 and not t.extractors and not t.manual,
                        "Half of your tool budget is used and no extractor has run. Stop reading: write an "
                        "extractor for the dispatcher you understand best and run it now, then refine.")
    res = run_agent(llm, tb, tool_schemas("recon"), recon_prompt(cfg.recon_budget, deploy, product), user,
                    cfg.recon_budget, out / "transcript.jsonl", deadline=deadline, reminders=[no_extractor_yet])
    passes = 1
    # Understood the dispatch but enumerated nothing: a second, fresh context that starts from the agent's
    # own notes and only has to turn them into extractors.
    if not tb.entries() and tb.notes and (deadline is None or time.time() < deadline - 120):
        budget2 = max(10, cfg.recon_budget // 2)
        tb.finished = False
        res2 = run_agent(
            llm, tb, tool_schemas("recon"), recon_prompt(budget2, deploy, product),
            "An earlier pass worked out how requests reach code but did not enumerate any entries. Its "
            f"notes:\n{tb.notes}\n\nWrite one extractor per dispatcher described there, run each with "
            "run_extractor, fix what the checks report, then call finish with the notes (updated).",
            budget2, out / "transcript-2.jsonl", deadline=deadline)
        res = {k: (res.get(k, 0) + res2.get(k, 0)) if isinstance(res2.get(k), (int, float)) and k != "finished"
               else res2.get(k) for k in res2}
        passes = 2
    entries = tb.entries()
    source = "agent"
    if not entries:  # the agent produced nothing usable: keep codegraph's routes so review can start
        db = codegraph_db(root)
        entries = [{"route": r["route"], "method": r["method"], "handler_file": r["file"],
                    "handler": r.get("handler", ""), "exposure": "unknown", "origin": "codegraph"}
                   for r in (codegraph_routes(db, root) if db else [])]
        source = "codegraph-fallback"
    for i, e in enumerate(entries):
        e["id"] = f"E{i + 1}"
        e["resolved"] = tb._check_entry(e) is None
    (out / "entries.json").write_text(json.dumps(entries, indent=1, ensure_ascii=False))
    by_exp = collections.Counter(e["exposure"] for e in entries)
    m = _metrics(llm, {"stage": "recon", "source": source, "entries": len(entries),
                       "resolved": sum(e["resolved"] for e in entries), "by_exposure": dict(by_exp),
                       "extractors": {k: len(v["entries"]) for k, v in tb.extractors.items()},
                       "manual_entries": len(tb.manual), "coverage": tb.coverage, "notes": tb.notes,
                       "passes": passes, **res})
    (out / "recon.json").write_text(json.dumps(m, indent=1, ensure_ascii=False))
    return m


# ----------------------------------------------------------------- review

def _units(entries: list[dict]) -> list[dict]:
    """One unit per handler (several routes can run the same code), most exposed first."""
    by_handler: dict[tuple, list[dict]] = {}
    for e in entries:
        by_handler.setdefault((e.get("handler_file") or "", e.get("handler") or "", e.get("route")
                               if not e.get("handler_file") else ""), []).append(e)
    units = []
    for (hf, h, _), es in by_handler.items():
        exp = min((e.get("exposure", "unknown") for e in es), key=lambda x: EXPOSURE_RANK.get(x, 1))
        units.append({"handler_file": hf, "handler": h, "exposure": exp, "entries": es,
                      "resolved": all(e.get("resolved", True) for e in es)})
    units.sort(key=lambda u: (not u["resolved"], EXPOSURE_RANK.get(u["exposure"], 1),
                              u["entries"][0].get("route", "")))
    return units


def _route_key(route: str, n: int = 2) -> str:
    return "/".join([p for p in re.split(r"[/?]", route or "") if p][:n])


def _peers(unit: dict, entries: list[dict]) -> list[str]:
    """Similar entries for access-control comparison: same route prefix, then same handler directory."""
    keys = {_route_key(e.get("route", "")) for e in unit["entries"]}
    hdir = os.path.dirname(unit["handler_file"])
    own = {id(e) for e in unit["entries"]}
    near = [e for e in entries if id(e) not in own and _route_key(e.get("route", "")) in keys]
    near += [e for e in entries if id(e) not in own and e not in near and hdir
             and os.path.dirname(e.get("handler_file") or "") == hdir]
    return [f"{e.get('method', 'ANY')} {e.get('route')} -> {e.get('handler_file')}::{e.get('handler', '')} "
            f"auth={e.get('auth', '?')} exposure={e.get('exposure')}" for e in near[:PEERS_MAX]]


def _handler_snippet(root: Path, unit: dict, lines: int = 70) -> str:
    """The handler's code, so the reviewer starts reading the right place."""
    f = root / unit["handler_file"] if unit["handler_file"] else None
    if f is None or not f.is_file():
        return ""
    text = f.read_text(errors="ignore").splitlines()
    name = re.escape((unit["handler"] or "").split("::")[-1].split(".")[-1])
    start = 0
    if name:
        rx = re.compile(rf"(function|def|func|fn|sub)\s+&?{name}\b|\b{name}\s*[:=]\s*(async\s*)?(function|\()"
                        rf"|\b(public|private|protected|static|async)\b[^;=]*\b{name}\s*\(")
        start = next((i for i, ln in enumerate(text) if rx.search(ln)), 0)
    body = "\n".join(f"{i + 1:5d}| {text[i]}" for i in range(start, min(len(text), start + lines)))
    return f"{unit['handler_file']} lines {start + 1}-{min(len(text), start + lines)} of {len(text)}:\n{body}"


def _review_unit(cfg: AuditConfig, root: Path, out: Path, unit: dict, entries: list[dict], facts: FactBook,
                 system: str, deadline: float | None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    uid = ",".join(e["id"] for e in unit["entries"][:5])
    tb = Toolbox(cfg, root, out, facts=facts, unit=uid)
    llm = LLM(cfg)
    entry_view = {"routes": [{k: e.get(k) for k in ("id", "method", "route", "kind", "auth", "exposure",
                                                     "declared_at") if e.get(k)} for e in unit["entries"][:20]],
                  "more_routes": max(0, len(unit["entries"]) - 20),
                  "handler_file": unit["handler_file"], "handler": unit["handler"]}
    peers = _peers(unit, entries)
    user = "\n\n".join(x for x in (
        "Entry to review:\n" + json.dumps(entry_view, ensure_ascii=False),
        ("Similar entries (peers):\n" + "\n".join(peers)) if peers else "",
        facts.prompt_block(),
        _handler_snippet(root, unit)) if x)
    res = run_agent(llm, tb, tool_schemas("review"), system, user, cfg.review_budget, out / "transcript.jsonl",
                    deadline=deadline)
    for x in tb.findings + tb.cards:
        x["entries"] = [e["id"] for e in unit["entries"]]
        x["handler"] = f"{unit['handler_file']}::{unit['handler']}"
    return {"findings": tb.findings, "cards": tb.cards, **_metrics(llm, res)}


def review(cfg: AuditConfig, root: Path, out: Path, entries: list[dict], deploy: str = "", product: str = "",
           surface_notes: str = "", deadline: float | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    units = _units(entries)
    facts = FactBook(root)
    system = review_prompt(cfg.review_budget, deploy, product, surface_notes)
    results, skipped = _schedule(
        units, lambda i, u: _review_unit(cfg, root, out / f"unit-{i:04d}", u, entries, facts, system, deadline),
        cfg.workers, deadline, cfg.stopped)
    findings = [f for r in results for f in r["findings"]]
    cards = [c for r in results for c in r["cards"]]
    not_reviewed = [e["id"] for u in skipped for e in u["entries"]]
    (out / "findings.json").write_text(json.dumps({"findings": findings, "not_reviewed": not_reviewed},
                                                  indent=1, ensure_ascii=False))
    (out / "cards.json").write_text(json.dumps(cards, indent=1, ensure_ascii=False))
    (out / "facts.json").write_text(json.dumps(facts.facts, indent=1, ensure_ascii=False))
    s = lambda k: sum(r.get(k, 0) for r in results)  # noqa: E731
    m = {"stage": "review", "entries": len(entries), "units": len(units), "reviewed_units": len(results),
         "skipped_units": len(skipped), "not_reviewed_entries": len(not_reviewed),
         "prompt_tokens": s("prompt_tokens"), "completion_tokens": s("completion_tokens"),
         "cached_tokens": s("cached_tokens"), "reasoning_tokens": s("reasoning_tokens"), "steps": s("steps"),
         "errors": sum(1 for r in results if r.get("error")), "facts": len(facts.facts),
         "cards": len(cards), "n_findings": len(findings),
         "authz_verdicts": dict(collections.Counter(c.get("authz_verdict") for c in cards)),
         "wall_s": round(time.time() - t0, 1)}
    (out / "metrics.json").write_text(json.dumps(m, indent=1))
    return m


# ----------------------------------------------------------------- both

def run(cfg: AuditConfig, root: Path, out: Path, deploy: str = "", product: str = "",
        start: float | None = None, deadline: float | None = None) -> dict:
    """recon (reused when out/recon/entries.json exists) then review, within one wall-clock budget."""
    start = start or time.time()
    deadline = deadline or start + cfg.time_budget_s
    ef = out / "recon" / "entries.json"
    if ef.exists():
        rec = json.loads((out / "recon" / "recon.json").read_text()) if (out / "recon" / "recon.json").exists() else {}
        rec.setdefault("reused", True)
    else:
        rec = recon(cfg, root, out / "recon", deploy, product, start + cfg.recon_share * (deadline - start))
    entries = json.loads(ef.read_text())
    rv = review(cfg, root, out / "review", entries, deploy, product, rec.get("notes") or "", deadline)
    tok = lambda m, k: (m or {}).get(k, 0) or 0  # noqa: E731
    m = {"recon": rec, "review": rv,
         "total_tokens": sum(tok(x, "prompt_tokens") + tok(x, "completion_tokens") for x in (rec, rv)),
         "total_cached_tokens": sum(tok(x, "cached_tokens") for x in (rec, rv)),
         "total_wall_s": round(time.time() - start, 1), "time_budget_s": round(deadline - start)}
    (out / "metrics.json").write_text(json.dumps(m, indent=1, ensure_ascii=False))
    return m
