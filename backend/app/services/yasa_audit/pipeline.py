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
from .llm import LLM, limiter_for
from .prompts import access_model_text, access_prompt, recon_prompt, review_prompt
from .toolbox import FactBook, IssueBoard, Toolbox, tool_schemas

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

def _access_agent(cfg: AuditConfig, root: Path, out: Path, deploy: str, product: str,
                  deadline: float | None, user: str, holder: dict) -> None:
    """Works out the project-wide access-control model; publishes it in holder['model']."""
    tb = Toolbox(cfg, root, out, unit="access")
    tb.finish_gates = [(lambda t: t.access_model is None,
                        "record_access_model first (how requests are authenticated and authorized)")]
    llm = LLM(cfg)
    try:
        holder["res"] = run_agent(llm, tb, tool_schemas("access"), access_prompt(cfg.access_budget, deploy, product),
                                  user, cfg.access_budget, out / "transcript-access.jsonl", deadline=deadline)
    except Exception as e:  # the surface agent and the review still run without a model
        holder["error"] = f"{type(e).__name__}: {e}"
    holder["model"], holder["llm"] = tb.access_model, llm
    holder["done"].set()


def recon(cfg: AuditConfig, root: Path, out: Path, deploy: str = "", product: str = "",
          deadline: float | None = None) -> dict:
    """Two agents in parallel: one maps the attack surface (entries.json), one the access-control model.
    The model is sent to the surface agent as soon as it is recorded, for the entries' exposure."""
    out.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_codegraph(root, out)
    except Exception:
        pass
    tb = Toolbox(cfg, root, out, unit="recon")
    user = (f"Files by extension (vendored and VCS directories left out): {_ext_counts(root)}\n\n"
            f"Top-level layout:\n{tb.list_dir('.', 2)}\n\n"
            f"codegraph route evidence:\n{tb.codegraph_routes(limit=25)}")
    holder: dict = {"model": None, "done": threading.Event()}
    access = threading.Thread(target=_access_agent, daemon=True,
                              args=(cfg, root, out, deploy, product, deadline, user, holder))
    access.start()

    tb.finish_gates = [(lambda t: (t.extractors or t.manual) and t.coverage is None,
                        "run check_coverage once with a pattern for how this project reads request data")]
    llm = LLM(cfg)
    no_extractor_yet = (lambda steps, t: steps >= cfg.recon_budget // 2 and not t.extractors and not t.manual,
                        "Half of your tool budget is used and no extractor has run. Stop reading: write an "
                        "extractor for the dispatcher you understand best and run it now, then refine.")
    model_ready = (lambda steps, t: holder["done"].is_set() and holder["model"] is not None,
                   lambda t: "The access-control model is ready. Use it to set each entry's exposure (the "
                             "least privileged principal that can call it); re-run extractors if needed:\n"
                             + access_model_text(holder["model"]))
    res = run_agent(llm, tb, tool_schemas("recon"), recon_prompt(cfg.recon_budget, deploy, product), user,
                    cfg.recon_budget, out / "transcript.jsonl", deadline=deadline,
                    reminders=[no_extractor_yet, model_ready])
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
            budget2, out / "transcript-2.jsonl", deadline=deadline,
            reminders=[model_ready] if holder["model"] is None else [])
        res = {k: (res.get(k, 0) + res2.get(k, 0)) if isinstance(res2.get(k), (int, float)) and k != "finished"
               else res2.get(k) for k in res2}
        passes = 2
    # the review needs the model: wait for the access agent within the deadline
    holder["done"].wait(timeout=None if deadline is None else max(0.0, deadline + 60 - time.time()))
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
                       "access_model": holder["model"], "access_error": holder.get("error"),
                       "passes": passes, **res})
    if holder.get("llm") is not None:  # both agents' tokens count
        a = _metrics(holder["llm"], holder.get("res") or {})
        for k in ("prompt_tokens", "completion_tokens", "cached_tokens", "reasoning_tokens", "llm_calls"):
            m[k] = m.get(k, 0) + a.get(k, 0)
        m["access_agent"] = {k: a.get(k) for k in ("steps", "wall_s", "tool_counts", "finished",
                                                   "prompt_tokens", "llm_calls")}
    (out / "recon.json").write_text(json.dumps(m, indent=1, ensure_ascii=False))
    return m


# ----------------------------------------------------------------- review

SPLIT_ROUTES = 8  # a handler serving more routes than this is generic: review it per resource


def _resource_key(route: str) -> str:
    """The route without its parameters and trailing id-like segments: /apis/g/v1/posts/{name}/x -> /apis/g/v1/posts."""
    parts = [p for p in re.split(r"[/?]", route or "") if p]
    while parts and (parts[-1].startswith(("{", ":", "<", "*")) or "{" in parts[-1]):
        parts.pop()
    keep = []
    for p in parts:
        if p.startswith(("{", ":", "<", "*")):
            break
        keep.append(p)
    return "/" + "/".join(keep)


def _handler_id(e: dict) -> tuple:
    """What identifies the code an entry runs: file, name and first line. A name alone does not identify
    anonymous code (callbacks, lambdas, closures: every route of a file may be 'app.post'), so the
    handler_line, or else the registration line in the same file, is part of the identity."""
    hf, h = e.get("handler_file") or "", e.get("handler") or ""
    line = e.get("handler_line") or 0
    if not line and e.get("declared_at"):
        f, _, ln = str(e["declared_at"]).rpartition(":")
        if f.lstrip("./") == hf and ln.isdigit():
            line = int(ln)
    return (hf, h, int(line or 0), "" if hf else e.get("route"))


def _units(entries: list[dict]) -> list[dict]:
    """One unit per handler (several routes can run the same code), most exposed first.

    A generic handler (one function serving many resources, e.g. a CRUD dispatcher) is split into one
    unit per resource: access control and object ownership differ per resource, and one context cannot
    judge dozens of them.
    """
    by_handler: dict[tuple, list[dict]] = {}
    for e in entries:
        by_handler.setdefault(_handler_id(e), []).append(e)
    groups: list[tuple[str, str, list[dict], bool]] = []
    by_res: dict[str, list[dict]] = {}  # routes of generic handlers, by resource (all their verbs together)
    for (hf, h, _line, _), es in by_handler.items():
        if len(es) > SPLIT_ROUTES:
            for e in es:
                by_res.setdefault(_resource_key(e.get("route", "")), []).append(e)
        else:
            groups.append((hf, h, es, False))
    for es in by_res.values():
        groups.append((es[0].get("handler_file") or "", es[0].get("handler") or "", es, True))
    units = []
    for hf, h, es, generic in groups:
        exp = min((e.get("exposure", "unknown") for e in es), key=lambda x: EXPOSURE_RANK.get(x, 1))
        units.append({"handler_file": hf, "handler": h, "handler_line": _handler_id(es[0])[2] or None,
                      "exposure": exp, "entries": es, "generic": generic,
                      "handlers": sorted({f"{e.get('handler_file')}::{e.get('handler')}" for e in es}),
                      "resolved": all(e.get("resolved", True) for e in es)})
    units.sort(key=lambda u: (EXPOSURE_RANK.get(u["exposure"], 1), not u["resolved"],
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
    if unit.get("handler_line"):
        start = max(0, min(len(text) - 1, int(unit["handler_line"]) - 1))
    elif name:
        rx = re.compile(rf"(function|def|func|fn|sub)\s+&?{name}\b|\b{name}\s*[:=]\s*(async\s*)?(function|\()"
                        rf"|\b(public|private|protected|static|async)\b[^;=]*\b{name}\s*\(")
        start = next((i for i, ln in enumerate(text) if rx.search(ln)), 0)
    body = "\n".join(f"{i + 1:5d}| {text[i]}" for i in range(start, min(len(text), start + lines)))
    return f"{unit['handler_file']} lines {start + 1}-{min(len(text), start + lines)} of {len(text)}:\n{body}"


def _review_unit(cfg: AuditConfig, root: Path, out: Path, unit: dict, entries: list[dict], facts: FactBook,
                 system: str, deadline: float | None, issues: IssueBoard | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    uid = ",".join(e["id"] for e in unit["entries"][:5])
    tb = Toolbox(cfg, root, out, facts=facts, unit=uid, issues=issues)
    llm = LLM(cfg)
    entry_view = {"routes": [{k: e.get(k) for k in ("id", "method", "route", "kind", "auth", "exposure",
                                                     "declared_at") if e.get(k)} for e in unit["entries"][:20]],
                  "more_routes": max(0, len(unit["entries"]) - 20),
                  "handler_file": unit["handler_file"], "handler": unit["handler"]}
    if unit.get("generic"):
        entry_view["handlers"] = unit["handlers"][:10]
        entry_view["note"] = ("these handlers are shared by many resources; review them for the resource of "
                              "these routes only (its access rules, ownership and stored data)")
    peers = _peers(unit, entries)
    user = "\n\n".join(x for x in (
        "Entry to review:\n" + json.dumps(entry_view, ensure_ascii=False),
        ("Similar entries (peers):\n" + "\n".join(peers)) if peers else "",
        facts.prompt_block(),
        issues.prompt_block() if issues is not None else "",
        _handler_snippet(root, unit)) if x)
    seen_facts = {f["id"] for f in facts.facts}
    seen_issues = {i["id"] for i in issues.issues} if issues is not None else set()

    def updates() -> str | None:
        """What other units verified or reported since this one started (units run in parallel)."""
        nf = facts.since(seen_facts, uid)
        ni = issues.since(seen_issues, uid) if issues is not None else []
        rows = [f"- {f['id']}: {f['statement']}" for f in nf]
        rows += [f"- {i['id']} ({i['cwe']}, {i['where']}): {i['root_cause']} -> use same_as={i['id']} if this "
                 "entry has the same root cause" for i in ni]
        return ("New from reviewers working in parallel:\n" + "\n".join(rows)) if rows else None

    res = run_agent(llm, tb, tool_schemas("review"), system, user, cfg.review_budget, out / "transcript.jsonl",
                    deadline=deadline, updates=updates)
    for x in tb.findings + tb.cards:
        x["entries"] = [e["id"] for e in unit["entries"]]
        x["handler"] = f"{unit['handler_file']}::{unit['handler']}"
    return {"findings": tb.findings, "cards": tb.cards, **_metrics(llm, res)}


def review(cfg: AuditConfig, root: Path, out: Path, entries: list[dict], deploy: str = "", product: str = "",
           surface_notes: str = "", deadline: float | None = None, access_model: dict | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    units = _units(entries)
    facts = FactBook(root)
    issues = IssueBoard()
    system = review_prompt(cfg.review_budget, deploy, product, surface_notes, access_model)
    results, skipped = _schedule(
        units, lambda i, u: _review_unit(cfg, root, out / f"unit-{i:04d}", u, entries, facts, system, deadline,
                                  issues),
        cfg.workers, deadline, cfg.stopped)
    findings = [f for r in results for f in r["findings"]]
    cards = [c for r in results for c in r["cards"]]
    not_reviewed = [e["id"] for u in skipped for e in u["entries"]]
    (out / "findings.json").write_text(json.dumps({"findings": findings, "not_reviewed": not_reviewed},
                                                  indent=1, ensure_ascii=False))
    (out / "cards.json").write_text(json.dumps(cards, indent=1, ensure_ascii=False))
    (out / "facts.json").write_text(json.dumps(facts.facts, indent=1, ensure_ascii=False))
    (out / "issues.json").write_text(json.dumps(issues.issues, indent=1, ensure_ascii=False))
    s = lambda k: sum(r.get(k, 0) for r in results)  # noqa: E731
    m = {"stage": "review", "entries": len(entries), "units": len(units), "reviewed_units": len(results),
         "skipped_units": len(skipped), "not_reviewed_entries": len(not_reviewed),
         "prompt_tokens": s("prompt_tokens"), "completion_tokens": s("completion_tokens"),
         "cached_tokens": s("cached_tokens"), "reasoning_tokens": s("reasoning_tokens"), "steps": s("steps"),
         "errors": sum(1 for r in results if r.get("error")), "facts": len(facts.facts),
         "cards": len(cards), "n_findings": len(findings), "root_causes": len(issues.issues),
         "authz_verdicts": dict(collections.Counter(c.get("authz_verdict") for c in cards)),
         "workers": cfg.workers, "llm_limiter": limiter_for(cfg).stats(),
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
    rv = review(cfg, root, out / "review", entries, deploy, product, rec.get("notes") or "", deadline,
                rec.get("access_model"))
    tok = lambda m, k: (m or {}).get(k, 0) or 0  # noqa: E731
    m = {"recon": rec, "review": rv,
         "total_tokens": sum(tok(x, "prompt_tokens") + tok(x, "completion_tokens") for x in (rec, rv)),
         "total_cached_tokens": sum(tok(x, "cached_tokens") for x in (rec, rv)),
         "total_wall_s": round(time.time() - start, 1), "time_budget_s": round(deadline - start)}
    (out / "metrics.json").write_text(json.dumps(m, indent=1, ensure_ascii=False))
    return m
