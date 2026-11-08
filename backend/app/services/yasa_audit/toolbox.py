"""Tools exposed to the agents.

- Navigation: list_dir / read_file / grep (ripgrep) and yasa-mcp queries (functions, callers, call graph,
  route -> handler, symbol search), answered from codegraph while YASA's call graph is not built.
- Recon: codegraph's route evidence, `run_extractor` (the agent writes a small program that enumerates
  the project's entries; the tool runs it and checks the result), `check_coverage` (are the places
  that read request data reachable from the entries found so far?).
- Review: `record_card` (what an entry does and its access-control verdict), `report_finding`,
  `add_fact` (a verified project fact shared with later reviewers).

All file access is confined to the project root (realpath + is_relative_to).
"""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from .config import AuditConfig

SKIP_DIRS = {".yasa", ".codegraph", "node_modules", ".git"}
MAX_OUT = 8000
ENTRY_KEYS = ("route", "method", "handler_file", "handler", "auth", "exposure", "declared_at", "kind")
EXPOSURES = ("public", "authenticated", "privileged", "unknown")
FINDING_REQUIRED = ("vuln_type", "cwe", "sink_file", "sink_line", "source", "entry", "required_privilege", "verdict")


def clip(text: str, limit: int = MAX_OUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars; narrow the query]"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def verify_evidence(root: Path, evidence: list[dict]) -> str | None:
    """None when every {file, line, quote} is found in the code within a few lines of `line`."""
    if not evidence:
        return "evidence is required: [{file, line, quote}]"
    for ev in evidence:
        if not isinstance(ev, dict):
            return "each evidence item is an object {file, line, quote}"
        p = (root / str(ev.get("file", "")).lstrip("/")).resolve()
        if not p.is_relative_to(root) or not p.is_file():
            return f"evidence file not found: {ev.get('file')}"
        lines = p.read_text(errors="ignore").splitlines()
        line, quote = int(ev.get("line") or 0), _norm(str(ev.get("quote") or ""))
        if not quote:
            return "each evidence item needs a quote copied from the code"
        window = _norm(" ".join(lines[max(0, line - 4):line + 3]))
        if quote not in window:
            return f"quote not found near {ev.get('file')}:{line}"
    return None


class FactBook:
    """Project facts shared by all review units.

    A fact is accepted only when every piece of evidence (file, line, quote) is found in the code, so
    reviewers cannot pass on guesses. Facts are short and numbered; reviewers cite the ids they relied
    on (record_card.facts_used), and the block given to later units keeps the most cited facts within a
    character budget, so foundational facts are not pushed out by recent, narrow ones.
    """

    MAX_STATEMENT = 240

    def __init__(self, root: Path, char_budget: int = 9000):
        self.root, self.char_budget = root, char_budget
        self.facts: list[dict] = []
        self._lock = threading.Lock()

    def verify(self, evidence: list[dict]) -> str | None:
        return verify_evidence(self.root, evidence)

    def add(self, statement: str, evidence: list[dict], unit: str) -> str:
        statement = _norm(statement)
        if len(statement) > self.MAX_STATEMENT:
            return (f"rejected: the statement has {len(statement)} characters; state the fact in at most "
                    f"{self.MAX_STATEMENT} (one claim, no explanation)")
        err = self.verify(evidence)
        if err:
            return f"rejected: {err}"
        with self._lock:
            for f in self.facts:
                if f["statement"].lower() == statement.lower():
                    return f"already known as {f['id']}"
            fid = f"F{len(self.facts) + 1}"
            self.facts.append({"id": fid, "statement": statement, "evidence": evidence, "unit": unit,
                               "cited": 0})
        return f"accepted as {fid}"

    def cite(self, ids: Any) -> list[str]:
        """Count citations; returns the ids that do not exist."""
        unknown = []
        with self._lock:
            by_id = {f["id"]: f for f in self.facts}
            for i in ids if isinstance(ids, list) else []:
                if str(i) in by_id:
                    by_id[str(i)]["cited"] += 1
                else:
                    unknown.append(str(i))
        return unknown

    def prompt_block(self) -> str:
        with self._lock:
            facts = sorted(self.facts, key=lambda f: (-f["cited"], int(f["id"][1:])))
        rows, used = [], 0
        for f in facts:
            where = ", ".join(f"{e.get('file')}:{e.get('line')}" for e in f["evidence"][:2])
            row = f"- {f['id']}: {f['statement']} ({where})"
            if used + len(row) > self.char_budget:
                continue
            rows.append(row)
            used += len(row) + 1
        if not rows:
            return ""
        return ("Verified project facts (rely on them instead of re-deriving; cite the ids you used in "
                "record_card.facts_used):\n" + "\n".join(rows))


class Toolbox:
    def __init__(self, cfg: AuditConfig, root: str | Path, run_dir: Path, facts: FactBook | None = None,
                 unit: str = ""):
        self.cfg = cfg
        self.root = Path(root).resolve()
        self.run_dir = run_dir
        self.facts = facts
        self.unit = unit
        self.findings: list[dict] = []
        self.cards: list[dict] = []
        self.finished = False
        self.notes = ""
        self.extractors: dict[str, dict] = {}  # name -> {"code", "entries"}
        self.manual: list[dict] = []
        self.coverage: dict | None = None
        self.access_model: dict | None = None
        # (condition, message): finish is refused while a condition holds (e.g. no access model yet)
        self.finish_gates: list[tuple[Any, str]] = []

    # ---------- helpers ----------
    def _safe(self, rel: str) -> Path:
        p = (self.root / str(rel).lstrip("/")).resolve()
        if not p.is_relative_to(self.root):
            raise ValueError("path escapes project root")
        return p

    def _mcp(self, args: list[str], timeout: int = 60) -> str:
        cmd = [self.cfg.yasamcp_bin, *args, "-p", str(self.root), "-j"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "error: navigation query timed out"
        except FileNotFoundError:
            return "error: yasa-mcp is not installed (see backend/scripts/setup_yasa.sh)"
        out = (r.stdout or "") + ("\n" + r.stderr[-1500:] if r.returncode and r.stderr else "")
        return clip(out.strip() or "(no result)")

    def _yasa_index_ready(self) -> bool:
        """yasa-mcp's func/callers/callgraph need the YASA call graph written by init."""
        d = self.root / ".yasa" / "yasamcp"
        return (d / "yasa.db").exists() and (d / "fingerprint_cache.json").exists()

    def _codegraph(self, args: list[str], timeout: int = 60) -> str:
        """Same questions answered from codegraph's index (built in seconds even for large projects)."""
        if not (self.root / ".codegraph" / "codegraph.db").exists():
            return "error: no navigation index for this project (use grep / read_file)"
        cmd = [self.cfg.codegraph_bin, *args, "-p", str(self.root)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "error: navigation query timed out"
        except FileNotFoundError:
            return "error: codegraph is not installed (see backend/scripts/setup_yasa.sh)"
        out = (r.stdout or "") + ("\n" + r.stderr[-1500:] if r.returncode and r.stderr else "")
        return clip("[codegraph]\n" + (out.strip() or "(no result)"))

    # ---------- navigation ----------
    def list_dir(self, path: str = ".", depth: int = 2) -> str:
        base = self._safe(path)
        lines = []
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(base)
            if any(part in SKIP_DIRS for part in rel.parts) or len(rel.parts) > int(depth):
                continue
            lines.append("  " * (len(rel.parts) - 1) + rel.name + ("/" if p.is_dir() else ""))
        return clip("\n".join(lines) or "(empty)")

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> str:
        p = self._safe(path)
        if not p.is_file():
            return f"error: not a file: {path}"
        lines = p.read_text(errors="ignore").splitlines()
        start = max(1, int(start_line or 1))
        end = int(end_line or 0) or min(len(lines), start + 119)
        end = min(end, start + 249, len(lines))
        body = "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(start, end + 1))
        return clip(f"{path} lines {start}-{end} of {len(lines)}\n{body}")

    def grep_rows(self, pattern: str, glob: str = "") -> list[str]:
        """All matching "file:line:code" rows, paths relative to the project root.

        ripgrep resolves a --glob that contains '/' against its working directory, so it runs inside
        the project root and searches '.'; otherwise path globs such as app/**/*.php never match.
        Case-sensitive unless the pattern says otherwise ((?i)).
        """
        cmd = [self.cfg.rg_bin, "-n", "--no-heading", "-s", "-M", "300", "--engine", "auto"]
        for d in SKIP_DIRS:
            cmd += ["-g", f"!{d}"]
        if glob:
            cmd += ["-g", glob]
        cmd += ["-e", pattern, "."]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=self.root)
        return sorted(line[2:] if line.startswith("./") else line for line in r.stdout.splitlines())

    def grep(self, pattern: str, glob: str = "", max_results: int = 60) -> str:
        try:
            rows = self.grep_rows(pattern, glob)
        except FileNotFoundError:
            return "error: ripgrep not found (set YASA_RG_BIN)"
        except subprocess.TimeoutExpired:
            return "error: search timed out; narrow the pattern or the glob"
        more = f"\n...[{len(rows) - int(max_results)} more matches]" if len(rows) > int(max_results) else ""
        return clip("\n".join(rows[: int(max_results)]) + more or "(no matches)")

    def find_function(self, name: str, file_path: str = "", detail: str = "summary") -> str:
        if not self._yasa_index_ready():
            return self._codegraph(["node", name])
        args = ["func", "--name", name, "--detail", detail, "--max-results", "10"]
        if file_path:
            args += ["--file-path", file_path]
        return self._mcp(args)

    def find_callers(self, name: str, file_path: str = "", line: int = 0) -> str:
        if not self._yasa_index_ready():
            return self._codegraph(["callers", name, "-l", "30"])
        args = ["callers", name, "--max-results", "30"]
        if file_path:
            args += ["--file-path", file_path]
        if line:
            args += ["--line", str(line)]
        return self._mcp(args)

    def call_graph(self, name: str, depth: int = 2, file_path: str = "") -> str:
        if not self._yasa_index_ready():
            return self._codegraph(["callees", name, "-l", "30"])
        args = ["callgraph", name, "--depth", str(depth), "--maxcallees", "8"]
        if file_path:
            args += ["--file-path", file_path]
        return self._mcp(args)

    def find_api(self, api_name: str) -> str:
        if not self._yasa_index_ready():
            return self._codegraph(["query", api_name, "-l", "20"])
        return self._mcp(["api", api_name, "--max-results", "20"])

    def search_symbol(self, query: str) -> str:
        if not self._yasa_index_ready():
            return self._codegraph(["query", query, "-l", "20"])
        return self._mcp(["search", query, "--max-results", "20"])

    # ---------- recon ----------
    def codegraph_routes(self, contains: str = "", limit: int = 40) -> str:
        """Routes codegraph's framework resolvers recognised (evidence, possibly incomplete or empty)."""
        from .discovery import codegraph_db, codegraph_routes
        db = codegraph_db(self.root)
        if db is None:
            return "no codegraph index"
        routes = [r for r in codegraph_routes(db, self.root)
                  if not contains or contains in r["route"] or contains in r["file"]]
        head = f"{len(routes)} routes recognised by codegraph"
        rows = [f"{r['method']} {r['route']} -> {r['file']}:{r['line']} {r.get('handler', '')}"
                for r in routes[: int(limit)]]
        return clip(head + ("\n" + "\n".join(rows) if rows else ""))

    def entries(self) -> list[dict]:
        """Union of all extractor outputs and manual entries, deduplicated."""
        seen, out = set(), []
        for e in [x for ex in self.extractors.values() for x in ex["entries"]] + self.manual:
            key = (e.get("method", "ANY"), e.get("route"), e.get("handler_file"), e.get("handler"))
            if key not in seen:
                seen.add(key)
                out.append(e)
        return out

    def _check_entry(self, e: dict) -> str | None:
        """None when the handler is concrete code in the project, else the reason it is not."""
        f = str(e.get("handler_file") or "")
        if not f:
            return "no handler_file"
        try:
            p = self._safe(f)
        except ValueError:
            return "handler_file escapes the project"
        if not p.is_file():
            return "handler_file does not exist"
        h = str(e.get("handler") or "").split("::")[-1].split(".")[-1].split("#")[-1]
        if h and h not in p.read_text(errors="ignore"):
            return f"handler '{h}' does not occur in handler_file"
        return None

    def _clean(self, raw: Any, origin: str) -> tuple[list[dict], list[str]]:
        if not isinstance(raw, list):
            return [], ["output must be a JSON list of entry objects"]
        out, problems = [], []
        for e in raw:
            if not isinstance(e, dict) or not e.get("route"):
                problems.append(f"skipped item without route: {str(e)[:120]}")
                continue
            e = {k: e.get(k) for k in ENTRY_KEYS if e.get(k) not in (None, "")} | {"origin": origin}
            e["handler_file"] = str(e.get("handler_file", "")).lstrip("./") if e.get("handler_file") else ""
            if e.get("exposure") not in EXPOSURES:
                e["exposure"] = "unknown"
            e["method"] = str(e.get("method") or "ANY").upper()
            out.append(e)
        return out, problems

    def _summary(self, entries: list[dict]) -> dict:
        bad = [(e, why) for e in entries if (why := self._check_entry(e))]
        by_exp: dict[str, int] = {}
        for e in entries:
            by_exp[e["exposure"]] = by_exp.get(e["exposure"], 0) + 1
        ok = [e for e in entries if not self._check_entry(e)]
        rnd = random.Random(len(entries))
        return {"entries": len(entries), "handler_resolved": len(ok), "handler_unresolved": len(bad),
                "by_exposure": by_exp,
                "unresolved_samples": [f"{e['route']} -> {e.get('handler_file')}::{e.get('handler')} ({why})"
                                       for e, why in bad[:8]],
                "random_resolved_samples_to_check_by_reading": [
                    f"{e['method']} {e['route']} -> {e['handler_file']}::{e.get('handler', '')} "
                    f"auth={e.get('auth', '?')} exposure={e['exposure']}"
                    for e in rnd.sample(ok, min(8, len(ok)))]}

    def run_extractor(self, name: str, code: str) -> str:
        """Run a Python program the agent wrote. It receives the project root as sys.argv[1] and must
        print a JSON list of entries. The result replaces any earlier extractor of the same name."""
        if not re.fullmatch(r"[\w-]{1,40}", str(name)):
            return "error: name must be 1-40 letters, digits, '-' or '_'"
        work = Path(tempfile.mkdtemp(prefix="extractor-", dir=str(self.run_dir)))
        script = work / f"{name}.py"
        script.write_text(code)
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}
        try:
            r = subprocess.run([sys.executable, "-I", str(script), str(self.root)], capture_output=True,
                               text=True, timeout=180, cwd=work, env=env)
        except subprocess.TimeoutExpired:
            return "error: extractor ran longer than 180 s"
        if r.returncode:
            return clip(f"error: extractor exited {r.returncode}\n{r.stderr[-3000:]}", 4000)
        try:
            raw = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return clip(f"error: stdout is not JSON ({e}); first bytes: {r.stdout[:300]!r}", 2000)
        entries, problems = self._clean(raw, f"extractor:{name}")
        prev = self.extractors.get(name)
        self.extractors[name] = {"code": code, "entries": entries}
        (self.run_dir / "extractors").mkdir(exist_ok=True)
        (self.run_dir / "extractors" / f"{name}.py").write_text(code)
        res = {"extractor": name, **self._summary(entries), "problems": problems[:5],
               "total_entries_all_extractors": len(self.entries())}
        if prev is not None:  # a rewrite must not silently lose part of the surface
            key = lambda e: (e.get("method"), e.get("route"))  # noqa: E731
            old, new = {key(e): e for e in prev["entries"]}, {key(e): e for e in entries}
            removed = [old[k] for k in old.keys() - new.keys()]
            by_dir: dict[str, int] = {}
            for e in removed:
                d = "/".join(os.path.dirname(str(e.get("handler_file") or "?")).split("/")[:4]) or "."
                by_dir[d] = by_dir.get(d, 0) + 1
            res["change_from_previous_version"] = {
                "previous": len(old), "now": len(new), "added": len(new.keys() - old.keys()),
                "removed": len(removed),
                "removed_by_directory": sorted(by_dir.items(), key=lambda kv: -kv[1])[:10]}
            if len(removed) > max(5, len(old) // 5):
                res["warning"] = (f"this version lost {len(removed)} of {len(old)} entries of the previous "
                                  "one; check that this was intended (a bug in the rewrite, an exception "
                                  "caught too broadly, a changed path) before you finish")
        return clip(json.dumps(res, ensure_ascii=False, indent=1))

    def add_entries(self, entries: list[dict]) -> str:
        """Add entries by hand (a few special ones an extractor would not cover)."""
        clean, problems = self._clean(entries, "manual")
        self.manual += clean
        return clip(json.dumps({**self._summary(clean), "problems": problems[:5],
                                "total_entries_all_extractors": len(self.entries())}, ensure_ascii=False))

    def check_coverage(self, request_read_pattern: str, glob: str = "", depth: int = 3) -> str:
        """Places that read request data (ripgrep pattern for THIS project's request API) that are not
        in, or reachable within `depth` codegraph edges from, any entry's handler file. Uncovered places
        point at entry points the extractors have missed (or at code that is not request-reachable)."""
        from .discovery import reachable_files
        try:
            rows = self.grep_rows(request_read_pattern, glob)
        except subprocess.TimeoutExpired:
            return "error: search timed out; narrow the pattern"
        sites = [r.split(":", 2) for r in rows if r.count(":") >= 2]
        files = sorted({s[0] for s in sites})
        handlers = sorted({e["handler_file"] for e in self.entries() if e.get("handler_file")})
        reach = reachable_files(self.root, handlers, depth=int(depth)) or set(handlers)
        unc = [s for s in sites if s[0] not in reach]
        by_dir: dict[str, int] = {}
        for s in unc:
            d = "/".join(s[0].split("/")[:-1]) or "."
            by_dir[d] = by_dir.get(d, 0) + 1
        self.coverage = {"pattern": request_read_pattern, "sites": len(sites), "files": len(files),
                         "covered_sites": len(sites) - len(unc), "uncovered_sites": len(unc)}
        share = len(unc) / len(sites) if sites else 0.0
        res = {**self.coverage, "uncovered_share": round(share, 2),
               "reading": ("most request reads are not reachable from your entries: some dispatcher or "
                           "area is missing, or entries point at the wrong handlers" if share > 0.5 else
                           "some request reads are not reachable: look at the directories below" if share > 0.1
                           else "request reads are covered"),
               "uncovered_by_directory": sorted(by_dir.items(), key=lambda kv: -kv[1])[:20],
               "uncovered_samples": [":".join(s)[:200] for s in unc[:10]]}
        return clip(json.dumps(res, ensure_ascii=False, indent=1))

    # ---------- review / output ----------
    def _anchor_ok(self, anchor: Any) -> bool:
        m = re.match(r"^\s*([^:\s]+):(\d+)", str(anchor or ""))
        if not m:
            return False
        try:
            p = self._safe(m.group(1))
        except ValueError:
            return False
        return p.is_file() and 0 < int(m.group(2)) <= len(p.read_text(errors="ignore").splitlines())

    def record_card(self, **card: Any) -> str:
        """Record (or replace) this unit's card. Every hypothesis must name the operation that makes the
        risk plausible, as file:line, so risks are derived from code rather than from a checklist."""
        hyps = card.get("hypotheses") or []
        bad = [str(h.get("risk", "?")) for h in hyps if isinstance(h, dict) and not self._anchor_ok(h.get("anchor"))]
        if bad:
            return ("rejected: these hypotheses have no anchor (file:line of the operation in the code that "
                    f"makes the risk plausible): {bad[:6]}. Anchor them, or drop risks the code gives no "
                    "reason to suspect.")
        unknown = self.facts.cite(card.get("facts_used")) if self.facts is not None else []
        card["_unit"] = self.unit
        self.cards = [card]  # a later call updates the card
        return "card recorded" + (f" (unknown fact ids ignored: {unknown})" if unknown else "")

    def record_access_model(self, **model: Any) -> str:
        """The project-wide model of how requests are authenticated and authorized (recon stage)."""
        need = ("authentication", "authorization", "permission_mapping", "principals")
        missing = [k for k in need if not str(model.get(k) or "").strip()]
        if missing:
            return f"rejected: missing {', '.join(missing)}"
        err = verify_evidence(self.root, model.get("evidence") or [])
        if err:
            return f"rejected: {err}"
        self.access_model = {k: model.get(k) for k in (*need, "public_by_default", "evidence")}
        return "access model recorded"

    def report_finding(self, **finding: Any) -> str:
        missing = [k for k in FINDING_REQUIRED if finding.get(k) in (None, "")]
        if missing:
            return f"rejected: missing {', '.join(missing)}; send the finding again with them"
        if finding.get("verdict") not in ("confirmed", "likely"):
            return "rejected: verdict must be confirmed or likely (record rejected risks in record_card)"
        finding["_unit"] = self.unit
        self.findings.append(finding)
        return f"recorded #{len(self.findings)}"

    def add_fact(self, statement: str, evidence: Any) -> str:
        if self.facts is None:
            return "error: no fact book in this stage"
        if isinstance(evidence, dict):
            evidence = [evidence]
        return self.facts.add(str(statement), evidence if isinstance(evidence, list) else [], self.unit)

    def finish(self, notes: str = "", _force: bool = False) -> str:
        for cond, msg in self.finish_gates:
            if not _force and cond(self):
                return f"not finished: {msg}"
        self.finished = True
        self.notes = notes
        return f"finished ({len(self.findings)} findings, {len(self.cards)} cards)"


def tool_schemas(role: str) -> list[dict]:
    """role: 'recon' (surface), 'access' (access-control model) or 'review'."""
    def fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
        return {"type": "function", "function": {
            "name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required}}}

    s, i = {"type": "string"}, {"type": "integer"}
    tools = [
        fn("list_dir", "List files under a project directory (relative path).", {"path": s, "depth": i}, []),
        fn("read_file", "Read a file with line numbers (default 120 lines, at most 250 per call).",
           {"path": s, "start_line": i, "end_line": i}, ["path"]),
        fn("grep", "Ripgrep regex over the project, case-sensitive ((?i) for insensitive). Returns "
                   "file:line:text. glob is relative to the project root, e.g. app/**/*.php or *.xml.",
           {"pattern": s, "glob": s, "max_results": i}, ["pattern"]),
        fn("find_function", "Find a function definition by name. detail=full returns the body.",
           {"name": s, "file_path": s, "detail": {"type": "string", "enum": ["summary", "full"]}}, ["name"]),
        fn("find_callers", "Find call sites of a function.", {"name": s, "file_path": s, "line": i}, ["name"]),
        fn("call_graph", "Call graph (callees) of a function to a given depth.",
           {"name": s, "depth": i, "file_path": s}, ["name"]),
        fn("find_api", "Map an HTTP route / API name to its implementing function.", {"api_name": s},
           ["api_name"]),
        fn("search_symbol", "Search functions/classes/files by name.", {"query": s}, ["query"]),
    ]
    entry = {"type": "object", "properties": {
        "route": s, "method": s, "handler_file": s, "handler": s, "kind": s, "declared_at": s,
        "auth": {"type": "string", "description": "what the code/config says about authentication or "
                 "authorization for this entry, verbatim where possible"},
        "exposure": {"type": "string", "enum": list(EXPOSURES)}}}
    if role == "access":
        tools += [
            fn("record_access_model",
               "Record how THIS project authenticates and authorizes requests, once, before finish. "
               "Reviewers of every entry rely on it instead of re-reading the security chain.",
               {"authentication": {"type": "string", "description": "how a request gets an identity "
                                   "(sessions, tokens, filters) and what an anonymous request is"},
                "authorization": {"type": "string", "description": "where access is decided (file:line) "
                                  "and what happens when no rule matches"},
                "permission_mapping": {"type": "string", "description": "how a request (method, path, "
                                       "resource) is turned into the permission that is checked"},
                "principals": {"type": "string", "description": "the roles/principals from least to most "
                               "privileged, who gets each (any visitor, any registered user, ...), and how "
                               "to tell from an entry's declaration which is the least one that can call it"},
                "public_by_default": s,
                "evidence": {"type": "array", "items": {"type": "object", "properties": {
                    "file": s, "line": i, "quote": s}}}},
               ["authentication", "authorization", "permission_mapping", "principals", "evidence"]),
        ]
    elif role == "recon":
        tools += [
            fn("codegraph_routes", "Routes that codegraph's framework resolvers recognised. Evidence only: "
               "may be empty or incomplete for this project.", {"contains": s, "limit": i}, []),
            fn("run_extractor",
               "Run a Python 3 program you wrote that enumerates entries of THIS project. It gets the "
               "project root as sys.argv[1], may read any file there (standard library only, no network) "
               "and must print a JSON list of objects with keys route, method, handler_file (relative), "
               "handler (function/method name), kind, auth, exposure (public|authenticated|privileged|"
               "unknown), declared_at (file:line). Returns counts, unresolved handlers and random samples "
               "to verify. Several extractors may cover different parts of the surface; the same name "
               "replaces the earlier version.", {"name": s, "code": s}, ["name", "code"]),
            fn("add_entries", "Add a few entries by hand (same keys as extractor output).",
               {"entries": {"type": "array", "items": entry}}, ["entries"]),
            fn("check_coverage",
               "Coverage check: give a ripgrep pattern matching how THIS project reads request data "
               "(e.g. the request object's getter calls). Lists read sites not reachable from any "
               "entry handler found so far, grouped by directory.",
               {"request_read_pattern": s, "glob": s, "depth": i}, ["request_read_pattern"]),
        ]
    else:
        tools += [
            fn("record_card",
               "Record this entry's card: first as soon as you know the scenario and access control, "
               "then again with every hypothesis's final status (a later call replaces the card).",
               {"function": {"type": "string", "description": "what the entry does, in business terms"},
                "callers": {"type": "string", "description": "who can call it, with the evidence"},
                "authz_verdict": {"type": "string", "enum": ["ok", "missing_authentication",
                                                             "missing_authorization", "object_level",
                                                             "unclear"]},
                "authz_evidence": {"type": "string", "description": "file:line of the checks that apply"},
                "inputs": s, "objects": {"type": "string", "description": "data/resources it reads or changes"},
                "persists": {"type": "string", "description": "user-controlled values it stores, and where"},
                "hypotheses": {"type": "array", "items": {"type": "object", "properties": {
                    "risk": s,
                    "anchor": {"type": "string", "description": "file:line of the operation that makes this "
                               "risk plausible (where the request value is stored, queried, fetched, "
                               "rendered, used to pick an object, ...)"},
                    "why": s, "status": {"type": "string", "enum": ["confirmed", "rejected", "open"]},
                    "evidence": s}, "required": ["risk", "anchor", "status"]}},
                "facts_used": {"type": "array", "items": s,
                               "description": "ids of verified facts you relied on (e.g. F3)"}},
               ["function", "callers", "authz_verdict", "hypotheses"]),
            fn("report_finding", "Record ONE vulnerability (access control or data flow) you confirmed or "
               "consider likely, with file:line hops.",
               {"vuln_type": s, "cwe": s, "sink_file": s, "sink_line": i,
                "source": {"type": "string", "description": "attacker-controlled input and where"},
                "entry": {"type": "string", "description": "route and who can reach it"},
                "required_privilege": {"type": "string",
                                       "enum": ["none", "customer", "admin", "operator_or_cli"]},
                "hops": {"type": "array", "items": s},
                "sanitizers": s,
                "verdict": {"type": "string", "enum": ["confirmed", "likely"]}},
               ["vuln_type", "cwe", "sink_file", "sink_line", "source", "entry", "required_privilege",
                "verdict"]),
            fn("add_fact", "Share a project fact other reviewers can rely on: one claim, at most 240 "
               "characters (e.g. how a helper escapes, that all data access goes through a typed query API, "
               "which base class enforces login). Rejected unless each quote is found at file:line.",
               {"statement": s, "evidence": {"type": "array", "items": {"type": "object", "properties": {
                   "file": s, "line": i, "quote": s}}}}, ["statement", "evidence"]),
        ]
    tools.append(fn("finish", "Call once when you are done.", {"notes": s}, []))
    return tools
