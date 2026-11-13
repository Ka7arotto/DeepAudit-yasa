"""What is worth protecting: sensitive operations and identity subsystems, mapped once per project.

Entry-first review starts where requests come in and reads forward. It stops at the first sanitizer,
does not see code that no route reaches directly (render pipelines, hooks, extension points), and judges
one route at a time, never the design of a module. This stage maps the other end, so the review can
also start there:

operations  Seven fixed classes of harmful operation (OP_CLASSES). They describe effects, not
            frameworks. An agent finds how THIS project performs each class: the sensitive fields of
            its data model, the guards the project applies itself (permission and ownership checks,
            escaping, allowlists), the helpers the operations go through. It writes each form as a
            declarative recipe: a search pattern and, optionally, the project's guard for it. The
            executor here expands a recipe over the whole project and places every site in the call
            graph. It reports which entries reach the site, whether anything calls it at all (an
            extension point), and whether the guard is on the way. The agent refines its recipes on
            these counters, the same way it refines extractors on coverage. Each site becomes part of
            a review unit that works backward from the operation to every way of reaching it.
identity    The subsystems that create or prove an identity (registration, login, recovery, SSO,
            tokens, account linking, user management), each with its routes, files, models and
            settings. Each subsystem gets one design review against a fixed checklist
            (IDENTITY_CHECKLIST). The flaws in these subsystems sit in how the parts fit together,
            not on one route.

Everything in this module is deterministic: the agents decide what to look for, and this code
expands it and does the counting.
"""

from __future__ import annotations

import collections
import json
import random
import re
import threading
from pathlib import Path
from typing import Any

from .discovery import _connect, codegraph_db

# The classes are fixed and framework-independent; their concrete forms come from the project.
OP_CLASSES: dict[str, str] = {
    "credential_or_privilege_write": "sets or changes an account's password, credentials, tokens, role, group "
                                     "membership or permissions (creating an account with them included)",
    "personal_data_output": "puts personal or secret fields (email, IP address, password hash, token, phone, "
                            "address) into a response, export, feed or log that someone else can read",
    "object_by_request_id": "loads, changes or deletes a stored object chosen by an id, key or path that "
                            "comes from the request",
    "outbound_request": "makes the server fetch a URL or connect to a host (HTTP clients, URL openers, "
                        "mail or webhook senders, embed/preview fetchers)",
    "raw_markup_output": "writes stored or request data into HTML, markup or an attribute without the "
                         "project's escaping (raw template output, innerHTML, unescaped attributes, "
                         "directive, shortcode or Markdown processing that runs after sanitizing)",
    "state_change_in_read_path": "changes persistent state on a path meant to only read (GET handlers, "
                                 "permission or visibility callbacks, renderers, getters, feeds)",
    "file_write": "writes, moves, extracts or deletes a file (uploads, exports, caches, archives, "
                  "generated code or configuration)",
}

IDENTITY_KINDS = ("registration", "login", "password_recovery", "sso", "api_token", "account_linking",
                  "invitation", "mfa", "session", "user_management")

# One design question per item, the same for every project and subsystem.
IDENTITY_CHECKLIST: dict[str, str] = {
    "identity_binding": "How is an external or asserted identity (SSO/OAuth subject, email, username, "
                        "invitation, token owner) bound to a local account? Is the key immutable and "
                        "verified, or a field the user or the provider can change (email, username, "
                        "display name)? Can one identity reach another's account?",
    "record_claiming": "Can an existing record that is not an active, credentialed account (deactivated, "
                       "guest, pending, invited, imported, soft-deleted, unverified) be claimed by "
                       "registration, login, SSO or recovery, and what does the claimant inherit (groups, "
                       "roles, data, history)?",
    "token_lifecycle": "For each secret the subsystem issues (reset codes, activation and invitation links, "
                       "API or access tokens, remember-me, sessions, MFA codes): does it expire, is it "
                       "single-use, bound to the account and purpose, stored hashed, compared in constant "
                       "time, and revoked when the password, email or role changes?",
    "defaults": "What does an install with no configuration allow (open registration, the role of new "
                "accounts, verification off, SSO auto-create or auto-link, token scopes), and which "
                "security settings are off by default?",
    "privilege_ceiling": "Can a manager grant or reach more than they hold: assign roles, groups or "
                         "permissions above their own, change the credentials, email or MFA of an account "
                         "more privileged than themselves, or get there indirectly (groups, invitations, "
                         "impersonation, token scopes)?",
}
DESIGN_STATUSES = ("sound", "flaw", "owner_decision", "unclear", "not_applicable")

# Code that is not the product: tests, vendored dependencies, built bundles.
NOISE_PATH = re.compile(r"(^|/)(tests?|spec|specs|__tests__|__mocks__|fixtures?|vendor|node_modules|"
                        r"bower_components)(/|$)|\.(test|spec)\.\w+$|\.min\.js$")
MAX_SITES = 1500  # a recipe matching more is a word search, not an operation
ANCESTOR_DEPTH = 6
GUARD_DEPTH = 3  # the guard counts when it is in the operation's function or a caller this close
REACH_ORDER = {"handler": 0, "entry": 1, "no_callers": 2, "internal": 3}

FUNCS = ("function", "method")
TYPES = ("class", "interface", "trait", "enum", "struct")


# ----------------------------------------------------------------- the call index

def _tail(name: str) -> str:
    return re.split(r"::|\.|#|->|\\", name or "")[-1]


class CallIndex:
    """Function spans and reverse call edges from codegraph's index, loaded once.

    A call to an interface or parent method counts as a call to the implementations of it (the same
    rule graph.py follows for find_callers). Without an index every site is file-level code.
    """

    def __init__(self, root: Path):
        self.root = root
        self.spans: dict[str, list[tuple[int, int, str]]] = collections.defaultdict(list)
        self.loc: dict[str, tuple[str, int, int, str]] = {}  # id -> (file, start, end, qualified name)
        self.callers: dict[str, set[str]] = collections.defaultdict(set)
        self.overrides: dict[str, list[str]] = collections.defaultdict(list)  # method -> parent methods
        self._lines: dict[str, list[str]] = {}
        db = codegraph_db(root)
        self.indexed = db is not None
        if db is not None:
            self._load(db)

    def _load(self, db: Path) -> None:
        con = _connect(db)
        try:
            kinds = (*FUNCS, *TYPES)
            nodes = con.execute("select id, kind, name, qualified_name, file_path, start_line, end_line from nodes "
                                f"where kind in ({','.join('?' * len(kinds))})", kinds).fetchall()
            edges = con.execute("select source, target, kind from edges where kind in "
                                "('calls', 'instantiates', 'contains', 'extends', 'implements')").fetchall()
        finally:
            con.close()
        kind_of, name_of = {}, {}
        for nid, kind, name, qn, f, s, e in nodes:
            kind_of[nid], name_of[nid] = kind, name
            if kind in FUNCS and f:
                self.loc[nid] = (f, int(s or 0), int(e or s or 0), qn or name)
                self.spans[f].append((int(s or 0), int(e or s or 0), nid))
        methods: dict[tuple[str, str], list[str]] = collections.defaultdict(list)  # (type, name) -> methods
        owner: dict[str, str] = {}
        parents: dict[str, list[str]] = collections.defaultdict(list)
        for src, dst, kind in edges:
            if kind in ("calls", "instantiates"):
                self.callers[dst].add(src)
            elif kind == "contains" and kind_of.get(src) in TYPES and kind_of.get(dst) in FUNCS:
                owner[dst] = src
                methods[(src, name_of[dst])].append(dst)
            elif kind in ("extends", "implements"):
                parents[src].append(dst)
        for m, t in owner.items():
            for p in parents.get(t, []):
                self.overrides[m] += methods.get((p, name_of[m]), [])
        for f in self.spans:
            self.spans[f].sort()

    def lines(self, file: str) -> list[str]:
        if file not in self._lines:
            p = self.root / file
            try:
                self._lines[file] = p.read_text(errors="ignore").splitlines() if p.is_file() else []
            except OSError:
                self._lines[file] = []
        return self._lines[file]

    def enclosing(self, file: str, line: int) -> str | None:
        """The innermost function or method whose span contains file:line."""
        best = None
        for s, e, nid in self.spans.get(file, ()):
            if s > line:
                break
            if s <= line <= e and (best is None or e - s < best[1] - best[0]):
                best = (s, e, nid)
        return best[2] if best else None

    def named(self, file: str, name: str) -> str | None:
        """A function or method of the file called `name` (the last part of a qualified name)."""
        tail = _tail(name)
        return next((nid for _s, _e, nid in self.spans.get(file, ()) if _tail(self.loc[nid][3]) == tail), None)

    def direct_callers(self, fid: str) -> set[str]:
        out = set(self.callers.get(fid, ()))
        for p in self.overrides.get(fid, ()):
            out |= self.callers.get(p, set())
        return out - {fid}

    def ancestors(self, fid: str, depth: int = ANCESTOR_DEPTH, cap: int = 800) -> dict[str, int]:
        """Functions that reach fid through calls, with their distance."""
        seen, frontier = {fid: 0}, [fid]
        for d in range(1, depth + 1):
            nxt = []
            for f in frontier:
                for c in self.direct_callers(f):
                    if c not in seen:
                        seen[c] = d
                        nxt.append(c)
            frontier = nxt
            if not frontier or len(seen) > cap:
                break
        seen.pop(fid)
        return seen

    def span_text(self, fid: str) -> tuple[str, int, list[str]]:
        f, s, e, _ = self.loc[fid]
        return f, s, self.lines(f)[max(0, s - 1):e]


def _entry_maps(index: CallIndex, entries: list[dict]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Entry ids by the function that handles them, and by handler file."""
    by_fn: dict[str, list[str]] = collections.defaultdict(list)
    by_file: dict[str, list[str]] = collections.defaultdict(list)
    for i, e in enumerate(entries):
        eid, f = str(e.get("id") or f"#{i}"), str(e.get("handler_file") or "")
        if not f:
            continue
        by_file[f].append(eid)
        fid = (index.enclosing(f, int(e["handler_line"])) if e.get("handler_line") else None) \
            or index.named(f, str(e.get("handler") or ""))
        if fid:
            by_fn[fid].append(eid)
    return by_fn, by_file


# ----------------------------------------------------------------- recipes

RECIPE_KEYS = ("name", "op_class", "pattern", "glob", "exclude", "guard", "why")


def check_recipe(r: dict) -> str | None:
    if not re.fullmatch(r"[\w-]{1,40}", str(r.get("name") or "")):
        return "name must be 1-40 letters, digits, '-' or '_'"
    if r.get("op_class") not in OP_CLASSES:
        return f"op_class must be one of {', '.join(OP_CLASSES)}"
    if not str(r.get("pattern") or "").strip():
        return "pattern is required"
    for k in ("exclude", "guard"):
        if r.get(k):
            try:
                re.compile(r[k])
            except re.error as e:
                return f"{k} is not a Python regular expression: {e}"
    return None


def expand(recipe: dict, rows: list[str], index: CallIndex, entries: list[dict],
           maps: tuple[dict, dict] | None = None) -> list[dict]:
    """The sites of a recipe (ripgrep rows "file:line:code"), each placed in the call graph."""
    by_fn, by_file = maps or _entry_maps(index, entries)
    exclude = re.compile(recipe["exclude"]) if recipe.get("exclude") else None
    guard = re.compile(recipe["guard"]) if recipe.get("guard") else None
    sites = []
    for row in rows:
        parts = row.split(":", 2)
        if len(parts) < 3 or not parts[1].isdigit() or NOISE_PATH.search(parts[0]):
            continue
        file, line, code = parts[0], int(parts[1]), parts[2].strip()
        if exclude and exclude.search(code):
            continue
        fid = index.enclosing(file, line)
        site: dict[str, Any] = {"recipe": recipe["name"], "op_class": recipe["op_class"], "file": file,
                                "line": line, "code": code[:200]}
        if fid is None:  # file-level code: a script, a template, a module body
            site.update(function=f"<{file}>", span=[1, len(index.lines(file))])
            ids = by_file.get(file, [])
            site["reach"] = "handler" if ids else "no_callers"
            site["entries"] = ids[:40]
            near: dict[str, int] = {}
        else:
            f, s, e, qn = index.loc[fid]
            site.update(function=qn, span=[s, e])
            near = index.ancestors(fid)
            if by_fn.get(fid):
                site["reach"], ids = "handler", list(by_fn[fid])
            else:
                ids = sorted({x for a in near for x in by_fn.get(a, ())})
                site["reach"] = "entry" if ids else ("internal" if near else "no_callers")
            site["entries"] = ids[:40]
            site["callers"] = len(index.direct_callers(fid))
        site["entries_total"] = len(ids)
        if guard is not None:
            site["guard_at"] = _guard_at(index, guard, file, line, fid, near)
        sites.append(site)
    return sites


def _guard_at(index: CallIndex, guard: re.Pattern, file: str, line: int, fid: str | None,
              near: dict[str, int]) -> str | None:
    """Where the project's guard for this operation is applied on the way to it: in the operation's
    function before the operation, or in a caller within GUARD_DEPTH calls. None when it is not."""
    if fid is None:
        rows = [(i + 1, t) for i, t in enumerate(index.lines(file)[:line])]
        hit = next((n for n, t in rows if guard.search(t)), None)
        return f"{file}:{hit}" if hit else None
    scopes = [(fid, line)] + [(a, None) for a, d in sorted(near.items(), key=lambda kv: kv[1]) if d <= GUARD_DEPTH]
    for nid, until in scopes[:60]:
        f, s, body = index.span_text(nid)
        for i, t in enumerate(body):
            if until is not None and s + i > until:
                break
            if guard.search(t):
                return f"{f}:{s + i}"
    return None


def site_key(s: dict) -> str:
    return f"{s['file']}:{s['line']}"


def counters(recipe: dict, sites: list[dict], entries_known: int, seed: int = 0) -> dict:
    """What the agent refines a recipe on."""
    reach = collections.Counter(s["reach"] for s in sites)
    out: dict[str, Any] = {
        "recipe": recipe["name"], "op_class": recipe["op_class"], "sites": len(sites),
        "files": len({s["file"] for s in sites}), "functions": len({(s["file"], s["function"]) for s in sites}),
        "reach": {k: reach.get(k, 0) for k in REACH_ORDER},
        "reach_meaning": "handler: in an entry's handler; entry: an entry reaches it through calls; no_callers: "
                         "nothing in the repository calls it (framework hook, extension point, public API, "
                         "or dead code); internal: called, but no enumerated entry reaches it",
        "entries_known": entries_known}
    if recipe.get("guard"):
        g = [s for s in sites if s.get("guard_at")]
        out["guard"] = {"pattern": recipe["guard"], "guarded": len(g), "unguarded": len(sites) - len(g)}
    rnd = random.Random(seed or len(sites))
    fmt = lambda s: (f"{site_key(s)} in {s['function']} [{s['reach']}"  # noqa: E731
                     + (f", guard at {s['guard_at']}" if s.get("guard_at") else
                        ", no guard" if recipe.get("guard") else "") + f"] {s['code'][:110]}")
    out["samples_to_read"] = [fmt(s) for s in rnd.sample(sites, min(6, len(sites)))]
    if recipe.get("guard"):
        out["unguarded_samples"] = [fmt(s) for s in sites if not s.get("guard_at")][:6]
    if not sites:
        out["note"] = "no site: check the pattern against code you have read (ripgrep syntax, case-sensitive)"
    return out


# ----------------------------------------------------------------- identity subsystems

def check_identity(subsystems: Any, root: Path) -> tuple[list[dict], list[str]]:
    """Clean the agent's identity subsystems; problems are returned to it."""
    if not isinstance(subsystems, list):
        return [], ["subsystems must be a list (empty if the project creates no identities)"]
    out, problems = [], []
    for s in subsystems:
        if not isinstance(s, dict) or not str(s.get("name") or "").strip():
            problems.append(f"skipped an item without a name: {str(s)[:100]}")
            continue
        kind = str(s.get("kind") or "")
        if kind not in IDENTITY_KINDS:
            problems.append(f"{s['name']}: kind must be one of {', '.join(IDENTITY_KINDS)}")
            continue
        routes = [str(r) for r in (s.get("routes") or []) if str(r).strip()]
        bad = []
        for r in routes:
            try:
                re.compile(r)
            except re.error:
                bad.append(r)
        files = [str(f).strip().lstrip("./") for f in (s.get("files") or []) + (s.get("models") or [])
                 if str(f).strip()]
        missing = [f for f in files if not (root / f).exists()]
        if bad or missing or not (routes or files):
            problems.append(f"{s['name']}: " + "; ".join(
                x for x in (f"routes that are not regular expressions: {bad}" if bad else "",
                            f"files that do not exist: {missing[:5]}" if missing else "",
                            "give its routes or files" if not (routes or files) else "") if x))
            continue
        out.append({"name": str(s["name"])[:80], "kind": kind, "routes": routes[:12],
                    "files": [str(f).strip().lstrip("./") for f in (s.get("files") or [])][:20],
                    "models": [str(f).strip().lstrip("./") for f in (s.get("models") or [])][:10],
                    "settings": [str(x)[:200] for x in (s.get("settings") or [])][:12],
                    "notes": str(s.get("notes") or "")[:1500]})
    return out, problems


def _under(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def group_identity(subsystem: dict, entries: list[dict], sites: list[dict]) -> dict:
    """The entries and operation sites that belong to an identity subsystem."""
    rx = [re.compile(r, re.I) for r in subsystem["routes"]]
    files = subsystem["files"] + subsystem["models"]
    ids = [str(e.get("id") or f"#{i}") for i, e in enumerate(entries)
           if any(r.search(str(e.get("route") or "")) for r in rx) or _under(str(e.get("handler_file") or ""), files)]
    own = set(ids)
    near = [s for s in sites if _under(s["file"], files) or own & set(s.get("entries") or [])]
    return {**subsystem, "entry_ids": ids, "site_keys": [site_key(s) for s in near]}


# ----------------------------------------------------------------- the map

def build(tb: Any, recipes: dict[str, dict], identity: list[dict] | None, absent: dict[str, str],
          entries: list[dict]) -> dict:
    """Expand every recipe over the final entries, group the identity subsystems: recon/assets.json."""
    index = tb.call_index()
    maps = _entry_maps(index, entries)
    sites: dict[str, dict] = {}
    per_recipe = {}
    for r in recipes.values():
        try:
            rows = tb.grep_rows(r["pattern"], r.get("glob") or "")
        except Exception:  # a pattern that times out now is left out, not the whole map
            continue
        found = expand(r, rows, index, entries, maps)
        per_recipe[r["name"]] = len(found)
        for s in found:  # one site per file:line (two recipes may find the same operation)
            sites.setdefault(site_key(s), s)
    groups = [group_identity(s, entries, list(sites.values())) for s in (identity or [])]
    reach = collections.Counter(s["reach"] for s in sites.values())
    return {"recipes": list(recipes.values()), "absent": absent, "sites": list(sites.values()),
            "identity": groups,
            "summary": {"recipes": per_recipe, "sites": len(sites), "indexed": index.indexed,
                        "by_class": dict(collections.Counter(s["op_class"] for s in sites.values())),
                        "by_reach": dict(reach),
                        "unguarded": sum(1 for s in sites.values() if "guard_at" in s and not s["guard_at"]),
                        "absent": sorted(absent), "identity_subsystems": len(groups)}}


# ----------------------------------------------------------------- review units

class Anchors:
    """file:line anchors of the hypotheses reviewers recorded, shared by parallel units: an operation
    that an entry's reviewer already traced is not reviewed a second time."""

    def __init__(self) -> None:
        self._by_file: dict[str, set[int]] = collections.defaultdict(set)
        self._lock = threading.Lock()

    def add(self, anchor: Any) -> None:
        m = re.match(r"^\s*([^:\s]+):(\d+)", str(anchor or ""))
        if m:
            with self._lock:
                self._by_file[m.group(1).lstrip("./")].add(int(m.group(2)))

    def covers(self, file: str, line: int, slack: int = 2) -> bool:
        with self._lock:
            return any(abs(x - line) <= slack for x in self._by_file.get(file, ()))


def operation_units(sites: list[dict], entries: list[dict], entry_units: list[dict],
                    rank: dict[str, int]) -> list[dict]:
    """One unit per function that performs sensitive operations outside an entry's handler, most exposed
    and unguarded first. Sites inside a handler go to that entry's unit instead (the same code is
    reviewed once, with the operation pointed out)."""
    by_id = {e.get("id"): e for e in entries}
    unit_of = {e.get("id"): u for u in entry_units for e in u["entries"]}
    groups: dict[tuple, list[dict]] = collections.defaultdict(list)
    for s in sites:
        owners = [unit_of[i] for i in s.get("entries") or [] if i in unit_of]
        if s["reach"] == "handler" and owners:
            for u in {id(u): u for u in owners}.values():
                u.setdefault("operations", []).append(s)
            continue
        groups[(s["file"], s["function"])].append(s)
    units = []
    for (file, fn), ss in groups.items():
        reached = [by_id[i] for i in sorted({i for s in ss for i in s.get("entries") or []}) if i in by_id]
        exposure = min((e.get("exposure", "unknown") for e in reached), key=lambda x: rank.get(x, 1),
                       default="unknown")
        units.append({"kind": "operation", "handler_file": file, "handler": fn, "span": ss[0]["span"],
                      "sites": sorted(ss, key=lambda s: s["line"]), "entries": reached, "exposure": exposure,
                      "reach": min((s["reach"] for s in ss), key=REACH_ORDER.get),
                      "unguarded": any("guard_at" in s and not s["guard_at"] for s in ss)})
    units.sort(key=lambda u: (rank.get(u["exposure"], 1), not u["unguarded"], REACH_ORDER[u["reach"]],
                              -len(u["sites"]), u["handler_file"], u["sites"][0]["line"]))
    return units


def design_units(identity: list[dict], entries: list[dict], sites: list[dict], limit: int) -> list[dict]:
    """One design-review unit per identity subsystem (the ones with the most code first)."""
    by_id = {e.get("id"): e for e in entries}
    by_key = {site_key(s): s for s in sites}
    units = [{"kind": "design", "handler_file": "", "handler": g["name"], "subsystem": g,
              "entries": [by_id[i] for i in g.get("entry_ids", []) if i in by_id],
              "sites": [by_key[k] for k in g.get("site_keys", []) if k in by_key]} for g in identity]
    units.sort(key=lambda u: -(len(u["entries"]) + len(u["sites"]) + len(u["subsystem"]["files"])))
    return units[:limit]


def interleave(first: list, second: list, every: int) -> list:
    """`second` takes every `every`-th slot from the start, so neither kind of unit waits for the other
    to be used up (the time budget usually ends before both are)."""
    if every < 2:
        return first + second
    out: list = []
    i = j = 0
    while i < len(first) or j < len(second):
        if j < len(second) and (i >= len(first) or (len(out) + 1) % every == 0):
            out.append(second[j])
            j += 1
        else:
            out.append(first[i])
            i += 1
    return out


def _site_row(s: dict) -> str:
    g = ""
    if "guard_at" in s:
        g = f"  [project's guard {'at ' + s['guard_at'] if s['guard_at'] else 'not found on the way'}]"
    return f"- {site_key(s)} ({s['op_class']}, recipe {s['recipe']}): {s['code'][:160]}{g}"


def _entry_row(e: dict) -> str:
    who = (e.get("who_can_call") or {}).get("least_privileged")
    return (f"- {e.get('id')} {e.get('method', 'ANY')} {e.get('route')} -> {e.get('handler_file')}::"
            f"{e.get('handler', '')} exposure={e.get('exposure')}" + (f" who_can_call={who}" if who else ""))


def handler_operations(unit: dict) -> str:
    """For an entry unit: the sensitive operations in its handler, from the project's operation map."""
    ss = unit.get("operations") or []
    if not ss:
        return ""
    return ("Sensitive operations in this handler (from the project's operation map; check who can make "
            "each happen and with which values):\n" + "\n".join(_site_row(s) for s in ss[:12]))


def operation_brief(unit: dict, siblings: list[dict], recipes: dict[str, dict]) -> str:
    """The user message of an operation unit."""
    ss = unit["sites"]
    classes = sorted({s["op_class"] for s in ss})
    rows = [f"Sensitive operation(s) to review, in {unit['handler_file']}::{unit['handler']} "
            f"(lines {unit['span'][0]}-{unit['span'][1]}):"]
    rows += [_site_row(s) for s in ss[:12]]
    rows += [f"Class {c}: {OP_CLASSES[c]}" for c in classes]
    whys = {s["recipe"]: recipes.get(s["recipe"], {}).get("why") for s in ss}
    rows += [f"Recipe {k}: {v}" for k, v in whys.items() if v]
    if unit["entries"]:
        rows.append(f"Entries that reach it through calls ({len(unit['entries'])}; the static call graph can "
                    "miss some):")
        rows += [_entry_row(e) for e in unit["entries"][:15]]
    elif unit["reach"] == "no_callers":
        rows.append("Nothing in the repository calls this code: it is a framework hook, an extension point, "
                    "a public API for plugins or themes, file-level code the framework loads, or dead code. "
                    "Find out which.")
    else:
        rows.append("It is called, but no enumerated entry reaches it: find the callers (hooks, events, "
                    "jobs, render pipelines, entries the reconnaissance missed).")
    if siblings:
        rows.append("The same operation elsewhere, WITH the project's guard on the way (compare: what do "
                    "they check that this code does not?):")
        rows += [_site_row(s) for s in siblings[:6]]
    return "\n".join(rows)


def design_brief(unit: dict) -> str:
    """The user message of an identity design unit."""
    g = unit["subsystem"]
    rows = [f"Identity subsystem to review: {g['name']} (kind: {g['kind']})"]
    for label, key in (("Files", "files"), ("Models", "models"), ("Settings and defaults", "settings")):
        if g.get(key):
            rows.append(f"{label}: " + ", ".join(g[key]))
    if g.get("notes"):
        rows.append("Notes from the agent that mapped it: " + g["notes"])
    if unit["entries"]:
        rows.append(f"Its entries ({len(unit['entries'])}):")
        rows += [_entry_row(e) for e in unit["entries"][:25]]
    if unit["sites"]:
        rows.append("Sensitive operations in or behind it:")
        rows += [_site_row(s) for s in unit["sites"][:15]]
    rows.append("Checklist (answer every item with record_design):")
    rows += [f"- {k}: {q}" for k, q in IDENTITY_CHECKLIST.items()]
    return "\n".join(rows)


def classes_text() -> str:
    return "\n".join(f"- {k}: {v}" for k, v in OP_CLASSES.items())


def dump(data: dict, path: Path) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False))
