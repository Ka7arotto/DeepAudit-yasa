"""Evidence from codegraph's index for the route-reconnaissance agent.

codegraph (written by `yasa-mcp init`, or `codegraph init` directly) resolves routes for many
frameworks and records calls / imports / references between files. Nothing here decides what the
attack surface is: the recon agent reads this as one source of evidence among the directory layout,
the code itself and the navigation tools, and decides.

The index stays usable while the slower YASA call-graph step of init is still running; stages read a
private snapshot so they neither wait on nor race with the background init.
"""

from __future__ import annotations

import collections
import json
import re
import sqlite3
import subprocess
from pathlib import Path

HTTP_VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY", "USE", "ALL"}


# Test code, fixtures and demos are not entries, whatever framework resolver produced them.
NOISE_RE = re.compile(r"(^|/)(tests?|__tests__|__mocks__|spec|e2e|fixtures?|demos?|examples?|stories|storybook|"
                      r"mocks?)/|\.(test|spec|stories|e2e)\.[cm]?[jt]sx?$|_test\.(py|go)$|(^|/)test_[^/]+\.py$",
                      re.I)  # case-insensitive: Java/PHP projects use Test/ and Tests/
# Client-side component files: their routes (React Router, Vue Router, ...) are not server entries.
FRONTEND_EXT = (".tsx", ".jsx", ".vue", ".svelte")

CLIENT_DEPS = {"react", "react-dom", "vue", "svelte", "@angular/core", "preact", "solid-js", "ember-source"}
SERVER_DEPS = {"express", "koa", "fastify", "@hapi/hapi", "hapi", "@nestjs/core", "next", "nuxt", "@remix-run/node",
               "restify", "@sveltejs/kit", "sails", "loopback", "@adonisjs/core", "egg"}
_CLIENT_PKG: dict[str, bool] = {}


def is_client_package(root: Path, rel: str) -> bool:
    """rel lies in a JS package that depends on a UI framework and on no server framework."""
    parts = Path(rel).parts[:-1]
    for i in range(len(parts), -1, -1):
        d = root.joinpath(*parts[:i]) if i else root
        pj = d / "package.json"
        if not pj.exists():
            continue
        key = str(pj)
        if key not in _CLIENT_PKG:
            try:
                data = json.loads(pj.read_text(errors="ignore"))
            except ValueError:
                data = {}
            deps = set()
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                deps |= set((data.get(k) or {}).keys())
            _CLIENT_PKG[key] = bool(deps & CLIENT_DEPS) and not (deps & SERVER_DEPS)
        return _CLIENT_PKG[key]
    return False


_SNAPSHOTS: dict[str, Path] = {}


def codegraph_db(root: Path) -> Path | None:
    """The codegraph index for root: a private snapshot when one was taken, else the live file."""
    snap = _SNAPSHOTS.get(str(root.resolve()))
    if snap is not None and snap.exists():
        return snap
    p = root / ".codegraph" / "codegraph.db"
    return p if p.exists() and p.stat().st_size > 0 else None


def snapshot_codegraph(root: Path, dest_dir: Path) -> Path | None:
    """Copy the live index (WAL mode, still opened by a background yasa-mcp init) into dest_dir.

    Later reads use the copy, so they neither wait on nor race with the init process. Returns None
    (and the live index stays in use) when there is no complete index or the copy fails.
    """
    key = str(root.resolve())
    if key in _SNAPSHOTS and _SNAPSHOTS[key].exists():
        return _SNAPSHOTS[key]
    live = root / ".codegraph" / "codegraph.db"
    if not codegraph_ready(root):
        return None
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "codegraph.snapshot.db"
    try:
        src = _connect(live)
        try:
            dst = sqlite3.connect(dest)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
    except sqlite3.Error:
        dest.unlink(missing_ok=True)
        return None
    _SNAPSHOTS[key] = dest
    return dest


def codegraph_ready(root: Path) -> bool:
    """codegraph has finished writing its index (it records index_state=complete)."""
    db = root / ".codegraph" / "codegraph.db"
    if not db.exists() or db.stat().st_size == 0:
        return False
    try:
        con = _connect(db)
        try:
            row = con.execute("select value from project_metadata where key = 'index_state'").fetchone()
        finally:
            con.close()
    except sqlite3.Error:
        return False
    return bool(row and row[0] == "complete")


def ensure_codegraph(codegraph_bin: str, root: Path, timeout_s: int = 300) -> Path | None:
    """Build codegraph's index directly when yasa-mcp init did not leave one."""
    if (db := codegraph_db(root)) is not None:
        return db
    if not Path(codegraph_bin).exists():
        return None
    try:
        subprocess.run([codegraph_bin, "init", str(root)], capture_output=True, timeout=timeout_s,
                       start_new_session=True)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return codegraph_db(root)


def _connect(db: Path) -> sqlite3.Connection:
    """Read an existing index, allowing SQLite to initialize WAL sidecars if needed."""
    uri = db.resolve().as_uri()
    try:
        con = sqlite3.connect(f"{uri}?mode=rw", uri=True, timeout=10)
    except sqlite3.OperationalError:
        # Read-only filesystems can still serve an index whose WAL sidecars are present.
        con = sqlite3.connect(f"{uri}?mode=ro", uri=True, timeout=10)
    try:
        con.execute("PRAGMA query_only=ON")
    except sqlite3.Error:
        con.close()
        raise
    return con


def _split_route(name: str) -> tuple[str, str]:
    """codegraph names routes 'GET /x' (or just '/x' for some resolvers)."""
    head, _, tail = name.partition(" ")
    if tail and head.upper() in HTTP_VERBS:
        return head.upper(), tail
    return "ANY", name


def _enclosing_functions(con: sqlite3.Connection, files: set[str]) -> dict[str, list[tuple]]:
    """file -> [(start, end, name, exported)] of functions / methods, for registration-site lookup."""
    out: dict[str, list[tuple]] = collections.defaultdict(list)
    try:
        rows = con.execute("select file_path, start_line, end_line, name, is_exported from nodes "
                           "where kind in ('function', 'method')").fetchall()
    except sqlite3.Error:  # older index without spans: routes still work, without registration_fn
        return out
    for path, start, end, name, exported in rows:
        if path in files:
            out[path].append((start or 0, end or 0, name, bool(exported)))
    return out


def codegraph_routes(db: Path, root: Path | None = None) -> list[dict]:
    """Server routes from codegraph. root is the project directory (db may be a snapshot elsewhere)."""
    root = root or db.parent.parent
    con = _connect(db)
    try:
        routes = [r for r in con.execute("select id, name, file_path, start_line from nodes where kind='route'")
                  if not NOISE_RE.search(r[2] or "")]
        functions = _enclosing_functions(con, {r[2] for r in routes})
        handlers: dict[str, list[tuple]] = collections.defaultdict(list)
        for src, _kind, name, path, line in con.execute(
                "select e.source, t.kind, t.name, t.file_path, t.start_line from edges e "
                "join nodes s on s.id = e.source join nodes t on t.id = e.target "
                "where s.kind = 'route' and e.kind in ('calls', 'references') "
                "and t.kind in ('function', 'method')"):
            handlers[src].append((name, path, line))
    finally:
        con.close()
    out = []
    lines_cache: dict[str, list[str]] = {}
    for rid, name, path, line in routes:
        method, route = _split_route(name)
        hs = handlers.get(rid, [])
        if path not in lines_cache:
            p = root / path
            lines_cache[path] = p.read_text(errors="ignore").splitlines() if p.is_file() else []
        reg = " ".join(lines_cache[path][max(0, line - 1):line + 2])
        # Handler = the referenced function named last on the registration line (earlier ones are
        # middleware); resolvers that point at the decorated function have it on the next lines.
        named = sorted((reg.rfind(h[0]), h) for h in hs if h[0] and reg.rfind(h[0]) >= 0)
        h = named[-1][1] if named else (hs[-1] if hs else None)
        if method == "ANY" and (path.endswith(FRONTEND_EXT) or (h and str(h[1]).endswith(FRONTEND_EXT))):
            continue  # client-side router (React Router, Vue Router ...): not a server entry
        if path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte")) and is_client_package(root, path):
            continue  # code of a UI package (client fetch calls, routers), not served by the backend
        if h and NOISE_RE.search(str(h[1])):
            continue
        # The function whose body registers the route: the engine has to start there, because a
        # file-level start only defines it (e.g. module.exports = function apiRoutes() { router.get(...) }).
        around = [f for f in functions.get(path, []) if f[0] <= line <= f[1]]
        reg_fn = min(around, key=lambda f: f[1] - f[0]) if around else None
        out.append({"route": route, "method": method, "file": h[1] if h else path,
                    "line": h[2] if h else line, "handler": h[0] if h else "",
                    "registered_at": f"{path}:{line}",
                    "registration_fn": reg_fn[2] if reg_fn else "",
                    "middleware": [x[0] for _, x in named[:-1]] if named else [],
                    "guards": [], "via": "codegraph"})
    return out


def reachable_files(root: Path, entry_files: list[str], depth: int = 6) -> set[str]:
    """Files reachable from entry files over codegraph's static edges (empty without an index)."""
    db = codegraph_db(root)
    if db is None or not entry_files:
        return set()
    con = _connect(db)
    try:
        graph: dict[str, set[str]] = collections.defaultdict(set)
        for a, b in con.execute(
                "select distinct s.file_path, t.file_path from edges e join nodes s on s.id = e.source "
                "join nodes t on t.id = e.target where e.kind in ('calls', 'imports', 'instantiates', "
                "'references', 'extends', 'implements') and s.file_path <> t.file_path"):
            graph[a].add(b)
    finally:
        con.close()
    seen = set(entry_files)
    frontier = set(entry_files)
    for _ in range(depth):
        frontier = {b for a in frontier for b in graph.get(a, ())} - seen
        if not frontier:
            break
        seen |= frontier
    return seen
