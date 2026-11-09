"""Code navigation answered from codegraph's index (.codegraph/codegraph.db), read-only.

codegraph builds the index in seconds to a minute even for large projects (tree-sitter, many
languages) and records calls, inheritance and containment. The questions agents ask are answered here
with plain SQL: where a function is defined, who calls it, what it calls, which symbols match a name.

Calls whose receiver type codegraph cannot see may be missing or attributed to a same-named function
elsewhere; answers say so where it matters, and read_file / grep remain the ground truth. A call to
an interface or abstract method is followed to the implementations codegraph knows (implements and
extends edges), and callers of an implementation include calls made through its interface.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from .discovery import _connect

FUNCS = ("function", "method")
TYPES = ("class", "interface", "trait", "enum", "struct")
CALLS = ("calls", "instantiates")
SELF_CALL = re.compile(r"(?:\$this|\bthis|\bself|\bsuper|\bparent|\bstatic)\s*(?:->|\.|::)\s*(\w+)\s*\(")


class CodeGraph:
    def __init__(self, db: Path, root: Path):
        self.db, self.root = db, root

    # ---------- plumbing ----------
    def _rows(self, sql: str, args: Iterable = ()) -> list[tuple]:
        con = _connect(self.db)
        try:
            return con.execute(sql, tuple(args)).fetchall()
        finally:
            con.close()

    def _functions(self, name: str, file_path: str = "", limit: int = 10) -> list[tuple]:
        """(id, qualified_name, file, start, end, signature) of functions/methods called `name`.
        A name with '::' or '.' matches the end of the qualified name."""
        q = f"select id, qualified_name, file_path, start_line, end_line, signature from nodes where kind in " \
            f"({','.join('?' * len(FUNCS))}) and "
        args: list = list(FUNCS)
        if "::" in name or "." in name:
            tail = name.replace(".", "::")
            q += "(qualified_name = ? or qualified_name like ?)"
            args += [tail, "%" + tail]
        else:
            q += "name = ?"
            args.append(name)
        if file_path:
            q += " and (file_path = ? or file_path like ?)"
            args += [file_path.lstrip("./"), "%" + file_path.lstrip("./")]
        return self._rows(q + " order by file_path, start_line limit ?", [*args, limit])

    def _owner(self, fid: str) -> tuple | None:
        """(type id, type name, kind) that contains a method."""
        rows = self._rows("select n.id, n.name, n.kind from edges e join nodes n on n.id = e.source where "
                          f"e.kind = 'contains' and e.target = ? and n.kind in ({','.join('?' * len(TYPES))})",
                          [fid, *TYPES])
        return rows[0] if rows else None

    def _implementations(self, fid: str) -> list[tuple]:
        """Methods with the same name in types that implement or extend the method's owner."""
        owner = self._owner(fid)
        if owner is None:
            return []
        name = self._rows("select name from nodes where id = ?", [fid])[0][0]
        return self._rows(
            "select m.id, m.qualified_name, m.file_path, m.start_line, m.end_line, m.signature "
            "from edges h join edges c on c.source = h.source and c.kind = 'contains' "
            "join nodes m on m.id = c.target where h.kind in ('implements', 'extends') and h.target = ? "
            f"and m.name = ? and m.kind in ({','.join('?' * len(FUNCS))}) limit 8", [owner[0], name, *FUNCS])

    def _overridden(self, fid: str) -> list[tuple]:
        """Same-named methods of the types the method's owner implements or extends (the interface
        methods a call may go through)."""
        owner = self._owner(fid)
        if owner is None:
            return []
        name = self._rows("select name from nodes where id = ?", [fid])[0][0]
        parents = self._parents([owner[0]])
        if not parents:
            return []
        return self._rows(
            "select m.id, m.qualified_name from edges c join nodes m on m.id = c.target where c.kind = 'contains' "
            f"and c.source in ({','.join('?' * len(parents))}) and m.name = ? and m.kind in "
            f"({','.join('?' * len(FUNCS))})", [*parents, name, *FUNCS])

    @staticmethod
    def _norm(qn: str) -> str:
        return re.sub(r"[\\.:/]+", ".", qn).strip(".")

    def _parents(self, type_ids: list[str]) -> list[str]:
        """Types that these types extend or implement. codegraph links a parent by its short name, so
        when several types share it, the one the file imports (else the same namespace) is taken."""
        if not type_ids:
            return []
        marks = ",".join("?" * len(type_ids))
        rows = self._rows("select s.file_path, s.qualified_name, t.id, t.name from edges e join nodes s on s.id = "
                          "e.source join nodes t on t.id = e.target where e.kind in ('extends', 'implements') "
                          f"and e.source in ({marks})", type_ids)
        out = []
        for file, src_qn, tid, tname in rows:
            cands = self._rows(f"select id, qualified_name from nodes where name = ? and kind in "
                               f"({','.join('?' * len(TYPES))})", [tname, *TYPES])
            if len(cands) > 1:
                imports = {self._norm(n) for (n,) in self._rows(
                    "select name from nodes where kind = 'import' and file_path = ?", [file])}
                ns = self._norm(src_qn).rsplit(".", 1)[0]
                pick = [c for c in cands if self._norm(c[1]) in imports] or \
                       [c for c in cands if self._norm(c[1]).rsplit(".", 1)[0] == ns]
                if pick:
                    tid = pick[0][0]
            out.append(tid)
        return out

    def _in_hierarchy(self, fid: str, name: str) -> tuple | None:
        """The method `name` of the caller's own type or its ancestors (nearest first)."""
        owner = self._owner(fid)
        if owner is None:
            return None
        level, seen = [owner[0]], {owner[0]}
        for _ in range(8):
            if not level:
                break
            marks = ",".join("?" * len(level))
            hit = self._rows(
                "select m.id, m.qualified_name, m.file_path, m.start_line from edges c join nodes m on m.id = c.target "
                f"where c.kind = 'contains' and c.source in ({marks}) and m.name = ? and m.kind in "
                f"({','.join('?' * len(FUNCS))}) limit 1", [*level, name, *FUNCS])
            if hit:
                return hit[0]
            level = [p for p in self._parents(level) if p not in seen]
            seen.update(level)
        return None

    def _line(self, file: str, line: int) -> str:
        try:
            with (self.root / file).open(errors="ignore") as fh:
                for i, text in enumerate(fh, 1):
                    if i == line:
                        return text.strip()[:160]
        except OSError:
            pass
        return ""

    # ---------- questions ----------
    def find_function(self, name: str, file_path: str = "", detail: str = "summary") -> str:
        rows = self._functions(name, file_path)
        if not rows:
            return f"no function or method named {name!r} in the index (try grep)"
        out = []
        for _fid, qn, f, s, e, sig in rows:
            out.append(f"{qn}  {f}:{s}-{e}  {sig or ''}".rstrip())
            if detail == "full" and len(rows) <= 3:
                try:
                    lines = (self.root / f).read_text(errors="ignore").splitlines()[s - 1:min(e, s + 149)]
                    out += [f"{s + i:5d}| {t}" for i, t in enumerate(lines)]
                except OSError:
                    pass
        return "\n".join(out)

    def find_callers(self, name: str, file_path: str = "", limit: int = 30) -> str:
        """Call sites of the function(s) called `name` (file_path narrows to the definition's file),
        including calls through an interface or parent method they implement."""
        targets = self._functions(name, file_path, limit=20)
        if not targets:
            return f"no function or method named {name!r} in the index (try grep)"
        via = {t[0]: "" for t in targets}
        for t in targets:
            for oid, oqn in self._overridden(t[0]):
                via.setdefault(oid, f"  (through {oqn})")
        marks = ",".join("?" * len(via))
        rows = self._rows(
            "select e.target, s.file_path, e.line, s.qualified_name from edges e join nodes s on s.id = e.source "
            f"where e.kind in ('calls', 'instantiates') and e.target in ({marks}) order by s.file_path, e.line "
            "limit ?", [*via, limit + 1])
        out = [f"{f}:{ln}  in {src}{via[t]}  | {self._line(f, ln or 0)}" for t, f, ln, src in rows[:limit]]
        more = "\n...[more call sites; narrow with file_path]" if len(rows) > limit else ""
        return ("\n".join(out) + more) if out else (
            f"no recorded calls to {name!r} (dynamic dispatch may hide them; try grep)")

    def call_graph(self, name: str, depth: int = 2, file_path: str = "", per_node: int = 12) -> str:
        """What the function calls, as a tree to `depth`; calls to an interface or abstract method also
        show the implementations; calls codegraph could not resolve are counted."""
        roots = self._functions(name, file_path, limit=3)
        if not roots:
            return f"no function or method named {name!r} in the index (try grep)"
        depth = max(1, min(int(depth or 2), 4))
        out: list[str] = []
        seen: set[str] = set()

        def walk(fid: str, level: int) -> None:
            if level > depth or fid in seen:
                return
            seen.add(fid)
            rows = self._rows(
                "select e.line, t.id, t.qualified_name, t.file_path, t.start_line from edges e join nodes t on "
                "t.id = e.target where e.source = ? and e.kind in ('calls', 'instantiates') order by e.line",
                [fid])
            pad = "  " * level
            src_file = self._rows("select file_path from nodes where id = ?", [fid])[0][0]
            for ln, tid, tqn, tf, ts in rows[:per_node]:
                # A call on this/self/super is the caller's own (inherited) method, whatever same-named
                # function codegraph attributed it to.
                tname = tqn.replace(".", "::").rsplit("::", 1)[-1]
                if tname in SELF_CALL.findall(self._line(src_file, ln or 0)):
                    own = self._in_hierarchy(fid, tname)
                    if own and own[0] != tid:
                        tid, tqn, tf, ts = own
                out.append(f"{pad}line {ln}: {tqn}  ({tf}:{ts})")
                for iid, iqn, iff, iss, _, _ in self._implementations(tid):
                    out.append(f"{pad}  -> implemented by {iqn}  ({iff}:{iss})")
                    walk(iid, level + 1)
                walk(tid, level + 1)
            if len(rows) > per_node:
                out.append(f"{pad}...[{len(rows) - per_node} more calls]")
            unres = self._rows("select count(*) from unresolved_refs where from_node_id = ?", [fid])[0][0]
            if unres and level == 1:
                out.append(f"{pad}(+{unres} calls the index could not resolve: framework, dynamic or external)")

        for fid, qn, f, s, e, _ in roots:
            out.append(f"{qn}  {f}:{s}-{e}")
            walk(fid, 1)
        return "\n".join(out)

    def search_symbol(self, query: str, limit: int = 20) -> str:
        try:
            rows = self._rows(
                "select n.kind, n.qualified_name, n.file_path, n.start_line from nodes_fts f join nodes n on "
                "n.rowid = f.rowid where nodes_fts match ? and n.kind not in ('import', 'file') limit ?",
                ['"' + query.replace('"', "") + '"*', limit])
        except sqlite3.Error:
            rows = []
        if not rows:
            rows = self._rows("select kind, qualified_name, file_path, start_line from nodes where name like ? "
                              "and kind not in ('import', 'file') limit ?", [f"%{query}%", limit])
        return "\n".join(f"{k:9} {qn}  {f}:{s}" for k, qn, f, s in rows) or f"no symbol matching {query!r}"
