"""codegraph evidence for the recon agent (no tools needed)."""

import shutil
import sqlite3

from app.services.yasa_audit.discovery import (
    codegraph_ready,
    codegraph_routes,
    reachable_files,
)


def _write(root, files):
    for rel, txt in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(txt)


def _codegraph(root, nodes, edges, complete=True):
    """Minimal codegraph.db: the columns discovery reads."""
    (root / ".codegraph").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / ".codegraph" / "codegraph.db")
    con.execute("create table nodes (id text, kind text, name text, file_path text, start_line int, "
                "end_line int, is_exported int)")
    con.execute("create table edges (source text, target text, kind text)")
    con.execute("create table project_metadata (key text, value text)")
    con.executemany("insert into nodes values (?,?,?,?,?,?,?)", [(*n, None, 0) for n in nodes])
    con.executemany("insert into edges values (?,?,?)", edges)
    con.execute("insert into project_metadata values ('index_state', ?)", ("complete" if complete else "running",))
    con.commit()
    con.close()


def test_codegraph_routes_pick_handler_named_on_registration_line(tmp_path):
    _write(tmp_path, {"server.ts": "\n" * 9 + "app.get('/orders/:id', auth.isAuthorized(), orders.show)\n",
                      "routes/orders.ts": "export function show() {}\n"})
    _codegraph(tmp_path, [
        ("r1", "route", "GET /orders/:id", "server.ts", 10),
        ("f1", "function", "isAuthorized", "lib/auth.ts", 3),
        ("f2", "function", "show", "routes/orders.ts", 1),
        ("f3", "function", "unrelated", "lib/x.ts", 1),
    ], [("r1", "f2", "references"), ("r1", "f1", "calls"), ("r1", "f3", "references")])
    (r,) = codegraph_routes(tmp_path / ".codegraph" / "codegraph.db")
    assert (r["method"], r["route"], r["file"], r["line"], r["handler"]) == \
        ("GET", "/orders/:id", "routes/orders.ts", 1, "show")
    assert r["middleware"] == ["isAuthorized"] and r["registered_at"] == "server.ts:10"
    assert codegraph_ready(tmp_path)


def test_reachable_files(tmp_path):
    _codegraph(tmp_path, [("a", "file", "a", "index.php", 1), ("b", "function", "b", "lib/b.php", 1),
                          ("c", "function", "c", "lib/c.php", 1), ("d", "function", "d", "lib/d.php", 1)],
               [("a", "b", "calls"), ("b", "c", "instantiates"), ("d", "a", "calls")])
    assert reachable_files(tmp_path, ["index.php"]) == {"index.php", "lib/b.php", "lib/c.php"}
    assert reachable_files(tmp_path, ["index.php"], depth=1) == {"index.php", "lib/b.php"}


def test_codegraph_routes_skip_client_tests_and_record_registration_fn(tmp_path):
    from app.services.yasa_audit.discovery import codegraph_routes

    _write(tmp_path, {
        "server/package.json": '{"dependencies": {"express": "4"}}',
        "server/routes.js": "module.exports = function apiRoutes() {\n  const r = express.Router();\n"
                            "  r.get('/posts', auth, http(api.posts.browse));\n};\n",
        "web/package.json": '{"dependencies": {"react": "18"}}',
        "web/src/api.js": "fetch('/x')\n",
        "web/src/App.tsx": "<Route path='/a' element={<A/>} />\n",
        "server/routes.test.js": "r.get('/t', h)\n",
    })
    _codegraph(tmp_path, [
        ("r1", "route", "GET /posts", "server/routes.js", 3),
        ("r2", "route", "GET /x", "web/src/api.js", 1),          # client fetch in a UI package
        ("r3", "route", "/a", "web/src/App.tsx", 1),              # client router
        ("r4", "route", "GET /t", "server/routes.test.js", 1),    # test
        ("fn", "function", "apiRoutes", "server/routes.js", 1),
        ("h", "function", "http", "server/http.js", 1),
    ], [("r1", "h", "calls")])
    con = sqlite3.connect(tmp_path / ".codegraph" / "codegraph.db")
    con.execute("update nodes set end_line = 4 where id = 'fn'")
    con.commit()
    con.close()
    routes = codegraph_routes(tmp_path / ".codegraph" / "codegraph.db", tmp_path)
    assert [(r["route"], r["registration_fn"]) for r in routes] == [("/posts", "apiRoutes")]


def test_snapshot_is_used_and_survives_live_index_changes(tmp_path):
    from app.services.yasa_audit.discovery import codegraph_db, snapshot_codegraph

    _codegraph(tmp_path, [("r1", "route", "GET /a", "a.js", 1)], [])
    snap = snapshot_codegraph(tmp_path, tmp_path / "run")
    assert snap is not None and codegraph_db(tmp_path) == snap
    (tmp_path / ".codegraph" / "codegraph.db").write_bytes(b"garbage")   # live index rewritten / locked
    con = sqlite3.connect(snap)
    assert con.execute("select count(*) from nodes where kind='route'").fetchone()[0] == 1
    con.close()


def test_snapshot_skipped_when_index_incomplete(tmp_path):
    from app.services.yasa_audit.discovery import snapshot_codegraph

    _codegraph(tmp_path, [], [], complete=False)
    assert snapshot_codegraph(tmp_path, tmp_path / "run") is None


def test_wal_index_without_sidecars_can_be_read_and_snapshotted(tmp_path):
    from app.services.yasa_audit.discovery import _connect, snapshot_codegraph

    source = tmp_path / "source.db"
    con = sqlite3.connect(source)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE project_metadata(key TEXT, value TEXT)")
    con.execute("INSERT INTO project_metadata VALUES('index_state', 'complete')")
    con.execute("CREATE TABLE nodes(id TEXT, kind TEXT, name TEXT, file_path TEXT, start_line INT, end_line INT, is_exported INT)")
    con.execute("INSERT INTO nodes VALUES('r', 'route', 'GET /a', 'a.js', 1, 1, 0)")
    con.execute("CREATE TABLE edges(source TEXT, target TEXT, kind TEXT)")
    con.commit()
    assert con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    con.close()
    root = tmp_path / "project #1"
    (root / ".codegraph").mkdir(parents=True)
    db = root / ".codegraph" / "codegraph.db"
    shutil.copyfile(source, db)  # checkpointed WAL database, no -wal or -shm files
    assert not (root / ".codegraph" / "codegraph.db-wal").exists()
    assert codegraph_ready(root)
    snap = snapshot_codegraph(root, tmp_path / "run")
    assert snap is not None
    assert codegraph_routes(snap, root)[0]["route"] == "/a"
    con = _connect(db)
    try:
        import pytest
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            con.execute("DELETE FROM nodes")
    finally:
        con.close()


def test_connect_never_creates_missing_database(tmp_path):
    import pytest

    from app.services.yasa_audit.discovery import _connect

    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        _connect(missing)
    assert not missing.exists()
