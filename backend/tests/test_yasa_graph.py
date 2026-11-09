"""Code navigation answered from codegraph's index (graph.py)."""

import sqlite3

from app.services.yasa_audit.config import AuditConfig
from app.services.yasa_audit.graph import CodeGraph
from app.services.yasa_audit.toolbox import Toolbox

NODE_COLS = ("id", "kind", "name", "qualified_name", "file_path", "start_line", "end_line", "signature")


def _index(root, nodes, edges, unresolved=()):
    """A codegraph.db with the tables and columns graph.py reads."""
    (root / ".codegraph").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / ".codegraph" / "codegraph.db")
    con.execute("create table nodes (id text primary key, kind text, name text, qualified_name text, "
                "file_path text, start_line int, end_line int, signature text)")
    con.execute("create table edges (source text, target text, kind text, line int)")
    con.execute("create table unresolved_refs (from_node_id text, reference_name text)")
    con.execute("create table project_metadata (key text, value text)")
    con.execute("create virtual table nodes_fts using fts5(id, name, qualified_name, content='nodes', "
                "content_rowid='rowid')")
    con.executemany(f"insert into nodes ({','.join(NODE_COLS)}) values (?,?,?,?,?,?,?,?)",
                    [(*n, *([None] * (8 - len(n)))) for n in nodes])
    con.execute("insert into nodes_fts (rowid, id, name, qualified_name) select rowid, id, name, qualified_name "
                "from nodes")
    con.executemany("insert into edges values (?,?,?,?)", [(*e, None)[:4] for e in edges])
    con.executemany("insert into unresolved_refs values (?,?)", unresolved)
    con.execute("insert into project_metadata values ('index_state', 'complete')")
    con.commit()
    con.close()
    return CodeGraph(root / ".codegraph" / "codegraph.db", root)


def _write(root, files):
    for rel, txt in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(txt)


def _app(tmp_path):
    """Two classes named Controller; the endpoint's base class imports the web one. An endpoint calls
    an interface method (implemented once) and an inherited permission check through $this."""
    _write(tmp_path, {
        "web/Controller.php": "<?php\nnamespace web;\nclass Controller {\n  function requirePermission($p) {}\n}\n",
        "cli/Controller.php": "<?php\nnamespace cli;\nclass Controller {\n  function requirePermission($p) {}\n}\n",
        "app/Base.php": "<?php\nnamespace app;\nuse web\\Controller;\nclass Base extends Controller {\n"
                        "  function guard() {\n    $this->requirePermission('edit');\n  }\n}\n",
        "app/Posts.php": "<?php\nnamespace app;\nclass Posts extends Base {\n  function actionSave() {\n"
                         "    $this->guard();\n    $this->store->save($post);\n  }\n}\n",
        "app/Store.php": "<?php\nnamespace app;\ninterface Store {\n  function save($p);\n}\n",
        "app/DbStore.php": "<?php\nnamespace app;\nclass DbStore implements Store {\n  function save($p) {}\n}\n",
    })
    return _index(tmp_path, [
        ("c_web", "class", "Controller", "web::Controller", "web/Controller.php", 3, 5),
        ("m_web", "method", "requirePermission", "web::Controller::requirePermission", "web/Controller.php", 4, 4),
        ("c_cli", "class", "Controller", "cli::Controller", "cli/Controller.php", 3, 5),
        ("m_cli", "method", "requirePermission", "cli::Controller::requirePermission", "cli/Controller.php", 4, 4),
        ("c_base", "class", "Base", "app::Base", "app/Base.php", 4, 8),
        ("m_guard", "method", "guard", "app::Base::guard", "app/Base.php", 5, 7),
        ("i_use", "import", "web\\Controller", "app::web\\Controller", "app/Base.php", 3, 3),
        ("c_posts", "class", "Posts", "app::Posts", "app/Posts.php", 3, 8),
        ("m_save", "method", "actionSave", "app::Posts::actionSave", "app/Posts.php", 4, 7, "actionSave()"),
        ("i_store", "interface", "Store", "app::Store", "app/Store.php", 3, 5),
        ("m_isave", "method", "save", "app::Store::save", "app/Store.php", 4, 4),
        ("c_db", "class", "DbStore", "app::DbStore", "app/DbStore.php", 3, 5),
        ("m_dbsave", "method", "save", "app::DbStore::save", "app/DbStore.php", 4, 4),
    ], [
        ("c_web", "m_web", "contains"), ("c_cli", "m_cli", "contains"), ("c_base", "m_guard", "contains"),
        ("c_posts", "m_save", "contains"), ("i_store", "m_isave", "contains"), ("c_db", "m_dbsave", "contains"),
        ("c_base", "c_cli", "extends"),          # codegraph guessed the wrong Controller by its short name
        ("c_posts", "c_base", "extends"), ("c_db", "i_store", "implements"),
        ("m_save", "m_guard", "calls", 5), ("m_save", "m_isave", "calls", 6),
        ("m_guard", "m_cli", "calls", 6),        # ... and the wrong requirePermission
    ], unresolved=[("m_save", "render")])


def test_call_graph_follows_interfaces_and_corrects_self_calls(tmp_path):
    out = _app(tmp_path).call_graph("actionSave", depth=2)
    assert out.splitlines()[0] == "app::Posts::actionSave  app/Posts.php:4-7"
    assert "  line 5: app::Base::guard  (app/Base.php:5)" in out
    assert "    line 6: web::Controller::requirePermission  (web/Controller.php:4)" in out  # the imported parent
    assert "cli::Controller" not in out
    assert "  line 6: app::Store::save  (app/Store.php:4)" in out
    assert "    -> implemented by app::DbStore::save  (app/DbStore.php:4)" in out
    assert "(+1 calls the index could not resolve" in out


def test_callers_include_calls_through_the_interface(tmp_path):
    g = _app(tmp_path)
    out = g.find_callers("save", "app/DbStore.php")
    assert out == "app/Posts.php:6  in app::Posts::actionSave  (through app::Store::save)  | $this->store->save($post);"
    assert g.find_callers("nothing").startswith("no function or method named")


def test_find_function_and_search(tmp_path):
    g = _app(tmp_path)
    assert g.find_function("Posts::actionSave") == "app::Posts::actionSave  app/Posts.php:4-7  actionSave()"
    full = g.find_function("guard", detail="full")
    assert "    6|     $this->requirePermission('edit');" in full
    assert "app::Store  app/Store.php:3" in g.search_symbol("Stor")
    assert "requirePermission" in g.search_symbol("requirePerm")


def test_toolbox_answers_from_the_index_or_says_there_is_none(tmp_path):
    tb = Toolbox(AuditConfig(), tmp_path, tmp_path / "out")
    assert tb.call_graph("x").startswith("error: no code index")
    _app(tmp_path)
    assert "implemented by app::DbStore::save" in tb.call_graph("actionSave")
    assert tb.find_callers("guard").startswith("app/Posts.php:5  in app::Posts::actionSave")
