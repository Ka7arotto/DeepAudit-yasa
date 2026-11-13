"""The sensitive-asset map (assets.py) and the operation and identity design review units."""

import json
import shutil
import sqlite3
import time
from types import SimpleNamespace

import pytest

from app.services.yasa_audit import assets
from app.services.yasa_audit.config import AuditConfig
from app.services.yasa_audit.toolbox import Toolbox, tool_schemas

RG = shutil.which("rg")
needs_rg = pytest.mark.skipif(RG is None, reason="ripgrep not installed")


def _cfg(**kw):
    cfg = AuditConfig(**kw)
    if RG:
        cfg.rg_bin = RG
    return cfg


def _write(root, files):
    for rel, txt in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(txt)


def _index(root, nodes, edges):
    """A codegraph.db with the columns assets.CallIndex reads."""
    (root / ".codegraph").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / ".codegraph" / "codegraph.db")
    con.execute("create table nodes (id text primary key, kind text, name text, qualified_name text, "
                "file_path text, start_line int, end_line int)")
    con.execute("create table edges (source text, target text, kind text, line int)")
    con.executemany("insert into nodes values (?,?,?,?,?,?,?)", nodes)
    con.executemany("insert into edges values (?,?,?,?)", [(*e, None) for e in edges])
    con.commit()
    con.close()


def _call(name, args, cid):
    return SimpleNamespace(id=cid, function=SimpleNamespace(name=name, arguments=json.dumps(args)))


class ScriptedLLM:
    def __init__(self, script):
        self.script = list(script)
        self.usage = SimpleNamespace(prompt=0, completion=0, cached=0, reasoning=0, calls=0)

    def chat(self, messages, tools=None):
        self.usage.calls += 1
        name, args = self.script.pop(0) if self.script else ("finish", {"notes": "done"})
        return SimpleNamespace(content="", tool_calls=[_call(name, args, f"c{self.usage.calls}")])


USERS = "\n".join([
    "<?php",                                       # 1
    "class Users {",                               # 2
    "  function actionSave($u) {",                 # 3
    "    $this->requireAdmin();",                  # 4
    "    $u->role = $_POST['role'];",              # 5
    "  }",                                         # 6
    "  function actionPromote($u) {",              # 7
    "    $this->roles->setRole($u, 'editor');",    # 8
    "  }",                                         # 9
    "}", ""])
ROLES = "<?php\nclass Roles {\n  function setRole($u, $r) {\n    $u->role = $r;\n  }\n}\n"
HOOKS = "<?php\nclass Hooks {\n  /** Plugins call this with imported rows. */\n  function onImport($u, $row) {\n" \
        "    $u->role = $row['role'];\n  }\n}\n"


def _project(tmp_path):
    _write(tmp_path, {"app/Users.php": USERS, "app/Roles.php": ROLES, "app/Hooks.php": HOOKS,
                      "tests/UsersTest.php": "<?php\n$u->role = 'admin';\n"})
    _index(tmp_path, [
        ("c_users", "class", "Users", "Users", "app/Users.php", 2, 10),
        ("m_save", "method", "actionSave", "Users::actionSave", "app/Users.php", 3, 6),
        ("m_promote", "method", "actionPromote", "Users::actionPromote", "app/Users.php", 7, 9),
        ("c_roles", "class", "Roles", "Roles", "app/Roles.php", 2, 6),
        ("m_setrole", "method", "setRole", "Roles::setRole", "app/Roles.php", 3, 5),
        ("c_hooks", "class", "Hooks", "Hooks", "app/Hooks.php", 2, 7),
        ("m_import", "method", "onImport", "Hooks::onImport", "app/Hooks.php", 4, 6),
    ], [("c_users", "m_save", "contains"), ("c_users", "m_promote", "contains"),
        ("c_roles", "m_setrole", "contains"), ("c_hooks", "m_import", "contains"),
        ("m_promote", "m_setrole", "calls")])
    return [{"id": "E1", "method": "POST", "route": "/users/save", "handler_file": "app/Users.php",
             "handler": "actionSave", "exposure": "privileged"},
            {"id": "E2", "method": "POST", "route": "/users/promote", "handler_file": "app/Users.php",
             "handler": "actionPromote", "exposure": "authenticated"}]


@needs_rg
def test_recipe_places_every_site_in_the_call_graph_with_its_guard(tmp_path):
    entries = _project(tmp_path)
    tb = Toolbox(_cfg(), tmp_path, tmp_path / "out")
    tb.entries_source = lambda: entries
    assert tb.run_recipe("r", "made_up_class", "x", why="").startswith("rejected: op_class")
    assert "rejected: guard" in tb.run_recipe("r", "file_write", "x", guard="(", why="")
    res = json.loads(tb.run_recipe("role-write", "credential_or_privilege_write", r"->role\s*=",
                                   guard=r"requireAdmin\(|->can\(", why="role column of the users table"))
    # the test file is not product code; the other three are the handler, a callee, an extension point
    assert res["sites"] == 3 and res["reach"] == {"handler": 1, "entry": 1, "no_callers": 1, "internal": 0}
    assert res["guard"] == {"pattern": r"requireAdmin\(|->can\(", "guarded": 1, "unguarded": 2}
    assert "credential_or_privilege_write" not in res["classes_left"] and "file_write" in res["classes_left"]
    sites = {s["function"]: s for s in assets.expand(tb.recipes["role-write"],
                                                     tb.grep_rows(r"->role\s*="), tb.call_index(), entries)}
    assert sites["Users::actionSave"]["reach"] == "handler" and sites["Users::actionSave"]["guard_at"] == \
        "app/Users.php:4"
    # reached from E2 through a call; the guard in the sibling handler does not count for it
    assert sites["Roles::setRole"]["entries"] == ["E2"] and sites["Roles::setRole"]["guard_at"] is None
    assert sites["Hooks::onImport"]["reach"] == "no_callers" and sites["Hooks::onImport"]["entries"] == []
    assert "rejected: a recipe" in tb.class_absent("credential_or_privilege_write", "none")
    assert tb.class_absent("file_write", "no file APIs: grep fopen|file_put_contents finds nothing") == \
        "recorded: file_write absent"


@needs_rg
def test_a_recipe_that_matches_every_mention_is_rejected(tmp_path, monkeypatch):
    _write(tmp_path, {"a.php": "role\nrole\nrole\n"})
    monkeypatch.setattr(assets, "MAX_SITES", 2)
    tb = Toolbox(_cfg(), tmp_path, tmp_path / "out")
    assert "rejected: 3 matches" in tb.run_recipe("w", "credential_or_privilege_write", "role", why="")
    assert tb.recipes == {}


def test_calls_through_a_parent_method_reach_the_implementation(tmp_path):
    _write(tmp_path, {"a.php": "\n" * 30})
    _index(tmp_path, [("i", "interface", "Store", "Store", "a.php", 1, 3), ("i_save", "method", "save", "Store::save",
                                                                          "a.php", 2, 2),
                      ("c", "class", "Db", "Db", "a.php", 5, 9), ("c_save", "method", "save", "Db::save", "a.php", 6, 8),
                      ("h", "method", "handle", "Ctl::handle", "a.php", 11, 14)],
           [("i", "i_save", "contains"), ("c", "c_save", "contains"), ("c", "i", "implements"),
            ("h", "i_save", "calls")])
    idx = assets.CallIndex(tmp_path)
    assert idx.enclosing("a.php", 7) == "c_save" and idx.ancestors("c_save") == {"h": 1}


def test_operations_in_a_handler_join_its_unit_and_the_rest_are_units_of_their_own():
    entries = [{"id": "E1", "route": "/a", "exposure": "public"}, {"id": "E2", "route": "/b", "exposure": "privileged"}]
    entry_units = [{"kind": "entry", "entries": [entries[0]]}, {"kind": "entry", "entries": [entries[1]]}]
    site = lambda f, ln, reach, ids, guard=None: {  # noqa: E731
        "recipe": "r", "op_class": "file_write", "file": f, "line": ln, "code": "write()", "function": f + "::fn",
        "span": [1, 50], "reach": reach, "entries": ids, **({"guard_at": guard} if guard is not False else {})}
    sites = [site("h.php", 3, "handler", ["E1"], False), site("deep.php", 9, "entry", ["E2"], None),
             site("deep.php", 12, "entry", ["E2"], None), site("ext.php", 4, "no_callers", [], None),
             site("pub.php", 5, "entry", ["E1"], "pub.php:2")]
    ops = assets.operation_units(sites, entries, entry_units, {"public": 0, "unknown": 1, "privileged": 3})
    assert entry_units[0]["operations"][0]["file"] == "h.php"  # reviewed with its handler, not twice
    assert "Sensitive operations in this handler" in assets.handler_operations(entry_units[0])
    # most exposed first; one unit per function (the two sites of deep.php together)
    assert [u["handler_file"] for u in ops] == ["pub.php", "ext.php", "deep.php"]
    assert [len(u["sites"]) for u in ops] == [1, 1, 2] and ops[0]["exposure"] == "public"
    assert ops[1]["reach"] == "no_callers" and ops[2]["unguarded"]
    order = assets.interleave(["a", "b", "c", "d"], ["X", "Y"], 3)
    assert order == ["a", "b", "X", "c", "d", "Y"] and assets.interleave(["a"], ["X", "Y"], 3) == ["a", "X", "Y"]
    brief = assets.operation_brief(ops[1], [sites[4]], {"r": {"why": "the cache writer"}})
    assert "Nothing in the repository calls this code" in brief and "WITH the project's guard" in brief
    assert "Recipe r: the cache writer" in brief


def test_identity_subsystems_and_the_design_checklist(tmp_path):
    _write(tmp_path, {"web/Register.php": "<?php\nfunction register() {\n  $u = User::findByEmail($e);\n}\n",
                      "config.php": "<?php\nreturn ['allowPublicRegistration' => true];\n"})
    tb = Toolbox(_cfg(), tmp_path, tmp_path / "out")
    tb.entries_source = lambda: [{"route": "/register", "handler_file": "web/Register.php"},
                                 {"route": "/login", "handler_file": "web/Login.php"}]
    assert tb.record_identity([{"name": "x", "kind": "magic"}]).startswith("rejected")
    assert "do not exist" in tb.record_identity([{"name": "x", "kind": "login", "files": ["nope.php"]}])
    res = tb.record_identity([{"name": "registration", "kind": "registration", "routes": ["^/register"],
                               "files": ["web/Register.php"], "settings": ["config.php:2 allowPublicRegistration"]},
                              {"name": "broken", "kind": "sso", "routes": ["("]}])
    assert "registration (registration): 1 entries so far" in res and "not recorded: broken" in res
    g = assets.group_identity(tb.identity[0], [{"id": "E1", "route": "/register"}, {"id": "E2", "route": "/x",
                                                                                     "handler_file": "web/Register.php"}],
                              [{"file": "web/Register.php", "line": 3}])
    assert g["entry_ids"] == ["E1", "E2"] and g["site_keys"] == ["web/Register.php:3"]
    ev = [{"file": "web/Register.php", "line": 3, "quote": "User::findByEmail($e)"}]
    out = tb.record_design([{"item": "record_claiming", "status": "flaw", "answer": "loads by email"},
                            {"item": "defaults", "status": "owner_decision", "answer": "open", "evidence": [
                                {"file": "config.php", "line": 2, "quote": "'allowPublicRegistration' => true"}]},
                            {"item": "nope", "status": "sound", "answer": "x"}])
    assert "record_claiming: evidence is required" in out and "unknown item 'nope'" in out and "answered: 1" in out
    out = tb.record_design({"item": "record_claiming", "status": "flaw", "answer": "loads by email", "evidence": ev})
    assert "answered: 2" in out and "left: identity_binding, token_lifecycle, privilege_ceiling" in out
    names = {t["function"]["name"] for t in tool_schemas("design")}
    assert {"record_design", "report_finding", "record_card"} <= names
    assert {"run_recipe", "record_identity", "class_absent"} <= {t["function"]["name"] for t in tool_schemas("assets")}
    assert "record_design" not in {t["function"]["name"] for t in tool_schemas("review")}


@needs_rg
def test_run_maps_assets_and_reviews_operations_and_identity_design(tmp_path, monkeypatch):
    from app.services.yasa_audit import pipeline

    proj = tmp_path / "p"
    _write(proj, {
        "web/Download.php": "<?php\nclass Download {\n  function execute() {\n    echo 'file';\n  }\n}\n",
        "web/Home.php": "<?php\nclass Home {\n  function execute() {\n    Cache::put($_GET['k']);\n  }\n}\n",
        "web/Register.php": "<?php\nclass Register {\n  function execute() {\n    $u = User::findByEmail($_POST['e']);\n"
                            "    $u->role = 'member';\n  }\n}\n",
        "lib/Cache.php": "<?php\nclass Cache {\n  static function put($k) {\n    file_put_contents('/c/' . $k, 1);\n"
                         "  }\n}\n",
        "lib/Hooks.php": "<?php\nclass Hooks {\n  function onImport($u, $row) {\n    $u->role = $row['role'];\n  }\n}\n",
        "config.php": "<?php\nreturn ['allowPublicRegistration' => true];\n"})
    extractor = ("import json, os, sys\nr = sys.argv[1]\nprint(json.dumps([{'route': '/' + f[:-4].lower(), "
                 "'handler_file': 'web/' + f, 'handler': 'execute', 'exposure': 'public'} "
                 "for f in sorted(os.listdir(os.path.join(r, 'web')))]))")
    model = {"authentication": "none", "authorization": "none", "permission_mapping": "none",
             "ladder": ["anonymous"], "shared_protections": "none", "principals": "anyone",
             "evidence": [{"file": "web/Home.php", "line": 3, "quote": "function execute()"}]}
    absent = [c for c in assets.OP_CLASSES if c not in ("credential_or_privilege_write", "file_write")]
    ok = lambda f, ln, q: [{"file": f, "line": ln, "quote": q}]  # noqa: E731
    reg = ("web/Register.php", 4, "User::findByEmail($_POST['e'])")
    scripts = {
        "recon": [("run_extractor", {"name": "web", "code": extractor}),
                  ("check_coverage", {"request_read_pattern": r"\$_(GET|POST)"}), ("finish", {"notes": "web/*"})],
        "access": [("record_access_model", model), ("finish", {})],
        "assets": [("finish", {}),  # refused: classes and identity left
                   ("run_recipe", {"name": "role-write", "op_class": "credential_or_privilege_write",
                                   "pattern": r"->role = ", "why": "users.role column"}),
                   ("run_recipe", {"name": "cache-write", "op_class": "file_write", "pattern": "file_put_contents",
                                   "why": "the file cache"}),
                   *[("class_absent", {"op_class": c, "reason": "searched, none"}) for c in absent],
                   ("record_identity", {"subsystems": [{"name": "registration", "kind": "registration",
                                                        "routes": ["^/register"], "files": ["web/Register.php"],
                                                        "settings": ["config.php:2 allowPublicRegistration"]}]}),
                   ("finish", {"notes": "mapped"})],
        "/download": [("record_card", {"function": "download", "callers": "anyone", "authz_verdict": "ok",
                                       "hypotheses": []})],
        # the entry reviewer traces the cache write: the operation unit for it is not run again
        "/home": [("record_card", {"function": "home", "callers": "anyone", "authz_verdict": "ok", "hypotheses": [
            {"risk": "path traversal in the cache key", "anchor": "lib/Cache.php:4", "status": "rejected"}]})],
        "/register": [("record_card", {"function": "register", "callers": "anyone", "authz_verdict": "ok",
                                       "hypotheses": []})],
        "operation": [("record_card", {"function": "plugin import sets roles", "callers": "plugins (no caller)",
                                       "authz_verdict": "unclear", "hypotheses": [
                                           {"risk": "role from imported row", "anchor": "lib/Hooks.php:4",
                                            "status": "open"}], "open_leads": ["lib/Hooks.php:4 role from row"]})],
        "design": [("finish", {}),  # refused: checklist not answered
                   ("record_design", {"items": [
                       {"item": "record_claiming", "status": "flaw", "answer": "an existing account is loaded by "
                        "email and given the posted password", "evidence": ok(*reg)},
                       {"item": "defaults", "status": "owner_decision", "answer": "registration open by default",
                        "evidence": ok("config.php", 2, "'allowPublicRegistration' => true")},
                       *[{"item": k, "status": "unclear", "answer": "not read"} for k in
                         ("identity_binding", "token_lifecycle", "privilege_ceiling")]]}),
                   ("report_finding", {"vuln_type": "Account takeover", "cwe": "CWE-287",
                                       "sink_file": "web/Register.php", "sink_line": 4, "source": "email",
                                       "entry": "POST /register (public)", "required_privilege": "public",
                                       "verdict": "likely", "root_cause": "registration reuses an account by email",
                                       "impact": "takes over an inactive account when registration is open",
                                       "route_evidence": {"file": reg[0], "line": 2, "quote": "class Register"}}),
                   ("finish", {})],
        "verify": [("conclude", {"verdict": "uncertain", "reason": "not settled"})],
    }
    users = {}

    class Router(ScriptedLLM):
        def chat(self, messages, tools=None):
            if not self.script and not self.usage.calls:  # a reminder may follow the first user message
                system, user = messages[0]["content"], messages[1]["content"]
                key = ("assets" if "worth protecting" in system else "access" if "controls ACCESS" in system
                       else "verify" if "Try to refute it" in user else "design" if "Identity subsystem" in user
                       else "operation" if "Sensitive operation(s) to review" in user
                       else next((k for k in ("/download", "/home", "/register") if f'"route": "{k}"' in user),
                                 "recon"))
                users.setdefault(key, user)
                self.script = list(scripts[key])
            return super().chat(messages, tools)

    monkeypatch.setattr(pipeline, "LLM", lambda cfg: Router([]))
    m = pipeline.run(_cfg(workers=1), proj, tmp_path / "out", deadline=time.time() + 600)
    a = m["recon"]["assets"]
    assert a["sites"] == 3 and a["by_class"] == {"credential_or_privilege_write": 2, "file_write": 1}
    assert a["identity_subsystems"] == 1 and a["finished"] and m["recon"]["assets_agent"]["steps"] >= 10
    rv = m["review"]
    assert rv["units"] == 3 and rv["reviewed_units"] == 3 and rv["design_units"] == 1
    # the role write in /register's handler goes to that entry; the cache write was traced by /home's
    # reviewer; only the extension point with no caller is reviewed as an operation unit
    assert rv["operation_units"] == 2 and rv["operation_units_covered_by_entry_review"] == 1
    assert rv["reviewed_operation_units"] == 1
    assert "Sensitive operations in this handler" in users["/register"] and "web/Register.php:5" in users["/register"]
    assert "Nothing in the repository calls this code" in users["operation"]
    assert "Checklist (answer every item with record_design)" in users["design"] and "allowPublicRegistration" in \
        users["design"]
    data = json.loads((tmp_path / "out" / "review" / "findings.json").read_text())
    (sheet,) = data["design_worksheet"]
    assert sheet["subsystem"] == "registration" and sheet["complete"] and len(sheet["items"]) == 5
    assert rv["design_items"] == {"flaw": 1, "owner_decision": 1, "unclear": 3}
    (f,) = data["findings"]
    assert f["unit_kind"] == "design" and f["handler"] == "identity:registration" and f["entries"]
    assert any(lead["handler"] == "lib/Hooks.php::<lib/Hooks.php>" for lead in data["open_leads"])
    assert data["not_reviewed_operations"] == [] and data["not_reviewed_design"] == []
    saved = json.loads((tmp_path / "out" / "recon" / "assets.json").read_text())
    assert {r["name"] for r in saved["recipes"]} == {"role-write", "cache-write"}
