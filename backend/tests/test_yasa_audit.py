"""Unit tests for app.services.yasa_audit (no LLM, no YASA binary needed; ripgrep from PATH)."""

import importlib.util
import json
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.yasa_audit.config import AuditConfig
from app.services.yasa_audit.toolbox import FactBook, Toolbox, tool_schemas

BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "yasa_audit" / "eval.py"
RG = shutil.which("rg")
needs_rg = pytest.mark.skipif(RG is None, reason="ripgrep not installed")


def _cfg(**kw) -> AuditConfig:
    cfg = AuditConfig(**kw)
    if RG:
        cfg.rg_bin = RG
    return cfg


def _write(root, files):
    for rel, txt in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(txt)


def _call(name, args, cid="c1"):
    return SimpleNamespace(id=cid, function=SimpleNamespace(name=name, arguments=json.dumps(args)))


class ScriptedLLM:
    """Returns the scripted tool calls in order, then finish."""

    def __init__(self, script):
        self.script = list(script)
        self.usage = SimpleNamespace(prompt=0, completion=0, cached=0, reasoning=0, calls=0)

    def chat(self, messages, tools=None):
        self.usage.calls += 1
        name, args = self.script.pop(0) if self.script else ("finish", {"notes": "done"})
        return SimpleNamespace(content="", tool_calls=[_call(name, args, f"c{self.usage.calls}")])


class ByRole:
    """LLM factory for recon tests: each agent gets the scripted model for its role, picked from its
    system prompt at the first call (the two agents start in parallel, in no fixed order)."""

    def __init__(self, **roles):
        self.roles = roles

    def __call__(self, cfg):
        roles = self.roles

        class Proxy:
            usage = SimpleNamespace(prompt=0, completion=0, cached=0, reasoning=0, calls=0)

            def chat(self, messages, tools=None):
                role = "access" if "controls ACCESS" in messages[0]["content"] else "surface"
                return roles[role].chat(messages, tools)

        return Proxy()


# ---------------------------------------------------------------- toolbox


def test_toolbox_confines_paths(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.ts").write_text("x\ny\n")
    (tmp_path / "proj_evil").mkdir()
    (tmp_path / "proj_evil" / "secret.txt").write_text("s")
    tb = Toolbox(AuditConfig(), tmp_path / "proj", tmp_path / "out")
    assert "a.ts lines 1-2" in tb.read_file("a.ts")
    with pytest.raises(ValueError):
        tb.read_file("../proj_evil/secret.txt")  # sibling dir with the same prefix
    (tmp_path / "proj" / "link").symlink_to(tmp_path / "proj_evil")
    with pytest.raises(ValueError):
        tb.read_file("link/secret.txt")


@needs_rg
def test_grep_path_globs_match_relative_to_project(tmp_path):
    """Regression: rg resolved globs containing '/' against the process cwd, so they never matched."""
    _write(tmp_path, {"app/code/A/Ctrl.php": "<?php $this->getRequest()->getParam('id');\n",
                      "lib/B.php": "<?php getParam('x');\n"})
    tb = Toolbox(_cfg(), tmp_path, tmp_path)
    assert tb.grep("getParam", glob="app/**/*.php").splitlines() == [
        "app/code/A/Ctrl.php:1:<?php $this->getRequest()->getParam('id');"]
    assert len(tb.grep_rows("getParam")) == 2
    assert tb.grep("getparam") == "(no matches)"  # case-sensitive by default
    assert len(tb.grep_rows("(?i)getparam")) == 2


def test_tool_schemas_per_role():
    recon = {t["function"]["name"] for t in tool_schemas("recon")}
    review = {t["function"]["name"] for t in tool_schemas("review")}
    assert {"run_extractor", "check_coverage", "codegraph_routes", "finish"} <= recon
    assert {"record_card", "report_finding", "add_fact", "finish"} <= review
    assert not recon & {"report_finding", "record_card"} and not review & {"run_extractor"}


EXTRACTOR = """
import json, os, sys
root = sys.argv[1]
out = []
for d, _, fs in os.walk(os.path.join(root, 'controllers')):
    for f in sorted(fs):
        rel = os.path.relpath(os.path.join(d, f), root)
        out.append({'route': '/' + f[:-4].lower(), 'method': 'GET', 'handler_file': rel,
                    'handler': 'execute', 'exposure': 'public' if 'Public' in f else 'privileged',
                    'auth': 'none' if 'Public' in f else 'ACL admin'})
out.append({'route': '/ghost', 'handler_file': 'controllers/Missing.php', 'handler': 'execute'})
out.append({'no_route': True})
print(json.dumps(out))
"""


def test_run_extractor_runs_agent_code_and_checks_handlers(tmp_path):
    proj, out = tmp_path / "p", tmp_path / "o"
    out.mkdir()
    _write(proj, {"controllers/PublicView.php": "<?php class PublicView { function execute() {} }",
                  "controllers/AdminSave.php": "<?php class AdminSave { function execute() {} }",
                  "controllers/Broken.php": "<?php class Broken { function run() {} }"})
    tb = Toolbox(AuditConfig(), proj, out)
    res = json.loads(tb.run_extractor("pages", EXTRACTOR))
    assert res["entries"] == 4 and res["handler_resolved"] == 2 and res["handler_unresolved"] == 2
    assert res["by_exposure"] == {"privileged": 2, "public": 1, "unknown": 1}
    assert any("does not exist" in u for u in res["unresolved_samples"])
    assert any("does not occur" in u for u in res["unresolved_samples"])  # Broken has no execute()
    assert res["problems"] and len(res["random_resolved_samples_to_check_by_reading"]) == 2
    assert (out / "extractors" / "pages.py").read_text() == EXTRACTOR
    # same name replaces, another name adds; manual entries are merged and deduplicated
    tb.run_extractor("pages", "import json; print(json.dumps([{'route': '/a', "
                              "'handler_file': 'controllers/AdminSave.php'}]))")
    tb.add_entries([{"route": "/a", "handler_file": "controllers/AdminSave.php"},
                    {"route": "/b", "handler_file": "controllers/PublicView.php", "exposure": "public"}])
    assert [e["route"] for e in tb.entries()] == ["/a", "/b"]
    assert tb.run_extractor("bad name!", "").startswith("error")
    assert "exited 1" in tb.run_extractor("boom", "raise SystemExit(1)")
    assert "not JSON" in tb.run_extractor("text", "print('hello')")


@needs_rg
def test_check_coverage_reports_request_reads_outside_entries(tmp_path):
    _write(tmp_path, {"web/Page.php": "<?php $r->getParam('a');\n",
                      "api/Rest.php": "<?php $r->getParam('b');\n$r->getParam('c');\n"})
    tb = Toolbox(_cfg(), tmp_path, tmp_path)
    tb.add_entries([{"route": "/page", "handler_file": "web/Page.php", "handler": "getParam"}])
    res = json.loads(tb.check_coverage(r"getParam\("))
    assert (res["sites"], res["covered_sites"], res["uncovered_sites"]) == (3, 1, 2)
    assert res["uncovered_by_directory"] == [["api", 2]]


def test_factbook_accepts_only_evidence_found_in_code(tmp_path):
    _write(tmp_path, {"lib/Escaper.php": "<?php\nclass Escaper {\n  function escapeHtml($s) {\n"
                                         "    return htmlspecialchars($s, ENT_QUOTES);\n  }\n}\n"})
    fb = FactBook(tmp_path)
    ok = [{"file": "lib/Escaper.php", "line": 4, "quote": "htmlspecialchars($s,   ENT_QUOTES)"}]
    assert fb.add("escapeHtml HTML-escapes with ENT_QUOTES", ok, "u1") == "accepted as F1"
    assert fb.add("escapeHtml  html-escapes with ENT_QUOTES", ok, "u2") == "already known as F1"
    assert fb.add("x" * 300, ok, "u2").startswith("rejected: the statement has 300")
    assert fb.add("x", [{"file": "lib/Escaper.php", "line": 4, "quote": "strip_tags"}], "u3").startswith("rejected")
    assert fb.add("x", [{"file": "../etc/passwd", "line": 1, "quote": "root"}], "u3").startswith("rejected")
    assert fb.add("x", [], "u3").startswith("rejected")
    assert "F1: escapeHtml" in fb.prompt_block() and "lib/Escaper.php:4" in fb.prompt_block()
    assert len(fb.facts) == 1


# ---------------------------------------------------------------- pipeline


def test_units_dedupe_handlers_and_order_by_exposure():
    from app.services.yasa_audit.pipeline import _peers, _units

    entries = [
        {"id": "E1", "route": "/admin/x", "handler_file": "a/Admin.php", "handler": "execute",
         "exposure": "privileged"},
        {"id": "E2", "route": "/V1/carts/:id", "handler_file": "q/Cart.php", "handler": "get",
         "exposure": "authenticated"},
        {"id": "E3", "route": "/V1/guest-carts/:id", "handler_file": "q/Cart.php", "handler": "get",
         "exposure": "public"},
        {"id": "E4", "route": "/V1/carts/:id/items", "handler_file": "q/Item.php", "handler": "save",
         "exposure": "authenticated"},
        {"id": "E5", "route": "/broken", "handler_file": "x/Gone.php", "handler": "run", "exposure": "public",
         "resolved": False},
    ]
    units = _units(entries)
    # exposure first: an unresolved public entry still comes before authenticated and privileged ones
    assert [[e["id"] for e in u["entries"]] for u in units] == [["E2", "E3"], ["E5"], ["E4"], ["E1"]]
    assert units[0]["exposure"] == "public"  # the most exposed route of a handler decides
    peers = _peers(units[2], entries)  # the /V1/carts/:id/items unit
    assert any("/V1/carts/:id ->" in p for p in peers)


def test_handler_snippet_starts_at_the_handler(tmp_path):
    from app.services.yasa_audit.pipeline import _handler_snippet

    _write(tmp_path, {"C.php": "<?php\n" + "// pad\n" * 30 + "    public function execute()\n    {\n"})
    snip = _handler_snippet(tmp_path, {"handler_file": "C.php", "handler": "Ns\\C::execute"}, lines=3)
    assert snip.startswith("C.php lines 32-33") and "public function execute()" in snip


def test_recon_falls_back_to_codegraph_when_agent_finds_nothing(tmp_path, monkeypatch):
    from app.services.yasa_audit import pipeline

    monkeypatch.setattr(pipeline, "LLM", lambda cfg: ScriptedLLM([]))
    monkeypatch.setattr(pipeline, "codegraph_db", lambda root: Path("x"))
    monkeypatch.setattr(pipeline, "codegraph_routes", lambda db, root: [
        {"route": "/orders/:id", "method": "GET", "file": "r.ts", "handler": "show"}])
    m = pipeline.recon(AuditConfig(), tmp_path, tmp_path / "recon")
    assert m["source"] == "codegraph-fallback" and m["entries"] == 1
    (e,) = json.loads((tmp_path / "recon" / "entries.json").read_text())
    assert e["id"] == "E1" and e["handler_file"] == "r.ts" and e["resolved"] is False


@needs_rg
def test_run_recon_then_review_end_to_end(tmp_path, monkeypatch):
    from app.services.yasa_audit import pipeline

    proj = tmp_path / "p"
    _write(proj, {"web/Download.php": "<?php\nclass Download {\n  function execute() {\n"
                                      "    readfile('/srv/files/' . $_GET['name']);\n  }\n}\n",
                  "web/Home.php": "<?php\nclass Home {\n  function execute() { echo 'hi'; }\n}\n"})
    extractor = ("import json, os, sys\nr = sys.argv[1]\nprint(json.dumps([{'route': '/' + f[:-4].lower(), "
                 "'handler_file': 'web/' + f, 'handler': 'execute', 'exposure': 'public'} "
                 "for f in sorted(os.listdir(os.path.join(r, 'web')))]))")
    scripts = {
        "access": [("finish", {"notes": "too early"}),  # refused: no access model yet
                   ("record_access_model", {"authentication": "none", "authorization": "none",
                                            "permission_mapping": "none", "principals": "anyone",
                                            "evidence": [{"file": "web/Home.php", "line": 3,
                                                          "quote": "function execute()"}]}),
                   ("finish", {"notes": "no access control"})],
        "recon": [("run_extractor", {"name": "web", "code": extractor}),
                  ("finish", {"notes": "too early"}),  # refused: coverage not checked
                  ("check_coverage", {"request_read_pattern": r"\$_GET"}),
                  ("finish", {"notes": "web/<Name>.php::execute serves /<name>"})],
        "/download": [("record_card", {"function": "file download", "callers": "anyone",
                                       "authz_verdict": "ok", "hypotheses": [
                                           {"risk": "path traversal", "why": "name joins a path",
                                            "status": "confirmed"}]}),  # refused: no anchor
                      ("record_card", {"function": "file download", "callers": "anyone",
                                       "authz_verdict": "ok", "facts_used": ["F9"], "hypotheses": [
                                           {"risk": "path traversal", "anchor": "web/Download.php:4",
                                            "why": "name joins a path", "status": "confirmed"}]}),
                      ("add_fact", {"statement": "Download reads files under /srv/files", "evidence": [
                          {"file": "web/Download.php", "line": 4, "quote": "readfile('/srv/files/'"}]}),
                      ("report_finding", {"vuln_type": "Path traversal", "cwe": "CWE-22",
                                          "sink_file": "web/Download.php", "sink_line": 4,
                                          "source": "$_GET['name']", "entry": "GET /download (public)",
                                          "required_privilege": "none", "verdict": "confirmed"})],
        "/home": [("record_card", {"function": "home page", "callers": "anyone", "authz_verdict": "ok",
                                   "hypotheses": []})],
    }
    users, systems = [], []

    class Router(ScriptedLLM):
        def chat(self, messages, tools=None):
            if not self.script and len(messages) == 2:
                user = messages[1]["content"]
                users.append(user)
                systems.append(messages[0]["content"])
                key = next((k for k in ("/download", "/home") if f'"route": "{k}"' in user),
                           "access" if "controls ACCESS" in messages[0]["content"] else "recon")
                self.script = list(scripts[key])
            return super().chat(messages, tools)

    monkeypatch.setattr(pipeline, "LLM", lambda cfg: Router([]))
    cfg = _cfg(workers=1)
    m = pipeline.run(cfg, proj, tmp_path / "out", deadline=time.time() + 600)
    assert m["recon"]["entries"] == 2 and m["recon"]["resolved"] == 2
    assert m["recon"]["access_model"]["principals"] == "anyone" and m["recon"]["coverage"]["sites"] == 1
    assert m["recon"]["notes"] == "web/<Name>.php::execute serves /<name>"  # the early finish was refused
    assert "- principals: anyone" in systems[-1]  # reviewers get the access model
    assert m["review"]["units"] == 2 and m["review"]["reviewed_units"] == 2 and m["review"]["facts"] == 1
    data = json.loads((tmp_path / "out" / "review" / "findings.json").read_text())
    (f,) = data["findings"]
    assert f["cwe"] == "CWE-22" and f["handler"] == "web/Download.php::execute" and data["not_reviewed"] == []
    cards = json.loads((tmp_path / "out" / "review" / "cards.json").read_text())
    assert {c["function"] for c in cards} == {"file download", "home page"}  # one card per unit
    assert next(c for c in cards if c["function"] == "file download")["hypotheses"][0]["anchor"] == \
        "web/Download.php:4"
    assert any("readfile('/srv/files/'" in u for u in users[1:])  # the handler's code is in the unit
    m2 = pipeline.run(cfg, proj, tmp_path / "out", deadline=time.time() + 600)  # recon reused
    assert m2["recon"].get("reused") is True


def test_schedule_respects_deadline_and_order():
    from app.services.yasa_audit.pipeline import MIN_UNIT_S, _schedule

    seen = []
    results, skipped = _schedule(["a", "b", "c"], lambda i, u: seen.append(u) or {"findings": [u]},
                                 workers=1, deadline=None)
    assert seen == ["a", "b", "c"] and skipped == []
    results, skipped = _schedule(["a", "b"], lambda i, u: {"findings": [u]}, workers=2,
                                 deadline=time.time() + MIN_UNIT_S / 2)
    assert results == [] and sorted(skipped) == ["a", "b"]


def test_schedule_skips_when_stopped():
    from app.services.yasa_audit.pipeline import _schedule

    results, skipped = _schedule([1, 2, 3], lambda i, u: {"u": u}, 2, None, stop=lambda: True)
    assert results == [] and skipped == [1, 2, 3]


# ---------------------------------------------------------------- agent loop and usage


def test_agent_loop_stops_after_deadline(tmp_path):
    from app.services.yasa_audit.agent_loop import run_agent

    tb = Toolbox(AuditConfig(), tmp_path, tmp_path)
    res = run_agent(ScriptedLLM([("list_dir", {})] * 5), tb, tool_schemas("review"), "sys", "user",
                    budget=50, log_path=tmp_path / "t.jsonl", deadline=time.time() - 120)
    assert res["timed_out"] and res["steps"] == 0


def test_agent_loop_sends_reminder_once(tmp_path):
    from app.services.yasa_audit.agent_loop import run_agent

    seen_msgs = []

    class FakeLLM:
        def chat(self, messages, tools=None):
            seen_msgs.append([m["content"] for m in messages if m["role"] == "user"])
            return SimpleNamespace(content="", tool_calls=[_call("list_dir", {})])

    tb = Toolbox(AuditConfig(), tmp_path, tmp_path)
    run_agent(FakeLLM(), tb, tool_schemas("recon"), "sys", "user", budget=6,
              log_path=tmp_path / "t.jsonl", reminders=[(lambda steps, t: steps >= 2, "WRITE AN EXTRACTOR")])
    assert sum(m.count("WRITE AN EXTRACTOR") for m in seen_msgs[-1:]) == 1
    assert not any("WRITE AN EXTRACTOR" in m for m in seen_msgs[1])  # not before step 2


def test_agent_loop_stops_when_cancelled(tmp_path):
    from app.services.yasa_audit.agent_loop import run_agent

    class FakeLLM:
        def chat(self, messages, tools=None):  # pragma: no cover - must not be called
            raise AssertionError("LLM called after cancel")

    tb = Toolbox(AuditConfig(should_stop=lambda: True), tmp_path, tmp_path)
    res = run_agent(FakeLLM(), tb, tool_schemas("review"), "s", "u", budget=5, log_path=tmp_path / "t.jsonl")
    assert res["steps"] == 0 and not res["finished"]


def test_llm_usage_counts_cached_and_reasoning_tokens():
    from app.services.yasa_audit.llm import Usage

    u = Usage()
    u.add(SimpleNamespace(prompt_tokens=100, completion_tokens=20,
                          prompt_tokens_details=SimpleNamespace(cached_tokens=64),
                          completion_tokens_details=SimpleNamespace(reasoning_tokens=12)), 1.0)
    u.add(SimpleNamespace(prompt_tokens=10, completion_tokens=5, prompt_tokens_details=None,
                          completion_tokens_details=None), 1.0)
    assert (u.prompt, u.completion, u.cached, u.reasoning, u.calls) == (110, 25, 64, 12, 2)


# ---------------------------------------------------------------- DeepAudit task integration


def test_to_deepaudit_findings_maps_privilege_and_filters():
    from app.services.yasa_audit.runner import to_deepaudit_findings

    raw = [
        {"vuln_type": "SQL injection", "cwe": "CWE-89", "sink_file": "a/Dao.java", "sink_line": 12,
         "source": "req.getParameter(id)", "hops": ["A:1", "B:2"], "verdict": "confirmed",
         "required_privilege": "none", "entry": "GET /x"},
        {"cwe": "CWE-89", "sink_file": "a/Dao.java", "sink_line": 12, "verdict": "likely"},  # dup
        {"cwe": "CWE-22", "sink_file": "b.ts", "sink_line": "7", "verdict": "likely"},
        {"cwe": "CWE-639", "sink_file": "c.php", "sink_line": 3, "verdict": "confirmed",
         "required_privilege": "admin"},
        {"cwe": "CWE-89", "sink_file": "setup/x.php", "sink_line": 3, "verdict": "confirmed",
         "required_privilege": "operator_or_cli"},
        {"cwe": "CWE-78", "sink_file": "d.ts", "sink_line": 3, "verdict": "false_positive"},
        {"cwe": "CWE-9999", "sink_file": "e.ts", "sink_line": None, "verdict": "confirmed"},
    ]
    out = to_deepaudit_findings(raw)
    assert [f["file_path"] for f in out] == ["a/Dao.java", "b.ts", "c.php", "setup/x.php", "e.ts"]
    sqli, trav, idor, cli, other = out
    assert sqli["vulnerability_type"] == "sql_injection" and sqli["severity"] == "high"
    assert "1. A:1" in sqli["description"] and "Entry: GET /x" in sqli["description"]
    assert "verdict" not in sqli and "is_verified" not in sqli  # static verdict is not verification
    assert trav["severity"] == "medium" and trav["line_start"] == 7  # likely -> one level lower
    assert idor["severity"] == "medium" and cli["severity"] == "low"
    assert other["vulnerability_type"] == "other" and other["line_start"] is None


def test_audit_scope_with_mode():
    from app.api.v1.endpoints.agent_tasks import AgentTaskCreate, _audit_scope_with_mode

    assert _audit_scope_with_mode(None, "agent") is None
    assert _audit_scope_with_mode({"product": "x"}, "yasa") == {"product": "x", "mode": "yasa"}
    assert AgentTaskCreate(project_id="p").audit_mode == "agent"
    with pytest.raises(ValueError):
        AgentTaskCreate(project_id="p", audit_mode="nope")


async def test_execute_yasa_task_saves_findings(tmp_path, monkeypatch):
    from app.services.yasa_audit import task as ytask

    monkeypatch.setattr(ytask, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(ytask, "check_tools", lambda cfg: [])
    monkeypatch.setattr(ytask, "init_navigation", lambda *a, **k: None)
    seen = {}

    def fake_audit(cfg, root, out, deploy, product, start, deadline):
        seen["workers"], seen["budget"], seen["product"] = cfg.workers, round(deadline - start), product
        return {"recon": {"entries": 3, "resolved": 3}, "review": {"units": 3, "reviewed_units": 2},
                "findings": [{"cwe": "CWE-89", "sink_file": "A.java", "sink_line": 5, "verdict": "confirmed"},
                             {"cwe": "CWE-862", "sink_file": "B.java", "sink_line": 9, "verdict": "likely"}],
                "not_reviewed": ["E3"], "tokens": 150}

    monkeypatch.setattr(ytask, "run_entry_audit", fake_audit)

    class DB:
        async def commit(self):
            pass

        async def refresh(self, obj):
            pass

    events = []

    class Emitter:
        def __getattr__(self, name):
            async def emit(*a, **k):
                events.append(name)
            return emit

    saved = {}

    async def save(db, task_id, findings, project_root=None):
        saved["findings"] = findings
        return len(findings)

    t = SimpleNamespace(id="t1", audit_scope={"mode": "yasa", "product": "public: /login"},
                        timeout_seconds=1200, total_files=10, critical_count=0, high_count=0,
                        medium_count=0, low_count=0)
    llm = SimpleNamespace(provider="openai", base_url="http://llm", api_key="k", model="m",
                          timeout=60, temperature=0.1, max_tokens=4096)
    await ytask.execute_yasa_task(DB(), t, str(tmp_path), llm, Emitter(), lambda: False, save,
                                  lambda f: 42.0)
    assert seen == {"workers": 16, "budget": 1200, "product": "public: /login"}
    assert [f["file_path"] for f in saved["findings"]] == ["A.java", "B.java"]
    assert t.findings_count == 2 and t.tokens_used == 150 and t.status == "completed"
    assert (t.high_count, t.medium_count) == (1, 1) and t.security_score == 42.0
    assert "emit_task_complete" in events and "emit_warning" in events  # E3 not reviewed


def test_count_sources_skips_vendor_dirs(tmp_path):
    from app.services.yasa_audit.task import count_sources

    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    for p in ("src/A.java", "src/b.jsp", "src/c.ts", "src/readme.md", "node_modules/x/i.js"):
        (tmp_path / p).write_text("")
    assert count_sources(tmp_path) == 3


def test_scope_tree_applies_excludes_and_targets(tmp_path):
    from app.services.yasa_audit.task import scope_tree

    src = tmp_path / "p"
    for rel in ("src/A.java", "src/B.java", "node_modules/x/i.js", "app.log", "web/c.jsp"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("x")
    assert scope_tree(src, tmp_path / "s0", ["*.min.js"], None) == (src, 0)
    root, dropped = scope_tree(src, tmp_path / "s1", ["node_modules/**", "*.log"], None)
    kept = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert kept == ["src/A.java", "src/B.java", "web/c.jsp"] and dropped == 2
    root, dropped = scope_tree(src, tmp_path / "s2", ["*.log"], ["src/A.java", "./web/c.jsp"])
    kept = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert kept == ["src/A.java", "web/c.jsp"] and dropped == 3


def test_benchmark_scoring():
    spec = importlib.util.spec_from_file_location("yasa_bench_eval", BENCH)
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
    findings = [
        {"sink_file": "routes/search.ts", "sink_line": 23, "cwe": "CWE-89", "verdict": "confirmed"},
        {"sink_file": "routes/keyServer.ts", "sink_line": 14, "cwe": "CWE-22", "verdict": "likely"},
        {"sink_file": "routes/trackOrder.ts", "sink_line": 18, "cwe": "CWE-89", "verdict": "false_positive"},
        {"sink_file": "routes/vulnCodeFixes.ts", "sink_line": 83, "cwe": "CWE-22", "verdict": "likely"},
    ]
    r = ev.score("juice-mini", findings)
    assert r["recall"] == "1/18"
    assert [n["id"] for n in r["negative_hits"]] == ["JS-N02"]
    assert r["wrongly_rejected"] == ["JS-E01"]
    assert r["unmatched"] == []
    assert json.dumps(r)


def test_run_extractor_reports_lost_entries_on_rewrite(tmp_path):
    _write(tmp_path / "p", {f"c/A{i}.php": "<?php function execute() {}" for i in range(10)})
    tb = Toolbox(AuditConfig(), tmp_path / "p", tmp_path)
    gen = ("import json; print(json.dumps([{'route': '/a%d' % i, 'handler_file': 'c/A%d.php' % i, "
           "'handler': 'execute'} for i in range({n})]))")
    assert "change_from_previous_version" not in json.loads(tb.run_extractor("x", gen.replace("{n}", "10")))
    res = json.loads(tb.run_extractor("x", gen.replace("{n}", "3")))
    ch = res["change_from_previous_version"]
    assert (ch["previous"], ch["now"], ch["removed"], ch["added"]) == (10, 3, 7, 0)
    assert "lost 7 of 10" in res["warning"] and ch["removed_by_directory"] == [["c", 7]]


def test_agent_loop_explains_unparsable_arguments_and_forces_finish(tmp_path):
    from app.services.yasa_audit.agent_loop import run_agent

    class FakeLLM:
        def __init__(self):
            self.seen = []

        def chat(self, messages, tools=None):
            self.seen.append([t["function"]["name"] for t in tools])
            if len(self.seen) == 1:  # a long call cut off mid-JSON
                bad = SimpleNamespace(id="c1", function=SimpleNamespace(name="list_dir", arguments='{"path": "a'))
                return SimpleNamespace(content="", tool_calls=[bad])
            if [t for t in tools if t["function"]["name"] != "finish"]:
                return SimpleNamespace(content="", tool_calls=[_call("list_dir", {})])
            return SimpleNamespace(content="", tool_calls=[_call("finish", {"notes": "two dispatchers"})])

    llm = FakeLLM()
    tb = Toolbox(AuditConfig(), tmp_path, tmp_path)
    res = run_agent(llm, tb, tool_schemas("recon"), "s", "u", budget=2, log_path=tmp_path / "t.jsonl")
    log = [json.loads(line) for line in (tmp_path / "t.jsonl").read_text().splitlines()]
    assert "not valid JSON" in next(e["content"] for e in log if e.get("role") == "tool")
    assert llm.seen[-1] == ["finish"] and res["finished"] and tb.notes == "two dispatchers"


@needs_rg
def test_recon_second_pass_turns_notes_into_extractors(tmp_path, monkeypatch):
    from app.services.yasa_audit import pipeline

    _write(tmp_path, {"api/Posts.java": "class Posts {\n  Mono<ServerResponse> list(ServerRequest r) {\n"
                                        "    return r.queryParam(\"q\");\n  }\n}\n"})
    extractor = ("import json; print(json.dumps([{'route': '/apis/posts', 'handler_file': 'api/Posts.java', "
                 "'handler': 'list', 'exposure': 'authenticated'}]))")
    model = {"authentication": "session", "authorization": "RBAC filter", "permission_mapping": "verb+path",
             "principals": "anonymous < user", "evidence": [{"file": "api/Posts.java", "line": 2,
                                                             "quote": "list(ServerRequest r)"}]}
    script = [("list_dir", {})] * 8 + [                       # pass 1 only reads (budget 2, +6 grace) ...
              ("finish", {"notes": "RouterFunction beans: /apis/posts -> Posts::list"}),  # ... forced finish
              ("run_extractor", {"name": "router", "code": extractor}),                  # pass 2
              ("record_access_model", model),
              ("check_coverage", {"request_read_pattern": r"queryParam\("}),
              ("finish", {"notes": "RouterFunction beans, 1 extractor"})]
    surface = ScriptedLLM([x for x in script if x[0] != "record_access_model"])
    access = ScriptedLLM([("record_access_model", model), ("finish", {})])
    seen = []
    orig = surface.chat

    def chat(messages, tools=None):
        seen.append(messages[-1]["content"] if messages[-1]["role"] == "user" else messages[1]["content"])
        return orig(messages, tools)

    surface.chat = chat
    monkeypatch.setattr(pipeline, "LLM", ByRole(access=access, surface=surface))
    cfg = _cfg(recon_budget=2)
    m = pipeline.recon(cfg, tmp_path, tmp_path / "recon")
    assert m["passes"] == 2 and m["source"] == "agent" and m["entries"] == 1 and m["resolved"] == 1
    assert any("/apis/posts -> Posts::list" in x for x in seen) and m["notes"] == "RouterFunction beans, 1 extractor"
    assert m["access_model"]["principals"] == "anonymous < user"


def test_recon_finish_gates_and_access_model_evidence(tmp_path):
    _write(tmp_path, {"Sec.java": "class Sec {\n  boolean allowed() { return true; }\n}\n"})
    tb = Toolbox(AuditConfig(), tmp_path, tmp_path)
    tb.finish_gates = [(lambda t: t.access_model is None, "record_access_model first")]
    assert tb.finish("x") == "not finished: record_access_model first" and not tb.finished
    base = {"authentication": "a", "authorization": "b", "permission_mapping": "c", "principals": "d"}
    assert tb.record_access_model(**base).startswith("rejected: evidence is required")
    assert "quote not found" in tb.record_access_model(
        **base, evidence=[{"file": "Sec.java", "line": 2, "quote": "denyAll"}])
    assert tb.record_access_model(**base, evidence=[{"file": "Sec.java", "line": 2, "quote": "allowed()"}]) == \
        "access model recorded"
    assert tb.finish("done").startswith("finished") and tb.finished
    tb2 = Toolbox(AuditConfig(), tmp_path, tmp_path)
    tb2.finish_gates = tb.finish_gates
    tb2.finish("forced", _force=True)
    assert tb2.finished and tb2.notes == "forced"


def test_record_card_requires_anchors_and_counts_fact_citations(tmp_path):
    _write(tmp_path, {"A.java": "a\nb\nc\n"})
    fb = FactBook(tmp_path)
    fb.add("first", [{"file": "A.java", "line": 1, "quote": "a"}], "u0")
    fb.add("second", [{"file": "A.java", "line": 2, "quote": "b"}], "u0")
    tb = Toolbox(AuditConfig(), tmp_path, tmp_path, facts=fb, unit="E1")
    card = {"function": "f", "callers": "c", "authz_verdict": "ok"}
    assert tb.record_card(**card, hypotheses=[{"risk": "sqli", "status": "rejected"}]).startswith("rejected")
    assert tb.record_card(**card, hypotheses=[{"risk": "x", "anchor": "A.java:99", "status": "open"}]) \
        .startswith("rejected")  # line out of range
    assert "unknown fact ids ignored: ['F7']" in tb.record_card(
        **card, hypotheses=[{"risk": "idor", "anchor": "A.java:3", "status": "open"}], facts_used=["F2", "F7"])
    tb.record_card(**card, hypotheses=[], facts_used=["F2"])
    assert len(tb.cards) == 1  # a later call replaces the card
    block = fb.prompt_block()
    assert block.index("F2: second") < block.index("F1: first")  # most cited first


def test_adaptive_limiter_halves_on_rate_limit_and_grows_back():
    from app.services.yasa_audit.llm import AdaptiveLimiter, _is_rate_limit

    lim = AdaptiveLimiter(ceiling=16, grow_after=2)
    for _ in range(3):
        lim.acquire()
    assert lim.stats()["peak_in_flight"] == 3
    lim.release(rate_limited=True)
    assert lim.limit == 8 and lim.stats()["rate_limited"] == 1
    lim.release()
    lim.release()
    assert lim.limit == 9  # two successes in a row -> +1
    err = type("RateLimitError", (Exception,), {})("slow down")
    assert _is_rate_limit(err) and not _is_rate_limit(ValueError("boom"))

def test_report_finding_requires_fields(tmp_path):
    tb = Toolbox(AuditConfig(), tmp_path, tmp_path, unit="E1")
    assert tb.report_finding().startswith("rejected: missing vuln_type")
    full = {"vuln_type": "IDOR", "cwe": "CWE-639", "sink_file": "a.java", "sink_line": 3, "source": "id",
            "entry": "GET /x", "required_privilege": "customer"}
    assert tb.report_finding(**full, verdict="false_positive").startswith("rejected: verdict")
    assert tb.report_finding(**full, verdict="likely") == "recorded #1" and tb.findings[0]["_unit"] == "E1"


def test_recon_sends_access_model_to_the_surface_agent(tmp_path, monkeypatch):
    import threading

    from app.services.yasa_audit import pipeline

    _write(tmp_path, {"Sec.java": "class Sec {\n  boolean allowed() { return true; }\n}\n"})
    recorded = threading.Event()
    model = {"authentication": "a", "authorization": "b", "permission_mapping": "c", "principals": "anon < admin",
             "evidence": [{"file": "Sec.java", "line": 2, "quote": "allowed()"}]}

    class Access(ScriptedLLM):
        def chat(self, messages, tools=None):
            r = super().chat(messages, tools)
            if self.usage.calls == 2:
                recorded.set()
            return r

    surface_msgs = []

    class Surface(ScriptedLLM):
        def chat(self, messages, tools=None):
            recorded.wait(5)
            time.sleep(0.05)  # let the access agent publish its result
            surface_msgs.append([m["content"] for m in messages if m["role"] == "user"])
            return super().chat(messages, tools)

    monkeypatch.setattr(pipeline, "LLM", ByRole(
        access=Access([("record_access_model", model), ("finish", {})]),
        surface=Surface([("list_dir", {}), ("list_dir", {}), ("finish", {"notes": "n"})])))
    m = pipeline.recon(AuditConfig(), tmp_path, tmp_path / "recon")
    assert m["access_model"]["principals"] == "anon < admin" and m["access_agent"]["finished"]
    assert any("access-control model is ready" in u and "anon < admin" in u for msgs in surface_msgs for u in msgs)


def test_generic_handlers_are_reviewed_per_resource():
    from app.services.yasa_audit.pipeline import SPLIT_ROUTES, _resource_key, _units

    assert _resource_key("/apis/g/v1/posts/{name}/status") == "/apis/g/v1/posts"
    assert _resource_key("/V1/carts/:cartId/items") == "/V1/carts"
    entries, n = [], 0
    for res, exp in (("posts", "public"), ("users", "privileged"), ("menus", "privileged")):
        for verb, h in (("GET", "Get"), ("PUT", "Update"), ("DELETE", "Delete")):
            n += 1
            entries.append({"id": f"E{n}", "route": f"/apis/g/v1/{res}/{{name}}", "method": verb,
                            "handler_file": f"x/Extension{h}Handler.java", "handler": "handle",
                            "exposure": exp if verb == "GET" else "privileged"})
    entries += [dict(e, id=f"X{i}", route=e["route"].replace("/g/", f"/g{i}/"))
                for i in range(SPLIT_ROUTES) for e in entries[:3]]  # every generic handler > SPLIT_ROUTES
    entries.append({"id": "S1", "route": "/login", "handler_file": "Login.java", "handler": "login",
                    "exposure": "public"})
    units = _units(entries)
    posts = next(u for u in units if u["entries"][0]["route"] == "/apis/g/v1/posts/{name}")
    assert posts["generic"] and len(posts["entries"]) == 3 and len(posts["handlers"]) == 3
    assert posts["exposure"] == "public"
    users = next(u for u in units if u["entries"][0]["route"] == "/apis/g/v1/users/{name}")
    assert users["exposure"] == "privileged"  # not dragged to public by the posts routes
    assert not next(u for u in units if u["entries"][0]["id"] == "S1")["generic"]
