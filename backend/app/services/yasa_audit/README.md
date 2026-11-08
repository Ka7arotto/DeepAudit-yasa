# yasa_audit: entry-first audit

Two stages under one wall-clock budget (default 30 minutes):

1. **recon** — an agent maps the attack surface of the project.
2. **review** — every entry point is reviewed in its own fresh context.

There is no per-framework code, no routing DSL and no sink list. Project knowledge lives in what the
agents write (extractor programs, entry cards, verified facts), and correctness comes from checks that
do not depend on the framework.

## recon

The agent starts from the directory layout, codegraph's route evidence and the navigation tools
(yasa-mcp: functions, callers, call graph, symbol search; answered from codegraph until YASA's call
graph is built). It works out where requests come in and how the dispatch chooses the code to run,
for every dispatcher the project has (pages, REST, GraphQL, admin area, ...).

It then writes a small **extractor program** per dispatcher and runs it with `run_extractor`. The
program applies the mapping it found (code, config, naming conventions, schemas, DI bindings — whatever
this project uses) to the whole tree and prints entries:

```json
{"route": "/V1/carts/:cartId", "method": "GET", "handler_file": "app/.../CartRepository.php",
 "handler": "get", "kind": "rest", "auth": "resource Magento_Cart::manage",
 "exposure": "privileged", "declared_at": "app/.../etc/webapi.xml:40"}
```

Three checks are returned to the agent after each run, and it fixes the extractor when one fails:

| Check | What it catches |
| --- | --- |
| handler resolves to a file that contains the handler | interfaces, wrong paths, name-only guesses |
| random samples the agent must read back | a mapping that is plausible but wrong |
| `check_coverage`: code that reads request data, not reachable from any entry | dispatchers or areas not covered yet |

If the agent produces nothing usable, codegraph's own routes are used so the review can start.
Output: `recon/entries.json`, `recon/recon.json` (counts, coverage, the agent's notes on each
dispatcher), `recon/extractors/*.py`.

## review

Entries that run the same handler form one unit; units are ordered public → unknown → authenticated →
privileged. Each unit gets the entry, similar entries for comparison (peers), the handler's code and the
verified facts so far. The reviewer:

1. understands the scenario: what it does, who can call it, inputs, data touched, values it stores;
2. judges access control (missing authentication / authorization, object-level authorization);
3. lists the risks plausible for *this* function (it stores a file, fetches a URL, builds a query,
   renders data, loads an object by id, ...);
4. traces each risk with the navigation tools to a confirmed path or a rejection with evidence;
5. records a card, reports findings (with `required_privilege`), and shares facts.

Facts are accepted only when each quote is found at the cited file:line, so later reviewers can rely on
them instead of re-deriving the same framework behaviour. The system prompt is identical for every unit
(facts and the entry go in the user message), which keeps the provider's prefix cache effective.

There is no re-review stage. Output: `review/findings.json` (with `not_reviewed` entry ids when the
budget runs out), `review/cards.json`, `review/facts.json`, `metrics.json` (tokens, cached tokens,
reasoning tokens, wall time).

## Usage

```bash
bash backend/scripts/setup_yasa.sh        # yasa-mcp bundle + codegraph + ripgrep into ~/.yasamcp
export LLM_BASE_URL=... LLM_API_KEY=... LLM_MODEL=...   # OpenAI-compatible with tool calling
cd backend
uv run python -m app.services.yasa_audit init  /path/to/project            # navigation index
uv run python -m app.services.yasa_audit recon /path/to/project --out out/ # surface only
uv run python -m app.services.yasa_audit run   /path/to/project --out out/ \
       --deploy "Linux, nginx, PHP 8.3" \
       --product "Roles: guest, customer, admin. Public by design: catalog, login. CLI input is trusted."
```

`run` reuses `out/recon/entries.json` when it exists. In DeepAudit, the "YASA" task mode runs the same
`run` after the navigation index is ready; `product` and `deploy` come from the task's `audit_scope`.

## Not in this version

Automatic YASA taint rules (sources, sinks, sanitizers) and engine runs. The earlier rule-building,
residual-sink and grouped-triage pipeline is in git history (before `feat/entry-first-review`).
