# yasa_audit: entry-first audit, with sensitive operations and identity design

Three stages under one wall-clock budget (default 30 minutes):

1. **recon** — agents map the attack surface, the access-control model and what is worth protecting
   (sensitive operations, identity subsystems).
2. **review** — every entry point, every sensitive operation outside a handler and every identity
   subsystem is reviewed in its own fresh context.
3. **verify** — every reported root cause gets a sceptical agent that tries to refute it.

There is no per-framework code, no routing DSL and no sink list. Project knowledge lives in what the
agents write (extractor programs, entry cards, verified facts), and correctness comes from checks that
do not depend on the framework.

## recon

The agent starts from the directory layout, codegraph's route evidence and the navigation tools
(functions, callers, call graph, symbol search; answered from codegraph's index by `graph.py`). It works out where requests come in and how the dispatch chooses the code to run,
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

## Sensitive operations and identity subsystems (`assets.py`)

Starting only from entries misses three kinds of flaw. The first is code that no route reaches
directly: render pipelines, hooks, and extension points with no caller in the repository. The second is
a value that is sanitized at the entry and transformed again by another component. The third is the
design of a module, such as how a login binds an external identity, which no single route shows. A
third recon agent, running in parallel with the other two, maps the other end of the flow.

**Operations.** The classes are fixed, describe effects rather than frameworks, and never change per
project:

| Class | The operation |
| --- | --- |
| `credential_or_privilege_write` | sets a password, credential, token, role, group or permission |
| `personal_data_output` | puts email, IP, password hash, token, ... into something others read |
| `object_by_request_id` | loads, changes or deletes an object chosen by a request id |
| `outbound_request` | the server fetches a URL or connects to a host |
| `raw_markup_output` | data written into HTML or an attribute without the project's escaping |
| `state_change_in_read_path` | persistent state changed by a GET, a permission callback, a renderer |
| `file_write` | writes, moves, extracts or deletes a file |

How *this* project performs each class is found from evidence, not from a rule list:

- the sensitive fields of its data model;
- the guards the project applies itself (a permission or ownership check, an escaping call, an
  allowlist), which show what it treats as sensitive;
- the helpers that codegraph navigation leads to.

The agent writes each form as a declarative **recipe**:

```json
{"name": "role-write", "op_class": "credential_or_privilege_write", "pattern": "->role\\s*=",
 "guard": "requireAdmin\\(|->can\\(", "why": "users.role, set by Users::actionSave (app/Users.php:5)"}
```

`run_recipe` expands a recipe over the whole project (tests and vendored code left out). It places
every site in codegraph's call graph, following calls through interfaces and parent methods, and returns
counters the agent refines the recipe on, just as it refines an extractor on coverage:

| Counter | Meaning |
| --- | --- |
| `handler` | the site is in an entry's handler |
| `entry` | an enumerated entry reaches the site through calls |
| `no_callers` | nothing in the repository calls the site: a framework hook, an extension point, a public API, or dead code |
| `internal` | something calls the site, but no enumerated entry reaches it |
| `guarded` / `unguarded` | whether the guard pattern appears in the operation's function before it, or in a caller within three calls |

The agent can finish only when each class has a recipe or has been declared absent (`class_absent`,
with what it searched).

**Identity subsystems.** The same agent records registration, login, recovery, SSO, tokens, account
linking, invitations, MFA, sessions and user management with `record_identity`. Each subsystem carries
its route patterns, files, models and settings (defaults with `file:line`).

Once the entries are final, the recipes are expanded again against them, and the subsystems are joined
to their entries and sites. Output: `recon/assets.json`.

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

There is no re-review stage.

### Three kinds of unit

| Kind | Unit | Starts from | Question |
| --- | --- | --- | --- |
| entry | entries sharing one handler | the route, forward | is this entry vulnerable? |
| operation | a function performing sensitive operations outside every handler | the operation, backward | can anyone make it happen with values they control? |
| design | one identity subsystem (at most `design_units_max`) | routes, models and settings together | does the design hold? |

- **Operation units.** A site inside a handler is not a unit of its own: it is listed in that entry's
  unit ("sensitive operations in this handler"), so the code is reviewed once. Every other site is
  grouped by function. The reviewer works backward through the entries listed and through paths the
  index cannot see (hooks, events, render pipelines, jobs). It is shown sibling sites of the same recipe
  where the project's guard is on the way: a check the siblings make and this path does not is the
  most likely flaw. When nothing calls the code, the threat model is a plugin or integration written
  the way the project's documentation shows. Units are ordered by the exposure of the entries that
  reach them, with unguarded and caller-less sites first. If an entry reviewer has already anchored a
  hypothesis at the same `file:line`, the operation unit is skipped and the result is shared.
- **Design units.** The reviewer answers a fixed checklist with `record_design` and cannot finish until
  every item is answered:
  - identity binding;
  - claiming of existing records (inactive, guest, pending);
  - token lifecycle (expiry, single use, hashing, constant-time comparison, revocation);
  - defaults;
  - privilege ceiling (granting or reaching more than one holds).

  Each answer has a status:
  - `sound`, `flaw` and `owner_decision` need quoted evidence;
  - `unclear` and `not_applicable` do not.

  A flaw that has been traced to its harm is also reported as a finding, with its preconditions in the
  impact.

The schedule puts design units first, because they are few and nothing else covers them. Entry units
follow, and operation units take every `operation_every`-th slot, so neither kind waits for the other to
be used up. All units share facts, root causes and anchors. Each finding carries `unit_kind`.

Output:
- `review/findings.json`:
  - `findings`;
  - `open_leads`;
  - `design_worksheet`: per subsystem, every checklist item with its status, answer and evidence. This is
    what a human reviews for defaults and design trade-offs.
  - `not_reviewed`, `not_reviewed_operations` and `not_reviewed_design`, when the budget runs out.
- `review/cards.json`, `review/facts.json`.
- `metrics.json`: units of each kind, tokens, cached tokens, reasoning tokens, wall time.

## Usage

```bash
bash backend/scripts/setup_yasa.sh        # codegraph + ripgrep into ~/.yasamcp/tools
export LLM_BASE_URL=... LLM_API_KEY=... LLM_MODEL=...   # OpenAI-compatible with tool calling
cd backend
uv run python -m app.services.yasa_audit init  /path/to/project            # codegraph index
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

## Code index

`codegraph` (tree-sitter, many languages) indexes the project in seconds to a minute: calls,
inheritance, containment and the routes of common frameworks. `graph.py` answers the navigation tools
from it with read-only SQL. Calls to an interface or abstract method are followed to the
implementations, callers of an implementation include calls through its interface, and a call on
`this` / `self` / `super` / `parent` is resolved in the caller's own class hierarchy (a parent named by
its short name is taken from the file's imports). Calls whose receiver type is not visible statically
may still be missing or attributed to a same-named function, so agents treat the index as navigation
and the code as the evidence.

The YASA engine's index is no longer built: on PHP it resolved 3% of the calls codegraph resolves
(inherited methods were missing), on TypeScript it produced nothing after ten minutes, and on Java it
was not better than codegraph plus the implementation step above, while costing 1-10 minutes per run.
