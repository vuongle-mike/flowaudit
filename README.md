# FlowAudit

Local security scanner and plugin for **Codex and Claude Code**: browser discovery, screenshot flow graphs, authenticated OWASP ZAP checks, evidence-backed verification and the complete **70-requirement ASVS 5.0.0 L1 checklist**.

The three-command CLI handles the common path. The MCP integration remains available when Codex or Claude Code should make application-specific exploration and ASVS decisions. No additional model API key or hosted LLM service is required by the scanner.

## Install in Claude Code (recommended)

In Claude Code, run:

```text
/plugin marketplace add vuongle-mike/flowaudit
/plugin install flowaudit@flowaudit-marketplace
```

Start a new session, then ask:

```text
/flowaudit:flowaudit Scan http://localhost:9000. Open the login browser so I can complete OTP, then continue with a passive scan and an offline report.
```

The repository root is the complete Claude plugin. It includes its own MCP launcher and runtime source; no checkout path, npm command or hand-written profile is needed. Node.js 20.19+ and npm must already be available. First use downloads locked dependencies and Chromium and builds a private runtime. macOS and Linux are the supported bootstrap platforms; Linux may require Playwright system libraries and a graphical display for login. The initial download can exceed the client's MCP startup timeout; see [setup recovery](docs/plugins.md#setup-recovery).

`start_login` opens a real browser. Complete login/OTP there, then tell Claude you are done and provide a short non-secret protected-page label, such as “Invoices”. `finish_login` checks that the label is absent without authentication and saves the session locally. No Enter in a separate terminal is needed. Anonymous scans use `create_public_project` directly.

For ZAP checks, Claude calls `prepare_zap`, polls `setup_status`, then calls `enable_project_zap` before starting the scan. Docker must already be installed and running. This starts a dedicated ZAP container on `127.0.0.1:18091`; the browser/scanner stay on the host so interactive login works. A target resolvable only on the host may still need Docker DNS/network configuration. If ZAP cannot start, browser exploration remains available and ZAP checks must be reported as untested.

Profiles, session secrets, scan data and versioned runtimes live under `~/.local/share/flowaudit` (override with `FLOWAUDIT_HOME`). They are outside the plugin cache and survive plugin updates. New profiles are passive; active test workflows still need explicit scoped configuration. Cross-origin SSO and SPA authentication without a usable protected HTTP probe remain unsupported.

To update: `/plugin marketplace update flowaudit-marketplace`, then `/plugin update flowaudit@flowaudit-marketplace`, then start a new session. The bundles under `plugins/` are advanced adapters for separately managed scanner deployments.

## Scan another application

Install once from this directory:

```sh
npm ci
npx playwright install chromium
npm run build
npm link
```

Then create and run a passive project:

```sh
flowaudit init https://staging.example.com --name billing --roles user,admin
flowaudit run billing
flowaudit report billing --open
```

`init` opens a normal Chromium window for each role. Log in, including MFA if needed, return to the terminal and press Enter. The captured browser state stays in the git-ignored `projects/billing/secrets.json`; it is never put in a prompt or report. Use `--public` for a site without login. Use `--active` only for an application that is explicitly approved for active testing.

`run` starts/builds the local scanner and ZAP containers, explores the visible UI, runs the selected ZAP profile and creates an offline report. Docker must be running, and the target URL must be reachable from Docker. Prefer a test or staging URL. The default profile blocks logout, delete, payment, checkout and all unapproved mutation requests.

For a long, high-coverage staging campaign, add an explicit deep profile:

```json
{
  "mode": "active",
  "allowedActions": ["/test-records/save"],
  "tests": {
    "activeScan": {
      "role": "admin",
      "profile": "deep",
      "attackStrength": "MEDIUM",
      "scannerIds": [],
      "methods": ["GET", "POST"],
      "includePathEndpoints": true,
      "maxEndpoints": 1000,
      "discoveryPaths": ["/.git/config", "/.env", "/composer.lock"]
    }
  }
}
```

An empty `scannerIds` uses the built-in injection-oriented deep set. The scanner intersects it with the rules installed in the dedicated ZAP instance. It does not enable denial-of-service or brute-force scanners. Each POST candidate must come from observed traffic and match an exact path in `allowedActions`; use resettable test data because active payloads can create or alter records.

Without `npm link`, use the equivalent project-local form:

```sh
npm run scan -- init https://staging.example.com --name billing --roles user,admin
npm run scan -- run billing
npm run scan -- report billing --open
```

The generated `projects/billing/project.json` is the advanced configuration. Edit it only when you need narrower scope, approved mutation endpoints, business authorization rules, custom limits or additional sensitive selectors. A captured session can expire; rerun `init` with the same options and `--force` to recapture it.

To test a public login form with a small, explicit POST budget:

```sh
flowaudit init https://staging.example.com \
  --name billing-login \
  --public \
  --login-test /authenticate \
  --login-path /login \
  --username-field email \
  --password-field password \
  --csrf-field _token \
  --max-login-attempts 5

flowaudit run billing-login
```

`--login-test` enables active mode for that exact POST endpoint. The verifier sends one unique invalid baseline, two SQL tautology cases, one XSS execution marker and one template expression. It refreshes the login page and CSRF state before every request and does not guess real usernames or passwords. Supply `--success-path` and `--success-contains` when a successful authentication has a stable protected marker; otherwise response differences remain `needs-review` rather than being called an authentication bypass.

## Local acceptance demo

### Public file and debug disclosure checks

Add `--public-checks` to `init --public --login-test /authenticate` to enable a bounded file check and header/parameter-type mutations of the configured login form. `--public-checks` alone checks only `/.gitignore`. Existing projects can add this under `tests` in `project.json`:

```json
"publicSurface": {
  "role": "anonymous",
  "files": ["/.gitignore"],
  "maxRequests": 30,
  "forms": [
    {"pagePath":"/login","submitPath":"/authenticate","fields":["email","password"],"headerMutation":true},
    {"pagePath":"/forgot-password","submitPath":"/forgot-password","fields":["email"],"headerMutation":false}
  ]
}
```

Set `mode` to `active`. Each form is an explicit POST allowlist entry and must match the real form action. Only URL-encoded forms are supported by these checks. Hidden values and cookies are refreshed per request; normal input uses unique addresses under `example.invalid` and invalid test passwords. Recovery submissions must be appropriate for the target test environment. Redirects are recorded but never followed by the mutation transport. The request budget includes form refresh navigations, excludes their subresources, and is bounded additionally by the global scan budgets.

File detection compares recognizable non-HTML content against a random missing path and repeats positive candidates. Debug detection requires stack trace plus source-file/line evidence, reads up to 2 MB, and retains a bounded debug excerpt without framework request/environment dumps. Positive mutations are repeated with fresh CSRF; blocked/truncated results remain inconclusive. An error page is not automatically SQL injection or authentication bypass. Debug error handling is ASVS 5.0 L2, so these findings do not invent a mapping to the L1 checklist.

Run the same CLI `flowaudit run <project>` or MCP `run_verifiers`. The local fixture has `/public-form` → `/public-submit` and `/.gitignore` for vulnerable/fixed acceptance, tested with `node --import tsx --test test/public-checks.test.ts`.

### Screenshots and finding flow

Public form tests now send the POST through a real Chromium navigation. A positive confirmation is photographed from the server response as rendered in that browser, using its original HTML and allowed in-scope resources. The transport does not use `setContent`, `route.fulfill`, or HTML reconstruction. Sensitive fields are masked before saving the viewport screenshot.

Report export embeds existing screenshots only. Findings show the source form and **Live server response screenshot**; **Trace path in screen flow** connects them to the verification HTTP evidence. Each capture records the response URL, status, timestamp and SHA-256. Click images to enlarge. Same-screen actions remain available in screen details; verification edges require `run_verifiers` with fresh tokens rather than replay as UI clicks.

Redirects, popups, WebSockets, non-allowlisted requests and out-of-scope assets are blocked. Resource loading is bounded to 32 requests per browser response and the global budgets. A download, redirect, unrenderable response or capture failure has no screenshot; HTTP evidence remains available. The file check uses HTTP transport, so no application screen is invented for `/.gitignore`.

Legacy generated response previews are removed during re-export. Re-export never creates an image from stored response text. Real screenshots for older scans require running the test again.

### Invoice acceptance demo

Requires Node 20.19+ and npm. Run from this directory:

```sh
npm ci
npx playwright install chromium
npm run build
npm run init:demo
npm run doctor
npm run demo
```

`demo` launches isolated vulnerable and fixed invoice fixtures, records three roles, verifies four scenarios and writes HTML/JSON reports under `demo-results/<mode>/runs/<scan-id>/report/`. It uses browser verifiers without ZAP by default. The simple CLI and client skill provide autonomous discovery; this repeatable acceptance command follows a fixed fixture flow.

Expected browser verification results:

| Scenario                    | Vulnerable fixture | Fixed fixture  |
| --------------------------- | ------------------ | -------------- |
| Reflected XSS execution     | confirmed          | not-reproduced |
| Cross-tenant invoice access | confirmed          | not-reproduced |
| User accessing admin data   | confirmed          | not-reproduced |
| Old session after logout    | confirmed          | not-reproduced |

Non-reproduction never automatically becomes an ASVS pass. Other requirements remain in the checklist awaiting evidence or review.

To exercise the same three-command path against the vulnerable Compose fixture:

```sh
npm run init:demo
npm run scan -- run demo
npm run scan -- report demo --open
```

To operate the fixture interactively, keep it running in a terminal:

```sh
PORT=13000 npm run fixture
```

Use `examples/local.json` when creating a scan. Demo credentials are generated in `.secrets/demo.json`. The fixture exists for local test data only.

## Docker Compose with ZAP

Requires Docker Compose. The initializer preserves existing configuration and secrets.

```sh
npm run init:demo
docker compose up --build -d --wait
node --import tsx scripts/smoke-docker.ts
```

Compose starts scanner, ZAP and the fixture. The fixture UI is at `http://127.0.0.1:13000`; the scanner reaches it at `http://fixture:3000`. ZAP's control API is kept inside the Compose network, protected by the generated `.env` API key. Scanner results are persisted to `scan-data/` on the host.

Use `/app/examples/docker.json` as `create_scan.configPath` from the Docker MCP service. Returned `/data/...` report paths correspond to `scan-data/...` on the host. The smoke script exercises the real stdio MCP, browser, authenticated ZAP and verifier workflows and prints report locations.

To run the fixed fixture after completing a scan:

```sh
FIXTURE_MODE=fixed docker compose up -d fixture
```

Each new scan initializes a fresh unsaved session in its **dedicated** ZAP instance before recording browser traffic. Do not point the adapter at a shared/manual ZAP instance. Initialization clears that instance's scan history to prevent old alert deduplication from hiding new results.

Stop the services without deleting artifacts:

```sh
docker compose down
```

## Connect the clients

See [plugin installation](docs/plugins.md) for the two bundles and invocation-specific configuration.

```sh
export FLOWAUDIT_ROOT="$PWD"
export FLOWAUDIT_RUNTIME=local  # use docker for the Compose service
npm run mcp
```

`npm run mcp` speaks JSON-RPC over stdio; it is normally launched by the client, not interacted with as a text terminal. The first local invocation starts a private loopback worker. Client disconnect/reconnect retains live browser sessions and jobs. Set `FLOWAUDIT_DATA` to choose the local store, default `.runs`. Stop a local worker with `npm run worker:stop`; active scans then remain readable as interrupted.

The plugin skill asks the client to create a scan, authenticate roles, explore unvisited actions, inspect blockers, run jobs, review evidence and export a report. Target-page text is treated as untrusted input, never as instructions to access files or broaden scope.

## Configuration and supported checks

Most projects should start with `flowaudit init`. The generated file uses a captured `storageState` authentication profile. `examples/local.json` and `examples/docker.json` show advanced form authentication, explicit verifier rules and the acceptance fixture.

- Scope checks run at request dispatch and before following redirects. Off-origin login/SSO is outside the single-origin MVP.
- Captured browser-state, form, cookie and bearer authentication require a protected probe URL and a positive authenticated-content marker. The CLI lets a user complete MFA/CAPTCHA in the capture browser.
- Defaults are 100 states per role, 300 actions, 30 minutes and 5 requests/second. The demo raises throughput only in its ephemeral test config.
- Passive mode is the default for new configurations. Active mode must be explicitly enabled; demo configurations enable it for their local fixtures.
- ZAP active scanning provides the `xss` profile for **rule 40012 on GET query endpoints**. An explicit `tests.activeScan.profile: "deep"` enables a broader interpreter-focused rule set, path-only endpoints, request-shape deduplication, configurable discovery paths and observed POST bodies. POST remains unavailable unless both `methods` includes `POST` and the exact path is present in `allowedActions`.
- A configured `tests.login` workflow separately submits 2-10 bounded POST cases to one exact login endpoint, refreshes CSRF state, compares them with an invalid baseline and records SQL error, authentication and XSS evidence. It does not perform password brute force.
- Authorization checks need explicitly configured owner/attacker roles, a discovery selector and a protected-content marker. The scanner does not infer authorization from HTTP 200 alone.
- Logout/session verification is a separate workflow. General exploration blocks logout, payment, delete and other sensitive actions. Permitted mutations require exact endpoint paths in `allowedActions`.
- Credentials, learned tokens and sensitive-selector text are redacted from evidence; screenshots mask inputs and configured sensitive elements. Use test data and select additional private fields for your application.

See [architecture and limitations](docs/architecture.md) and [MCP interface](docs/protocol.md) for detail. Browser discovery currently targets the main document; popups, frames, shadow-only controls, canvas interaction and file uploads do not have full exploration support. Report coverage includes discovered actions that were not attempted, blocked branches, budget limits and jobs.

## Report and ASVS

The HTML report embeds React, the graph renderer, screenshots and data. It opens offline with no CDN or API. Select a screenshot node, transition or finding to inspect evidence; filter by role and highlight a recorded route to a finding. The ASVS checklist is searchable and filterable. The companion JSON uses schema version 1.

Every assessment preserves a versioned requirement ID, source text, evidence, scope and rationale. Pass/fail requires evidence; not-applicable requires an explanation. Requirements that need architecture, source or configuration review are retained. The report never assigns ASVS compliance based on an absence of alerts.

Official source and license are pinned under `data/`, with original and canonical SHA-256 in the provenance record. ASVS content is CC BY-SA 4.0; see `data/ASVS-LICENSE.md`.

## Validation

```sh
npm run typecheck
npm test
```

Browser integration tests run when the installed Chromium executable is available; the test output explicitly marks missing-browser skips. To require the dedicated live ZAP test, start a separate ZAP instance on port 18090 with `api.filexfer=true`, Graal.js, API host `zap` and key supplied through `ZAP_TEST_KEY`, then run:

```sh
ZAP_INTEGRATION=1 ZAP_TEST_KEY='<local-key>' npm test
```

`ZAP_TEST_API` and `ZAP_TEST_PROXY` override the default `http://127.0.0.1:18090`. The live fixture test uses `host.docker.internal` to let Docker ZAP reach the host's temporary fixture.

Automated tests cover the stdio MCP worker, reconnect, browser state grouping, replay, credentials, scope, cancellation, ASVS integrity/assessment validation, offline report rendering and the live ZAP guard. Docker Compose is exercised separately by `scripts/smoke-docker.ts`.

Actual client startup/discovery was checked, but full workflow execution inside both signed-in clients remains unverified: Codex's tool call was cancelled by the client, and Claude Code lacked usable authentication. See [recorded client smoke results](docs/client-smoke.md). These are distinct from the passing automated MCP integration.

## Troubleshooting

- **Chromium missing:** run `npx playwright install chromium`; Linux also needs `npx playwright install --with-deps chromium`. `CHROMIUM_PATH` can select an installed executable.
- **Another worker owns store:** reconnect to the existing worker. Use `npm run worker:stop` for the same `FLOWAUDIT_DATA`; do not delete a live lock.
- **Authentication failed:** check the profile selectors, secret reference and authenticated probe. A failed role can be reopened after fixing credentials in a new scan.
- **ZAP guard upload unavailable:** use the provided dedicated Compose service with `api.filexfer=true` and Graal.js. The adapter stops rather than scanning without its guard.
- **Container path in report result:** map `/data/<id>/...` to `scan-data/<id>/...` on the host.
- **Interrupted scan:** inspect/export its partial results, then start a fresh scan. Browser sessions survive client reconnect, but not a worker/process crash.
