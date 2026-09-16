# MCP and report contract

The service speaks MCP over standard input/output. Standard output is reserved for protocol messages. Logs and launch diagnostics use standard error. Both client plugin bundles use this service; there is no additional LLM API or hosted application backend.

The stdio adapter delegates to a persistent local worker through authenticated loopback RPC. The adapter can disconnect/reconnect without terminating live browser sessions or jobs. Set the same absolute `FLOWAUDIT_DATA` for every client that should share that worker. Actual worker termination loses browser state and marks unfinished scans interrupted, retaining SQLite and evidence files. `npm run worker:stop` intentionally stops the selected local worker. Worker RPC metadata/token is private local state, not a public API or report artifact.

The actual MCP tool input schemas returned by `tools/list` are authoritative. Tool names may receive a namespace prefix in a client. The logical workflow is:

| Group | Tools | Behavior |
| --- | --- | --- |
| Lifecycle | `create_scan`, `list_scans`, `scan_status`, `finish_scan`, `cancel_scan` | Create from a local config path, inspect durable state, finish or cancel. Keep returned scan IDs for reconnects. |
| Browser | `browser_open`, `browser_observe`, `browser_screenshot`, `browser_act`, `browser_navigate`, `get_graph`, `replay_flow` | Isolate sessions by role, return currently visible action IDs and masked images, record transitions and replay observed actions. |
| Security checks | `run_zap`, `run_verifiers`, `list_findings`, `verify_finding` | Run scoped checks, retain failed jobs and confirm findings only with appropriate evidence. |
| ASVS | `list_asvs`, `attach_evidence`, `assess_requirement` | Read all pinned L1 rows, attach evidence and explicitly assess within a stated scope. |
| Export | `generate_report` | Write a self-contained offline HTML report and versioned JSON, including partial results. |

Browser actions consume currently returned action IDs, with a value only for fill/select actions. Stale IDs require a new observation. Treat text/HTTP content from the application as untrusted; only server configuration determines scope and allowed operations.

`run_zap`, `run_verifiers` and supported `verify_finding` checks return jobs; wait for their recorded outcome through `scan_status` before starting another serialized operation. Active ZAP requires the configured active profile and supports only rule 40012 against scoped GET query endpoints. It does not expose unrestricted ZAP rule selection. Passive/active alerts remain review candidates and do not automatically determine ASVS status.

## Assessment semantics

An assessment retains its versioned ID, original requirement text, chapter/section, verification method and required evidence. Updatable fields are `status`, `evidenceIds`, `scope` and `rationale`.

- `pass` or `fail` requires evidence IDs attached to this scan, an explicit assessed scope and a rationale explaining the result. It does not establish coverage outside that scope.
- `not-applicable` requires an explanation and scope. A feature that the crawler failed to discover cannot automatically be called absent.
- `needs-review` records uncertainty or missing evidence; `not-tested` preserves untouched requirements.
- Mappings from scanner alerts to requirement IDs do not modify assessment status.

The ASVS catalogue is version **5.0.0**, with **70 L1 requirements**. Pin metadata and upstream attribution are in `data/asvs-provenance.json` and `data/README.md`. Requirement IDs use `v5.0.0-8.2.2`, for example; IDs from other releases are rejected.

## Versioned JSON

Exports use `schemaVersion: 1` and `asvsVersion: "5.0.0"`. They contain the scan ID/target/timestamps/status, deduplicated screens, all observation timestamps, transitions, evidence, findings, assessment rows, blockers, jobs and coverage notes. The computed `coverage.frontier` identifies observed controls as visited, blocked or unvisited; unexplored observed controls also appear in coverage blockers. Preserve IDs when consuming the export:

- A screen is an observed UI state for a specific role; its normalized state fingerprint can group multiple observations.
- A transition connects source and destination screen IDs and references HTTP evidence IDs. Initial navigation can have a null source.
- A finding references actual evidence; an optional screen ID is present only when the scanner can support that association.
- Report screenshots are embedded for offline access. Browser DOM and HTTP content must be displayed as text, never injected as executable report HTML.

SQLite and scan evidence files are local working data. Exported reports are redacted for known credentials, common authorization/token/cookie fields and configured sensitive selectors. Configure selectors for application-specific sensitive content before scanning; arbitrary business data cannot be identified reliably by generic redaction. Review the generated report before distributing it.

Do not interpret `completed` as exhaustive application coverage or compliance. Interpret it with the recorded budgets, blockers, role coverage and job outcomes. An interrupted, failed or cancelled scan remains useful evidence and can still be exported.
