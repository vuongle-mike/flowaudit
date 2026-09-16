# Actual client compatibility smoke result

The installed Codex and Claude Code CLIs were launched against the compiled `dist/src/mcp.js` service with temporary invocation-only MCP settings and separate empty scan stores. The prompt requested exactly one `list_scans` call, followed by a short result marker. No target application, credentials or scan creation were involved. Global MCP settings and plugin marketplaces were not modified.

| Client | Observed compatibility | Result and remaining acceptance |
| --- | --- | --- |
| Codex CLI **0.146.0** | The client discovered `security_scan_smoke.list_scans` and emitted an MCP tool-call event with `{}` arguments. | The tool event ended `failed` with `user cancelled MCP tool call`; no scan list was returned. A successful tool call still requires a client session in which that read-only operation is approved. |
| Claude Code **2.1.238** | Startup reported the MCP server `connected` and advertised all **20** scanner tools. | The model request ended `authentication_failed` with `Not logged in · Please run /login`. MCP connection/tool discovery succeeded; actual invocation remains unverified in an authenticated Claude session. |

Codex's initial attempt inside the task filesystem sandbox could not initialize its native app-server/state database. The authorized retry outside that outer sandbox reached the MCP call described above. This was a client startup constraint; it did not indicate an MCP protocol failure.

Each client invocation had a 60-second process timeout. Claude additionally had a USD 0.25 request budget and reported zero API cost because authentication failed. The prompts prohibited other tools and scan creation. No approval bypass or automatic login was attempted after these results.

These checks establish actual-client startup/discovery evidence, not successful end-to-end scan acceptance. The separate automated stdio integration tests exercise protocol calls. Complete the two-client fixture workflow in `plugins.md` to establish authenticated browser exploration and real report generation through each client.
