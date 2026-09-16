# Actual client compatibility smoke result

The installed Codex and Claude Code CLIs were launched against the compiled `dist/src/mcp.js` service with temporary invocation-only MCP settings and separate empty scan stores. The prompt requested exactly one `list_scans` call, followed by a short result marker. No target application, credentials or scan creation were involved. Global MCP settings and plugin marketplaces were not modified.

| Client | Observed compatibility | Result and remaining acceptance |
| --- | --- | --- |
| Codex CLI **0.146.0** | The client discovered `security_scan_smoke.list_scans` and emitted an MCP tool-call event with `{}` arguments. | The tool event ended `failed` with `user cancelled MCP tool call`; no scan list was returned. A successful tool call still requires a client session in which that read-only operation is approved. |
| Claude Code **2.1.238** | Startup reported the MCP server `connected` and advertised all **20** scanner tools. | The model request ended `authentication_failed` with `Not logged in · Please run /login`. MCP connection/tool discovery succeeded; actual invocation remains unverified in an authenticated Claude session. |

Codex's initial attempt inside the task filesystem sandbox could not initialize its native app-server/state database. The authorized retry outside that outer sandbox reached the MCP call described above. This was a client startup constraint; it did not indicate an MCP protocol failure.

Each client invocation had a 60-second process timeout. Claude additionally had a USD 0.25 request budget and reported zero API cost because authentication failed. The prompts prohibited other tools and scan creation. No approval bypass or automatic login was attempted after these results.

These checks establish actual-client startup/discovery evidence, not successful end-to-end scan acceptance. The separate automated stdio integration tests exercise protocol calls. Complete the two-client fixture workflow in `plugins.md` to establish authenticated browser exploration and real report generation through each client.

## Packaged Claude plugin (0.5.0)

The complete repository-root plugin was validated with Claude CLI, added as a local marketplace and installed into an isolated Claude configuration directory. The installed cache entry reported FlowAudit 0.5.0 enabled with its bundled MCP configuration. This test did not change the user's normal Claude settings.

The installed cached launcher was then exercised through the real stdio MCP SDK from an unrelated working directory with an empty private runtime home. It installed dependencies, built, discovered the onboarding/setup tools, created an anonymous fixture profile, opened Chromium, saved a real screenshot and exported an offline HTML report. A second connection reused the runtime and read the persisted scan. The repeatable command is `node --import tsx scripts/smoke-plugin.ts <installed-plugin-root>`.

Browser integration tests separately exercised manual-login session capture against the fixture, rejection of an anonymous probe marker, private-file permissions, replay of the captured profile, cancellation and external-redirect blocking. The OTP step remains user-driven; these tests do not claim integration with a particular OTP provider.

The dedicated Docker ZAP setup was started, its API authenticated successfully on loopback port 18091, and its configuration attached to a passive project. The test removed only its own Docker project afterward. This verifies setup, not a full ZAP scan against an arbitrary user application.

Full model-directed exploration from an authenticated Claude conversation remains distinct from these packaging, protocol and browser checks; the earlier model authentication limitation still applies.
