# Use FlowAudit in Codex or Claude Code

Both bundles use the same MCP service and byte-identical exploration skill. They require a local scanner checkout, Node.js 20.19 or newer for local mode, and Docker Compose for the full ZAP stack. Installing a bundle does not install Docker, download browsers, start containers or register credentials.

Create the target project first with the root README's simple flow:

```sh
flowaudit init https://staging.example.com --name billing --roles user,admin
```

This creates `projects/billing/project.json` and captures each authenticated browser session locally. The CLI can complete the entire scan with `flowaudit run billing`; install a client bundle when you want Codex or Claude Code to choose application-specific MCP actions and assess additional ASVS evidence.

From the scanner project directory, set a durable absolute location and start the services using the root README:

```sh
export FLOWAUDIT_ROOT="$PWD"
export FLOWAUDIT_RUNTIME=docker
npm run init:demo
docker compose up -d --build
```

Wait for healthy scanner/ZAP services. The plugin launches `sh "$FLOWAUDIT_ROOT/plugins/mcp-launch.sh"`. Docker mode calls `docker compose --project-directory "$FLOWAUDIT_ROOT" exec -T scanner node dist/src/mcp.js`, so it is independent of the client's working directory. Keep the project at that location. Use `/projects/billing/project.json` for the project above; the acceptance fixture remains at `/app/examples/docker.json`. State/reports under `/data` are mounted at `scan-data/` on the host.

For development without Docker, first install/build the project and install Playwright Chromium as described in the root README, then set `FLOWAUDIT_RUNTIME=local` and `FLOWAUDIT_DATA` to an absolute state-directory path (default is the project's `.runs`). Start the fixture with `PORT=13000 npm run fixture` and use the absolute path to `examples/local.json`. This local example omits ZAP; ZAP checks require a separate reachable configured instance.

The stdio adapter attaches to a persistent local worker. Reconnecting the client with the same state directory resumes access to that worker's live scans and browser sessions. A worker crash or intentional `npm run worker:stop` interrupts unfinished scans; retained evidence can still be read/exported, but lost browser sessions require a fresh scan. A worker keeps its launch environment until restarted.

## Codex bundle

The bundle is `plugins/codex/flowaudit`. It has the supported `.codex-plugin/plugin.json` compatibility manifest, `.mcp.json` and `skills/flowaudit/SKILL.md`. To install it into your personal plugin collection, use the built-in plugin-creator in Codex with this request, replacing the path with your checkout:

> Register the existing plugin at /absolute/path/flowaudit/plugins/codex/flowaudit in my personal marketplace. Preserve the existing manifest, MCP configuration and skill content. Do not publish it.

Then install **FlowAudit** from that local source in the app's plugin directory and start a new task. This repository does not modify your personal marketplace or existing Codex settings automatically. OpenAI documents the compatibility layout and local marketplace workflow in [Package your plugin](https://developers.openai.com/plugins/build/plugins).

The client must supply `FLOWAUDIT_ROOT` to its MCP process. For a client launched from a terminal, export it before launch. For a GUI whose environment does not inherit your shell, add a non-secret `env` object inside the bundle's `mcpServers.flowaudit` configuration before installing, with `FLOWAUDIT_ROOT` set to the absolute checkout path and `FLOWAUDIT_RUNTIME` set to `docker` or `local`. Keep credentials in the scanner's secret file, outside this configuration.

You can also test the shared service directly, independently of plugin installation:

```sh
codex mcp add flowaudit --env FLOWAUDIT_ROOT="$FLOWAUDIT_ROOT" --env FLOWAUDIT_RUNTIME="$FLOWAUDIT_RUNTIME" -- sh "$FLOWAUDIT_ROOT/plugins/mcp-launch.sh"
codex mcp list
```

For a custom local state directory, additionally pass `--env FLOWAUDIT_DATA=/absolute/path/to/state` when registering the server. Docker uses the Compose service's `/data` setting regardless of the host's local state setting.

Restart the client and inspect `/mcp`. A direct MCP connection tests the tools; to test the full bundle also load the bundled skill using the plugin installation above. Avoid simultaneously enabling both registrations of the same server. [Codex MCP configuration](https://developers.openai.com/codex/mcp) documents the CLI and app settings.

## Claude Code bundle

Start a local session with the complete plugin directory:

```sh
claude --plugin-dir "$FLOWAUDIT_ROOT/plugins/claude/flowaudit"
```

Inspect `/mcp` for the plugin's `flowaudit` server and use `/flowaudit:flowaudit` to invoke its skill. The MCP tools are client-namespaced but retain the underlying names described in `docs/protocol.md`. The `.claude-plugin/plugin.json` manifest and plugin-root `.mcp.json` follow [Claude Code's plugin reference](https://code.claude.com/docs/en/plugins-reference). A `--plugin-dir` registration lasts for the current session; distributing through a Claude marketplace is optional and separate.

## End-to-end client acceptance

Run this workflow once in each actual client, sequentially. The process must have access to the same scanner state directory. Do not run the two clients' browser scans simultaneously.

1. Ask the client to use the bundled skill to scan the configured invoice fixture, starting from the config path and role names only. Secrets are read by the MCP server.
2. Confirm it invokes `create_scan`, authenticates with `browser_open`, chooses returned action IDs, discovers reachable detail/modal/tab/admin screens for the relevant roles, and reads `get_graph`.
3. On the Docker fixture's active profile, run `run_zap` and `run_verifiers`, polling `scan_status` until each job finishes before starting the next. Active ZAP tests reflected XSS rule 40012 on scoped GET query endpoints. Inspect evidence and review ASVS results; keep missing source/configuration evidence visible.
4. Call `finish_scan` and `generate_report`; open the HTML offline and confirm role filters, screen screenshots, action evidence and findings work.
5. Repeat against the fixed fixture. The four fixture verifier cases should no longer be confirmed. This is not a claim that the fixed fixture satisfies all ASVS requirements.

The automated MCP protocol test verifies tool discovery/calls over stdio and preservation of browser sessions across a client reconnect. Actual-client acceptance remains incomplete: the recorded Codex CLI attempt ended with tool cancellation; Claude Code connected but its model request lacked usable authentication. See [client smoke results](client-smoke.md). Neither result establishes the full workflow above.

## Troubleshooting

| Symptom                                           | Resolution                                                                                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Set FLOWAUDIT_ROOT...`                       | Supply the absolute project path to the client process or its MCP `env` configuration, then reconnect.                                                              |
| Docker command or scanner service unavailable     | Start Docker, run the root Compose setup and confirm `docker compose ps` lists the scanner.                                                                         |
| `Build the scanner first`                         | In local mode, run `npm install` and `npm run build` from the scanner project.                                                                                      |
| Config or secret file cannot be found             | Use scanner-host paths. For Compose use `/app/...` and check the configured volume mount. Do not paste secret contents into chat.                                   |
| Only the login page is discovered                 | Inspect the authentication blocker, selectors and probe configuration. Complete required MFA/CAPTCHA out of band; do not mark the scan successful.                  |
| Another scan is already active                    | Read its status and finish/cancel it before starting another. Preserve interrupted results for reporting.                                                           |
| ZAP is unavailable or the role is unauthenticated | Correct the API/proxy URL, API key environment name or role profile. Preserve a failed job and partial report until checks actually complete.                       |
| Client times out during a check                   | Reconnect and inspect persisted scan/job status before retrying. Avoid duplicating active scans; configure a longer tool timeout if the client supports it.         |
| Reconnect shows a scan as interrupted             | The worker stopped or crashed. Read/export retained results and start a fresh scan for browser operations. A stdio-only disconnect should preserve the live worker. |
| Updated code or environment is not taking effect  | Rebuild, finish/cancel any current scan, and restart the worker with the desired environment. Reconnecting only the client does not replace the worker.             |
| No ASVS passes after a clean scan                 | Expected: provide requirement-specific evidence, scope and rationale. Empty alerts cannot establish a pass.                                                         |
