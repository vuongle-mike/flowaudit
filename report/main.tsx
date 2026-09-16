import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./style.css";
import type {
  AssessmentStatus,
  Evidence,
  Finding,
  ScanData,
  Screen,
  Transition,
} from "../src/types.js";

type Payload = ScanData & {
  screenshots: Record<string, string>;
  reportWarnings: string[];
  exportedAt: string;
};
const data: Payload = JSON.parse(
  document.getElementById("scan-data")!.textContent!,
);
const statuses: AssessmentStatus[] = [
  "pass",
  "fail",
  "needs-review",
  "not-tested",
  "not-applicable",
];
const pretty = (text: string) => text.replaceAll("-", " ");
function pathLabel(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.pathname + parsed.search;
  } catch {
    return url;
  }
}
function formatTime(value: string): string {
  return new Date(value).toLocaleString();
}
function Tag({ value }: { value: string }) {
  return <span className={`tag ${value}`}>{pretty(value)}</span>;
}
function Empty({ title, body }: { title: string; body: string }) {
  return (
    <div className="empty">
      <span className="empty-symbol">◎</span>
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}

type ScreenNode = Node<
  { screen: Screen; image?: string; findings: number; highlighted: boolean },
  "screen"
>;
function ScreenCard({ data: node }: NodeProps<ScreenNode>) {
  return (
    <div className={`screen-node ${node.highlighted ? "highlighted" : ""}`}>
      <Handle type="target" position={Position.Left} />
      <div className="screen-image">
        {node.image ? (
          <img
            src={node.image}
            alt={`Screenshot of ${node.screen.title || pathLabel(node.screen.url)}`}
            draggable={false}
          />
        ) : (
          <span>No screenshot</span>
        )}
      </div>
      <div className="screen-caption">
        <div>
          <strong>{node.screen.title || "Untitled screen"}</strong>
          <span>{pathLabel(node.screen.url)}</span>
        </div>
        {node.findings > 0 && <b className="finding-count">{node.findings}</b>}
      </div>
      <div className="screen-footer">
        <span>{node.screen.role}</span>
        <span>
          {node.screen.kind === "browser-response"
            ? "Live response screenshot"
            : `${node.screen.actions.length} actions`}
        </span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { screen: ScreenCard };

function graphPath(target: string | undefined): {
  nodes: Set<string>;
  edges: Set<string>;
} {
  const result = { nodes: new Set<string>(), edges: new Set<string>() };
  if (!target) return result;
  const targetScreen = data.screens.find((screen) => screen.id === target);
  if (!targetScreen) return result;
  const screens = data.screens.filter(
    (screen) => screen.role === targetScreen.role,
  );
  const valid = new Set(screens.map((screen) => screen.id));
  const edges = data.transitions.filter(
    (edge) => valid.has(edge.to) && (!edge.from || valid.has(edge.from)),
  );
  const roots = screens.filter(
    (screen) =>
      edges.some((edge) => edge.to === screen.id && !edge.from) ||
      !edges.some((edge) => edge.to === screen.id && edge.from !== edge.to),
  );
  const queue = (roots.length ? roots : screens.slice(0, 1)).map(
    (screen) => screen.id,
  );
  const previous = new Map<string, Transition | null>(
    queue.map((id) => [id, null]),
  );
  while (queue.length) {
    const current = queue.shift()!;
    if (current === target) break;
    for (const edge of edges.filter((edge) => edge.from === current)) {
      if (!previous.has(edge.to)) {
        previous.set(edge.to, edge);
        queue.push(edge.to);
      }
    }
  }
  result.nodes.add(target);
  let cursor = target;
  while (previous.get(cursor)) {
    const edge = previous.get(cursor)!;
    result.edges.add(edge.id);
    result.nodes.add(edge.from!);
    cursor = edge.from!;
  }
  return result;
}

function makeGraph(
  role: string,
  finding: Finding | undefined,
): { nodes: ScreenNode[]; edges: Edge[] } {
  const screens = data.screens.filter(
    (screen) => role === "all" || screen.role === role,
  );
  const valid = new Set(screens.map((screen) => screen.id));
  const transitions = data.transitions.filter(
    (edge) =>
      edge.from &&
      edge.from !== edge.to &&
      valid.has(edge.from) &&
      valid.has(edge.to),
  );
  const targetId = finding?.resultScreenId ?? finding?.screenId;
  const marked = graphPath(targetId);
  const levels = new Map<string, number>();
  const roots = screens.filter(
    (screen) =>
      data.transitions.some((edge) => edge.to === screen.id && !edge.from) ||
      !transitions.some(
        (edge) => edge.to === screen.id && edge.from !== edge.to,
      ),
  );
  const queue = roots.map((screen) => screen.id);
  for (const root of queue) levels.set(root, 0);
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of transitions.filter((edge) => edge.from === current)) {
      if (!levels.has(edge.to)) {
        levels.set(edge.to, Math.min((levels.get(current) ?? 0) + 1, 12));
        queue.push(edge.to);
      }
    }
  }
  const occupied = new Map<number, number>();
  const nodes: ScreenNode[] = screens.map((screen) => {
    const level = levels.get(screen.id) ?? 0;
    const row = occupied.get(level) ?? 0;
    occupied.set(level, row + 1);
    return {
      id: screen.id,
      type: "screen",
      position: { x: level * 310, y: row * 248 },
      data: {
        screen,
        image: data.screenshots[screen.id],
        findings: data.findings.filter(
          (item) =>
            item.status !== "not-reproduced" &&
            (item.screenId === screen.id || item.resultScreenId === screen.id),
        ).length,
        highlighted: marked.nodes.has(screen.id),
      },
      style: {
        opacity: targetId && !marked.nodes.has(screen.id) ? 0.42 : 1,
      },
    };
  });
  const edges: Edge[] = transitions.map((edge) => ({
    id: edge.id,
    source: edge.from!,
    target: edge.to,
    type: "smoothstep",
    label:
      edge.action.length > 32 ? `${edge.action.slice(0, 30)}…` : edge.action,
    animated: marked.edges.has(edge.id),
    style: {
      stroke: marked.edges.has(edge.id) ? "#e77630" : "#a6b2bd",
      strokeWidth: marked.edges.has(edge.id) ? 3 : 1.5,
      opacity: targetId && !marked.edges.has(edge.id) ? 0.3 : 1,
    },
    labelStyle: { fill: "#526171", fontSize: 10 },
    labelBgStyle: { fill: "#f6f8fa" },
    labelBgPadding: [6, 4],
  }));
  return { nodes, edges };
}

function EvidenceList({ ids }: { ids: string[] }) {
  const items = ids
    .map((id) => data.evidence.find((item) => item.id === id))
    .filter((item): item is Evidence => !!item);
  return (
    <div className="evidence-list">
      {items.length === 0 ? (
        <p className="muted small">No linked evidence was captured.</p>
      ) : (
        items.map((item) => (
          <details key={item.id}>
            <summary>
              <Tag value={item.kind} />
              <span>
                {item.method ?? ""} {item.url ? pathLabel(item.url) : item.id}
              </span>
              {item.status !== undefined && <b>{item.status}</b>}
            </summary>
            <div className="evidence-body">
              <dl>
                <dt>Evidence ID</dt>
                <dd>{item.id}</dd>
                <dt>Captured</dt>
                <dd>{formatTime(item.at)}</dd>
                {item.role && (
                  <>
                    <dt>Role</dt>
                    <dd>{item.role}</dd>
                  </>
                )}
                {item.url && (
                  <>
                    <dt>URL</dt>
                    <dd>{item.url}</dd>
                  </>
                )}
              </dl>
              {item.browserCapture && (
                <div className="notice">
                  <strong>Live browser capture</strong>
                  <p>{item.browserCapture.note}</p>
                  <dl>
                    <dt>Document response</dt>
                    <dd>
                      {item.browserCapture.status} · {item.browserCapture.url}
                    </dd>
                    <dt>Response SHA-256</dt>
                    <dd>{item.browserCapture.responseSha256}</dd>
                    <dt>Captured</dt>
                    <dd>{formatTime(item.browserCapture.at)}</dd>
                  </dl>
                </div>
              )}
              {item.note && <p>{item.note}</p>}
              {item.requestHeaders && (
                <>
                  <h4>Request headers</h4>
                  <pre>{JSON.stringify(item.requestHeaders, null, 2)}</pre>
                </>
              )}
              {item.requestBody && (
                <>
                  <h4>Request body</h4>
                  <pre>{item.requestBody}</pre>
                </>
              )}
              {item.responseHeaders && (
                <>
                  <h4>Response headers</h4>
                  <pre>{JSON.stringify(item.responseHeaders, null, 2)}</pre>
                </>
              )}
              {item.responseBody && (
                <>
                  <h4>Response body</h4>
                  <pre>{item.responseBody}</pre>
                </>
              )}
            </div>
          </details>
        ))
      )}
    </div>
  );
}

function ScreenshotView({ screen }: { screen: Screen }) {
  const [expanded, setExpanded] = useState(false);
  const image = data.screenshots[screen.id];
  const label =
    screen.kind === "browser-response"
      ? "Live server response screenshot"
      : "Captured application screen";
  return (
    <figure className="visual-card">
      <figcaption>
        <strong>{label}</strong>
        <span>{screen.title}</span>
      </figcaption>
      {image ? (
        <button
          className="screenshot-button"
          onClick={() => setExpanded(true)}
          aria-label={`Enlarge ${screen.title}`}
        >
          <img src={image} alt={`${label}: ${screen.title}`} />
          <span>Click to enlarge</span>
        </button>
      ) : (
        <p className="notice">
          Screenshot unavailable. HTTP evidence is retained below.
        </p>
      )}
      <p className="small muted">{screen.captureNote || screen.url}</p>
      {expanded && (
        <div
          className="image-overlay"
          role="dialog"
          aria-modal="true"
          aria-label={`Screenshot: ${screen.title}`}
          onClick={() => setExpanded(false)}
        >
          <button
            className="button"
            autoFocus
            onClick={() => setExpanded(false)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setExpanded(false);
            }}
          >
            Close screenshot ×
          </button>
          <img
            src={image}
            alt={`${label}: ${screen.title}`}
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </figure>
  );
}

function FindingDetail({
  finding,
  showGraph,
  completed = false,
}: {
  finding: Finding;
  showGraph: (finding: Finding) => void;
  completed?: boolean;
}) {
  return (
    <div className="finding-detail">
      <div className="tag-row">
        {!completed && <Tag value={finding.severity} />}
        <Tag value={finding.status} />
        <span className="muted small">
          {finding.source} · {finding.ruleId}
        </span>
      </div>
      <h2>{finding.title}</h2>
      <p>{finding.description}</p>
      {finding.detectionReason && (
        <>
          <h3>Detection reason</h3>
          <pre>{finding.detectionReason}</pre>
        </>
      )}
      <dl>
        <dt>Role</dt>
        <dd>{finding.role ?? "Unspecified"}</dd>
        <dt>Location</dt>
        <dd>{finding.url ?? "Not captured"}</dd>
        {finding.parameterChannel && (
          <>
            <dt>Input channel</dt>
            <dd>{finding.parameterChannel}</dd>
          </>
        )}
        {finding.parameter && (
          <>
            <dt>Parameter</dt>
            <dd>{finding.parameter}</dd>
          </>
        )}
        {finding.occurrences && finding.occurrences > 1 && (
          <>
            <dt>Grouped occurrences</dt>
            <dd>{finding.occurrences}</dd>
          </>
        )}
        <dt>ASVS mapping</dt>
        <dd>
          {finding.asvsIds.length ? finding.asvsIds.join(", ") : "Not mapped"}
        </dd>
      </dl>
      {finding.locations && finding.locations.length > 1 && (
        <details>
          <summary>Affected locations ({finding.locations.length})</summary>
          <ul>
            {finding.locations.map((location) => (
              <li key={location}>{location}</li>
            ))}
          </ul>
        </details>
      )}
      <h3>Screenshots and test result</h3>
      <div className="visual-gallery">
        {[finding.screenId, finding.resultScreenId]
          .filter((id, i, ids) => id && ids.indexOf(id) === i)
          .map((id) => {
            const screen = data.screens.find((s) => s.id === id);
            return screen ? <ScreenshotView key={id} screen={screen} /> : null;
          })}
      </div>
      {!finding.resultScreenId && (
        <p className="notice">
          No live result screenshot was captured. The server may have returned a
          download, redirect or non-renderable response. No synthetic image is
          substituted; see HTTP evidence below.
        </p>
      )}
      {(finding.resultScreenId || finding.screenId) &&
      data.screens.some(
        (screen) => screen.id === (finding.resultScreenId || finding.screenId),
      ) ? (
        <button className="button primary" onClick={() => showGraph(finding)}>
          Trace path in screen flow <span>↗</span>
        </button>
      ) : (
        <p className="notice">
          This finding has no verified screen association. It is retained here
          without a guessed graph link.
        </p>
      )}
      <h3>{completed ? "Executed test cases" : "Reproduction steps"}</h3>
      {finding.steps.length ? (
        <ol className="steps">
          {finding.steps.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      ) : (
        <p className="muted">
          {completed
            ? "No test cases recorded."
            : "No reproduction steps provided."}
        </p>
      )}
      <h3>Evidence</h3>
      <EvidenceList ids={finding.evidenceIds} />
    </div>
  );
}

function App() {
  const [tab, setTab] = useState("flow");
  const [role, setRole] = useState("all");
  const [findingId, setFindingId] = useState("");
  const [screenId, setScreenId] = useState("");
  const [edgeId, setEdgeId] = useState("");
  const [search, setSearch] = useState("");
  const [assessmentFilter, setAssessmentFilter] = useState("all");
  const [findingFilter, setFindingFilter] = useState("all");
  const [fullImage, setFullImage] = useState(false);
  const roles = [...new Set(data.screens.map((screen) => screen.role))];
  const finding = data.findings.find((item) => item.id === findingId);
  const screen = data.screens.find((item) => item.id === screenId);
  const edge = data.transitions.find((item) => item.id === edgeId);
  const graph = useMemo(() => makeGraph(role, finding), [role, finding]);
  const informationalObservations = data.findings.filter(
    (item) => item.source === "zap" && item.severity === "info",
  );
  const actionableFindings = data.findings.filter(
    (item) =>
      item.status !== "not-reproduced" &&
      !(item.source === "zap" && item.severity === "info"),
  );
  const completedChecks = data.findings.filter(
    (item) => item.status === "not-reproduced",
  );
  const displayBlockers = [
    ...data.blockers
      .reduce((grouped, blocker) => {
        const normalized = {
          ...blocker,
          reason: blocker.reason.split("\n", 1)[0],
        };
        const key = JSON.stringify([
          normalized.role,
          normalized.url,
          normalized.action,
          normalized.reason,
        ]);
        const existing = grouped.get(key);
        if (existing) {
          existing.occurrences =
            (existing.occurrences ?? 1) + (normalized.occurrences ?? 1);
          existing.at = normalized.at;
        } else
          grouped.set(key, {
            ...normalized,
            occurrences: normalized.occurrences ?? 1,
          });
        return grouped;
      }, new Map<string, (typeof data.blockers)[number]>())
      .values(),
  ];
  const confirmed = data.findings.filter((item) => item.status === "confirmed");
  const assessed = data.assessments.filter((item) =>
    ["pass", "fail", "not-applicable"].includes(item.status),
  ).length;
  const assessmentCounts = Object.fromEntries(
    statuses.map((status) => [
      status,
      data.assessments.filter((item) => item.status === status).length,
    ]),
  );
  const shownAssessments = data.assessments.filter(
    (item) =>
      (assessmentFilter === "all" || item.status === assessmentFilter) &&
      `${item.id} ${item.text} ${item.chapter} ${item.section}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  const shownFindings = actionableFindings.filter(
    (item) =>
      findingFilter === "all" ||
      item.status === findingFilter ||
      (findingFilter === "unlinked" &&
        (!item.screenId ||
          !data.screens.some((screen) => screen.id === item.screenId))),
  );
  function showGraph(item: Finding) {
    const target = item.resultScreenId ?? item.screenId;
    setFindingId(item.id);
    setRole(
      target
        ? (data.screens.find((screen) => screen.id === target)?.role ?? "all")
        : "all",
    );
    setScreenId(target ?? "");
    setEdgeId("");
    setTab("flow");
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">F</span>
          <div>
            flow<span>audit</span>
          </div>
        </div>
        <div className="workspace-label">LOCAL ASSESSMENT</div>
        <nav aria-label="Report sections">
          {[
            ["flow", "◫", "Screen flow"],
            ["findings", "◈", "Findings"],
            ["checks", "✓", "Completed checks"],
            ["asvs", "▦", "ASVS checklist"],
            ["coverage", "◎", "Coverage & jobs"],
          ].map(([id, icon, label]) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => setTab(id)}
            >
              <span>{icon}</span>
              {label}
              {id === "findings" && <b>{actionableFindings.length}</b>}
              {id === "checks" && <b>{completedChecks.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="offline-dot" /> Self-contained report
          <p>
            All evidence stays in this file.
            <br />
            No external requests.
          </p>
          <span>ASVS {data.asvsVersion} · L1</span>
        </div>
      </aside>
      <main>
        <header className="page-header">
          <div>
            <div className="eyebrow">
              SECURITY ASSESSMENT <span>/</span> {data.id.slice(0, 12)}
            </div>
            <h1>{data.name}</h1>
            <p className="target">{data.target}</p>
          </div>
          <div className="header-meta">
            <Tag value={data.status} />
            <span>{formatTime(data.startedAt)}</span>
            <span>Exported {formatTime(data.exportedAt)}</span>
          </div>
        </header>
        <section className="metrics" aria-label="Assessment metrics">
          <div>
            <span>Confirmed findings</span>
            <strong>
              {confirmed.length}
              <small
                className={
                  confirmed.some((item) => item.severity === "high")
                    ? "danger-text"
                    : ""
                }
              >
                {confirmed.filter((item) => item.severity === "high").length}{" "}
                high severity
              </small>
              <small>
                {
                  actionableFindings.filter(
                    (item) => item.status === "needs-review",
                  ).length
                }{" "}
                review candidates · {completedChecks.length} bounded checks
                {informationalObservations.length
                  ? ` · ${informationalObservations.length} info observations in JSON`
                  : ""}
              </small>
            </strong>
          </div>
          <div>
            <span>Observed screens</span>
            <strong>
              {data.screens.filter((s) => s.kind !== "browser-response").length}
              <small>
                {
                  data.screens.filter((s) => s.kind === "browser-response")
                    .length
                }{" "}
                live response screenshots · {roles.length} roles ·{" "}
                {data.observations.length} observations
              </small>
            </strong>
          </div>
          <div>
            <span>ASVS requirements assessed</span>
            <strong>
              {assessed}
              <small>of {data.assessments.length} L1 requirements</small>
            </strong>
          </div>
          <div>
            <span>Exploration coverage</span>
            <strong className="word-metric">
              {data.coverage.complete ? "Scope explored" : "Partial"}
              <small>
                {data.coverage.actions} actions · {displayBlockers.length}{" "}
                blockers
              </small>
            </strong>
          </div>
        </section>
        <div className="scope-notice">
          <span>i</span>
          <p>
            Results apply only to the roles, paths and actions recorded in this
            scan. Missing alerts do not establish security or ASVS compliance.
          </p>
        </div>

        {tab === "flow" && (
          <section className="section">
            <div className="section-heading">
              <div>
                <h2>Explore the application</h2>
                <p>Screens, actions and the evidence connecting them.</p>
              </div>
              <div className="toolbar">
                <label>
                  Role
                  <select
                    aria-label="Filter graph by role"
                    value={role}
                    onChange={(event) => {
                      setRole(event.target.value);
                      setFindingId("");
                    }}
                  >
                    <option value="all">All roles</option>
                    {roles.map((item) => (
                      <option key={item}>{item}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Finding
                  <select
                    aria-label="Highlight finding path"
                    value={findingId}
                    onChange={(event) => {
                      const next = data.findings.find(
                        (item) => item.id === event.target.value,
                      );
                      if (next) showGraph(next);
                      else setFindingId("");
                    }}
                  >
                    <option value="">All paths</option>
                    {actionableFindings.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.title}
                        {item.screenId
                          ? ""
                          : item.resultScreenId
                            ? " (direct HTTP)"
                            : " (unlinked)"}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </div>
            {finding && (
              <div className="trace-banner">
                <span>
                  <b>{finding.title}</b> ·{" "}
                  {finding.resultScreenId
                    ? finding.screenId
                      ? "Source form → verification request → saved Live server response screenshot."
                      : "Direct HTTP check; no source application screen was recorded."
                    : finding.screenId
                      ? "Highlighted path uses recorded transitions."
                      : "No verified screen link is available."}
                </span>
                <button onClick={() => setFindingId("")}>Clear ×</button>
              </div>
            )}
            <details className="screenshot-library" open>
              <summary>
                Screenshot library · application screens and HTTP results (
                {graph.nodes.length})
              </summary>
              <div className="visual-gallery">
                {graph.nodes.map((node) => (
                  <ScreenshotView key={node.id} screen={node.data.screen} />
                ))}
              </div>
            </details>
            <div className="graph-panel">
              {graph.nodes.length ? (
                <ReactFlow
                  key={role}
                  nodes={graph.nodes}
                  edges={graph.edges}
                  nodeTypes={nodeTypes}
                  fitView
                  minZoom={0.08}
                  maxZoom={2}
                  nodesDraggable={false}
                  nodesConnectable={false}
                  onNodeClick={(_, node) => {
                    setScreenId(node.id);
                    setEdgeId("");
                  }}
                  onEdgeClick={(_, edge) => {
                    setEdgeId(edge.id);
                    setScreenId("");
                  }}
                  onPaneClick={() => {
                    setScreenId("");
                    setEdgeId("");
                  }}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background
                    variant={BackgroundVariant.Dots}
                    gap={22}
                    color="#d9e0e7"
                  />
                  <Controls showInteractive={false} />
                  <MiniMap
                    nodeColor={(node) =>
                      (node.data as ScreenNode["data"]).highlighted
                        ? "#ea985d"
                        : "#c8d7d4"
                    }
                    pannable
                    zoomable
                  />
                </ReactFlow>
              ) : (
                <Empty
                  title="No screens captured"
                  body="Partial reports remain available when exploration is blocked or cancelled."
                />
              )}
            </div>
            <div className="graph-legend">
              <span>
                <i className="legend-screen" /> Observed screen
              </span>
              <span>
                <i className="legend-path" /> Finding path
              </span>
              <span>
                Click a screen or transition to inspect evidence. Same-screen
                actions remain in screen details.
              </span>
            </div>
            {screen && (
              <div className="detail-panel screen-detail">
                <div>
                  <div className="section-heading">
                    <div>
                      <div className="eyebrow">
                        SCREEN DETAIL · {screen.role}
                      </div>
                      <h2>{screen.title || "Untitled screen"}</h2>
                      <p>{screen.url}</p>
                    </div>
                    <button className="button" onClick={() => setScreenId("")}>
                      Close
                    </button>
                  </div>
                  {data.screenshots[screen.id] ? (
                    <button
                      className="screenshot-button"
                      onClick={() => setFullImage(true)}
                    >
                      <img
                        src={data.screenshots[screen.id]}
                        alt="Full captured screen"
                      />
                      <span>Click to enlarge</span>
                    </button>
                  ) : (
                    <p className="notice">Screenshot unavailable.</p>
                  )}
                </div>
                <div>
                  <h3>
                    {screen.kind === "browser-response"
                      ? "Saved HTTP response"
                      : "Captured state"}
                  </h3>
                  {screen.captureNote && (
                    <p className="notice">{screen.captureNote}</p>
                  )}
                  {screen.evidenceIds && (
                    <EvidenceList ids={screen.evidenceIds} />
                  )}
                  <h3>Recorded transitions</h3>
                  <div className="action-list">
                    {data.transitions
                      .filter((t) => t.from === screen.id || t.to === screen.id)
                      .map((t) => (
                        <button
                          className="text-button"
                          key={t.id}
                          onClick={() => {
                            setEdgeId(t.id);
                            setScreenId("");
                          }}
                        >
                          {t.action} · {t.evidenceIds.length} HTTP records
                        </button>
                      ))}
                  </div>
                  <dl>
                    <dt>Screen ID</dt>
                    <dd>{screen.id}</dd>
                    <dt>Observed</dt>
                    <dd>{formatTime(screen.observedAt)}</dd>
                    <dt>Observations</dt>
                    <dd>
                      {
                        data.observations.filter(
                          (item) => item.screenId === screen.id,
                        ).length
                      }
                    </dd>
                  </dl>
                  <details>
                    <summary>Visible text</summary>
                    <pre>{screen.text}</pre>
                  </details>
                  <h3>Available actions</h3>
                  <div className="action-list">
                    {screen.actions.map((action) => (
                      <div key={action.id}>
                        <Tag value={action.kind} />
                        <span>{action.label}</span>
                        {action.blocked && (
                          <span className="danger-text">{action.blocked}</span>
                        )}
                      </div>
                    ))}
                  </div>
                  <h3>Findings on this screen</h3>
                  {data.findings
                    .filter(
                      (item) =>
                        item.status !== "not-reproduced" &&
                        (item.screenId === screen.id ||
                          item.resultScreenId === screen.id),
                    )
                    .map((item) => (
                      <button
                        className="text-button"
                        key={item.id}
                        onClick={() => {
                          setFindingId(item.id);
                          setTab("findings");
                        }}
                      >
                        {item.title} →
                      </button>
                    ))}
                </div>
              </div>
            )}
            {edge && (
              <div className="detail-panel">
                <div className="section-heading">
                  <div>
                    <div className="eyebrow">TRANSITION · {edge.role}</div>
                    <h2>{edge.action}</h2>
                    <p>{formatTime(edge.at)}</p>
                  </div>
                  <button className="button" onClick={() => setEdgeId("")}>
                    Close
                  </button>
                </div>
                <dl>
                  <dt>From</dt>
                  <dd>
                    {edge.from
                      ? (data.screens.find((item) => item.id === edge.from)
                          ?.url ?? edge.from)
                      : "Session entry"}
                  </dd>
                  <dt>To</dt>
                  <dd>
                    {data.screens.find((item) => item.id === edge.to)?.url ??
                      edge.to}
                  </dd>
                  {edge.selector && (
                    <>
                      <dt>Selector</dt>
                      <dd>{edge.selector}</dd>
                    </>
                  )}
                  {edge.value && (
                    <>
                      <dt>Input value</dt>
                      <dd>{edge.value}</dd>
                    </>
                  )}
                </dl>
                <h3>HTTP and verification evidence</h3>
                <EvidenceList ids={edge.evidenceIds} />
              </div>
            )}
          </section>
        )}

        {tab === "findings" && (
          <section className="section">
            <div className="section-heading">
              <div>
                <h2>Findings</h2>
                <p>
                  Confirmed issues and observations requiring further review.
                </p>
              </div>
              <select
                aria-label="Filter findings"
                value={findingFilter}
                onChange={(event) => setFindingFilter(event.target.value)}
              >
                <option value="all">All actionable findings</option>
                <option value="confirmed">Confirmed</option>
                <option value="needs-review">Needs review</option>
                <option value="unlinked">Without a screen link</option>
              </select>
            </div>
            {shownFindings.length ? (
              <div className="findings-layout">
                <div className="finding-list">
                  {shownFindings.map((item) => (
                    <button
                      className={`finding-item ${item.id === findingId ? "selected" : ""}`}
                      key={item.id}
                      onClick={() => setFindingId(item.id)}
                    >
                      <div className="tag-row">
                        <Tag value={item.severity} />
                        <Tag value={item.status} />
                      </div>
                      <strong>{item.title}</strong>
                      <span>
                        {item.role ?? "Any role"} · {item.source}
                      </span>
                      {!item.screenId && <small>Unlinked evidence</small>}
                    </button>
                  ))}
                </div>
                <div className="detail-panel">
                  {finding && shownFindings.includes(finding) ? (
                    <FindingDetail finding={finding} showGraph={showGraph} />
                  ) : (
                    <Empty
                      title="Select a finding"
                      body="Review the evidence, reproduction steps and ASVS references."
                    />
                  )}
                </div>
              </div>
            ) : (
              <Empty
                title="No matching findings"
                body="An empty finding list does not mean the application has passed ASVS."
              />
            )}
          </section>
        )}

        {tab === "checks" && (
          <section className="section">
            <div className="section-heading">
              <div>
                <h2>Completed bounded checks</h2>
                <p>
                  Tests that did not reproduce an issue in the recorded cases.
                  They are evidence of the listed cases, not a broad security
                  pass.
                </p>
              </div>
            </div>
            {completedChecks.length ? (
              <div className="findings-layout">
                <div className="finding-list">
                  {completedChecks.map((item) => (
                    <button
                      className={`finding-item ${item.id === findingId ? "selected" : ""}`}
                      key={item.id}
                      onClick={() => setFindingId(item.id)}
                    >
                      <div className="tag-row">
                        <Tag value={item.status} />
                      </div>
                      <strong>{item.title}</strong>
                      <span>
                        {item.role ?? "Any role"} · {item.ruleId}
                      </span>
                    </button>
                  ))}
                </div>
                <div className="detail-panel">
                  {finding && completedChecks.includes(finding) ? (
                    <FindingDetail
                      finding={finding}
                      showGraph={showGraph}
                      completed
                    />
                  ) : (
                    <Empty
                      title="Select a completed check"
                      body="Inspect the exact cases and linked request evidence."
                    />
                  )}
                </div>
              </div>
            ) : (
              <Empty
                title="No completed checks"
                body="No configured verifier finished with a non-reproduction result."
              />
            )}
          </section>
        )}

        {tab === "asvs" && (
          <section className="section">
            <div className="section-heading">
              <div>
                <h2>ASVS {data.asvsVersion} · Level 1</h2>
                <p>
                  Each requirement retains its assessment scope and evidence
                  needs.
                </p>
              </div>
            </div>
            <div className="assessment-counts">
              {statuses.map((status) => (
                <button
                  key={status}
                  className={assessmentFilter === status ? "chosen" : ""}
                  onClick={() =>
                    setAssessmentFilter(
                      assessmentFilter === status ? "all" : status,
                    )
                  }
                >
                  <Tag value={status} />
                  <strong>{assessmentCounts[status]}</strong>
                </button>
              ))}
            </div>
            <div className="checklist-toolbar">
              <input
                aria-label="Search ASVS requirements"
                placeholder="Search requirement ID, chapter or text…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
              <select
                aria-label="Filter ASVS status"
                value={assessmentFilter}
                onChange={(event) => setAssessmentFilter(event.target.value)}
              >
                <option value="all">All statuses</option>
                {statuses.map((status) => (
                  <option key={status} value={status}>
                    {pretty(status)}
                  </option>
                ))}
              </select>
              <span>{shownAssessments.length} requirements</span>
            </div>
            <div className="checklist">
              {shownAssessments.map((item) => (
                <details key={item.id} className="requirement">
                  <summary>
                    <span className="requirement-id">{item.id}</span>
                    <span className="requirement-text">
                      {item.text}
                      <small>
                        {item.chapter} / {item.section}
                      </small>
                    </span>
                    <Tag value={item.status} />
                  </summary>
                  <div className="requirement-body">
                    <dl>
                      <dt>Assessment method</dt>
                      <dd>{item.method || "Not specified"}</dd>
                      <dt>Evidence needed</dt>
                      <dd>{item.evidenceNeeded || "Not specified"}</dd>
                      <dt>Scope evaluated</dt>
                      <dd>{item.scope || "No scope evaluated yet"}</dd>
                      <dt>Rationale</dt>
                      <dd>{item.rationale || "No assessment recorded"}</dd>
                    </dl>
                    <EvidenceList ids={item.evidenceIds} />
                  </div>
                </details>
              ))}
            </div>
            {!shownAssessments.length && (
              <Empty
                title="No matching requirements"
                body="Try a different search or assessment status."
              />
            )}
          </section>
        )}

        {tab === "coverage" && (
          <section className="section">
            <div className="section-heading">
              <div>
                <h2>Coverage & execution</h2>
                <p>What ran, what was observed and where the scan stopped.</p>
              </div>
              <Tag value={data.status} />
            </div>
            <div className="coverage-grid">
              <div className="detail-panel">
                <h3>Observed coverage</h3>
                <dl>
                  <dt>Unique screens</dt>
                  <dd>
                    {
                      data.screens.filter((s) => s.kind !== "browser-response")
                        .length
                    }{" "}
                    application states;{" "}
                    {
                      data.screens.filter((s) => s.kind === "browser-response")
                        .length
                    }{" "}
                    live response screenshots
                  </dd>
                  <dt>All observations</dt>
                  <dd>{data.observations.length}</dd>
                  <dt>Recorded transitions</dt>
                  <dd>{data.transitions.length}</dd>
                  <dt>Executed actions</dt>
                  <dd>{data.coverage.actions}</dd>
                  <dt>HTTP evidence</dt>
                  <dd>
                    {
                      data.evidence.filter((item) => item.kind === "http")
                        .length
                    }
                  </dd>
                  <dt>Start</dt>
                  <dd>{formatTime(data.startedAt)}</dd>
                  <dt>Finish</dt>
                  <dd>
                    {data.finishedAt
                      ? formatTime(data.finishedAt)
                      : "Not finished at export"}
                  </dd>
                </dl>
                <p className="notice">
                  {data.coverage.complete
                    ? "The configured exploration scope was processed. This does not establish complete application coverage."
                    : "Exploration is partial. Unvisited states and untested requirements remain outside the evidence."}
                </p>
                {data.coverage.notes.map((note, index) => (
                  <p className="coverage-note" key={index}>
                    {note}
                  </p>
                ))}
              </div>
              <div className="detail-panel">
                <h3>Execution jobs</h3>
                {data.jobs.length ? (
                  data.jobs.map((job) => (
                    <div className="job" key={job.id}>
                      <div>
                        <strong>{job.kind}</strong>
                        <Tag value={job.status} />
                      </div>
                      <code>{job.id}</code>
                      {job.error && <p className="danger-text">{job.error}</p>}
                    </div>
                  ))
                ) : (
                  <p className="muted">No background jobs recorded.</p>
                )}
                <h3>Roles observed</h3>
                <div className="role-list">
                  {roles.map((role) => (
                    <div key={role}>
                      <b>{role}</b>
                      <span>
                        {
                          data.screens.filter(
                            (screen) =>
                              screen.role === role &&
                              screen.kind !== "browser-response",
                          ).length
                        }{" "}
                        screens
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <h3>Blocked or skipped branches</h3>
            {displayBlockers.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Role</th>
                      <th>Location / action</th>
                      <th>Reason</th>
                      <th>Count</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayBlockers.map((blocker, index) => (
                      <tr key={index}>
                        <td>{blocker.role ?? "—"}</td>
                        <td>
                          {blocker.url && <span>{blocker.url}</span>}
                          {blocker.action && <small>{blocker.action}</small>}
                        </td>
                        <td>{blocker.reason}</td>
                        <td>{blocker.occurrences ?? 1}</td>
                        <td>{formatTime(blocker.at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="notice">
                No blockers were recorded. Unrecorded branches are not evidence
                of full coverage.
              </p>
            )}
            {data.reportWarnings.length > 0 && (
              <>
                <h3>Export warnings</h3>
                {data.reportWarnings.map((warning, index) => (
                  <p className="notice" key={index}>
                    {warning}
                  </p>
                ))}
              </>
            )}
          </section>
        )}
        <footer>
          flowaudit <span>·</span> Offline evidence report <span>·</span> Schema{" "}
          {data.schemaVersion} <span>·</span> No compliance certification
        </footer>
      </main>
      {fullImage && screen && (
        <div
          className="image-modal"
          role="dialog"
          aria-modal="true"
          aria-label="Enlarged screenshot"
          onClick={() => setFullImage(false)}
        >
          <button className="button" onClick={() => setFullImage(false)}>
            Close screenshot ×
          </button>
          <img
            src={data.screenshots[screen.id]}
            alt="Enlarged captured screen"
          />
        </div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
