import type { ScanData } from "./types.js";
export function explorationFrontier(data: ScanData) {
  return data.screens.flatMap((screen) =>
    screen.actions.map((action) => ({
      screenId: screen.id,
      role: screen.role,
      url: screen.url,
      actionId: action.id,
      action: action.label,
      kind: action.kind,
      status: action.blocked
        ? "blocked"
        : data.transitions.some(
              (t) =>
                t.from === screen.id &&
                t.action === `${action.kind}: ${action.label}`,
            )
          ? "visited"
          : "unvisited",
      reason: action.blocked || "No recorded execution from this state",
    })),
  );
}
export function withCoverage(data: ScanData): ScanData {
  const frontier = explorationFrontier(data);
  return {
    ...data,
    coverage: { ...data.coverage, frontier },
    blockers: [
      ...data.blockers,
      ...frontier
        .filter((f) => f.status !== "visited")
        .map((f) => ({
          role: f.role,
          url: f.url,
          action: f.action,
          reason:
            f.status === "blocked"
              ? f.reason
              : "Discovered action not explored",
          at: data.finishedAt || data.startedAt,
        })),
    ],
  };
}
