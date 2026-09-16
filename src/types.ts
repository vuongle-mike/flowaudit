export type Status =
  "running" | "completed" | "cancelled" | "interrupted" | "failed";
export type AssessmentStatus =
  "pass" | "fail" | "needs-review" | "not-tested" | "not-applicable";
export interface AuthProfile {
  secretRef: string;
  type: "form" | "cookie" | "bearer" | "storageState";
  loginPath?: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  loggedInSelector?: string;
  probePath: string;
  probeContains: string;
}
export interface ProjectConfig {
  name: string;
  target: string;
  includePaths: string[];
  excludePaths: string[];
  roles: Record<string, AuthProfile>;
  secretsFile: string;
  mode: "passive" | "active";
  allowedActions: string[];
  sensitiveSelectors: string[];
  limits: {
    statesPerRole: number;
    actions: number;
    minutes: number;
    requestsPerSecond: number;
  };
  zap?: { apiUrl: string; proxyUrl: string; apiKeyEnv: string };
  tests?: {
    activeScan?: {
      role?: string;
      profile: "xss" | "deep";
      attackStrength: "LOW" | "MEDIUM" | "HIGH" | "INSANE";
      scannerIds: string[];
      methods: Array<"GET" | "POST">;
      includePathEndpoints: boolean;
      maxEndpoints: number;
      discoveryPaths: string[];
    };
    publicSurface?: {
      role: string;
      files: string[];
      maxRequests: number;
      forms: Array<{
        pagePath: string;
        submitPath: string;
        fields: string[];
        headerMutation: boolean;
      }>;
    };
    login?: {
      role: string;
      loginPath: string;
      submitPath: string;
      usernameField: string;
      passwordField: string;
      csrfField?: string;
      maxAttempts: number;
      successPath?: string;
      successContains?: string;
      failureContains?: string;
    };
    xss?: { role: string; path: string; parameter: string };
    authorization?: Array<{
      name: string;
      ownerRole: string;
      attackerRole: string;
      discoveryPath: string;
      linkSelector: string;
      protectedMarker: string;
      asvsIds: string[];
    }>;
    session?: {
      role: string;
      logoutPath: string;
      protectedPath: string;
      protectedMarker: string;
    };
  };
}
export interface Action {
  id: string;
  kind: "click" | "fill" | "select";
  label: string;
  selector: string;
  href?: string;
  inputType?: string;
  required?: boolean;
  blocked?: string;
  options?: string[];
}
export interface Screen {
  kind?: "browser" | "http-response" | "browser-response";
  evidenceIds?: string[];
  captureNote?: string;
  id: string;
  role: string;
  url: string;
  title: string;
  text: string;
  fingerprint: string;
  screenshot: string;
  actions: Action[];
  observedAt: string;
}
export interface Transition {
  kind?: "browser" | "verification";
  id: string;
  role: string;
  from: string | null;
  to: string;
  action: string;
  actionId?: string;
  selector?: string;
  value?: string;
  evidenceIds: string[];
  at: string;
}
export interface Evidence {
  browserCapture?: {
    method: "browser-navigation";
    screenshot: string;
    responseSha256: string;
    url: string;
    status: number;
    at: string;
    note: string;
  };
  id: string;
  kind: "http" | "verification" | "manual";
  role?: string;
  transitionId?: string;
  url?: string;
  method?: string;
  status?: number;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBody?: string;
  note?: string;
  at: string;
}
export interface Finding {
  resultScreenId?: string;
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
  status: "confirmed" | "needs-review" | "not-reproduced";
  source: "zap" | "verifier";
  ruleId: string;
  role?: string;
  url?: string;
  parameter?: string;
  parameterChannel?: string;
  detectionReason?: string;
  occurrences?: number;
  locations?: string[];
  screenId?: string;
  evidenceIds: string[];
  asvsIds: string[];
  steps: string[];
  description: string;
}
export interface Assessment {
  id: string;
  chapter: string;
  section: string;
  text: string;
  level: number;
  status: AssessmentStatus;
  method: string;
  evidenceNeeded: string;
  evidenceIds: string[];
  rationale: string;
  scope: string;
}
export interface Blocker {
  role?: string;
  url?: string;
  action?: string;
  reason: string;
  at: string;
  occurrences?: number;
}
export interface ScanData {
  schemaVersion: 1;
  id: string;
  name: string;
  target: string;
  status: Status;
  startedAt: string;
  finishedAt?: string;
  screens: Screen[];
  observations: Array<{ screenId: string; at: string }>;
  transitions: Transition[];
  evidence: Evidence[];
  findings: Finding[];
  assessments: Assessment[];
  blockers: Blocker[];
  jobs: Array<{ id: string; kind: string; status: string; error?: string }>;
  coverage: {
    actions: number;
    complete: boolean;
    notes: string[];
    frontier?: Array<{
      screenId: string;
      role: string;
      url: string;
      actionId: string;
      action: string;
      kind: string;
      status: string;
      reason: string;
    }>;
  };
  asvsVersion: "5.0.0";
}
