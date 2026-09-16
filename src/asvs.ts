import { createHash } from "node:crypto";
import catalogue from "../data/asvs-5.0.0.en.json" with { type: "json" };
import provenance from "../data/asvs-provenance.json" with { type: "json" };
import type { Assessment, AssessmentStatus } from "./types.js";

export const ASVS_VERSION = "5.0.0" as const;
export const ASVS_PROVENANCE = Object.freeze(provenance);
export const ASVS_IDS = {
  xss: ["v5.0.0-1.2.1", "v5.0.0-3.2.2"],
  sqlInjection: ["v5.0.0-1.2.4"],
  authorizationObject: ["v5.0.0-8.2.2"],
  authorizationFunction: ["v5.0.0-8.2.1"],
  session: ["v5.0.0-7.4.1"],
  cookieSecure: ["v5.0.0-3.3.1"],
  hsts: ["v5.0.0-3.4.1"],
} as const;

// A mapping is a triage aid, never an assessment or proof of a whole requirement.
// Only L1 requirements are mapped. HttpOnly, CSP and clickjacking are L2 in 5.0.0.
export const ZAP_ASVS_MAP: Readonly<Record<string, readonly string[]>> = {
  "3": ["v5.0.0-14.2.1"],
  "6": ["v5.0.0-5.3.2"],
  "7": ["v5.0.0-5.3.2"],
  "41": ["v5.0.0-13.4.1"],
  "42": ["v5.0.0-13.4.1"],
  "10011": ASVS_IDS.cookieSecure,
  "10019": ["v5.0.0-4.1.1"],
  "10024": ["v5.0.0-14.2.1"],
  "10035": ASVS_IDS.hsts,
  "10040": ["v5.0.0-12.2.1"],
  "10042": ["v5.0.0-12.2.1"],
  "10047": ["v5.0.0-12.2.1"],
  "10098": ["v5.0.0-3.4.2"],
  "40012": ASVS_IDS.xss,
  "40014": ASVS_IDS.xss,
  "40016": ASVS_IDS.xss,
  "40017": ASVS_IDS.xss,
  "40018": ["v5.0.0-1.2.4"],
  "40019": ["v5.0.0-1.2.4"],
  "90019": ["v5.0.0-1.3.2"],
  "90020": ["v5.0.0-1.2.5"],
  "90023": ["v5.0.0-1.5.1"],
};

export function mapZapAlert(ruleId: string | number): string[] {
  return [...(ZAP_ASVS_MAP[String(ruleId).split("-")[0]] ?? [])];
}

type Guidance = { method: string; evidenceNeeded: string };
const guidance: Record<string, Guidance> = {
  "V1.2": {
    method:
      "Targeted dynamic injection checks plus source review of each interpreter sink.",
    evidenceNeeded:
      "Input/response and execution evidence for failures; source locations, encoding context and parameterization checks across the declared scope for a pass.",
  },
  "V1.3": {
    method:
      "Source/configuration review and targeted sanitizer or dynamic-evaluation tests.",
    evidenceNeeded:
      "Sanitizer library/version/configuration, untrusted-input data flow and positive/negative regression cases.",
  },
  "V1.5": {
    method:
      "Review XML parser configuration and test external-entity handling in an authorized fixture.",
    evidenceNeeded:
      "Parser initialization/configuration and reproducible tests proving unsafe XML features are disabled.",
  },
  "V2.1": {
    method: "Manual documentation review.",
    evidenceNeeded:
      "Versioned input-validation rules specifying formats and business/security constraints.",
  },
  "V2.2": {
    method:
      "Compare documented rules with server-side implementation; test invalid input directly against the service.",
    evidenceNeeded:
      "Input-validation specification, relevant server code and boundary/negative test results for security decisions.",
  },
  "V2.3": {
    method:
      "Replay documented business workflows with skipped and reordered steps.",
    evidenceNeeded:
      "Business workflow specification, expected state transitions and actual server responses to reordered steps.",
  },
  "V3.2": {
    method:
      "Inspect browser rendering contexts and relevant rendering code; run targeted browser tests.",
    evidenceNeeded:
      "Response headers, intended rendering context, output-rendering source locations and execution/non-execution evidence.",
  },
  "V3.3": {
    method:
      "Inspect every in-scope Set-Cookie response and cookie configuration.",
    evidenceNeeded:
      "Redacted Set-Cookie attributes including Secure and __Host-/__Secure- name prefixes, deployment scheme and the assessed cookie inventory.",
  },
  "V3.4": {
    method:
      "Inspect HTTP responses and deployment configuration; test origin validation where applicable.",
    evidenceNeeded:
      "Endpoint/response inventory, HSTS max-age and/or CORS allowlist configuration, including negative-origin and sensitive-data checks.",
  },
  "V3.5": {
    method:
      "Review CSRF design and test state-changing requests from disallowed browser origins.",
    evidenceNeeded:
      "Sensitive-operation inventory, HTTP methods, token/header validation and successful/blocked cross-origin test results.",
  },
  "V4.1": {
    method: "Compare response content with media-type and charset headers.",
    evidenceNeeded:
      "HTTP responses for all declared API content types and the corresponding server response configuration.",
  },
  "V4.4": {
    method:
      "Inspect WebSocket connection inventory and transport configuration.",
    evidenceNeeded:
      "Observed WSS endpoints, TLS configuration and proof insecure WS connections are unavailable, or explained non-applicability.",
  },
  "V5.2": {
    method:
      "Review upload rules and test authorized boundary sizes and mismatched file content.",
    evidenceNeeded:
      "Documented size/type limits, validation implementation and upload rejection/acceptance results; avoid availability-impacting live tests.",
  },
  "V5.3": {
    method:
      "Review file-storage/path construction and test direct retrieval/path handling in scope.",
    evidenceNeeded:
      "Storage execution policy, trusted path construction or sanitization code and representative negative test responses.",
  },
  "V6.1": {
    method: "Manual authentication security documentation review.",
    evidenceNeeded:
      "Versioned credential-abuse controls including rate limits, automation defenses, response policy and malicious-lockout prevention.",
  },
  "V6.2": {
    method:
      "Review password policy/handling code and exercise the relevant account/password UI in a test account.",
    evidenceNeeded:
      "Requirement-specific registration/change/login cases, server-side password handling configuration and UI behavior evidence with passwords redacted.",
  },
  "V6.3": {
    method:
      "Review authentication defenses against documented controls and default-account inventory.",
    evidenceNeeded:
      "Configured abuse defenses and bounded test results; account inventory proving default accounts are absent or disabled.",
  },
  "V6.4": {
    method: "Review and test account activation/recovery lifecycle.",
    evidenceNeeded:
      "Initial-secret generator/configuration, expiry and single-use results, and recovery UI/source inventory.",
  },
  "V7.2": {
    method:
      "Review backend session verification/generation and compare tokens across authentication.",
    evidenceNeeded:
      "Backend validation/generation source, randomness configuration and redacted session rotation tests; a small token sample cannot establish entropy.",
  },
  "V7.4": {
    method:
      "Replay the previous session after termination; test account disable/delete separately when supported.",
    evidenceNeeded:
      "Authenticated baseline, termination event, replay with the prior session and server rejection or unauthorized data access; backend invalidation design.",
  },
  "V8.1": {
    method: "Manual authorization-model review.",
    evidenceNeeded:
      "Versioned function/resource access matrix defining roles, tenants, ownership and explicit permissions.",
  },
  "V8.2": {
    method:
      "Compare owner/attacker role requests against explicit function and object access rules.",
    evidenceNeeded:
      "Authorization matrix, owner baseline, lower-privilege/other-tenant response, protected-data marker and reproducible steps; HTTP 200 alone is insufficient.",
  },
  "V8.3": {
    method:
      "Review server-side enforcement and bypass client-side controls with direct requests.",
    evidenceNeeded:
      "Trusted service-layer enforcement locations and negative authorization tests across the declared operations.",
  },
  "V9.1": {
    method:
      "Review token signature/algorithm/key-source configuration and targeted invalid-token cases.",
    evidenceNeeded:
      "Issuer trust configuration, algorithm allowlist and server rejection of tampered tokens/untrusted keys; never attach live token values.",
  },
  "V9.2": {
    method:
      "Test token acceptance before/after its validity interval and review server checks.",
    evidenceNeeded:
      "Redacted token claims, test timestamps, server responses and verification configuration.",
  },
  "V10.4": {
    method:
      "Review OAuth authorization-server policy and execute requirement-specific flow/replay cases.",
    evidenceNeeded:
      "Registered client configuration and redacted redirect, code reuse/expiry, grant and refresh-token replay results, or evidence OAuth is not present.",
  },
  "V11.3": {
    method: "Manual cryptographic implementation/configuration review.",
    evidenceNeeded:
      "Inventory of encryption uses, libraries, modes and padding with source/config references; browser scanning cannot establish this requirement.",
  },
  "V11.4": {
    method: "Manual cryptographic implementation/dependency review.",
    evidenceNeeded:
      "Inventory of cryptographic hashing, HMAC/KDF/random-generation uses and approved algorithm configuration.",
  },
  "V12.1": {
    method: "Independent TLS configuration review and handshake tests.",
    evidenceNeeded:
      "TLS protocol negotiation results and deployment configuration for every in-scope endpoint; browser success is insufficient.",
  },
  "V12.2": {
    method:
      "Inspect external connection inventory and TLS/certificate validation.",
    evidenceNeeded:
      "Endpoint inventory, transport/redirect behavior and certificate chain/trust results; describe local HTTP fixture exceptions without claiming a pass.",
  },
  "V13.4": {
    method:
      "Inspect deployment artifacts and attempt scoped source-metadata retrieval.",
    evidenceNeeded:
      "Deployment configuration excluding source-control directories, filesystem access constraints and HTTP denial evidence.",
  },
  "V14.2": {
    method:
      "Inspect data flows and redacted HTTP captures for sensitive URL values.",
    evidenceNeeded:
      "Sensitive-data inventory, request-field placement across workflows and source/config references; output must redact actual secrets.",
  },
  "V14.3": {
    method:
      "Observe DOM/storage after logout, expiry and offline termination; review cleanup design.",
    evidenceNeeded:
      "Before/after redacted client-storage/DOM observations and termination cleanup implementation.",
  },
  "V15.1": {
    method: "Manual maintenance-policy review.",
    evidenceNeeded:
      "Versioned risk-based dependency remediation deadlines and general update policy.",
  },
  "V15.2": {
    method:
      "Compare component inventory and vulnerability dates with documented remediation deadlines.",
    evidenceNeeded:
      "SBOM/lockfile, vulnerability assessment dates, component versions and the update/remediation policy.",
  },
  "V15.3": {
    method:
      "Review response schemas/serializers against explicit field-level access rules.",
    evidenceNeeded:
      "Allowed field matrix, serializer/source references and responses for different roles showing only authorized required fields.",
  },
};

export function assertCatalogueIntegrity(): void {
  // TypeScript reformats copied JSON in dist. Verify the parsed content at runtime;
  // the provenance fixture test separately verifies the original upstream bytes.
  if (
    createHash("sha256").update(JSON.stringify(catalogue)).digest("hex") !==
    provenance.canonicalSha256
  ) {
    throw new Error(
      "ASVS catalogue checksum mismatch; restore the pinned upstream source.",
    );
  }
  if (catalogue.Version !== ASVS_VERSION)
    throw new Error("Unexpected ASVS version.");
}

export function createAssessments(): Assessment[] {
  assertCatalogueIntegrity();
  const rows = catalogue.Requirements.flatMap((chapter) =>
    chapter.Items.flatMap((section) =>
      section.Items.filter((requirement) => requirement.L === "1").map(
        (requirement) => {
          const help = guidance[section.Shortcode];
          if (!help)
            throw new Error(`Missing review guidance for ${section.Shortcode}`);
          return {
            id: `v${ASVS_VERSION}-${requirement.Shortcode.slice(1)}`,
            chapter: `${chapter.Shortcode} ${chapter.Name}`,
            section: `${section.Shortcode} ${section.Name}`,
            text: requirement.Description,
            level: 1,
            status: "not-tested" as const,
            ...help,
            evidenceIds: [],
            rationale:
              "No assessment has been performed. Missing evidence: " +
              help.evidenceNeeded,
            scope: "",
          };
        },
      ),
    ),
  );
  if (
    rows.length !== provenance.level1Count ||
    new Set(rows.map((row) => row.id)).size !== rows.length
  ) {
    throw new Error(
      "ASVS L1 catalogue count or IDs do not match the pinned release.",
    );
  }
  return rows;
}

const definitionIds = new Set(createAssessments().map((row) => row.id));
const statuses = new Set<AssessmentStatus>([
  "pass",
  "fail",
  "needs-review",
  "not-tested",
  "not-applicable",
]);
export type AssessmentPatch = Partial<
  Pick<Assessment, "status" | "evidenceIds" | "rationale" | "scope">
>;

/** Return a validated copy; never mutate the original row or silently mark a requirement passed. */
export function validateAssessmentUpdate(
  assessment: Assessment,
  patch: AssessmentPatch,
  evidenceIdsSet: ReadonlySet<string>,
): Assessment {
  if (!definitionIds.has(assessment.id))
    throw new Error("Unknown or unversioned ASVS L1 requirement ID.");
  if (!patch || typeof patch !== "object" || Array.isArray(patch))
    throw new Error("Assessment patch must be an object.");
  const allowed = new Set(["status", "evidenceIds", "rationale", "scope"]);
  for (const key of Object.keys(patch))
    if (!allowed.has(key))
      throw new Error(`Immutable or unknown assessment field: ${key}`);
  const next = { ...assessment, ...patch };
  if (!statuses.has(next.status))
    throw new Error("Invalid ASVS assessment status.");
  for (const key of ["rationale", "scope"] as const) {
    if (typeof next[key] !== "string") throw new Error(`${key} must be text.`);
    next[key] = next[key].trim();
  }
  if (
    !Array.isArray(next.evidenceIds) ||
    next.evidenceIds.some(
      (id) => typeof id !== "string" || !evidenceIdsSet.has(id),
    )
  ) {
    throw new Error(
      "Every evidence ID must refer to evidence attached to this scan.",
    );
  }
  next.evidenceIds = [...new Set(next.evidenceIds)];
  if (next.status === "pass" || next.status === "fail") {
    if (!next.evidenceIds.length || !next.scope || !next.rationale) {
      throw new Error(
        "Pass/fail requires evidence, assessed scope, and rationale.",
      );
    }
    if (next.rationale.startsWith("No assessment has been performed.")) {
      throw new Error(
        "Replace the unassessed rationale with the evidence-based assessment.",
      );
    }
  }
  if (
    next.status === "not-applicable" &&
    (!next.scope ||
      !next.rationale ||
      next.rationale.startsWith("No assessment has been performed."))
  ) {
    throw new Error(
      "Not-applicable requires an explanation and the assessed scope.",
    );
  }
  if (next.status === "needs-review" && !next.rationale)
    throw new Error(
      "Needs-review must explain the missing evidence or unresolved question.",
    );
  return next;
}

export const updateAssessment = validateAssessmentUpdate;
