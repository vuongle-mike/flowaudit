import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
  ASVS_IDS,
  ASVS_PROVENANCE,
  ASVS_VERSION,
  assertCatalogueIntegrity,
  createAssessments,
  mapZapAlert,
  validateAssessmentUpdate,
} from "../src/asvs.js";

test("ASVS official release bytes, full L1 count, IDs and text match provenance", () => {
  const sourceRoot = new URL("../../data/asvs-5.0.0.en.json", import.meta.url);
  const bytes = readFileSync(
    existsSync(sourceRoot)
      ? sourceRoot
      : new URL("../data/asvs-5.0.0.en.json", import.meta.url),
  );
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35",
  );
  const source = JSON.parse(bytes.toString());
  const expected = source.Requirements.flatMap((chapter: any) =>
    chapter.Items.flatMap((section: any) =>
      section.Items.filter((row: any) => row.L === "1"),
    ),
  );
  const rows = createAssessments();
  assert.equal(ASVS_VERSION, "5.0.0");
  assert.equal(ASVS_PROVENANCE.license, "CC-BY-SA-4.0");
  assert.ok(ASVS_PROVENANCE.source.includes("/OWASP/ASVS/v5.0.0/"));
  assert.equal(rows.length, 70);
  assert.deepEqual(
    rows.map((row) => row.id),
    ASVS_PROVENANCE.requirementIds,
  );
  assert.deepEqual(
    rows.map((row) => row.id),
    expected.map((row: any) => "v5.0.0-" + row.Shortcode.slice(1)),
  );
  assert.deepEqual(
    rows.map((row) => row.text),
    expected.map((row: any) => row.Description),
  );
  assertCatalogueIntegrity();
});

test("every requirement starts unassessed with useful review and evidence instructions", () => {
  const first = createAssessments();
  for (const row of first) {
    assert.equal(row.status, "not-tested");
    assert.deepEqual(row.evidenceIds, []);
    assert.equal(row.scope, "");
    assert.ok(row.method.length > 20);
    assert.ok(row.evidenceNeeded.length > 40);
    assert.match(row.rationale, /Missing evidence:/);
  }
  first[0].status = "pass";
  first[0].evidenceIds.push("mutation");
  assert.equal(createAssessments()[0].status, "not-tested");
  assert.deepEqual(createAssessments()[0].evidenceIds, []);
});

test("pass/fail require actual scan evidence, scope and evidence-based rationale", () => {
  const row = createAssessments()[0];
  const evidence = new Set(["proof-1"]);
  for (const status of ["pass", "fail"] as const) {
    assert.throws(
      () => validateAssessmentUpdate(row, { status }, evidence),
      /requires evidence/,
    );
    assert.throws(
      () =>
        validateAssessmentUpdate(
          row,
          {
            status,
            evidenceIds: ["other-scan"],
            scope: "/search",
            rationale: "Reviewed",
          },
          evidence,
        ),
      /attached to this scan/,
    );
    assert.throws(
      () =>
        validateAssessmentUpdate(
          row,
          {
            status,
            evidenceIds: ["proof-1"],
            scope: " ",
            rationale: "Reviewed",
          },
          evidence,
        ),
      /requires evidence/,
    );
    assert.throws(
      () =>
        validateAssessmentUpdate(
          row,
          { status, evidenceIds: ["proof-1"], scope: "/search" },
          evidence,
        ),
      /Replace the unassessed rationale/,
    );
    const result = validateAssessmentUpdate(
      row,
      {
        status,
        evidenceIds: ["proof-1", "proof-1"],
        scope: " /search input q for userA ",
        rationale:
          "Inspected encoding at the HTML text sink against the attached source and browser case.",
      },
      evidence,
    );
    assert.equal(result.status, status);
    assert.equal(result.scope, "/search input q for userA");
    assert.deepEqual(result.evidenceIds, ["proof-1"]);
  }
  assert.equal(row.status, "not-tested");
});

test("non-applicability needs an explanation and scope; immutable definition cannot change", () => {
  const row = createAssessments().find((row) => row.id === "v5.0.0-10.4.1")!;
  assert.throws(
    () =>
      validateAssessmentUpdate(row, { status: "not-applicable" }, new Set()),
    /explanation/,
  );
  const reviewed = validateAssessmentUpdate(
    row,
    {
      status: "not-applicable",
      scope: "Invoice fixture at build abc",
      rationale:
        "The fixture has form authentication only and no OAuth authorization server.",
    },
    new Set(),
  );
  assert.equal(reviewed.status, "not-applicable");
  assert.throws(
    () =>
      validateAssessmentUpdate(
        row,
        { text: "Changed requirement" } as any,
        new Set(),
      ),
    /Immutable/,
  );
  assert.throws(
    () => validateAssessmentUpdate({ ...row, id: "10.4.1" }, {}, new Set()),
    /Unknown or unversioned/,
  );
  assert.throws(
    () =>
      validateAssessmentUpdate(row, { status: "compliant" } as any, new Set()),
    /Invalid/,
  );
  assert.throws(
    () =>
      validateAssessmentUpdate(
        row,
        { status: "needs-review", rationale: "" },
        new Set(),
      ),
    /explain/,
  );
});

test("ZAP mappings remain versioned L1 triage hints and never alter assessments", () => {
  const rows = createAssessments();
  assert.deepEqual(mapZapAlert("40012"), [...ASVS_IDS.xss]);
  assert.deepEqual(mapZapAlert("10035-1"), [...ASVS_IDS.hsts]);
  assert.deepEqual(mapZapAlert("10010"), []); // HttpOnly belongs to L2 in ASVS 5.
  assert.deepEqual(mapZapAlert("999999"), []);
  const ids = new Set(rows.map((row) => row.id));
  for (const id of Object.values(ASVS_IDS).flat()) assert.ok(ids.has(id));
  assert.ok(rows.every((row) => row.status === "not-tested"));
});
