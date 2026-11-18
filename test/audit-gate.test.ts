// Root test of scripts/audit-gate.mjs, the dependency audit of CI job g6-compliance. The judgement and the CLI take
// their inputs as arguments: these cases never run npm and never reach the network. The report below has the shape
// `npm audit --json` gave on 2026-11-18: nine high entries, one advisory at their root (GHSA-fc5q-39xc-vjpf on
// picomatch 4.0.7).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmdirSync, symlinkSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_COMMAND, BLOCKING, SEVERITIES, isMain, judge, run } from "../scripts/audit-gate.mjs";
import type { AuditException, CliDeps } from "../scripts/audit-gate.mjs";
import shipped from "../scripts/audit-exceptions.json" with { type: "json" };

const PICOMATCH = {
  source: 1247710,
  name: "picomatch",
  dependency: "picomatch",
  title: "picomatch vulnerable to ReDoS through single-branch repeated extglobs",
  url: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
  severity: "high",
  cwe: ["CWE-1333"],
  cvss: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
  range: "<=4.0.7",
};

const FIX = { name: "typescript-eslint", version: "8.47.0", isSemVerMajor: true };

const entry = (name: string, via: unknown[], range: string, severity = "high", nodes = [`node_modules/${name}`]) => ({
  name,
  severity,
  via,
  range,
  nodes,
  fixAvailable: FIX,
});

/** An advisory of another package, for the cases that add one. */
const advisory = (name: string, ghsa: string, severity: string, range = "*") => ({
  source: 2,
  name,
  title: "another flaw",
  url: `https://github.com/advisories/${ghsa}`,
  severity,
  range,
});

/** A fresh copy of the report of 2026-11-18, for each case to change. */
function report() {
  const tse = ">=8.47.1-alpha.0";
  const vulnerabilities: Record<string, ReturnType<typeof entry>> = {
    "@typescript-eslint/eslint-plugin": entry(
      "@typescript-eslint/eslint-plugin",
      ["@typescript-eslint/parser", "@typescript-eslint/type-utils", "@typescript-eslint/utils"],
      tse,
    ),
    "@typescript-eslint/parser": entry("@typescript-eslint/parser", ["@typescript-eslint/typescript-estree"], tse),
    "@typescript-eslint/type-utils": entry(
      "@typescript-eslint/type-utils",
      ["@typescript-eslint/typescript-estree", "@typescript-eslint/utils"],
      tse,
    ),
    "@typescript-eslint/typescript-estree": entry("@typescript-eslint/typescript-estree", ["tinyglobby"], tse),
    "@typescript-eslint/utils": entry("@typescript-eslint/utils", ["@typescript-eslint/typescript-estree"], tse),
    fdir: entry("fdir", ["picomatch"], ">=5.2.1"),
    picomatch: entry("picomatch", [{ ...PICOMATCH }], "*"),
    tinyglobby: entry("tinyglobby", ["fdir", "picomatch"], "*"),
    "typescript-eslint": entry(
      "typescript-eslint",
      [
        "@typescript-eslint/eslint-plugin",
        "@typescript-eslint/parser",
        "@typescript-eslint/typescript-estree",
        "@typescript-eslint/utils",
      ],
      tse,
    ),
  };
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 9, critical: 0, total: 9 } },
  };
}

const LOCK = { lockfileVersion: 3, packages: { "node_modules/picomatch": { version: "4.0.7" } } };

const EXCEPTION: AuditException = {
  advisory: "GHSA-fc5q-39xc-vjpf",
  package: "picomatch",
  version: "4.0.7",
  severity: "high",
  range: "<=4.0.7",
  latest: "4.0.7",
  added: "2026-11-18",
  reason: "No fixed version of picomatch is published.",
};

const LATEST = { picomatch: "4.0.7" };
const TODAY = "2026-11-18";
const NO_COUNTS = { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } };

/** The problems of a case: the report of 2026-11-18 and its exception, with the given changes (null included). */
function problems(over: { audit?: unknown; lock?: unknown; exceptions?: unknown; latest?: Record<string, string>; today?: string }) {
  return judge({
    audit: Object.hasOwn(over, "audit") ? over.audit : report(),
    lock: Object.hasOwn(over, "lock") ? over.lock : LOCK,
    exceptions: Object.hasOwn(over, "exceptions") ? over.exceptions : [EXCEPTION],
    latest: over.latest ?? LATEST,
    today: over.today ?? TODAY,
  }).problems;
}

/** The picomatch advisory left unexcepted (a malformed exception excepts nothing). */
const NOT_EXCEPTED = /^GHSA-fc5q-39xc-vjpf \(high\) on picomatch <=4\.0\.7: .*; not excepted$/;

/** Asserts exactly one problem, matching `re`. */
function one(list: string[], re: RegExp) {
  assert.equal(list.length, 1, list.join("\n"));
  assert.match(list[0] ?? "", re);
}

/** Asserts exactly as many problems as patterns, each pattern matching one of them. */
function each(list: string[], ...res: RegExp[]) {
  assert.equal(list.length, res.length, list.join("\n"));
  for (const re of res) assert.ok(list.some((p) => re.test(p)), `${String(re)} in:\n${list.join("\n")}`);
}

test("the report of 2026-11-18 passes with its one exception", () => {
  const v = judge({ audit: report(), lock: LOCK, exceptions: [EXCEPTION], latest: LATEST, today: TODAY });
  assert.deepEqual(v.problems, []);
  assert.equal(v.vulnerable, 9);
  assert.deepEqual(
    v.advisories.map((a) => a.url),
    ["https://github.com/advisories/GHSA-fc5q-39xc-vjpf"],
  );
  assert.deepEqual(v.excepted, [EXCEPTION]);
});

test("without the exception, the picomatch advisory fails the audit", () => {
  one(problems({ exceptions: [] }), NOT_EXCEPTED);
});

test("a new high advisory fails even with picomatch excepted: on a dependent, on picomatch, or the same id elsewhere", () => {
  const onDependent = report();
  onDependent.vulnerabilities.tinyglobby?.via.push(advisory("tinyglobby", "GHSA-aaaa-bbbb-cccc", "high", "<=0.2.17"));
  one(problems({ audit: onDependent }), /^GHSA-aaaa-bbbb-cccc \(high\) on tinyglobby <=0\.2\.17: another flaw; not excepted$/);

  const onPicomatch = report();
  onPicomatch.vulnerabilities.picomatch?.via.push(advisory("picomatch", "GHSA-gggg-hhhh-jjjj", "high"));
  one(problems({ audit: onPicomatch }), /^GHSA-gggg-hhhh-jjjj \(high\) on picomatch \*: another flaw; not excepted$/);

  const sameIdElsewhere = report();
  sameIdElsewhere.vulnerabilities.fdir?.via.push(advisory("fdir", "GHSA-fc5q-39xc-vjpf", "high"));
  one(problems({ audit: sameIdElsewhere }), /^GHSA-fc5q-39xc-vjpf \(high\) on fdir \*: another flaw; not excepted$/);
});

test("a critical advisory fails; a moderate or a low one does not", () => {
  const add = (severity: string) => {
    const audit = report();
    audit.vulnerabilities["left-pad"] = entry("left-pad", [advisory("left-pad", "GHSA-dddd-eeee-ffff", severity)], "*", severity);
    return problems({ audit });
  };
  one(add("critical"), /^GHSA-dddd-eeee-ffff \(critical\) on left-pad/);
  assert.deepEqual(add("moderate"), []);
  assert.deepEqual(add("low"), []);
});

test("a severity npm does not report fails", () => {
  const audit = report();
  audit.vulnerabilities["left-pad"] = entry("left-pad", [advisory("left-pad", "GHSA-dddd-eeee-ffff", "High")], "*", "High");
  each(
    problems({ audit }),
    /^GHSA-dddd-eeee-ffff on left-pad: unknown severity "High"$/,
    /^left-pad: unknown severity "High"$/,
  );
  assert.deepEqual([...SEVERITIES], ["info", "low", "moderate", "high", "critical"]);
});

test("the exception lapses when its advisory leaves the audit", () => {
  one(
    problems({ audit: { auditReportVersion: 2, vulnerabilities: {}, metadata: NO_COUNTS } }),
    /^exception GHSA-fc5q-39xc-vjpf \(picomatch\): the advisory is no longer in the audit; remove the exception$/,
  );
});

test("the exception lapses when an installed copy differs, or is missing", () => {
  const lock = { lockfileVersion: 3, packages: { "node_modules/picomatch": { version: "4.0.6" } } };
  one(problems({ lock }), /: node_modules\/picomatch is 4\.0\.6, the exception covers 4\.0\.7$/);
  one(problems({ lock: { lockfileVersion: 3, packages: {} } }), /: node_modules\/picomatch is absent from package-lock\.json/);

  const twoCopies = report();
  const nested = "node_modules/fdir/node_modules/picomatch";
  twoCopies.vulnerabilities.picomatch = entry("picomatch", [{ ...PICOMATCH }], "*", "high", ["node_modules/picomatch", nested]);
  const lock2 = { lockfileVersion: 3, packages: { "node_modules/picomatch": { version: "4.0.7" }, [nested]: { version: "2.3.1" } } };
  one(problems({ audit: twoCopies, lock: lock2 }), /: node_modules\/fdir\/node_modules\/picomatch is 2\.3\.1, the exception covers 4\.0\.7$/);

  const noCopy = report();
  noCopy.vulnerabilities.picomatch = entry("picomatch", [{ ...PICOMATCH }], "*", "high", []);
  one(problems({ audit: noCopy }), /: the audit lists no installed copy of picomatch$/);

  each(
    problems({ lock: { lockfileVersion: 1 } }),
    /^package-lock\.json has no packages object$/,
    /: node_modules\/picomatch is absent from package-lock\.json/,
  );
});

test("the exception lapses when another version becomes the latest", () => {
  one(
    problems({ latest: { picomatch: "4.0.8" } }),
    /: picomatch 4\.0\.8 is now the latest version \(it was 4\.0\.7 when the exception was written\); check whether it fixes GHSA-fc5q-39xc-vjpf/,
  );
});

test("the exception lapses when the latest version could not be read", () => {
  one(problems({ latest: {} }), /: the latest published version of picomatch could not be read$/);
});

test("the exception lapses when the advisory's vulnerable range changes, or gains a second range", () => {
  const audit = report();
  audit.vulnerabilities.picomatch = entry("picomatch", [{ ...PICOMATCH, range: "<4.0.8" }], "*");
  one(problems({ audit }), /: the vulnerable range is now "<4\.0\.8", the exception was written for "<=4\.0\.7"; a fixed version may exist/);

  // One advisory reported twice on the package, a backported fix giving it a second range: in either order.
  for (const via of [
    [{ ...PICOMATCH, source: 3, range: "<2.3.3" }, { ...PICOMATCH }],
    [{ ...PICOMATCH }, { ...PICOMATCH, source: 3, range: "<2.3.3" }],
  ]) {
    const split = report();
    split.vulnerabilities.picomatch = entry("picomatch", via, "*");
    one(problems({ audit: split }), /: the vulnerable range is now "<2\.3\.3" and "<=4\.0\.7", the exception was written for "<=4\.0\.7"/);
  }
});

test("the exception lapses when the advisory's severity changes", () => {
  const audit = report();
  audit.vulnerabilities.picomatch = entry("picomatch", [{ ...PICOMATCH, severity: "critical" }], "*", "critical");
  one(problems({ audit }), /: the severity is now "critical", the exception was written for "high"; check the advisory again/);
});

test("a report that names a package without its entry, or a via item of no known shape, fails", () => {
  const ghost = report();
  ghost.vulnerabilities.fdir = entry("fdir", ["picomatch", "ghost"], ">=5.2.1");
  one(problems({ audit: ghost }), /^the audit names ghost without an entry for it$/);

  const odd = report();
  odd.vulnerabilities.fdir = entry("fdir", ["picomatch", 42], ">=5.2.1");
  one(problems({ audit: odd }), /^fdir: an item of its via is neither a package name nor an advisory$/);

  const noSeverity: Record<string, unknown> = { ...report().vulnerabilities };
  noSeverity.fdir = { name: "fdir", via: ["picomatch"], range: ">=5.2.1", nodes: ["node_modules/fdir"] };
  each(
    problems({ audit: { ...report(), vulnerabilities: noSeverity } }),
    /^fdir: no severity$/,
    /^the report's metadata counts 9 package\(s\) of severity high or critical, its entries list 8$/,
  );
});

test("a package more severe than every advisory behind it fails", () => {
  const audit = report();
  audit.vulnerabilities.picomatch = entry("picomatch", [{ ...PICOMATCH, severity: "moderate" }], "*");
  const list = problems({ audit });
  const unexplained = list.filter((p) => / is high but no advisory of severity high or above explains it$/.test(p));
  assert.equal(unexplained.length, 9, list.join("\n"));

  // A critical package whose only root is the excepted high advisory: a critical advisory is missing from the report.
  const missing = report();
  missing.vulnerabilities.fdir = entry("fdir", ["picomatch"], ">=5.2.1", "critical");
  one(problems({ audit: missing }), /^fdir is critical but no advisory of severity critical or above explains it$/);
});

test("a report whose counts list more high or critical packages than its entries, or no counts, fails", () => {
  const counts = { vulnerabilities: { ...NO_COUNTS.vulnerabilities, critical: 1, total: 1 } };
  one(
    problems({ audit: { auditReportVersion: 2, vulnerabilities: {}, metadata: counts }, exceptions: [] }),
    /^the report's metadata counts 1 package\(s\) of severity high or critical, its entries list 0$/,
  );
  one(
    problems({ audit: { auditReportVersion: 2, vulnerabilities: {} }, exceptions: [] }),
    /^the report has no metadata\.vulnerabilities counts of its high and critical packages$/,
  );
  assert.deepEqual(problems({ audit: { auditReportVersion: 2, vulnerabilities: {}, metadata: NO_COUNTS }, exceptions: [] }), []);
});

test("an advisory without a title or a range is still named when it fails", () => {
  const audit = report();
  audit.vulnerabilities.fdir?.via.push({ source: 3, name: "fdir", severity: "high" });
  one(problems({ audit }), /^npm advisory 3 \(high\) on fdir \(no range\): \(no title\); not excepted$/);
});

test("an unreadable report fails", () => {
  for (const audit of [null, {}, { auditReportVersion: 1, vulnerabilities: {} }, { auditReportVersion: 2, error: { code: "ENOTFOUND" }, vulnerabilities: {} }]) {
    one(problems({ audit }), /^npm audit gave no readable report/);
  }
});

test("malformed, duplicated or future-dated exceptions fail", () => {
  const malformed = (change: Partial<AuditException>, re: RegExp) =>
    each(problems({ exceptions: [{ ...EXCEPTION, ...change }] }), re, NOT_EXCEPTED);
  malformed({ advisory: "CVE-2026-0001" }, /^exception 1: "CVE-2026-0001" is not a GHSA id$/);
  malformed({ added: "2026-02-30" }, /^exception 1: "2026-02-30" is not a day written YYYY-MM-DD$/);
  malformed({ added: "2099-01-01" }, /^exception 1: written on 2099-01-01, after today \(2026-11-18\)$/);
  malformed({ reason: " " }, /^exception 1: field "reason" missing or empty$/);
  malformed({ package: "Pico Match" }, /^exception 1: "Pico Match" is not a package name$/);
  malformed({ package: "p".repeat(215) }, /^exception 1: "p{215}" is not a package name$/);
  malformed({ severity: "severe" }, /^exception 1: "severe" is not a severity npm reports$/);
  each(problems({ exceptions: {} }), /^the exceptions file is not a list$/, NOT_EXCEPTED);
  one(problems({ exceptions: [EXCEPTION, { ...EXCEPTION }] }), /^exception 2: GHSA-fc5q-39xc-vjpf for picomatch is listed twice$/);
  one(problems({ today: "18/11/2026" }), /^today "18\/11\/2026" is not a day written YYYY-MM-DD$/);
});

/** The CLI on the report of 2026-11-18, with the given effects changed; returns its exit code and printed lines. */
async function cli(over: Partial<CliDeps>) {
  const lines: string[] = [];
  const asked: string[] = [];
  const code = await run({
    audit: () => ({ stdout: JSON.stringify(report()), stderr: "", status: 1 }),
    latestOf: (name) => {
      asked.push(name);
      return Promise.resolve({ version: "4.0.7" });
    },
    exceptions: [EXCEPTION],
    lock: LOCK,
    today: TODAY,
    out: (line) => lines.push(`out ${line}`),
    err: (line) => lines.push(`err ${line}`),
    ...over,
  });
  return { code, lines, asked };
}

test("the CLI exits 0 on the report of 2026-11-18, and asks the registry, not the file, for the latest version", async () => {
  const ok = await cli({});
  assert.equal(ok.code, 0, ok.lines.join("\n"));
  assert.deepEqual(ok.asked, ["picomatch"]);
  assert.deepEqual(ok.lines, [
    "out audit gate: 9 vulnerable package(s), 1 advisory(ies) (high 1)",
    "out   excepted: GHSA-fc5q-39xc-vjpf on picomatch 4.0.7, since 2026-11-18: No fixed version of picomatch is published.",
    "out audit gate OK: no advisory of severity high or critical outside the exceptions, and every exception still holds.",
  ]);
  const newer = await cli({ latestOf: () => Promise.resolve({ version: "4.0.8" }) });
  assert.equal(newer.code, 1);
  assert.ok(newer.lines.some((l) => /picomatch 4\.0\.8 is now the latest version/.test(l)), newer.lines.join("\n"));
});

test("the CLI exits 1 when npm prints no JSON, the report is unreadable, or the registry cannot be read", async () => {
  const silent = await cli({ audit: () => ({ stdout: "", stderr: "npm ERR! network", status: 1 }) });
  assert.equal(silent.code, 1);
  assert.deepEqual(silent.lines, ["err audit gate FAILED: `npm audit --json` printed no JSON (exit 1):\nnpm ERR! network"]);

  const refused = await cli({ audit: () => ({ stdout: JSON.stringify({ error: { code: "ENOAUDIT" } }), status: 1 }) });
  assert.equal(refused.code, 1);
  assert.ok(refused.lines.some((l) => /npm audit gave no readable report/.test(l)), refused.lines.join("\n"));
  assert.ok(refused.lines.every((l) => !l.includes("undefined")), refused.lines.join("\n"));

  const offline = await cli({ latestOf: () => Promise.resolve({ error: "fetch failed" }) });
  assert.equal(offline.code, 1);
  assert.ok(offline.lines.includes("err audit gate: picomatch: fetch failed"), offline.lines.join("\n"));
  assert.ok(offline.lines.some((l) => /could not be read$/.test(l)), offline.lines.join("\n"));
});

test("the CLI runs only as the entry point, a linked path included", () => {
  const url = new URL("../scripts/audit-gate.mjs", import.meta.url);
  const script = fileURLToPath(url);
  assert.equal(isMain(script, url.href), true);
  assert.equal(isMain(fileURLToPath(import.meta.url), url.href), false);
  assert.equal(isMain(undefined, url.href), false);
  // A directory link to scripts/ (a junction on Windows, a symbolic link elsewhere), removed afterwards.
  const dir = mkdtempSync(join(tmpdir(), "audit-gate-"));
  try {
    const link = join(dir, "scripts");
    symlinkSync(dirname(script), link, "junction");
    try {
      assert.equal(isMain(join(link, "audit-gate.mjs"), url.href), true);
    } finally {
      unlinkSync(link);
    }
  } finally {
    rmdirSync(dir);
  }
});

test("the shipped exceptions file holds the one picomatch advisory, and it matches package-lock.json", () => {
  assert.equal(shipped.length, 1);
  assert.equal(shipped[0]?.advisory, "GHSA-fc5q-39xc-vjpf");
  assert.equal(shipped[0]?.package, "picomatch");
  const lock: unknown = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  const latest = { picomatch: shipped[0]?.latest ?? "" };
  assert.deepEqual(judge({ audit: report(), lock, exceptions: shipped, latest, today: TODAY }).problems, []);
});

test("CI job g6-compliance runs the gate in place of npm audit --audit-level=high, blocking and unconditional", () => {
  // A Windows checkout under core.autocrlf has CRLF line endings, the runner's checkout LF: both are read as LF.
  const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8").replace(/\r\n/g, "\n");
  const start = ci.indexOf("\n  g6-compliance:\n");
  assert.ok(start >= 0, "job g6-compliance not found");
  const rest = ci.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-z0-9-]+:\n/);
  const job = next >= 0 ? rest.slice(0, next + 1) : rest;
  assert.match(job, /\n {8}run: node scripts\/audit-gate\.mjs\n/);
  assert.doesNotMatch(job, /continue-on-error|\n\s+if:/);
  assert.doesNotMatch(ci, /npm audit --audit-level/);
});

test("the gate audits the whole tree at the high threshold", () => {
  assert.equal(AUDIT_COMMAND, "npm audit --json");
  assert.deepEqual([...BLOCKING], ["high", "critical"]);
});
