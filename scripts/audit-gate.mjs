// scripts/audit-gate.mjs — the dependency audit of CI job g6-compliance. Node 24, no dependencies.
//
// Runs `npm audit --json` and fails on any advisory of severity high or critical, as `npm audit --audit-level=high`
// did, except an advisory named in scripts/audit-exceptions.json. An exception names one advisory and one package. It
// is pinned to what it was written for: the installed version of the package, the advisory's severity and vulnerable
// range, and the latest version published. It lapses (the gate fails) as soon as one of them changes or the advisory
// leaves the audit; a new latest version may carry the fix. A lapsed exception is removed, or renewed after a check.
//
// `judge` is pure and `run` takes its effects as arguments, so the root test replays both offline. Only the wiring at
// the bottom runs npm and reads the registry, and only when this file is the entry point (`isMain`, links resolved).
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The command the CLI runs: the whole tree, development dependencies included, as before. */
export const AUDIT_COMMAND = "npm audit --json";
/** The severities that fail the audit (the former `--audit-level=high`). */
export const BLOCKING = Object.freeze(["high", "critical"]);
/** The severities npm reports; any other one is refused. */
export const SEVERITIES = Object.freeze(["info", "low", "moderate", "high", "critical"]);

const GHSA = /^GHSA(?:-[0-9a-z]{4}){3}$/;
const GHSA_URL = /\/advisories\/(GHSA(?:-[0-9a-z]{4}){3})$/;
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const FIELDS = ["advisory", "package", "version", "severity", "range", "latest", "added", "reason"];

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o, k) => (isObject(o) && Object.hasOwn(o, k) ? o[k] : undefined);
const isName = (s) => typeof s === "string" && s.length <= 214 && NPM_NAME.test(s);
const isDay = (s) => {
  if (typeof s !== "string" || !DAY.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
};
const isAdvisory = (v) => isObject(v) && typeof v.name === "string" && typeof v.severity === "string";
const ghsaOf = (a) => (typeof a.url === "string" ? (GHSA_URL.exec(a.url)?.[1] ?? null) : null);
const labelOf = (a) => ghsaOf(a) ?? `npm advisory ${String(a.source)}`;
const keyOf = (a) => `${labelOf(a)}|${a.name}`;
const quoted = (list) => list.map((s) => `"${s}"`).join(" and ");
const rank = (s) => SEVERITIES.indexOf(s);
const describe = (a) =>
  `${labelOf(a)} (${a.severity}) on ${a.name} ${typeof a.range === "string" ? a.range : "(no range)"}: ${typeof a.title === "string" ? a.title : "(no title)"}`;

/** Why an exception entry is malformed, or null when it is well formed. `today` is null when unknown. */
function malformed(e, today) {
  if (!isObject(e)) return "not an object";
  for (const f of FIELDS) if (typeof e[f] !== "string" || e[f].trim() === "") return `field "${f}" missing or empty`;
  if (!GHSA.test(e.advisory)) return `"${e.advisory}" is not a GHSA id`;
  if (!isName(e.package)) return `"${e.package}" is not a package name`;
  if (!SEVERITIES.includes(e.severity)) return `"${e.severity}" is not a severity npm reports`;
  if (!isDay(e.added)) return `"${e.added}" is not a day written YYYY-MM-DD`;
  if (today !== null && e.added > today) return `written on ${e.added}, after today (${today})`;
  return null;
}

/**
 * Judge an `npm audit --json` report (auditReportVersion 2) against the exceptions. `lock` is the parsed
 * package-lock.json, `latest` the latest published version of each excepted package, `today` the UTC day.
 * Returns every reason to fail.
 */
export function judge({ audit, lock, exceptions, latest, today }) {
  if (!isObject(audit) || audit.auditReportVersion !== 2 || Object.hasOwn(audit, "error") || !isObject(audit.vulnerabilities)) {
    return { problems: ["npm audit gave no readable report (auditReportVersion 2 with a vulnerabilities object)"], advisories: [], excepted: [] };
  }
  const problems = [];
  const vulns = audit.vulnerabilities;
  if (!isDay(today)) problems.push(`today "${String(today)}" is not a day written YYYY-MM-DD`);
  if (!isObject(own(lock, "packages"))) problems.push("package-lock.json has no packages object");

  // The exceptions: well formed, and each (advisory, package) once.
  const valid = new Map();
  if (!Array.isArray(exceptions)) problems.push("the exceptions file is not a list");
  else {
    exceptions.forEach((e, i) => {
      const why = malformed(e, isDay(today) ? today : null);
      if (why) { problems.push(`exception ${i + 1}: ${why}`); return; }
      const key = `${e.advisory}|${e.package}`;
      if (valid.has(key)) { problems.push(`exception ${i + 1}: ${e.advisory} for ${e.package} is listed twice`); return; }
      valid.set(key, e);
    });
  }

  // Every distinct advisory, grouped by (advisory, package): npm may report one advisory more than once on a package.
  const groups = new Map();
  const note = (a) => {
    if (!SEVERITIES.includes(a.severity)) problems.push(`${labelOf(a)} on ${a.name}: unknown severity "${a.severity}"`);
    const k = keyOf(a);
    if (!groups.has(k)) groups.set(k, new Map());
    groups.get(k).set(JSON.stringify([a.source, a.severity, a.range, a.title]), a);
    return k;
  };
  // Every vulnerable package is followed down its `via` chain to the advisories at its root.
  const rootsOf = (start) => {
    const roots = new Set();
    const seen = new Set();
    const stack = [start];
    while (stack.length > 0) {
      const name = stack.pop();
      if (seen.has(name)) continue;
      seen.add(name);
      const entry = own(vulns, name);
      if (!isObject(entry) || !Array.isArray(entry.via)) { problems.push(`the audit names ${name} without an entry for it`); continue; }
      for (const v of entry.via) {
        if (typeof v === "string") stack.push(v);
        else if (isAdvisory(v)) roots.add(note(v));
        else problems.push(`${name}: an item of its via is neither a package name nor an advisory`);
      }
    }
    return roots;
  };
  let vulnerable = 0;
  let blockingEntries = 0;
  for (const [name, entry] of Object.entries(vulns)) {
    vulnerable++;
    const roots = rootsOf(name);
    const severity = own(entry, "severity");
    if (typeof severity !== "string") { problems.push(`${name}: no severity`); continue; }
    if (!SEVERITIES.includes(severity)) { problems.push(`${name}: unknown severity "${severity}"`); continue; }
    if (!BLOCKING.includes(severity)) continue;
    blockingEntries++;
    // npm gives a package the highest severity of what it reaches: an advisory at that level must be among its roots.
    const top = Math.max(-1, ...[...roots].flatMap((k) => [...groups.get(k).values()].map((a) => rank(a.severity))));
    if (top < rank(severity)) problems.push(`${name} is ${severity} but no advisory of severity ${severity} or above explains it`);
  }
  // The counts npm prints with the report may not list more high or critical packages than its entries do.
  const counts = own(own(audit, "metadata"), "vulnerabilities");
  const countOf = (s) => own(counts, s);
  if (!BLOCKING.every((s) => Number.isInteger(countOf(s)) && countOf(s) >= 0)) {
    problems.push("the report has no metadata.vulnerabilities counts of its high and critical packages");
  } else {
    const claimed = BLOCKING.reduce((n, s) => n + countOf(s), 0);
    if (claimed > blockingEntries) {
      problems.push(`the report's metadata counts ${claimed} package(s) of severity high or critical, its entries list ${blockingEntries}`);
    }
  }
  for (const [k, group] of groups) {
    if (valid.has(k)) continue;
    for (const a of group.values()) {
      if (BLOCKING.includes(a.severity)) {
        problems.push(`${describe(a)}; not excepted`);
      }
    }
  }

  // Each exception holds only while nothing it was written for has changed.
  const excepted = [];
  for (const [k, e] of valid) {
    const at = `exception ${e.advisory} (${e.package})`;
    const group = groups.get(k);
    if (!group) { problems.push(`${at}: the advisory is no longer in the audit; remove the exception`); continue; }
    excepted.push(e);
    const reported = [...group.values()];
    const ranges = [...new Set(reported.map((a) => String(a.range)))].sort();
    if (ranges.length !== 1 || ranges[0] !== e.range) {
      problems.push(`${at}: the vulnerable range is now ${quoted(ranges)}, the exception was written for "${e.range}"; a fixed version may exist: update ${e.package}, or renew the exception`);
    }
    const severities = [...new Set(reported.map((a) => a.severity))].sort();
    if (severities.length !== 1 || severities[0] !== e.severity) {
      problems.push(`${at}: the severity is now ${quoted(severities)}, the exception was written for "${e.severity}"; check the advisory again, then renew or remove the exception`);
    }
    const nodes = own(own(vulns, e.package), "nodes");
    if (!Array.isArray(nodes) || nodes.length === 0) problems.push(`${at}: the audit lists no installed copy of ${e.package}`);
    else {
      for (const node of nodes) {
        const v = own(own(own(lock, "packages"), node), "version");
        if (v !== e.version) problems.push(`${at}: ${String(node)} is ${typeof v === "string" ? v : "absent from package-lock.json"}, the exception covers ${e.version}`);
      }
    }
    const l = own(latest, e.package);
    if (typeof l !== "string") problems.push(`${at}: the latest published version of ${e.package} could not be read`);
    else if (l !== e.latest) {
      problems.push(`${at}: ${e.package} ${l} is now the latest version (it was ${e.latest} when the exception was written); check whether it fixes ${e.advisory}, then update ${e.package} or renew the exception`);
    }
  }
  const advisories = [...groups.values()].flatMap((g) => [...g.values()]);
  return { problems: [...new Set(problems)], advisories, excepted, vulnerable };
}

/**
 * The CLI, its effects passed in: `audit()` runs AUDIT_COMMAND, `latestOf(name)` reads the registry, `exceptions` and
 * `lock` are the parsed files, `today` the UTC day, `out` and `err` the two output streams. Resolves to the exit code.
 */
export async function run({ audit, latestOf, exceptions, lock, today, out, err }) {
  const r = audit();
  let report;
  try { report = typeof r.stdout === "string" ? JSON.parse(r.stdout) : undefined; } catch { report = undefined; }
  if (report === undefined) {
    const detail = String(r.stderr || r.error?.message || "").trim().slice(-2000);
    err(`audit gate FAILED: \`${AUDIT_COMMAND}\` printed no JSON (exit ${String(r.status)})${detail ? `:\n${detail}` : ""}`);
    return 1;
  }
  const latest = Object.create(null);
  for (const e of Array.isArray(exceptions) ? exceptions : []) {
    const name = own(e, "package");
    if (!isName(name) || Object.hasOwn(latest, name)) continue;
    const answer = await latestOf(name);
    const version = own(answer, "version");
    latest[name] = typeof version === "string" ? version : undefined;
    if (typeof version !== "string") err(`audit gate: ${name}: ${String(own(answer, "error") ?? "no version in the answer")}`);
  }
  const v = judge({ audit: report, lock, exceptions, latest, today });
  if (v.vulnerable !== undefined) {
    const counts = SEVERITIES.map((s) => [s, v.advisories.filter((a) => a.severity === s).length]).filter(([, n]) => n > 0);
    out(`audit gate: ${v.vulnerable} vulnerable package(s), ${v.advisories.length} advisory(ies) (${counts.map(([s, n]) => `${s} ${n}`).join(", ") || "none"})`);
  }
  for (const e of v.excepted) out(`  excepted: ${e.advisory} on ${e.package} ${e.version}, since ${e.added}: ${e.reason}`);
  if (v.problems.length > 0) {
    err("audit gate FAILED:");
    for (const p of v.problems) err(`  - ${p}`);
    return 1;
  }
  out("audit gate OK: no advisory of severity high or critical outside the exceptions, and every exception still holds.");
  return 0;
}

/** Whether `argv1` (process.argv[1]) names the file of `moduleUrl`, links and letter case resolved on both sides. */
export function isMain(argv1, moduleUrl) {
  if (typeof argv1 !== "string" || argv1 === "") return false;
  try {
    return realpathSync.native(resolve(argv1)) === realpathSync.native(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

/** The latest published version of `name` on the npm registry, or the reason it could not be read. */
async function latestVersion(name) {
  if (!isName(name)) return { error: "not a package name" };
  const path = name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  try {
    const res = await fetch(`https://registry.npmjs.org/${path}`, {
      headers: { accept: "application/vnd.npm.install-v1+json" },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) return { error: `registry answered HTTP ${res.status}` };
    const v = own(own(await res.json(), "dist-tags"), "latest");
    return typeof v === "string" ? { version: v } : { error: "no dist-tags.latest in the registry answer" };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

if (isMain(process.argv[1], import.meta.url)) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  process.exitCode = await run({
    // npm exits 1 when it finds anything: `run` reads the report from stdout whatever the status.
    audit: () => spawnSync(AUDIT_COMMAND, { cwd: root, shell: true, encoding: "utf8", maxBuffer: 1 << 26 }),
    latestOf: latestVersion,
    exceptions: JSON.parse(readFileSync(resolve(root, "scripts/audit-exceptions.json"), "utf8")),
    lock: JSON.parse(readFileSync(resolve(root, "package-lock.json"), "utf8")),
    today: new Date().toISOString().slice(0, 10),
    out: (line) => console.log(line),
    err: (line) => console.error(line),
  });
}
