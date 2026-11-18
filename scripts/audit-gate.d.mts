// scripts/audit-gate.d.mts — type surface of what scripts/audit-gate.mjs exports, for the root test
// test/audit-gate.test.ts. Runtime implementation = audit-gate.mjs; Node ignores this file.

/** One entry of scripts/audit-exceptions.json. */
export interface AuditException {
  /** The advisory, by its GHSA id. */
  advisory: string;
  /** The vulnerable package the advisory names. */
  package: string;
  /** The installed version of that package the exception covers. */
  version: string;
  /** The advisory's severity when the exception was written. */
  severity: string;
  /** The advisory's vulnerable range when the exception was written. */
  range: string;
  /** The latest published version of the package when the exception was written. */
  latest: string;
  /** The day the exception was written, YYYY-MM-DD (UTC). */
  added: string;
  /** Why the advisory is accepted for now. */
  reason: string;
}

/** An advisory as `npm audit --json` reports it in the `via` of the package it names. */
export interface AuditAdvisory {
  source?: number;
  name: string;
  title?: string;
  url?: string;
  severity: string;
  range?: string;
}

export interface Verdict {
  /** Every reason to fail; empty when the audit passes. */
  problems: string[];
  /** The advisories found in the report, of any severity. */
  advisories: AuditAdvisory[];
  /** The exceptions that matched an advisory of the report. */
  excepted: AuditException[];
  /** The number of vulnerable packages in the report (absent when the report is unreadable). */
  vulnerable?: number;
}

/** What running AUDIT_COMMAND gives back (the shape of `spawnSync` with an encoding). */
export interface AuditRun {
  stdout: string;
  stderr?: string;
  status: number | null;
  error?: Error;
}

/** The effects of the CLI, passed in. */
export interface CliDeps {
  audit: () => AuditRun;
  latestOf: (name: string) => Promise<{ version: string } | { error: string }>;
  exceptions: unknown;
  lock: unknown;
  today: string;
  out: (line: string) => void;
  err: (line: string) => void;
}

/** The command the CLI runs: the whole tree, development dependencies included. */
export const AUDIT_COMMAND: string;
/** The severities that fail the audit. */
export const BLOCKING: readonly string[];
/** The severities npm reports; any other one is refused. */
export const SEVERITIES: readonly string[];

/** Judge an `npm audit --json` report against the exceptions. Pure: no file, process or network access. */
export function judge(input: {
  audit: unknown;
  lock: unknown;
  exceptions: unknown;
  latest: Readonly<Record<string, string>>;
  today: string;
}): Verdict;

/** The CLI with its effects passed in; resolves to the exit code (0 pass, 1 fail). */
export function run(deps: CliDeps): Promise<number>;

/** Whether `argv1` (process.argv[1]) names the file of `moduleUrl`, links and letter case resolved on both sides. */
export function isMain(argv1: string | undefined, moduleUrl: string): boolean;
