/**
 * Harness — tool REGISTRY.
 *
 * The registry is DATA (`HARNESS_TOOLS`) so the closed allowlist and the descriptions are inspectable
 * without standing up a server (the oracle of registry.test.ts and the vocab oracle read this table directly).
 *
 * `ALLOWED_TOOL_NAMES` is the closed universe of the surface (`attest`·`gate`·`cascade`·`calibrate`·`judge`). `gate`
 * came first, then `cascade`, `attest` and `calibrate`; `judge`, the link to Genkan's kernel, came last. registry.test.ts
 * asserts BOTH: (a) the CLOSED ALLOWLIST `REGISTERED_TOOL_NAMES ⊆ ALLOWED_TOOL_NAMES`, and (b) the EXACT set
 * `{attest,gate,cascade,calibrate,judge}`. Plus a static side-effect scan of `src/tools/**`.
 *
 * Like everything under `src/tools/`, this file does no I/O: it imports the frozen-schema PROJECTION (`../schema-projection.ts`,
 * which owns a `node:fs` read at load, as `../policy-committed.ts` does for the committed tables) and the pure gate logic; it
 * never touches `node:fs`/`node:net`/`node:child_process`/`fetch`/`process.env`. The kernel runner of `judge` is injected
 * by the entry point (src/kernel.ts, through server.ts), never imported here.
 */
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import type { Prediction, AttestedPrice } from "@monark/contracts";
import { toolInputStandardSchema, toolOutputStandardSchema, TOOL_INPUT_SCHEMA, TOOL_OUTPUT_SCHEMA } from "../schema-projection.ts";
import { cascadeInputStandardSchema, cascadeOutputStandardSchema, CASCADE_INPUT_SCHEMA, CASCADE_OUTPUT_SCHEMA } from "../schema-projection.ts";
import type { Json } from "../schema-projection.ts";
import { attestInputStandardSchema, attestOutputStandardSchema, ATTEST_INPUT_SCHEMA, ATTEST_OUTPUT_SCHEMA } from "../schema-projection.ts";
import { calibrateInputStandardSchema, calibrateOutputStandardSchema, CALIBRATE_INPUT_SCHEMA, CALIBRATE_OUTPUT_SCHEMA } from "../schema-projection.ts";
import { runGateExplained, honestyText, aciHonestyText, gateVerdictSummary, toolErrorCode, ERROR_CODE_META_KEY, GATE_TOOL_NAME, GATE_TOOL_DESCRIPTION, type HarnessParams, type RunGateOptions } from "./gate.ts";
import { runCascade, cascadeHonestyText, CASCADE_TOOL_NAME, CASCADE_TOOL_DESCRIPTION, type CascadeInput } from "./cascade.ts";
import { runAttest, attestHonestyText, ATTEST_TOOL_NAME, ATTEST_TOOL_DESCRIPTION } from "./attest.ts";
import { runCalibrate, calibrateHonestyText, calibrateVerdictSummary, CALIBRATE_TOOL_NAME, CALIBRATE_TOOL_DESCRIPTION, type CalibrateInput } from "./calibrate.ts";
import { judgeInputStandardSchema, judgeOutputStandardSchema, JUDGE_INPUT_SCHEMA, JUDGE_OUTPUT_SCHEMA } from "../schema-projection.ts";
import { runJudgeExplained, judgeHonestyText, judgeVerdictSummary, JUDGE_TOOL_NAME, JUDGE_TOOL_DESCRIPTION, type JudgeInput, type KernelRunner } from "./judge.ts";

/** Closed universe of the tool surface (four tools, then `judge`, the fifth). */
export const ALLOWED_TOOL_NAMES = ["attest", "gate", "cascade", "calibrate", "judge"] as const;
export type AllowedToolName = (typeof ALLOWED_TOOL_NAMES)[number];

/** The tool input envelope: frozen `Prediction` + non-frozen params + OPTIONAL frozen `AttestedPrice`. */
export interface GateEnvelope {
  readonly prediction: Prediction;
  readonly params: HarnessParams;
  /** OPTIONAL caller-carried attestation: `required` stays `{prediction,params}`; absent ⇒ byte-identical behaviour. */
  readonly attested?: AttestedPrice;
}

export interface HarnessToolDescriptor {
  readonly name: AllowedToolName;
  readonly description: string;
  readonly inputSchemaJson: Json;
  readonly outputSchemaJson: Json;
  /** Per-tool projected SDK schemas: each tool owns its own input/output shape (gate: envelope -> GateDecision;
   *  cascade: FinancialSystem -> Prediction; attest: no input -> its attested testimony; calibrate: scores -> its envelope;
   *  judge: envelope, order and limits -> its verdict). registerTools hardcodes none. */
  readonly inputStandardSchema: StandardSchemaWithJSON;
  readonly outputStandardSchema: StandardSchemaWithJSON;
  /** Executes the tool: caller-carried args (validated at the SDK boundary) -> structured content + text. `ctx.nowMs`
   *  is the current instant injected by the entry point (src/); `gate` and `judge` read it. `ctx.kernel`
   *  is the kernel runner, which only `judge` reads. `gate` and `calibrate` answer at once; `judge` answers when its kernel
   *  has (a promise), and the entry points await both alike. */
  readonly run: (args: unknown, ctx?: ToolRunContext) => ToolRunResult | Promise<ToolRunResult>;
}

/** What a tool run answers: the structured content and the text of `content`. */
export interface ToolRunResult {
  readonly text: string;
  readonly structured: Record<string, unknown>;
}

/** What an entry point injects into a tool run: the current instant, read in src/, never under src/tools/; and the
 *  runner of Genkan's kernel (src/kernel.ts), started in src/, never under src/tools/. */
export type ToolRunContext = Pick<RunGateOptions, "nowMs"> & { readonly kernel?: KernelRunner };

/** The tools registered (`gate`, `cascade`, `attest`, `calibrate`, then `judge`). */
export const HARNESS_TOOLS: readonly HarnessToolDescriptor[] = [
  {
    name: GATE_TOOL_NAME,
    description: GATE_TOOL_DESCRIPTION,
    inputSchemaJson: TOOL_INPUT_SCHEMA,
    outputSchemaJson: TOOL_OUTPUT_SCHEMA,
    inputStandardSchema: toolInputStandardSchema,
    outputStandardSchema: toolOutputStandardSchema,
    run: (args, ctx) => {
      const env = args as GateEnvelope;
      const { decision, aci } = runGateExplained(env.prediction, env.params, env.attested, ctx);
      // structuredContent = the closed GateDecision ONLY; honesty prose rides in `content` text.
      // The honesty text is keyed on the PRESENCE of a BYO calibration, not task_class alone, and on the resolved cell; with the online
      // level of a class, it is the level's text and figures, which the closed decision cannot carry. The
      // verdict summary (a delivery aid for text-only clients, derived from `decision`) follows the prose.
      const prose = aci === undefined ? honestyText(env.prediction.task_class, decision.verdict.cell_key ?? env.prediction.predictor_id, env.params.calibration !== undefined) : aciHonestyText(aci);
      const text = `${prose} ${gateVerdictSummary(decision)}`;
      return { text, structured: decision as unknown as Record<string, unknown> };
    },
  },
  {
    name: CASCADE_TOOL_NAME,
    description: CASCADE_TOOL_DESCRIPTION,
    inputSchemaJson: CASCADE_INPUT_SCHEMA,
    outputSchemaJson: CASCADE_OUTPUT_SCHEMA,
    inputStandardSchema: cascadeInputStandardSchema,
    outputStandardSchema: cascadeOutputStandardSchema,
    run: (args) => {
      const input = args as CascadeInput;
      const prediction = runCascade(input);
      // structuredContent = the closed Prediction ONLY (K-1); honesty prose rides in `content` text.
      return { text: cascadeHonestyText(), structured: prediction as unknown as Record<string, unknown> };
    },
  },
  {
    name: ATTEST_TOOL_NAME,
    description: ATTEST_TOOL_DESCRIPTION,
    inputSchemaJson: ATTEST_INPUT_SCHEMA,
    outputSchemaJson: ATTEST_OUTPUT_SCHEMA,
    inputStandardSchema: attestInputStandardSchema,
    outputStandardSchema: attestOutputStandardSchema,
    run: () => {
      // No caller input: the witness is the committed internal fixture (ADR-M005 H3).
      const output = runAttest();
      // structuredContent = the K-1 envelope {price, provenance, label}; `price` alone is the frozen
      // contract, label/provenance ride OUTSIDE it. Honesty prose rides in `content` text (K-1).
      return { text: attestHonestyText(), structured: output as unknown as Record<string, unknown> };
    },
  },
  {
    name: CALIBRATE_TOOL_NAME,
    description: CALIBRATE_TOOL_DESCRIPTION,
    inputSchemaJson: CALIBRATE_INPUT_SCHEMA,
    outputSchemaJson: CALIBRATE_OUTPUT_SCHEMA,
    inputStandardSchema: calibrateInputStandardSchema,
    outputStandardSchema: calibrateOutputStandardSchema,
    run: (args) => {
      const input = args as CalibrateInput;
      const result = runCalibrate(input);
      // structuredContent = the calibrate envelope {qhat,n,alpha,method,scores_sha256,label,reason}; the
      // honesty label rides IN the output and ALSO in `content` text,
      // followed by the verdict summary (a delivery aid for text-only clients, derived from `result`).
      const text = `${calibrateHonestyText()} ${calibrateVerdictSummary(result)}`;
      return { text, structured: result as unknown as Record<string, unknown> };
    },
  },
  {
    name: JUDGE_TOOL_NAME,
    description: JUDGE_TOOL_DESCRIPTION,
    inputSchemaJson: JUDGE_INPUT_SCHEMA,
    outputSchemaJson: JUDGE_OUTPUT_SCHEMA,
    inputStandardSchema: judgeInputStandardSchema,
    outputStandardSchema: judgeOutputStandardSchema,
    run: async (args, ctx) => {
      const { output, aci } = await runJudgeExplained(args as JudgeInput, ctx);
      // structuredContent = {decision, gate_error, kernel_verdict, kernel_reason, reduce_only, kernel_request_sha256}; the honesty prose and
      // the verdict summary (derived from the output) ride in `content` text, with between them, on the online level of a class, its text and figures.
      const level = aci === undefined ? "" : `${aciHonestyText(aci)} `;
      return { text: `${judgeHonestyText(output)} ${level}${judgeVerdictSummary(output)}`, structured: output as unknown as Record<string, unknown> };
    },
  },
];

/** The names actually registered, in registry order: `["gate","cascade","attest","calibrate","judge"]`. */
export const REGISTERED_TOOL_NAMES: readonly string[] = HARNESS_TOOLS.map((t) => t.name);

/**
 * Register every harness tool on a fresh `McpServer` instance (the stateless per-request factory).
 * Input/output are the PROJECTED frozen schemas; the SDK enforces `additionalProperties:false`
 * at the boundary (measured), and `runGate` re-asserts the closed contract on the way out.
 * `clock` is the entry point's clock (server.ts): read per call, never here by itself; absent,
 * the tools run without `nowMs`. `kernel` is the runner of Genkan's kernel (server.ts hands src/kernel.ts's); absent, `judge`
 * denies every order `unavailable`. A tool error keeps the SDK's own error result, first content byte-identical (the
 * error message), and adds its stable code in `_meta`; any other throw takes the SDK path unchanged.
 */
export function registerTools(server: McpServer, clock?: () => number, kernel?: KernelRunner): void {
  for (const tool of HARNESS_TOOLS) {
    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputStandardSchema,
        outputSchema: tool.outputStandardSchema,
      },
      async (args: unknown) => {
        try {
          const ctx: ToolRunContext = { ...(clock === undefined ? {} : { nowMs: clock() }), ...(kernel === undefined ? {} : { kernel }) };
          const { text, structured } = await tool.run(args, ctx);
          return { content: [{ type: "text" as const, text }], structuredContent: structured };
        } catch (error) {
          const code = toolErrorCode(error);
          if (code === undefined || !(error instanceof Error)) throw error;
          return { content: [{ type: "text" as const, text: error.message }], isError: true, _meta: { [ERROR_CODE_META_KEY]: code } };
        }
      },
    );
  }
}
