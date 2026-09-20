import { S3Client } from "@aws-sdk/client-s3";
import { formatBytes, formatMonthlyCost } from "../cost/estimator.js";
import { scanFleet, FleetScanResult, BucketAuditResult } from "../fleet/scanner.js";
import { readStorageLensMetrics } from "../lens/reader.js";
import { S3Provider, detectProvider, getProviderDisplayName } from "../providers/detector.js";
import {
  clearScreen,
  moveTo,
  colors,
  setupTerminalHygiene,
  enableRawMode,
  TerminalStream,
} from "./terminal.js";
import { scanMultipartUploads } from "../scanner/multipart.js";
import { auditBucketLifecycle, evaluateUploadCoverage } from "../lifecycle/audit.js";
import { assessBucketBlastRadius } from "../safety/blast-radius.js";
import { createPlan, writePlanFile, Plan } from "../planner/plan.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DashboardBucketItem {
  bucket: string;
  region: string;
  status: string;
  strandedBytes: number;
  zombieCount: number;
  noncurrentBytes: number;
  noncurrentCount: number;
  eodmCount: number;
  monthlyWasteUSD: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL_BLOCKED";
  lifecycleStatus: string;
  ghostRules: string[];
  oldestUploadDate?: string;
  provider: S3Provider;
  providerDisplayName: string;
  providerNotes?: string;
}

export interface DashboardState {
  buckets: DashboardBucketItem[];
  selectedIndex: number;
  scrollOffset: number;
  maxVisibleRows: number;
  isDrawerOpen: boolean;
  statusMessage: string;
  provider: S3Provider;
  isLoading: boolean;
  totalMonthlyWasteUSD: number;
  lastPlanPath?: string;
}

export type DashboardAction =
  | { type: "NAVIGATE_UP" }
  | { type: "NAVIGATE_DOWN" }
  | { type: "TOGGLE_DRAWER" }
  | { type: "SET_STATUS"; message: string }
  | { type: "SET_BUCKETS"; buckets: DashboardBucketItem[] }
  | { type: "PLAN_CREATED"; planPath: string; bucket: string }
  | { type: "SET_LOADING"; loading: boolean };

export interface DashboardOptions {
  lensSource?: string;
  provider?: S3Provider | string;
  endpoint?: string;
  olderThanDays?: number;
  prefix?: string;
  roleName?: string;
  externalId?: string;
  outPlanDir?: string;
  stream?: TerminalStream;
  stdin?: NodeJS.ReadStream;
  signal?: AbortSignal;
  terminalWidth?: number;
  terminalHeight?: number;
  initialBuckets?: DashboardBucketItem[];
  onExit?: () => void;
}


// ─── State Reducer ────────────────────────────────────────────────────────────

export function createInitialDashboardState(
  provider: S3Provider = "aws",
  buckets: DashboardBucketItem[] = []
): DashboardState {
  const totalMonthlyWasteUSD = buckets.reduce((sum, b) => sum + b.monthlyWasteUSD, 0);
  return {
    buckets,
    selectedIndex: 0,
    scrollOffset: 0,
    maxVisibleRows: 10,
    isDrawerOpen: false,
    statusMessage: "Ready",
    provider,
    isLoading: buckets.length === 0,
    totalMonthlyWasteUSD,
  };
}

export function dashboardReducer(
  state: DashboardState,
  action: DashboardAction
): DashboardState {
  switch (action.type) {
    case "NAVIGATE_UP": {
      if (state.buckets.length === 0) return state;
      const nextIndex = Math.max(0, state.selectedIndex - 1);
      let nextOffset = state.scrollOffset;
      if (nextIndex < nextOffset) {
        nextOffset = nextIndex;
      }
      return {
        ...state,
        selectedIndex: nextIndex,
        scrollOffset: nextOffset,
      };
    }
    case "NAVIGATE_DOWN": {
      if (state.buckets.length === 0) return state;
      const nextIndex = Math.min(state.buckets.length - 1, state.selectedIndex + 1);
      let nextOffset = state.scrollOffset;
      if (nextIndex >= nextOffset + state.maxVisibleRows) {
        nextOffset = nextIndex - state.maxVisibleRows + 1;
      }
      return {
        ...state,
        selectedIndex: nextIndex,
        scrollOffset: nextOffset,
      };
    }
    case "TOGGLE_DRAWER":
      return {
        ...state,
        isDrawerOpen: !state.isDrawerOpen,
      };
    case "SET_STATUS":
      return {
        ...state,
        statusMessage: action.message,
      };
    case "SET_BUCKETS": {
      const totalWaste = action.buckets.reduce((sum, b) => sum + b.monthlyWasteUSD, 0);
      const clampedIndex = action.buckets.length > 0
        ? Math.min(state.selectedIndex, action.buckets.length - 1)
        : 0;
      return {
        ...state,
        buckets: action.buckets,
        totalMonthlyWasteUSD: totalWaste,
        selectedIndex: clampedIndex,
        scrollOffset: 0,
        isLoading: false,
        statusMessage: `Loaded ${action.buckets.length} bucket(s).`,
      };
    }
    case "PLAN_CREATED":
      return {
        ...state,
        lastPlanPath: action.planPath,
        statusMessage: `✓ Plan created for '${action.bucket}': ${action.planPath}`,
      };
    case "SET_LOADING":
      return {
        ...state,
        isLoading: action.loading,
      };
    default:
      return state;
  }
}

export function handleDashboardKey(
  state: DashboardState,
  key: string
): {
  state: DashboardState;
  shouldExit?: boolean;
  shouldCreatePlan?: boolean;
  shouldRefresh?: boolean;
} {
  switch (key) {
    case "up":
    case "k":
      return { state: dashboardReducer(state, { type: "NAVIGATE_UP" }) };
    case "down":
    case "j":
      return { state: dashboardReducer(state, { type: "NAVIGATE_DOWN" }) };
    case "enter":
      return { state: dashboardReducer(state, { type: "TOGGLE_DRAWER" }) };
    case "p":
      return { state, shouldCreatePlan: true };
    case "r":
      return { state, shouldRefresh: true };
    case "q":
    case "ctrl+c":
    case "escape":
      return { state, shouldExit: true };
    default:
      return { state };
  }
}

// ─── Data Ingestion ───────────────────────────────────────────────────────────

export async function loadDashboardData(
  s3Client: S3Client,
  options: DashboardOptions = {}
): Promise<DashboardBucketItem[]> {
  const detected = detectProvider(options.endpoint, options.provider);
  const displayName = getProviderDisplayName(detected);

  if (options.lensSource) {
    const lensMetrics = await readStorageLensMetrics(s3Client, options.lensSource);
    return lensMetrics.map((m) => {
      const riskLevel: DashboardBucketItem["riskLevel"] =
        m.wasteScore > 50 ? "HIGH" : m.wasteScore > 15 ? "MEDIUM" : "LOW";
      return {
        bucket: m.bucketName,
        region: m.region,
        status: "AUDITED",
        strandedBytes: m.incompleteMpuOlderThan7DaysBytes,
        zombieCount: m.incompleteMpuOlderThan7DaysBytes > 0 ? 1 : 0,
        noncurrentBytes: m.noncurrentBytes,
        noncurrentCount: 0,
        eodmCount: m.deleteMarkerCount,
        monthlyWasteUSD: m.estimatedMonthlyWasteUSD,
        riskLevel,
        lifecycleStatus: m.incompleteMpuOlderThan7DaysBytes > 0 ? "UNPROTECTED" : "COVERED",
        ghostRules: [],
        provider: detected,
        providerDisplayName: displayName,
      };
    });
  }

  const fleetResult: FleetScanResult = await scanFleet({
    olderThanDays: options.olderThanDays ?? 7,
    prefix: options.prefix,
    endpoint: options.endpoint,
    discoveryClient: s3Client,
  });

  return fleetResult.bucketResults.map((b) => {
    let riskLevel: DashboardBucketItem["riskLevel"] = "LOW";
    if (b.status === "ERROR") {
      riskLevel = "HIGH";
    } else if ((b.totalZombieUploads ?? 0) > 0 && !b.lifecycleAudit?.hasCoveringRule) {
      riskLevel = "HIGH";
    } else if ((b.totalZombieUploads ?? 0) > 0) {
      riskLevel = "MEDIUM";
    }

    const lifecycleStatus = b.lifecycleAudit?.ghostRulesDetected?.length
      ? "GHOST_RULE"
      : b.lifecycleAudit?.hasCoveringRule
      ? "COVERED"
      : "UNPROTECTED";

    const oldestUploadDate = b.zombieUploads?.[0]?.initiated;

    return {
      bucket: b.bucket,
      region: b.region ?? "—",
      status: b.status,
      strandedBytes: b.totalStrandedBytes ?? 0,
      zombieCount: b.totalZombieUploads ?? 0,
      noncurrentBytes: 0,
      noncurrentCount: 0,
      eodmCount: 0,
      monthlyWasteUSD: b.estimatedMonthlyWasteUSD ?? 0,
      riskLevel,
      lifecycleStatus,
      ghostRules: b.lifecycleAudit?.ghostRulesDetected ?? [],
      oldestUploadDate,
      provider: detected,
      providerDisplayName: displayName,
      providerNotes: b.lifecycleAudit?.providerNotes,
    };
  });
}

// ─── Rendering Engine ─────────────────────────────────────────────────────────

export function renderDashboard(
  state: DashboardState,
  terminalWidth = 100,
  terminalHeight = 28
): string {
  const lines: string[] = [];
  const width = Math.max(80, terminalWidth);

  // ── Header Bar ───────────────────────────────────────────────────────────────
  const title = `🛡️  s3-guardian v1.5.0 — Fleet Storage Governance Dashboard`;
  const providerLabel = `[Connected: ${getProviderDisplayName(state.provider)}]`;
  const scannedLabel = `Buckets: ${state.buckets.length}`;
  const totalWasteLabel = `Fleet Waste: ${formatMonthlyCost(state.totalMonthlyWasteUSD)}`;

  lines.push(colors.bold(colors.cyan(title)));
  lines.push(
    `${colors.green(providerLabel)}  │  ${colors.bold(scannedLabel)}  │  ${colors.yellow(totalWasteLabel)}`
  );
  lines.push(colors.gray("─".repeat(width)));

  // ── Main Pane Columns ────────────────────────────────────────────────────────
  const colBucketWidth = Math.max(24, Math.floor(width * 0.32));
  const colMpuWidth = 18;
  const colNoncurrentWidth = 16;
  const colWasteWidth = 14;
  const colRiskWidth = 12;

  const headerRow =
    "Bucket Name".padEnd(colBucketWidth) +
    "Stranded MPU".padEnd(colMpuWidth) +
    "Noncurrent".padEnd(colNoncurrentWidth) +
    "Waste/Mo".padEnd(colWasteWidth) +
    "Risk Level".padEnd(colRiskWidth);

  lines.push(colors.bold(headerRow));
  lines.push(colors.gray("─".repeat(width)));

  if (state.isLoading) {
    lines.push(colors.yellow("  ⏳ Scanning fleet storage across regions and accounts..."));
    for (let i = 0; i < state.maxVisibleRows - 1; i++) {
      lines.push("");
    }
  } else if (state.buckets.length === 0) {
    lines.push(colors.dim("  No buckets discovered or match filter."));
    for (let i = 0; i < state.maxVisibleRows - 1; i++) {
      lines.push("");
    }
  } else {
    const visibleBuckets = state.buckets.slice(
      state.scrollOffset,
      state.scrollOffset + state.maxVisibleRows
    );

    for (let i = 0; i < state.maxVisibleRows; i++) {
      const bucket = visibleBuckets[i];
      if (!bucket) {
        lines.push("");
        continue;
      }

      const globalIndex = state.scrollOffset + i;
      const isSelected = globalIndex === state.selectedIndex;

      let nameDisplay = bucket.bucket;
      if (nameDisplay.length > colBucketWidth - 2) {
        nameDisplay = nameDisplay.slice(0, colBucketWidth - 4) + "..";
      }

      const mpuDisplay = `${formatBytes(bucket.strandedBytes)} (${bucket.zombieCount})`;
      const noncurrentDisplay = bucket.eodmCount > 0
        ? `${formatBytes(bucket.noncurrentBytes)} (${bucket.eodmCount} DMs)`
        : formatBytes(bucket.noncurrentBytes);
      const wasteDisplay = formatMonthlyCost(bucket.monthlyWasteUSD);

      let riskFormatted: string = bucket.riskLevel;
      if (bucket.riskLevel === "LOW") {
        riskFormatted = colors.green("LOW");
      } else if (bucket.riskLevel === "MEDIUM") {
        riskFormatted = colors.yellow("MEDIUM");
      } else if (bucket.riskLevel === "HIGH" || bucket.riskLevel === "CRITICAL_BLOCKED") {
        riskFormatted = colors.red(bucket.riskLevel);
      }

      const rowText =
        (isSelected ? "▶ " : "  ") +
        nameDisplay.padEnd(colBucketWidth - 2) +
        mpuDisplay.padEnd(colMpuWidth) +
        noncurrentDisplay.padEnd(colNoncurrentWidth) +
        wasteDisplay.padEnd(colWasteWidth) +
        riskFormatted;

      if (isSelected) {
        lines.push(colors.inverse(colors.bold(rowText)));
      } else {
        lines.push(rowText);
      }
    }
  }

  lines.push(colors.gray("─".repeat(width)));

  // ── Selected Bucket Inspector Drawer ─────────────────────────────────────────
  const selectedBucket = state.buckets[state.selectedIndex];
  if (selectedBucket) {
    const drawerIndicator = state.isDrawerOpen ? "[▲ Expanded Inspector]" : "[▼ Detail Inspector]";
    lines.push(colors.bold(colors.cyan(`┌─ ${drawerIndicator} : ${selectedBucket.bucket} `) + "─".repeat(Math.max(0, width - selectedBucket.bucket.length - 30)) + "┐"));

    const oldest = selectedBucket.oldestUploadDate
      ? new Date(selectedBucket.oldestUploadDate).toISOString().split("T")[0]
      : "None";
    const eodm = selectedBucket.eodmCount > 0 ? String(selectedBucket.eodmCount) : "0";

    lines.push(
      `│ Region: ${selectedBucket.region.padEnd(16)} │ Provider: ${selectedBucket.providerDisplayName.padEnd(18)} │ Status: ${selectedBucket.status.padEnd(14)} │`
    );
    lines.push(
      `│ Oldest Upload: ${oldest.padEnd(10)} │ EODM Count: ${eodm.padEnd(16)} │ Stranded: ${formatBytes(selectedBucket.strandedBytes).padEnd(12)} │`
    );
    lines.push(
      `│ Lifecycle: ${selectedBucket.lifecycleStatus.padEnd(13)} │ Waste: ${formatMonthlyCost(selectedBucket.monthlyWasteUSD).padEnd(21)} │ Risk: ${selectedBucket.riskLevel.padEnd(16)} │`
    );

    if (state.isDrawerOpen && selectedBucket.ghostRules.length > 0) {
      lines.push(colors.red(`│ ⚠️  Ghost Rules Detected: ${selectedBucket.ghostRules[0].slice(0, width - 32)} │`));
    }

    lines.push("└" + "─".repeat(width - 2) + "┘");
  } else {
    lines.push(colors.dim("  [No bucket selected]"));
  }

  // ── Footer Hotkeys & Status Line ─────────────────────────────────────────────
  lines.push(colors.dim(`Status: ${state.statusMessage}`));
  const hotkeys = `[↑/↓, j/k] Navigate  │  [Enter] Inspect  │  [P] Create Plan  │  [R] Refresh  │  [Q] Quit`;
  lines.push(colors.bold(colors.cyan(hotkeys)));

  return lines.join("\n");
}

// ─── Dashboard Runner ─────────────────────────────────────────────────────────

export async function launchDashboard(
  s3Client: S3Client,
  options: DashboardOptions = {}
): Promise<void> {
  const stream = options.stream ?? process.stdout;
  const stdin = options.stdin ?? process.stdin;

  const detected = detectProvider(options.endpoint, options.provider);
  let state = createInitialDashboardState(detected, options.initialBuckets ?? []);

  // Setup screen hygiene and restore hooks
  const cleanupHygiene = setupTerminalHygiene(stream);

  const redraw = () => {
    clearScreen(stream);
    moveTo(1, 1, stream);
    const rendered = renderDashboard(
      state,
      process.stdout.columns || options.terminalWidth || 100,
      process.stdout.rows || options.terminalHeight || 28
    );
    stream.write(rendered + "\n");
  };

  // Initial render
  redraw();

  // Load buckets asynchronously if not provided
  if (!options.initialBuckets || options.initialBuckets.length === 0) {
    loadDashboardData(s3Client, options)
      .then((buckets) => {
        state = dashboardReducer(state, { type: "SET_BUCKETS", buckets });
        redraw();
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        state = dashboardReducer(state, { type: "SET_STATUS", message: `Error loading: ${msg}` });
        state = dashboardReducer(state, { type: "SET_LOADING", loading: false });
        redraw();
      });
  }

  return new Promise<void>((resolve) => {
    let closed = false;
    let disableRaw: (() => void) | undefined;

    const cleanup = () => {
      if (closed) return;
      closed = true;
      if (disableRaw) {
        disableRaw();
      }
      cleanupHygiene();
      options.onExit?.();
      resolve();
    };

    if (options.signal) {
      if (options.signal.aborted) {
        cleanup();
        return;
      }
      options.signal.addEventListener("abort", () => cleanup(), { once: true });
    }

    disableRaw = enableRawMode(async (key) => {
      const result = handleDashboardKey(state, key);
      state = result.state;

      if (result.shouldExit) {
        cleanup();
        return;
      }

      if (result.shouldRefresh) {
        state = dashboardReducer(state, { type: "SET_LOADING", loading: true });
        state = dashboardReducer(state, { type: "SET_STATUS", message: "Refreshing fleet data..." });
        redraw();

        loadDashboardData(s3Client, options)
          .then((buckets) => {
            state = dashboardReducer(state, { type: "SET_BUCKETS", buckets });
            redraw();
          })
          .catch((err: unknown) => {
            const msg = err instanceof Error ? err.message : String(err);
            state = dashboardReducer(state, { type: "SET_STATUS", message: `Refresh failed: ${msg}` });
            state = dashboardReducer(state, { type: "SET_LOADING", loading: false });
            redraw();
          });
        return;
      }

      if (result.shouldCreatePlan) {
        const selected = state.buckets[state.selectedIndex];
        if (selected) {
          state = dashboardReducer(state, {
            type: "SET_STATUS",
            message: `Generating plan for '${selected.bucket}'...`,
          });
          redraw();

          try {
            const planFile = options.outPlanDir
              ? `${options.outPlanDir}/plan-${selected.bucket}.json`
              : `plan-${selected.bucket}.json`;

            const [scanResult, lifecycleAudit] = await Promise.all([
              scanMultipartUploads(s3Client, selected.bucket, {
                olderThanDays: options.olderThanDays ?? 7,
                endpoint: options.endpoint,
                prefix: options.prefix,
              }),
              auditBucketLifecycle(s3Client, selected.bucket, options.endpoint),
            ]);

            const now = new Date();
            const enrichedUploads = scanResult.uploads.map((u) => {
              const coverage = evaluateUploadCoverage(
                u.key,
                new Date(u.initiated),
                lifecycleAudit.mpuRules ?? [],
                now
              );
              return { ...u, lifecycleStatus: coverage.status };
            });

            const blastTargets = enrichedUploads.map((u) => ({
              key: u.key,
              timestamp: u.initiated,
            }));

            const blastAudit = await assessBucketBlastRadius(s3Client, selected.bucket, {
              targets: blastTargets,
              provider: selected.provider,
              now,
            });

            const plan: Plan = createPlan({
              bucket: selected.bucket,
              endpoint: options.endpoint ?? null,
              olderThanDays: options.olderThanDays ?? 7,
              uploads: enrichedUploads,
              lifecycleAudit,
              blastRadiusAudit: blastAudit,
            });

            await writePlanFile(planFile, plan);
            state = dashboardReducer(state, {
              type: "PLAN_CREATED",
              planPath: planFile,
              bucket: selected.bucket,
            });
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            state = dashboardReducer(state, {
              type: "SET_STATUS",
              message: `Plan creation failed: ${msg}`,
            });
          }
        }
      }

      redraw();
    }, stdin);
  });
}
