import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  GetBucketLifecycleConfigurationCommand,
  GetObjectCommand,
} from "@aws-sdk/client-s3";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import {
  DashboardBucketItem,
  DashboardState,
  createInitialDashboardState,
  dashboardReducer,
  handleDashboardKey,
  renderDashboard,
  loadDashboardData,
  launchDashboard,
} from "../src/tui/dashboard.js";
import { TerminalStream } from "../src/tui/terminal.js";

const s3Mock = mockClient(S3Client);

describe("Dashboard State & Reducer", () => {
  const sampleBuckets: DashboardBucketItem[] = [
    {
      bucket: "prod-data-archive",
      region: "us-east-1",
      status: "AUDITED",
      strandedBytes: 10737418240, // 10 GiB
      zombieCount: 3,
      noncurrentBytes: 5368709120, // 5 GiB
      noncurrentCount: 12,
      eodmCount: 4,
      monthlyWasteUSD: 0.23,
      riskLevel: "HIGH",
      lifecycleStatus: "UNPROTECTED",
      ghostRules: ["Ghost rule with invalid tag"],
      oldestUploadDate: "2026-01-01T00:00:00.000Z",
      provider: "aws",
      providerDisplayName: "Amazon S3",
    },
    {
      bucket: "staging-logs",
      region: "eu-west-1",
      status: "AUDITED",
      strandedBytes: 2147483648, // 2 GiB
      zombieCount: 1,
      noncurrentBytes: 0,
      noncurrentCount: 0,
      eodmCount: 0,
      monthlyWasteUSD: 0.05,
      riskLevel: "LOW",
      lifecycleStatus: "COVERED",
      ghostRules: [],
      oldestUploadDate: "2026-02-01T00:00:00.000Z",
      provider: "aws",
      providerDisplayName: "Amazon S3",
    },
    {
      bucket: "backup-vault",
      region: "us-west-2",
      status: "AUDITED",
      strandedBytes: 5368709120,
      zombieCount: 2,
      noncurrentBytes: 0,
      noncurrentCount: 0,
      eodmCount: 0,
      monthlyWasteUSD: 0.12,
      riskLevel: "MEDIUM",
      lifecycleStatus: "COVERED",
      ghostRules: [],
      provider: "aws",
      providerDisplayName: "Amazon S3",
    },
  ];

  it("createInitialDashboardState initializes defaults correctly", () => {
    const stateEmpty = createInitialDashboardState();
    expect(stateEmpty.selectedIndex).toBe(0);
    expect(stateEmpty.scrollOffset).toBe(0);
    expect(stateEmpty.isDrawerOpen).toBe(false);
    expect(stateEmpty.isLoading).toBe(true);
    expect(stateEmpty.totalMonthlyWasteUSD).toBe(0);
    expect(stateEmpty.statusMessage).toBe("Ready");

    const stateWithBuckets = createInitialDashboardState("wasabi", sampleBuckets);
    expect(stateWithBuckets.provider).toBe("wasabi");
    expect(stateWithBuckets.isLoading).toBe(false);
    expect(stateWithBuckets.totalMonthlyWasteUSD).toBeCloseTo(0.40, 2);
  });

  it("navigates down and up with clamping and scrolling", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);
    state.maxVisibleRows = 2; // enforce scrolling with 2 visible rows

    // Navigate down to item 1
    state = dashboardReducer(state, { type: "NAVIGATE_DOWN" });
    expect(state.selectedIndex).toBe(1);
    expect(state.scrollOffset).toBe(0);

    // Navigate down to item 2 (triggers scrollOffset shift)
    state = dashboardReducer(state, { type: "NAVIGATE_DOWN" });
    expect(state.selectedIndex).toBe(2);
    expect(state.scrollOffset).toBe(1);

    // Navigate down again (clamps at last item)
    state = dashboardReducer(state, { type: "NAVIGATE_DOWN" });
    expect(state.selectedIndex).toBe(2);
    expect(state.scrollOffset).toBe(1);

    // Navigate up to item 1
    state = dashboardReducer(state, { type: "NAVIGATE_UP" });
    expect(state.selectedIndex).toBe(1);
    expect(state.scrollOffset).toBe(1);

    // Navigate up to item 0 (triggers scrollOffset shift)
    state = dashboardReducer(state, { type: "NAVIGATE_UP" });
    expect(state.selectedIndex).toBe(0);
    expect(state.scrollOffset).toBe(0);

    // Navigate up again (clamps at 0)
    state = dashboardReducer(state, { type: "NAVIGATE_UP" });
    expect(state.selectedIndex).toBe(0);
    expect(state.scrollOffset).toBe(0);
  });

  it("handles navigation gracefully when bucket list is empty", () => {
    const emptyState = createInitialDashboardState("aws", []);
    const down = dashboardReducer(emptyState, { type: "NAVIGATE_DOWN" });
    expect(down.selectedIndex).toBe(0);
    const up = dashboardReducer(emptyState, { type: "NAVIGATE_UP" });
    expect(up.selectedIndex).toBe(0);
  });

  it("toggles detail drawer", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);
    expect(state.isDrawerOpen).toBe(false);

    state = dashboardReducer(state, { type: "TOGGLE_DRAWER" });
    expect(state.isDrawerOpen).toBe(true);

    state = dashboardReducer(state, { type: "TOGGLE_DRAWER" });
    expect(state.isDrawerOpen).toBe(false);
  });

  it("updates status message and loading state", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);

    state = dashboardReducer(state, { type: "SET_STATUS", message: "Fetching updates..." });
    expect(state.statusMessage).toBe("Fetching updates...");

    state = dashboardReducer(state, { type: "SET_LOADING", loading: true });
    expect(state.isLoading).toBe(true);
  });

  it("updates buckets list and handles index clamping", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);
    state.selectedIndex = 2;

    const smallerList = [sampleBuckets[0]!];
    state = dashboardReducer(state, { type: "SET_BUCKETS", buckets: smallerList });

    expect(state.buckets.length).toBe(1);
    expect(state.selectedIndex).toBe(0); // clamped to 0
    expect(state.totalMonthlyWasteUSD).toBeCloseTo(0.23, 2);
    expect(state.isLoading).toBe(false);
    expect(state.statusMessage).toContain("Loaded 1 bucket(s)");
  });

  it("handles PLAN_CREATED action", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);
    state = dashboardReducer(state, {
      type: "PLAN_CREATED",
      planPath: "plan-prod-data-archive.json",
      bucket: "prod-data-archive",
    });

    expect(state.lastPlanPath).toBe("plan-prod-data-archive.json");
    expect(state.statusMessage).toContain("Plan created for 'prod-data-archive'");
  });
});

describe("Dashboard Key Handling (handleDashboardKey)", () => {
  const state = createInitialDashboardState("aws", [
    {
      bucket: "test-bucket",
      region: "us-east-1",
      status: "AUDITED",
      strandedBytes: 1000,
      zombieCount: 1,
      noncurrentBytes: 0,
      noncurrentCount: 0,
      eodmCount: 0,
      monthlyWasteUSD: 0.1,
      riskLevel: "LOW",
      lifecycleStatus: "COVERED",
      ghostRules: [],
      provider: "aws",
      providerDisplayName: "Amazon S3",
    },
  ]);

  it("handles arrow keys and vim keybindings (j/k)", () => {
    expect(handleDashboardKey(state, "down").state.selectedIndex).toBe(0);
    expect(handleDashboardKey(state, "j").state.selectedIndex).toBe(0);
    expect(handleDashboardKey(state, "up").state.selectedIndex).toBe(0);
    expect(handleDashboardKey(state, "k").state.selectedIndex).toBe(0);
  });

  it("handles enter to toggle drawer", () => {
    const res = handleDashboardKey(state, "enter");
    expect(res.state.isDrawerOpen).toBe(true);
  });

  it("handles p to trigger plan creation", () => {
    const res = handleDashboardKey(state, "p");
    expect(res.shouldCreatePlan).toBe(true);
  });

  it("handles r to trigger data refresh", () => {
    const res = handleDashboardKey(state, "r");
    expect(res.shouldRefresh).toBe(true);
  });

  it("handles q, escape, and ctrl+c to trigger exit", () => {
    expect(handleDashboardKey(state, "q").shouldExit).toBe(true);
    expect(handleDashboardKey(state, "escape").shouldExit).toBe(true);
    expect(handleDashboardKey(state, "ctrl+c").shouldExit).toBe(true);
  });

  it("ignores unknown keys", () => {
    const res = handleDashboardKey(state, "x");
    expect(res.state).toEqual(state);
    expect(res.shouldExit).toBeUndefined();
    expect(res.shouldCreatePlan).toBeUndefined();
  });
});

describe("Dashboard Renderer (renderDashboard)", () => {
  const sampleBuckets: DashboardBucketItem[] = [
    {
      bucket: "enterprise-warehouse-bucket-very-long-name-to-test-truncation",
      region: "us-east-1",
      status: "AUDITED",
      strandedBytes: 10737418240, // 10 GiB
      zombieCount: 5,
      noncurrentBytes: 1073741824, // 1 GiB
      noncurrentCount: 10,
      eodmCount: 8,
      monthlyWasteUSD: 1.5,
      riskLevel: "HIGH",
      lifecycleStatus: "UNPROTECTED",
      ghostRules: ["Overlapping noncurrent rule without tag filter"],
      oldestUploadDate: "2026-01-15T12:00:00.000Z",
      provider: "aws",
      providerDisplayName: "Amazon S3",
    },
  ];

  it("renders header bar with title, provider, bucket count, and fleet waste", () => {
    const state = createInitialDashboardState("aws", sampleBuckets);
    const rendered = renderDashboard(state, 120, 30);

    expect(rendered).toContain("s3-guardian v1.5.0");
    expect(rendered).toContain("Fleet Storage Governance Dashboard");
    expect(rendered).toContain("Connected: AWS S3");
    expect(rendered).toContain("Buckets: 1");
    expect(rendered).toContain("Fleet Waste: $1.50/mo");
  });

  it("renders column headers and table rows with selection indicator", () => {
    const state = createInitialDashboardState("aws", sampleBuckets);
    const rendered = renderDashboard(state, 120, 30);

    expect(rendered).toContain("Bucket Name");
    expect(rendered).toContain("Stranded MPU");
    expect(rendered).toContain("Noncurrent");
    expect(rendered).toContain("Waste/Mo");
    expect(rendered).toContain("Risk Level");

    // Selected row starts with ▶
    expect(rendered).toContain("▶ ");
    expect(rendered).toContain("10.00 GB (5)");
    expect(rendered).toContain("1.00 GB (8 DMs)");
    expect(rendered).toContain("$1.50/mo");
    expect(rendered).toContain("HIGH");
  });

  it("renders detail inspector drawer and shows ghost rule warnings when open", () => {
    let state = createInitialDashboardState("aws", sampleBuckets);
    state.isDrawerOpen = true;

    const rendered = renderDashboard(state, 120, 30);
    expect(rendered).toContain("[▲ Expanded Inspector]");
    expect(rendered).toContain("Region: us-east-1");
    expect(rendered).toContain("Provider: Amazon S3");
    expect(rendered).toContain("Oldest Upload: 2026-01-15");
    expect(rendered).toContain("EODM Count: 8");
    expect(rendered).toContain("Lifecycle: UNPROTECTED");
    expect(rendered).toContain("Ghost Rules Detected");
  });

  it("renders loading banner when state is loading", () => {
    const loadingState = createInitialDashboardState("aws", []);
    loadingState.isLoading = true;

    const rendered = renderDashboard(loadingState, 120, 30);
    expect(rendered).toContain("Scanning fleet storage");
  });

  it("renders empty state message when no buckets match", () => {
    const emptyState = createInitialDashboardState("aws", []);
    emptyState.isLoading = false;

    const rendered = renderDashboard(emptyState, 120, 30);
    expect(rendered).toContain("No buckets discovered or match filter");
  });

  it("renders footer with status message and hotkeys", () => {
    const state = createInitialDashboardState("aws", sampleBuckets);
    state.statusMessage = "All systems operational";

    const rendered = renderDashboard(state, 120, 30);
    expect(rendered).toContain("Status: All systems operational");
    expect(rendered).toContain("[↑/↓, j/k] Navigate");
    expect(rendered).toContain("[Enter] Inspect");
    expect(rendered).toContain("[P] Create Plan");
    expect(rendered).toContain("[R] Refresh");
    expect(rendered).toContain("[Q] Quit");
  });
});

describe("Data Ingestion (loadDashboardData)", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("loads metrics from Storage Lens export when lensSource is provided", async () => {
    const csvContent = [
      "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
      "BUCKET,111111111111,lens-target-bucket,us-east-1,1000000000000,2147483648,15,5368709120,5368709120",
    ].join("\n");

    const s3Client = new S3Client({});
    s3Mock.on(GetObjectCommand).resolves({
      Body: Readable.from([csvContent]) as any,
    });

    const items = await loadDashboardData(s3Client, {
      lensSource: "s3://lens-bucket/export.csv",
    });

    expect(items.length).toBe(1);
    expect(items[0]!.bucket).toBe("lens-target-bucket");
    expect(items[0]!.region).toBe("us-east-1");
    expect(items[0]!.strandedBytes).toBe(5368709120);
    expect(items[0]!.eodmCount).toBe(15);
    expect(items[0]!.monthlyWasteUSD).toBeGreaterThan(0);
  });

  it("loads fleet scan data across buckets when lensSource is omitted", async () => {
    const s3Client = new S3Client({});
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "audit-test-bucket", CreationDate: new Date() }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-west-2",
    });
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [
        {
          Key: "large-data.tar",
          UploadId: "u123",
          Initiated: new Date(Date.now() - 15 * 86400000), // 15 days ago
          StorageClass: "STANDARD",
        },
      ],
      IsTruncated: false,
    });
    s3Mock.on(ListPartsCommand).resolves({
      Parts: [{ Size: 104857600 }], // 100 MiB
      IsTruncated: false,
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [],
    });

    const items = await loadDashboardData(s3Client, { olderThanDays: 7 });

    expect(items.length).toBe(1);
    expect(items[0]!.bucket).toBe("audit-test-bucket");
    expect(items[0]!.region).toBe("us-west-2");
    expect(items[0]!.zombieCount).toBe(1);
    expect(items[0]!.strandedBytes).toBe(104857600);
    expect(items[0]!.lifecycleStatus).toBe("UNPROTECTED");
    expect(items[0]!.riskLevel).toBe("HIGH");
  });
});

describe("Dashboard Interactive Loop (launchDashboard)", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("runs interactive dashboard, reacts to key events, and exits on 'q'", async () => {
    const s3Client = new S3Client({});
    const outputs: string[] = [];
    const stream: TerminalStream = {
      write: (chunk: string) => outputs.push(chunk),
    };

    const stdinEmitter = new EventEmitter() as any;
    stdinEmitter.isTTY = true;
    stdinEmitter.resume = vi.fn();
    stdinEmitter.pause = vi.fn();
    stdinEmitter.setEncoding = vi.fn();

    const sampleItem: DashboardBucketItem = {
      bucket: "fast-bucket",
      region: "us-east-1",
      status: "AUDITED",
      strandedBytes: 1024,
      zombieCount: 1,
      noncurrentBytes: 0,
      noncurrentCount: 0,
      eodmCount: 0,
      monthlyWasteUSD: 0.05,
      riskLevel: "LOW",
      lifecycleStatus: "COVERED",
      ghostRules: [],
      provider: "aws",
      providerDisplayName: "Amazon S3",
    };

    let exited = false;
    const launchPromise = launchDashboard(s3Client, {
      initialBuckets: [sampleItem],
      stream,
      stdin: stdinEmitter,
      onExit: () => {
        exited = true;
      },
    });

    // Initial render should have completed
    expect(outputs.length).toBeGreaterThan(0);
    expect(outputs.join("\n")).toContain("fast-bucket");

    // Send key 'j' (down)
    stdinEmitter.emit("data", "j");

    // Send key 'enter' (inspect drawer)
    stdinEmitter.emit("data", "\r");

    // Send key 'q' (exit)
    stdinEmitter.emit("data", "q");

    await launchPromise;
    expect(exited).toBe(true);
  });
});
