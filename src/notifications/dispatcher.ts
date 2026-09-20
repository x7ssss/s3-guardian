import { formatBytes, formatMonthlyCost } from "../cost/estimator.js";

export type WebhookType = "slack" | "discord" | "pagerduty" | "generic";

export interface AuditNotificationData {
  scope: "bucket" | "fleet";
  target: string;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  totalEstimatedMonthlyWasteUSD: number;
  bucketsDiscovered?: number;
  bucketsAudited?: number;
  bucketsSkipped?: number;
  policyViolations?: string[];
}

export interface DispatchOptions {
  webhookUrl: string;
  webhookType?: WebhookType | string;
  notifyAlways?: boolean;
  logger?: {
    warn?: (msg: string) => void;
    error?: (msg: string) => void;
    log?: (msg: string) => void;
  };
  /** Injectable fetch for unit tests */
  fetchFn?: typeof fetch;
}

export interface DispatchResult {
  sent: boolean;
  reason?: string;
  statusCode?: number;
  targetType?: WebhookType;
}

/**
 * Autodetects the webhook destination from the URL or respects the explicit type.
 */
export function detectWebhookType(
  url: string,
  explicitType?: string
): WebhookType {
  if (explicitType) {
    const lower = explicitType.toLowerCase().trim();
    if (
      lower === "slack" ||
      lower === "discord" ||
      lower === "pagerduty" ||
      lower === "generic"
    ) {
      return lower;
    }
  }

  const lowerUrl = url.toLowerCase();
  if (lowerUrl.includes("hooks.slack.com")) {
    return "slack";
  }
  if (
    lowerUrl.includes("discord.com/api/webhooks") ||
    lowerUrl.includes("discordapp.com/api/webhooks")
  ) {
    return "discord";
  }
  if (lowerUrl.includes("events.pagerduty.com")) {
    return "pagerduty";
  }

  return "generic";
}

/**
 * Alert Fatigue Circuit Breaker:
 * Suppresses notifications by default if waste is $0.00 and no policy violations exist.
 */
export function shouldSendNotification(
  data: AuditNotificationData,
  notifyAlways: boolean = false
): boolean {
  if (notifyAlways) {
    return true;
  }
  const hasWaste = data.totalEstimatedMonthlyWasteUSD > 0;
  const hasViolations = Boolean(
    data.policyViolations && data.policyViolations.length > 0
  );
  return hasWaste || hasViolations;
}

/**
 * Builds Slack Block Kit payload.
 */
export function buildSlackPayload(data: AuditNotificationData): Record<string, unknown> {
  const wasteStr = formatMonthlyCost(data.totalEstimatedMonthlyWasteUSD);
  const bytesStr = formatBytes(data.totalStrandedBytes);

  const fields = [
    { type: "mrkdwn", text: `*Target:*\n\`${data.target}\`` },
    { type: "mrkdwn", text: `*Estimated Waste:*\n${wasteStr}` },
    { type: "mrkdwn", text: `*Zombie Uploads:*\n${data.totalZombieUploads}` },
    { type: "mrkdwn", text: `*Stranded Bytes:*\n${bytesStr}` },
  ];

  if (data.scope === "fleet" && data.bucketsAudited !== undefined) {
    fields.push({
      type: "mrkdwn",
      text: `*Buckets Audited:*\n${data.bucketsAudited}/${data.bucketsDiscovered ?? "?"}`,
    });
  }

  const blocks: Record<string, unknown>[] = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: "🛡️ s3-guardian Audit Alert",
        emoji: true,
      },
    },
    {
      type: "section",
      fields,
    },
  ];

  if (data.policyViolations && data.policyViolations.length > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Policy Violations:*\n${data.policyViolations.map((v) => `• ${v}`).join("\n")}`,
      },
    });
  }

  return {
    text: `🛡️ s3-guardian: ${wasteStr} stranded in ${data.target}`,
    blocks,
  };
}

/**
 * Builds Discord Rich Embed payload.
 */
export function buildDiscordPayload(data: AuditNotificationData): Record<string, unknown> {
  const wasteStr = formatMonthlyCost(data.totalEstimatedMonthlyWasteUSD);
  const bytesStr = formatBytes(data.totalStrandedBytes);
  const hasViolations = Boolean(
    data.policyViolations && data.policyViolations.length > 0
  );

  const fields = [
    { name: "Target", value: data.target, inline: true },
    { name: "Estimated Waste", value: wasteStr, inline: true },
    { name: "Zombie Uploads", value: String(data.totalZombieUploads), inline: true },
    { name: "Stranded Storage", value: bytesStr, inline: true },
  ];

  if (data.scope === "fleet" && data.bucketsAudited !== undefined) {
    fields.push({
      name: "Buckets Audited",
      value: `${data.bucketsAudited} of ${data.bucketsDiscovered ?? "?"}`,
      inline: true,
    });
  }

  if (hasViolations && data.policyViolations) {
    fields.push({
      name: "Policy Violations",
      value: data.policyViolations.join("\n"),
      inline: false,
    });
  }

  return {
    content: "🛡️ **s3-guardian Audit Alert**",
    embeds: [
      {
        title: `Audit Summary: ${data.target}`,
        color: hasViolations ? 15158332 : 15844367, // Red or Gold
        fields,
        footer: { text: "s3-guardian v0.5.0" },
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

/**
 * Builds PagerDuty Event API v2 payload.
 */
export function buildPagerDutyPayload(
  data: AuditNotificationData,
  url: string
): Record<string, unknown> {
  const wasteStr = formatMonthlyCost(data.totalEstimatedMonthlyWasteUSD);
  const hasViolations = Boolean(
    data.policyViolations && data.policyViolations.length > 0
  );

  // Extract routing key from URL query (?routing_key=...) or path if present
  let routingKey = "s3-guardian";
  try {
    const parsedUrl = new URL(url);
    const keyParam = parsedUrl.searchParams.get("routing_key");
    if (keyParam) {
      routingKey = keyParam;
    }
  } catch {
    // ignore
  }

  return {
    routing_key: routingKey,
    event_action: "trigger",
    payload: {
      summary: `s3-guardian: ${wasteStr} stranded multipart uploads in ${data.target}`,
      severity: hasViolations ? "error" : "warning",
      source: "s3-guardian",
      custom_details: {
        target: data.target,
        scope: data.scope,
        totalZombieUploads: data.totalZombieUploads,
        totalStrandedBytes: data.totalStrandedBytes,
        totalEstimatedMonthlyWasteUSD: data.totalEstimatedMonthlyWasteUSD,
        policyViolations: data.policyViolations ?? [],
      },
    },
  };
}

/**
 * Builds Generic JSON payload.
 */
export function buildGenericPayload(data: AuditNotificationData): Record<string, unknown> {
  return {
    service: "s3-guardian",
    version: "0.5.0",
    timestamp: new Date().toISOString(),
    audit: data,
  };
}

/**
 * Dispatches an audit summary webhook notification.
 *
 * Invariants:
 *  - Alert Fatigue Circuit Breaker: Skips if waste is $0.00 and no policy violations, unless notifyAlways is set.
 *  - Native global fetch with 10-second timeout.
 *  - Exponential backoff retry (up to 2 attempts).
 *  - Best-Effort Delivery: Logs warning on failure and never throws.
 */
export async function dispatchNotification(
  data: AuditNotificationData,
  options: DispatchOptions
): Promise<DispatchResult> {
  const warn = options.logger?.warn ?? console.warn;
  const targetType = detectWebhookType(options.webhookUrl, options.webhookType);

  // 1. Alert Fatigue Circuit Breaker
  if (!shouldSendNotification(data, options.notifyAlways)) {
    return {
      sent: false,
      reason: "CIRCUIT_BREAKER_SUPPRESSED",
      targetType,
    };
  }

  // 2. Build target payload
  let payload: Record<string, unknown>;
  switch (targetType) {
    case "slack":
      payload = buildSlackPayload(data);
      break;
    case "discord":
      payload = buildDiscordPayload(data);
      break;
    case "pagerduty":
      payload = buildPagerDutyPayload(data, options.webhookUrl);
      break;
    case "generic":
    default:
      payload = buildGenericPayload(data);
      break;
  }

  const fetchImpl = options.fetchFn ?? globalThis.fetch;
  const maxAttempts = 2;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await fetchImpl(options.webhookUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "s3-guardian/0.5.0",
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000), // 10s timeout
      });

      if (response.ok) {
        return {
          sent: true,
          statusCode: response.status,
          targetType,
        };
      }

      // Retry on 5xx server errors
      if (response.status >= 500 && attempt < maxAttempts) {
        await new Promise((res) => setTimeout(res, 300 * attempt));
        continue;
      }

      warn(
        `[s3-guardian] Webhook delivery to ${targetType} returned HTTP ${response.status}: ${response.statusText}`
      );
      return {
        sent: false,
        reason: `HTTP_${response.status}`,
        statusCode: response.status,
        targetType,
      };
    } catch (err: unknown) {
      if (attempt < maxAttempts) {
        await new Promise((res) => setTimeout(res, 300 * attempt));
        continue;
      }
      const msg = err instanceof Error ? err.message : String(err);
      warn(`[s3-guardian] Failed to dispatch webhook notification to ${targetType}: ${msg}`);
      return {
        sent: false,
        reason: msg,
        targetType,
      };
    }
  }

  return {
    sent: false,
    reason: "MAX_ATTEMPTS_EXCEEDED",
    targetType,
  };
}
