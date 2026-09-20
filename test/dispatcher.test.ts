import { describe, it, expect, vi } from "vitest";
import {
  detectWebhookType,
  shouldSendNotification,
  buildSlackPayload,
  buildDiscordPayload,
  buildPagerDutyPayload,
  buildGenericPayload,
  dispatchNotification,
  AuditNotificationData,
} from "../src/notifications/dispatcher.js";

describe("Notification Dispatcher", () => {
  const sampleData: AuditNotificationData = {
    scope: "fleet",
    target: "all-buckets",
    totalZombieUploads: 5,
    totalStrandedBytes: 104857600, // 100 MB
    totalEstimatedMonthlyWasteUSD: 2.3,
    bucketsDiscovered: 10,
    bucketsAudited: 8,
    bucketsSkipped: 2,
    policyViolations: ["Estimated waste $2.30 exceeds threshold $1.00"],
  };

  const zeroWasteData: AuditNotificationData = {
    scope: "bucket",
    target: "clean-bucket",
    totalZombieUploads: 0,
    totalStrandedBytes: 0,
    totalEstimatedMonthlyWasteUSD: 0,
    policyViolations: [],
  };

  describe("detectWebhookType()", () => {
    it("autodetects Slack from hooks.slack.com", () => {
      expect(
        detectWebhookType("https://hooks.slack.com/services/T00/B00/XXXX")
      ).toBe("slack");
    });

    it("autodetects Discord from discord.com/api/webhooks", () => {
      expect(
        detectWebhookType("https://discord.com/api/webhooks/12345/abcdef")
      ).toBe("discord");
    });

    it("autodetects PagerDuty from events.pagerduty.com", () => {
      expect(
        detectWebhookType("https://events.pagerduty.com/v2/enqueue")
      ).toBe("pagerduty");
    });

    it("defaults to generic for other URLs", () => {
      expect(detectWebhookType("https://api.mycompany.com/webhook")).toBe(
        "generic"
      );
    });

    it("respects explicit webhookType regardless of URL", () => {
      expect(
        detectWebhookType("https://custom.com/webhook", "slack")
      ).toBe("slack");
      expect(
        detectWebhookType("https://hooks.slack.com/xxx", "generic")
      ).toBe("generic");
    });
  });

  describe("shouldSendNotification() - Alert Fatigue Circuit Breaker", () => {
    it("suppresses notification when waste is 0 and no policy violations", () => {
      expect(shouldSendNotification(zeroWasteData, false)).toBe(false);
    });

    it("dispatches notification when waste is > 0", () => {
      expect(shouldSendNotification(sampleData, false)).toBe(true);
    });

    it("dispatches notification when waste is 0 but policy violations exist", () => {
      const violatedZeroWaste: AuditNotificationData = {
        ...zeroWasteData,
        policyViolations: ["Bucket has no active MPU lifecycle rule"],
      };
      expect(shouldSendNotification(violatedZeroWaste, false)).toBe(true);
    });

    it("bypasses circuit breaker when notifyAlways is true", () => {
      expect(shouldSendNotification(zeroWasteData, true)).toBe(true);
    });
  });

  describe("Payload formatting", () => {
    it("builds Slack Block Kit payload with summary metrics", () => {
      const payload = buildSlackPayload(sampleData);
      expect(payload.text).toContain("s3-guardian");
      expect(payload.text).toContain("$2.30/mo");
      const blocks = payload.blocks as Array<{ type: string; fields?: any[]; text?: any }>;
      expect(blocks[0].type).toBe("header");
      expect(blocks[1].type).toBe("section");
      expect(JSON.stringify(blocks)).toContain("all-buckets");
      expect(JSON.stringify(blocks)).toContain("100.00 MB");
      expect(JSON.stringify(blocks)).toContain("Estimated waste $2.30 exceeds threshold");
    });

    it("builds Discord Rich Embed payload", () => {
      const payload = buildDiscordPayload(sampleData);
      expect(payload.content).toContain("s3-guardian Audit Alert");
      const embeds = payload.embeds as any[];
      expect(embeds).toHaveLength(1);
      expect(embeds[0].title).toContain("all-buckets");
      expect(embeds[0].color).toBe(15158332); // Red due to policy violation
      expect(JSON.stringify(embeds[0].fields)).toContain("$2.30/mo");
      expect(JSON.stringify(embeds[0].fields)).toContain("100.00 MB");
    });

    it("builds PagerDuty Event API v2 payload with routing_key and custom_details", () => {
      const payload = buildPagerDutyPayload(
        sampleData,
        "https://events.pagerduty.com/v2/enqueue?routing_key=pd-test-key"
      );
      expect(payload.routing_key).toBe("pd-test-key");
      expect(payload.event_action).toBe("trigger");
      const innerPayload = payload.payload as any;
      expect(innerPayload.severity).toBe("error");
      expect(innerPayload.summary).toContain("$2.30/mo");
      expect(innerPayload.custom_details.totalZombieUploads).toBe(5);
    });

    it("builds Generic JSON payload", () => {
      const payload = buildGenericPayload(sampleData);
      expect(payload.service).toBe("s3-guardian");
      expect(payload.version).toBe("0.5.0");
      expect((payload.audit as any).target).toBe("all-buckets");
    });
  });

  describe("dispatchNotification()", () => {
    it("skips fetch when circuit breaker triggers", async () => {
      const mockFetch = vi.fn();

      const result = await dispatchNotification(zeroWasteData, {
        webhookUrl: "https://hooks.slack.com/services/test",
        notifyAlways: false,
        fetchFn: mockFetch as any,
      });

      expect(result.sent).toBe(false);
      expect(result.reason).toBe("CIRCUIT_BREAKER_SUPPRESSED");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("dispatches successfully when conditions are met", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
      });

      const result = await dispatchNotification(sampleData, {
        webhookUrl: "https://hooks.slack.com/services/test",
        fetchFn: mockFetch as any,
      });

      expect(result.sent).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(result.targetType).toBe("slack");
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("retries on 500 server error and succeeds on second attempt", async () => {
      const mockFetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 502,
          statusText: "Bad Gateway",
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
        });

      const result = await dispatchNotification(sampleData, {
        webhookUrl: "https://discord.com/api/webhooks/123/abc",
        fetchFn: mockFetch as any,
      });

      expect(result.sent).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("best-effort delivery: never throws on network failure and returns sent: false", async () => {
      const mockFetch = vi
        .fn()
        .mockRejectedValue(new Error("ECONNREFUSED"));

      const warnings: string[] = [];
      const result = await dispatchNotification(sampleData, {
        webhookUrl: "https://events.pagerduty.com/v2/enqueue",
        fetchFn: mockFetch as any,
        logger: { warn: (msg) => warnings.push(msg) },
      });

      expect(result.sent).toBe(false);
      expect(result.reason).toContain("ECONNREFUSED");
      expect(warnings.length).toBeGreaterThan(0);
    });
  });
});
