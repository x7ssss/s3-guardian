import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { AuditLogWriter } from "../src/state/audit-writer.js";
import { createAuditEvent, AuditEvent } from "../src/state/types.js";

describe("AuditLogWriter", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), "s3-guardian-writer-test-" + Math.random().toString(36).slice(2));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it("creates directory and writes an audit event to audit.jsonl", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    const event = createAuditEvent({
      eventType: "DISCOVERY",
      accountId: "123456789012",
      bucketName: "my-test-bucket",
      targetCount: 15,
      bytesFreed: 0,
    });

    await writer.append(event);
    await writer.close();

    const logPath = path.join(tempDir, "audit.jsonl");
    const content = await fs.readFile(logPath, "utf8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);

    const parsed = JSON.parse(lines[0]!);
    expect(parsed.eventId).toBe(event.eventId);
    expect(parsed.eventType).toBe("DISCOVERY");
    expect(parsed.accountId).toBe("123456789012");
    expect(parsed.bucketName).toBe("my-test-bucket");
    expect(parsed.targetCount).toBe(15);
  });

  it("handles high-volume concurrent appends without corruption or interleaved JSON", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    const eventCount = 100;
    const events: AuditEvent[] = [];

    for (let i = 0; i < eventCount; i++) {
      events.push(
        createAuditEvent({
          eventType: i % 2 === 0 ? "DISCOVERY" : "REMEDIATION_EXECUTED",
          accountId: "123456789012",
          bucketName: `bucket-${i}`,
          targetCount: i,
          bytesFreed: i * 1024,
          estimatedSavingsUSD: i * 0.01,
          details: { index: i, payload: "x".repeat(50) },
        })
      );
    }

    // Fire all appends simultaneously
    await Promise.all(events.map((e) => writer.append(e)));
    await writer.close();

    const logPath = path.join(tempDir, "audit.jsonl");
    const content = await fs.readFile(logPath, "utf8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(eventCount);

    // Verify every single line is valid JSON with no truncation or mangling
    const parsedEvents: AuditEvent[] = lines.map((line) => JSON.parse(line));
    expect(parsedEvents).toHaveLength(eventCount);

    // Verify all event IDs are present in output
    const expectedIds = new Set(events.map((e) => e.eventId));
    for (const pe of parsedEvents) {
      expect(expectedIds.has(pe.eventId)).toBe(true);
    }
  });

  it("rejects append after close()", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    await writer.append(
      createAuditEvent({
        eventType: "DISCOVERY",
        accountId: "123",
        bucketName: "b1",
      })
    );
    await writer.close();

    await expect(
      writer.append(
        createAuditEvent({
          eventType: "CANARY_VERIFIED",
          accountId: "123",
          bucketName: "b1",
        })
      )
    ).rejects.toThrow("Cannot append to closed AuditLogWriter");
  });

  it("supports multiple calls to close() idempotently", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    await writer.append(
      createAuditEvent({
        eventType: "DISCOVERY",
        accountId: "123",
        bucketName: "b1",
      })
    );
    await writer.close();
    await expect(writer.close()).resolves.toBeUndefined();
  });
});
