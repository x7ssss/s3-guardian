import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { STSSessionPool, isStsThrottlingError } from "../src/auth/sts-pool.js";

const stsMock = mockClient(STSClient);

describe("STSSessionPool", () => {
  beforeEach(() => {
    stsMock.reset();
  });

  it("successfully assumes role and caches credentials", async () => {
    const expiration = new Date(Date.now() + 3600_000); // 1 hour
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_TEST_KEY",
        SecretAccessKey: "TEST_SECRET",
        SessionToken: "TEST_TOKEN",
        Expiration: expiration,
      },
      AssumedRoleUser: {
        AssumedRoleId: "AROA123:session-1",
        Arn: "arn:aws:sts::111111111111:assumed-role/TestRole/session-1",
      },
    });

    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });
    const creds = await pool.assumeRole({
      accountId: "111111111111",
      roleName: "TestRole",
    });

    expect(creds.accessKeyId).toBe("ASIA_TEST_KEY");
    expect(creds.secretAccessKey).toBe("TEST_SECRET");
    expect(creds.sessionToken).toBe("TEST_TOKEN");
    expect(creds.expiration).toEqual(expiration);
    expect(creds.roleArn).toBe("arn:aws:iam::111111111111:role/TestRole");
    expect(pool.size).toBe(1);

    // Second call should return cached credentials without calling STS again
    const creds2 = await pool.assumeRole({
      accountId: "111111111111",
      roleName: "TestRole",
    });

    expect(creds2).toBe(creds);
    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(1);
  });

  it("passes externalId and durationSeconds to AssumeRoleCommand", async () => {
    const expiration = new Date(Date.now() + 1800_000);
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_EXT_KEY",
        SecretAccessKey: "EXT_SECRET",
        SessionToken: "EXT_TOKEN",
        Expiration: expiration,
      },
    });

    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });
    await pool.assumeRole({
      accountId: "222222222222",
      roleName: "PartnerRole",
      externalId: "ext-tenant-xyz",
      durationSeconds: 1800,
    });

    const calls = stsMock.commandCalls(AssumeRoleCommand);
    expect(calls).toHaveLength(1);
    const input = calls[0].args[0].input;
    expect(input.RoleArn).toBe("arn:aws:iam::222222222222:role/PartnerRole");
    expect(input.ExternalId).toBe("ext-tenant-xyz");
    expect(input.DurationSeconds).toBe(1800);
  });

  it("differentiates cache keys by externalId", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_KEY",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });
    await pool.assumeRole({
      accountId: "111111111111",
      roleName: "SharedRole",
      externalId: "tenant-a",
    });

    await pool.assumeRole({
      accountId: "111111111111",
      roleName: "SharedRole",
      externalId: "tenant-b",
    });

    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(2);
    expect(pool.size).toBe(2);
  });

  it("proactively refreshes credentials when remaining lifetime is <= 5 minutes", async () => {
    let mockCurrentTime = new Date("2026-09-20T12:00:00Z");
    const nowFn = () => mockCurrentTime;

    // First session expires in 4 minutes from now (within the 5-minute proactive refresh window)
    const initialExpiration = new Date("2026-09-20T12:04:00Z");
    const refreshedExpiration = new Date("2026-09-20T13:00:00Z");

    stsMock
      .on(AssumeRoleCommand)
      .resolvesOnce({
        Credentials: {
          AccessKeyId: "ASIA_INITIAL",
          SecretAccessKey: "SECRET1",
          SessionToken: "TOKEN1",
          Expiration: initialExpiration,
        },
      })
      .resolvesOnce({
        Credentials: {
          AccessKeyId: "ASIA_REFRESHED",
          SecretAccessKey: "SECRET2",
          SessionToken: "TOKEN2",
          Expiration: refreshedExpiration,
        },
      });

    const pool = new STSSessionPool({
      stsClient: stsMock as unknown as STSClient,
      proactiveRefreshWindowMs: 300_000, // 5 min
      nowFn,
    });

    // Call 1: initial fetch
    const creds1 = await pool.assumeRole({
      accountId: "111111111111",
      roleName: "WorkerRole",
    });
    expect(creds1.accessKeyId).toBe("ASIA_INITIAL");

    // Call 2: since remaining lifetime is 4 minutes (<= 5 min window), it must refresh
    const creds2 = await pool.assumeRole({
      accountId: "111111111111",
      roleName: "WorkerRole",
    });
    expect(creds2.accessKeyId).toBe("ASIA_REFRESHED");
    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(2);
  });

  it("deduplicates concurrent in-flight requests for the same role", async () => {
    let callCount = 0;
    stsMock.on(AssumeRoleCommand).callsFake(async () => {
      callCount++;
      await new Promise((res) => setTimeout(res, 20));
      return {
        Credentials: {
          AccessKeyId: `ASIA_KEY_${callCount}`,
          SecretAccessKey: "SECRET",
          SessionToken: "TOKEN",
          Expiration: new Date(Date.now() + 3600_000),
        },
      };
    });

    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });

    // Fire 3 simultaneous assumeRole calls for the same role
    const [c1, c2, c3] = await Promise.all([
      pool.assumeRole({ accountId: "123456789012", roleName: "ConcurrentRole" }),
      pool.assumeRole({ accountId: "123456789012", roleName: "ConcurrentRole" }),
      pool.assumeRole({ accountId: "123456789012", roleName: "ConcurrentRole" }),
    ]);

    expect(c1.accessKeyId).toBe("ASIA_KEY_1");
    expect(c2.accessKeyId).toBe("ASIA_KEY_1");
    expect(c3.accessKeyId).toBe("ASIA_KEY_1");
    expect(callCount).toBe(1);
  });

  it("retries on STS ThrottlingException with jittered backoff and succeeds", async () => {
    const sleepCalls: number[] = [];
    const sleepFn = async (ms: number) => {
      sleepCalls.push(ms);
    };

    const throttlingError = new Error("Rate exceeded");
    throttlingError.name = "ThrottlingException";

    stsMock
      .on(AssumeRoleCommand)
      .rejectsOnce(throttlingError)
      .rejectsOnce(throttlingError)
      .resolvesOnce({
        Credentials: {
          AccessKeyId: "ASIA_AFTER_THROTTLE",
          SecretAccessKey: "SECRET",
          SessionToken: "TOKEN",
          Expiration: new Date(Date.now() + 3600_000),
        },
      });

    const pool = new STSSessionPool({
      stsClient: stsMock as unknown as STSClient,
      sleepFn,
      maxRetries: 3,
    });

    const creds = await pool.assumeRole({
      accountId: "999999999999",
      roleName: "ThrottledRole",
    });

    expect(creds.accessKeyId).toBe("ASIA_AFTER_THROTTLE");
    expect(sleepCalls).toHaveLength(2);
    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(3);
  });

  it("throws immediately on non-retryable error (e.g. AccessDenied)", async () => {
    const accessDenied = new Error("User is not authorized to perform: sts:AssumeRole");
    accessDenied.name = "AccessDenied";

    stsMock.on(AssumeRoleCommand).rejects(accessDenied);

    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });

    await expect(
      pool.assumeRole({
        accountId: "111111111111",
        roleName: "ForbiddenRole",
      })
    ).rejects.toThrow(/not authorized/i);

    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(1);
  });

  it("destroy() clears cache and prevents further assumeRole calls", async () => {
    const pool = new STSSessionPool({ stsClient: stsMock as unknown as STSClient });
    await pool.destroy();

    await expect(
      pool.assumeRole({
        accountId: "111111111111",
        roleName: "TestRole",
      })
    ).rejects.toThrow(/destroyed/i);
  });

  it("isStsThrottlingError correctly identifies various throttling codes", () => {
    expect(isStsThrottlingError({ name: "ThrottlingException" })).toBe(true);
    expect(isStsThrottlingError({ name: "Throttling" })).toBe(true);
    expect(isStsThrottlingError({ name: "RequestLimitExceeded" })).toBe(true);
    expect(isStsThrottlingError({ statusCode: 429 })).toBe(true);
    expect(isStsThrottlingError({ message: "Rate exceeded for STS" })).toBe(true);
    expect(isStsThrottlingError({ name: "AccessDenied" })).toBe(false);
    expect(isStsThrottlingError(null)).toBe(false);
  });
});
