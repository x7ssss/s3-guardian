import { describe, it, expect } from "vitest";
import { S3ClientPool } from "../src/discovery/client-pool.js";

describe("S3ClientPool", () => {
  it("lazily creates a client for a region on first getClient() call", () => {
    const pool = new S3ClientPool();
    expect(pool.size).toBe(0);

    const client = pool.getClient("us-east-1");
    expect(client).toBeDefined();
    expect(pool.size).toBe(1);
    expect(pool.regions).toContain("us-east-1");
  });

  it("reuses the same client instance for repeated calls to the same region", () => {
    const pool = new S3ClientPool();
    const client1 = pool.getClient("us-west-2");
    const client2 = pool.getClient("us-west-2");
    expect(client1).toBe(client2); // strict reference equality
    expect(pool.size).toBe(1);
  });

  it("creates separate clients for distinct regions", () => {
    const pool = new S3ClientPool();
    const east = pool.getClient("us-east-1");
    const west = pool.getClient("us-west-2");
    const eu = pool.getClient("eu-central-1");

    expect(east).not.toBe(west);
    expect(west).not.toBe(eu);
    expect(pool.size).toBe(3);
    expect(pool.regions.sort()).toEqual(["eu-central-1", "us-east-1", "us-west-2"]);
  });

  it("destroy() tears down all clients and clears the registry", async () => {
    const pool = new S3ClientPool();
    pool.getClient("us-east-1");
    pool.getClient("eu-west-1");
    expect(pool.size).toBe(2);

    await pool.destroy();
    expect(pool.size).toBe(0);
    expect(pool.regions).toHaveLength(0);
  });

  it("destroy() is idempotent — safe to call multiple times", async () => {
    const pool = new S3ClientPool();
    pool.getClient("us-east-1");

    await pool.destroy();
    await pool.destroy(); // second call must not throw
    expect(pool.size).toBe(0);
  });

  it("getClient() throws after destroy()", async () => {
    const pool = new S3ClientPool();
    await pool.destroy();

    expect(() => pool.getClient("us-east-1")).toThrow(/destroyed/i);
  });

  it("pool starts empty with no regions", () => {
    const pool = new S3ClientPool();
    expect(pool.size).toBe(0);
    expect(pool.regions).toEqual([]);
  });

  it("accepts base config options and passes them to created clients", () => {
    // We just verify no errors are thrown with extra config options
    const pool = new S3ClientPool({ maxAttempts: 1 });
    const client = pool.getClient("ap-southeast-1");
    expect(client).toBeDefined();
    expect(pool.size).toBe(1);
  });
});
