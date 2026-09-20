import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { writeAtomic } from "../src/state/atomic-file.js";

describe("Atomic File Writer (writeAtomic)", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), "s3-guardian-atomic-test-" + Math.random().toString(36).slice(2));
    await fs.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it("atomically writes string content to a new file and creates nested directory", async () => {
    const target = path.join(tempDir, "nested", "dir", "test.txt");
    const content = "Hello Atomic World!\nLine 2";

    await writeAtomic(target, content);

    const readBack = await fs.readFile(target, "utf8");
    expect(readBack).toBe(content);

    // Verify no stray .tmp files left in the directory
    const dirEntries = await fs.readdir(path.dirname(target));
    expect(dirEntries).toEqual(["test.txt"]);
  });

  it("atomically writes binary Buffer content", async () => {
    const target = path.join(tempDir, "binary.bin");
    const buffer = Buffer.from([0x00, 0xff, 0x42, 0x13, 0x37]);

    await writeAtomic(target, buffer);

    const readBack = await fs.readFile(target);
    expect(Buffer.compare(readBack, buffer)).toBe(0);
  });

  it("atomically overwrites existing file content cleanly", async () => {
    const target = path.join(tempDir, "overwrite.txt");
    await fs.writeFile(target, "initial content", "utf8");

    const newContent = "updated content 12345";
    await writeAtomic(target, newContent);

    const readBack = await fs.readFile(target, "utf8");
    expect(readBack).toBe(newContent);
  });

  it("cleans up temporary file if writeFile throws an error", async () => {
    const target = path.join(tempDir, "fail.txt");

    await expect(
      writeAtomic(target, "should fail", {
        _fs: {
          writeFile: async () => {
            throw new Error("Disk error during writeFile");
          },
        },
      })
    ).rejects.toThrow("Disk error during writeFile");

    const dirEntries = await fs.readdir(tempDir);
    expect(dirEntries.filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
  });

  it("retries on transient Windows EPERM / EBUSY error and succeeds", async () => {
    const target = path.join(tempDir, "retry-success.txt");
    let renameAttempts = 0;

    await writeAtomic(target, "eventually wrote successfully", {
      maxRetryMs: 2000,
      _fs: {
        rename: async (src, dest) => {
          renameAttempts++;
          if (renameAttempts <= 2) {
            const err = new Error("File locked by AV scanner") as any;
            err.code = "EPERM";
            throw err;
          }
          return fs.rename(src, dest);
        },
      },
    });

    expect(renameAttempts).toBeGreaterThanOrEqual(3);
    const readBack = await fs.readFile(target, "utf8");
    expect(readBack).toBe("eventually wrote successfully");
  });

  it("fails and unlinks tmp file if transient error persists beyond maxRetryMs", async () => {
    const target = path.join(tempDir, "retry-timeout.txt");

    await expect(
      writeAtomic(target, "timeout content", {
        maxRetryMs: 100,
        _fs: {
          rename: async () => {
            const err = new Error("File busy permanently") as any;
            err.code = "EBUSY";
            throw err;
          },
        },
      })
    ).rejects.toThrow("File busy permanently");

    const dirEntries = await fs.readdir(tempDir);
    expect(dirEntries.filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
  });

  it("immediately throws non-transient errors (e.g. ENOSPC) without retry loop", async () => {
    const target = path.join(tempDir, "hard-fail.txt");
    let renameAttempts = 0;

    await expect(
      writeAtomic(target, "no space", {
        _fs: {
          rename: async () => {
            renameAttempts++;
            const err = new Error("No space left on device") as any;
            err.code = "ENOSPC";
            throw err;
          },
        },
      })
    ).rejects.toThrow("No space left on device");
    expect(renameAttempts).toBe(1);

    const dirEntries = await fs.readdir(tempDir);
    expect(dirEntries.filter((f) => f.endsWith(".tmp"))).toHaveLength(0);
  });
});
