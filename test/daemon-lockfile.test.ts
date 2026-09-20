import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  acquireDaemonLock,
  releaseDaemonLock,
  getLockFilePath,
  isPidAlive,
  DaemonLockError,
} from "../src/daemon/lockfile.js";

describe("Daemon PID Lockfile", () => {
  const testLockName = "unit-test-lock-" + Math.random().toString(36).slice(2, 8);
  const testLockFilePath = getLockFilePath(testLockName);

  afterEach(() => {
    try {
      if (fs.existsSync(testLockFilePath)) {
        fs.unlinkSync(testLockFilePath);
      }
    } catch {
      // ignore
    }
  });

  it("generates deterministic sanitized lockfile path in os.tmpdir", () => {
    const lockPath = getLockFilePath("my-service/test:1");
    expect(lockPath).toBe(path.join(os.tmpdir(), "s3-guardian-my-service_test_1.lock"));
  });

  it("correctly identifies process aliveness", () => {
    expect(isPidAlive(process.pid)).toBe(true);
    // Negative or 0 PIDs are not alive
    expect(isPidAlive(0)).toBe(false);
    expect(isPidAlive(-1)).toBe(false);
    // A huge PID unlikely to exist
    expect(isPidAlive(99999999)).toBe(false);
  });

  it("acquires lock successfully and writes PID", () => {
    const lock = acquireDaemonLock(testLockName);
    expect(lock.lockName).toBe(testLockName);
    expect(lock.pid).toBe(process.pid);
    expect(fs.existsSync(testLockFilePath)).toBe(true);

    const content = fs.readFileSync(testLockFilePath, "utf8").trim();
    expect(parseInt(content, 10)).toBe(process.pid);

    lock.release();
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });

  it("prevents concurrent lock acquisition by active process", () => {
    const lock1 = acquireDaemonLock(testLockName);
    try {
      expect(() => {
        acquireDaemonLock(testLockName);
      }).toThrow(DaemonLockError);
    } finally {
      lock1.release();
    }
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });

  it("reclaims stale lock when holding PID is dead", () => {
    // Write a lockfile with a PID that is definitely not alive
    const deadPid = 99999999;
    fs.writeFileSync(testLockFilePath, `${deadPid}\n`);

    const lock = acquireDaemonLock(testLockName);
    expect(lock.pid).toBe(process.pid);

    const content = fs.readFileSync(testLockFilePath, "utf8").trim();
    expect(parseInt(content, 10)).toBe(process.pid);

    lock.release();
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });

  it("reclaims stale lock when lockfile contains invalid or corrupted non-numeric content", () => {
    fs.writeFileSync(testLockFilePath, `corrupted-pid-text\n`);

    const lock = acquireDaemonLock(testLockName);
    expect(lock.pid).toBe(process.pid);

    const content = fs.readFileSync(testLockFilePath, "utf8").trim();
    expect(parseInt(content, 10)).toBe(process.pid);

    lock.release();
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });

  it("releases lock via releaseDaemonLock helper with lock name string", () => {
    acquireDaemonLock(testLockName);
    expect(fs.existsSync(testLockFilePath)).toBe(true);

    releaseDaemonLock(testLockName);
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });

  it("releases lock via releaseDaemonLock helper with DaemonLock object", () => {
    const lock = acquireDaemonLock(testLockName);
    expect(fs.existsSync(testLockFilePath)).toBe(true);

    releaseDaemonLock(lock);
    expect(fs.existsSync(testLockFilePath)).toBe(false);
  });
});
