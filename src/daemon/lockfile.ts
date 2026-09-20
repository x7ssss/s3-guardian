import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export class DaemonLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DaemonLockError";
  }
}

export interface DaemonLock {
  lockName: string;
  lockFilePath: string;
  pid: number;
  release: () => void;
}

/**
 * Returns the deterministic lockfile path in the OS temporary directory.
 */
export function getLockFilePath(lockName: string): string {
  const sanitized = lockName.replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(os.tmpdir(), `s3-guardian-${sanitized}.lock`);
}

/**
 * Checks if a process with the given PID is currently active.
 * Uses process.kill(pid, 0) which tests existence without sending a fatal signal.
 */
export function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    const code = (err as Record<string, unknown>)?.code;
    if (code === "ESRCH") {
      // ESRCH: No such process
      return false;
    }
    if (code === "EPERM") {
      // EPERM: Process exists, but we lack permissions to signal it
      return true;
    }
    return false;
  }
}

/**
 * Acquires an exclusive PID lockfile for a daemon instance using atomic 'wx' flag.
 * If an existing lockfile is found:
 * - Inspects the recorded PID.
 * - If the PID is still alive, throws DaemonLockError.
 * - If the PID is dead (stale lock), reclaims the lockfile cleanly.
 *
 * Attaches a synchronous exit hook to ensure the lockfile is released on process exit.
 */
export function acquireDaemonLock(lockName: string): DaemonLock {
  const lockFilePath = getLockFilePath(lockName);
  const currentPid = process.pid;

  let acquired = false;

  try {
    // Atomic creation with 'wx' fails if file already exists
    fs.writeFileSync(lockFilePath, `${currentPid}\n`, { flag: "wx" });
    acquired = true;
  } catch (err: unknown) {
    const code = (err as Record<string, unknown>)?.code;
    if (code === "EEXIST") {
      // Lockfile already exists — inspect if holding process is still alive
      let existingPid: number | null = null;
      try {
        const content = fs.readFileSync(lockFilePath, "utf8").trim();
        const parsed = parseInt(content, 10);
        if (!isNaN(parsed)) {
          existingPid = parsed;
        }
      } catch {
        // If file disappeared or cannot be read, proceed to reclaim
      }

      if (existingPid !== null && isPidAlive(existingPid)) {
        throw new DaemonLockError(
          `Daemon lock '${lockName}' already held by active process PID ${existingPid} (${lockFilePath})`
        );
      }

      // Stale lock detected (process dead or invalid file content) — reclaim lock
      try {
        fs.unlinkSync(lockFilePath);
      } catch {
        // Best-effort unlink
      }

      try {
        fs.writeFileSync(lockFilePath, `${currentPid}\n`, { flag: "wx" });
        acquired = true;
      } catch (retryErr: unknown) {
        throw new DaemonLockError(
          `Failed to acquire reclaimed daemon lock '${lockName}': ${
            retryErr instanceof Error ? retryErr.message : String(retryErr)
          }`
        );
      }
    } else {
      throw err;
    }
  }

  if (!acquired) {
    throw new DaemonLockError(`Failed to acquire lock for '${lockName}'`);
  }

  let isReleased = false;

  const onProcessExit = () => {
    if (isReleased) return;
    try {
      if (fs.existsSync(lockFilePath)) {
        const content = fs.readFileSync(lockFilePath, "utf8").trim();
        if (parseInt(content, 10) === currentPid) {
          fs.unlinkSync(lockFilePath);
        }
      }
    } catch {
      // Best-effort cleanup on process exit
    }
  };

  process.on("exit", onProcessExit);

  const release = () => {
    if (isReleased) return;
    isReleased = true;
    process.removeListener("exit", onProcessExit);

    try {
      if (fs.existsSync(lockFilePath)) {
        const content = fs.readFileSync(lockFilePath, "utf8").trim();
        if (parseInt(content, 10) === currentPid) {
          fs.unlinkSync(lockFilePath);
        }
      }
    } catch {
      // Best-effort cleanup
    }
  };

  return {
    lockName,
    lockFilePath,
    pid: currentPid,
    release,
  };
}

/**
 * Releases a daemon lock, accepting either a DaemonLock instance or a lock name string.
 */
export function releaseDaemonLock(lockOrName: DaemonLock | string): void {
  if (typeof lockOrName === "object" && lockOrName !== null && "release" in lockOrName) {
    lockOrName.release();
    return;
  }

  const lockFilePath = getLockFilePath(lockOrName);
  try {
    if (fs.existsSync(lockFilePath)) {
      const content = fs.readFileSync(lockFilePath, "utf8").trim();
      if (parseInt(content, 10) === process.pid) {
        fs.unlinkSync(lockFilePath);
      }
    }
  } catch {
    // Best effort
  }
}
