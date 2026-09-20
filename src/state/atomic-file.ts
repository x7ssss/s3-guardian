import * as fs from "node:fs/promises";
import * as path from "node:path";
import { randomUUID } from "node:crypto";

export interface WriteAtomicOptions {
  maxRetryMs?: number;
  /** Internal test injection hooks */
  _fs?: {
    rename?: (src: string, dest: string) => Promise<void>;
    writeFile?: (handle: fs.FileHandle, content: string | Buffer) => Promise<void>;
  };
}

/**
 * Atomically writes content to a target file using write-to-temp and atomic rename.
 *
 * Windows NTFS Safety:
 * - Writes to a temporary file located in the EXACT same directory to avoid cross-device EXDEV errors.
 * - Flushes file descriptor data to disk via fd.sync() before closing.
 * - Retries rename with exponential backoff and full jitter on Windows EPERM, EBUSY, and EACCES.
 * - Safely skips directory fsync on Windows (unsupported on Windows directories) while executing directory sync on POSIX.
 * - Cleans up the temporary file on unrecoverable failure.
 */
export async function writeAtomic(
  targetPath: string,
  content: string | Buffer,
  options: WriteAtomicOptions = {}
): Promise<void> {
  const dir = path.dirname(targetPath);
  await fs.mkdir(dir, { recursive: true });

  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.${randomUUID().slice(0, 8)}.tmp`;
  const handle = await fs.open(tmpPath, "w");

  try {
    if (options._fs?.writeFile) {
      await options._fs.writeFile(handle, content);
    } else {
      await handle.writeFile(content);
    }
    await handle.sync();
  } catch (err) {
    await handle.close().catch(() => {});
    await fs.unlink(tmpPath).catch(() => {});
    throw err;
  }
  await handle.close();

  const maxRetryMs = options.maxRetryMs ?? 3000;
  const startTime = Date.now();
  let attempt = 0;
  const renameFn = options._fs?.rename ?? fs.rename;

  while (true) {
    try {
      await renameFn(tmpPath, targetPath);
      break;
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as { code: unknown }).code
          : undefined;

      const isTransientWindowsLock =
        code === "EPERM" || code === "EBUSY" || code === "EACCES";

      if (!isTransientWindowsLock || Date.now() - startTime >= maxRetryMs) {
        await fs.unlink(tmpPath).catch(() => {});
        throw err;
      }

      attempt++;
      const maxDelay = Math.min(500, 25 * Math.pow(2, attempt));
      const delay = Math.floor(Math.random() * maxDelay) + 10;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  // Directory sync on POSIX platforms only
  if (process.platform !== "win32") {
    try {
      const dirHandle = await fs.open(dir, "r");
      try {
        await dirHandle.sync();
      } finally {
        await dirHandle.close();
      }
    } catch {
      // Best-effort directory fsync
    }
  }
}
