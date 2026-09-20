import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import { AuditEvent } from "./types.js";

export interface AuditLogWriterOptions {
  stateDir?: string;
}

/**
 * Append-only Audit Log Writer for linearizable JSONL event streams.
 *
 * Guarantees:
 * - Strict line-by-line serialization through an internal promise queue,
 *   preventing chunk interleaving during high concurrency.
 * - Adheres to Node.js stream backpressure: awaits 'drain' when stream buffer fills.
 * - Clean teardown via close(), ensuring all buffered writes are flushed to disk.
 */
export class AuditLogWriter {
  public readonly stateDir: string;
  public readonly logPath: string;

  private stream: fsSync.WriteStream | null = null;
  private isClosed: boolean = false;
  private initPromise: Promise<void> | null = null;
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(options: AuditLogWriterOptions = {}) {
    this.stateDir = options.stateDir ?? path.resolve(process.cwd(), ".s3-guardian");
    this.logPath = path.join(this.stateDir, "audit.jsonl");
  }

  private async ensureInitialized(): Promise<void> {
    if (this.isClosed) {
      throw new Error("Cannot initialize closed AuditLogWriter");
    }
    if (this.stream) return;

    if (!this.initPromise) {
      this.initPromise = (async () => {
        await fs.mkdir(this.stateDir, { recursive: true });
        const stream = fsSync.createWriteStream(this.logPath, {
          flags: "a",
          encoding: "utf8",
        });

        stream.on("error", (err) => {
          // Prevent unhandled stream error crashes
          console.error(`[s3-guardian:audit] Stream error on ${this.logPath}:`, err);
        });

        this.stream = stream;
      })();
    }

    await this.initPromise;
  }

  /**
   * Serializes and appends an AuditEvent to the JSONL ledger.
   * Respects write backpressure.
   */
  async append(event: AuditEvent): Promise<void> {
    if (this.isClosed) {
      throw new Error("Cannot append to closed AuditLogWriter");
    }

    const task = this.appendQueue.then(async () => {
      await this.ensureInitialized();
      if (!this.stream || this.isClosed) {
        throw new Error("AuditLogWriter stream is not available");
      }

      const line = JSON.stringify(event) + "\n";
      const canWriteMore = this.stream.write(line);

      if (!canWriteMore) {
        await new Promise<void>((resolve) => {
          this.stream?.once("drain", resolve);
        });
      }
    });

    this.appendQueue = task.catch(() => {});
    return task;
  }

  /**
   * Flushes all queued appends and cleanly closes the underlying file stream.
   */
  async close(): Promise<void> {
    if (this.isClosed) return;
    this.isClosed = true;

    await this.appendQueue;

    if (this.stream) {
      const streamToClose = this.stream;
      this.stream = null;
      await new Promise<void>((resolve, reject) => {
        streamToClose.end((err?: Error | null) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }
}
