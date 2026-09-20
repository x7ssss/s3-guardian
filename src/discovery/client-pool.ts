import { S3Client, S3ClientConfig } from "@aws-sdk/client-s3";

/**
 * A thread-safe, cached registry of S3Client instances keyed by AWS region.
 *
 * Invariants:
 *  - One client per region is created lazily and reused for all requests.
 *  - `followRegionRedirects: false` keeps routing explicit; callers are
 *    responsible for resolving the correct region before dispatching.
 *  - `destroy()` tears down all regional clients cleanly (e.g. on process exit).
 */
export class S3ClientPool {
  private readonly clients = new Map<string, S3Client>();
  private readonly baseConfig: Omit<S3ClientConfig, "region">;
  private destroyed = false;

  constructor(baseConfig: Omit<S3ClientConfig, "region"> = {}) {
    this.baseConfig = {
      ...baseConfig,
      // Explicit routing: never silently follow redirects to another region
      followRegionRedirects: false,
    };
  }

  /**
   * Returns (or lazily creates) a cached S3Client for the given region.
   * Throws if the pool has been destroyed.
   */
  getClient(region: string): S3Client {
    if (this.destroyed) {
      throw new Error(
        `S3ClientPool has been destroyed; cannot get client for region "${region}"`
      );
    }

    const existing = this.clients.get(region);
    if (existing) {
      return existing;
    }

    const client = new S3Client({
      ...this.baseConfig,
      region,
    });

    this.clients.set(region, client);
    return client;
  }

  /**
   * Returns all currently cached regions.
   */
  get regions(): string[] {
    return Array.from(this.clients.keys());
  }

  /**
   * Returns the number of cached regional clients.
   */
  get size(): number {
    return this.clients.size;
  }

  /**
   * Tears down all regional clients and marks the pool as destroyed.
   * Subsequent calls to `getClient()` will throw.
   * Safe to call multiple times.
   */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;

    const destroyPromises: Promise<void>[] = [];
    for (const [, client] of this.clients) {
      // S3Client.destroy() is synchronous in @aws-sdk v3 but wrapped for
      // forward-compatibility if a future version makes it async.
      destroyPromises.push(Promise.resolve(client.destroy()));
    }
    await Promise.all(destroyPromises);
    this.clients.clear();
  }
}
