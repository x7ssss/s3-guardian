import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { withRetry, RetryOptions } from "../utils/retry.js";

export interface AssumeRoleOptions {
  accountId: string;
  roleName: string;
  externalId?: string;
  roleSessionName?: string;
  durationSeconds?: number;
}

export interface AssumedRoleCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
  roleArn: string;
  accountId: string;
  roleName: string;
  assumedRoleId?: string;
}

export interface STSSessionPoolOptions {
  stsClient?: STSClient;
  proactiveRefreshWindowMs?: number;
  defaultDurationSeconds?: number;
  maxRetries?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  nowFn?: () => Date;
  sleepFn?: (ms: number) => Promise<void>;
}

/**
 * Detects if an error from STS is a rate-limiting or throttling error.
 */
export function isStsThrottlingError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as Record<string, unknown>;
  const name = String(e.name || e.Code || "");
  const message = String(e.message || "");
  const status =
    (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    e.statusCode ??
    e.status;

  return (
    status === 429 ||
    status === 503 ||
    name === "ThrottlingException" ||
    name === "Throttling" ||
    name === "RequestLimitExceeded" ||
    name === "SlowDown" ||
    /throttl|rate.?exceeded|request.?limit/i.test(message)
  );
}

/**
 * Thread-safe pool managing assumed-role STS credentials with proactive refresh
 * and full jitter exponential backoff on STS ThrottlingException.
 *
 * Invariants:
 *  - Caches credentials by `${accountId}:${roleName}:${externalId || 'none'}`.
 *  - Proactively refreshes credentials when remaining lifetime <= proactiveRefreshWindowMs (default 5 min).
 *  - Full jitter exponential backoff on STS throttling to avoid synchronized retry storms.
 *  - Isolates credentials per role assumption; callers receive static credential identities.
 */
export class STSSessionPool {
  private readonly client: STSClient;
  private readonly ownsClient: boolean;
  private readonly cache = new Map<string, AssumedRoleCredentials>();
  private readonly inFlight = new Map<string, Promise<AssumedRoleCredentials>>();
  private readonly proactiveRefreshWindowMs: number;
  private readonly defaultDurationSeconds: number;
  private readonly maxRetries: number;
  private readonly initialDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly nowFn: () => Date;
  private readonly sleepFn?: (ms: number) => Promise<void>;
  private destroyed = false;

  constructor(options: STSSessionPoolOptions = {}) {
    if (options.stsClient) {
      this.client = options.stsClient;
      this.ownsClient = false;
    } else {
      this.client = new STSClient({ region: "us-east-1" });
      this.ownsClient = true;
    }

    this.proactiveRefreshWindowMs = options.proactiveRefreshWindowMs ?? 300_000; // 5 minutes
    this.defaultDurationSeconds = options.defaultDurationSeconds ?? 3600; // 1 hour
    this.maxRetries = options.maxRetries ?? 5;
    this.initialDelayMs = options.initialDelayMs ?? 100;
    this.maxDelayMs = options.maxDelayMs ?? 3000;
    this.nowFn = options.nowFn ?? (() => new Date());
    this.sleepFn = options.sleepFn;
  }

  /**
   * Generates a cache key for the requested session.
   */
  private getCacheKey(accountId: string, roleName: string, externalId?: string): string {
    return `${accountId}:${roleName}:${externalId || "none"}`;
  }

  /**
   * Constructs the full IAM role ARN if not already fully qualified.
   */
  private formatRoleArn(accountId: string, roleName: string): string {
    if (roleName.startsWith("arn:aws:iam::")) {
      return roleName;
    }
    return `arn:aws:iam::${accountId}:role/${roleName}`;
  }

  /**
   * Generates a compliant RoleSessionName (2-64 chars, regex [\w+=,.@-]*).
   */
  private generateSessionName(accountId: string, roleSessionName?: string): string {
    if (roleSessionName) {
      return roleSessionName.replace(/[^\w+=,.@-]/g, "-").slice(0, 64);
    }
    const cleanAccount = accountId.replace(/[^\w]/g, "");
    const suffix = Date.now().toString(36);
    return `s3-guardian-${cleanAccount}-${suffix}`.slice(0, 64);
  }

  /**
   * Retrieves valid credentials from cache or assumes the role via STS.
   * Proactively refreshes if session expiration is within the proactive refresh window.
   */
  async assumeRole(options: AssumeRoleOptions): Promise<AssumedRoleCredentials> {
    if (this.destroyed) {
      throw new Error("STSSessionPool has been destroyed; cannot assume role");
    }

    const { accountId, roleName, externalId } = options;
    const cacheKey = this.getCacheKey(accountId, roleName, externalId);
    const now = this.nowFn();

    // Check cached credentials
    const cached = this.cache.get(cacheKey);
    if (cached) {
      const remainingLifetimeMs = cached.expiration.getTime() - now.getTime();
      if (remainingLifetimeMs > this.proactiveRefreshWindowMs) {
        return cached;
      }
    }

    // Deduplicate in-flight assumeRole calls for the same role
    const activePromise = this.inFlight.get(cacheKey);
    if (activePromise) {
      return activePromise;
    }

    const fetchPromise = this.executeAssumeRole(options, cacheKey);
    this.inFlight.set(cacheKey, fetchPromise);

    try {
      return await fetchPromise;
    } finally {
      this.inFlight.delete(cacheKey);
    }
  }

  private async executeAssumeRole(
    options: AssumeRoleOptions,
    cacheKey: string
  ): Promise<AssumedRoleCredentials> {
    const { accountId, roleName, externalId, roleSessionName } = options;
    const roleArn = this.formatRoleArn(accountId, roleName);
    const sessionName = this.generateSessionName(accountId, roleSessionName);

    // Duration must be between 900 and 43200 seconds
    const durationSeconds = Math.max(
      900,
      Math.min(43200, options.durationSeconds ?? this.defaultDurationSeconds)
    );

    const retryOpts: RetryOptions = {
      maxRetries: this.maxRetries,
      initialDelayMs: this.initialDelayMs,
      maxDelayMs: this.maxDelayMs,
      shouldRetry: isStsThrottlingError,
      sleepFn: this.sleepFn,
    };

    const command = new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: sessionName,
      DurationSeconds: durationSeconds,
      ExternalId: externalId || undefined,
    });

    const response = await withRetry(() => this.client.send(command), retryOpts);

    if (
      !response.Credentials ||
      !response.Credentials.AccessKeyId ||
      !response.Credentials.SecretAccessKey ||
      !response.Credentials.SessionToken ||
      !response.Credentials.Expiration
    ) {
      throw new Error(
        `STS AssumeRole did not return complete credentials for role ARN: ${roleArn}`
      );
    }

    const creds: AssumedRoleCredentials = {
      accessKeyId: response.Credentials.AccessKeyId,
      secretAccessKey: response.Credentials.SecretAccessKey,
      sessionToken: response.Credentials.SessionToken,
      expiration: response.Credentials.Expiration,
      roleArn,
      accountId,
      roleName,
      assumedRoleId: response.AssumedRoleUser?.AssumedRoleId,
    };

    this.cache.set(cacheKey, creds);
    return creds;
  }

  /**
   * Returns the count of active cached sessions.
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Clears cached sessions.
   */
  clear(): void {
    this.cache.clear();
    this.inFlight.clear();
  }

  /**
   * Tears down the pool and optional underlying STS client.
   */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;
    this.clear();
    if (this.ownsClient) {
      this.client.destroy();
    }
  }
}
