export interface RetryOptions {
  maxRetries?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  shouldRetry?: (error: unknown) => boolean;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
  sleepFn?: (ms: number) => Promise<void>;
}

/**
 * Detects if an error is an AWS S3 503 Slow Down rate-limiting error.
 */
export function isSlowDownError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as Record<string, unknown>;
  const status =
    (err.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    err.statusCode ??
    err.status;
  const name = String(err.name || err.Code || "");
  const message = String(err.message || "");

  return (
    status === 503 ||
    name === "SlowDown" ||
    name === "Throttling" ||
    name === "ThrottlingException" ||
    /slow down|slowdown|503/i.test(message)
  );
}

const defaultSleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Executes an asynchronous action with exponential backoff and full jitter.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const maxRetries = options.maxRetries ?? 5;
  const initialDelayMs = options.initialDelayMs ?? 100;
  const maxDelayMs = options.maxDelayMs ?? 3000;
  const shouldRetry = options.shouldRetry ?? isSlowDownError;
  const sleep = options.sleepFn ?? defaultSleep;

  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt++;
      if (attempt > maxRetries || !shouldRetry(err)) {
        throw err;
      }

      // Exponential backoff with full jitter: sleep = rand(0, min(maxDelay, initialDelay * 2^(attempt - 1)))
      const backoffCap = Math.min(
        maxDelayMs,
        initialDelayMs * Math.pow(2, attempt - 1)
      );
      const delayMs = Math.floor(Math.random() * backoffCap);

      options.onRetry?.(err, attempt, delayMs);
      await sleep(delayMs);
    }
  }
}
