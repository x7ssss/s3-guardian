export type LimitFunction = <T>(fn: () => Promise<T>) => Promise<T>;

/**
 * Creates a bounded concurrency runner without external dependencies.
 * Ensures that no more than `concurrency` asynchronous tasks run simultaneously.
 */
export function createConcurrencyLimiter(concurrency: number): LimitFunction {
  if (concurrency < 1) {
    throw new Error("Concurrency must be at least 1");
  }

  let activeCount = 0;
  const queue: (() => void)[] = [];

  const resumeNext = () => {
    activeCount--;
    if (queue.length > 0) {
      activeCount++;
      const nextFn = queue.shift()!;
      nextFn();
    }
  };

  return async function limit<T>(fn: () => Promise<T>): Promise<T> {
    if (activeCount >= concurrency) {
      await new Promise<void>((resolve) => queue.push(resolve));
    } else {
      activeCount++;
    }

    try {
      return await fn();
    } finally {
      resumeNext();
    }
  };
}
