/**
 * Zero-allocation volumetric ring buffer using Float32Array.
 * Maintains a continuous running sum for O(1) error rate computation without V8 GC churn.
 */
export class VolumetricRingBuffer {
  private readonly buffer: Float32Array;
  private readonly windowSize: number;
  private pointer: number = 0;
  private count: number = 0;
  private runningSum: number = 0;

  constructor(windowSize: number = 200) {
    if (windowSize <= 0 || !Number.isInteger(windowSize)) {
      throw new Error("windowSize must be a positive integer");
    }
    this.windowSize = windowSize;
    this.buffer = new Float32Array(windowSize);
  }

  /**
   * Records a batch or item outcome with an error ratio [0.0, 1.0].
   */
  recordOutcome(errorRatio: number): void {
    const clamped = Math.max(0, Math.min(1, Number.isFinite(errorRatio) ? errorRatio : 1));
    const oldValue = this.buffer[this.pointer]!;

    this.buffer[this.pointer] = clamped;
    this.runningSum = Math.max(0, this.runningSum - oldValue + clamped);

    this.pointer = (this.pointer + 1) % this.windowSize;
    if (this.count < this.windowSize) {
      this.count++;
    }
  }

  /**
   * Returns the current moving error rate in [0.0, 1.0] in O(1) time.
   */
  getErrorRate(): number {
    if (this.count === 0) {
      return 0;
    }
    const rate = this.runningSum / this.count;
    return Math.max(0, Math.min(1, rate));
  }

  /**
   * Returns the number of recorded samples up to windowSize.
   */
  getCount(): number {
    return this.count;
  }

  /**
   * Returns the total capacity / window size.
   */
  getWindowSize(): number {
    return this.windowSize;
  }

  /**
   * Resets the buffer back to pristine empty state.
   */
  reset(): void {
    this.buffer.fill(0);
    this.pointer = 0;
    this.count = 0;
    this.runningSum = 0;
  }
}
