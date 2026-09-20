export const BYTES_PER_GIB = 1024 * 1024 * 1024; // 1,073,741,824 bytes
export const S3_STANDARD_PRICE_PER_GIB_MONTH = 0.023; // AWS S3 Standard baseline ($0.023/GB/month)

/**
 * Calculates monthly financial waste in USD based on stranded bytes.
 * Uses AWS S3 Standard baseline ($0.023 / GiB / month).
 * Returns rounded to the cent (2 decimal places).
 */
export function calculateMonthlyCostUSD(
  bytes: number,
  pricePerGiB: number = S3_STANDARD_PRICE_PER_GIB_MONTH
): number {
  if (bytes <= 0) return 0;
  const cost = (bytes / BYTES_PER_GIB) * pricePerGiB;
  return Math.round(cost * 100) / 100;
}

/**
 * Formats a monthly dollar cost to the cent, e.g. "$12.34/mo".
 */
export function formatMonthlyCost(costUSD: number): string {
  const safeCost = Math.max(0, costUSD);
  return `$${safeCost.toFixed(2)}/mo`;
}

/**
 * Formats raw byte count into human-readable representation (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const unitIndex = Math.min(i, units.length - 1);

  if (unitIndex === 0) {
    return `${bytes} B`;
  }

  const value = bytes / Math.pow(k, unitIndex);
  return `${value.toFixed(2)} ${units[unitIndex]}`;
}
