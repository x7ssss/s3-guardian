/**
 * Region normalization utilities for S3 bucket location resolution.
 *
 * AWS S3 has two legacy quirks we must handle:
 *   1. `GetBucketLocation` returns `null` / `undefined` / `""` for us-east-1.
 *   2. `GetBucketLocation` returns the string `"EU"` for eu-west-1 (pre-2006 buckets).
 */

/** The canonical fallback region for S3 buckets with no location constraint. */
export const US_EAST_1 = "us-east-1";

/** Legacy region string returned by GetBucketLocation for old EU buckets. */
export const LEGACY_EU_REGION = "EU";

/** Canonical region for legacy "EU" buckets. */
export const EU_WEST_1 = "eu-west-1";

/**
 * Normalizes a raw `LocationConstraint` value from `GetBucketLocationCommand`
 * into a canonical AWS region string.
 *
 * Handles:
 *   - `null` | `undefined` | `""` → `"us-east-1"` (S3 default region)
 *   - `"EU"` → `"eu-west-1"` (legacy location constraint)
 *   - Any other string → returned as-is
 */
export function normalizeBucketRegion(
  locationConstraint: string | null | undefined
): string {
  if (!locationConstraint || locationConstraint.trim() === "") {
    return US_EAST_1;
  }
  if (locationConstraint === LEGACY_EU_REGION) {
    return EU_WEST_1;
  }
  return locationConstraint;
}

/**
 * Resolves the canonical region for a bucket from `GetBucketLocation` output.
 * Accepts the full response shape from the AWS SDK.
 *
 * Falls back to `BucketRegion` (present in modern `ListBuckets` output
 * in some SDKs / endpoints) before applying normalizeBucketRegion.
 */
export function resolveBucketRegion(response: {
  LocationConstraint?: string | null;
  BucketRegion?: string | null;
}): string {
  // Modern SDK / endpoint may provide BucketRegion directly
  if (response.BucketRegion && response.BucketRegion.trim() !== "") {
    return normalizeBucketRegion(response.BucketRegion);
  }
  return normalizeBucketRegion(response.LocationConstraint);
}
