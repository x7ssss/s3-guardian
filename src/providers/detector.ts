export type S3Provider =
  | "aws"
  | "r2"
  | "wasabi"
  | "b2"
  | "minio"
  | "ceph"
  | "custom";

export const KNOWN_PROVIDERS: readonly S3Provider[] = [
  "aws",
  "r2",
  "wasabi",
  "b2",
  "minio",
  "ceph",
  "custom",
];

export const PROVIDER_REGEXES: Record<
  Exclude<S3Provider, "aws" | "custom">,
  RegExp
> = {
  r2: /\.r2\.cloudflarestorage\.com|\.r2\.dev/i,
  wasabi: /\.wasabisys\.com/i,
  b2: /\.backblazeb2\.com/i,
  minio: /:9000$|:9000\/|minio\./i,
  ceph: /:7480$|:7480\/|\.ceph\.|ceph\./i,
};

/**
 * Detects the S3 backend provider from the endpoint URL or explicit provider override.
 *
 * Matching rules:
 * - Explicit provider overrides auto-detection if specified.
 * - R2: /\.r2\.cloudflarestorage\.com/ or /\.r2\.dev/
 * - Wasabi: /\.wasabisys\.com/
 * - B2: /\.backblazeb2\.com/
 * - MinIO: /:9000$|minio\./
 * - Ceph: /:7480$|\.ceph\./
 * - Falls back to 'aws' if no endpoint or standard AWS domain.
 */
export function detectProvider(
  endpoint?: string | null,
  explicitProvider?: string | null
): S3Provider {
  if (explicitProvider && explicitProvider.trim()) {
    const norm = explicitProvider.trim().toLowerCase();
    if (KNOWN_PROVIDERS.includes(norm as S3Provider)) {
      return norm as S3Provider;
    }
    return "custom";
  }

  if (!endpoint || !endpoint.trim()) {
    return "aws";
  }

  const clean = endpoint.trim().replace(/\/+$/, "");

  if (PROVIDER_REGEXES.r2.test(clean)) {
    return "r2";
  }
  if (PROVIDER_REGEXES.wasabi.test(clean)) {
    return "wasabi";
  }
  if (PROVIDER_REGEXES.b2.test(clean)) {
    return "b2";
  }
  if (
    PROVIDER_REGEXES.minio.test(clean) ||
    clean.includes("localhost:9000") ||
    clean.includes("127.0.0.1:9000")
  ) {
    return "minio";
  }
  if (
    PROVIDER_REGEXES.ceph.test(clean) ||
    clean.includes(":7480")
  ) {
    return "ceph";
  }
  if (/\.amazonaws\.com/i.test(clean)) {
    return "aws";
  }

  return "custom";
}

/**
 * Returns a user-friendly display name for the detected S3 provider.
 */
export function getProviderDisplayName(provider: S3Provider): string {
  switch (provider) {
    case "aws":
      return "AWS S3";
    case "r2":
      return "Cloudflare R2";
    case "wasabi":
      return "Wasabi";
    case "b2":
      return "Backblaze B2";
    case "minio":
      return "MinIO";
    case "ceph":
      return "Ceph RADOS Gateway";
    case "custom":
      return "Custom S3";
  }
}
