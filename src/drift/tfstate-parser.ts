/**
 * Terraform State (v4) Parser for S3 Bucket Lifecycle Configurations.
 *
 * Invariants:
 *  - Zero third-party parser dependencies (uses native JSON.parse).
 *  - Parses Terraform state schema version 4.
 *  - Extracts resource instances of type `aws_s3_bucket_lifecycle_configuration`
 *    and legacy `aws_s3_bucket` with inline `lifecycle_rule`.
 *  - Normalizes lifecycle rules into a consistent representation for drift comparison.
 */

export interface ManagedTransition {
  days?: number;
  date?: string;
  storageClass: string;
}

export interface ManagedNoncurrentTransition {
  noncurrentDays?: number;
  storageClass: string;
}

export interface ManagedLifecycleRule {
  id: string;
  status: "Enabled" | "Disabled";
  prefix?: string;
  abortIncompleteMultipartUploadDays?: number;
  noncurrentVersionExpirationDays?: number;
  expiredObjectDeleteMarker?: boolean;
  transitions?: ManagedTransition[];
  noncurrentVersionTransitions?: ManagedNoncurrentTransition[];
  objectSizeGreaterThan?: number;
  objectSizeLessThan?: number;
  hasObjectSizeGreaterThanFilter?: boolean;
  hasTagFilter?: boolean;
}

export interface ManagedBucketLifecycle {
  bucket: string;
  resourceType: "aws_s3_bucket_lifecycle_configuration" | "aws_s3_bucket";
  resourceName: string;
  module?: string;
  rules: ManagedLifecycleRule[];
}

export interface TerraformStateParseResult {
  version: number;
  terraformVersion?: string;
  buckets: Record<string, ManagedBucketLifecycle>;
  totalManagedBuckets: number;
}

interface RawTfStateResourceInstance {
  schema_version?: number;
  attributes?: Record<string, unknown>;
}

interface RawTfStateResource {
  mode?: string;
  type?: string;
  name?: string;
  module?: string;
  provider?: string;
  instances?: RawTfStateResourceInstance[];
}

interface RawTfState {
  version?: number;
  terraform_version?: string;
  resources?: RawTfStateResource[];
}

function parseNumber(val: unknown): number | undefined {
  if (typeof val === "number" && !isNaN(val)) return val;
  if (typeof val === "string") {
    const parsed = parseInt(val, 10);
    if (!isNaN(parsed)) return parsed;
  }
  return undefined;
}

function parseLifecycleConfigurationRule(rawRule: Record<string, unknown>): ManagedLifecycleRule {
  const id = typeof rawRule.id === "string" ? rawRule.id : "";
  const rawStatus = typeof rawRule.status === "string" ? rawRule.status : "";
  const status: "Enabled" | "Disabled" = rawStatus.toLowerCase() === "disabled" ? "Disabled" : "Enabled";

  let prefix: string | undefined;
  if (typeof rawRule.prefix === "string" && rawRule.prefix.length > 0) {
    prefix = rawRule.prefix;
  }

  // MPU Abort
  let abortDays: number | undefined;
  const abortBlock = rawRule.abort_incomplete_multipart_upload;
  if (Array.isArray(abortBlock) && abortBlock.length > 0 && typeof abortBlock[0] === "object" && abortBlock[0] !== null) {
    abortDays = parseNumber(abortBlock[0].days_after_initiation);
  } else if (typeof abortBlock === "object" && abortBlock !== null) {
    abortDays = parseNumber((abortBlock as Record<string, unknown>).days_after_initiation);
  }

  // Noncurrent Version Expiration
  let noncurrentDays: number | undefined;
  const noncurrentBlock = rawRule.noncurrent_version_expiration;
  if (Array.isArray(noncurrentBlock) && noncurrentBlock.length > 0 && typeof noncurrentBlock[0] === "object" && noncurrentBlock[0] !== null) {
    noncurrentDays = parseNumber(noncurrentBlock[0].noncurrent_days);
  } else if (typeof noncurrentBlock === "object" && noncurrentBlock !== null) {
    noncurrentDays = parseNumber((noncurrentBlock as Record<string, unknown>).noncurrent_days);
  }

  // Expired Object Delete Marker
  let expiredMarker: boolean | undefined;
  const expirationBlock = rawRule.expiration;
  if (Array.isArray(expirationBlock) && expirationBlock.length > 0 && typeof expirationBlock[0] === "object" && expirationBlock[0] !== null) {
    expiredMarker = expirationBlock[0].expired_object_delete_marker === true;
  } else if (typeof expirationBlock === "object" && expirationBlock !== null) {
    expiredMarker = (expirationBlock as Record<string, unknown>).expired_object_delete_marker === true;
  }

  // Transitions
  const transitions: ManagedTransition[] = [];
  const rawTransitions = rawRule.transition;
  if (Array.isArray(rawTransitions)) {
    for (const t of rawTransitions) {
      if (typeof t === "object" && t !== null) {
        const sc = typeof t.storage_class === "string" ? t.storage_class : "";
        if (sc) {
          transitions.push({
            days: parseNumber(t.days),
            date: typeof t.date === "string" && t.date ? t.date : undefined,
            storageClass: sc,
          });
        }
      }
    }
  }

  // Noncurrent Version Transitions
  const noncurrentTransitions: ManagedNoncurrentTransition[] = [];
  const rawNcTransitions = rawRule.noncurrent_version_transition;
  if (Array.isArray(rawNcTransitions)) {
    for (const t of rawNcTransitions) {
      if (typeof t === "object" && t !== null) {
        const sc = typeof t.storage_class === "string" ? t.storage_class : "";
        if (sc) {
          noncurrentTransitions.push({
            noncurrentDays: parseNumber(t.noncurrent_days),
            storageClass: sc,
          });
        }
      }
    }
  }

  // Filters: object_size_greater_than, object_size_less_than, tags, and prefix
  let objectSizeGreaterThan: number | undefined;
  let objectSizeLessThan: number | undefined;
  let hasTagFilter = false;

  const rawFilter = rawRule.filter;
  const filterObj = Array.isArray(rawFilter) && rawFilter.length > 0
    ? (rawFilter[0] as Record<string, unknown>)
    : typeof rawFilter === "object" && rawFilter !== null
    ? (rawFilter as Record<string, unknown>)
    : undefined;

  if (filterObj) {
    if (typeof filterObj.prefix === "string" && filterObj.prefix.length > 0 && !prefix) {
      prefix = filterObj.prefix;
    }
    const gt = parseNumber(filterObj.object_size_greater_than);
    if (gt !== undefined && gt > 0) {
      objectSizeGreaterThan = gt;
    }
    const lt = parseNumber(filterObj.object_size_less_than);
    if (lt !== undefined && lt > 0) {
      objectSizeLessThan = lt;
    }
    if (filterObj.tag && (Array.isArray(filterObj.tag) ? filterObj.tag.length > 0 : Object.keys(filterObj.tag).length > 0)) {
      hasTagFilter = true;
    }

    // Inspect nested 'and' inside filter if present
    const andBlock = Array.isArray(filterObj.and) && filterObj.and.length > 0
      ? (filterObj.and[0] as Record<string, unknown>)
      : typeof filterObj.and === "object" && filterObj.and !== null
      ? (filterObj.and as Record<string, unknown>)
      : undefined;

    if (andBlock) {
      if (typeof andBlock.prefix === "string" && andBlock.prefix.length > 0 && !prefix) {
        prefix = andBlock.prefix;
      }
      const andGt = parseNumber(andBlock.object_size_greater_than);
      if (andGt !== undefined && andGt > 0) {
        objectSizeGreaterThan = andGt;
      }
      const andLt = parseNumber(andBlock.object_size_less_than);
      if (andLt !== undefined && andLt > 0) {
        objectSizeLessThan = andLt;
      }
      if (andBlock.tags || andBlock.tag) {
        hasTagFilter = true;
      }
    }
  }

  return {
    id,
    status,
    prefix,
    abortIncompleteMultipartUploadDays: abortDays,
    noncurrentVersionExpirationDays: noncurrentDays,
    expiredObjectDeleteMarker: expiredMarker,
    transitions: transitions.length > 0 ? transitions : undefined,
    noncurrentVersionTransitions: noncurrentTransitions.length > 0 ? noncurrentTransitions : undefined,
    objectSizeGreaterThan,
    objectSizeLessThan,
    hasObjectSizeGreaterThanFilter: objectSizeGreaterThan !== undefined && objectSizeGreaterThan > 0,
    hasTagFilter,
  };
}

function parseLegacyBucketLifecycleRule(rawRule: Record<string, unknown>): ManagedLifecycleRule {
  const id = typeof rawRule.id === "string" ? rawRule.id : "";
  const enabled = rawRule.enabled !== false;
  const status: "Enabled" | "Disabled" = enabled ? "Enabled" : "Disabled";
  const prefix = typeof rawRule.prefix === "string" && rawRule.prefix ? rawRule.prefix : undefined;

  const abortDays = parseNumber(rawRule.abort_incomplete_multipart_upload_days);

  let noncurrentDays: number | undefined;
  const nc = rawRule.noncurrent_version_expiration;
  if (Array.isArray(nc) && nc.length > 0 && typeof nc[0] === "object" && nc[0] !== null) {
    noncurrentDays = parseNumber(nc[0].days);
  } else if (typeof nc === "object" && nc !== null) {
    noncurrentDays = parseNumber((nc as Record<string, unknown>).days);
  }

  const transitions: ManagedTransition[] = [];
  if (Array.isArray(rawRule.transition)) {
    for (const t of rawRule.transition) {
      if (typeof t === "object" && t !== null) {
        const sc = typeof t.storage_class === "string" ? t.storage_class : "";
        if (sc) {
          transitions.push({
            days: parseNumber(t.days),
            date: typeof t.date === "string" && t.date ? t.date : undefined,
            storageClass: sc,
          });
        }
      }
    }
  }

  const hasTagFilter = Boolean(rawRule.tags && typeof rawRule.tags === "object" && Object.keys(rawRule.tags).length > 0);

  return {
    id,
    status,
    prefix,
    abortIncompleteMultipartUploadDays: abortDays,
    noncurrentVersionExpirationDays: noncurrentDays,
    transitions: transitions.length > 0 ? transitions : undefined,
    hasTagFilter,
  };
}

/**
 * Parses a Terraform state JSON string and extracts all S3 bucket lifecycle configurations.
 */
export function parseTerraformState(stateJsonString: string): TerraformStateParseResult {
  let parsed: RawTfState;
  try {
    parsed = JSON.parse(stateJsonString) as RawTfState;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid Terraform state JSON: ${msg}`);
  }

  const version = parsed.version ?? 4;
  const terraformVersion = parsed.terraform_version;
  const buckets: Record<string, ManagedBucketLifecycle> = {};

  if (!Array.isArray(parsed.resources)) {
    return {
      version,
      terraformVersion,
      buckets,
      totalManagedBuckets: 0,
    };
  }

  for (const resource of parsed.resources) {
    if (!resource || resource.mode !== "managed" || !Array.isArray(resource.instances)) {
      continue;
    }

    // 1. aws_s3_bucket_lifecycle_configuration (modern Terraform AWS provider v4+)
    if (resource.type === "aws_s3_bucket_lifecycle_configuration") {
      for (const instance of resource.instances) {
        const attrs = instance.attributes;
        if (!attrs) continue;

        const bucketName = (typeof attrs.bucket === "string" && attrs.bucket) || (typeof attrs.id === "string" && attrs.id);
        if (!bucketName) continue;

        const rules: ManagedLifecycleRule[] = [];
        if (Array.isArray(attrs.rule)) {
          for (const rawRule of attrs.rule) {
            if (typeof rawRule === "object" && rawRule !== null) {
              rules.push(parseLifecycleConfigurationRule(rawRule as Record<string, unknown>));
            }
          }
        }

        // Direct aws_s3_bucket_lifecycle_configuration takes precedence over legacy resource
        buckets[bucketName] = {
          bucket: bucketName,
          resourceType: "aws_s3_bucket_lifecycle_configuration",
          resourceName: resource.name ?? "this",
          module: resource.module,
          rules,
        };
      }
    }

    // 2. aws_s3_bucket (legacy Terraform AWS provider with inline lifecycle_rule)
    if (resource.type === "aws_s3_bucket") {
      for (const instance of resource.instances) {
        const attrs = instance.attributes;
        if (!attrs) continue;

        const bucketName = (typeof attrs.bucket === "string" && attrs.bucket) || (typeof attrs.id === "string" && attrs.id);
        if (!bucketName) continue;

        // If already discovered via dedicated aws_s3_bucket_lifecycle_configuration, keep that
        if (buckets[bucketName] && buckets[bucketName].resourceType === "aws_s3_bucket_lifecycle_configuration") {
          continue;
        }

        const rawRules = attrs.lifecycle_rule;
        if (Array.isArray(rawRules) && rawRules.length > 0) {
          const rules: ManagedLifecycleRule[] = [];
          for (const rawRule of rawRules) {
            if (typeof rawRule === "object" && rawRule !== null) {
              rules.push(parseLegacyBucketLifecycleRule(rawRule as Record<string, unknown>));
            }
          }

          buckets[bucketName] = {
            bucket: bucketName,
            resourceType: "aws_s3_bucket",
            resourceName: resource.name ?? "this",
            module: resource.module,
            rules,
          };
        }
      }
    }
  }

  return {
    version,
    terraformVersion,
    buckets,
    totalManagedBuckets: Object.keys(buckets).length,
  };
}
