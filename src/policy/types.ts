export type PolicyLevel =
  | "GLOBAL"
  | "OU"
  | "ACCOUNT"
  | "BUCKET_TAG"
  | "OBJECT_TAG";

export type ActionMode =
  | "MONITOR_ONLY"
  | "PLAN_ONLY"
  | "AUTO_REMEDIATE";

export type StorageClass =
  | "STANDARD_IA"
  | "ONEZONE_IA"
  | "INTELLIGENT_TIERING"
  | "GLACIER_IR"
  | "GLACIER"
  | "DEEP_ARCHIVE";

export interface PolicyScope {
  level: PolicyLevel;
  organizationId?: string;
  ouId?: string;
  accountId?: string;
  priority?: number;
}

export interface PolicyDefaults {
  action?: ActionMode;
  mpuAbortDays?: number;
  retainVersions?: number;
  maxNoncurrentDays?: number;
}

export interface BucketMatchCriteria {
  nameRegex?: string;
  regions?: string[];
  tags?: Record<string, string>;
}

export interface ObjectMatchCriteria {
  prefix?: string;
  tags?: Record<string, string>;
  minSizeKb?: number;
}

export interface RuleMatchCriteria {
  bucket?: BucketMatchCriteria;
  object?: ObjectMatchCriteria;
}

export interface RuleTransition {
  days: number;
  storageClass: StorageClass;
  minSizeKb?: number;
}

export interface PolicyRule {
  id: string;
  match: RuleMatchCriteria;
  action?: ActionMode;
  transitions?: RuleTransition[];
  expirationDays?: number;
  noncurrentExpirationDays?: number;
  retainVersions?: number;
  mpuAbortDays?: number;
}

export interface GuardianPolicy {
  schemaVersion: "1";
  policyId: string;
  scope: PolicyScope;
  defaults?: PolicyDefaults;
  rules: PolicyRule[];
}

export interface RuleProvenance {
  policyId: string;
  ruleId: string;
  level: PolicyLevel;
}

export interface EffectivePolicyRule extends PolicyRule {
  action: ActionMode;
  provenance?: Record<string, RuleProvenance>;
}

export interface ResolvedPolicy {
  bucketName: string;
  action: ActionMode;
  effectiveRules: EffectivePolicyRule[];
  provenance: Record<string, RuleProvenance>;
}

export interface BucketMetadata {
  name: string;
  region: string;
  accountId?: string;
  ouId?: string;
  tags: Record<string, string>;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Precedence order: Local Object Tag (40) > Bucket Tag (30) > Account (25) > OU (20) > Global Org (10) */
export const POLICY_LEVEL_PRECEDENCE: Record<PolicyLevel, number> = {
  OBJECT_TAG: 40,
  BUCKET_TAG: 30,
  ACCOUNT: 25,
  OU: 20,
  GLOBAL: 10,
};

/** Action mode restrictiveness order: lowest rank wins (MONITOR_ONLY < PLAN_ONLY < AUTO_REMEDIATE) */
export const ACTION_MODE_PRECEDENCE: Record<ActionMode, number> = {
  MONITOR_ONLY: 1,
  PLAN_ONLY: 2,
  AUTO_REMEDIATE: 3,
};
