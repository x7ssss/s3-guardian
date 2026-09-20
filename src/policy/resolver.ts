import {
  GuardianPolicy,
  BucketMetadata,
  ResolvedPolicy,
  EffectivePolicyRule,
  PolicyLevel,
  ActionMode,
  POLICY_LEVEL_PRECEDENCE,
  ACTION_MODE_PRECEDENCE,
  RuleProvenance,
  PolicyRule,
} from "./types.js";

interface ScoredRule {
  rule: PolicyRule;
  policy: GuardianPolicy;
  level: PolicyLevel;
  levelScore: number;
  priority: number;
}

/**
 * Checks if a policy's scope matches the target bucket's account / OU.
 */
function scopeMatches(policy: GuardianPolicy, bucket: BucketMetadata): boolean {
  const { scope } = policy;
  if (scope.accountId && bucket.accountId && scope.accountId !== bucket.accountId) {
    return false;
  }
  if (scope.ouId && bucket.ouId && scope.ouId !== bucket.ouId) {
    return false;
  }
  return true;
}

/**
 * Checks if a rule's bucket match criteria matches the target bucket metadata.
 */
function bucketCriteriaMatches(rule: PolicyRule, bucket: BucketMetadata): boolean {
  const bucketMatch = rule.match?.bucket;
  if (!bucketMatch) {
    return true; // No bucket-level filter matches all buckets
  }

  // Name regex check
  if (bucketMatch.nameRegex) {
    try {
      const re = new RegExp(bucketMatch.nameRegex);
      if (!re.test(bucket.name)) {
        return false;
      }
    } catch {
      return false;
    }
  }

  // Region check
  if (bucketMatch.regions && bucketMatch.regions.length > 0) {
    if (!bucketMatch.regions.includes(bucket.region)) {
      return false;
    }
  }

  // Bucket tag matching (all specified tags must match)
  if (bucketMatch.tags) {
    for (const [k, v] of Object.entries(bucketMatch.tags)) {
      if (bucket.tags[k] !== v) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Resolves declarative policies against bucket metadata, applying:
 * 1. Precedence hierarchy (OBJECT_TAG > BUCKET_TAG > ACCOUNT > OU > GLOBAL).
 * 2. Fail-Safe action mode (lowest rank / most restrictive wins).
 * 3. Leaf-level property merging with fine-grained provenance tracking.
 */
export function resolveBucketPolicy(
  bucketMetadata: BucketMetadata,
  policies: GuardianPolicy[]
): ResolvedPolicy {
  const matchingPolicies: GuardianPolicy[] = [];
  const candidateRules: ScoredRule[] = [];

  for (const policy of policies) {
    if (!scopeMatches(policy, bucketMetadata)) {
      continue;
    }

    let policyMatched = false;
    const level = policy.scope.level;
    const levelScore = POLICY_LEVEL_PRECEDENCE[level] ?? 10;
    const priority = policy.scope.priority ?? 0;

    for (const rule of policy.rules) {
      if (bucketCriteriaMatches(rule, bucketMetadata)) {
        policyMatched = true;
        candidateRules.push({
          rule,
          policy,
          level,
          levelScore,
          priority,
        });
      }
    }

    if (policyMatched || (policy.defaults && Object.keys(policy.defaults).length > 0)) {
      matchingPolicies.push(policy);
    }
  }

  // Sort candidate rules in descending order of precedence:
  // 1. levelScore (OBJECT_TAG: 40 > BUCKET_TAG: 30 > ACCOUNT: 25 > OU: 20 > GLOBAL: 10)
  // 2. explicit priority (higher wins)
  // 3. deterministic tie-break by policyId, ruleId
  candidateRules.sort((a, b) => {
    if (b.levelScore !== a.levelScore) {
      return b.levelScore - a.levelScore;
    }
    if (b.priority !== a.priority) {
      return b.priority - a.priority;
    }
    const polCmp = a.policy.policyId.localeCompare(b.policy.policyId);
    if (polCmp !== 0) return polCmp;
    return a.rule.id.localeCompare(b.rule.id);
  });

  // Action Mode Resolution (Fail-Safe Invariant: lowest rank wins: MONITOR_ONLY < PLAN_ONLY < AUTO_REMEDIATE)
  const candidateActionModes: ActionMode[] = [];
  for (const sr of candidateRules) {
    if (sr.rule.action) {
      candidateActionModes.push(sr.rule.action);
    }
    if (sr.policy.defaults?.action) {
      candidateActionModes.push(sr.policy.defaults.action);
    }
  }

  let effectiveAction: ActionMode = "PLAN_ONLY";
  if (candidateActionModes.length > 0) {
    candidateActionModes.sort(
      (a, b) => ACTION_MODE_PRECEDENCE[a] - ACTION_MODE_PRECEDENCE[b]
    );
    effectiveAction = candidateActionModes[0]!;
  }

  // Leaf-level property merge with provenance tracking
  // Group rules by object match key (e.g. prefix + tags signature)
  const provenance: Record<string, RuleProvenance> = {};
  const groups = new Map<string, ScoredRule[]>();

  for (const sr of candidateRules) {
    const prefix = sr.rule.match?.object?.prefix ?? "";
    const groupKey = prefix;
    if (!groups.has(groupKey)) {
      groups.set(groupKey, []);
    }
    groups.get(groupKey)!.push(sr);
  }

  const effectiveRules: EffectivePolicyRule[] = [];

  for (const [groupKey, rulesInGroup] of groups.entries()) {
    // Highest precedence rule in this group acts as primary
    const primary = rulesInGroup[0]!;
    const mergedRule: EffectivePolicyRule = {
      id: primary.rule.id,
      match: {
        bucket: primary.rule.match?.bucket,
        object: {
          prefix: primary.rule.match?.object?.prefix,
          tags: primary.rule.match?.object?.tags,
          minSizeKb: primary.rule.match?.object?.minSizeKb,
        },
      },
      action: primary.rule.action ?? effectiveAction,
    };

    const ruleProvenance: Record<string, RuleProvenance> = {};

    // Merge leaf properties across rules in group from highest to lowest precedence
    // 1. mpuAbortDays
    for (const sr of rulesInGroup) {
      if (sr.rule.mpuAbortDays !== undefined) {
        if (mergedRule.mpuAbortDays === undefined) {
          mergedRule.mpuAbortDays = sr.rule.mpuAbortDays;
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["mpuAbortDays"] = prov;
          provenance["mpuAbortDays"] = prov;
          provenance[`${primary.rule.id}.mpuAbortDays`] = prov;
        }
      }
    }

    // Fall back to policy defaults for mpuAbortDays if not set
    if (mergedRule.mpuAbortDays === undefined) {
      for (const p of matchingPolicies) {
        if (p.defaults?.mpuAbortDays !== undefined) {
          mergedRule.mpuAbortDays = p.defaults.mpuAbortDays;
          const prov: RuleProvenance = {
            policyId: p.policyId,
            ruleId: "defaults",
            level: p.scope.level,
          };
          ruleProvenance["mpuAbortDays"] = prov;
          provenance["mpuAbortDays"] = prov;
          provenance[`${primary.rule.id}.mpuAbortDays`] = prov;
          break;
        }
      }
    }

    // 2. expirationDays
    for (const sr of rulesInGroup) {
      if (sr.rule.expirationDays !== undefined) {
        if (mergedRule.expirationDays === undefined) {
          mergedRule.expirationDays = sr.rule.expirationDays;
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["expirationDays"] = prov;
          provenance["expirationDays"] = prov;
          provenance[`${primary.rule.id}.expirationDays`] = prov;
        }
      }
    }

    // 3. transitions
    for (const sr of rulesInGroup) {
      if (sr.rule.transitions && sr.rule.transitions.length > 0) {
        if (mergedRule.transitions === undefined) {
          mergedRule.transitions = [...sr.rule.transitions];
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["transitions"] = prov;
          provenance["transitions"] = prov;
          provenance[`${primary.rule.id}.transitions`] = prov;
        }
      }
    }

    // 4. noncurrentExpirationDays
    for (const sr of rulesInGroup) {
      if (sr.rule.noncurrentExpirationDays !== undefined) {
        if (mergedRule.noncurrentExpirationDays === undefined) {
          mergedRule.noncurrentExpirationDays = sr.rule.noncurrentExpirationDays;
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["noncurrentExpirationDays"] = prov;
          provenance["noncurrentExpirationDays"] = prov;
          provenance[`${primary.rule.id}.noncurrentExpirationDays`] = prov;
        }
      }
    }

    // Fall back to policy defaults for maxNoncurrentDays
    if (mergedRule.noncurrentExpirationDays === undefined) {
      for (const p of matchingPolicies) {
        if (p.defaults?.maxNoncurrentDays !== undefined) {
          mergedRule.noncurrentExpirationDays = p.defaults.maxNoncurrentDays;
          const prov: RuleProvenance = {
            policyId: p.policyId,
            ruleId: "defaults",
            level: p.scope.level,
          };
          ruleProvenance["noncurrentExpirationDays"] = prov;
          provenance["noncurrentExpirationDays"] = prov;
          provenance[`${primary.rule.id}.noncurrentExpirationDays`] = prov;
          break;
        }
      }
    }

    // 5. retainVersions
    for (const sr of rulesInGroup) {
      if (sr.rule.retainVersions !== undefined) {
        if (mergedRule.retainVersions === undefined) {
          mergedRule.retainVersions = sr.rule.retainVersions;
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["retainVersions"] = prov;
          provenance["retainVersions"] = prov;
          provenance[`${primary.rule.id}.retainVersions`] = prov;
        }
      }
    }

    if (mergedRule.retainVersions === undefined) {
      for (const p of matchingPolicies) {
        if (p.defaults?.retainVersions !== undefined) {
          mergedRule.retainVersions = p.defaults.retainVersions;
          const prov: RuleProvenance = {
            policyId: p.policyId,
            ruleId: "defaults",
            level: p.scope.level,
          };
          ruleProvenance["retainVersions"] = prov;
          provenance["retainVersions"] = prov;
          provenance[`${primary.rule.id}.retainVersions`] = prov;
          break;
        }
      }
    }

    // 6. object minSizeKb
    for (const sr of rulesInGroup) {
      if (sr.rule.match?.object?.minSizeKb !== undefined) {
        if (mergedRule.match.object!.minSizeKb === undefined) {
          mergedRule.match.object!.minSizeKb = sr.rule.match.object.minSizeKb;
          const prov: RuleProvenance = {
            policyId: sr.policy.policyId,
            ruleId: sr.rule.id,
            level: sr.level,
          };
          ruleProvenance["minSizeKb"] = prov;
          provenance["minSizeKb"] = prov;
          provenance[`${primary.rule.id}.minSizeKb`] = prov;
        }
      }
    }

    mergedRule.provenance = ruleProvenance;
    effectiveRules.push(mergedRule);
  }

  // If no rules existed but matching policies had defaults (e.g. default mpuAbortDays)
  if (effectiveRules.length === 0 && matchingPolicies.length > 0) {
    for (const p of matchingPolicies) {
      if (p.defaults?.mpuAbortDays !== undefined) {
        const prov: RuleProvenance = {
          policyId: p.policyId,
          ruleId: "defaults",
          level: p.scope.level,
        };
        provenance["mpuAbortDays"] = prov;
        provenance["default-mpu-abort.mpuAbortDays"] = prov;

        effectiveRules.push({
          id: "default-mpu-abort",
          match: {},
          action: effectiveAction,
          mpuAbortDays: p.defaults.mpuAbortDays,
          provenance: { mpuAbortDays: prov },
        });
        break;
      }
    }
  }

  return {
    bucketName: bucketMetadata.name,
    action: effectiveAction,
    effectiveRules,
    provenance,
  };
}
