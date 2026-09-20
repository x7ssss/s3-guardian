/**
 * HCL Patcher and POSIX Unified Diff Generator for Terraform S3 Lifecycle Configurations.
 *
 * Invariants:
 *  - Strictly ZERO external diff or parser libraries.
 *  - Generates standard POSIX unified diff format compatible with `git apply`.
 *  - Inspects existing `aws_s3_bucket_lifecycle_configuration` resource blocks.
 *  - Supports:
 *      1. Injecting `abort_incomplete_multipart_upload` rules.
 *      2. Injecting `noncurrent_version_expiration` rules.
 *      3. Constraining unconstrained transition rules with `object_size_greater_than = 131072`.
 *      4. Appending brand-new `aws_s3_bucket_lifecycle_configuration` resource if none exists.
 */

export interface DriftRecommendations {
  missingAbortMpu?: boolean;
  abortMpuDays?: number; // default: 7
  missingNoncurrentExpiration?: boolean;
  noncurrentDays?: number; // default: 30
  missingEodm?: boolean; // default: true
  missingTransitionFilterRuleIds?: string[];
  targetMinSizeBytes?: number; // default: 131072
  tfFilePath?: string; // default: "main.tf"
}

export interface HclPatchResult {
  patch: string;
  patchedContent: string;
  modified: boolean;
}

interface DiffOp {
  type: "equal" | "delete" | "insert";
  line: string;
}

/**
 * Computes standard unified diff between original and patched strings.
 */
export function createUnifiedDiff(
  originalContent: string,
  patchedContent: string,
  filePath = "main.tf"
): string {
  if (originalContent === patchedContent) {
    return "";
  }

  const oldLines = originalContent.split("\n");
  const newLines = patchedContent.split("\n");

  const ops = computeLcsDiff(oldLines, newLines);
  const hunks = buildUnifiedHunks(ops, 3);

  if (hunks.length === 0) {
    return "";
  }

  const sanitizedPath = filePath.replace(/\\/g, "/");
  const header = `--- a/${sanitizedPath}\n+++ b/${sanitizedPath}\n`;
  return header + hunks.join("\n") + "\n";
}

function computeLcsDiff(a: string[], b: string[]): DiffOp[] {
  const m = a.length;
  const n = b.length;

  if (m === 0) {
    return b.map((line) => ({ type: "insert", line }));
  }
  if (n === 0) {
    return a.map((line) => ({ type: "delete", line }));
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (a[i] === b[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const result: DiffOp[] = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      result.push({ type: "equal", line: a[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.push({ type: "insert", line: b[j - 1] });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      result.push({ type: "delete", line: a[i - 1] });
      i--;
    }
  }

  return result.reverse();
}

function buildUnifiedHunks(ops: DiffOp[], context = 3): string[] {
  interface HunkRange {
    start: number;
    end: number; // inclusive
  }

  const changeIndices: number[] = [];
  for (let i = 0; i < ops.length; i++) {
    if (ops[i].type !== "equal") {
      changeIndices.push(i);
    }
  }

  if (changeIndices.length === 0) return [];

  const rawRanges: HunkRange[] = [];
  for (const idx of changeIndices) {
    rawRanges.push({
      start: Math.max(0, idx - context),
      end: Math.min(ops.length - 1, idx + context),
    });
  }

  // Merge overlapping or adjacent ranges
  const mergedRanges: HunkRange[] = [];
  let cur = rawRanges[0];
  for (let i = 1; i < rawRanges.length; i++) {
    if (rawRanges[i].start <= cur.end + 1) {
      cur.end = Math.max(cur.end, rawRanges[i].end);
    } else {
      mergedRanges.push(cur);
      cur = rawRanges[i];
    }
  }
  mergedRanges.push(cur);

  // Build each hunk
  const hunks: string[] = [];

  // Track 1-based line positions in original and patched files
  let oldLineNum = 1;
  let newLineNum = 1;
  let opIdx = 0;

  for (const range of mergedRanges) {
    // Advance to range.start
    while (opIdx < range.start) {
      if (ops[opIdx].type === "equal" || ops[opIdx].type === "delete") oldLineNum++;
      if (ops[opIdx].type === "equal" || ops[opIdx].type === "insert") newLineNum++;
      opIdx++;
    }

    const hunkOldStart = oldLineNum;
    const hunkNewStart = newLineNum;
    let hunkOldCount = 0;
    let hunkNewCount = 0;
    const hunkLines: string[] = [];

    while (opIdx <= range.end) {
      const op = ops[opIdx];
      if (op.type === "equal") {
        hunkLines.push(" " + op.line);
        hunkOldCount++;
        hunkNewCount++;
        oldLineNum++;
        newLineNum++;
      } else if (op.type === "delete") {
        hunkLines.push("-" + op.line);
        hunkOldCount++;
        oldLineNum++;
      } else if (op.type === "insert") {
        hunkLines.push("+" + op.line);
        hunkNewCount++;
        newLineNum++;
      }
      opIdx++;
    }

    const hunkHeader = `@@ -${hunkOldStart},${hunkOldCount} +${hunkNewStart},${hunkNewCount} @@`;
    hunks.push([hunkHeader, ...hunkLines].join("\n"));
  }

  return hunks;
}

/**
 * Finds the bounds [startIndex, endIndex] of the `aws_s3_bucket_lifecycle_configuration` resource
 * associated with `bucketName` inside `content`.
 */
function findLifecycleResourceBounds(
  content: string,
  bucketName: string
): { startIndex: number; endIndex: number; resourceName: string } | null {
  const resourceRegex = /resource\s+"aws_s3_bucket_lifecycle_configuration"\s+"([^"]+)"\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = resourceRegex.exec(content)) !== null) {
    const resourceName = match[1];
    const startIndex = match.index;
    const openBraceIndex = content.indexOf("{", startIndex);
    if (openBraceIndex === -1) continue;

    // Find matching closing brace
    let depth = 1;
    let i = openBraceIndex + 1;
    while (i < content.length && depth > 0) {
      if (content[i] === "{") depth++;
      else if (content[i] === "}") depth--;
      i++;
    }

    if (depth === 0) {
      const endIndex = i; // exclusive
      const blockBody = content.slice(startIndex, endIndex);

      // Check if this resource targets bucketName
      const directMatch = new RegExp(`bucket\\s*=\\s*["']?${escapeRegExp(bucketName)}["']?`).test(blockBody);
      const safeBucket = bucketName.replace(/[^a-zA-Z0-9_]/g, "_");
      const nameMatch = resourceName === `lifecycle_${safeBucket}` || resourceName === safeBucket;
      const refMatch = new RegExp(`aws_s3_bucket\\.${escapeRegExp(safeBucket)}\\.(id|bucket)`).test(blockBody);

      if (directMatch || nameMatch || refMatch) {
        return { startIndex, endIndex, resourceName };
      }
    }
  }

  return null;
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Inspects `originalTfContent` and generates an updated HCL string applying drift recommendations.
 */
export function generateHclPatch(
  originalTfContent: string,
  bucketName: string,
  recommendations: DriftRecommendations = {}
): HclPatchResult {
  const abortDays = recommendations.abortMpuDays ?? 7;
  const noncurrentDays = recommendations.noncurrentDays ?? 30;
  const minSize = recommendations.targetMinSizeBytes ?? 131072;
  const filePath = recommendations.tfFilePath ?? "main.tf";

  let modifiedContent = originalTfContent;
  const bounds = findLifecycleResourceBounds(originalTfContent, bucketName);

  if (!bounds) {
    // No aws_s3_bucket_lifecycle_configuration found for this bucket:
    // Generate and append a brand-new complete resource block.
    const safeName = bucketName.replace(/[^a-zA-Z0-9_]/g, "_");
    let newResource = `\n# Terraform (AWS Provider v4+) Lifecycle Configuration for '${bucketName}'\n`;
    newResource += `resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_${safeName}" {\n`;
    newResource += `  bucket = "${bucketName}"\n\n`;

    newResource += `  rule {\n`;
    newResource += `    id     = "s3-guardian-abort-mpu"\n`;
    newResource += `    status = "Enabled"\n\n`;
    newResource += `    filter {}\n\n`;
    newResource += `    abort_incomplete_multipart_upload {\n`;
    newResource += `      days_after_initiation = ${abortDays}\n`;
    newResource += `    }\n`;
    newResource += `  }\n`;

    if (recommendations.missingNoncurrentExpiration) {
      newResource += `\n  rule {\n`;
      newResource += `    id     = "s3-guardian-expire-noncurrent-versions"\n`;
      newResource += `    status = "Enabled"\n\n`;
      newResource += `    filter {}\n\n`;
      newResource += `    noncurrent_version_expiration {\n`;
      newResource += `      noncurrent_days = ${noncurrentDays}\n`;
      newResource += `    }\n`;
      newResource += `  }\n`;

      if (recommendations.missingEodm !== false) {
        newResource += `\n  rule {\n`;
        newResource += `    id     = "s3-guardian-cleanup-eodm"\n`;
        newResource += `    status = "Enabled"\n\n`;
        newResource += `    filter {}\n\n`;
        newResource += `    expiration {\n`;
        newResource += `      expired_object_delete_marker = true\n`;
        newResource += `    }\n`;
        newResource += `  }\n`;
      }
    }

    newResource += `}\n`;

    const needsNewline = modifiedContent.length > 0 && !modifiedContent.endsWith("\n");
    modifiedContent = modifiedContent + (needsNewline ? "\n" : "") + newResource;

    const patch = createUnifiedDiff(originalTfContent, modifiedContent, filePath);
    return {
      patch,
      patchedContent: modifiedContent,
      modified: originalTfContent !== modifiedContent,
    };
  }

  // Target resource exists: patch inside the block
  let blockContent = originalTfContent.slice(bounds.startIndex, bounds.endIndex);
  let blockModified = false;

  // 1. Check and inject missing abort_incomplete_multipart_upload rule
  const hasMpuRule = /abort_incomplete_multipart_upload\s*\{/.test(blockContent);
  const shouldAddMpu = recommendations.missingAbortMpu ?? !hasMpuRule;

  if (shouldAddMpu && !hasMpuRule) {
    const closingBraceIndex = blockContent.lastIndexOf("}");
    if (closingBraceIndex !== -1) {
      const mpuRuleSnippet =
        `  rule {\n` +
        `    id     = "s3-guardian-abort-mpu"\n` +
        `    status = "Enabled"\n\n` +
        `    filter {}\n\n` +
        `    abort_incomplete_multipart_upload {\n` +
        `      days_after_initiation = ${abortDays}\n` +
        `    }\n` +
        `  }\n`;

      const insertPos = closingBraceIndex;
      const before = blockContent.slice(0, insertPos);
      const after = blockContent.slice(insertPos);
      const separator = before.endsWith("\n\n") ? "" : before.endsWith("\n") ? "\n" : "\n\n";

      blockContent = before + separator + mpuRuleSnippet + after;
      blockModified = true;
    }
  }

  // 2. Check and inject missing noncurrent_version_expiration rule
  const hasNoncurrentRule = /noncurrent_version_expiration\s*\{/.test(blockContent);
  if (recommendations.missingNoncurrentExpiration && !hasNoncurrentRule) {
    const closingBraceIndex = blockContent.lastIndexOf("}");
    if (closingBraceIndex !== -1) {
      let ncSnippet =
        `  rule {\n` +
        `    id     = "s3-guardian-expire-noncurrent-versions"\n` +
        `    status = "Enabled"\n\n` +
        `    filter {}\n\n` +
        `    noncurrent_version_expiration {\n` +
        `      noncurrent_days = ${noncurrentDays}\n` +
        `    }\n` +
        `  }\n`;

      if (recommendations.missingEodm !== false && !/expired_object_delete_marker\s*=\s*true/.test(blockContent)) {
        ncSnippet +=
          `\n  rule {\n` +
          `    id     = "s3-guardian-cleanup-eodm"\n` +
          `    status = "Enabled"\n\n` +
          `    filter {}\n\n` +
          `    expiration {\n` +
          `      expired_object_delete_marker = true\n` +
          `    }\n` +
          `  }\n`;
      }

      const insertPos = closingBraceIndex;
      const before = blockContent.slice(0, insertPos);
      const after = blockContent.slice(insertPos);
      const separator = before.endsWith("\n\n") ? "" : before.endsWith("\n") ? "\n" : "\n\n";

      blockContent = before + separator + ncSnippet + after;
      blockModified = true;
    }
  }

  // 3. Inject object_size_greater_than into transition rules lacking it
  // Match rule blocks inside the resource
  const ruleRegex = /rule\s*\{/g;
  let ruleMatch: RegExpExecArray | null;
  const rulePositions: Array<{ start: number; end: number }> = [];

  while ((ruleMatch = ruleRegex.exec(blockContent)) !== null) {
    const rStart = ruleMatch.index;
    const braceIdx = blockContent.indexOf("{", rStart);
    if (braceIdx === -1) continue;

    let d = 1;
    let idx = braceIdx + 1;
    while (idx < blockContent.length && d > 0) {
      if (blockContent[idx] === "{") d++;
      else if (blockContent[idx] === "}") d--;
      idx++;
    }
    if (d === 0) {
      rulePositions.push({ start: rStart, end: idx });
    }
  }

  // Iterate rules in reverse so replacements don't shift earlier offsets
  for (let ri = rulePositions.length - 1; ri >= 0; ri--) {
    const { start: rStart, end: rEnd } = rulePositions[ri];
    const ruleText = blockContent.slice(rStart, rEnd);

    // Is it a transition rule?
    const hasTransition = /transition\s*\{/.test(ruleText);
    const targetsArchive = /storage_class\s*=\s*"(GLACIER|STANDARD_IA|ONEZONE_IA|GLACIER_IR|DEEP_ARCHIVE)"/i.test(ruleText);

    if (hasTransition || targetsArchive) {
      const hasSizeFilter = /object_size_greater_than\s*=/.test(ruleText);
      if (!hasSizeFilter) {
        let updatedRuleText = ruleText;

        // Does it have a filter block?
        const filterMatch = /filter\s*\{([^}]*)\}/.exec(ruleText);
        if (filterMatch) {
          const filterBody = filterMatch[1].trim();
          let newFilterBody: string;
          if (filterBody.length === 0) {
            newFilterBody = `\n      object_size_greater_than = ${minSize}\n    `;
          } else {
            newFilterBody = `\n      ${filterBody}\n      object_size_greater_than = ${minSize}\n    `;
          }
          updatedRuleText = ruleText.replace(filterMatch[0], `filter {${newFilterBody}}`);
        } else {
          // No filter block: inject filter right after status or id
          const statusMatch = /status\s*=\s*"[^"]*"/.exec(ruleText);
          if (statusMatch) {
            const insertion = `${statusMatch[0]}\n\n    filter {\n      object_size_greater_than = ${minSize}\n    }`;
            updatedRuleText = ruleText.replace(statusMatch[0], insertion);
          }
        }

        if (updatedRuleText !== ruleText) {
          blockContent = blockContent.slice(0, rStart) + updatedRuleText + blockContent.slice(rEnd);
          blockModified = true;
        }
      }
    }
  }

  if (blockModified) {
    modifiedContent =
      originalTfContent.slice(0, bounds.startIndex) +
      blockContent +
      originalTfContent.slice(bounds.endIndex);
  }

  const patch = createUnifiedDiff(originalTfContent, modifiedContent, filePath);
  return {
    patch,
    patchedContent: modifiedContent,
    modified: originalTfContent !== modifiedContent,
  };
}
