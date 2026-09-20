import { GuardianPolicy, PolicyRule, PolicyScope } from "./types.js";

/**
 * Strips comments from a line, ignoring '#' characters inside quotes.
 */
function stripComment(line: string): string {
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "#" && !inSingle && !inDouble) {
      return line.slice(0, i);
    }
  }
  return line;
}

/**
 * Parses scalar strings, numbers, booleans, durations, and sizes.
 */
export function parseScalar(raw: string): any {
  const trimmed = raw.trim();

  // Empty
  if (trimmed === "" || trimmed === "~" || trimmed.toLowerCase() === "null") {
    return null;
  }

  // Quoted string (double quotes)
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }

  // Quoted string (single quotes)
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }

  // Booleans
  if (/^(true|yes|on)$/i.test(trimmed)) return true;
  if (/^(false|no|off)$/i.test(trimmed)) return false;

  // Human durations: e.g. 7d -> 7, 24h -> 1, 48h -> 2, 2w -> 14
  const durationMatch = /^(\d+)\s*([dhw])$/i.exec(trimmed);
  if (durationMatch) {
    const val = parseInt(durationMatch[1]!, 10);
    const unit = durationMatch[2]!.toLowerCase();
    if (unit === "d") return val;
    if (unit === "h") return Math.round(val / 24);
    if (unit === "w") return val * 7;
  }

  // Human sizes: e.g. 128KiB -> 128, 1MiB -> 1024
  const sizeMatch = /^(\d+)\s*(kib|kb|mib|mb|gib|gb)$/i.exec(trimmed);
  if (sizeMatch) {
    const val = parseInt(sizeMatch[1]!, 10);
    const unit = sizeMatch[2]!.toLowerCase();
    if (unit === "kib" || unit === "kb") return val;
    if (unit === "mib" || unit === "mb") return val * 1024;
    if (unit === "gib" || unit === "gb") return val * 1024 * 1024;
  }

  // Pure numbers
  if (/^-?\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }
  if (/^-?\d+\.\d+$/.test(trimmed)) {
    return parseFloat(trimmed);
  }

  // Unquoted string
  return trimmed;
}

interface YamlLineToken {
  indent: number;
  isArrayItem: boolean;
  key?: string;
  rawValue?: string;
  lineNum: number;
}

/**
 * Tokenizes lines in YAML content, enforcing indentation rules (no tabs).
 */
function tokenizeYaml(content: string): YamlLineToken[] {
  const lines = content.split(/\r?\n/);
  const tokens: YamlLineToken[] = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]!;
    const stripped = stripComment(rawLine);

    if (stripped.trim().length === 0) {
      continue;
    }

    // Check for tabs in indentation
    const leadingWhitespaceMatch = /^(\s*)/.exec(stripped);
    const leadingWhitespace = leadingWhitespaceMatch ? leadingWhitespaceMatch[1]! : "";
    if (leadingWhitespace.includes("\t")) {
      throw new Error(
        `YAML syntax error at line ${i + 1}: tab characters are not allowed for indentation.`
      );
    }

    const indent = leadingWhitespace.length;
    const lineContent = stripped.trim();

    if (lineContent.startsWith("- ") || lineContent === "-") {
      const rest = lineContent === "-" ? "" : lineContent.slice(2).trim();
      if (rest.length === 0) {
        tokens.push({
          indent,
          isArrayItem: true,
          lineNum: i + 1,
        });
      } else {
        // Check if `- key: value`
        const colonMatch = /^([^:\s][^:]*?):\s*(.*)$/.exec(rest);
        if (colonMatch) {
          tokens.push({
            indent,
            isArrayItem: true,
            key: colonMatch[1]!.trim(),
            rawValue: colonMatch[2]!.trim() || undefined,
            lineNum: i + 1,
          });
        } else {
          tokens.push({
            indent,
            isArrayItem: true,
            rawValue: rest,
            lineNum: i + 1,
          });
        }
      }
    } else {
      // Key-value pair: key: value or key:
      const colonMatch = /^([^:\s][^:]*?):\s*(.*)$/.exec(lineContent);
      if (!colonMatch) {
        throw new Error(
          `YAML syntax error at line ${i + 1}: expected key-value pair or list item, got: '${lineContent}'`
        );
      }
      tokens.push({
        indent,
        isArrayItem: false,
        key: colonMatch[1]!.trim(),
        rawValue: colonMatch[2]!.trim() || undefined,
        lineNum: i + 1,
      });
    }
  }

  return tokens;
}

/**
 * Parses a block of YAML tokens into a JavaScript object or array.
 */
function parseYamlTokens(
  tokens: YamlLineToken[],
  startIndex: number,
  currentIndent: number
): { result: any; nextIndex: number } {
  if (startIndex >= tokens.length) {
    return { result: null, nextIndex: startIndex };
  }

  const firstToken = tokens[startIndex]!;
  if (firstToken.indent < currentIndent) {
    return { result: null, nextIndex: startIndex };
  }

  // Check if current block is an array
  if (firstToken.isArrayItem) {
    const list: any[] = [];
    let i = startIndex;

    while (i < tokens.length) {
      const token = tokens[i]!;
      if (token.indent < currentIndent) {
        break;
      }
      if (token.indent !== currentIndent || !token.isArrayItem) {
        break;
      }

      if (token.key !== undefined) {
        // `- key: value` -> object element
        const itemObj: Record<string, any> = {};
        if (token.rawValue !== undefined) {
          itemObj[token.key] = parseScalar(token.rawValue);
          i++;
        } else {
          // `- key:` -> child block
          if (i + 1 < tokens.length && tokens[i + 1]!.indent > token.indent) {
            const child = parseYamlTokens(tokens, i + 1, tokens[i + 1]!.indent);
            itemObj[token.key] = child.result;
            i = child.nextIndex;
          } else {
            itemObj[token.key] = null;
            i++;
          }
        }

        // Parse remaining sibling properties of this object (with indent > token.indent)
        while (i < tokens.length && tokens[i]!.indent > token.indent && !tokens[i]!.isArrayItem) {
          const propToken = tokens[i]!;
          if (propToken.key !== undefined) {
            if (propToken.rawValue !== undefined) {
              itemObj[propToken.key] = parseScalar(propToken.rawValue);
              i++;
            } else {
              if (i + 1 < tokens.length && tokens[i + 1]!.indent > propToken.indent) {
                const child = parseYamlTokens(tokens, i + 1, tokens[i + 1]!.indent);
                itemObj[propToken.key] = child.result;
                i = child.nextIndex;
              } else {
                itemObj[propToken.key] = null;
                i++;
              }
            }
          } else {
            i++;
          }
        }

        list.push(itemObj);
      } else if (token.rawValue !== undefined) {
        // `- value` -> scalar element
        list.push(parseScalar(token.rawValue));
        i++;
      } else {
        // `- ` -> nested block
        if (i + 1 < tokens.length && tokens[i + 1]!.indent > token.indent) {
          const child = parseYamlTokens(tokens, i + 1, tokens[i + 1]!.indent);
          list.push(child.result);
          i = child.nextIndex;
        } else {
          list.push(null);
          i++;
        }
      }
    }

    return { result: list, nextIndex: i };
  }

  // Current block is an object
  const obj: Record<string, any> = {};
  let i = startIndex;

  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token.indent < currentIndent) {
      break;
    }
    if (token.indent !== currentIndent || token.isArrayItem) {
      break;
    }

    if (token.key !== undefined) {
      if (token.rawValue !== undefined) {
        obj[token.key] = parseScalar(token.rawValue);
        i++;
      } else {
        // Sub-block
        if (i + 1 < tokens.length && tokens[i + 1]!.indent > token.indent) {
          const child = parseYamlTokens(tokens, i + 1, tokens[i + 1]!.indent);
          obj[token.key] = child.result;
          i = child.nextIndex;
        } else {
          obj[token.key] = null;
          i++;
        }
      }
    } else {
      i++;
    }
  }

  return { result: obj, nextIndex: i };
}

/**
 * Parses native Guardian YAML subset into an object.
 */
export function parseYamlSubset(content: string): any {
  const tokens = tokenizeYaml(content);
  if (tokens.length === 0) {
    return {};
  }
  const rootIndent = tokens[0]!.indent;
  const parsed = parseYamlTokens(tokens, 0, rootIndent);
  return parsed.result ?? {};
}

/**
 * Validates and normalizes raw parsed policy into a GuardianPolicy.
 */
function normalizeGuardianPolicy(raw: any): GuardianPolicy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Invalid GuardianPolicy: policy document must be an object.");
  }

  const schemaVersion = String(raw.schemaVersion ?? "");
  if (schemaVersion !== "1") {
    throw new Error(
      `Invalid GuardianPolicy: unsupported schemaVersion "${raw.schemaVersion}". Expected "1".`
    );
  }

  if (typeof raw.policyId !== "string" || raw.policyId.trim() === "") {
    throw new Error("Invalid GuardianPolicy: missing or empty required field 'policyId'.");
  }

  if (!raw.scope || typeof raw.scope !== "object" || typeof raw.scope.level !== "string") {
    throw new Error("Invalid GuardianPolicy: missing required field 'scope.level'.");
  }

  const validLevels = ["GLOBAL", "OU", "ACCOUNT", "BUCKET_TAG", "OBJECT_TAG"];
  if (!validLevels.includes(raw.scope.level)) {
    throw new Error(
      `Invalid GuardianPolicy: invalid scope.level '${raw.scope.level}'. Expected one of: ${validLevels.join(", ")}.`
    );
  }

  if (!Array.isArray(raw.rules)) {
    throw new Error("Invalid GuardianPolicy: missing required field 'rules' (must be an array).");
  }

  const rules: PolicyRule[] = raw.rules.map((r: any, idx: number) => {
    if (!r || typeof r !== "object") {
      throw new Error(`Invalid GuardianPolicy: rule at index ${idx} must be an object.`);
    }
    if (typeof r.id !== "string" || r.id.trim() === "") {
      throw new Error(`Invalid GuardianPolicy: rule at index ${idx} is missing required 'id'.`);
    }
    return {
      id: r.id.trim(),
      match: r.match ?? {},
      action: r.action,
      transitions: Array.isArray(r.transitions) ? r.transitions : undefined,
      expirationDays: r.expirationDays,
      noncurrentExpirationDays: r.noncurrentExpirationDays,
      retainVersions: r.retainVersions,
      mpuAbortDays: r.mpuAbortDays,
    };
  });

  return {
    schemaVersion: "1",
    policyId: raw.policyId.trim(),
    scope: raw.scope as PolicyScope,
    defaults: raw.defaults,
    rules,
  };
}

/**
 * Parses a GuardianPolicy from either JSON or native YAML subset.
 */
export function parsePolicyDocument(content: string): GuardianPolicy {
  const trimmed = content.trim();

  // Try JSON first if content looks like JSON
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      return normalizeGuardianPolicy(parsed);
    } catch (err: unknown) {
      // If JSON parse fails, attempt YAML parsing unless it's strictly malformed JSON
      if (/tab characters/i.test(String(err))) {
        throw err;
      }
    }
  }

  // Parse as Guardian YAML subset
  const parsedYaml = parseYamlSubset(content);
  return normalizeGuardianPolicy(parsedYaml);
}
