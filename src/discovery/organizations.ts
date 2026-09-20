import {
  OrganizationsClient,
  ListAccountsCommand,
  Account,
} from "@aws-sdk/client-organizations";
import { readFile } from "node:fs/promises";
import { resolve as pathResolve } from "node:path";

export interface OrganizationAccount {
  id: string;
  name: string;
  arn?: string;
  email?: string;
  status: string;
  joinedTimestamp?: Date;
}

export class OrganizationsDiscoveryError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "OrganizationsDiscoveryError";
  }
}

export interface DiscoverAccountsOptions {
  client?: OrganizationsClient;
  activeOnly?: boolean;
  includeAccounts?: string[];
  excludeAccounts?: string[];
}

export interface ResolveAccountsOptions {
  useOrg?: boolean;
  orgClient?: OrganizationsClient;
  accounts?: string[];
  accountsFile?: string;
  excludeAccounts?: string[];
  activeOnly?: boolean;
}

/**
 * Parses a file containing AWS Account IDs (12 digits).
 * Supports newline-delimited or comma-separated account IDs,
 * ignores empty lines, and strips comments starting with # or //.
 */
export async function parseAccountsFile(filePath: string): Promise<string[]> {
  const fullPath = pathResolve(filePath);
  const content = await readFile(fullPath, "utf8");

  const accountIds: string[] = [];
  const lines = content.split(/\r?\n/);

  for (const rawLine of lines) {
    // Strip comments
    let line = rawLine;
    const hashIndex = line.indexOf("#");
    if (hashIndex !== -1) {
      line = line.substring(0, hashIndex);
    }
    const slashIndex = line.indexOf("//");
    if (slashIndex !== -1) {
      line = line.substring(0, slashIndex);
    }

    line = line.trim();
    if (!line) continue;

    // Line may contain multiple comma-separated IDs
    const parts = line.split(",").map((p) => p.trim()).filter(Boolean);
    for (const part of parts) {
      // Remove any surrounding quotes
      const cleanId = part.replace(/^["']|["']$/g, "");
      if (cleanId) {
        accountIds.push(cleanId);
      }
    }
  }

  // Deduplicate preserving order
  return Array.from(new Set(accountIds));
}

/**
 * Queries AWS Organizations ListAccounts to discover member accounts.
 *
 * Invariants:
 *  - Lazy/paged retrieval with NextToken until exhausted.
 *  - Filters to Status === 'ACTIVE' by default.
 *  - Gracefully maps AccessDenied and OrganizationsNotInUse to OrganizationsDiscoveryError.
 */
export async function discoverOrganizationAccounts(
  options: DiscoverAccountsOptions = {}
): Promise<OrganizationAccount[]> {
  const client = options.client ?? new OrganizationsClient({ region: "us-east-1" });
  const activeOnly = options.activeOnly ?? true;
  const includeSet = options.includeAccounts && options.includeAccounts.length > 0
    ? new Set(options.includeAccounts)
    : undefined;
  const excludeSet = options.excludeAccounts && options.excludeAccounts.length > 0
    ? new Set(options.excludeAccounts)
    : undefined;

  const accounts: OrganizationAccount[] = [];
  let nextToken: string | undefined = undefined;

  try {
    do {
      const command: ListAccountsCommand = new ListAccountsCommand({
        NextToken: nextToken,
      });

      const response = await client.send(command);
      const rawAccounts: Account[] = response.Accounts ?? [];

      for (const raw of rawAccounts) {
        if (!raw.Id) continue;

        const id = raw.Id;
        const name = raw.Name ?? id;
        const status = raw.Status ?? "UNKNOWN";

        // Filter active only if enabled
        if (activeOnly && status !== "ACTIVE") {
          continue;
        }

        // Apply explicit exclusion
        if (excludeSet && excludeSet.has(id)) {
          continue;
        }

        // Apply explicit inclusion if specified
        if (includeSet && !includeSet.has(id)) {
          continue;
        }

        accounts.push({
          id,
          name,
          arn: raw.Arn,
          email: raw.Email,
          status,
          joinedTimestamp: raw.JoinedTimestamp,
        });
      }

      nextToken = response.NextToken;
    } while (nextToken);

    return accounts;
  } catch (err: unknown) {
    const e = err as Record<string, unknown>;
    const name = String(e.name || e.Code || "");
    const message = String(e.message || "");
    const status =
      (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      e.statusCode ??
      e.status;

    if (
      name === "AWSOrganizationsNotInUseException" ||
      /not in use/i.test(message)
    ) {
      throw new OrganizationsDiscoveryError(
        `AWS Organizations is not in use for this AWS account or caller is not management/delegated admin: ${message}`,
        err
      );
    }

    if (name === "AccessDeniedException" || status === 403) {
      throw new OrganizationsDiscoveryError(
        `Access denied listing AWS Organization accounts. Ensure 'organizations:ListAccounts' is granted: ${message}`,
        err
      );
    }

    throw new OrganizationsDiscoveryError(
      `Failed to discover organization accounts: ${message || String(err)}`,
      err
    );
  }
}

/**
 * Resolves the target accounts from either AWS Organizations, an explicit accounts list,
 * and/or an accounts file, applying exclusions.
 */
export async function resolveTargetAccounts(
  options: ResolveAccountsOptions
): Promise<OrganizationAccount[]> {
  const explicitAccounts: string[] = [];

  if (options.accounts && options.accounts.length > 0) {
    explicitAccounts.push(...options.accounts);
  }

  if (options.accountsFile) {
    const fileAccounts = await parseAccountsFile(options.accountsFile);
    explicitAccounts.push(...fileAccounts);
  }

  const dedupedExplicit = Array.from(new Set(explicitAccounts));
  const excludeSet = new Set(options.excludeAccounts ?? []);

  if (options.useOrg) {
    return await discoverOrganizationAccounts({
      client: options.orgClient,
      activeOnly: options.activeOnly ?? true,
      includeAccounts: dedupedExplicit.length > 0 ? dedupedExplicit : undefined,
      excludeAccounts: options.excludeAccounts,
    });
  }

  // Without Organizations, build account objects directly from explicit IDs
  return dedupedExplicit
    .filter((id) => !excludeSet.has(id))
    .map((id) => ({
      id,
      name: id,
      status: "ACTIVE",
    }));
}
