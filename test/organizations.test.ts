import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  OrganizationsClient,
  ListAccountsCommand,
} from "@aws-sdk/client-organizations";
import {
  discoverOrganizationAccounts,
  parseAccountsFile,
  resolveTargetAccounts,
  OrganizationsDiscoveryError,
} from "../src/discovery/organizations.js";
import { writeFile, unlink, mkdir } from "node:fs/promises";
import { resolve as pathResolve } from "node:path";
import { tmpdir } from "node:os";

const orgMock = mockClient(OrganizationsClient);

describe("AWS Organizations Discovery", () => {
  beforeEach(() => {
    orgMock.reset();
  });

  describe("discoverOrganizationAccounts", () => {
    it("lists active accounts from a single page", async () => {
      orgMock.on(ListAccountsCommand).resolves({
        Accounts: [
          { Id: "111111111111", Name: "Production", Status: "ACTIVE", Arn: "arn:aws:organizations::111:account/o-123/111" },
          { Id: "222222222222", Name: "Staging", Status: "ACTIVE" },
          { Id: "333333333333", Name: "SuspendedAccount", Status: "SUSPENDED" },
        ],
      });

      const accounts = await discoverOrganizationAccounts({
        client: orgMock as unknown as OrganizationsClient,
      });

      // Default filters out SUSPENDED accounts
      expect(accounts).toHaveLength(2);
      expect(accounts.map((a) => a.id)).toEqual(["111111111111", "222222222222"]);
      expect(accounts[0].name).toBe("Production");
    });

    it("paginates across multiple pages using NextToken", async () => {
      orgMock
        .on(ListAccountsCommand)
        .resolvesOnce({
          Accounts: [
            { Id: "111111111111", Name: "Account-1", Status: "ACTIVE" },
          ],
          NextToken: "token-page-2",
        })
        .resolvesOnce({
          Accounts: [
            { Id: "222222222222", Name: "Account-2", Status: "ACTIVE" },
          ],
        });

      const accounts = await discoverOrganizationAccounts({
        client: orgMock as unknown as OrganizationsClient,
      });

      expect(accounts).toHaveLength(2);
      expect(accounts.map((a) => a.id)).toEqual(["111111111111", "222222222222"]);
      expect(orgMock.commandCalls(ListAccountsCommand)).toHaveLength(2);
    });

    it("applies inclusion and exclusion filters", async () => {
      orgMock.on(ListAccountsCommand).resolves({
        Accounts: [
          { Id: "111111111111", Name: "Account-1", Status: "ACTIVE" },
          { Id: "222222222222", Name: "Account-2", Status: "ACTIVE" },
          { Id: "333333333333", Name: "Account-3", Status: "ACTIVE" },
        ],
      });

      const accounts = await discoverOrganizationAccounts({
        client: orgMock as unknown as OrganizationsClient,
        includeAccounts: ["111111111111", "222222222222"],
        excludeAccounts: ["222222222222"],
      });

      expect(accounts).toHaveLength(1);
      expect(accounts[0].id).toBe("111111111111");
    });

    it("throws OrganizationsDiscoveryError if AWS Organizations is not in use", async () => {
      const error = new Error("AWS Organizations is not in use for this AWS account");
      error.name = "AWSOrganizationsNotInUseException";

      orgMock.on(ListAccountsCommand).rejects(error);

      await expect(
        discoverOrganizationAccounts({
          client: orgMock as unknown as OrganizationsClient,
        })
      ).rejects.toThrow(OrganizationsDiscoveryError);
    });

    it("throws OrganizationsDiscoveryError on 403 AccessDenied", async () => {
      const error = new Error("User is not authorized to perform: organizations:ListAccounts");
      error.name = "AccessDeniedException";

      orgMock.on(ListAccountsCommand).rejects(error);

      await expect(
        discoverOrganizationAccounts({
          client: orgMock as unknown as OrganizationsClient,
        })
      ).rejects.toThrow(/Access denied/i);
    });
  });

  describe("parseAccountsFile", () => {
    const testFilePath = pathResolve(tmpdir(), `s3-guardian-test-accounts-${Date.now()}.txt`);

    it("parses newline-delimited and comma-separated accounts ignoring comments", async () => {
      const fileContent = `
# Production accounts
111111111111
222222222222, 333333333333 // Inline comment

# Staging
444444444444
   
555555555555
      `;

      await writeFile(testFilePath, fileContent, "utf8");

      try {
        const accounts = await parseAccountsFile(testFilePath);
        expect(accounts).toEqual([
          "111111111111",
          "222222222222",
          "333333333333",
          "444444444444",
          "555555555555",
        ]);
      } finally {
        await unlink(testFilePath).catch(() => {});
      }
    });
  });

  describe("resolveTargetAccounts", () => {
    it("resolves explicit accounts without AWS Organizations", async () => {
      const resolved = await resolveTargetAccounts({
        accounts: ["111111111111", "222222222222", "111111111111"],
        excludeAccounts: ["222222222222"],
      });

      expect(resolved).toEqual([
        { id: "111111111111", name: "111111111111", status: "ACTIVE" },
      ]);
    });

    it("combines explicit accounts and accounts file", async () => {
      const testFile = pathResolve(tmpdir(), `accounts-combine-${Date.now()}.txt`);
      await writeFile(testFile, "222222222222\n333333333333", "utf8");

      try {
        const resolved = await resolveTargetAccounts({
          accounts: ["111111111111"],
          accountsFile: testFile,
          excludeAccounts: ["333333333333"],
        });

        expect(resolved.map((a) => a.id)).toEqual(["111111111111", "222222222222"]);
      } finally {
        await unlink(testFile).catch(() => {});
      }
    });

    it("delegates to discoverOrganizationAccounts when useOrg is true", async () => {
      orgMock.on(ListAccountsCommand).resolves({
        Accounts: [
          { Id: "111111111111", Name: "Org-1", Status: "ACTIVE" },
          { Id: "222222222222", Name: "Org-2", Status: "ACTIVE" },
        ],
      });

      const resolved = await resolveTargetAccounts({
        useOrg: true,
        orgClient: orgMock as unknown as OrganizationsClient,
        excludeAccounts: ["222222222222"],
      });

      expect(resolved).toHaveLength(1);
      expect(resolved[0].id).toBe("111111111111");
    });
  });
});
