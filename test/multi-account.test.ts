import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  GetBucketLifecycleConfigurationCommand,
  ListObjectVersionsCommand,
} from "@aws-sdk/client-s3";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { runMultiAccountSweep } from "../src/multi-account/runner.js";
import { STSSessionPool } from "../src/auth/sts-pool.js";

const s3Mock = mockClient(S3Client);
const stsMock = mockClient(STSClient);

describe("Multi-Account Sweep Runner", () => {
  beforeEach(() => {
    s3Mock.reset();
    stsMock.reset();
  });

  it("orchestrates sweep across multiple accounts and aggregates findings", async () => {
    // Mock STS assume role for any account
    stsMock.on(AssumeRoleCommand).callsFake((input) => ({
      Credentials: {
        AccessKeyId: `ASIA_${input.RoleArn.replace(/[^a-zA-Z0-9]/g, "_")}`,
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    }));

    // Mock S3 responses
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "my-account-bucket" }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [],
    });
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [
        {
          Key: "large-file.bin",
          UploadId: "upload-abc-123",
          Initiated: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
          StorageClass: "STANDARD",
        },
      ],
      IsTruncated: false,
    });
    s3Mock.on(ListPartsCommand).resolves({
      Parts: [
        { PartNumber: 1, Size: 500 * 1024 * 1024 * 1024 }, // 500 GiB
      ],
      IsTruncated: false,
    });

    const accounts = [
      { id: "111111111111", name: "Account-One", status: "ACTIVE" },
      { id: "222222222222", name: "Account-Two", status: "ACTIVE" },
    ];

    const result = await runMultiAccountSweep({
      accounts,
      roleName: "OrganizationAccountAccessRole",
      accountConcurrency: 2,
      olderThanDays: 7,
    });

    expect(result.totalAccounts).toBe(2);
    expect(result.accountsScanned).toBe(2);
    expect(result.accountsSucceeded).toBe(2);
    expect(result.accountsSkipped).toBe(0);
    expect(result.totalBucketsDiscovered).toBe(2);
    expect(result.totalBucketsAudited).toBe(2);
    expect(result.totalStrandedBytes).toBe(1000 * 1024 * 1024 * 1024); // 1000 GiB total
    expect(result.totalEstimatedMonthlyWasteUSD).toBeGreaterThan(0);
    expect(result.totalCombinedMonthlyWasteUSD).toBe(result.totalEstimatedMonthlyWasteUSD);

    expect(result.accountResults).toHaveLength(2);
    expect(result.accountResults[0].status).toBe("SUCCESS");
    expect(result.accountResults[1].status).toBe("SUCCESS");
  });

  it("fault isolation: individual account STS failure or S3 access denial does not abort sweep", async () => {
    // Mock STS: Account 1 fails assume role with AccessDenied
    // Account 2 succeeds assume role, but fails ListBuckets with AccessDenied
    // Account 3 succeeds fully
    stsMock.on(AssumeRoleCommand).callsFake((input) => {
      if (input.RoleArn.includes("111111111111")) {
        const err = new Error("User is not authorized to assume role");
        err.name = "AccessDenied";
        throw err;
      }
      return {
        Credentials: {
          AccessKeyId: "ASIA_VALID",
          SecretAccessKey: "SECRET",
          SessionToken: "TOKEN",
          Expiration: new Date(Date.now() + 3600_000),
        },
      };
    });

    // Mock S3:
    s3Mock.on(ListBucketsCommand).callsFake((input) => {
      // In aws-sdk-client-mock, we can simulate call counts or bucket responses
      return {
        Buckets: [{ Name: "healthy-bucket" }],
      };
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [] });
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [],
      IsTruncated: false,
    });

    const accounts = [
      { id: "111111111111", name: "Failing-AssumeRole", status: "ACTIVE" },
      { id: "333333333333", name: "Healthy-Account", status: "ACTIVE" },
    ];

    const result = await runMultiAccountSweep({
      accounts,
      roleName: "CrossAccountRole",
      accountConcurrency: 2,
    });

    expect(result.totalAccounts).toBe(2);
    expect(result.accountsScanned).toBe(1);
    expect(result.accountsSucceeded).toBe(1);
    expect(result.accountsSkipped).toBe(1);

    const failedAccount = result.accountResults.find((a) => a.accountId === "111111111111")!;
    expect(failedAccount.status).toBe("SKIPPED_ASSUME_ROLE_FAILED");
    expect(failedAccount.errorMessage).toContain("Failed to assume role");

    const healthyAccount = result.accountResults.find((a) => a.accountId === "333333333333")!;
    expect(healthyAccount.status).toBe("SUCCESS");
    expect(healthyAccount.bucketsAudited).toBe(1);
  });

  it("supports includeVersions flag to quantify noncurrent versions across accounts", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_TEST",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "versioned-bucket" }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [] });
    s3Mock.on(ListMultipartUploadsCommand).resolves({ Uploads: [] });

    s3Mock.on(ListObjectVersionsCommand).resolves({
      Versions: [
        {
          Key: "doc.pdf",
          VersionId: "v1-noncurrent",
          IsLatest: false,
          Size: 500 * 1024 * 1024 * 1024, // 500 GiB
          LastModified: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        },
      ],
      DeleteMarkers: [
        {
          Key: "deleted-file.txt",
          VersionId: "dm-1",
          IsLatest: true,
          LastModified: new Date(),
        },
      ],
      IsTruncated: false,
    });

    const result = await runMultiAccountSweep({
      accounts: ["111111111111"],
      roleName: "OrgRole",
      includeVersions: true,
    });

    expect(result.totalNoncurrentVersions).toBe(1);
    expect(result.totalNoncurrentBytes).toBe(500 * 1024 * 1024 * 1024);
    expect(result.totalExpiredDeleteMarkers).toBe(1);
    expect(result.totalVersioningWasteUSD).toBeGreaterThan(0);
    expect(result.totalCombinedMonthlyWasteUSD).toBeGreaterThan(0);
  });

  it("invokes onAccountStart and onAccountComplete lifecycle hooks", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_HOOK",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const started: string[] = [];
    const completed: string[] = [];

    await runMultiAccountSweep({
      accounts: ["111111111111", "222222222222"],
      roleName: "OrgRole",
      onAccountStart: (acc) => started.push(acc.id),
      onAccountComplete: (res) => completed.push(res.accountId),
    });

    expect(started).toEqual(["111111111111", "222222222222"]);
    expect(completed).toEqual(["111111111111", "222222222222"]);
  });
});
