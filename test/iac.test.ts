import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import {
  generateTerraformSnippet,
  generateCloudFormationSnippet,
  formatOrSaveIac,
} from "../src/remediation/iac.js";

describe("IaC Remediation Generators", () => {
  const tempDir = path.join(os.tmpdir(), `s3-guardian-iac-test-${Date.now()}`);

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe("generateTerraformSnippet()", () => {
    it("generates valid modern Terraform AWS provider v4+ resource block", () => {
      const snippet = generateTerraformSnippet("my-prod-bucket", 7);

      expect(snippet).toContain('resource "aws_s3_bucket_lifecycle_configuration"');
      expect(snippet).toContain('bucket = "my-prod-bucket"');
      expect(snippet).toContain('id     = "s3-guardian-abort-mpu"');
      expect(snippet).toContain('status = "Enabled"');
      expect(snippet).toContain("abort_incomplete_multipart_upload {");
      expect(snippet).toContain("days_after_initiation = 7");
      expect(snippet).toContain("abort_incomplete_multipart_upload_days");
    });

    it("respects custom daysAfterInitiation", () => {
      const snippet = generateTerraformSnippet("analytics-bucket", 14);

      expect(snippet).toContain("days_after_initiation = 14");
      expect(snippet).toContain('bucket = "analytics-bucket"');
    });

    it("sanitizes bucket name for Terraform resource identifier", () => {
      const snippet = generateTerraformSnippet("my.complex-bucket_name.2026");

      expect(snippet).toContain('resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_my_complex_bucket_name_2026"');
    });
  });

  describe("generateCloudFormationSnippet()", () => {
    it("generates YAML snippet for AWS::S3::Bucket with LifecycleConfiguration.Rules", () => {
      const snippet = generateCloudFormationSnippet("my-cfn-bucket", 7);

      expect(snippet).toContain("Type: AWS::S3::Bucket");
      expect(snippet).toContain('BucketName: "my-cfn-bucket"');
      expect(snippet).toContain("LifecycleConfiguration:");
      expect(snippet).toContain("Rules:");
      expect(snippet).toContain("- Id: s3-guardian-abort-mpu");
      expect(snippet).toContain("Status: Enabled");
      expect(snippet).toContain("AbortIncompleteMultipartUpload:");
      expect(snippet).toContain("DaysAfterInitiation: 7");
    });

    it("respects custom daysAfterInitiation", () => {
      const snippet = generateCloudFormationSnippet("my-cfn-bucket", 3);

      expect(snippet).toContain("DaysAfterInitiation: 3");
    });
  });

  describe("formatOrSaveIac()", () => {
    it("formats multiple buckets with Terraform by default", async () => {
      const output = await formatOrSaveIac(["bucket-1", "bucket-2"], {
        format: "terraform",
        daysAfterInitiation: 5,
      });

      expect(output).toContain('bucket = "bucket-1"');
      expect(output).toContain('bucket = "bucket-2"');
      expect(output).toContain("days_after_initiation = 5");
    });

    it("formats multiple buckets with CloudFormation separated by YAML doc separator", async () => {
      const output = await formatOrSaveIac(["bucket-a", "bucket-b"], {
        format: "cloudformation",
        daysAfterInitiation: 10,
      });

      expect(output).toContain('BucketName: "bucket-a"');
      expect(output).toContain('BucketName: "bucket-b"');
      expect(output).toContain("---");
      expect(output).toContain("DaysAfterInitiation: 10");
    });

    it("saves snippet to specified outIac file path", async () => {
      const targetFile = path.join(tempDir, "lifecycle.tf");

      const output = await formatOrSaveIac("saved-bucket", {
        format: "terraform",
        outIac: targetFile,
      });

      const fileContent = await fs.readFile(targetFile, "utf8");
      expect(fileContent).toBe(output);
      expect(fileContent).toContain('bucket = "saved-bucket"');
    });
  });
});
