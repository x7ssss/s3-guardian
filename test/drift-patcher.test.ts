import { describe, it, expect } from "vitest";
import {
  createUnifiedDiff,
  generateHclPatch,
} from "../src/drift/hcl-patcher.js";

describe("HCL Patcher & Unified Diff Generator", () => {
  describe("createUnifiedDiff", () => {
    it("returns empty string when original and patched content are identical", () => {
      const content = `resource "aws_s3_bucket" "test" {\n  bucket = "test"\n}\n`;
      expect(createUnifiedDiff(content, content, "main.tf")).toBe("");
    });

    it("generates valid unified diff header and hunks for line additions", () => {
      const original = `line 1\nline 2\nline 3\n`;
      const patched = `line 1\nline 2\nline 2.5\nline 3\n`;

      const diff = createUnifiedDiff(original, patched, "main.tf");
      expect(diff).toContain("--- a/main.tf\n+++ b/main.tf\n");
      expect(diff).toContain("@@ -1,4 +1,5 @@");
      expect(diff).toContain("+line 2.5");
      expect(diff).toContain(" line 1");
    });
  });

  describe("generateHclPatch", () => {
    it("injects missing abort_incomplete_multipart_upload rule into existing lifecycle configuration", () => {
      const originalTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_my_bucket" {
  bucket = "my-bucket"

  rule {
    id     = "existing-expiration"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }
  }
}
`.trim();

      const result = generateHclPatch(originalTf, "my-bucket", {
        missingAbortMpu: true,
        abortMpuDays: 7,
        tfFilePath: "modules/s3/main.tf",
      });

      expect(result.modified).toBe(true);
      expect(result.patch).toContain("--- a/modules/s3/main.tf");
      expect(result.patch).toContain("+++ b/modules/s3/main.tf");
      expect(result.patch).toContain("+    id     = \"s3-guardian-abort-mpu\"");
      expect(result.patch).toContain("+      days_after_initiation = 7");

      expect(result.patchedContent).toContain("s3-guardian-abort-mpu");
      expect(result.patchedContent).toContain("existing-expiration");
    });

    it("injects missing noncurrent_version_expiration and eodm rules", () => {
      const originalTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_my_bucket" {
  bucket = "my-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

      const result = generateHclPatch(originalTf, "my-bucket", {
        missingNoncurrentExpiration: true,
        noncurrentDays: 60,
      });

      expect(result.modified).toBe(true);
      expect(result.patch).toContain("+    id     = \"s3-guardian-expire-noncurrent-versions\"");
      expect(result.patch).toContain("+      noncurrent_days = 60");
      expect(result.patch).toContain("+    id     = \"s3-guardian-cleanup-eodm\"");
      expect(result.patch).toContain("+      expired_object_delete_marker = true");

      expect(result.patchedContent).toContain("s3-guardian-expire-noncurrent-versions");
      expect(result.patchedContent).toContain("s3-guardian-cleanup-eodm");
    });

    it("injects object_size_greater_than filter into unconstrained transition rules", () => {
      const originalTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_data" {
  bucket = "data-bucket"

  rule {
    id     = "archive-rule"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}
`.trim();

      const result = generateHclPatch(originalTf, "data-bucket", {
        missingTransitionFilterRuleIds: ["archive-rule"],
        targetMinSizeBytes: 131072,
      });

      expect(result.modified).toBe(true);
      expect(result.patch).toContain("+      object_size_greater_than = 131072");
      expect(result.patchedContent).toContain("object_size_greater_than = 131072");
    });

    it("preserves existing filter attributes when injecting object_size_greater_than", () => {
      const originalTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_data" {
  bucket = "data-bucket"

  rule {
    id     = "archive-rule"
    status = "Enabled"

    filter {
      prefix = "telemetry/"
    }

    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}
`.trim();

      const result = generateHclPatch(originalTf, "data-bucket", {
        missingTransitionFilterRuleIds: ["archive-rule"],
        targetMinSizeBytes: 131072,
      });

      expect(result.modified).toBe(true);
      expect(result.patchedContent).toContain("prefix = \"telemetry/\"");
      expect(result.patchedContent).toContain("object_size_greater_than = 131072");
    });

    it("appends a brand new lifecycle configuration resource if none exists for bucket", () => {
      const originalTf = `
resource "aws_s3_bucket" "unmanaged" {
  bucket = "brand-new-bucket"
}
`.trim();

      const result = generateHclPatch(originalTf, "brand-new-bucket", {
        missingAbortMpu: true,
        abortMpuDays: 7,
      });

      expect(result.modified).toBe(true);
      expect(result.patchedContent).toContain("resource \"aws_s3_bucket_lifecycle_configuration\" \"lifecycle_brand_new_bucket\"");
      expect(result.patchedContent).toContain("bucket = \"brand-new-bucket\"");
      expect(result.patchedContent).toContain("s3-guardian-abort-mpu");
    });

    it("returns modified: false when configuration is already fully compliant", () => {
      const compliantTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_safe" {
  bucket = "safe-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "safe-transition"
    status = "Enabled"

    filter {
      object_size_greater_than = 131072
    }

    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}
`.trim();

      const result = generateHclPatch(compliantTf, "safe-bucket", {
        missingAbortMpu: false,
      });

      expect(result.modified).toBe(false);
      expect(result.patch).toBe("");
      expect(result.patchedContent).toBe(compliantTf);
    });
  });
});
