import { describe, it, expect } from "vitest";
import {
  detectProvider,
  getProviderDisplayName,
  PROVIDER_REGEXES,
  KNOWN_PROVIDERS,
} from "../src/providers/detector.js";

describe("S3 Provider Detection (src/providers/detector.ts)", () => {
  describe("detectProvider() - Endpoint regex matching", () => {
    it("detects Cloudflare R2 endpoints", () => {
      expect(detectProvider("https://abc12345.r2.cloudflarestorage.com")).toBe("r2");
      expect(detectProvider("https://my-bucket.r2.cloudflarestorage.com/")).toBe("r2");
      expect(detectProvider("https://custom.r2.dev")).toBe("r2");
      expect(PROVIDER_REGEXES.r2.test("https://myaccount.r2.cloudflarestorage.com")).toBe(true);
    });

    it("detects Wasabi endpoints", () => {
      expect(detectProvider("https://s3.wasabisys.com")).toBe("wasabi");
      expect(detectProvider("https://s3.us-central-1.wasabisys.com/")).toBe("wasabi");
      expect(detectProvider("https://s3.eu-central-1.wasabisys.com")).toBe("wasabi");
      expect(PROVIDER_REGEXES.wasabi.test("https://s3.wasabisys.com")).toBe(true);
    });

    it("detects Backblaze B2 endpoints", () => {
      expect(detectProvider("https://s3.us-west-000.backblazeb2.com")).toBe("b2");
      expect(detectProvider("https://s3.us-east-005.backblazeb2.com/")).toBe("b2");
      expect(PROVIDER_REGEXES.b2.test("https://s3.us-west-000.backblazeb2.com")).toBe(true);
    });

    it("detects MinIO endpoints (port 9000 or minio domain)", () => {
      expect(detectProvider("http://localhost:9000")).toBe("minio");
      expect(detectProvider("http://localhost:9000/")).toBe("minio");
      expect(detectProvider("http://127.0.0.1:9000")).toBe("minio");
      expect(detectProvider("http://minio.internal:9000/")).toBe("minio");
      expect(detectProvider("https://minio.company.com")).toBe("minio");
      expect(detectProvider("http://minio.production.local:9000")).toBe("minio");
    });

    it("detects Ceph RADOS Gateway endpoints (port 7480 or ceph domain)", () => {
      expect(detectProvider("http://ceph-rados.internal:7480")).toBe("ceph");
      expect(detectProvider("http://localhost:7480/")).toBe("ceph");
      expect(detectProvider("http://192.168.1.10:7480")).toBe("ceph");
      expect(detectProvider("https://storage.ceph.corp.net")).toBe("ceph");
      expect(detectProvider("http://ceph.internal")).toBe("ceph");
    });

    it("detects standard AWS S3 endpoints", () => {
      expect(detectProvider("https://s3.amazonaws.com")).toBe("aws");
      expect(detectProvider("https://s3.us-east-1.amazonaws.com")).toBe("aws");
      expect(detectProvider("https://mybucket.s3.eu-central-1.amazonaws.com/")).toBe("aws");
    });

    it("falls back to 'aws' when no endpoint is provided or endpoint is empty", () => {
      expect(detectProvider(undefined)).toBe("aws");
      expect(detectProvider(null)).toBe("aws");
      expect(detectProvider("")).toBe("aws");
      expect(detectProvider("   ")).toBe("aws");
    });

    it("identifies unrecognized endpoints as 'custom'", () => {
      expect(detectProvider("https://s3.example.com")).toBe("custom");
      expect(detectProvider("http://local-storage:8080")).toBe("custom");
      expect(detectProvider("https://storage.mycorp.org/")).toBe("custom");
    });
  });

  describe("detectProvider() - Explicit provider override", () => {
    it("overrides endpoint autodetection when explicit provider is set", () => {
      expect(detectProvider("http://localhost:9000", "r2")).toBe("r2");
      expect(detectProvider("https://s3.wasabisys.com", "b2")).toBe("b2");
      expect(detectProvider("https://s3.amazonaws.com", "minio")).toBe("minio");
      expect(detectProvider("https://s3.amazonaws.com", "ceph")).toBe("ceph");
      expect(detectProvider(undefined, "wasabi")).toBe("wasabi");
      expect(detectProvider(undefined, "custom")).toBe("custom");
    });

    it("normalizes case-insensitively and handles whitespace", () => {
      expect(detectProvider(undefined, "WASABI")).toBe("wasabi");
      expect(detectProvider(undefined, "  R2  ")).toBe("r2");
      expect(detectProvider(undefined, "B2")).toBe("b2");
      expect(detectProvider(undefined, "MinIO")).toBe("minio");
      expect(detectProvider(undefined, "CEPH")).toBe("ceph");
      expect(detectProvider(undefined, "AWS")).toBe("aws");
    });

    it("falls back to 'custom' for unknown explicit provider names", () => {
      expect(detectProvider(undefined, "unknown-cloud")).toBe("custom");
      expect(detectProvider(undefined, "gcs-compat")).toBe("custom");
    });
  });

  describe("getProviderDisplayName()", () => {
    it("returns formatted display names for all known providers", () => {
      expect(getProviderDisplayName("aws")).toBe("AWS S3");
      expect(getProviderDisplayName("r2")).toBe("Cloudflare R2");
      expect(getProviderDisplayName("wasabi")).toBe("Wasabi");
      expect(getProviderDisplayName("b2")).toBe("Backblaze B2");
      expect(getProviderDisplayName("minio")).toBe("MinIO");
      expect(getProviderDisplayName("ceph")).toBe("Ceph RADOS Gateway");
      expect(getProviderDisplayName("custom")).toBe("Custom S3");
    });
  });

  describe("KNOWN_PROVIDERS", () => {
    it("lists all supported provider keys", () => {
      expect(KNOWN_PROVIDERS).toEqual([
        "aws",
        "r2",
        "wasabi",
        "b2",
        "minio",
        "ceph",
        "custom",
      ]);
    });
  });
});
