import { describe, it, expect, vi } from "vitest";
import { S3Client } from "@aws-sdk/client-s3";
import {
  configureProviderClient,
  applyProviderMiddleware,
  createR2ChecksumStrippingMiddleware,
  createCephMinio405SuppressionMiddleware,
  is405MethodNotAllowedError,
} from "../src/providers/quirks.js";

describe("S3 Provider Quirks & Middleware (src/providers/quirks.ts)", () => {
  describe("configureProviderClient()", () => {
    it("configures Cloudflare R2 checksums and defaults region to auto", () => {
      const base = { region: "us-east-1" };
      const configured = configureProviderClient(base, "r2");

      expect((configured as Record<string, unknown>).requestChecksumCalculation).toBe("WHEN_REQUIRED");
      expect((configured as Record<string, unknown>).responseChecksumValidation).toBe("WHEN_REQUIRED");
      expect(configured.region).toBe("auto");
    });

    it("preserves explicit non-us-east-1 region for R2", () => {
      const base = { region: "auto" };
      const configured = configureProviderClient(base, "r2");
      expect(configured.region).toBe("auto");
    });

    it("enables forcePathStyle for MinIO, Ceph, and Backblaze B2", () => {
      const baseMinio = configureProviderClient({}, "minio");
      expect(baseMinio.forcePathStyle).toBe(true);

      const baseCeph = configureProviderClient({}, "ceph");
      expect(baseCeph.forcePathStyle).toBe(true);

      const baseB2 = configureProviderClient({}, "b2");
      expect(baseB2.forcePathStyle).toBe(true);
    });

    it("leaves AWS and custom provider configs unchanged", () => {
      const awsConfig = configureProviderClient({ region: "us-west-2" }, "aws");
      expect(awsConfig.forcePathStyle).toBeUndefined();
      expect((awsConfig as Record<string, unknown>).requestChecksumCalculation).toBeUndefined();
      expect(awsConfig.region).toBe("us-west-2");

      const customConfig = configureProviderClient({ region: "eu-central-1" }, "custom");
      expect(customConfig.forcePathStyle).toBeUndefined();
    });
  });

  describe("createR2ChecksumStrippingMiddleware()", () => {
    it("strips x-amz-sdk-checksum-algorithm and x-amz-checksum-crc32 case-insensitively", async () => {
      const middleware = createR2ChecksumStrippingMiddleware();
      const next = vi.fn().mockImplementation(async (args) => ({ output: "ok", args }));

      const inputArgs = {
        request: {
          headers: {
            "x-amz-sdk-checksum-algorithm": "CRC32",
            "X-Amz-Checksum-Crc32": "abc123crc",
            "x-amz-date": "20260920T120000Z",
            Authorization: "AWS4-HMAC-SHA256 ...",
          },
        },
      };

      const handler = middleware(next);
      await handler(inputArgs);

      expect(next).toHaveBeenCalledOnce();
      expect(inputArgs.request.headers["x-amz-sdk-checksum-algorithm"]).toBeUndefined();
      expect(inputArgs.request.headers["X-Amz-Checksum-Crc32"]).toBeUndefined();
      expect(inputArgs.request.headers["x-amz-date"]).toBe("20260920T120000Z");
      expect(inputArgs.request.headers["Authorization"]).toBe("AWS4-HMAC-SHA256 ...");
    });

    it("passes through cleanly when headers are absent", async () => {
      const middleware = createR2ChecksumStrippingMiddleware();
      const next = vi.fn().mockResolvedValue({ output: "pass" });

      const res = await middleware(next)({});
      expect(res).toEqual({ output: "pass" });
      expect(next).toHaveBeenCalledOnce();
    });
  });

  describe("createCephMinio405SuppressionMiddleware()", () => {
    it("catches 405 MethodNotAllowed and returns safe empty output with $metadata.httpStatusCode 405", async () => {
      const middleware = createCephMinio405SuppressionMiddleware();
      const error405 = Object.assign(new Error("Method Not Allowed"), {
        name: "MethodNotAllowed",
        $metadata: { httpStatusCode: 405 },
        $response: { statusCode: 405 },
      });
      const next = vi.fn().mockRejectedValue(error405);

      const handler = middleware(next);
      const result = (await handler({})) as { output: { $metadata: { httpStatusCode: number } } };

      expect(result).toBeDefined();
      expect(result.output.$metadata.httpStatusCode).toBe(405);
    });

    it("catches 405 statusCode errors from MinIO and returns safe empty response", async () => {
      const middleware = createCephMinio405SuppressionMiddleware();
      const error405 = Object.assign(new Error("405 Method Not Allowed"), {
        statusCode: 405,
      });
      const next = vi.fn().mockRejectedValue(error405);

      const handler = middleware(next);
      const result = (await handler({})) as { output: { $metadata: { httpStatusCode: number } } };

      expect(result).toBeDefined();
      expect(result.output.$metadata.httpStatusCode).toBe(405);
    });

    it("re-throws non-405 errors (e.g. 403 AccessDenied, 404 NoSuchBucket)", async () => {
      const middleware = createCephMinio405SuppressionMiddleware();
      const error403 = Object.assign(new Error("Access Denied"), {
        name: "AccessDenied",
        $metadata: { httpStatusCode: 403 },
      });
      const next = vi.fn().mockRejectedValue(error403);

      const handler = middleware(next);
      await expect(handler({})).rejects.toThrow("Access Denied");
    });
  });

  describe("applyProviderMiddleware()", () => {
    it("registers stripR2ChecksumHeaders middleware when provider is r2", () => {
      const client = new S3Client({ region: "auto" });
      const beforeCount = client.middlewareStack.identify().length;

      applyProviderMiddleware(client, "r2");

      const identifiers = client.middlewareStack.identify();
      expect(identifiers.length).toBeGreaterThan(beforeCount);
      expect(identifiers.some((id) => id.includes("stripR2ChecksumHeaders"))).toBe(true);
    });

    it("registers suppressCephMinio405 middleware when provider is ceph or minio", () => {
      const clientCeph = new S3Client({ region: "us-east-1" });
      applyProviderMiddleware(clientCeph, "ceph");
      expect(
        clientCeph.middlewareStack.identify().some((id) => id.includes("suppressCephMinio405"))
      ).toBe(true);

      const clientMinio = new S3Client({ region: "us-east-1" });
      applyProviderMiddleware(clientMinio, "minio");
      expect(
        clientMinio.middlewareStack.identify().some((id) => id.includes("suppressCephMinio405"))
      ).toBe(true);
    });

    it("does not add quirks middleware for aws or custom providers", () => {
      const clientAws = new S3Client({ region: "us-east-1" });
      const beforeCount = clientAws.middlewareStack.identify().length;
      applyProviderMiddleware(clientAws, "aws");
      expect(clientAws.middlewareStack.identify().length).toBe(beforeCount);
    });
  });

  describe("is405MethodNotAllowedError()", () => {
    it("returns true for errors with httpStatusCode 405", () => {
      expect(is405MethodNotAllowedError({ $metadata: { httpStatusCode: 405 } })).toBe(true);
      expect(is405MethodNotAllowedError({ statusCode: 405 })).toBe(true);
      expect(is405MethodNotAllowedError({ status: 405 })).toBe(true);
    });

    it("returns true for errors with name MethodNotAllowed", () => {
      expect(is405MethodNotAllowedError({ name: "MethodNotAllowed" })).toBe(true);
      expect(is405MethodNotAllowedError({ Code: "MethodNotAllowed" })).toBe(true);
      expect(is405MethodNotAllowedError(new Error("HTTP 405 Method Not Allowed"))).toBe(true);
    });

    it("returns false for non-405 errors", () => {
      expect(is405MethodNotAllowedError(null)).toBe(false);
      expect(is405MethodNotAllowedError(undefined)).toBe(false);
      expect(is405MethodNotAllowedError({ $metadata: { httpStatusCode: 404 } })).toBe(false);
      expect(is405MethodNotAllowedError(new Error("AccessDenied"))).toBe(false);
    });
  });
});
