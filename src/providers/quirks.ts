import { S3Client, S3ClientConfig } from "@aws-sdk/client-s3";
import { S3Provider } from "./detector.js";

/**
 * Inspects whether an unknown error indicates HTTP 405 MethodNotAllowed,
 * which Ceph and MinIO return for unsupported S3 extensions (e.g. Object Lock, Lifecycle).
 */
export function is405MethodNotAllowedError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const errorObj = err as Record<string, unknown>;
  const name = String(errorObj.name || errorObj.Code || "");
  const status =
    (errorObj.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    errorObj.statusCode ??
    errorObj.status;
  const message = String(errorObj.message || "");

  return (
    status === 405 ||
    name === "MethodNotAllowed" ||
    /MethodNotAllowed|405 Method Not Allowed/i.test(message)
  );
}

/**
 * Returns a modified S3ClientConfig tailored to target provider quirks:
 *  - R2: sets requestChecksumCalculation: "WHEN_REQUIRED", responseChecksumValidation: "WHEN_REQUIRED",
 *    and defaults region to 'auto'.
 *  - MinIO / Ceph / B2: sets forcePathStyle: true.
 */
export function configureProviderClient(
  s3ClientConfig: S3ClientConfig,
  provider: S3Provider
): S3ClientConfig {
  const config: S3ClientConfig = { ...s3ClientConfig };

  if (provider === "r2") {
    (config as Record<string, unknown>).requestChecksumCalculation = "WHEN_REQUIRED";
    (config as Record<string, unknown>).responseChecksumValidation = "WHEN_REQUIRED";
    if (!config.region || config.region === "us-east-1") {
      config.region = "auto";
    }
  } else if (provider === "minio" || provider === "ceph" || provider === "b2") {
    config.forcePathStyle = true;
  }

  return config;
}

/**
 * Creates middleware to strip unsupported R2 checksum headers on finalizeRequest step.
 */
export function createR2ChecksumStrippingMiddleware() {
  return ((next: (args: any) => Promise<any>) => async (args: any) => {
    const a = args as { request?: { headers?: Record<string, string> } };
    if (a?.request?.headers && typeof a.request.headers === "object") {
      for (const key of Object.keys(a.request.headers)) {
        const lower = key.toLowerCase();
        if (
          lower === "x-amz-sdk-checksum-algorithm" ||
          lower === "x-amz-checksum-crc32"
        ) {
          delete a.request.headers[key];
        }
      }
    }
    return next(args);
  }) as any;
}

/**
 * Creates middleware to suppress HTTP 405 MethodNotAllowed errors from Ceph / MinIO on deserialize step.
 */
export function createCephMinio405SuppressionMiddleware() {
  return ((next: (args: any) => Promise<any>) => async (args: any) => {
    try {
      return await next(args);
    } catch (err: unknown) {
      if (is405MethodNotAllowedError(err)) {
        return {
          response: (err as Record<string, unknown>)?.$response ?? {},
          output: {
            $metadata: {
              httpStatusCode: 405,
            },
          } as any,
        };
      }
      throw err;
    }
  }) as any;
}

/**
 * Applies targeted middleware to the S3Client based on provider quirks:
 *  - R2: adds middleware on 'finalizeRequest' to strip x-amz-sdk-checksum-algorithm
 *    and x-amz-checksum-crc32 headers.
 *  - Ceph / MinIO: adds middleware on 'deserialize' to catch HTTP 405 MethodNotAllowed
 *    and return a safe empty response payload for unsupported queries.
 */
export function applyProviderMiddleware(
  client: S3Client,
  provider: S3Provider
): S3Client {
  if (provider === "r2") {
    client.middlewareStack.add(createR2ChecksumStrippingMiddleware(), {
      step: "finalizeRequest",
      name: "stripR2ChecksumHeaders",
      tags: ["CHECKSUM", "R2"],
    });
  }

  if (provider === "minio" || provider === "ceph") {
    client.middlewareStack.add(createCephMinio405SuppressionMiddleware(), {
      step: "deserialize",
      name: "suppressCephMinio405",
      tags: ["ERROR_HANDLING", "405"],
    });
  }

  return client;
}
