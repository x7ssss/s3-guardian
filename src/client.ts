import { S3Client, S3ClientConfig } from "@aws-sdk/client-s3";
import { S3Provider, detectProvider } from "./providers/detector.js";
import { configureProviderClient, applyProviderMiddleware } from "./providers/quirks.js";

export interface S3ClientConfigOptions {
  region?: string;
  endpoint?: string;
  forcePathStyle?: boolean;
  credentials?: S3ClientConfig["credentials"];
  provider?: S3Provider | string;
}

/**
 * Creates an S3Client honoring standard ambient AWS credentials,
 * standard AWS environment variables, custom endpoint/forcePathStyle options,
 * and multi-cloud provider configurations (R2, Wasabi, B2, MinIO, Ceph).
 */
export function createS3Client(options: S3ClientConfigOptions = {}): S3Client {
  const endpoint =
    options.endpoint ||
    process.env.AWS_ENDPOINT_URL_S3 ||
    process.env.AWS_ENDPOINT_URL;

  const provider = detectProvider(endpoint, options.provider);

  const region =
    options.region ||
    process.env.AWS_REGION ||
    process.env.AWS_DEFAULT_REGION ||
    (provider === "r2" ? "auto" : "us-east-1");

  const forcePathStyle =
    options.forcePathStyle ??
    (process.env.AWS_S3_FORCE_PATH_STYLE === "true" ||
      process.env.AWS_FORCE_PATH_STYLE === "true" ||
      undefined);

  const baseConfig: S3ClientConfig = {
    region,
  };

  if (endpoint) {
    baseConfig.endpoint = endpoint;
  }

  if (forcePathStyle !== undefined) {
    baseConfig.forcePathStyle = forcePathStyle;
  }

  if (options.credentials !== undefined) {
    baseConfig.credentials = options.credentials;
  }

  const configuredConfig = configureProviderClient(baseConfig, provider);
  const client = new S3Client(configuredConfig);
  return applyProviderMiddleware(client, provider);
}
