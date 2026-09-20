import { S3Client, S3ClientConfig } from "@aws-sdk/client-s3";

export interface S3ClientConfigOptions {
  region?: string;
  endpoint?: string;
  forcePathStyle?: boolean;
  credentials?: S3ClientConfig["credentials"];
}

/**
 * Creates an S3Client honoring standard ambient AWS credentials,
 * standard AWS environment variables, and custom endpoint/forcePathStyle options.
 */
export function createS3Client(options: S3ClientConfigOptions = {}): S3Client {
  const endpoint =
    options.endpoint ||
    process.env.AWS_ENDPOINT_URL_S3 ||
    process.env.AWS_ENDPOINT_URL;

  const region =
    options.region ||
    process.env.AWS_REGION ||
    process.env.AWS_DEFAULT_REGION ||
    "us-east-1";

  const forcePathStyle =
    options.forcePathStyle ??
    (process.env.AWS_S3_FORCE_PATH_STYLE === "true" ||
      process.env.AWS_FORCE_PATH_STYLE === "true" ||
      undefined);

  const config: S3ClientConfig = {
    region,
  };

  if (endpoint) {
    config.endpoint = endpoint;
  }

  if (forcePathStyle !== undefined) {
    config.forcePathStyle = forcePathStyle;
  }

  if (options.credentials !== undefined) {
    config.credentials = options.credentials;
  }

  return new S3Client(config);
}
