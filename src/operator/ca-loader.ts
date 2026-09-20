import * as fs from "node:fs";
import type * as tlsTypes from "node:tls";
import { createRequire } from "node:module";

const nodeRequire =
  typeof require !== "undefined"
    ? require
    : createRequire(
        typeof __filename !== "undefined"
          ? __filename
          : "file://" + process.cwd().replace(/\\/g, "/") + "/index.js"
      );
const tls = nodeRequire("node:tls");
const https = nodeRequire("node:https");

const PEM_CERT_REGEX = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Track loaded custom CA certificates in-process. */
const customCertificates: string[] = [];
let isTlsPatched = false;

/**
 * Patches tls.createSecureContext so that any created TLS context
 * automatically incorporates custom enterprise CA certificates.
 */
function patchTlsCreateSecureContext(): void {
  if (isTlsPatched) return;
  isTlsPatched = true;

  const originalCreateSecureContext = tls.createSecureContext;

  tls.createSecureContext = function (options?: tlsTypes.SecureContextOptions): tlsTypes.SecureContext {
    const context = originalCreateSecureContext.call(tls, options);

    for (const cert of customCertificates) {
      try {
        if (context && context.context && typeof context.context.addCACert === "function") {
          context.context.addCACert(cert);
        }
      } catch {
        // Silently ignore individual certificate parse/duplicate errors
      }
    }

    return context;
  };
}

/**
 * Loads custom CA certificates from process.env.NODE_EXTRA_CA_CERTS (or optional explicit path).
 *
 * Injects certificates into Node TLS contexts:
 * 1. Appends PEM certificates to tls.rootCertificates if extensible.
 * 2. Monkey-patches tls.createSecureContext so AWS SDK v3 and Node https client
 *    trust custom enterprise CAs (e.g. air-gapped MinIO/Ceph clusters) without TLS panics.
 * 3. Appends PEMs to https.globalAgent.options.ca for default HTTPS agents.
 *
 * Returns array of loaded PEM certificate strings.
 */
export function loadCustomCaCertificates(explicitPath?: string): string[] {
  const caPath = explicitPath ?? process.env.NODE_EXTRA_CA_CERTS;
  if (!caPath || caPath.trim() === "") {
    return [];
  }

  if (!fs.existsSync(caPath)) {
    throw new Error(`Custom CA certificate file not found at path: ${caPath}`);
  }

  const rawPem = fs.readFileSync(caPath, "utf8");
  const matches = rawPem.match(PEM_CERT_REGEX);

  if (!matches || matches.length === 0) {
    return [];
  }

  for (const cert of matches) {
    const trimmed = cert.trim();
    if (trimmed && !customCertificates.includes(trimmed)) {
      customCertificates.push(trimmed);
    }
  }

  // Attempt appending to tls.rootCertificates if extensible in the running Node runtime
  try {
    if (Array.isArray(tls.rootCertificates) && !Object.isFrozen(tls.rootCertificates)) {
      for (const cert of customCertificates) {
        if (!tls.rootCertificates.includes(cert)) {
          (tls.rootCertificates as string[]).push(cert);
        }
      }
    }
  } catch {
    // tls.rootCertificates is frozen in some Node versions; createSecureContext patch handles it
  }

  // Patch tls.createSecureContext for all future TLS handshakes
  patchTlsCreateSecureContext();

  // Inject into https.globalAgent options
  try {
    if (https && https.globalAgent) {
      const agentOptions = (https.globalAgent.options || {}) as Record<string, unknown> & { ca?: string | string[] };
      const currentCa = Array.isArray(agentOptions.ca)
        ? agentOptions.ca
        : typeof agentOptions.ca === "string"
        ? [agentOptions.ca]
        : [];

      https.globalAgent.options = {
        ...agentOptions,
        ca: [...currentCa, ...customCertificates],
      };
    }
  } catch {
    // Ignore agent patching failure
  }

  return [...customCertificates];
}

/**
 * Returns all custom CA certificates currently registered in memory.
 */
export function getCustomCaCertificates(): string[] {
  return [...customCertificates];
}

/**
 * Clears registered custom CA certificates (primarily for test isolation).
 */
export function clearCustomCaCertificates(): void {
  customCertificates.length = 0;
}
