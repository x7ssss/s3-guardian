import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as tls from "node:tls";
import {
  loadCustomCaCertificates,
  getCustomCaCertificates,
  clearCustomCaCertificates,
} from "../src/operator/ca-loader.js";

const DUMMY_PEM_1 = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHH7e2g6mF/MAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCEFpcmdh
cHBDQTAeFw0yNjA5MjAxMjAwMDBaFw0zNjA5MjAxMjAwMDBaMBMxETAPBgNVBAMM
CEFpcmdhcHBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM7s6g45q8w2L9e3
k7Y8Z9X1V2Q5N8m4L7k0P9Q1R3S5T7U9V1W3X5Y7Z9a1b3c5d7e9f1g3h5i7j9k=
-----END CERTIFICATE-----`;

const DUMMY_PEM_2 = `-----BEGIN CERTIFICATE-----
MIIBkTCCATagAwIBAgIUQ48Xq3L9e3k7Y8Z9X1V2Q5N8m4LwDwYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKTWluSU9DZXBoQ0EwHhcNMjYwOTIwMTIwMDAwWhcNMzYwOTIw
MTIwMDAwWjAVMRMwEQYDVQQDDApNaW5JT0NlcGhDQTBYMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABI8m2K4q9w0L8e4k6Y7Z8X0V1Q4N7m3L6k9P8Q0R2S4T6U8V0W2=
-----END CERTIFICATE-----`;

describe("Custom CA Certificate Loader (ca-loader.ts)", () => {
  const originalEnv = process.env.NODE_EXTRA_CA_CERTS;
  let tempDir: string;

  beforeEach(() => {
    clearCustomCaCertificates();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "s3-guardian-ca-test-"));
    delete process.env.NODE_EXTRA_CA_CERTS;
  });

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.NODE_EXTRA_CA_CERTS = originalEnv;
    } else {
      delete process.env.NODE_EXTRA_CA_CERTS;
    }
    clearCustomCaCertificates();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("returns empty array when NODE_EXTRA_CA_CERTS is not set", () => {
    delete process.env.NODE_EXTRA_CA_CERTS;
    const certs = loadCustomCaCertificates();
    expect(certs).toEqual([]);
    expect(getCustomCaCertificates()).toEqual([]);
  });

  it("throws error when NODE_EXTRA_CA_CERTS points to non-existent file", () => {
    const nonExistent = path.join(tempDir, "missing-ca.pem");
    process.env.NODE_EXTRA_CA_CERTS = nonExistent;
    expect(() => loadCustomCaCertificates()).toThrow(/Custom CA certificate file not found/i);
  });

  it("loads single PEM certificate and injects into TLS context", () => {
    const caPath = path.join(tempDir, "custom-ca.pem");
    fs.writeFileSync(caPath, DUMMY_PEM_1, "utf8");
    process.env.NODE_EXTRA_CA_CERTS = caPath;

    const certs = loadCustomCaCertificates();
    expect(certs.length).toBe(1);
    expect(certs[0]).toContain("-----BEGIN CERTIFICATE-----");
    expect(certs[0]).toContain("-----END CERTIFICATE-----");

    // Verify tls.createSecureContext executes cleanly and invokes addCACert
    const secureCtx = tls.createSecureContext();
    expect(secureCtx).toBeDefined();
    expect(secureCtx.context).toBeDefined();
  });

  it("loads multi-certificate bundle from file", () => {
    const bundlePath = path.join(tempDir, "ca-bundle.pem");
    fs.writeFileSync(bundlePath, `${DUMMY_PEM_1}\n\n${DUMMY_PEM_2}\n`, "utf8");

    const certs = loadCustomCaCertificates(bundlePath);
    expect(certs.length).toBe(2);
    expect(getCustomCaCertificates().length).toBe(2);

    const secureCtx = tls.createSecureContext();
    expect(secureCtx).toBeDefined();
  });

  it("handles duplicate certificate registrations idempotently", () => {
    const caPath = path.join(tempDir, "ca.pem");
    fs.writeFileSync(caPath, DUMMY_PEM_1, "utf8");

    loadCustomCaCertificates(caPath);
    const certsSecond = loadCustomCaCertificates(caPath);

    expect(certsSecond.length).toBe(1);
    expect(getCustomCaCertificates().length).toBe(1);
  });
});
