import { describe, it, expect } from "vitest";
import {
  parseScalar,
  parseYamlSubset,
  parsePolicyDocument,
} from "../src/policy/index.js";

describe("Declarative Policy Parser (Zero-Dependency YAML & JSON)", () => {
  describe("parseScalar()", () => {
    it("parses booleans correctly", () => {
      expect(parseScalar("true")).toBe(true);
      expect(parseScalar("True")).toBe(true);
      expect(parseScalar("yes")).toBe(true);
      expect(parseScalar("on")).toBe(true);

      expect(parseScalar("false")).toBe(false);
      expect(parseScalar("False")).toBe(false);
      expect(parseScalar("no")).toBe(false);
      expect(parseScalar("off")).toBe(false);
    });

    it("parses numbers correctly", () => {
      expect(parseScalar("42")).toBe(42);
      expect(parseScalar("-10")).toBe(-10);
      expect(parseScalar("3.14")).toBe(3.14);
      expect(parseScalar("0")).toBe(0);
    });

    it("parses human duration units into days", () => {
      expect(parseScalar("7d")).toBe(7);
      expect(parseScalar("30d")).toBe(30);
      expect(parseScalar("24h")).toBe(1);
      expect(parseScalar("48h")).toBe(2);
      expect(parseScalar("2w")).toBe(14);
    });

    it("parses human size units into KiB", () => {
      expect(parseScalar("128KiB")).toBe(128);
      expect(parseScalar("128kb")).toBe(128);
      expect(parseScalar("1MiB")).toBe(1024);
      expect(parseScalar("2mb")).toBe(2048);
      expect(parseScalar("1GiB")).toBe(1024 * 1024);
    });

    it("parses quoted strings and unescapes correctly", () => {
      expect(parseScalar('"hello world"')).toBe("hello world");
      expect(parseScalar('"with \\"quotes\\""')).toBe('with "quotes"');
      expect(parseScalar("'single quoted'")).toBe("single quoted");
    });

    it("parses null, tilde, and empty values as null", () => {
      expect(parseScalar("")).toBe(null);
      expect(parseScalar("~")).toBe(null);
      expect(parseScalar("null")).toBe(null);
      expect(parseScalar("Null")).toBe(null);
    });

    it("returns plain strings when no other type matches", () => {
      expect(parseScalar("STANDARD_IA")).toBe("STANDARD_IA");
      expect(parseScalar("production-data/")).toBe("production-data/");
    });
  });

  describe("parseYamlSubset()", () => {
    it("parses basic key-value pairs and comments", () => {
      const yaml = `
# Global config comment
schemaVersion: "1"
policyId: test-global-policy # inline comment
scope:
  level: GLOBAL
  priority: 10
`;
      const result = parseYamlSubset(yaml);
      expect(result).toEqual({
        schemaVersion: "1",
        policyId: "test-global-policy",
        scope: {
          level: "GLOBAL",
          priority: 10,
        },
      });
    });

    it("preserves hash '#' inside quotes without treating as comment", () => {
      const yaml = `
key: "value with # hashtag"
another: 'also # not a comment'
`;
      const result = parseYamlSubset(yaml);
      expect(result.key).toBe("value with # hashtag");
      expect(result.another).toBe("also # not a comment");
    });

    it("parses arrays of objects and nested structures", () => {
      const yaml = `
rules:
  - id: abort-incomplete-mpu
    mpuAbortDays: 7d
    action: AUTO_REMEDIATE
  - id: tier-infrequent-access
    match:
      object:
        prefix: logs/
        minSizeKb: 128KiB
    transitions:
      - days: 30d
        storageClass: STANDARD_IA
`;
      const result = parseYamlSubset(yaml);
      expect(result.rules).toHaveLength(2);
      expect(result.rules[0]).toEqual({
        id: "abort-incomplete-mpu",
        mpuAbortDays: 7,
        action: "AUTO_REMEDIATE",
      });
      expect(result.rules[1].id).toBe("tier-infrequent-access");
      expect(result.rules[1].match.object.prefix).toBe("logs/");
      expect(result.rules[1].match.object.minSizeKb).toBe(128);
      expect(result.rules[1].transitions[0]).toEqual({
        days: 30,
        storageClass: "STANDARD_IA",
      });
    });

    it("parses arrays of scalars", () => {
      const yaml = `
regions:
  - us-east-1
  - us-west-2
  - eu-west-1
`;
      const result = parseYamlSubset(yaml);
      expect(result.regions).toEqual(["us-east-1", "us-west-2", "eu-west-1"]);
    });

    it("strictly rejects tab characters in indentation with a syntax error", () => {
      const yamlWithTab = "scope:\n\tlevel: GLOBAL";
      expect(() => parseYamlSubset(yamlWithTab)).toThrowError(
        /tab characters are not allowed for indentation/i
      );
    });

    it("throws syntax error on malformed key-value line", () => {
      const badYaml = "not-a-valid-line-without-colon";
      expect(() => parseYamlSubset(badYaml)).toThrowError(
        /expected key-value pair or list item/i
      );
    });
  });

  describe("parsePolicyDocument()", () => {
    it("parses JSON policy document correctly", () => {
      const jsonPolicy = JSON.stringify({
        schemaVersion: "1",
        policyId: "json-policy-1",
        scope: {
          level: "ACCOUNT",
          accountId: "123456789012",
        },
        rules: [
          {
            id: "rule-1",
            mpuAbortDays: 7,
            match: {
              object: { prefix: "temp/" },
            },
          },
        ],
      });

      const policy = parsePolicyDocument(jsonPolicy);
      expect(policy.schemaVersion).toBe("1");
      expect(policy.policyId).toBe("json-policy-1");
      expect(policy.scope.level).toBe("ACCOUNT");
      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0]?.id).toBe("rule-1");
      expect(policy.rules[0]?.mpuAbortDays).toBe(7);
    });

    it("parses YAML policy document correctly", () => {
      const yamlPolicy = `
schemaVersion: "1"
policyId: org-default-lifecycle
scope:
  level: OU
  ouId: ou-prod-001
  priority: 50
defaults:
  action: PLAN_ONLY
  mpuAbortDays: 7d
rules:
  - id: cleanup-scratch
    match:
      bucket:
        regions:
          - us-east-1
      object:
        prefix: scratch/
    expirationDays: 14d
`;

      const policy = parsePolicyDocument(yamlPolicy);
      expect(policy.schemaVersion).toBe("1");
      expect(policy.policyId).toBe("org-default-lifecycle");
      expect(policy.scope.level).toBe("OU");
      expect(policy.scope.ouId).toBe("ou-prod-001");
      expect(policy.defaults?.action).toBe("PLAN_ONLY");
      expect(policy.defaults?.mpuAbortDays).toBe(7);
      expect(policy.rules).toHaveLength(1);
      expect(policy.rules[0]?.expirationDays).toBe(14);
    });

    it("throws when schemaVersion is invalid or unsupported", () => {
      const invalid = `
schemaVersion: "2"
policyId: test
scope:
  level: GLOBAL
rules: []
`;
      expect(() => parsePolicyDocument(invalid)).toThrowError(
        /unsupported schemaVersion "2"/i
      );
    });

    it("throws when scope.level is invalid", () => {
      const invalid = `
schemaVersion: "1"
policyId: test
scope:
  level: INVALID_LEVEL
rules: []
`;
      expect(() => parsePolicyDocument(invalid)).toThrowError(
        /invalid scope\.level 'INVALID_LEVEL'/i
      );
    });

    it("throws when policyId is missing", () => {
      const invalid = `
schemaVersion: "1"
scope:
  level: GLOBAL
rules: []
`;
      expect(() => parsePolicyDocument(invalid)).toThrowError(
        /missing or empty required field 'policyId'/i
      );
    });

    it("throws when rules is missing or not an array", () => {
      const invalid = `
schemaVersion: "1"
policyId: test
scope:
  level: GLOBAL
`;
      expect(() => parsePolicyDocument(invalid)).toThrowError(
        /missing required field 'rules'/i
      );
    });

    it("throws when a rule is missing 'id'", () => {
      const invalid = `
schemaVersion: "1"
policyId: test
scope:
  level: GLOBAL
rules:
  - mpuAbortDays: 7d
`;
      expect(() => parsePolicyDocument(invalid)).toThrowError(
        /missing required 'id'/i
      );
    });
  });
});
