/**
 * Egress / data-residency gate tests. Run: npx tsx test/security/egress.test.ts
 * Proves deny-by-default and the classification gate — the controls that stop
 * CUI from reaching an unauthorized or foreign-jurisdiction destination.
 */

import { checkEgress } from "../../src/security/egress/allowlist.js";
import type { SecurityConfig } from "../../src/security/types.js";

let pass = 0;
let fail = 0;
function ok(name: string, cond: boolean, extra = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name} ${extra}`);
  }
}

const SEC: SecurityConfig = {
  enabled: true,
  classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"] },
  egress: {
    allowlist: [
      {
        provider: "bedrock",
        allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com",
        authorizedClassifications: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"],
        authorization: "Bedrock GovCloud — FedRAMP High / IL4-5",
      },
      {
        provider: "local",
        allowedHost: "llm.internal.mil",
        authorizedClassifications: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"],
        authorization: "Self-hosted inside the boundary",
      },
    ],
  },
};

console.log("Egress gate:");

// Authorized destinations
ok(
  "Bedrock GovCloud + CUI → allow",
  checkEgress("bedrock", "bedrock-runtime.us-gov-west-1.amazonaws.com", "CUI", SEC).allowed === true,
);
ok("self-hosted + CUI → allow", checkEgress("local", "llm.internal.mil", "CUI", SEC).allowed === true);

// Deny-by-default: provider not in the allow-list (the Kimi/Moonshot case)
ok(
  "Kimi (unlisted PRC provider) → DENY",
  checkEgress("kimi-coding", "api.kimi.com", "CUI", SEC).allowed === false,
);
ok(
  "commercial anthropic (unlisted) → DENY",
  checkEgress("anthropic", "api.anthropic.com", "CUI", SEC).allowed === false,
);

// Host mismatch for a listed provider → deny (defends against config drift / SSRF)
ok(
  "Bedrock listed but wrong host → DENY",
  checkEgress("bedrock", "bedrock-runtime.us-east-1.amazonaws.com", "CUI", SEC).allowed === false,
);

// Classification gate: destination not authorized for the data class
const SEC2: SecurityConfig = {
  ...SEC,
  egress: {
    allowlist: [
      {
        provider: "commercial",
        allowedHost: "api.example.com",
        authorizedClassifications: ["UNCLASSIFIED"],
      },
    ],
  },
};
ok(
  "UNCLASS-only destination + CUI request → DENY",
  checkEgress("commercial", "api.example.com", "CUI", SEC2).allowed === false,
);
ok(
  "UNCLASS-only destination + UNCLASSIFIED request → allow",
  checkEgress("commercial", "api.example.com", "UNCLASSIFIED", SEC2).allowed === true,
);

console.log(`\nEgress: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
