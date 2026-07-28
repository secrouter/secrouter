/**
 * SigV4 signer test — validates against the published AWS `get-vanilla` vector
 * from the aws-sig-v4-test-suite. Run: npx tsx test/security/sigv4.test.ts
 */

import { signRequest } from "../../src/security/transport/sigv4.js";

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

console.log("SigV4:");

// AWS aws-sig-v4-test-suite "get-vanilla":
//   GET https://example.amazonaws.com/  on 2015-08-30T12:36:00Z
//   AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, us-east-1/service
const headers = signRequest({
  method: "GET",
  url: "https://example.amazonaws.com/",
  region: "us-east-1",
  service: "service",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  now: new Date("2015-08-30T12:36:00Z"),
});

const expected =
  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
  "SignedHeaders=host;x-amz-date, " +
  "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

ok("Authorization matches AWS get-vanilla vector", headers.Authorization === expected, `\n    got: ${headers.Authorization}\n    exp: ${expected}`);
ok("X-Amz-Date set", headers["X-Amz-Date"] === "20150830T123600Z");

// Session token path adds the security-token header.
const withTok = signRequest({
  method: "POST",
  url: "https://bedrock-runtime.us-gov-west-1.amazonaws.com/model/anthropic.claude/invoke",
  region: "us-gov-west-1",
  service: "bedrock",
  accessKeyId: "AKID",
  secretAccessKey: "secret",
  sessionToken: "tok123",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ x: 1 }),
  now: new Date("2026-01-02T03:04:05Z"),
});
ok("session token → X-Amz-Security-Token header", withTok["X-Amz-Security-Token"] === "tok123");
ok("signed headers include content-type + security-token", /SignedHeaders=content-type;host;x-amz-date;x-amz-security-token/.test(withTok.Authorization));

console.log(`\nSigV4: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
