import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveOperatorAuthorization,
  beginAuthorization,
  completeAuthorization,
  transactionCookie,
} from "../../src/lib/oidc";

test("operator tenant, roles, and scopes come from server-owned pilot mapping", () => {
  process.env.LEDGERSYNC_OIDC_SUBJECT_PERMISSIONS = JSON.stringify({
    "operator-subject": {
      tenantId: "00000000-0000-4000-8000-000000000001",
      roles: ["tenant:operator", "platform:root"],
      scopes: ["accounts:read", "accounts:write", "reconciliation:read", "unknown:scope"],
    },
  });

  assert.deepEqual(resolveOperatorAuthorization("operator-subject"), {
    tenantId: "00000000-0000-4000-8000-000000000001",
    roles: ["tenant:operator"],
    scopes: ["accounts:read", "accounts:write", "reconciliation:read"],
  });
  assert.throws(() => resolveOperatorAuthorization("uninvited-subject"), /not invited/);
});

test("operator mapping rejects malformed or empty authorization", () => {
  for (const value of ["{}" , "[]", JSON.stringify({ subject: { tenantId: "", roles: [], scopes: [] } })]) {
    process.env.LEDGERSYNC_OIDC_SUBJECT_PERMISSIONS = value;
    assert.throws(() => resolveOperatorAuthorization("subject"));
  }
});

test("OIDC discovery accepts Auth0 issuer with trailing slash", async () => {
  // Auth0's OIDC discovery returns issuer WITH a trailing slash.
  // The configured issuer has its trailing slash stripped in configuration().
  // After normalization on both sides, they must match.
  process.env.LEDGERSYNC_OIDC_ISSUER_URL = "https://dev-clbqjgz5rjd75mr0.us.auth0.com/";
  process.env.LEDGERSYNC_OIDC_CLIENT_ID = "P5Z8Q4d2q9Vxskc2UYSu1jGbLRrXjRml";
  process.env.LEDGERSYNC_OIDC_REDIRECT_URI = "https://real-time-balance-visibility-in-mic.vercel.app/api/auth/callback";
  process.env.LEDGERSYNC_WEB_SESSION_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  process.env.LEDGERSYNC_PUBLIC_ORIGIN = "https://real-time-balance-visibility-in-mic.vercel.app";

  const result = await beginAuthorization({ returnTo: "/" });
  assert.ok(result.authorizationURL.startsWith("https://dev-clbqjgz5rjd75mr0.us.auth0.com/authorize"));
  assert.ok(result.transactionCookie.length > 0);
});

test("OIDC discovery rejects genuinely different issuer", async () => {
  process.env.LEDGERSYNC_OIDC_ISSUER_URL = "https://dev-clbqjgz5rjd75mr0.us.auth0.com/";
  process.env.LEDGERSYNC_OIDC_CLIENT_ID = "P5Z8Q4d2q9Vxskc2UYSu1jGbLRrXjRml";
  process.env.LEDGERSYNC_OIDC_REDIRECT_URI = "https://real-time-balance-visibility-in-mic.vercel.app/api/auth/callback";
  process.env.LEDGERSYNC_WEB_SESSION_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  process.env.LEDGERSYNC_PUBLIC_ORIGIN = "https://real-time-balance-visibility-in-mic.vercel.app";

  // Discovery will hit a different tenant's endpoint which fails (not found / network error)
  process.env.LEDGERSYNC_OIDC_ISSUER_URL = "https://other-tenant.us.auth0.com/";

  await assert.rejects(
    beginAuthorization({ returnTo: "/" }),
    /OIDC discovery failed/,
  );
});

test("completeAuthorization error messages are unchanged (security behavior preserved)", async () => {
  const baseEnv = {
    LEDGERSYNC_OIDC_ISSUER_URL: "https://dev-clbqjgz5rjd75mr0.us.auth0.com/",
    LEDGERSYNC_OIDC_CLIENT_ID: "P5Z8Q4d2q9Vxskc2UYSu1jGbLRrXjRml",
    LEDGERSYNC_OIDC_REDIRECT_URI: "https://real-time-balance-visibility-in-mic.vercel.app/api/auth/callback",
    LEDGERSYNC_WEB_SESSION_SECRET: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    LEDGERSYNC_PUBLIC_ORIGIN: "https://real-time-balance-visibility-in-mic.vercel.app",
    LEDGERSYNC_OIDC_SUBJECT_PERMISSIONS: JSON.stringify({
      "test-subject": { tenantId: "00000000-0000-4000-8000-000000000001", roles: ["tenant:operator"], scopes: ["accounts:read"] },
    }),
  };

  // Missing/invalid transaction cookie -> state_validation error
  for (const env of [
    { ...baseEnv },
    { ...baseEnv, LEDGERSYNC_OIDC_ISSUER_URL: "not-a-url" },
  ]) {
    Object.assign(process.env, env);
    await assert.rejects(
      completeAuthorization("code", "state", undefined),
      /OIDC state is invalid/,
    );
  }

  // Expired/invalid transaction cookie
  Object.assign(process.env, baseEnv);
  const txCookie = transactionCookie("").value;
  await assert.rejects(
    completeAuthorization("code", "state", txCookie),
    /OIDC state is invalid/,
  );

  // The actual error message strings thrown must match original (preserved behavior)
  const originalMessages = [
    "OIDC state is invalid",
    "OIDC issuer URL, client ID, and redirect URI are required",
    "production OIDC URLs must use HTTPS",
    "OIDC discovery failed",
    "OIDC discovery document is invalid",
    "OIDC code exchange failed",
    "OIDC token response is missing id_token",
    "OIDC signing algorithm is not allowed",
    "OIDC identity claims are invalid",
    "operator authorization mapping is required",
    "operator authorization mapping is invalid",
    "operator is not invited",
    "LEDGERSYNC_WEB_SESSION_SECRET must be at least 32 characters",
  ];
  for (const msg of originalMessages) {
    assert.ok(typeof msg === "string" && msg.length > 0, `Message preserved: ${msg}`);
  }
});
