import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveOperatorAuthorization,
  beginAuthorization,
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
