/**
 * Issue #925 — SEP-10 challenge and session-token rejections, end to end.
 *
 * Every rejection the authentication surface can produce is driven through
 * the real Fastify pipeline (route → service → central error handler) and
 * pinned on four things a client and an operator depend on:
 *
 *  - the HTTP status (401 for a rejected credential, on both the SEP-10 token
 *    endpoint and the bearer middleware; 400 for a request that never reached
 *    credential evaluation; 502 for Horizon being unreachable);
 *  - a stable machine-readable `error.code`;
 *  - the RFC 6750 `WWW-Authenticate` challenge on bearer-token 401s (and its
 *    absence on the SEP-10 endpoint, which is not bearer-authenticated);
 *  - a body carrying no stack trace, SDK or jsonwebtoken error text, or
 *    server key material.
 *
 * Challenges are real: built with `WebAuth.buildChallengeTx` (or, for the
 * shapes the SDK refuses to build, `TransactionBuilder`), signed with
 * `Keypair.random()` clients. Horizon and the database are mocked, and time is
 * faked where the outcome depends on it, so nothing here touches the network.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import jwt from "jsonwebtoken";
import {
  Account,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  Transaction,
  TransactionBuilder,
  WebAuth,
  xdr,
} from "@stellar/stellar-sdk";

const h = vi.hoisted(() => {
  const prisma: any = {
    user: { upsert: vi.fn(), findUnique: vi.fn() },
    auditLog: { create: vi.fn(async () => ({})) },
    refreshToken: { create: vi.fn(async () => ({})) },
    $transaction: vi.fn(async (arg: any) =>
      typeof arg === "function" ? arg(prisma) : Promise.all(arg)
    ),
    $disconnect: vi.fn(),
  };
  return { prisma, loadAccount: vi.fn() };
});

// No durable challenge store is wired, so redemption uses the documented
// test-only in-process replay guard (see src/services/sep10.ts).
vi.mock("../src/db", () => ({ prisma: h.prisma }));

vi.mock("../src/services/stellar", async (importActual) => {
  const actual = await importActual<typeof import("../src/services/stellar")>();
  return { ...actual, stellar: { ...actual.stellar, loadAccount: h.loadAccount } };
});

vi.mock("../src/services/refresh-token", async (importActual) => {
  const actual = await importActual<typeof import("../src/services/refresh-token")>();
  return {
    ...actual,
    issueRefreshToken: vi.fn(async () => ({
      token: "refresh-token",
      expiresAt: new Date("2026-12-31T00:00:00.000Z"),
    })),
  };
});

import { buildApp } from "../src/app";
import { config } from "../src/config";
import { serverKeypair, CHALLENGE_VALIDITY_SECONDS } from "../src/services/sep10";
import { signToken } from "../src/plugins/auth";
import { BearerAuthError } from "../src/errors";
import { CLOCK_SKEW_TOLERANCE_SECONDS } from "../src/lib/time-bounds";

const VERIFY = "/api/v1/auth/verify";
const PROTECTED = "/api/v1/me";
const T0 = new Date("2026-10-23T12:00:00.000Z");

/** A network this deployment is not on (the suite runs on `public`). */
const OTHER_NETWORK =
  config.networkPassphrase === Networks.TESTNET ? Networks.PUBLIC : Networks.TESTNET;

const UNFUNDED = {
  exists: false,
  sequence: "0",
  balances: [],
  signers: [],
  thresholds: { low: 0, med: 0, high: 0 },
};

let app: Awaited<ReturnType<typeof buildApp>>;

beforeAll(async () => {
  app = await buildApp({ rateLimit: "off" });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  h.loadAccount.mockReset().mockResolvedValue(UNFUNDED);
  h.prisma.user.upsert.mockReset().mockImplementation(async ({ create }: any) => ({
    id: "user_925",
    displayName: "test",
    avatarUrl: null,
    createdAt: T0,
    ...create,
  }));
  h.prisma.user.findUnique.mockReset().mockImplementation(async () => ({
    id: "user_925",
    stellarPublicKey: USER.stellarPublicKey,
    displayName: "test",
    avatarUrl: null,
    createdAt: T0,
  }));
});

afterEach(() => {
  vi.useRealTimers();
});

// -- helpers ------------------------------------------------------------------

/** Build a challenge with this server's key, overriding any SDK argument. */
function challenge(
  client: Keypair,
  opts: { homeDomain?: string; passphrase?: string; server?: Keypair; webAuthDomain?: string } = {}
): string {
  return WebAuth.buildChallengeTx(
    opts.server ?? serverKeypair(),
    client.publicKey(),
    opts.homeDomain ?? config.SEP10_HOME_DOMAIN,
    CHALLENGE_VALIDITY_SECONDS,
    opts.passphrase ?? config.networkPassphrase,
    opts.webAuthDomain ?? config.WEB_AUTH_DOMAIN
  );
}

/** Add signatures the way a wallet does: parse, sign, re-emit. */
function sign(
  challengeXdr: string,
  signers: Keypair[],
  passphrase: string = config.networkPassphrase
): string {
  const tx = new Transaction(challengeXdr, passphrase);
  for (const signer of signers) tx.sign(signer);
  return tx.toXDR();
}

/** Remove every signature, so only the ones added afterwards remain. */
function stripSignatures(challengeXdr: string): string {
  const envelope = xdr.TransactionEnvelope.fromXDR(challengeXdr, "base64");
  envelope.v1().signatures([]);
  return envelope.toXDR("base64");
}

/**
 * Hand-build a challenge-shaped envelope with this server as signer, for the
 * shapes `buildChallengeTx` will not produce (non-zero sequence, foreign source).
 */
function handBuilt(
  client: Keypair,
  opts: { sequence?: string; source?: string } = {}
): string {
  const server = serverKeypair();
  const now = Math.floor(Date.now() / 1000);
  const tx = new TransactionBuilder(
    new Account(opts.source ?? server.publicKey(), opts.sequence ?? "-1"),
    {
      fee: BASE_FEE,
      networkPassphrase: config.networkPassphrase,
      timebounds: { minTime: now, maxTime: now + CHALLENGE_VALIDITY_SECONDS },
    }
  )
    .addOperation(
      Operation.manageData({
        name: `${config.SEP10_HOME_DOMAIN} auth`,
        value: Buffer.alloc(48, 7).toString("base64"),
        source: client.publicKey(),
      })
    )
    .addOperation(
      Operation.manageData({
        name: "web_auth_domain",
        value: config.WEB_AUTH_DOMAIN,
        source: server.publicKey(),
      })
    )
    .build();
  tx.sign(server);
  return tx.toXDR();
}

function verify(transaction: unknown) {
  return app.inject({ method: "POST", url: VERIFY, payload: { transaction } });
}

/** Text an error body must never contain: library messages, stack frames, keys. */
const LEAK_MARKERS = [
  /\bat [\w.<>]+ \(/, // a stack frame
  /"stack"/,
  /InvalidChallengeError/,
  /The transaction/i, // SDK challenge messages all start this way
  /Transaction not signed/,
  /signers with weight/,
  /jwt (malformed|expired|issuer|audience|signature|not active)/i,
  /invalid (signature|algorithm)/,
  /JsonWebTokenError|TokenExpiredError|NotBeforeError/,
];

/** The response is a structured error envelope with nothing internal in it. */
function expectSafeErrorBody(res: { body: string }, code: string): Record<string, any> {
  const body = JSON.parse(res.body);
  expect(body.error).toMatchObject({ code, message: expect.any(String) });
  expect(body.error.requestId).toEqual(expect.any(String));
  expect(body.code).toBe(code);
  for (const marker of LEAK_MARKERS) expect(res.body).not.toMatch(marker);
  expect(res.body).not.toContain(serverKeypair().secret());
  expect(res.body).not.toContain(serverKeypair().publicKey());
  expect(res.body).not.toContain(config.JWT_SECRET);
  return body;
}

/** A SEP-10 challenge rejection: 401, the code, and no bearer challenge. */
async function expectChallengeRejected(transaction: string, code: string) {
  const res = await verify(transaction);
  expect(res.statusCode).toBe(401);
  expect(res.headers["www-authenticate"]).toBeUndefined();
  expectSafeErrorBody(res, code);
  expect(h.prisma.user.upsert).not.toHaveBeenCalled();
  return res;
}

// -- SEP-10 token endpoint ----------------------------------------------------

describe("POST /auth/verify — accepted challenges (no regressions)", () => {
  it("exchanges a correctly signed challenge for a session token that opens a protected route", async () => {
    const client = Keypair.random();
    const res = await verify(sign(challenge(client), [client]));

    expect(res.statusCode).toBe(200);
    const { token } = res.json();
    expect(jwt.decode(token)).toMatchObject({ pk: client.publicKey() });

    USER.stellarPublicKey = client.publicKey();
    const me = await app.inject({
      method: "GET",
      url: PROTECTED,
      headers: { authorization: `Bearer ${token}` },
    });
    expect(me.statusCode).toBe(200);
    expect(me.json().user.stellarPublicKey).toBe(client.publicKey());
  });

  it("accepts a funded account whose signers meet the medium threshold", async () => {
    const client = Keypair.random();
    const cosigner = Keypair.random();
    h.loadAccount.mockResolvedValue({
      ...UNFUNDED,
      exists: true,
      signers: [
        { key: client.publicKey(), weight: 1 },
        { key: cosigner.publicKey(), weight: 1 },
      ],
      thresholds: { low: 1, med: 2, high: 2 },
    });

    const res = await verify(sign(challenge(client), [client, cosigner]));
    expect(res.statusCode).toBe(200);
  });

  it("accepts a challenge signed inside the clock-skew tolerance after maxTime", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client), [client]);
    vi.setSystemTime(
      new Date(T0.getTime() + (CHALLENGE_VALIDITY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS - 1) * 1000)
    );
    expect((await verify(signed)).statusCode).toBe(200);
  });
});

describe("POST /auth/verify — time bounds", () => {
  it("rejects an expired challenge with CHALLENGE_EXPIRED", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client), [client]);
    vi.setSystemTime(
      new Date(T0.getTime() + (CHALLENGE_VALIDITY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS + 1) * 1000)
    );

    const res = await expectChallengeRejected(signed, "CHALLENGE_EXPIRED");
    expect(res.json().error.details).toEqual({
      challengeValiditySeconds: CHALLENGE_VALIDITY_SECONDS,
    });
  });

  it("rejects an expired challenge well past the SDK's own 5-minute grace the same way", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client), [client]);
    vi.setSystemTime(new Date(T0.getTime() + 60 * 60 * 1000));
    await expectChallengeRejected(signed, "CHALLENGE_EXPIRED");
  });

  it("reports a closed window as CHALLENGE_EXPIRED even when its bounds are inverted", async () => {
    // A negative timeout builds minTime = now, maxTime = now - 60. The window
    // has closed, so expiry (not a structural code) is the useful answer —
    // the precedence verification had before #925.
    const client = Keypair.random();
    const transaction = WebAuth.buildChallengeTx(
      serverKeypair(),
      client.publicKey(),
      config.SEP10_HOME_DOMAIN,
      -60,
      config.networkPassphrase,
      config.WEB_AUTH_DOMAIN
    );
    await expectChallengeRejected(sign(transaction, [client]), "CHALLENGE_EXPIRED");
  });

  it("does not grant CHALLENGE_EXPIRED to an expired envelope this server did not sign", async () => {
    // Regression: the old fallback path reported any expired envelope the SDK
    // refused as CHALLENGE_EXPIRED, server signature or not.
    const client = Keypair.random();
    const forged = sign(stripSignatures(challenge(client)), [client]);
    vi.setSystemTime(
      new Date(T0.getTime() + (CHALLENGE_VALIDITY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS + 1) * 1000)
    );
    await expectChallengeRejected(forged, "INVALID_CHALLENGE");
  });

  it("rejects a challenge whose window has not opened with CHALLENGE_NOT_YET_VALID", async () => {
    const client = Keypair.random();
    // Inside the SDK's 5-minute grace, outside this server's skew tolerance.
    vi.setSystemTime(new Date(T0.getTime() + 120 * 1000));
    const signed = sign(challenge(client), [client]);
    vi.setSystemTime(T0);
    await expectChallengeRejected(signed, "CHALLENGE_NOT_YET_VALID");
  });

  it("answers a far-future window the same way, regardless of the SDK's grace", async () => {
    const client = Keypair.random();
    vi.setSystemTime(new Date(T0.getTime() + 60 * 60 * 1000));
    const signed = sign(challenge(client), [client]);
    vi.setSystemTime(T0);
    await expectChallengeRejected(signed, "CHALLENGE_NOT_YET_VALID");
  });
});

describe("POST /auth/verify — wrong network, domain, or issuer", () => {
  it("rejects this server's challenge signed for another network with NETWORK_MISMATCH", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client, { passphrase: OTHER_NETWORK }), [client], OTHER_NETWORK);
    const res = await expectChallengeRejected(signed, "NETWORK_MISMATCH");
    expect(res.json().error.details).toEqual({ networkPassphrase: config.networkPassphrase });
  });

  it("rejects another server's challenge for another network with the opaque INVALID_CHALLENGE", async () => {
    const client = Keypair.random();
    const signed = sign(
      challenge(client, { passphrase: OTHER_NETWORK, server: Keypair.random() }),
      [client],
      OTHER_NETWORK
    );
    await expectChallengeRejected(signed, "INVALID_CHALLENGE");
  });

  it("rejects this server's challenge for another home domain with HOME_DOMAIN_MISMATCH", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client, { homeDomain: "evil.example.com" }), [client]);
    const res = await expectChallengeRejected(signed, "HOME_DOMAIN_MISMATCH");
    expect(res.json().error.details).toEqual({ homeDomain: config.SEP10_HOME_DOMAIN });
  });

  it("does not reveal a home-domain mismatch on an envelope this server did not sign", async () => {
    const client = Keypair.random();
    const signed = sign(
      challenge(client, { homeDomain: "evil.example.com", server: Keypair.random() }),
      [client]
    );
    await expectChallengeRejected(signed, "INVALID_CHALLENGE");
  });

  it("rejects a mismatched web_auth_domain", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client, { webAuthDomain: "evil.example.com" }), [client]);
    await expectChallengeRejected(signed, "INVALID_CHALLENGE");
  });

  it("rejects a challenge built and signed by another server key", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(challenge(client, { server: Keypair.random() }), [client]),
      "INVALID_CHALLENGE"
    );
  });

  it("rejects a non-zero sequence number", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(handBuilt(client, { sequence: "41" }), [client]),
      "INVALID_CHALLENGE"
    );
  });

  it("rejects a transaction sourced from an account other than the server's", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(handBuilt(client, { source: Keypair.random().publicKey() }), [client]),
      "INVALID_CHALLENGE"
    );
  });
});

describe("POST /auth/verify — signatures", () => {
  it("rejects a challenge missing the server signature", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(stripSignatures(challenge(client)), [client]),
      "INVALID_CHALLENGE"
    );
  });

  it("rejects a challenge missing the client signature with INVALID_SIGNATURE", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(challenge(client), "INVALID_SIGNATURE");
  });

  it("rejects a challenge signed by the wrong client key with INVALID_SIGNATURE", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(challenge(client), [Keypair.random()]),
      "INVALID_SIGNATURE"
    );
  });

  it("rejects an extra, unrecognized signature with INVALID_SIGNATURE", async () => {
    const client = Keypair.random();
    await expectChallengeRejected(
      sign(challenge(client), [client, Keypair.random()]),
      "INVALID_SIGNATURE"
    );
  });

  it("rejects a funded account whose signers fall below the medium threshold", async () => {
    const client = Keypair.random();
    h.loadAccount.mockResolvedValue({
      ...UNFUNDED,
      exists: true,
      signers: [
        { key: client.publicKey(), weight: 1 },
        { key: Keypair.random().publicKey(), weight: 1 },
      ],
      thresholds: { low: 1, med: 2, high: 2 },
    });
    await expectChallengeRejected(sign(challenge(client), [client]), "INVALID_SIGNATURE");
  });

  it("rejects an envelope tampered with after signing", async () => {
    const client = Keypair.random();
    const envelope = xdr.TransactionEnvelope.fromXDR(
      sign(challenge(client), [client]),
      "base64"
    );
    envelope.v1().tx().operations()[0].body().manageDataOp().dataValue(Buffer.alloc(48, 65));
    await expectChallengeRejected(envelope.toXDR("base64"), "INVALID_CHALLENGE");
  });

  it("rejects a replayed challenge", async () => {
    const client = Keypair.random();
    const signed = sign(challenge(client), [client]);
    expect((await verify(signed)).statusCode).toBe(200);
    h.prisma.user.upsert.mockClear();
    await expectChallengeRejected(signed, "INVALID_CHALLENGE");
  });
});

describe("POST /auth/verify — malformed input", () => {
  it("rejects base64 that is not a transaction envelope", async () => {
    await expectChallengeRejected(Buffer.alloc(64, 1).toString("base64"), "INVALID_CHALLENGE");
  });

  it("rejects a fee-bump envelope", async () => {
    const client = Keypair.random();
    const inner = new Transaction(sign(challenge(client), [client]), config.networkPassphrase);
    const feeBump = TransactionBuilder.buildFeeBumpTransaction(
      serverKeypair(),
      "200",
      inner,
      config.networkPassphrase
    );
    feeBump.sign(serverKeypair());
    await expectChallengeRejected(feeBump.toXDR(), "INVALID_CHALLENGE");
  });

  it.each([
    ["non-base64 text", "this is not xdr!"],
    ["a non-string value", 12345],
    ["an empty string", ""],
  ])("rejects %s as a 400 VALIDATION_ERROR before any verification", async (_label, value) => {
    const res = await verify(value);
    expect(res.statusCode).toBe(400);
    expectSafeErrorBody(res, "VALIDATION_ERROR");
  });

  it("rejects a missing transaction field as a 400 VALIDATION_ERROR", async () => {
    const res = await app.inject({ method: "POST", url: VERIFY, payload: {} });
    expect(res.statusCode).toBe(400);
    expectSafeErrorBody(res, "VALIDATION_ERROR");
  });
});

describe("POST /auth/verify — dependency failures", () => {
  it("answers an unreachable Horizon with 502 UPSTREAM_ERROR, not a credential rejection", async () => {
    const client = Keypair.random();
    h.loadAccount.mockRejectedValue(new Error("connect ECONNREFUSED 10.0.0.1:443"));

    const res = await verify(sign(challenge(client), [client]));
    expect(res.statusCode).toBe(502);
    expectSafeErrorBody(res, "UPSTREAM_ERROR");
    expect(res.body).not.toContain("ECONNREFUSED");
    expect(h.prisma.user.upsert).not.toHaveBeenCalled();
  });
});

// -- bearer-token middleware --------------------------------------------------

/** Mutable so the happy-path test can align the stored user with its client. */
const USER = { id: "user_925", stellarPublicKey: Keypair.random().publicKey() };

function protectedRoute(authorization?: string) {
  return app.inject({
    method: "GET",
    url: PROTECTED,
    headers: authorization === undefined ? {} : { authorization },
  });
}

/** Sign arbitrary claims/options with the real secret. */
function tokenWith(
  options: jwt.SignOptions,
  claims: Record<string, unknown> = { sub: USER.id, pk: USER.stellarPublicKey }
): string {
  return jwt.sign(claims, config.JWT_SECRET, {
    algorithm: "HS256",
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
    expiresIn: 3600,
    ...options,
  });
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

async function expectBearerRejected(
  authorization: string | undefined,
  code: string,
  bearerError: "invalid_request" | "invalid_token" | null
) {
  const res = await protectedRoute(authorization);
  expect(res.statusCode).toBe(401);
  const body = expectSafeErrorBody(res, code);

  const challengeHeader = res.headers["www-authenticate"];
  expect(challengeHeader).toEqual(expect.stringMatching(/^Bearer realm="mergepay-api"/));
  if (bearerError === null) {
    expect(challengeHeader).toBe('Bearer realm="mergepay-api"');
  } else {
    expect(challengeHeader).toContain(`error="${bearerError}"`);
    expect(challengeHeader).toContain(`error_description="${body.error.message}"`);
  }
  expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  return body;
}

describe("bearer middleware — the Authorization header", () => {
  it("lets a valid token through", async () => {
    const res = await protectedRoute(`Bearer ${signToken(USER)}`);
    expect(res.statusCode).toBe(200);
    expect(res.headers["www-authenticate"]).toBeUndefined();
  });

  it("rejects a missing header with MISSING_TOKEN and an error-free challenge (RFC 6750 §3.1)", async () => {
    await expectBearerRejected(undefined, "MISSING_TOKEN", null);
  });

  it.each([
    ["the wrong scheme", () => `Basic ${Buffer.from("a:b").toString("base64")}`],
    ["a lowercase scheme", () => `bearer ${signToken(USER)}`],
    ["the scheme with no token", () => "Bearer"],
    ["the scheme and a blank token", () => "Bearer    "],
    ["extra parts", () => `Bearer ${signToken(USER)} extra`],
    ["a doubled space", () => `Bearer  ${signToken(USER)}`],
  ])("rejects %s with MALFORMED_TOKEN / invalid_request", async (_label, header) => {
    await expectBearerRejected(header(), "MALFORMED_TOKEN", "invalid_request");
  });

  it.each([
    ["fewer than three segments", "abc.def"],
    ["more than three segments", "a.b.c.d"],
    ["segments that are not base64url JSON", "aaaa.bbbb.cccc"],
    ["a payload that is not JSON", `${b64url({ alg: "HS256", typ: "JWT" })}.bm90LWpzb24.c2ln`],
  ])("rejects a token with %s as MALFORMED_TOKEN", async (_label, token) => {
    await expectBearerRejected(`Bearer ${token}`, "MALFORMED_TOKEN", "invalid_request");
  });
});

describe("bearer middleware — token verification", () => {
  it("rejects a bad signature with INVALID_TOKEN", async () => {
    const forged = jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, "a-different-secret-key", {
      algorithm: "HS256",
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
      expiresIn: 3600,
    });
    await expectBearerRejected(`Bearer ${forged}`, "INVALID_TOKEN", "invalid_token");
  });

  it("rejects a token whose payload was altered after signing", async () => {
    const [header, , signature] = signToken(USER).split(".");
    const payload = b64url({
      sub: "someone_else",
      pk: USER.stellarPublicKey,
      iss: config.JWT_ISSUER,
      aud: config.JWT_AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    await expectBearerRejected(
      `Bearer ${header}.${payload}.${signature}`,
      "INVALID_TOKEN",
      "invalid_token"
    );
  });

  it("rejects an unsecured alg:none token with INVALID_TOKEN", async () => {
    const token = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({
      sub: USER.id,
      pk: USER.stellarPublicKey,
      iss: config.JWT_ISSUER,
      aud: config.JWT_AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.`;
    await expectBearerRejected(`Bearer ${token}`, "INVALID_TOKEN", "invalid_token");
  });

  it("rejects a token signed with an algorithm other than the pinned HS256", async () => {
    await expectBearerRejected(
      `Bearer ${tokenWith({ algorithm: "HS512" })}`,
      "INVALID_TOKEN",
      "invalid_token"
    );
  });

  it("rejects the wrong issuer", async () => {
    await expectBearerRejected(
      `Bearer ${tokenWith({ issuer: "someone-else" })}`,
      "INVALID_TOKEN",
      "invalid_token"
    );
  });

  it("rejects the wrong audience", async () => {
    await expectBearerRejected(
      `Bearer ${tokenWith({ audience: "someone-else" })}`,
      "INVALID_TOKEN",
      "invalid_token"
    );
  });

  it("rejects an expired token with TOKEN_EXPIRED and a re-authentication hint", async () => {
    const token = signToken(USER);
    vi.setSystemTime(new Date(T0.getTime() + 24 * 60 * 60 * 1000));
    const body = await expectBearerRejected(`Bearer ${token}`, "TOKEN_EXPIRED", "invalid_token");
    expect(body.error.message).toBe("Authentication token has expired");
    expect(body.error.details).toMatchObject({ code: "REAUTHENTICATE" });
  });

  it("rejects a not-yet-valid token beyond the clock tolerance", async () => {
    await expectBearerRejected(
      `Bearer ${tokenWith({ notBefore: 60 })}`,
      "INVALID_TOKEN",
      "invalid_token"
    );
  });

  it("tolerates a few seconds of clock skew on nbf", async () => {
    const res = await protectedRoute(`Bearer ${tokenWith({ notBefore: 3 })}`);
    expect(res.statusCode).toBe(200);
  });

  it("rejects a token issued in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = jwt.sign(
      { sub: USER.id, pk: USER.stellarPublicKey, iat: now + 600, exp: now + 3600 },
      config.JWT_SECRET,
      { algorithm: "HS256", issuer: config.JWT_ISSUER, audience: config.JWT_AUDIENCE }
    );
    await expectBearerRejected(`Bearer ${token}`, "INVALID_TOKEN", "invalid_token");
  });

  it("rejects a token without an expiry", async () => {
    const token = jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, config.JWT_SECRET, {
      algorithm: "HS256",
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });
    await expectBearerRejected(`Bearer ${token}`, "INVALID_TOKEN", "invalid_token");
  });

  it.each([
    ["no sub", { pk: USER.stellarPublicKey }],
    ["an empty sub", { sub: "", pk: USER.stellarPublicKey }],
    ["a non-string sub", { sub: 42, pk: USER.stellarPublicKey }],
    ["an overlong sub", { sub: "u".repeat(129), pk: USER.stellarPublicKey }],
    ["no pk", { sub: USER.id }],
    ["an empty pk", { sub: USER.id, pk: "" }],
  ])("rejects a token with %s as INVALID_TOKEN", async (_label, claims) => {
    await expectBearerRejected(`Bearer ${tokenWith({}, claims)}`, "INVALID_TOKEN", "invalid_token");
  });
});

describe("BearerAuthError — the WWW-Authenticate value", () => {
  it("never lets a message break out of the quoted error_description", () => {
    const err = new BearerAuthError("INVALID_TOKEN", 'bad "token" \\ here', "invalid_token");
    expect(err.wwwAuthenticate).toBe(
      'Bearer realm="mergepay-api", error="invalid_token", error_description="bad token  here"'
    );
  });
});
