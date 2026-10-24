/**
 * SEP-24 session-completion and session-status validation (#643).
 *
 * The deposit/withdrawal *initiation* contract lives in
 * `src/validations/sep24.ts` and is covered by the existing SEP-24 suites. The
 * two remaining SEP-24 inputs — the path/query of an anchor-session status read
 * and the signed challenge posted to complete an interactive session — were
 * still parsed with ad-hoc inline rules. These tests pin the centralized
 * schemas and prove that the routes reject malformed input before reading a
 * session, calling the anchor, or writing an audit row.
 */
import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  Account,
  BASE_FEE,
  Keypair,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";

const h = vi.hoisted(() => {
  const model = () => ({
    create: vi.fn(),
    findUnique: vi.fn(async () => null),
    findFirst: vi.fn(),
    findMany: vi.fn(async () => []),
    update: vi.fn(),
    updateMany: vi.fn(async () => ({ count: 1 })),
    delete: vi.fn(),
    deleteMany: vi.fn(),
    count: vi.fn(async () => 0),
    upsert: vi.fn(),
  });
  const prisma: any = {
    anchorSession: model(),
    withdrawal: model(),
    auditLog: model(),
    statusHistory: model(),
    $transaction: vi.fn(async (arg: any) =>
      typeof arg === "function" ? arg(prisma) : Promise.all(arg)
    ),
    $disconnect: vi.fn(),
  };
  return { prisma };
});

vi.mock("../src/db", () => ({ prisma: h.prisma }));
vi.mock("../src/services/anchor", () => ({
  anchorService: {
    getToml: vi.fn(),
    getChallenge: vi.fn(),
    getToken: vi.fn(),
    startInteractive: vi.fn(),
  },
  mapAnchorStatus: vi.fn((status: string) => status),
}));

import { buildApp } from "../src/app";
import { config } from "../src/config";
import { signToken } from "../src/plugins/auth";
import { anchorService } from "../src/services/anchor";
import {
  sep24CompleteRequestSchema,
  sep24SessionParamsSchema,
  sep24SessionQuerySchema,
} from "../src/validations/sep24";

const prisma = h.prisma;
let app: Awaited<ReturnType<typeof buildApp>>;
let userSeq = 0;

const authHeader = () => ({
  authorization: `Bearer ${signToken({
    id: `user_${(userSeq += 1)}`,
    stellarPublicKey: Keypair.random().publicKey(),
  })}`,
  "content-type": "application/json",
});

/** A canonical signed envelope, as the completion route requires. */
function signedXdr(): string {
  const signer = Keypair.random();
  const transaction = new TransactionBuilder(new Account(signer.publicKey(), "0"), {
    fee: BASE_FEE,
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(Operation.manageData({ name: "sep24-test", value: "signed" }))
    .setTimeout(60)
    .build();
  transaction.sign(signer);
  return transaction.toXDR();
}

const fakeSession = (over: Record<string, unknown> = {}) => ({
  id: "session_1",
  userId: "user_1",
  anchorName: config.ANCHOR_NAME,
  kind: "deposit",
  assetCode: "XLM",
  interactiveUrl: null,
  externalTransactionId: null,
  anchorToken: null,
  status: "incomplete",
  failureReason: null,
  retryCount: 0,
  lastPolledAt: null,
  createdAt: new Date("2026-01-01T00:00:00.000Z"),
  updatedAt: new Date("2026-01-01T00:00:00.000Z"),
  ...over,
});

beforeEach(async () => {
  vi.clearAllMocks();
  // Rejections are the subject here; turn the limiter off so one suite cannot
  // spend another suite's budget (CONTRIBUTING's guidance for contract tests).
  if (!app) app = await buildApp({ rateLimit: "off" });
});

function expectValidation400(res: { statusCode: number; json: () => any }) {
  const body = res.json();
  expect(res.statusCode).toBe(400);
  expect(body.error.code).toBe("VALIDATION_ERROR");
  expect(body.error.details.length).toBeGreaterThan(0);
  return body;
}

describe("sep24CompleteRequestSchema", () => {
  it("accepts a canonical signed Stellar envelope", () => {
    const result = sep24CompleteRequestSchema.safeParse({
      signedXdr: signedXdr(),
    });
    expect(result.success).toBe(true);
  });

  it("rejects a missing, empty, placeholder, or non-XDR payload", () => {
    const invalid = [
      {},
      { signedXdr: "" },
      { signedXdr: "AAAA..." },
      { signedXdr: "not-xdr!!" },
      { signedXdr: Buffer.from("mergepay").toString("base64") },
      { signedXdr: 12345 },
    ];
    for (const payload of invalid) {
      expect(
        sep24CompleteRequestSchema.safeParse(payload).success,
        JSON.stringify(payload)
      ).toBe(false);
    }
  });

  it("rejects an unknown field rather than silently dropping it", () => {
    const result = sep24CompleteRequestSchema.safeParse({
      signedXdr: signedXdr(),
      extra: "unexpected",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0].code).toBe("unrecognized_keys");
    }
  });
});

describe("sep24SessionParamsSchema / sep24SessionQuerySchema", () => {
  it("accepts a normal session id", () => {
    expect(sep24SessionParamsSchema.parse({ id: "session_1" })).toEqual({
      id: "session_1",
    });
    // Opaque anchor ids may contain `:` and `.`.
    expect(sep24SessionParamsSchema.parse({ id: "acct:nonce.1" }).id).toBe(
      "acct:nonce.1"
    );
  });

  it("rejects empty, overlong, or path-like session ids", () => {
    for (const id of ["", "a".repeat(121), "../other", "has space", "a/b"]) {
      expect(sep24SessionParamsSchema.safeParse({ id }).success, id).toBe(false);
    }
  });

  it("accepts no query parameters or a bounded lang", () => {
    expect(sep24SessionQuerySchema.parse({})).toEqual({});
    expect(sep24SessionQuerySchema.parse({ lang: "en" })).toEqual({ lang: "en" });
    expect(sep24SessionQuerySchema.parse({ lang: "pt-BR" })).toEqual({
      lang: "pt-BR",
    });
  });

  it("rejects unknown query keys and malformed lang values", () => {
    for (const query of [
      { foo: "bar" },
      { asset_code: "XLM" },
      { lang: "e" },
      { lang: "x".repeat(11) },
      { lang: ["en"] },
    ]) {
      expect(sep24SessionQuerySchema.safeParse(query).success).toBe(false);
    }
  });
});

describe("POST /anchors/sessions/:id/complete — validation before anchor I/O", () => {
  const url = "/anchors/sessions/session_1/complete";

  it.each([
    ["a missing body", {}],
    ["an empty signed XDR", { signedXdr: "" }],
    ["the old placeholder", { signedXdr: "AAAA..." }],
    ["non-base64 text", { signedXdr: "not-xdr!!" }],
    [
      "canonical base64 that is not a Stellar transaction",
      { signedXdr: Buffer.from("mergepay").toString("base64") },
    ],
    ["an unknown body field", { signedXdr: signedXdr(), extra: true }],
  ])("rejects %s without reading a session or calling the anchor", async (label, payload) => {
    const res = await app.inject({
      method: "POST",
      url,
      headers: authHeader(),
      payload,
    });

    const body = expectValidation400(res);
    expect(body.error.details.some((d: any) => d.field === "signedXdr" || d.field === "extra")).toBe(
      true
    );
    expect(prisma.anchorSession.findUnique).not.toHaveBeenCalled();
    expect(anchorService.getToken).not.toHaveBeenCalled();
    expect(anchorService.startInteractive).not.toHaveBeenCalled();
  });

  it("rejects an unknown query parameter before reading a session", async () => {
    const res = await app.inject({
      method: "POST",
      url: `${url}?foo=bar`,
      headers: authHeader(),
      payload: { signedXdr: signedXdr() },
    });

    expectValidation400(res);
    expect(prisma.anchorSession.findUnique).not.toHaveBeenCalled();
  });

  it("rejects a malformed session id before reading a session", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/anchors/sessions/bad%20id/complete",
      headers: authHeader(),
      payload: { signedXdr: signedXdr() },
    });

    expectValidation400(res);
    expect(prisma.anchorSession.findUnique).not.toHaveBeenCalled();
  });
});

describe("GET /anchors/sessions/:id — validation before the session read", () => {
  it("rejects an unknown query parameter", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/anchors/sessions/session_1?foo=bar",
      headers: authHeader(),
    });

    expectValidation400(res);
    expect(prisma.anchorSession.findUnique).not.toHaveBeenCalled();
  });

  it("rejects a malformed session id", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/anchors/sessions/bad%20id",
      headers: authHeader(),
    });

    expectValidation400(res);
    expect(prisma.anchorSession.findUnique).not.toHaveBeenCalled();
  });

  it("still accepts a bounded lang and returns the caller's session", async () => {
    prisma.anchorSession.findUnique.mockResolvedValueOnce(
      fakeSession({ userId: "user_current" })
    );
    // The route signs a token with a fresh user id, so mirror that id on the
    // row the mock returns.
    const token = signToken({
      id: "user_current",
      stellarPublicKey: Keypair.random().publicKey(),
    });

    const res = await app.inject({
      method: "GET",
      url: "/anchors/sessions/session_1?lang=en",
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().session.id).toBe("session_1");
    expect(prisma.anchorSession.findUnique).toHaveBeenCalledWith({
      where: { id: "session_1" },
    });
  });
});
