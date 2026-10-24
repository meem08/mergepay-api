/**
 * Route-level proof that settlement payload validation is wired into the
 * execution pipeline (#644).
 *
 * The schema unit tests live in tests/validations/settlement.test.ts. This file
 * covers the other half of the acceptance criteria: a request that fails
 * validation never reaches the database lookups, the Horizon account load, or
 * the XDR builder, and an intent with a malformed stored public key is refused
 * before any unsigned transaction is produced.
 *
 * Only Prisma and the Horizon-facing service are stubbed — the routes, the
 * guards, the shared schemas, the error envelope, and serialization are real.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import { Prisma } from "@prisma/client";

const h = vi.hoisted(() => {
  const model = () => ({
    create: vi.fn(),
    createMany: vi.fn(),
    findUnique: vi.fn(),
    findUniqueOrThrow: vi.fn(),
    findFirst: vi.fn(),
    findMany: vi.fn(async () => []),
    update: vi.fn(),
    updateMany: vi.fn(),
    upsert: vi.fn(),
    delete: vi.fn(),
    deleteMany: vi.fn(),
    count: vi.fn(async () => 0),
  });
  const prisma: any = {
    user: model(),
    group: model(),
    groupMember: model(),
    expense: model(),
    expenseShare: model(),
    settlement: model(),
    statusHistory: model(),
    treasuryTransaction: model(),
    treasuryProposal: model(),
    invite: model(),
    invitation: model(),
    auditLog: model(),
    idempotencyKey: model(),
    webhook: model(),
    webhookDelivery: model(),
    $transaction: vi.fn(async (arg: any) =>
      typeof arg === "function" ? arg(prisma) : Promise.all(arg)
    ),
    $queryRaw: vi.fn(async () => []),
    $executeRaw: vi.fn(async () => 0),
    $disconnect: vi.fn(),
  };
  const loadAccount = vi.fn();
  const buildPayment = vi.fn();
  return { prisma, loadAccount, buildPayment };
});

vi.mock("../src/db", () => ({ prisma: h.prisma }));
vi.mock("../src/services/stellar", async (importActual) => {
  const actual = await importActual<typeof import("../src/services/stellar")>();
  return {
    ...actual,
    stellar: {
      ...actual.stellar,
      loadAccount: h.loadAccount,
      buildPayment: h.buildPayment,
    },
  };
});

import { buildApp } from "../src/app";
import { signToken } from "../src/plugins/auth";

const GROUP_ID = "group_1";
const USER_ID = "user_1";
const RECIPIENT_ID = "user_2";
const PAYER_ID = "payer_1";

const USER_KEY = Keypair.random().publicKey();
const RECIPIENT_KEY = Keypair.random().publicKey();
const PAYER_KEY = Keypair.random().publicKey();
const USDC_ISSUER = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

function userRow(id: string, stellarPublicKey: string) {
  return {
    id,
    stellarPublicKey,
    displayName: id,
    avatarUrl: null,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };
}

function authHeader() {
  return {
    authorization: `Bearer ${signToken({ id: USER_ID, stellarPublicKey: USER_KEY })}`,
  };
}

function settlementRow(data: Record<string, any>) {
  return {
    id: "settle_new",
    shortCode: "ABC2345XYZ",
    groupId: GROUP_ID,
    fromUserId: USER_ID,
    toUserId: RECIPIENT_ID,
    amount: "10",
    assetCode: "XLM",
    assetIssuer: null,
    status: "pending",
    memo: "MP:ABC2345XYZ",
    retryCount: 0,
    createdAt: new Date(),
    ...data,
  };
}

function fundedAccount() {
  return {
    exists: true,
    sequence: "1",
    // Funded above the payment, the envelope fee, and the base reserve so the
    // preflight in src/services/settlement-preflight.ts passes.
    balances: [{ assetCode: "XLM", assetIssuer: null, balance: "1000.0000000" }],
    signers: [{ key: USER_KEY, weight: 1 }],
    thresholds: { low: 0, med: 0, high: 0 },
  };
}

let app: Awaited<ReturnType<typeof buildApp>>;

beforeEach(async () => {
  vi.clearAllMocks();
  if (!app) app = await buildApp({ rateLimit: "off" });

  h.prisma.$transaction.mockImplementation(async (arg: any) =>
    typeof arg === "function" ? arg(h.prisma) : Promise.all(arg)
  );

  h.prisma.groupMember.findUnique.mockImplementation(async (args: any) => {
    const key = args?.where?.groupId_userId;
    if (!key) return null;
    if (key.userId === USER_ID) {
      return { groupId: key.groupId, userId: USER_ID, role: "member" };
    }
    if (key.userId === RECIPIENT_ID) {
      const user = userRow(RECIPIENT_ID, RECIPIENT_KEY);
      return args?.include?.user
        ? { groupId: key.groupId, userId: RECIPIENT_ID, role: "member", user }
        : user;
    }
    if (key.userId === PAYER_ID) {
      return { groupId: key.groupId, userId: PAYER_ID, role: "member" };
    }
    return null;
  });
  h.prisma.group.findUnique.mockResolvedValue({ id: GROUP_ID, archived: false });
  h.prisma.groupMember.findMany.mockResolvedValue([]);

  // Outstanding debt from the caller to the recipient, so the freeform
  // settle-up limit check (verifySettlementLimit) passes for the valid case.
  h.prisma.expense.findMany.mockResolvedValue([
    {
      payerUserId: RECIPIENT_ID,
      shares: [
        {
          userId: USER_ID,
          shareAmount: new Prisma.Decimal("100"),
          status: "pending",
        },
      ],
    },
  ]);
  h.prisma.settlement.findMany.mockResolvedValue([]);

  h.prisma.expenseShare.findUnique.mockResolvedValue({ id: "share_1", status: "pending" });
  h.prisma.expenseShare.update.mockResolvedValue({});

  h.prisma.settlement.findFirst.mockResolvedValue(null);
  h.prisma.settlement.create.mockImplementation(async (args: any) =>
    settlementRow(args?.data ?? {})
  );
  h.prisma.statusHistory.create.mockResolvedValue({});
  h.prisma.auditLog.create.mockResolvedValue({ id: "audit_1" });
  h.prisma.idempotencyKey.findUnique.mockResolvedValue(null);
  h.prisma.idempotencyKey.findFirst.mockResolvedValue(null);
  h.prisma.idempotencyKey.create.mockResolvedValue({});

  h.loadAccount.mockResolvedValue(fundedAccount());
  h.buildPayment.mockReturnValue("unsigned-xdr");
});

function settleUp(body: unknown) {
  return app.inject({
    method: "POST",
    url: `/groups/${GROUP_ID}/settlements`,
    headers: authHeader(),
    payload: body as any,
  });
}

function expectNoStellarWork() {
  expect(h.loadAccount).not.toHaveBeenCalled();
  expect(h.buildPayment).not.toHaveBeenCalled();
}

describe("POST /groups/:id/settlements — payload validation", () => {
  const valid = {
    toUserId: RECIPIENT_ID,
    amount: "10",
    assetCode: "XLM",
  };

  it("settles a valid payload and builds the payment from the validated intent", async () => {
    const res = await settleUp(valid);

    expect(res.statusCode).toBe(200);
    expect(res.json().xdr).toBe("unsigned-xdr");
    expect(h.loadAccount).toHaveBeenCalledWith(USER_KEY);
    expect(h.buildPayment).toHaveBeenCalledWith(
      expect.objectContaining({
        sourcePublicKey: USER_KEY,
        destination: RECIPIENT_KEY,
        asset: { code: "XLM", issuer: null },
        amount: "10",
      })
    );
  });

  it.each([
    ["a missing recipient", { amount: "10", assetCode: "XLM" }],
    ["a malformed recipient id", { toUserId: "user 2", amount: "10", assetCode: "XLM" }],
    ["an oversized recipient id", { toUserId: "u".repeat(65), amount: "10", assetCode: "XLM" }],
    ["a zero amount", { toUserId: RECIPIENT_ID, amount: "0", assetCode: "XLM" }],
    ["a negative amount", { toUserId: RECIPIENT_ID, amount: "-5", assetCode: "XLM" }],
    ["excess precision", { toUserId: RECIPIENT_ID, amount: "1.12345678", assetCode: "XLM" }],
    ["exponent notation", { toUserId: RECIPIENT_ID, amount: "1e3", assetCode: "XLM" }],
    ["an unsupported asset", { toUserId: RECIPIENT_ID, amount: "10", assetCode: "DOGE" }],
    [
      "an issuer on the native asset",
      { toUserId: RECIPIENT_ID, amount: "10", assetCode: "XLM", assetIssuer: USDC_ISSUER },
    ],
    [
      "a mismatched USDC issuer",
      { toUserId: RECIPIENT_ID, amount: "10", assetCode: "USDC", assetIssuer: RECIPIENT_KEY },
    ],
    [
      "an out-of-range signing window",
      { toUserId: RECIPIENT_ID, amount: "10", assetCode: "XLM", validitySeconds: 5 },
    ],
    [
      "an unknown key (client-supplied deadline)",
      {
        toUserId: RECIPIENT_ID,
        amount: "10",
        assetCode: "XLM",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    ],
  ])("rejects %s before any Stellar work", async (_label, body) => {
    const res = await settleUp(body);

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expectNoStellarWork();
    expect(h.prisma.settlement.create).not.toHaveBeenCalled();
  });

  it("refuses to build an envelope for a recipient whose stored key is malformed", async () => {
    h.prisma.groupMember.findUnique.mockImplementation(async (args: any) => {
      const key = args?.where?.groupId_userId;
      if (!key) return null;
      if (key.userId === RECIPIENT_ID) {
        return {
          groupId: key.groupId,
          userId: RECIPIENT_ID,
          role: "member",
          user: userRow(RECIPIENT_ID, "GNOTAVALIDSTELLARKEY"),
        };
      }
      return { groupId: key.groupId, userId: key.userId, role: "member" };
    });

    const res = await settleUp(valid);

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expect(res.json().error.message).toMatch(/Invalid Stellar account ID/);
    // Validation happens before the Horizon account load and envelope build.
    expectNoStellarWork();
  });
});

describe("POST /expenses/:id/settle — participant share validation", () => {
  function expenseRow(over: Record<string, any> = {}) {
    return {
      id: "expense_1",
      groupId: GROUP_ID,
      payerUserId: PAYER_ID,
      assetCode: "XLM",
      assetIssuer: null,
      payer: userRow(PAYER_ID, PAYER_KEY),
      shares: [
        {
          id: "share_1",
          expenseId: "expense_1",
          userId: USER_ID,
          shareAmount: new Prisma.Decimal("10"),
          status: "pending",
        },
      ],
      ...over,
    };
  }

  function settleExpense() {
    return app.inject({
      method: "POST",
      url: "/expenses/expense_1/settle",
      headers: authHeader(),
      payload: {},
    });
  }

  it("settles a valid share and builds the payment from the validated share", async () => {
    h.prisma.expense.findUnique.mockResolvedValue(expenseRow());

    const res = await settleExpense();

    expect(res.statusCode).toBe(200);
    expect(h.buildPayment).toHaveBeenCalledWith(
      expect.objectContaining({
        destination: PAYER_KEY,
        amount: "10",
      })
    );
  });

  it("rejects a stored share amount that cannot be represented on-chain", async () => {
    h.prisma.expense.findUnique.mockResolvedValue(
      expenseRow({
        shares: [
          {
            id: "share_1",
            expenseId: "expense_1",
            userId: USER_ID,
            // 8 decimal places — not representable as stroops.
            shareAmount: new Prisma.Decimal("1.12345678"),
            status: "pending",
          },
        ],
      })
    );

    const res = await settleExpense();

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expectNoStellarWork();
  });

  it("refuses to build an envelope for a payer whose stored key is malformed", async () => {
    h.prisma.expense.findUnique.mockResolvedValue(
      expenseRow({ payer: userRow(PAYER_ID, "GPAYERNOTAKEY") })
    );

    const res = await settleExpense();

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expectNoStellarWork();
  });
});

describe("POST /settlements/:id/confirm and /settlements/execute — body validation", () => {
  it("rejects an envelope with internal whitespace before loading the settlement", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/settlements/settle_1/confirm",
      headers: { ...authHeader(), "idempotency-key": "confirm-key" },
      payload: { signedXdr: "AAAA\nBBBB" },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expect(h.prisma.settlement.findUnique).not.toHaveBeenCalled();
  });

  it("rejects an oversized envelope before loading the settlement", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/settlements/settle_1/confirm",
      headers: { ...authHeader(), "idempotency-key": "confirm-key" },
      payload: { signedXdr: "A".repeat(100_001) },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expect(h.prisma.settlement.findUnique).not.toHaveBeenCalled();
  });

  it("rejects a malformed settlement id on execute before any lookup", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/settlements/execute",
      headers: { ...authHeader(), "x-idempotency-key": "execute-key" },
      payload: { settlementId: "not a valid id", signedXdr: "AAAA-signed-envelope" },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expect(h.prisma.settlement.findUnique).not.toHaveBeenCalled();
  });
});
