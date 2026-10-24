/**
 * Group expense currency conversion and breakdown calculation.
 *
 * The service under test (`src/services/expense-calculation.ts`) is the pure
 * arithmetic layer that turns stored group expenses into per-participant shares
 * and balances, including the case where a group's expenses span more than one
 * Stellar asset.
 *
 * The tests pin the properties that make the output safe to hand to settlement
 * transaction construction:
 *   - splits distribute the total to the stroop, including tail remainders;
 *   - conversion uses integer math only, so no float drift can appear;
 *   - every asset's paid/owed totals stay in balance;
 *   - normalizing into a target asset preserves each asset total exactly;
 *   - corrupt or ambiguous input is rejected rather than silently netted.
 */
import { describe, expect, it } from "vitest";

import {
  EXPENSE_CALCULATION_ERROR_CODES,
  calculateGroupExpenseBreakdown,
  convertAmount,
  convertStroops,
  isExpenseCalculationError,
  splitExpense,
  type ConversionRounding,
  type ExpenseCalculationErrorCode,
  type ExpenseRecord,
  type ExpenseSplitMode,
  type ParticipantAmounts,
} from "../src/services/expense-calculation";
import { computeNetBalancesByAsset } from "../src/services/settlement";
import { MAX_STROOPS, toStroops } from "../src/services/money";

const USDC_ISSUER =
  "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

const XLM = { assetCode: "XLM", assetIssuer: null } as const;
const USDC = { assetCode: "USDC", assetIssuer: USDC_ISSUER } as const;

function expectCode(fn: () => unknown, code: ExpenseCalculationErrorCode): void {
  try {
    fn();
  } catch (error) {
    expect(isExpenseCalculationError(error)).toBe(true);
    expect((error as { code: string }).code).toBe(code);
    return;
  }
  throw new Error(`Expected an ExpenseCalculationError with code ${code}`);
}

function shareTotal(shares: { amount: string }[]): bigint {
  return shares.reduce((sum, share) => sum + toStroops(share.amount), 0n);
}

function byUser(participants: ParticipantAmounts[]) {
  return Object.fromEntries(participants.map((p) => [p.userId, p]));
}

function netSum(participants: ParticipantAmounts[]): bigint {
  return participants.reduce((sum, p) => sum + toStroops(p.net), 0n);
}

function amountSum(participants: ParticipantAmounts[], field: "paid" | "owed") {
  return participants.reduce((sum, p) => sum + toStroops(p[field]), 0n);
}

/** A Prisma.Decimal-shaped value, to prove stored rows pass through unchanged. */
const decimal = (value: string) => ({ toString: () => value });

const dinner: ExpenseRecord = {
  id: "exp_xlm_dinner",
  payerUserId: "alice",
  amount: "30",
  ...XLM,
  shares: [
    { userId: "alice", shareAmount: "10", settled: true },
    { userId: "bob", shareAmount: "10" },
    { userId: "carol", shareAmount: "10" },
  ],
};

const cab: ExpenseRecord = {
  id: "exp_usdc_cab",
  payerUserId: "bob",
  amount: decimal("100"),
  ...USDC,
  shares: [
    { userId: "alice", shareAmount: "25" },
    { userId: "bob", shareAmount: "25", settled: true },
    { userId: "carol", shareAmount: "50" },
  ],
};

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

describe("convertAmount / convertStroops", () => {
  it("converts at unity and at a fractional rate without float artifacts", () => {
    expect(convertAmount("123.4567891", "1")).toBe("123.4567891");
    expect(convertAmount("10", "0.1")).toBe("1");
    expect(convertAmount("2.5", "0.1")).toBe("0.25");
    expect(convertAmount("1.2345678", "10")).toBe("12.345678");
  });

  it("is exact where binary floating point is not", () => {
    // 0.1 + 0.2 !== 0.3 in IEEE-754. Integer stroop conversion has no such gap.
    const a = convertAmount("0.1", "0.1");
    const b = convertAmount("0.2", "0.1");
    expect(a).toBe("0.01");
    expect(b).toBe("0.02");
    expect(toStroops(a) + toStroops(b)).toBe(toStroops(convertAmount("0.3", "0.1")));
  });

  it.each<[ConversionRounding, string]>([
    ["down", "0"],
    ["up", "0.0000001"],
    ["half-up", "0.0000001"],
  ])("rounds a half-stroop result with %s", (rounding, expected) => {
    // 5 stroops * 0.1 = 0.5 stroops.
    expect(convertAmount("0.0000005", "0.1", rounding)).toBe(expected);
  });

  it("supports signed stroop conversion for net balances", () => {
    expect(convertStroops(5n, "0.1")).toBe(1n);
    expect(convertStroops(-5n, "0.1")).toBe(-1n);
    expect(convertStroops(-5n, "0.1", "down")).toBe(0n);
  });

  it("converts zero without error", () => {
    expect(convertAmount("0", "10")).toBe("0");
    expect(convertStroops(0n, "10")).toBe(0n);
  });

  it("rejects malformed, non-positive, or over-precise rates", () => {
    for (const rate of ["0", "-1", "1e-1", "abc", ".1", "1.", "0.00000001"]) {
      expectCode(
        () => convertAmount("1", rate),
        EXPENSE_CALCULATION_ERROR_CODES.INVALID_RATE
      );
    }
  });

  it("rejects malformed, negative, and over-precise amounts", () => {
    for (const amount of ["", "-1", "abc", "1.00000001", "1e3", " 1 "]) {
      expectCode(
        () => convertAmount(amount, "1"),
        EXPENSE_CALCULATION_ERROR_CODES.INVALID_AMOUNT
      );
    }
  });

  it("rejects an unknown rounding mode at runtime", () => {
    expectCode(
      () => convertStroops(1n, "1", "sideways" as ConversionRounding),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_ROUNDING
    );
  });

  it("refuses a converted amount outside Stellar's Int64 range", () => {
    expectCode(
      () => convertStroops(MAX_STROOPS, "2"),
      EXPENSE_CALCULATION_ERROR_CODES.AMOUNT_OVERFLOW
    );
  });
});

// ---------------------------------------------------------------------------
// Splitting
// ---------------------------------------------------------------------------

describe("splitExpense — equal", () => {
  it("splits cleanly when the amount is a multiple", () => {
    const result = splitExpense("9", "equal", [
      { userId: "a" },
      { userId: "b" },
      { userId: "c" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["3", "3", "3"]);
    expect(result.remainderStroops).toBe("0");
  });

  it("assigns a single tail stroop by largest remainder (10 / 3)", () => {
    const result = splitExpense("10", "equal", [
      { userId: "a" },
      { userId: "b" },
      { userId: "c" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual([
      "3.3333334",
      "3.3333333",
      "3.3333333",
    ]);
    expect(result.remainderStroops).toBe("1");
    expect(shareTotal(result.shares)).toBe(toStroops("10"));
  });

  it("spreads a two-stroop tail over two participants (101 / 7)", () => {
    const ids = ["a", "b", "c", "d", "e", "f", "g"];
    const result = splitExpense(
      "101",
      "equal",
      ids.map((userId) => ({ userId }))
    );
    expect(result.shares.map((s) => s.amount)).toEqual([
      "14.4285715",
      "14.4285715",
      "14.4285714",
      "14.4285714",
      "14.4285714",
      "14.4285714",
      "14.4285714",
    ]);
    expect(result.remainderStroops).toBe("2");
    expect(shareTotal(result.shares)).toBe(toStroops("101"));
  });

  it("splits the smallest representable amount (1 stroop / 3)", () => {
    const result = splitExpense("0.0000001", "equal", [
      { userId: "a" },
      { userId: "b" },
      { userId: "c" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual([
      "0.0000001",
      "0",
      "0",
    ]);
    expect(result.remainderStroops).toBe("1");
    expect(shareTotal(result.shares)).toBe(1n);
  });

  it("gives a single participant the entire amount", () => {
    const result = splitExpense("42.5", "equal", [{ userId: "solo" }]);
    expect(result.shares).toEqual([{ userId: "solo", amount: "42.5" }]);
    expect(result.remainderStroops).toBe("0");
  });

  it("distributes every sample amount exactly across participant counts", () => {
    const amounts = ["1", "7", "10", "99", "100", "101", "0.0000001", "713.5"];
    for (const amount of amounts) {
      for (let count = 1; count <= 9; count++) {
        const participants = Array.from({ length: count }, (_, index) => ({
          userId: `u${index}`,
        }));
        const result = splitExpense(amount, "equal", participants);
        expect(result.shares).toHaveLength(count);
        expect(shareTotal(result.shares)).toBe(toStroops(amount));
      }
    }
  });

  it("rejects zero, negative, and unpresentable totals", () => {
    for (const amount of ["0", "-10"]) {
      expectCode(
        () => splitExpense(amount, "equal", [{ userId: "a" }]),
        EXPENSE_CALCULATION_ERROR_CODES.INVALID_AMOUNT
      );
    }
  });

  it("rejects an empty participant list", () => {
    expectCode(
      () => splitExpense("10", "equal", []),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_PARTICIPANTS
    );
  });

  it("rejects duplicate participants", () => {
    expectCode(
      () =>
        splitExpense("10", "equal", [
          { userId: "a" },
          { userId: "a" },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.DUPLICATE_PARTICIPANT
    );
  });

  it("rejects an unknown split mode", () => {
    expectCode(
      () =>
        splitExpense("10", "weighted" as ExpenseSplitMode, [
          { userId: "a" },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_SPLIT
    );
  });
});

describe("splitExpense — percentage", () => {
  it("assigns exact percentage shares (33.33 / 33.33 / 33.34)", () => {
    const result = splitExpense("100", "percentage", [
      { userId: "a", percent: "33.33" },
      { userId: "b", percent: "33.33" },
      { userId: "c", percent: "33.34" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual([
      "33.33",
      "33.33",
      "33.34",
    ]);
    expect(result.remainderStroops).toBe("0");
    expect(shareTotal(result.shares)).toBe(toStroops("100"));
  });

  it("allocates a two-stroop tail by largest fractional remainder", () => {
    // 2 stroops at 33.3333 / 33.3333 / 33.3334: the last share has the
    // largest remainder and gets the first stroop; the tie goes to the earliest
    // participant, matching the documented deterministic tie-break.
    const result = splitExpense("0.0000002", "percentage", [
      { userId: "a", percent: "33.3333" },
      { userId: "b", percent: "33.3333" },
      { userId: "c", percent: "33.3334" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual([
      "0.0000001",
      "0",
      "0.0000001",
    ]);
    expect(result.remainderStroops).toBe("2");
    expect(shareTotal(result.shares)).toBe(2n);
  });

  it("drops a single leftover stroop onto the first share (50/50 of 1 stroop)", () => {
    const result = splitExpense("0.0000001", "percentage", [
      { userId: "a", percent: "50" },
      { userId: "b", percent: "50" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["0.0000001", "0"]);
    expect(result.remainderStroops).toBe("1");
  });

  it("accepts numeric percentages for a simple 60/40 split", () => {
    const result = splitExpense("100", "percentage", [
      { userId: "a", percent: 60 },
      { userId: "b", percent: 40 },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["60", "40"]);
    expect(result.shares.map((s) => s.percent)).toEqual(["60", "40"]);
  });

  it("lets a 0% participant hold no share", () => {
    const result = splitExpense("10", "percentage", [
      { userId: "a", percent: "100" },
      { userId: "b", percent: "0" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["10", "0"]);
  });

  it("rejects percentages that do not sum to exactly 100", () => {
    expectCode(
      () =>
        splitExpense("100", "percentage", [
          { userId: "a", percent: "33.33" },
          { userId: "b", percent: "33.33" },
          { userId: "c", percent: "33.33" },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_PERCENT
    );
  });

  it("rejects a missing, malformed, or over-precise percent", () => {
    for (const percent of [undefined, "-1", "abc", "33.3333333"]) {
      expectCode(
        () =>
          splitExpense("100", "percentage", [
            { userId: "a", percent: 100 },
            { userId: "b", percent },
          ]),
        EXPENSE_CALCULATION_ERROR_CODES.INVALID_PERCENT
      );
    }
  });
});

describe("splitExpense — custom", () => {
  it("returns exact custom amounts", () => {
    const result = splitExpense("30", "custom", [
      { userId: "a", amount: "10" },
      { userId: "b", amount: "20" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["10", "20"]);
    expect(result.remainderStroops).toBe("0");
  });

  it("is immune to the 0.1 + 0.2 trap", () => {
    const result = splitExpense("0.3", "custom", [
      { userId: "a", amount: "0.1" },
      { userId: "b", amount: "0.2" },
    ]);
    expect(shareTotal(result.shares)).toBe(toStroops("0.3"));
  });

  it("accepts a zero share alongside a positive one", () => {
    const result = splitExpense("10", "custom", [
      { userId: "a", amount: "10" },
      { userId: "b", amount: "0" },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["10", "0"]);
  });

  it("accepts Prisma.Decimal-like values", () => {
    const result = splitExpense("10", "custom", [
      { userId: "a", amount: decimal("4") },
      { userId: "b", amount: decimal("6") },
    ]);
    expect(result.shares.map((s) => s.amount)).toEqual(["4", "6"]);
  });

  it("rejects a missing amount", () => {
    expectCode(
      () =>
        splitExpense("30", "custom", [
          { userId: "a", amount: "10" },
          { userId: "b" },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_SPLIT
    );
  });

  it("rejects amounts that do not sum exactly to the total", () => {
    for (const shares of [
      [
        { userId: "a", amount: "0.07" },
        { userId: "b", amount: "0.06" },
      ],
      [
        { userId: "a", amount: "20" },
        { userId: "b", amount: "20" },
      ],
    ]) {
      expectCode(
        () => splitExpense("0.14", "custom", shares),
        EXPENSE_CALCULATION_ERROR_CODES.INVALID_SPLIT
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Breakdown
// ---------------------------------------------------------------------------

describe("calculateGroupExpenseBreakdown — per asset", () => {
  it("records who paid, who owes, and the net for each asset", () => {
    const result = calculateGroupExpenseBreakdown([dinner, cab]);

    expect(result.assets.map((a) => a.assetCode)).toEqual(["XLM", "USDC"]);
    expect(result.normalized).toBeUndefined();

    const xlm = result.assets.find((a) => a.assetCode === "XLM")!;
    expect(xlm.assetIssuer).toBeNull();
    expect(xlm.total).toBe("30");
    expect(xlm.expenseCount).toBe(1);
    expect(byUser(xlm.participants)).toMatchObject({
      alice: { paid: "30", owed: "10", net: "20" },
      bob: { paid: "0", owed: "10", net: "-10" },
      carol: { paid: "0", owed: "10", net: "-10" },
    });

    const usdc = result.assets.find((a) => a.assetCode === "USDC")!;
    expect(usdc.assetIssuer).toBe(USDC_ISSUER);
    expect(usdc.total).toBe("100");
    expect(byUser(usdc.participants)).toMatchObject({
      bob: { paid: "100", owed: "25", net: "75" },
      alice: { paid: "0", owed: "25", net: "-25" },
      carol: { paid: "0", owed: "50", net: "-50" },
    });
  });

  it("keeps each asset's paid, owed, and net totals exact", () => {
    const result = calculateGroupExpenseBreakdown([dinner, cab]);
    for (const asset of result.assets) {
      expect(amountSum(asset.participants, "paid")).toBe(toStroops(asset.total));
      expect(amountSum(asset.participants, "owed")).toBe(toStroops(asset.total));
      expect(netSum(asset.participants)).toBe(0n);
    }
  });

  it("never lets one asset's credit cancel another's debt", () => {
    const result = calculateGroupExpenseBreakdown([dinner, cab]);
    const xlm = byUser(result.assets.find((a) => a.assetCode === "XLM")!.participants);
    const usdc = byUser(result.assets.find((a) => a.assetCode === "USDC")!.participants);

    // Alice owes USDC, but is owed XLM; the per-asset nets stay independent.
    expect(xlm.alice.net).toBe("20");
    expect(usdc.alice.net).toBe("-25");
  });

  it("agrees with the settlement engine's gross net balances for one asset", () => {
    const breakdown = calculateGroupExpenseBreakdown([dinner]);
    const netFromEngine = Object.fromEntries(
      computeNetBalancesByAsset(
        dinner.shares.map((share) => ({
          payerUserId: dinner.payerUserId,
          userId: share.userId,
          shareAmount: share.shareAmount.toString(),
          settled: share.settled ?? false,
          ...XLM,
        })),
        []
      )[0].balances.map((balance) => [balance.userId, balance.net])
    );

    expect(byUser(breakdown.assets[0].participants)).toMatchObject({
      alice: { net: netFromEngine.alice },
      bob: { net: netFromEngine.bob },
      carol: { net: netFromEngine.carol },
    });
  });

  it("aggregates several expenses in the same asset", () => {
    const lunch: ExpenseRecord = {
      payerUserId: "bob",
      amount: "9",
      ...XLM,
      shares: [
        { userId: "alice", shareAmount: "3" },
        { userId: "bob", shareAmount: "3" },
        { userId: "carol", shareAmount: "3" },
      ],
    };

    const result = calculateGroupExpenseBreakdown([dinner, lunch]);
    const xlm = result.assets[0];
    expect(xlm.expenseCount).toBe(2);
    expect(xlm.total).toBe("39");
    expect(byUser(xlm.participants)).toMatchObject({
      alice: { paid: "30", owed: "13", net: "17" },
      bob: { paid: "9", owed: "13", net: "-4" },
      carol: { paid: "0", owed: "13", net: "-13" },
    });
    expect(netSum(xlm.participants)).toBe(0n);
  });

  it("derives the total from shares when the stored amount is omitted", () => {
    const result = calculateGroupExpenseBreakdown([
      {
        payerUserId: "alice",
        ...XLM,
        shares: [
          { userId: "alice", shareAmount: "1" },
          { userId: "bob", shareAmount: "2" },
        ],
      },
    ]);
    const xlm = result.assets[0];
    expect(xlm.total).toBe("3");
    expect(byUser(xlm.participants).alice).toMatchObject({
      paid: "3",
      owed: "1",
      net: "2",
    });
  });

  it("includes a participant with a zero share", () => {
    const result = calculateGroupExpenseBreakdown([
      {
        payerUserId: "alice",
        amount: "10",
        ...XLM,
        shares: [
          { userId: "alice", shareAmount: "10" },
          { userId: "bob", shareAmount: "0" },
        ],
      },
    ]);
    expect(byUser(result.assets[0].participants).bob).toMatchObject({
      paid: "0",
      owed: "0",
      net: "0",
    });
  });

  it("groups USDC by canonical issuer even when the row omits it", () => {
    const result = calculateGroupExpenseBreakdown([
      {
        payerUserId: "alice",
        amount: "10",
        assetCode: "USDC",
        // No issuer: the registry fills in the configured one.
        shares: [
          { userId: "alice", shareAmount: "10" },
          { userId: "bob", shareAmount: "0" },
        ],
      },
      cab,
    ]);
    expect(result.assets).toHaveLength(1);
    expect(result.assets[0].assetCode).toBe("USDC");
    expect(result.assets[0].expenseCount).toBe(2);
  });

  it("returns an empty breakdown for a group with no expenses", () => {
    expect(calculateGroupExpenseBreakdown([])).toEqual({ assets: [] });
  });
});

describe("calculateGroupExpenseBreakdown — normalization", () => {
  it("normalizes every asset into USDC and offsets the nets", () => {
    const result = calculateGroupExpenseBreakdown([dinner, cab], {
      targetAsset: USDC,
      rates: [
        { fromAssetCode: "XLM", fromAssetIssuer: null, rate: "0.1" },
      ],
    });

    expect(result.normalized).toBeDefined();
    const normalized = result.normalized!;
    expect(normalized.assetCode).toBe("USDC");
    expect(normalized.assetIssuer).toBe(USDC_ISSUER);
    // 30 XLM -> 3 USDC, plus 100 USDC.
    expect(normalized.total).toBe("103");
    expect(byUser(normalized.participants)).toMatchObject({
      alice: { paid: "3", owed: "26", net: "-23" },
      bob: { paid: "100", owed: "26", net: "74" },
      carol: { paid: "0", owed: "51", net: "-51" },
    });
    expect(normalized.appliedRates).toEqual([
      { fromAssetCode: "XLM", fromAssetIssuer: null, rate: "0.1" },
    ]);
    expect(amountSum(normalized.participants, "paid")).toBe(toStroops("103"));
    expect(amountSum(normalized.participants, "owed")).toBe(toStroops("103"));
    expect(netSum(normalized.participants)).toBe(0n);
  });

  it("normalizes into XLM with the inverse rate", () => {
    const result = calculateGroupExpenseBreakdown([dinner, cab], {
      targetAsset: XLM,
      rates: [
        {
          fromAssetCode: "USDC",
          fromAssetIssuer: USDC_ISSUER,
          rate: "10",
        },
      ],
    });

    const normalized = result.normalized!;
    expect(normalized.assetCode).toBe("XLM");
    expect(normalized.total).toBe("1030");
    expect(byUser(normalized.participants)).toMatchObject({
      alice: { paid: "30", owed: "260", net: "-230" },
      bob: { paid: "1000", owed: "260", net: "740" },
      carol: { paid: "0", owed: "510", net: "-510" },
    });
    expect(normalized.appliedRates).toEqual([
      {
        fromAssetCode: "USDC",
        fromAssetIssuer: USDC_ISSUER,
        rate: "10",
      },
    ]);
    expect(netSum(normalized.participants)).toBe(0n);
  });

  it("records no applied rate when every asset is already the target", () => {
    const result = calculateGroupExpenseBreakdown([cab], {
      targetAsset: USDC,
    });
    expect(result.normalized!.total).toBe("100");
    expect(result.normalized!.appliedRates).toEqual([]);
  });

  it("preserves each asset total exactly when a rate does not divide evenly", () => {
    const oneStroop = (payer: string, debtor: string): ExpenseRecord => ({
      payerUserId: payer,
      amount: "0.0000001",
      ...XLM,
      shares: [{ userId: debtor, shareAmount: "0.0000001" }],
    });
    const twoStroops = (payer: string, debtor: string): ExpenseRecord => ({
      payerUserId: payer,
      amount: "0.0000002",
      ...XLM,
      shares: [{ userId: debtor, shareAmount: "0.0000002" }],
    });

    const result = calculateGroupExpenseBreakdown(
      [
        oneStroop("alice", "bob"),
        oneStroop("bob", "carol"),
        twoStroops("carol", "alice"),
      ],
      {
        targetAsset: USDC,
        // 4 XLM stroops * 0.3 = 1.2 stroops -> 1 target stroop, allocated by
        // largest remainder rather than truncated away or invented.
        rates: [{ fromAssetCode: "XLM", rate: "0.3" }],
      }
    );

    const normalized = result.normalized!;
    expect(normalized.total).toBe("0.0000001");
    expect(byUser(normalized.participants)).toMatchObject({
      // Paid: 1, 1, 2 stroops -> 0.3, 0.3, 0.6; the largest remainder is carol's.
      alice: { paid: "0" },
      bob: { paid: "0" },
      carol: { paid: "0.0000001" },
      // Owed: 2, 1, 1 stroops -> 0.6, 0.3, 0.3; alice gets the target stroop.
    });
    expect(byUser(normalized.participants).alice.owed).toBe("0.0000001");
    expect(amountSum(normalized.participants, "paid")).toBe(1n);
    expect(amountSum(normalized.participants, "owed")).toBe(1n);
    expect(netSum(normalized.participants)).toBe(0n);
  });

  it("keeps totals exact across several awkward rates", () => {
    for (const rate of ["0.1", "0.3333333", "1.5", "10"]) {
      const result = calculateGroupExpenseBreakdown([dinner, cab], {
        targetAsset: USDC,
        rates: [
          { fromAssetCode: "XLM", rate },
          {
            fromAssetCode: "USDC",
            fromAssetIssuer: USDC_ISSUER,
            rate: "1",
          },
        ],
      });
      const normalized = result.normalized!;
      expect(amountSum(normalized.participants, "paid")).toBe(
        toStroops(normalized.total)
      );
      expect(amountSum(normalized.participants, "owed")).toBe(
        toStroops(normalized.total)
      );
      expect(netSum(normalized.participants)).toBe(0n);
    }
  });

  it("requires a rate for every non-target asset", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([dinner, cab], {
          targetAsset: USDC,
        }),
      EXPENSE_CALCULATION_ERROR_CODES.MISSING_RATE
    );
  });

  it("rejects duplicate conversion rates for one asset", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([dinner], {
          targetAsset: USDC,
          rates: [
            { fromAssetCode: "XLM", rate: "0.1" },
            { fromAssetCode: "XLM", rate: "0.2" },
          ],
        }),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_RATE
    );
  });

  it("rejects a malformed rate even before it is needed", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([], {
          targetAsset: USDC,
          rates: [{ fromAssetCode: "XLM", rate: "nope" }],
        }),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_RATE
    );
  });

  it("returns an empty normalized breakdown for an empty group", () => {
    const result = calculateGroupExpenseBreakdown([], { targetAsset: XLM });
    expect(result.normalized).toEqual({
      assetCode: "XLM",
      assetIssuer: null,
      total: "0",
      participants: [],
      appliedRates: [],
    });
  });
});

describe("calculateGroupExpenseBreakdown — invalid data", () => {
  it("rejects an unsupported asset", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          {
            payerUserId: "alice",
            amount: "10",
            assetCode: "DOGE",
            shares: [{ userId: "bob", shareAmount: "10" }],
          },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.UNSUPPORTED_ASSET
    );
  });

  it("rejects an expense whose amount disagrees with its shares", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          {
            id: "corrupt",
            payerUserId: "alice",
            amount: "31",
            ...XLM,
            shares: [
              { userId: "alice", shareAmount: "10" },
              { userId: "bob", shareAmount: "20" },
            ],
          },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INCONSISTENT_EXPENSE
    );
  });

  it("rejects duplicate shares for one user on one expense", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          {
            payerUserId: "alice",
            amount: "10",
            ...XLM,
            shares: [
              { userId: "bob", shareAmount: "5" },
              { userId: "bob", shareAmount: "5" },
            ],
          },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.DUPLICATE_PARTICIPANT
    );
  });

  it("rejects an expense with no shares", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          { payerUserId: "alice", amount: "10", ...XLM, shares: [] },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_PARTICIPANTS
    );
  });

  it("rejects a missing payer or a negative share", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          { payerUserId: "", amount: "10", ...XLM, shares: [{ userId: "bob", shareAmount: "10" }] },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_PARTICIPANTS
    );

    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          {
            payerUserId: "alice",
            amount: "10",
            ...XLM,
            shares: [{ userId: "bob", shareAmount: "-1" }],
          },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_AMOUNT
    );
  });

  it("rejects a zero-total expense", () => {
    expectCode(
      () =>
        calculateGroupExpenseBreakdown([
          {
            payerUserId: "alice",
            amount: "0",
            ...XLM,
            shares: [{ userId: "bob", shareAmount: "0" }],
          },
        ]),
      EXPENSE_CALCULATION_ERROR_CODES.INVALID_AMOUNT
    );
  });
});
