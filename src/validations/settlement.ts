/**
 * Zod schemas for settlement payloads and for the payment intent that is
 * handed to the XDR builder — issue #644.
 *
 * Two classes of value are validated here:
 *
 *  - **Request payloads** (`POST /expenses/:id/settle`,
 *    `POST /groups/:id/settlements`, `POST /settlements/:id/confirm`,
 *    `POST /settlements/execute`). Every schema is `.strict()`, so a misspelled
 *    or unexpected key is a 400 rather than being silently stripped — a client
 *    that sent `ammount` must not receive a confirmation for the part it did
 *    not send (the same rule `src/schemas/groups.ts` applies to group bodies).
 *  - **The intent** (`settlementIntentSchema`) that is about to become an
 *    unsigned Stellar payment. Its public keys are checksum-validated with the
 *    SDK's `StrKey` rules, its asset must be one this API supports on the
 *    configured network, and its amount must be a positive, 7-decimal,
 *    Int64-range value — all *before* a sequence number is loaded or an
 *    envelope is built. A malformed intent can therefore never reach Horizon.
 *
 * Sanitization is deliberately narrow: whitespace around a signed envelope is
 * trimmed and internal whitespace is rejected, amounts keep the shared
 * whitespace-padding rejection from `src/lib/money.ts`, and nothing else is
 * rewritten. The API never holds a private key, so no schema here accepts,
 * returns, or stores one.
 */
import { z } from "zod";
import { StrKey } from "@stellar/stellar-sdk";
import { refineStellarAsset, stellarAmountSchema } from "../lib/stellar-validation";
import { intentValiditySchema } from "../lib/time-bounds";

/**
 * A Stellar ed25519 public key (`G…`), checksum-validated with the SDK's own
 * StrKey rules. Anything else — a secret seed (`S…`), a muxed address, a
 * truncated key, or a string that merely starts with `G` — is rejected.
 */
export const settlementPublicKeySchema = z
  .string()
  .min(1, "A Stellar public key is required")
  .refine((value) => StrKey.isValidEd25519PublicKey(value), {
    message:
      "Invalid Stellar account ID. Expected a valid public key beginning with 'G' and matching Stellar's ed25519 rules.",
  });

/**
 * A participant's identifier as it appears in a settlement payload: the user id
 * of the other party, or a settlement id. Bounded and character-restricted, so
 * an oversized or path-shaped value is rejected before it reaches Prisma.
 */
export const settlementIdentifierSchema = z
  .string()
  .trim()
  .min(1, "A settlement identifier is required")
  .max(64)
  .regex(/^[A-Za-z0-9_-]+$/, "Not a valid settlement identifier");

/**
 * A participant's share of an expense, as it is about to be turned into a
 * payment. The amount is validated with the same stroop-exact rules the request
 * bodies use, so a share that could not be represented on-chain is refused
 * before the intent is built rather than by Horizon later.
 */
export const settlementShareSchema = z
  .object({
    userId: settlementIdentifierSchema,
    amount: stellarAmountSchema,
  })
  .strict();

/** Asset fields shared by the payloads and the intent. */
const assetCodeSchema = z
  .string()
  .min(1, "assetCode is required")
  .max(12, "assetCode must be 12 characters or fewer");
const assetIssuerSchema = z.string().nullable().optional();

/**
 * Body of `POST /expenses/:id/settle`.
 *
 * Every field is optional: omitting them means "settle the share in the
 * expense's own asset with the default signing window". When an asset code is
 * chosen, it must be one this API supports and its issuer — if given — must be
 * a well-formed key for exactly that supported asset. An issuer sent without a
 * code is rejected instead of ignored: it describes nothing, so honouring the
 * request silently would drop what the client meant.
 */
export const settleExpensePayloadSchema = z
  .object({
    assetCode: assetCodeSchema.optional(),
    assetIssuer: assetIssuerSchema,
    validitySeconds: intentValiditySchema.optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.assetCode === undefined) {
      if (val.assetIssuer) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["assetIssuer"],
          message: "assetIssuer is only valid together with assetCode",
        });
      }
      return;
    }
    refineStellarAsset(ctx, val.assetCode, val.assetIssuer);
  });

/**
 * Body of `POST /groups/:id/settlements` — a freeform settle-up against the
 * group's net balance. The amount is the value that will move on-chain, so it
 * is validated here rather than left to the balance check.
 */
export const freeformSettlementPayloadSchema = z
  .object({
    toUserId: settlementIdentifierSchema,
    amount: stellarAmountSchema,
    assetCode: assetCodeSchema,
    assetIssuer: assetIssuerSchema,
    validitySeconds: intentValiditySchema.optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    refineStellarAsset(ctx, val.assetCode, val.assetIssuer);
  });

/**
 * Maximum length of a signed envelope this API will accept.
 *
 * A Stellar payment envelope with a handful of signatures is a few kilobytes of
 * base64; 100 KB leaves generous headroom while still refusing a payload whose
 * size, not its content, is the attack. Fastify's body limit already bounds the
 * whole request, but the schema is the layer that knows this field is an XDR.
 */
export const MAX_SIGNED_XDR_CHARS = 100_000;

/**
 * The wallet's signed envelope. Surrounding whitespace is trimmed (base64 is
 * routinely wrapped or padded by clients); internal whitespace is rejected,
 * because an envelope with line breaks in it is not a value this API should
 * quietly reflow before checking it against the intent.
 */
export const signedXdrSchema = z
  .string()
  .trim()
  .min(1, "signedXdr is required")
  .max(MAX_SIGNED_XDR_CHARS, "signedXdr is too large")
  .refine((value) => !/\s/.test(value), {
    message: "signedXdr must not contain whitespace",
  });

/** Body of `POST /settlements/:id/confirm`. */
export const settlementConfirmPayloadSchema = z
  .object({ signedXdr: signedXdrSchema })
  .strict();

/** Body of `POST /settlements/execute`. */
export const settlementExecutePayloadSchema = z
  .object({
    settlementId: settlementIdentifierSchema,
    signedXdr: signedXdrSchema,
  })
  .strict();

/**
 * A settlement's short code, as embedded in the payment memo. Generated by the
 * server (`shortCode()` — 10 characters from an unambiguous alphabet) and
 * bounded here so a persisted or injected value cannot produce an over-long
 * memo.
 */
export const settlementMemoCodeSchema = z
  .string()
  .min(1)
  .max(16)
  .regex(/^[A-Z0-9]+$/, "Settlement memo code must be upper-case alphanumeric");

/**
 * The complete payment intent handed to the XDR builder.
 *
 * This is the last gate before an unsigned transaction exists. Source and
 * destination keys are validated as ed25519 public keys, the asset must be a
 * supported one, the amount must be representable in stroops, the memo code
 * must fit its alphabet, and the validity window must be within the shared
 * intent bounds. Callers pass values derived from authenticated context and
 * persisted rows — never raw request fields — so a failure here means the
 * intent itself is malformed, and no Horizon call is made.
 */
export const settlementIntentSchema = z
  .object({
    fromPublicKey: settlementPublicKeySchema,
    toPublicKey: settlementPublicKeySchema,
    assetCode: assetCodeSchema,
    assetIssuer: assetIssuerSchema,
    amount: stellarAmountSchema,
    memoCode: settlementMemoCodeSchema,
    validitySeconds: intentValiditySchema,
  })
  .strict()
  .superRefine((val, ctx) => {
    refineStellarAsset(ctx, val.assetCode, val.assetIssuer);
  });

export type SettlementIntent = z.infer<typeof settlementIntentSchema>;
export type SettlementShare = z.infer<typeof settlementShareSchema>;
export type SettleExpensePayload = z.infer<typeof settleExpensePayloadSchema>;
export type FreeformSettlementPayload = z.infer<
  typeof freeformSettlementPayloadSchema
>;
