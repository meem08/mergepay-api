# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Rate-limit tiers for the sensitive routes still on the global bucket (#682, #693)** — Four new policies in `src/lib/rate-limit.ts`, each with its own key prefix and env-tunable budget: `authLogout` (`POST /auth/logout`, IP-keyed — the route answers `ok` without a valid token, so the revoke-and-audit path is reachable anonymously), `expenseMutate` (`PATCH`/`DELETE /expenses/:id`, which rewrite every participant's obligations while only creation was budgeted), `treasuryConfig` (`POST /groups/:id/treasury/enable` and `.../validate-signers`, one Horizon account read per call), and `webhookTest` (`POST /groups/:groupId/webhooks/:webhookId/test`, which turns one inbound request into an outbound delivery with retries). `GET /withdraw/:id` now takes the existing `anchorPoll` budget — it was the one anchor-transaction read left unbudgeted.
- **Filtering on the group transaction-history endpoints (#692)** — `GET /groups/:id/settlements` takes `status` (the public settlement status, including the two values derived from the signing deadline rather than stored), `asset`, `startDate`/`endDate`, and `includeTotal`; `GET /groups/:id/ledger` takes `type` (which selects which of the three tables are read at all) and a date range; `GET /groups/:groupId/webhooks/:webhookId/deliveries` takes `status` and `event`. Every filter is pushed into the query rather than applied to a fetched page, so pages stay full and `hasMore` stays exact.
- **Non-throwing signed-XDR inspection (#694)** — `src/services/xdr-inspection.ts` reports which field of an envelope diverged from a stored intent (`{ ok: false, code, field, message }`) instead of raising, for callers that need to classify an envelope rather than reject a request. It composes the same primitives the submission path uses, so there is one description of what "matches the intent" means.

### Changed

- **Cursor pagination on the two unbounded list endpoints (#692)** — `GET /groups/:groupId/webhooks/:webhookId/deliveries` and `GET /groups/:groupId/webhooks` answered with unbounded `findMany` queries. Both now use the shared `(createdAt, id)` cursor contract and return standard `meta`. The delivery list also stops returning the stored request payload and the receiver's response body, which were never appropriate for a list response.

### Removed

- **The duplicate XDR intent validator in `src/utils/stellar-xdr.ts` (#694)** — `validateTransactionIntent` was a second, weaker copy of the submission path's rules: it never verified signatures or sequence numbers, compared amounts as raw strings (so `"10"` did not match `"10.0000000"`), and reported a fee-bump envelope as "must contain exactly one operation". It had no callers outside its own test. `isValidXdr`, which production code does use, is unchanged.

### Verified

- **Rate limiting on authentication and SEP-10 challenge endpoints (#918)** — `src/routes/auth.ts` already gives the unauthenticated SEP-10 entry points their own budgets through `rateLimited("authChallenge")` (20 requests / 60s per IP) and `rateLimited("authVerify")` (10 / 60s), plus `authLogout`; the policies live in `src/lib/rate-limit.ts` and are registered with `@fastify/rate-limit` in `src/plugins/rate-limit.ts`, which returns HTTP 429 with `x-ratelimit-*` and `retry-after` under the standard `RATE_LIMITED` envelope. `tests/rate-limit-tiers.test.ts` and `tests/rate-limit-sensitive-routes.test.ts` drive rapid successive requests past both budgets against the real app, and `tests/integration/sep10-auth-rate-limit.test.ts` covers the same contract end to end.
- **Background worker sync of pending Stellar settlement statuses (#920)** — `src/worker/tasks/tx-status-sync.ts` polls the rows that still owe an on-chain answer (settlements stuck in `verifying` with a recorded hash, and treasury intents in `pending`/`awaiting_signatures`), reads each hash from Horizon through `stellar.getTransaction` under the shared retry policy, and writes `confirmed` or `failed` back with a compare-and-set update plus an audit row; a Horizon that stays unreachable leaves the row untouched for the next cycle instead of failing it. The task runs from `runWorkerCycle` in `src/worker/index.ts`, and its 15 tests in `tests/worker/tx-status-sync.test.ts` cover the candidate queries, confirmation, failure, verification mismatch, deferral, and concurrent-write paths.
- **Debt simplification test coverage (#685)** — Comprehensive test suites already verify greedy debt-simplification algorithm across circular debts (balanced/uneven rings, bidirectional netting), zero-balance members, unequal shares, and multi-asset segregation. 61 tests across `tests/settlement.test.ts` (lines 287-454) and `tests/multi-asset-settlement.test.ts` enforce mathematical completeness and (n-1) transfer bound.
- **Treasury multisig implementation (#686)** — Unsigned XDR proposal storage, live-weight signer verification from Horizon, cryptographic signature validation, threshold-based auto-submission fully implemented in `src/routes/treasury-proposals.ts` (~208 lines) and `src/services/treasury-signatures.ts` (~473 lines). Admin-only signers enforced, unauthorized/invalid signatures rejected, 44+ integration tests covering proposal lifecycle.
