# Issue traceability — #384, #634, #638, #639

Four open issues describe work that landed on `main` through earlier PRs (#849–#865,
#856, #863 …) without ever linking the issue numbers, so GitHub never closed them.
This document maps each issue's acceptance criteria to the code and tests that
satisfy it, so maintainers can verify and close without re-reading the whole tree.

Verified on `main` at the time of writing: `npm run build` succeeds and
`npm test` passes (210 files, 4320 tests).

---

## #384 — Centralized Fastify error formatting handler

| Acceptance criterion | Where it is satisfied |
| --- | --- |
| Centralized error handler registered in the Fastify app | `src/plugins/error-handler.ts` — registered via `errorHandlerPlugin` (`app.setErrorHandler`) in `src/app.ts` |
| Zod validation errors format into a clear array of field-level issues | `err instanceof ZodError` branch returns `details` (field/message/code) and `issues` (path/message/code); Fastify/ajv `FST_ERR_VALIDATION` errors are normalized to the same `VALIDATION_ERROR` contract |
| Non-validation errors return a standard `{ …, error, message, timestamp }` JSON structure | `src/utils/error-response.ts` — `formatErrorResponse()` stamps `timestamp`, `requestId`, and a stable `code`; Prisma, request-limit, Horizon, timeout, and 429 errors each map to their own code/status before the generic 500 fallback |
| Stack traces hidden in production; detailed Pino logs kept server-side | Fixed, client-safe messages in responses; stack and error objects only in server logs (`request.log.error` on ≥500) |
| Tests for 400 / 401 / 500 response format | `tests/error-contract.test.ts` (401, 500), `tests/error-handler.test.ts`, `tests/error-shape.test.ts`, `tests/error-non-error-throw.test.ts`, `tests/prisma-error.test.ts`, `tests/error-handler-logging.test.ts` |

---

## #634 — Error handling and retry logic for Stellar Horizon I/O

| Acceptance criterion | Where it is satisfied |
| --- | --- |
| Resilient wrapper utility for Horizon requests | `src/services/horizon-retry.ts` — `withHorizonRetry()` with bounded attempts, exponential backoff + jitter (`horizonRetryDelayMs`), and injectable delay for tests |
| Handle common Horizon error codes (transaction failed, resource missing, rate limit) | `classifyHorizonError()` — `tx_*` / `op_*` result codes, HTTP 404 (missing resource), 429 (rate limit), 408, 5xx; categories `transient` / `indeterminate` / `permanent` |
| Meaningful error messages to callers | Horizon failures surface through `src/plugins/error-handler.ts` as `UPSTREAM_ERROR` / rate-limited envelopes with `Retry-After` where applicable |
| Safe transaction submission checks | `src/services/stellar.ts` — reads (`loadAccount`, `getTransaction`) retry with `horizonReadPolicy()` + endpoint failover (`withHorizonFailover`); submissions are deliberately never blindly retried and are reconciled by hash in the worker (`src/worker/tasks/tx-status-sync.ts`, which wraps every Horizon read in `withHorizonRetry`) |
| Unit tests mocking Horizon responses / retry on timeouts | `tests/horizon-retry.test.ts`, `tests/stellar-horizon-retry.test.ts`, `tests/horizon-network-failure-retry.test.ts`, `tests/horizon-query-retry.test.ts`, `tests/services/stellar.test.ts` |

---

## #638 — Rate limiting and request throttling for sensitive endpoints

| Acceptance criterion | Where it is satisfied |
| --- | --- |
| `@fastify/rate-limit` configured globally in app initialization | `src/plugins/rate-limit.ts`, registered in `src/app.ts` (`buildApp`) before the route plugins |
| Custom limits on sensitive route groups (auth, settlements) | `src/lib/rate-limit.ts` — per-route policies (`authChallenge`, `authVerify`, `settlementCreate`, `settlementConfirm`, `settlementExecute`, `treasurySubmit`, …) named by the routes they guard; auth and settlement tiers are stricter than the read-only global budget |
| `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers returned | `addHeaders` in the plugin: `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`, `retry-after`; asserted in `tests/rate-limit-headers.test.ts` |
| Tests verifying 429 Too Many Requests on exceeding limits | `tests/rate-limit-sensitive-routes.test.ts` (per-route budgets + production 429 envelope on auth and settlement routes), `tests/rate-limit-tiers.test.ts`, `tests/rate-limit.test.ts`, `tests/rateLimit.test.ts`, `tests/rate-limit-policies.test.ts`, `tests/integration/sep10-auth-rate-limit.test.ts` |

---

## #639 — Zod request validation middleware for SEP-10 routes

| Acceptance criterion | Where it is satisfied |
| --- | --- |
| Dedicated Zod schemas for SEP-10 request bodies and query parameters | `src/validations/sep10.ts` — `sep10ChallengeRequestSchema`, `sep10VerifyRequestSchema`, `sep10QuerySchema` (strict; unknown keys rejected) |
| Zod validation attached to all SEP-10 routes | `src/routes/auth.ts` — `/auth/challenge` and `/auth/verify` parse body and query through the schemas before any XDR, signature, or database work |
| Invalid requests return structured 400 with Zod error details | `ZodError` branch of the central handler returns `400 VALIDATION_ERROR` with `details` and `issues` (see #384) |
| Tests for valid and invalid payloads | `tests/sep10-request-validation.test.ts`, `tests/sep10-strict-validation.test.ts`, `tests/sep10-challenge-validation.test.ts`, `tests/validations/sep10.test.ts`, `tests/sep10.test.ts` |
