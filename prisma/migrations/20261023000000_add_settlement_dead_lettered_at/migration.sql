-- Explicit dead-letter marker for worker settlements (issue #926).
--
-- A settlement that exhausts its bounded retry budget (or fails permanently)
-- is already moved to status = 'failed' with its retry count, error category,
-- and sanitized reason persisted. This timestamp makes the "worker gave up"
-- event queryable without parsing failure_reason, and keeps dead-lettered jobs
-- distinguishable from failures recorded on the request path.
ALTER TABLE "settlements" ADD COLUMN "dead_lettered_at" TIMESTAMP(3);

CREATE INDEX "settlements_dead_lettered_at_idx" ON "settlements"("dead_lettered_at");
