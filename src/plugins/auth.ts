import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import { z } from "zod";
import { Errors } from "../errors";
import { verifyToken } from "../services/jwt";
import type { AuthUser } from "../services/jwt";

/*
 * The JWT utilities live in src/services/jwt.ts (issue #421). They are
 * re-exported here so this plugin stays the single import point the routes
 * and tests have always used, while the crypto itself remains unit-testable
 * without building a Fastify instance.
 */
export { signToken, verifyToken } from "../services/jwt";
export type { AuthUser } from "../services/jwt";

declare module "fastify" {
  interface FastifyRequest {
    user?: AuthUser;
  }
  interface FastifyInstance {
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

/**
 * `Bearer <token68>` (RFC 6750 §2.1): the scheme, exactly one space, and one
 * token with no further parts. The scheme is matched case-sensitively, as the
 * rate limiter's identity key (src/plugins/rate-limit.ts) is — a spelling one
 * accepted and the other did not would move an authenticated caller out of its
 * per-user bucket.
 */
const authorizationHeaderSchema = z
  .string()
  .regex(/^Bearer [A-Za-z0-9\-._~+/]+=*$/, "Authorization must be 'Bearer <token>'");

/**
 * Authenticate a request from its `Authorization` header.
 *
 * Each failure has its own stable code so clients can branch without parsing
 * messages: MISSING_TOKEN (no header), MALFORMED_TOKEN (not `Bearer <token>`,
 * or not a JWT), and from `verifyToken` TOKEN_EXPIRED / INVALID_TOKEN. All are
 * 401s carrying an RFC 6750 `WWW-Authenticate` challenge (set by the error
 * handler). The JWT library's own error text is never echoed back.
 */
async function authenticate(req: FastifyRequest, _reply: FastifyReply) {
  const header = req.headers.authorization;
  if (header === undefined || header.trim() === "") {
    throw Errors.missingToken();
  }

  const parsedHeader = authorizationHeaderSchema.safeParse(header);
  if (!parsedHeader.success) {
    throw Errors.malformedToken("Authorization header must be of the form 'Bearer <token>'");
  }

  // verifyToken raises the specific 401 the caller should act on, so its
  // AppErrors must reach the error handler unmodified.
  req.user = verifyToken(parsedHeader.data.slice("Bearer ".length));
}

export default fp(async function authPlugin(app: FastifyInstance) {
  app.decorate("authenticate", authenticate);
});

/** Read the authenticated user or throw 401. */
export function requireUser(req: FastifyRequest): AuthUser {
  if (!req.user) throw Errors.unauthorized();
  return req.user;
}
