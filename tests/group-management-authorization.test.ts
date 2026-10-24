/**
 * Issue #635 — strict membership and role verification middleware for group
 * management routes.
 *
 * Two layers:
 *  1. The reusable preHandler hooks (src/middleware/group-guard.ts) in
 *     isolation: membership, admin role, the `active` (non-archived) option,
 *     and the failure modes (401 unauthenticated, 400 malformed id, 403
 *     non-member / insufficient role / archived group).
 *  2. The actual group management routes in src/routes/groups.ts on the real
 *     app: a non-member is refused with 403 before any handler or write runs,
 *     a regular member cannot reach the admin-only mutations, an archived
 *     group's state is frozen to writes while its history stays readable, and
 *     a role claimed in the body/query/headers is never believed.
 *
 * The membership lookup is stubbed at the Prisma boundary, so these assertions
 * cover the real guards, the real route table, and the real error envelope —
 * only the database is mocked.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import Fastify from "fastify";

const h = vi.hoisted(() => {
  const model = () => ({
    create: vi.fn(),
    createMany: vi.fn(),
    findUnique: vi.fn(),
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
  /** `${groupId}:${userId}` → role; absent means "not a member". */
  const roles = new Map<string, string>();
  /** Group ids currently archived. */
  const archived = new Set<string>();
  return { prisma, roles, archived };
});

vi.mock("../src/db", () => ({ prisma: h.prisma }));
vi.mock("../src/services/stellar", async (importActual) => {
  const actual = await importActual<typeof import("../src/services/stellar")>();
  return {
    ...actual,
    stellar: {
      ...actual.stellar,
      loadAccount: vi.fn(async () => ({
        exists: false,
        sequence: "0",
        balances: [],
        signers: [],
        thresholds: { low: 0, med: 0, high: 0 },
      })),
    },
  };
});

import { buildApp } from "../src/app";
import { signToken } from "../src/plugins/auth";
import authPlugin from "../src/plugins/auth";
import errorHandlerPlugin from "../src/plugins/error-handler";
import groupAccessPlugin from "../src/plugins/group-access";
import {
  groupMembership,
  requireGroupAdmin,
  requireGroupMember,
} from "../src/middleware/group-guard";

const GROUP_ID = "group_mgmt_1";
const OTHER_GROUP_ID = "group_mgmt_2";
const PUBLIC_KEY = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

let userSeq = 0;
/** A fresh user id per scenario, so one scenario's identity never leaks into another. */
function newUser(role: string | null, group = GROUP_ID): string {
  userSeq += 1;
  const id = `user_mgmt_${userSeq}`;
  if (role) h.roles.set(`${group}:${id}`, role);
  return id;
}

function bearer(userId: string) {
  return { authorization: `Bearer ${signToken({ id: userId, stellarPublicKey: PUBLIC_KEY })}` };
}

function groupRow(id: string, over: Record<string, unknown> = {}) {
  return {
    id,
    name: "Trip",
    description: null,
    createdByUserId: "user_creator",
    treasuryEnabled: false,
    treasuryAccountPublicKey: null,
    treasuryRequiredSigners: null,
    archived: h.archived.has(id),
    createdAt: new Date("2026-01-01T00:00:00Z"),
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  h.roles.clear();
  h.archived.clear();

  h.prisma.$transaction.mockImplementation(async (arg: any) =>
    typeof arg === "function" ? arg(h.prisma) : Promise.all(arg)
  );

  h.prisma.groupMember.findUnique.mockImplementation(async (args: any) => {
    const key = args?.where?.groupId_userId;
    if (!key) return null;
    const role = h.roles.get(`${key.groupId}:${key.userId}`);
    return role ? { groupId: key.groupId, userId: key.userId, role } : null;
  });
  h.prisma.groupMember.update.mockImplementation(async (args: any) => {
    const key = args?.where?.groupId_userId;
    return {
      groupId: key?.groupId,
      userId: key?.userId,
      role: args?.data?.role,
      joinedAt: new Date("2026-01-01T00:00:00Z"),
      user: {
        id: key?.userId,
        stellarPublicKey: PUBLIC_KEY,
        displayName: "Member",
        avatarUrl: null,
        createdAt: new Date("2026-01-01T00:00:00Z"),
      },
    };
  });
  h.prisma.groupMember.delete.mockResolvedValue({});

  h.prisma.group.findUnique.mockImplementation(async (args: any) => {
    const id = args?.where?.id;
    if (id !== GROUP_ID && id !== OTHER_GROUP_ID) return null;
    return groupRow(id);
  });
  h.prisma.group.update.mockImplementation(async (args: any) =>
    groupRow(args?.where?.id ?? GROUP_ID, args?.data ?? {})
  );

  h.prisma.invite.create.mockImplementation(async (args: any) => ({
    id: "invite_1",
    groupId: args?.data?.groupId,
    code: "CODE1234",
    createdByUserId: args?.data?.createdByUserId,
    maxUses: args?.data?.maxUses ?? null,
    expiresAt: args?.data?.expiresAt ?? null,
    uses: 0,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  }));
  h.prisma.invitation.create.mockImplementation(async (args: any) => ({
    id: "invitation_1",
    groupId: args?.data?.groupId,
    inviteePublicKey: args?.data?.inviteePublicKey,
    status: "PENDING",
    createdAt: new Date("2026-01-01T00:00:00Z"),
  }));
  h.prisma.auditLog.create.mockResolvedValue({});
  h.prisma.expense.findUnique.mockReset();
});

// ---------------------------------------------------------------------------
// 1. The reusable hooks in isolation
// ---------------------------------------------------------------------------

async function hooksApp() {
  const app = Fastify();
  await app.register(authPlugin);
  await app.register(errorHandlerPlugin);
  await app.register(groupAccessPlugin);

  const memberHandler = vi.fn(async (req: any) => ({ membership: groupMembership(req) }));
  const adminHandler = vi.fn(async (req: any) => ({ membership: groupMembership(req) }));

  await app.register(async (scoped) => {
    scoped.addHook("preHandler", scoped.authenticate);
    scoped.get("/member/:id", { preHandler: requireGroupMember({ param: "id" }) }, memberHandler);
    scoped.get(
      "/member-active/:id",
      { preHandler: requireGroupMember({ param: "id", active: true }) },
      memberHandler
    );
    scoped.post("/admin/:id", { preHandler: requireGroupAdmin({ param: "id" }) }, adminHandler);
    scoped.post(
      "/admin-active/:id",
      { preHandler: requireGroupAdmin({ param: "id", active: true }) },
      adminHandler
    );
  });

  await app.ready();
  return { app, memberHandler, adminHandler };
}

describe("requireGroupMember / requireGroupAdmin — membership and role", () => {
  it("rejects a non-member with 403 and never runs the handler", async () => {
    const { app, memberHandler } = await hooksApp();
    const res = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(newUser(null)),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("FORBIDDEN");
    expect(res.json().error.message).toBe("You are not a member of this group");
    expect(memberHandler).not.toHaveBeenCalled();
  });

  it("admits a member with the verified role attached to the request", async () => {
    const { app } = await hooksApp();
    const userId = newUser("member");
    const res = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(userId),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().membership).toEqual({ groupId: GROUP_ID, userId, role: "member" });
  });

  it("admits an admin on a member hook (admin implies member)", async () => {
    const { app } = await hooksApp();
    const res = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(newUser("admin")),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().membership.role).toBe("admin");
  });

  it("rejects a regular member on an admin hook with 403", async () => {
    const { app, adminHandler } = await hooksApp();
    const res = await app.inject({
      method: "POST",
      url: `/admin/${GROUP_ID}`,
      headers: bearer(newUser("member")),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.message).toBe("Only a group admin can perform this action");
    expect(adminHandler).not.toHaveBeenCalled();
  });

  it("admits an administrator on an admin hook", async () => {
    const { app, adminHandler } = await hooksApp();
    const userId = newUser("admin");
    const res = await app.inject({
      method: "POST",
      url: `/admin/${GROUP_ID}`,
      headers: bearer(userId),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().membership).toEqual({ groupId: GROUP_ID, userId, role: "admin" });
    expect(adminHandler).toHaveBeenCalledOnce();
  });
});

describe("requireGroupMember / requireGroupAdmin — the active (non-archived) option", () => {
  it("refuses writes against an archived group with 403", async () => {
    const { app, adminHandler } = await hooksApp();
    h.archived.add(GROUP_ID);

    const res = await app.inject({
      method: "POST",
      url: `/admin-active/${GROUP_ID}`,
      headers: bearer(newUser("admin")),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.message).toBe("Group is archived");
    expect(adminHandler).not.toHaveBeenCalled();
  });

  it("keeps an archived group readable for its members", async () => {
    const { app } = await hooksApp();
    h.archived.add(GROUP_ID);

    const res = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(newUser("member")),
    });

    expect(res.statusCode).toBe(200);
  });

  it("still refuses a non-member of an archived group (no read access either)", async () => {
    const { app } = await hooksApp();
    h.archived.add(GROUP_ID);

    const res = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(newUser(null)),
    });

    expect(res.statusCode).toBe(403);
  });

  it("does not apply the archived rule to hooks that omit it (idempotent archive, leave)", async () => {
    const { app } = await hooksApp();
    h.archived.add(GROUP_ID);

    const asAdmin = await app.inject({
      method: "POST",
      url: `/admin/${GROUP_ID}`,
      headers: bearer(newUser("admin")),
    });
    expect(asAdmin.statusCode).toBe(200);

    const asMember = await app.inject({
      method: "GET",
      url: `/member/${GROUP_ID}`,
      headers: bearer(newUser("member")),
    });
    expect(asMember.statusCode).toBe(200);
  });
});

describe("requireGroupMember / requireGroupAdmin — failure modes", () => {
  it("rejects an unauthenticated request with 401 before any membership lookup", async () => {
    const { app, memberHandler } = await hooksApp();

    const res = await app.inject({ method: "GET", url: `/member/${GROUP_ID}` });

    expect(res.statusCode).toBe(401);
    expect(h.prisma.groupMember.findUnique).not.toHaveBeenCalled();
    expect(memberHandler).not.toHaveBeenCalled();
  });

  it("rejects a malformed (oversized) group id with 400 before any lookup", async () => {
    const { app } = await hooksApp();

    const res = await app.inject({
      method: "GET",
      url: `/member/${"x".repeat(65)}`,
      headers: bearer(newUser("admin")),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("VALIDATION_ERROR");
    expect(h.prisma.groupMember.findUnique).not.toHaveBeenCalled();
  });

  it("never believes a role claimed in the body, query string, or headers", async () => {
    const { app, adminHandler } = await hooksApp();
    const res = await app.inject({
      method: "POST",
      url: `/admin-active/${GROUP_ID}?role=admin&isAdmin=true`,
      headers: {
        ...bearer(newUser("member")),
        "x-role": "admin",
        "x-group-role": "admin",
      },
      payload: { role: "admin", groupMembership: { role: "admin" } },
    });

    expect(res.statusCode).toBe(403);
    expect(adminHandler).not.toHaveBeenCalled();
  });

  it("authorizes against the path group only, never a group id in the body or query", async () => {
    const { app } = await hooksApp();
    // Admin of the other group, plain member of the target group.
    const userId = newUser("member");
    h.roles.set(`${OTHER_GROUP_ID}:${userId}`, "admin");

    const res = await app.inject({
      method: "POST",
      url: `/admin-active/${GROUP_ID}?groupId=${OTHER_GROUP_ID}&id=${OTHER_GROUP_ID}`,
      headers: bearer(userId),
      payload: { groupId: OTHER_GROUP_ID, id: OTHER_GROUP_ID },
    });

    expect(res.statusCode).toBe(403);
    for (const [args] of h.prisma.groupMember.findUnique.mock.calls) {
      expect(args.where.groupId_userId.groupId).toBe(GROUP_ID);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. The group management routes on the real app
// ---------------------------------------------------------------------------

type Role = "member" | "admin";
interface GroupRoute {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  role: Role;
  /**
   * True for routes that change group state: they must refuse an archived
   * group. Reads, leaving, and archiving itself stay reachable.
   */
  liveGroupRequired: boolean;
}

/** Every route in src/routes/groups.ts addressed by a group id. */
const GROUP_ROUTES: GroupRoute[] = [
  { method: "GET", path: "/groups/:id", role: "member", liveGroupRequired: false },
  { method: "GET", path: "/groups/:id/balance", role: "member", liveGroupRequired: false },
  { method: "PATCH", path: "/groups/:id", role: "admin", liveGroupRequired: true },
  { method: "POST", path: "/groups/:id/invite", role: "admin", liveGroupRequired: true },
  { method: "POST", path: "/groups/:id/leave", role: "member", liveGroupRequired: false },
  { method: "PATCH", path: "/groups/:id/members/:memberId", role: "admin", liveGroupRequired: true },
  { method: "DELETE", path: "/groups/:id/members/:memberId", role: "admin", liveGroupRequired: true },
  { method: "POST", path: "/groups/:id/members/role", role: "admin", liveGroupRequired: true },
  { method: "POST", path: "/groups/:id/archive", role: "admin", liveGroupRequired: false },
];

function concreteUrl(routePath: string, groupId = GROUP_ID): string {
  return routePath.replace(":id", groupId).replace(":memberId", "user_target");
}

function payloadFor(route: GroupRoute): Record<string, unknown> | undefined {
  if (route.method === "GET" || route.method === "DELETE") return undefined;
  if (route.path === "/groups/:id") return { name: "Renamed" };
  if (route.path.endsWith("/members/:memberId")) return { role: "admin" };
  if (route.path.endsWith("/members/role")) return { userId: "user_target", role: "admin" };
  return {};
}

/** Mutations that must never happen when a guard rejects a request. */
function writes(): number {
  const p = h.prisma;
  return [
    p.group.create,
    p.group.update,
    p.groupMember.create,
    p.groupMember.update,
    p.groupMember.delete,
    p.invitation.create,
    p.invite.create,
    p.auditLog.create,
    p.$transaction,
  ].reduce((n, fn) => n + fn.mock.calls.length, 0);
}

let realApp: Awaited<ReturnType<typeof buildApp>>;
async function app() {
  if (!realApp) realApp = await buildApp({ rateLimit: "off" });
  return realApp;
}

describe("group management routes — strict membership and role verification", () => {
  it.each(GROUP_ROUTES)(
    "$method $path — a non-member gets 403 and no write happens",
    async (route) => {
      const res = await (await app()).inject({
        method: route.method,
        url: concreteUrl(route.path),
        headers: bearer(newUser(null)),
        payload: payloadFor(route),
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("FORBIDDEN");
      expect(writes()).toBe(0);
    }
  );

  it.each(GROUP_ROUTES.filter((r) => r.role === "admin"))(
    "$method $path — a regular member gets 403 (admin required) and no write happens",
    async (route) => {
      const res = await (await app()).inject({
        method: route.method,
        url: concreteUrl(route.path),
        headers: bearer(newUser("member")),
        payload: payloadFor(route),
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.message).toBe("Only a group admin can perform this action");
      expect(writes()).toBe(0);
    }
  );

  it.each(GROUP_ROUTES.filter((r) => r.liveGroupRequired))(
    "$method $path — an admin of an archived group gets 403 and no write happens",
    async (route) => {
      h.archived.add(GROUP_ID);
      const res = await (await app()).inject({
        method: route.method,
        url: concreteUrl(route.path),
        headers: bearer(newUser("admin")),
        payload: payloadFor(route),
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("FORBIDDEN");
      expect(res.json().error.message).toBe("Group is archived");
      expect(writes()).toBe(0);
    }
  );

  it.each(GROUP_ROUTES.filter((r) => !r.liveGroupRequired))(
    "$method $path — an archived group stays reachable for its members",
    async (route) => {
      h.archived.add(GROUP_ID);
      const res = await (await app()).inject({
        method: route.method,
        url: concreteUrl(route.path),
        headers: bearer(newUser(route.role)),
        payload: payloadFor(route),
      });

      expect(res.statusCode).toBe(200);
    }
  );

  it.each(GROUP_ROUTES.filter((r) => r.role === "admin"))(
    "$method $path — an admin of a live group is admitted",
    async (route) => {
      const res = await (await app()).inject({
        method: route.method,
        url: concreteUrl(route.path),
        headers: bearer(newUser("admin")),
        payload: payloadFor(route),
      });

      // Handlers may answer 404 for a target this mock does not hold, but the
      // guard itself must admit the role it requires.
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    }
  );

  it("returns 404 for a non-member of an unknown group without leaking group existence", async () => {
    const res = await (await app()).inject({
      method: "PATCH",
      url: "/groups/group_missing",
      headers: bearer(newUser("admin")),
      payload: { name: "Renamed" },
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe("NOT_FOUND");
    expect(writes()).toBe(0);
  });

  it("rejects an unauthenticated request with 401 before any membership lookup", async () => {
    const res = await (await app()).inject({
      method: "POST",
      url: `/groups/${GROUP_ID}/archive`,
    });

    expect(res.statusCode).toBe(401);
    expect(h.prisma.groupMember.findUnique).not.toHaveBeenCalled();
    expect(writes()).toBe(0);
  });
});
