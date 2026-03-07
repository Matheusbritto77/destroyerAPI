import { db } from "./db";
import { config } from "./config";
import { security } from "./security";
import { z } from "zod";

const difficultySchema = z.enum(["EASY", "MEDIUM", "HARD", "IMPOSSIBLE"]);
const nicknameSchema = z
  .string()
  .trim()
  .min(3)
  .max(18)
  .regex(/^[A-Za-z0-9_]+$/);

const googleAuthSchema = z.object({
  idToken: z.string().min(32),
  nonce: z.string().min(16).max(255)
});

const nicknameRequestSchema = z.object({
  nickname: nicknameSchema
});

const syncSchema = z.object({
  records: z
    .array(
      z.object({
        difficulty: difficultySchema,
        score: z.number().int().nonnegative(),
        level: z.number().int().positive(),
        playedAtMillis: z.number().int().positive()
      })
    )
    .min(1)
    .max(4)
});

const refreshSchema = z.object({
  refreshToken: z.string().min(32)
});

type UserRow = {
  id: string;
  nickname: string | null;
  nickname_normalized: string | null;
  email: string | null;
  full_name: string | null;
  avatar_url: string | null;
  updated_at: number;
};

type AuthContext = {
  user: UserRow;
  accessToken: string;
};

const rateLimitWindowMs = 60_000;
const rateLimitMaxRequests = 90;
const leaderboardCache = new Map<string, { expiresAt: number; payload: unknown }>();
const rateLimits = new Map<string, { count: number; resetAt: number }>();

const selectUserById = db.query<UserRow, [string]>(
  `SELECT id, nickname, nickname_normalized, email, full_name, avatar_url, updated_at
   FROM users WHERE id = ?`
);
const selectUserBySubHash = db.query<UserRow, [string]>(
  `SELECT id, nickname, nickname_normalized, email, full_name, avatar_url, updated_at
    FROM users WHERE google_sub_hash = ?`);
const selectRefreshToken = db.query<
  { id: string; user_id: string; expires_at: number; revoked_at: number | null },
  [string]
>(
  `SELECT id, user_id, expires_at, revoked_at
   FROM refresh_tokens
   WHERE token_hash = ?`
);
const countNickname = db.query<{ count: number }, [string]>(
  `SELECT COUNT(*) as count FROM users WHERE nickname_normalized = ?`
);
const selectWorldRecord = db.query<
  { id: string; score: number; level: number },
  [string, string]
>(
  `SELECT id, score, level
   FROM world_records
   WHERE user_id = ? AND difficulty = ?`
);

const insertUser = db.prepare(
  `INSERT INTO users (
      id, google_sub_hash, google_issuer, email, email_verified, full_name, avatar_url, created_at, updated_at
   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const updateUserProfile = db.prepare(
  `UPDATE users
   SET email = ?, email_verified = ?, full_name = ?, avatar_url = ?, updated_at = ?
   WHERE id = ?`
);
const insertRefreshToken = db.prepare(
  `INSERT INTO refresh_tokens (
      id, user_id, token_hash, expires_at, created_at, user_agent, ip_address
   ) VALUES (?, ?, ?, ?, ?, ?, ?)`
);
const revokeRefreshToken = db.prepare(
  `UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`
);
const setNickname = db.prepare(
  `UPDATE users
   SET nickname = ?, nickname_normalized = ?, updated_at = ?
   WHERE id = ?`
);
const insertWorldRecord = db.prepare(
  `INSERT INTO world_records (
      id, user_id, difficulty, score, level, played_at, created_at, updated_at
   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
);
const updateWorldRecord = db.prepare(
  `UPDATE world_records
   SET score = ?, level = ?, played_at = ?, updated_at = ?
   WHERE id = ?`
);

function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "cross-origin-resource-policy": "same-site",
      ...headers
    }
  });
}

function normalizeNickname(nickname: string): string {
  return nickname.trim().toLowerCase();
}

function clientIp(req: Request, server: Bun.Server<unknown>): string {
  return server.requestIP(req)?.address ?? "0.0.0.0";
}

function enforceRateLimit(req: Request, server: Bun.Server<unknown>, keySuffix: string): Response | null {
  const ip = clientIp(req, server);
  const key = `${ip}:${keySuffix}`;
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || current.resetAt <= now) {
    rateLimits.set(key, { count: 1, resetAt: now + rateLimitWindowMs });
    return null;
  }

  current.count += 1;
  if (current.count > rateLimitMaxRequests) {
    return json(
      { error: "rate_limit_exceeded", message: "Too many requests. Try again shortly." },
      429,
      { "retry-after": String(Math.ceil((current.resetAt - now) / 1000)) }
    );
  }
  return null;
}

async function readJson<T>(req: Request, schema: z.ZodSchema<T>): Promise<T> {
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > 32_768) {
    throw new Error("Payload too large.");
  }

  const body = await req.json();
  return schema.parse(body);
}

function getAllowedOrigin(origin: string | null): string | null {
  if (!origin) return null;
  if (config.allowedOrigins.length === 0) return null;
  return config.allowedOrigins.includes(origin) ? origin : null;
}

function withCors(req: Request, res: Response): Response {
  const origin = getAllowedOrigin(req.headers.get("origin"));
  if (!origin) return res;
  const headers = new Headers(res.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("vary", "Origin");
  headers.set("access-control-allow-headers", "authorization, content-type");
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  return new Response(res.body, { status: res.status, headers });
}

function createSessionPayload(user: UserRow) {
  return {
    profile: {
      nickname: user.nickname,
      email: user.email,
      fullName: user.full_name,
      avatarUrl: user.avatar_url,
      nicknameRequired: !user.nickname
    }
  };
}

async function issueSession(user: UserRow, req: Request, server: Bun.Server<unknown>) {
  const accessToken = await security.issueAccessToken({
    sub: user.id,
    nicknameSet: Boolean(user.nickname)
  });
  const refreshToken = security.issueOpaqueRefreshToken();
  const now = Date.now();
  const expiresAt = now + config.refreshTokenTtlSeconds * 1000;

  insertRefreshToken.run(
    crypto.randomUUID(),
    user.id,
    security.hashOpaqueToken(refreshToken),
    expiresAt,
    now,
    req.headers.get("user-agent"),
    clientIp(req, server)
  );

  return {
    accessToken,
    refreshToken,
    expiresInSeconds: config.accessTokenTtlSeconds,
    ...createSessionPayload(user)
  };
}

function invalidateLeaderboardCache(difficulties: string[]) {
  if (difficulties.length === 0) return;
  const set = new Set(difficulties);
  Array.from(leaderboardCache.keys()).forEach((key) => {
    if (Array.from(set).some((difficulty) => key.startsWith(`${difficulty}:`))) {
      leaderboardCache.delete(key);
    }
  });
}

function fetchLeaderboardPage(difficulty: z.infer<typeof difficultySchema>, page: number, pageSize: number) {
  const totalRow = db
    .query<{ count: number }, [string]>(
      `SELECT COUNT(*) as count
       FROM world_records wr
       JOIN users u ON u.id = wr.user_id
       WHERE wr.difficulty = ? AND u.nickname IS NOT NULL`
    )
    .get(difficulty);
  const total = totalRow?.count ?? 0;
  const offset = (page - 1) * pageSize;
  const entries = db
    .query<
      {
        position: number;
        nickname: string;
        score: number;
        level: number;
        played_at: number;
      },
      [string, number, number]
    >(
      `WITH ranked AS (
         SELECT
           wr.user_id,
           u.nickname,
           wr.score,
           wr.level,
           wr.played_at,
           ROW_NUMBER() OVER (
             ORDER BY wr.score DESC, wr.level DESC, wr.played_at ASC, wr.updated_at ASC
           ) AS position
         FROM world_records wr
         JOIN users u ON u.id = wr.user_id
         WHERE wr.difficulty = ? AND u.nickname IS NOT NULL
       )
       SELECT position, nickname, score, level, played_at
       FROM ranked
       LIMIT ? OFFSET ?`
    )
    .all(difficulty, pageSize, offset);

  return {
    difficulty,
    page,
    pageSize,
    total,
    hasMore: offset + entries.length < total,
    entries: entries.map((entry) => ({
      position: entry.position,
      nickname: entry.nickname,
      score: entry.score,
      level: entry.level,
      playedAtMillis: entry.played_at
    }))
  };
}

function fetchUserPosition(userId: string, difficulty: z.infer<typeof difficultySchema>) {
  return db
    .query<
      {
        position: number;
        nickname: string | null;
        score: number;
        level: number;
      },
      [string, string]
    >(
      `WITH ranked AS (
         SELECT
           wr.user_id,
           u.nickname,
           wr.score,
           wr.level,
           ROW_NUMBER() OVER (
             ORDER BY wr.score DESC, wr.level DESC, wr.played_at ASC, wr.updated_at ASC
           ) AS position
         FROM world_records wr
         JOIN users u ON u.id = wr.user_id
         WHERE wr.difficulty = ? AND u.nickname IS NOT NULL
       )
       SELECT position, nickname, score, level
       FROM ranked
       WHERE user_id = ?`
    )
    .get(difficulty, userId);
}

async function requireAuth(req: Request): Promise<AuthContext> {
  const header = req.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) {
    throw new Response(
      JSON.stringify({ error: "unauthorized", message: "Missing bearer token." }),
      { status: 401, headers: { "content-type": "application/json; charset=utf-8" } }
    );
  }

  const payload = await security.verifyAccessToken(header.slice("Bearer ".length));
  const userId = payload.sub;
  if (!userId) {
    throw new Response(
      JSON.stringify({ error: "unauthorized", message: "Invalid token subject." }),
      { status: 401, headers: { "content-type": "application/json; charset=utf-8" } }
    );
  }

  const user = selectUserById.get(userId);
  if (!user) {
    throw new Response(
      JSON.stringify({ error: "unauthorized", message: "User not found." }),
      { status: 401, headers: { "content-type": "application/json; charset=utf-8" } }
    );
  }

  return { user, accessToken: header.slice("Bearer ".length) };
}

async function handleGoogleAuth(req: Request, server: Bun.Server<unknown>) {
  const payload = await readJson(req, googleAuthSchema);
  const google = await security.verifyGoogleIdToken(payload.idToken, payload.nonce);
  const googleSub = z.string().parse(google.sub);
  const issuer = z.string().parse(google.iss);
  const subHash = security.hashGoogleSub(googleSub);
  const email = typeof google.email === "string" ? google.email : null;
  const fullName = typeof google.name === "string" ? google.name : null;
  const avatarUrl = typeof google.picture === "string" ? google.picture : null;
  const emailVerified = google.email_verified === true ? 1 : 0;
  const now = Date.now();

  let user: UserRow | null = selectUserBySubHash.get(subHash) ?? null;
  if (!user) {
    const id = crypto.randomUUID();
    insertUser.run(id, subHash, issuer, email, emailVerified, fullName, avatarUrl, now, now);
    user = selectUserById.get(id) ?? null;
  } else {
    updateUserProfile.run(email, emailVerified, fullName, avatarUrl, now, user.id);
    user = selectUserById.get(user.id) ?? null;
  }

  if (!user) {
    return json({ error: "auth_failed", message: "Unable to create or load user." }, 500);
  }

  return json(await issueSession(user, req, server));
}

async function handleRefresh(req: Request, server: Bun.Server<unknown>) {
  const body = await readJson(req, refreshSchema);
  const tokenHash = security.hashOpaqueToken(body.refreshToken);
  const stored = selectRefreshToken.get(tokenHash);
  const now = Date.now();

  if (!stored || stored.revoked_at || stored.expires_at <= now) {
    return json({ error: "invalid_refresh_token", message: "Refresh token is invalid or expired." }, 401);
  }

  revokeRefreshToken.run(now, stored.id);
  const user = selectUserById.get(stored.user_id);
  if (!user) {
    return json({ error: "invalid_refresh_token", message: "User does not exist." }, 401);
  }

  return json(await issueSession(user, req, server));
}

async function handleNickname(req: Request) {
  const auth = await requireAuth(req);
  const body = await readJson(req, nicknameRequestSchema);
  const normalized = normalizeNickname(body.nickname);

  if (auth.user.nickname_normalized !== normalized && (countNickname.get(normalized)?.count ?? 0) > 0) {
    return json({ error: "nickname_taken", message: "Nickname already exists." }, 409);
  }

  const now = Date.now();
  setNickname.run(body.nickname.trim(), normalized, now, auth.user.id);
  const updated = selectUserById.get(auth.user.id);
  if (!updated) {
    return json({ error: "profile_update_failed", message: "Unable to update nickname." }, 500);
  }

  return json({
    ...createSessionPayload(updated),
    accessToken: await security.issueAccessToken({
      sub: updated.id,
      nicknameSet: true
    }),
    expiresInSeconds: config.accessTokenTtlSeconds
  });
}

async function handleLeaderboard(req: Request) {
  const url = new URL(req.url);
  const page = Number(url.searchParams.get("page") ?? 1);
  const pageSize = Math.min(Number(url.searchParams.get("pageSize") ?? 20), 50);
  const difficulty = difficultySchema.parse(url.pathname.split("/").pop());

  if (!Number.isFinite(page) || page < 1 || !Number.isFinite(pageSize) || pageSize < 1) {
    return json({ error: "invalid_pagination", message: "Invalid page or pageSize." }, 400);
  }

  const cacheKey = `${difficulty}:${page}:${pageSize}`;
  const now = Date.now();
  const cached = leaderboardCache.get(cacheKey);
  let payload: ReturnType<typeof fetchLeaderboardPage>;
  if (cached && cached.expiresAt > now) {
    payload = cached.payload as ReturnType<typeof fetchLeaderboardPage>;
  } else {
    payload = fetchLeaderboardPage(difficulty, page, pageSize);
    leaderboardCache.set(cacheKey, {
      expiresAt: now + config.leaderboardCacheTtlMs,
      payload
    });
  }

  let self = null;
  try {
    const auth = await requireAuth(req);
    self = fetchUserPosition(auth.user.id, difficulty);
  } catch (_: unknown) {
    self = null;
  }

  return json(
    {
      ...payload,
      self: self
        ? {
            position: self.position,
            nickname: self.nickname,
            score: self.score,
            level: self.level
          }
        : null
    },
    200,
    {
      "cache-control": `private, max-age=${Math.floor(config.leaderboardCacheTtlMs / 1000)}`
    }
  );
}

async function handleSync(req: Request) {
  const auth = await requireAuth(req);
  const body = await readJson(req, syncSchema);
  const touchedDifficulties: string[] = [];
  const now = Date.now();

  const transaction = db.transaction((records: z.infer<typeof syncSchema>["records"]) => {
    for (const record of records) {
      const existing = selectWorldRecord.get(auth.user.id, record.difficulty);
      const shouldUpdate =
        !existing ||
        record.score > existing.score ||
        (record.score === existing.score && record.level > existing.level);

      if (!shouldUpdate) {
        continue;
      }

      touchedDifficulties.push(record.difficulty);
      if (!existing) {
        insertWorldRecord.run(
          crypto.randomUUID(),
          auth.user.id,
          record.difficulty,
          record.score,
          record.level,
          record.playedAtMillis,
          now,
          now
        );
      } else {
        updateWorldRecord.run(
          record.score,
          record.level,
          record.playedAtMillis,
          now,
          existing.id
        );
      }
    }
  });

  transaction(body.records);
  invalidateLeaderboardCache(touchedDifficulties);

  const summary = body.records.map((record) => {
    const self = fetchUserPosition(auth.user.id, record.difficulty);
    return {
      difficulty: record.difficulty,
      position: self?.position ?? null,
      score: self?.score ?? null,
      level: self?.level ?? null
    };
  });

  return json({
    synced: touchedDifficulties,
    summary,
    nicknameRequired: !auth.user.nickname
  });
}

async function handleProfile(req: Request) {
  const auth = await requireAuth(req);
  const positions = difficultySchema.options.map((difficulty) => ({
    difficulty,
    ...(() => {
      const self = fetchUserPosition(auth.user.id, difficulty);
      return {
        position: self?.position ?? null,
        score: self?.score ?? null,
        level: self?.level ?? null
      };
    })()
  }));

  return json({
    ...createSessionPayload(auth.user),
    positions
  });
}

const server = Bun.serve({
  port: config.port,
  idleTimeout: 30,
  async fetch(req, server) {
    if (req.method === "OPTIONS") {
      return withCors(req, new Response(null, { status: 204 }));
    }

    const url = new URL(req.url);
    const rateLimitResponse = enforceRateLimit(req, server, `${req.method}:${url.pathname}`);
    if (rateLimitResponse) {
      return withCors(req, rateLimitResponse);
    }

    try {
      if (req.method === "POST" && url.pathname === "/v1/auth/google") {
        return withCors(req, await handleGoogleAuth(req, server));
      }
      if (req.method === "POST" && url.pathname === "/v1/auth/refresh") {
        return withCors(req, await handleRefresh(req, server));
      }
      if (req.method === "POST" && url.pathname === "/v1/profile/nickname") {
        return withCors(req, await handleNickname(req));
      }
      if (req.method === "GET" && url.pathname.startsWith("/v1/leaderboards/")) {
        return withCors(req, await handleLeaderboard(req));
      }
      if (req.method === "POST" && url.pathname === "/v1/leaderboards/sync") {
        return withCors(req, await handleSync(req));
      }
      if (req.method === "GET" && url.pathname === "/v1/profile") {
        return withCors(req, await handleProfile(req));
      }
      if (req.method === "GET" && url.pathname === "/healthz") {
        return withCors(req, json({ ok: true, now: Date.now() }));
      }

      return withCors(req, json({ error: "not_found", message: "Route not found." }, 404));
    } catch (error) {
      if (error instanceof Response) {
        return withCors(req, error);
      }
      if (error instanceof z.ZodError) {
        return withCors(
          req,
          json(
            {
              error: "validation_error",
              message: "Request payload is invalid.",
              details: error.flatten()
            },
            400
          )
        );
      }
      if (error instanceof Error) {
        return withCors(req, json({ error: "bad_request", message: error.message }, 400));
      }
      return withCors(
        req,
        json({ error: "internal_error", message: "Unexpected server error." }, 500)
      );
    }
  }
});

console.log(`Destroyer2D world API listening on http://localhost:${server.port}`);
