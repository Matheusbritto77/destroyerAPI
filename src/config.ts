const required = (name: string): string => {
  const value = Bun.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

const normalizePem = (value: string): string => value.replace(/\\n/g, "\n");

export const config = {
  port: Number(Bun.env.PORT ?? 3000),
  databasePath: Bun.env.DATABASE_PATH ?? "./data/world-records.sqlite",
  googleClientId: required("GOOGLE_CLIENT_ID"),
  tokenPepper: required("TOKEN_PEPPER"),
  jwtPrivateKeyPem: normalizePem(required("JWT_PRIVATE_KEY_PEM")),
  jwtPublicKeyPem: normalizePem(required("JWT_PUBLIC_KEY_PEM")),
  allowedOrigins: (Bun.env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  accessTokenTtlSeconds: Number(Bun.env.ACCESS_TOKEN_TTL_SECONDS ?? 3600),
  refreshTokenTtlSeconds: Number(Bun.env.REFRESH_TOKEN_TTL_SECONDS ?? 60 * 60 * 24 * 30),
  leaderboardCacheTtlMs: Number(Bun.env.LEADERBOARD_CACHE_TTL_MS ?? 15000)
};

if (config.tokenPepper.length < 32) {
  throw new Error("TOKEN_PEPPER must have at least 32 characters.");
}
