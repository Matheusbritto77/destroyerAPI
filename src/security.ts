import { createHmac, randomBytes } from "node:crypto";
import {
  SignJWT,
  importPKCS8,
  importSPKI,
  jwtVerify,
  type JWTPayload
} from "jose";
import { config } from "./config";

const privateKey = await importPKCS8(config.jwtPrivateKeyPem, "EdDSA");
const publicKey = await importSPKI(config.jwtPublicKeyPem, "EdDSA");

const hmac = (value: string): string =>
  createHmac("sha256", config.tokenPepper).update(value).digest("hex");

export const security = {
  hashOpaqueToken: hmac,
  hashLocalIdentity(value: string) {
    return hmac(`local-auth:${value}`);
  },
  issueOpaqueRefreshToken() {
    return randomBytes(48).toString("base64url");
  },
  async hashPassword(password: string) {
    return Bun.password.hash(password, {
      algorithm: "argon2id",
      memoryCost: 19456,
      timeCost: 2
    });
  },
  async verifyPassword(password: string, hash: string) {
    return Bun.password.verify(password, hash);
  },
  async issueAccessToken(payload: { sub: string; nicknameSet: boolean }) {
    return new SignJWT({
      scope: "access",
      nicknameSet: payload.nicknameSet
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
      .setIssuedAt()
      .setSubject(payload.sub)
      .setAudience("destroyer2d-mobile")
      .setIssuer("destroyer2d-world-api")
      .setExpirationTime(`${config.accessTokenTtlSeconds}s`)
      .sign(privateKey);
  },
  async verifyAccessToken(token: string): Promise<JWTPayload> {
    const result = await jwtVerify(token, publicKey, {
      issuer: "destroyer2d-world-api",
      audience: "destroyer2d-mobile"
    });

    if (result.payload.scope !== "access") {
      throw new Error("Invalid token scope.");
    }

    return result.payload;
  }
};
