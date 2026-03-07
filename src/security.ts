import { createHmac, randomBytes } from "node:crypto";
import {
  SignJWT,
  createRemoteJWKSet,
  importPKCS8,
  importSPKI,
  jwtVerify,
  type JWTPayload
} from "jose";
import { config } from "./config";

const googleJwks = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

const privateKey = await importPKCS8(config.jwtPrivateKeyPem, "EdDSA");
const publicKey = await importSPKI(config.jwtPublicKeyPem, "EdDSA");

const hmac = (value: string): string =>
  createHmac("sha256", config.tokenPepper).update(value).digest("hex");

export const security = {
  hashOpaqueToken: hmac,
  hashGoogleSub(sub: string) {
    return hmac(`google-sub:${sub}`);
  },
  issueOpaqueRefreshToken() {
    return randomBytes(48).toString("base64url");
  },
  async verifyGoogleIdToken(idToken: string, nonce: string) {
    const result = await jwtVerify(idToken, googleJwks, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: config.googleClientId
    });

    if (nonce && result.payload.nonce !== nonce) {
      throw new Error("Invalid OAuth nonce.");
    }

    return result.payload;
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
