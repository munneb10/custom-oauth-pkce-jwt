import express, { Request, Response } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";

// ---------- CONFIG ----------
const PORT = 4000;
const JWT_SECRET = "dev-secret-change-me"; // in real systems use env + strong secret

// Single demo client (your SPA)
const CLIENTS = [
  {
    clientId: "demo-client",
    redirectUris: ["http://localhost:3000/"],
    name: "Demo PKCE Client"
  }
];

// Single demo user
const USERS = [
  {
    id: "user-1",
    username: "muneeb",
    password: "password123",
    name: "Muneeb Developer",
    email: "muneeb@example.com"
  }
];

// ---------- TYPES ----------
interface AuthCodeRecord {
  code: string;
  clientId: string;
  redirectUri: string;
  userId: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: number;
}

interface TokenPayload {
  sub: string; // userId
  client_id: string;
  scope: string;
  type: "access" | "refresh";
}

// ---------- IN-MEMORY STORES ----------
const authCodes = new Map<string, AuthCodeRecord>();

// We use JWT refresh tokens, but you could also use opaque values + store here
const activeRefreshTokens = new Set<string>();

// ---------- EXPRESS SETUP ----------
const app = express();
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---------- HELPER FUNCTIONS ----------

function findClient(clientId: string) {
  return CLIENTS.find((c) => c.clientId === clientId);
}

function findUser(username: string, password: string) {
  return USERS.find((u) => u.username === username && u.password === password);
}

function generateRandomString(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("hex");
}

// Issue a JWT access token
function issueAccessToken(userId: string, clientId: string, scope: string) {
  const payload: TokenPayload = {
    sub: userId,
    client_id: clientId,
    scope,
    type: "access"
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "5m"
  });

  return token;
}

// Issue a JWT refresh token
function issueRefreshToken(userId: string, clientId: string, scope: string) {
  const payload: TokenPayload = {
    sub: userId,
    client_id: clientId,
    scope,
    type: "refresh"
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "7d"
  });

  activeRefreshTokens.add(token);
  return token;
}

// Verify refresh token
function verifyRefreshToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
    if (decoded.type !== "refresh") return null;
    if (!activeRefreshTokens.has(token)) return null;
    return decoded;
  } catch {
    return null;
  }
}

// ---------- AUTHORIZATION ENDPOINT ----------

// Step 1: Client redirects user here with PKCE params
// GET /authorize?response_type=code&client_id=demo-client&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...
app.get("/authorize", (req: Request, res: Response) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    state
  } = req.query;

  if (response_type !== "code") {
    return res.status(400).send("Unsupported response_type");
  }

  if (
    typeof client_id !== "string" ||
    typeof redirect_uri !== "string" ||
    typeof code_challenge !== "string" ||
    typeof code_challenge_method !== "string"
  ) {
    return res.status(400).send("Missing required parameters");
  }

  const client = findClient(client_id);
  if (!client) {
    return res.status(400).send("Unknown client_id");
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send("Invalid redirect_uri");
  }

  if (code_challenge_method !== "S256") {
    return res.status(400).send("Only S256 is supported");
  }

  // Render a simple login form with hidden fields to preserve OAuth params
  const html = `
    <html>
      <body>
        <h2>Login - ${client.name}</h2>
        <form method="POST" action="/authorize">
          <input type="hidden" name="client_id" value="${client_id}" />
          <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
          <input type="hidden" name="code_challenge" value="${code_challenge}" />
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method}" />
          <input type="hidden" name="state" value="${state ?? ""}" />
          <div>
            <label>Username:</label>
            <input name="username" value="muneeb" />
          </div>
          <div>
            <label>Password:</label>
            <input name="password" type="password" value="password123" />
          </div>
          <button type="submit">Login & Authorize</button>
        </form>
      </body>
    </html>
  `;
  res.send(html);
});

// Handle login & issue authorization code
app.post("/authorize", (req: Request, res: Response) => {
  const {
    username,
    password,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    state
  } = req.body;

  if (
    !username ||
    !password ||
    !client_id ||
    !redirect_uri ||
    !code_challenge ||
    !code_challenge_method
  ) {
    return res.status(400).send("Missing fields");
  }

  const user = findUser(username, password);
  if (!user) {
    return res.status(401).send("Invalid credentials");
  }

  const client = findClient(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send("Invalid client or redirect_uri");
  }

  // Create authorization code
  const code = generateRandomString(16);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

  const record: AuthCodeRecord = {
    code,
    clientId: client_id,
    redirectUri: redirect_uri,
    userId: user.id,
    codeChallenge: code_challenge,
    codeChallengeMethod: "S256",
    expiresAt
  };

  authCodes.set(code, record);

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);

  res.redirect(url.toString());
});

// ---------- TOKEN ENDPOINT ----------

// Handles both:
// - authorization_code grant
// - refresh_token grant
app.post("/token", (req: Request, res: Response) => {
  const { grant_type } = req.body;

  if (!grant_type) {
    return res.status(400).json({ error: "invalid_request" });
  }

  if (grant_type === "authorization_code") {
    return handleAuthorizationCodeGrant(req, res);
  }

  if (grant_type === "refresh_token") {
    return handleRefreshTokenGrant(req, res);
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

// --- Authorization Code Grant ---
function handleAuthorizationCodeGrant(req: Request, res: Response) {
  const { code, redirect_uri, client_id, code_verifier } = req.body;

  if (!code || !redirect_uri || !client_id || !code_verifier) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const record = authCodes.get(code);
  if (!record) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  if (record.expiresAt < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({ error: "invalid_grant", error_description: "code expired" });
  }

  if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  // Verify PKCE: S256(code_verifier) == code_challenge
  const hashed = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  if (hashed !== record.codeChallenge) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE mismatch" });
  }

  // Code is one-time-use
  authCodes.delete(code);

  const scope = "openid profile email";

  const access_token = issueAccessToken(record.userId, client_id, scope);
  const refresh_token = issueRefreshToken(record.userId, client_id, scope);
  const expires_in = 5 * 60; // 5 minutes

  return res.status(200).json({
    token_type: "Bearer",
    access_token,
    refresh_token,
    expires_in,
    scope
  });
}

// --- Refresh Token Grant ---
function handleRefreshTokenGrant(req: Request, res: Response) {
  const { refresh_token, client_id } = req.body;

  if (!refresh_token || !client_id) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const payload = verifyRefreshToken(refresh_token);
  if (!payload) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  if (payload.client_id !== client_id) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  // Rotate refresh token (invalidate old, issue new)
  activeRefreshTokens.delete(refresh_token);

  const scope = payload.scope;
  const access_token = issueAccessToken(payload.sub, client_id, scope);
  const new_refresh_token = issueRefreshToken(payload.sub, client_id, scope);
  const expires_in = 5 * 60;

  return res.status(200).json({
    token_type: "Bearer",
    access_token,
    refresh_token: new_refresh_token,
    expires_in,
    scope
  });
}

// ---------- USERINFO ENDPOINT (optional nice-to-have) ----------
app.get("/userinfo", (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" });
  }

  const token = authHeader.slice("Bearer ".length);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
    if (decoded.type !== "access") {
      return res.status(401).json({ error: "invalid_token" });
    }

    const user = USERS.find((u) => u.id === decoded.sub);
    if (!user) {
      return res.status(404).json({ error: "user_not_found" });
    }

    return res.json({
      sub: user.id,
      name: user.name,
      email: user.email
    });
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});
