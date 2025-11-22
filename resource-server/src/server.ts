import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

// Same secret as auth-server (for demo only)
const JWT_SECRET = "dev-secret-change-me";
const PORT = 5000;

interface TokenPayload {
  sub: string;
  client_id: string;
  scope: string;
  type: "access" | "refresh";
}

const app = express();
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use(express.json());

// Middleware to validate access token
function authenticate(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" });
  }

  const token = authHeader.slice("Bearer ".length);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
    if (decoded.type !== "access") {
      return res.status(401).json({ error: "invalid_token_type" });
    }

    // attach user info to request
    (req as any).user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// Protected route
app.get("/profile", authenticate, (req: Request, res: Response) => {
  const user = (req as any).user as TokenPayload;

  res.json({
    message: "Secure profile data from Resource Server",
    userId: user.sub,
    clientId: user.client_id,
    scope: user.scope,
    fakeProfile: {
      name: "Muneeb Developer",
      role: "OAuth 2.0 PKCE Jedi",
      country: "Sweden"
    }
  });
});

app.listen(PORT, () => {
  console.log(`Resource server running on http://localhost:${PORT}`);
});
