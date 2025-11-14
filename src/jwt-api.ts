import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const PORT = Number(process.env.PORT_JWT || 3001);

interface JwtPayloadCustom {
  sub: string;
  role: "admin" | "user";
}

app.post("/auth/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (username !== "alice" || password !== "password123") {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  const payload: JwtPayloadCustom = {
    sub: "user-123",
    role: "admin"
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });

  res.json({ token });
});

// middleware para verificar JWT
function authenticateJwt(
  req: Request & { user?: JwtPayloadCustom },
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Falta header Authorization" });
  }

  const token = authHeader.substring("Bearer ".length);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayloadCustom;
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "JWT inválido o expirado" });
  }
}

// endpoint protegido
app.get(
  "/api/self",
  authenticateJwt,
  (req: Request & { user?: JwtPayloadCustom }, res: Response) => {
    res.json({
      message: "Acceso concedido vía JWT",
      user: req.user
    });
  }
);

app.listen(PORT, () => {
  console.log(`JWT API escuchando en http://localhost:${PORT}`);
});
