import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
// @ts-ignore
import macaroon from "macaroon";

const app = express();
app.use(express.json());

const MACAROON_SECRET = process.env.MACAROON_SECRET || "dev-macaroon-secret";
const PORT = Number(process.env.PORT_MACAROON || 3002);

// Utilidad para crear un macaroon con caveats
function emitirMacaroon(userId: string) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAt = nowSeconds + 15 * 60; // 15 min

  // location opcional, puede ser la URL de tu API
  const location = "http://localhost:" + PORT;
  const identifier = userId;

  // crear macaroon base
  let m = macaroon.newMacaroon({
    identifier,
    location,
    secret: MACAROON_SECRET
  });

  // caveats de primer partido
  m = m.addFirstPartyCaveat(`role = admin`);
  m = m.addFirstPartyCaveat(`path = /api/secret-macaroons`);
  m = m.addFirstPartyCaveat(`expires <= ${expiresAt}`);

  // serializar para mandar al cliente
  return m.serialize();
}

// login que emite macaroon
app.post("/auth/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (username !== "bob" || password !== "password123") {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  const userId = "user-456";
  const macaroonToken = emitirMacaroon(userId);

  res.json({
    macaroon: macaroonToken,
    note: "Usar este valor en el header Authorization: Macaroon <TOKEN>"
  });
});

// middleware para verificar macaroon
function authenticateMacaroon(
  req: Request & { userId?: string },
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Macaroon ")) {
    return res.status(401).json({ error: "Falta header Authorization Macaroon" });
  }

  const token = authHeader.substring("Macaroon ".length);

  try {
    const m = macaroon.importMacaroon(token);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const requestedPath = req.path;

    // Verificación de firma + caveats “a mano”
    // 1) verificar firma base: si la secret no es la misma, esto falla
    // (según la lib, puede ser m.verify o similar; acá lo simplificamos)
    m.verify(MACAROON_SECRET, (caveat: string) => {
      // esta función se ejecuta por cada caveat, debe devolver true/false
      if (caveat.startsWith("role =")) {
        const [, value] = caveat.split("=");
        const role = value.trim();
        return role === "admin";
      }

      if (caveat.startsWith("path =")) {
        const [, value] = caveat.split("=");
        const path = value.trim();
        return path === requestedPath;
      }

      if (caveat.startsWith("expires <=")) {
        const [, value] = caveat.split("<=");
        const exp = Number(value.trim());
        return nowSeconds <= exp;
      }

      // si aparece una caveat que no conocemos, por seguridad rechazamos
      return false;
    });

    // si no tiró error, está todo OK: el identifier lo tomamos como userId
    req.userId = m.identifier;
    next();
  } catch (err) {
    console.error("Error verificando macaroon:", err);
    return res.status(403).json({ error: "Macaroon inválido o restricciones no cumplidas" });
  }
}

// endpoint protegido por macaroons
app.get(
  "/api/secret-macaroons",
  authenticateMacaroon,
  (req: Request & { userId?: string }, res: Response) => {
    res.json({
      message: "Acceso concedido vía Macaroons",
      userId: req.userId
    });
  }
);

app.listen(PORT, () => {
  console.log(`Macaroons API escuchando en http://localhost:${PORT}`);
});
