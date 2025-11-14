require("dotenv").config();
const express = require("express");
const {
  MacaroonsBuilder,
  MacaroonsVerifier,
} = require("macaroons.js");
const { amigos } = require("./data");

const app = express();
app.use(express.json());

const MACAROON_SECRET =
  process.env.MACAROON_SECRET || "dev-macaroon-secret";
const PORT = Number(process.env.PORT_MACAROON || 3002);


function emitirMacaroon(userId) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAt = nowSeconds + 15 * 60; // 15 min

  const location = "http://localhost:" + PORT;
  const secretKey = MACAROON_SECRET;
  const identifier = userId;

  const macaroon = new MacaroonsBuilder(location, secretKey, identifier)
    .add_first_party_caveat("role = admin")
    //    .add_first_party_caveat("path = /api/secret-macaroons")
    .add_first_party_caveat(`expires <= ${expiresAt}`)
    .getMacaroon();

  // Serializamos según la doc (base64url)
  return macaroon.serialize();
}

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;

  if (username !== "bob" || password !== "password123") {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  const userId = "user-456";
  const macaroonToken = emitirMacaroon(userId);

  res.json({
    macaroon: macaroonToken,
  });
});


// -------------------------------------------------------
// Middleware
// -------------------------------------------------------
function authenticateMacaroon(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Macaroon ")) {
    return res
      .status(401)
      .json({ error: "Falta header Authorization Macaroon" });
  }

  const token = authHeader.substring("Macaroon ".length).trim();

  try {

    const m = MacaroonsBuilder.deserialize(token);

    const verifier = new MacaroonsVerifier(m);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const requestedPath = req.path;

    verifier.satisfyGeneral((caveat) => {
      if (typeof caveat !== "string") return false;

      if (caveat.startsWith("role =")) {
        const role = caveat.split("=")[1].trim();
        return role === "admin";
      }

      // if (caveat.startsWith("path =")) {
      //   const path = caveat.split("=")[1].trim();
      //   return path === requestedPath;
      // }

      if (caveat.startsWith("method =")) {
        const method = caveat.split("=")[1].trim();
        // Comparamos el caveat con el método de la petición actual
        return method === req.method;
      }

      if (caveat.startsWith("expires <=")) {
        const exp = Number(caveat.split("<=")[1].trim());
        if (Number.isNaN(exp)) return false;
        return nowSeconds <= exp;
      }

      // Caveat desconocida
      return false;
    });

    const valid = verifier.isValid(MACAROON_SECRET);

    if (!valid) {
      return res.status(403).json({
        error: "Macaroon inválido o restricciones no cumplidas",
      });
    }

    // En macaroons.js el identifier es parte del macaroon
    req.userId = m.identifier;

    next();
  } catch (err) {
    console.error("Error verificando macaroon:", err);
    return res.status(403).json({
      error: "Macaroon inválido o restricciones no cumplidas",
    });
  }
}

// -------------------------------------------------------
// Endpoints protegidos
// -------------------------------------------------------
app.get("/api/amigos", authenticateMacaroon, (req, res) => {
  res.json({
    data: amigos
  });
});

app.post("/api/amigos", authenticateMacaroon, (req, res) => {
  const { nombre, apellido } = req.body;
  if (!nombre || !apellido) res.status(400).json({ message: "Invalid data" });

  amigos.push({ nombre, apellido })
  res.status(200).json({
    data: amigos
  });
});

app.post(
  "/api/amigos/delegate-readonly",
  authenticateMacaroon, // ¡Nos aseguramos de que solo un admin pueda delegar
  (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader.substring("Macaroon ".length).trim();

    try {
      let m = MacaroonsBuilder.deserialize(token);

      // Añadir el nuevo caveat 
      // No se necesita el "secret" para añadir caveats.
      m = new MacaroonsBuilder(m)
        .add_first_party_caveat("method = GET")
        .getMacaroon();

      res.json({
        delegated_macaroon: m.serialize(),
        note: "Este token solo sirve para peticiones GET",
      });
    } catch (err) {
      console.error("Error atenuando macaroon:", err);
      res.status(500).json({ error: "No se pudo delegar el token" });
    }
  }
);

app.listen(PORT, () => {
  console.log(`Macaroons API escuchando en http://localhost:${PORT}`);
});
