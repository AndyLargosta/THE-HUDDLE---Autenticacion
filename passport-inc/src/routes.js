const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const db = require("./db");
const {
  requireAuth,
  requireAdmin,
  checkBruteForce,
  registerFailedAttempt,
  resetAttempts,
  generateCsrfToken,
  verifyCsrfToken,
} = require("./middleware");

const router = express.Router();
const SALT_ROUNDS = 10;
const SESSION_HOURS = 24;

// ─── Sanitizar input (anti XSS) ──────────────────────────────────────────────
function sanitize(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// ─── REGISTRO ────────────────────────────────────────────────────────────────
router.post("/register", async (req, res) => {
  try {
    const email = sanitize(req.body.email?.trim());
    const password = req.body.password;

    if (!email || !password)
      return res.status(400).json({ error: "Email y contraseña requeridos" });

    if (password.length < 6)
      return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing)
      return res.status(400).json({ error: "El email ya está registrado" });

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const id = uuidv4();

    db.prepare("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)")
      .run(id, email, password_hash);

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (err) {
    res.status(500).json({ error: "Error al registrar usuario" });
  }
});

// ─── LOGIN ───────────────────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
  try {
    const email = sanitize(req.body.email?.trim());
    const password = req.body.password;
    const mode = req.body.mode || "cookie"; // "cookie" o "jwt"

    if (!email || !password)
      return res.status(400).json({ error: "Email y contraseña requeridos" });

    // Verificar brute force
    let user;
    try {
      user = checkBruteForce(email);
    } catch (err) {
      return res.status(429).json({ error: err.message });
    }

    if (!user)
      return res.status(401).json({ error: "Credenciales inválidas" });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      registerFailedAttempt(email);
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    resetAttempts(email);
    const csrfToken = generateCsrfToken(user.id);

    // Modo Cookie
    if (mode === "cookie") {
      const sessionId = uuidv4();
      const expiresAt = new Date(Date.now() + SESSION_HOURS * 3600000).toISOString();

      db.prepare("INSERT INTO sessions (id, uid, expires_at) VALUES (?, ?, ?)")
        .run(sessionId, user.id, expiresAt);

      res.cookie("sessionId", sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: SESSION_HOURS * 3600000,
      });

      return res.json({
        message: "Login exitoso",
        mode: "cookie",
        user: { id: user.id, email: user.email, role: user.role },
        csrfToken,
      });
    }

    // Modo JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.json({
      message: "Login exitoso",
      mode: "jwt",
      token,
      user: { id: user.id, email: user.email, role: user.role },
      csrfToken,
    });
  } catch (err) {
    console.error("ERROR LOGIN:", err)
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

// ─── LOGOUT ──────────────────────────────────────────────────────────────────
router.post("/logout", requireAuth, (req, res) => {
  const sessionId = req.cookies?.sessionId;
  if (sessionId) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
    res.clearCookie("sessionId");
  }
  res.json({ message: "Sesión cerrada" });
});

// ─── PERFIL (ruta protegida) ──────────────────────────────────────────────────
router.get("/profile", requireAuth, (req, res) => {
  const user = db.prepare("SELECT id, email, role, created_at FROM users WHERE id = ?")
    .get(req.user.id);
  res.json({ user });
});

// ─── CSRF TOKEN (para el frontend) ───────────────────────────────────────────
router.get("/csrf-token", requireAuth, (req, res) => {
  const token = generateCsrfToken(req.user.id);
  res.json({ csrfToken: token });
});

// ─── ADMIN: ver todos los usuarios ───────────────────────────────────────────
router.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(
    "SELECT id, email, role, login_attempts, locked_until, created_at FROM users"
  ).all();
  res.json({ users });
});

// ─── ADMIN: eliminar usuario ──────────────────────────────────────────────────
router.delete("/admin/users/:id", requireAuth, requireAdmin, verifyCsrfToken, (req, res) => {
  const { id } = req.params;
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM csrf_tokens WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ message: "Usuario eliminado" });
});

// ─── ADMIN: ver intentos fallidos ────────────────────────────────────────────
router.get("/admin/failed-attempts", requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(
    "SELECT email, login_attempts, locked_until FROM users WHERE login_attempts > 0"
  ).all();
  res.json({ users });
});

module.exports = router;