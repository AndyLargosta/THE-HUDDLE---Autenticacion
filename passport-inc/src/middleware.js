const jwt = require("jsonwebtoken")
const db = require("./db")
const { use } = require("react")

// anti brute-force
const MAX_ATTEMPTS = 5
const LOCK_MINUTES = 15

function checkBruteForce(email) {
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    if (!user) return null

    if (user.locked_until) {
        const lockedUntil = new Date(user.locked_until)
        if (lockedUntil > new Date()) {
            const minutesLeft = Math.ceil((lockedUntil - new Date()) / 60000)
            throw new Error(`Cuenta bloqueada. Intenta en ${minutesLeft} minutos`)
        } else {
            db.prepare("UPDATE user SET login_attempts = 0, locked_until = NULL WHERE email = ?").run(email)
        }
    }

    return user
}

function registerFailedAttempt(email) {
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    if (!user) return 

    const attempts = user.login_attempts + 1

    if (attempts >= MAX_ATTEMPTS) {
        const lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60000).toISOString()
        db.prepare("UPDATE users SET login_attempts = ?, locked_until = ? WHERE email = ?")
            .run(attempts, email)
    }
}

function reserAttempts(email) {
    db.prepare("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE email = ?").run(email)
}

// VERIFICAR AUTENTICACION (Cookie o JWT)
function requireAuth(req, res, next) {
    // JWT
    const authHeader = req.headers["authorization"]
    if (authHeader && authHeader.starsWith("Bearer ")) {
        const token = authHeader.split(" ")[1]
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET)
            req.user = decoded
            return next()
        }   catch {
            return res.status(401).json({error: "Token invalido o"})
        }
    }

    // COOKIE 
    const sessionId = req.cookies?.sessionId
    if (sessionId) {
        const session = db.prepare("SELECT * FROM sessions WHERE id = ?").get(sessionId)
        if (!session || new Date(session.expires_at) < new Date()) {
            return res.status(401).json({error: "Sesion expirada"})
        }
        const user = db.prepare("SELECT id, email, role FROM users WHERE id = ?").get(session.user_id)
        if (!user) return res.status(401).json({error: "Usuario no encontrado"})
            req.user = user
        return next()
    }

    return res.status(401).json({error: "No autenticado"})
}

// verificar rol admin
function requireAdmin(req, res, next) {
    if (req.user?.role !== "admin") {
        return res.status(403).json({error: "Acceso denegado"})
    }
    next()
}

// CSRF
function generateCsrfToken(userId) {
    const { v4: uuidv4} = require("uuid")
    const token = uuidv4()
    db.prepare("INSERT INTO csrf_tokens (token, user_id) VALUES (?, ?").run(token, userId)
    return token
}

function verifyCsrToken(req, res, next) {
    const token = req.headers["x-csrf-token"] || req.body?.csrfToken
    if (!token) return res.status(403).json({error: "CSRF token faltante"})

    const found = db.prepare("SELECT * FROM csrf_tokens WHERE token = ?").get(token)
    if (!found) return res.status(403).json({error: "CSRF token invalido"})

    // eliminar token usado (single-use)
    db.prepare("DELETE FROM csrf_tokens WHERE token = ?").run(token)
    next()
}

module.exports = {
    requireAuth,
    requireAdmin,
    checkBruteForce,
    registerFailedAttempt,
    reserAttempts,
    generateCsrfToken,
    verifyCsrToken
}