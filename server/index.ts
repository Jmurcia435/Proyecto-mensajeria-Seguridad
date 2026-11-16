import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express, { type NextFunction, type Request, type Response } from 'express'
import cookieParser from 'cookie-parser'
import Database from 'better-sqlite3'

const root = path.dirname(fileURLToPath(import.meta.url))
const isProduction = process.env.NODE_ENV === 'production'
const secureCookies = process.env.COOKIE_SECURE === 'true'
const csrfCookieName = 'cipher_csrf'
const port = Number(process.env.PORT ?? 8787)
const databasePath = process.env.DATABASE_PATH ?? path.join(root, '..', 'data', 'cipher.sqlite')
fs.mkdirSync(path.dirname(databasePath), { recursive: true })
const database = new Database(databasePath)
database.pragma('journal_mode = WAL')
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    signing_public_key TEXT,
    public_key_signature TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    ephemeral_public_key TEXT NOT NULL,
    sent_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS messages_participants ON messages(sender_id, recipient_id, sent_at);
`)
for (const column of [
  'signing_public_key TEXT',
  'public_key_signature TEXT',
]) {
  try {
    database.exec(`ALTER TABLE users ADD COLUMN ${column}`)
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes('duplicate column name')) throw error
  }
}
for (const column of [
  'sender_ciphertext TEXT',
  'sender_iv TEXT',
  'sender_salt TEXT',
  'sender_ephemeral_public_key TEXT',
  'recipient_ciphertext TEXT',
  'recipient_iv TEXT',
  'recipient_salt TEXT',
  'recipient_ephemeral_public_key TEXT',
]) {
  try {
    database.exec(`ALTER TABLE messages ADD COLUMN ${column}`)
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes('duplicate column name')) throw error
  }
}

type AuthenticatedRequest = Request & { user?: { id: number; username: string; publicKey: string; signingPublicKey: string; publicKeySignature: string } }

const app = express()
app.use(express.json({ limit: '32kb' }))
app.use(cookieParser())
app.use((request, response, next) => {
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('X-Frame-Options', 'DENY')
  response.setHeader('Referrer-Policy', 'same-origin')
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
  if (!request.cookies[csrfCookieName]) response.cookie(csrfCookieName, crypto.randomBytes(32).toString('base64url'), { httpOnly: false, sameSite: 'strict', secure: secureCookies, maxAge: 1000 * 60 * 60 * 24, path: '/' })
  if (request.path.startsWith('/api/')) response.setHeader('Cache-Control', 'no-store')
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    const cookieToken = request.cookies[csrfCookieName]
    const headerToken = request.get('X-CSRF-Token')
    if (!cookieToken || !headerToken || cookieToken !== headerToken) return response.status(403).json({ error: 'Token CSRF inválido.' })
  }
  next()
})

const hashPassword = (password: string, salt = crypto.randomBytes(16)) => {
  const hash = crypto.scryptSync(password, salt, 64)
  return `${salt.toString('base64')}.${hash.toString('base64')}`
}
const verifyPassword = (password: string, stored: string) => {
  const [saltValue, hashValue] = stored.split('.')
  if (!saltValue || !hashValue) return false
  const expected = Buffer.from(hashValue, 'base64')
  const actual = crypto.scryptSync(password, Buffer.from(saltValue, 'base64'), expected.length)
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
}
const tokenHash = (token: string) => crypto.createHash('sha256').update(token).digest('hex')
const createSession = (userId: number, response: Response) => {
  const token = crypto.randomBytes(32).toString('base64url')
  database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(tokenHash(token), userId, new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString())
  response.cookie('cipher_session', token, { httpOnly: true, sameSite: 'lax', secure: secureCookies, maxAge: 1000 * 60 * 60 * 24 * 30, path: '/' })
}
const validationError = (response: Response, message: string) => response.status(400).json({ error: message })
const loginAttempts = new Map<string, { failures: number; resetAt: number; blockedUntil: number }>()
const loginAttemptKey = (request: Request, username: string) => `${request.ip}:${username.toLowerCase()}`
const isLoginBlocked = (key: string) => {
  const state = loginAttempts.get(key)
  if (!state) return false
  if (state.blockedUntil > Date.now()) return true
  if (state.resetAt <= Date.now()) loginAttempts.delete(key)
  return false
}
const recordLoginFailure = (key: string) => {
  const now = Date.now()
  const current = loginAttempts.get(key)
  const state = current && current.resetAt > now ? current : { failures: 0, resetAt: now + 15 * 60 * 1000, blockedUntil: 0 }
  state.failures += 1
  if (state.failures >= 5) state.blockedUntil = now + 15 * 60 * 1000
  loginAttempts.set(key, state)
}
const clearLoginFailures = (key: string) => loginAttempts.delete(key)
const verifyIdentitySignature = (publicKey: string, signingPublicKey: string, signature: string) => {
  try {
    return crypto.verify(null, Buffer.from(publicKey, 'base64'), { key: Buffer.from(signingPublicKey, 'base64'), format: 'der', type: 'spki' }, Buffer.from(signature, 'base64'))
  } catch {
    return false
  }
}
const identityFingerprint = (signingPublicKey: string) => crypto.createHash('sha256').update(Buffer.from(signingPublicKey, 'base64')).digest('hex').match(/.{1,4}/g)?.join(' ').toUpperCase() ?? ''

function requireAuth(request: AuthenticatedRequest, response: Response, next: NextFunction) {
  const token = request.cookies.cipher_session as string | undefined
  if (!token) return response.status(401).json({ error: 'Sesión no válida.' })
  const row = database.prepare(`
    SELECT u.id, u.username, u.public_key AS publicKey,
      u.signing_public_key AS signingPublicKey, u.public_key_signature AS publicKeySignature
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(tokenHash(token), new Date().toISOString()) as AuthenticatedRequest['user'] | undefined
  if (!row) return response.status(401).json({ error: 'Sesión expirada.' })
  request.user = row
  next()
}

app.post('/api/auth/register', (request, response) => {
  const { username, password, publicKey, signingPublicKey, publicKeySignature } = request.body as Record<string, unknown>
  if (typeof username !== 'string' || !/^[a-z0-9._-]{3,20}$/.test(username)) return validationError(response, 'Username inválido.')
  if (typeof password !== 'string' || password.length < 8) return validationError(response, 'La contraseña debe tener al menos 8 caracteres.')
  if (typeof publicKey !== 'string' || typeof signingPublicKey !== 'string' || typeof publicKeySignature !== 'string') return validationError(response, 'Faltan las claves de cifrado y firma.')
  if (!verifyIdentitySignature(publicKey, signingPublicKey, publicKeySignature)) return validationError(response, 'La firma de identidad no es válida.')
  try {
    const result = database.prepare('INSERT INTO users (username, password_hash, public_key, encrypted_private_key, signing_public_key, public_key_signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(username, hashPassword(password), publicKey, '', signingPublicKey, publicKeySignature, new Date().toISOString())
    createSession(Number(result.lastInsertRowid), response)
    return response.status(201).json({ id: Number(result.lastInsertRowid), username: username.toLowerCase(), publicKey, signingPublicKey, publicKeySignature, fingerprint: identityFingerprint(signingPublicKey) })
  } catch (error) {
    if (error instanceof Error && error.message.includes('UNIQUE')) return response.status(409).json({ error: 'Ese username ya está en uso.' })
    return response.status(500).json({ error: 'No se pudo crear la cuenta.' })
  }
})

app.post('/api/auth/login', (request, response) => {
  const { username, password } = request.body as Record<string, unknown>
  if (typeof username !== 'string' || typeof password !== 'string') return validationError(response, 'Completa username y contraseña.')
  const attemptKey = loginAttemptKey(request, username)
  if (isLoginBlocked(attemptKey)) return response.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos.' })
  const user = database.prepare('SELECT id, username, public_key AS publicKey, signing_public_key AS signingPublicKey, public_key_signature AS publicKeySignature, password_hash FROM users WHERE username = ? COLLATE NOCASE').get(username) as (AuthenticatedRequest['user'] & { password_hash: string }) | undefined
  if (!user || !verifyPassword(password, user.password_hash)) {
    recordLoginFailure(attemptKey)
    return response.status(401).json({ error: 'Username o contraseña incorrectos.' })
  }
  if (!user.signingPublicKey || !user.publicKeySignature) return response.status(409).json({ error: 'Esta cuenta necesita registrarse de nuevo para activar su identidad segura.' })
  clearLoginFailures(attemptKey)
  createSession(user.id, response)
  return response.json({ id: user.id, username: user.username, publicKey: user.publicKey, signingPublicKey: user.signingPublicKey, publicKeySignature: user.publicKeySignature, fingerprint: identityFingerprint(user.signingPublicKey) })
})

app.post('/api/auth/logout', requireAuth, (request, response) => {
  const token = request.cookies.cipher_session as string
  database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token))
  response.clearCookie('cipher_session', { httpOnly: true, sameSite: 'lax', secure: secureCookies, path: '/' })
  response.status(204).end()
})

app.get('/api/auth/me', requireAuth, (request: AuthenticatedRequest, response) => response.json(request.user))

app.get('/api/users', requireAuth, (request: AuthenticatedRequest, response) => {
  const search = typeof request.query.search === 'string' ? request.query.search.trim() : ''
  const rows = database.prepare('SELECT username, public_key AS publicKey, signing_public_key AS signingPublicKey, public_key_signature AS publicKeySignature FROM users WHERE id != ? AND username LIKE ? COLLATE NOCASE ORDER BY username LIMIT 20').all(request.user!.id, `%${search}%`) as Array<{ username: string; publicKey: string; signingPublicKey: string; publicKeySignature: string; fingerprint?: string }>
  rows.forEach((row) => Object.assign(row, { fingerprint: identityFingerprint(row.signingPublicKey) }))
  response.json(rows)
})

app.get('/api/messages/:username', requireAuth, (request: AuthenticatedRequest, response) => {
  const contact = database.prepare('SELECT id, username, public_key AS publicKey, signing_public_key AS signingPublicKey, public_key_signature AS publicKeySignature FROM users WHERE username = ? COLLATE NOCASE').get(request.params.username) as { id: number; username: string; publicKey: string; signingPublicKey: string; publicKeySignature: string } | undefined
  if (!contact) return response.status(404).json({ error: 'Usuario no encontrado.' })
  const rows = database.prepare(`
    SELECT id, sender_id AS senderId, recipient_id AS recipientId,
      sender_ciphertext AS senderCiphertext, sender_iv AS senderIv,
      sender_salt AS senderSalt,
      sender_ephemeral_public_key AS senderEphemeralPublicKey,
      recipient_ciphertext AS recipientCiphertext, recipient_iv AS recipientIv,
      recipient_salt AS recipientSalt,
      recipient_ephemeral_public_key AS recipientEphemeralPublicKey,
      sent_at AS sentAt
    FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY sent_at ASC
  `).all(request.user!.id, contact.id, contact.id, request.user!.id)
  response.json({ contact: { ...contact, fingerprint: identityFingerprint(contact.signingPublicKey) }, messages: rows })
})

app.post('/api/messages', requireAuth, (request: AuthenticatedRequest, response) => {
  const { recipient, senderCiphertext, senderIv, senderSalt, senderEphemeralPublicKey, recipientCiphertext, recipientIv, recipientSalt, recipientEphemeralPublicKey } = request.body as Record<string, unknown>
  const envelopes = [senderCiphertext, senderIv, senderSalt, senderEphemeralPublicKey, recipientCiphertext, recipientIv, recipientSalt, recipientEphemeralPublicKey]
  if (![recipient, ...envelopes].every((value) => typeof value === 'string' && value.length > 0 && value.length < 10000)) return validationError(response, 'Sobre de mensaje inválido.')
  const target = database.prepare('SELECT id, username FROM users WHERE username = ? COLLATE NOCASE').get(recipient) as { id: number; username: string } | undefined
  if (!target) return response.status(404).json({ error: 'El destinatario no existe.' })
  if (target.id === request.user!.id) return validationError(response, 'No puedes enviarte un mensaje a ti mismo.')
  const message = { id: crypto.randomUUID(), senderId: request.user!.id, recipientId: target.id, senderCiphertext, senderIv, senderSalt, senderEphemeralPublicKey, recipientCiphertext, recipientIv, recipientSalt, recipientEphemeralPublicKey, sentAt: new Date().toISOString() }
  database.prepare(`
    INSERT INTO messages (
      id,       sender_id, recipient_id, ciphertext, iv, ephemeral_public_key,
      sender_ciphertext, sender_iv, sender_salt, sender_ephemeral_public_key,
      recipient_ciphertext, recipient_iv, recipient_salt, recipient_ephemeral_public_key, sent_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(message.id, message.senderId, message.recipientId, message.recipientCiphertext, message.recipientIv, message.recipientEphemeralPublicKey, message.senderCiphertext, message.senderIv, message.senderSalt, message.senderEphemeralPublicKey, message.recipientCiphertext, message.recipientIv, message.recipientSalt, message.recipientEphemeralPublicKey, message.sentAt)
  response.status(201).json(message)
})

if (isProduction) {
  const dist = path.join(root, '..', 'dist')
  app.use(express.static(dist))
  app.use((request, response, next) => {
    if (request.path.startsWith('/api/')) return next()
    response.sendFile(path.join(dist, 'index.html'))
  })
}

app.use((error: unknown, _request: Request, response: Response, next: NextFunction) => {
  if (response.headersSent) return next(error)
  console.error(error)
  response.status(500).json({ error: 'Error interno del servidor.' })
})

app.listen(port, () => console.log(`Cipher API listening on http://localhost:${port}`))
