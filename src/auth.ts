import * as bcrypt from 'bcryptjs'
import * as crypto from 'crypto'
import * as jwt from 'jsonwebtoken'

// Types - clean and complete
export interface User {
  username: string
  password: string
  role: string
  createdAt: string
}

export interface AuthOptions {
  secret: string
  tokenExpiry?: string
  refreshTokenExpiry?: string
  saltRounds?: number
}

export interface AuthPayload {
  username: string
  role?: string
  [key: string]: any
}

export interface LoginResult {
  accessToken: string
  refreshToken: string
  user: { username: string; role: string }
}

export interface RegisterResult {
  username: string
  role: string
  createdAt: string
}

export interface UserStore {
  get(username: string): User | undefined
  set(username: string, user: User): void
  delete(username: string): void
  list(): User[]
}

class InMemoryStore implements UserStore {
  private data = new Map<string, User>()
  get(u: string) { return this.data.get(u) }
  set(u: string, user: User) { this.data.set(u, user) }
  delete(u: string) { this.data.delete(u) }
  list() { return Array.from(this.data.values()) }
}

export class AuthError extends Error {
  constructor(message: string, public code: string) {
    super(message)
    this.name = 'AuthError'
  }
}

export class ValidationError extends AuthError {
  constructor(m: string) { super(m, 'VALIDATION') }
}

export class AuthFailure extends AuthError {
  constructor(m = 'Invalid credentials') { super(m, 'AUTH_FAILURE') }
}

export class TokenError extends AuthError {
  constructor(m: string) { super(m, 'TOKEN') }
}

/**
 * top-auth-module — zjednodušeno k dokonalosti
 * 
 * Propracováno:
 * - Security: bcrypt + jwt + revocation + rotate refresh + validace
 * - DX: plné typy, jasné chyby, snadné middleware
 * - Flexibilita: injektovatelné store (pro db)
 * - Žádný bloat, auditovatelné
 * 
 * Pro: Express, Fastify, Next.js API routes, custom servery, cokoliv TS/JS
 */
export class AuthModule {
  private secret: string
  private tokenExpiry: string
  private refreshExpiry: string
  private saltRounds: number
  private users: UserStore
  private revoked = new Set<string>()

  constructor(options: AuthOptions, store?: UserStore) {
    if (!options.secret || options.secret.length < 32) {
      throw new ValidationError('Provide strong secret (min 32 chars) from env')
    }
    this.secret = options.secret
    this.tokenExpiry = options.tokenExpiry || '15m'
    this.refreshExpiry = options.refreshTokenExpiry || '7d'
    this.saltRounds = options.saltRounds || 12
    this.users = store || new InMemoryStore()
  }

  async hashPassword(pw: string): Promise<string> {
    if (!pw || pw.length < 8) throw new ValidationError('Password >= 8 chars')
    return bcrypt.hash(pw, this.saltRounds)
  }

  async comparePassword(pw: string, hash: string): Promise<boolean> {
    if (!pw || !hash) return false
    return bcrypt.compare(pw, hash)
  }

  async register(username: string, password: string, role = 'user'): Promise<RegisterResult> {
    if (!username || username.length < 3) throw new ValidationError('Username >= 3 chars')
    if (this.users.get(username)) throw new AuthFailure('User exists')
    const hashed = await this.hashPassword(password)
    const user: User = { username, password: hashed, role, createdAt: new Date().toISOString() }
    this.users.set(username, user)
    return { username, role, createdAt: user.createdAt }
  }

  async login(username: string, password: string): Promise<LoginResult> {
    const user = this.users.get(username)
    if (!user || !(await this.comparePassword(password, user.password))) {
      throw new AuthFailure()
    }
    const accessToken = this.sign({ username: user.username, role: user.role }, this.tokenExpiry)
    const refreshToken = this.sign({ username: user.username, type: 'refresh' }, this.refreshExpiry)
    return { accessToken, refreshToken, user: { username: user.username, role: user.role } }
  }

  private sign(payload: object, exp: string): string {
    return jwt.sign(payload, this.secret, { expiresIn: exp, jwtid: crypto.randomUUID() })
  }

  verifyToken(token: string): AuthPayload {
    if (!token) throw new TokenError('Token required')
    if (this.revoked.has(token)) throw new TokenError('Revoked')
    try {
      return jwt.verify(token, this.secret) as AuthPayload
    } catch (e: any) {
      if (e.name === 'TokenExpiredError') throw new TokenError('Expired')
      throw new TokenError('Invalid')
    }
  }

  refresh(refreshToken: string): { accessToken: string; refreshToken: string } {
    const d = this.verifyToken(refreshToken) as any
    if (d.type !== 'refresh') throw new TokenError('Not refresh token')
    this.revoked.add(refreshToken)
    const accessToken = this.sign({ username: d.username, role: d.role || 'user' }, this.tokenExpiry)
    const newRefresh = this.sign({ username: d.username, type: 'refresh' }, this.refreshExpiry)
    return { accessToken, refreshToken: newRefresh }
  }

  revoke(token: string): boolean {
    if (!token) return false
    this.revoked.add(token)
    return true
  }

  // Express / Fastify style middleware
  authenticate() {
    return (req: any, res: any, next: any) => {
      const h = req.headers?.authorization
      if (!h) return res.status(401).json({ error: 'No auth' })
      const [type, token] = h.split(' ')
      if (type !== 'Bearer' || !token) return res.status(401).json({ error: 'Bad header' })
      try {
        req.user = this.verifyToken(token)
        next()
      } catch (e: any) {
        res.status(401).json({ error: e.message || 'Auth fail' })
      }
    }
  }

  authorize(...roles: string[]) {
    return (req: any, res: any, next: any) => {
      if (!req.user) return res.status(401).json({ error: 'Auth required' })
      if (roles.length && !roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Forbidden' })
      }
      next()
    }
  }

  // User helpers
  getUser(u: string) {
    const x = this.users.get(u)
    return x ? { username: x.username, role: x.role, createdAt: x.createdAt } : null
  }

  deleteUser(u: string) {
    if (!this.users.get(u)) throw new AuthFailure('Not found')
    this.users.delete(u)
  }

  listUsers() {
    return this.users.list().map(u => ({ username: u.username, role: u.role, createdAt: u.createdAt }))
  }
}

export default AuthModule
