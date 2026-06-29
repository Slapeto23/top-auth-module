# top-auth-module

**Zjednodušeno k dokonalosti. Propracováno do posledního detailu.**

Nejčistší a nejbezpečnější TypeScript autentizační modul, který reálně používáš v produkci.

Malý povrch (auditovatelný), silné bezpečnostní základy, perfektní developer experience.

## Pro koho je
- Vývojáři, kteří potřebují rychle a správně přidat auth do API / web app
- Next.js, Express, Fastify, custom Node servery
- Každý, kdo nechce 20 závislostí a magic black boxy
- Projekty, kde záleží na typech, bezpečnosti a jednoduchosti

## Co dělá (a proč je TOP)
- Registrace + login s bcrypt hashem
- Access + Refresh tokeny s **rotací** (revoke starý refresh)
- Plná revokace tokenů
- Middleware pro autentizaci a autorizaci (roles)
- User management (get, list, delete)
- Vlastní úložiště uživatelů (default in-memory, připoj libovolnou DB)
- Všechny chyby typované
- Žádné defaultní tajemství — vyžaduje silný secret

## Instalace
```bash
npm install top-auth-module bcryptjs jsonwebtoken
# nebo pnpm / yarn
npm install -D @types/bcryptjs @types/jsonwebtoken typescript
```

## Quickstart (5 vteřin)
```ts
import { AuthModule } from 'top-auth-module'

const auth = new AuthModule({
  secret: process.env.AUTH_SECRET!   // min 32 znaků
})

// Register
await auth.register('petr', 'superTajneHeslo123', 'admin')

// Login
const { accessToken, refreshToken } = await auth.login('petr', 'superTajneHeslo123')

// Verify
const user = auth.verifyToken(accessToken)
console.log(user.username, user.role)
```

## Express middleware
```ts
app.post('/login', async (req, res) => {
  const t = await auth.login(req.body.user, req.body.pass)
  res.json(t)
})

app.get('/me', auth.authenticate(), (req, res) => {
  res.json({ user: req.user })
})

app.get('/admin', auth.authenticate(), auth.authorize('admin'), handler)
```

## Refresh flow (správně)
```ts
const newTokens = auth.refresh(oldRefreshToken)
// starý refresh je automaticky zneplatněn
```

## Použití s vlastním store (DB / Redis)
```ts
const dbStore: UserStore = {
  get: (u) => db.users.findOne({username: u}),
  set: (u, user) => db.users.upsert(...),
  delete: (u) => db.users.remove(u),
  list: () => db.users.findAll()
}
const auth = new AuthModule({ secret: process.env.SECRET! }, dbStore)
```

## API přehled
- `register(username, pass, role?)`
- `login(username, pass)` → {access, refresh, user}
- `verifyToken(token)`
- `refresh(refreshToken)`
- `revoke(token)`
- `authenticate()` — middleware
- `authorize(...roles)` — middleware
- `getUser` / `deleteUser` / `listUsers`

## Bezpečnostní poznámky (důležité)
- VŽY používej silný secret z env (32+ znaků)
- Používej HTTPS
- Nastav správné expirace (krátký access + dlouhý refresh)
- Pro produkci připoj persist store + rate limiting
- Revoke na logout + na refresh rotate

## Proč právě tento
- Žádný zbytečný kód
- Všechny vzory jsou vyzkoušené a zjednodušené
- Plná typová bezpečnost
- Snadno rozšiřitelné
- Stojí za to se tím chlubit

MIT — používej volně.

Vytvořeno s láskou k čistotě a praktičnosti.
