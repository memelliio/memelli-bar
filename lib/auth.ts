import crypto from 'crypto';
import { pool, SCHEMA } from './db';

// Compatible with control_store.users (the real 57-row table) + app_sessions.
// Password is stored SPLIT across two columns: password_salt + password_hash.
//   password_salt = randomBytes(16).hex  (32 chars)
//   password_hash = scryptSync(pw, salt, 32).hex  (64 chars)

export const COOKIE = 'mio_sess';
export const MAX_AGE = 2592000; // 30 days, seconds

export function hashPassword(pw: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 32).toString('hex');
  return { salt, hash };
}

export function verifyPassword(pw: string, salt: string, hash: string): boolean {
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 32).toString('hex');
  const a = Buffer.from(test, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function newSessionToken(): string {
  return '*sess*' + crypto.randomBytes(24).toString('hex') + '*';
}

export function newUserId(): string {
  return crypto.randomUUID(); // users.id is a UUID string
}

export function cookieString(token: string, maxAge = MAX_AGE): string {
  return `${COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`;
}

export async function createSession(
  token: string,
  userId: string,
  ip: string | null,
  ua: string | null,
) {
  const expires = new Date(Date.now() + 1000 * MAX_AGE);
  await pool.query(
    `INSERT INTO ${SCHEMA}.app_sessions (token, user_id, ip, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5)`,
    [token, userId, ip, ua, expires],
  );
}

export type SessionUser = {
  user_id: string;
  email: string;
  full_name: string | null;
  role: string;
  tier: string | null;
};

export async function userFromToken(token: string | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  const r = await pool.query(
    `SELECT s.user_id, u.email, u.full_name, u.role, u.tier
       FROM ${SCHEMA}.app_sessions s
       JOIN ${SCHEMA}.users u ON u.id = s.user_id
      WHERE s.token = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
    [token],
  );
  return (r.rows[0] as SessionUser) || null;
}

export function ipOf(req: Request): string | null {
  return req.headers.get('x-forwarded-for') || null;
}
export function uaOf(req: Request): string | null {
  return req.headers.get('user-agent') || null;
}
