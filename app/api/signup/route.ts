import { NextResponse } from 'next/server';
import { pool, SCHEMA } from '@/lib/db';
import {
  hashPassword,
  newUserId,
  newSessionToken,
  createSession,
  cookieString,
  ipOf,
  uaOf,
} from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Byte-compatible with live api_auth_signup: writes control_store.app_users
// (id, email, password_hash[salt:hash], full_name, role, plan, signup_source).
export async function POST(req: Request) {
  let b: any = {};
  try {
    b = await req.json();
  } catch {
    /* ignore */
  }
  const email = ((b.email || '') + '').toLowerCase().trim();
  if (!email || !b.password) {
    return NextResponse.json({ ok: false, error: 'email + password required' }, { status: 400 });
  }

  const ex = await pool.query(`SELECT 1 FROM ${SCHEMA}.app_users WHERE email=$1`, [email]);
  if (ex.rows[0]) {
    return NextResponse.json({ ok: false, error: 'email already registered' }, { status: 409 });
  }

  const uid = newUserId();
  const password_hash = hashPassword(b.password);
  await pool.query(
    `INSERT INTO ${SCHEMA}.app_users (id,email,password_hash,full_name,role,plan,signup_source,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
    [uid, email, password_hash, b.name || b.full_name || null, 'customer', 'free', 'web'],
  );

  const token = newSessionToken();
  await createSession(token, uid, ipOf(req), uaOf(req));

  const res = NextResponse.json({ ok: true, user_id: uid, email, token });
  res.headers.set('Set-Cookie', cookieString(token));
  return res;
}
