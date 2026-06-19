import { NextResponse } from 'next/server';
import { pool, SCHEMA } from '@/lib/db';
import {
  verifyPassword,
  newSessionToken,
  createSession,
  cookieString,
  ipOf,
  uaOf,
} from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

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

  const u = await pool.query(
    `SELECT id, password_salt, password_hash FROM ${SCHEMA}.users WHERE email=$1`,
    [email],
  );
  const row = u.rows[0];
  if (!row || !verifyPassword(b.password, row.password_salt, row.password_hash)) {
    return NextResponse.json({ ok: false, error: 'invalid credentials' }, { status: 401 });
  }

  const token = newSessionToken();
  await createSession(token, row.id, ipOf(req), uaOf(req));

  // best-effort login bookkeeping (columns exist on users)
  pool
    .query(
      `UPDATE ${SCHEMA}.users
         SET last_login_at=NOW(), last_login_ip=$2, login_count=COALESCE(login_count,0)+1
       WHERE id=$1`,
      [row.id, ipOf(req)],
    )
    .catch(() => {});

  const res = NextResponse.json({ ok: true, user_id: row.id, token });
  res.headers.set('Set-Cookie', cookieString(token));
  return res;
}
