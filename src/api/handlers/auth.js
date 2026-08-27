import { generateJWT, verifyJWT, hashPassword, verifyPassword } from '../../core/auth.js';
import { getConfig, setConfig } from '../../data/config.js';
import { getCookieValue } from '../utils.js';

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 300; // 5 分钟

async function checkRateLimit(env, ip) {
  const key = `login_attempts:${ip}`;
  const raw = await env.SUBSCRIPTIONS_KV.get(key);
  const attempts = raw ? parseInt(raw, 10) : 0;
  return attempts >= MAX_LOGIN_ATTEMPTS;
}

async function recordFailedAttempt(env, ip) {
  const key = `login_attempts:${ip}`;
  const raw = await env.SUBSCRIPTIONS_KV.get(key);
  const attempts = (raw ? parseInt(raw, 10) : 0) + 1;
  await env.SUBSCRIPTIONS_KV.put(key, String(attempts), { expirationTtl: LOCKOUT_SECONDS });
  return attempts;
}

async function clearAttempts(env, ip) {
  await env.SUBSCRIPTIONS_KV.delete(`login_attempts:${ip}`);
}

async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

  if (await checkRateLimit(env, ip)) {
    return new Response(
      JSON.stringify({ success: false, message: '登录尝试过多，请 5 分钟后再试' }),
      { status: 429, headers: { 'Content-Type': 'application/json' } }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(
      JSON.stringify({ success: false, message: '请求格式错误' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const config = await getConfig(env);

  // 用户名必须匹配；密码校验兼容历史明文与 PBKDF2 哈希两种存储
  if (body.username === config.ADMIN_USERNAME) {
    const stored = config.ADMIN_PASSWORD;
    let passwordOk = false;
    let needsMigration = false;

    if (typeof stored === 'string' && stored.startsWith('pbkdf2$')) {
      passwordOk = await verifyPassword(body.password, stored);
    } else if (body.password === stored) {
      // 历史明文比对：登录成功后迁移为哈希
      passwordOk = true;
      needsMigration = true;
    }

    if (passwordOk) {
      // 明文密码自动迁移为哈希，不影响本次登录
      if (needsMigration) {
        try {
          const hashed = await hashPassword(body.password);
          await setConfig(env, { ...config, ADMIN_PASSWORD: hashed });
        } catch (err) {
          console.error('[auth] 密码哈希迁移失败（登录仍继续）:', err);
        }
      }
      await clearAttempts(env, ip);
      const token = await generateJWT(body.username, config.JWT_SECRET);

      return new Response(
        JSON.stringify({ success: true }),
        {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': 'token=' + token + '; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=86400'
          }
        }
      );
    }
  }

  const attempts = await recordFailedAttempt(env, ip);
  const remaining = MAX_LOGIN_ATTEMPTS - attempts;
  const message = remaining > 0
    ? `用户名或密码错误（还可尝试 ${remaining} 次）`
    : '登录尝试过多，请 5 分钟后再试';

  return new Response(
    JSON.stringify({ success: false, message }),
    { status: remaining > 0 ? 200 : 429, headers: { 'Content-Type': 'application/json' } }
  );
}

function handleLogout() {
  return new Response('', {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': 'token=; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=0'
    }
  });
}

async function getUserFromRequest(request, env) {
  const token = getCookieValue(request.headers.get('Cookie'), 'token');
  const config = await getConfig(env);
  const user = token ? await verifyJWT(token, config.JWT_SECRET) : null;
  return { user, config };
}

export { handleLogin, handleLogout, getUserFromRequest };
