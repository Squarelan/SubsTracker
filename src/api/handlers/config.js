import { getConfig, setConfig } from '../../data/config.js';
import { generateRandomSecret, sanitizeNotificationHours } from '../utils.js';
import { hashPassword } from '../../core/auth.js';

// 这些字段可能包含 token/密钥，绝不下发到浏览器
const SECRET_FIELDS = [
  'TG_BOT_TOKEN',
  'NOTIFYX_API_KEY',
  'WEBHOOK_URL',
  'WEBHOOK_HEADERS',
  'WECHATBOT_WEBHOOK',
  'RESEND_API_KEY',
  'BARK_DEVICE_KEY',
  'THIRD_PARTY_API_TOKEN',
  'GOTIFY_APP_TOKEN',
  'SERVERCHAN_SENDKEY',
  'PUSHPLUS_TOKEN',
  'NTFY_TOKEN'
];

function isConfiguredSecret(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function buildSafeConfig(config) {
  const { JWT_SECRET, ADMIN_PASSWORD, ...safeConfig } = config;
  const response = { ...safeConfig };

  // 对每个敏感字段：返回空字符串 + 一个 *_CONFIGURED 标记
  SECRET_FIELDS.forEach((key) => {
    response[`${key}_CONFIGURED`] = isConfiguredSecret(safeConfig[key]);
    response[key] = '';
  });

  return response;
}

function normalizeClearSecretFields(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.filter(item => typeof item === 'string' && item.trim().length > 0).map(item => item.trim());
  }
  if (typeof value === 'string') {
    return value.split(/[,，\s]+/).map(v => v.trim()).filter(Boolean);
  }
  return [];
}

/**
 * 仅当本次请求显式提交了该字段（值 !== undefined）才采用新值；
 * 否则沿用已有配置。避免 || '' 在字段未提交时清空已有配置。
 * 注意：传 '' 会被视为主动清空（因为 '' !== undefined）。
 */
function keepIfUndef(newVal, existingVal) {
  return newVal !== undefined ? newVal : existingVal;
}

function mergeSecretField(existingConfig, newConfig, key, clearSecretFields = []) {
  // 显式清空优先级最高
  if (clearSecretFields.includes(key)) return '';

  const incoming = newConfig?.[key];
  if (typeof incoming !== 'string') return existingConfig?.[key] || '';

  const trimmed = incoming.trim();

  // 兼容旧前端：曾用 "********" 作为占位符，表示不修改
  if (trimmed === '********') return existingConfig?.[key] || '';

  // 安全默认：空字符串不再代表清空（避免前端未回显导致误清空）
  if (!trimmed) return existingConfig?.[key] || '';

  return trimmed;
}

async function handleGetConfig(env) {
  const config = await getConfig(env);
  return new Response(
    JSON.stringify(buildSafeConfig(config)),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

async function handleUpdateConfig(request, env) {
  try {
    const config = await getConfig(env);
    const newConfig = await request.json();
    const clearSecretFields = normalizeClearSecretFields(newConfig?.CLEAR_SECRET_FIELDS);

    const updatedConfig = {
      ...config,
      ADMIN_USERNAME: keepIfUndef(newConfig.ADMIN_USERNAME, config.ADMIN_USERNAME),
      THEME_MODE: keepIfUndef(newConfig.THEME_MODE, 'system'),

      TG_BOT_TOKEN: mergeSecretField(config, newConfig, 'TG_BOT_TOKEN', clearSecretFields),
      TG_CHAT_ID: keepIfUndef(newConfig.TG_CHAT_ID, config.TG_CHAT_ID || ''),
      TG_TOPIC_ID: keepIfUndef(newConfig.TG_TOPIC_ID, config.TG_TOPIC_ID || '') != null
        ? String(keepIfUndef(newConfig.TG_TOPIC_ID, config.TG_TOPIC_ID || '')).trim()
        : '',

      NOTIFYX_API_KEY: mergeSecretField(config, newConfig, 'NOTIFYX_API_KEY', clearSecretFields),

      WEBHOOK_URL: mergeSecretField(config, newConfig, 'WEBHOOK_URL', clearSecretFields),
      WEBHOOK_METHOD: keepIfUndef(newConfig.WEBHOOK_METHOD, config.WEBHOOK_METHOD || 'POST'),
      WEBHOOK_HEADERS: mergeSecretField(config, newConfig, 'WEBHOOK_HEADERS', clearSecretFields),
      WEBHOOK_TEMPLATE: keepIfUndef(newConfig.WEBHOOK_TEMPLATE, config.WEBHOOK_TEMPLATE || ''),

      SHOW_LUNAR: newConfig.SHOW_LUNAR === true,

      WECHATBOT_WEBHOOK: mergeSecretField(config, newConfig, 'WECHATBOT_WEBHOOK', clearSecretFields),
      WECHATBOT_MSG_TYPE: keepIfUndef(newConfig.WECHATBOT_MSG_TYPE, config.WECHATBOT_MSG_TYPE || 'text'),
      WECHATBOT_AT_MOBILES: keepIfUndef(newConfig.WECHATBOT_AT_MOBILES, config.WECHATBOT_AT_MOBILES || ''),
      WECHATBOT_AT_ALL: keepIfUndef(newConfig.WECHATBOT_AT_ALL, config.WECHATBOT_AT_ALL || 'false'),

      RESEND_API_KEY: mergeSecretField(config, newConfig, 'RESEND_API_KEY', clearSecretFields),
      EMAIL_FROM: keepIfUndef(newConfig.EMAIL_FROM, config.EMAIL_FROM || ''),
      EMAIL_FROM_NAME: keepIfUndef(newConfig.EMAIL_FROM_NAME, config.EMAIL_FROM_NAME || '订阅提醒系统'),
      EMAIL_TO: keepIfUndef(newConfig.EMAIL_TO, config.EMAIL_TO || ''),

      BARK_DEVICE_KEY: mergeSecretField(config, newConfig, 'BARK_DEVICE_KEY', clearSecretFields),
      BARK_SERVER: keepIfUndef(newConfig.BARK_SERVER, config.BARK_SERVER || 'https://api.day.app'),
      BARK_IS_ARCHIVE: keepIfUndef(newConfig.BARK_IS_ARCHIVE, config.BARK_IS_ARCHIVE || 'false'),

      GOTIFY_SERVER_URL: keepIfUndef(newConfig.GOTIFY_SERVER_URL, config.GOTIFY_SERVER_URL || '').trim(),
      GOTIFY_APP_TOKEN: mergeSecretField(config, newConfig, 'GOTIFY_APP_TOKEN', clearSecretFields),

      SERVERCHAN_SENDKEY: mergeSecretField(config, newConfig, 'SERVERCHAN_SENDKEY', clearSecretFields),

      PUSHPLUS_TOKEN: mergeSecretField(config, newConfig, 'PUSHPLUS_TOKEN', clearSecretFields),
      PUSHPLUS_TOPIC: keepIfUndef(newConfig.PUSHPLUS_TOPIC, config.PUSHPLUS_TOPIC || '').trim(),
      PUSHPLUS_CHANNEL: keepIfUndef(newConfig.PUSHPLUS_CHANNEL, config.PUSHPLUS_CHANNEL || '').trim(),

      NTFY_SERVER: keepIfUndef(newConfig.NTFY_SERVER, config.NTFY_SERVER || 'https://ntfy.sh').trim() || 'https://ntfy.sh',
      NTFY_TOPIC: keepIfUndef(newConfig.NTFY_TOPIC, config.NTFY_TOPIC || '').trim(),
      NTFY_TOKEN: mergeSecretField(config, newConfig, 'NTFY_TOKEN', clearSecretFields),

      ENABLED_NOTIFIERS: keepIfUndef(newConfig.ENABLED_NOTIFIERS, config.ENABLED_NOTIFIERS || ['notifyx']),
      TIMEZONE: keepIfUndef(newConfig.TIMEZONE, config.TIMEZONE || 'UTC'),

      THIRD_PARTY_API_TOKEN: mergeSecretField(config, newConfig, 'THIRD_PARTY_API_TOKEN', clearSecretFields),

      DEBUG_LOGS: newConfig.DEBUG_LOGS === true,
      PAYMENT_HISTORY_LIMIT: Number.isFinite(Number(newConfig.PAYMENT_HISTORY_LIMIT))
        ? Math.min(1000, Math.max(10, Math.floor(Number(newConfig.PAYMENT_HISTORY_LIMIT))))
        : (config.PAYMENT_HISTORY_LIMIT || 100)
    };

    updatedConfig.NOTIFICATION_HOURS = sanitizeNotificationHours(newConfig.NOTIFICATION_HOURS);

    if (newConfig.ADMIN_PASSWORD) {
      // 改密码时存 PBKDF2 哈希，不再明文落库
      updatedConfig.ADMIN_PASSWORD = await hashPassword(String(newConfig.ADMIN_PASSWORD));
    }

    if (!updatedConfig.JWT_SECRET || updatedConfig.JWT_SECRET === 'your-secret-key') {
      updatedConfig.JWT_SECRET = generateRandomSecret();
      console.log('[安全] 生成新的JWT密钥');
    }

    await setConfig(env, updatedConfig);

    return new Response(
      JSON.stringify({ success: true }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('配置保存错误:', error);
    return new Response(
      JSON.stringify({ success: false, message: '更新配置失败: ' + error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

export { SECRET_FIELDS, handleGetConfig, handleUpdateConfig };
