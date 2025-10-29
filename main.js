// Telegram Bot for WireGuard Config Generation on Cloudflare Pages
import * as AdminHandlers from './admin-handlers.js';

const TELEGRAM_API = 'https://api.telegram.org/bot';

// Generate random cool filename (8 characters)
function generateCoolFilename() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const coolPrefixes = ['cyber', 'neon', 'nova', 'flux', 'apex', 'vortex', 'quantum', 'stellar'];
  const prefix = coolPrefixes[Math.floor(Math.random() * coolPrefixes.length)];
  let random = '';
  for (let i = 0; i < 8; i++) {
    random += chars[Math.floor(Math.random() * chars.length)];
  }
  return `${prefix}_${random}`;
}

// Generate WireGuard keypair using Curve25519
async function generateWireGuardKeys() {
  // Generate private key (32 random bytes)
  const privateKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(privateKeyBytes);
  
  // Clamp the private key according to Curve25519 spec
  privateKeyBytes[0] &= 248;
  privateKeyBytes[31] &= 127;
  privateKeyBytes[31] |= 64;
  
  // Convert private key to base64
  const privateKey = bytesToBase64(privateKeyBytes);
  
  // Generate public key from private key using X25519
  const publicKeyBytes = await x25519(privateKeyBytes);
  const publicKey = bytesToBase64(publicKeyBytes);
  
  return { privateKey, publicKey };
}

// Convert bytes to base64 (WireGuard format)
function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert base64 to bytes
function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// X25519 scalar multiplication (Curve25519)
async function x25519(scalar) {
  // Base point for Curve25519 (9)
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  
  return curve25519(scalar, basePoint);
}

// Curve25519 scalar multiplication implementation
function curve25519(n, p) {
  const P = 2n ** 255n - 19n;
  const A24 = 121665n;
  
  // Convert inputs to BigInt
  const nBigInt = bytesToBigInt(n);
  const pBigInt = bytesToBigInt(p);
  
  // Montgomery ladder
  let x1 = pBigInt;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = pBigInt;
  let z3 = 1n;
  let swap = 0n;
  
  for (let t = 254; t >= 0; t--) {
    const kt = (nBigInt >> BigInt(t)) & 1n;
    swap ^= kt;
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    swap = kt;
    
    const A = modAdd(x2, z2, P);
    const AA = modMul(A, A, P);
    const B = modSub(x2, z2, P);
    const BB = modMul(B, B, P);
    const E = modSub(AA, BB, P);
    const C = modAdd(x3, z3, P);
    const D = modSub(x3, z3, P);
    const DA = modMul(D, A, P);
    const CB = modMul(C, B, P);
    
    x3 = modMul(modAdd(DA, CB, P), modAdd(DA, CB, P), P);
    z3 = modMul(x1, modMul(modSub(DA, CB, P), modSub(DA, CB, P), P), P);
    x2 = modMul(AA, BB, P);
    z2 = modMul(E, modAdd(AA, modMul(A24, E, P), P), P);
  }
  
  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);
  
  // Compute result = x2 * z2^(p-2) mod p
  const result = modMul(x2, modInverse(z2, P), P);
  
  return bigIntToBytes(result);
}

// Helper functions for BigInt operations
function bytesToBigInt(bytes) {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result |= BigInt(bytes[i]) << BigInt(8 * i);
  }
  return result;
}

function bigIntToBytes(bigint) {
  const bytes = new Uint8Array(32);
  let n = bigint;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return bytes;
}

function modAdd(a, b, p) {
  return (a + b) % p;
}

function modSub(a, b, p) {
  return (a - b + p) % p;
}

function modMul(a, b, p) {
  return (a * b) % p;
}

function modInverse(a, p) {
  // Fermat's little theorem: a^(p-2) mod p
  return modPow(a, p - 2n, p);
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

function cswap(swap, a, b) {
  const dummy = swap * (a ^ b);
  a ^= dummy;
  b ^= dummy;
  return [a, b];
}

// Generate client IP from CIDR ranges
async function generateClientIP(userId, country, env) {
  // Get CIDR ranges for country
  const ranges = await getCIDRRanges(env, country);
  
  // Always include default range
  const allRanges = ['10.66.0.0/32', ...ranges];
  
  // Select random range
  const selectedRange = allRanges[Math.floor(Math.random() * allRanges.length)];
  
  // Parse CIDR
  const [baseIP, prefix] = selectedRange.split('/');
  const prefixNum = parseInt(prefix);
  
  // For /32, use the exact IP
  if (prefixNum === 32) {
    return baseIP;
  }
  
  // For other ranges, generate random IP within range
  const parts = baseIP.split('.').map(Number);
  const hostBits = 32 - prefixNum;
  const maxHosts = Math.pow(2, hostBits) - 2; // -2 for network and broadcast
  const hostNum = (userId % maxHosts) + 1;
  
  // Calculate IP
  let ip = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  ip = (ip & ~((1 << hostBits) - 1)) | hostNum;
  
  return [
    (ip >>> 24) & 0xFF,
    (ip >>> 16) & 0xFF,
    (ip >>> 8) & 0xFF,
    ip & 0xFF
  ].join('.');
}

// Get CIDR ranges for country
async function getCIDRRanges(env, country) {
  const rangesKey = `cidr:${country}`;
  const data = await env.DB.get(rangesKey);
  
  if (!data) return [];
  
  try {
    const ranges = JSON.parse(data);
    return ranges.ranges || [];
  } catch {
    return [];
  }
}

// Save CIDR ranges for country
async function saveCIDRRanges(env, country, ranges) {
  const rangesKey = `cidr:${country}`;
  await env.DB.put(rangesKey, JSON.stringify({
    country,
    ranges,
    updatedAt: new Date().toISOString()
  }));
}

// DNS Providers
const DNS_PROVIDERS = {
  'radar': {
    name: '📡 رادار',
    dns: '10.202.10.10, 10.202.10.11'
  },
  'cloudflare_google': {
    name: '🌐 کلودفلر + گوگل',
    dns: '1.1.1.1, 8.8.8.8'
  },
  'opendns': {
    name: '🔓 OpenDNS',
    dns: '208.67.222.222, 208.67.220.220'
  },
  'electro': {
    name: '⚡ الکترو',
    dns: '78.157.42.100, 78.157.42.101'
  },
  'shecan': {
    name: '🔐 شکن',
    dns: '178.22.122.100, 185.51.200.2'
  },
  'pishgaman': {
    name: '🚀 پیشگامان',
    dns: '5.202.100.100, 5.202.100.101'
  },
  'shatel': {
    name: '📶 شاتل',
    dns: '85.15.1.14, 85.15.1.15'
  },
  '403': {
    name: '🛡️ 403',
    dns: '10.202.10.202, 10.202.10.102'
  },
  'begzar': {
    name: '🌟 بگذر',
    dns: '185.55.226.26, 185.55.225.25'
  },
  'hostiran': {
    name: '💻 هاست ایران',
    dns: '172.29.0.100, 172.29.2.100'
  }
};

// Get DNS keyboard with better layout
function getDNSKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '🌍 ' + DNS_PROVIDERS.cloudflare_google.name, callback_data: 'wg_dns_cloudflare_google' }
      ],
      [
        { text: '🔒 ' + DNS_PROVIDERS.opendns.name, callback_data: 'wg_dns_opendns' }
      ],
      [
        { text: '📡 ' + DNS_PROVIDERS.radar.name, callback_data: 'wg_dns_radar' }
      ],
      [
        { text: '⚡ ' + DNS_PROVIDERS.electro.name, callback_data: 'wg_dns_electro' }
      ],
      [
        { text: '🔓 ' + DNS_PROVIDERS.shecan.name, callback_data: 'wg_dns_shecan' }
      ],
      [
        { text: '🌐 ' + DNS_PROVIDERS.pishgaman.name, callback_data: 'wg_dns_pishgaman' }
      ],
      [
        { text: '📶 ' + DNS_PROVIDERS.shatel.name, callback_data: 'wg_dns_shatel' }
      ],
      [
        { text: '🚀 ' + DNS_PROVIDERS['403'].name, callback_data: 'wg_dns_403' }
      ],
      [
        { text: '🔑 ' + DNS_PROVIDERS.begzar.name, callback_data: 'wg_dns_begzar' }
      ],
      [
        { text: '☁️ ' + DNS_PROVIDERS.hostiran.name, callback_data: 'wg_dns_hostiran' }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'back_to_main' }
      ]
    ]
  };
}

// Get keepalive keyboard
function getKeepaliveKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '✅ فعال (توصیه می‌شود)', callback_data: 'keepalive_on' },
        { text: '❌ غیرفعال', callback_data: 'keepalive_off' }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'back_to_main' }
      ]
    ]
  };
}

// Create WireGuard config
function createWireGuardConfig(privateKey, publicKey, clientIP, serverPublicKey, serverEndpoint, dnsServers, keepalive = true) {
  let config = `[Interface]
PrivateKey = ${privateKey}
Address = ${clientIP}/32
DNS = ${dnsServers}

[Peer]
PublicKey = ${serverPublicKey}
Endpoint = ${serverEndpoint}
AllowedIPs = 0.0.0.0/0`;

  if (keepalive) {
    config += `\nPersistentKeepalive = 25`;
  }
  
  return config;
}

// Send message to Telegram
async function sendTelegramMessage(botToken, chatId, text, replyMarkup = null) {
  const url = `${TELEGRAM_API}${botToken}/sendMessage`;
  const body = {
    chat_id: chatId,
    text: text,
    parse_mode: 'HTML'
  };
  if (replyMarkup) body.reply_markup = replyMarkup;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return response.json();
}

// Send document to Telegram
async function sendTelegramDocument(botToken, chatId, filename, content, caption) {
  const url = `${TELEGRAM_API}${botToken}/sendDocument`;
  
  const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
  const parts = [];
  
  parts.push(`--${boundary}\r\n`);
  parts.push(`Content-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`);
  
  parts.push(`--${boundary}\r\n`);
  parts.push(`Content-Disposition: form-data; name="document"; filename="${filename}"\r\n`);
  parts.push(`Content-Type: text/plain\r\n\r\n`);
  parts.push(`${content}\r\n`);
  
  if (caption) {
    parts.push(`--${boundary}\r\n`);
    parts.push(`Content-Disposition: form-data; name="caption"\r\n\r\n${caption}\r\n`);
    parts.push(`--${boundary}\r\n`);
    parts.push(`Content-Disposition: form-data; name="parse_mode"\r\n\r\nHTML\r\n`);
  }
  
  parts.push(`--${boundary}--\r\n`);
  
  const body = parts.join('');
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
    body: body
  });
  return response.json();
}

// Answer callback query
async function answerCallbackQuery(botToken, callbackQueryId, text = '') {
  const url = `${TELEGRAM_API}${botToken}/answerCallbackQuery`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      callback_query_id: callbackQueryId,
      text: text,
      show_alert: false
    })
  });
}

// Get main keyboard
function getMainKeyboard(isAdmin = false) {
  const keyboard = [
    [
      { text: '🔐 وایرگارد', callback_data: 'wireguard' },
      { text: '🌐 DNS', callback_data: 'dns' }
    ],
    [
      { text: '👤 حساب کاربری', callback_data: 'account' }
    ]
  ];
  
  if (isAdmin) {
    keyboard.push([{ text: '⚙️ پنل ادمین', callback_data: 'admin_panel' }]);
  }
  
  return { inline_keyboard: keyboard };
}

// Get admin panel keyboard
function getAdminKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '📢 پیام همگانی', callback_data: 'admin_broadcast' },
        { text: '📊 آمار کامل', callback_data: 'admin_stats' }
      ],
      [
        { text: '🌐 مدیریت Endpoint', callback_data: 'admin_endpoints' },
        { text: '🔗 لیست Endpoint', callback_data: 'admin_list_endpoints' }
      ],
      [
        { text: '➕ افزودن DNS', callback_data: 'admin_add_dns' },
        { text: '📋 لیست DNS', callback_data: 'admin_list_dns' }
      ],
      [
        { text: '📐 مدیریت CIDR', callback_data: 'admin_cidr' },
        { text: '📋 لیست CIDR', callback_data: 'admin_list_cidr' }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'back_to_main' }
      ]
    ]
  };
}

// Get country keyboard for DNS/Endpoint selection
function getCountryKeyboard(type) {
  return {
    inline_keyboard: [
      [
        { text: '🇨🇦 کانادا', callback_data: `country_CA_${type}` },
        { text: '🇶🇦 قطر', callback_data: `country_QA_${type}` },
        { text: '🇧🇪 بلژیک', callback_data: `country_BE_${type}` }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'admin_panel' }
      ]
    ]
  };
}

// Get country keyboard with availability info
async function getCountryKeyboardWithAvailability(env, type) {
  const countries = ['CA', 'QA', 'BE'];
  
  // Get all endpoints and DNS
  const endpointsList = await env.DB.list({ prefix: 'endpoint:' });
  const dnsList = await env.DB.list({ prefix: 'dns:' });
  
  // Count by country
  const availability = {};
  for (const country of countries) {
    availability[country] = { endpoints: 0, dns: 0 };
  }
  
  for (const key of endpointsList.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const ep = JSON.parse(data);
      if (availability[ep.country]) {
        availability[ep.country].endpoints++;
      }
    }
  }
  
  for (const key of dnsList.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const dns = JSON.parse(data);
      if (availability[dns.country]) {
        availability[dns.country].dns++;
      }
    }
  }
  
  // Build keyboard with availability
  const keyboard = [];
  
  // Single row with 3 countries
  keyboard.push([
    { text: `🇨🇦 کانادا (${availability.CA.endpoints}/${availability.CA.dns})`, callback_data: `country_CA_${type}` },
    { text: `🇶🇦 قطر (${availability.QA.endpoints}/${availability.QA.dns})`, callback_data: `country_QA_${type}` },
    { text: `🇧🇪 بلژیک (${availability.BE.endpoints}/${availability.BE.dns})`, callback_data: `country_BE_${type}` }
  ]);
  
  // Back button
  keyboard.push([
    { text: '🔙 بازگشت', callback_data: 'back_to_main' }
  ]);
  
  return { inline_keyboard: keyboard };
}

// Get country flag
function getCountryFlag(countryCode) {
  const flags = {
    'CA': '🇨🇦',
    'QA': '🇶🇦',
    'BE': '🇧🇪'
  };
  return flags[countryCode] || '🌍';
}

// Get country name
function getCountryName(countryCode) {
  const names = {
    'CA': 'کانادا',
    'QA': 'قطر',
    'BE': 'بلژیک'
  };
  return names[countryCode] || 'نامشخص';
}

// Handle WireGuard button - show country selection with availability
async function handleWireGuardButton(chatId, userId, username, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `🔐 <b>ساخت کانفیگ WireGuard</b>\n\n🌍 لطفاً لوکیشن (کشور) مورد نظر خود را انتخاب کنید:\n\n💡 <i>اعداد نشان‌دهنده تعداد Endpoint و DNS موجود هستند</i>`;
  
  const keyboard = await getCountryKeyboardWithAvailability(env, 'wg_location');
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, keyboard);
}

// Handle WireGuard location selection
async function handleWireGuardLocation(chatId, userId, username, country, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  await env.DB.put(`session:${chatId}:wg_country`, country, { expirationTtl: 300 });
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  const message = `${flag} <b>${countryName}</b>\n\n🌐 <b>انتخاب سرویس DNS</b>\n\n💡 <i>DNS مناسب خود را انتخاب کنید:\n\n🌍 بین‌المللی - برای دسترسی جهانی\n📡 ایرانی - برای سرعت بیشتر در ایران</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getDNSKeyboard());
}

// Handle DNS selection - ask about keepalive
async function handleWireGuardDNSSelection(chatId, userId, username, dnsProvider, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  // Store DNS provider
  await env.DB.put(`session:${chatId}:wg_dns`, dnsProvider, { expirationTtl: 300 });
  
  const dnsName = DNS_PROVIDERS[dnsProvider].name;
  const message = `${dnsName}\n\n⏱️ <b>PersistentKeepalive</b>\n\nآیا می‌خواهید قابلیت PersistentKeepalive فعال باشد؟\n\n<i>این قابلیت اتصال را پایدار نگه می‌دارد و برای اکثر کاربران توصیه می‌شود.</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getKeepaliveKeyboard());
}

// Handle keepalive selection and generate config
async function handleKeepaliveSelection(chatId, userId, username, keepalive, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId, '🔄 در حال ساخت کانفیگ...');
  
  try {
    // Get selected country and DNS
    const country = await env.DB.get(`session:${chatId}:wg_country`) || 'US';
    const dnsProvider = await env.DB.get(`session:${chatId}:wg_dns`) || 'cloudflare_google';
    
    await env.DB.delete(`session:${chatId}:wg_country`);
    await env.DB.delete(`session:${chatId}:wg_dns`);
    
    // Generate keys
    const { privateKey, publicKey } = await generateWireGuardKeys();
    const clientIP = await generateClientIP(userId, country, env);
    
    // Get random endpoint for selected country
    const endpoint = await getRandomEndpoint(env, country);
    
    if (!endpoint) {
      await sendTelegramMessage(
        env.BOT_TOKEN,
        chatId,
        '⚠️ متأسفانه Endpoint برای این کشور موجود نیست. لطفاً کشور دیگری انتخاب کنید.',
        getMainKeyboard(isAdmin(userId, env))
      );
      return;
    }
    
    const serverPublicKey = env.WG_SERVER_PUBLIC_KEY || 'YOUR_SERVER_PUBLIC_KEY';
    
    // Get DNS servers
    const dnsServers = DNS_PROVIDERS[dnsProvider].dns;
    const dnsName = DNS_PROVIDERS[dnsProvider].name;
    
    // Create config with keepalive option
    const config = createWireGuardConfig(privateKey, publicKey, clientIP, serverPublicKey, endpoint.address, dnsServers, keepalive);
    
    // Increment endpoint usage
    await incrementEndpointUsage(env, endpoint.id);
    
    // Save to KV
    const configData = {
      userId,
      username,
      publicKey,
      clientIP,
      dnsProvider,
      country,
      endpoint: endpoint.address,
      keepalive,
      createdAt: new Date().toISOString()
    };
    
    await env.DB.put(
      `user:${userId}`,
      JSON.stringify(configData),
      { expirationTtl: 86400 * 30 }
    );
    
    // Update stats
    await incrementStat(env, 'total_configs');
    
    // Generate cool filename
    const filename = `${generateCoolFilename()}.conf`;
    
    const flag = getCountryFlag(country);
    const countryName = getCountryName(country);
    
    const keepaliveStatus = keepalive ? '✅ فعال' : '❌ غیرفعال';
    
    // Send config as file
    const caption = `✨ <b>کانفیگ WireGuard شما آماده است</b>\n\n🎯 نام فایل: <code>${filename}</code>\n${flag} لوکیشن: ${countryName}\n🌐 IP: <code>${clientIP}</code>\n${dnsName} DNS: فعال\n⏱️ Keepalive: ${keepaliveStatus}\n⏰ ${new Date().toLocaleString('fa-IR')}`;
    
    await sendTelegramDocument(env.BOT_TOKEN, chatId, filename, config, caption);
    
    // Send back to main menu
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '🏠 منوی اصلی:',
      getMainKeyboard(isAdmin(userId, env))
    );
    
  } catch (error) {
    console.error('Error generating config:', error);
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '❌ خطا در ساخت کانفیگ. لطفاً دوباره تلاش کنید.',
      getMainKeyboard(isAdmin(userId, env))
    );
  }
}

// Handle DNS button - show available DNS by country
async function handleDNSButton(chatId, userId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `🌐 <b>انتخاب DNS</b>

لطفاً نوع DNS مورد نظر خود را انتخاب کنید:`;
  
  const keyboard = {
    inline_keyboard: [
      [
        { text: '📡 IPv4', callback_data: 'user_dns_ipv4' },
        { text: '📡 IPv6', callback_data: 'user_dns_ipv6' }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'back_to_main' }
      ]
    ]
  };
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, keyboard);
}

// Handle user DNS type selection
async function handleUserDNSType(chatId, userId, type, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `📍 <b>انتخاب کشور برای DNS ${type === 'ipv4' ? 'IPv4' : 'IPv6'}</b>

لطفاً کشور مورد نظر را انتخاب کنید:`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getCountryKeyboard(`user_${type}`));
}

// Handle user country selection for DNS
async function handleUserDNSCountry(chatId, userId, country, type, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId, '🔍 در حال جستجو...');
  
  const dnsType = type.replace('user_', '');
  const availableDNS = await getDNSByCountry(env, country, dnsType);
  
  if (availableDNS.length === 0) {
    const flag = getCountryFlag(country);
    const countryName = getCountryName(country);
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      `${flag} <b>${countryName}</b>\n\n⚠️ متأسفانه DNS ${dnsType === 'ipv4' ? 'IPv4' : 'IPv6'} برای این کشور موجود نیست.`,
      getMainKeyboard(isAdmin(userId, env))
    );
    return;
  }
  
  // Get first available DNS
  const dns = availableDNS[0];
  const deleted = await incrementDNSUsage(env, dns.id);
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  const typeLabel = dnsType === 'ipv4' ? 'IPv4' : 'IPv6';
  
  let message = `${flag} <b>DNS ${typeLabel} - ${countryName}</b>\n\n`;
  message += `📡 آدرس: <code>${dns.address}</code>\n\n`;
  
  if (deleted) {
    message += `✅ این DNS به شما اختصاص یافت و از لیست حذف شد.`;
  } else {
    const remaining = 3 - (dns.usageCount || 0);
    message += `📊 تعداد باقیمانده: ${remaining} نفر`;
  }
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getMainKeyboard(isAdmin(userId, env)));
}

// Handle Account button
async function handleAccountButton(chatId, userId, username, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  try {
    const userData = await env.DB.get(`user:${userId}`);
    
    if (userData) {
      const data = JSON.parse(userData);
      const accountMessage = `👤 <b>اطلاعات حساب کاربری</b>

🆔 شناسه: <code>${userId}</code>
👨‍💻 نام کاربری: ${username ? '@' + username : 'ندارد'}
🌐 IP اختصاصی: <code>${data.clientIP}</code>
🔑 کلید عمومی: <code>${data.publicKey.substring(0, 30)}...</code>
📅 تاریخ ثبت: ${new Date(data.createdAt).toLocaleString('fa-IR')}

✅ وضعیت: فعال`;
      
      await sendTelegramMessage(env.BOT_TOKEN, chatId, accountMessage, getMainKeyboard());
    } else {
      await sendTelegramMessage(
        env.BOT_TOKEN,
        chatId,
        '⚠️ شما هنوز کانفیگی ساخته‌اید. از دکمه 🔐 وایرگارد استفاده کنید.',
        getMainKeyboard()
      );
    }
  } catch (error) {
    console.error('Error fetching account:', error);
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '❌ خطا در دریافت اطلاعات حساب.',
      getMainKeyboard()
    );
  }
}

// Increment stat
async function incrementStat(env, key) {
  try {
    const current = await env.DB.get(`stat:${key}`);
    const value = current ? parseInt(current) + 1 : 1;
    await env.DB.put(`stat:${key}`, value.toString());
  } catch (error) {
    console.error('Error incrementing stat:', error);
  }
}

// Get random endpoint for country
async function getRandomEndpoint(env, country) {
  const list = await env.DB.list({ prefix: `endpoint:${country}:` });
  const availableEndpoints = [];
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const endpoint = JSON.parse(data);
      if (endpoint.usageCount < 5) {
        availableEndpoints.push({ id: key.name, ...endpoint });
      }
    }
  }
  
  if (availableEndpoints.length === 0) return null;
  return availableEndpoints[Math.floor(Math.random() * availableEndpoints.length)];
}

// Increment endpoint usage
async function incrementEndpointUsage(env, endpointId) {
  const data = await env.DB.get(endpointId);
  if (!data) return;
  
  const endpoint = JSON.parse(data);
  endpoint.usageCount = (endpoint.usageCount || 0) + 1;
  
  if (endpoint.usageCount >= 5) {
    await env.DB.delete(endpointId);
  } else {
    await env.DB.put(endpointId, JSON.stringify(endpoint));
  }
}

// Check if user is admin
function isAdmin(userId, env) {
  return userId.toString() === env.ADMIN_ID;
}

// Save DNS to KV
async function saveDNS(env, dnsData) {
  const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
  await env.DB.put(dnsId, JSON.stringify(dnsData));
  return dnsId;
}

// Get all DNS by country and type
async function getDNSByCountry(env, country, type) {
  const list = await env.DB.list({ prefix: 'dns:' });
  const dnsItems = [];
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const dns = JSON.parse(data);
      if (dns.country === country && dns.type === type && dns.usageCount < 3) {
        dnsItems.push({ id: key.name, ...dns });
      }
    }
  }
  
  return dnsItems;
}

// Get DNS by ID
async function getDNSById(env, dnsId) {
  const data = await env.DB.get(dnsId);
  return data ? JSON.parse(data) : null;
}

// Increment DNS usage
async function incrementDNSUsage(env, dnsId) {
  const dns = await getDNSById(env, dnsId);
  if (!dns) return false;
  
  dns.usageCount = (dns.usageCount || 0) + 1;
  
  if (dns.usageCount >= 3) {
    // Delete DNS after 3 uses
    await env.DB.delete(dnsId);
    return true; // DNS deleted
  } else {
    // Update usage count
    await env.DB.put(dnsId, JSON.stringify(dns));
    return false; // DNS still available
  }
}

// Handle admin panel
async function handleAdminPanel(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const adminMessage = `⚙️ <b>پنل مدیریت ادمین</b>

🎛️ از دکمه‌های زیر برای مدیریت ربات استفاده کنید:`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, adminMessage, getAdminKeyboard());
}

// Handle add DNS - step 1: choose type
async function handleAdminAddDNS(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `➕ <b>افزودن DNS جدید</b>

لطفاً نوع DNS را انتخاب کنید:`;
  
  const keyboard = {
    inline_keyboard: [
      [
        { text: '📡 IPv4', callback_data: 'admin_dns_type_ipv4' },
        { text: '📡 IPv6', callback_data: 'admin_dns_type_ipv6' }
      ],
      [
        { text: '🔙 بازگشت', callback_data: 'admin_panel' }
      ]
    ]
  };
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, keyboard);
}

// Handle DNS type selection
async function handleDNSTypeSelection(chatId, type, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  // Store the type in user session (using KV)
  await env.DB.put(`session:${chatId}:dns_type`, type, { expirationTtl: 300 });
  
  const message = `📍 <b>انتخاب کشور برای DNS ${type === 'ipv4' ? 'IPv4' : 'IPv6'}</b>

لطفاً کشور مورد نظر را انتخاب کنید:`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getCountryKeyboard(type));
}

// Handle country selection for DNS
async function handleDNSCountrySelection(chatId, country, type, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  // Store country in session
  await env.DB.put(`session:${chatId}:dns_country`, country, { expirationTtl: 300 });
  await env.DB.put(`session:${chatId}:dns_type`, type, { expirationTtl: 300 });
  await env.DB.put(`session:${chatId}:waiting_dns`, 'true', { expirationTtl: 300 });
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  const typeLabel = type === 'ipv4' ? 'IPv4' : 'IPv6';
  
  const message = `${flag} <b>افزودن DNS ${typeLabel} برای ${countryName}</b>

📝 لطفاً لیست آدرس‌های DNS را ارسال کنید:

<i>فرمت: هر خط یک آدرس
مثال برای IPv4:
1.1.1.1
8.8.8.8
9.9.9.9

مثال برای IPv6:
2606:4700:4700::1111
2001:4860:4860::8888</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message);
}

// Handle list DNS
async function handleAdminListDNS(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const list = await env.DB.list({ prefix: 'dns:' });
  
  if (list.keys.length === 0) {
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '📋 <b>لیست DNS</b>\n\n⚠️ هیچ DNS ثبت شده‌ای وجود ندارد.',
      getAdminKeyboard()
    );
    return;
  }
  
  let message = '📋 <b>لیست DNS های ثبت شده</b>\n\n';
  
  // Group by country
  const byCountry = {};
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const dns = JSON.parse(data);
      if (!byCountry[dns.country]) {
        byCountry[dns.country] = { ipv4: [], ipv6: [] };
      }
      byCountry[dns.country][dns.type].push(dns);
    }
  }
  
  for (const [country, types] of Object.entries(byCountry)) {
    const flag = getCountryFlag(country);
    const countryName = getCountryName(country);
    message += `\n${flag} <b>${countryName}</b>\n`;
    
    if (types.ipv4.length > 0) {
      message += `  📡 IPv4:\n`;
      types.ipv4.forEach(dns => {
        message += `    • <code>${dns.address}</code> (${dns.usageCount || 0}/3)\n`;
      });
    }
    
    if (types.ipv6.length > 0) {
      message += `  📡 IPv6:\n`;
      types.ipv6.forEach(dns => {
        message += `    • <code>${dns.address}</code> (${dns.usageCount || 0}/3)\n`;
      });
    }
  }
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getAdminKeyboard());
}

// Handle CIDR management
async function handleAdminCIDR(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `📐 <b>مدیریت CIDR Range</b>\n\n📍 لطفاً کشور مورد نظر را انتخاب کنید:`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getCountryKeyboard('cidr'));
}

// Handle CIDR country selection
async function handleCIDRCountrySelection(chatId, country, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  await env.DB.put(`session:${chatId}:cidr_country`, country, { expirationTtl: 300 });
  await env.DB.put(`session:${chatId}:waiting_cidr`, 'true', { expirationTtl: 300 });
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  
  const message = `${flag} <b>افزودن CIDR Range برای ${countryName}</b>\n\n📝 لطفاً لیست CIDR Range ها را ارسال کنید:\n\n<i>فرمت: هر خط یک CIDR\nمثال:\n10.66.0.0/24\n172.16.0.0/16\n192.168.1.0/24\n\nنکته: Range پیش‌فرض 10.66.0.0/32 همیشه اضافه می‌شود</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message);
}

// Handle list CIDR
async function handleAdminListCIDR(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const list = await env.DB.list({ prefix: 'cidr:' });
  
  if (list.keys.length === 0) {
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '📐 <b>لیست CIDR Range</b>\n\n⚠️ هیچ CIDR ثبت شده‌ای وجود ندارد.',
      getAdminKeyboard()
    );
    return;
  }
  
  let message = '📐 <b>لیست CIDR Range های ثبت شده</b>\n\n';
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const cidr = JSON.parse(data);
      const flag = getCountryFlag(cidr.country);
      const countryName = getCountryName(cidr.country);
      message += `\n${flag} <b>${countryName}</b>\n`;
      message += `  • پیش‌فرض: <code>10.66.0.0/32</code>\n`;
      cidr.ranges.forEach(range => {
        message += `  • <code>${range}</code>\n`;
      });
    }
  }
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getAdminKeyboard());
}

// Handle admin stats
async function handleAdminStats(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const stats = await getBotStats(env);
  const dnsList = await env.DB.list({ prefix: 'dns:' });
  const endpointsList = await env.DB.list({ prefix: 'endpoint:' });
  const cidrList = await env.DB.list({ prefix: 'cidr:' });
  
  const message = `📊 <b>آمار کامل ربات</b>\n\n👥 کل کاربران: <b>${stats.totalUsers}</b>\n🔐 کل کانفیگ‌ها: <b>${stats.totalConfigs}</b>\n🌐 کل DNS ها: <b>${dnsList.keys.length}</b>\n🔗 کل Endpoint ها: <b>${endpointsList.keys.length}</b>\n📐 کل CIDR ها: <b>${cidrList.keys.length}</b>\n💾 وضعیت KV: ${stats.kvStatus}\n📡 وضعیت ربات: ${stats.uptime}\n⏰ آخرین بروزرسانی: ${new Date(stats.timestamp).toLocaleString('fa-IR')}`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getAdminKeyboard());
}

// Handle /start command
async function handleStartCommand(chatId, userId, env) {
  await incrementStat(env, 'total_users');
  
  const welcomeMessage = `🎉 <b>به ربات WireGuard خوش آمدید!</b>

✨ این ربات به شما کمک می‌کند تا به راحتی کانفیگ WireGuard دریافت کنید.

🔽 از دکمه‌های زیر استفاده کنید:`;

  const isAdminUser = isAdmin(userId, env);
  await sendTelegramMessage(env.BOT_TOKEN, chatId, welcomeMessage, getMainKeyboard(isAdminUser));
}

// Main update handler
export async function handleUpdate(update, env, ctx) {
  try {
    // Handle callback queries (button presses)
    if (update.callback_query) {
      const callbackQuery = update.callback_query;
      const chatId = callbackQuery.message.chat.id;
      const userId = callbackQuery.from.id;
      const username = callbackQuery.from.username;
      const data = callbackQuery.data;
      
      // Main menu buttons
      if (data === 'wireguard') {
        await handleWireGuardButton(chatId, userId, username, env, callbackQuery.id);
      } else if (data.startsWith('country_') && data.includes('_wg_location')) {
        const country = data.replace('country_', '').replace('_wg_location', '');
        await handleWireGuardLocation(chatId, userId, username, country, env, callbackQuery.id);
      } else if (data.startsWith('wg_dns_')) {
        const dnsProvider = data.replace('wg_dns_', '');
        await handleWireGuardDNSSelection(chatId, userId, username, dnsProvider, env, callbackQuery.id);
      } else if (data === 'keepalive_on' || data === 'keepalive_off') {
        const keepalive = data === 'keepalive_on';
        await handleKeepaliveSelection(chatId, userId, username, keepalive, env, callbackQuery.id);
      } else if (data === 'dns') {
        await handleDNSButton(chatId, userId, env, callbackQuery.id);
      } else if (data === 'account') {
        await handleAccountButton(chatId, userId, username, env, callbackQuery.id);
      }
      // Admin panel
      else if (data === 'admin_panel') {
        if (isAdmin(userId, env)) {
          await handleAdminPanel(chatId, env, callbackQuery.id);
        }
      } else if (data === 'admin_broadcast') {
        if (isAdmin(userId, env)) {
          await AdminHandlers.handleAdminBroadcast(chatId, env, callbackQuery.id, answerCallbackQuery, sendTelegramMessage);
        }
      } else if (data === 'admin_endpoints') {
        if (isAdmin(userId, env)) {
          await AdminHandlers.handleAdminEndpoints(chatId, env, callbackQuery.id, answerCallbackQuery, sendTelegramMessage, getCountryKeyboard);
        }
      } else if (data === 'admin_list_endpoints') {
        if (isAdmin(userId, env)) {
          await AdminHandlers.handleAdminListEndpoints(chatId, env, callbackQuery.id, answerCallbackQuery, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName);
        }
      } else if (data.startsWith('country_') && data.includes('_endpoint')) {
        if (isAdmin(userId, env)) {
          const country = data.replace('country_', '').replace('_endpoint', '');
          await AdminHandlers.handleEndpointCountrySelection(chatId, country, env, callbackQuery.id, answerCallbackQuery, sendTelegramMessage, getCountryFlag, getCountryName);
        }
      } else if (data === 'admin_add_dns') {
        if (isAdmin(userId, env)) {
          await handleAdminAddDNS(chatId, env, callbackQuery.id);
        }
      } else if (data === 'admin_list_dns') {
        if (isAdmin(userId, env)) {
          await handleAdminListDNS(chatId, env, callbackQuery.id);
        }
      } else if (data === 'admin_stats') {
        if (isAdmin(userId, env)) {
          await handleAdminStats(chatId, env, callbackQuery.id);
        }
      } else if (data === 'admin_cidr') {
        if (isAdmin(userId, env)) {
          await handleAdminCIDR(chatId, env, callbackQuery.id);
        }
      } else if (data === 'admin_list_cidr') {
        if (isAdmin(userId, env)) {
          await handleAdminListCIDR(chatId, env, callbackQuery.id);
        }
      } else if (data.startsWith('country_') && data.includes('_cidr')) {
        if (isAdmin(userId, env)) {
          const country = data.replace('country_', '').replace('_cidr', '');
          await handleCIDRCountrySelection(chatId, country, env, callbackQuery.id);
        }
      } else if (data === 'admin_dns_type_ipv4' || data === 'admin_dns_type_ipv6') {
        if (isAdmin(userId, env)) {
          const type = data.replace('admin_dns_type_', '');
          await handleDNSTypeSelection(chatId, type, env, callbackQuery.id);
        }
      } else if (data.startsWith('country_') && (data.includes('_ipv4') || data.includes('_ipv6'))) {
        if (isAdmin(userId, env)) {
          const parts = data.replace('country_', '').split('_');
          const country = parts[0];
          const type = parts[1];
          await handleDNSCountrySelection(chatId, country, type, env, callbackQuery.id);
        } else {
          // User DNS selection
          const parts = data.replace('country_', '').split('_');
          const country = parts[0];
          const type = parts[1].replace('user_', '');
          await handleUserDNSCountry(chatId, userId, country, type, env, callbackQuery.id);
        }
      } else if (data === 'user_dns_ipv4' || data === 'user_dns_ipv6') {
        const type = data.replace('user_dns_', '');
        await handleUserDNSType(chatId, userId, type, env, callbackQuery.id);
      } else if (data === 'back_to_main') {
        await answerCallbackQuery(env.BOT_TOKEN, callbackQuery.id);
        await sendTelegramMessage(
          env.BOT_TOKEN,
          chatId,
          '🏠 منوی اصلی:',
          getMainKeyboard(isAdmin(userId, env))
        );
      }
      return;
    }
    
    // Handle messages
    const message = update.message;
    if (!message || !message.text) return;
    
    const chatId = message.chat.id;
    const userId = message.from.id;
    const username = message.from.username;
    const text = message.text.trim();
    
    // Check if admin is sending broadcast
    const waitingBroadcast = await env.DB.get(`session:${chatId}:waiting_broadcast`);
    if (waitingBroadcast === 'true' && isAdmin(userId, env)) {
      await env.DB.delete(`session:${chatId}:waiting_broadcast`);
      await AdminHandlers.processBroadcast(chatId, text, env, sendTelegramMessage, getAdminKeyboard, isAdmin);
      return;
    }
    
    // Check if admin is adding endpoints
    const waitingEndpoints = await env.DB.get(`session:${chatId}:waiting_endpoints`);
    if (waitingEndpoints === 'true' && isAdmin(userId, env)) {
      await env.DB.delete(`session:${chatId}:waiting_endpoints`);
      await env.DB.delete(`session:${chatId}:endpoint_country`);
      await AdminHandlers.processEndpoints(chatId, text, env, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName);
      return;
    }
    
    // Check if admin is adding CIDR
    const waitingCIDR = await env.DB.get(`session:${chatId}:waiting_cidr`);
    if (waitingCIDR === 'true' && isAdmin(userId, env)) {
      const country = await env.DB.get(`session:${chatId}:cidr_country`);
      
      await env.DB.delete(`session:${chatId}:waiting_cidr`);
      await env.DB.delete(`session:${chatId}:cidr_country`);
      
      // Parse CIDR ranges
      const lines = text.split('\n').filter(line => line.trim());
      const validRanges = [];
      
      for (const line of lines) {
        const trimmed = line.trim();
        // Validate CIDR format
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(trimmed)) {
          validRanges.push(trimmed);
        }
      }
      
      if (validRanges.length > 0) {
        await saveCIDRRanges(env, country, validRanges);
        
        const flag = getCountryFlag(country);
        const countryName = getCountryName(country);
        
        await sendTelegramMessage(
          env.BOT_TOKEN,
          chatId,
          `✅ <b>CIDR Range ها اضافه شدند</b>\n\n${flag} کشور: ${countryName}\n✔️ تعداد: ${validRanges.length}\n\n📐 Range ها:\n${validRanges.map(r => `  • <code>${r}</code>`).join('\n')}`,
          getAdminKeyboard()
        );
      } else {
        await sendTelegramMessage(
          env.BOT_TOKEN,
          chatId,
          '❌ هیچ CIDR معتبری یافت نشد. فرمت صحیح: 10.66.0.0/24',
          getAdminKeyboard()
        );
      }
      return;
    }
    
    // Check if admin is adding DNS (now supports multiple lines)
    const waitingDNS = await env.DB.get(`session:${chatId}:waiting_dns`);
    if (waitingDNS === 'true' && isAdmin(userId, env)) {
      await env.DB.delete(`session:${chatId}:waiting_dns`);
      await env.DB.delete(`session:${chatId}:dns_type`);
      await env.DB.delete(`session:${chatId}:dns_country`);
      await AdminHandlers.processDNSList(chatId, text, env, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName);
      return;
    }
    
    // Handle commands
    if (text === '/start') {
      await handleStartCommand(chatId, userId, env);
    } else {
      await sendTelegramMessage(
        env.BOT_TOKEN,
        chatId,
        '❓ از دکمه‌های زیر استفاده کنید:',
        getMainKeyboard(isAdmin(userId, env))
      );
    }
  } catch (error) {
    console.error('Error handling update:', error);
  }
}

// Get bot stats
async function getBotStats(env) {
  try {
    const totalConfigs = await env.DB.get('stat:total_configs') || '0';
    const totalUsers = await env.DB.get('stat:total_users') || '0';
    
    // Test KV connection
    const kvStatus = await testKVConnection(env);
    
    return {
      totalConfigs: parseInt(totalConfigs),
      totalUsers: parseInt(totalUsers),
      kvStatus: kvStatus ? '✅ متصل' : '❌ قطع',
      uptime: '✅ فعال',
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      totalConfigs: 0,
      totalUsers: 0,
      kvStatus: '❌ خطا',
      uptime: '⚠️ نامشخص',
      timestamp: new Date().toISOString(),
      error: error.message
    };
  }
}

// Test KV connection
async function testKVConnection(env) {
  try {
    await env.DB.put('health_check', Date.now().toString(), { expirationTtl: 60 });
    const value = await env.DB.get('health_check');
    return value !== null;
  } catch (error) {
    return false;
  }
}

// Generate web panel
function generateWebPanel() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پنل مدیریت ربات WireGuard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      background: rgba(255, 255, 255, 0.95);
      border-radius: 20px;
      padding: 30px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }
    h1 { color: #667eea; text-align: center; margin-bottom: 30px; font-size: 2.5em; }
    .tabs { display: flex; gap: 10px; margin-bottom: 30px; border-bottom: 2px solid #eee; }
    .tab { padding: 15px 30px; background: none; border: none; cursor: pointer; font-size: 1.1em; color: #666; border-bottom: 3px solid transparent; transition: all 0.3s; }
    .tab.active { color: #667eea; border-bottom-color: #667eea; font-weight: bold; }
    .tab:hover { color: #667eea; }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2); }
    .stat-value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
    .stat-label { font-size: 1.1em; opacity: 0.9; }
    .section { background: #f8f9fa; padding: 25px; border-radius: 15px; margin-bottom: 20px; }
    .section h2 { color: #333; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; }
    th, td { padding: 15px; text-align: right; border-bottom: 1px solid #eee; }
    th { background: #667eea; color: white; font-weight: bold; }
    tr:hover { background: #f5f5f5; }
    .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-size: 1em; transition: all 0.3s; margin: 5px; }
    .btn-primary { background: #667eea; color: white; }
    .btn-primary:hover { background: #5568d3; }
    .btn-danger { background: #e74c3c; color: white; }
    .btn-danger:hover { background: #c0392b; }
    .btn-success { background: #27ae60; color: white; }
    .btn-success:hover { background: #229954; }
    .loading { text-align: center; padding: 40px; color: #667eea; font-size: 1.2em; }
    .empty-state { text-align: center; padding: 60px 20px; color: #999; }
    .action-buttons { display: flex; gap: 10px; margin-bottom: 20px; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center; }
    .modal.active { display: flex; }
    .modal-content { background: white; padding: 30px; border-radius: 15px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
    .modal-content h3 { color: #667eea; margin-bottom: 20px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; margin-bottom: 8px; color: #333; font-weight: bold; }
    .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 1em; font-family: inherit; }
    .form-group input:focus, .form-group select:focus, .form-group textarea:focus { outline: none; border-color: #667eea; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🤖 پنل مدیریت ربات WireGuard</h1>
    <div class="stats-grid" id="stats">
      <div class="stat-card"><div class="stat-label">👥 کل کاربران</div><div class="stat-value" id="totalUsers">-</div></div>
      <div class="stat-card"><div class="stat-label">🔐 کل کانفیگ‌ها</div><div class="stat-value" id="totalConfigs">-</div></div>
      <div class="stat-card"><div class="stat-label">🌐 کل DNS ها</div><div class="stat-value" id="totalDNS">-</div></div>
      <div class="stat-card"><div class="stat-label">🔗 کل Endpoint ها</div><div class="stat-value" id="totalEndpoints">-</div></div>
      <div class="stat-card"><div class="stat-label">💾 وضعیت KV</div><div class="stat-value" id="kvStatus">-</div></div>
    </div>
    <div class="tabs">
      <button class="tab active" onclick="switchTab('dns')">🌐 مدیریت DNS</button>
      <button class="tab" onclick="switchTab('endpoints')">🔗 مدیریت Endpoint</button>
      <button class="tab" onclick="switchTab('cidr')">📐 مدیریت CIDR</button>
    </div>
    <div id="dns-tab" class="tab-content active">
      <div class="section">
        <h2>🌐 مدیریت DNS</h2>
        <div class="action-buttons">
          <button class="btn btn-success" onclick="showAddDNSModal()">➕ افزودن DNS</button>
          <button class="btn btn-primary" onclick="loadDNS()">🔄 بروزرسانی</button>
        </div>
        <div id="dnsList" class="loading">در حال بارگذاری...</div>
      </div>
    </div>
    <div id="endpoints-tab" class="tab-content">
      <div class="section">
        <h2>🔗 مدیریت Endpoint</h2>
        <div class="action-buttons">
          <button class="btn btn-success" onclick="showAddEndpointModal()">➕ افزودن Endpoint</button>
          <button class="btn btn-primary" onclick="loadEndpoints()">🔄 بروزرسانی</button>
        </div>
        <div id="endpointsList" class="loading">در حال بارگذاری...</div>
      </div>
    </div>
    <div id="cidr-tab" class="tab-content">
      <div class="section">
        <h2>📐 مدیریت CIDR Range</h2>
        <div class="action-buttons">
          <button class="btn btn-success" onclick="showAddCIDRModal()">➕ افزودن CIDR</button>
          <button class="btn btn-primary" onclick="loadCIDR()">🔄 بروزرسانی</button>
        </div>
        <div id="cidrList" class="loading">در حال بارگذاری...</div>
      </div>
    </div>
  </div>
  
  <!-- Add DNS Modal -->
  <div id="addDNSModal" class="modal" onclick="if(event.target===this) closeModal('addDNSModal')">
    <div class="modal-content">
      <h3>➕ افزودن DNS</h3>
      <form onsubmit="addDNS(event)">
        <div class="form-group">
          <label>کشور:</label>
          <select id="dnsCountry" required></select>
        </div>
        <div class="form-group">
          <label>نوع:</label>
          <select id="dnsType" required>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
          </select>
        </div>
        <div class="form-group">
          <label>آدرس DNS (هر خط یکی):</label>
          <textarea id="dnsAddresses" rows="5" placeholder="1.1.1.1&#10;8.8.8.8" required></textarea>
        </div>
        <div class="action-buttons">
          <button type="submit" class="btn btn-primary">✅ ذخیره</button>
          <button type="button" class="btn btn-danger" onclick="closeModal('addDNSModal')">❌ انصراف</button>
        </div>
      </form>
    </div>
  </div>
  
  <!-- Add Endpoint Modal -->
  <div id="addEndpointModal" class="modal" onclick="if(event.target===this) closeModal('addEndpointModal')">
    <div class="modal-content">
      <h3>➕ افزودن Endpoint</h3>
      <form onsubmit="addEndpoint(event)">
        <div class="form-group">
          <label>کشور:</label>
          <select id="endpointCountry" required></select>
        </div>
        <div class="form-group">
          <label>آدرس Endpoint (هر خط یکی):</label>
          <textarea id="endpointAddresses" rows="5" placeholder="1.2.3.4:51820&#10;5.6.7.8:51820" required></textarea>
        </div>
        <div class="action-buttons">
          <button type="submit" class="btn btn-primary">✅ ذخیره</button>
          <button type="button" class="btn btn-danger" onclick="closeModal('addEndpointModal')">❌ انصراف</button>
        </div>
      </form>
    </div>
  </div>
  
  <!-- Add CIDR Modal -->
  <div id="addCIDRModal" class="modal" onclick="if(event.target===this) closeModal('addCIDRModal')">
    <div class="modal-content">
      <h3>➕ افزودن CIDR Range</h3>
      <form onsubmit="addCIDR(event)">
        <div class="form-group">
          <label>کشور:</label>
          <select id="cidrCountry" required></select>
        </div>
        <div class="form-group">
          <label>CIDR Range ها (هر خط یکی):</label>
          <textarea id="cidrRanges" rows="5" placeholder="10.100.0.0/24&#10;172.16.0.0/16" required></textarea>
        </div>
        <div class="action-buttons">
          <button type="submit" class="btn btn-primary">✅ ذخیره</button>
          <button type="button" class="btn btn-danger" onclick="closeModal('addCIDRModal')">❌ انصراف</button>
        </div>
      </form>
    </div>
  </div>
  <script>
    function switchTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById(tab + '-tab').classList.add('active');
      if (tab === 'dns') loadDNS();
      if (tab === 'endpoints') loadEndpoints();
      if (tab === 'cidr') loadCIDR();
    }
    async function loadStats() {
      try {
        const r = await fetch('/api/stats');
        const d = await r.json();
        document.getElementById('totalUsers').textContent = d.totalUsers || 0;
        document.getElementById('totalConfigs').textContent = d.totalConfigs || 0;
        document.getElementById('totalDNS').textContent = d.totalDNS || 0;
        document.getElementById('totalEndpoints').textContent = d.totalEndpoints || 0;
        document.getElementById('kvStatus').innerHTML = d.kvStatus || '❓';
      } catch (e) { console.error(e); }
    }
    async function loadCountries() {
      try {
        const r = await fetch('/api/countries/list');
        const countries = await r.json();
        return countries.map(c => \`<option value="\${c.code}">\${c.flag} \${c.name}</option>\`).join('');
      } catch (e) {
        return '<option value="">خطا در بارگذاری</option>';
      }
    }
    function showAddDNSModal() {
      loadCountries().then(html => {
        document.getElementById('dnsCountry').innerHTML = html;
        document.getElementById('addDNSModal').classList.add('active');
      });
    }
    function showAddEndpointModal() {
      loadCountries().then(html => {
        document.getElementById('endpointCountry').innerHTML = html;
        document.getElementById('addEndpointModal').classList.add('active');
      });
    }
    function showAddCIDRModal() {
      loadCountries().then(html => {
        document.getElementById('cidrCountry').innerHTML = html;
        document.getElementById('addCIDRModal').classList.add('active');
      });
    }
    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }
    async function loadDNS() {
      const c = document.getElementById('dnsList');
      c.innerHTML = '<div class="loading">در حال بارگذاری...</div>';
      try {
        const r = await fetch('/api/dns/list');
        const d = await r.json();
        if (d.length === 0) { c.innerHTML = '<div class="empty-state">هیچ DNS ثبت شده‌ای وجود ندارد</div>'; return; }
        let h = '<table><thead><tr><th>کشور</th><th>نوع</th><th>آدرس</th><th>استفاده</th><th>عملیات</th></tr></thead><tbody>';
        d.forEach(dns => {
          h += \`<tr><td>\${dns.flag} \${dns.countryName}</td><td>\${dns.type === 'ipv4' ? 'IPv4' : 'IPv6'}</td><td><code>\${dns.address}</code></td><td>\${dns.usageCount}/3</td><td><button class="btn btn-danger" onclick="deleteDNS('\${dns.id}')">🗑️</button></td></tr>\`;
        });
        h += '</tbody></table>';
        c.innerHTML = h;
      } catch (e) { c.innerHTML = '<div class="empty-state">خطا در بارگذاری</div>'; }
    }
    async function loadEndpoints() {
      const c = document.getElementById('endpointsList');
      c.innerHTML = '<div class="loading">در حال بارگذاری...</div>';
      try {
        const r = await fetch('/api/endpoints/list');
        const d = await r.json();
        if (d.length === 0) { c.innerHTML = '<div class="empty-state">هیچ Endpoint ثبت شده‌ای وجود ندارد</div>'; return; }
        let h = '<table><thead><tr><th>کشور</th><th>آدرس</th><th>استفاده</th><th>عملیات</th></tr></thead><tbody>';
        d.forEach(ep => {
          h += \`<tr><td>\${ep.flag} \${ep.countryName}</td><td><code>\${ep.address}</code></td><td>\${ep.usageCount}/5</td><td><button class="btn btn-danger" onclick="deleteEndpoint('\${ep.id}')">🗑️</button></td></tr>\`;
        });
        h += '</tbody></table>';
        c.innerHTML = h;
      } catch (e) { c.innerHTML = '<div class="empty-state">خطا در بارگذاری</div>'; }
    }
    async function deleteDNS(id) {
      if (!confirm('حذف شود؟')) return;
      try {
        await fetch('/api/dns/delete/' + id, { method: 'DELETE' });
        alert('✅ حذف شد');
        loadDNS();
        loadStats();
      } catch (e) { alert('❌ خطا'); }
    }
    async function deleteEndpoint(id) {
      if (!confirm('حذف شود؟')) return;
      try {
        await fetch('/api/endpoints/delete/' + id, { method: 'DELETE' });
        alert('✅ حذف شد');
        loadEndpoints();
        loadStats();
      } catch (e) { alert('❌ خطا'); }
    }
    async function loadCIDR() {
      const c = document.getElementById('cidrList');
      c.innerHTML = '<div class="loading">در حال بارگذاری...</div>';
      try {
        const r = await fetch('/api/cidr/list');
        const d = await r.json();
        if (d.length === 0) { c.innerHTML = '<div class="empty-state">هیچ CIDR ثبت شده‌ای وجود ندارد</div>'; return; }
        let h = '<table><thead><tr><th>کشور</th><th>Range ها</th><th>عملیات</th></tr></thead><tbody>';
        d.forEach(cidr => {
          const ranges = cidr.ranges.map(r => \`<code>\${r}</code>\`).join('<br>');
          h += \`<tr><td>\${cidr.flag} \${cidr.countryName}</td><td>\${ranges}</td><td><button class="btn btn-danger" onclick="deleteCIDR('\${cidr.country}')">🗑️</button></td></tr>\`;
        });
        h += '</tbody></table>';
        c.innerHTML = h;
      } catch (e) { c.innerHTML = '<div class="empty-state">خطا در بارگذاری</div>'; }
    }
    async function deleteCIDR(country) {
      if (!confirm('حذف شود؟')) return;
      try {
        await fetch('/api/cidr/delete/' + country, { method: 'DELETE' });
        alert('✅ حذف شد');
        loadCIDR();
        loadStats();
      } catch (e) { alert('❌ خطا'); }
    }
    async function addDNS(e) {
      e.preventDefault();
      const country = document.getElementById('dnsCountry').value;
      const type = document.getElementById('dnsType').value;
      const addresses = document.getElementById('dnsAddresses').value.split('\\n').filter(l => l.trim());
      
      let successCount = 0;
      for (const address of addresses) {
        try {
          const r = await fetch('/api/dns/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ country, type, address: address.trim() })
          });
          if (r.ok) successCount++;
        } catch (e) {}
      }
      
      closeModal('addDNSModal');
      alert(\`✅ \${successCount} DNS اضافه شد\`);
      loadDNS();
      loadStats();
      document.getElementById('dnsAddresses').value = '';
    }
    async function addEndpoint(e) {
      e.preventDefault();
      const country = document.getElementById('endpointCountry').value;
      const addresses = document.getElementById('endpointAddresses').value.split('\\n').filter(l => l.trim());
      
      let successCount = 0;
      for (const address of addresses) {
        try {
          const r = await fetch('/api/endpoints/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ country, address: address.trim() })
          });
          if (r.ok) successCount++;
        } catch (e) {}
      }
      
      closeModal('addEndpointModal');
      alert(\`✅ \${successCount} Endpoint اضافه شد\`);
      loadEndpoints();
      loadStats();
      document.getElementById('endpointAddresses').value = '';
    }
    async function addCIDR(e) {
      e.preventDefault();
      const country = document.getElementById('cidrCountry').value;
      const ranges = document.getElementById('cidrRanges').value.split('\\n').filter(l => l.trim()).map(l => l.trim());
      
      try {
        const r = await fetch('/api/cidr/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ country, ranges })
        });
        
        if (r.ok) {
          closeModal('addCIDRModal');
          alert(\`✅ \${ranges.length} CIDR Range اضافه شد\`);
          loadCIDR();
          loadStats();
          document.getElementById('cidrRanges').value = '';
        } else {
          alert('❌ خطا در افزودن');
        }
      } catch (e) {
        alert('❌ خطا در ارتباط با سرور');
      }
    }
    loadStats();
    loadDNS();
  </script>
</body>
</html>`;
}

// Generate HTML dashboard
function generateDashboard(stats) {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پنل مدیریت ربات WireGuard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: rgba(255, 255, 255, 0.95);
      border-radius: 20px;
      padding: 40px;
      max-width: 800px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }
    h1 {
      color: #667eea;
      text-align: center;
      margin-bottom: 10px;
      font-size: 2.5em;
    }
    .subtitle {
      text-align: center;
      color: #666;
      margin-bottom: 40px;
      font-size: 1.1em;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 25px;
      border-radius: 15px;
      text-align: center;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      transition: transform 0.3s ease;
    }
    .stat-card:hover {
      transform: translateY(-5px);
    }
    .stat-value {
      font-size: 2.5em;
      font-weight: bold;
      margin: 10px 0;
    }
    .stat-label {
      font-size: 1.1em;
      opacity: 0.9;
    }
    .status-section {
      background: #f8f9fa;
      padding: 25px;
      border-radius: 15px;
      margin-bottom: 20px;
    }
    .status-item {
      display: flex;
      justify-content: space-between;
      padding: 15px;
      background: white;
      margin: 10px 0;
      border-radius: 10px;
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    }
    .status-label {
      font-weight: bold;
      color: #333;
    }
    .status-value {
      color: #667eea;
      font-weight: bold;
    }
    .footer {
      text-align: center;
      color: #666;
      margin-top: 30px;
      padding-top: 20px;
      border-top: 2px solid #eee;
    }
    .emoji {
      font-size: 1.5em;
      margin-left: 10px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1><span class="emoji">🤖</span>پنل مدیریت ربات</h1>
    <p class="subtitle">آمار و وضعیت ربات WireGuard</p>
    
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">📊 کل کانفیگ‌ها</div>
        <div class="stat-value">${stats.totalConfigs}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">👥 کل کاربران</div>
        <div class="stat-value">${stats.totalUsers}</div>
      </div>
    </div>
    
    <div class="status-section">
      <h2 style="margin-bottom: 15px; color: #333;">🔍 وضعیت سیستم</h2>
      <div class="status-item">
        <span class="status-label">📡 وضعیت ربات</span>
        <span class="status-value">${stats.uptime}</span>
      </div>
      <div class="status-item">
        <span class="status-label">💾 اتصال دیتابیس (KV)</span>
        <span class="status-value">${stats.kvStatus}</span>
      </div>
      <div class="status-item">
        <span class="status-label">⏰ آخرین بروزرسانی</span>
        <span class="status-value">${new Date(stats.timestamp).toLocaleString('fa-IR')}</span>
      </div>
    </div>
    
    <div class="footer">
      <p>🔐 ربات WireGuard - ساخته شده با Cloudflare Pages</p>
      <p style="margin-top: 10px; font-size: 0.9em;">Powered by Cloudflare Workers & KV</p>
    </div>
  </div>
</body>
</html>`;
}

// Worker-style fetch handler for Pages Functions
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Admin panel
    if (url.pathname === '/' || url.pathname === '/admin') {
      const html = generateWebPanel();
      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    
    // API endpoints
    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env, url);
    }
    
    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Not Found', { status: 404 });
  }
};

// Handle API requests
async function handleAPI(request, env, url) {
  const path = url.pathname;
  const method = request.method;
  
  try {
    // Stats API
    if (path === '/api/stats' && method === 'GET') {
      return await getStatsAPI(env);
    }
    
    // DNS APIs
    if (path === '/api/dns/list' && method === 'GET') {
      return await getDNSListAPI(env);
    }
    if (path === '/api/dns/add' && method === 'POST') {
      return await addDNSAPI(request, env);
    }
    if (path.startsWith('/api/dns/delete/') && method === 'DELETE') {
      const id = path.split('/').pop();
      return await deleteDNSAPI(env, id);
    }
    
    // Endpoint APIs
    if (path === '/api/endpoints/list' && method === 'GET') {
      return await getEndpointsListAPI(env);
    }
    if (path === '/api/endpoints/add' && method === 'POST') {
      return await addEndpointAPI(request, env);
    }
    if (path.startsWith('/api/endpoints/delete/') && method === 'DELETE') {
      const id = path.split('/').pop();
      return await deleteEndpointAPI(env, id);
    }
    
    // Countries API
    if (path === '/api/countries/list' && method === 'GET') {
      return await getCountriesListAPI(env);
    }
    if (path === '/api/countries/add' && method === 'POST') {
      return await addCountryAPI(request, env);
    }
    
    // CIDR APIs
    if (path === '/api/cidr/list' && method === 'GET') {
      return await getCIDRListAPI(env);
    }
    if (path === '/api/cidr/add' && method === 'POST') {
      return await addCIDRAPI(request, env);
    }
    if (path.startsWith('/api/cidr/delete/') && method === 'DELETE') {
      const country = path.split('/').pop();
      return await deleteCIDRAPI(env, country);
    }
    
    return new Response('Not Found', { status: 404 });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// API: Get stats
async function getStatsAPI(env) {
  const stats = await getBotStats(env);
  const dnsList = await env.DB.list({ prefix: 'dns:' });
  const endpointsList = await env.DB.list({ prefix: 'endpoint:' });
  
  // Test KV connection
  const kvConnected = await testKVConnection(env);
  const kvStatusText = kvConnected ? '✅ متصل' : '❌ قطع';
  
  return new Response(JSON.stringify({
    totalUsers: stats.totalUsers,
    totalConfigs: stats.totalConfigs,
    totalDNS: dnsList.keys.length,
    totalEndpoints: endpointsList.keys.length,
    kvStatus: kvStatusText,
    botStatus: stats.uptime
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Get DNS list
async function getDNSListAPI(env) {
  const list = await env.DB.list({ prefix: 'dns:' });
  const dnsItems = [];
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const dns = JSON.parse(data);
      dnsItems.push({
        id: key.name,
        ...dns,
        flag: getCountryFlag(dns.country),
        countryName: getCountryName(dns.country)
      });
    }
  }
  
  return new Response(JSON.stringify(dnsItems), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Add DNS
async function addDNSAPI(request, env) {
  const { country, type, address } = await request.json();
  
  const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
  const dnsData = {
    address,
    type,
    country,
    usageCount: 0,
    createdAt: new Date().toISOString()
  };
  
  await env.DB.put(dnsId, JSON.stringify(dnsData));
  
  return new Response(JSON.stringify({ success: true, id: dnsId }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Delete DNS
async function deleteDNSAPI(env, id) {
  await env.DB.delete(id);
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Get endpoints list
async function getEndpointsListAPI(env) {
  const list = await env.DB.list({ prefix: 'endpoint:' });
  const endpoints = [];
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const ep = JSON.parse(data);
      endpoints.push({
        id: key.name,
        ...ep,
        flag: getCountryFlag(ep.country),
        countryName: getCountryName(ep.country)
      });
    }
  }
  
  return new Response(JSON.stringify(endpoints), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Add endpoint
async function addEndpointAPI(request, env) {
  const { country, address } = await request.json();
  
  const endpointId = `endpoint:${country}:${Date.now()}:${Math.random().toString(36).substring(7)}`;
  const endpointData = {
    address,
    country,
    usageCount: 0,
    createdAt: new Date().toISOString()
  };
  
  await env.DB.put(endpointId, JSON.stringify(endpointData));
  
  return new Response(JSON.stringify({ success: true, id: endpointId }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Delete endpoint
async function deleteEndpointAPI(env, id) {
  await env.DB.delete(id);
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Get countries list
async function getCountriesListAPI(env) {
  const countries = [
    { code: 'CA', name: 'کانادا', flag: '🇨🇦' },
    { code: 'QA', name: 'قطر', flag: '🇶🇦' },
    { code: 'BE', name: 'بلژیک', flag: '🇧🇪' }
  ];
  
  // Count DNS and endpoints for each country
  const dnsList = await env.DB.list({ prefix: 'dns:' });
  const endpointsList = await env.DB.list({ prefix: 'endpoint:' });
  
  for (const country of countries) {
    country.dnsCount = 0;
    country.endpointCount = 0;
    
    for (const key of dnsList.keys) {
      const data = await env.DB.get(key.name);
      if (data) {
        const dns = JSON.parse(data);
        if (dns.country === country.code) country.dnsCount++;
      }
    }
    
    for (const key of endpointsList.keys) {
      const data = await env.DB.get(key.name);
      if (data) {
        const ep = JSON.parse(data);
        if (ep.country === country.code) country.endpointCount++;
      }
    }
  }
  
  return new Response(JSON.stringify(countries), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Add country
async function addCountryAPI(request, env) {
  const { code, name, flag, dnsv4, dnsv6 } = await request.json();
  
  // Add DNS for new country
  for (const address of dnsv4) {
    const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    await env.DB.put(dnsId, JSON.stringify({
      address,
      type: 'ipv4',
      country: code,
      usageCount: 0,
      createdAt: new Date().toISOString(),
      isDefault: true
    }));
  }
  
  for (const address of dnsv6) {
    const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    await env.DB.put(dnsId, JSON.stringify({
      address,
      type: 'ipv6',
      country: code,
      usageCount: 0,
      createdAt: new Date().toISOString(),
      isDefault: true
    }));
  }
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Get CIDR list
async function getCIDRListAPI(env) {
  const list = await env.DB.list({ prefix: 'cidr:' });
  const cidrItems = [];
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const cidr = JSON.parse(data);
      cidrItems.push({
        country: cidr.country,
        ranges: ['10.66.0.0/32', ...cidr.ranges],
        flag: getCountryFlag(cidr.country),
        countryName: getCountryName(cidr.country),
        updatedAt: cidr.updatedAt
      });
    }
  }
  
  return new Response(JSON.stringify(cidrItems), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Add CIDR
async function addCIDRAPI(request, env) {
  const { country, ranges } = await request.json();
  
  await saveCIDRRanges(env, country, ranges);
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// API: Delete CIDR
async function deleteCIDRAPI(env, country) {
  const rangesKey = `cidr:${country}`;
  await env.DB.delete(rangesKey);
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
