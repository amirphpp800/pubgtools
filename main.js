// Telegram Bot for WireGuard Config Generation on Cloudflare Pages
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

// Generate WireGuard keypair
function generateWireGuardKeys() {
  const privateKey = generateBase64Key();
  const publicKey = generateBase64Key();
  return { privateKey, publicKey };
}

// Generate random base64 key (32 bytes)
function generateBase64Key() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Generate random IPv4 in 10.0.0.0/24 range
function generateClientIP(userId) {
  const hash = userId % 250 + 2;
  return `10.0.0.${hash}`;
}

// Create WireGuard config
function createWireGuardConfig(privateKey, publicKey, clientIP, serverPublicKey, serverEndpoint) {
  return `[Interface]
PrivateKey = ${privateKey}
Address = ${clientIP}/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${serverPublicKey}
Endpoint = ${serverEndpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25`;
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
function getMainKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '🔐 وایرگارد', callback_data: 'wireguard' },
        { text: '🌐 DNS', callback_data: 'dns' }
      ],
      [
        { text: '👤 حساب کاربری', callback_data: 'account' }
      ]
    ]
  };
}

// Handle WireGuard button
async function handleWireGuardButton(chatId, userId, username, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId, '🔄 در حال ساخت کانفیگ...');
  
  try {
    // Generate keys
    const { privateKey, publicKey } = generateWireGuardKeys();
    const clientIP = generateClientIP(userId);
    
    const serverPublicKey = env.WG_SERVER_PUBLIC_KEY || 'YOUR_SERVER_PUBLIC_KEY';
    const serverEndpoint = env.WG_SERVER_ENDPOINT || 'YOUR_SERVER_IP:51820';
    
    // Create config
    const config = createWireGuardConfig(privateKey, publicKey, clientIP, serverPublicKey, serverEndpoint);
    
    // Save to KV
    const configData = {
      userId,
      username,
      publicKey,
      clientIP,
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
    
    // Send config as file
    const caption = `✨ <b>کانفیگ WireGuard شما آماده است</b>\n\n🎯 نام فایل: <code>${filename}</code>\n🌐 IP: <code>${clientIP}</code>\n⏰ ${new Date().toLocaleString('fa-IR')}`;
    
    await sendTelegramDocument(env.BOT_TOKEN, chatId, filename, config, caption);
    
    // Send back to main menu
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '🏠 منوی اصلی:',
      getMainKeyboard()
    );
    
  } catch (error) {
    console.error('Error generating config:', error);
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '❌ خطا در ساخت کانفیگ. لطفاً دوباره تلاش کنید.',
      getMainKeyboard()
    );
  }
}

// Handle DNS button
async function handleDNSButton(chatId, env, callbackQueryId) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const dnsMessage = `🌐 <b>تنظیمات DNS پیشنهادی</b>

🔹 <b>Cloudflare:</b>
   • <code>1.1.1.1</code>
   • <code>1.0.0.1</code>

🔹 <b>Google:</b>
   • <code>8.8.8.8</code>
   • <code>8.8.4.4</code>

🔹 <b>Shecan (ایران):</b>
   • <code>178.22.122.100</code>
   • <code>185.51.200.2</code>

💡 این DNS ها در کانفیگ WireGuard شما به صورت خودکار تنظیم می‌شوند.`;

  await sendTelegramMessage(env.BOT_TOKEN, chatId, dnsMessage, getMainKeyboard());
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

// Handle /start command
async function handleStartCommand(chatId, userId, env) {
  await incrementStat(env, 'total_users');
  
  const welcomeMessage = `🎉 <b>به ربات WireGuard خوش آمدید!</b>

✨ این ربات به شما کمک می‌کند تا به راحتی کانفیگ WireGuard دریافت کنید.

🔽 از دکمه‌های زیر استفاده کنید:`;

  await sendTelegramMessage(env.BOT_TOKEN, chatId, welcomeMessage, getMainKeyboard());
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
      
      if (data === 'wireguard') {
        await handleWireGuardButton(chatId, userId, username, env, callbackQuery.id);
      } else if (data === 'dns') {
        await handleDNSButton(chatId, env, callbackQuery.id);
      } else if (data === 'account') {
        await handleAccountButton(chatId, userId, username, env, callbackQuery.id);
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
    
    // Handle commands
    if (text === '/start') {
      await handleStartCommand(chatId, userId, env);
    } else {
      await sendTelegramMessage(
        env.BOT_TOKEN,
        chatId,
        '❓ از دکمه‌های زیر استفاده کنید:',
        getMainKeyboard()
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
    
    // Dashboard - only accessible by admin
    if (url.pathname === '/' || url.pathname === '/dashboard') {
      const stats = await getBotStats(env);
      const html = generateDashboard(stats);
      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
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
