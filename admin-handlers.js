// Admin handlers for Telegram Bot

// Handle broadcast message
export async function handleAdminBroadcast(chatId, env, callbackQueryId, answerCallbackQuery, sendTelegramMessage) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  await env.DB.put(`session:${chatId}:waiting_broadcast`, 'true', { expirationTtl: 600 });
  
  const message = `📢 <b>پیام همگانی</b>\n\n📝 لطفاً پیام خود را برای ارسال به تمام کاربران وارد کنید:\n\n<i>پیام شما به تمام کاربران ربات ارسال خواهد شد.</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message);
}

// Process broadcast message
export async function processBroadcast(chatId, text, env, sendTelegramMessage, getAdminKeyboard, isAdmin) {
  const usersList = await env.DB.list({ prefix: 'user:' });
  let successCount = 0;
  let failCount = 0;
  
  for (const key of usersList.keys) {
    try {
      const userData = await env.DB.get(key.name);
      if (userData) {
        const user = JSON.parse(userData);
        const userChatId = user.userId;
        
        await sendTelegramMessage(env.BOT_TOKEN, userChatId, `📢 <b>پیام از ادمین:</b>\n\n${text}`);
        successCount++;
      }
    } catch (error) {
      failCount++;
    }
  }
  
  await sendTelegramMessage(
    env.BOT_TOKEN,
    chatId,
    `✅ <b>پیام همگانی ارسال شد</b>\n\n✔️ موفق: ${successCount}\n❌ ناموفق: ${failCount}`,
    getAdminKeyboard()
  );
}

// Handle endpoints management
export async function handleAdminEndpoints(chatId, env, callbackQueryId, answerCallbackQuery, sendTelegramMessage, getCountryKeyboard) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const message = `🌐 <b>مدیریت Endpoint ها</b>\n\n📍 لطفاً کشور مورد نظر را انتخاب کنید:`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getCountryKeyboard('endpoint'));
}

// Handle endpoint country selection
export async function handleEndpointCountrySelection(chatId, country, env, callbackQueryId, answerCallbackQuery, sendTelegramMessage, getCountryFlag, getCountryName) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  await env.DB.put(`session:${chatId}:endpoint_country`, country, { expirationTtl: 300 });
  await env.DB.put(`session:${chatId}:waiting_endpoints`, 'true', { expirationTtl: 300 });
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  
  const message = `${flag} <b>افزودن Endpoint برای ${countryName}</b>\n\n📝 لطفاً لیست Endpoint ها را ارسال کنید:\n\n<i>فرمت: هر خط یک Endpoint\nمثال:\n1.2.3.4:51820\n5.6.7.8:51820\n9.10.11.12:51820</i>`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message);
}

// Detect country from IP using API
async function detectCountryFromIP(ip) {
  try {
    const response = await fetch(`https://api.iplocation.net/?cmd=ip-country&ip=${ip}`);
    const data = await response.json();
    
    if (data && data.country_code2) {
      return {
        code: data.country_code2.toUpperCase(),
        name: data.country_name || 'Unknown'
      };
    }
    return null;
  } catch (error) {
    console.error('Error detecting country:', error);
    return null;
  }
}

// Add country to system if not exists
async function addCountryIfNotExists(env, countryCode, countryName) {
  const countriesKey = 'countries:list';
  const countriesData = await env.DB.get(countriesKey);
  
  let countries = [];
  if (countriesData) {
    countries = JSON.parse(countriesData);
  }
  
  // Check if country already exists
  const exists = countries.some(c => c.code === countryCode);
  
  if (!exists) {
    countries.push({
      code: countryCode,
      name: countryName,
      addedAt: new Date().toISOString(),
      autoAdded: true
    });
    
    await env.DB.put(countriesKey, JSON.stringify(countries));
    return true;
  }
  
  return false;
}

// Process endpoints list
export async function processEndpoints(chatId, text, env, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName) {
  const selectedCountry = await env.DB.get(`session:${chatId}:endpoint_country`);
  
  const lines = text.split('\n').filter(line => line.trim());
  let successCount = 0;
  let failCount = 0;
  let autoDetectedCount = 0;
  let newCountriesAdded = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    // Validate IP:PORT format
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$/.test(trimmed)) {
      // Extract IP without port
      const ip = trimmed.split(':')[0];
      
      // Try to detect country from IP
      let detectedCountry = await detectCountryFromIP(ip);
      
      let finalCountry = selectedCountry;
      
      if (detectedCountry) {
        // Add country to system if not exists
        const wasAdded = await addCountryIfNotExists(env, detectedCountry.code, detectedCountry.name);
        if (wasAdded) {
          newCountriesAdded.push(`${detectedCountry.code} (${detectedCountry.name})`);
        }
        
        // Use detected country
        finalCountry = detectedCountry.code;
        autoDetectedCount++;
      }
      
      const endpointId = `endpoint:${finalCountry}:${Date.now()}:${Math.random().toString(36).substring(7)}`;
      const endpointData = {
        address: trimmed,
        country: finalCountry,
        usageCount: 0,
        createdAt: new Date().toISOString()
      };
      await env.DB.put(endpointId, JSON.stringify(endpointData));
      successCount++;
    } else {
      failCount++;
    }
  }
  
  const flag = getCountryFlag(selectedCountry);
  const countryName = getCountryName(selectedCountry);
  
  let message = `✅ <b>Endpoint ها اضافه شدند</b>\n\n${flag} کشور انتخابی: ${countryName}\n✔️ موفق: ${successCount}\n❌ نامعتبر: ${failCount}`;
  
  if (autoDetectedCount > 0) {
    message += `\n🌍 تشخیص خودکار: ${autoDetectedCount}`;
  }
  
  if (newCountriesAdded.length > 0) {
    message += `\n\n🆕 <b>کشورهای جدید اضافه شده:</b>\n${newCountriesAdded.map(c => `  • ${c}`).join('\n')}`;
  }
  
  await sendTelegramMessage(
    env.BOT_TOKEN,
    chatId,
    message,
    getAdminKeyboard()
  );
}

// Handle list endpoints
export async function handleAdminListEndpoints(chatId, env, callbackQueryId, answerCallbackQuery, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName) {
  await answerCallbackQuery(env.BOT_TOKEN, callbackQueryId);
  
  const list = await env.DB.list({ prefix: 'endpoint:' });
  
  if (list.keys.length === 0) {
    await sendTelegramMessage(
      env.BOT_TOKEN,
      chatId,
      '🔗 <b>لیست Endpoint ها</b>\n\n⚠️ هیچ Endpoint ثبت شده‌ای وجود ندارد.',
      getAdminKeyboard()
    );
    return;
  }
  
  let message = '🔗 <b>لیست Endpoint های ثبت شده</b>\n\n';
  
  // Group by country
  const byCountry = {};
  
  for (const key of list.keys) {
    const data = await env.DB.get(key.name);
    if (data) {
      const endpoint = JSON.parse(data);
      if (!byCountry[endpoint.country]) {
        byCountry[endpoint.country] = [];
      }
      byCountry[endpoint.country].push(endpoint);
    }
  }
  
  for (const [country, endpoints] of Object.entries(byCountry)) {
    const flag = getCountryFlag(country);
    const countryName = getCountryName(country);
    message += `\n${flag} <b>${countryName}</b>\n`;
    
    endpoints.forEach(ep => {
      message += `  • <code>${ep.address}</code> (${ep.usageCount || 0}/5)\n`;
    });
  }
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, message, getAdminKeyboard());
}

// Process DNS list
export async function processDNSList(chatId, text, env, sendTelegramMessage, getAdminKeyboard, getCountryFlag, getCountryName) {
  const country = await env.DB.get(`session:${chatId}:dns_country`);
  const dnsType = await env.DB.get(`session:${chatId}:dns_type`);
  
  const lines = text.split('\n').filter(line => line.trim());
  let successCount = 0;
  let failCount = 0;
  let newCountriesAdded = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    const isIPv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(trimmed);
    const isIPv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(trimmed);
    
    if ((dnsType === 'ipv4' && isIPv4) || (dnsType === 'ipv6' && isIPv6)) {
      let finalCountry = country;
      
      // For IPv4, try to detect country
      if (dnsType === 'ipv4') {
        const detectedCountry = await detectCountryFromIP(trimmed);
        
        if (detectedCountry) {
          // Add country to system if not exists
          const wasAdded = await addCountryIfNotExists(env, detectedCountry.code, detectedCountry.name);
          if (wasAdded) {
            newCountriesAdded.push(`${detectedCountry.code} (${detectedCountry.name})`);
          }
          
          // Use detected country
          finalCountry = detectedCountry.code;
        }
      }
      
      const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
      const dnsData = {
        address: trimmed,
        type: dnsType,
        country: finalCountry,
        usageCount: 0,
        createdAt: new Date().toISOString()
      };
      await env.DB.put(dnsId, JSON.stringify(dnsData));
      successCount++;
    } else {
      failCount++;
    }
  }
  
  const flag = getCountryFlag(country);
  const countryName = getCountryName(country);
  
  let message = `✅ <b>DNS ها اضافه شدند</b>\n\n${flag} کشور انتخابی: ${countryName}\n📡 نوع: ${dnsType === 'ipv4' ? 'IPv4' : 'IPv6'}\n✔️ موفق: ${successCount}\n❌ نامعتبر: ${failCount}`;
  
  if (newCountriesAdded.length > 0) {
    message += `\n\n🆕 <b>کشورهای جدید اضافه شده:</b>\n${newCountriesAdded.map(c => `  • ${c}`).join('\n')}`;
  }
  
  await sendTelegramMessage(
    env.BOT_TOKEN,
    chatId,
    message,
    getAdminKeyboard()
  );
}
