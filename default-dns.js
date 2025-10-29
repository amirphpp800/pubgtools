// Default DNS servers for countries
export const DEFAULT_DNS = {
  'IR': {
    ipv4: ['10.202.10.10', '10.202.10.11', '178.22.122.100', '185.51.200.2'],
    ipv6: []
  },
  'US': {
    ipv4: ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4'],
    ipv6: ['2606:4700:4700::1111', '2001:4860:4860::8888']
  },
  'DE': {
    ipv4: ['9.9.9.9', '149.112.112.112'],
    ipv6: ['2620:fe::fe', '2620:fe::9']
  },
  'GB': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111', '2001:4860:4860::8888']
  },
  'FR': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'NL': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'CA': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111', '2001:4860:4860::8888']
  },
  'JP': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'SG': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'AE': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'TR': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'SE': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'AU': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111', '2001:4860:4860::8888']
  },
  'BR': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'IN': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'QA': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  },
  'BE': {
    ipv4: ['1.1.1.1', '8.8.8.8'],
    ipv6: ['2606:4700:4700::1111']
  }
};

// Initialize default DNS for a country
export async function initializeDefaultDNS(env, country) {
  const dns = DEFAULT_DNS[country];
  if (!dns) return 0;
  
  let count = 0;
  
  // Add IPv4
  for (const address of dns.ipv4) {
    const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    const dnsData = {
      address,
      type: 'ipv4',
      country,
      usageCount: 0,
      createdAt: new Date().toISOString(),
      isDefault: true
    };
    await env.DB.put(dnsId, JSON.stringify(dnsData));
    count++;
  }
  
  // Add IPv6
  for (const address of dns.ipv6) {
    const dnsId = `dns:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    const dnsData = {
      address,
      type: 'ipv6',
      country,
      usageCount: 0,
      createdAt: new Date().toISOString(),
      isDefault: true
    };
    await env.DB.put(dnsId, JSON.stringify(dnsData));
    count++;
  }
  
  return count;
}

// Initialize all default DNS
export async function initializeAllDefaultDNS(env) {
  let totalCount = 0;
  for (const country of Object.keys(DEFAULT_DNS)) {
    const count = await initializeDefaultDNS(env, country);
    totalCount += count;
  }
  return totalCount;
}
