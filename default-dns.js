// This file is kept for backward compatibility
// All DNS management is now done through KV storage
// No default DNS - admin must add them manually

// Only 3 countries are supported: Canada (CA), Qatar (QA), Belgium (BE)
// Other countries can be added manually through admin panel

export const DEFAULT_DNS = {};

// Initialize default DNS for a country (empty - for compatibility)
export async function initializeDefaultDNS(env, country) {
  return 0;
}

// Initialize all default DNS (empty - for compatibility)
export async function initializeAllDefaultDNS(env) {
  return 0;
}
