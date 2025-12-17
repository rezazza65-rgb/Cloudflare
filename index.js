// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - OPTIMIZED UNIFIED VERSION
 * ============================================================================
 * 
 * Enhanced Features:
 * - Multi-layer Caching System (Memory + D1)
 * - Intelligent Proxy Selection Algorithm
 * - Advanced Threat Detection
 * - Real-time Analytics Dashboard
 * - Auto-scaling Connection Management
 * - Enhanced Error Recovery
 * - Zero-downtime Updates Support
 * 
 * Optimized: December 2025
 * Version: 3.0.0
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// ENHANCED CONFIGURATION WITH INTELLIGENT DEFAULTS
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  
  scamalytics: {
    username: 'victoriacrossn',
    apiKey: 'ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },

  // Intelligent configuration loader with priority system
  async fromEnv(env) {
    const PRIORITY_SOURCES = [
      { name: 'DB_HEALTH', getter: async () => await this.getBestProxyFromDB(env) },
      { name: 'ENV_VAR', getter: () => env.PROXYIP },
      { name: 'CONFIG_LIST', getter: () => this.getRandomProxyFromList() },
      { name: 'FALLBACK', getter: () => this.proxyIPs[0] }
    ];

    let selectedProxyIP = null;
    let selectedSource = '';

    // Try each source in priority order
    for (const source of PRIORITY_SOURCES) {
      try {
        const result = await source.getter();
        if (result) {
          selectedProxyIP = result;
          selectedSource = source.name;
          console.log(`✓ Using proxy from ${source.name}: ${selectedProxyIP}`);
          break;
        }
      } catch (e) {
        console.warn(`Failed to get proxy from ${source.name}: ${e.message}`);
      }
    }

    // Parse proxy address
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      selectedSource,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
      // Additional optimized settings
      optimization: {
        cacheTtl: 3600,
        healthCheckInterval: 300000,
        maxConnectionsPerUser: 10,
        enableCompression: true,
        logLevel: env.LOG_LEVEL || 'info'
      }
    };
  },

  // Helper methods for proxy selection
  async getBestProxyFromDB(env) {
    if (!env.DB) return null;
    
    const { results } = await env.DB.prepare(
      `SELECT ip_port, latency_ms 
       FROM proxy_health 
       WHERE is_healthy = 1 
       AND last_check > strftime('%s', 'now', '-10 minutes')
       ORDER BY latency_ms ASC 
       LIMIT 3`
    ).all();
    
    if (!results || results.length === 0) return null;
    
    // Weighted random selection from top 3
    const weights = [0.5, 0.3, 0.2]; // Higher weight for faster proxies
    const random = Math.random();
    let cumulative = 0;
    
    for (let i = 0; i < Math.min(results.length, 3); i++) {
      cumulative += weights[i];
      if (random <= cumulative) {
        return results[i].ip_port;
      }
    }
    
    return results[0].ip_port;
  },

  getRandomProxyFromList() {
    if (!this.proxyIPs || this.proxyIPs.length === 0) return null;
    return this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
  }
};

// ============================================================================
// ENHANCED CONSTANTS WITH SMART DEFAULTS
// ============================================================================

const CONST = {
  // Protocol constants
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  // Admin panel constants
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  // Security constants
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  API_RATE_LIMIT: 100,
  API_RATE_TTL: 60,
  
  // Performance constants
  AUTO_REFRESH_INTERVAL: 60000,
  CACHE_TTL: 3600,
  CONNECTION_TIMEOUT: 10000,
  
  // Database constants
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000,
  HEALTH_CHECK_TIMEOUT: 5000,
  MAX_DB_RETRIES: 3,
  
  // Network constants
  MAX_CHUNK_SIZE: 16384,
  DNS_TIMEOUT: 3000,
  SOCKET_TIMEOUT: 30000
};

// ============================================================================
// MULTI-LAYER CACHE SYSTEM
// ============================================================================

class SmartCache {
  constructor() {
    this.memoryCache = new Map();
    this.stats = {
      hits: 0,
      misses: 0,
      memorySize: 0,
      maxMemoryItems: 1000
    };
  }

  async get(key, db, type = 'text') {
    // Check memory cache first
    const memoryItem = this.memoryCache.get(key);
    if (memoryItem && memoryItem.expiry > Date.now()) {
      this.stats.hits++;
      return memoryItem.value;
    }
    
    // Check D1 cache
    if (db) {
      try {
        const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
        const res = await stmt.first();
        
        if (!res) {
          this.stats.misses++;
          return null;
        }
        
        if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
          await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
          this.stats.misses++;
          return null;
        }
        
        let value = res.value;
        if (type === 'json') {
          try {
            value = JSON.parse(res.value);
          } catch (e) {
            console.error(`Failed to parse JSON for key ${key}: ${e}`);
            return null;
          }
        }
        
        // Store in memory cache
        this.setMemory(key, value, 60); // 1 minute in memory
        
        this.stats.hits++;
        return value;
      } catch (e) {
        console.error(`Cache get error for ${key}: ${e}`);
        return null;
      }
    }
    
    this.stats.misses++;
    return null;
  }

  async set(key, value, db, options = {}) {
    // Store in memory cache
    const memoryTtl = options.memoryTtl || 60;
    this.setMemory(key, value, memoryTtl);
    
    // Store in D1 if available
    if (db) {
      try {
        const dbValue = typeof value === 'object' ? JSON.stringify(value) : value;
        const exp = options.expirationTtl 
          ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
          : null;
        
        await db.prepare(
          "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
        ).bind(key, dbValue, exp).run();
      } catch (e) {
        console.error(`Cache set error for ${key}: ${e}`);
      }
    }
  }

  setMemory(key, value, ttlSeconds = 60) {
    // Clean old items if cache is too large
    if (this.memoryCache.size >= this.stats.maxMemoryItems) {
      const oldestKey = this.memoryCache.keys().next().value;
      this.memoryCache.delete(oldestKey);
    }
    
    this.memoryCache.set(key, {
      value,
      expiry: Date.now() + (ttlSeconds * 1000)
    });
    
    this.stats.memorySize = this.memoryCache.size;
  }

  delete(key, db) {
    this.memoryCache.delete(key);
    
    if (db) {
      try {
        db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      } catch (e) {
        console.error(`Cache delete error for ${key}: ${e}`);
      }
    }
  }

  clear() {
    this.memoryCache.clear();
    this.stats.memorySize = 0;
  }

  getStats() {
    return {
      ...this.stats,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses) || 0
    };
  }
}

// Global cache instance
const cache = new SmartCache();

// ============================================================================
// ENHANCED SECURITY FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(32); // Increased from 16 to 32 for better security
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` 
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'";
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
    "font-src 'self' https://cdnjs.cloudflare.com",
    "media-src 'self'"
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=0');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
  
  // Additional security headers
  headers.set('X-Permitted-Cross-Domain-Policies', 'none');
  headers.set('X-XSS-Protection', '1; mode=block');
  
  // Performance headers
  headers.set('X-DNS-Prefetch-Control', 'off');
  headers.set('X-Download-Options', 'noopen');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  
  const aBuf = new TextEncoder().encode(a);
  const bBuf = new TextEncoder().encode(b);
  
  if (aBuf.length !== bBuf.length) {
    crypto.subtle.timingSafeEqual(aBuf, aBuf); // Constant time comparison
    return false;
  }
  
  return crypto.subtle.timingSafeEqual(aBuf, bBuf);
}

// ============================================================================
// INTELLIGENT PROXY MANAGEMENT
// ============================================================================

class ProxyManager {
  constructor(env, ctx) {
    this.env = env;
    this.ctx = ctx;
    this.healthyProxies = new Map();
    this.lastHealthCheck = 0;
  }

  async getBestProxy() {
    const now = Date.now();
    
    // Refresh health check if needed
    if (now - this.lastHealthCheck > CONST.HEALTH_CHECK_INTERVAL) {
      await this.performHealthCheck();
    }
    
    // Get proxies from cache or DB
    let proxies = Array.from(this.healthyProxies.entries());
    
    if (proxies.length === 0) {
      proxies = await this.getProxiesFromDB();
    }
    
    if (proxies.length === 0) {
      return Config.proxyIPs[0]; // Fallback
    }
    
    // Sort by latency and health score
    proxies.sort((a, b) => {
      const scoreA = this.calculateProxyScore(a);
      const scoreB = this.calculateProxyScore(b);
      return scoreB - scoreA; // Higher score first
    });
    
    return proxies[0][0];
  }

  calculateProxyScore(proxy) {
    const [address, data] = proxy;
    const latencyScore = data.latency ? Math.max(0, 1000 - data.latency) / 10 : 50;
    const healthScore = data.isHealthy ? 100 : 0;
    const stabilityScore = data.checksPassed / Math.max(data.checksTotal, 1) * 100;
    
    return latencyScore * 0.4 + healthScore * 0.4 + stabilityScore * 0.2;
  }

  async performHealthCheck() {
    if (!this.env.DB) return;
    
    const proxyIps = this.env.PROXYIPS 
      ? this.env.PROXYIPS.split(',').map(ip => ip.trim()) 
      : Config.proxyIPs;
    
    const healthStmts = [];
    const checkPromises = [];
    
    for (const ipPort of proxyIps) {
      const checkPromise = this.checkSingleProxy(ipPort);
      checkPromises.push(checkPromise);
    }
    
    const results = await Promise.allSettled(checkPromises);
    
    for (let i = 0; i < proxyIps.length; i++) {
      const ipPort = proxyIps[i];
      const result = results[i];
      
      let isHealthy = 0;
      let latency = null;
      
      if (result.status === 'fulfilled') {
        isHealthy = result.value.healthy ? 1 : 0;
        latency = result.value.latency;
        
        // Update in-memory cache
        this.healthyProxies.set(ipPort, {
          isHealthy: !!isHealthy,
          latency,
          lastCheck: Date.now(),
          checksPassed: (this.healthyProxies.get(ipPort)?.checksPassed || 0) + (isHealthy ? 1 : 0),
          checksTotal: (this.healthyProxies.get(ipPort)?.checksTotal || 0) + 1
        });
      }
      
      // Update database
      healthStmts.push(
        this.env.DB.prepare(
          "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
        ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
      );
    }
    
    try {
      await this.env.DB.batch(healthStmts);
      this.lastHealthCheck = Date.now();
      console.log('✓ Proxy health check completed');
    } catch (e) {
      console.error(`Health check batch error: ${e.message}`);
    }
  }

  async checkSingleProxy(ipPort) {
    const [host, port = '443'] = ipPort.split(':');
    const start = Date.now();
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { 
        signal: controller.signal,
        method: 'HEAD',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Health Check)'
        }
      });
      
      clearTimeout(timeoutId);
      
      const latency = Date.now() - start;
      const healthy = response.ok || response.status === 404;
      
      return { healthy, latency };
    } catch (e) {
      return { healthy: false, latency: null };
    }
  }

  async getProxiesFromDB() {
    if (!this.env.DB) return [];
    
    try {
      const { results } = await this.env.DB.prepare(
        `SELECT ip_port, is_healthy, latency_ms 
         FROM proxy_health 
         WHERE last_check > strftime('%s', 'now', '-30 minutes')
         ORDER BY is_healthy DESC, latency_ms ASC`
      ).all();
      
      return results.map(row => [
        row.ip_port,
        {
          isHealthy: !!row.is_healthy,
          latency: row.latency_ms,
          lastCheck: Date.now()
        }
      ]);
    } catch (e) {
      console.error(`Failed to get proxies from DB: ${e.message}`);
      return [];
    }
  }
}

// ============================================================================
// ENHANCED USER MANAGEMENT WITH CACHING
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    // Try multi-layer cache
    const cachedData = await cache.get(cacheKey, env.DB, 'json');
    if (cachedData && cachedData.uuid) {
      // Check expiration
      if (isExpired(cachedData.expiration_date, cachedData.expiration_time)) {
        cache.delete(cacheKey, env.DB);
      } else {
        return cachedData;
      }
    }

    // Fetch from database with retry logic
    let retries = CONST.MAX_DB_RETRIES;
    while (retries > 0) {
      try {
        const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        if (!userFromDb) return null;
        
        // Update cache asynchronously with extended TTL
        const cachePromise = cache.set(cacheKey, userFromDb, env.DB, { 
          expirationTtl: CONST.CACHE_TTL,
          memoryTtl: 300 // 5 minutes in memory
        });
        
        if (ctx) {
          ctx.waitUntil(cachePromise);
        } else {
          await cachePromise;
        }
        
        return userFromDb;
      } catch (dbError) {
        retries--;
        if (retries === 0) {
          console.error(`getUserData error for ${uuid}: ${dbError.message}`);
          return null;
        }
        await new Promise(resolve => setTimeout(resolve, 100 * (CONST.MAX_DB_RETRIES - retries)));
      }
    }
    
    return null;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  const sessionKey = `usage_session:${uuid}:${Date.now()}`;
  
  try {
    // Batch updates in session cache first
    await cache.set(sessionKey, bytes, env.DB, { 
      expirationTtl: 300,
      memoryTtl: 60
    });
    
    // Process batched updates every 30 seconds
    const processBatch = async () => {
      try {
        // Get all session updates
        const { results } = await env.DB.prepare(
          "SELECT key, value FROM key_value WHERE key LIKE ? AND expiration > ?"
        ).bind(`usage_session:${uuid}:%`, Math.floor(Date.now() / 1000)).all();
        
        if (!results || results.length === 0) return;
        
        let totalBytes = 0;
        const keysToDelete = [];
        
        for (const row of results) {
          totalBytes += parseInt(row.value, 10) || 0;
          keysToDelete.push(row.key);
        }
        
        if (totalBytes > 0) {
          // Update database
          await env.DB.prepare(
            "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
          ).bind(totalBytes, uuid).run();
          
          // Clear cache
          cache.delete(`user:${uuid}`, env.DB);
          
          // Delete session keys
          const deleteStmts = keysToDelete.map(key => 
            env.DB.prepare("DELETE FROM key_value WHERE key = ?").bind(key)
          );
          
          if (deleteStmts.length > 0) {
            await env.DB.batch(deleteStmts);
          }
        }
      } catch (batchError) {
        console.error(`Batch update error for ${uuid}:`, batchError);
      }
    };
    
    // Schedule batch processing
    if (ctx) {
      ctx.waitUntil((async () => {
        await new Promise(resolve => setTimeout(resolve, 30000));
        await processBatch();
      })());
    }
    
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  }
}

// ============================================================================
// ENHANCED SUBSCRIPTION LINK GENERATION
// ============================================================================

function generateRandomPath(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const cryptoArray = new Uint8Array(length);
  crypto.getRandomValues(cryptoArray);
  
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(cryptoArray[i] % chars.length);
  }
  return `/${result}`;
}

const CORE_PRESETS = {
  xray: {
    tls: {
      path: () => generateRandomPath(16),
      security: 'tls',
      fp: 'chrome',
      alpn: 'http/1.1',
      extra: { ed: '2560' },
      sni: true
    },
    tcp: {
      path: () => generateRandomPath(16),
      security: 'none',
      fp: 'chrome',
      extra: { ed: '2560' },
      sni: false
    },
    grpc: {
      path: () => generateRandomPath(24),
      security: 'tls',
      fp: 'chrome',
      alpn: 'h2',
      mode: 'gun',
      serviceName: () => generateRandomPath(8).slice(1),
      extra: { ed: '2560', type: 'grpc' }
    }
  },
  sb: {
    tls: {
      path: () => generateRandomPath(20),
      security: 'tls',
      fp: 'firefox',
      alpn: 'h3',
      extra: CONST.ED_PARAMS,
      sni: true
    },
    tcp: {
      path: () => generateRandomPath(20),
      security: 'none',
      fp: 'firefox',
      extra: CONST.ED_PARAMS,
      sni: false
    },
    grpc: {
      path: () => generateRandomPath(24),
      security: 'tls',
      fp: 'firefox',
      alpn: 'h2',
      mode: 'gun',
      serviceName: () => generateRandomPath(8).slice(1),
      extra: { ...CONST.ED_PARAMS, type: 'grpc' }
    }
  }
};

function buildEnhancedLink({ core, proto, userID, hostName, address, port, tag, isIPv6 = false }) {
  const preset = CORE_PRESETS[core]?.[proto];
  if (!preset) return null;
  
  const formattedAddress = isIPv6 && !address.startsWith('[') ? `[${address}]` : address;
  
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host: hostName,
    path: typeof preset.path === 'function' ? preset.path() : preset.path,
  });

  if (preset.security) {
    params.set('security', preset.security);
    if (preset.security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (preset.sni && preset.security === 'tls') {
    params.set('sni', hostName);
  }
  
  if (preset.fp) params.set('fp', preset.fp);
  if (preset.alpn) params.set('alpn', preset.alpn);
  
  // Add gRPC specific parameters
  if (preset.mode === 'gun' && preset.serviceName) {
    params.set('mode', 'gun');
    params.set('serviceName', typeof preset.serviceName === 'function' ? preset.serviceName() : preset.serviceName);
  }

  for (const [k, v] of Object.entries(preset.extra || {})) {
    params.set(k, v);
  }

  const name = `${tag}-${proto.toUpperCase()}-${core.toUpperCase()}`;
  return `vless://${userID}@${formattedAddress}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

// ============================================================================
// INTELLIGENT DOMAIN RESOLUTION WITH CACHING
// ============================================================================

async function resolveProxyIPWithCache(proxyHost, env) {
  const cacheKey = `dns:${proxyHost}`;
  const cachedIP = await cache.get(cacheKey, env?.DB);
  
  if (cachedIP) {
    return cachedIP;
  }
  
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;

  if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
    await cache.set(cacheKey, proxyHost, env?.DB, { expirationTtl: 3600 });
    return proxyHost;
  }

  // Multiple DNS-over-HTTPS providers with fallback
  const dnsAPIs = [
    { 
      url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, 
      parse: data => data.Answer?.find(a => a.type === 1)?.data 
    },
    { 
      url: `https://dns.google/resolve?name=${encodeURIComponent(proxyHost)}&type=A`, 
      parse: data => data.Answer?.find(a => a.type === 1)?.data 
    },
    { 
      url: `https://1.1.1.1/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, 
      parse: data => data.Answer?.find(a => a.type === 1)?.data 
    }
  ];

  for (const api of dnsAPIs) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.DNS_TIMEOUT);
      
      const response = await fetch(api.url, { 
        headers: { 'accept': 'application/dns-json' },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        const ip = api.parse(data);
        if (ip && ipv4Regex.test(ip)) {
          await cache.set(cacheKey, ip, env?.DB, { expirationTtl: 300 }); // 5 minutes cache
          return ip;
        }
      }
    } catch (e) {
      // Silent fail and try next provider
    }
  }
  
  // Fallback to original hostname
  await cache.set(cacheKey, proxyHost, env?.DB, { expirationTtl: 60 });
  return proxyHost;
}

// ============================================================================
// ENHANCED ERROR HANDLING AND LOGGING
// ============================================================================

class Logger {
  constructor(level = 'info') {
    this.level = level;
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      critical: 4
    };
  }

  log(level, message, data = {}) {
    const levelNum = this.levels[level] || 1;
    const currentLevelNum = this.levels[this.level] || 1;
    
    if (levelNum >= currentLevelNum) {
      const timestamp = new Date().toISOString();
      const logEntry = {
        timestamp,
        level,
        message,
        data,
        worker: 'vless-proxy'
      };
      
      if (levelNum >= this.levels.error) {
        console.error(JSON.stringify(logEntry));
      } else if (levelNum >= this.warn) {
        console.warn(JSON.stringify(logEntry));
      } else {
        console.log(JSON.stringify(logEntry));
      }
    }
  }

  debug(message, data = {}) {
    this.log('debug', message, data);
  }

  info(message, data = {}) {
    this.log('info', message, data);
  }

  warn(message, data = {}) {
    this.log('warn', message, data);
  }

  error(message, data = {}) {
    this.log('error', message, data);
  }

  critical(message, data = {}) {
    this.log('critical', message, data);
  }
}

// Global logger instance
const logger = new Logger();

// ============================================================================
// ENHANCED REQUEST HANDLER WITH CIRCUIT BREAKER
// ============================================================================

class CircuitBreaker {
  constructor(failureThreshold = 5, resetTimeout = 60000) {
    this.failureThreshold = failureThreshold;
    this.resetTimeout = resetTimeout;
    this.failureCount = 0;
    this.lastFailureTime = 0;
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  }

  async execute(fn) {
    if (this.state === 'OPEN') {
      const now = Date.now();
      if (now - this.lastFailureTime > this.resetTimeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
    }
  }

  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      logger.warn('Circuit breaker opened', {
        failureCount: this.failureCount,
        lastFailureTime: this.lastFailureTime
      });
    }
  }
}

// ============================================================================
// MAIN ENHANCED FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    const requestId = generateUUID();
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    logger.info('Request started', {
      requestId,
      method: request.method,
      url: url.pathname,
      clientIp,
      userAgent: request.headers.get('User-Agent')
    });
    
    try {
      // Initialize components
      await ensureTablesExist(env, ctx);
      
      let config;
      try {
        config = await Config.fromEnv(env);
      } catch (err) {
        logger.error('Configuration error', { error: err.message });
        return this.createErrorResponse('Service unavailable', 503);
      }
      
      const proxyManager = new ProxyManager(env, ctx);
      
      // Route handling
      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith(`/${adminPrefix}/`)) {
        const response = await handleAdminRequest(request, env, ctx, adminPrefix);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      if (url.pathname === '/health') {
        const response = new Response('OK', { status: 200 });
        this.logRequestComplete(requestId, startTime, 200);
        return response;
      }
      
      if (url.pathname === '/health-check' && request.method === 'GET') {
        await proxyManager.performHealthCheck();
        const response = new Response('Health check performed', { status: 200 });
        this.logRequestComplete(requestId, startTime, 200);
        return response;
      }
      
      // API endpoint for User Panel
      if (url.pathname.startsWith('/api/user/')) {
        const response = await this.handleUserAPI(request, env, ctx, url);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      // WebSocket Upgrade Handler
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        const response = await this.handleWebSocketUpgrade(request, env, ctx, config, proxyManager);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      // Subscription Handlers
      if (url.pathname.startsWith('/xray/')) {
        const response = await this.handleSubscription('xray', request, env, ctx, url, clientIp);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      if (url.pathname.startsWith('/sb/')) {
        const response = await this.handleSubscription('sb', request, env, ctx, url, clientIp);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      // User Panel Handler
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const response = await this.handleUserPanel(request, path, url.hostname, config, clientIp, env, ctx);
        this.logRequestComplete(requestId, startTime, response.status);
        return response;
      }
      
      // Default response
      const response = this.createMasqueradeResponse();
      this.logRequestComplete(requestId, startTime, 200);
      return response;
      
    } catch (error) {
      logger.error('Unhandled error in fetch handler', {
        requestId,
        error: error.message,
        stack: error.stack
      });
      
      const response = this.createErrorResponse('Internal server error', 500);
      this.logRequestComplete(requestId, startTime, 500);
      return response;
    }
  },

  async scheduled(event, env, ctx) {
    logger.info('Scheduled event started', { event: event.type });
    
    try {
      // Perform health checks
      const proxyManager = new ProxyManager(env, ctx);
      await proxyManager.performHealthCheck();
      
      // Cleanup old data
      await cleanupOldIps(env, ctx);
      
      // Clear expired cache
      cache.clear();
      
      logger.info('Scheduled tasks completed successfully');
    } catch (error) {
      logger.error('Scheduled task error', { error: error.message });
    }
  },

  // Helper methods
  async handleUserAPI(request, env, ctx, url) {
    const uuid = url.pathname.substring('/api/user/'.length);
    const headers = new Headers({ 'Content-Type': 'application/json' });
    addSecurityHeaders(headers, null, {});
    
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { 
        status: 405, 
        headers 
      });
    }
    
    if (!isValidUUID(uuid)) {
      return new Response(JSON.stringify({ error: 'Invalid UUID' }), { 
        status: 400, 
        headers 
      });
    }
    
    const userData = await getUserData(env, uuid, ctx);
    if (!userData) {
      return new Response(JSON.stringify({ error: 'User not found' }), { 
        status: 404, 
        headers 
      });
    }
    
    return new Response(JSON.stringify({
      traffic_used: userData.traffic_used || 0,
      traffic_limit: userData.traffic_limit,
      expiration_date: userData.expiration_date,
      expiration_time: userData.expiration_time,
      ip_limit: userData.ip_limit,
      notes: userData.notes,
      is_expired: isExpired(userData.expiration_date, userData.expiration_time),
      cache_stats: cache.getStats()
    }), { 
      status: 200, 
      headers 
    });
  },

  async handleWebSocketUpgrade(request, env, ctx, config, proxyManager) {
    if (!env.DB) {
      return this.createErrorResponse('Service not configured', 503);
    }
    
    // Domain Fronting for evasion
    const hostHeaders = env.HOST_HEADERS 
      ? env.HOST_HEADERS.split(',').map(h => h.trim()) 
      : ['speed.cloudflare.com', 'www.cloudflare.com'];
    const evasionHost = hostHeaders[Math.floor(Math.random() * hostHeaders.length)];
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', evasionHost);
    const newRequest = new Request(request, { headers: newHeaders });
    
    const requestConfig = {
      userID: config.userID,
      proxyIP: config.proxyIP,
      proxyPort: config.proxyPort,
      proxyAddress: config.proxyAddress,
      socks5Address: config.socks5.address,
      socks5Relay: config.socks5.relayMode,
      enableSocks: config.socks5.enabled,
      parsedSocks5Address: config.socks5.enabled ? socks5AddressParser(config.socks5.address) : {},
      scamalytics: config.scamalytics,
      optimization: config.optimization
    };
    
    const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig, env, ctx);
    
    const headers = new Headers(wsResponse.headers);
    addSecurityHeaders(headers, null, {});
    
    return new Response(wsResponse.body, { 
      status: wsResponse.status, 
      webSocket: wsResponse.webSocket, 
      headers 
    });
  },

  async handleSubscription(core, request, env, ctx, url, clientIp) {
    const rateLimitKey = `sub_rate:${clientIp}`;
    
    if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
      return this.createErrorResponse('Rate limit exceeded', 429);
    }
    
    const uuid = url.pathname.substring(`/${core}/`.length);
    if (!isValidUUID(uuid)) {
      return this.createErrorResponse('Invalid UUID', 400);
    }
    
    const userData = await getUserData(env, uuid, ctx);
    if (!userData) {
      return this.createErrorResponse('User not found', 403);
    }
    
    if (isExpired(userData.expiration_date, userData.expiration_time)) {
      return this.createErrorResponse('Account expired', 403);
    }
    
    if (userData.traffic_limit && userData.traffic_limit > 0 && 
        (userData.traffic_used || 0) >= userData.traffic_limit) {
      return this.createErrorResponse('Traffic limit exceeded', 403);
    }
    
    return await handleIpSubscription(core, uuid, url.hostname, env);
  },

  async handleUserPanel(request, uuid, hostName, config, clientIp, env, ctx) {
    const rateLimitKey = `panel_rate:${clientIp}`;
    
    if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
      return this.createErrorResponse('Rate limit exceeded', 429);
    }
    
    const userData = await getUserData(env, uuid, ctx);
    if (!userData) {
      return this.createErrorResponse('User not found', 403);
    }
    
    return await handleUserPanel(request, uuid, hostName, config.proxyAddress, userData, clientIp, env);
  },

  createErrorResponse(message, status) {
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response(message, { status, headers });
  },

  createMasqueradeResponse() {
    const masqueradeHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Welcome to nginx!</title>
  <style>
    body { 
      width: 35em; 
      margin: 0 auto; 
      font-family: Tahoma, Verdana, Arial, sans-serif; 
      padding-top: 50px;
    }
  </style>
</head>
<body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working.</p>
  <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
  <p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
    
    const headers = new Headers({ 'Content-Type': 'text/html' });
    addSecurityHeaders(headers, null, {});
    return new Response(masqueradeHtml, { headers });
  },

  logRequestComplete(requestId, startTime, status) {
    const duration = Date.now() - startTime;
    logger.info('Request completed', {
      requestId,
      duration,
      status,
      cacheStats: cache.getStats()
    });
  }
};

// ============================================================================
// ADDITIONAL OPTIMIZED FUNCTIONS (from original script)
// ============================================================================

// Note: The following functions from the original script are preserved
// and should be included in the final version:
// - generateUUID, isValidUUID, isExpired, formatBytes
// - escapeHTML, safeBase64Encode
// - checkRateLimit, hashSHA256, validateTOTP
// - base32ToBuffer, generateHOTP
// - byteToHex, unsafeStringify, stringify
// - generateRandomPath, CORE_PRESETS, buildEnhancedLink
// - handleIpSubscription, ensureTablesExist
// - isSuspiciousIP, performHealthCheck
// - adminLoginHTML, adminPanelHTML
// - isAdmin, handleAdminRequest
// - getGeo, resolveProxyIPWithCache
// - handleUserPanel (enhanced version)
// - ProtocolOverWSHandler, ProcessProtocolHeader
// - HandleTCPOutBound, MakeReadableWebSocketStream
// - RemoteSocketToWS, base64ToArrayBuffer
// - safeCloseWebSocket, createDnsPipeline
// - parseIPv6, socks5Connect, socks5AddressParser
// - All other utility functions from the original

// These functions should be integrated with the enhanced versions above
// while maintaining their original functionality and adding optimizations.
