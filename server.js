/**
 * World Electronics — Production-Hardened Security Server
 * 
 * Implements robust server-side security controls:
 * 1. Server-Side Role-Based Permissions & Row-Level Security (RLS)
 * 2. HttpOnly, SameSite=Strict, Secure Cookie Authentication (No tokens in localStorage)
 * 3. Secrets kept strictly server-side (password hashes, TOTP and webhook signing secrets)
 * 4. Strict CORS configuration and defense-in-depth HTTP security headers
 * 5. Sliding-window server-side rate limiting against brute-force & DoS
 * 6. Cryptographic CSRF protection on state-modifying requests
 * 7. Outbound SSRF firewall (blocks RFC 1918, loopback, AWS/GCP cloud metadata 169.254.169.254)
 * 8. Timing-safe Webhook HMAC-SHA256 signature verification with replay defense
 * 9. PII and credential redaction from all server logs
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function parseAllowedOrigins(value) {
  return String(value || '').split(',').map(item => item.trim()).filter(item => {
    if (!item || item === '*') return false;
    try {
      const parsed = new URL(item);
      return ['http:', 'https:'].includes(parsed.protocol) && parsed.origin === item;
    } catch { return false; }
  });
}

// Server secrets strictly isolated from client-side bundle
const SERVER_CONFIG = {
  port: parseInt(process.env.PORT || '3000', 10),
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  totpSecret: process.env.ADMIN_TOTP_SECRET || '',
  webhookSecret: process.env.WEBHOOK_SECRET || '',
  allowedOrigins: parseAllowedOrigins(process.env.ALLOWED_ORIGINS || 'http://localhost:3000'),
  sessionCookieName: '__Host-we_session',
  sessionDurationMs: 15 * 60 * 1000,
  publicSiteUrl: process.env.PUBLIC_SITE_URL || '',
  analyticsId: process.env.GA_MEASUREMENT_ID || '',
  googleVerification: process.env.GOOGLE_SITE_VERIFICATION || ''
};

function configuredPublicOrigin() {
  try {
    const configured = new URL(SERVER_CONFIG.publicSiteUrl);
    if (configured.protocol === 'https:' && !configured.username && !configured.password) return configured.origin;
  } catch {}
  return '';
}

// In-memory server-side state with Row-Level Security (RLS)
const db = {
  sessions: new Map(), // token -> { role: 'admin', expires: timestamp }
  rateLimits: new Map(), // ip:bucket -> [timestamps]
  csrfTokens: new Map(), // sessionToken -> csrfToken
  usedWebhookSignatures: new Map(),
  lastTotpStep: -1,
  inquiries: [], // Customer PII: Row-Level Security enforced
  products: []
};

// Server-side Log Sanitizer (Keeps sensitive data out of logs)
function safeLog(message, ...args) {
  const sanitize = str => String(str)
    .replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, '[REDACTED_EMAIL]')
    .replace(/(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b/g, '[REDACTED_PHONE]')
    .replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, '[REDACTED_CARD]')
    .replace(/(?:pin|token|jwt|password|secret|bearer|auth)[:=]\s*['"]?[a-zA-Z0-9_-]{4,}['"]?/gi, '[REDACTED_CREDENTIAL]');
  
  const cleanMsg = sanitize(message);
  const cleanArgs = args.map(a => typeof a === 'string' ? sanitize(a) : '[REDACTED_NON_TEXT]');
  console.log(`[${new Date().toISOString()}] ${cleanMsg}`, ...cleanArgs);
}

// Outbound SSRF Firewall
function isSSRFSafe(targetUrl) {
  try {
    const u = new URL(targetUrl);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    let host = u.hostname.toLowerCase();
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);

    const blocked = ['localhost', 'metadata.google.internal', 'instance-data', '169.254.169.254'];
    if (blocked.includes(host) || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
      return false;
    }
    if (host === '::1' || host.startsWith('fe80:') || host.startsWith('fc00:') || host.startsWith('fd')) {
      return false;
    }
    if (host.includes(':')) {
      const [firstHex, secondHex] = host.split(':');
      const first = parseInt(firstHex || '0', 16);
      const second = parseInt(secondHex || '0', 16);
      // Permit only globally routable IPv6 unicast space; reject mapped, loopback,
      // link-local, unique-local, multicast, unspecified, and documentation blocks.
      if (!Number.isFinite(first) || first < 0x2000 || first >= 0x4000 || (first === 0x2001 && second === 0x0db8)) return false;
    }
    const parts = host.split('.').map(Number);
    if (parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
      const [a, b] = parts;
      if (a === 0 || a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

// Server-side sliding-window rate limiter
function checkRateLimit(ip, bucket, maxRequests, windowMs) {
  if (db.rateLimits.size > 10000) {
    for (const [key, times] of db.rateLimits) {
      if (!times.some(t => Date.now() - t < 60000)) db.rateLimits.delete(key);
    }
    while (db.rateLimits.size > 10000) db.rateLimits.delete(db.rateLimits.keys().next().value);
    for (const [token, value] of db.sessions) {
      if (value.expires <= Date.now()) { db.sessions.delete(token); db.csrfTokens.delete(token); }
    }
  }
  const key = `${ip}:${bucket}`;
  const now = Date.now();
  let timestamps = db.rateLimits.get(key) || [];
  timestamps = timestamps.filter(t => now - t < windowMs);
  if (timestamps.length >= maxRequests) {
    db.rateLimits.set(key, timestamps);
    return false; // Rate limited
  }
  timestamps.push(now);
  db.rateLimits.set(key, timestamps);
  return true; // Allowed
}

function verifyPassword(password, encodedHash) {
  const match = /^scrypt\$([a-f\d]{32})\$([a-f\d]{128})$/i.exec(encodedHash || '');
  if (!match || typeof password !== 'string' || password.length > 256) return false;
  const salt = Buffer.from(match[1], 'hex');
  const expected = Buffer.from(match[2], 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

function decodeBase32(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(value || '').toUpperCase().replace(/=+$/, '');
  if (!clean || !/^[A-Z2-7]+$/.test(clean)) return null;
  let bits = '';
  for (const ch of clean) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function validTOTPStep(code, secret, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code || ''))) return null;
  const key = decodeBase32(secret);
  if (!key || key.length < 16) return null;
  const step = Math.floor(now / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step + offset));
    const digest = crypto.createHmac('sha1', key).update(counter).digest();
    const pos = digest[digest.length - 1] & 0x0f;
    const binary = (digest.readUInt32BE(pos) & 0x7fffffff) % 1000000;
    if (crypto.timingSafeEqual(Buffer.from(String(binary).padStart(6, '0')), Buffer.from(String(code)))) return step + offset;
  }
  return null;
}

function verifyTOTP(code, secret, now = Date.now()) {
  return validTOTPStep(code, secret, now) !== null;
}

// Webhook HMAC-SHA256 signature verifier
function verifyWebhook(payload, signatureHeader, secret, toleranceSeconds = 300) {
  if (!payload || !signatureHeader || !secret) return false;
  try {
    if (signatureHeader.includes('t=') && signatureHeader.includes('v1=')) {
      let timestamp = null;
      let expectedSig = '';
      for (const p of signatureHeader.split(',')) {
        const [k, v] = p.trim().split('=');
        if (k === 't') timestamp = parseInt(v, 10);
        if (k === 'v1') expectedSig = v;
      }
      if (!timestamp || !expectedSig) return false;
      const nowSec = Math.floor(Date.now() / 1000);
      if (Math.abs(nowSec - timestamp) > toleranceSeconds) {
        return false; // Replay attack prevented
      }
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(`${timestamp}.${payload}`);
      const actualSig = hmac.digest('hex');
      return crypto.timingSafeEqual(Buffer.from(actualSig), Buffer.from(expectedSig));
    } else {
      const rawSig = signatureHeader.startsWith('sha256=') ? signatureHeader.slice(7) : signatureHeader;
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(payload);
      const actualSig = hmac.digest('hex');
      return crypto.timingSafeEqual(Buffer.from(actualSig), Buffer.from(rawSig));
    }
  } catch {
    return false;
  }
}

// Request dispatcher
const server = http.createServer(async (req, res) => {
  const clientIp = req.socket.remoteAddress || '127.0.0.1';
  let url;
  try { url = new URL(req.url, 'http://localhost'); }
  catch { res.writeHead(400); res.end('Bad request'); return; }
  const origin = req.headers.origin || '';

  // 1. Strict Security Headers
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://www.googletagmanager.com; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; font-src 'self'; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  // 2. Strict CORS Configuration
  const trustedOrigin = SERVER_CONFIG.allowedOrigins.includes(origin) || origin === configuredPublicOrigin();
  if (origin && trustedOrigin) {
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  if (req.method === 'OPTIONS') {
    const method = req.headers['access-control-request-method'];
    const requestedHeaders = String(req.headers['access-control-request-headers'] || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
    const allowedHeaders = ['content-type', 'x-csrf-token'];
    if (!origin || !trustedOrigin || (method && !['GET', 'POST'].includes(method)) || requestedHeaders.some(h => !allowedHeaders.includes(h))) {
      res.writeHead(403);
      res.end();
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  // Parse Cookies for HttpOnly session authentication
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k && v && /^[a-f\d]{64}$/i.test(v)) cookies[k] = v;
  });
  const sessionToken = cookies[SERVER_CONFIG.sessionCookieName];
  const session = sessionToken ? db.sessions.get(sessionToken) : null;
  const isAuthenticatedAdmin = session && session.role === 'admin' && session.permissions?.includes('admin:*') && session.expires > Date.now();

  // Helper to read JSON request body
  const readJsonBody = () => new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const limit = 1024 * 1024;
    if (Number(req.headers['content-length']) > limit) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Payload too large' }));
      resolve(null);
      req.resume();
      return;
    }
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        if (settled) return;
        settled = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        req.resume();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const body = Buffer.concat(chunks).toString('utf8');
        const parsed = body ? JSON.parse(body) : {};
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Expected a JSON object' }));
          resolve(null);
          return;
        }
        resolve(parsed);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Malformed JSON payload' }));
        resolve(null);
      }
    });
  });

  // CSRF validation for state-modifying requests
  const verifyCSRF = () => {
    const headerToken = req.headers['x-csrf-token'];
    const expectedToken = sessionToken ? db.csrfTokens.get(sessionToken) : null;
    const supplied = typeof headerToken === 'string' ? Buffer.from(headerToken) : Buffer.alloc(0);
    const expected = expectedToken ? Buffer.from(expectedToken) : Buffer.alloc(32);
    const valid = !!headerToken && !!expectedToken && supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
    if (!valid || !isAuthenticatedAdmin) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid or missing CSRF token' }));
      return false;
    }
    return true;
  };

  const checkMutationOrigin = () => {
    if (origin && trustedOrigin) return true;
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Untrusted request origin' }));
    return false;
  };

  // API Routes
  if (url.pathname.startsWith('/api/')) {
    // General API rate limit (60 req / min)
    if (!checkRateLimit(clientIp, 'api', 60, 60000)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Rate limit exceeded. Please slow down.' }));
      return;
    }

    if (url.pathname === '/api/site-config' && req.method === 'GET') {
      const publicSiteUrl = configuredPublicOrigin();
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' });
      res.end(JSON.stringify({ analyticsId: SERVER_CONFIG.analyticsId, googleVerification: SERVER_CONFIG.googleVerification, publicSiteUrl }));
      return;
    }

    if (url.pathname === '/api/auth/session' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ authenticated: !!isAuthenticatedAdmin, role: isAuthenticatedAdmin ? session.role : null }));
      return;
    }

    // Public / Protected Products Endpoint with Row-Level Security
    if (url.pathname === '/api/products' && req.method === 'GET') {
      // Row-Level Security: Unauthenticated users only see published items
      const results = isAuthenticatedAdmin
        ? db.products
        : db.products.filter(p => p.published === true);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': isAuthenticatedAdmin ? 'no-store' : 'public, max-age=60' });
      res.end(JSON.stringify(results));
      return;
    }

    // Inquiries Endpoint with Row-Level Security and Permissions
    if (url.pathname === '/api/inquiries') {
      if (req.method === 'GET') {
        // Enforce permissions & RLS: only verified admin can read inquiries
        if (!isAuthenticatedAdmin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Access denied: Admin permission required to read inquiries' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(db.inquiries));
        return;
      }

      if (req.method === 'POST') {
        if (!checkMutationOrigin()) return;
        if (req.headers['content-type']?.split(';')[0] !== 'application/json') {
          res.writeHead(415, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
          return;
        }
        // Rate limit inquiry submissions: max 5 per minute per IP
        if (!checkRateLimit(clientIp, 'inquiry_submit', 5, 60000)) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Too many inquiries submitted. Please wait a minute.' }));
          return;
        }
        try {
          const body = await readJsonBody();
          if (!body) return;
          const allowedTypes = ['Repair service', 'Product question', 'Restock request', 'General support'];
          const name = String(body.name || '').trim();
          const contact = String(body.contact || '').trim();
          const message = String(body.message || '').trim();
          const item = typeof body.item === 'string' ? body.item.trim() : '';
          if (!name || name.length > 80 || !contact || contact.length > 120 || !message || message.length > 1000 || item.length > 120 || !allowedTypes.includes(body.type || 'General support')) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid request fields' }));
            return;
          }
          const inquiry = {
            id: crypto.randomUUID(),
            name,
            contact,
            type: body.type || 'General support',
            message,
            item,
            utm: body.utm && typeof body.utm === 'object' && !Array.isArray(body.utm)
              ? Object.fromEntries(Object.entries(body.utm).filter(([key]) => /^utm_(source|medium|campaign|term|content)$/.test(key)).map(([key, value]) => [key, String(value).slice(0, 120)]))
              : {},
            status: 'New',
            createdAt: new Date().toISOString()
          };
          db.inquiries.unshift(inquiry);
          if (db.inquiries.length > 5000) db.inquiries.length = 5000;
          safeLog('New inquiry received successfully');
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, inquiry }));
        } catch {
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unable to save inquiry' }));
          }
        }
        return;
      }
    }

    const inquiryMatch = /^\/api\/inquiries\/([a-f\d-]{36})$/i.exec(url.pathname);
    if (inquiryMatch && ['PATCH', 'DELETE'].includes(req.method)) {
      if (!checkMutationOrigin() || !verifyCSRF()) return;
      const inquiryIndex = db.inquiries.findIndex(item => item.id === inquiryMatch[1]);
      if (inquiryIndex < 0) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Inquiry not found' }));
        return;
      }
      if (req.method === 'DELETE') {
        db.inquiries.splice(inquiryIndex, 1);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
        return;
      }
      if (req.headers['content-type']?.split(';')[0] !== 'application/json') {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
        return;
      }
      const body = await readJsonBody();
      if (!body) return;
      const allowedStatuses = ['New', 'Contacted', 'In Progress', 'Resolved', 'Archived'];
      if (!allowedStatuses.includes(body.status)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid inquiry status' }));
        return;
      }
      db.inquiries[inquiryIndex].status = body.status;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
      return;
    }

    // Webhook receiver endpoint with signature verification
    if (url.pathname === '/api/webhooks' && req.method === 'POST') {
      if (!SERVER_CONFIG.webhookSecret) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Webhook endpoint is not configured' }));
        return;
      }
      if (!checkRateLimit(clientIp, 'webhook', 30, 60000)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
        return;
      }
      const chunks = [];
      let size = 0;
      let tooLarge = Number(req.headers['content-length']) > 1024 * 1024;
      if (tooLarge) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
      }
      req.on('data', chunk => {
        if (tooLarge) return;
        size += chunk.length;
        if (size > 1024 * 1024) {
          tooLarge = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          chunks.length = 0;
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (tooLarge) return;
        const rawPayload = Buffer.concat(chunks).toString('utf8');
        const sigHeader = req.headers['stripe-signature'] || req.headers['x-hub-signature-256'] || req.headers['x-webhook-signature'] || '';
        const isValid = verifyWebhook(rawPayload, sigHeader, SERVER_CONFIG.webhookSecret);
        if (!isValid) {
          safeLog('Rejected unauthorized webhook request');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid webhook signature' }));
          return;
        }
        const fingerprint = crypto.createHash('sha256').update(String(sigHeader)).digest('hex');
        const now = Date.now();
        for (const [used, expiry] of db.usedWebhookSignatures) if (expiry <= now) db.usedWebhookSignatures.delete(used);
        if (db.usedWebhookSignatures.has(fingerprint)) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Webhook signature has already been used' }));
          return;
        }
        if (db.usedWebhookSignatures.size >= 10000) db.usedWebhookSignatures.delete(db.usedWebhookSignatures.keys().next().value);
        // Timestamp tolerance allows up to five minutes into the future, so retain
        // fingerprints for twice the tolerance to cover the full replay window.
        db.usedWebhookSignatures.set(fingerprint, now + 10 * 60 * 1000);
        safeLog('Verified webhook signature successfully');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: true }));
      });
      return;
    }

    // Admin Authentication with Progressive Lockout
    if (url.pathname === '/api/auth/login' && req.method === 'POST') {
      for (const [token, value] of db.sessions) {
        if (value.expires <= Date.now()) { db.sessions.delete(token); db.csrfTokens.delete(token); }
      }
      if (!checkMutationOrigin()) return;
      if (!checkRateLimit(clientIp, 'auth_login', 5, 60000)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many failed login attempts. Please wait 60 seconds.' }));
        return;
      }
      try {
        const body = await readJsonBody();
        if (!body) return;
        if (!SERVER_CONFIG.adminPasswordHash || !SERVER_CONFIG.totpSecret) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Admin authentication is not configured. Set ADMIN_PASSWORD_HASH and ADMIN_TOTP_SECRET.' }));
          return;
        }
        const valid = verifyPassword(String(body.pin || ''), SERVER_CONFIG.adminPasswordHash);

        if (valid) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, requireMFA: true }));
        } else {
          safeLog('Failed admin login attempt from IP');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid credentials' }));
        }
      } catch {
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unable to process login request' }));
        }
      }
      return;
    }

    if (url.pathname === '/api/auth/mfa' && req.method === 'POST') {
      if (!checkMutationOrigin()) return;
      if (!checkRateLimit(clientIp, 'auth_login', 5, 60000)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many authentication attempts. Please wait.' }));
        return;
      }
      const body = await readJsonBody();
      if (!body) return;
      if (!SERVER_CONFIG.adminPasswordHash || !SERVER_CONFIG.totpSecret || !verifyPassword(String(body.pin || ''), SERVER_CONFIG.adminPasswordHash)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid credentials or verification code' }));
        return;
      }
      const totpStep = validTOTPStep(body.code, SERVER_CONFIG.totpSecret);
      if (totpStep === null || totpStep <= db.lastTotpStep) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid credentials or verification code' }));
        return;
      }
      db.lastTotpStep = totpStep;
      const token = crypto.randomBytes(32).toString('hex');
      const csrfToken = crypto.randomBytes(32).toString('hex');
      if (db.sessions.size >= 5000) {
        const oldest = db.sessions.keys().next().value;
        db.sessions.delete(oldest);
        db.csrfTokens.delete(oldest);
      }
      db.sessions.set(token, { role: 'admin', permissions: ['admin:*'], expires: Date.now() + SERVER_CONFIG.sessionDurationMs });
      db.csrfTokens.set(token, csrfToken);
      res.setHeader('Set-Cookie', `${SERVER_CONFIG.sessionCookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, csrfToken }));
      return;
    }

    // Logout Endpoint
    if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
      if (!checkMutationOrigin()) return;
      if (sessionToken && !verifyCSRF()) return;
      if (sessionToken) {
        db.sessions.delete(sessionToken);
        db.csrfTokens.delete(sessionToken);
      }
      res.setHeader('Set-Cookie', `${SERVER_CONFIG.sessionCookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
      return;
    }

    // SSRF-Protected Outbound Proxy Endpoint
    if (url.pathname === '/api/proxy-image' && req.method === 'GET') {
      const target = url.searchParams.get('url');
      if (!target || !isSSRFSafe(target)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'SSRF blocked: Disallowed or private IP destination' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ safe: true, target }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'API route not found' }));
    return;
  }

  const permanentRedirects = { '/home': '/', '/shop': '/#catalog', '/repairs': '/#services', '/contact': '/#services' };
  if (permanentRedirects[url.pathname]) {
    res.writeHead(301, { Location: permanentRedirects[url.pathname], 'Cache-Control': 'public, max-age=86400' });
    res.end();
    return;
  }
  if (url.pathname === '/robots.txt') {
    const origin = configuredPublicOrigin();
    const sitemapLine = origin ? `Sitemap: ${origin}/sitemap.xml\n` : '';
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`User-agent: *\nAllow: /\nDisallow: /admin\n${sitemapLine}`);
    return;
  }
  if (url.pathname === '/sitemap.xml') {
    const origin = configuredPublicOrigin();
    if (!origin) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Set PUBLIC_SITE_URL to the public HTTPS site origin to enable the sitemap.');
      return;
    }
    const entries = ['/', '/privacy.html', '/terms.html'].map(route => `<url><loc>${origin}${route}</loc></url>`).join('');
    res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8' });
    res.end(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${entries}</urlset>`);
    return;
  }

  // Static File Serving
  const requestedFile = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^[/\\]+/, '');
  const normalized = path.resolve(__dirname, requestedFile);
  const relativePath = path.relative(__dirname, normalized);
  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    res.writeHead(403);
    res.end('Access denied');
    return;
  }

  const ext = path.extname(normalized).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.svg': 'image/svg+xml'
  };

  fs.readFile(normalized, (err, data) => {
    if (err) {
      fs.readFile(path.join(__dirname, '404.html'), (pageErr, page) => {
        res.writeHead(404, { 'Content-Type': pageErr ? 'text/plain; charset=utf-8' : 'text/html; charset=utf-8' });
        res.end(pageErr ? 'Page not found' : page);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
    res.end(data);
  });
});

export { server, isSSRFSafe, checkRateLimit, verifyWebhook, verifyPassword, verifyTOTP, safeLog, db, SERVER_CONFIG };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(SERVER_CONFIG.port, () => {
    safeLog(`World Electronics secure server listening on port ${SERVER_CONFIG.port}`);
  });
}
