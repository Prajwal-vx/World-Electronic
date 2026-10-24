/**
 * World Electronics — Production-Hardened Storefront & Administration Engine
 * 
 * Security Controls Implemented:
 * 1. Cryptographic Authentication: PBKDF2-SHA256 (100,000 rounds) + 16-byte random salt.
 * 2. Brute-Force & Rate-Limiting Protection: Exponential delay and progressive lockout.
 * 3. Session Security: Ephemeral session tokens, activity tracking, 15-minute idle timeout.
 * 4. Stored & DOM XSS Prevention: Context-aware HTML entity escaping across all dynamic templates.
 * 5. Prototype Pollution Defense: Strict sanitization and key-filtering (__proto__, constructor).
 * 6. Cross-Tab Sync Hardening: Schema validation of BroadcastChannel & storage events; credentials non-syncable.
 * 7. Mass-Assignment & Parameter Tampering Guards: Explicit allowlists on quick-edits and status changes.
 * 8. Safe Data Portability: Automatic credential redaction during exports; 2MB size cap and deep validation on imports.
 * 9. Inquiry Spam Defense: Client-side rate limiting (max 5/min) and bounded storage.
 * 10. Navigation & Tabnabbing Protection: Validated outbound links with noopener/noreferrer.
 */

/* 1. Configuration, Seed Data, and Secure Defaults */
const CONFIG = Object.freeze({
  prefix: 'worldElectronics.v1',
  channel: 'world-electronics-sync-v1',
  schema: 1,
  categories: Object.freeze(['Home Appliances', 'Laptops & PCs', 'Mobile & Tablets', 'Accessories']),
  icons: Object.freeze({
    'Home Appliances': '⌂',
    'Laptops & PCs': '▰',
    'Mobile & Tablets': '▣',
    'Accessories': '⌘'
  }),
  maxImportBytes: 2 * 1024 * 1024 // 2 MB limit
});

const seedProducts = [
  { id: 'lap-study-01', name: 'Everyday Student Laptop', brand: 'Acer', model: 'Aspire 5 A515', category: 'Laptops & PCs', price: 649, previousPrice: 699, stock: 12, threshold: 4, featured: true, published: true, description: 'A dependable everyday laptop for classes, research, and streaming. Comfortable keyboard, quick startup, and room to grow.', specs: { Processor: 'Intel Core i5', Memory: '16 GB', Storage: '512 GB SSD', Display: '15.6” Full HD' }, keywords: ['student', 'study', 'laptop', 'school'], warranty: '1 year limited', rating: 4.6, icon: '💻' },
  { id: 'lap-work-02', name: 'Pro Productivity Laptop', brand: 'Lenovo', model: 'ThinkPad E14 Gen 5', category: 'Laptops & PCs', price: 1199, previousPrice: 1299, stock: 3, threshold: 4, featured: true, published: true, description: 'A focused work companion with a durable build, clear display, and reliable performance for busy days.', specs: { Processor: 'AMD Ryzen 7', Memory: '16 GB', Storage: '1 TB SSD', Display: '14” WUXGA' }, keywords: ['office', 'business', 'work', 'portable'], warranty: '1 year limited', rating: 4.8, icon: '🖥️' },
  { id: 'lap-game-03', name: 'Performance Gaming Laptop', brand: 'ASUS', model: 'TUF Gaming A15', category: 'Laptops & PCs', price: 1599, previousPrice: null, stock: 0, threshold: 3, featured: true, published: true, description: 'A capable gaming and creative-work machine with a high-refresh display and dedicated graphics.', specs: { Processor: 'AMD Ryzen 7', Memory: '16 GB', Graphics: 'GeForce RTX 4060', Display: '15.6” 144 Hz' }, keywords: ['gaming', 'creator', 'graphics', 'high performance'], warranty: '1 year limited', rating: 4.7, icon: '🎮' },
  { id: 'pc-home-04', name: 'Compact Home Desktop', brand: 'HP', model: 'Pavilion TP01', category: 'Laptops & PCs', price: 899, previousPrice: null, stock: 6, threshold: 3, featured: false, published: true, description: 'A tidy desktop setup for home computing, family projects, and video calls.', specs: { Processor: 'Intel Core i5', Memory: '16 GB', Storage: '512 GB SSD', Connectivity: 'Wi-Fi 6' }, keywords: ['desktop', 'home office', 'family'], warranty: '1 year limited', rating: 4.4, icon: '🖥️' },
  { id: 'mob-premium-05', name: 'Pro Camera Smartphone', brand: 'Samsung', model: 'Galaxy S24', category: 'Mobile & Tablets', price: 999, previousPrice: 1099, stock: 8, threshold: 3, featured: true, published: true, description: 'A premium everyday smartphone with a vivid display, capable camera system, and long software support.', specs: { Display: '6.2” AMOLED', Storage: '256 GB', Camera: '50 MP triple camera', Connectivity: '5G' }, keywords: ['phone', 'smartphone', 'camera', 'android'], warranty: '1 year limited', rating: 4.8, icon: '📱' },
  { id: 'mob-android-06', name: 'Everyday Android Phone', brand: 'Motorola', model: 'Edge 50 Fusion', category: 'Mobile & Tablets', price: 499, previousPrice: null, stock: 2, threshold: 4, featured: false, published: true, description: 'A balanced smartphone with a bright screen, dependable battery, and plenty of space for daily essentials.', specs: { Display: '6.7” pOLED', Storage: '256 GB', Camera: '50 MP', Battery: '5000 mAh' }, keywords: ['phone', 'android', 'value', '5g'], warranty: '1 year limited', rating: 4.3, icon: '📱' },
  { id: 'mob-budget-07', name: 'Simple Budget Smartphone', brand: 'Nokia', model: 'G42 5G', category: 'Mobile & Tablets', price: 229, previousPrice: 259, stock: 15, threshold: 5, featured: false, published: true, description: 'An approachable, easy-to-use smartphone with solid battery life and everyday connectivity.', specs: { Display: '6.56” HD+', Storage: '128 GB', Battery: '5000 mAh', Connectivity: '5G' }, keywords: ['budget', 'phone', 'starter', 'value'], warranty: '1 year limited', rating: 4.1, icon: '📲' },
  { id: 'tab-08', name: 'Everyday Tablet', brand: 'Apple', model: 'iPad 10th Gen', category: 'Mobile & Tablets', price: 449, previousPrice: null, stock: 5, threshold: 3, featured: true, published: true, description: 'A versatile tablet for reading, learning, video calls, and creative downtime.', specs: { Display: '10.9” Liquid Retina', Storage: '64 GB', Connectivity: 'Wi-Fi', Camera: '12 MP' }, keywords: ['tablet', 'ipad', 'study', 'portable'], warranty: '1 year limited', rating: 4.7, icon: '📟' },
  { id: 'tv-09', name: '4K Smart Television', brand: 'LG', model: 'UQ75 55-inch', category: 'Home Appliances', price: 699, previousPrice: 799, stock: 4, threshold: 3, featured: true, published: true, description: 'A crisp 4K screen with built-in streaming apps for a welcoming family entertainment setup.', specs: { Display: '55” 4K UHD', HDR: 'HDR10', Smart: 'webOS', Connectivity: 'Wi-Fi, HDMI' }, keywords: ['tv', 'television', 'living room', '4k'], warranty: '2 years limited', rating: 4.5, icon: '📺' },
  { id: 'fridge-10', name: 'Frost-Free Family Refrigerator', brand: 'Whirlpool', model: 'WRT318FZDM', category: 'Home Appliances', price: 1099, previousPrice: null, stock: 1, threshold: 3, featured: false, published: true, description: 'A practical frost-free refrigerator with flexible shelves and generous family storage.', specs: { Capacity: '18 cu. ft.', Type: 'Top freezer', Finish: 'Stainless look', Efficiency: 'ENERGY STAR' }, keywords: ['fridge', 'refrigerator', 'kitchen', 'appliance'], warranty: '1 year limited', rating: 4.4, icon: '🧊' },
  { id: 'washer-11', name: 'Front-Load Washing Machine', brand: 'Samsung', model: 'WF45T6000AW', category: 'Home Appliances', price: 849, previousPrice: 949, stock: 7, threshold: 3, featured: false, published: true, description: 'An efficient front-load washer with helpful cycles and a generous drum for busy households.', specs: { Capacity: '4.5 cu. ft.', Type: 'Front load', Cycles: '12', Efficiency: 'ENERGY STAR' }, keywords: ['washer', 'washing machine', 'laundry'], warranty: '1 year limited', rating: 4.6, icon: '🫧' },
  { id: 'micro-12', name: 'Compact Countertop Microwave', brand: 'Panasonic', model: 'NN-SN67KS', category: 'Home Appliances', price: 189, previousPrice: null, stock: 10, threshold: 3, featured: false, published: true, description: 'Quick, even heating in a compact format that fits neatly on a countertop.', specs: { Capacity: '1.2 cu. ft.', Power: '1200 W', Controls: 'Inverter', Finish: 'Stainless steel' }, keywords: ['microwave', 'kitchen', 'appliance'], warranty: '1 year limited', rating: 4.3, icon: '♨️' },
  { id: 'audio-13', name: 'Wireless Noise-Canceling Headphones', brand: 'Sony', model: 'WH-CH720N', category: 'Accessories', price: 149, previousPrice: 179, stock: 0, threshold: 4, featured: true, published: true, description: 'Lightweight wireless headphones for focused listening, calls, and commutes.', specs: { Connection: 'Bluetooth 5.2', Battery: 'Up to 35 hours', NoiseControl: 'Active noise canceling', Mic: 'Built-in' }, keywords: ['headphones', 'audio', 'wireless', 'commute'], warranty: '1 year limited', rating: 4.5, icon: '🎧' },
  { id: 'keyboard-14', name: 'Wireless Keyboard & Mouse Set', brand: 'Logitech', model: 'MK540', category: 'Accessories', price: 69, previousPrice: null, stock: 9, threshold: 4, featured: false, published: true, description: 'A comfortable wireless desktop set with a familiar layout and easy setup.', specs: { Connection: '2.4 GHz USB receiver', Layout: 'Full-size', Battery: 'Long-life', Compatibility: 'Windows, ChromeOS' }, keywords: ['keyboard', 'mouse', 'office', 'accessory'], warranty: '1 year limited', rating: 4.4, icon: '⌨️' },
  { id: 'charger-15', name: '65W USB-C Fast Charger', brand: 'Anker', model: 'Nano II 65W', category: 'Accessories', price: 39, previousPrice: 49, stock: 2, threshold: 5, featured: false, published: true, description: 'A compact USB-C charger for compatible phones, tablets, and many laptops.', specs: { Output: '65 W max', Ports: '1 × USB-C', Technology: 'GaN II', Compatibility: 'USB-C PD devices' }, keywords: ['charger', 'usb c', 'power', 'travel'], warranty: '18 months', rating: 4.6, icon: '🔌' },
  { id: 'storage-16', name: 'Portable SSD 1TB', brand: 'Samsung', model: 'T7 Shield', category: 'Accessories', price: 119, previousPrice: null, stock: 14, threshold: 4, featured: false, published: true, description: 'Fast portable storage with a rugged exterior for creative projects and everyday backups.', specs: { Capacity: '1 TB', Interface: 'USB 3.2 Gen 2', Speed: 'Up to 1050 MB/s', Protection: 'IP65 rated' }, keywords: ['ssd', 'storage', 'backup', 'portable'], warranty: '3 years limited', rating: 4.8, icon: '💾' }
];

const seedServices = [
  { id: 'svc-laptop', name: 'Laptop Diagnostics', type: 'Computer repair', price: 49, description: 'A careful assessment of laptop hardware, software, and performance concerns.', published: true },
  { id: 'svc-phone', name: 'Smartphone Repair Consultation', type: 'Mobile support', price: 25, description: 'Talk through phone concerns and possible next steps with a technician.', published: true },
  { id: 'svc-appliance', name: 'Appliance Diagnostics', type: 'Home appliance', price: 59, description: 'Initial troubleshooting for common household electronics and appliance issues.', published: true },
  { id: 'svc-general', name: 'General Electronics Support', type: 'Consultation', price: 35, description: 'Friendly help with setup, connectivity, and everyday technology questions.', published: true }
];

const defaults = Object.freeze({
  storeName: 'World Electronics',
  currency: 'NPR',
  locale: 'en-NP',
  email: '',
  phone: '',
  whatsapp: '',
  address: '',
  latitude: '',
  longitude: '',
  hours: Object.freeze({
    mon: ['09:00', '18:00'],
    tue: ['09:00', '18:00'],
    wed: ['09:00', '18:00'],
    thu: ['09:00', '18:00'],
    fri: ['09:00', '18:00'],
    sat: ['10:00', '16:00'],
    sun: null
  }),
  lowStock: 4,
  broadcast: true,
  activityLimit: 50,
  servicesDefault: 'By appointment',
  timezone: 'local'
});

const keys = Object.freeze({
  products: 'products',
  services: 'services',
  inquiries: 'inquiries',
  settings: 'settings',
  activity: 'activity',
  preferences: 'preferences'
});

/* 2. Security Utilities & Cryptographic Primitives */
const Security = {
  /**
   * Complete HTML entity encoding to neutralize Stored and Reflected XSS
   * Covers &, <, >, ", ', `, and /
   */
  escapeHTML(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"'`/]/g, c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '`': '&#96;',
      '/': '&#x2F;'
    }[c]));
  },

  safeText(s, maxLen = 1000) {
    if (typeof s !== 'string') return '';
    return s.trim().slice(0, maxLen);
  },

  /**
   * SSRF Protection: Blocks loopback, private networks (RFC 1918),
   * cloud metadata (169.254.169.254, AWS/GCP/Azure), IPv6 private, and non-standard IPs.
   */
  isSSRFSafeURL(v) {
    if (!v || typeof v !== 'string') return false;
    try {
      const u = new URL(v.trim());
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
      let host = u.hostname.toLowerCase();
      if (!host) return false;
      if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);

      const blockedHosts = ['localhost', 'metadata.google.internal', 'instance-data', '169.254.169.254'];
      if (blockedHosts.includes(host) || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
        return false;
      }
      if (host === '::1' || host === '::' || host.startsWith('fe80:') || host.startsWith('fc00:') || host.startsWith('fd')) {
        return false;
      }
      if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) return false;

      const ipv4Parts = host.split('.').map(Number);
      if (ipv4Parts.length === 4 && ipv4Parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
        const [a, b] = ipv4Parts;
        if (a === 0 || a === 127) return false; // Loopback
        if (a === 10) return false; // 10.0.0.0/8
        if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12
        if (a === 192 && b === 168) return false; // 192.168.0.0/16
        if (a === 169 && b === 254) return false; // Link-local & cloud metadata
        if (a === 100 && b >= 64 && b <= 127) return false; // Carrier-grade NAT
        if (a >= 224) return false; // Multicast & reserved
      }
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Safe URL validation: restricts protocol strictly to https: or http: and enforces SSRF safety
   * Prevents javascript:, data:, blob:, file:, and control-character injection
   */
  safeURL(v) {
    if (!v || typeof v !== 'string') return '';
    try {
      const u = new URL(v.trim());
      if ((u.protocol === 'https:' || u.protocol === 'http:') && this.isSSRFSafeURL(u.href)) {
        return u.href;
      }
      return '';
    } catch {
      return '';
    }
  },

  /**
   * Prototype pollution defense: deep clones objects while stripping
   * __proto__, constructor, and prototype properties.
   */
  deepCloneSafe(obj, depth = 0) {
    if (depth > 20 || obj === null || typeof obj !== 'object') {
      return obj;
    }
    if (Array.isArray(obj)) {
      return obj.map(item => this.deepCloneSafe(item, depth + 1));
    }
    const clean = Object.create(null);
    for (const key of Object.keys(obj)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      clean[key] = this.deepCloneSafe(obj[key], depth + 1);
    }
    return { ...clean };
  },

  randomHex(bytes = 16) {
    const arr = new Uint8Array(bytes);
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(arr);
    } else if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(arr);
    } else {
      for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * PBKDF2 Password / PIN hashing using Web Cryptography API
   * Generates a 256-bit derived key using 100,000 iterations of SHA-256
   */
  async hashPIN(pin, saltHex) {
    const cryptoSubtle = (typeof window !== 'undefined' && window.crypto?.subtle) ||
                         (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle);
    if (!cryptoSubtle) {
      throw new Error('Web Cryptography API is unavailable.');
    }
    const enc = new TextEncoder();
    const pinBuffer = enc.encode(String(pin));
    const saltMatch = saltHex.match(/.{1,2}/g) || [];
    const saltBuffer = new Uint8Array(saltMatch.map(b => parseInt(b, 16)));

    const keyMaterial = await cryptoSubtle.importKey(
      'raw',
      pinBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await cryptoSubtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return Array.from(new Uint8Array(derivedBits), b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Timing-safe string comparison to protect against timing attacks
   */
  timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let mismatch = a.length === b.length ? 0 : 1;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const charA = i < a.length ? a.charCodeAt(i) : 0;
      const charB = i < b.length ? b.charCodeAt(i) : 0;
      mismatch |= charA ^ charB;
    }
    return mismatch === 0;
  },

  /**
   * Cryptographic Anti-CSRF Protection
   */
  _csrfToken: null,

  generateCSRFToken() {
    this._csrfToken = this.randomHex(32);
    return this._csrfToken;
  },

  getCSRFToken() {
    if (!this._csrfToken) {
      this.generateCSRFToken();
    }
    return this._csrfToken;
  },

  verifyCSRFToken(token) {
    if (!token || !this._csrfToken) return false;
    return this.timingSafeEqual(String(token), this._csrfToken);
  },

  /**
   * HMAC-SHA256 signature computation using Web Crypto API
   */
  async computeHmacSha256(keyStr, dataStr) {
    const cryptoSubtle = (typeof window !== 'undefined' && window.crypto?.subtle) ||
                         (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle);
    if (!cryptoSubtle) throw new Error('Web Cryptography API is unavailable.');
    const enc = new TextEncoder();
    const key = await cryptoSubtle.importKey('raw', enc.encode(keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await cryptoSubtle.sign('HMAC', key, enc.encode(dataStr));
    return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Webhook Signature Verification with Replay Attack Prevention (toleranceSeconds)
   */
  async verifyWebhookSignature(payload, signatureHeader, secret, toleranceSeconds = 300) {
    if (!payload || !signatureHeader || !secret) return false;
    try {
      if (signatureHeader.includes('t=') && signatureHeader.includes('v1=')) {
        let timestamp = null;
        let expectedSig = '';
        const parts = signatureHeader.split(',');
        for (const p of parts) {
          const [k, v] = p.trim().split('=');
          if (k === 't') timestamp = parseInt(v, 10);
          if (k === 'v1') expectedSig = v;
        }
        if (!timestamp || !expectedSig) return false;
        const nowSec = Math.floor(Date.now() / 1000);
        if (Math.abs(nowSec - timestamp) > toleranceSeconds) {
          return false; // Replay attack prevented
        }
        const dataToSign = `${timestamp}.${payload}`;
        const actualSig = await this.computeHmacSha256(secret, dataToSign);
        return this.timingSafeEqual(actualSig, expectedSig);
      } else {
        const rawSig = signatureHeader.startsWith('sha256=') ? signatureHeader.slice(7) : signatureHeader;
        const actualSig = await this.computeHmacSha256(secret, payload);
        return this.timingSafeEqual(actualSig, rawSig);
      }
    } catch {
      return false;
    }
  },

  /**
   * Multi-Factor Authentication: RFC 6238 Standard TOTP Implementation
   */
  TOTP: {
    base32Alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

    base32Decode(str) {
      const alphabet = this.base32Alphabet;
      let bits = 0, value = 0;
      const output = [];
      const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
      for (let i = 0; i < clean.length; i++) {
        const idx = alphabet.indexOf(clean[i]);
        if (idx === -1) continue;
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
          output.push((value >>> (bits - 8)) & 255);
          bits -= 8;
        }
      }
      return new Uint8Array(output);
    },

    base32Encode(bytes) {
      const alphabet = this.base32Alphabet;
      let bits = 0, value = 0, output = '';
      for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
          output += alphabet[(value >>> (bits - 5)) & 31];
          bits -= 5;
        }
      }
      if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31];
      }
      return output;
    },

    generateSecret(bytes = 20) {
      const arr = new Uint8Array(bytes);
      if (typeof window !== 'undefined' && window.crypto?.getRandomValues) {
        window.crypto.getRandomValues(arr);
      } else if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
        globalThis.crypto.getRandomValues(arr);
      } else {
        for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
      }
      return this.base32Encode(arr);
    },

    async generateTOTP(secretBase32, timeSec = Math.floor(Date.now() / 1000)) {
      const cryptoSubtle = (typeof window !== 'undefined' && window.crypto?.subtle) ||
                           (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle);
      if (!cryptoSubtle) throw new Error('Web Cryptography API is unavailable.');
      const keyBytes = this.base32Decode(secretBase32);
      const counter = Math.floor(timeSec / 30);
      const buffer = new ArrayBuffer(8);
      const view = new DataView(buffer);
      const high = Math.floor(counter / 0x100000000);
      const low = counter >>> 0;
      view.setUint32(0, high, false);
      view.setUint32(4, low, false);

      const key = await cryptoSubtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
      const signature = await cryptoSubtle.sign('HMAC', key, buffer);
      const hmac = new Uint8Array(signature);
      const offset = hmac[hmac.length - 1] & 0x0f;
      const codeVal = ((hmac[offset] & 0x7f) << 24) |
                      ((hmac[offset + 1] & 0xff) << 16) |
                      ((hmac[offset + 2] & 0xff) << 8) |
                      (hmac[offset + 3] & 0xff);
      return String(codeVal % 1000000).padStart(6, '0');
    },

    async verifyTOTP(token, secretBase32, window = 1, timeSec = Math.floor(Date.now() / 1000)) {
      if (!token || typeof token !== 'string') return false;
      const cleanToken = token.trim().replace(/\s+/g, '');
      if (!/^\d{6}$/.test(cleanToken)) return false;
      for (let offset = -window; offset <= window; offset++) {
        const stepTime = timeSec + (offset * 30);
        const code = await this.generateTOTP(secretBase32, stepTime);
        if (Security.timingSafeEqual(cleanToken, code)) {
          return true;
        }
      }
      return false;
    },

    generateRecoveryCodes(count = 8) {
      const codes = [];
      for (let i = 0; i < count; i++) {
        const part1 = Security.randomHex(2).toUpperCase();
        const part2 = Security.randomHex(2).toUpperCase();
        codes.push(`${part1}-${part2}`);
      }
      return codes;
    }
  },

  /**
   * Log Sanitization: Automatically scrubs PII, credentials, tokens, and cards
   */
  redactSensitiveData(text) {
    if (typeof text !== 'string') return text;
    return text
      .replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, '[REDACTED_EMAIL]')
      .replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, '[REDACTED_CARD]')
      .replace(/(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b/g, '[REDACTED_PHONE]')
      .replace(/(?:pin|token|jwt|password|secret|bearer|auth)[:=]\s*['"]?[a-zA-Z0-9_-]{4,}['"]?/gi, '[REDACTED_CREDENTIAL]');
  },

  /**
   * Database Security & Parameterized Query Builder (SQL Injection Defense)
   */
  DatabaseSecurity: {
    sanitizeIdentifier(ident) {
      if (typeof ident !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(ident)) {
        throw new Error('Invalid SQL identifier detected: SQL injection blocked.');
      }
      return `"${ident.replace(/"/g, '""')}"`;
    },

    buildParameterizedQuery(table, filters = {}) {
      const safeTable = this.sanitizeIdentifier(table);
      const clauses = [];
      const params = [];
      let idx = 1;
      for (const [col, val] of Object.entries(filters)) {
        const safeCol = this.sanitizeIdentifier(col);
        clauses.push(`${safeCol} = $${idx++}`);
        params.push(val);
      }
      const where = clauses.length ? ` WHERE ${clauses.join(' AND ')}` : '';
      return {
        sql: `SELECT * FROM ${safeTable}${where}`,
        params
      };
    }
  }
};

/* 3. Schema Validation & Input Sanitization Engine */
const Validator = {
  isValidId(id) {
    return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,60}$/.test(id);
  },

  isValidCurrency(code) {
    return typeof code === 'string' && /^[A-Z]{3}$/.test(code);
  },

  isValidLocale(locale) {
    return typeof locale === 'string' && /^[a-z]{2,3}(-[A-Za-z0-9]+)*$/i.test(locale);
  },

  isValidCoords(lat, lng) {
    if (lat === '' && lng === '') return true;
    const nLat = Number(lat), nLng = Number(lng);
    return Number.isFinite(nLat) && Number.isFinite(nLng) && nLat >= -90 && nLat <= 90 && nLng >= -180 && nLng <= 180;
  },

  isValidEmail(email) {
    if (!email) return true;
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) && email.length <= 120;
  },

  isValidTime(time) {
    return typeof time === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(time);
  },

  isSafeProduct(p) {
    if (!p || typeof p !== 'object') return false;
    if (!this.isValidId(p.id)) return false;
    if (typeof p.name !== 'string' || !p.name.trim() || p.name.length > 100) return false;
    if (typeof p.brand !== 'string' || !p.brand.trim() || p.brand.length > 60) return false;
    if (typeof p.model !== 'string' || !p.model.trim() || p.model.length > 80) return false;
    if (!CONFIG.categories.includes(p.category)) return false;
    if (typeof p.price !== 'number' || !Number.isFinite(p.price) || p.price <= 0 || p.price > 1000000) return false;
    if (p.previousPrice !== null && (typeof p.previousPrice !== 'number' || !Number.isFinite(p.previousPrice) || p.previousPrice < 0 || p.previousPrice > 1000000)) return false;
    if (!Number.isInteger(p.stock) || p.stock < 0 || p.stock > 100000) return false;
    if (p.threshold !== undefined && (!Number.isInteger(p.threshold) || p.threshold < 1 || p.threshold > 1000)) return false;
    if (typeof p.description !== 'string' || !p.description.trim() || p.description.length > 1000) return false;
    if (p.image && typeof p.image === 'string' && p.image.length > 500) return false;
    if (p.specs && typeof p.specs === 'object') {
      const entries = Object.entries(p.specs);
      if (entries.length > 30) return false;
      for (const [k, v] of entries) {
        if (typeof k !== 'string' || typeof v !== 'string' || k.length > 80 || v.length > 120) return false;
      }
    }
    if (p.keywords && (!Array.isArray(p.keywords) || p.keywords.length > 30 || p.keywords.some(k => typeof k !== 'string' || k.length > 40))) return false;
    return true;
  },

  isSafeService(s) {
    if (!s || typeof s !== 'object') return false;
    if (!this.isValidId(s.id)) return false;
    if (typeof s.name !== 'string' || !s.name.trim() || s.name.length > 100) return false;
    if (typeof s.type !== 'string' || !s.type.trim() || s.type.length > 60) return false;
    if (typeof s.price !== 'number' || !Number.isFinite(s.price) || s.price < 0 || s.price > 100000) return false;
    if (typeof s.description !== 'string' || !s.description.trim() || s.description.length > 1000) return false;
    return true;
  },

  isSafeInquiry(i) {
    if (!i || typeof i !== 'object') return false;
    if (!this.isValidId(i.id)) return false;
    if (typeof i.name !== 'string' || !i.name.trim() || i.name.length > 80) return false;
    if (typeof i.contact !== 'string' || !i.contact.trim() || i.contact.length > 120) return false;
    if (!['Repair service', 'Product question', 'Restock request', 'General support'].includes(i.type)) return false;
    if (typeof i.message !== 'string' || !i.message.trim() || i.message.length > 1000) return false;
    if (!['New', 'Contacted', 'In Progress', 'Resolved', 'Archived'].includes(i.status)) return false;
    return true;
  },

  validateSettings(s) {
    if (!s || typeof s !== 'object') return false;
    if (typeof s.storeName !== 'string' || !s.storeName.trim() || s.storeName.length > 80) return false;
    if (!this.isValidCurrency(s.currency)) return false;
    if (!this.isValidLocale(s.locale)) return false;
    if (!this.isValidEmail(s.email)) return false;
    if (typeof s.phone === 'string' && s.phone.length > 40) return false;
    if (typeof s.whatsapp === 'string' && s.whatsapp.length > 40) return false;
    if (typeof s.address === 'string' && s.address.length > 200) return false;
    if (!this.isValidCoords(s.latitude, s.longitude)) return false;
    if (!Number.isInteger(s.lowStock) || s.lowStock < 1 || s.lowStock > 1000) return false;
    if (!Number.isInteger(s.activityLimit) || s.activityLimit < 5 || s.activityLimit > 500) return false;
    return true;
  },

  /**
   * File Upload Validation (Extension, MIME type, Size, and Content Safety)
   */
  validateFileUpload(file, options = {}) {
    if (!file || typeof file !== 'object') {
      return { valid: false, error: 'No file provided.' };
    }
    const maxSize = options.maxSize || CONFIG.maxImportBytes;
    if (file.size <= 0) {
      return { valid: false, error: 'Empty file rejected.' };
    }
    if (file.size > maxSize) {
      return { valid: false, error: `File exceeds maximum allowed size (${Math.round(maxSize / (1024 * 1024))} MB).` };
    }
    const name = String(file.name || '').toLowerCase();
    const allowedExtensions = options.allowedExtensions || ['.json'];
    const hasValidExt = allowedExtensions.some(ext => name.endsWith(ext));
    if (!hasValidExt) {
      return { valid: false, error: `Invalid file extension. Allowed: ${allowedExtensions.join(', ')}` };
    }
    const blockedExtensions = ['.html', '.htm', '.svg', '.js', '.mjs', '.php', '.exe', '.sh', '.bat', '.cmd'];
    if (blockedExtensions.some(ext => name.endsWith(ext))) {
      return { valid: false, error: 'Executable or script file type blocked.' };
    }
    if (file.type) {
      const allowedMimes = options.allowedMimeTypes || ['application/json', 'text/json'];
      if (!allowedMimes.includes(file.type.toLowerCase())) {
        return { valid: false, error: `Invalid MIME type (${file.type}).` };
      }
    }
    return { valid: true };
  },

  /**
   * Password / PIN Strength Policy & Default Credential Prevention
   */
  isStrongPIN(pin) {
    if (typeof pin !== 'string') return false;
    if (pin.length < 6 || pin.length > 64) return false;
    const weakList = ['1234', '123456', '000000', '111111', 'password', 'admin123', 'qwerty'];
    if (weakList.includes(pin.toLowerCase())) return false;
    return true;
  }
};

/* 4. Authentication & Ephemeral Session Service */
const AuthService = {
  failedAttempts: 0,
  lockoutUntil: 0,
  sessionToken: null, // Strictly in-memory ephemeral token — NEVER stored in localStorage
  sessionExpires: 0,
  csrfToken: null,
  pendingAuth: null, // Ephemeral state between step 1 (PIN) and step 2 (MFA)
  SESSION_DURATION_MS: 15 * 60 * 1000, // 15-minute inactivity session timeout
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION_MS: 60 * 1000, // 60-second progressive lockout

  purgeStorageTokens() {
    if (typeof localStorage !== 'undefined') {
      const keysToPurge = [
        `${CONFIG.prefix}.authToken`,
        `${CONFIG.prefix}.sessionToken`,
        `${CONFIG.prefix}.jwt`,
        `${CONFIG.prefix}.token`
      ];
      keysToPurge.forEach(k => {
        try { localStorage.removeItem(k); } catch {}
      });
    }
    if (typeof sessionStorage !== 'undefined') {
      try {
        sessionStorage.removeItem(`${CONFIG.prefix}.authToken`);
        sessionStorage.removeItem(`${CONFIG.prefix}.sessionToken`);
        sessionStorage.removeItem(`${CONFIG.prefix}.jwt`);
      } catch {}
    }
  },

  isLockedOut() {
    const now = Date.now();
    if (this.lockoutUntil > now) {
      return Math.ceil((this.lockoutUntil - now) / 1000);
    }
    return 0;
  },

  async authenticate(enteredPin) {
    this.purgeStorageTokens();
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: String(enteredPin || '') })
      });
      const result = await response.json();
      if (!response.ok) return { success: false, error: result.error || 'Authentication failed.' };
      if (result.requireMFA) {
        this.pendingAuth = { pin: String(enteredPin || ''), expires: Date.now() + 5 * 60 * 1000 };
        return { success: false, requireMFA: true };
      }
      this.csrfToken = result.csrfToken || null;
      this.sessionToken = 'server-cookie-session';
      this.sessionExpires = Date.now() + this.SESSION_DURATION_MS;
      this.failedAttempts = 0;
      return { success: true };
    } catch {
      return { success: false, error: 'Could not reach the secure sign-in service.' };
    }
  },

  async verifyMFA(enteredCode) {
    if (!this.pendingAuth || Date.now() > this.pendingAuth.expires) {
      this.pendingAuth = null;
      return { success: false, error: 'MFA session expired. Please enter PIN again.' };
    }
    try {
      const response = await fetch('/api/auth/mfa', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: this.pendingAuth.pin, code: String(enteredCode || '') })
      });
      const result = await response.json();
      if (!response.ok) return { success: false, error: result.error || 'Invalid verification code.' };
      this.pendingAuth = null;
      this.csrfToken = result.csrfToken || null;
      this.sessionToken = 'server-cookie-session';
      this.sessionExpires = Date.now() + this.SESSION_DURATION_MS;
      return { success: true };
    } catch {
      return { success: false, error: 'Could not reach the secure verification service.' };
    }
  },

  isAuthenticated() {
    if (!this.sessionToken) return false;
    if (Date.now() > this.sessionExpires) {
      this.logout();
      return false;
    }
    // Refresh session on verified active usage
    this.sessionExpires = Date.now() + this.SESSION_DURATION_MS;
    return true;
  },

  checkPermission(permission) {
    if (!this.isAuthenticated()) {
      return false;
    }
    const allowedAdminPermissions = [
      'read:inquiries',
      'write:inquiries',
      'write:inventory',
      'write:services',
      'write:settings',
      'export:data',
      'import:data',
      'reset:data'
    ];
    return allowedAdminPermissions.includes(permission);
  },

  logout() {
    const csrfToken = this.csrfToken;
    if (this.sessionToken && csrfToken) {
      fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': csrfToken } }).catch(() => {});
    }
    this.sessionToken = null;
    this.csrfToken = null;
    this.pendingAuth = null;
    this.sessionExpires = 0;
    this.purgeStorageTokens();
    if (typeof document !== 'undefined') {
      const adminView = document.querySelector('#adminView');
      const storeView = document.querySelector('#storeView');
      if (adminView && !adminView.classList.contains('hidden')) {
        adminView.classList.add('hidden');
        if (storeView) storeView.classList.remove('hidden');
        if (typeof window !== 'undefined' && window.scrollTo) window.scrollTo(0, 0);
      }
    }
  },

};

/* 5. Client-Side Abuse Prevention & Rate Limiter */
const InquiryLimiter = {
  submissions: [],
  MAX_PER_MINUTE: 5,
  isRateLimited() {
    const now = Date.now();
    this.submissions = this.submissions.filter(t => now - t < 60000);
    if (this.submissions.length >= this.MAX_PER_MINUTE) {
      return true;
    }
    this.submissions.push(now);
    return false;
  }
};

/* 6. State Management, Persistence, and Storage */
const Store = {
  data: {
    products: [],
    services: [],
    inquiries: [],
    settings: { ...defaults },
    activity: [],
    preferences: { wishlist: [], compare: [] }
  },
  revision: 0,
  seen: new Set(),
  channel: null,

  load() {
    AuthService.purgeStorageTokens();
    let recovered = false;
    if (typeof localStorage === 'undefined') {
      this.data.products = structuredClone(seedProducts);
      this.data.services = structuredClone(seedServices);
      this.data.settings = { ...defaults };
      return;
    }
    for (const [name, key] of Object.entries(keys)) {
      try {
        const raw = localStorage.getItem(`${CONFIG.prefix}.${key}`);
        if (raw !== null) {
          const parsed = JSON.parse(raw);
          if (name === 'settings' && parsed && typeof parsed === 'object') {
            const safeParsed = Security.deepCloneSafe(parsed);
            // Move the original demo defaults to the requested Nepalese rupee display.
            if (safeParsed.currency === 'USD' && (!safeParsed.locale || safeParsed.locale === 'en-US')) {
              safeParsed.currency = 'NPR';
              safeParsed.locale = 'en-NP';
            }
            // The server owns authentication; remove old browser-stored PIN hashes and MFA secrets.
            delete safeParsed.auth;
            delete safeParsed.pin;
            try { localStorage.setItem(`${CONFIG.prefix}.${key}`, JSON.stringify(safeParsed)); } catch {}
            this.data.settings = {
              ...defaults,
              ...safeParsed,
              hours: { ...defaults.hours, ...(safeParsed.hours || {}) }
            };
          } else if (Array.isArray(parsed)) {
            const cleaned = Security.deepCloneSafe(parsed);
            if (name === 'products') {
              this.data.products = cleaned.filter(p => Validator.isSafeProduct(p));
            } else if (name === 'services') {
              this.data.services = cleaned.filter(s => Validator.isSafeService(s));
            } else if (name === 'inquiries') {
              this.data.inquiries = cleaned.filter(i => Validator.isSafeInquiry(i));
            } else {
              this.data[name] = cleaned;
            }
          } else {
            recovered = true;
          }
        } else {
          recovered = true;
        }
      } catch {
        recovered = true;
      }
    }

    if (recovered && (!this.data.products.length || !this.data.services.length)) {
      this.data.products = structuredClone(seedProducts);
      this.data.services = structuredClone(seedServices);
      this.data.settings = { ...defaults };
      this.log('Demo data initialized with secure defaults');
      this.saveAll(false);
    }
  },

  save(name, broadcast = true) {
    if (typeof localStorage === 'undefined') return;
    try {
      const sanitized = Security.deepCloneSafe(this.data[name]);
      if (name === 'settings' && sanitized && typeof sanitized === 'object') {
        delete sanitized.auth;
        delete sanitized.pin;
      }
      localStorage.setItem(`${CONFIG.prefix}.${keys[name]}`, JSON.stringify(sanitized));
    } catch (e) {
      Toast.show('Browser storage is full or restricted. Changes could not persist.', 'error');
    }
    this.revision++;
    if (broadcast && this.data.settings.broadcast) {
      this.publish(name);
    }
    window.dispatchEvent(new CustomEvent('we:change', { detail: { name, revision: this.revision } }));
  },

  saveAll(broadcast = true) {
    Object.keys(keys).forEach(k => this.save(k, broadcast));
  },

  publish(name) {
    if (!this.channel) return;
    // Strictly redact credentials and auth secrets before publishing over BroadcastChannel
    let broadcastData = this.data[name];
    if (name === 'settings') {
      broadcastData = { ...this.data.settings };
      delete broadcastData.auth;
      delete broadcastData.pin;
    }
    const msg = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      origin: tabId,
      name,
      data: Security.deepCloneSafe(broadcastData)
    };
    try {
      this.channel.postMessage(msg);
    } catch {}
  },

  getInquiries() {
    // Row-level security: only authenticated admin sessions can access customer inquiries
    if (!AuthService.isAuthenticated()) {
      return [];
    }
    return this.data.inquiries;
  },

  getPublishedProducts() {
    return this.data.products.filter(p => p.published !== false);
  },

  getPublishedServices() {
    return this.data.services.filter(s => s.published !== false);
  },

  log(action) {
    const sanitized = Security.redactSensitiveData(String(action || ''));
    const cleanAction = Security.safeText(sanitized, 150);
    this.data.activity.unshift({
      id: uid(),
      action: cleanAction,
      time: new Date().toISOString()
    });
    this.data.activity = this.data.activity.slice(0, Math.max(5, +this.data.settings.activityLimit || 50));
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(`${CONFIG.prefix}.activity`, JSON.stringify(this.data.activity));
      } catch {}
    }
  },

  refresh(name, raw) {
    try {
      const value = JSON.parse(raw);
      if (name === 'settings' && value && typeof value === 'object') {
        const safeVal = Security.deepCloneSafe(value);
        delete safeVal.auth; // Never overwrite auth from untrusted storage events
        delete safeVal.pin;
        if (Validator.validateSettings(safeVal)) {
          this.data.settings = {
            ...defaults,
            ...safeVal,
            hours: { ...defaults.hours, ...(safeVal.hours || {}) }
          };
          return true;
        }
      } else if (Array.isArray(value)) {
        const cleaned = Security.deepCloneSafe(value);
        if (name === 'products') {
          this.data.products = cleaned.filter(p => Validator.isSafeProduct(p));
        } else if (name === 'services') {
          this.data.services = cleaned.filter(s => Validator.isSafeService(s));
        } else if (name === 'inquiries') {
          this.data.inquiries = cleaned.filter(i => Validator.isSafeInquiry(i));
        } else {
          this.data[name] = cleaned;
        }
        return true;
      }
      return false;
    } catch {
      return false;
    }
  },

  reset() {
    if (!AuthService.isAuthenticated()) {
      Toast.show('Unauthorized: Admin session required to reset data.', 'error');
      return;
    }
    this.data = {
      products: structuredClone(seedProducts),
      services: structuredClone(seedServices),
      inquiries: [],
      settings: { ...defaults, hours: structuredClone(defaults.hours) },
      activity: [],
      preferences: { wishlist: [], compare: [] }
    };
    this.log('Catalog and demo data reset to verified baseline');
    this.saveAll();
  }
};

const tabId = `tab-${Math.random().toString(36).slice(2)}`;
const uid = () => `we-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
const escapeHTML = s => Security.escapeHTML(s);

/**
 * Currency formatter with locale and code validation
 * Strictly prevents unescaped characters or injection
 */
const money = n => {
  const safeCurrency = Validator.isValidCurrency(Store.data.settings.currency) ? Store.data.settings.currency : 'NPR';
  const safeLocale = Validator.isValidLocale(Store.data.settings.locale) ? Store.data.settings.locale : 'en-NP';
  try {
    return new Intl.NumberFormat(safeLocale, {
      style: 'currency',
      currency: safeCurrency,
      maximumFractionDigits: 2
    }).format(+n || 0);
  } catch {
    return `${safeCurrency} ${(+n || 0).toFixed(2)}`;
  }
};

const products = () => Store.data.products.filter(p => p.published !== false);
const stockState = p => p.stock <= 0 ? 'out' : p.stock <= +(p.threshold ?? Store.data.settings.lowStock) ? 'low' : 'in';
const stockText = p => stockState(p) === 'out' ? 'Out of Stock' : stockState(p) === 'low' ? `Low Stock · ${p.stock} left` : `In Stock · ${p.stock} available`;
const safeURL = v => Security.safeURL(v);

/* 7. Toasts, Cross-Tab Hardened Synchronization, Services */
const Toast = {
  show(message, type = 'success') {
    const el = document.createElement('div');
    el.className = `toast ${type === 'error' ? 'error' : 'success'}`;
    el.textContent = Security.safeText(message, 300);
    const stack = document.querySelector('#toastStack');
    if (stack) {
      stack.append(el);
      setTimeout(() => el.remove(), 3800);
    }
  }
};

const InventoryService = {
  upsert(record) {
    if (!AuthService.isAuthenticated()) {
      Toast.show('Unauthorized: Admin session required.', 'error');
      return;
    }
    if (!Validator.isSafeProduct(record)) {
      Toast.show('Invalid product data submitted.', 'error');
      return;
    }
    const i = Store.data.products.findIndex(p => p.id === record.id);
    if (i < 0) Store.data.products.unshift(record);
    else Store.data.products[i] = record;
    Store.log(`${i < 0 ? 'Added' : 'Updated'} product: ${record.name}`);
    Store.save('products');
  },

  remove(id) {
    if (!AuthService.isAuthenticated()) {
      Toast.show('Unauthorized: Admin session required.', 'error');
      return;
    }
    const p = Store.data.products.find(x => x.id === id);
    if (!p) return;
    Store.data.products = Store.data.products.filter(x => x.id !== id);
    Store.log(`Deleted product: ${p.name}`);
    Store.save('products');
  },

  update(id, changes) {
    if (!AuthService.isAuthenticated()) {
      Toast.show('Unauthorized: Admin session required.', 'error');
      return;
    }
    const p = Store.data.products.find(x => x.id === id);
    if (!p) return;
    // Allowlist allowed partial fields
    const safeChanges = {};
    for (const [k, v] of Object.entries(changes)) {
      if (['price', 'stock', 'featured', 'published'].includes(k)) {
        safeChanges[k] = v;
      }
    }
    this.upsert({ ...p, ...safeChanges });
  }
};

const SyncEngine = {
  init() {
    if ('BroadcastChannel' in window) {
      try {
        Store.channel = new BroadcastChannel(CONFIG.channel);
        Store.channel.onmessage = e => this.receive(e.data);
      } catch {}
    }
    window.addEventListener('storage', e => {
      if (!e.key?.startsWith(CONFIG.prefix + '.') || !e.newValue) return;
      const name = Object.keys(keys).find(k => `${CONFIG.prefix}.${keys[k]}` === e.key);
      if (name && Store.refresh(name, e.newValue)) {
        Store.revision++;
        this.render(name);
      }
    });
    window.addEventListener('we:change', e => this.render(e.detail.name));
    this.status();
  },

  receive(m) {
    if (!m || typeof m !== 'object' || m.origin === tabId || !m.id || Store.seen.has(m.id)) return;
    Store.seen.add(m.id);
    if (Store.seen.size > 150) Store.seen.delete(Store.seen.values().next().value);

    // Only allow known data collections
    if (!['products', 'services', 'inquiries', 'settings', 'activity', 'preferences'].includes(m.name)) return;

    // Never sync authentication credentials across BroadcastChannel
    if (m.name === 'settings') {
      if (!m.data || typeof m.data !== 'object') return;
      const safeData = Security.deepCloneSafe(m.data);
      delete safeData.auth;
      delete safeData.pin;
      if (Validator.validateSettings(safeData)) {
        Store.data.settings = {
          ...Store.data.settings,
          ...safeData,
        };
        try {
          localStorage.setItem(`${CONFIG.prefix}.settings`, JSON.stringify(Store.data.settings));
        } catch {}
        Store.revision++;
        this.render('settings', true);
      }
      return;
    }

    if (Array.isArray(m.data)) {
      if (m.data.length > 500) return; // Prevent memory exhaustion
      const cleaned = Security.deepCloneSafe(m.data);
      let valid = false;
      if (m.name === 'products') valid = cleaned.every(p => Validator.isSafeProduct(p));
      else if (m.name === 'services') valid = cleaned.every(s => Validator.isSafeService(s));
      else if (m.name === 'inquiries') valid = cleaned.every(i => Validator.isSafeInquiry(i));
      else valid = true;

      if (valid) {
        Store.data[m.name] = cleaned;
        try {
          localStorage.setItem(`${CONFIG.prefix}.${keys[m.name]}`, JSON.stringify(Store.data[m.name]));
        } catch {}
        Store.revision++;
        this.render(m.name, true);
      }
    }
  },

  render(name, remote = false) {
    UI.renderAll();
    if (remote) Toast.show(`${escapeHTML(name[0].toUpperCase() + name.slice(1))} updated in another tab`, 'success');
  },

  status() {
    const on = !!Store.data.settings.broadcast;
    for (const el of [document.querySelector('#liveSync'), document.querySelector('#adminSync')]) {
      if (el) {
        el.classList.toggle('off', !on);
        if (el.lastChild) {
          el.lastChild.textContent = on ? ' Live sync ready' : ' Local updates only';
        }
      }
    }
  }
};

const TechMatch = {
  recommend(use, budget, priority) {
    const map = {
      study: ['Laptops & PCs', 'Accessories'],
      work: ['Laptops & PCs', 'Accessories'],
      gaming: ['Laptops & PCs'],
      mobile: ['Mobile & Tablets', 'Accessories'],
      home: ['Home Appliances', 'Accessories']
    };
    const validUses = Object.keys(map);
    const safeUse = validUses.includes(use) ? use : 'study';
    const safeBudget = Number.isFinite(budget) && budget > 0 ? budget : 800;
    const safePriority = ['value', 'performance', 'portable', 'reliable'].includes(priority) ? priority : 'value';

    let pool = products().filter(p => map[safeUse].includes(p.category) && p.price <= safeBudget && p.stock > 0);
    const words = {
      value: ['budget', 'everyday', 'value'],
      performance: ['gaming', 'performance', 'pro'],
      portable: ['portable', 'phone', 'tablet', 'laptop'],
      reliable: ['reliable', 'everyday', 'family']
    }[safePriority];

    pool.sort((a, b) => {
      const score = p => (p.featured ? 2 : 0) +
                         (stockState(p) === 'in' ? 1 : 0) +
                         (words.some(w => `${p.name} ${p.description} ${(p.keywords || []).join(' ')}`.toLowerCase().includes(w)) ? 2 : 0) +
                         (p.rating || 0) / 5;
      return score(b) - score(a);
    });

    return pool.slice(0, 3).map(p => ({
      p,
      reason: `Fits your ${safeUse === 'study' ? 'study and everyday' : safeUse} needs, stays within ${money(safeBudget)}, and supports your ${safePriority} priority. ${stockText(p)}.`
    }));
  }
};

const TechCare = {
  guide(category) {
    const safeCat = CONFIG.categories.includes(category) ? category : 'Laptops & PCs';
    const tips = {
      'Laptops & PCs': ['Keep vents clear and install system updates regularly.', 'Use a padded sleeve for travel and avoid extreme heat.'],
      'Mobile & Tablets': ['Use a reputable charger and keep the device dry.', 'Back up important data and install security updates.'],
      'Home Appliances': ['Leave ventilation space and follow the manufacturer’s cleaning guidance.', 'If you notice unusual heat, smell, or noise, stop use and seek qualified support.'],
      'Accessories': ['Store cables without tight bends and keep connectors clean and dry.', 'Check device compatibility before connecting power accessories.']
    }[safeCat] || [];

    const services = Store.data.services.filter(s => s.published && [safeCat, 'General support', 'Consultation'].some(k =>
      `${s.type} ${s.name}`.toLowerCase().includes(k.toLowerCase()) ||
      safeCat === 'Laptops & PCs' && /computer/i.test(s.type) ||
      safeCat === 'Mobile & Tablets' && /mobile/i.test(s.type) ||
      safeCat === 'Home Appliances' && /appliance/i.test(s.type)
    ));
    return { tips, services };
  }
};

/* 8. Storefront Rendering Engine & UI Helpers */
const UI = {
  filters: { q: '', category: '', availability: '', min: '', max: '', featured: false, sort: 'featured' },

  renderAll() {
    this.renderProducts();
    this.renderServices();
    this.renderCounts();
    this.renderAdmin();
    this.renderPreferences();
    SyncEngine.status();
    this.updateHours();
    this.renderFooter();
  },

  renderFooter() {
    const host = document.querySelector('#footerContact');
    const year = document.querySelector('#copyrightYear');
    if (year) year.textContent = String(new Date().getFullYear());
    if (!host) return;
    const { email, phone } = Store.data.settings;
    host.replaceChildren();
    if (phone) {
      const link = document.createElement('a');
      link.href = `tel:${phone.replace(/[^+\d]/g, '')}`;
      link.textContent = phone;
      host.append(link);
    }
    if (email) {
      const link = document.createElement('a');
      link.href = `mailto:${email}`;
      link.textContent = email;
      host.append(link);
    }
  },

  renderProducts() {
    const grid = document.querySelector('#productGrid');
    if (!grid) return;
    let list = products();
    const f = this.filters;
    const q = Security.safeText(f.q, 100).toLowerCase();

    if (q) {
      list = list.filter(p => `${p.name} ${p.brand} ${p.model} ${p.description} ${JSON.stringify(p.specs || {})} ${(p.keywords || []).join(' ')}`.toLowerCase().includes(q));
    }
    if (f.category) list = list.filter(p => p.category === f.category);
    if (f.availability) list = list.filter(p => stockState(p) === f.availability);
    if (f.featured) list = list.filter(p => p.featured);
    if (f.min !== '') list = list.filter(p => p.price >= +f.min);
    if (f.max !== '') list = list.filter(p => p.price <= +f.max);

    if (f.sort === 'price-up') list.sort((a, b) => a.price - b.price);
    if (f.sort === 'price-down') list.sort((a, b) => b.price - a.price);
    if (f.sort === 'rating') list.sort((a, b) => (b.rating || 0) - (a.rating || 0));
    if (f.sort === 'stock') list.sort((a, b) => b.stock - a.stock);
    if (f.sort === 'featured') list.sort((a, b) => (+b.featured) - (+a.featured));

    const resultCountEl = document.querySelector('#resultCount');
    if (resultCountEl) {
      resultCountEl.textContent = `${list.length} ${list.length === 1 ? 'result' : 'results'}`;
    }
    const currencyLabelEl = document.querySelector('#currencyLabel');
    if (currencyLabelEl) {
      currencyLabelEl.textContent = Security.escapeHTML(Store.data.settings.currency);
    }
    const sliderValEl = document.querySelector('#sliderVal');
    const priceSliderEl = document.querySelector('#priceSlider');
    if (sliderValEl && priceSliderEl) {
      sliderValEl.textContent = money(priceSliderEl.value);
    }

    grid.replaceChildren();
    if (!list.length) {
      grid.innerHTML = '<div class="empty"><div style="font-size:2rem">⌕</div><h3>No products match those filters</h3><p>Try changing your search or clearing a filter.</p><button class="btn primary" data-action="clear">Clear filters</button></div>';
    } else {
      list.forEach(p => grid.append(this.productCard(p)));
    }
    this.renderChips();
  },

  productCard(p) {
    const el = document.createElement('article');
    el.className = 'card';
    const img = safeURL(p.image);
    const safeName = escapeHTML(p.name);
    const safeBrand = escapeHTML(p.brand);
    const safeModel = escapeHTML(p.model);
    const safeCategory = escapeHTML(p.category);
    const safeIcon = escapeHTML(p.icon || CONFIG.icons[p.category] || '✦');
    const safeId = escapeHTML(p.id);

    const specsSummary = Object.entries(p.specs || {}).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(' · ') || (p.description || '').slice(0, 86);

    el.innerHTML = `
      <div class="product-art">
        ${img ? `<img src="${escapeHTML(img)}" alt="${safeName}" loading="lazy" decoding="async">` : `<span class="emoji-art" aria-hidden="true">${safeIcon}</span>`}
        <span class="badge">${safeCategory}</span>
        ${p.featured ? '<span class="badge featured">★ Featured</span>' : ''}
      </div>
      <div class="card-body">
        <div class="meta">${safeBrand} · ${safeModel}</div>
        <h3>${safeName}</h3>
        <div class="spec">${escapeHTML(specsSummary)}</div>
        <div class="price-row">
          <span class="price">${escapeHTML(money(p.price))}</span>
          ${p.previousPrice ? `<span class="oldprice">${escapeHTML(money(p.previousPrice))}</span>` : ''}
        </div>
        ${p.rating ? `<div class="meta" aria-label="Rated ${escapeHTML(p.rating)} out of 5">★ ${escapeHTML(p.rating)} / 5</div>` : ''}
        <div class="stock ${escapeHTML(stockState(p))}">${escapeHTML(stockText(p))}</div>
        <div class="card-actions">
          <button class="btn outline" data-action="detail" data-id="${safeId}">Details</button>
          <button class="btn outline" data-action="wish" data-id="${safeId}" aria-label="Add ${safeName} to wishlist">♡</button>
          <button class="btn outline" data-action="compare" data-id="${safeId}" aria-label="Compare ${safeName}">⇄</button>
          ${p.stock > 0 ? `<button class="btn primary" data-action="whatsapp" data-id="${safeId}">Ask on WhatsApp</button>` : `<button class="btn outline" data-action="restock" data-id="${safeId}">Ask about restock</button>`}
        </div>
      </div>
    `;

    const image = el.querySelector('img');
    if (image) {
      image.onerror = () => {
        image.remove();
        el.querySelector('.product-art').insertAdjacentHTML('afterbegin', `<span class="emoji-art" aria-hidden="true">${safeIcon}</span>`);
      };
    }
    return el;
  },

  renderChips() {
    const host = document.querySelector('#activeChips');
    if (!host) return;
    host.replaceChildren();
    const f = this.filters;
    const items = [
      ['Search', f.q, 'q'],
      ['Category', f.category, 'category'],
      ['Availability', f.availability, 'availability'],
      ['Min', f.min, 'min'],
      ['Max', f.max, 'max'],
      ['Featured', f.featured ? 'Featured' : '', 'featured']
    ];
    items.filter(x => x[1]).forEach(([label, val, key]) => {
      const b = document.createElement('button');
      b.className = 'chip';
      b.textContent = `${label}: ${val} ×`;
      b.onclick = () => {
        if (key === 'featured') f.featured = false;
        else f[key] = '';
        this.syncControls();
        this.renderProducts();
      };
      host.append(b);
    });
  },

  renderServices() {
    const g = document.querySelector('#serviceGrid');
    if (!g) return;
    g.replaceChildren();
    const items = Store.data.services.filter(s => s.published);
    if (!items.length) {
      g.innerHTML = '<div class="empty">No services are currently listed.</div>';
      return;
    }
    items.forEach(s => {
      const d = document.createElement('article');
      d.className = 'service-card';
      d.innerHTML = `
        <div class="iconbox">⚙</div>
        <div class="meta">${escapeHTML(s.type)}</div>
        <h3>${escapeHTML(s.name)}</h3>
        <p>${escapeHTML(s.description)}</p>
        <div class="service-price">Starting at ${escapeHTML(money(s.price))}</div>
        <button class="btn outline small" style="margin-top:13px" data-action="serviceInquiry" data-id="${escapeHTML(s.id)}">Ask about service</button>
      `;
      g.append(d);
    });
  },

  renderCounts() {
    const w = Store.data.preferences.wishlist || [];
    const c = Store.data.preferences.compare || [];
    const wishEl = document.querySelector('#wishCount');
    const compEl = document.querySelector('#compareCount');
    if (wishEl) wishEl.textContent = w.length;
    if (compEl) compEl.textContent = c.length;
  },

  renderPreferences() {},

  syncControls() {
    for (const id of ['categoryFilter', 'availabilityFilter', 'minPrice', 'maxPrice', 'featuredFilter', 'sortFilter']) {
      const el = document.getElementById(id);
      if (!el) continue;
      const key = {
        categoryFilter: 'category',
        availabilityFilter: 'availability',
        minPrice: 'min',
        maxPrice: 'max',
        featuredFilter: 'featured',
        sortFilter: 'sort'
      }[id];
      if (el.type === 'checkbox') el.checked = !!this.filters[key];
      else el.value = this.filters[key] || '';
    }
  },

  updateHours() {
    const now = new Date();
    const day = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'][now.getDay()];
    const hours = Store.data.settings.hours?.[day];
    let text = 'Hours not configured';

    if (Array.isArray(hours) && hours.length === 2 && hours[0] && hours[1]) {
      const [oh, om] = hours[0].split(':').map(Number);
      const [ch, cm] = hours[1].split(':').map(Number);
      const cur = now.getHours() * 60 + now.getMinutes();
      const open = oh * 60 + om;
      const close = ch * 60 + cm;
      const isOpen = close === open ? false : close < open ? cur >= open || cur < close : cur >= open && cur < close;
      text = `${isOpen ? 'Open now' : 'Closed'} · ${escapeHTML(hours[0])}–${escapeHTML(hours[1])}`;
    } else if (hours === null) {
      text = 'Closed today';
    }

    const storeStatusEl = document.querySelector('#storeStatus');
    const clockEl = document.querySelector('#clock');
    if (storeStatusEl) storeStatusEl.textContent = text;
    if (clockEl) clockEl.textContent = now.toLocaleTimeString(Store.data.settings.locale || 'en-US', { hour: 'numeric', minute: '2-digit' });
  },

  renderAdmin() {
    const adminView = document.querySelector('#adminView');
    if (!adminView || adminView.classList.contains('hidden')) return;
    if (!AuthService.isAuthenticated()) {
      AuthService.logout();
      Toast.show('Session expired. Please log in again.', 'error');
      return;
    }
    Admin.render();
  }
};

/* 9. Customer Dialogs & Outbound Actions */
const Customer = {
  open(id) {
    const p = Store.data.products.find(x => x.id === id);
    if (!p) return;
    const titleEl = document.querySelector('#detailTitle');
    if (titleEl) titleEl.textContent = p.name;

    const specs = Object.entries(p.specs || {})
      .map(([k, v]) => `<li><strong>${escapeHTML(k)}:</strong> ${escapeHTML(v)}</li>`)
      .join('');
    const compatible = (p.compatibleAccessories || [])
      .map(accId => Store.data.products.find(x => x.id === accId)?.name)
      .filter(Boolean);

    const contentEl = document.querySelector('#detailContent');
    if (contentEl) {
      contentEl.innerHTML = `
        <div class="detail-layout">
          <div class="detail-art">${escapeHTML(p.icon || '✦')}</div>
          <div>
            <div class="meta">${escapeHTML(p.brand)} · ${escapeHTML(p.model)} · ${escapeHTML(p.category)}</div>
            <h2>${escapeHTML(p.name)}</h2>
            <p>${escapeHTML(p.description)}</p>
            <div class="price">${escapeHTML(money(p.price))}</div>
            <p class="stock ${escapeHTML(stockState(p))}">${escapeHTML(stockText(p))}</p>
            <p><strong>Warranty:</strong> ${escapeHTML(p.warranty || 'Ask for details')}</p>
            <h3>Specifications</h3>
            <ul>${specs}</ul>
            ${compatible.length ? `<p><strong>Compatible accessories:</strong> ${compatible.map(escapeHTML).join(', ')}</p>` : ''}
            <div class="banner"><strong>Care tip:</strong> ${escapeHTML(TechCare.guide(p.category).tips[0] || 'Follow manufacturer care guidance.')}</div>
          </div>
        </div>
      `;
    }
    openDialog('detailDialog');
  },

  toggle(key, id) {
    if (key !== 'wishlist' && key !== 'compare') return;
    const a = Store.data.preferences[key] || [];
    const i = a.indexOf(id);
    if (i >= 0) {
      a.splice(i, 1);
    } else {
      if (key === 'compare' && a.length >= 4) {
        Toast.show('Compare up to four products at a time.', 'error');
        return;
      }
      if (key === 'wishlist' && a.length >= 50) {
        Toast.show('Wishlist limit reached.', 'error');
        return;
      }
      a.push(id);
    }
    Store.data.preferences[key] = a;
    Store.save('preferences', false);
    UI.renderCounts();
    Toast.show(i >= 0 ? 'Removed from your list' : 'Added to your list');
    if (key === 'compare' && a.length > 1) this.showCompare();
  },

  wishlist() {
    const a = Store.data.preferences.wishlist || [];
    const host = document.querySelector('#wishContent');
    if (!host) return;
    host.innerHTML = a.map(id => Store.data.products.find(p => p.id === id)).filter(Boolean).map(p => `
      <div class="panel" style="margin:8px 0">
        <strong>${escapeHTML(p.name)}</strong> · ${escapeHTML(money(p.price))}
        <button class="btn small outline" data-action="detail" data-id="${escapeHTML(p.id)}">Details</button>
        <button class="btn small outline" data-action="wish" data-id="${escapeHTML(p.id)}">Remove</button>
      </div>
    `).join('') || '<div class="empty">Your wishlist is empty. Save products to revisit them here.</div>';
    openDialog('wishDialog');
  },

  showCompare() {
    const a = (Store.data.preferences.compare || []).map(id => Store.data.products.find(p => p.id === id)).filter(Boolean);
    const host = document.querySelector('#compareContent');
    if (!host) return;

    host.innerHTML = a.length ? `
      <div class="tablewrap">
        <table class="table">
          <thead>
            <tr>
              <th>Product</th>
              ${a.map(p => `<th>${escapeHTML(p.name)}</th>`).join('')}
            </tr>
          </thead>
          <tbody>
            ${[
              ['Price', p => money(p.price)],
              ['Category', p => p.category],
              ['Brand / model', p => `${p.brand} ${p.model}`],
              ['Stock', stockText],
              ['Rating', p => p.rating ? `${p.rating} / 5` : 'Not rated'],
              ['Specifications', p => Object.entries(p.specs || {}).map(([k, v]) => `${k}: ${v}`).join(' · ')]
            ].map(([k, fn]) => `
              <tr>
                <th>${escapeHTML(k)}</th>
                ${a.map(p => `<td>${escapeHTML(fn(p))}</td>`).join('')}
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      <button class="btn outline" data-action="clearCompare">Clear comparison</button>
    ` : '<div class="empty">Choose products with ⇄ to compare their details.</div>';
    openDialog('compareDialog');
  },

  inquiry(type = 'General support', item = '') {
    const typeEl = document.querySelector('#inqType');
    if (typeEl) typeEl.value = type;
    const sel = document.querySelector('#inqProduct');
    if (sel) {
      sel.innerHTML = '<option value="">General request</option>' + [...products(), ...Store.data.services].map(x => `
        <option value="${escapeHTML(x.id)}">${escapeHTML(x.name)}</option>
      `).join('');
      sel.value = item;
    }
    openDialog('inquiryDialog');
  },

  whatsapp(id) {
    const p = Store.data.products.find(x => x.id === id);
    if (!p) return;
    const number = (Store.data.settings.whatsapp || '').replace(/\D/g, '');
    if (!number || number.length < 7 || number.length > 15) {
      this.inquiry('Product question', id);
      Toast.show('Configure an international WhatsApp number in settings first.', 'error');
      return;
    }
    const text = encodeURIComponent(`Hello, I have a question about ${p.name} (${p.model}).`);
    const safeUrl = `https://wa.me/${number}?text=${text}`;
    window.open(safeUrl, '_blank', 'noopener,noreferrer');
  },

  directions() {
    const s = Store.data.settings;
    let url = '';
    if (Validator.isValidCoords(s.latitude, s.longitude) && s.latitude !== '' && s.longitude !== '') {
      url = `https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(`${s.latitude},${s.longitude}`)}`;
    } else if (s.address && typeof s.address === 'string' && s.address.trim().length > 0) {
      url = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(s.address.trim())}`;
    } else {
      Toast.show('Add a valid store address or coordinates in settings first.', 'error');
      return;
    }
    window.open(url, '_blank', 'noopener,noreferrer');
  }
};

function openDialog(id) {
  const d = document.getElementById(id);
  if (d && !d.open) {
    d.showModal();
    setTimeout(() => d.querySelector('button,input,select')?.focus(), 30);
  }
}

function closeDialog(id) {
  document.getElementById(id)?.close();
}

function confirmAction(message) {
  const dialog = document.querySelector('#confirmDialog');
  const confirmButton = document.querySelector('#confirmActionButton');
  const messageEl = document.querySelector('#confirmMessage');
  if (!dialog || !confirmButton || !messageEl) return Promise.resolve(false);
  messageEl.textContent = message;
  dialog.returnValue = '';
  return new Promise(resolve => {
    const finish = value => { dialog.close(); resolve(value); };
    const onClose = () => resolve(dialog.returnValue === 'confirm');
    dialog.addEventListener('close', onClose, { once: true });
    confirmButton.onclick = () => { dialog.returnValue = 'confirm'; finish(true); };
    dialog.showModal();
  });
}

/* 10. Admin Controller & Protected Management Operations */
const Admin = {
  render() {
    if (!AuthService.isAuthenticated()) {
      AuthService.logout();
      return;
    }
    this.stats();
    this.products();
    this.services();
    this.inquiries();
    this.activity();
    this.settings();
  },

  stats() {
    const p = Store.data.products.filter(x => x.published !== false);
    const s = Store.data.services.filter(x => x.published);
    const i = Store.data.inquiries.filter(x => x.status === 'New' || x.status === 'In Progress');
    const vals = [
      ['Active catalog items', p.length],
      ['Total stock units', p.reduce((n, x) => n + (+x.stock || 0), 0)],
      ['Low-stock products', p.filter(x => stockState(x) === 'low').length],
      ['Out of stock', p.filter(x => stockState(x) === 'out').length],
      ['Featured items', p.filter(x => x.featured).length],
      ['Product categories', new Set(p.map(x => x.category)).size],
      ['Active services', s.length],
      ['New / pending inquiries', i.length]
    ];
    const statsEl = document.querySelector('#stats');
    if (statsEl) {
      statsEl.innerHTML = vals.map(([a, b]) => `<div class="stat"><b>${escapeHTML(b)}</b><span>${escapeHTML(a)}</span></div>`).join('');
    }
    const w = p.filter(x => stockState(x) !== 'in');
    const watchEl = document.querySelector('#stockWatch');
    if (watchEl) {
      watchEl.innerHTML = w.length ? w.slice(0, 7).map(x => `
        <div style="padding:8px 0; border-bottom:1px solid #e2e8f0">
          <strong>${escapeHTML(x.name)}</strong>
          <span class="stock ${escapeHTML(stockState(x))}">${escapeHTML(stockText(x))}</span>
        </div>
      `).join('') : '<p>All published products are above low-stock thresholds.</p>';
    }
  },

  activity() {
    const listEl = document.querySelector('#activityList');
    if (!listEl) return;
    listEl.innerHTML = Store.data.activity.slice(0, 8).map(x => `
      <div style="padding:8px 0; border-bottom:1px solid #e2e8f0">
        <strong>${escapeHTML(x.action)}</strong>
        <div class="meta">${escapeHTML(new Date(x.time).toLocaleString())}</div>
      </div>
    `).join('') || '<p>No activity yet.</p>';
  },

  products() {
    const searchEl = document.querySelector('#adminProductSearch');
    const q = Security.safeText(searchEl ? searchEl.value : '', 100).toLowerCase();
    const rows = Store.data.products.filter(p => `${p.name} ${p.brand} ${p.model}`.toLowerCase().includes(q));
    const tableEl = document.querySelector('#productTable');
    if (!tableEl) return;

    tableEl.innerHTML = rows.map(p => `
      <tr>
        <td>
          <strong>${escapeHTML(p.name)}</strong>
          <div class="meta">${escapeHTML(p.brand)} · ${escapeHTML(p.model)}</div>
        </td>
        <td>${escapeHTML(p.category)}</td>
        <td>
          <input aria-label="Price for ${escapeHTML(p.name)}" type="number" min="0.01" max="1000000" step="0.01" value="${+p.price}" data-quick="price" data-id="${escapeHTML(p.id)}" style="width:90px; padding:6px; border:1px solid #cbd5e1; border-radius:7px">
        </td>
        <td>
          <input aria-label="Stock for ${escapeHTML(p.name)}" type="number" min="0" max="100000" step="1" value="${+p.stock}" data-quick="stock" data-id="${escapeHTML(p.id)}" style="width:70px; padding:6px; border:1px solid #cbd5e1; border-radius:7px">
        </td>
        <td>${p.published ? 'Published' : 'Hidden'}${p.featured ? ' · ★' : ''}</td>
        <td>
          <div class="rowactions">
            <button class="btn small outline" data-admin-action="editProduct" data-id="${escapeHTML(p.id)}">Edit</button>
            <button class="btn small outline" data-admin-action="feature" data-id="${escapeHTML(p.id)}">${p.featured ? 'Unfeature' : 'Feature'}</button>
            <button class="btn small outline" data-admin-action="publishProduct" data-id="${escapeHTML(p.id)}">${p.published ? 'Hide' : 'Publish'}</button>
            <button class="btn small danger" data-admin-action="deleteProduct" data-id="${escapeHTML(p.id)}">Delete</button>
          </div>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="6">No matching products.</td></tr>';
  },

  services() {
    const tableEl = document.querySelector('#serviceTable');
    if (!tableEl) return;
    tableEl.innerHTML = Store.data.services.map(s => `
      <tr>
        <td>
          <strong>${escapeHTML(s.name)}</strong>
          <div class="meta">${escapeHTML(s.description)}</div>
        </td>
        <td>${escapeHTML(s.type)}</td>
        <td>${escapeHTML(money(s.price))}</td>
        <td>${s.published ? 'Published' : 'Hidden'}</td>
        <td>
          <div class="rowactions">
            <button class="btn small outline" data-admin-action="editService" data-id="${escapeHTML(s.id)}">Edit</button>
            <button class="btn small outline" data-admin-action="publishService" data-id="${escapeHTML(s.id)}">${s.published ? 'Hide' : 'Publish'}</button>
            <button class="btn small danger" data-admin-action="deleteService" data-id="${escapeHTML(s.id)}">Delete</button>
          </div>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="5">No services added.</td></tr>';
  },

  inquiries() {
    const statusEl = document.querySelector('#inquiryStatus');
    const status = statusEl ? statusEl.value : '';
    const rows = Store.data.inquiries.filter(i => !status || i.status === status);
    const tableEl = document.querySelector('#inquiryTable');
    if (!tableEl) return;

    tableEl.innerHTML = rows.map(i => `
      <tr>
        <td>${escapeHTML(new Date(i.time).toLocaleString())}</td>
        <td>
          ${escapeHTML(i.name)}
          <div class="meta">${escapeHTML(i.contact)}</div>
        </td>
        <td>${escapeHTML(i.type)}</td>
        <td>
          ${escapeHTML(i.item || 'General request')}
          <div class="meta">${escapeHTML(i.message)}</div>
        </td>
        <td>
          <select data-inq-status="${escapeHTML(i.id)}" aria-label="Status for inquiry from ${escapeHTML(i.name)}">
            ${['New', 'Contacted', 'In Progress', 'Resolved', 'Archived'].map(s => `
              <option ${i.status === s ? 'selected' : ''}>${escapeHTML(s)}</option>
            `).join('')}
          </select>
        </td>
        <td>
          <button class="btn small danger" data-admin-action="deleteInquiry" data-id="${escapeHTML(i.id)}">Delete</button>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="6">No inquiries yet.</td></tr>';
  },

  settings() {
    const s = Store.data.settings;
    const days = { mon: 'Monday', tue: 'Tuesday', wed: 'Wednesday', thu: 'Thursday', fri: 'Friday', sat: 'Saturday', sun: 'Sunday' };
    const hours = Object.entries(days).map(([k, label]) => `
      <div class="field">
        <label>${escapeHTML(label)}</label>
        <div class="range-row">
          <input aria-label="${escapeHTML(label)} opening time" type="time" name="${escapeHTML(k)}Open" value="${escapeHTML(s.hours?.[k]?.[0] || '')}">
          <input aria-label="${escapeHTML(label)} closing time" type="time" name="${escapeHTML(k)}Close" value="${escapeHTML(s.hours?.[k]?.[1] || '')}">
        </div>
        <label class="check">
          <input type="checkbox" name="${escapeHTML(k)}Closed" ${s.hours?.[k] === null ? 'checked' : ''}> Closed
        </label>
      </div>
    `).join('');

    const formEl = document.querySelector('#settingsForm');
    if (!formEl) return;

    formEl.innerHTML = `
      <div class="field">
        <label>Store name</label>
        <input name="storeName" value="${escapeHTML(s.storeName)}" required maxlength="80">
      </div>
      <div class="field">
        <label>Currency code (ISO 4217, 3 letters)</label>
        <input name="currency" value="${escapeHTML(s.currency)}" required pattern="[A-Za-z]{3}" maxlength="3">
      </div>
      <div class="field">
        <label>Locale tag (e.g. en-US)</label>
        <input name="locale" value="${escapeHTML(s.locale)}" required maxlength="20">
      </div>
      <div class="field">
        <label>Contact email</label>
        <input name="email" type="email" value="${escapeHTML(s.email)}" maxlength="120">
      </div>
      <div class="field">
        <label>Contact phone</label>
        <input name="phone" value="${escapeHTML(s.phone)}" maxlength="40">
      </div>
      <div class="field">
        <label>WhatsApp number (international format)</label>
        <input name="whatsapp" value="${escapeHTML(s.whatsapp)}" maxlength="40">
      </div>
      <div class="field wide">
        <label>Store address</label>
        <input name="address" value="${escapeHTML(s.address)}" maxlength="200">
      </div>
      <div class="field">
        <label>Latitude (-90 to 90)</label>
        <input name="latitude" type="number" step="any" min="-90" max="90" value="${escapeHTML(s.latitude)}">
      </div>
      <div class="field">
        <label>Longitude (-180 to 180)</label>
        <input name="longitude" type="number" step="any" min="-180" max="180" value="${escapeHTML(s.longitude)}">
      </div>
      <div class="field">
        <label>Low-stock threshold default</label>
        <input name="lowStock" type="number" min="1" max="1000" value="${+s.lowStock}">
      </div>
      <div class="field">
        <label>Activity history limit</label>
        <input name="activityLimit" type="number" min="5" max="500" value="${+s.activityLimit}">
      </div>
      <div class="field">
        <label>Repair service default</label>
        <input name="servicesDefault" value="${escapeHTML(s.servicesDefault)}" maxlength="80">
      </div>
      <label class="check">
        <input name="broadcast" type="checkbox" ${s.broadcast ? 'checked' : ''}> Broadcast updates to compatible same-origin tabs
      </label>
      <div class="wide">
        <h3>Store operating hours</h3>
        <p class="notice">Equal opening and closing times are treated as closed. Closing times before opening support overnight hours.</p>
      </div>
      ${hours}
    `;
  },

  productForm(p = {}) {
    if (!AuthService.isAuthenticated()) return;
    const isEdit = !!p.id;
    const host = document.querySelector('#productFormHost');
    if (!host) return;

    host.innerHTML = `
      <form id="productEditForm" class="panel adminform">
        <input type="hidden" name="id" value="${escapeHTML(p.id || '')}">
        <div class="field">
          <label>Product name</label>
          <input name="name" required maxlength="100" value="${escapeHTML(p.name || '')}">
        </div>
        <div class="field">
          <label>Brand</label>
          <input name="brand" required maxlength="60" value="${escapeHTML(p.brand || '')}">
        </div>
        <div class="field">
          <label>Model</label>
          <input name="model" required maxlength="80" value="${escapeHTML(p.model || '')}">
        </div>
        <div class="field">
          <label>Category</label>
          <select name="category" required>
            ${CONFIG.categories.map(c => `<option ${p.category === c ? 'selected' : ''}>${escapeHTML(c)}</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label>Price</label>
          <input name="price" type="number" min="0.01" max="1000000" step="0.01" required value="${p.price ?? ''}">
        </div>
        <div class="field">
          <label>Previous price (optional)</label>
          <input name="previousPrice" type="number" min="0" max="1000000" step="0.01" value="${p.previousPrice ?? ''}">
        </div>
        <div class="field">
          <label>Stock quantity</label>
          <input name="stock" type="number" min="0" max="100000" step="1" required value="${p.stock ?? 0}">
        </div>
        <div class="field">
          <label>Low-stock threshold</label>
          <input name="threshold" type="number" min="1" max="1000" step="1" required value="${p.threshold ?? Store.data.settings.lowStock}">
        </div>
        <div class="field">
          <label>Image URL (optional, http/https only)</label>
          <input name="image" type="url" maxlength="500" value="${escapeHTML(p.image || '')}">
        </div>
        <div class="field">
          <label>Warranty</label>
          <input name="warranty" maxlength="100" value="${escapeHTML(p.warranty || '')}">
        </div>
        <div class="field wide">
          <label>Description</label>
          <textarea name="description" required maxlength="1000">${escapeHTML(p.description || '')}</textarea>
        </div>
        <div class="field">
          <label>Specifications (one name: value per line)</label>
          <textarea name="specs">${escapeHTML(Object.entries(p.specs || {}).map(([k, v]) => `${k}: ${v}`).join('\n'))}</textarea>
        </div>
        <div class="field">
          <label>Search keywords (comma separated)</label>
          <textarea name="keywords">${escapeHTML((p.keywords || []).join(', '))}</textarea>
        </div>
        <div class="field">
          <label>Compatible accessory IDs (comma separated)</label>
          <input name="compatibleAccessories" maxlength="300" value="${escapeHTML((p.compatibleAccessories || []).join(', '))}">
        </div>
        <div class="field">
          <label>Relevant service IDs (comma separated)</label>
          <input name="serviceIds" maxlength="300" value="${escapeHTML((p.serviceIds || []).join(', '))}">
        </div>
        <label class="check">
          <input name="featured" type="checkbox" ${p.featured ? 'checked' : ''}> Featured
        </label>
        <label class="check">
          <input name="published" type="checkbox" ${p.published !== false ? 'checked' : ''}> Published
        </label>
        <div class="form-actions wide">
          <button type="button" class="btn outline" id="cancelProduct">Cancel</button>
          <button type="reset" class="btn outline">Reset form</button>
          <button class="btn primary">${isEdit ? 'Save changes' : 'Add product'}</button>
        </div>
      </form>
    `;

    document.querySelector('#productEditForm').onsubmit = e => {
      e.preventDefault();
      if (!AuthService.isAuthenticated()) return;
      const f = new FormData(e.currentTarget);
      const rawId = f.get('id');
      const id = rawId ? String(rawId) : uid();
      const price = +f.get('price');
      const stock = +f.get('stock');
      const threshold = +f.get('threshold');
      const name = Security.safeText(f.get('name'), 100);
      const brand = Security.safeText(f.get('brand'), 60);
      const model = Security.safeText(f.get('model'), 80);
      const category = String(f.get('category'));

      if (!name || !brand || !model || !CONFIG.categories.includes(category)) {
        Toast.show('Fill in all required fields with valid values.', 'error');
        return;
      }
      if (!Number.isFinite(price) || price <= 0 || price > 1000000 || !Number.isInteger(stock) || stock < 0 || stock > 100000 || !Number.isInteger(threshold) || threshold < 1) {
        Toast.show('Enter a valid price, whole stock quantity, and threshold.', 'error');
        return;
      }

      // Safe prototype-pollution-free specs parsing
      const specs = Object.create(null);
      const specLines = String(f.get('specs') || '').split('\n').slice(0, 30);
      for (const line of specLines) {
        const ix = line.indexOf(':');
        if (ix > 0) {
          const k = line.slice(0, ix).trim();
          const v = line.slice(ix + 1).trim();
          if (k && k !== '__proto__' && k !== 'constructor' && k !== 'prototype' && k.length <= 80 && v.length <= 120) {
            specs[k] = v;
          }
        }
      }

      const previousRaw = f.get('previousPrice');
      const previous = previousRaw === '' ? null : +previousRaw;
      if (previous !== null && (!Number.isFinite(previous) || previous < 0 || previous > 1000000)) {
        Toast.show('Previous price must be nonnegative.', 'error');
        return;
      }

      const rawImg = String(f.get('image') || '');
      const image = safeURL(rawImg);

      const rec = {
        id,
        name,
        brand,
        model,
        category,
        price,
        previousPrice: previous,
        stock,
        threshold,
        image,
        description: Security.safeText(f.get('description'), 1000),
        specs: { ...specs },
        keywords: String(f.get('keywords') || '').split(',').map(x => Security.safeText(x, 40)).filter(Boolean).slice(0, 30),
        warranty: Security.safeText(f.get('warranty'), 100),
        compatibleAccessories: String(f.get('compatibleAccessories') || '').split(',').map(x => Security.safeText(x, 60)).filter(Boolean).slice(0, 20),
        serviceIds: String(f.get('serviceIds') || '').split(',').map(x => Security.safeText(x, 60)).filter(Boolean).slice(0, 20),
        featured: f.has('featured'),
        published: f.has('published'),
        rating: p.rating || null,
        icon: p.icon || CONFIG.icons[category] || '✦'
      };

      if (!Validator.isSafeProduct(rec)) {
        Toast.show('Product data validation failed.', 'error');
        return;
      }

      InventoryService.upsert(rec);
      document.querySelector('#productFormHost').replaceChildren();
      Toast.show('Product saved successfully');
    };

    document.querySelector('#cancelProduct').onclick = () => {
      document.querySelector('#productFormHost').replaceChildren();
    };
  },

  serviceForm(s = {}) {
    if (!AuthService.isAuthenticated()) return;
    const editing = !!s.id;
    const host = document.querySelector('#serviceFormHost');
    if (!host) return;

    host.innerHTML = `
      <form id="serviceEditForm" class="panel adminform">
        <input type="hidden" name="id" value="${escapeHTML(s.id || '')}">
        <div class="field">
          <label>Service name</label>
          <input name="name" required maxlength="100" value="${escapeHTML(s.name || '')}">
        </div>
        <div class="field">
          <label>Service type</label>
          <input name="type" required maxlength="60" value="${escapeHTML(s.type || 'Consultation')}">
        </div>
        <div class="field">
          <label>Price</label>
          <input name="price" type="number" min="0" max="100000" step="0.01" required value="${s.price ?? ''}">
        </div>
        <div class="field">
          <label>Published</label>
          <label class="check">
            <input name="published" type="checkbox" ${s.published !== false ? 'checked' : ''}> Visible to customers
          </label>
        </div>
        <div class="field wide">
          <label>Description</label>
          <textarea name="description" required maxlength="1000">${escapeHTML(s.description || '')}</textarea>
        </div>
        <div class="form-actions wide">
          <button type="button" class="btn outline" id="cancelService">Cancel</button>
          <button class="btn primary">${editing ? 'Save changes' : 'Add service'}</button>
        </div>
      </form>
    `;

    document.querySelector('#serviceEditForm').onsubmit = e => {
      e.preventDefault();
      if (!AuthService.isAuthenticated()) return;
      const f = new FormData(e.currentTarget);
      const rawId = f.get('id');
      const id = rawId ? String(rawId) : uid();
      const price = +f.get('price');
      const name = Security.safeText(f.get('name'), 100);
      const type = Security.safeText(f.get('type'), 60);
      const description = Security.safeText(f.get('description'), 1000);

      if (!name || !type || !description || !Number.isFinite(price) || price < 0 || price > 100000) {
        Toast.show('Enter valid service details and a nonnegative price.', 'error');
        return;
      }

      const rec = {
        id,
        name,
        type,
        price,
        description,
        published: f.has('published')
      };

      if (!Validator.isSafeService(rec)) {
        Toast.show('Service validation failed.', 'error');
        return;
      }

      const i = Store.data.services.findIndex(x => x.id === id);
      if (i < 0) Store.data.services.unshift(rec);
      else Store.data.services[i] = rec;
      Store.log(`${i < 0 ? 'Added' : 'Updated'} service: ${rec.name}`);
      Store.save('services');
      Toast.show('Service saved successfully');
      document.querySelector('#serviceFormHost').replaceChildren();
    };

    document.querySelector('#cancelService').onclick = () => {
      document.querySelector('#serviceFormHost').replaceChildren();
    };
  }
};

/* 11. Event Wiring, Dialog Management, and Input Guards */
async function showAdmin() {
  try {
    const response = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' });
    const status = response.ok ? await response.json() : null;
    if (!status?.authenticated) {
      AuthService.logout();
      Toast.show('Your secure admin session is missing or expired. Please sign in again.', 'error');
      return false;
    }
  } catch {
    Toast.show('Could not verify your admin session with the server.', 'error');
    return false;
  }
  document.querySelector('#storeView').classList.add('hidden');
  document.querySelector('#adminView').classList.remove('hidden');
  Admin.render();
  window.scrollTo(0, 0);
  return true;
}

function setFilter(key, value) {
  UI.filters[key] = value;
  UI.renderProducts();
}

function clearFilters() {
  UI.filters = { q: '', category: '', availability: '', min: '', max: '', featured: false, sort: 'featured' };
  const navS = document.querySelector('#navSearch');
  const catS = document.querySelector('#catalogSearch');
  const pSlider = document.querySelector('#priceSlider');
  if (navS) navS.value = '';
  if (catS) catS.value = '';
  if (pSlider) pSlider.value = pSlider.max;
  UI.syncControls();
  UI.renderProducts();
}

function requestAdmin() {
  if (AuthService.isAuthenticated()) {
    showAdmin();
    return;
  }
  const pinInput = document.querySelector('#pinInput');
  if (pinInput) pinInput.value = '';
  const mfaInput = document.querySelector('#mfaInput');
  if (mfaInput) mfaInput.value = '';
  const pinStep = document.querySelector('#pinStep');
  const mfaStep = document.querySelector('#mfaStep');
  if (pinStep) pinStep.style.display = 'block';
  if (mfaStep) mfaStep.style.display = 'none';

  const lockoutBanner = document.querySelector('#pinLockoutBanner');
  if (lockoutBanner) {
    const lockedSeconds = AuthService.isLockedOut();
    if (lockedSeconds > 0) {
      lockoutBanner.style.display = 'block';
      lockoutBanner.textContent = `Too many failed attempts. Access locked for ${lockedSeconds} seconds.`;
    } else {
      lockoutBanner.style.display = 'none';
    }
  }
  openDialog('pinDialog');
}

function initApp() {
// Global Activity Tracker for Inactivity Timeout
['click', 'keydown', 'mousemove', 'scroll'].forEach(evt => {
  window.addEventListener(evt, () => {
    if (AuthService.sessionToken && !AuthService.isAuthenticated()) {
      AuthService.logout();
      Toast.show('Admin session expired due to inactivity.', 'error');
    }
  }, { passive: true });
});

// Admin PIN Authentication Handling
document.querySelector('#pinForm').onsubmit = async e => {
  e.preventDefault();
  const pinInput = document.querySelector('#pinInput');
  const pinSubmitBtn = document.querySelector('#pinSubmitBtn');
  const lockoutBanner = document.querySelector('#pinLockoutBanner');
  const enteredPin = pinInput.value;

  if (pinSubmitBtn) pinSubmitBtn.disabled = true;

  try {
    const res = await AuthService.authenticate(enteredPin);
    if (res.success) {
      closeDialog('pinDialog');
      pinInput.value = '';
      if (lockoutBanner) lockoutBanner.style.display = 'none';
      showAdmin();
      Toast.show('Authenticated as administrator');
    } else if (res.requireMFA) {
      const pinStep = document.querySelector('#pinStep');
      const mfaStep = document.querySelector('#mfaStep');
      if (pinStep) pinStep.style.display = 'none';
      if (mfaStep) mfaStep.style.display = 'block';
      setTimeout(() => document.querySelector('#mfaInput')?.focus(), 50);
      Toast.show('Please enter your 2-factor authentication code.');
    } else if (res.lockedOut) {
      if (lockoutBanner) {
        lockoutBanner.style.display = 'block';
        lockoutBanner.textContent = `Too many failed attempts. Access locked for ${res.seconds} seconds.`;
      }
      Toast.show(`Account locked for ${res.seconds} seconds.`, 'error');
    } else {
      Toast.show(res.error || `Incorrect password. ${res.remainingAttempts ?? ''} ${res.remainingAttempts ? 'attempt(s) remaining.' : ''}`, 'error');
    }
  } finally {
    if (pinSubmitBtn) pinSubmitBtn.disabled = false;
  }
};

document.querySelector('#mfaSubmitBtn')?.addEventListener('click', async () => {
  const mfaInput = document.querySelector('#mfaInput');
  const mfaBtn = document.querySelector('#mfaSubmitBtn');
  if (!mfaInput) return;
  if (mfaBtn) mfaBtn.disabled = true;
  try {
    const res = await AuthService.verifyMFA(mfaInput.value);
    if (res.success) {
      closeDialog('pinDialog');
      mfaInput.value = '';
      document.querySelector('#pinInput').value = '';
      showAdmin();
      Toast.show(res.usedRecoveryCode ? `Authenticated with recovery code (${res.remainingCodes} left)` : 'MFA verified: Authenticated as administrator');
    } else {
      Toast.show(res.error || 'Invalid verification code.', 'error');
    }
  } finally {
    if (mfaBtn) mfaBtn.disabled = false;
  }
});

document.querySelector('#mfaBackBtn')?.addEventListener('click', () => {
  const pinStep = document.querySelector('#pinStep');
  const mfaStep = document.querySelector('#mfaStep');
  if (pinStep) pinStep.style.display = 'block';
  if (mfaStep) mfaStep.style.display = 'none';
  AuthService.pendingAuth = null;
});

['adminEntry', 'footerAdmin'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.onclick = requestAdmin;
});

document.querySelector('#exitAdmin').onclick = () => {
  AuthService.logout();
  Toast.show('Logged out of admin session');
};

document.querySelector('#pinToggle').onclick = () => {
  const p = document.querySelector('#pinInput');
  if (!p) return;
  p.type = p.type === 'password' ? 'text' : 'password';
  document.querySelector('#pinToggle').textContent = p.type === 'password' ? 'Show' : 'Hide';
};

// Search & Filter event bindings
document.querySelector('#navSearch').oninput = e => {
  UI.filters.q = e.target.value;
  const catSearch = document.querySelector('#catalogSearch');
  if (catSearch) catSearch.value = e.target.value;
  document.querySelector('#catalog')?.scrollIntoView({ behavior: 'smooth' });
  UI.renderProducts();
};

document.querySelector('#catalogSearch').oninput = e => {
  UI.filters.q = e.target.value;
  const navSearch = document.querySelector('#navSearch');
  if (navSearch) navSearch.value = e.target.value;
  UI.renderProducts();
};

document.querySelector('#categoryFilter').onchange = e => setFilter('category', e.target.value);
document.querySelector('#availabilityFilter').onchange = e => setFilter('availability', e.target.value);
document.querySelector('#minPrice').oninput = e => setFilter('min', e.target.value);
document.querySelector('#maxPrice').oninput = e => setFilter('max', e.target.value);
document.querySelector('#featuredFilter').onchange = e => setFilter('featured', e.target.checked);
document.querySelector('#sortFilter').onchange = e => setFilter('sort', e.target.value);
document.querySelector('#priceSlider').oninput = e => {
  const maxPriceEl = document.querySelector('#maxPrice');
  if (maxPriceEl) maxPriceEl.value = e.target.value;
  setFilter('max', e.target.value);
};

document.querySelector('#clearFilters').onclick = clearFilters;
document.querySelector('#clearFiltersTop').onclick = clearFilters;

document.querySelector('#productGrid').addEventListener('click', e => {
  const b = e.target.closest('[data-action]');
  if (!b) return;
  const { action, id } = b.dataset;
  if (action === 'detail') Customer.open(id);
  if (action === 'wish') Customer.toggle('wishlist', id);
  if (action === 'compare') Customer.toggle('compare', id);
  if (action === 'whatsapp') Customer.whatsapp(id);
  if (action === 'restock') Customer.inquiry('Restock request', id);
  if (action === 'clear') clearFilters();
});

document.querySelector('#serviceGrid').onclick = e => {
  const b = e.target.closest('[data-action="serviceInquiry"]');
  if (b) Customer.inquiry('Repair service', b.dataset.id);
};

document.querySelector('#wishNav').onclick = () => Customer.wishlist();
document.querySelector('#compareNav').onclick = () => Customer.showCompare();
document.querySelector('#directionsBtn').onclick = () => Customer.directions();
document.querySelector('#repairInquiryBtn').onclick = () => Customer.inquiry('Repair service');

// TechMatch guidance button
document.querySelector('#runMatch').onclick = () => {
  const use = document.querySelector('#matchUse').value;
  const budget = +document.querySelector('#matchBudget').value;
  const priority = document.querySelector('#matchPriority').value;
  const res = TechMatch.recommend(use, budget, priority);
  const host = document.querySelector('#matchResult');
  if (!host) return;

  host.innerHTML = res.length ?
    '<h3>Your matches</h3>' + res.map(({ p, reason }) => `
      <div class="panel" style="margin-top:9px">
        <strong>${escapeHTML(p.name)}</strong> · ${escapeHTML(money(p.price))}
        <p>${escapeHTML(reason)}</p>
        <button class="btn small primary" data-action="detail" data-id="${escapeHTML(p.id)}">View details</button>
      </div>
    `).join('') :
    '<div class="banner">No in-stock matches in this sample catalog. Try a larger budget or different use.</div>';
};

document.querySelector('#matchResult').onclick = e => {
  const b = e.target.closest('[data-action="detail"]');
  if (b) Customer.open(b.dataset.id);
};

// TechCare Passport button
document.querySelector('#passportBtn').onclick = () => {
  const category = document.querySelector('#passportDevice').value;
  const { tips, services } = TechCare.guide(category);
  const host = document.querySelector('#passportResult');
  if (!host) return;

  host.innerHTML = `
    <div style="margin-top:16px">
      <h3>Care notes</h3>
      <ul>${tips.map(t => `<li>${escapeHTML(t)}</li>`).join('')}</ul>
      <h3>Related support in this demo</h3>
      ${services.length ? services.map(s => `
        <p><strong>${escapeHTML(s.name)}</strong> · ${escapeHTML(money(s.price))}</p>
      `).join('') : '<p>No directly related published service is listed; general support is available.</p>'}
    </div>
  `;
};

// Customer Inquiry Submission with Rate Limiting & Input Validation
document.querySelector('#inquiryForm').onsubmit = async e => {
  e.preventDefault();
  if (InquiryLimiter.isRateLimited()) {
    Toast.show('You have submitted multiple requests recently. Please wait a minute before trying again.', 'error');
    return;
  }

  const itemId = document.querySelector('#inqProduct').value;
  const item = [...Store.data.products, ...Store.data.services].find(x => x.id === itemId);
  const inquiry = {
    id: uid(),
    name: Security.safeText(document.querySelector('#inqName').value, 80),
    contact: Security.safeText(document.querySelector('#inqContact').value, 120),
    type: document.querySelector('#inqType').value,
    item: item?.name ? Security.safeText(item.name, 100) : '',
    message: Security.safeText(document.querySelector('#inqMessage').value, 1000),
    status: 'New',
    time: new Date().toISOString()
  };

  if (!Validator.isSafeInquiry(inquiry)) {
    Toast.show('Please complete all required fields with valid input.', 'error');
    return;
  }

  const status = document.querySelector('#inquiryStatus');
  const submit = e.currentTarget.querySelector('button[type="submit"],button:not([type])');
  const loader = document.querySelector('#loadingIndicator');
  if (submit) submit.disabled = true;
  if (loader) loader.hidden = false;
  if (status) { status.className = 'form-status'; status.textContent = 'Sending your request…'; }
  try {
    const response = await fetch('/api/inquiries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: inquiry.name, contact: inquiry.contact, type: inquiry.type, message: inquiry.message, utm: (() => { try { return JSON.parse(sessionStorage.getItem('we.utm') || '{}'); } catch { return {}; } })() })
    });
    if (!response.ok) throw new Error('The request could not be sent. Please try again shortly.');
  } catch (error) {
    if (loader) loader.hidden = true;
    if (status) { status.className = 'form-status error'; status.textContent = error.message || 'Connection problem. Please try again.'; }
    Toast.show('Your request could not be sent. Please try again.', 'error');
    if (submit) submit.disabled = false;
    return;
  }
  if (loader) loader.hidden = true;
  Store.data.inquiries.unshift(inquiry);
  // Cap stored inquiries to prevent quota exhaustion
  if (Store.data.inquiries.length > 200) {
    Store.data.inquiries = Store.data.inquiries.slice(0, 200);
  }
  Store.log('New customer inquiry submitted');
  Store.save('inquiries');
  e.currentTarget.reset();
  if (status) { status.className = 'form-status success'; status.textContent = 'Thanks. Your request was sent successfully.'; }
  Toast.show('Your request was sent successfully.');
  closeDialog('inquiryDialog');
  if (submit) submit.disabled = false;
  UI.renderCounts();
};

// Admin Section Switching
document.querySelector('#adminView').addEventListener('click', async e => {
  const tab = e.target.closest('[data-admin-tab]');
  if (tab) {
    document.querySelectorAll('[data-admin-tab]').forEach(x => x.classList.toggle('active', x === tab));
    document.querySelectorAll('.adminsection').forEach(x => x.classList.toggle('active', x.id === `admin-${tab.dataset.adminTab}`));
  }
});

document.querySelector('#addProduct').onclick = () => Admin.productForm();
document.querySelector('#addService').onclick = () => Admin.serviceForm();
document.querySelector('#adminProductSearch').oninput = () => Admin.products();

// Quick edit handling with strict allowlist and bounds validation
document.querySelector('#productTable').addEventListener('change', e => {
  if (!AuthService.isAuthenticated()) {
    Toast.show('Unauthorized: Admin session required.', 'error');
    return;
  }
  const el = e.target.closest('[data-quick]');
  if (!el) return;
  const field = el.dataset.quick;
  if (field !== 'price' && field !== 'stock') {
    Toast.show('Invalid property edit.', 'error');
    Admin.products();
    return;
  }
  const val = +el.value;
  if (!Number.isFinite(val) || val < 0 || (field === 'price' && val <= 0) || (field === 'stock' && !Number.isInteger(val))) {
    Toast.show('Enter a valid positive number.', 'error');
    Admin.products();
    return;
  }
  if (field === 'price' && val > 1000000) {
    Toast.show('Price exceeds maximum allowed limit.', 'error');
    Admin.products();
    return;
  }
  if (field === 'stock' && val > 100000) {
    Toast.show('Stock exceeds maximum allowed limit.', 'error');
    Admin.products();
    return;
  }
  InventoryService.update(el.dataset.id, { [field]: val });
  Toast.show('Quick edit saved');
});

// Admin actions delegation
document.querySelector('#adminView').addEventListener('click', async e => {
  const b = e.target.closest('[data-admin-action]');
  if (!b) return;
  if (!AuthService.isAuthenticated()) {
    Toast.show('Unauthorized: Admin session required.', 'error');
    return;
  }
  const { adminAction: a, id } = b.dataset;

  if (a === 'editProduct') {
    Admin.productForm(Store.data.products.find(p => p.id === id));
  }
  if (a === 'deleteProduct') {
    if (await confirmAction('Delete this product from the local catalog?')) InventoryService.remove(id);
  }
  if (a === 'feature') {
    const p = Store.data.products.find(x => x.id === id);
    if (p) InventoryService.update(id, { featured: !p.featured });
  }
  if (a === 'publishProduct') {
    const p = Store.data.products.find(x => x.id === id);
    if (p) InventoryService.update(id, { published: !p.published });
  }
  if (a === 'editService') {
    Admin.serviceForm(Store.data.services.find(s => s.id === id));
  }
  if (a === 'publishService') {
    const s = Store.data.services.find(x => x.id === id);
    if (s) {
      s.published = !s.published;
      Store.log(`${s.published ? 'Published' : 'Unpublished'} service: ${s.name}`);
      Store.save('services');
    }
  }
  if (a === 'deleteService') {
    if (await confirmAction('Delete this service?')) {
      Store.data.services = Store.data.services.filter(s => s.id !== id);
      Store.log('Deleted repair service');
      Store.save('services');
    }
  }
  if (a === 'deleteInquiry') {
    if (await confirmAction('Delete this inquiry?')) {
      Store.data.inquiries = Store.data.inquiries.filter(i => i.id !== id);
      Store.log('Deleted customer inquiry');
      Store.save('inquiries');
    }
  }
});

document.querySelector('#inquiryStatus').onchange = () => Admin.inquiries();

document.querySelector('#inquiryTable').onchange = e => {
  if (!AuthService.isAuthenticated()) return;
  const sel = e.target.closest('[data-inq-status]');
  if (!sel) return;
  const allowedStatuses = ['New', 'Contacted', 'In Progress', 'Resolved', 'Archived'];
  if (!allowedStatuses.includes(sel.value)) {
    Toast.show('Invalid status selected.', 'error');
    Admin.inquiries();
    return;
  }
  const i = Store.data.inquiries.find(x => x.id === sel.dataset.inqStatus);
  if (i) {
    i.status = sel.value;
    Store.log(`Inquiry status changed to ${i.status}`);
    Store.save('inquiries');
  }
};

// Admin Settings Save
document.querySelector('#saveSettings').onclick = () => {
  if (!AuthService.isAuthenticated()) return;
  const form = document.querySelector('#settingsForm');
  if (!form || !form.reportValidity()) return;

  const f = new FormData(form);
  const s = { ...Store.data.settings };

  for (const k of ['storeName', 'currency', 'locale', 'email', 'phone', 'whatsapp', 'address', 'latitude', 'longitude', 'servicesDefault']) {
    s[k] = Security.safeText(f.get(k), 200);
  }
  s.currency = s.currency.toUpperCase();
  s.lowStock = +f.get('lowStock');
  s.activityLimit = +f.get('activityLimit');
  s.broadcast = !!form.elements.broadcast?.checked;

  if (!Validator.validateSettings(s)) {
    Toast.show('Invalid settings entered. Check currency code, locale, threshold, and coordinates.', 'error');
    return;
  }

  s.hours = {};
  for (const k of ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']) {
    const a = form.elements[`${k}Open`]?.value;
    const b = form.elements[`${k}Close`]?.value;
    const closed = form.elements[`${k}Closed`]?.checked;
    if (closed) {
      s.hours[k] = null;
    } else if (Validator.isValidTime(a) && Validator.isValidTime(b)) {
      s.hours[k] = [a, b];
    } else {
      s.hours[k] = null;
    }
  }

  Store.data.settings = s;
  Store.log('Updated store settings');
  Store.save('settings');
  UI.renderAll();
  Toast.show('Settings saved successfully');
};

// Data Export with Credential Redaction
document.querySelector('#exportData').onclick = () => {
  if (!AuthService.isAuthenticated()) {
    Toast.show('Unauthorized: Admin session required.', 'error');
    return;
  }
  const cleanSettings = { ...Store.data.settings };
  // Strictly REDACT all credentials from exports
  delete cleanSettings.auth;
  delete cleanSettings.pin;

  const exportPayload = {
    schema: CONFIG.schema,
    exportedAt: new Date().toISOString(),
    products: Store.data.products,
    services: Store.data.services,
    inquiries: Store.data.inquiries,
    settings: cleanSettings,
    activity: Store.data.activity,
    preferences: Store.data.preferences
  };

  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `world-electronics-export-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  Toast.show('Sanitized demo data exported (credentials safely redacted)');
};

// Data Import with 2MB File Cap, Schema Verification, and Deep Validation
document.querySelector('#importFile').onchange = async e => {
  if (!AuthService.isAuthenticated()) {
    Toast.show('Unauthorized: Admin session required.', 'error');
    e.target.value = '';
    return;
  }
  const file = e.target.files[0];
  if (!file) return;

  const fileValidation = Validator.validateFileUpload(file, {
    maxSize: CONFIG.maxImportBytes,
    allowedExtensions: ['.json'],
    allowedMimeTypes: ['application/json', 'text/json']
  });

  if (!fileValidation.valid) {
    Toast.show(`Import rejected: ${fileValidation.error}`, 'error');
    e.target.value = '';
    return;
  }

  try {
    const text = await file.text();
    const x = JSON.parse(text);

    if (x.schema !== CONFIG.schema || !Array.isArray(x.products) || !Array.isArray(x.services) || !Array.isArray(x.inquiries) || !x.settings || typeof x.settings !== 'object') {
      throw new Error('Unsupported or malformed data schema.');
    }

    if (x.products.length > 500 || x.services.length > 100 || x.inquiries.length > 200) {
      throw new Error('Import contains excessive record counts.');
    }

    const cleanedProducts = Security.deepCloneSafe(x.products);
    const cleanedServices = Security.deepCloneSafe(x.services);
    const cleanedInquiries = Security.deepCloneSafe(x.inquiries);
    const cleanedSettings = Security.deepCloneSafe(x.settings);

    if (!cleanedProducts.every(p => Validator.isSafeProduct(p))) {
      throw new Error('Product catalog contains invalid product records.');
    }
    if (!cleanedServices.every(s => Validator.isSafeService(s))) {
      throw new Error('Service list contains invalid service records.');
    }
    if (!cleanedInquiries.every(i => Validator.isSafeInquiry(i))) {
      throw new Error('Inquiries contain invalid data records.');
    }

    // Preserve the current admin authentication credentials
    delete cleanedSettings.auth;
    delete cleanedSettings.pin;

    if (!await confirmAction('Import will replace current catalog records in this browser. Continue?')) {
      return;
    }

    Store.data = {
      products: cleanedProducts,
      services: cleanedServices,
      inquiries: cleanedInquiries,
      settings: {
        ...defaults,
        ...cleanedSettings,
        hours: { ...defaults.hours, ...(cleanedSettings.hours || {}) }
      },
      activity: Array.isArray(x.activity) ? Security.deepCloneSafe(x.activity).slice(0, 50) : [],
      preferences: { wishlist: [], compare: [], ...Security.deepCloneSafe(x.preferences || {}) }
    };

    Store.log('Imported validated demo data snapshot');
    Store.saveAll();
    UI.renderAll();
    Toast.show('Data imported successfully');
  } catch (err) {
    Toast.show(`Import rejected: ${err.message}`, 'error');
  } finally {
    e.target.value = '';
  }
};

document.querySelector('#resetData').onclick = async () => {
  if (!AuthService.isAuthenticated()) {
    Toast.show('Unauthorized: Admin session required.', 'error');
    return;
  }
  if (await confirmAction('Reset the complete catalog to original verified defaults? This replaces modified records in this browser.')) {
    Store.reset();
    UI.renderAll();
    Toast.show('Demo catalog reset to baseline');
  }
};

document.querySelector('#settingsForm')?.addEventListener('submit', e => e.preventDefault());
document.querySelectorAll('[data-close]').forEach(b => b.onclick = () => closeDialog(b.dataset.close));
document.querySelectorAll('dialog').forEach(d => {
  d.addEventListener('click', e => {
    if (e.target === d) d.close();
  });
  if (d.id === 'pinDialog') d.addEventListener('close', () => {
    document.querySelector('#pinInput').value = '';
    document.querySelector('#mfaInput').value = '';
    AuthService.pendingAuth = null;
  });
});

document.querySelector('#wishContent').onclick = e => {
  const b = e.target.closest('[data-action]');
  if (!b) return;
  if (b.dataset.action === 'wish') {
    Customer.toggle('wishlist', b.dataset.id);
    Customer.wishlist();
  } else if (b.dataset.action === 'detail') {
    Customer.open(b.dataset.id);
  }
};

document.querySelector('#compareContent').onclick = e => {
  if (e.target.closest('[data-action="clearCompare"]')) {
    Store.data.preferences.compare = [];
    Store.save('preferences', false);
    UI.renderCounts();
    Customer.showCompare();
  }
};

const menuToggle = document.querySelector('#menuToggle');
const mainLinks = document.querySelector('#mainLinks');
menuToggle?.addEventListener('click', () => {
  const open = menuToggle.getAttribute('aria-expanded') !== 'true';
  menuToggle.setAttribute('aria-expanded', String(open));
  menuToggle.setAttribute('aria-label', open ? 'Close navigation menu' : 'Open navigation menu');
  mainLinks?.classList.toggle('open', open);
});
mainLinks?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => {
  mainLinks.classList.remove('open');
  menuToggle?.setAttribute('aria-expanded', 'false');
  menuToggle?.setAttribute('aria-label', 'Open navigation menu');
}));

window.addEventListener('scroll', () => {
  const nav = document.querySelector('#nav');
  if (nav) nav.classList.toggle('scrolled', window.scrollY > 12);
}, { passive: true });

// Theme, cookie choice, search attribution and small accessibility helpers.
const themeButton = document.querySelector('#themeToggle');
const applyTheme = dark => {
  document.documentElement.classList.toggle('dark-mode', dark);
  themeButton?.setAttribute('aria-pressed', String(dark));
  if (themeButton) themeButton.textContent = dark ? '☀' : '☾';
};
try { applyTheme(localStorage.getItem('we.theme') === 'dark'); } catch {}
themeButton?.addEventListener('click', () => {
  const dark = !document.documentElement.classList.contains('dark-mode');
  applyTheme(dark);
  try { localStorage.setItem('we.theme', dark ? 'dark' : 'light'); } catch {}
});
const banner = document.querySelector('#cookieBanner');
let consent = '';
try { consent = localStorage.getItem('we.consent') || ''; } catch {}
if (!consent && banner) banner.hidden = false;
let siteConfig = null;
const addSearchConsoleVerification = token => {
  if (!token) return;
  const meta = document.querySelector('#googleVerification') || document.createElement('meta');
  meta.name = 'google-site-verification'; meta.content = token;
  if (!meta.isConnected) document.head.append(meta);
};
const loadAnalytics = () => {
  if (!siteConfig?.analyticsId || window.gtag) return;
  const id = String(siteConfig.analyticsId);
  window.dataLayer = window.dataLayer || [];
  window.gtag = function(){ window.dataLayer.push(arguments); };
  window.gtag('js', new Date());
  window.gtag('config', id, { anonymize_ip: true });
  const script = document.createElement('script'); script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(id)}`;
  document.head.append(script);
};
fetch('/api/site-config').then(response => response.ok ? response.json() : null).then(config => {
  if (!config) return;
  siteConfig = config;
  addSearchConsoleVerification(config.googleVerification);
  if (config.publicSiteUrl) {
    const origin = String(config.publicSiteUrl).replace(/\/$/, '');
    const canonical = document.querySelector('#canonicalUrl');
    if (canonical) canonical.href = `${origin}${location.pathname === '/' ? '/' : location.pathname}`;
    const og = document.querySelector('meta[property="og:image"]');
    if (og) og.content = `${origin}/og-image.svg`;
    const schema = document.querySelector('#organizationSchema');
    if (schema) schema.textContent = JSON.stringify({ '@context':'https://schema.org', '@type':'Organization', name:'World Electronics', url:`${origin}/`, logo:`${origin}/favicon.svg`, description:'Technology products and repair support.' });
  }
  if (consent === 'analytics') loadAnalytics();
}).catch(() => {});
const saveConsent = choice => {
  try { localStorage.setItem('we.consent', choice); } catch {}
  if (banner) banner.hidden = true;
  if (choice === 'analytics') loadAnalytics();
};
document.querySelector('#cookieAccept')?.addEventListener('click', () => saveConsent('analytics'));
document.querySelector('#cookieDecline')?.addEventListener('click', () => saveConsent('essential'));
const topButton = document.querySelector('#backToTop');
const progress = document.querySelector('#scrollProgress');
window.addEventListener('scroll', () => {
  const max = document.documentElement.scrollHeight - innerHeight;
  if (progress) progress.style.transform = `scaleX(${max > 0 ? scrollY / max : 0})`;
  topButton?.classList.toggle('visible', scrollY > 500);
}, { passive: true });
topButton?.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
document.querySelector('#copyPageLink')?.addEventListener('click', async e => {
  try { await navigator.clipboard.writeText(location.href); e.currentTarget.textContent = 'Link copied'; Toast.show('Page link copied.'); }
  catch { Toast.show('Could not copy the link. Please copy it from your address bar.', 'error'); }
});
// Retain only campaign attribution values for this browser tab.
const utm = Object.fromEntries(Array.from(new URLSearchParams(location.search).entries()).filter(([key]) => /^utm_(source|medium|campaign|term|content)$/.test(key)));
if (Object.keys(utm).length) { try { sessionStorage.setItem('we.utm', JSON.stringify(utm)); } catch {} }

setInterval(() => UI.updateHours(), 30000);

/* 12. Application Initialization Bootstrapper */
Store.load();
SyncEngine.init();
UI.renderAll();
UI.syncControls();
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
}

// Export modules for unit testing if running in test environment
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Security, Validator, AuthService, InquiryLimiter, Store, InventoryService, CONFIG };
}
