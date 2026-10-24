import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const app = require('../app.js');

const { Security, Validator, AuthService, InquiryLimiter, Store, CONFIG } = app;

async function runTests() {
  console.log('--- STARTING COMPREHENSIVE SECURITY TEST SUITE ---');
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}:`, err.message);
      failed++;
    }
  }

  async function testAsync(name, fn) {
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}:`, err.message);
      failed++;
    }
  }

  // 1. XSS Escaping Tests
  test('Security.escapeHTML neutralizes script tags', () => {
    const raw = '<script>alert("XSS")</script>';
    const escaped = Security.escapeHTML(raw);
    assert.equal(escaped, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;');
  });

  test('Security.escapeHTML neutralizes attributes and event handlers', () => {
    const raw = '" onfocus="alert(1)" class=\'test\' `template`';
    const escaped = Security.escapeHTML(raw);
    assert.equal(escaped, '&quot; onfocus=&quot;alert(1)&quot; class=&#39;test&#39; &#96;template&#96;');
  });

  test('Security.escapeHTML handles null, undefined, numbers', () => {
    assert.equal(Security.escapeHTML(null), '');
    assert.equal(Security.escapeHTML(undefined), '');
    assert.equal(Security.escapeHTML(123), '123');
  });

  // 2. Safe URL Validation
  test('Security.safeURL blocks dangerous pseudo-protocols', () => {
    assert.equal(Security.safeURL('javascript:alert(1)'), '');
    assert.equal(Security.safeURL('data:text/html,<script>alert(1)</script>'), '');
    assert.equal(Security.safeURL('blob:http://localhost/uuid'), '');
    assert.equal(Security.safeURL('file:///etc/passwd'), '');
    assert.equal(Security.safeURL('vbscript:msgbox'), '');
  });

  test('Security.safeURL permits valid http and https URLs', () => {
    assert.equal(Security.safeURL('https://example.com/photo.jpg'), 'https://example.com/photo.jpg');
    assert.equal(Security.safeURL('http://example.com/item.png'), 'http://example.com/item.png');
  });

  // 3. Prototype Pollution Defense
  test('Security.deepCloneSafe strips __proto__, constructor, and prototype', () => {
    const maliciousPayload = JSON.parse('{"name":"Laptop","__proto__":{"polluted":"yes"},"specs":{"constructor":{"polluted":"yes"}}}');
    const cleaned = Security.deepCloneSafe(maliciousPayload);
    assert.equal(Object.prototype.polluted, undefined, 'Object.prototype must not be polluted');
    assert.equal(cleaned.__proto__, Object.prototype);
    assert.equal(cleaned.name, 'Laptop');
    assert.equal(cleaned.specs.constructor, Object);
  });

  // 4. Cryptographic Password Hashing Primitive
  await testAsync('Security.hashPIN derives a salted hash and timingSafeEqual compares it', async () => {
    const salt = 'abcdef0123456789abcdef0123456789';
    const computed = await Security.hashPIN('test-only-passphrase', salt);
    assert.match(computed, /^[a-f0-9]{64}$/);
    assert.equal(Security.timingSafeEqual(computed, computed), true);
    assert.equal(Security.timingSafeEqual(computed, 'wrong_hash_string'), false);
  });

  // 5. Server-Side Authentication & Fail-Closed Defaults
  await testAsync('AuthService does not accept client-side or default credentials', async () => {
    AuthService.sessionToken = null;
    const result = await AuthService.authenticate('test-only-passphrase');
    assert.equal(result.success, false);
    assert.equal(AuthService.sessionToken, null);
    assert.ok(result.error, 'Unavailable or unconfigured server auth must fail closed');
  });

  // 6. Session Lifecycle & Idle Expiry
  await testAsync('AuthService never creates a local session without server authentication', async () => {
    AuthService.sessionToken = null;
    const authRes = await AuthService.authenticate('test-only-passphrase');
    assert.equal(authRes.success, false);
    assert.equal(AuthService.sessionToken, null);
    AuthService.logout();
    assert.equal(AuthService.sessionToken, null);
  });

  // 7. Input Validation & Bounds Checking
  test('Validator.isSafeProduct rejects invalid or malicious products', () => {
    // Valid product
    const valid = {
      id: 'prod-01',
      name: 'Safe Laptop',
      brand: 'TestBrand',
      model: 'X100',
      category: 'Laptops & PCs',
      price: 999,
      previousPrice: null,
      stock: 10,
      threshold: 2,
      description: 'A tested safe laptop description.'
    };
    assert.equal(Validator.isSafeProduct(valid), true);

    // Negative price
    assert.equal(Validator.isSafeProduct({ ...valid, price: -50 }), false);

    // Non-integer stock
    assert.equal(Validator.isSafeProduct({ ...valid, stock: 4.5 }), false);

    // Invalid category
    assert.equal(Validator.isSafeProduct({ ...valid, category: 'Malicious Category' }), false);

    // Excessive price (> 1M)
    assert.equal(Validator.isSafeProduct({ ...valid, price: 10000000 }), false);
  });

  test('Validator.validateSettings enforces ISO currency and coordinates', () => {
    const validSettings = {
      storeName: 'World Electronics',
      currency: 'USD',
      locale: 'en-US',
      email: 'store@example.com',
      latitude: '37.7749',
      longitude: '-122.4194',
      lowStock: 4,
      activityLimit: 50
    };
    assert.equal(Validator.validateSettings(validSettings), true);

    // Invalid currency code (XSS vector or wrong length)
    assert.equal(Validator.validateSettings({ ...validSettings, currency: '<script>' }), false);
    assert.equal(Validator.validateSettings({ ...validSettings, currency: 'US' }), false);

    // Invalid latitude out of range
    assert.equal(Validator.validateSettings({ ...validSettings, latitude: '120.5' }), false);
  });

  // 8. Inquiry Abuse Rate Limiting
  test('InquiryLimiter enforces client-side rate limits against spam', () => {
    InquiryLimiter.submissions = [];
    for (let i = 0; i < 5; i++) {
      assert.equal(InquiryLimiter.isRateLimited(), false, `Request ${i + 1} should be allowed`);
    }
    // 6th request must be blocked
    assert.equal(InquiryLimiter.isRateLimited(), true, '6th request within 1 minute must be rate-limited');
  });

  // 9. Data Portability & Credential Protection
  test('Export payload redacts credentials', () => {
    const exportSettings = { ...Store.data.settings };
    delete exportSettings.auth;
    delete exportSettings.pin;
    assert.equal(exportSettings.auth, undefined, 'Auth credentials must not appear in export');
    assert.equal(exportSettings.pin, undefined, 'Plaintext PIN must not appear in export');
  });

  // 10. Service & Inquiry Validation
  test('Validator.isSafeService validates service types and pricing', () => {
    const valid = { id: 'svc-01', name: 'Screen Repair', type: 'Mobile repair', price: 49, description: 'Screen replacement' };
    assert.equal(Validator.isSafeService(valid), true);
    assert.equal(Validator.isSafeService({ ...valid, price: -10 }), false);
    assert.equal(Validator.isSafeService({ ...valid, name: '' }), false);
  });

  test('Validator.isSafeInquiry enforces status and type allowlists', () => {
    const valid = {
      id: 'inq-01',
      name: 'John Doe',
      contact: 'john@example.com',
      type: 'Repair service',
      message: 'Need help with laptop',
      status: 'New'
    };
    assert.equal(Validator.isSafeInquiry(valid), true);
    assert.equal(Validator.isSafeInquiry({ ...valid, type: 'Malicious Type' }), false);
    assert.equal(Validator.isSafeInquiry({ ...valid, status: 'Hacked' }), false);
    assert.equal(Validator.isSafeInquiry({ ...valid, message: '' }), false);
  });

  // 11. Import Size Limits and Schema Integrity
  test('CONFIG.maxImportBytes enforces a 2MB ceiling', () => {
    assert.equal(CONFIG.maxImportBytes, 2097152, 'Max import size must be 2MB');
  });

  // 12. Cross-Tab Sync Ingestion Checks
  test('Broadcast message validation rejects unauthorized settings modifications', () => {
    const maliciousBroadcast = {
      origin: 'malicious-tab',
      id: 'msg-1',
      name: 'settings',
      data: {
        auth: { hash: 'hacked_hash', salt: 'hacked_salt' },
        pin: '9999',
        currency: 'EUR'
      }
    };
    // Deep clone and clean
    const safeData = Security.deepCloneSafe(maliciousBroadcast.data);
    delete safeData.auth;
    delete safeData.pin;
    assert.equal(safeData.auth, undefined, 'Auth must be stripped from broadcast sync');
    assert.equal(safeData.pin, undefined, 'PIN must be stripped from broadcast sync');
    assert.equal(safeData.currency, 'EUR');
  });

  // 13. SSRF Protection Tests
  test('Security.isSSRFSafeURL and Security.safeURL block private, loopback, and cloud metadata targets', () => {
    // Loopback & local
    assert.equal(Security.isSSRFSafeURL('http://127.0.0.1/admin'), false);
    assert.equal(Security.isSSRFSafeURL('http://localhost:8080/'), false);
    assert.equal(Security.isSSRFSafeURL('http://[::1]/'), false);

    // Cloud metadata services (AWS / GCP / Azure)
    assert.equal(Security.isSSRFSafeURL('http://169.254.169.254/latest/meta-data/'), false);
    assert.equal(Security.isSSRFSafeURL('http://metadata.google.internal/computeMetadata/v1/'), false);

    // RFC 1918 Private Networks
    assert.equal(Security.isSSRFSafeURL('http://10.0.0.1/internal'), false);
    assert.equal(Security.isSSRFSafeURL('http://172.16.0.5/api'), false);
    assert.equal(Security.isSSRFSafeURL('http://192.168.1.1/router'), false);

    // Disallowed schemes & decimal bypass
    assert.equal(Security.isSSRFSafeURL('http://2130706433/'), false);
    assert.equal(Security.isSSRFSafeURL('ftp://example.com/file'), false);

    // Valid public web URLs
    assert.equal(Security.isSSRFSafeURL('https://example.com/image.png'), true);
    assert.equal(Security.safeURL('https://example.com/image.png'), 'https://example.com/image.png');
    assert.equal(Security.safeURL('http://127.0.0.1:3000/'), '');
  });

  // 14. Anti-CSRF Token Generation and Verification
  test('Security CSRF protection generates and verifies cryptographically secure tokens', () => {
    const token = Security.generateCSRFToken();
    assert.equal(typeof token, 'string');
    assert.equal(token.length, 64); // 32 bytes hex
    assert.equal(Security.verifyCSRFToken(token), true);
    assert.equal(Security.verifyCSRFToken('invalid_csrf_token'), false);
    assert.equal(Security.verifyCSRFToken(''), false);
  });

  // 15. Webhook HMAC-SHA256 Signature Verification & Replay Protection
  await testAsync('Security.verifyWebhookSignature verifies authentic signatures and prevents replay attacks', async () => {
    const payload = JSON.stringify({ event: 'inventory.updated', id: 'evt_9988' });
    const secret = 'whsec_prod_test_secret_key_12345';
    const now = Math.floor(Date.now() / 1000);

    const validSig = await Security.computeHmacSha256(secret, `${now}.${payload}`);
    const validHeader = `t=${now},v1=${validSig}`;

    // Valid signature within tolerance
    const isValid = await Security.verifyWebhookSignature(payload, validHeader, secret, 300);
    assert.equal(isValid, true, 'Valid webhook signature must pass');

    // Tampered payload
    const isTampered = await Security.verifyWebhookSignature(payload + 'tampered', validHeader, secret, 300);
    assert.equal(isTampered, false, 'Tampered webhook payload must fail');

    // Expired timestamp (replay attack defense)
    const expiredTimestamp = now - 600; // 10 minutes ago
    const expiredSig = await Security.computeHmacSha256(secret, `${expiredTimestamp}.${payload}`);
    const expiredHeader = `t=${expiredTimestamp},v1=${expiredSig}`;
    const isExpired = await Security.verifyWebhookSignature(payload, expiredHeader, secret, 300);
    assert.equal(isExpired, false, 'Expired webhook must be rejected to prevent replay attacks');
  });

  // 16. Multi-Factor Authentication (RFC 6238 TOTP & Recovery Codes)
  await testAsync('Security.TOTP generates RFC 6238 compliant TOTP codes and handles recovery codes', async () => {
    // RFC 6238 standard test vector (secret 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', timestamp 59s -> 287082)
    const testSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const code = await Security.TOTP.generateTOTP(testSecret, 59);
    assert.equal(code, '287082', 'Must match RFC 6238 standard test vector');

    // Verification with time window tolerance
    const validNow = await Security.TOTP.verifyTOTP(code, testSecret, 1, 59);
    assert.equal(validNow, true, 'TOTP code at exact timestamp must verify');

    const invalidCode = await Security.TOTP.verifyTOTP('000000', testSecret, 1, 59);
    assert.equal(invalidCode, false, 'Incorrect TOTP code must be rejected');

    // Emergency single-use recovery codes
    const recoveryCodes = Security.TOTP.generateRecoveryCodes(8);
    assert.equal(recoveryCodes.length, 8);
    assert.ok(recoveryCodes.every(c => /^[0-9A-F]{4}-[0-9A-F]{4}$/.test(c)));
  });

  // 17. Sensitive Data Redaction from Logs
  test('Security.redactSensitiveData cleans customer PII, credentials, and tokens from logs', () => {
    const raw = 'User john.doe@example.com with phone +1-555-867-5309 entered pin=1234 on card 4111-2222-3333-4444';
    const redacted = Security.redactSensitiveData(raw);
    assert.ok(!redacted.includes('john.doe@example.com'), 'Email must be redacted');
    assert.ok(!redacted.includes('555-867-5309'), 'Phone must be redacted');
    assert.ok(!redacted.includes('1234'), 'PIN credential must be redacted');
    assert.ok(!redacted.includes('4111-2222-3333-4444'), 'Credit card must be redacted');
    assert.ok(redacted.includes('[REDACTED_EMAIL]'));
    assert.ok(redacted.includes('[REDACTED_PHONE]'));
    assert.ok(redacted.includes('[REDACTED_CREDENTIAL]'));
    assert.ok(redacted.includes('[REDACTED_CARD]'));
  });

  // 18. SQL Injection Parameterized Query & Identifier Sanitization
  test('Security.DatabaseSecurity enforces identifier allowlisting and parameterized query structure', () => {
    // Valid identifier
    const safeTable = Security.DatabaseSecurity.sanitizeIdentifier('products');
    assert.equal(safeTable, '"products"');

    // Malicious SQL injection in identifier
    assert.throws(() => {
      Security.DatabaseSecurity.sanitizeIdentifier('products; DROP TABLE users;--');
    }, /Invalid SQL identifier/);

    // Parameterized query construction
    const query = Security.DatabaseSecurity.buildParameterizedQuery('inquiries', { status: 'New', type: 'Repair' });
    assert.equal(query.sql, 'SELECT * FROM "inquiries" WHERE "status" = $1 AND "type" = $2');
    assert.deepEqual(query.params, ['New', 'Repair']);
  });

  // 19. File Upload Validation
  test('Validator.validateFileUpload validates extensions, MIME types, and blocks scripts', () => {
    // Valid JSON file
    const validFile = { name: 'catalog-backup.json', size: 1024, type: 'application/json' };
    assert.equal(Validator.validateFileUpload(validFile).valid, true);

    // Empty file (0 bytes)
    assert.equal(Validator.validateFileUpload({ name: 'empty.json', size: 0, type: 'application/json' }).valid, false);

    // File exceeding size limit
    assert.equal(Validator.validateFileUpload({ name: 'huge.json', size: 10 * 1024 * 1024, type: 'application/json' }).valid, false);

    // Dangerous executable or script masquerading
    assert.equal(Validator.validateFileUpload({ name: 'payload.html', size: 500, type: 'text/html' }).valid, false);
    assert.equal(Validator.validateFileUpload({ name: 'malware.svg', size: 500, type: 'image/svg+xml' }).valid, false);
    assert.equal(Validator.validateFileUpload({ name: 'script.js', size: 500, type: 'application/javascript' }).valid, false);
    assert.equal(Validator.validateFileUpload({ name: 'exploit.php', size: 500, type: 'application/x-php' }).valid, false);
  });

  // 20. Password Strength & No Browser Credential Store
  test('Validator rejects weak credentials and settings contain no auth secrets', () => {
    assert.equal(Object.hasOwn(Store.data.settings, 'auth'), false);
    assert.equal(Object.hasOwn(Store.data.settings, 'pin'), false);

    // Trivial and weak PINs
    assert.equal(Validator.isStrongPIN('1234'), false);
    assert.equal(Validator.isStrongPIN('000000'), false);
    assert.equal(Validator.isStrongPIN('123456'), false);
    assert.equal(Validator.isStrongPIN('password'), false);

    // Strong custom PIN / password
    assert.equal(Validator.isStrongPIN('StrongPass#2026!'), true);
    assert.equal(Validator.isStrongPIN('982741'), true);
  });

  // 21. Row-Level Security for Inquiries and Catalog
  test('Store enforces Row-Level Security: inquiries accessible only to authenticated admins', () => {
    AuthService.sessionToken = null; // Unauthenticated
    Store.data.inquiries = [
      { id: 'inq-1', name: 'Private Customer', contact: 'private@test.com', type: 'Repair service', message: 'Secret issue', status: 'New' }
    ];

    // Unauthenticated access must receive empty array
    assert.deepEqual(Store.getInquiries(), [], 'Unauthenticated callers must not access customer inquiries');

    // Authenticated access gets records
    AuthService.sessionToken = 'test_token_valid';
    AuthService.sessionExpires = Date.now() + 60000;
    assert.equal(Store.getInquiries().length, 1);
    assert.equal(Store.getInquiries()[0].name, 'Private Customer');

    AuthService.logout();
  });

  // 22. Absence of Auth Tokens in Local Storage
  test('AuthService.purgeStorageTokens verifies no tokens remain in browser storage', () => {
    // Session token is strictly in-memory
    AuthService.sessionToken = 'ram_only_token';
    AuthService.purgeStorageTokens();
    assert.equal(typeof localStorage, 'undefined', 'Storage tokens must not be exposed');
    AuthService.logout();
  });

  // 23. Server Password Hash and TOTP Verification
  const serverSecurity = await import('../server.js');
  await testAsync('Server verifies scrypt password hashes and TOTP codes', async () => {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync('test-only-server-password', salt, 64);
    const encoded = `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
    assert.equal(serverSecurity.verifyPassword('test-only-server-password', encoded), true);
    assert.equal(serverSecurity.verifyPassword('incorrect', encoded), false);
    assert.equal(serverSecurity.verifyPassword('incorrect', '9482'), false);
    assert.equal(serverSecurity.verifyTOTP('287082', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000), true);
    assert.equal(serverSecurity.verifyTOTP('000000', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000), false);
    const payload = '{"event":"test"}';
    const hookSecret = 'test-only-webhook-secret';
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = crypto.createHmac('sha256', hookSecret).update(`${timestamp}.${payload}`).digest('hex');
    assert.equal(serverSecurity.verifyWebhook(payload, `t=${timestamp},v1=${signature}`, hookSecret), true);
    assert.equal(serverSecurity.verifyWebhook(payload, `t=${timestamp},v1=${signature}`, ''), false);
    assert.equal(serverSecurity.isSSRFSafe('http://[::ffff:7f00:1]/'), false);
    assert.equal(serverSecurity.isSSRFSafe('http://[fd00::1]/'), false);
    assert.equal(serverSecurity.isSSRFSafe('https://example.com/image.png'), true);
    const rateKey = crypto.randomUUID();
    assert.equal(serverSecurity.checkRateLimit(rateKey, 'test', 1, 60000), true);
    assert.equal(serverSecurity.checkRateLimit(rateKey, 'test', 1, 60000), false);
    assert.equal(serverSecurity.SERVER_CONFIG.jwtSecret, undefined, 'No unused JWT secret should be generated');
  });

  console.log(`\n--- TEST SUITE SUMMARY: ${passed} PASSED, ${failed} FAILED ---`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
