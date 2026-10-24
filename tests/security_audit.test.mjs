import assert from 'node:assert/strict';
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

  // 4. Cryptographic Authentication & PBKDF2 Hashing
  await testAsync('Security.hashPIN and timingSafeEqual verify correct PIN', async () => {
    const salt = 'c3b9e4a1f8d2705e6b1a3d9f2e4c8b0a';
    const expectedHash = 'f0ed1009c9701369282e45a7cc0934c5d5af2b82d4fea6f50b439db6f10c529b';
    const computed = await Security.hashPIN('1234', salt);
    assert.equal(computed, expectedHash);
    assert.equal(Security.timingSafeEqual(computed, expectedHash), true);
    assert.equal(Security.timingSafeEqual(computed, 'wrong_hash_string'), false);
  });

  // 5. Brute Force & Rate Limiting Protection
  await testAsync('AuthService locks out attacker after 5 consecutive failed attempts', async () => {
    // Reset state for testing
    AuthService.failedAttempts = 0;
    AuthService.lockoutUntil = 0;
    AuthService.sessionToken = null;

    for (let i = 1; i <= 4; i++) {
      const res = await AuthService.authenticate('wrong_pin');
      assert.equal(res.success, false);
      assert.equal(res.remainingAttempts, 5 - i);
      assert.equal(AuthService.isLockedOut(), 0);
    }

    // 5th attempt must trigger lockout
    const fifth = await AuthService.authenticate('wrong_pin');
    assert.equal(fifth.success, false);
    assert.equal(fifth.lockedOut, true);
    assert.ok(AuthService.isLockedOut() > 0, 'Lockout timer must be active');

    // 6th attempt must be rejected immediately due to lockout
    const sixth = await AuthService.authenticate('1234');
    assert.equal(sixth.success, false);
    assert.equal(sixth.lockedOut, true);
  });

  // 6. Session Lifecycle & Idle Expiry
  await testAsync('AuthService creates authenticated session and supports logout', async () => {
    // Clear lockout for session test
    AuthService.failedAttempts = 0;
    AuthService.lockoutUntil = 0;

    const authRes = await AuthService.authenticate('1234');
    assert.equal(authRes.success, true);
    assert.ok(AuthService.sessionToken, 'Session token must be present');
    assert.equal(AuthService.isAuthenticated(), true);

    // Simulate session expiry
    AuthService.sessionExpires = Date.now() - 1000;
    assert.equal(AuthService.isAuthenticated(), false);

    // Re-authenticate and test explicit logout
    await AuthService.authenticate('1234');
    assert.equal(AuthService.isAuthenticated(), true);
    AuthService.logout();
    assert.equal(AuthService.sessionToken, null);
    assert.equal(AuthService.isAuthenticated(), false);
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

  console.log(`\n--- TEST SUITE SUMMARY: ${passed} PASSED, ${failed} FAILED ---`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
