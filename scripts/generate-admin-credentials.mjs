import crypto from 'node:crypto';

function base32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i < bits.length; i += 5) output += alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return output;
}

if (!process.stdin.isTTY || !process.stdin.setRawMode) {
  process.stderr.write('Run this helper in an interactive terminal so the password is not echoed.\n');
  process.exit(1);
}

process.stdout.write('Admin password (minimum 12 characters): ');
process.stdin.setRawMode(true);
process.stdin.resume();
let password = '';
process.stdin.on('data', chunk => {
  for (const char of chunk.toString('utf8')) {
    if (char === '\u0003') { process.stdout.write('\nCancelled.\n'); process.exit(1); }
    if (char === '\r' || char === '\n') {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
      if (password.length < 12 || password.length > 256) {
        process.stderr.write('Use a password between 12 and 256 characters.\n');
        process.exit(1);
      }
      const salt = crypto.randomBytes(16);
      const hash = crypto.scryptSync(password, salt, 64);
      const totpSecret = base32(crypto.randomBytes(20));
      password = '';
      process.stdout.write(`ADMIN_PASSWORD_HASH=scrypt$${salt.toString('hex')}$${hash.toString('hex')}\n`);
      process.stdout.write(`ADMIN_TOTP_SECRET=${totpSecret}\n`);
      process.stdout.write('Store both values in your server secret manager. Do not commit them.\n');
      process.exit(0);
    }
    if (char === '\u007f' || char === '\b') password = password.slice(0, -1);
    else if (char >= ' ') password += char;
  }
});
