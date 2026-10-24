# Security notes

## Implemented in this demo

- Admin login is verified by the server using a configured scrypt hash. There is no built-in password or PIN.
- Admin sessions use random `Secure`, `HttpOnly`, `SameSite=Strict` cookies. CSRF tokens are kept in server memory and checked on authenticated logout. Mutating browser API requests also require an allowed origin.
- TOTP verification can be enabled with a server-only secret. Login is rate-limited, JSON bodies are size-limited, and webhook handling is disabled until a signing secret is configured.
- Inquiry reads require an authenticated admin session. Public product reads expose only records explicitly marked published.
- Imported JSON is size-limited, parsed, schema-checked, and validated. Existing browser-stored auth hashes, PINs, and tokens are purged.
- Dynamic storefront values are escaped before HTML insertion. There is no SQL database or SQL execution path in this project.
- No source maps or third-party npm dependencies are present in the repository.

## Configure before deployment

1. Run `node scripts/generate-admin-credentials.mjs` in an interactive terminal. It prints a scrypt password hash and a TOTP secret; save both in the deployment secret manager, not in source control.
2. Set `ADMIN_PASSWORD_HASH`, `ADMIN_TOTP_SECRET`, `ALLOWED_ORIGINS`, and `PUBLIC_SITE_URL`. Set `WEBHOOK_SECRET` only when a webhook provider is configured.
3. Serve the site over HTTPS. The admin cookie is always marked `Secure`.

## Scope limits

This repository has no persistent database. Catalog edits and the storefront admin data remain browser-local; server inquiries are held in process memory and disappear on restart. The server's `Map`-based rate limits and replay cache are per-process, so a multi-instance deployment needs shared storage. There are no per-customer or multi-tenant records, so row-level access is limited to the single-store published-product/admin-inquiry rules. Do not use this prototype to store production customer or payment data without a persistent server-side data layer and deployment-specific security review.
