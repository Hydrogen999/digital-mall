# Digital Mall: security hardening and upgrade plan

## 1. Do these BEFORE you deploy (things code can't do for you)

1. **Delete the old default accounts if they ever existed in your live database.**
   The previous version exposed `/admin/create` (creates `admin@mall.test` / `admin123`) and `/seed`
   (vendors with password `demo123`). If anyone, including you, ever opened those URLs on the live site,
   those accounts exist and the passwords are public knowledge. Delete them, then create a real admin:
   `flask --app app create-admin`
2. **Set `SECRET_KEY`** (32+ random characters) and a real `PAYSTACK_SECRET_KEY`. The app now refuses to start
   in production without them. Rotate both if the old defaults (`dev-change-me-please`, `sk_test_xxxx`) were ever live.
3. **Set the Paystack webhook URL** in your Paystack dashboard to `https://YOUR-DOMAIN/paystack-webhook`.
4. **KYC ID photos uploaded before this change are public Cloudinary URLs.** New uploads are private/signed.
   Ask existing vendors to re-submit, or move/delete the old assets in the Cloudinary console.
5. **Install the new requirements in staging first**: `pip install -r requirements.txt && pip-audit`.
   I couldn't install packages in my sandbox, so the version bumps are untested together.
6. **Turn on the Content-Security-Policy**: it ships in `report-only` mode. Open the site, check the browser
   console for CSP violations, then set `CSP_MODE=enforce`. (Tailwind's CDN build is the likeliest culprit.)
7. Enable 2-factor auth on: your Render/host account, GitHub, Cloudinary, Paystack, and the Gmail used for mail.
   Use a Gmail *app password*, not the account password.

## 2. What was fixed

| Severity | Issue | Fix |
|---|---|---|
| Critical | Shop activation was **free**: `POST /vendor/pay-activation` activated any vendor, even unapproved/unpaid | Real Paystack payment; activation only on a verified, amount-checked payment; only admin-approved shops may pay |
| Critical | Public `/admin/create` with `admin123`; public `/seed` with `demo123` | Removed; replaced by CLI commands `create-admin` and `seed-demo` |
| Critical | Stored XSS in chat (`innerHTML`) | `textContent` only; server-side length limits |
| Critical | `javascript:` links in vendor "social links" rendered in the admin panel (admin-takeover vector) | Only http(s) URLs saved *and* re-checked at render |
| High | Orders could never be marked PAID: Paystack was not sent your order reference, so the webhook couldn't match | Reference now sent; webhook + return page both verify with Paystack and are idempotent |
| High | No CSRF protection anywhere | Session token + Origin check on every POST (forms and fetch) |
| High | Webhook trusted payload, never checked amount | Signature check + re-verify with Paystack + exact amount check |
| High | Stock was lost when Paystack init failed; abandoned checkouts held stock forever | Stock restored; unpaid orders auto-expire after 2h |
| High | Race conditions: overselling, double wallet payout, double withdrawal | Row locks and atomic SQL updates |
| High | KYC ID images stored as public URLs | Private "authenticated" Cloudinary assets, signed URLs for admins only |
| High | `debug=True` + `0.0.0.0` default entry point (Werkzeug debugger = remote code execution) | Debug only when `APP_ENV=development`, bound to localhost |
| High | Weak default secrets | Production refuses to boot without strong secrets |
| Medium | Open redirect on login (`//evil.com`) | Strict same-site check |
| Medium | Brute-force login | Rate limits per IP and per IP+email; constant-time check for unknown emails |
| Medium | Uploads checked by file extension only | Real decode with Pillow, re-encode (strips GPS/EXIF), magic-byte check for video, size caps |
| Medium | Logout via GET (CSRF logout) | POST only |
| Medium | Session fixation / weak cookies | `session.clear()` on login; `__Host-` Secure, HttpOnly, SameSite=Lax cookies |
| Medium | Missing security headers | CSP (nonce), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, no-store for logged-in pages |
| Medium | Unlisted/suspended-shop products viewable by ID | Visibility check |
| Medium | Reviews allowed from unpaid orders, unlimited, rating unvalidated (500 error) | Paid only, one per shop, 1-5 enforced |
| Medium | Reel likes unlimited; reel could tag another shop's product | One like per user; product ownership enforced |
| Medium | Email HTML built from user input (HTML injection) | Everything escaped |
| Low | Socket.IO `cors_allowed_origins="*"`, unvalidated payloads | Same-origin only, validated + rate-limited |
| Low | Money parsed with bare `float()` (NaN/inf/negative) | Strict Decimal parsing and ranges |
| Low | No audit trail for admin actions | Structured `mall.audit` log lines |

## 3. Functional issues I found while reading

- `cart.html` used `cart` and `KEY` variables that were never defined, nothing rendered the cart items, and
  `static/js/shop.js` is an empty file. As uploaded, the cart page could not work. I wrote `static/js/cart.js`.
- Chat history was never loaded; reloading the page showed an empty conversation. Now loaded (last 200 messages).
- The apply form's `legal_name` and `whatsapp` fields were never saved.
- Order items with status PENDING were displayed as "Delivered".
- Flash messages only appeared on some pages; now shown globally.
- `create_shop.html` posts to `/vendor/shop/create`, which doesn't exist, and `register.html` isn't routed. Both look
  like dead files.
- The activation page says "one-time fee, never pay again", but shops expire after 30 days and are asked to pay again.
  Pick one: change the copy or the model.

## 4. Upgrades I recommend next (not done yet; each needs your decision)

**Security**
1. **Email verification + password reset** (and block login until verified). Needed for any real marketplace.
2. **2FA (TOTP) for admin accounts**, plus an IP allow-list for `/admin` if you have a fixed office IP.
3. **Build Tailwind locally** instead of the CDN. This removes the biggest third-party script from every page,
   lets you delete `'unsafe-inline'`/CDN hosts from the CSP, and is what Tailwind itself recommends for production.
   Self-host Socket.IO's client too (or add SRI hashes).
4. **Rate limiting backed by Redis** (the built-in limiter is per-process memory; it resets on restart and isn't
   shared between workers).
5. **Session invalidation on password change** (add a `session_version` column).
6. **Store money as integer kobo**, not `Float`. Floats are wrong for money; this needs a small DB migration.
7. **Use Flask-Migrate/Alembic**: `db.create_all()` never alters existing tables, so schema changes will bite later.
8. Move email to a **background queue**; today a slow SMTP call can stall a request (including the webhook).
9. Centralised error tracking (Sentry) and uptime alerts; ship `mall.audit` logs somewhere you can't edit from the app.
10. Dependabot or `pip-audit` in CI; keep `runtime.txt` on the latest 3.12.x patch.

**Product / marketplace**
1. Vendors can't edit or delete products, or edit their shop after approval; add that.
2. **Auto-release escrow** after N days if the buyer never clicks "Received" (otherwise vendors can be stuck unpaid).
3. Dispute/refund flow. Today an order flagged `REFUND_REQUIRED` (paid after the stock was released) only appears in
   logs; it needs an admin screen.
4. Real payouts via the Paystack Transfers API instead of manual "mark as paid", and verify the bank account name
   matches the KYC name (Paystack account resolution).
5. Pagination on shop/search/admin lists; indexes on `Order.reference`, `Product.shop_id`, `OrderItem.shop_id`.
6. Switch from `NullPool` to a real connection pool (NullPool opens a new DB connection per request).
7. Search: Postgres full-text instead of `ILIKE '%…%'`.
8. Accessibility pass (labels, focus states, contrast) and SEO basics (meta descriptions, sitemap).
9. Automated tests for money flows (checkout -> webhook -> ship -> confirm -> withdraw). These are the paths where a
   bug costs real money.
