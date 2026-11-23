# WedPlan — Backend

Express 5, MongoDB, Better Auth, JWT, Image Hosting, Stripe.
See `../README-START-HERE.md` for full setup and verification.

Quick start:
```powershell
copy .env.example .env
npm.cmd install
npm.cmd run check
npm.cmd run seed
npm.cmd start
```

The seed command is optional and requires admin and demo vendors credentials
provided privately in `.env`.

Production note: set BETTER_AUTH_URL and CLIENT_URL to the SAME Vercel URL
used to proxy `/api/auth` through `next.config.mjs`.
Never commit `.env` or Stripe / Google / MongoDB secrets.
