# Fictional Demo Ledger Generator

An online-ready demo application with admin-managed logins, password hashing, rate-limited login, a SQLite audit history, and PDF output. It intentionally generates only synthetic sample transactions. Every PDF is visibly marked **FICTIONAL DEMO — NOT A REAL BANK STATEMENT** and uses generic styling, not a real bank's identity or template.

## Deploy (recommended easy path: Render)

1. Create a private GitHub repository and upload these project files.
2. In Render, choose **New + → Blueprint** and connect that repository. Render reads `render.yaml`.
3. In Render's service Environment settings, set `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Use a unique admin username and a long random password (16+ characters); do not share it.
4. Deploy. Open the provided `https://...onrender.com` address.
5. Sign in as the admin. Create each user's username and a unique password of at least 12 characters, and share credentials privately.

The supplied Render blueprint uses a paid Starter service with a persistent disk so the SQLite database and generation history survive redeploys. Check current Render pricing before deployment. Do not deploy with the fallback development session secret; Render generates one from `render.yaml`.

## Run locally

Requires Node.js 20+. In this folder:

```sh
npm install
```

Set environment variables `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `SESSION_SECRET` (a long random value), then run:

```sh
npm start
```

Open `http://localhost:3000`.

## Security notes

- Admin account is created from environment variables on first startup only if that username does not already exist.
- Passwords are hashed using bcrypt. Sessions are HTTP-only, same-site cookies; HTTPS is expected in production.
- User creation and deactivation are admin-only. A user can see only their own generation history; admins can see all history.
- For a production deployment, use a managed database, backups, an explicit privacy/retention policy, CSRF protection for state-changing routes, and regular dependency updates. Do not enter real account numbers, customer identifiers, or confidential banking data.
