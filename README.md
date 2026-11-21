# RICKY Resources — starter website

A Flask starter for a creator-only resource shop with Discord login, boost-proof submissions, manual owner approval, resource downloads, and one-use/multi-use access codes.

## Included
- Discord OAuth login
- Owner check using Discord ID configured in `.env`
- Resource catalog and detail pages
- Owner resource upload (ZIP/RAR/7Z)
- Screenshot proof submissions
- Owner approve/decline
- Account-persistent unlocks
- Redeem codes with use limits and expiration
- Profile display-name customization
- My Resources downloads

## Run locally
1. Install Python 3.10+.
2. Extract this ZIP.
3. Copy `.env.example` to `.env` and edit values.
4. Run:
   ```bash
   pip install -r requirements.txt
   python app.py
   ```
5. Open `http://127.0.0.1:5000`.

## Discord OAuth setup
In the Discord Developer Portal, create an application and add the OAuth2 redirect URL matching `DISCORD_REDIRECT_URI`. Copy Client ID and Client Secret into `.env`. Scope is `identify`. The configured owner is your Discord user ID:

`1565278113527496769`

## Important deployment/security notes
- This is a starter MVP, not production-hardened.
- The Flask session key is set inside `app.py` in this version. Keep the file private and rotate the key if compromised.
- Deploy with HTTPS and a production WSGI server, not Flask's development server.
- Keep `uploads/` and `ricky.db` on persistent storage and back them up.
- OAuth currently supports Discord only. Google and TikTok sign-in are not wired up; their OAuth setups require separate provider configuration.
- Proof approval is manual. Screenshot proof does not automatically verify Discord boosts.
- Add email/Discord notifications, CSRF protection, rate limiting, and admin audit logs before public launch.
- Configure file-size limits and scan uploads before accepting public uploads (only owner can upload in this app).
