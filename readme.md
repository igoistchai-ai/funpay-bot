# NEZZX AI Telegram Conv

Single-file FastAPI app with a Telegram Inbox-style dashboard. `bot.py` contains the web app, Telegram Stars key bot, key/licence storage, Telegram MTProto account connection, and ChatGPT integration.

## Included

- Dark three-column Inbox inspired by the supplied reference image.
- Existing key login, one-time FREE PLAN, Telegram Stars subscription purchase, expiry messages, and admin-issued/revoked keys.
- Telegram user-account login using phone number, login code, and optional 2FA password.
- Chat list, unread counts, search, message history and manual message sending.
- OpenAI-generated reply drafts for review before sending.
- Four AI conversation styles: Friendly, MM2 Trade, Find Players, and Safe Trade.
- Optional per-private-chat incoming auto-replies. The switch is off by default. The AI does not start cold chats; the user must enable it for each chat.
- Stored Telegram session string is encrypted using `cryptography`; phone codes and 2FA passwords are not stored.
- MTProto client profile is prefilled as `NEZZX AI Telegram Conv` (device/app metadata, not a browser HTTP User-Agent).

## Render setup

**Build command**

```bash
pip install -r requirements.txt
```

**Start command**

```bash
python bot.py
```

Add these environment variables in Render. Do not commit actual values to GitHub.

| Variable | Required for | Value |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | `/start`, key delivery, Telegram Stars | Token from BotFather |
| `TELEGRAM_BOT_USERNAME` | Link to the key/payment bot in the dashboard | Bot username without `@` |
| `TELEGRAM_API_ID` | Connect a personal Telegram account | API ID from `my.telegram.org` |
| `TELEGRAM_API_HASH` | Connect a personal Telegram account | API hash from `my.telegram.org` |
| `OPENAI_API_KEY` | AI drafts and auto-replies | OpenAI API key |
| `OPENAI_MODEL` | Optional model override | Defaults to `gpt-4.1-mini` |
| `SESSION_SECRET` | Encrypt stored Telegram sessions | Long random secret; keep stable between deploys |
| `DASHBOARD_PASSWORD` | Browser admin login | Long random admin password |
| `ADMIN_TELEGRAM_ID` | Admin payment/licence identity | Defaults to `8357023784` |
| `DATA_DIR` | Persistent database/session storage | Set to `/var/data` if a Render persistent disk is mounted there |

`PORT` and `RENDER_EXTERNAL_URL` are supplied by Render. A persistent disk mounted at `/var/data` plus `DATA_DIR=/var/data` is recommended: without persistent storage, SQLite licences and encrypted Telegram sessions may be lost after a redeploy/restart. Keep `SESSION_SECRET` unchanged or previously stored sessions cannot be decrypted.

## First launch

1. Create/configure the Telegram bot and set its token.
2. Obtain Telegram API ID and API hash from `my.telegram.org`; set both in Render.
3. Set `OPENAI_API_KEY` and `SESSION_SECRET`.
4. Deploy, then open the Render URL. Sign in with a purchased key or the configured admin password.
5. Go to **Settings → Telegram account**. Submit a phone number, then the code Telegram sends. If Telegram requests a 2FA password, enter it in the next field.
6. Go to **Messages**, choose a private chat and use **Suggest reply** for a draft. To allow replies to future incoming messages in that individual chat, switch **AI replies** on and select a mode.

The Telegram phone/code/2FA flow requires valid Telegram API credentials. ChatGPT usage requires a separate OpenAI API key; a ChatGPT web subscription is not itself an API key.

## Safety and operational notes

- Auto-reply is opt-in per chat and handles only incoming private messages. It is disabled by default and does not send opening messages to strangers.
- The AI prompt disallows fabricated item values, fake guarantors, requests for passwords or login codes, and pressure after refusal. Review AI drafts before sending when you need full control.
- Telegram may limit accounts that send too frequently. Use auto-reply only in conversations where it is appropriate and welcomed.
- User-account session access is powerful. Protect the dashboard password, Render account, persistent disk, bot token, OpenAI key and `SESSION_SECRET`.
- This bundle was syntax-checked and smoke-tested locally. Real Telegram sign-in, payment processing and OpenAI calls require your own valid secrets and cannot be verified without them.


### Telegram API credentials

The `.env.example` file includes **fictional demo values** for `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` so the variable names are already filled in. They will not authenticate with Telegram. Replace both with real credentials from https://my.telegram.org before connecting an account.
