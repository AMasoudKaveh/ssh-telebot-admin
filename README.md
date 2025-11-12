# ssh-telebot-admin

Telegram bot to manage Linux SSH users.

## Features
- Create SSH users with a fixed password
- Set per-user `maxlogins` (PAM limits)
- List online SSH users by **unique sessions** (PID-based, accurate)
- Show current client IPs per username
- Admin-only access control

## Tech
- Python 3
- [pyTelegramBotAPI](https://pypi.org/project/pyTelegramBotAPI/)
- `ss`, `ps`, PAM limits (`/etc/security/limits.d/`)

## Config
Edit the script and set:
- `TOKEN`
- `FIXED_PASSWORD`
- `ADMIN_IDS` (Telegram numeric IDs)
- `SSH_PORT` and `SSH_HOST`

> **Security:** Do **not** commit real tokens/passwords. Use placeholders or environment variables.

## Run (systemd)
Create `/etc/systemd/system/ssh-bot.service` and point to your script, then:
```bash
systemctl daemon-reload
systemctl enable --now ssh-bot
