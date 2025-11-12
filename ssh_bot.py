#!/usr/bin/env python3
import os, re, html, subprocess
import telebot

# ===== Configuration =====
TOKEN = "Your Bot token"
FIXED_PASSWORD = "Your ssh password"
LIMITS_FILE = "/etc/security/limits.d/ssh_maxlogins.conf"
SSH_PORT = 22  # SSH server port used for incoming connections
SSH_HOST = "your ssh Host"

# Admin Telegram numeric IDs (integers)
ADMIN_IDS = {123456789}

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# Per-chat state machine for creating users
# states[chat_id] = {"step": "await_username" | "await_limit", "username": str}
states = {}

# Track bot messages per chat for later cleanup
BOT_MSGS = {}   # {chat_id: [message_id, ...]}
MAX_TRACKED = 10

USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{1,31}$')

# ===== Helpers =====
def _is_admin(message):
    return (message.from_user is not None) and (message.from_user.id in ADMIN_IDS)

def _track_msg(chat_id, msg_id):
    lst = BOT_MSGS.setdefault(chat_id, [])
    lst.append(msg_id)
    if len(lst) > MAX_TRACKED:
        del lst[:-MAX_TRACKED]

def _cleanup_old_messages(chat_id):
    lst = BOT_MSGS.get(chat_id, [])
    for mid in lst:
        try:
            bot.delete_message(chat_id, mid)
        except Exception:
            pass
    BOT_MSGS[chat_id] = []

def run(cmd, input_text=None):
    res = subprocess.run(
        cmd,
        input=(input_text.encode() if input_text else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False
    )
    return res.returncode, res.stdout.decode(errors="ignore"), res.stderr.decode(errors="ignore")

def user_exists(username):
    rc, _, _ = run(["id", "-u", username])
    return rc == 0

def create_user(username):
    if user_exists(username):
        return True, "exists"
    rc, out, err = run(["/usr/sbin/useradd", "-m", "-s", "/bin/bash", username])
    if rc != 0:
        return False, (err.strip() or out.strip() or "useradd failed")
    return True, "created"

def set_password(username, password):
    rc, out, err = run(["/usr/sbin/chpasswd"], input_text=f"{username}:{password}")
    if rc != 0:
        return False, (err.strip() or out.strip() or "chpasswd failed")
    return True, "ok"

def ensure_limits_file():
    if not os.path.exists(LIMITS_FILE):
        open(LIMITS_FILE, "a").close()

def set_maxlogins(username, n):
    ensure_limits_file()
    with open(LIMITS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    lines = [ln for ln in lines if not ln.strip().startswith(f"{username} ")]
    lines.append(f"{username} hard maxlogins {n}\n")
    with open(LIMITS_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

def delete_user(username):
    rc, out, err = run(["/usr/sbin/userdel", "-r", username])
    if rc != 0:
        return False, (err.strip() or out.strip() or "userdel failed")
    return True, "deleted"

# ===== Handlers =====
@bot.message_handler(commands=['whoami'])
def handle_whoami(message):
    uid = message.from_user.id if message.from_user else None
    sent = bot.reply_to(message, f"Your Telegram numeric ID:\n<code>{uid}</code>", parse_mode="HTML")
    _track_msg(message.chat.id, sent.message_id)

@bot.message_handler(commands=['start', 'help'])
def handle_start(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return
    sent = bot.reply_to(
        message,
        ("سلام! 👋\n"
         "دستورات:\n"
         "• /newuser — ساخت یوزر SSH (می‌پرسد اسم و محدودیت همزمانی ۱..۵)\n"
         "• /online — نمایش فقط نام یوزرهای SSH آنلاین + تعداد نشست‌ها (مثال: <code>pooya - 2</code>)\n"
         "• /deluser &lt;username&gt; — حذف کاربر و Home\n"
         "• /cancel — لغو فرایند جاری\n"
         "• /whoami — نمایش آی‌دی عددی تلگرام شما\n\n"
         f"پسورد پیش‌فرض: <code>{FIXED_PASSWORD}</code>")
    )
    _track_msg(message.chat.id, sent.message_id)

@bot.message_handler(commands=['cancel'])
def handle_cancel(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return
    states.pop(message.chat.id, None)
    sent = bot.reply_to(message, "لغو شد. ✅")
    _track_msg(message.chat.id, sent.message_id)

@bot.message_handler(commands=['newuser'])
def handle_newuser(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return
    states[message.chat.id] = {"step": "await_username"}
    sent = bot.reply_to(message, "نام کاربر جدید را بفرست (مثال: <code>test2</code>).")
    _track_msg(message.chat.id, sent.message_id)

@bot.message_handler(commands=['deluser'])
def handle_deluser(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return
    chat_id = message.chat.id
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) != 2:
        sent = bot.reply_to(message, "نحوه استفاده:\n<code>/deluser USERNAME</code>")
        _track_msg(chat_id, sent.message_id)
        return

    username = parts[1].strip()
    if not USERNAME_RE.match(username) or username in {"root"}:
        sent = bot.reply_to(message, "❌ یوزرنیم نامعتبر/غیرمجاز است.")
        _track_msg(chat_id, sent.message_id)
        return
    if not user_exists(username):
        sent = bot.reply_to(message, f"ℹ️ کاربر <b>{html.escape(username)}</b> وجود ندارد.")
        _track_msg(chat_id, sent.message_id)
        return

    ok, info = delete_user(username)
    if not ok:
        sent = bot.reply_to(message, f"❌ خطا در حذف کاربر:\n<code>{html.escape(info)}</code>")
        _track_msg(chat_id, sent.message_id)
        return

    sent = bot.reply_to(message, f"🗑️ کاربر <b>{html.escape(username)}</b> حذف شد.")
    _track_msg(chat_id, sent.message_id)

@bot.message_handler(commands=['online'])
def handle_online(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return

    chat_id = message.chat.id
    try:
        bot.delete_message(chat_id, message.message_id)
    except Exception:
        pass
    _cleanup_old_messages(chat_id)

    # Only established inbound connections to SSH_PORT
    cmd = f"ss -tnp 'sport = :{SSH_PORT}' | grep ESTAB | grep sshd || true"
    try:
        raw = subprocess.check_output(
            ["bash", "-lc", cmd],
            stderr=subprocess.STDOUT, timeout=6
        ).decode(errors="ignore")
    except Exception as e:
        sent = bot.send_message(chat_id, f"❌ خطا:\n<code>{html.escape(str(e))}</code>", parse_mode="HTML")
        _track_msg(chat_id, sent.message_id)
        return

    # Collect unique PIDs and map them to usernames via `ps`
    pids = set()
    for ln in raw.splitlines():
        m_pid = re.search(r"pid=(\d+)", ln)
        if m_pid:
            pids.add(m_pid.group(1))

    if not pids:
        sent = bot.send_message(chat_id, "هیچ کاربر SSH الآن آنلاین نیست (یا ربات با root اجرا نمی‌شود).")
        _track_msg(chat_id, sent.message_id)
        return

    user_pids = {}  # {user: set(pids)}
    for pid in pids:
        try:
            cmdline = subprocess.check_output(
                ["ps", "-p", pid, "-o", "cmd="],
                stderr=subprocess.STDOUT, timeout=2
            ).decode(errors="ignore").strip()
        except Exception:
            continue
        m_user = re.search(r"sshd:\s*([^\s@]+)", cmdline)
        if not m_user:
            continue
        u = m_user.group(1)
        user_pids.setdefault(u, set()).add(pid)

    if not user_pids:
        sent = bot.send_message(chat_id, "اتصال هست، اما نام کاربر از PIDها به‌دست نیامد (احتمالاً دسترسی ناکافی).")
        _track_msg(chat_id, sent.message_id)
        return

    rows = [f"{u} - {len(pids)}" for u, pids in sorted(user_pids.items(),
                                                       key=lambda x: (-len(x[1]), x[0]))]
    text = "<code>" + html.escape("\n".join(rows)) + "</code>"
    sent = bot.send_message(chat_id, text, parse_mode="HTML")
    _track_msg(chat_id, sent.message_id)

@bot.message_handler(commands=['ip'])
def handle_ip(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return

    parts = message.text.strip().split(maxsplit=1)
    if len(parts) != 2:
        bot.reply_to(message, "نحوه استفاده:\n<code>/ip USERNAME</code>", parse_mode="HTML")
        return

    target = parts[1].strip()
    if not USERNAME_RE.match(target):
        bot.reply_to(message, "❌ یوزرنیم نامعتبر است.")
        return

    # Established inbound SSH connections: map pid -> client IP
    cmd = f"ss -tnp 'sport = :{SSH_PORT}' | grep ESTAB | grep sshd || true"
    try:
        raw = subprocess.check_output(["bash", "-lc", cmd],
                                      stderr=subprocess.STDOUT, timeout=6).decode(errors="ignore")
    except Exception as e:
        bot.reply_to(message, f"❌ خطا:\n<code>{html.escape(str(e))}</code>", parse_mode="HTML")
        return

    pid_to_ip = {}
    for ln in raw.splitlines():
        m_pid = re.search(r"pid=(\d+)", ln)
        if not m_pid:
            continue
        pid = m_pid.group(1)

        # remote column is field #5 in `ss` output
        try:
            remote = ln.split()[4]
        except Exception:
            continue

        # Extract IP without port (IPv4/IPv6)
        m_ip = re.match(r'^\[?([^\]]+)\]?:\d+$', remote)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        pid_to_ip[pid] = ip

    if not pid_to_ip:
        bot.reply_to(message, "الان اتصال ورودی فعالی به پورت SSH نداریم یا ربات با روت اجرا نمی‌شود.")
        return

    # Resolve pid -> username via `ps` and filter by requested username
    user_ips = set()
    for pid, ip in pid_to_ip.items():
        try:
            cmdline = subprocess.check_output(["ps", "-p", pid, "-o", "cmd="],
                                              stderr=subprocess.STDOUT, timeout=2)\
                                .decode(errors="ignore").strip()
        except Exception:
            continue
        m_user = re.search(r"sshd:\s*([^\s@]+)", cmdline)
        if not m_user:
            continue
        u = m_user.group(1)
        if u == target:
            user_ips.add(ip)

    if not user_ips:
        bot.reply_to(message, f"برای کاربر <b>{html.escape(target)}</b> اتصال فعالی پیدا نشد.", parse_mode="HTML")
        return

    lines = "\n".join(sorted(user_ips))
    bot.reply_to(message, f"🌐 IPهای متصل برای <b>{html.escape(target)}</b>:\n<code>{html.escape(lines)}</code>",
                 parse_mode="HTML")

@bot.message_handler(func=lambda m: True)
def handle_conversation(message):
    if not _is_admin(message):
        bot.reply_to(message, "⛔️ دسترسی نداری.")
        return

    chat_id = message.chat.id
    st = states.get(chat_id)

    if not st:
        sent = bot.reply_to(message, "برای شروع ساخت یوزر دستور /newuser را بفرست.")
        _track_msg(chat_id, sent.message_id)
        return

    # Step 1: ask for username
    if st["step"] == "await_username":
        username = message.text.strip()
        if not USERNAME_RE.match(username):
            sent = bot.reply_to(message, "❌ یوزرنیم نامعتبر. باید با حرف کوچک شروع شود و فقط a-z, 0-9, _, - مجازند. دوباره بفرست.")
            _track_msg(chat_id, sent.message_id)
            return
        st["username"] = username
        st["step"] = "await_limit"
        sent = bot.reply_to(message, "حداکثر تعداد نشست همزمان را بفرست (یک عدد بین 1 تا 5).")
        _track_msg(chat_id, sent.message_id)
        return

    # Step 2: ask for max concurrent sessions (1..5)
    if st["step"] == "await_limit":
        try:
            limit = int(message.text.strip())
        except ValueError:
            sent = bot.reply_to(message, "❌ عدد بین 1 تا 5 بفرست.")
            _track_msg(chat_id, sent.message_id)
            return
        if not (1 <= limit <= 5):
            sent = bot.reply_to(message, "❌ عدد بین 1 تا 5 بفرست.")
            _track_msg(chat_id, sent.message_id)
            return

        username = st["username"]

        ok, info = create_user(username)
        if not ok:
            sent = bot.reply_to(message, f"❌ خطا در ایجاد کاربر:\n<code>{html.escape(info)}</code>")
            _track_msg(chat_id, sent.message_id)
            states.pop(chat_id, None)
            return

        ok2, info2 = set_password(username, FIXED_PASSWORD)
        if not ok2:
            sent = bot.reply_to(message, f"❌ کاربر ایجاد شد ولی تنظیم پسورد شکست خورد:\n<code>{html.escape(info2)}</code>")
            _track_msg(chat_id, sent.message_id)
            states.pop(chat_id, None)
            return

        try:
            set_maxlogins(username, limit)
        except Exception as e:
            sent = bot.reply_to(message, f"❌ پسورد تنظیم شد ولی تعیین محدودیت نشست شکست خورد:\n<code>{html.escape(str(e))}</code>")
            _track_msg(chat_id, sent.message_id)
            states.pop(chat_id, None)
            return

        detail = (
            f"SSH Host : {SSH_HOST}\n"
            f"SSH Port : {SSH_PORT}\n"
            f"Username : {username}\n"
            f"Password : {FIXED_PASSWORD}"
        )
        sent1 = bot.send_message(chat_id, f"✅ کاربر <b>{html.escape(username)}</b> {'ساخته شد' if info!='exists' else 'قبلاً وجود داشت (به‌روزرسانی شد)'}.\n"
                                          f"👤 حداکثر نشست همزمان: <b>{limit}</b>")
        _track_msg(chat_id, sent1.message_id)

        sent2 = bot.send_message(chat_id, f"<code>{html.escape(detail)}</code>", parse_mode="HTML")
        _track_msg(chat_id, sent2.message_id)

        states.pop(chat_id, None)
        return

# ===== Main loop =====
if __name__ == "__main__":
    bot.infinity_polling(skip_pending=True, timeout=20)
