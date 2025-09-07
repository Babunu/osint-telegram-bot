# bot.py
import os, logging, requests, whois, exifread, phonenumbers
from phonenumbers import carrier, geocoder
from shodan import Shodan
from telegram import Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, filters
)

# Logging setup
logging.basicConfig(level=logging.INFO)

# Env variables
BOT_TOKEN = os.environ['8211165873:AAGx5ExYn-NxWxDEzzChEIEB3CfYUT0zmQc']
HIBP_KEY = os.environ.get('HIBP_API_KEY')
SHODAN_KEY = os.environ.get('1Xt9oPyo0NGkyZ8qGilNxuZJG5cZ5C3p')

# ---------------- Handlers ----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔎 OSINT Bot ready. Type /help for commands.")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (
        "🛠 Available Commands:\n"
        "/ip <ip> - IP lookup\n"
        "/whois <domain> - Domain WHOIS\n"
        "/email <email> - Breach check (HIBP)\n"
        "/shodan <query> - Shodan search\n"
        "/phone <number> - Phone info\n"
        "/url <url> - URL header info\n"
        "📷 Send an image - Extract EXIF metadata"
    )
    await update.message.reply_text(txt)

# 🔹 IP Lookup
async def ip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ip 8.8.8.8")
        return
    ip = context.args[0]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        j = r.json()
        if j.get('status') == 'success':
            out = (f"🌍 IP: {ip}\nCountry: {j.get('country')}\nRegion: {j.get('regionName')}\n"
                   f"City: {j.get('city')}\nISP: {j.get('isp')}\nASN: {j.get('as')}")
        else:
            out = f"Lookup failed: {j.get('message','unknown')}"
    except Exception as e:
        out = f"Error: {e}"
    await update.message.reply_text(out)

# 🔹 WHOIS
async def whois_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /whois example.com")
        return
    domain = context.args[0]
    try:
        w = whois.whois(domain)
        out = (f"🔑 Domain: {domain}\nRegistrar: {w.registrar}\n"
               f"Created: {w.creation_date}\nExpires: {w.expiration_date}")
    except Exception as e:
        out = f"WHOIS error: {e}"
    await update.message.reply_text(str(out))

# 🔹 HIBP Email Check
async def email_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /email user@example.com")
        return
    if not HIBP_KEY:
        await update.message.reply_text("HIBP API key not configured.")
        return
    email = context.args[0]
    headers = {'hibp-api-key': HIBP_KEY, 'user-agent': 'OSINTBot/1.0'}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}?truncateResponse=false"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            names = [b.get('Name') for b in breaches]
            msg = f"⚠️ Breaches found: {len(names)}\n" + ", ".join(names[:10])
        elif r.status_code == 404:
            msg = "✅ No breaches found for this account."
        else:
            msg = f"HIBP error: {r.status_code}"
    except Exception as e:
        msg = f"Error: {e}"
    await update.message.reply_text(msg)

# 🔹 Shodan Search
async def shodan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SHODAN_KEY:
        await update.message.reply_text("Shodan API key not configured.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /shodan apache country:IN")
        return
    query = " ".join(context.args)
    try:
        api = Shodan(SHODAN_KEY)
        res = api.search(query)
        total = res.get('total',0)
        matches = res.get('matches',[])[:5]
        text = f"📡 Shodan results: {total}\n"
        for m in matches:
            text += f"{m.get('ip_str')} - {m.get('port')} - {m.get('org')}\n"
    except Exception as e:
        text = f"Shodan error: {e}"
    await update.message.reply_text(text)

# 🔹 Phone Lookup
async def phone_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /phone +911234567890")
        return
    num = context.args[0]
    try:
        parsed = phonenumbers.parse(num, None)
        valid = phonenumbers.is_valid_number(parsed)
        country = geocoder.description_for_number(parsed, "en")
        sim = carrier.name_for_number(parsed, "en")
        msg = (f"📞 Number: {num}\nValid: {valid}\nCountry: {country}\nCarrier: {sim}")
    except Exception as e:
        msg = f"Error: {e}"
    await update.message.reply_text(msg)

# 🔹 URL Headers
async def url_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /url https://example.com")
        return
    url = context.args[0]
    try:
        r = requests.head(url, timeout=10, allow_redirects=True)
        headers = "\n".join([f"{k}: {v}" for k,v in r.headers.items()])
        msg = f"🌐 URL: {url}\nStatus: {r.status_code}\n\nHeaders:\n{headers}"
    except Exception as e:
        msg = f"Error: {e}"
    await update.message.reply_text(msg)

# 🔹 EXIF Metadata
async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = await update.message.photo[-1].get_file()
    path = "temp.jpg"
    await file.download_to_drive(path)

    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        if tags:
            info = []
            for tag in ["Image Make", "Image Model", "EXIF DateTimeOriginal", "GPS GPSLatitude", "GPS GPSLongitude"]:
                if tag in tags:
                    info.append(f"{tag}: {tags[tag]}")
            msg = "\n".join(info) if info else "No major EXIF data found."
        else:
            msg = "No EXIF metadata found."
    except Exception as e:
        msg = f"Error: {e}"

    await update.message.reply_text(msg)

# ---------------- Main ----------------
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("ip", ip_cmd))
    app.add_handler(CommandHandler("whois", whois_cmd))
    app.add_handler(CommandHandler("email", email_cmd))
    app.add_handler(CommandHandler("shodan", shodan_cmd))
    app.add_handler(CommandHandler("phone", phone_cmd))
    app.add_handler(CommandHandler("url", url_cmd))
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))

    print("✅ OSINT Bot started (polling). Ctrl+C to stop.")
    app.run_polling()

if __name__ == "__main__":
    main()