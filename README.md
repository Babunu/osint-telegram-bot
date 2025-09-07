# 🔎 OSINT Telegram Bot

A simple Telegram bot for OSINT (Open-Source Intelligence) built with Python.  
It can fetch WHOIS, IP details, email breach info, Shodan search, phone lookup, URL headers, and EXIF metadata from images.

---

## 🚀 Features
- `/ip <ip>` → IP geolocation
- `/whois <domain>` → Domain WHOIS
- `/email <email>` → Breach check (HaveIBeenPwned API)
- `/shodan <query>` → Shodan search
- `/phone <number>` → Phone number info
- `/url <url>` → URL headers
- 📷 Send an image → Extract EXIF metadata

---

## ⚙️ Setup (Termux / Linux / VPS)

1. Clone repo:
```bash
git clone https://github.com/yourusername/osint-telegram-bot.git
cd osint-telegram-bot