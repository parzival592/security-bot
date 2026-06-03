import os
import re
import requests
import tldextract
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)

# -----------------------------
# LOAD ENV VARIABLES
# -----------------------------
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

# -----------------------------
# BASIC URL CHECKS
# -----------------------------

def check_https(url):
    return url.startswith("https://")

def check_length(url):
    return len(url) > 75

def check_ip(url):
    return re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url)

def check_keywords(url):
    keywords = ["login", "verify", "bank", "secure", "update", "free", "account"]
    return any(k in url.lower() for k in keywords)

def get_domain(url):
    ext = tldextract.extract(url)
    return ext.domain + "." + ext.suffix

def check_random(domain):
    return bool(re.search(r"[a-z0-9]{12,}", domain))


# -----------------------------
# VIRUSTOTAL CHECK
# -----------------------------

def virustotal_scan(url):
    if not VT_API_KEY:
        return 0

    try:
        api = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {"apikey": VT_API_KEY, "resource": url}
        response = requests.get(api, params=params)
        data = response.json()
        return data.get("positives", 0)
    except:
        return 0


# -----------------------------
# ANALYZER ENGINE
# -----------------------------

def analyze_url(url):
    score = 0
    reasons = []

    if not check_https(url):
        score += 20
        reasons.append("No HTTPS")

    if check_length(url):
        score += 15
        reasons.append("URL too long")

    if check_ip(url):
        score += 25
        reasons.append("Uses IP address")

    if check_keywords(url):
        score += 20
        reasons.append("Phishing keywords detected")

    domain = get_domain(url)
    if check_random(domain):
        score += 20
        reasons.append("Suspicious domain pattern")

    vt = virustotal_scan(url)
    if vt > 0:
        score += vt * 5
        reasons.append(f"VirusTotal flagged by {vt} engines")

    if score <= 20:
        status = "🟢 SAFE"
    elif score <= 50:
        status = "🟡 SUSPICIOUS"
    else:
        status = "🔴 DANGEROUS"

    return status, score, reasons


# -----------------------------
# TELEGRAM HANDLERS
# -----------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🕵️ Cybersecurity Bot\nSend me a URL to analyze."
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text

    if not url.startswith("http"):
        await update.message.reply_text("Send a valid URL starting with http/https")
        return

    status, score, reasons = analyze_url(url)

    msg = f"{status}\nRisk Score: {score}/100\n\nReasons:\n- " + "\n- ".join(reasons)

    await update.message.reply_text(msg)


# -----------------------------
# MAIN BOT
# -----------------------------

def main():
    if not BOT_TOKEN:
        print("ERROR: BOT_TOKEN not found in .env")
        return

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
