import os
import yt_dlp
import asyncio
import time
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes
)

TOKEN = "YOUR_BOT_TOKEN"
DOWNLOAD_PATH = "downloads"

os.makedirs(DOWNLOAD_PATH, exist_ok=True)

user_last_request = {}
queue = asyncio.Semaphore(1)  # 1 download at a time (mobile safe)


# START
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name
    await update.message.reply_text(
        f"Hello welcome Back 😊 {name}\n\n"
        "/help\n/download <video link>"
    )


# HELP
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send:\n/download <video link>\n\n"
        "Choose quality.\n"
        "If file >50MB it will not upload (Telegram limit)."
    )


# DOWNLOAD COMMAND
async def download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # Anti spam (5 sec cooldown)
    if user_id in user_last_request:
        if time.time() - user_last_request[user_id] < 5:
            await update.message.reply_text("Wait 5 seconds.")
            return

    user_last_request[user_id] = time.time()

    if not context.args:
        await update.message.reply_text("Send link after /download")
        return

    url = context.args[0]
    context.user_data["url"] = url

    try:
        with yt_dlp.YoutubeDL({"quiet": True}) as ydl:
            info = ydl.extract_info(url, download=False)
            title = info.get("title")
            thumbnail = info.get("thumbnail")
    except:
        await update.message.reply_text("Invalid Link")
        return

    keyboard = [
        [InlineKeyboardButton("360p", callback_data="360")],
        [InlineKeyboardButton("720p", callback_data="720")],
        [InlineKeyboardButton("Audio Only", callback_data="audio")]
    ]

    await update.message.reply_photo(
        photo=thumbnail,
        caption=f"{title}\n\nSelect Quality:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


# PROGRESS HOOK
async def progress_hook(d, message):
    if d["status"] == "downloading":
        percent = d.get("_percent_str", "0%")
        try:
            await message.edit_text(f"Downloading... {percent}")
        except:
            pass


# QUALITY HANDLER
async def quality_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with queue:

        query = update.callback_query
        await query.answer()

        url = context.user_data.get("url")
        quality = query.data

        msg = await query.message.reply_text("Starting Download...")

        filename = f"{query.from_user.id}_{int(time.time())}.mp4"
        filepath = os.path.join(DOWNLOAD_PATH, filename)

        ydl_opts = {
            "outtmpl": filepath,
            "progress_hooks": [
                lambda d: asyncio.create_task(progress_hook(d, msg))
            ],
            "quiet": True,
            "noplaylist": True
        }

        if quality == "audio":
            ydl_opts["format"] = "bestaudio"
        else:
            ydl_opts["format"] = f"best[height<={quality}]"

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.download([url])

            if not os.path.exists(filepath):
                await msg.edit_text("Download failed.")
                return

            size = os.path.getsize(filepath) / (1024 * 1024)

            if size > 50:
                await msg.edit_text(
                    "Apka video 50Mb Se Jada ka hai.\n"
                    "Telegram bot upload limit exceed."
                )
                os.remove(filepath)
                return

            await msg.edit_text("Uploading...")
            await query.message.reply_document(
                InputFile(filepath),
                read_timeout=300,
                write_timeout=300,
                connect_timeout=300
            )

            os.remove(filepath)

        except Exception as e:
            await msg.edit_text(f"Error: {str(e)}")


app = ApplicationBuilder().token(TOKEN).build()

app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("download", download))
app.add_handler(CallbackQueryHandler(quality_handler))

print("Bot Running...")
app.run_polling()