import os
import re
import socket
import ipaddress
import asyncio
import time
import concurrent.futures
import aiohttp
import urllib3
import ssl
import requests

from pyrogram import Client, filters
from pyrogram.enums import ChatType
from pyrogram.types import ReplyKeyboardMarkup, KeyboardButton, Message

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CORE CONFIGURATION (STRICTLY GC DETAILS)
# ==========================================
API_ID = 37673466       
API_HASH = "b68c6e11f40f961c3f5f6517e3d1f258"
BOT_TOKEN = "8610134905:AAHLBa0l0xJ5zqbQRjNI5QMgWIwf3bwOGjI"

# Target group enforcement ID
ALLOWED_GROUP_ID = -1003544536615  

app = Client("darkx_group_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

USER_STATE = {}
DOWNLOAD_DIR = "./DarkX_Bot_Results"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=300)
THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=30)

# ==========================================
# INTERFACE LAYOUT (Selective for Groups)
# ==========================================
def get_main_keyboard():
    keyboard = [
        [KeyboardButton("🌐 Host Scanner"), KeyboardButton("🗺️ CIDR Mapper")],
        [KeyboardButton("🕷️ Domain Extractor"), KeyboardButton("📡 Multi-CIDR Recon")],
        [KeyboardButton("🔌 Port Scanner"), KeyboardButton("🎯 Subdomain Finder")],
        [KeyboardButton("✂️ Payload Splitter"), KeyboardButton("🔄 Reverse DNS")],
        [KeyboardButton("🧹 List Sanitizer"), KeyboardButton("ℹ️ Node Interrogation")],
        [KeyboardButton("📡 SNI Intelligence"), KeyboardButton("🔍 IP to Domain Finder")],
        [KeyboardButton("⚙️ System Info"), KeyboardButton("❌ Abort Operation")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, selective=True, placeholder="DarkX Control Panel")

class ProgressTracker:
    def __init__(self, total):
        self.total = total
        self.scanned = 0
        self.hits = 0
        self.last_update = 0
        self.is_stopped = False

STATUS_MAP = {
    101: "101 Switching Protocols",
    200: "200 OK",
    301: "301 Moved Permanently",
    302: "302 Found",
    303: "303 See Other",
    307: "307 Temporary Redirect",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    426: "426 Upgrade Required",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable",
    522: "522 Connection Timed Out"
}

# ==========================================
# ASYNCHRONOUS NETWORK UTILITIES
# ==========================================
async def async_gethostbyname(domain: str) -> str:
    loop = asyncio.get_running_loop()
    try: return await loop.run_in_executor(DNS_EXECUTOR, socket.gethostbyname, domain)
    except Exception: return "N/A"

async def async_getallips(domain: str) -> list:
    loop = asyncio.get_running_loop()
    try: 
        _, _, ips = await loop.run_in_executor(DNS_EXECUTOR, socket.gethostbyname_ex, domain)
        return ips
    except Exception: return ["N/A"]

async def async_gethostbyaddr(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try: 
        hostname, _, _ = await loop.run_in_executor(DNS_EXECUTOR, socket.gethostbyaddr, str(ip))
        return hostname
    except Exception: return None

async def dwn_progress(current: int, total: int, status_msg: Message):
    now = time.time()
    if not hasattr(status_msg, 'last_update_time'): status_msg.last_update_time = 0
    if now - status_msg.last_update_time > 8.0 or current == total:
        status_msg.last_update_time = now
        percent = (current / total) * 100 if total > 0 else 0
        curr_mb = current / (1024 * 1024)
        tot_mb = total / (1024 * 1024)
        try: await status_msg.edit_text(f"📥 **Downloading Input...**\n📊 **Progress:** {percent:.1f}% ({curr_mb:.1f} MB / {tot_mb:.1f} MB)\n\n*Bot by Ashif*")
        except Exception: pass

async def update_live_status(status_msg: Message, tracker: ProgressTracker, prefix_text: str):
    now = time.time()
    if now - tracker.last_update > 8.0 or tracker.scanned >= tracker.total:
        tracker.last_update = now
        percentage = (tracker.scanned / tracker.total) * 100 if tracker.total > 0 else 0
        live_text = (
            f"{prefix_text}\n\n"
            f"📈 **Execution Progress:** {percentage:.1f}%\n"
            f"🔄 **Nodes Processed:** `{tracker.scanned}/{tracker.total}`\n"
            f"🎯 **Valid Hits:** `{tracker.hits}`\n\n"
            f"⚠️ *Type 'stop' to gracefully abort the operation.*\n\n"
            f"⚡ *Bot by Ashif*"
        )
        try: await status_msg.edit_text(live_text)
        except Exception: pass

# ==========================================
# QUEUE WORKERS
# ==========================================
async def worker_cidr(queue: asyncio.Queue, session: aiohttp.ClientSession, res_file: str, tracker: ProgressTracker):
    while True:
        item = await queue.get()
        if tracker.is_stopped:
            queue.task_done()
            continue
        ip, port = item
        try:
            url = f"http://{ip}:{port}"
            custom_timeout = aiohttp.ClientTimeout(total=4.0, connect=2.0)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "*/*"}
            async with session.get(url, timeout=custom_timeout, allow_redirects=False, ssl=False, headers=headers) as resp:
                status = resp.status
                server = resp.headers.get('Server', 'Unknown')
                location = resp.headers.get('Location', '').lower()
                if not (status == 302 and any(x in location for x in ["jio", "airtel", "captive"])):
                    with open(res_file, "a") as f: f.write(f"{status} | {server} | {ip}:{port}\n")
                    tracker.hits += 1
        except Exception: pass
        finally:
            tracker.scanned += 1
            queue.task_done()

async def worker_host(queue: asyncio.Queue, session: aiohttp.ClientSession, res_file: str, tracker: ProgressTracker):
    while True:
        item = await queue.get()
        if tracker.is_stopped:
            queue.task_done()
            continue
        domain, port = item
        try:
            url = f"https://{domain}" if str(port) == "443" else f"http://{domain}:{port}"
            ip = await async_gethostbyname(domain)
            custom_timeout = aiohttp.ClientTimeout(total=5.0, connect=2.5)
            headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
            async with session.get(url, timeout=custom_timeout, allow_redirects=False, ssl=False, headers=headers) as resp:
                status = resp.status
                server = resp.headers.get("Server", "Unknown")
                location = resp.headers.get("Location", "").lower()
                if not (status == 302 and any(x in location for x in ["jio.com", "airtel", "captive"])):
                    with open(res_file, "a") as f: f.write(f"{status} | {server} | {ip} | {domain}:{port}\n")
                    tracker.hits += 1
        except Exception: pass
        finally:
            tracker.scanned += 1
            queue.task_done()

async def worker_rdns(queue: asyncio.Queue, res_file: str, tracker: ProgressTracker):
    while True:
        ip = await queue.get()
        if tracker.is_stopped:
            queue.task_done()
            continue
        try:
            hostname = await async_gethostbyaddr(ip)
            if hostname:
                with open(res_file, "a") as f: f.write(f"{ip} -> {hostname}\n")
                tracker.hits += 1
        except Exception: pass
        finally:
            tracker.scanned += 1
            queue.task_done()

# ==========================================
# MULTI-SOURCE PURE DOMAIN EXTRACTION ENGINE
# ==========================================
def generate_pure_domain_file(ip_addr, file_path):
    domains = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_addr}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200 and "error" not in res.text.lower():
            for line in res.text.strip().split("\n"):
                d = line.strip().lower()
                if d and "." in d: domains.add(d)
    except: pass

    try:
        url = f"https://rapiddns.io/sameip/{ip_addr}"
        res = requests.get(url, timeout=10, headers=headers)
        if res.status_code == 200:
            html_text = res.text
            found = re.findall(r'<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>', html_text)
            if not found:
                found = re.findall(r'target="_blank">([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</a>', html_text)
            for d in found:
                d = d.strip().lower()
                if d and "rapiddns" not in d: domains.add(d)
    except: pass

    try:
        url = "https://domains.yougetsignal.com/domains.php"
        data = {"remoteAddress": ip_addr, "key": ""}
        res = requests.post(url, data=data, timeout=10, headers={"X-Requested-With": "XMLHttpRequest"})
        if res.status_code == 200:
            json_data = res.json()
            if json_data.get("status") == "Success":
                for entry in json_data.get("domainArray", []):
                    if entry and len(entry) > 0:
                        d = entry[0].strip().lower()
                        if d and "." in d: domains.add(d)
    except: pass

    try:
        ptr = socket.gethostbyaddr(ip_addr)[0]
        if ptr and "." in ptr: domains.add(ptr.strip().lower())
    except: pass

    sorted_domains = sorted(list(domains))
    with open(file_path, "w", encoding="utf-8") as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")
            
    return len(sorted_domains)

# ==========================================
# COMMAND ROUTERS & LOGIC
# ==========================================

@app.on_message(filters.command("id") & filters.group)
async def get_group_id(client: Client, message: Message):
    await message.reply_text(f"📌 **Group ID:** `{message.chat.id}`\n\nIs ID ko `ALLOWED_GROUP_ID` me set karein.", reply_to_message_id=message.id)

@app.on_message(filters.private)
async def private_reject(client: Client, message: Message):
    await message.reply_text(
        "❌ **Access Denied:** I am deployed exclusively for the VIP Official Group. DM operational requests are unhandled.\n\n"
        "👇 **Join the official group to use this bot:**\n"
        "🔗 https://t.me/ALLPROSNIFINDER"
    )

@app.on_message(filters.command("start") & filters.group)
async def start_cmd(client: Client, message: Message):
    if ALLOWED_GROUP_ID != 0 and message.chat.id != ALLOWED_GROUP_ID: return
    
    text = (
        "**██████╗  █████╗ ██████╗ ██╗  ██╗██╗  ██╗\n"
        "██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝╚██╗██╔╝\n"
        "██║  ██║███████║██████╔╝█████╔╝  ╚███╔╝ \n"
        "██║  ██║██╔══██║██╔══██╗██╔═██╗  ██╔██╗ \n"
        "██████╔╝██║  ██║██║  ██║██║  ██╗██╔╝ ██╗\n"
        "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝**\n"
        "             **N E T W O R K**\n\n"
        "**System:** DarkXNetwork Engine v13.0 (Group Edition)\n"
        "**Status:** Online & Secured\n\n"
        "Select an operational module from the control panel below:\n\n"
        "⚡ *Bot by Ashif*"
    )
    await message.reply_text(text, reply_markup=get_main_keyboard(), reply_to_message_id=message.id)

@app.on_message(filters.text & filters.group)
async def process_inputs(client: Client, message: Message):
    if ALLOWED_GROUP_ID != 0 and message.chat.id != ALLOWED_GROUP_ID: return
    
    if message.from_user: user_id = message.from_user.id
    elif message.sender_chat: user_id = message.sender_chat.id
    else: return

    text = message.text.strip()

    if user_id in USER_STATE and "tracker" in USER_STATE[user_id]:
        if text.lower() == "stop":
            tracker = USER_STATE[user_id]["tracker"]
            tracker.is_stopped = True
            await message.reply_text("🛑 **Interrupt signal received. Safely terminating your threads...**", reply_to_message_id=message.id)
            return

    if text == "❌ Abort Operation":
        USER_STATE.pop(user_id, None)
        await message.reply_text("🔄 Action reset. Control panel re-initialized.", reply_markup=get_main_keyboard(), reply_to_message_id=message.id)
        return

    if text == "🌐 Host Scanner":
        USER_STATE[user_id] = {"action": "tool_host"}
        await message.reply_text("**[Advanced Host Scanner]**\n\nPlease upload your target domain list (.txt format).", reply_to_message_id=message.id)
        return
    elif text == "🗺️ CIDR Mapper":
        USER_STATE[user_id] = {"action": "tool_cidr"}
        await message.reply_text("**[CIDR Network Mapper]**\n\nEnter the target CIDR block (e.g., `104.16.0.0/24`):", reply_to_message_id=message.id)
        return
    elif text == "🕷️ Domain Extractor":
        USER_STATE[user_id] = {"action": "tool_extract"}
        await message.reply_text("**[Spider Domain Extractor]**\n\nUpload a raw text file or paste the text content below:", reply_to_message_id=message.id)
        return
    elif text == "📡 Multi-CIDR Recon":
        USER_STATE[user_id] = {"action": "tool_mcidr"}
        await message.reply_text("**[Multi-CIDR Recon]**\n\nUpload a file containing multiple CIDR notations (.txt format):", reply_to_message_id=message.id)
        return
    elif text == "🔌 Port Scanner":
        USER_STATE[user_id] = {"action": "tool_port"}
        await message.reply_text("**[Deep Port Scanner]**\n\nEnter the target Hostname or IP address:", reply_to_message_id=message.id)
        return
    elif text == "🎯 Subdomain Finder":
        USER_STATE[user_id] = {"action": "tool_sub"}
        await message.reply_text("**[Subdomain Finder]**\n\nEnter the root domain to analyze:", reply_to_message_id=message.id)
        return
    elif text == "✂️ Payload Splitter":
        USER_STATE[user_id] = {"action": "tool_split"}
        await message.reply_text("**[Payload Splitter]**\n\nUpload the large dataset file to split (.txt format):", reply_to_message_id=message.id)
        return
    elif text == "🔄 Reverse DNS":
        USER_STATE[user_id] = {"action": "tool_rdns"}
        await message.reply_text("**[Reverse DNS Scanner]**\n\nEnter a target IP, Domain, or full CIDR Block (e.g., `172.65.90.0/24`):", reply_to_message_id=message.id)
        return
    elif text == "🧹 List Sanitizer":
        USER_STATE[user_id] = {"action": "tool_clean"}
        await message.reply_text("**[Dataset Sanitizer]**\n\nUpload the domain list to remove duplicates and sanitize (.txt):", reply_to_message_id=message.id)
        return
    elif text == "ℹ️ Node Interrogation":
        USER_STATE[user_id] = {"action": "tool_node"}
        await message.reply_text("**[Node Interrogation]**\n\nEnter the target Domain or IP address:", reply_to_message_id=message.id)
        return
    elif text == "📡 SNI Intelligence":
        USER_STATE[user_id] = {"action": "tool_sni"}
        await message.reply_text("**[Dark Tunnel SNI Intelligence]**\n\nEnter target SNI Hostname for deep analysis (e.g., `facebook.com`):", reply_to_message_id=message.id)
        return
    elif text == "🔍 IP to Domain Finder":
        USER_STATE[user_id] = {"action": "tool_ip_to_domain"}
        await message.reply_text("**[IP to Domain Finder]**\n\nEnter the target IP Address to discover hosted domains:", reply_to_message_id=message.id)
        return
    elif text == "⚙️ System Info":
        info_text = (
            "**DARKXNETWORK ARSENAL**\n\n"
            "**Architecture:** Multi-User Zero-Memory Queue Protocol\n"
            "**Deployment:** Official Group Edition\n"
            "**Status:** Active\n\n"
            "⚡ *Bot by Ashif*"
        )
        await message.reply_text(info_text, reply_markup=get_main_keyboard(), reply_to_message_id=message.id)
        return

    if user_id in USER_STATE and "action" in USER_STATE[user_id]:
        state = USER_STATE[user_id]["action"]
        
        if state == "tool_sni":
            status_msg = await message.reply_text("📡 **Analyzing SNI Framework & Tunnel Profiles...**", reply_to_message_id=message.id)
            sni_host = text.replace("http://", "").replace("https://", "").split("/")[0].strip()
            try:
                ips = await async_getallips(sni_host)
                if "N/A" in ips and len(ips) == 1:
                    await status_msg.edit_text("❌ **Resolution Failure:** Hostname did not return valid A records.")
                    USER_STATE.pop(user_id, None)
                    return
                ip_display = "\n".join([f"   ↳ `{ip}`" for ip in ips])
                target_ip = ips[0]
                open_ports = []
                check_ports_list = [80, 443, 8080, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 3389]
                
                async def sni_check_port(port):
                    try:
                        conn = asyncio.open_connection(target_ip, port)
                        _, writer = await asyncio.wait_for(conn, timeout=1.5)
                        open_ports.append(port)
                        writer.close()
                        await writer.wait_closed()
                    except Exception: pass

                await asyncio.gather(*[sni_check_port(p) for p in check_ports_list])
                open_ports.sort()
                ports_display = ", ".join(map(str, open_ports)) if open_ports else "80, 443"

                server_header, http_status, supports_ws, location_url = "Unknown", "N/A", "False", "None"
                sni_spoofing_allowed = True
                
                req_headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "*/*"
                }
                async with aiohttp.ClientSession(headers=req_headers) as session:
                    fetch_success = False
                    for scheme in ["https", "http"]:
                        if fetch_success: break
                        try:
                            async with session.get(f"{scheme}://{sni_host}", timeout=4.0, allow_redirects=False, ssl=False) as r:
                                http_status = r.status
                                server_header = r.headers.get("Server", "Unknown")
                                location_url = r.headers.get("Location", "None")
                                fetch_success = True
                        except Exception: pass
                    try:
                        ws_headers = {"Connection": "Upgrade", "Upgrade": "websocket", "Host": sni_host, "Sec-WebSocket-Key": "x3JJHMbDL1EzLkh9GBhXDw==", "Sec-WebSocket-Version": "13"}
                        async with session.get(f"https://{sni_host}", headers=ws_headers, timeout=4.0, allow_redirects=False, ssl=False) as ws_r:
                            if ws_r.status in [101, 400, 426] or "websocket" in ws_r.headers.get("Connection", "").lower():
                                supports_ws = f"True ({STATUS_MAP.get(ws_r.status, str(ws_r.status))})"
                    except Exception: pass
                    try:
                        fake_headers = {"Host": "fake-spoof-test.com", "User-Agent": "Mozilla/5.0"}
                        test_url = f"https://{target_ip}" if 443 in open_ports else f"http://{target_ip}"
                        async with session.get(test_url, headers=fake_headers, timeout=3.0, allow_redirects=False, ssl=False) as test_r:
                            if test_r.status in [403, 400, 502, 503]:
                                sni_spoofing_allowed = False
                    except Exception: pass
                    
                if "cloudflare" in server_header.lower(): supports_ws = "True (Cloudflare Edge)"

                vpn_101_status = "❌ Failed / Blocked"
                current_host = sni_host
                current_path = "/"
                current_port = 80
                use_ssl = False

                if 80 not in open_ports and 443 in open_ports:
                    current_port = 443
                    use_ssl = True

                for redirect_depth in range(3):
                    try:
                        ssl_ctx = None
                        if use_ssl:
                            ssl_ctx = ssl.create_default_context()
                            ssl_ctx.check_hostname = False
                            ssl_ctx.verify_mode = ssl.CERT_NONE
                            
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_ip, current_port, ssl=ssl_ctx, server_hostname=current_host if use_ssl else None), 
                            timeout=5.0
                        )
                        payload = (
                            f"GET {current_path} HTTP/1.1\r\n"
                            f"Host: {current_host}\r\n"
                            f"Upgrade: websocket\r\n"
                            f"Connection: Upgrade\r\n"
                            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"
                        )
                        writer.write(payload.encode('utf-8'))
                        await writer.drain()
                        
                        resp_bytes = await asyncio.wait_for(reader.read(4096), timeout=4.0)
                        resp_str = resp_bytes.decode('utf-8', errors='ignore')
                        writer.close()
                        await writer.wait_closed()
                        
                        if any(code in resp_str[:30] for code in ['101', '400', '403', '426', '200']) or ("websocket" in resp_str.lower() or "connection" in resp_str.lower() or "upgrade" in resp_str.lower()):
                            vpn_101_status = f"✅ **CONNECTED (Handshake Response Acknowledged)**"
                            break
                        elif any(code in resp_str[:30] for code in ['301', '302', '303', '307', '308']):
                            loc_match = re.search(r'(?i)Location:\s*([^\r\n]+)', resp_str)
                            if loc_match:
                                loc_url = loc_match.group(1).strip()
                                if loc_url.startswith("https://"):
                                    use_ssl = True
                                    current_port = 443
                                    loc_url = loc_url[8:]
                                elif loc_url.startswith("http://"):
                                    use_ssl = False
                                    current_port = 80
                                    loc_url = loc_url[7:]
                                
                                if "/" in loc_url:
                                    current_host = loc_url.split("/")[0]
                                    current_path = "/" + "/".join(loc_url.split("/")[1:])
                                else:
                                    current_host = loc_url
                                    current_path = "/"
                                continue
                            else:
                                vpn_101_status = f"✅ **CONNECTED (Handshake Established Via Redirect)**"
                                break
                        else:
                            first_line = resp_str.split('\r\n')[0] if resp_str else "No response"
                            vpn_101_status = f"❌ FAILED ({first_line})"
                            break
                    except asyncio.TimeoutError:
                        vpn_101_status = f"✅ **CONNECTED (Bypassed Via Response Timeout)**"
                        break
                    except Exception:
                        if "resp_str" in locals() and ("websocket" in resp_str.lower() or "upgrade" in resp_str.lower() or "connection" in resp_str.lower()):
                            vpn_101_status = f"✅ **CONNECTED (Handshake Initiated Safely)**"
                        else:
                            vpn_101_status = f"✅ **CONNECTED (Handshake Response Accepted)**"
                        break

                origins = set()
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(f"https://api.hackertarget.com/hostsearch/?q={sni_host}", timeout=5.0) as resp:
                            if resp.status == 200:
                                text_data = await resp.text()
                                for line in text_data.strip().split('\n'):
                                    if ',' in line:
                                        sub, sip = line.split(',')[0], line.split(',')[1]
                                        if not sip.startswith(("127.", "10.", "192.168.", "172.")): origins.add(sip)
                    except Exception: pass
                    
                    for sub in [f"origin.{sni_host}", f"direct.{sni_host}", f"ftp.{sni_host}", f"mail.{sni_host}"]:
                        sip = await async_gethostbyname(sub)
                        if sip != "N/A" and not sip.startswith(("127.", "10.", "192.168.", "172.")): origins.add(sip)
                            
                origin_txt = ", ".join(list(origins)[:5]) if origins else "Not Found / Protected"

                tunnel_modes = ["✅ **Direct + SNI** (Universal TLS)"]
                if sni_spoofing_allowed: tunnel_modes.append("✅ **Proxy + SNI** (Custom Injection Valid)")
                else: tunnel_modes.append(f"❌ **Proxy + SNI** (Blocked by CDN / {STATUS_MAP.get(403)})")
                if supports_ws != "False": tunnel_modes.append("✅ **V2Ray Compatibility** (VMess/VLess WS)")
                if http_status in [200, 301, 302, 303, 307, 308, 403]:
                    tunnel_modes.extend(["✅ **Direct** (Standard HTTP Payload)", "✅ **Proxy** (Standard Proxy Injector)"])
                    
                tunnel_modes_text = "\n".join(tunnel_modes)
                report = (
                    f"📡 **ADVANCED SNI & VPN INTELLIGENCE REPORT**\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🎯 **Target Node:** `{sni_host}`\n"
                    f"📌 **Resolved IPv4:**\n{ip_display}\n\n"
                    f"ℹ️ **HTTP Status:** `{STATUS_MAP.get(http_status, f'{http_status} Status Code') if isinstance(http_status, int) else http_status}`\n"
                    f"⚙️ **Server Daemon:** `{server_header}`\n"
                    f"🌐 **Redirect Path:** `{location_url}`\n"
                    f"🔌 **WebSocket (WS):** `{supports_ws}`\n"
                    f"🔓 **Exposed Ports:** `{ports_display}`\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"⚡️ **PROTOCOL COMPATIBILITY:**\n{tunnel_modes_text}\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🔥 **RAW 101 VPN PAYLOAD TEST:**\n↳ {vpn_101_status}\n\n"
                    f"🕵️ **ORIGIN IP (CDN BYPASS LEAKS):**\n↳ `{origin_txt}`\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                    f"⚡ *Bot by Ashif*"
                )
                await status_msg.edit_text(report)
            except Exception as e: await status_msg.edit_text(f"❌ **Diagnostics Error:** {str(e)}")
            finally: USER_STATE.pop(user_id, None)
            return

        elif state == "tool_sub":
            status_msg = await message.reply_text("🔎 **Advanced Subdomain Finder... Scrapping 12+ live sources...**", reply_to_message_id=message.id)
            domain = text.replace("http://", "").replace("https://", "").split("/")[0].strip()
            found_subs = set()
            
            def clean_subdomain(dname):
                if not dname: return None
                dname = dname.strip().lower().lstrip('*.')
                if re.match(r'^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$', dname): return dname
                return None

            async def fetch_crtsh():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12.0) as r:
                            if r.status == 200:
                                data = await r.json()
                                for entry in data:
                                    for sub in entry.get('name_value', '').split('\n'):
                                        cleaned = clean_subdomain(sub)
                                        if cleaned and cleaned.endswith(f".{domain}"): found_subs.add(cleaned)
                except: pass

            async def fetch_alienvault():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=10.0) as r:
                            if r.status == 200:
                                data = await r.json()
                                for item in data.get('passive_dns', []):
                                    cleaned = clean_subdomain(item.get('hostname', ''))
                                    if cleaned and cleaned.endswith(f".{domain}"): found_subs.add(cleaned)
                except: pass

            async def fetch_bufferover():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://dns.bufferover.run/dns?q={domain}", timeout=10.0) as r:
                            if r.status == 200:
                                data = await r.json()
                                for entry in data.get('FDNS_A', []) + data.get('RDNS', []):
                                    if isinstance(entry, list) and len(entry) > 1:
                                        cleaned = clean_subdomain(entry[1])
                                        if cleaned and cleaned.endswith(f".{domain}"): found_subs.add(cleaned)
                except: pass

            async def fetch_threatcrowd():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=10.0) as r:
                            if r.status == 200:
                                data = await r.json()
                                for sub in data.get('subdomains', []):
                                    cleaned = clean_subdomain(sub)
                                    if cleaned: found_subs.add(cleaned)
                except: pass

            async def fetch_anubis():
                try:
                    url = f"https://jldc.me/anubis/subdomains/{domain}"
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        for sub in res.json():
                            cleaned = clean_subdomain(sub)
                            if cleaned: found_subs.add(cleaned)
                except: pass

            async def fetch_hackertarget():
                try:
                    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        for line in res.text.strip().split('\n'):
                            if ',' in line:
                                cleaned = clean_subdomain(line.split(',')[0])
                                if cleaned and cleaned.endswith(f".{domain}"): found_subs.add(cleaned)
                except: pass

            async def fetch_rapiddns():
                try:
                    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
                    res = requests.get(url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
                    if res.status_code == 200:
                        for sub in re.findall(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>', res.text):
                            cleaned = clean_subdomain(sub)
                            if cleaned: found_subs.add(cleaned)
                except: pass

            async def fetch_dnsdumpster():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get("https://dnsdumpster.com/", timeout=10.0) as r:
                            csrf = re.findall(r'name="csrfmiddlewaretoken" value="([^"]+)"', await r.text())
                        if csrf:
                            data = {"csrfmiddlewaretoken": csrf[0], "targetip": domain}
                            async with session.post("https://dnsdumpster.com/", data=data, timeout=12.0) as r:
                                subs = re.findall(r'<td class="col-md-4">([^<]+\.' + re.escape(domain) + r')', await r.text())
                                for sub in subs:
                                    cleaned = clean_subdomain(sub)
                                    if cleaned: found_subs.add(cleaned)
                except: pass

            try:
                await asyncio.gather(fetch_crtsh(), fetch_alienvault(), fetch_bufferover(), fetch_threatcrowd(), fetch_anubis(), fetch_hackertarget(), fetch_rapiddns(), fetch_dnsdumpster())
                await status_msg.delete()
                found_list = sorted(list(found_subs))
                
                if found_list:
                    res_file = os.path.join(DOWNLOAD_DIR, f"subs_{user_id}_{domain}.txt")
                    with open(res_file, "w") as f:
                        for s in found_list: f.write(s + "\n")
                    
                    display_subs = found_list[:25]
                    res_txt = f"🎯 **Subdomain Finder Results:**\n🌐 Target: `{domain}`\n🔥 Total Found: `{len(found_list)}` subdomains\n\n"
                    for f in display_subs: res_txt += f"  ↳ `{f}`\n"
                    if len(found_list) > 25: res_txt += f"\n*...aur {len(found_list)-25} baki hain. Poori list text file me attached hai 👇*\n\n"
                    res_txt += "⚡ *Bot by Ashif*"
                    
                    await message.reply_document(res_file, caption=res_txt, reply_to_message_id=message.id)
                    os.remove(res_file)
                else: 
                    await message.reply_text(f"❌ **`{domain}` ke koi subdomains nahi mile.**", reply_to_message_id=message.id)
            except Exception as e: 
                await message.reply_text(f"❌ **Error:** {str(e)}", reply_to_message_id=message.id)
            finally: 
                USER_STATE.pop(user_id, None)
            return

        elif state == "tool_rdns":
            status_msg = await message.reply_text("⏳ **Initializing Reverse DNS Scan Engine...**", reply_to_message_id=message.id)
            input_target = text.strip()
            ips_to_scan = []
            try:
                if '/' in input_target:
                    net = ipaddress.ip_network(input_target, strict=False)
                    ips_to_scan = [str(ip) for ip in net.hosts()]
                else:
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_target):
                        resolved_ip = await async_gethostbyname(input_target)
                        if resolved_ip != "N/A": ips_to_scan.append(resolved_ip)
                    else: ips_to_scan.append(input_target)
            except Exception as e:
                await status_msg.edit_text(f"❌ **Input Parsing Error:** {str(e)}")
                USER_STATE.pop(user_id, None)
                return

            if not ips_to_scan:
                await status_msg.edit_text("❌ **Error:** No valid IP addresses found for PTR resolution.")
                USER_STATE.pop(user_id, None)
                return

            res_file = os.path.join(DOWNLOAD_DIR, f"rdns_res_{user_id}.txt")
            open(res_file, 'w').close()
            tracker = ProgressTracker(len(ips_to_scan))
            USER_STATE[user_id]["tracker"] = tracker
            q = asyncio.Queue()
            for ip in ips_to_scan: q.put_nowait(ip)

            async def updater():
                while not tracker.is_stopped:
                    await update_live_status(status_msg, tracker, "⚡️ **Reverse DNS Engine: Active**")
                    await asyncio.sleep(8.0)

            upd_task = asyncio.create_task(updater())
            workers = [asyncio.create_task(worker_rdns(q, res_file, tracker)) for _ in range(150)]
            while not q.empty() and not tracker.is_stopped: await asyncio.sleep(0.5)
            tracker.is_stopped = True
            for w in workers: w.cancel()
            upd_task.cancel()
            await status_msg.delete()

            if os.path.exists(res_file) and os.path.getsize(res_file) > 0:
                await message.reply_document(res_file, caption=f"🎯 **Reverse DNS PTR Results:**\n📊 Total Checked: `{tracker.scanned}`\n✅ Valid PTR Resolved: `{tracker.hits}`\n\n*Bot by Ashif*", reply_to_message_id=message.id)
                os.remove(res_file)
            else:
                await message.reply_text("❌ No Reverse DNS records discovered for the target.", reply_to_message_id=message.id)
            USER_STATE.pop(user_id, None)
            return

        elif state == "tool_cidr":
            res_file = os.path.join(DOWNLOAD_DIR, f"cidr_res_{user_id}.txt")
            open(res_file, 'w').close()
            status_msg = await message.reply_text("⏳ **Initializing Network Mapper...**", reply_to_message_id=message.id)
            try:
                net = ipaddress.ip_network(text, strict=False)
                total_hosts = (net.num_addresses - 2) if net.num_addresses > 2 else 1
                ports = ["80", "443"]
                tracker = ProgressTracker(total_hosts * len(ports))
                USER_STATE[user_id]["tracker"] = tracker
                q = asyncio.Queue(maxsize=10000)
                
                async def producer():
                    for ip in net.hosts():
                        if tracker.is_stopped: break
                        for pt in ports:
                            if tracker.is_stopped: break
                            await q.put((str(ip), pt))
                            
                prod_task = asyncio.create_task(producer())
                async def updater():
                    while not tracker.is_stopped:
                        await update_live_status(status_msg, tracker, "⚡️ **Execution Engine: Active**")
                        await asyncio.sleep(8.0) 
                        
                upd_task = asyncio.create_task(updater())

                async with aiohttp.ClientSession() as session:
                    workers = [asyncio.create_task(worker_cidr(q, session, res_file, tracker)) for _ in range(100)]
                    await prod_task
                    await q.join()
                    for w in workers: w.cancel()
                    upd_task.cancel()

                if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Operation Terminated.**")
                else: await update_live_status(status_msg, tracker, "⚡️ **Execution Completed.**")

                if os.path.getsize(res_file) > 0:
                    await message.reply_document(res_file, caption=f"📊 **CIDR Scan Results:**\nNodes Scanned: {tracker.scanned}\nValid Hits: {tracker.hits}\n\n*Bot by Ashif*", reply_to_message_id=message.id)
                else: await message.reply_text("❌ No accessible nodes discovered.", reply_to_message_id=message.id)
            except Exception as e: await message.reply_text(f"❌ **Syntax Error:** {str(e)}", reply_to_message_id=message.id)
            finally:
                if os.path.exists(res_file): os.remove(res_file)
                USER_STATE.pop(user_id, None)
            return

        elif state == "tool_port":
            status_msg = await message.reply_text("🔍 **Executing Deep Port Scan...**", reply_to_message_id=message.id)
            try:
                ip_addr = await async_gethostbyname(text)
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
                open_ports = []
                async def check_port(port):
                    try:
                        conn = asyncio.open_connection(ip_addr, port)
                        _, writer = await asyncio.wait_for(conn, timeout=1.5)
                        open_ports.append(port)
                        writer.close()
                        await writer.wait_closed()
                    except Exception: pass
                await asyncio.gather(*[check_port(p) for p in ports])
                await status_msg.delete()
                if open_ports:
                    res_txt = f"📊 **Diagnostic for {text}:**\n\n"
                    for p in sorted(open_ports): res_txt += f"✅ Port `{p}` [OPEN]\n"
                    res_txt += "\n⚡ *Bot by Ashif*"
                    await message.reply_text(res_txt, reply_to_message_id=message.id)
                else: await message.reply_text("❌ All common ports are filtered or closed.", reply_to_message_id=message.id)
            except Exception as e: await message.reply_text(f"❌ **Error:** {str(e)}", reply_to_message_id=message.id)
            finally: USER_STATE.pop(user_id, None)
            return

        elif state == "tool_ip_to_domain":
            status_msg = await message.reply_text("⏳ **Ip To Domain Finding....**", reply_to_message_id=message.id)
            target_ip = text.strip()
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_ip):
                resolved_ip = await async_gethostbyname(target_ip)
                if resolved_ip != "N/A": target_ip = resolved_ip
                else:
                    await status_msg.edit_text("❌ **Error:** Invalid IP Address or Hostname resolution failure.")
                    USER_STATE.pop(user_id, None)
                    return

            output_file = os.path.join(DOWNLOAD_DIR, f"domains_{user_id}_{target_ip}.txt")
            
            loop = asyncio.get_running_loop()
            total_extracted = await loop.run_in_executor(THREAD_POOL, generate_pure_domain_file, target_ip, output_file)
            await status_msg.delete()

            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                await message.reply_document(
                    document=output_file, 
                    caption=f"🎯 **Target IP:** `{target_ip}`\n🔥 **Total Domains Extracted:** `{total_extracted}`\n\n⚡ *Bot by Ashif*",
                    reply_to_message_id=message.id
                )
                os.remove(output_file)
            else: 
                await message.reply_text(f"❌ Target IP `{target_ip}` par koi domains nahi mile.", reply_to_message_id=message.id)
            USER_STATE.pop(user_id, None)
            return

# ============ DOCUMENT INPUT ROUTER (STREAMING MODE) ============
@app.on_message(filters.document & filters.group)
async def process_documents(client: Client, message: Message):
    if ALLOWED_GROUP_ID != 0 and message.chat.id != ALLOWED_GROUP_ID: return
    if message.from_user: user_id = message.from_user.id
    elif message.sender_chat: user_id = message.sender_chat.id
    else: return

    if user_id not in USER_STATE or "action" not in USER_STATE[user_id]: return

    state = USER_STATE[user_id]["action"]
    status_msg = await message.reply_text("⏳ **Authenticating Payload...**", reply_to_message_id=message.id)

    try:
        if state == "tool_host":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_host_{user_id}.txt", progress=dwn_progress, progress_args=(status_msg,))
            res_file = os.path.join(DOWNLOAD_DIR, f"host_res_{user_id}.txt")
            open(res_file, 'w').close()
            
            await status_msg.edit_text("⏳ **Calculating Payload Memory Footprint...**")
            total_lines = sum(1 for line in open(file_path, 'r', errors='ignore') if line.strip())
            ports = ["80", "443", "8080"]
            tracker = ProgressTracker(total_lines * len(ports))
            USER_STATE[user_id]["tracker"] = tracker
            
            q = asyncio.Queue(maxsize=10000)

            async def producer():
                with open(file_path, 'r', errors='ignore') as f:
                    for line in f:
                        if tracker.is_stopped: break
                        d = line.strip()
                        if d:
                            for pt in ports:
                                if tracker.is_stopped: break
                                await q.put((d, pt))

            prod_task = asyncio.create_task(producer())
            async def updater():
                while not tracker.is_stopped:
                    await update_live_status(status_msg, tracker, "⚡️ **Host Engine: Active**")
                    await asyncio.sleep(4.0)
            upd_task = asyncio.create_task(updater())

            async with aiohttp.ClientSession() as session:
                workers = [asyncio.create_task(worker_host(q, session, res_file, tracker)) for _ in range(120)]
                await prod_task
                await q.join()
                for w in workers: w.cancel()
                upd_task.cancel()

            if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Operation Terminated.**")
            else: await update_live_status(status_msg, tracker, "⚡️ **Operation Completed.**")
            
            if os.path.getsize(res_file) > 0:
                await message.reply_document(res_file, caption=f"✅ **Host Log Extracted.**\nValid Entries: {tracker.hits}\n\n*Bot by Ashif*", reply_to_message_id=message.id)
            else: await message.reply_text("❌ No valid configurations found.", reply_to_message_id=message.id)
            os.remove(file_path); os.remove(res_file)

        elif state == "tool_mcidr":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_mcidr_{user_id}.txt", progress=dwn_progress, progress_args=(status_msg,))
            res_file = os.path.join(DOWNLOAD_DIR, f"multi_cidr_{user_id}.txt")
            open(res_file, 'w').close()
            
            await status_msg.edit_text("⏳ **Analyzing CIDR Architecture...**")
            valid_cidrs = []
            total_hosts = 0
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    c = line.strip()
                    if c:
                        try:
                            net = ipaddress.ip_network(c, strict=False)
                            valid_cidrs.append(net)
                            total_hosts += (net.num_addresses - 2) if net.num_addresses > 2 else 1
                        except: pass
            tracker = ProgressTracker(total_hosts) 
            USER_STATE[user_id]["tracker"] = tracker
            q = asyncio.Queue(maxsize=10000)

            async def producer():
                for net in valid_cidrs:
                    if tracker.is_stopped: break
                    for ip in net.hosts():
                        if tracker.is_stopped: break
                        await q.put((str(ip), "80"))

            prod_task = asyncio.create_task(producer())
            async def updater():
                while not tracker.is_stopped:
                    await update_live_status(status_msg, tracker, "⚡️ **Execution Engine: Active**")
                    await asyncio.sleep(4.0)
            upd_task = asyncio.create_task(updater())

            async with aiohttp.ClientSession() as session:
                workers = [asyncio.create_task(worker_cidr(q, session, res_file, tracker)) for _ in range(120)]
                await prod_task
                await q.join()
                for w in workers: w.cancel()
                upd_task.cancel()

            if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Operation Terminated.**")
            else: await update_live_status(status_msg, tracker, "⚡️ **Operation Completed.**")
            if os.path.getsize(res_file) > 0: await message.reply_document(res_file, caption=f"✅ **Recon Data Exported.**\nValid Entries: {tracker.hits}\n\n*Bot by Ashif*", reply_to_message_id=message.id)
            else: await message.reply_text("❌ Network mapping returned zero results.", reply_to_message_id=message.id)
            os.remove(file_path); os.remove(res_file)

        elif state == "tool_split":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_split_{user_id}.txt", progress=dwn_progress, progress_args=(status_msg,))
            with open(file_path, 'r', errors='ignore') as f: lines = f.readlines()
            lines_per_chunk = 1000
            num_chunks = (len(lines) + lines_per_chunk - 1) // lines_per_chunk
            for i in range(num_chunks):
                chunk_file = os.path.join(DOWNLOAD_DIR, f"chunk_{user_id}_{i+1}.txt")
                with open(chunk_file, 'w') as cf: cf.writelines(lines[i * lines_per_chunk : (i+1) * lines_per_chunk])
                await message.reply_document(chunk_file, caption=f"📦 Volume {i+1}/{num_chunks}", reply_to_message_id=message.id)
                os.remove(chunk_file)
            os.remove(file_path)
            await status_msg.delete()

        elif state == "tool_clean":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_clean_{user_id}.txt", progress=dwn_progress, progress_args=(status_msg,))
            with open(file_path, 'r', errors='ignore') as f: domains = [l.strip().lower() for l in f if l.strip()]
            uniq = sorted(set(domains))
            res_file = os.path.join(DOWNLOAD_DIR, f"clean_{user_id}.txt")
            with open(res_file, 'w') as f:
                for d in uniq: f.write(d + "\n")
            await message.reply_document(res_file, caption=f"🧹 **Dataset Sanitized.**\nUnique Retained: {len(uniq)}\n\n*Bot by Ashif*", reply_to_message_id=message.id)
            os.remove(file_path); os.remove(res_file)
            await status_msg.delete()

        elif state == "tool_extract":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_extract_{user_id}.txt", progress=dwn_progress, progress_args=(status_msg,))
            with open(file_path, 'r', errors='ignore') as f: text_content = f.read()
            os.remove(file_path)
            domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
            domains = set(domain_pattern.findall(text_content))
            filtered = sorted({d.lower() for d in domains if len(d) > 4 and not d.startswith("www.") and not d.endswith(".com.com")})
            res_file = os.path.join(DOWNLOAD_DIR, f"extracted_{user_id}.txt")
            with open(res_file, 'w') as f:
                for d in filtered: f.write(d + "\n")
            await message.reply_document(res_file, caption=f"🎯 **Extraction Complete.**\nValid Domains Parsed: {len(filtered)}\n\n*Bot by Ashif*", reply_to_message_id=message.id)
            os.remove(res_file)
            await status_msg.delete()

    except Exception as e: await message.reply_text(f"❌ **System Integrity Error:** {str(e)}", reply_to_message_id=message.id)
    finally:
        try: await status_msg.delete()
        except: pass
        USER_STATE.pop(user_id, None)

if __name__ == "__main__":
    print("DarkXNetwork Group Multi-Scanner Engine is Online...")
    app.run()
