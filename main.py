import os
import json
import time
import hashlib
import requests
import socket
import re
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ==========================================
# 1. Configurations
# ==========================================
BOT_TOKEN = os.getenv('BOT_TOKEN')
CHANNEL_V2RAY = '@zVPN24'
CHANNEL_MTPROTO = '@zProxy24'
CUSTOM_REMARK_V2RAY = '⚙️@zVPN24'

if not BOT_TOKEN:
    print("❌ BOT_TOKEN is missing! Please set it in GitHub Secrets.")
    exit(1)

bot = telebot.TeleBot(BOT_TOKEN)

# فایل‌های دیتابیس
HISTORY_FILE = 'history.json'
GEO_CACHE_FILE = 'geo_cache.json'
SOURCES_FILE = 'sources.txt'

# ==========================================
# 2. File & Cache Management
# ==========================================
def load_json(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_json(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_lines_from_file(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def generate_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# ==========================================
# 3. Network & Geo-Location Functions
# ==========================================
def check_liveness(ip, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return result == 0
    except:
        return False

def get_location_info(ip, geo_cache):
    """دریافت لوکیشن و دیتاسنتر. در صورت عدم شناسایی، None برمی‌گرداند."""
    now = time.time()
    if ip in geo_cache and (now - geo_cache[ip].get('time', 0)) < 864000:
        if geo_cache[ip].get('loc') == 'Unknown':
            return None
        return geo_cache[ip]

    try:
        # درخواست نام کشور، کد کشور و نام دیتاسنتر (ISP/Org)
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp,org", timeout=3).json()
        if resp.get('countryCode'):
            flag = chr(ord(resp['countryCode'][0]) + 127397) + chr(ord(resp['countryCode'][1]) + 127397)
            loc = resp['country']
            code = resp['countryCode']
            
            # تمیز کردن نام دیتاسنتر از کاراکترهایی که مارک‌داون تلگرام را خراب می‌کنند
            raw_isp = resp.get('org') or resp.get('isp') or "Unknown ISP"
            isp = raw_isp.replace('_', ' ').replace('*', '').replace('`', '')
            
            data = {'loc': loc, 'flag': flag, 'code': code, 'isp': isp, 'time': now}
            geo_cache[ip] = data
            return data
    except:
        pass
    
    return None # اگر لوکیشن پیدا نشد عبور کن

def fix_base64(s):
    return s + '=' * (4 - len(s) % 4)

# ==========================================
# 4. Config Analyzer & Modifier
# ==========================================
def process_config(raw_config, geo_cache):
    config = raw_config.strip()
    config_hash = generate_hash(config)
    ip = port = None
    config_type = "UNKNOWN"
    final_config = config

    try:
        if config.startswith("tg://proxy"):
            config_type = "MTPROTO"
            ip_match = re.search(r'server=([^&]+)', config)
            port_match = re.search(r'port=(\d+)', config)
            if ip_match and port_match:
                ip, port = ip_match.group(1), port_match.group(1)

        elif config.startswith("vmess://"):
            config_type = "V2RAY"
            b64_str = config.replace("vmess://", "")
            decoded = base64.b64decode(fix_base64(b64_str)).decode('utf-8')
            v_data = json.loads(decoded)
            ip, port = v_data.get("add"), v_data.get("port")
            
            if ip and port and check_liveness(ip, port):
                geo_info = get_location_info(ip, geo_cache)
                if not geo_info: # فیلتر لوکیشن
                    return None
                    
                # ساخت ریمارک: ⚙️@zVPN24 | 🇩🇪 DE
                remark = f"{CUSTOM_REMARK_V2RAY} | {geo_info['flag']} {geo_info['code']}"
                v_data['ps'] = remark
                
                new_b64 = base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
                final_config = f"vmess://{new_b64}"
                return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash}

        elif any(config.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
            config_type = "V2RAY"
            parsed = urlparse(config)
            ip, port = parsed.hostname, parsed.port
            
            if ip and port and check_liveness(ip, port):
                geo_info = get_location_info(ip, geo_cache)
                if not geo_info: # فیلتر لوکیشن
                    return None
                    
                base_uri = config.split('#')[0]
                # چسباندن ریمارک بدون urlencode تا در تلگرام زیبا دیده شود
                remark = f"{CUSTOM_REMARK_V2RAY} | {geo_info['flag']} {geo_info['code']}"
                final_config = f"{base_uri}#{remark}"
                
                return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash}

        # پردازش پروکسی‌ها
        if ip and port and config_type == "MTPROTO" and check_liveness(ip, port):
            geo_info = get_location_info(ip, geo_cache)
            if not geo_info:
                return None
            return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash}
            
    except Exception:
        pass
        
    return None

# ==========================================
# 5. Scrapers (Sources & YAML Converter)
# ==========================================
def convert_yaml_sub(link):
    """تبدیل لینک‌های YAML به V2Ray با استفاده از 3 مبدل پشتیبان"""
    apis = [
        f"https://sub.v1.mk/sub?target=v2ray&url={link}",
        f"https://api.v1.mk/sub?target=v2ray&url={link}",
        f"https://api.nameless13.com/sub?target=v2ray&url={link}"
    ]
    
    for api in apis:
        try:
            r = requests.get(api, timeout=10)
            if r.status_code == 200:
                text = r.text.strip()
                # مبدل‌ها نتیجه را Base64 می‌دهند، دی‌کد می‌کنیم
                decoded = base64.b64decode(fix_base64(text)).decode('utf-8')
                return decoded.splitlines()
        except:
            continue
            
    return [] # اگر هر 3 مبدل شکست خوردند، لیست خالی برمی‌گرداند

def get_raw_configs():
    configs = []
    raw_sources = get_lines_from_file(SOURCES_FILE)
    subs = []
    channels = []
    
    for s in raw_sources:
        if s.startswith('http') and 't.me' not in s:
            subs.append(s)
        else:
            ch = s.replace('https://t.me/s/', '').replace('https://t.me/', '').replace('@', '').strip()
            channels.append(ch)
            
    # پردازش ساب‌لینک‌ها (عادی و YAML)
    for link in subs:
        try:
            r = requests.get(link, timeout=10)
            if r.status_code == 200:
                text = r.text.strip()
                
                # بررسی اینکه آیا محتوا YAML/Clash است یا خیر
                if "proxies:" in text or "port:" in text:
                    configs.extend(convert_yaml_sub(link))
                else:
                    if "://" not in text[:50]:
                        try:
                            text = base64.b64decode(fix_base64(text)).decode('utf-8')
                        except:
                            pass
                    configs.extend(text.splitlines())
        except:
            continue
            
    # پردازش تلگرام
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    for channel in channels:
        try:
            r = requests.get(f"https://t.me/s/{channel}", headers=headers, timeout=10)
            if r.status_code == 200:
                html = unquote(r.text)
                messages = html.split('tgme_widget_message js-widget_message')
                for msg in messages:
                    if f'datetime="{today_str}' in msg:
                        found = re.findall(r'(vless://[^\s<"]+|vmess://[^\s<"]+|trojan://[^\s<"]+|ss://[^\s<"]+|tg://proxy\?[^\s<"]+)', msg)
                        configs.extend(found)
        except:
            continue
            
    return list(set([c.strip() for c in configs if c.strip()]))

# ==========================================
# 6. Main Execution & Telegram Publisher
# ==========================================
def main():
    history = load_json(HISTORY_FILE)
    geo_cache = load_json(GEO_CACHE_FILE)
    
    print("🔄 Scraping sources...")
    raw_configs = get_raw_configs()
    
    new_configs = [c for c in raw_configs if generate_hash(c) not in history]
    total_new = len(new_configs)
    print(f"📊 Found {total_new} new unique configs. Running Liveness test...")
    
    active_results = []
    processed_count = 0
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(process_config, conf, geo_cache): conf for conf in new_configs}
        for future in as_completed(futures):
            processed_count += 1
            res = future.result()
            
            if res:
                active_results.append(res)
                history[res['hash']] = time.time()
                print(f"[{processed_count}/{total_new}] ✅ Active IP Found: {res['ip']} ({res['geo']['code']})")
            elif processed_count % 10 == 0 or processed_count == total_new:
                print(f"[{processed_count}/{total_new}] ⏳ Processing...")

    save_json(HISTORY_FILE, history)
    save_json(GEO_CACHE_FILE, geo_cache)
    
    print(f"\n🎯 Total Active Configs: {len(active_results)}")
    print("🚀 Starting Telegram Publisher...")

    # انتشار V2Ray
    v2ray_configs = [c for c in active_results if c['type'] == 'V2RAY']
    for idx, c in enumerate(v2ray_configs, 1):
        # استفاده از کوت باز (Backtick) برای کپی با یک لمس
        geo = c['geo']
        msg = f"📍 **Location:** {geo['flag']} {geo['loc']}\n" \
              f"🏢 **ISP:** {geo['isp']}\n" \
              f"🛡 **Type:** {c['type']}\n" \
              f"🌐 **IP:** `{c['ip']}`\n\n" \
              f"`{c['config']}`\n\n" \
              f"📡 @zVPN24"
        try:
            bot.send_message(CHANNEL_V2RAY, msg, parse_mode='Markdown')
            print(f"  👉 Posted V2Ray [{idx}/{len(v2ray_configs)}]: {c['ip']}")
            time.sleep(1)
        except Exception as e:
            print(f"  ❌ V2Ray Publish Error: {e}")

    # انتشار MTProto
    mtproto_configs = [c for c in active_results if c['type'] == 'MTPROTO']
    chunks = [mtproto_configs[i:i+4] for i in range(0, len(mtproto_configs), 4)]
    
    for idx, chunk in enumerate(chunks, 1):
        markup = InlineKeyboardMarkup(row_width=2)
        buttons = [InlineKeyboardButton(text=f"Connect {c['geo']['flag']}", url=c['config']) for c in chunk]
        markup.add(*buttons)
        
        text_message = "⚡️ **Fast & Active MTProto Proxies**\n\n" \
                       "👇 Click the buttons below to connect:\n\n" \
                       f"🟢 @zProxy24"
        try:
            bot.send_message(CHANNEL_MTPROTO, text_message, reply_markup=markup, parse_mode='Markdown')
            print(f"  👉 Posted MTProto Chunk [{idx}/{len(chunks)}]")
            time.sleep(1.5)
        except Exception as e:
            print(f"  ❌ MTProto Publish Error: {e}")

    print("🎉 All operations completed successfully!")

if __name__ == "__main__":
    main()
