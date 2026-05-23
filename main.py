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
import maxminddb  # کتابخانه رسمی برای خواندن دیتابیس‌های آفلاین Geo

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

# فایل‌ها
HISTORY_FILE = 'history.json'
SOURCES_FILE = 'sources.txt'

# دیتابیس‌های آفلاین
COUNTRY_DB_FILE = 'GeoLite2-Country.mmdb'
ASN_DB_FILE = 'GeoLite2-ASN.mmdb'
# لینک‌های دیتابیس رایگان و آپدیت‌شده گیت‌هاب (PrxyHunter)
COUNTRY_DB_URL = 'https://github.com/PrxyHunter/GeoLite2/releases/latest/download/GeoLite2-Country.mmdb'
ASN_DB_URL = 'https://github.com/PrxyHunter/GeoLite2/releases/latest/download/GeoLite2-ASN.mmdb'

# ==========================================
# 2. File & Database Management
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

def update_offline_geo_dbs():
    """دانلود دیتابیس‌های آفلاین در صورتی که وجود ندارند یا بیشتر از 10 روز از عمرشان گذشته است."""
    ten_days = 10 * 24 * 60 * 60
    now = time.time()
    
    for url, filepath in [(COUNTRY_DB_URL, COUNTRY_DB_FILE), (ASN_DB_URL, ASN_DB_FILE)]:
        needs_download = False
        if not os.path.exists(filepath):
            needs_download = True
        elif (now - os.path.getmtime(filepath)) > ten_days:
            needs_download = True
            
        if needs_download:
            print(f"📥 Downloading/Updating offline GeoDB: {filepath}...")
            try:
                r = requests.get(url, stream=True, timeout=30)
                if r.status_code == 200:
                    with open(filepath, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=1024*1024):
                            f.write(chunk)
                    print(f"✅ {filepath} updated successfully.")
            except Exception as e:
                print(f"❌ Failed to download {filepath}: {e}")

# ==========================================
# 3. Network & Offline Geo-Location Functions
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

def get_location_info_offline(ip, reader_country, reader_asn):
    """استخراج کشور و دیتاسنتر در کسری از میلی‌ثانیه بدون نیاز به اینترنت"""
    try:
        country_data = reader_country.get(ip)
        asn_data = reader_asn.get(ip)
        
        # اگر کشور پیدا نشد، کلا کانفیگ رو رد کن
        if country_data and 'country' in country_data and 'iso_code' in country_data['country']:
            code = country_data['country']['iso_code']
            loc = country_data['country']['names'].get('en', code)
            flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        else:
            return None 

        # استخراج دیتاسنتر (ASN)
        isp = "Unknown ISP"
        if asn_data and 'autonomous_system_organization' in asn_data:
            isp = asn_data['autonomous_system_organization'].replace('_', ' ').replace('*', '').replace('`', '')

        return {'loc': loc, 'flag': flag, 'code': code, 'isp': isp}
    except:
        return None

def fix_base64(s):
    return s + '=' * (4 - len(s) % 4)

# ==========================================
# 4. Config Analyzer & Modifier
# ==========================================
def process_config(raw_config, reader_country, reader_asn):
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
                geo_info = get_location_info_offline(ip, reader_country, reader_asn)
                if not geo_info: 
                    return None
                    
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
                geo_info = get_location_info_offline(ip, reader_country, reader_asn)
                if not geo_info: 
                    return None
                    
                base_uri = config.split('#')[0]
                remark = f"{CUSTOM_REMARK_V2RAY} | {geo_info['flag']} {geo_info['code']}"
                final_config = f"{base_uri}#{remark}"
                
                return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash}

        if ip and port and config_type == "MTPROTO" and check_liveness(ip, port):
            geo_info = get_location_info_offline(ip, reader_country, reader_asn)
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
                decoded = base64.b64decode(fix_base64(text)).decode('utf-8')
                return decoded.splitlines()
        except:
            continue
    return []

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
            
    for link in subs:
        try:
            r = requests.get(link, timeout=10)
            if r.status_code == 200:
                text = r.text.strip()
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
    # 1. آپدیت و راه‌اندازی دیتابیس آفلاین GeoIP
    update_offline_geo_dbs()
    
    if not os.path.exists(COUNTRY_DB_FILE) or not os.path.exists(ASN_DB_FILE):
        print("❌ Critical: Offline Geo databases are missing! Exiting...")
        exit(1)
        
    reader_country = maxminddb.open_database(COUNTRY_DB_FILE)
    reader_asn = maxminddb.open_database(ASN_DB_FILE)

    history = load_json(HISTORY_FILE)
    print("🔄 Scraping sources...")
    raw_configs = get_raw_configs()
    
    new_configs = [c for c in raw_configs if generate_hash(c) not in history]
    total_new = len(new_configs)
    print(f"📊 Found {total_new} new unique configs. Running Liveness test...")
    
    active_results = []
    processed_count = 0
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        # ارسال readers به تردها (کتابخانه maxminddb از ThreadPool پشتیبانی می‌کند)
        futures = {executor.submit(process_config, conf, reader_country, reader_asn): conf for conf in new_configs}
        for future in as_completed(futures):
            processed_count += 1
            res = future.result()
            
            if res:
                active_results.append(res)
                history[res['hash']] = time.time()
                print(f"[{processed_count}/{total_new}] ✅ Active: {res['ip']} ({res['geo']['code']} - {res['geo']['isp']})")
            elif processed_count % 10 == 0 or processed_count == total_new:
                print(f"[{processed_count}/{total_new}] ⏳ Processing...")

    save_json(HISTORY_FILE, history)
    reader_country.close()
    reader_asn.close()
    
    print(f"\n🎯 Total Active Configs: {len(active_results)}")
    print("🚀 Starting Telegram Publisher...")

    # انتشار V2Ray
    v2ray_configs = [c for c in active_results if c['type'] == 'V2RAY']
    for idx, c in enumerate(v2ray_configs, 1):
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
