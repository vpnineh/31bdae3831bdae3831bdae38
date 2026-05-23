import os
import json
import time
import hashlib
import requests
import socket
import re
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import maxminddb  
from telebot.apihelper import ApiTelegramException

# ==========================================
# 1. Configurations
# ==========================================
BOT_TOKEN = os.getenv('BOT_TOKEN')
CHANNEL_V2RAY = '@zVPN24'
CHANNEL_MTPROTO = '@zProxy24'
CUSTOM_REMARK_V2RAY = '🚀@zVPN24'

if not BOT_TOKEN:
    print("❌ BOT_TOKEN is missing! Please set it in GitHub Secrets.")
    exit(1)

bot = telebot.TeleBot(BOT_TOKEN)

# فایل‌ها (هیستوری به txt تغییر کرد برای سرعت فوق‌العاده)
HISTORY_FILE = 'history.txt'
SOURCES_FILE = 'sources.txt'

COUNTRY_DB_FILE = 'GeoLite2-Country.mmdb'
ASN_DB_FILE = 'GeoLite2-ASN.mmdb'
COUNTRY_DB_URL = 'https://github.com/PrxyHunter/GeoLite2/releases/latest/download/GeoLite2-Country.mmdb'
ASN_DB_URL = 'https://github.com/PrxyHunter/GeoLite2/releases/latest/download/GeoLite2-ASN.mmdb'

# ==========================================
# 2. Advanced Deep Hash & History Management
# ==========================================
def load_history(filepath):
    """بارگذاری 40 هزار هش در یک Set برای جستجوی صفر ثانیه‌ای"""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def append_to_history(filepath, new_hashes, max_lines=40000):
    if not new_hashes: return
    
    # خواندن فایل موجود
    existing = []
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            existing = [line.strip() for line in f if line.strip()]
            
    # اضافه کردن هش‌های جدید به انتهای لیست
    existing.extend(new_hashes)
    
    # اگر تعداد از 40 هزار خط گذشت، فقط 40 هزار تای جدیدتر را نگه دار
    if len(existing) > max_lines:
        existing = existing[-max_lines:]
        
    # بازنویسی فایل تمیز شده
    with open(filepath, 'w', encoding='utf-8') as f:
        for h in existing:
            f.write(h + '\n')

def get_deep_hash(config):
    """
    استخراج هویت اصلی سرور: ریمارک‌ها و پارامترهای اضافی حذف می‌شوند
    و هش فقط بر اساس (IP + Port + Password/UUID) ساخته می‌شود.
    """
    config = config.strip()
    try:
        if config.startswith("vmess://"):
            b64_str = config.replace("vmess://", "")
            decoded = base64.b64decode(s=b64_str + '=' * (4 - len(b64_str) % 4)).decode('utf-8')
            v_data = json.loads(decoded)
            # هسته Vmess: آی‌پی + پورت + آیدی
            core_str = f"vmess|{v_data.get('add')}:{v_data.get('port')}|{v_data.get('id')}"
            return hashlib.sha256(core_str.encode()).hexdigest()
            
        elif any(config.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
            parsed = urlparse(config)
            # هسته Vless/Trojan: پروتکل + آی‌پی + پورت + یوزرنیم (همان UUID یا پسورد)
            core_str = f"{parsed.scheme}|{parsed.hostname}:{parsed.port}|{parsed.username}"
            return hashlib.sha256(core_str.encode()).hexdigest()
            
        elif config.startswith("tg://proxy"):
            ip_m = re.search(r'server=([^&]+)', config)
            port_m = re.search(r'port=(\d+)', config)
            sec_m = re.search(r'secret=([^&]+)', config)
            if ip_m and port_m and sec_m:
                # هسته پروکسی: آی‌پی + پورت + سکرت
                core_str = f"mtproto|{ip_m.group(1)}:{port_m.group(1)}|{sec_m.group(1)}"
                return hashlib.sha256(core_str.encode()).hexdigest()
    except:
        pass
    
    # اگر فرمت ناشناخته بود، کل رشته را هش کن
    return hashlib.sha256(config.encode('utf-8')).hexdigest()

# ==========================================
# 3. Offline Geo-Location Functions
# ==========================================
def update_offline_geo_dbs():
    ten_days = 10 * 24 * 60 * 60
    now = time.time()
    for url, filepath in [(COUNTRY_DB_URL, COUNTRY_DB_FILE), (ASN_DB_URL, ASN_DB_FILE)]:
        needs_download = False
        if not os.path.exists(filepath):
            needs_download = True
        elif (now - os.path.getmtime(filepath)) > ten_days:
            needs_download = True
            
        if needs_download:
            print(f"📥 Downloading offline GeoDB: {filepath}...")
            try:
                r = requests.get(url, stream=True, timeout=30)
                if r.status_code == 200:
                    with open(filepath, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=1024*1024):
                            f.write(chunk)
            except Exception as e:
                print(f"❌ Failed to download {filepath}: {e}")

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
    try:
        country_data = reader_country.get(ip)
        asn_data = reader_asn.get(ip)
        
        if country_data and 'country' in country_data and 'iso_code' in country_data['country']:
            code = country_data['country']['iso_code']
            loc = country_data['country']['names'].get('en', code)
            flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        else:
            return None 

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
    config_hash = get_deep_hash(config) # استفاده از هش عمیق
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
            
            security = v_data.get("tls") or "none"
            if security == "": security = "none"
            
            if ip and port and check_liveness(ip, port):
                geo_info = get_location_info_offline(ip, reader_country, reader_asn)
                if not geo_info: return None
                    
                v_data['ps'] = f"{CUSTOM_REMARK_V2RAY} | {geo_info['flag']} {geo_info['code']}"
                new_b64 = base64.b64encode(json.dumps(v_data).encode('utf-8')).decode('utf-8')
                final_config = f"vmess://{new_b64}"
                return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash, "security": security.upper()}

        elif any(config.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
            config_type = "V2RAY"
            parsed = urlparse(config)
            ip, port = parsed.hostname, parsed.port
            
            query_params = parse_qs(parsed.query)
            security = query_params.get("security", ["none"])[0]
            
            if ip and port and check_liveness(ip, port):
                geo_info = get_location_info_offline(ip, reader_country, reader_asn)
                if not geo_info: return None
                    
                base_uri = config.split('#')[0]
                final_config = f"{base_uri}#{CUSTOM_REMARK_V2RAY} | {geo_info['flag']} {geo_info['code']}"
                return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash, "security": security.upper()}

        if ip and port and config_type == "MTPROTO" and check_liveness(ip, port):
            geo_info = get_location_info_offline(ip, reader_country, reader_asn)
            if not geo_info: return None
            return {"type": config_type, "config": final_config, "geo": geo_info, "ip": ip, "hash": config_hash}
            
    except Exception:
        pass
    return None

# ==========================================
# 5. Scrapers
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
    if not os.path.exists(SOURCES_FILE):
        print(f"❌ '{SOURCES_FILE}' not found!")
        return []
        
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        raw_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
    subs = [s for s in raw_sources if s.startswith('http') and 't.me' not in s]
    channels = [s.replace('https://t.me/s/', '').replace('https://t.me/', '').replace('@', '').strip() for s in raw_sources if not (s.startswith('http') and 't.me' not in s)]
            
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
                for msg in html.split('tgme_widget_message js-widget_message'):
                    if f'datetime="{today_str}' in msg:
                        configs.extend(re.findall(r'(vless://[^\s<"]+|vmess://[^\s<"]+|trojan://[^\s<"]+|ss://[^\s<"]+|tg://proxy\?[^\s<"]+)', msg))
        except:
            continue
            
    return list(set([c.strip() for c in configs if c.strip()]))

# ==========================================
# 6. Main Engine
# ==========================================
def main():
    update_offline_geo_dbs()
    if not os.path.exists(COUNTRY_DB_FILE) or not os.path.exists(ASN_DB_FILE):
        print("❌ Critical: Offline Geo databases missing!")
        exit(1)
        
    reader_country = maxminddb.open_database(COUNTRY_DB_FILE)
    reader_asn = maxminddb.open_database(ASN_DB_FILE)

    # بارگیری سریع هیستوری در یک Set
    history = load_history(HISTORY_FILE)
    print(f"📚 Loaded {len(history)} hashes from deep history.")
    
    print("🔄 Scraping sources...")
    raw_configs = get_raw_configs()
    
    # فیلتر عمیق: فقط کانفیگ‌هایی که هویت آن‌ها در تاریخچه نیست وارد می‌شوند
    new_configs = []
    for c in raw_configs:
        h = get_deep_hash(c)
        if h not in history:
            new_configs.append(c)
            # هش را موقتا در مموری اضافه می‌کنیم تا در یک ران هم تکراری نگیرد
            history.add(h) 
            
    total_new = len(new_configs)
    print(f"📊 Found {total_new} deeply unique configs. Testing...")
    
    active_results = []
    new_active_hashes = []
    processed_count = 0
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(process_config, conf, reader_country, reader_asn): conf for conf in new_configs}
        for future in as_completed(futures):
            processed_count += 1
            res = future.result()
            if res:
                active_results.append(res)
                new_active_hashes.append(res['hash']) # نگه داشتن هش‌های جدید برای فایل
                print(f"[{processed_count}/{total_new}] ✅ Active: {res['ip']} ({res['geo']['code']} - {res['geo']['isp']})")
            elif processed_count % 10 == 0 or processed_count == total_new:
                print(f"[{processed_count}/{total_new}] ⏳ Processing...")

    # فقط هش سرورهای فعال جدید به فایل اضافه می‌شود
    append_to_history(HISTORY_FILE, new_active_hashes)
    reader_country.close()
    reader_asn.close()
    
    print(f"\n🎯 Total Active Configs: {len(active_results)}")
    if not active_results:
        return
        
    print("🚀 Starting Telegram Publisher...")

    v2ray_configs = [c for c in active_results if c['type'] == 'V2RAY']
    for idx, c in enumerate(v2ray_configs, 1):
        geo = c['geo']
        security = c.get('security', 'NONE')
        
        msg = f"🛡 <b>Type:</b> #{c['type']}\n" \
              f"📍 <b>Location:</b> {geo['flag']} {geo['loc']}\n" \
              f"🏢 <b>Datacenter:</b> {geo['isp']}\n" \
              f"🔒 <b>Security:</b> {security}\n\n" \
              f"<blockquote><code>{c['config']}</code></blockquote>\n\n" \
              f"📡 @zVPN24"
              
        while True:
            try:
                bot.send_message(CHANNEL_V2RAY, msg, parse_mode='HTML')
                print(f"  👉 Posted V2Ray [{idx}/{len(v2ray_configs)}]")
                time.sleep(3.5)
                break
            except ApiTelegramException as e:
                if e.error_code == 429:
                    r = int(e.result_json['parameters']['retry_after'])
                    print(f"  ⚠️ Rate Limit! Sleep {r}s...")
                    time.sleep(r + 1)
                else: break
            except Exception: break

    mtproto_configs = [c for c in active_results if c['type'] == 'MTPROTO']
    chunks = [mtproto_configs[i:i+4] for i in range(0, len(mtproto_configs), 4)]
    
    for idx, chunk in enumerate(chunks, 1):
        markup = InlineKeyboardMarkup(row_width=2)
        buttons = [InlineKeyboardButton(text=f"Connect {c['geo']['flag']}", url=c['config']) for c in chunk]
        markup.add(*buttons)
        
        msg = "⚡️ <b>Fast & Active MTProto Proxies</b>\n\n👇 Click the buttons below to connect:\n\n🟢 @zProxy24"
        while True:
            try:
                bot.send_message(CHANNEL_MTPROTO, msg, reply_markup=markup, parse_mode='HTML')
                print(f"  👉 Posted MTProto Chunk [{idx}/{len(chunks)}]")
                time.sleep(3.5)
                break
            except ApiTelegramException as e:
                if e.error_code == 429:
                    r = int(e.result_json['parameters']['retry_after'])
                    print(f"  ⚠️ Rate Limit! Sleep {r}s...")
                    time.sleep(r + 1)
                else: break
            except Exception: break

    print("🎉 All operations completed successfully!")

if __name__ == "__main__":
    main()
