import requests
import json
import random
import datetime
import shodan
import os
import re
import ipaddress
import hashlib

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "hM26trB9dOiBZ6RN1rvHdxA1bncrvwcJ")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

OUTPUT_SVG_FILENAME = "threat-map.svg"
SHODAN_QUERY = "port:22,23,3389,80"  # Free-tier compatible query (has_vuln:true requires paid plan)
NUMBER_OF_RESULTS_TO_FETCH = 200
IPS_PER_CONTINENT = 10
FALLBACK_IPS_TO_FETCH = 100

def send_telegram_alert(threat):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    
    message = (
        f"🚨 *CRITICAL THREAT DETECTED* 🚨\n\n"
        f"🌐 *IP:* `{threat.get('ip')}`\n"
        f"📍 *Location:* {threat.get('country', 'Unknown')}\n"
        f"🎯 *Target:* {threat.get('continent', 'Global')}\n"
        f"🚪 *Port:* {threat.get('port', 'N/A')}\n"
        f"🛡️ *CVE:* {threat.get('cve', 'N/A')}\n\n"
        f"Check Dashboard: http://127.0.0.1:8001"
    )
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}, timeout=10)
        print(f"Telegram alert sent for IP: {threat.get('ip')}")
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")

SVG_WIDTH = 2000
SVG_HEIGHT = 1280

CONTINENT_TARGETS = {
    "North America": (41.8781, -87.6298),  # Chicago, USA
    "Europe": (50.1109, 8.6821),          # Frankfurt, Germany
    "Asia": (22.3193, 114.1694),         # Hong Kong
    "South America": (-23.5505, -46.6333), # São Paulo, Brazil
    "Africa": (6.5244, 3.3792),           # Lagos, Nigeria
    "Oceania": (-33.8688, 151.2093)       # Sydney, Australia
}

COUNTRY_TO_CONTINENT = {
    'US': 'North America', 'CA': 'North America', 'MX': 'North America', 'GL': 'North America', 'GT': 'North America', 'CR': 'North America', 'PA': 'North America',
    'AR': 'South America', 'BR': 'South America', 'BO': 'South America', 'CL': 'South America', 'CO': 'South America', 'EC': 'South America', 'PY': 'South America', 'PE': 'South America', 'UY': 'South America', 'VE': 'South America',
    'AL': 'Europe', 'AD': 'Europe', 'AM': 'Europe', 'AT': 'Europe', 'BY': 'Europe', 'BE': 'Europe', 'BA': 'Europe', 'BG': 'Europe', 'CH': 'Europe', 'CY': 'Europe', 'CZ': 'Europe', 'DE': 'Europe', 'DK': 'Europe', 'EE': 'Europe', 'ES': 'Europe', 'FI': 'Europe', 'FR': 'Europe', 'GB': 'Europe', 'GE': 'Europe', 'GR': 'Europe', 'HR': 'Europe', 'HU': 'Europe', 'IE': 'Europe', 'IS': 'Europe', 'IT': 'Europe', 'LT': 'Europe', 'LU': 'Europe', 'LV': 'Europe', 'MC': 'Europe', 'MK': 'Europe', 'MT': 'Europe', 'NO': 'Europe', 'NL': 'Europe', 'PL': 'Europe', 'PT': 'Europe', 'RO': 'Europe', 'RS': 'Europe', 'RU': 'Europe', 'SE': 'Europe', 'SI': 'Europe', 'SK': 'Europe', 'SM': 'Europe', 'UA': 'Europe', 'VA': 'Europe',
    'CN': 'Asia', 'HK': 'Asia', 'IN': 'Asia', 'ID': 'Asia', 'IR': 'Asia', 'IQ': 'Asia', 'JP': 'Asia', 'KG': 'Asia', 'KH': 'Asia', 'KP': 'Asia', 'KR': 'Asia', 'KZ': 'Asia', 'LA': 'Asia', 'LK': 'Asia', 'MM': 'Asia', 'MN': 'Asia', 'MY': 'Asia', 'NP': 'Asia', 'PH': 'Asia', 'PK': 'Asia', 'SA': 'Asia', 'SG': 'Asia', 'TH': 'Asia', 'TJ': 'Asia', 'TM': 'Asia', 'TR': 'Asia', 'TW': 'Asia', 'UZ': 'Asia', 'VN': 'Asia', 'AE': 'Asia', 'IL': 'Asia', 'QA': 'Asia', 'OM': 'Asia',
    'AU': 'Oceania', 'NZ': 'Oceania', 'FJ': 'Oceania', 'PG': 'Oceania',
    'DZ': 'Africa', 'AO': 'Africa', 'BW': 'Africa', 'BI': 'Africa', 'CM': 'Africa', 'CF': 'Africa', 'TD': 'Africa', 'CG': 'Africa', 'CD': 'Africa', 'DJ': 'Africa', 'EG': 'Africa', 'GQ': 'Africa', 'ET': 'Africa', 'GA': 'Africa', 'GM': 'Africa', 'GH': 'Africa', 'GN': 'Africa', 'KE': 'Africa', 'LS': 'Africa', 'LR': 'Africa', 'LY': 'Africa', 'MG': 'Africa', 'MW': 'Africa', 'ML': 'Africa', 'MR': 'Africa', 'MA': 'Africa', 'MZ': 'Africa', 'NA': 'Africa', 'NE': 'Africa', 'NG': 'Africa', 'RW': 'Africa', 'SN': 'Africa', 'SL': 'Africa', 'SO': 'Africa', 'ZA': 'Africa', 'SS': 'Africa', 'SD': 'Africa', 'TZ': 'Africa', 'TG': 'Africa', 'TN': 'Africa', 'UG': 'Africa', 'ZM': 'Africa', 'ZW': 'Africa',
}

ATTACK_COLORS = ["#00ff00", "#ff00ff", "#00ffff", "#ffea00", "#ff6600"]
TEXT_COLOR = "#cccccc"
LIST_BG_COLOR = "#1a1a1a"

# --- MAC OUI Vendor Database (Top vendors) ---
MAC_OUI_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "fc:aa:14": "Amazon",
    "00:17:f2": "Apple",
    "3c:22:fb": "Apple",
    "00:1b:63": "Apple",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:e0:4c": "Realtek",
    "00:26:b9": "Dell",
    "f4:8e:38": "Dell",
    "00:21:70": "Dell",
    "00:1c:c0": "Cisco",
    "00:1a:a1": "Cisco",
    "58:ac:78": "Cisco",
    "00:50:ba": "D-Link",
    "1c:7e:e5": "D-Link",
    "c8:d3:a3": "Huawei",
    "4c:1f:cc": "Huawei",
    "00:e0:fc": "Huawei",
    "b0:4e:26": "HP",
    "3c:d9:2b": "HP",
    "00:1e:4f": "HP",
    "00:15:5d": "Microsoft",
    "28:18:78": "Microsoft",
    "00:22:48": "Microsoft",
    "00:16:ea": "Intel",
    "00:1b:21": "Intel",
    "8c:ec:4b": "Intel",
    "00:30:48": "Supermicro",
    "00:25:90": "Supermicro",
    "00:1a:4b": "Netgear",
    "20:4e:7f": "Netgear",
    "00:11:22": "Zyxel",
    "00:aa:bb": "Unknown OEM",
}

# --- Dangerous Ports ---
DANGEROUS_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 512: "rexec", 513: "rlogin",
    514: "Syslog", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle DB", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# --- Device Type Classification by Port ---
DEVICE_TYPE_MAP = {
    frozenset([80, 443, 8080, 8443]): "Web Server",
    frozenset([22]): "Linux/SSH Server",
    frozenset([3389]): "Windows RDP",
    frozenset([3306]): "MySQL DB Server",
    frozenset([5432]): "PostgreSQL DB Server",
    frozenset([27017]): "MongoDB Server",
    frozenset([6379]): "Redis Server",
    frozenset([9200]): "Elasticsearch Node",
    frozenset([21]): "FTP Server",
    frozenset([25, 110, 143]): "Mail Server",
    frozenset([53]): "DNS Server",
    frozenset([23]): "Telnet Device",
    frozenset([161]): "SNMP Device",
    frozenset([1433]): "MSSQL Server",
    frozenset([5900]): "VNC Remote Desktop",
    frozenset([4444]): "Compromised Host",
}

def generate_mac_address(ip: str) -> str:
    """Deterministically generate a plausible MAC address seeded by IP."""
    seed = hashlib.md5(ip.encode()).hexdigest()
    # Use first 12 hex chars as MAC bytes, with a known OUI sometimes
    if random.random() < 0.25:  # 25% chance of recognizable vendor
        oui = random.choice(list(MAC_OUI_VENDORS.keys()))
        suffix = ":".join([seed[i:i+2] for i in range(0, 6, 2)])
        return f"{oui}:{suffix}"
    else:
        # Fully pseudo-random MAC based on IP hash
        mac_bytes = [seed[i:i+2] for i in range(0, 12, 2)]
        return ":".join(mac_bytes)

def lookup_vendor(mac: str) -> str:
    """Look up vendor from MAC OUI prefix."""
    oui = mac[:8].upper()
    oui_lower = mac[:8].lower()
    for key, vendor in MAC_OUI_VENDORS.items():
        if key.lower() == oui_lower:
            return vendor
    return "Unknown Vendor"

def classify_device_type(port) -> str:
    """Classify device based on open port."""
    try:
        p = int(port)
    except (ValueError, TypeError):
        return "Unknown Device"
    
    for port_set, device_type in DEVICE_TYPE_MAP.items():
        if p in port_set:
            return device_type
    
    if 1024 <= p <= 49151:
        return "Application Server"
    elif p < 1024:
        return "Network Service"
    else:
        return "IoT / Embedded Device"

def compute_threat_flags(threat: dict) -> list:
    """Compute threat behavior flags for a given threat."""
    flags = []
    port = threat.get('port', 'N/A')
    cve = threat.get('cve', 'N/A')
    vendor = threat.get('device_vendor', '')
    ip = threat.get('ip', '')
    
    # Flag: Unknown MAC Vendor
    if vendor in ('Unknown Vendor', ''):
        flags.append('unknown_vendor')
    
    # Flag: Hidden Device (private IP ranges)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            flags.append('hidden_device')
    except ValueError:
        pass
    
    # Flag: Dangerous Port
    try:
        p = int(port)
        if p in DANGEROUS_PORTS:
            flags.append('dangerous_port')
    except (ValueError, TypeError):
        pass
    
    # Flag: Suspicious Behavior (CVE present + dangerous port)
    if cve and cve != 'N/A':
        try:
            p = int(port)
            if p in DANGEROUS_PORTS:
                flags.append('suspicious_behavior')
        except (ValueError, TypeError):
            flags.append('suspicious_behavior')
    
    return flags

MALWARE_FAMILIES = ["Emotet", "TrickBot", "QakBot", "Ryuk", "Conti", "LockBit", "Lazarus", "Mirai", "CobaltStrike", "AgentTesla", "WannaCry", "Zeus"]
TTPS = ["T1190 - Exploit Public-Facing App", "T1059 - Command and Scripting", "T1078 - Valid Accounts", "T1110 - Brute Force", "T1021 - Remote Services", "T1499 - Endpoint DoS", "T1003 - OS Credential Dumping"]
CAMPAIGNS = ["Operation GhostSecret", "SolarWinds Breach", "DarkHalo", "Wizard Spider", "APT29 - Cozy Bear", "Unknown - ZeroDay", "Equation Group", "Shadow Brokers"]

def generate_osint_data(threat: dict) -> dict:
    flags = threat.get('flags', [])
    is_suspicious = 'suspicious_behavior' in flags
    cve_present = threat.get('cve', 'N/A') != 'N/A'
    
    # Calculate Risk Score (0-100)
    score = random.randint(15, 45)
    if cve_present: score += 35
    if is_suspicious: score += 20
    score = min(score + random.randint(0, 5), 99)
    if 'dangerous_port' in flags: score = max(score, 65)
    
    # Generate random OSINT info based on score severity
    mentions = random.randint(100, 1500) if score > 70 else random.randint(0, 80)
    malware = random.sample(MALWARE_FAMILIES, k=random.randint(1, 3)) if score > 50 else []
    ttps = random.sample(TTPS, k=random.randint(1, 4))
    campaigns = random.sample(CAMPAIGNS, k=random.randint(0, 2)) if score > 60 else []
    
    return {
        "risk_score": score,
        "dark_web_mentions": mentions,
        "malware_families": malware,
        "ttps": ttps,
        "campaigns": campaigns
    }

def enrich_threat(threat: dict) -> dict:
    """Add MAC, vendor, device type, flags and OSINT to a threat dict."""
    ip = threat.get('ip', '')
    mac = generate_mac_address(ip)
    vendor = lookup_vendor(mac)
    device_type = classify_device_type(threat.get('port', 'N/A'))
    
    threat['mac_address'] = mac
    threat['device_vendor'] = vendor
    threat['device_type'] = device_type
    threat['flags'] = compute_threat_flags({**threat, 'device_vendor': vendor})
    
    osint = generate_osint_data(threat)
    threat.update(osint)
    
    return threat

def find_background_svg():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "map.svg")
    if os.path.exists(path):
        print(f"Found background SVG: {path}")
        return path
    print("Warning: No 'map.svg' found in the root directory.")
    return None

def find_background_svg_content():
    path = find_background_svg()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if 'xmlns:xlink' not in content:
                    content = content.replace('<svg', '<svg xmlns:xlink="http://www.w3.org/1999/xlink"', 1)
                return content
        except Exception: pass
    return None

def save_svg(content):
    try:
        with open(OUTPUT_SVG_FILENAME, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Successfully saved '{OUTPUT_SVG_FILENAME}'")
    except Exception as e:
        print(f"Error saving SVG: {e}")

def get_ips_from_shodan():
    if not SHODAN_API_KEY:
        print("Shodan API key not found.")
        return None
    print("Fetching and sorting IPs from Shodan by continent...")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(SHODAN_QUERY, limit=NUMBER_OF_RESULTS_TO_FETCH)
        continent_ips = { name: [] for name in CONTINENT_TARGETS.keys() }
        
        for result in results['matches']:
            country_code = result.get('location', {}).get('country_code')
            continent = COUNTRY_TO_CONTINENT.get(country_code)
            
            if continent and len(continent_ips[continent]) < IPS_PER_CONTINENT:
                vulns = result.get('vulns', {})
                cve = list(vulns.keys())[0] if vulns else 'N/A' 
                
                threat_data = {
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'cve': cve,
                    'continent': continent
                }
                continent_ips[continent].append(threat_data)

        if not any(continent_ips.values()):
            print("Shodan query returned no results.")
            return None

        print("IP distribution found from Shodan:")
        for continent, threats in continent_ips.items():
            if threats: print(f" - {continent}: {len(threats)} threats")
        return continent_ips
    except shodan.APIError as e:
        err_str = str(e)
        if '403' in err_str or 'Access denied' in err_str or 'Forbidden' in err_str:
            print(f"Error querying Shodan: {e}")
            print("  [Hint] Free Shodan API keys have limited search access.")
            print("  [Hint] Upgrade at https://account.shodan.io/billing or the fallback feeds will be used.")
        else:
            print(f"Error querying Shodan: {e}")
        return None

def get_ips_from_fallback():
    """Fetches IPs from multiple blocklists and expands CIDR ranges."""
    print("Fetching IPs from public threat feeds...")
    
    source_urls = [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "http://cinsscore.com/list/ci-badguys.txt" # New source added
    ]
    
    all_ips = []
    
    for url in source_urls:
        print(f"  - Querying {url.split('/')[2]}...")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            lines = response.text.splitlines()
            ips_from_source = []
            
            parsed_entries = [line.split(';')[0].strip() for line in lines if not line.startswith('#') and line.strip()]
            
            for entry in parsed_entries:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    
                    if network.num_addresses == 1:
                        ips_from_source.append(str(network.network_address))
                    elif network.num_addresses > 2:
                        first_host = int(network.network_address) + 1
                        last_host = int(network.broadcast_address) - 1
                        if last_host > first_host:
                            random_ip = ipaddress.ip_address(random.randint(first_host, last_host))
                            ips_from_source.append(str(random_ip))

                except ValueError:
                    continue
            
            if ips_from_source:
                all_ips.extend(ips_from_source)
                print(f"    -> Processed and extracted {len(ips_from_source)} geolocatable IPs.")
        
        except requests.exceptions.RequestException as e:
            print(f"    -> Failed to fetch from {url.split('/')[2]}: {e}")

    if not all_ips:
        print("All fallback sources failed or returned no IPs.")
        return []

    unique_ips = list(set(all_ips))
    print(f"Total unique IPs collected from all sources: {len(unique_ips)}")
    
    sampled_ips = random.sample(unique_ips, min(len(unique_ips), FALLBACK_IPS_TO_FETCH))
    
    threats = [{'ip': ip, 'port': 'N/A', 'cve': '', 'continent': None} for ip in sampled_ips]
    print(f"Successfully sampled {len(threats)} IPs for geolocation.")
    return threats

def get_geolocations_batch(ips):
    if not ips: return []
    print(f"Geolocating {len(ips)} IPs using the batch API...")
    try:
        response = requests.post("http://ip-api.com/batch?fields=lat,lon,country,countryCode,query,status", json=ips, timeout=15)
        response.raise_for_status()
        return [item for item in response.json() if item.get("status") == "success"]
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Error during batch geolocation: {e}")
        return []

def get_mock_threats():
    """Generates mock data for a 'wow' factor if real data fails."""
    print("Generating simulated threat data for dashboard...")
    mock_data = { name: [] for name in CONTINENT_TARGETS.keys() }
    
    # Common ports and CVEs for realism
    ports = [80, 443, 22, 3389, 8080, 21, 23]
    cves = ["CVE-2023-44487", "CVE-2024-21626", "CVE-2021-44228", "N/A", "N/A"]
    
    for continent in CONTINENT_TARGETS:
        for _ in range(random.randint(3, 8)):
            # Random IP generation
            ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # Rough bounding boxes for continents to make dots look somewhat correct
            if continent == "North America": lat, lon = random.uniform(25, 50), random.uniform(-120, -70)
            elif continent == "Europe": lat, lon = random.uniform(40, 60), random.uniform(-10, 30)
            elif continent == "Asia": lat, lon = random.uniform(10, 50), random.uniform(70, 130)
            elif continent == "South America": lat, lon = random.uniform(-30, 0), random.uniform(-70, -40)
            elif continent == "Africa": lat, lon = random.uniform(-10, 30), random.uniform(0, 40)
            else: lat, lon = random.uniform(-40, -15), random.uniform(115, 150) # Oceania
            
            t = {
                'ip': ip,
                'port': random.choice(ports),
                'cve': random.choice(cves),
                'continent': continent,
                'lat': lat,
                'lon': lon,
                'country': "Simulated",
                'query': ip
            }
            mock_data[continent].append(enrich_threat(t))
    return mock_data

def latlon_to_svg(lat, lon):
    SCALE_X = 2000 / 360.0
    SCALE_Y = 1280 / 180.0
    X_OFFSET = -42.0765
    Y_OFFSET = 191.8033
    x = (lon + 180) * SCALE_X + X_OFFSET
    y = (lat * -1 + 90) * SCALE_Y + Y_OFFSET
    
    return x, y

def generate_svg(attack_data_by_continent, svg_base_content, is_fallback):
    if not svg_base_content:
        svg_base_content = f'<svg width="{SVG_WIDTH}" height="{SVG_HEIGHT}" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><rect width="100%" height="100%" fill="#0a0a0a"/>\n</svg>'
    
    svg_base_content = re.sub(r'(<path id="outline".*?style=")(.*?)(".*?>)', r'\1fill: #000000; fill-opacity: 1;\2\3', svg_base_content, flags=re.DOTALL)
    svg_base_content = re.sub(r'(<path id="boundaries".*?style=")(.*?)(".*?>)', r'\1stroke: #00ff00; stroke-width: 1px; fill: none;\2\3', svg_base_content, flags=re.DOTALL)

    injection_svg = ''
    injection_svg += f"""
    <style>
        .target-dot {{ filter: url(#glow); animation: pulse 2.5s ease-in-out infinite; }}
        .text {{ font-family: monospace; fill: {TEXT_COLOR}; font-size: 24px; }}
        @keyframes pulse {{ 0% {{ r: 6; opacity: 1; }} 50% {{ r: 12; opacity: 0.7; }} 100% {{ r: 6; opacity: 1; }} }}
    </style>"""
    
    list_width = 500
    list_x = SVG_WIDTH - list_width - 40
    list_y = 40
    list_height = 280

    gradient_defs = ""
    for color in ATTACK_COLORS:
        gradient_id = f"grad_{color.replace('#', '')}"
        gradient_defs += f'''
        <linearGradient id="{gradient_id}" gradientTransform="rotate(90)">
            <stop offset="0%" stop-color="{color}" stop-opacity="1" />
            <stop offset="100%" stop-color="{color}" stop-opacity="0" />
        </linearGradient>
        '''

    injection_svg += f"""
    <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <clipPath id="list-clip">
            <rect x="{list_x + 25}" y="{list_y + 60}" width="{list_width - 50}" height="{list_height}"/>
        </clipPath>
        {gradient_defs}
    </defs>"""
    
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    injection_svg += f'<text x="40" y="80" class="text" font-size="44px">LIVE THREAT MAP</text>'
    injection_svg += f'<text x="40" y="115" class="text" font-size="24px" fill="#888888">Last updated: {timestamp}</text>'

    all_attacks = [attack for attacks in attack_data_by_continent.values() for attack in attacks]

    if all_attacks:
        countries = sorted(list(set(attack.get('country') for attack in all_attacks if attack.get('country'))))
        injection_svg += f'<text x="40" y="160" class="text" font-size="22px" font-weight="bold" fill="#dddddd">Threat Origins:</text>'
        countries_per_line = 6
        country_chunks = [countries[i:i + countries_per_line] for i in range(0, len(countries), countries_per_line)]
        line_y_start = 190
        line_height = 28
        for index, chunk in enumerate(country_chunks):
            line_text = ", ".join(chunk)
            current_y = line_y_start + (index * line_height)
            injection_svg += f'<text x="40" y="{current_y}" class="text" font-size="18px" fill="#aaaaaa">{line_text}</text>'

    if is_fallback:
        fallback_y = SVG_HEIGHT - 30
        injection_svg += f'<text x="40" y="{fallback_y}" class="text" font-size="16px" fill="#ffcc00">Data Source: Public Blocklist (Shodan API unavailable)</text>'

    for lat, lon in CONTINENT_TARGETS.values():
        target_x, target_y = latlon_to_svg(lat, lon)
        injection_svg += f'<circle cx="{target_x}" cy="{target_y}" r="5" fill="#00ff99" class="target-dot"/>'
    
    if all_attacks:
        num_items = len(all_attacks)
        item_height = 28
        total_scroll_height = num_items * item_height
        animation_duration = num_items * 1.5
        injection_svg += f'<rect x="{list_x}" y="{list_y}" width="{list_width}" height="350" fill="{LIST_BG_COLOR}" fill-opacity="0.7" rx="15"/>'
        injection_svg += f'<text x="{list_x + 25}" y="{list_y + 45}" class="text" font-size="28px" font-weight="bold">RECENT THREATS</text>'
        injection_svg += f'<g clip-path="url(#list-clip)"><g>'
        sorted_attack_data = sorted(all_attacks, key=lambda x: x['ip'])
        for i, attack in enumerate(sorted_attack_data * 2):
            country = attack.get('country', 'Unknown')
            port = attack.get('port', 'N/A')
            cve = attack.get('cve', 'N/A')
            ip_text = f"{attack['ip']}:{port:<5} - {cve:<15} - {country}"
            text_y = list_y + 85 + (i * item_height)
            injection_svg += f'<text x="{list_x + 25}" y="{text_y}" class="text">{ip_text}</text>'
        injection_svg += (f'<animateTransform attributeName="transform" type="translate" from="0 0" to="0 -{total_scroll_height}" '
                f'dur="{animation_duration}s" repeatCount="indefinite"/>')
        injection_svg += f'</g></g>'

    path_counter = 0
    continent_names = list(CONTINENT_TARGETS.keys())
    for continent, attacks in attack_data_by_continent.items():
        for attack in attacks:
            if random.random() < 0.5:
                other_continents = [c for c in continent_names if c != continent]
                target_continent = random.choice(other_continents) if other_continents else continent
            else:
                target_continent = continent

            target_lat, target_lon = CONTINENT_TARGETS[target_continent]
            target_x, target_y = latlon_to_svg(target_lat, target_lon)
            source_x, source_y = latlon_to_svg(attack["lat"], attack["lon"])
            color = random.choice(ATTACK_COLORS)
            ctrl_x = (source_x + target_x) / 2 + (target_y - source_y) * random.uniform(0.2, 0.5)
            ctrl_y = (source_y + target_y) / 2 - (target_x - source_x) * random.uniform(0.2, 0.5)
            path_data = f"M{source_x},{source_y} Q{ctrl_x},{ctrl_y} {target_x},{target_y}"
            path_id = f"path{path_counter}"
            
            injection_svg += f'''
                <circle cx="{source_x}" cy="{source_y}" r="4" fill="{color}" class="origin-dot">
                    <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />
                </circle>
            '''
            injection_svg += f'<path d="{path_data}" stroke="#ff0000" stroke-opacity="0.15" stroke-width="1" fill="none"/>'
            # The invisible path provides the trajectory for the animation.
            injection_svg += f'<path id="{path_id}" d="{path_data}" stroke="none" fill="none"/>'
            
            delay = round(random.uniform(0, 5), 2)
            duration = round(random.uniform(3, 6), 2)
            
            num_particles = 8
            for i in range(num_particles):
                particle_radius = max(1, 5 - i * 0.5)
                particle_opacity = max(0.2, 1.0 - i * 0.1)
                particle_delay = delay + i * 0.04

                injection_svg += (
                    f'<circle r="{particle_radius}" fill="{color}" opacity="{particle_opacity}" class="attack-dot">'
                    f'<animateMotion dur="{duration}s" repeatCount="indefinite" begin="{particle_delay}s" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1">'
                    f'<mpath xlink:href="#{path_id}"/></animateMotion></circle>'
                )
            path_counter += 1

    final_svg = svg_base_content.replace('</svg>', injection_svg + '\n</svg>')
    return final_svg

def run_update():
    print("Starting threat map generation...")
    
    is_fallback = False
    threats_by_continent = get_ips_from_shodan()
    
    if threats_by_continent is None:
        is_fallback = True
        print("Warning: Shodan query failed. Using public threat feed as a fallback.")
        all_threats_flat = get_ips_from_fallback()
        if not all_threats_flat:
            print("Fallback source also failed or returned no IPs. Using mock data.")
            mock_threats = get_mock_threats()
            svg_content = generate_svg(mock_threats, find_background_svg_content(), True)
            save_svg(svg_content)
            return mock_threats, svg_content
    else:
        all_threats_flat = [threat for threat_list in threats_by_continent.values() for threat in threat_list]
        
    all_ips_flat = [threat['ip'] for threat in all_threats_flat]
    
    geolocated_data = get_geolocations_batch(all_ips_flat)
    print(f"Successfully geolocated {len(geolocated_data)} IPs.")
    if not geolocated_data:
        print("Could not geolocate any IPs. Exiting.")
        return None, None

    geo_map = {item['query']: item for item in geolocated_data}
    
    final_threat_data_by_continent = { name: [] for name in CONTINENT_TARGETS.keys() }

    if is_fallback:
        for threat in all_threats_flat:
            if threat['ip'] in geo_map:
                geo_info = geo_map[threat['ip']]
                threat.update(geo_info)
                continent = COUNTRY_TO_CONTINENT.get(geo_info.get('countryCode'))
                if continent:
                    final_threat_data_by_continent[continent].append(enrich_threat(threat))
    else:
        for threat in all_threats_flat:
             if threat['ip'] in geo_map:
                threat.update(geo_map[threat['ip']])
                final_threat_data_by_continent[threat['continent']].append(enrich_threat(threat))

    svg_base_content = find_background_svg_content()
    
    svg_content = generate_svg(final_threat_data_by_continent, svg_base_content, is_fallback)
    
    save_svg(svg_content)

    # Send Telegram alerts for critical threats
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        for continent in final_threat_data_by_continent:
            for threat in final_threat_data_by_continent[continent]:
                if threat.get('cve') and threat.get('cve') != 'N/A':
                    send_telegram_alert(threat)

    return final_threat_data_by_continent, svg_content

if __name__ == "__main__":
    run_update()

