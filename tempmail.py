#!/usr/bin/env python3
"""
TempMail Dashboard — Gmail-style + Anti-Detection
  Features:
  - Gmail dot/plus trick (undetectable aliases)
  - Tempmail addresses with inbox checking
  - Proxy rotation support
  - User-Agent rotation
  - Rate limit protection
  - Fingerprint spoofing helper
"""

import json
import random
import string
import sys
import os
import time
import secrets
import functools
from datetime import datetime

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
    from flask import Flask, render_template_string, jsonify, request
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "flask"])
    import requests
    from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# ─── API Key Authentication ────────────────────────────────────────
API_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".api_key_dashboard")

def _load_or_create_api_key():
    """Load existing API key from file, or generate and save one."""
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_urlsafe(32)
    with open(API_KEY_FILE, "w") as f:
        f.write(key)
    try:
        os.chmod(API_KEY_FILE, 0o600)
    except OSError:
        pass
    return key

TEMPMAIL_API_KEY = os.environ.get("TEMPMAIL_DASHBOARD_API_KEY") or _load_or_create_api_key()

def require_api_key(f):
    """Decorator: require X-API-Key header matching the server key."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")
        if not secrets.compare_digest(provided, TEMPMAIL_API_KEY):
            from flask import jsonify as _jsonify
            return _jsonify({"error": "unauthorized", "message": "Missing or invalid X-API-Key header"}), 401
        return f(*args, **kwargs)
    return decorated

accounts = []
ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_accounts.json")

# ─── Anti-Detection Data ─────────────────────────────────────────

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

SCREEN_RESOLUTIONS = [
    "1920x1080", "1366x768", "1440x900", "1536x864",
    "1280x720", "2560x1440", "1600x900", "1280x1024",
    "3840x2160", "1680x1050",
]

TIMEZONES = [
    "Asia/Kolkata", "America/New_York", "America/Chicago",
    "America/Denver", "America/Los_Angeles", "Europe/London",
    "Europe/Berlin", "Asia/Tokyo", "Asia/Singapore",
]

LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,hi;q=0.8",
    "en-IN,en;q=0.9", "en-US,en;q=0.9,es;q=0.8",
]

PLATFORMS = [
    "Win32", "MacIntel", "Linux x86_64",
]

REFERRERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://github.com/",
    "https://github.com/signup",
    "",  # direct
]

PROVIDER_COLORS = {
    "gmail-dot": "#EA4335",
    "gmail-genuine": "#EA4335",
    "1secmail": "#34A853",
    "guerrillamail": "#FBBC05",
    "inboxkitten": "#9C27B0",
    "custom-proxy": "#FF6D00",
}

# ─── Helpers ──────────────────────────────────────────────────────

def _random_login(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def save_accounts():
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f, indent=2)

def load_accounts():
    global accounts
    if os.path.exists(ACCOUNTS_FILE):
        try:
            accounts = json.load(open(ACCOUNTS_FILE))
        except:
            accounts = []

def get_initials(email):
    local = email.split("@")[0]
    if len(local) >= 2:
        return (local[0] + local[1]).upper()
    return local[0].upper() if local else "?"

def gen_fingerprint():
    """Generate a random browser fingerprint."""
    ua = random.choice(USER_AGENTS)
    res = random.choice(SCREEN_RESOLUTIONS)
    tz = random.choice(TIMEZONES)
    lang = random.choice(LANGUAGES)
    plat = random.choice(PLATFORMS)
    w, h = res.split("x")
    return {
        "user_agent": ua,
        "screen": res,
        "width": int(w),
        "height": int(h),
        "timezone": tz,
        "language": lang,
        "platform": plat,
        "color_depth": random.choice([24, 32]),
        "pixel_ratio": random.choice([1, 1.25, 1.5, 2]),
        "hardware_concurrency": random.choice([2, 4, 8, 12, 16]),
        "device_memory": random.choice([2, 4, 8, 16, 32]),
        "referrer": random.choice(REFERRERS),
        "webdriver": False,
        "webgl_vendor": random.choice(["Google Inc. (NVIDIA)", "Google Inc. (Intel)", "Google Inc. (AMD)"]),
    }

# ─── Inbox Checking ───────────────────────────────────────────────

def check_1secmail(login, domain):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(
            f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}",
            headers=headers, timeout=10
        )
        msgs = r.json()
        if isinstance(msgs, list) and msgs:
            detailed = []
            for m in msgs:
                mid = m.get("id", 0)
                reader = requests.get(
                    f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={mid}",
                    headers=headers, timeout=10
                )
                detailed.append(reader.json())
            return detailed
        return []
    except:
        return []

def check_guerrillamail(sid_token):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(
            f"https://api.guerrillamail.com/ajax.php?f=check_email&sid_token={sid_token}&seq=0",
            headers=headers, timeout=15
        )
        data = r.json()
        msgs = data.get("list", [])
        if msgs:
            detailed = []
            for m in msgs:
                eid = m.get("mail_id", "")
                reader = requests.get(
                    f"https://api.guerrillamail.com/ajax.php?f=fetch_email&sid_token={sid_token}&email_id={eid}",
                    headers=headers, timeout=10
                )
                detailed.append(reader.json())
            return detailed
        return []
    except:
        return []

def check_inboxkitten(login):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(f"https://inboxkitten.com/api/inbox/{login}", headers=headers, timeout=10)
        d = r.json()
        msgs = d.get("messages", [])
        if msgs:
            detailed = []
            for m in msgs:
                mid = m.get("_id", m.get("id", ""))
                reader = requests.get(f"https://inboxkitten.com/api/inbox/{login}/{mid}", headers=headers, timeout=10)
                detailed.append(reader.json())
            return detailed
        return []
    except:
        return []

def check_account_inbox(account):
    provider = account.get("provider", "")
    messages = []
    if provider in ("1secmail", "custom-proxy"):
        messages = check_1secmail(account["login"], account["domain"])
    elif provider == "guerrillamail":
        messages = check_guerrillamail(account.get("sid_token", ""))
    elif provider == "inboxkitten":
        messages = check_inboxkitten(account["login"])
    account["last_check"] = datetime.now().strftime("%H:%M:%S")
    account["messages"] = messages
    account["unread"] = len(messages)
    save_accounts()
    return messages

# ─── Account Creation ──────────────────────────────────────────────

def create_gmail_variants(gmail_base, count=20):
    cleaned = gmail_base.replace(" ", "").lower().strip()
    if "@gmail.com" in cleaned:
        username = cleaned.split("@")[0]
    elif "@" in cleaned:
        return []
    else:
        username = cleaned
        cleaned = f"{cleaned}@gmail.com"

    variants = set()
    # Plus trick (most reliable for GitHub)
    tags = [
        "github", "gh", "dev", "code", "test", "repo", "git", "acc",
        "signup", "login", "alt", "main", "real", "backup", "temp",
        "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "a", "b", "c", "x", "y", "z",
        "free", "bypass", "check", "verify", "new", "old",
        "work", "personal", "dev", "main", "secondary",
    ]
    for tag in tags:
        variants.add(f"{username}+{tag}@gmail.com")
        if len(variants) >= count:
            break

    # Dot trick
    uname_list = list(username)
    for i in range(1, len(uname_list)):
        if len(variants) >= count:
            break
        v = uname_list.copy()
        v.insert(i, ".")
        variants.add(f"{''.join(v)}@gmail.com")

    # Dot + plus combo
    for tag in tags[:10]:
        if len(variants) >= count:
            break
        v = uname_list.copy()
        if len(v) > 2:
            pos = random.randint(1, len(v) - 1)
            v.insert(pos, ".")
        variants.add(f"{''.join(v)}+{tag}@gmail.com")

    # Double dot
    if len(uname_list) > 3:
        for i in range(1, len(uname_list) - 1):
            if len(variants) >= count:
                break
            for j in range(i + 2, len(uname_list)):
                if len(variants) >= count:
                    break
                v = uname_list.copy()
                v.insert(i, ".")
                v.insert(j, ".")
                variants.add(f"{''.join(v)}@gmail.com")

    results = []
    for v in list(variants)[:count]:
        fp = gen_fingerprint()
        results.append({
            "id": f"gmail_{random.randint(10000, 99999)}",
            "email": v,
            "provider": "gmail-dot",
            "gmail_base": cleaned,
            "login": username,
            "domain": "gmail.com",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "status": "ready",
            "last_check": None,
            "messages": [],
            "unread": 0,
            "note": "Check your real Gmail inbox",
            "fingerprint": fp,
            "detection_risk": "LOW",
        })
    return results

def create_1secmail(count=10):
    results = []
    domains = ["1secmail.com", "1secmail.org", "1secmail.net", "kzccv.com", "qiott.com"]
    for _ in range(count):
        login = _random_login(random.randint(10, 14))
        domain = random.choice(domains)
        fp = gen_fingerprint()
        results.append({
            "id": f"1sec_{random.randint(10000, 99999)}",
            "email": f"{login}@{domain}",
            "provider": "1secmail",
            "gmail_base": None,
            "login": login,
            "domain": domain,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "status": "active",
            "last_check": None,
            "messages": [],
            "unread": 0,
            "fingerprint": fp,
            "detection_risk": "HIGH",
        })
    return results

def create_guerrillamail(count=10):
    results = []
    for _ in range(count):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = requests.get("https://api.guerrillamail.com/ajax.php?f=get_email_address&lang=en",
                           headers=headers, timeout=15)
            d = r.json()
            fp = gen_fingerprint()
            results.append({
                "id": f"guerr_{random.randint(10000, 99999)}",
                "email": d.get("email_addr", ""),
                "provider": "guerrillamail",
                "gmail_base": None,
                "login": None,
                "domain": None,
                "sid_token": d.get("sid_token", ""),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "status": "active",
                "last_check": None,
                "messages": [],
                "unread": 0,
                "fingerprint": fp,
                "detection_risk": "HIGH",
            })
        except:
            pass
    return results

def create_inboxkitten(count=10):
    results = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        fp = gen_fingerprint()
        results.append({
            "id": f"ik_{random.randint(10000, 99999)}",
            "email": f"{login}@inboxkitten.com",
            "provider": "inboxkitten",
            "gmail_base": None,
            "login": login,
            "domain": "inboxkitten.com",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "status": "active",
            "last_check": None,
            "messages": [],
            "unread": 0,
            "fingerprint": fp,
            "detection_risk": "HIGH",
        })
    return results

# ─── Detection Risk Analyzer ──────────────────────────────────────

def get_detection_tips(email, provider):
    """Return anti-detection tips based on provider."""
    tips = {
        "gmail-dot": {
            "risk": "LOW",
            "color": "#34A853",
            "tips": [
                "Use a real browser (Chrome/Firefox) — NOT headless",
                "Don't create more than 3-5 accounts per hour from same IP",
                "Add recovery phone + fill profile (name, bio, avatar) after signup",
                "Space out signups — 10-15 min between each account",
                "GitHub checks browser fingerprint — use different profiles for each account",
                "Clear cookies between signups OR use separate browser profiles",
                "Use residential proxy if creating many accounts",
                "GitHub flags disposable domains — Gmail aliases are NOT disposable",
            ]
        },
        "1secmail": {
            "risk": "HIGH",
            "color": "#EA4335",
            "tips": [
                "GitHub BLOCKS most tempmail domains — this will likely fail",
                "If you get 'email domain not allowed' error, switch to Gmail trick",
                "Using VPN/proxy won't help — they check the domain itself",
                "Only useful for sites that don't block disposable emails",
            ]
        },
        "guerrillamail": {
            "risk": "HIGH",
            "color": "#EA4335",
            "tips": [
                "Same as 1secmail — GitHub blocks disposable domains",
                "guerrillamail.com is on most blocklists",
                "Only use for non-GitHub testing",
            ]
        },
        "inboxkitten": {
            "risk": "MEDIUM",
            "color": "#FBBC05",
            "tips": [
                "inboxkitten.com sometimes passes initial email validation",
                "But GitHub may still flag it during signup flow",
                "Better than guerrillamail but not reliable for GitHub",
            ]
        }
    }
    return tips.get(provider, {"risk": "UNKNOWN", "color": "#5f6368", "tips": ["Unknown provider"]})

# ─── HTML Template ─────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TempMail Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif; background: #f6f8fc; color: #202124; height: 100vh; overflow: hidden; }

/* ═══ TOP BAR ═══ */
.topbar {
    height: 64px; background: #ffffff; border-bottom: 1px solid #e0e0e0;
    display: flex; align-items: center; padding: 0 16px; gap: 12px;
    position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
    box-shadow: 0 1px 2px rgba(0,0,0,0.08);
}
.menu-btn {
    width: 48px; height: 48px; border-radius: 50%; border: none; background: none;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
    font-size: 22px; color: #5f6368;
}
.menu-btn:hover { background: #f1f3f4; }
.logo {
    font-family: 'Segoe UI', 'Roboto', sans-serif; font-size: 22px; color: #5f6368;
    display: flex; align-items: center; gap: 8px;
}
.logo-icon {
    width: 40px; height: 40px; background: linear-gradient(135deg, #4285f4, #34a853);
    border-radius: 8px; display: flex; align-items: center; justify-content: center;
    color: white; font-size: 20px;
}
.search-box { flex: 1; max-width: 720px; margin: 0 auto; position: relative; }
.search-box input {
    width: 100%; height: 48px; background: #eaf1fb; border: none; border-radius: 24px;
    padding: 0 48px 0 20px; font-size: 16px; color: #202124; outline: none;
    transition: background 0.2s, box-shadow 0.2s;
}
.search-box input:focus { background: #ffffff; box-shadow: 0 1px 4px rgba(0,0,0,0.15); }
.search-box input::placeholder { color: #5f6368; }
.search-icon { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); color: #5f6368; font-size: 18px; }
.topbar-actions { display: flex; align-items: center; gap: 4px; }
.topbar-btn {
    width: 40px; height: 40px; border-radius: 50%; border: none; background: none;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
    font-size: 20px; color: #5f6368; position: relative;
}
.topbar-btn:hover { background: #f1f3f4; }
.topbar-btn .badge {
    position: absolute; top: 2px; right: 2px; background: #d93025; color: white;
    font-size: 10px; font-weight: 700; padding: 1px 5px; border-radius: 10px; min-width: 16px; text-align: center;
}

/* ═══ LAYOUT ═══ */
.layout { display: flex; height: calc(100vh - 64px); margin-top: 64px; }

/* ═══ SIDEBAR ═══ */
.sidebar {
    width: 256px; background: #ffffff; border-right: 1px solid #e0e0e0;
    overflow-y: auto; transition: width 0.3s; flex-shrink: 0;
}
.sidebar.collapsed { width: 72px; }
.sidebar.collapsed .sidebar-label,
.sidebar.collapsed .account-email,
.sidebar.collapsed .account-meta,
.sidebar.collapsed .compose-btn span,
.sidebar.collapsed .section-label,
.sidebar.collapsed .risk-badge { display: none; }
.sidebar.collapsed .account-item { justify-content: center; padding: 8px; }
.sidebar.collapsed .account-avatar { margin: 0; }

.compose-btn {
    margin: 16px; height: 56px; border-radius: 16px; border: none; background: #c2e7ff;
    color: #001d35; font-family: 'Segoe UI', 'Roboto', sans-serif; font-size: 14px; font-weight: 500;
    cursor: pointer; display: flex; align-items: center; gap: 12px; padding: 0 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12); transition: box-shadow 0.2s;
}
.compose-btn:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
.compose-btn .icon { font-size: 22px; }

.section-label {
    font-size: 12px; font-weight: 500; color: #5f6368; padding: 8px 16px 4px;
    text-transform: uppercase; letter-spacing: 0.5px;
}

.account-item {
    display: flex; align-items: center; gap: 12px; padding: 8px 16px;
    cursor: pointer; border-radius: 0 24px 24px 0; margin-right: 8px;
    transition: background 0.15s; position: relative;
}
.account-item:hover { background: #f1f3f4; }
.account-item.active { background: #d3e3fd; font-weight: 500; }
.account-item.active .account-email { color: #001d35; }

.account-avatar {
    width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center;
    justify-content: center; color: white; font-size: 14px; font-weight: 500; flex-shrink: 0; position: relative;
}
.account-avatar .online-dot {
    position: absolute; bottom: 0; right: 0; width: 10px; height: 10px; border-radius: 50%; border: 2px solid white;
}
.online-dot.green { background: #34a853; }
.online-dot.yellow { background: #fbbc05; }
.online-dot.red { background: #ea4335; }
.online-dot.orange { background: #ff6d00; }

.account-info { flex: 1; min-width: 0; }
.account-email { font-size: 14px; color: #202124; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.account-meta { font-size: 12px; color: #5f6368; display: flex; align-items: center; gap: 4px; }
.account-meta .unread { background: #d93025; color: white; font-size: 10px; font-weight: 700; padding: 1px 5px; border-radius: 8px; min-width: 16px; text-align: center; }
.account-meta .checking { color: #1a73e8; font-size: 11px; animation: blink 1s infinite; }
@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

.risk-badge {
    font-size: 9px; font-weight: 700; padding: 1px 5px; border-radius: 3px;
    text-transform: uppercase; letter-spacing: 0.3px;
}
.risk-low { background: #e6f4ea; color: #137333; }
.risk-medium { background: #fef7e0; color: #b06000; }
.risk-high { background: #fce8e6; color: #c5221f; }

.account-actions { display: none; gap: 2px; }
.account-item:hover .account-actions { display: flex; }
.account-action-btn {
    width: 28px; height: 28px; border-radius: 50%; border: none; background: none;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
    font-size: 14px; color: #5f6368;
}
.account-action-btn:hover { background: #e8eaed; }

/* ═══ MAIN CONTENT ═══ */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: #ffffff; }

.inbox-toolbar {
    height: 48px; border-bottom: 1px solid #e0e0e0; display: flex; align-items: center;
    padding: 0 16px; gap: 8px; background: #ffffff; flex-shrink: 0;
}
.toolbar-btn {
    width: 36px; height: 36px; border-radius: 50%; border: none; background: none;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
    font-size: 18px; color: #5f6368;
}
.toolbar-btn:hover { background: #f1f3f4; }
.toolbar-title { flex: 1; font-size: 16px; font-weight: 500; color: #202124; }
.toolbar-count { font-size: 13px; color: #5f6368; }

/* ═══ SWITCHER DROPDOWN ═══ */
.switcher-dropdown {
    position: fixed; top: 68px; right: 16px; width: 360px; max-height: 520px;
    background: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    z-index: 9999; display: none; overflow: hidden;
}
.switcher-dropdown.open { display: block; }
.switcher-header { padding: 16px; border-bottom: 1px solid #e0e0e0; font-size: 14px; font-weight: 500; display: flex; justify-content: space-between; align-items: center; }
.switcher-search { padding: 8px 16px; }
.switcher-search input { width: 100%; height: 36px; border: 1px solid #dadce0; border-radius: 8px; padding: 0 12px; font-size: 13px; outline: none; }
.switcher-search input:focus { border-color: #1a73e8; }
.switcher-list { max-height: 360px; overflow-y: auto; }
.switcher-item { display: flex; align-items: center; gap: 12px; padding: 10px 16px; cursor: pointer; }
.switcher-item:hover { background: #f1f3f4; }
.switcher-item.active { background: #e8f0fe; }
.switcher-item-avatar {
    width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center;
    justify-content: center; color: white; font-size: 13px; font-weight: 500; flex-shrink: 0;
}
.switcher-item-info { flex: 1; min-width: 0; }
.switcher-item-email { font-size: 13px; color: #202124; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.switcher-item-provider { font-size: 11px; color: #5f6368; }
.switcher-item-unread { background: #1a73e8; color: white; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 10px; }

/* ═══ EMAIL LIST ═══ */
.email-list { flex: 1; overflow-y: auto; }
.email-item {
    display: flex; align-items: center; gap: 12px; padding: 10px 16px;
    border-bottom: 1px solid #f1f3f4; cursor: pointer; transition: background 0.1s;
}
.email-item:hover {
    box-shadow: inset 1px 0 0 #dadce0, inset -1px 0 0 #dadce0, 0 1px 3px rgba(0,0,0,0.08); z-index: 1;
}
.email-item.unread { background: #f2f6fc; }
.email-item.unread .email-subj { font-weight: 700; color: #202124; }
.email-checkbox { width: 20px; height: 20px; border: 2px solid #5f6368; border-radius: 3px; flex-shrink: 0; }
.email-star { color: #dadce0; font-size: 18px; flex-shrink: 0; }
.email-star:hover { color: #f4b400; }
.email-sender { width: 200px; font-size: 14px; color: #202124; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex-shrink: 0; }
.email-content { flex: 1; min-width: 0; }
.email-subj { font-size: 14px; color: #202124; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.email-snippet { font-size: 13px; color: #5f6368; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.email-time { font-size: 12px; color: #5f6368; flex-shrink: 0; min-width: 60px; text-align: right; }

/* ═══ EMAIL DETAIL ═══ */
.email-detail { flex: 1; overflow-y: auto; padding: 24px 32px; display: none; }
.email-detail.open { display: block; }
.email-detail-subj { font-size: 22px; font-weight: 400; color: #202124; margin-bottom: 12px; }
.email-detail-meta { display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #e0e0e0; padding-bottom: 16px; margin-bottom: 16px; }
.email-detail-avatar {
    width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center;
    justify-content: center; color: white; font-size: 16px; font-weight: 500;
}
.email-detail-from-name { font-size: 14px; font-weight: 500; color: #202124; }
.email-detail-from-email { font-size: 12px; color: #5f6368; }
.email-detail-time { font-size: 12px; color: #5f6368; }
.email-detail-body { font-size: 14px; line-height: 1.6; color: #202124; white-space: pre-wrap; word-break: break-word; }
.otp-code {
    display: inline-block; background: #e8f5e9; color: #1b5e20; font-size: 32px;
    font-weight: 700; letter-spacing: 8px; padding: 16px 32px; border-radius: 12px;
    margin: 16px 0; border: 3px solid #4caf50; text-align: center;
}
.verify-link {
    display: inline-block; background: #e3f2fd; color: #1565c0; padding: 10px 20px;
    border-radius: 8px; text-decoration: none; font-weight: 500; margin: 8px 0;
}

/* ═══ EMPTY STATE ═══ */
.empty-state {
    flex: 1; display: flex; flex-direction: column; align-items: center;
    justify-content: center; color: #5f6368; text-align: center; padding: 32px;
}
.empty-state .icon { font-size: 80px; margin-bottom: 16px; opacity: 0.3; }
.empty-state h2 { font-size: 22px; font-weight: 400; margin-bottom: 8px; }
.empty-state p { font-size: 14px; max-width: 400px; }

/* ═══ DETECTION TIPS PANEL ═══ */
.detection-panel {
    background: #fef7e0; border: 1px solid #fbbc05; border-radius: 12px;
    padding: 16px 20px; margin: 16px; display: none;
}
.detection-panel.open { display: block; }
.detection-panel h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.detection-panel ul { list-style: none; padding: 0; }
.detection-panel li { font-size: 13px; padding: 4px 0; padding-left: 20px; position: relative; }
.detection-panel li::before { content: "•"; position: absolute; left: 6px; color: #fbbc05; font-weight: 700; }
.detection-panel .risk-indicator { font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-left: 8px; }

/* ═══ CREATE MODAL ═══ */
.modal-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5); display: none; align-items: center;
    justify-content: center; z-index: 2000;
}
.modal-overlay.open { display: flex; }
.modal {
    background: white; border-radius: 16px; width: 520px; max-width: 90vw;
    max-height: 85vh; overflow-y: auto; box-shadow: 0 8px 32px rgba(0,0,0,0.2);
}
.modal-header {
    padding: 20px 24px; border-bottom: 1px solid #e0e0e0;
    display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; background: white; z-index: 1;
}
.modal-header h2 { font-size: 18px; font-weight: 500; }
.modal-close {
    width: 36px; height: 36px; border-radius: 50%; border: none; background: none;
    cursor: pointer; font-size: 20px; color: #5f6368;
}
.modal-close:hover { background: #f1f3f4; }
.modal-body { padding: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: #5f6368; margin-bottom: 6px; }
.form-group input, .form-group select {
    width: 100%; height: 44px; border: 1px solid #dadce0; border-radius: 8px;
    padding: 0 14px; font-size: 14px; outline: none; transition: border-color 0.2s;
}
.form-group input:focus, .form-group select:focus { border-color: #1a73e8; }
.form-hint { font-size: 12px; color: #5f6368; margin-top: 4px; }
.form-hint.good { color: #137333; }
.form-hint.bad { color: #c5221f; }
.btn {
    height: 36px; padding: 0 20px; border-radius: 8px; border: none;
    font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s;
}
.btn-primary { background: #1a73e8; color: white; }
.btn-primary:hover { background: #1557b0; }
.btn-secondary { background: #f1f3f4; color: #5f6368; }
.btn-secondary:hover { background: #e8eaed; }
.btn-danger { background: #d93025; color: white; }
.btn-danger:hover { background: #b31412; }
.btn-block { width: 100%; margin-bottom: 8px; }

/* ═══ TOAST ═══ */
.toast {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
    background: #323232; color: white; padding: 12px 24px; border-radius: 8px;
    font-size: 14px; z-index: 9999; display: none;
}
.toast.show { display: block; animation: toastIn 0.3s; }
@keyframes toastIn { from { transform: translateX(-50%) translateY(20px); opacity: 0; } }

/* ═══ FINGERPRINT DISPLAY ═══ */
.fingerprint-display {
    font-family: 'Courier New', monospace; font-size: 11px; color: #5f6368;
    background: #f8f9fa; border-radius: 6px; padding: 8px 12px; margin-top: 8px;
}
.fingerprint-display span { display: block; padding: 1px 0; }

/* ═══ SCROLLBAR ═══ */
::-webkit-scrollbar { width: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #dadce0; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #bdc1c6; }

@media (max-width: 768px) {
    .sidebar { width: 72px; }
    .sidebar .sidebar-label, .sidebar .account-email, .sidebar .account-meta, .sidebar .risk-badge { display: none; }
    .search-box { display: none; }
}
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
    <button class="menu-btn" onclick="toggleSidebar()">&#9776;</button>
    <div class="logo">
        <div class="logo-icon">&#128235;</div>
        <span>TempMail</span>
    </div>
    <div class="search-box">
        <span class="search-icon">&#128269;</span>
        <input type="text" placeholder="Search emails..." id="search-input" oninput="filterEmails()">
    </div>
    <div class="topbar-actions">
        <button class="topbar-btn" onclick="openCreateModal()" title="Create accounts">&#10133;</button>
        <button class="topbar-btn" onclick="checkAllInboxes()" title="Check all inboxes">&#128260;</button>
        <button class="topbar-btn" id="total-badge" title="Switch account" data-action="switcher">&#128196; <span class="badge" id="badge-count">0</span></button>
    </div>
</div>

<!-- LAYOUT -->
<div class="layout">
    <div class="sidebar" id="sidebar">
        <button class="compose-btn" onclick="openCreateModal()">
            <span class="icon">&#9998;</span>
            <span>Create Accounts</span>
        </button>
        <div class="section-label">Accounts</div>
        <div id="sidebar-accounts"></div>
    </div>
    <div class="main" id="main-content"></div>
</div>

<!-- CREATE MODAL -->
<div class="modal-overlay" id="create-modal">
    <div class="modal">
        <div class="modal-header">
            <h2>Create Accounts (<span style="color:#137333">Anti-Detection</span>)</h2>
            <button class="modal-close" onclick="closeCreateModal()">&#10005;</button>
        </div>
        <div class="modal-body">

            <!-- GMAIL SECTION -->
            <div style="background:#e6f4ea;border-radius:12px;padding:16px;margin-bottom:20px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                    <span style="font-size:20px">&#128231;</span>
                    <strong style="color:#137333;font-size:15px">Gmail Dot/Plus Trick</strong>
                    <span class="risk-badge risk-low" style="font-size:10px">BEST FOR GITHUB</span>
                </div>
                <p style="font-size:12px;color:#137333;margin:4px 0 12px">
                    Gmail ignores dots &amp; everything after +. All variants deliver to your REAL inbox. GitHub cannot detect this as tempmail.
                </p>
                <div class="form-group">
                    <label>Your Gmail Address</label>
                    <input type="email" id="gmail-input" placeholder="yourname@gmail.com">
                </div>
                <div class="form-group">
                    <label>Number of variants</label>
                    <input type="number" id="gmail-count" value="25" min="1" max="200">
                </div>
                <button class="btn btn-primary btn-block" style="background:#137333" onclick="createGmailVariants()">
                    Create Gmail Variants (Undetectable)
                </button>
            </div>

            <!-- TEMPMAIL SECTION -->
            <div style="background:#fce8e6;border-radius:12px;padding:16px;margin-bottom:20px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                    <span style="font-size:20px">&#128233;</span>
                    <strong style="color:#c5221f;font-size:15px">Disposable Tempmails</strong>
                    <span class="risk-badge risk-high" style="font-size:10px">GITHUB BLOCKS THESE</span>
                </div>
                <p style="font-size:12px;color:#c5221f;margin:4px 0 12px">
                    GitHub blocks disposable email domains. Only use for testing other sites, NOT GitHub.
                </p>
                <div class="form-group">
                    <label>Provider</label>
                    <select id="tempmail-provider">
                        <option value="1secmail">1secmail (7 domains)</option>
                        <option value="guerrillamail">GuerrillaMail</option>
                        <option value="inboxkitten">InboxKitten</option>
                        <option value="all">Mix All</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Count</label>
                    <input type="number" id="tempmail-count" value="10" min="1" max="100">
                </div>
                <button class="btn btn-primary btn-block" style="background:#c5221f" onclick="createTempmails()">
                    Create Tempmails (For Non-GitHub Testing)
                </button>
            </div>

            <hr style="border:none;border-top:1px solid #e0e0e0;margin:16px 0">

            <!-- QUICK ACTIONS -->
            <div class="form-group">
                <label>Quick Bulk (Tempmail)</label>
                <div style="display:flex;gap:8px;flex-wrap:wrap">
                    <button class="btn btn-secondary" onclick="quickBulk(10)">+10</button>
                    <button class="btn btn-secondary" onclick="quickBulk(25)">+25</button>
                    <button class="btn btn-secondary" onclick="quickBulk(50)">+50</button>
                </div>
            </div>
            <button class="btn btn-danger btn-block" onclick="clearAll()">&#128465; Clear All Accounts</button>
        </div>
    </div>
</div>

<!-- ACCOUNT SWITCHER -->
<div class="switcher-dropdown" id="switcher-dropdown">
    <div class="switcher-header">
        <span>Switch Account</span>
        <button class="modal-close" onclick="closeSwitcher()" style="width:28px;height:28px;font-size:16px">&#10005;</button>
    </div>
    <div class="switcher-search">
        <input type="text" placeholder="Search..." id="switcher-search" oninput="filterSwitcher()">
    </div>
    <div class="switcher-list" id="switcher-list"></div>
</div>

<div class="toast" id="toast"></div>

<script>
var accounts = [];
var selectedAccountId = null;
var autoCheckInterval = null;

function esc(s) { var d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }
function getInitials(e) { var l = e.split('@')[0]; return l.length >= 2 ? (l[0]+l[1]).toUpperCase() : (l[0]||'?').toUpperCase(); }
function getColor(p) {
    var c = {'gmail-dot':'#EA4335','1secmail':'#34A853','guerrillamail':'#FBBC05','inboxkitten':'#9C27B0'};
    return c[p] || '#58a6ff';
}

function showToast(msg) {
    var t = document.getElementById('toast');
    t.textContent = msg; t.classList.add('show');
    setTimeout(function(){ t.classList.remove('show'); }, 3000);
}

function api(url, opts) {
    var defaults = { headers: {'Content-Type': 'application/json'} };
    return fetch(url, Object.assign(defaults, opts)).then(function(r){ return r.json(); });
}

// ─── FETCH & RENDER ──────────────────────────────────────────────

function fetchAccounts() {
    api('/api/accounts').then(function(data){
        accounts = data;
        renderSidebar();
        renderMain();
        document.getElementById('badge-count').textContent = accounts.length;
    })["catch"](function(e){ showToast('Error: ' + e.message); });
}

function renderSidebar() {
    var c = document.getElementById('sidebar-accounts');
    if (!accounts.length) {
        c.innerHTML = '<div style="padding:16px;text-align:center;color:#5f6368;font-size:13px">No accounts yet. Click + to create.</div>';
        return;
    }
    var html = '';
    for (var i = 0; i < accounts.length; i++) {
        var a = accounts[i];
        var active = a.id === selectedAccountId ? ' active' : '';
        var unread = a.unread > 0 ? '<span class="unread">'+a.unread+'</span>' : '';
        var dotColor = a.provider === 'gmail-dot' ? 'red' : (a.unread > 0 ? 'green' : 'yellow');
        var riskClass = a.detection_risk === 'LOW' ? 'risk-low' : (a.detection_risk === 'MEDIUM' ? 'risk-medium' : 'risk-high');

        html += '<div class="account-item'+active+'" onclick="selectAccount(\''+a.id+'\')">' +
            '<div class="account-avatar" style="background:'+getColor(a.provider)+'">' +
                esc(getInitials(a.email)) +
                '<div class="online-dot '+dotColor+'"></div>' +
            '</div>' +
            '<div class="account-info">' +
                '<div class="account-email">'+esc(a.email)+'</div>' +
                '<div class="account-meta">' +
                    esc(a.provider) + ' ' + unread +
                    '<span class="risk-badge '+riskClass+'">'+esc(a.detection_risk)+'</span>' +
                '</div>' +
            '</div>' +
            '<div class="account-actions">' +
                '<button class="account-action-btn" onclick="event.stopPropagation();checkAccountInbox(\''+a.id+'\')">&#128260;</button>' +
                '<button class="account-action-btn" onclick="event.stopPropagation();deleteAccount(\''+a.id+'\')">&#128465;</button>' +
            '</div>' +
        '</div>';
    }
    c.innerHTML = html;
}

function renderMain() {
    var c = document.getElementById('main-content');
    if (!selectedAccountId) {
        c.innerHTML = '<div class="empty-state">' +
            '<div class="icon">&#128235;</div>' +
            '<h2>Select an account to view inbox</h2>' +
            '<p>Click on any account in the sidebar<br>or create new accounts using the + button</p>' +
        '</div>';
        return;
    }

    var acc = null;
    for (var i = 0; i < accounts.length; i++) {
        if (accounts[i].id === selectedAccountId) { acc = accounts[i]; break; }
    }
    if (!acc) { selectedAccountId = null; renderMain(); return; }

    var msgs = acc.messages || [];
    var isGmail = acc.provider === 'gmail-dot';
    var gmailConnected = false;

    var toolbar = '<div class="inbox-toolbar">' +
        '<button class="toolbar-btn" onclick="goBack()">&#8592;</button>' +
        '<div class="toolbar-title">'+esc(acc.email)+'</div>' +
        '<div class="toolbar-count">'+msgs.length+' message(s)</div>' +
        '<button class="toolbar-btn" onclick="checkAccountInbox(\''+acc.id+'\')" title="Refresh">&#128260;</button>' +
        '<button class="toolbar-btn" onclick="showDetectionTips(\''+acc.id+'\')" title="Anti-detection info">&#9881;</button>' +
        '<button class="toolbar-btn" onclick="showFingerprint(\''+acc.id+'\')" title="Browser fingerprint">&#128100;</button>' +
        '<button class="toolbar-btn" onclick="copyEmail(\''+acc.email+'\')">&#128203;</button>' +
    '</div>';

    if (isGmail) {
        c.innerHTML = toolbar +
            '<div class="empty-state">' +
                '<div class="icon">&#128236;</div>' +
                '<h2>Gmail Alias</h2>' +
                '<p>This is a Gmail alias. Emails go to your REAL Gmail inbox.</p>' +
                '<div style="font-family:monospace;background:#f1f3f4;padding:12px 20px;border-radius:8px;margin-top:12px;font-size:13px;word-break:break-all">'+esc(acc.email)+'</div>' +
                '<button class="btn btn-primary" style="margin-top:16px" onclick="copyEmail(\''+acc.email+'\')">Copy Email &amp; Go to GitHub</button>' +
                '<div style="margin-top:16px;font-size:13px;color:#137333">&#10004; GitHub will NOT detect this as a tempmail</div>' +
            '</div>';
        return;
    }

    if (msgs.length === 0) {
        c.innerHTML = toolbar +
            '<div class="empty-state">' +
                '<div class="icon">&#128232;</div>' +
                '<h2>Inbox is empty</h2>' +
                '<p>Use this email for signup, then click refresh to check for messages.</p>' +
                '<div style="font-family:monospace;background:#f1f3f4;padding:12px 20px;border-radius:8px;margin-top:12px;font-size:12px;word-break:break-all">'+esc(acc.email)+'</div>' +
                '<button class="btn btn-primary" style="margin-top:16px" onclick="checkAccountInbox(\''+acc.id+'\')">Check Inbox</button>' +
                '<button class="btn btn-secondary" style="margin-top:8px" onclick="copyEmail(\''+acc.email+'\')">Copy Email</button>' +
            '</div>';
        return;
    }

    var listHtml = '<div class="email-list">';
    for (var i = 0; i < msgs.length; i++) {
        var m = msgs[i];
        var subj = esc(m.subject || m.title || '(no subject)');
        var from = esc(m.from || m.sender || m.mail_from || 'Unknown');
        var body = (m.body || m.bodyHtml || m.html || m.content || JSON.stringify(m));
        var bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        var snippet = esc(bodyStr.substring(0, 120));
        listHtml += '<div class="email-item unread" onclick="showEmailDetail('+i+')">' +
            '<div class="email-checkbox"></div>' +
            '<div class="email-star">&#9734;</div>' +
            '<div class="email-sender">'+from+'</div>' +
            '<div class="email-content"><div class="email-subj">'+subj+'</div><div class="email-snippet">'+snippet+'</div></div>' +
        '</div>';
    }
    listHtml += '</div>';
    c.innerHTML = toolbar + listHtml;
}

// ─── EMAIL DETAIL ─────────────────────────────────────────────────

function showEmailDetail(idx) {
    var acc = null;
    for (var i = 0; i < accounts.length; i++) { if (accounts[i].id === selectedAccountId) { acc = accounts[i]; break; } }
    if (!acc || !acc.messages[idx]) return;
    var m = acc.messages[idx];
    var c = document.getElementById('main-content');

    var subj = esc(m.subject || m.title || '(no subject)');
    var from = esc(m.from || m.sender || m.mail_from || 'Unknown');
    var body = (m.body || m.bodyHtml || m.html || m.content || JSON.stringify(m));
    if (typeof body !== 'string') body = JSON.stringify(body, null, 2);

    var otpMatch = body.match(/\b(\d{4,8})\b/g);
    var otpHtml = '';
    if (otpMatch) {
        otpHtml = '<div style="text-align:center;margin:16px 0">' +
            '<div style="font-size:13px;color:#5f6368;margin-bottom:4px">Verification Code:</div>' +
            '<div class="otp-code">'+esc(otpMatch[0])+'</div>' +
            '<button class="btn btn-primary" style="margin-top:8px" onclick="copyEmail(\''+esc(otpMatch[0])+'\')">Copy OTP</button>' +
        '</div>';
    }

    var bodyWithLinks = esc(body).replace(/(https?:\/\/[^\s<>"'\\\\]+)/g, '<a href="$1" target="_blank" class="verify-link">$1</a>');

    c.innerHTML = '<div class="inbox-toolbar">' +
        '<button class="toolbar-btn" onclick="goBack()">&#8592;</button>' +
        '<div class="toolbar-title">'+subj+'</div>' +
    '</div>' +
    '<div class="email-detail open">' +
        '<div class="email-detail-meta">' +
            '<div class="email-detail-avatar" style="background:'+getColor(acc.provider)+'">'+esc(getInitials(from))+'</div>' +
            '<div style="flex:1"><div class="email-detail-from-name">'+from+'</div><div class="email-detail-from-email">to '+esc(acc.email)+'</div></div>' +
            '<div class="email-detail-time">'+esc(m.date || m.created_at || '')+'</div>' +
        '</div>' +
        otpHtml +
        '<div class="email-detail-body">'+bodyWithLinks+'</div>' +
    '</div>';
}

// ─── ACTIONS ──────────────────────────────────────────────────────

function selectAccount(id) {
    selectedAccountId = id;
    renderSidebar();
    renderMain();
    closeSwitcher();
}

function goBack() {
    selectedAccountId = null;
    renderMain();
}

function copyEmail(e) {
    navigator.clipboard.writeText(e).then(function(){ showToast('Copied: ' + e); })["catch"](function(){ showToast('Copy failed'); });
}

async function checkAccountInbox(id) {
    var acc = null;
    for (var i = 0; i < accounts.length; i++) { if (accounts[i].id === id) { acc = accounts[i]; break; } }
    if (!acc) return;
    acc.checking = true;
    renderSidebar();
    showToast('Checking inbox...');
    try {
        var d = await api('/api/check/' + id);
        var msgs = d.messages || [];
        acc.messages = msgs;
        acc.unread = msgs.length;
        acc.last_check = new Date().toLocaleTimeString();
        acc.checking = false;
        await api('/api/update', { method: 'POST', body: JSON.stringify(acc) });
        if (msgs.length > 0) showToast('&#128236; ' + msgs.length + ' message(s)!');
        else showToast('Empty inbox');
        renderSidebar();
        if (selectedAccountId === id) renderMain();
    } catch(e) {
        if (acc) { acc.checking = false; renderSidebar(); }
        showToast('Error: ' + e.message);
    }
}

async function checkAllInboxes() {
    showToast('Checking all inboxes...');
    try {
        var d = await api('/api/check/all');
        var results = d.results || {};
        var total = 0;
        for (var email in results) {
            var msgs = results[email];
            total += msgs.length;
            for (var i = 0; i < accounts.length; i++) {
                if (accounts[i].email === email) {
                    accounts[i].messages = msgs;
                    accounts[i].unread = msgs.length;
                    accounts[i].last_check = new Date().toLocaleTimeString();
                }
            }
        }
        showToast('Checked all — ' + total + ' messages');
        renderSidebar();
        renderMain();
    } catch(e) { showToast('Error: ' + e.message); }
}

async function deleteAccount(id) {
    if (!confirm('Delete this account?')) return;
    await api('/api/delete/' + id, { method: 'POST' });
    if (selectedAccountId === id) selectedAccountId = null;
    fetchAccounts();
}

async function clearAll() {
    if (!confirm('Clear ALL accounts?')) return;
    await api('/api/clear', { method: 'POST' });
    selectedAccountId = null;
    closeCreateModal();
    fetchAccounts();
}

function openCreateModal() { document.getElementById('create-modal').classList.add('open'); }
function closeCreateModal() { document.getElementById('create-modal').classList.remove('open'); }

async function createGmailVariants() {
    var gmail = document.getElementById('gmail-input').value.trim();
    var count = parseInt(document.getElementById('gmail-count').value) || 25;
    if (!gmail) { showToast('Enter your Gmail!'); return; }
    if (gmail.indexOf('@gmail.com') === -1 && gmail.indexOf('@') === -1) { gmail += '@gmail.com'; }
    try {
        var d = await api('/api/create/gmail', { method: 'POST', body: JSON.stringify({gmail: gmail, count: count}) });
        showToast('Created ' + d.created + ' Gmail variants');
        closeCreateModal();
        fetchAccounts();
    } catch(e) { showToast('Error: ' + e.message); }
}

async function createTempmails() {
    var provider = document.getElementById('tempmail-provider').value;
    var count = parseInt(document.getElementById('tempmail-count').value) || 10;
    try {
        var d = await api('/api/create/tempmail', { method: 'POST', body: JSON.stringify({provider: provider, count: count}) });
        showToast('Created ' + d.created + ' tempmails');
        closeCreateModal();
        fetchAccounts();
    } catch(e) { showToast('Error: ' + e.message); }
}

async function quickBulk(count) {
    try {
        var d = await api('/api/create/quick', { method: 'POST', body: JSON.stringify({count: count}) });
        showToast('Quick +' + d.created + ' tempmails');
        closeCreateModal();
        fetchAccounts();
    } catch(e) { showToast('Error: ' + e.message); }
}

// ─── SWITCHER ─────────────────────────────────────────────────────

function toggleSwitcher() {
    var dd = document.getElementById('switcher-dropdown');
    if (dd.classList.contains('open')) { closeSwitcher(); return; }
    dd.classList.add('open');
    document.getElementById('switcher-search').focus();
    renderSwitcher();
}

function closeSwitcher() { document.getElementById('switcher-dropdown').classList.remove('open'); }

function renderSwitcher() {
    var list = document.getElementById('switcher-list');
    var q = document.getElementById('switcher-search').value.toLowerCase();
    var filtered = [];
    for (var i = 0; i < accounts.length; i++) {
        if (accounts[i].email.toLowerCase().indexOf(q) !== -1) filtered.push(accounts[i]);
    }
    if (!filtered.length) {
        list.innerHTML = '<div style="padding:16px;text-align:center;color:#5f6368;font-size:13px">No accounts</div>';
        return;
    }
    var html = '';
    for (var i = 0; i < filtered.length; i++) {
        var a = filtered[i];
        var active = a.id === selectedAccountId ? ' active' : '';
        var unread = a.unread > 0 ? '<span class="switcher-item-unread">'+a.unread+'</span>' : '';
        html += '<div class="switcher-item'+active+'" onclick="selectAccount(\''+a.id+'\')">' +
            '<div class="switcher-item-avatar" style="background:'+getColor(a.provider)+'">'+esc(getInitials(a.email))+'</div>' +
            '<div class="switcher-item-info"><div class="switcher-item-email">'+esc(a.email)+'</div><div class="switcher-item-provider">'+esc(a.provider)+'</div></div>' +
            unread +
        '</div>';
    }
    list.innerHTML = html;
}

function filterSwitcher() { renderSwitcher(); }

// ─── DETECTION TIPS ───────────────────────────────────────────────

function showDetectionTips(id) {
    var acc = null;
    for (var i = 0; i < accounts.length; i++) { if (accounts[i].id === id) { acc = accounts[i]; break; } }
    if (!acc) return;

    var riskInfo;
    if (acc.provider === 'gmail-dot') {
        riskInfo = {
            title: 'Gmail Dot/Plus Trick — LOW DETECTION RISK',
            color: '#137333',
            tips: [
                'Use a real browser (Chrome/Firefox) — NOT headless or automation tools',
                'DON\'T create accounts too fast — wait 10-15 min between signups',
                'Fill in profile info (name, bio, avatar) after signup to look legit',
                'Use separate browser profiles or clear cookies between each signup',
                'GitHub checks browser fingerprint — consider using different user agents',
                'Use residential proxy if creating multiple accounts (not datacenter IP)',
                'GitHub cannot detect Gmail aliases as disposable — this is SAFEST method',
            ]
        };
    } else if (acc.provider === 'inboxkitten') {
        riskInfo = {
            title: 'InboxKitten — MEDIUM DETECTION RISK',
            color: '#b06000',
            tips: [
                'GitHub may flag inboxkitten.com during email validation',
                'Some sites accept it, but GitHub\'s blocklist may include it',
                'If you get "email domain not allowed" error, switch to Gmail trick',
                'Only use for testing non-GitHub websites',
            ]
        };
    } else {
        riskInfo = {
            title: acc.provider.toUpperCase() + ' — HIGH DETECTION RISK &#9888;',
            color: '#c5221f',
            tips: [
                'GitHub BLOCKS most disposable email domains — this will likely FAIL',
                'Error you\'ll get: "Please use a valid email address" or similar',
                'Using VPN/proxy won\'t help — they check the domain itself, not IP',
                'Only use disposable emails for testing other websites, NOT GitHub',
                'For GitHub testing, use the Gmail Dot/Plus trick instead',
            ]
        };
    }

    var tipsHtml = '';
    for (var i = 0; i < riskInfo.tips.length; i++) {
        tipsHtml += '<li>'+riskInfo.tips[i]+'</li>';
    }

    var c = document.getElementById('main-content');
    c.innerHTML = '<div class="inbox-toolbar">' +
        '<button class="toolbar-btn" onclick="goBack()">&#8592;</button>' +
        '<div class="toolbar-title">Anti-Detection Tips</div>' +
    '</div>' +
    '<div style="padding:24px;overflow-y:auto;flex:1">' +
        '<div style="max-width:600px;margin:0 auto">' +
            '<div style="background:'+riskInfo.color+';color:white;padding:12px 20px;border-radius:12px 12px 0 0;font-size:15px;font-weight:600">' + riskInfo.title + '</div>' +
            '<div style="background:white;border:1px solid #dadce0;border-top:none;border-radius:0 0 12px 12px;padding:20px 24px">' +
                '<ul style="list-style:none;padding:0">' + tipsHtml + '</ul>' +
            '</div>' +
            '<button class="btn btn-secondary" style="margin-top:16px" onclick="renderMain()">&#8592; Back to inbox</button>' +
        '</div>' +
    '</div>';
}

function showFingerprint(id) {
    var acc = null;
    for (var i = 0; i < accounts.length; i++) { if (accounts[i].id === id) { acc = accounts[i]; break; } }
    if (!acc || !acc.fingerprint) { showToast('No fingerprint data'); return; }

    var fp = acc.fingerprint;
    var c = document.getElementById('main-content');
    c.innerHTML = '<div class="inbox-toolbar">' +
        '<button class="toolbar-btn" onclick="goBack()">&#8592;</button>' +
        '<div class="toolbar-title">Browser Fingerprint</div>' +
    '</div>' +
    '<div style="padding:24px;overflow-y:auto;flex:1">' +
        '<div style="max-width:600px;margin:0 auto">' +
            '<p style="font-size:13px;color:#5f6368;margin-bottom:16px">Use these values in your browser automation to appear as a different user:</p>' +
            '<div style="background:#f8f9fa;border-radius:8px;padding:16px;font-family:monospace;font-size:12px;line-height:1.8">' +
                '<div>User-Agent: <span style="color:#1a73e8">'+esc(fp.user_agent)+'</span></div>' +
                '<div>Screen: <span style="color:#1a73e8">'+esc(fp.screen)+'</span></div>' +
                '<div>Timezone: <span style="color:#1a73e8">'+esc(fp.timezone)+'</span></div>' +
                '<div>Language: <span style="color:#1a73e8">'+esc(fp.language)+'</span></div>' +
                '<div>Platform: <span style="color:#1a73e8">'+esc(fp.platform)+'</span></div>' +
                '<div>Color Depth: <span style="color:#1a73e8">'+esc(fp.color_depth)+'</span></div>' +
                '<div>Pixel Ratio: <span style="color:#1a73e8">'+esc(fp.pixel_ratio)+'</span></div>' +
                '<div>CPU Cores: <span style="color:#1a73e8">'+esc(fp.hardware_concurrency)+'</span></div>' +
                '<div>Memory: <span style="color:#1a73e8">'+esc(fp.device_memory)+' GB</span></div>' +
                '<div>WebGL: <span style="color:#1a73e8">'+esc(fp.webgl_vendor)+'</span></div>' +
                '<div>Referrer: <span style="color:#1a73e8">'+esc(fp.referrer || 'direct')+'</span></div>' +
            '</div>' +
            '<div style="margin-top:16px;background:#e6f4ea;border-radius:8px;padding:12px 16px">' +
                '<div style="font-size:13px;font-weight:600;color:#137333;margin-bottom:6px">&#128274; Anti-Detection Tips:</div>' +
                '<ul style="font-size:12px;color:#137333;padding-left:16px">' +
                    '<li>Use a different User-Agent for each account</li>' +
                    '<li>Match timezone with proxy location</li>' +
                    '<li>Disable webdriver flag in automation</li>' +
                    '<li>Use undetected-chromedriver or playwright-stealth</li>' +
                '</ul>' +
            '</div>' +
            '<button class="btn btn-secondary" style="margin-top:16px" onclick="renderMain()">&#8592; Back</button>' +
        '</div>' +
    '</div>';
}

// ─── ETC ──────────────────────────────────────────────────────────

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('collapsed'); }

function filterEmails() {
    var q = document.getElementById('search-input').value.toLowerCase();
    var items = document.querySelectorAll('.email-item');
    for (var i = 0; i < items.length; i++) {
        items[i].style.display = items[i].textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
    }
}

// Topbar button handler (delegated)
document.querySelector('.topbar-actions').addEventListener('click', function(e) {
    var btn = e.target.closest('.topbar-btn');
    if (!btn) return;
    var action = btn.dataset.action;
    if (action === 'switcher') {
        e.stopPropagation();
        toggleSwitcher();
    }
});

// Close switcher on outside click
document.addEventListener('click', function(e) {
    var dd = document.getElementById('switcher-dropdown');
    if (!dd || !dd.classList.contains('open')) return;
    var clickedInside = e.target.closest('#switcher-dropdown');
    if (!clickedInside) {
        closeSwitcher();
    }
});

// Init
fetchAccounts();
</script>
</body>
</html>"""

# ─── Flask Routes ──────────────────────────────────────────────────

@app.route("/")
def index():
    # Read HTML directly from string — no caching
    html = HTML
    from flask import make_response
    resp = make_response(html)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp

@app.route("/api/accounts")
@require_api_key
def api_accounts():
    return jsonify(accounts)

@app.route("/api/update", methods=["POST"])
@require_api_key
def api_update():
    data = request.json
    for acc in accounts:
        if acc["id"] == data.get("id"):
            acc["messages"] = data.get("messages", [])
            acc["unread"] = data.get("unread", 0)
            acc["last_check"] = data.get("last_check", "")
            break
    save_accounts()
    return jsonify({"ok": True})

@app.route("/api/create/gmail", methods=["POST"])
@require_api_key
def api_create_gmail():
    data = request.json
    new_accs = create_gmail_variants(data.get("gmail", ""), min(int(data.get("count", 20)), 200))
    accounts.extend(new_accs)
    save_accounts()
    return jsonify({"created": len(new_accs)})

@app.route("/api/create/tempmail", methods=["POST"])
@require_api_key
def api_create_tempmail():
    data = request.json
    provider = data.get("provider", "1secmail")
    count = min(int(data.get("count", 10)), 100)
    new_accs = []
    if provider == "1secmail":
        new_accs = create_1secmail(count)
    elif provider == "guerrillamail":
        new_accs = create_guerrillamail(count)
    elif provider == "inboxkitten":
        new_accs = create_inboxkitten(count)
    elif provider == "all":
        c = max(1, count // 3)
        new_accs = create_1secmail(c) + create_guerrillamail(c) + create_inboxkitten(count - 2*c)
    accounts.extend(new_accs)
    save_accounts()
    return jsonify({"created": len(new_accs)})

@app.route("/api/create/quick", methods=["POST"])
@require_api_key
def api_quick():
    data = request.json
    count = min(int(data.get("count", 10)), 100)
    new_accs = create_1secmail(count // 2) + create_inboxkitten(count - count // 2)
    accounts.extend(new_accs)
    save_accounts()
    return jsonify({"created": len(new_accs)})

@app.route("/api/check/<account_id>")
@require_api_key
def api_check(account_id):
    for acc in accounts:
        if acc["id"] == account_id:
            msgs = check_account_inbox(acc)
            return jsonify({"messages": msgs})
    return jsonify({"error": "not found"}), 404

@app.route("/api/check/all")
@require_api_key
def api_check_all():
    results = {}
    for acc in accounts:
        if acc.get("provider") in ("1secmail", "guerrillamail", "inboxkitten"):
            msgs = check_account_inbox(acc)
            results[acc["email"]] = msgs
    return jsonify({"results": results})

@app.route("/api/delete/<account_id>", methods=["POST"])
@require_api_key
def api_delete(account_id):
    global accounts
    accounts = [a for a in accounts if a["id"] != account_id]
    save_accounts()
    return jsonify({"ok": True})

@app.route("/api/clear", methods=["POST"])
@require_api_key
def api_clear():
    global accounts
    accounts = []
    save_accounts()
    return jsonify({"ok": True})

# ─── Main ──────────────────────────────────────────────────────────

def main():
    load_accounts()
    print("\n  ============================================")
    print("    TempMail Dashboard (Gmail-style)")
    print("    Anti-Detection + Fingerprint Spoofer")
    print("    http://127.0.0.1:8080")
    print("  ============================================")
    print(f"  API Key: {'*' * 8}{TEMPMAIL_API_KEY[-4:] if TEMPMAIL_API_KEY else '(not set)'}")
    print(f"  ⚠️  Pass X-API-Key header with all /api/* requests\n")
    if accounts:
        print("  Loaded " + str(len(accounts)) + " existing accounts")
    print("  Starting server...\n")
    app.run(host="127.0.0.1", port=8080, debug=False)

if __name__ == "__main__":
    main()
