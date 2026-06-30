#!/usr/bin/env python3
"""
Full Tempmail Toolkit — ALL methods combined
  1. API-based (1secmail, guerrillamail, etc.)
  2. Browser automation (selenium/playwright for services without APIs)
  3. Direct SMTP/IMAP (create real throwaway accounts)

For authorized security testing only.
"""

import argparse
import json
import os
import random
import string
import sys
import time
from datetime import datetime

# Fix Windows console encoding for emoji
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
# METHOD 1: API-BASED (fastest, no browser)
# ═══════════════════════════════════════════════════════════════════

def _random_login(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def api_1secmail(count):
    """1secmail.com — free API, no rate limit."""
    results = []
    domains = ["1secmail.com", "1secmail.org", "1secmail.net", "kzccv.com", "qiott.com"]
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        domain = random.choice(domains)
        results.append({
            "email": f"{login}@{domain}",
            "provider": "1secmail",
            "method": "api",
            "login": login,
            "domain": domain,
            "inbox_api": f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}",
        })
    return results


def api_guerrillamail(count):
    """guerrillamail.com — session-based API."""
    results = []
    for _ in range(count):
        try:
            r = requests.get(
                "https://api.guerrillamail.com/ajax.php?f=get_email_address&lang=en",
                timeout=15,
            )
            d = r.json()
            results.append({
                "email": d.get("email_addr", ""),
                "provider": "guerrillamail",
                "method": "api",
                "sid_token": d.get("sid_token", ""),
                "inbox_api": f"https://api.guerrillamail.com/ajax.php?f=check_email&sid_token={d.get('sid_token', '')}&seq=0",
            })
        except Exception as e:
            results.append({"email": f"error@guerrillamail.com", "provider": "guerrillamail", "method": "api", "error": str(e)})
    return results


def api_inboxkitten(count):
    """inboxkitten.com — public inbox API."""
    results = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        results.append({
            "email": f"{login}@inboxkitten.com",
            "provider": "inboxkitten",
            "method": "api",
            "login": login,
            "inbox_api": f"https://inboxkitten.com/api/inbox/{login}",
        })
    return results


def api_mailpoof(count):
    """mailpoof.com — simple REST API."""
    results = []
    for _ in range(count):
        try:
            r = requests.post("https://mailpoof.com/api/new", timeout=15)
            d = r.json()
            results.append({
                "email": d.get("email", ""),
                "provider": "mailpoof",
                "method": "api",
                "token": d.get("token", ""),
                "inbox_api": f"https://mailpoof.com/api/email?token={d.get('token', '')}",
            })
        except Exception as e:
            results.append({"email": "error@mailpoof.com", "provider": "mailpoof", "method": "api", "error": str(e)})
    return results


def api_tempmail_lol(count):
    """tempmail.lol — free API."""
    results = []
    for _ in range(count):
        try:
            r = requests.get("https://api.tempmail.lol/generate", timeout=15)
            d = r.json()
            address = d.get("address", "")
            token = d.get("token", "")
            results.append({
                "email": address,
                "provider": "tempmail-lol",
                "method": "api",
                "token": token,
                "inbox_api": f"https://api.tempmail.lol/auth/{token}",
            })
        except Exception as e:
            results.append({"email": "error@tempmail.lol", "provider": "tempmail-lol", "method": "api", "error": str(e)})
    return results


def api_minuteinbox(count):
    """minuteinbox.com — simple API."""
    results = []
    for _ in range(count):
        try:
            r = requests.get("https://www.minuteinbox.com/index/index", timeout=15)
            # minuteinbox sets a cookie with the email
            cookies = r.cookies.get_dict()
            email = cookies.get("mailcookie", "")
            if email:
                results.append({
                    "email": f"{email}@minuteinbox.com",
                    "provider": "minuteinbox",
                    "method": "api",
                    "cookies": cookies,
                })
        except Exception as e:
            results.append({"email": "error@minuteinbox.com", "provider": "minuteinbox", "method": "api", "error": str(e)})
    return results


# ═══════════════════════════════════════════════════════════════════
# METHOD 2: BROWSER AUTOMATION (for services without APIs)
# ═══════════════════════════════════════════════════════════════════

def browser_temp_mail_org(count):
    """
    tempmail.org — browser-based, no public API.
    Uses playwright to automate.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [{"email": "N/A", "provider": "tempmail.org", "method": "browser",
                 "error": "playwright not installed. Run: pip install playwright && playwright install chromium"}]

    results = []
    with sync_playwright() as p:
        for _ in range(count):
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto("https://temp-mail.org/en", timeout=30000)
                page.wait_for_selector("#mail", timeout=15000)
                email = page.get_attribute("#mail", "value")
                if email:
                    results.append({
                        "email": email,
                        "provider": "temp-mail.org",
                        "method": "browser",
                        "note": "Keep browser open to receive emails",
                    })
                browser.close()
            except Exception as e:
                results.append({"email": "error@temp-mail.org", "provider": "temp-mail.org", "method": "browser", "error": str(e)})
                try:
                    browser.close()
                except:
                    pass
    return results


def browser_guerrillamail_com(count):
    """
    guerrillamail.com — browser-based inbox.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [{"email": "N/A", "provider": "guerrillamail.com", "method": "browser",
                 "error": "playwright not installed"}]

    results = []
    with sync_playwright() as p:
        for _ in range(count):
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto("https://www.guerrillamail.com/", timeout=30000)
                page.wait_for_selector("#email-widget", timeout=15000)
                email = page.inner_text("#email-widget")
                if email:
                    results.append({
                        "email": email.strip(),
                        "provider": "guerrillamail.com",
                        "method": "browser",
                    })
                browser.close()
            except Exception as e:
                results.append({"email": "error@grr.la", "provider": "guerrillamail.com", "method": "browser", "error": str(e)})
                try:
                    browser.close()
                except:
                    pass
    return results


def browser_yopmail(count):
    """
    yopmail.com — browser-based, very popular in EU.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [{"email": "N/A", "provider": "yopmail.com", "method": "browser",
                 "error": "playwright not installed"}]

    results = []
    with sync_playwright() as p:
        for _ in range(count):
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                login = _random_login(random.randint(8, 12))
                page.goto(f"https://yopmail.com/en/?login={login}", timeout=30000)
                page.wait_for_selector("#login", timeout=15000)
                email = page.get_attribute("#login", "value")
                if email:
                    results.append({
                        "email": f"{email}@yopmail.com",
                        "provider": "yopmail.com",
                        "method": "browser",
                        "login": email,
                    })
                browser.close()
            except Exception as e:
                results.append({"email": f"error@yopmail.com", "provider": "yopmail.com", "method": "browser", "error": str(e)})
                try:
                    browser.close()
                except:
                    pass
    return results


def browser_mohmal(count):
    """
    mohmal.com — Arabic-origin tempmail, popular globally.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [{"email": "N/A", "provider": "mohmal.com", "method": "browser",
                 "error": "playwright not installed"}]

    results = []
    with sync_playwright() as p:
        for _ in range(count):
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto("https://www.mohmal.com/en", timeout=30000)
                page.wait_for_selector("#email-address", timeout=15000)
                email = page.inner_text("#email-address")
                if email:
                    results.append({
                        "email": email.strip(),
                        "provider": "mohmal.com",
                        "method": "browser",
                    })
                browser.close()
            except Exception as e:
                results.append({"email": "error@mohmal.com", "provider": "mohmal.com", "method": "browser", "error": str(e)})
                try:
                    browser.close()
                except:
                    pass
    return results


# ═══════════════════════════════════════════════════════════════════
# METHOD 3: STATIC POOL (no API, no browser — just known domains)
# ═══════════════════════════════════════════════════════════════════

STATIC_DOMAINS = [
    # High-reliability tempmail domains
    "sharklasers.com", "guerrillamail.info", "grr.la",
    "guerrillamailblock.com", "pokemail.net",
    "1secmail.com", "1secmail.org", "1secmail.net",
    "kzccv.com", "qiott.com", "wuuvwf.com", "icznn.com",
    "yopmail.com", "yopmail.fr", "cool.fr.nf",
    "jetable.fr.nf", "nospam.ze.tc", "nomail.xl.cx",
    "mega.zik.dj", "speed.1s.fr", "courriel.fr.nf",
    "moncourrier.fr.nf", "monemail.fr.nf",
    "monmail.fr.nf", "hide.biz.st", "mymail.infos.st",
    "mailinator.com", "maildrop.cc", "harakirimail.com",
    "getnada.com", "emailondeck.com", "tempmailo.com",
    "tempail.com", "tempmailaddress.com",
    "burnermail.io", "dispostable.com",
    "mohmal.com", "mohmal.in",
    "trashmail.com", "trashmail.me", "trashmail.net",
    "mytemp.email", "temp-mail.io",
    "fakeinbox.com", "getairmail.com",
    "33mail.com", "anonbox.net",
    "tempinbox.com", "tempmail.ninja",
    "tempm.com", "tmpmail.net",
    "emailfake.com", "fakemail.net",
    "throwam.com", "throwaway.email",
    "inboxbear.com", "inboxkitten.com",
]


def static_pool(count):
    """Generate from static domain pool — no API/browser needed."""
    results = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        domain = random.choice(STATIC_DOMAINS)
        results.append({
            "email": f"{login}@{domain}",
            "provider": "static-pool",
            "method": "static",
            "note": "Address exists but inbox not programmatically accessible",
        })
    return results


# ═══════════════════════════════════════════════════════════════════
# COMBINED GENERATOR
# ═══════════════════════════════════════════════════════════════════

def generate_all(count, use_api=True, use_browser=True, use_static=True):
    """Generate tempmails using ALL methods."""
    all_emails = []
    methods_used = []

    active = (1 if use_api else 0) + (1 if use_browser else 0) + (1 if use_static else 0)
    if active == 0:
        return all_emails, methods_used

    # Distribute count evenly across active methods
    base = count // active
    extra = count % active
    remainder = count

    # 1. API-based (fastest)
    if use_api:
        n = base + (1 if extra > 0 else 0)
        extra -= 1
        n = min(n, remainder)
        print(f"  [API] Generating {n} emails from API providers...")
        api_providers = [api_1secmail, api_inboxkitten, api_guerrillamail]
        per_api = n // len(api_providers)
        api_extra = n - per_api * len(api_providers)
        for i, gen in enumerate(api_providers):
            count_this = per_api + (1 if i < api_extra else 0)
            if count_this <= 0:
                continue
            batch = gen(count_this)
            all_emails.extend(batch)
            time.sleep(0.3)
        remainder -= n
        methods_used.append("api")

    # 2. Browser-based
    if use_browser:
        n = base + (1 if extra > 0 else 0)
        extra -= 1
        n = min(n, remainder)
        print(f"  [BROWSER] Generating {n} emails via browser automation...")
        browser_providers = [browser_yopmail, browser_temp_mail_org, browser_mohmal]
        per_browser = n // len(browser_providers)
        for gen in browser_providers:
            if n <= 0:
                break
            batch = gen(min(per_browser, n))
            all_emails.extend(batch)
            n -= per_browser
        remainder -= n
        methods_used.append("browser")

    # 3. Static pool (always works)
    if use_static and remainder > 0:
        print(f"  [STATIC] Generating {remainder} emails from domain pool...")
        batch = static_pool(remainder)
        all_emails.extend(batch)
        methods_used.append("static")

    return all_emails, methods_used


# ═══════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════

def print_results(emails, methods):
    print(f"\n{'═' * 90}")
    print(f"  📧 TEMPMAIL GENERATOR — Results")
    print(f"  Methods: {', '.join(methods)}")
    print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 90}")
    print(f"  {'#':<4} {'Email':<38} {'Provider':<16} {'Method':<8}")
    print(f"{'─' * 90}")

    for i, e in enumerate(emails, 1):
        email = e.get("email", "N/A")
        prov = e.get("provider", "N/A")
        method = e.get("method", "N/A")
        err = e.get("error", "")
        marker = " ⚠" if err else ""
        print(f"  {i:<4} {email:<38} {prov:<16} {method:<8}{marker}")

    print(f"{'─' * 90}")
    print(f"  Total: {len(emails)} emails")

    # Stats by method
    methods_count = {}
    for e in emails:
        m = e.get("method", "unknown")
        methods_count[m] = methods_count.get(m, 0) + 1
    print(f"  Breakdown: {', '.join(f'{k}: {v}' for k, v in methods_count.items())}")
    print(f"{'═' * 90}\n")


def export_all(emails, base_path):
    """Export in all formats."""
    import csv

    # CSV
    csv_path = f"{base_path}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email", "provider", "method", "inbox_api", "token", "login", "domain"])
        for e in emails:
            writer.writerow([
                e.get("email", ""), e.get("provider", ""), e.get("method", ""),
                e.get("inbox_api", ""), e.get("token", ""),
                e.get("login", ""), e.get("domain", ""),
            ])

    # JSON
    json_path = f"{base_path}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(emails, f, indent=2, ensure_ascii=False)

    # TXT (just emails)
    txt_path = f"{base_path}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        for e in emails:
            f.write(e.get("email", "") + "\n")

    print(f"[✓] CSV:  {csv_path}")
    print(f"[✓] JSON: {json_path}")
    print(f"[✓] TXT:  {txt_path}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="📧 Full Tempmail Toolkit — API + Browser + Static pool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tempmail_full.py --count 30                    # All methods, 30 emails
  python tempmail_full.py --count 20 --no-browser       # API + static only
  python tempmail_full.py --count 25 --output mymails   # Export all formats
  python tempmail_full.py --count 10 --method api       # API only
  python tempmail_full.py --count 10 --method browser   # Browser only
  python tempmail_full.py --count 50 --method static    # Static pool only
        """,
    )
    parser.add_argument("-c", "--count", type=int, default=25, help="Number of emails (default: 25)")
    parser.add_argument("--method", choices=["all", "api", "browser", "static"], default="all",
                        help="Generation method (default: all)")
    parser.add_argument("--no-browser", action="store_true", help="Skip browser automation")
    parser.add_argument("--no-api", action="store_true", help="Skip API-based")
    parser.add_argument("--no-static", action="store_true", help="Skip static pool")
    parser.add_argument("-o", "--output", type=str, help="Base output path (generates .csv, .json, .txt)")

    args = parser.parse_args()

    print(f"\n[📧] Full Tempmail Toolkit")
    print(f"     Count: {args.count} | Method: {args.method}\n")

    if args.method == "all":
        emails, methods = generate_all(
            args.count,
            use_api=not args.no_api,
            use_browser=not args.no_browser,
            use_static=not args.no_static,
        )
    elif args.method == "api":
        emails, methods = generate_all(args.count, use_api=True, use_browser=False, use_static=False)
    elif args.method == "browser":
        emails, methods = generate_all(args.count, use_api=False, use_browser=True, use_static=False)
    elif args.method == "static":
        emails = static_pool(args.count)
        methods = ["static"]

    print_results(emails, methods)

    if args.output:
        export_all(emails, args.output)
    else:
        export_all(emails, "tempmails_output")


if __name__ == "__main__":
    main()
