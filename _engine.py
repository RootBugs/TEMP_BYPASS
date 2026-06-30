#!/usr/bin/env python3
"""
Tempmail Generator — Multi-provider disposable email generator
For authorized security testing only.

Providers:
  1secmail      — 1secmail.com (5 API endpoints, no rate limit)
  guerrillamail — guerrillamail.com (session-based)
  tempmail-dev  — tempmail.dev (JSON API)
  throwmail     — throwmail.cc (instant, no signup)
  mailpoof      — mailpoof.com
  inboxkitten   — inboxkitten.com
  all           — round-robin across all providers
"""

import argparse
import json
import random
import string
import sys
import time
from datetime import datetime
from typing import Optional

# Fix Windows console encoding for emoji
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    print("[!] requests not found. Install: pip install requests")
    sys.exit(1)

# ── Provider Configs ──────────────────────────────────────────────

DOMAINS_1SECMAIL = [
    "1secmail.com", "1secmail.org", "1secmail.net",
    "kzccv.com", "qiott.com", "wuuvwf.com", "icznn.com"
]

DOMAINS_GUERRILLA = [
    "guerrillamail.com", "guerrillamail.info", "grr.la",
    "guerrillamailblock.com", "pokemail.net", "sharklasers.com"
]

DOMAINS_THROWMail = [
    "throwmail.cc", "throwmail.com"
]

DOMAINS_TEMPMAIL_DEV = [
    "tempmail.dev"
]

DOMAINS_MAILPOOF = [
    "mailpoof.com"
]

DOMAINS_INBOXKITTEN = [
    "inboxkitten.com"
]

DOMAINS_EMAILNATOR = [
    "emailnator.com"  # requires special handling
]

ALL_DOMAINS = (
    DOMAINS_1SECMAIL
    + DOMAINS_GUERRILLA
    + DOMAINS_THROWMail
    + DOMAINS_TEMPMAIL_DEV
    + DOMAINS_MAILPOOF
    + DOMAINS_INBOXKITTEN
)


def _random_login(length: int = 10) -> str:
    """Generate a random email local-part."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


# ── Provider: 1secmail ───────────────────────────────────────────

def gen_1secmail(count: int = 1) -> list[dict]:
    """Generate emails via 1secmail API."""
    emails = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        domain = random.choice(DOMAINS_1SECMAIL)
        email = f"{login}@{domain}"
        emails.append({
            "email": email,
            "provider": "1secmail",
            "inbox_check": f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}",
            "read_mail": f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={{domain}}&id={{id}}",
            "login": login,
            "domain": domain,
        })
    return emails


def check_1secmail(login: str, domain: str) -> list[dict]:
    """Check 1secmail inbox."""
    url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
    try:
        resp = requests.get(url, timeout=10)
        msgs = resp.json()
        return msgs
    except Exception as e:
        return [{"error": str(e)}]


def read_1secmail(login: str, domain: str, msg_id: int) -> dict:
    """Read a specific 1secmail message."""
    url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}"
    try:
        resp = requests.get(url, timeout=10)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# ── Provider: Guerrilla Mail ─────────────────────────────────────

def gen_guerrillamail(count: int = 1) -> list[dict]:
    """Generate emails via Guerrilla Mail API."""
    emails = []
    for _ in range(count):
        sid_resp = requests.get(
            "https://api.guerrillamail.com/ajax.php?f=get_email_address&lang=en",
            timeout=10,
        )
        data = sid_resp.json()
        email_addr = data.get("email_addr", "")
        sid_token = data.get("sid_token", "")
        if email_addr:
            emails.append({
                "email": email_addr,
                "provider": "guerrillamail",
                "sid_token": sid_token,
                "inbox_check": f"https://api.guerrillamail.com/ajax.php?f=check_email&sid_token={sid_token}&seq=0",
            })
    return emails


def check_guerrillamail(sid_token: str) -> list[dict]:
    """Check Guerrilla Mail inbox."""
    url = f"https://api.guerrillamail.com/ajax.php?f=check_email&sid_token={sid_token}&seq=0"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        return data.get("list", [])
    except Exception as e:
        return [{"error": str(e)}]


# ── Provider: TempMail.dev ───────────────────────────────────────

def gen_tempmail_dev(count: int = 1) -> list[dict]:
    """Generate emails via tempmail.dev API."""
    emails = []
    for _ in range(count):
        try:
            # Create a new inbox
            domain_resp = requests.get("https://api.tempmail.dev/domains", timeout=10)
            domains = domain_resp.json()
            if not domains:
                continue
            domain = random.choice(domains)
            login = _random_login(random.randint(8, 12))
            email = f"{login}@{domain['name']}"

            create_resp = requests.post(
                "https://api.tempmail.dev/inbox",
                json={"address": email, "ttl": 3600000},
                timeout=10,
            )
            inbox_data = create_resp.json()
            token = inbox_data.get("token", "")

            emails.append({
                "email": email,
                "provider": "tempmail-dev",
                "token": token,
                "inbox_check": f"https://api.tempmail.dev/inbox?token={token}",
            })
        except Exception as e:
            emails.append({
                "email": f"error@{domain.get('name', 'unknown')}",
                "provider": "tempmail-dev",
                "error": str(e),
            })
    return emails


# ── Provider: Throwmail.cc ───────────────────────────────────────

def gen_throwmail(count: int = 1) -> list[dict]:
    """Generate emails via throwmail.cc (instant, no API needed)."""
    emails = []
    for _ in range(count):
        domain = random.choice(DOMAINS_THROWMail)
        login = _random_login(random.randint(10, 16))
        email = f"{login}@{domain}"
        emails.append({
            "email": email,
            "provider": "throwmail",
            "inbox_check": f"https://throwmail.cc/?email={email}",
        })
    return emails


# ── Provider: Mailpoof ───────────────────────────────────────────

def gen_mailpoof(count: int = 1) -> list[dict]:
    """Generate emails via mailpoof.com API."""
    emails = []
    for _ in range(count):
        try:
            create_resp = requests.post(
                "https://mailpoof.com/api/new",
                timeout=10,
            )
            data = create_resp.json()
            email = data.get("email", "")
            token = data.get("token", "")
            if email:
                emails.append({
                    "email": email,
                    "provider": "mailpoof",
                    "token": token,
                    "inbox_check": f"https://mailpoof.com/api/email?token={token}",
                })
        except Exception as e:
            emails.append({
                "provider": "mailpoof",
                "error": str(e),
            })
    return emails


# ── Provider: InboxKitten ────────────────────────────────────────

def gen_inboxkitten(count: int = 1) -> list[dict]:
    """Generate emails via inboxkitten.com."""
    emails = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        email = f"{login}@inboxkitten.com"
        emails.append({
            "email": email,
            "provider": "inboxkitten",
            "inbox_check": f"https://inboxkitten.com/api/inbox/{login}",
            "login": login,
        })
    return emails


def check_inboxkitten(login: str) -> list[dict]:
    """Check InboxKitten inbox."""
    url = f"https://inboxkitten.com/api/inbox/{login}"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        return data.get("messages", [])
    except Exception as e:
        return [{"error": str(e)}]


# ── Generic / Random ─────────────────────────────────────────────

def gen_random(count: int = 1) -> list[dict]:
    """Generate random emails from pool of known tempmail domains."""
    emails = []
    for _ in range(count):
        login = _random_login(random.randint(8, 14))
        domain = random.choice(ALL_DOMAINS)
        emails.append({
            "email": f"{login}@{domain}",
            "provider": "random-pool",
            "note": "Static address — cannot check inbox",
        })
    return emails


# ── Provider Router ──────────────────────────────────────────────

PROVIDERS = {
    "1secmail": gen_1secmail,
    "guerrillamail": gen_guerrillamail,
    "tempmail-dev": gen_tempmail_dev,
    "throwmail": gen_throwmail,
    "mailpoof": gen_mailpoof,
    "inboxkitten": gen_inboxkitten,
    "random": gen_random,
    "all": None,  # special: use all providers in round-robin
}


def generate_emails(count: int, provider: str = "all") -> list[dict]:
    """Route to correct provider generator."""
    if provider != "all":
        gen_func = PROVIDERS.get(provider)
        if not gen_func:
            print(f"[!] Unknown provider: {provider}")
            print(f"    Available: {', '.join(PROVIDERS.keys())}")
            sys.exit(1)
        return gen_func(count)

    # Round-robin across API-based providers (skip random)
    api_providers = ["1secmail", "guerrillamail", "throwmail", "inboxkitten", "mailpoof", "tempmail-dev"]
    emails = []
    per_provider = max(1, count // len(api_providers))
    remainder = count - per_provider * len(api_providers)

    for pname in api_providers:
        n = per_provider + (1 if remainder > 0 else 0)
        remainder -= 1
        if n <= 0:
            break
        gen_func = PROVIDERS[pname]
        batch = gen_func(n)
        emails.extend(batch)
        time.sleep(0.3)  # polite rate limiting

    # Trim to exact count
    return emails[:count]


# ── Check Inbox Router ───────────────────────────────────────────

def check_inbox(email_data: dict) -> list[dict]:
    """Check inbox based on provider."""
    provider = email_data.get("provider", "")

    if provider == "1secmail":
        return check_1secmail(email_data["login"], email_data["domain"])
    elif provider == "guerrillamail":
        return check_guerrillamail(email_data["sid_token"])
    elif provider == "inboxkitten":
        return check_inboxkitten(email_data["login"])
    else:
        return [{"note": f"Inbox checking not implemented for provider '{provider}'"}]


# ── Output Formatting ────────────────────────────────────────────

def print_table(emails: list[dict]):
    """Pretty-print emails as a table."""
    print(f"\n{'─' * 80}")
    print(f"  {'#':<4} {'Email':<40} {'Provider':<16} {'Inbox URL'}")
    print(f"{'─' * 80}")
    for i, e in enumerate(emails, 1):
        email = e.get("email", "N/A")
        prov = e.get("provider", "N/A")
        inbox = e.get("inbox_check", "N/A")
        if len(inbox) > 50:
            inbox = inbox[:47] + "..."
        print(f"  {i:<4} {email:<40} {prov:<16} {inbox}")
    print(f"{'─' * 80}")
    print(f"  Total: {len(emails)} emails generated")
    print(f"  Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def export_csv(emails: list[dict], filepath: str):
    """Export emails to CSV."""
    import csv
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email", "provider", "inbox_check", "login", "domain", "token", "sid_token"])
        for e in emails:
            writer.writerow([
                e.get("email", ""),
                e.get("provider", ""),
                e.get("inbox_check", ""),
                e.get("login", ""),
                e.get("domain", ""),
                e.get("token", ""),
                e.get("sid_token", ""),
            ])
    print(f"[✓] Exported {len(emails)} emails to {filepath}")


def export_json(emails: list[dict], filepath: str):
    """Export emails to JSON."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(emails, f, indent=2, ensure_ascii=False)
    print(f"[✓] Exported {len(emails)} emails to {filepath}")


def export_txt(emails: list[dict], filepath: str):
    """Export emails as plain text (one per line)."""
    with open(filepath, "w", encoding="utf-8") as f:
        for e in emails:
            f.write(e.get("email", "") + "\n")
    print(f"[✓] Exported {len(emails)} emails to {filepath}")


# ── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="📧 Tempmail Generator — Multi-provider disposable email tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --count 25                          # Generate 25 from all providers
  %(prog)s --count 20 --provider 1secmail      # 20 from 1secmail only
  %(prog)s --count 30 --format csv --output mails.csv
  %(prog)s --check someone@1secmail.com        # Check an inbox
        """,
    )
    parser.add_argument("-c", "--count", type=int, default=20, help="Number of emails (default: 20)")
    parser.add_argument("-p", "--provider", type=str, default="all",
                        choices=list(PROVIDERS.keys()),
                        help="Provider to use (default: all)")
    parser.add_argument("--check", type=str, metavar="EMAIL", help="Check inbox of an email")
    parser.add_argument("--format", type=str, default="table",
                        choices=["table", "csv", "json", "txt"],
                        help="Output format (default: table)")
    parser.add_argument("-o", "--output", type=str, help="Output file path")
    parser.add_argument("--json", action="store_true", help="Alias for --format json")

    args = parser.parse_args()

    if args.json:
        args.format = "json"

    # Check inbox mode
    if args.check:
        email_str = args.check
        print(f"\n[📬] Checking inbox: {email_str}\n")

        if "@1secmail" in email_str:
            login, domain = email_str.split("@")
            msgs = check_1secmail(login, domain)
        elif "@inboxkitten.com" in email_str:
            login = email_str.split("@")[0]
            msgs = check_inboxkitten(login)
        else:
            msgs = [{"note": "Auto-detect failed. Use 1secmail or inboxkitten for inbox checking."}]

        if msgs:
            for m in msgs:
                print(json.dumps(m, indent=2))
        else:
            print("  (empty inbox)")
        return

    # Generate mode
    print(f"\n[📧] Generating {args.count} tempmails (provider: {args.provider})...\n")

    emails = generate_emails(args.count, args.provider)

    if not emails:
        print("[!] No emails generated. Check API availability.")
        sys.exit(1)

    # Output
    if args.format == "table":
        print_table(emails)
    elif args.format == "json":
        output = json.dumps(emails, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[✓] Saved to {args.output}")
        else:
            print(output)
    elif args.format == "csv":
        if args.output:
            export_csv(emails, args.output)
        else:
            export_csv(emails, "tempmails.csv")
    elif args.format == "txt":
        if args.output:
            export_txt(emails, args.output)
        else:
            export_txt(emails, "tempmails.txt")


if __name__ == "__main__":
    main()
