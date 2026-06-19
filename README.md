# 📧 TempMail Bypass — Gmail-Style Disposable Email Dashboard

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![GitHub](https://img.shields.io/badge/GitHub-RootBugs%2FTEMP__BYPASS-181717?logo=github)

> **Gmail dot/plus trick + disposable temp mails = unlimited email addresses for testing.**
> Anti-detection browser fingerprints, OTP auto-fetching, and a Gmail-style UI.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Gmail Dot/Plus Trick** | Generate 20–200+ undetectable Gmail aliases that all go to your real inbox |
| **Disposable Emails** | 1secmail, GuerrillaMail, InboxKitten — with real inbox checking |
| **Full Inbox API** | Create accounts, check inbox, read messages, get OTP codes |
| **Gmail-Style UI** | Sidebar, search, inbox view, email detail, account switcher |
| **OTP Auto-Detection** | Verification codes highlighted automatically with copy button |
| **Gmail IMAP OTP Fetcher** | Connect your real Gmail via App Password to fetch OTPs from aliases in real-time |
| **Anti-Detection** | Per-account browser fingerprints, risk analysis, detection tips |
| **Cross-Platform** | Windows (full support), Linux, macOS |

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install requests flask

# 2. Start the server (Port 9876 — Minimal UI)
python server.py

# OR start the Dashboard UI (Port 8080 — Full Gmail-style UI)
python tempmail_dashboard.py
```

Open **http://localhost:9876** or **http://localhost:8080** in your browser.

> ⚠️ `tempmail_full.py` and `tempmail_gen.py` are CLI-only tools for batch generation (no web UI).

---

## 📖 How It Works

### Gmail Dot/Plus Trick (Undetectable ✅)

Gmail **completely ignores** dots (`.`) and everything after a plus (`+`) in the local part of an email address.

| Your Gmail | Variant | Delivers To |
|------------|---------|-------------|
| `johndoe@gmail.com` | `john.doe@gmail.com` | ✅ johndoe@gmail.com |
| `johndoe@gmail.com` | `johndoe+github@gmail.com` | ✅ johndoe@gmail.com |
| `johndoe@gmail.com` | `john.doe+test@gmail.com` | ✅ johndoe@gmail.com |

**Why this works for GitHub / any site:**
- GitHub checks email domains against known disposable lists
- `gmail.com` is **not** a disposable domain
- The alias email is a **valid, unique** email address
- All emails arrive in your real Gmail inbox
- GitHub **cannot detect** this as a disposable email

### Disposable Tempmails (GitHub ❌ Blocks These)

| Provider | Domain | Inbox Checking | GitHub Works? |
|----------|--------|---------------|---------------|
| 1secmail | 1secmail.com, .net, .org, kzccv.com, qiott.com | ✅ Yes | ❌ No |
| GuerrillaMail | guerrillamail.com | ✅ Yes | ❌ No |
| InboxKitten | inboxkitten.com | ✅ Yes | ❌ No |

These work for **testing other websites** but GitHub will block them during signup.

---

## 📡 API Endpoints

All endpoints are on the server at the auto-detected port (default: **9876**).

### Account Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/accounts` | List all accounts with messages |
| `POST` | `/api/update` | Update account data (messages, unread, etc.) |
| `POST` | `/api/delete/<id>` | Delete a single account |
| `POST` | `/api/clear` | Delete all accounts |

### Account Creation

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/create/gmail` | `{"gmail": "you@gmail.com", "count": 25}` | Create Gmail dot/plus variants |
| `POST` | `/api/create/tempmail` | `{"provider": "1secmail", "count": 10}` | Create disposable emails |
| `POST` | `/api/create/quick` | `{"count": 10}` | Quick bulk (1secmail + InboxKitten mix) |

**Providers for `/api/create/tempmail`:**
- `1secmail` — 1secmail (uses random domains from a pool of 5+)
- `guerrillamail` — Real session-based GuerrillaMail addresses
- `inboxkitten` — InboxKitten addresses
- `all` — Round-robin mix of all providers

### Inbox Checking

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/check/<id>` | Check inbox for a specific account (by ID) |
| `GET` | `/api/check/all` | Check all disposable inboxes at once |

### Gmail IMAP OTP Fetching

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/gmail/fetch` | `{"gmail": "you@gmail.com", "password": "app_pass", "since": 10}` | Fetch OTP codes from real Gmail via IMAP |

> **Gmail App Password Required:** You need to generate an [App Password](https://myaccount.google.com/apppasswords) from your Google Account settings. Your regular Gmail password won't work with IMAP if 2FA is enabled.

---

## 🛡️ Anti-Detection System

Each generated account comes with a **unique browser fingerprint** to avoid detection:

```json
{
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
  "screen": "1920x1080",
  "timezone": "Asia/Kolkata",
  "language": "en-US,en;q=0.9",
  "platform": "Win32",
  "color_depth": 24,
  "pixel_ratio": 1.5,
  "hardware_concurrency": 8,
  "device_memory": 16,
  "webgl_vendor": "Google Inc. (NVIDIA)"
}
```

The dashboard shows:
- **Detection Risk** — LOW / MEDIUM / HIGH per account
- **Fingerprint Viewer** — See the spoofed browser profile
- **Anti-Detection Tips** — Provider-specific advice for avoiding blocks
- **User-Agent Rotation** — 10+ modern browser UAs (Chrome, Firefox, Edge, Safari)

---

## 🖥️ Dashboard UI

Two server options are available:

### 1. `server.py` — Minimal Server (Port 9876)
- Lightweight, single-file server
- Serves `index.html` with a clean Gmail-style UI
- Includes Gmail IMAP OTP fetcher panel
- Auto-loads/saves accounts to `accounts.json`

### 2. `tempmail_dashboard.py` — Full Dashboard (Port 8080)
- Self-contained (HTML template inline in Python)
- Enhanced anti-detection tips with provider-specific guidance
- Account switcher with search
- Per-account browser fingerprint details
- Auto-loads/saves accounts to `dashboard_accounts.json`

---

## 📁 Project Structure

```
TEMP_BYPASS/
├── server.py                  # 🚀 Main API server (port 9876)
├── tempmail_dashboard.py      # 🚀 Full dashboard server (port 8080)
├── index.html                 # Web UI for server.py
├── README.md                  # This file
├── .gitignore
├── accounts.json              # Data file for server.py (gitignored)
├── dashboard_accounts.json    # Data file for tempmail_dashboard.py (gitignored)
├── tempmail_full.py           # CLI-only — batch generation (gitignored)
├── tempmail_gen.py            # CLI-only — single-provider generation (gitignored)
├── start.bat                  # Windows launcher (gitignored)
└── __pycache__/               # Python cache (gitignored)
```

---

## 🔧 Advanced Usage

### Custom Gmail Variants

Use the API to create specific numbers of variants:

```bash
# Create 50 Gmail aliases
curl -X POST http://localhost:9876/api/create/gmail \
  -H "Content-Type: application/json" \
  -d '{"gmail": "youremail@gmail.com", "count": 50}'
```

### Batch Inbox Check

```bash
# Check all disposable inboxes at once
curl http://localhost:9876/api/check/all
```

### Fetch OTPs from Real Gmail

```bash
curl -X POST http://localhost:9876/api/gmail/fetch \
  -H "Content-Type: application/json" \
  -d '{"gmail": "youremail@gmail.com", "password": "xxxx xxxx xxxx xxxx", "since": 10}'
```

### Using with Automation (Selenium/Playwright)

The fingerprint data for each account can be used to configure your browser automation:

```python
# Example: Apply fingerprint to Playwright
await context.add_init_script("""
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
""")
await page.set_viewport_size({"width": 1920, "height": 1080})
```

---

## 🧪 Email Verification Test Results

| Provider | Inbox API | Received Email | Verified Working |
|----------|-----------|----------------|:----------------:|
| 1secmail | ✅ | ✅ (tested — auto-welcome arrives) | ✅ |
| GuerrillaMail | ✅ | ✅ (tested — welcome email received) | ✅ |
| InboxKitten | ✅ | ✅ (tested — API returns messages) | ✅ |
| Gmail IMAP OTP | ✅ | ✅ (tested — fetches OTP from real inbox) | ✅ |

---

## ⚠️ Legal Disclaimer

This tool is provided **for authorized security testing and educational purposes only**.

- Only use on systems you **own** or have **written permission** to test
- Unauthorized account creation may violate Terms of Service of websites
- The authors are not responsible for misuse of this tool
- Respect rate limits — do not abuse third-party APIs

---

## 🐛 Known Issues & Troubleshooting

| Problem | Solution |
|---------|----------|
| Port already in use | Server auto-increments port. Check console output for the actual URL |
| "Failed to connect" | Ensure `requests` and `flask` are installed: `pip install requests flask` |
| Inbox shows empty | Some providers require a few seconds for email delivery. Click "Check" again |
| Gmail OTP not working | Use an [App Password](https://myaccount.google.com/apppasswords), not your regular password |
| GitHub blocks email | Use **Gmail Dot/Plus trick** only — disposable domains won't work on GitHub |

---

## 📬 Support

- **GitHub Issues**: [RootBugs/TEMP_BYPASS](https://github.com/RootBugs/TEMP_BYPASS/issues)
- **Author**: [RootBugs](https://github.com/RootBugs)

---

<p align="center">
  <b>Made for Security Researchers</b>
  <br>
  <sub>For authorized testing only - RootBugs</sub>
</p>
<!-- // contrib: add_constant — buildContrib -->
<!-- // perm: add_conditional — updatePerm -->
<!-- // timeout: add_constant — validateTimeout -->
<!-- // context: add_conditional — saveContext -->
<!-- // batch: add_constant — createBatch -->
<!-- // focus: add_conditional — transformFocus -->
<!-- // init: add_function — checkInit -->
<!-- // edge: add_function — processEdge -->
<!-- // mock: add_constant — processMock -->
<!-- // spy: add_function — createSpy -->
<!-- // flow: add_function — saveFlow -->
<!-- // format: add_conditional — updateFormat -->
<!-- // compress: add_conditional — validateCompress -->
<!-- // transition: add_conditional — processTransition -->
<!-- // serialize: add_function — saveSerialize -->
<!-- // edge: add_function — saveEdge -->
<!-- // cache: add_conditional — buildCache -->
<!-- // encode: add_function — formatEncode -->
<!-- // guard: add_function — handleGuard -->
<!-- // split: add_function — getSplit -->
<!-- // guard: add_constant — handleGuard -->
<!-- // audit: add_function — validateAudit -->
<!-- // join: add_conditional — applyJoin -->
<!-- // animation: add_constant — loadAnimation -->
<!-- // guard: add_function — parseGuard -->
<!-- // flex: add_function — setupFlex -->
<!-- // debug: add_conditional — processDebug -->
<!-- // audit: add_constant — handleAudit -->
<!-- // flow: add_constant — updateFlow -->
<!-- // readme: add_conditional — createReadme -->
<!-- // encode: add_constant — buildEncode -->
<!-- // edge: add_conditional — getEdge -->
<!-- // cache: add_constant — createCache -->
<!-- // sub: add_constant — syncSub -->
<!-- // active: add_function — transformActive -->
<!-- // fixture: add_function — formatFixture -->
<!-- // metric: add_constant — fetchMetric -->
<!-- // timeout: add_constant — transformTimeout -->
<!-- // log: add_constant — validateLog -->
<!-- // session: add_function — applySession -->
<!-- // changelog: add_constant — syncChangelog -->
<!-- // readme: add_function — updateReadme -->
<!-- // serialize: add_conditional — buildSerialize -->
<!-- // decode: add_conditional — validateDecode -->
<!-- // perm: add_function — applyPerm -->
<!-- // docs: add_constant — loadDocs -->
<!-- // handle: add_constant — formatHandle -->
<!-- // hook: add_function — loadHook -->
<!-- // merge: add_conditional — handleMerge -->
<!-- // license: add_constant — syncLicense -->
<!-- // cleanup: add_constant — fetchCleanup -->
<!-- // buffer: add_constant — getBuffer -->
<!-- // batch: add_conditional — syncBatch -->
<!-- // active: add_conditional — formatActive -->
<!-- // context: add_conditional — parseContext -->
<!-- // compress: add_constant — validateCompress -->
<!-- // pub: add_constant — validatePub -->
<!-- // context: add_constant — updateContext -->
<!-- // log: add_constant — fetchLog -->
<!-- // test: add_constant — transformTest -->
<!-- // animation: add_function — setupAnimation -->
<!-- // decode: add_constant — setupDecode -->
<!-- // metric: add_constant — updateMetric -->
<!-- // hook: add_conditional — buildHook -->
<!-- // flex: add_function — handleFlex -->
<!-- // theme: add_conditional — handleTheme -->
<!-- // changelog: add_conditional — processChangelog -->
<!-- // fixture: add_conditional — processFixture -->
<!-- // hook: add_constant — processHook -->
<!-- // style: add_constant — handleStyle -->
<!-- // render: add_constant — getRender -->
<!-- // pub: add_constant — savePub -->
<!-- // join: add_constant — fetchJoin -->
<!-- // theme: add_conditional — updateTheme -->
<!-- // split: add_function — validateSplit -->
<!-- // decode: add_function — handleDecode -->
<!-- // lazy: add_function — handleLazy -->
<!-- // readme: add_function — parseReadme -->
<!-- // ref: add_conditional — checkRef -->
<!-- // fallback: add_function — processFallback -->
<!-- // timeout: add_conditional — transformTimeout -->
<!-- // handle: add_conditional — fetchHandle -->
<!-- // style: add_function — syncStyle -->
<!-- // route: add_constant — createRoute -->
<!-- // spy: add_conditional — saveSpy -->
<!-- // mock: add_conditional — getMock -->
<!-- // filter: add_function — validateFilter -->
<!-- // query: add_constant — updateQuery -->
<!-- // fallback: add_constant — saveFallback -->
<!-- // docs: add_conditional — loadDocs -->
<!-- // mock: add_constant — formatMock -->
<!-- // parse: add_function — validateParse -->
<!-- // setup: add_conditional — applySetup -->
<!-- // pub: add_function — transformPub -->
<!-- // deserialize: add_conditional — updateDeserialize -->
<!-- // join: add_function — buildJoin -->
<!-- // format: add_function — transformFormat -->
<!-- // join: add_conditional — checkJoin -->
<!-- // sort: add_constant — transformSort -->
<!-- // fixture: add_constant — transformFixture -->
<!-- // audit: add_function — updateAudit -->
<!-- // split: add_constant — setupSplit -->
<!-- // token: add_constant — applyToken -->
<!-- // token: add_conditional — createToken -->
<!-- // transform: add_function — checkTransform -->
<!-- // flex: add_conditional — processFlex -->
<!-- // license: add_function — initLicense -->
<!-- // test: add_function — saveTest -->
<!-- // guard: add_conditional — initGuard -->
<!-- // spy: add_constant — syncSpy -->
<!-- // context: add_constant — loadContext -->
<!-- // test: add_function — createTest -->
<!-- // state: add_constant — initState -->
<!-- // effect: add_constant — transformEffect -->
<!-- // deserialize: add_constant — syncDeserialize -->
<!-- // contrib: add_constant — setContrib -->
<!-- // check: add_conditional — setupCheck -->
<!-- // readme: add_conditional — formatReadme -->
<!-- // split: add_conditional — saveSplit -->
<!-- // flow: add_conditional — setupFlow -->
<!-- // transform: add_constant — loadTransform -->
<!-- // transition: add_constant — handleTransition -->
<!-- // spy: add_function — setupSpy -->
<!-- // deserialize: add_function — loadDeserialize -->
<!-- // grid: add_conditional — saveGrid -->
<!-- // session: add_function — processSession -->
<!-- // focus: add_conditional — setFocus -->
<!-- // log: add_conditional — setupLog -->
<!-- // handle: add_constant — handleHandle -->
<!-- // serialize: add_function — setSerialize -->
<!-- // query: add_function — loadQuery -->
<!-- // cache: add_conditional — handleCache -->
<!-- // split: add_conditional — handleSplit -->
<!-- // style: add_conditional — initStyle -->
<!-- // log: add_constant — fetchLog -->
<!-- // sort: add_function — saveSort -->
<!-- // changelog: add_function — setChangelog -->
<!-- // sub: add_conditional — createSub -->
<!-- // cleanup: add_function — getCleanup -->
<!-- // deserialize: add_constant — fetchDeserialize -->
<!-- // filter: add_conditional — getFilter -->
<!-- // edge: add_constant — saveEdge -->
<!-- // theme: add_function — parseTheme -->
<!-- // flow: add_constant — createFlow -->
<!-- // parse: add_constant — checkParse -->
<!-- // format: add_conditional — formatFormat -->
<!-- // grid: add_constant — processGrid -->
<!-- // retry: add_function — getRetry -->
<!-- // hook: add_constant — setHook -->
<!-- // stream: add_function — loadStream -->
<!-- // map: add_constant — validateMap -->
<!-- // logic: add_conditional — validateLogic -->
<!-- // filter: add_conditional — setFilter -->
<!-- // pub: add_constant — parsePub -->
<!-- // memo: add_function — createMemo -->
<!-- // cleanup: add_conditional — createCleanup -->
<!-- // contrib: add_conditional — transformContrib -->
<!-- // filter: add_function — transformFilter -->
<!-- // readme: add_conditional — createReadme -->
<!-- // grid: add_function — buildGrid -->
<!-- // stub: add_constant — validateStub -->
<!-- // mock: add_constant — formatMock -->
<!-- // test: add_conditional — checkTest -->
<!-- // timeout: add_conditional — initTimeout -->
<!-- // contrib: add_constant — handleContrib -->
<!-- // route: add_constant — parseRoute -->
<!-- // stub: add_constant — loadStub -->
<!-- // parse: add_function — handleParse -->
<!-- // layout: add_conditional — checkLayout -->
<!-- // edge: add_function — checkEdge -->
<!-- // style: add_constant — initStyle -->
<!-- // active: add_constant — handleActive -->
<!-- // split: add_constant — buildSplit -->
<!-- // pub: add_conditional — handlePub -->
<!-- // mutation: add_function — createMutation -->
<!-- // transform: add_function — setupTransform -->
<!-- // retry: add_constant — validateRetry -->
<!-- // readme: add_function — initReadme -->
<!-- // mutation: add_conditional — createMutation -->
<!-- // lazy: add_function — validateLazy -->
<!-- // hover: add_constant — processHover -->
<!-- // active: add_conditional — applyActive -->
<!-- // sort: add_function — saveSort -->
<!-- // auth: add_function — setAuth -->
<!-- // hover: add_constant — getHover -->
<!-- // transform: add_constant — setupTransform -->
<!-- // mutation: add_constant — parseMutation -->
<!-- // format: add_constant — createFormat -->
<!-- // flow: add_conditional — formatFlow -->
<!-- // debug: add_constant — fetchDebug -->
<!-- // lazy: add_function — processLazy -->
<!-- // ref: add_function — buildRef -->
<!-- // sub: add_function — fetchSub -->
<!-- // route: add_function — createRoute -->
<!-- // decode: add_function — saveDecode -->
<!-- // context: add_function — saveContext -->
<!-- // sub: add_conditional — fetchSub -->
<!-- // filter: add_conditional — loadFilter -->
<!-- // map: add_function — validateMap -->
<!-- // query: add_conditional — validateQuery -->
<!-- // trace: add_constant — setupTrace -->
<!-- // parse: add_function — setupParse -->
<!-- // sort: add_conditional — checkSort -->
<!-- // context: add_function — syncContext -->
<!-- // trace: add_function — syncTrace -->
<!-- // join: add_constant — applyJoin -->
<!-- // trace: add_function — fetchTrace -->
<!-- // hover: add_function — saveHover -->
<!-- // guard: add_constant — createGuard -->
<!-- // map: add_conditional — validateMap -->
<!-- // init: add_function — syncInit -->
<!-- // retry: add_constant — validateRetry -->
<!-- // theme: add_conditional — checkTheme -->
<!-- // encode: add_constant — updateEncode -->
<!-- // flow: add_conditional — fetchFlow -->
<!-- // guard: add_constant — setGuard -->
<!-- // encode: add_function — updateEncode -->
<!-- // split: add_constant — initSplit -->
<!-- // buffer: add_constant — getBuffer -->
<!-- // metric: add_constant — getMetric -->
<!-- // role: add_constant — initRole -->
<!-- // pub: add_constant — formatPub -->
<!-- // lazy: add_function — handleLazy -->
<!-- // grid: add_function — updateGrid -->
<!-- // merge: add_constant — fetchMerge -->
<!-- // license: add_function — fetchLicense -->
<!-- // cleanup: add_constant — getCleanup -->
<!-- // init: add_conditional — formatInit -->
<!-- // audit: add_constant — setupAudit -->
<!-- // batch: add_constant — getBatch -->

# Update 1 - 1152098725

# Update 2 - 1704730189

# Update 3 - 944533725

# Update 4 - 527839391

# Update 5 - 1436469010

# Update 6 - 1011648859

# Update 7 - 118134115

# Update 8 - 63628805

# Update 9 - 606695502

# Update 10 - 602961598

# Update 11 - 1172513981

# Update 12 - 117445179

# Update 13 - 1518278724

# Update 14 - 1558140356
