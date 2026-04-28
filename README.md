# SiriusXM Dealer Database App

A secure, encrypted Android (and desktop) customer database application built with [Kivy](https://kivy.org/), designed for SiriusXM dealers to manage customer subscription records. All data is protected at rest using a pure-Python AES-256-CBC encryption layer with no third-party cryptographic dependencies.

---

## Features

- **Encrypted at-rest storage** — the SQLite database is encrypted with AES-256-CBC and only decrypted in memory after a successful passphrase unlock.
- **Passphrase lock screen** — the app always starts on a lock screen; the database is never accessible without authentication.
- **Brute-force protection** — after 4 failed passphrase attempts a final warning is shown; the 5th failed attempt irreversibly wipes all data files.
- **No third-party crypto** — AES-256 is implemented in pure Python using only the standard library (`hashlib`, `hmac`, `os.urandom`, `struct`).
- **Background crypto** — all encryption/decryption runs on a daemon thread so the UI is never blocked.
- **Full CRUD** — add, view, edit, and delete customer records from the database screen.
- **Search & filter** — real-time search across all record fields.
- **Expired-subscription highlighting** — end dates that are today or in the past are shown in red.
- **Copy-to-clipboard** — copy individual field values directly from a record detail view.
- **Android back-button support** — navigates between screens and re-locks the app from the database screen.

---

## Screens

| Screen | Purpose |
|---|---|
| **Lock Screen** | Passphrase entry / first-run passphrase creation |
| **Database Screen** | Browse, search, select, and delete records |
| **Edit Screen** | Create new records or edit existing ones |
| **Output Screen** | Scrollable log / output viewer with clipboard support |

---

## Security Design

### Encryption

- **Algorithm:** AES-256-CBC
- **Key derivation:** PBKDF2-HMAC-SHA1, 10,000 iterations, 32-byte output
  - SHA-1 is used intentionally for speed on constrained mobile hardware; this avoids triggering Android's background-thread watchdog while still providing adequate security for local device storage.
- **Salt:** 16 random bytes generated once on first run and stored in `sxm_dealer.salt`.
- **IV:** Fresh 16 random bytes are generated for every encryption operation.
- **File format:** `MAGIC(8 bytes) | IV(16 bytes) | PKCS#7-padded ciphertext`

### File Layout

```
~/ (or app-private storage on Android)
├── sxm_dealer.db        # plaintext SQLite DB (only exists while app is unlocked)
├── sxm_dealer.db.enc    # AES-256-CBC encrypted DB (persisted on disk)
├── sxm_dealer.salt      # 16-byte random salt (generated once)
└── sxm_dealer.attempts  # JSON sidecar tracking failed unlock attempts
```

The plaintext `.db` file is removed from disk immediately after encryption, and is only written back during an active session after a successful unlock.

### Attempt Lockout

| Failed Attempts | Behaviour |
|---|---|
| 1–3 | "Wrong passphrase" toast notification |
| 4 | Toast + a red final-warning banner becomes visible |
| 5 | All data files are securely wiped (zeros written before deletion); no recovery possible |

---

## Customer Record Fields

Each customer record contains the following fields:

| Field | Description |
|---|---|
| `first_name` | Customer first name |
| `last_name` | Customer last name |
| `radio_id` | SiriusXM Radio ID (must be exactly 8 or 12 characters) |
| `address` | Street address |
| `city` | City |
| `province` | Province or state (exactly 2 letters, auto-uppercased) |
| `postal` | Postal or ZIP code (auto-uppercased) |
| `subscription` | Subscription plan or type |
| `start_date` | Subscription start date (`YYYY-MM-DD`) |
| `end_date` | Subscription end date (`YYYY-MM-DD`); shown in red if expired |
| `make_model` | Vehicle make and model |
| `phone` | Customer phone number |

---

## Requirements

### Python

- Python 3.8–3.11

### Dependencies

```
kivy
```

No third-party cryptography packages are required. All AES-256 operations use only Python standard library modules.

### Android

- Built with [python-for-android (p4a)](https://github.com/kivy/python-for-android)
- Targets API 26+
- Does **not** require `MANAGE_EXTERNAL_STORAGE` — the database is stored in the app's private internal storage directory.

---

## Installation & Running

### Desktop (development / testing)

```bash
pip install kivy
python sxmdatabase_aes256_add_delete_v1_0_main.py
```

The database and supporting files will be created in your home directory (`~/`).

### Android (via Buildozer)

1. Set up [Buildozer](https://buildozer.readthedocs.io/) with a `buildozer.spec` configured for your package name (`com.dealer.sxm`).
2. Run:
   ```bash
   buildozer android debug deploy run
   ```
3. The app will store all data in the app-private internal files directory (no external storage permission needed).

---

## First Run

On first launch, no encrypted database exists yet. The lock screen will prompt you to **create a passphrase**. This passphrase is used to derive the AES-256 encryption key that protects all future data. **There is no passphrase recovery** — if the passphrase is forgotten, data cannot be retrieved.

---

## Architecture Notes

- All `kivy.config.Config` settings are applied **before** any other Kivy import to prevent Android crash-on-launch issues.
- The Android environment is detected via `ANDROID_ARGUMENT` / `ANDROID_ROOT` environment variables set by p4a.
- `multitouch` emulation is enabled on desktop only; it is disabled on Android where it causes input conflicts.
- `requests` is imported lazily inside threads (never at module level) to avoid import-time failures on Android.
- The entire `App.build()` is wrapped in `try/except` so startup errors surface in `logcat` rather than causing a silent crash.
- The session passphrase is held in memory only — it is never written to disk.

---

## Version

`v1.0` — `sxmdatabase_aes256_add_delete_v1_0_main.py`
