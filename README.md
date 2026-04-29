# SiriusXM Dealer Database App

A secure, encrypted customer database for SiriusXM dealers. Built with Kivy for Android, it stores subscription records locally on-device with AES-256-CBC encryption and requires a passphrase to access any data.

---

## Features

- **AES-256-CBC encryption** — the database is never stored as plaintext at rest; it lives on disk as an encrypted `.enc` file and is only decrypted into memory after a correct passphrase is entered
- **Pure-Python crypto** — no NDK or third-party native library required; runs entirely on `hashlib`, `hmac`, and `os.urandom` from the Python stdlib
- **Passphrase protection with wipe-on-failure** — after 4 failed unlock attempts a final warning is displayed; the 5th failure permanently destroys all data
- **Inactivity auto-lock** — if the app is left idle for 60 seconds it re-encrypts the database, clears the passphrase from memory, and exits completely; a 10-second on-screen warning gives the user a chance to cancel
- **Background-thread crypto** — PBKDF2 key derivation and AES operations run on a daemon thread so the UI never freezes
- **Private storage only** — the database is written to the app's private files directory; no `MANAGE_EXTERNAL_STORAGE` permission is needed

---

## Screens

### Lock Screen
The first screen shown on every launch. The database is inaccessible until the correct passphrase is entered.

On first run there is no database yet, so the app prompts you to create a passphrase and confirm it. The database is created and immediately encrypted before anything is stored.

### Database Screen
Displays all customer records sorted by last name, then first name. Each row shows the customer's name, Radio ID, and subscription end date. End dates that are today or in the past are highlighted in red.

From this screen you can:
- **Add** a new record
- **Delete** a selected record (tap a row to select it; double-tap to open it for editing)
- **Search / browse** by scrolling
- **Quit** to exit cleanly

### Edit Screen
Add or update a customer record. Fields are validated before saving — Radio ID must be exactly 8 or 12 characters, Province/State must be exactly 2 letters, and dates must be in `yyyy-mm-dd` format.

### Output Screen
A scrollable text view for operation results and export output.

---

## Customer Record Fields

| Field | Description |
|---|---|
| First Name | Customer first name |
| Last Name | Customer last name |
| Radio ID | SiriusXM Radio ID — must be exactly 8 or 12 characters |
| Address | Street address |
| City | City |
| Province / State | 2-letter province or state code |
| Postal Code / Zip | Postal or ZIP code |
| Subscription | Subscription plan or tier |
| Start Date | Subscription start date (`yyyy-mm-dd`) |
| End Date | Subscription end date (`yyyy-mm-dd`) |
| Make / Model | Vehicle make and model |
| Phone | Customer phone number |

---

## Security

### Encryption
The database uses **AES-256-CBC** with a key derived from the user's passphrase via **PBKDF2-HMAC-SHA1** at 10,000 iterations and a random 16-byte salt. The salt is stored alongside the database; the passphrase is never written to disk in any form.

The encrypted file layout is:

```
MAGIC(8 bytes) | IV(16 bytes) | AES-256-CBC ciphertext
```

The `MAGIC` sentinel (`SXMENC01`) lets the app quickly detect a corrupt or unrecognised file without attempting full decryption.

### Failed Attempt Policy

| Attempts | Behaviour |
|---|---|
| 1 – 3 | "Wrong passphrase" toast |
| 4 | Toast + red warning banner: one attempt remaining |
| 5 | All data files are permanently wiped (no recovery) |

The attempt counter is stored in a plain JSON sidecar file. It resets to zero on a successful unlock.

### Inactivity Timeout
Once unlocked, the app monitors for inactivity:

- **50 seconds** of no touch activity — a full-screen red warning overlay appears with a live countdown
- **Tap anywhere** on the overlay to dismiss it and reset the 60-second timer
- **60 seconds** of no activity — the app re-encrypts the database, clears the passphrase from memory, and calls `os._exit(0)` to ensure no background process remains with access to the data

The timeout is only active while the user is past the lock screen. Returning to the lock screen manually (back button or Quit) cancels the timer and re-encrypts immediately.

The two timeout constants can be adjusted at the top of the file:

```python
IDLE_LIMIT  = 60   # total seconds of inactivity before shutdown
WARN_BEFORE = 10   # seconds before shutdown to show the warning overlay
```

---

## File Layout

All files are stored in the app's private directory. On Android this is `/data/data/com.dealer.sxm/files/`. On desktop it is the user's home directory (`~`).

| File | Purpose |
|---|---|
| `sxm_dealer.db` | Plaintext SQLite database — only exists while the app is unlocked |
| `sxm_dealer.db.enc` | AES-256-CBC encrypted database — the at-rest form |
| `sxm_dealer.salt` | 16-byte random salt used for key derivation |
| `sxm_dealer.attempts` | JSON file tracking failed unlock attempts |

---

## Requirements

- Python 3.8 – 3.11
- [Kivy](https://kivy.org/) 2.x
- [python-for-android (p4a)](https://python-for-android.readthedocs.io/) for building an APK
- No third-party crypto libraries — stdlib only

---

## Building for Android

```bash
# Install buildozer
pip install buildozer

# Initialise a buildozer.spec (first time only)
buildozer init

# Build and deploy to a connected device
buildozer android debug deploy run
```

Key `buildozer.spec` settings:

```ini
source.include_exts = py
requirements = python3,kivy
android.permissions =
# No external storage permissions needed
```

---

## Running on Desktop (Development)

```bash
pip install kivy
python sxmdatabase_aes256_add_delete_v1_1_main.py
```

The database will be created in your home directory. Mouse multitouch emulation is enabled on desktop (`Ctrl+click` to simulate a second touch point).

---

## Changelog

### v1.1
- Added `TimeoutManager` — inactivity tracking with a 1-second Clock interval
- Added `TimeoutOverlay` — full-screen warning with live countdown; any tap resets the timer
- Timeout triggers a clean shutdown: DB re-encrypted → passphrase cleared → process exits
- Voluntary lock (back button, Quit) now explicitly cancels the idle timer

### v1.0
- Initial release
- AES-256-CBC encryption with pure-Python implementation
- PBKDF2-HMAC-SHA1 key derivation (10,000 iterations)
- Passphrase attempt counter with wipe-on-5th-failure
- Lock, Database, Edit, and Output screens
- Adaptive layout for phones and tablets
- Expired subscription highlighting in the record list
