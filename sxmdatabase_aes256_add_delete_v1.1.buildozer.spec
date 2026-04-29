[app]

# ── App metadata ───────────────────────────────────────────────────────────────
title           = SiriusXM Dealer
package.name    = sxmdealer
package.domain  = com.dealer.sxm

source.dir          = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.1.0

# ── Requirements ───────────────────────────────────────────────────────────────
# Cython MUST stay 0.29.x — Cython 3 dropped `long`, which breaks pyjnius.
# hostpython3 forces the build toolchain to use Python 3 properly.
requirements = hostpython3,python3,kivy==2.3.0,requests,urllib3,certifi,charset-normalizer,idna,Cython==0.29.37,pyjnius==1.6.1

# ── Bootstrap ─────────────────────────────────────────────────────────────────
# CRITICAL FIX: Explicit sdl2 bootstrap prevents the "no bootstrap found"
# silent crash that kills the app immediately on launch.
p4a.bootstrap = sdl2

# ── Orientation ────────────────────────────────────────────────────────────────
orientation = portrait

# ── Permissions ────────────────────────────────────────────────────────────────
# Only INTERNET + NETWORK_STATE needed; no external storage used.
# Requesting unnecessary permissions triggers Play policy warnings.
android.permissions = INTERNET,ACCESS_NETWORK_STATE

# ── API levels ─────────────────────────────────────────────────────────────────
# targetSdkVersion 34 mandatory for Google Play since August 2024.
# minSdkVersion 26 = Android 8.0 (~99% of active devices).
android.minapi = 26
android.api    = 34
android.ndk    = 25b
android.sdk    = 34

# ── Architectures ─────────────────────────────────────────────────────────────
android.archs = arm64-v8a, armeabi-v7a

# ── Entry point ────────────────────────────────────────────────────────────────
android.entrypoint = org.kivy.android.PythonActivity

# ── CRITICAL: android:exported ─────────────────────────────────────────────────
# API 31+ requires every Activity with an intent-filter to declare
# android:exported explicitly. Without this the OS refuses to launch the app.
android.manifest_attributes = android:exported="true"

# ── Icon / splash ──────────────────────────────────────────────────────────────
# Uncomment and place files in source dir:
# icon.filename      = %(source.dir)s/icon.png
# presplash.filename = %(source.dir)s/presplash.png

# ── Backup (Play policy) ───────────────────────────────────────────────────────
android.allow_backup = True

# ── Gradle ────────────────────────────────────────────────────────────────────
# Java 17 source/target is required when compileSdk >= 34.
android.gradle_dependencies =
android.add_gradle_properties = android.defaults.buildfeatures.buildconfig=true

# ── p4a ───────────────────────────────────────────────────────────────────────
p4a.branch = master

# ── Misc ──────────────────────────────────────────────────────────────────────
android.meta_data =
android.features  =
fullscreen          = 0
android.fullscreen  = 0

[buildozer]
log_level    = 2
warn_on_root = 1
build_dir    = ./.buildozer
bin_dir      = ./bin
