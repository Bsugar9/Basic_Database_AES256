#!/usr/bin/env bash
# ============================================================
# build_apk.sh  —  SiriusXM Dealer APK builder
#
# Fixes applied vs previous version:
#   • Explicit p4a.bootstrap = sdl2  (prevents silent launch crash)
#   • android:exported="true"        (required API 31+)
#   • Internal storage DB path       (no storage permission needed)
#   • targetSdk 34 + Java 17         (Google Play compliance)
#   • Cython 0.29.37 pinned first    (pyjnius compat)
#
# After a crash-on-launch, run the logcat section at the bottom
# to read the actual error before rebuilding.
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[OK]${NC}    $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 1. System packages ──────────────────────────────────────────────────────
info "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    git zip unzip curl wget \
    openjdk-17-jdk \
    autoconf automake libtool \
    build-essential libffi-dev libssl-dev \
    ccache libsqlite3-dev lld \
    adb \
    > /dev/null 2>&1
ok "System packages ready."

# ── 2. Force Java 17 ───────────────────────────────────────────────────────
info "Setting Java 17 as active JDK..."
sudo update-alternatives --set java  \
    /usr/lib/jvm/java-17-openjdk-amd64/bin/java  2>/dev/null || true
sudo update-alternatives --set javac \
    /usr/lib/jvm/java-17-openjdk-amd64/bin/javac 2>/dev/null || true
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
[[ "$JAVA_VER" -ge 17 ]] || error "Java 17+ required. Got Java $JAVA_VER."
ok "Java $JAVA_VER active."

# ── 3. Python check ─────────────────────────────────────────────────────────
PY_MIN=$(python3 -c "import sys; print(sys.version_info.minor)")
[[ "$PY_MIN" -le 11 ]] || warn "Python 3.$PY_MIN — pyjnius most stable on 3.10/3.11."
ok "Python 3.$PY_MIN detected."

# ── 4. Virtual environment ─────────────────────────────────────────────────
VENV=".venv_build"
[[ -d "$VENV" ]] || python3 -m venv "$VENV"
# shellcheck disable=SC1090
source "$VENV/bin/activate"
pip install --quiet --upgrade pip
ok "Virtualenv active."

# ── 5. Pin Cython 0.29.x BEFORE everything else ────────────────────────────
info "Pinning Cython 0.29.37 (must precede all other installs)..."
pip install --quiet "Cython==0.29.37"
CY=$(python3 -c "import Cython; print(Cython.__version__)")
[[ "$CY" == 0.29* ]] || error "Cython version wrong: $CY"
ok "Cython $CY pinned."

# ── 6. Install buildozer + deps ────────────────────────────────────────────
info "Installing buildozer and Python deps..."
pip install --quiet "buildozer>=1.5.0" "pyjnius==1.6.1" requests colorama appdirs sh
ok "Build tools ready."

# ── 7. Validate buildozer.spec ─────────────────────────────────────────────
SPEC="buildozer.spec"
[[ -f "$SPEC" ]] || error "buildozer.spec not found in $(pwd)"

API=$(grep -E '^android\.api\s*=' "$SPEC" | awk -F'=' '{print $2}' | tr -d ' ')
[[ "$API" -ge 34 ]] || error "android.api=$API — Google Play requires >=34."

BOOTSTRAP=$(grep -E '^p4a\.bootstrap\s*=' "$SPEC" | awk -F'=' '{print $2}' | tr -d ' ')
[[ "$BOOTSTRAP" == "sdl2" ]] || warn "p4a.bootstrap is '$BOOTSTRAP' — should be 'sdl2'."

ok "buildozer.spec looks good (api=$API, bootstrap=$BOOTSTRAP)."

# ── 8. Build ───────────────────────────────────────────────────────────────
info "First build downloads Android SDK/NDK (~2 GB) — may take 20-40 min."
info "Running buildozer android debug..."
buildozer -v android debug 2>&1 | tee build.log

# ── 9. Result ──────────────────────────────────────────────────────────────
APK=$(find ./bin -name "*.apk" 2>/dev/null | head -1)
[[ -n "$APK" ]] || error "No APK found in ./bin — check build.log."

echo ""
echo -e "${GRN}══════════════════════════════════════════════════════${NC}"
echo -e "${GRN}  BUILD COMPLETE${NC}"
echo -e "${GRN}  APK: $APK${NC}"
echo -e "${GRN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "Install on device:"
echo "  adb install \"$APK\""
echo ""
echo "══════════════════════════════════════════════════════"
echo "  CRASH DIAGNOSIS — if app still closes on launch:"
echo "══════════════════════════════════════════════════════"
echo ""
echo "  Connect device via USB with USB Debugging ON, then:"
echo ""
echo "  # Stream live crash log (Ctrl-C to stop):"
echo "  adb logcat -s python:D AndroidRuntime:E ActivityManager:I | grep -i -E 'python|kivy|sxm|error|crash|exception'"
echo ""
echo "  # Or capture 5 seconds after tapping the app icon:"
echo "  adb logcat -d | grep -i -E 'python|kivy|fatal|exception|sxmdealer'"
echo ""
echo "  Common causes and fixes:"
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ 'No module named kivy'      → requirements line in .spec wrong  │"
echo "  │ 'Unable to start activity'  → android:exported missing in spec  │"
echo "  │ 'No bootstrap found'        → p4a.bootstrap = sdl2 missing      │"
echo "  │ sqlite3 OperationalError    → DB path unwritable on device      │"
echo "  │ 'ModuleNotFoundError:req..' → requests not in requirements      │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
