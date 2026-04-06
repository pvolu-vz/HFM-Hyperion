#!/usr/bin/env bash
# install_hfm_hyperion.sh — One-command installer for Oracle Hyperion HFM → Veza OAA integration
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/hfm-hyperion-veza"
REPO_URL="https://github.com/<org>/HFM-Hyperion.git"
BRANCH="main"
NON_INTERACTIVE=false
OVERWRITE_ENV=false
MIN_PYTHON="3.8"

# ─────────────────────────────────────────────────────────────────────────────
# CLI flags
# ─────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --non-interactive) NON_INTERACTIVE=true; shift ;;
        --overwrite-env)   OVERWRITE_ENV=true;   shift ;;
        --install-dir)     INSTALL_DIR="$2";     shift 2 ;;
        --repo-url)        REPO_URL="$2";        shift 2 ;;
        --branch)          BRANCH="$2";          shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --non-interactive   Use env vars instead of prompts"
            echo "  --overwrite-env     Overwrite existing .env file"
            echo "  --install-dir PATH  Installation directory (default: /opt/hfm-hyperion-veza)"
            echo "  --repo-url URL      Git repository URL"
            echo "  --branch NAME       Git branch to checkout (default: main)"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; exit 1; }

prompt_val() {
    local var_name="$1" prompt_text="$2" default_val="${3:-}"
    # Non-interactive: use env var
    if $NON_INTERACTIVE; then
        local env_val="${!var_name:-$default_val}"
        if [[ -z "$env_val" ]]; then
            error "Non-interactive mode: $var_name is required but not set"
        fi
        echo "$env_val"
        return
    fi
    # Interactive
    if [[ -n "$default_val" ]]; then
        read -rp "$prompt_text [$default_val]: " val
        echo "${val:-$default_val}"
    else
        read -rp "$prompt_text: " val
        if [[ -z "$val" ]]; then
            error "$var_name cannot be empty"
        fi
        echo "$val"
    fi
}

prompt_secret() {
    local var_name="$1" prompt_text="$2"
    if $NON_INTERACTIVE; then
        local env_val="${!var_name:-}"
        if [[ -z "$env_val" ]]; then
            error "Non-interactive mode: $var_name is required but not set"
        fi
        echo "$env_val"
        return
    fi
    read -rsp "$prompt_text: " val
    echo ""
    if [[ -z "$val" ]]; then
        error "$var_name cannot be empty"
    fi
    echo "$val"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Detect OS and install system dependencies
# ─────────────────────────────────────────────────────────────────────────────
info "Detecting operating system..."

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
else
    DISTRO="unknown"
fi

install_packages() {
    case "$DISTRO" in
        rhel|centos|fedora|rocky|almalinux|ol)
            info "Detected RHEL/CentOS/Fedora family — using dnf/yum"
            if command -v dnf &>/dev/null; then
                sudo dnf install -y git curl python3 python3-pip python3-devel
            elif command -v yum &>/dev/null; then
                sudo yum install -y git curl python3 python3-pip python3-devel
            else
                error "Neither dnf nor yum found"
            fi
            ;;
        ubuntu|debian|linuxmint|pop)
            info "Detected Debian/Ubuntu family — using apt"
            sudo apt-get update -qq
            sudo apt-get install -y git curl python3 python3-pip python3-venv
            ;;
        *)
            warn "Unknown distro '$DISTRO' — assuming packages are pre-installed"
            ;;
    esac
}

install_packages

# ─────────────────────────────────────────────────────────────────────────────
# 2. Verify Python version ≥ 3.8
# ─────────────────────────────────────────────────────────────────────────────
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    error "Python 3 is required but not found. Install Python >= $MIN_PYTHON and retry."
fi

PY_VER=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON_BIN" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON_BIN" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 8 ]]; }; then
    error "Python >= $MIN_PYTHON is required. Found: $PY_VER"
fi
info "Using $PYTHON_BIN ($PY_VER)"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Create directory layout
# ─────────────────────────────────────────────────────────────────────────────
info "Creating directory layout at $INSTALL_DIR ..."
sudo mkdir -p "$INSTALL_DIR/scripts"
sudo mkdir -p "$INSTALL_DIR/logs"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Clone / update repository
# ─────────────────────────────────────────────────────────────────────────────
SCRIPTS_DIR="$INSTALL_DIR/scripts"

if [[ -d "$SCRIPTS_DIR/.git" ]]; then
    info "Repository already cloned — pulling latest..."
    cd "$SCRIPTS_DIR"
    sudo git fetch origin
    sudo git checkout "$BRANCH"
    sudo git pull origin "$BRANCH"
else
    info "Cloning repository..."
    sudo git clone --branch "$BRANCH" "$REPO_URL" "$SCRIPTS_DIR"
fi

cd "$SCRIPTS_DIR"

# If the integration files are inside integrations/hfm-hyperion/, copy them up
if [[ -d "$SCRIPTS_DIR/integrations/hfm-hyperion" ]]; then
    sudo cp "$SCRIPTS_DIR/integrations/hfm-hyperion/hfm_hyperion.py" "$SCRIPTS_DIR/"
    sudo cp "$SCRIPTS_DIR/integrations/hfm-hyperion/requirements.txt" "$SCRIPTS_DIR/"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. Create Python virtual environment and install dependencies
# ─────────────────────────────────────────────────────────────────────────────
info "Creating Python virtual environment..."
sudo "$PYTHON_BIN" -m venv "$SCRIPTS_DIR/venv"
sudo "$SCRIPTS_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
sudo "$SCRIPTS_DIR/venv/bin/pip" install -r "$SCRIPTS_DIR/requirements.txt"
info "Dependencies installed"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Collect credentials and generate .env
# ─────────────────────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPTS_DIR/.env"

if [[ -f "$ENV_FILE" ]] && ! $OVERWRITE_ENV; then
    warn ".env already exists — skipping credential setup (use --overwrite-env to replace)"
else
    info "Configuring credentials..."

    VEZA_URL_VAL=$(prompt_val    "VEZA_URL"       "Veza instance URL (e.g. your-company.vezacloud.com)")
    VEZA_API_KEY_VAL=$(prompt_secret "VEZA_API_KEY"   "Veza API key")
    HFM_SEC_FILE_VAL=$(prompt_val   "HFM_SEC_FILE"   "Path to HFM .sec security export file" "/data/hfm/SW_Security.sec")
    HFM_GROUPS_CSV_VAL=$(prompt_val "HFM_GROUPS_CSV" "Path to EPM Groups CSV export file"    "/data/hfm/Groups.csv")

    sudo tee "$ENV_FILE" > /dev/null <<ENVEOF
# Oracle Hyperion HFM — Veza OAA Integration
# Generated by install_hfm_hyperion.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Veza Configuration
VEZA_URL=$VEZA_URL_VAL
VEZA_API_KEY=$VEZA_API_KEY_VAL

# HFM Data Source Files
# Paths can be local or on an SMB/CIFS mounted share
HFM_SEC_FILE=$HFM_SEC_FILE_VAL
HFM_GROUPS_CSV=$HFM_GROUPS_CSV_VAL

# OAA Provider Settings (optional overrides)
# PROVIDER_NAME=Oracle Hyperion HFM
# DATASOURCE_NAME=HFM Security
ENVEOF

    sudo chmod 600 "$ENV_FILE"
    info ".env written with mode 600"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Installation Complete"
echo "============================================================"
echo ""
echo "  Install directory : $INSTALL_DIR"
echo "  Scripts           : $SCRIPTS_DIR"
echo "  Virtual env       : $SCRIPTS_DIR/venv"
echo "  Config file       : $ENV_FILE"
echo "  Log directory     : $INSTALL_DIR/logs"
echo ""
echo "  Quick test (dry-run):"
echo "    cd $SCRIPTS_DIR"
echo "    source venv/bin/activate"
echo "    python3 hfm_hyperion.py --env-file .env --dry-run"
echo ""
echo "  Production run:"
echo "    cd $SCRIPTS_DIR"
echo "    source venv/bin/activate"
echo "    python3 hfm_hyperion.py --env-file .env"
echo ""
echo "============================================================"
