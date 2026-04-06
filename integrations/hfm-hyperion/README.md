# Oracle Hyperion HFM → Veza OAA Integration

Push identity, group, role, and security-class permission data from Oracle Hyperion Financial Management (HFM) into Veza's Authorization Graph using the Open Authorization API (OAA).

---

## Overview

This connector reads two flat-file exports from Oracle Hyperion HFM / EPM Shared Services and models them as a Veza **CustomApplication**:

| Source File | Contents |
|---|---|
| `.sec` file | HFM Security export — users, groups, roles, security classes, role-access assignments, and security-class-access permissions |
| `Groups.csv` | EPM Shared Services group definitions with descriptions and user-to-group membership |

### What appears in Veza

| Veza Entity Type | Source |
|---|---|
| **Provider** | `Oracle Hyperion HFM` |
| **Application** | Datasource name (default: `HFM Security`) |
| **Local Users** | Users extracted from `.sec` `!USERS_AND_GROUPS` section |
| **Local Groups** | Groups matched between `.sec` and `Groups.csv` |
| **Local Roles** | Unique roles from `.sec` `!ROLE_ACCESS` (e.g. Reviewer 1–7, Consolidate, Database Management) |
| **Resources** (type: `security_class`) | HFM Security Classes (e.g. `E_MXACO`, `E_AGBAR`) from `.sec` `!SECURITY_CLASSES` |
| **Permissions** | `None`, `Read`, `Promote`, `All` — mapped from `!SECURITY_CLASS_ACCESS` |

---

## How It Works

1. Parse the HFM `.sec` security export file to extract users, groups, security classes, role assignments, and security-class access permissions
2. Parse the `Groups.csv` EPM export to get group descriptions and user-to-group memberships
3. Classify identities as users or groups based on domain and presence in the Groups CSV
4. Build a Veza `CustomApplication` payload with local users, local groups, local roles, security-class resources, role assignments, and security-class permission bindings
5. Push the payload to Veza (or output dry-run summary)

---

## Prerequisites

- **OS**: Linux (RHEL/CentOS 7+, Ubuntu 18.04+) or macOS
- **Python**: 3.8+
- **Network**: Outbound HTTPS access to your Veza tenant (`https://<company>.vezacloud.com`)
- **HFM Exports**: The `.sec` and `Groups.csv` files, available on a local path or SMB/CIFS-mounted share
- **Veza**: API key with provider write permissions

---

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/<org>/HFM-Hyperion/main/integrations/hfm-hyperion/install_hfm_hyperion.sh | bash
```

The installer will prompt for your Veza URL, API key, and file paths.

### Non-interactive install (CI/CD)

```bash
VEZA_URL=your-company.vezacloud.com \
VEZA_API_KEY=your_key_here \
HFM_SEC_FILE=/data/hfm/SW_Security.sec \
HFM_GROUPS_CSV=/data/hfm/Groups.csv \
bash install_hfm_hyperion.sh --non-interactive
```

---

## Manual Installation

### RHEL / CentOS / Fedora

```bash
sudo dnf install -y git python3 python3-pip python3-devel
git clone https://github.com/<org>/HFM-Hyperion.git /opt/hfm-hyperion-veza/scripts
cd /opt/hfm-hyperion-veza/scripts/integrations/hfm-hyperion
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
# Edit .env with your credentials and file paths
```

### Ubuntu / Debian

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-pip python3-venv
git clone https://github.com/<org>/HFM-Hyperion.git /opt/hfm-hyperion-veza/scripts
cd /opt/hfm-hyperion-veza/scripts/integrations/hfm-hyperion
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
# Edit .env with your credentials and file paths
```

---

## Usage

### CLI Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--sec-file` | Yes* | `HFM_SEC_FILE` env var | Path to HFM `.sec` security export |
| `--groups-csv` | Yes* | `HFM_GROUPS_CSV` env var | Path to EPM Groups CSV export |
| `--env-file` | No | `.env` | Path to `.env` configuration file |
| `--veza-url` | Yes* | `VEZA_URL` env var | Veza instance URL |
| `--veza-api-key` | Yes* | `VEZA_API_KEY` env var | Veza API key |
| `--provider-name` | No | `Oracle Hyperion HFM` | Provider name in Veza UI |
| `--datasource-name` | No | `HFM Security` | Datasource name in Veza UI |
| `--dry-run` | No | `false` | Build payload without pushing to Veza |
| `--log-level` | No | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

*Can be provided via CLI flag, environment variable, or `.env` file.

### Examples

```bash
# Dry-run test
python3 hfm_hyperion.py \
  --sec-file /data/hfm/SW_Security_10-Mar-26.sec \
  --groups-csv /data/hfm/Groups.csv \
  --dry-run

# Production push
python3 hfm_hyperion.py --env-file /opt/hfm-hyperion-veza/scripts/.env

# Debug logging
python3 hfm_hyperion.py --env-file .env --log-level DEBUG

# Custom provider/datasource names
python3 hfm_hyperion.py --env-file .env \
  --provider-name "Hyperion HFM PROD" \
  --datasource-name "HFM Production - March 2026"
```

---

## Deployment on Linux

### Service account

```bash
sudo useradd -r -s /bin/bash -m -d /opt/hfm-hyperion-veza hfm-hyperion-veza
sudo chown -R hfm-hyperion-veza:hfm-hyperion-veza /opt/hfm-hyperion-veza
```

### File permissions

```bash
chmod 700 /opt/hfm-hyperion-veza/scripts
chmod 600 /opt/hfm-hyperion-veza/scripts/.env
```

### SELinux (RHEL / CentOS / Rocky)

```bash
# Check enforcement mode
getenforce

# If Enforcing, restore file contexts after install
sudo restorecon -Rv /opt/hfm-hyperion-veza/
```

### Cron scheduling

Create a wrapper script:

```bash
cat > /opt/hfm-hyperion-veza/scripts/run_hfm_veza.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/hfm-hyperion-veza/scripts
source venv/bin/activate
python3 hfm_hyperion.py --env-file .env \
  >> /opt/hfm-hyperion-veza/logs/hfm_veza.log 2>&1
EOF
chmod 700 /opt/hfm-hyperion-veza/scripts/run_hfm_veza.sh
```

Add cron entry (`/etc/cron.d/hfm-hyperion-veza`):

```cron
# Run HFM → Veza sync daily at 02:00 UTC
0 2 * * * hfm-hyperion-veza /opt/hfm-hyperion-veza/scripts/run_hfm_veza.sh
```

### Log rotation

Create `/etc/logrotate.d/hfm-hyperion-veza`:

```
/opt/hfm-hyperion-veza/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 hfm-hyperion-veza hfm-hyperion-veza
}
```

---

## SMB/CIFS Mount for Remote Files

If the HFM export files are on a Windows file share:

```bash
# Install CIFS utilities
sudo dnf install -y cifs-utils     # RHEL
sudo apt-get install -y cifs-utils  # Ubuntu

# Create mount point
sudo mkdir -p /mnt/hfm-share

# Mount the share (add to /etc/fstab for persistence)
sudo mount -t cifs //fileserver/hfm-exports /mnt/hfm-share \
  -o username=svc_hfm,domain=CORP,uid=hfm-hyperion-veza,gid=hfm-hyperion-veza,file_mode=0400,dir_mode=0500

# Update .env to use mounted paths
# HFM_SEC_FILE=/mnt/hfm-share/SW_Security.sec
# HFM_GROUPS_CSV=/mnt/hfm-share/Groups.csv
```

---

## Security Considerations

- **Credential storage**: The Veza API key is stored in `.env` with `chmod 600`. Rotate the key periodically according to your organization's policy.
- **File permissions**: Ensure the `.sec` and `Groups.csv` files are readable only by the service account.
- **SELinux / AppArmor**: After installation, restore file contexts (`restorecon`) or create AppArmor profiles as needed.
- **Network**: Only outbound HTTPS to Veza is required. No inbound ports need to be opened.

---

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `ModuleNotFoundError: oaaclient` | Activate the venv: `source venv/bin/activate` |
| `HFM .sec file not found` | Verify the path in `.env` or `--sec-file`. If using SMB, check the mount is active. |
| `VEZA_URL and VEZA_API_KEY are required` | Set credentials in `.env` or pass via CLI flags / env vars |
| `Veza push failed: 401` | API key is invalid or expired. Generate a new key in the Veza admin console. |
| `Veza push failed: 409` | Provider or datasource name conflict. Use `--provider-name` or `--datasource-name` to disambiguate. |
| `Veza warning: identity not found` | A `.sec` user identity could not be linked to an IdP. This is informational. |
| `Unknown access level` in logs | The `.sec` file contains a permission value not in (`None`, `Read`, `Promote`, `All`). Check the export. |
| Permission denied on `.env` | Run `chmod 600 .env` and ensure the correct user owns the file. |

---

## OAA Entity Mapping

```
┌─────────────────────────────────────────────────────────────┐
│  Source (.sec / Groups.csv)        Veza OAA Entity          │
├─────────────────────────────────────────────────────────────┤
│  HFM Instance                  →  Application               │
│  user@Group / user@Westrock    →  Local User                │
│  GROUP_*@Native Directory      →  Local Group               │
│  Groups.csv #group_children    →  Group Membership           │
│  !ROLE_ACCESS roles            →  Local Role                 │
│  !ROLE_ACCESS assignments      →  Role → User/Group binding  │
│  !SECURITY_CLASSES entries     →  Resource (security_class)  │
│  !SECURITY_CLASS_ACCESS        →  Permission binding         │
│    None / Read / Promote / All →  Custom Permissions         │
└─────────────────────────────────────────────────────────────┘
```

---

## Changelog

### v1.0.0 — Initial Release
- Parse HFM `.sec` security export (format 2.0, version 11.12)
- Parse EPM Shared Services `Groups.csv` with group definitions and memberships
- Model users, groups, roles, security classes, role assignments, and security-class permissions
- Support local files and SMB/CIFS mounted shares
- `--dry-run` mode for validation without pushing
- Bash one-command installer with RHEL and Ubuntu support
