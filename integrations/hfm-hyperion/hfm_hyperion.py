#!/usr/bin/env python3
"""
Oracle Hyperion HFM to Veza OAA Integration Script
Collects identity, role, and security-class permission data from HFM export files
(.sec and Groups CSV) and pushes to Veza as a CustomApplication.

Data sources:
  - .sec file  : HFM Security export (users, groups, roles, security classes, access)
  - Groups CSV : EPM Shared Services group definitions and membership

Supports local file paths and SMB/CIFS mounted shares.
"""

import argparse
import csv
import io
import logging
import os
import re
import sys
from collections import defaultdict

from dotenv import load_dotenv
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("hfm_hyperion")


# ===========================================================================
# .sec file parser
# ===========================================================================

def parse_sec_file(filepath):
    """Parse an HFM .sec security export file.

    Returns a dict with keys:
        file_format  : str
        version      : str
        users_and_groups : list[str]       – raw lines like 'user@Domain'
        security_classes : list[str]       – e.g. 'E_MXACO'
        role_access  : list[tuple[str,str]] – (role_name, identity)
        security_class_access : list[tuple[str,str,str,str]]
                                            – (class, identity, access, flag)
    """
    result = {
        "file_format": "",
        "version": "",
        "users_and_groups": [],
        "security_classes": [],
        "role_access": [],
        "security_class_access": [],
    }

    current_section = None

    with open(filepath, "r", encoding="utf-8-sig") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n\r")

            # Metadata headers
            if line.startswith("!FILE_FORMAT="):
                result["file_format"] = line.split("=", 1)[1]
                continue
            if line.startswith("!VERSION="):
                result["version"] = line.split("=", 1)[1]
                continue

            # Section markers
            if line == "!USERS_AND_GROUPS":
                current_section = "users_and_groups"
                continue
            if line == "!SECURITY_CLASSES":
                current_section = "security_classes"
                continue
            if line == "!ROLE_ACCESS":
                current_section = "role_access"
                continue
            if line == "!SECURITY_CLASS_ACCESS":
                current_section = "security_class_access"
                continue

            # Skip blanks and bracketed lines like '[Default]'
            if not line or line.startswith("["):
                continue

            # Collect data
            if current_section == "users_and_groups":
                result["users_and_groups"].append(line)
            elif current_section == "security_classes":
                result["security_classes"].append(line)
            elif current_section == "role_access":
                parts = line.split(";", 1)
                if len(parts) == 2:
                    result["role_access"].append((parts[0], parts[1]))
            elif current_section == "security_class_access":
                parts = line.split(";")
                if len(parts) >= 3:
                    sec_class = parts[0]
                    identity = parts[1]
                    access_level = parts[2]
                    flag = parts[3] if len(parts) > 3 else ""
                    result["security_class_access"].append(
                        (sec_class, identity, access_level, flag)
                    )

    log.info(
        "Parsed .sec file: %d users/groups, %d security classes, "
        "%d role assignments, %d security-class access entries",
        len(result["users_and_groups"]),
        len(result["security_classes"]),
        len(result["role_access"]),
        len(result["security_class_access"]),
    )
    return result


# ===========================================================================
# Groups CSV parser
# ===========================================================================

def parse_groups_csv(filepath):
    """Parse the EPM Shared Services Groups CSV export.

    The file contains repeated sections:
      #group            – group definitions (id,provider,name,description,internal_id)
      #group_children   – membership rows  (id,group_id,group_provider,user_id,user_provider)

    Returns:
        groups : dict  – group_id -> {name, provider, description, internal_id}
        memberships : dict – group_id -> list[{user_id, user_provider}]
    """
    groups = {}
    memberships = defaultdict(list)

    with open(filepath, "r", encoding="utf-8-sig") as fh:
        content = fh.read()

    # Split on section headers
    # Sections start with lines like "#group\n" or "#group_children\n"
    sections = re.split(r"(?m)^#(\w+)\s*$", content)

    # sections is interleaved: ['', 'group', '<data>', 'group_children', '<data>', ...]
    i = 1
    while i < len(sections) - 1:
        section_name = sections[i].strip()
        section_data = sections[i + 1].strip()
        i += 2

        if not section_data:
            continue

        reader = csv.DictReader(io.StringIO(section_data))

        if section_name == "group":
            for row in reader:
                gid = row.get("id", "").strip()
                if gid:
                    groups[gid] = {
                        "name": row.get("name", gid).strip(),
                        "provider": row.get("provider", "").strip(),
                        "description": row.get("description", "").strip(),
                        "internal_id": row.get("internal_id", "").strip(),
                    }

        elif section_name == "group_children":
            for row in reader:
                gid = row.get("id", "").strip()
                user_id = row.get("user_id", "").strip()
                user_provider = row.get("user_provider", "").strip()
                if gid and user_id:
                    memberships[gid].append({
                        "user_id": user_id,
                        "user_provider": user_provider,
                    })

    log.info(
        "Parsed Groups CSV: %d groups, %d membership entries",
        len(groups),
        sum(len(v) for v in memberships.values()),
    )
    return groups, memberships


# ===========================================================================
# Identity classification helpers
# ===========================================================================

NATIVE_DIRECTORY = "Native Directory"


def split_identity(raw):
    """Split 'name@Domain' into (name, domain)."""
    if "@" in raw:
        parts = raw.rsplit("@", 1)
        return parts[0], parts[1]
    return raw, ""


def is_group_entry(name, domain, group_lookup):
    """Determine if an identity from the .sec file is a group.

    Groups in the .sec file appear as 'GroupName@Native Directory' and exist
    in the Groups CSV lookup.  Service accounts (e.g. MerlinXL@Native Directory)
    that do NOT appear in the groups CSV are treated as users.
    Case-insensitive comparison.
    """
    if domain == NATIVE_DIRECTORY:
        name_lower = name.lower()
        for gname in group_lookup:
            if gname.lower() == name_lower:
                return True
    return False


# ===========================================================================
# OAA payload builder
# ===========================================================================

def build_oaa_payload(sec_data, groups_csv, memberships, args):
    """Build the CustomApplication OAA payload from parsed data."""

    app = CustomApplication(
        name=args.datasource_name,
        application_type=args.provider_name,
    )

    # ---- Custom permissions (from SECURITY_CLASS_ACCESS access levels) ----
    app.add_custom_permission("None", [OAAPermission.NonData])
    app.add_custom_permission("Read", [OAAPermission.DataRead, OAAPermission.MetadataRead])
    app.add_custom_permission("Promote", [
        OAAPermission.DataRead,
        OAAPermission.DataWrite,
        OAAPermission.MetadataRead,
    ])
    app.add_custom_permission("All", [
        OAAPermission.DataRead,
        OAAPermission.DataWrite,
        OAAPermission.DataCreate,
        OAAPermission.DataDelete,
        OAAPermission.MetadataRead,
        OAAPermission.MetadataWrite,
    ])

    # ---- Custom properties ----
    app.property_definitions.define_local_user_property("domain", OAAPropertyType.STRING)
    app.property_definitions.define_local_group_property("description", OAAPropertyType.STRING)
    app.property_definitions.define_local_group_property("provider", OAAPropertyType.STRING)
    app.property_definitions.define_local_group_property("internal_id", OAAPropertyType.STRING)
    app.property_definitions.define_resource_property("security_class", "class_name", OAAPropertyType.STRING)

    # ---- Classify identities from .sec USERS_AND_GROUPS ----
    # Identities are case-insensitive (e.g. lmercader@Westrock == LMercader@Group)
    user_dict = {}    # lowercase name -> (display_name, domain)
    group_set = set()
    group_display = {}  # lowercase -> original casing

    for raw in sec_data["users_and_groups"]:
        name, domain = split_identity(raw)
        key = name.lower()
        if is_group_entry(name, domain, groups_csv):
            group_set.add(key)
            if key not in group_display:
                group_display[key] = name
        else:
            if key not in user_dict:
                user_dict[key] = (name, domain)

    # ---- Create local groups ----
    # Groups CSV keys are case-sensitive original names; build a case-insensitive lookup
    groups_csv_lower = {k.lower(): v for k, v in groups_csv.items()}

    for gkey in sorted(group_set):
        display_name = group_display.get(gkey, gkey)
        ginfo = groups_csv_lower.get(gkey, {})
        group = app.add_local_group(
            name=display_name,
            unique_id=gkey,
        )
        if ginfo.get("description"):
            group.set_property("description", ginfo["description"])
        if ginfo.get("provider"):
            group.set_property("provider", ginfo["provider"])
        if ginfo.get("internal_id"):
            group.set_property("internal_id", ginfo["internal_id"])

    log.info("Created %d local groups", len(group_set))

    # ---- Create local users ----
    for ukey in sorted(user_dict):
        display_name, domain = user_dict[ukey]
        user = app.add_local_user(
            name=display_name,
            unique_id=ukey,
        )
        if domain:
            user.set_property("domain", domain)

    log.info("Created %d local users", len(user_dict))

    # ---- Assign group memberships from Groups CSV ----
    # Build case-insensitive membership lookup
    memberships_lower = {k.lower(): v for k, v in memberships.items()}

    membership_count = 0
    for gkey in group_set:
        members = memberships_lower.get(gkey, [])
        for member in members:
            uid_lower = member["user_id"].lower()
            if uid_lower in app.local_users:
                app.local_users[uid_lower].add_group(gkey)
                membership_count += 1

    log.info("Assigned %d group memberships", membership_count)

    # ---- Create local roles from ROLE_ACCESS ----
    role_names = sorted({role for role, _ in sec_data["role_access"]})
    for role_name in role_names:
        app.add_local_role(role_name, unique_id=role_name)

    log.info("Created %d local roles", len(role_names))

    # ---- Create security class resources ----
    for sc_name in sec_data["security_classes"]:
        resource = app.add_resource(
            name=sc_name,
            resource_type="security_class",
            description=f"HFM Security Class {sc_name}",
        )
        resource.set_property("class_name", sc_name)

    log.info("Created %d security class resources", len(sec_data["security_classes"]))

    # ---- Assign role access (case-insensitive identity lookup) ----
    role_assign_count = 0
    for role_name, raw_identity in sec_data["role_access"]:
        identity_name, domain = split_identity(raw_identity)
        key = identity_name.lower()

        if key in app.local_users:
            app.local_users[key].add_role(
                role_name, apply_to_application=True
            )
            role_assign_count += 1
        elif key in app.local_groups:
            app.local_groups[key].add_role(
                role_name, apply_to_application=True
            )
            role_assign_count += 1
        else:
            log.debug(
                "Role '%s' assigned to unknown identity '%s' — skipped",
                role_name,
                identity_name,
            )

    log.info("Assigned %d role-to-identity bindings", role_assign_count)

    # ---- Assign security-class access (case-insensitive identity lookup) ----
    sc_perm_count = 0
    for sec_class, raw_identity, access_level, _flag in sec_data["security_class_access"]:
        identity_name, domain = split_identity(raw_identity)
        key = identity_name.lower()

        # Validate access level
        if access_level not in ("None", "Read", "Promote", "All"):
            log.warning(
                "Unknown access level '%s' for class '%s' identity '%s' — skipped",
                access_level,
                sec_class,
                identity_name,
            )
            continue

        # Find the security class resource
        if sec_class not in app.resources:
            log.debug(
                "Security class '%s' not in resource list — skipped",
                sec_class,
            )
            continue

        resource = app.resources[sec_class]

        if key in app.local_users:
            app.local_users[key].add_permission(
                permission=access_level,
                resources=[resource],
            )
            sc_perm_count += 1
        elif key in app.local_groups:
            app.local_groups[key].add_permission(
                permission=access_level,
                resources=[resource],
            )
            sc_perm_count += 1
        else:
            log.debug(
                "Security-class access for unknown identity '%s' — skipped",
                identity_name,
            )

    log.info("Assigned %d security-class permission bindings", sc_perm_count)

    return app


# ===========================================================================
# Veza push
# ===========================================================================

def push_to_veza(veza_url, veza_api_key, provider_name, datasource_name, app, dry_run=False):
    """Push the CustomApplication payload to Veza."""

    if dry_run:
        log.info("[DRY RUN] Payload built successfully — skipping push to Veza")
        payload = app.get_payload()
        log.info(
            "[DRY RUN] Payload contains %d local users, %d local groups, "
            "%d local roles, %d resources",
            len(payload.get("applications", [{}])[0].get("local_users", [])),
            len(payload.get("applications", [{}])[0].get("local_groups", [])),
            len(payload.get("applications", [{}])[0].get("local_roles", [])),
            len(payload.get("applications", [{}])[0].get("resources", [])),
        )
        return True

    veza_con = OAAClient(url=veza_url, token=veza_api_key)
    try:
        provider = veza_con.get_provider(provider_name)
        if not provider:
            log.info("Creating new provider '%s'", provider_name)
            veza_con.create_provider(provider_name, "application")

        response = veza_con.push_application(
            provider_name=provider_name,
            data_source_name=datasource_name,
            application_object=app,
        )
        if response.get("warnings"):
            for w in response["warnings"]:
                log.warning("Veza warning: %s", w)
        log.info("Successfully pushed to Veza")
        return True

    except OAAClientError as e:
        log.error("Veza push failed: %s — %s (HTTP %s)", e.error, e.message, e.status_code)
        if hasattr(e, "details"):
            for d in e.details:
                log.error("  Detail: %s", d)
        return False


# ===========================================================================
# Configuration loader
# ===========================================================================

def load_config(args):
    """Load configuration with precedence: CLI arg > env var > .env file."""

    if args.env_file and os.path.exists(args.env_file):
        load_dotenv(args.env_file, override=True)
        log.info("Loaded environment from: %s", args.env_file)

    config = {
        "veza_url": args.veza_url or os.getenv("VEZA_URL"),
        "veza_api_key": args.veza_api_key or os.getenv("VEZA_API_KEY"),
        "sec_file": args.sec_file or os.getenv("HFM_SEC_FILE"),
        "groups_csv": args.groups_csv or os.getenv("HFM_GROUPS_CSV"),
        "provider_name": args.provider_name,
        "datasource_name": args.datasource_name,
    }

    return config


# ===========================================================================
# CLI
# ===========================================================================

def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Oracle Hyperion HFM to Veza OAA Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run with local files
  %(prog)s --sec-file /data/hfm/SW_Security.sec \\
           --groups-csv /data/hfm/Groups.csv --dry-run

  # Push to Veza using .env for credentials
  %(prog)s --sec-file /mnt/hfm-share/SW_Security.sec \\
           --groups-csv /mnt/hfm-share/Groups.csv \\
           --env-file /opt/hfm-hyperion-veza/scripts/.env

  # Override provider / datasource names
  %(prog)s --sec-file SW_Security.sec --groups-csv Groups.csv \\
           --provider-name "Oracle Hyperion HFM" \\
           --datasource-name "HFM Production"
        """,
    )

    parser.add_argument(
        "--sec-file",
        type=str,
        help="Path to HFM .sec security export file (also reads HFM_SEC_FILE env var)",
    )
    parser.add_argument(
        "--groups-csv",
        type=str,
        help="Path to EPM Groups CSV export file (also reads HFM_GROUPS_CSV env var)",
    )
    parser.add_argument(
        "--env-file",
        type=str,
        default=".env",
        help="Path to .env file (default: .env)",
    )
    parser.add_argument(
        "--veza-url",
        type=str,
        help="Veza instance URL (also reads VEZA_URL env var)",
    )
    parser.add_argument(
        "--veza-api-key",
        type=str,
        help="Veza API key (also reads VEZA_API_KEY env var)",
    )
    parser.add_argument(
        "--provider-name",
        type=str,
        default="Oracle Hyperion HFM",
        help="Veza provider name (default: Oracle Hyperion HFM)",
    )
    parser.add_argument(
        "--datasource-name",
        type=str,
        default="HFM Security",
        help="Veza datasource name (default: HFM Security)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build payload but skip pushing to Veza",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


# ===========================================================================
# Main
# ===========================================================================

def main():
    print("=" * 60)
    print("Oracle Hyperion HFM to Veza OAA Integration")
    print("=" * 60 + "\n")

    args = parse_arguments()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Load configuration
    config = load_config(args)

    # Validate required settings
    sec_file = config["sec_file"]
    groups_csv_path = config["groups_csv"]

    if not sec_file:
        log.error("HFM .sec file path is required (--sec-file or HFM_SEC_FILE env var)")
        sys.exit(1)
    if not groups_csv_path:
        log.error("Groups CSV file path is required (--groups-csv or HFM_GROUPS_CSV env var)")
        sys.exit(1)
    if not os.path.isfile(sec_file):
        log.error("HFM .sec file not found: %s", sec_file)
        sys.exit(1)
    if not os.path.isfile(groups_csv_path):
        log.error("Groups CSV file not found: %s", groups_csv_path)
        sys.exit(1)

    if not config["veza_url"] or not config["veza_api_key"]:
        if not args.dry_run:
            log.error("VEZA_URL and VEZA_API_KEY are required (set via CLI, env var, or .env file)")
            sys.exit(1)
        else:
            log.warning("Veza credentials not set — continuing in dry-run mode")

    # ---- Parse source data ----
    log.info("Parsing HFM .sec file: %s", sec_file)
    sec_data = parse_sec_file(sec_file)

    log.info("Parsing Groups CSV: %s", groups_csv_path)
    groups_data, memberships = parse_groups_csv(groups_csv_path)

    # ---- Build OAA payload ----
    log.info("Building OAA payload...")
    app = build_oaa_payload(sec_data, groups_data, memberships, args)

    # ---- Push to Veza ----
    log.info("=" * 40)
    success = push_to_veza(
        veza_url=config["veza_url"],
        veza_api_key=config["veza_api_key"],
        provider_name=config["provider_name"],
        datasource_name=config["datasource_name"],
        app=app,
        dry_run=args.dry_run,
    )

    if success:
        log.info("HFM Hyperion integration completed successfully")
        sys.exit(0)
    else:
        log.error("HFM Hyperion integration failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
