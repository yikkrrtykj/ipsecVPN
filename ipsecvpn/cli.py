"""V2.0 profile, handoff and authorized Ubuntu lab Hub operations."""

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path

from .diagnostics import status_report
from .handoff import build_plan, peer_parameters, render_peer_markdown
from .profile import ProfileError, backup_readiness, load_profile
from .renderer import render
from .secureio import Stop
from .transaction import Deployment

DEFAULT_PROFILES = Path("/etc/ipsecvpn/profiles")
HOST_ACTIONS = ("install", "apply", "backup", "rollback", "uninstall", "initiate", "rekey")


def _check(check_id, status, detail):
    return {"id": check_id, "status": status, "detail": detail}


def _host_checks():
    if platform.system() != "Linux":
        return [_check("host", "SKIP", "Linux host prerequisites cannot be checked here.")]
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [_check("host", "SKIP", "Could not read Linux distribution metadata.")]
    fields = {
        key: value.strip("\"'")
        for key, _, value in (line.partition("=") for line in os_release.splitlines())
    }
    if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID") != "24.04":
        return [_check("host", "FAIL", "The deployment target is Ubuntu 24.04.")]
    return [
        _check("host", "PASS", "OS metadata identifies Ubuntu 24.04."),
        *(
            _check(
                f"command_{name}",
                "PASS" if shutil.which(name) else "FAIL",
                f"Local executable discovery for {name}.",
            )
            for name in ("ip", "nft", "swanctl", "systemctl")
        ),
    ]


def check_host():
    checks = [
        *_host_checks(),
        _check("active_profile", "SKIP", "PR #1 does not activate profiles."),
        _check("vici_sa_xfrm", "SKIP", "Daemon, SA and XFRM state were not queried."),
        _check("business_udp_tcp", "SKIP", "No live business traffic was sent."),
        _check("firewall_handoff", "SKIP", "No remote firewall was contacted."),
    ]
    status = "FAIL" if any(check["status"] == "FAIL" for check in checks) else "SKIP"
    return {"status": status, "checks": checks}


def list_profiles(directory):
    try:
        paths = sorted(directory.iterdir())
    except FileNotFoundError:
        paths = []
    except OSError:
        raise ProfileError("Could not list the profile directory.") from None
    profiles = []
    seen = set()
    for path in paths:
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            event = load_profile(path)["event"]
            if event["id"] in seen:
                raise ProfileError("Duplicate event ID in the profile directory.")
            seen.add(event["id"])
            profiles.append({"status": "PASS", "event": event})
        except ProfileError as exc:
            profiles.append({"status": "FAIL", "detail": str(exc)})
    failed = any(profile["status"] == "FAIL" for profile in profiles)
    return {
        "status": "FAIL" if failed else "PASS" if profiles else "SKIP",
        "active_profile": {"status": "SKIP", "detail": "PR #1 does not activate profiles."},
        "profiles": profiles,
    }


def _parser():
    parser = argparse.ArgumentParser(prog="ipsecvpn", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    profiles = commands.add_parser("profiles", help="Inspect saved profiles.")
    profile_commands = profiles.add_subparsers(dest="profile_command", required=True)
    listing = profile_commands.add_parser("list", help="List saved profiles without activation.")
    listing.add_argument("--directory", type=Path, default=DEFAULT_PROFILES)
    listing.add_argument("--json", action="store_true")
    validate = commands.add_parser("validate", help="Validate a profile.")
    validate.add_argument("-c", "--config", type=Path, required=True)
    validate.add_argument("--json", action="store_true")
    check = commands.add_parser("check", help="Inspect local host prerequisites only.")
    check.add_argument("--json", action="store_true")
    for name in ("status", "doctor"):
        observation = commands.add_parser(name, help="Inspect the installed Hub without probes.")
        observation.add_argument("--json", action="store_true")
    plan = commands.add_parser("plan", help="Print a read-only topology plan as JSON.")
    plan.add_argument("-c", "--config", type=Path, required=True)
    export = commands.add_parser("export-peer", help="Print a site-side handoff.")
    export.add_argument("-c", "--config", type=Path, help="Or set IPSECVPN_CONFIG explicitly.")
    export.add_argument("--site", required=True)
    export.add_argument("--format", choices=("md", "json"), default="md")
    export.add_argument("--template", choices=("auto", "hillstone", "generic"), default="auto")
    rendering = commands.add_parser("render", help="Render a redacted deployment manifest.")
    rendering.add_argument("-c", "--config", type=Path, required=True)
    rendering.add_argument("--json", action="store_true")
    for action in HOST_ACTIONS:
        operation = commands.add_parser(
            action, help=f"{action.capitalize()} on an authorized lab VM."
        )
        mode = operation.add_mutually_exclusive_group(required=True)
        mode.add_argument("--dry-run", action="store_true")
        mode.add_argument("--confirm", action="store_true")
        operation.add_argument("--json", action="store_true")
        if action == "apply":
            operation.add_argument("-c", "--config", type=Path, required=True)
        if action == "rollback":
            operation.add_argument("--to", required=True)
        if action in {"apply", "rollback", "uninstall"}:
            operation.add_argument("--maintenance", action="store_true")
        if action in {"initiate", "rekey"}:
            operation.add_argument("--site", required=True)
        if action == "rekey":
            kind = operation.add_mutually_exclusive_group(required=True)
            kind.add_argument("--child", dest="kind", action="store_const", const="child")
            kind.add_argument("--ike", dest="kind", action="store_const", const="ike")
    return parser


def _run(args):
    if args.command in HOST_ACTIONS:
        return Deployment().dispatch(
            args.command,
            args.confirm,
            getattr(args, "config", None),
            getattr(args, "to", None),
            maintenance=getattr(args, "maintenance", False),
            site=getattr(args, "site", None),
            kind=getattr(args, "kind", None),
        )
    if args.command == "profiles":
        return list_profiles(args.directory)
    if args.command == "check":
        return check_host()
    if args.command in {"status", "doctor"}:
        return status_report()
    config = args.config
    if args.command == "export-peer" and config is None:
        config = os.environ.get("IPSECVPN_CONFIG")
        if not config:
            raise ProfileError("Select a profile explicitly with -c or IPSECVPN_CONFIG.")
    profile = load_profile(config)
    if args.command == "render":
        return render(profile)
    if args.command == "validate":
        return {
            "status": "PASS",
            "detail": "Profile schema and topology validated.",
            "backup": backup_readiness(profile),
        }
    if args.command == "plan":
        return build_plan(profile)
    return peer_parameters(profile, args.site, args.template)


def _print_text(result):
    print(
        "FAIL/STOP" if result.get("decision") == "STOP" else result["status"],
        result.get("detail", ""),
    )
    for site in result.get("sites", []):
        if "ike_state" in site:
            print(
                f"{site['site_id']} IKE={site['ike_state']} CHILD={site['child_state']} "
                f"business={site['data_path']['status']}"
            )
    for key in ("journal", "backup_id"):
        if key in result:
            print(f"{key} {result[key]}")
    for name, version in result.get("packages", {}).items():
        print(f"{name} {version}")
    if "diff" in result:
        print(json.dumps(result["diff"], sort_keys=True))
    backup = result.get("backup", {})
    if backup.get("enabled"):
        print(f"{backup['status']}/{backup['readiness']} external backup handoff inputs")
        for site_id, fields in backup.get("missing", {}).items():
            print(f"{site_id} missing {', '.join(fields)}")
    for check in result.get("checks", []):
        print(f"{check['status']} {check['id']} — {check['detail']}")
    if "active_profile" in result:
        print(f"SKIP active_profile — {result['active_profile']['detail']}")
    for profile in result.get("profiles", []):
        if profile["status"] == "PASS":
            print(f"PASS {profile['event']['id']} — {profile['event']['name']}")
        else:
            print(f"FAIL {profile['detail']}")


def main(argv=None):
    args = _parser().parse_args(argv)
    export_format = getattr(args, "format", None)
    json_output = (
        args.command in {"plan", "render"}
        or export_format == "json"
        or getattr(args, "json", False)
    )
    try:
        result = _run(args)
    except ProfileError as exc:
        result = {"status": "FAIL", "detail": str(exc)}
        if args.command in HOST_ACTIONS:
            result["decision"] = "STOP"
        if not json_output:
            status = "FAIL/STOP" if "decision" in result else "FAIL"
            print(f"{status} {result['detail']}", file=sys.stderr)
            return 1
    except (Stop, OSError, KeyError, ValueError) as exc:
        if args.command not in HOST_ACTIONS:
            raise
        detail = (
            str(exc)
            if isinstance(exc, Stop)
            else "A protected host check or state operation failed."
        )
        result = {"status": "FAIL", "decision": "STOP", "detail": detail}
        if hasattr(exc, "reason"):
            result["reason_code"] = exc.reason
        if not json_output:
            print(f"FAIL/STOP {detail}", file=sys.stderr)
            return 1
    if json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    elif export_format == "md":
        print(render_peer_markdown(result), end="")
    else:
        _print_text(result)
    return int(result["status"] == "FAIL")
