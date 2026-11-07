"""Read-only layered status for an installed lab Hub."""

import os
import platform

from .host import Host
from .live import owned_resources
from .sa import SAError
from .secureio import Stop, read_record
from .transaction import ACTIVE, INSTALLED, JOURNAL, TERMINAL, installed_record


def status_report(host=None):
    host = host or Host()
    result = {
        "status": "SKIP",
        "data_path": {"status": "SKIP", "reason_code": "NO_PROBE"},
        "sites": [],
        "checks": [],
    }
    if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return {**result, "detail": "Runtime inspection requires an authorized Ubuntu lab VM."}
    stage = "deployment"
    try:
        if read_record(INSTALLED) is None:
            return {**result, "detail": "No project installation was found."}
        stage = "host"
        host.probe()
        install = installed_record()
        pending = read_record(JOURNAL)
        if pending and pending["phase"] not in TERMINAL:
            raise SAError("UNFINISHED_TRANSACTION", "An unfinished transaction needs review.")
        stage = "daemon_and_kernel"
        active = read_record(ACTIVE)
        manifest, live, _ = owned_resources(host, install, active)
    except (Stop, OSError, KeyError, ValueError) as exc:
        detail = str(exc) if isinstance(exc, Stop) else "A protected observation was unavailable."
        reason = getattr(exc, "reason", "UNVERIFIED_RUNTIME")
        return {
            **result,
            "status": "FAIL",
            "decision": "STOP",
            "detail": detail,
            "checks": [{"id": stage, "status": "FAIL", "reason_code": reason, "detail": detail}],
        }
    result["checks"] = [
        {"id": "host_and_daemon", "status": "PASS", "detail": "Owned Ubuntu lab daemon verified."},
        {
            "id": "kernel_and_paths",
            "status": "PASS",
            "detail": "VICI, XFRM, protected routes and firewall are consistent.",
        },
        {"id": "business", "status": "SKIP", "detail": "No network probes were sent."},
    ]
    result["ownership"] = live.state
    if not manifest:
        return {**result, "detail": "The daemon is owned, with no active profile."}
    for link in manifest.links:
        ike = live.get(link.name)
        child = ike.child if ike else None
        rx_bytes, tx_bytes, rx_packets, tx_packets = child.counts if child else (0, 0, 0, 0)
        result["sites"].append(
            {
                "site_id": link.site_id,
                "ike_state": "ESTABLISHED" if ike else "DOWN",
                "child_state": "INSTALLED" if child else "DOWN",
                "auth_verified": bool(ike),
                "selector_verified": bool(child),
                "if_id_verified": bool(child),
                "kernel_sa_policy_verified": bool(child),
                "xfrm_interface": link.name,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "protected_route": "PASS",
                "egress_guard": "PASS",
                "data_path": result["data_path"],
                "reason_code": "NO_PROBE" if child else "CHILD_NOT_ESTABLISHED",
            }
        )
    complete = all(site["child_state"] == "INSTALLED" for site in result["sites"])
    return {
        **result,
        "status": "PASS" if complete else "SKIP",
        "detail": "Local tunnel evidence only. Business probes were not run.",
    }
