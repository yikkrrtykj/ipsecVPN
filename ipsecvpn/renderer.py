"""Deterministic, secret-free deployment resources for one V2 profile."""

import hashlib
import json
from dataclasses import asdict, dataclass

from .handoff import build_plan
from .profile import backup_readiness, validate_profile

TABLE = "ipsecvpn"
ROUTE_PROTOCOL = "242"
XFRM_METRIC = "40"
BLACKHOLE_METRIC = "32760"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Link:
    site_id: str
    if_id: int
    wan: str
    source: str
    gateway: str | None
    peer: str
    local_id: str
    remote_id: str
    local_ts: tuple[str, ...]
    remote_ts: tuple[str, ...]
    ike_proposal: str
    esp_proposal: str
    ike_lifetime: int
    child_lifetime: int
    dpd_delay: int

    @property
    def name(self):
        return f"ivp{self.if_id:08x}"

    @property
    def child(self):
        return f"{self.name}-child"


@dataclass(frozen=True)
class DeploymentManifest:
    event_id: str
    links: tuple[Link, ...]

    @property
    def networks(self):
        return sorted(cidr for link in self.links for cidr in link.remote_ts)

    def resources(self):
        return {
            "event_id": self.event_id,
            "links": [
                {**asdict(link), "xfrm_interface": link.name, "child": link.child}
                for link in self.links
            ],
            "routes": [
                {
                    "destination": cidr,
                    "interface": link.name,
                    "table": "main",
                    "metric": int(XFRM_METRIC),
                    "fallback": {"type": "blackhole", "metric": int(BLACKHOLE_METRIC)},
                }
                for link in self.links
                for cidr in link.remote_ts
            ],
            "forward_acl": [
                {
                    "iif": source.name,
                    "oif": target.name,
                    "source_cidrs": source.remote_ts,
                    "destination_cidrs": target.remote_ts,
                }
                for source, target in (self.links, self.links[::-1])
            ],
            "source_nat": False,
        }


def build_manifest(profile):
    validate_profile(profile)
    links = []
    for item in build_plan(profile)["connections"]:
        outer = item["outer_path"]
        links.append(
            Link(
                site_id=item["site_id"],
                if_id=item["xfrm_if_id"],
                wan=outer["interface"],
                source=outer.get("source_ip", item["hub"]["public_endpoint"]),
                gateway=outer.get("gateway"),
                peer=item["peer"]["public_endpoint"],
                local_id=item["hub"]["ike_identity"],
                remote_id=item["peer"]["ike_identity"],
                local_ts=tuple(item["hub_local_ts"]),
                remote_ts=tuple(item["hub_remote_ts"]),
                ike_proposal=item["ike"]["proposal"],
                esp_proposal=item["child"]["proposal"],
                ike_lifetime=item["ike"]["lifetime_seconds"],
                child_lifetime=item["child"]["lifetime_seconds"],
                dpd_delay=item["ike"]["dpd_delay_seconds"],
            )
        )
    return DeploymentManifest(
        profile["event"]["id"], tuple(sorted(links, key=lambda link: link.site_id))
    )


def connection_settings(link):
    return {
        "version": "2",
        "local_addrs": [link.source],
        "remote_addrs": [link.peer],
        "proposals": [link.ike_proposal],
        "reauth_time": "0",
        "rekey_time": f"{link.ike_lifetime}s",
        "dpd_delay": f"{link.dpd_delay}s",
        "mobike": "no",
        "encap": "yes",
        "local": {"auth": "psk", "id": link.local_id},
        "remote": {"auth": "psk", "id": link.remote_id},
        "children": {
            link.child: {
                "mode": "tunnel",
                "local_ts": list(link.local_ts),
                "remote_ts": list(link.remote_ts),
                "esp_proposals": [link.esp_proposal],
                "if_id_in": str(link.if_id),
                "if_id_out": str(link.if_id),
                "life_time": f"{link.child_lifetime}s",
                "rekey_time": f"{max(1, link.child_lifetime * 9 // 10)}s",
                "start_action": "none",
                "dpd_action": "clear",
                "close_action": "none",
            }
        },
    }


def _config_lines(section, indent=""):
    for key, value in section.items():
        if isinstance(value, dict):
            yield f"{indent}{key} {{"
            yield from _config_lines(value, indent + "    ")
            yield f"{indent}}}"
        else:
            formatted = ", ".join(value) if isinstance(value, list) else value
            yield f"{indent}{key} = {formatted}"


def swanctl_config(manifest, keys=None):
    """Render the same connection settings used by the targeted VICI loader."""
    links = manifest.links if manifest else ()
    document = {
        "connections": {link.name: connection_settings(link) for link in links},
        "secrets": {
            f"ike-{link.name}": {
                "id-1": link.local_id,
                "id-2": link.remote_id,
                "secret": "0x" + keys[link.site_id].hex(),
            }
            for link in links
            if keys is not None
        },
    }
    return "\n".join((*_config_lines(document), ""))


def nft_config(manifest, token, guarded=(), interfaces=(), handshake=None):
    """A private table; transition guards block all protected traffic."""
    links = manifest.links if manifest else ()
    names = sorted(set(interfaces) | {link.name for link in links})
    networks = sorted(set(guarded) | {cidr for link in links for cidr in link.remote_ts})
    lines = [
        f"table ip {TABLE} {{",
        f"    chain owner_{token} {{",
        "    }",
        "    chain forward {",
        "        type filter hook forward priority -5; policy accept;",
    ]
    for source, target in ((links[0], links[1]), (links[1], links[0])) if links else ():
        lines.append(
            f'        iifname "{source.name}" oifname "{target.name}" '
            f"ip saddr {{ {', '.join(source.remote_ts)} }} "
            f"ip daddr {{ {', '.join(target.remote_ts)} }} accept"
        )
    for name in names:
        lines.extend([f'        iifname "{name}" drop', f'        oifname "{name}" drop'])
    for cidr in networks:
        lines.append(f"        ip daddr {cidr} drop")
    lines.extend(
        [
            "    }",
            "    chain output {",
            "        type filter hook output priority -5; policy accept;",
        ]
    )
    for link in links:
        lines.append(
            f'        oifname "{link.name}" ip daddr {{ {", ".join(link.remote_ts)} }} accept'
        )
    for cidr in networks:
        lines.append(f"        ip daddr {cidr} drop")
    lines.extend(
        ["    }", "    chain input {", "        type filter hook input priority -5; policy accept;"]
    )
    for link in handshake.links if handshake else links:
        lines.append(
            f'        iifname "{link.wan}" ip saddr {link.peer} ip daddr {link.source} '
            "udp dport { 500, 4500 } accept"
        )
    for name in names:
        lines.append(f'        iifname "{name}" drop')
    lines.extend(
        ["        udp dport { 500, 4500 } drop", "        ip protocol esp drop", "    }", "}", ""]
    )
    return "\n".join(lines)


def external_backup(profile):
    state = backup_readiness(profile)
    if not state["enabled"]:
        return state
    return {
        **state,
        "status": "SKIP",
        "detail": "External backup is managed outside this Hub; no live readiness was evaluated.",
    }


def render(profile):
    manifest = build_manifest(profile)
    config = swanctl_config(manifest)
    nft = nft_config(manifest, "preview")
    return {
        "status": "PASS",
        "detail": "Offline rendering completed. Host and tunnel verification are SKIP.",
        "manifest": manifest.resources(),
        "files": {
            "swanctl.conf": {"sha256": digest(config.encode()), "preview": config},
            "ipsecvpn.nft": {"sha256": digest(nft.encode()), "preview": nft},
        },
        "permissions": "root and an explicitly authorized isolated Ubuntu 24.04 VM for writes",
        "startup_order": ["fail_closed_guard", "xfrm_and_routes", "vici", "verified_acl"],
        "backup": external_backup(profile),
        "site_to_site": {"status": "SKIP"},
    }


def resource_diff(before, target):
    previous = {link.name: link for link in before.links} if before else {}
    desired = {link.name: link for link in target.links} if target else {}
    return {
        "add": sorted(desired.keys() - previous.keys()),
        "remove": sorted(previous.keys() - desired.keys()),
        "update": sorted(
            name for name in previous.keys() & desired.keys() if previous[name] != desired[name]
        ),
        "previous_sha256": digest(canonical(before.resources())) if before else None,
        "target_sha256": digest(canonical(target.resources())) if target else None,
    }
