"""Build only the test network inside the disposable PR3 guest."""

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path

import yaml

from ipsecvpn.host import Host
from ipsecvpn.installer import install_files
from ipsecvpn.profile import load_profile, validate_profile
from ipsecvpn.renderer import DeploymentManifest, build_manifest, swanctl_config
from ipsecvpn.secureio import read_keys

HERE = Path(__file__).resolve().parent
TOPO = json.loads((HERE / "topology.json").read_text(encoding="ascii"))
PROFILE = Path("/etc/ipsecvpn/profiles/pr3-lab.yaml")
CLI = Path(sys.executable).with_name("ipsecvpn")
HOST = Host()
PEER_ROOT = Path("/run/ipsecvpn-pr3")
TOPOLOGY_UNIT = "ipsecvpn-pr3-topology.service"


def command(*args, allowed=(0,), timeout=55, input=None):
    proc = subprocess.run(
        args, capture_output=True, text=True, check=False, input=input, timeout=timeout
    )
    if proc.returncode not in allowed:
        # Never emit raw daemon errors or an argv that could carry fixture material.
        raise RuntimeError(f"{Path(args[0]).name} returned {proc.returncode}")
    return proc


def cli(*args, expect=0):
    proc = command(str(CLI), *args, "--json", allowed=(0, 1))
    report = json.loads(proc.stdout)
    if expect is not None and proc.returncode != expect:
        raise RuntimeError(
            f"{args[0]} returned {proc.returncode}: {report.get('detail', '')} "
            f"{report.get('reason_code', '')}".rstrip()
        )
    return report


def ip(*args, ns=None, allowed=(0,)):
    prefix = ("-n", ns) if ns else ()
    return command("ip", *prefix, *args, allowed=allowed)


def in_ns(name, *args):
    return ("ip", "netns", "exec", name, *args)


def peer_args(site, *args):
    ns = site["router"]
    # Preserve /run/charon.vici inside AppArmor, with a different mount and socket per peer.
    return in_ns(
        ns,
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "sh",
        "-ec",
        'mount --bind "$1" /run; shift; exec "$@"',
        "pr3-peer",
        str(PEER_ROOT / ns),
        *args,
    )


def peerctl(site, *args, **kwargs):
    return command(*peer_args(site, "/usr/sbin/swanctl", *args), **kwargs)


def addr(network, number):
    return str(IPv4Network(network)[number])


def require_lab():
    identity = command("hostname").stdout.strip()
    if identity != "ipsecvpn-pr3-lab":
        raise RuntimeError("PR3 guest identity is required.")
    HOST.probe()


def create_profile():
    profile = load_profile(HERE / "example.yaml")
    profile["hub"]["public_endpoint"] = str(IPv4Interface(TOPO["hub"]).ip)
    profile["hub"]["ike_identity"] = profile["hub"]["public_endpoint"]
    pair = profile["traffic_policy"]["allowed_site_pairs"][0]
    profile["security"]["dpd_delay_seconds"] = 2
    for side, site, link, fixture in zip(
        ("a", "b"), profile["sites"], profile["site_links"], TOPO["sites"], strict=True
    ):
        site["public_endpoint"] = str(IPv4Interface(fixture["endpoint"]).ip)
        site["ike_identity"] = site["public_endpoint"]
        site["lan_cidrs"] = fixture["lans"].copy()
        pair[f"{side}_cidrs"] = fixture["lans"]
        if "extra_lan" in fixture:
            site["lan_cidrs"].append(fixture["extra_lan"])
        link["outer_path"]["interface"] = TOPO["wan"]
    validate_profile(profile)
    for link in profile["site_links"]:
        path = Path(link["secret_ref"][5:])
        with path.open("xb") as stream:
            stream.write(os.urandom(32).hex().encode("ascii") + b"\n")
        path.chmod(0o600)
    write_profile(profile, PROFILE)
    return profile


def write_profile(profile, path):
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    path.chmod(0o600)


def bootstrap_network():
    require_lab()
    profile = load_profile(PROFILE)
    manifest = build_manifest(profile)
    keys = read_keys(profile)
    wan = TOPO["wan"]
    switch = "wan-switch"
    ip("netns", "add", switch)
    ip("link", "add", "bridge", "type", "bridge", ns=switch)
    ip("link", "set", "bridge", "up", ns=switch)
    ip("link", "add", wan, "type", "veth", "peer", "name", "hubport", "netns", switch)
    ip("link", "set", "hubport", "master", "bridge", ns=switch)
    ip("link", "set", "hubport", "up", ns=switch)
    ip("link", "set", wan, "address", "02:00:00:30:00:10")
    ip("addr", "add", TOPO["hub"], "dev", wan)
    ip("link", "set", wan, "up")
    for index, (site, link) in enumerate(zip(TOPO["sites"], manifest.links, strict=True)):
        router, host = site["router"], site["host"]
        for name in (router, host):
            ip("netns", "add", name)
            ip("link", "set", "lo", "up", ns=name)
        mesh = f"mesh{index}"
        ip("link", "add", mesh, "type", "veth", "peer", "name", "wan", "netns", router, ns=switch)
        ip("link", "set", mesh, "master", "bridge", ns=switch)
        ip("link", "set", mesh, "up", ns=switch)
        ip("addr", "add", site["endpoint"], "dev", "wan", ns=router)
        ip("link", "set", "wan", "up", ns=router)
        ip(
            "link",
            "add",
            "inside",
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            host,
            ns=router,
        )
        ip("link", "set", "inside", "up", ns=router)
        ip("link", "set", "eth0", "up", ns=host)
        networks = site["lans"] + ([site["extra_lan"]] if "extra_lan" in site else [])
        for net in networks:
            length = IPv4Network(net).prefixlen
            ip("addr", "add", f"{addr(net, 1)}/{length}", "dev", "inside", ns=router)
            ip("addr", "add", f"{addr(net, 11)}/{length}", "dev", "eth0", ns=host)
        ip("route", "add", "default", "via", addr(networks[0], 1), ns=host)
        command(
            *in_ns(
                router,
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=2",
                "net.ipv4.conf.default.rp_filter=2",
            )
        )
        ip("link", "add", "tunnel", "type", "xfrm", "if_id", str(link.if_id), ns=router)
        ip("link", "set", "tunnel", "up", ns=router)
        for remote in link.local_ts:
            ip("route", "add", remote, "dev", "tunnel", ns=router)
        start_peer(site, link, keys, manifest.event_id)


def start_peer(site, link, keys, event):
    root = PEER_ROOT / site["router"]
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    conf = Path(f"/etc/strongswan.d/pr3-{site['router']}.conf")
    daemon_config = next(iter(install_files(sys.executable).values())).decode()
    daemon_config = daemon_config.replace(
        "install_routes = no",
        "install_routes = no\n    retransmit_timeout = 1\n    retransmit_tries = 2",
    )
    conf.write_text(daemon_config, encoding="ascii")
    conf.chmod(0o600)
    proc = subprocess.Popen(
        peer_args(site, "env", f"STRONGSWAN_CONF={conf}", "/usr/sbin/charon-systemd"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (root / "pid").write_text(str(proc.pid), encoding="ascii")
    for _ in range(40):
        if (root / "charon.vici").is_socket():
            break
        if proc.poll() is not None:
            raise RuntimeError("Isolated peer charon exited before exposing VICI.")
        time.sleep(0.25)
    else:
        raise RuntimeError("Isolated peer VICI did not become available.")
    reverse = replace(
        link,
        source=link.peer,
        peer=link.source,
        local_id=link.remote_id,
        remote_id=link.local_id,
        local_ts=link.remote_ts,
        remote_ts=link.local_ts,
    )
    folder = Path(f"/etc/swanctl/pr3-{site['router']}")
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / "swanctl.conf"
    path.write_text(swanctl_config(DeploymentManifest(event, (reverse,)), keys), encoding="ascii")
    path.chmod(0o600)
    try:
        peerctl(site, "--load-all", "--noprompt", "--file", str(path))
    finally:
        path.unlink()


def install_topology_unit():
    unit = Path("/etc/systemd/system") / TOPOLOGY_UNIT
    unit.write_text(
        f"""[Unit]
Description=PR3 disposable isolated peer network
After=local-fs.target systemd-sysctl.service
Before=ipsecvpn-restore.service

[Service]
Type=oneshot
ExecStart={sys.executable} {__file__}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""",
        encoding="ascii",
    )
    command("systemctl", "daemon-reload")
    command("systemctl", "enable", TOPOLOGY_UNIT)
    command("systemctl", "start", TOPOLOGY_UNIT)
    command("systemctl", "is-active", TOPOLOGY_UNIT)


if __name__ == "__main__":
    bootstrap_network()
