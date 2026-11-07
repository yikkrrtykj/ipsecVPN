"""Read-only Linux probes and the constrained command runner."""

import json
import os
import platform
import re
import shutil
import subprocess
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from .renderer import TABLE, canonical, digest
from .secureio import Stop, read_file

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
UNIT = "strongswan.service"
DROPIN = Path("/etc/systemd/system/strongswan.service.d/99-ipsecvpn.conf")
PRIVATE_CONF = Path("/etc/strongswan.d/ipsecvpn-private.conf")
VICI_PATH = Path("/run/charon.vici")
SOCKET = f"unix://{VICI_PATH}"
PACKAGES = ("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins")
VENDOR_UNITS = {
    "/usr/lib/systemd/system/strongswan.service",
    "/lib/systemd/system/strongswan.service",
}
LAB_MARKER = Path("/etc/ipsecvpn/lab-authorized")
HOST_TOOLS = ("ip", "nft", "ss", "systemctl", "sysctl", "modprobe", "dpkg-query", "apt-get")


class CommandFailed(Stop):
    def __init__(self, step, code):
        super().__init__(f"{step} failed ({code}). Command output was suppressed.")


class Host:
    def __init__(self, step=None):
        self.step = step

    def command(self, label, *args, content=None, allowed=(0,), timeout=30, mutate=False):
        if mutate and self.step is not None:
            self.step(label, "STARTED")
        try:
            result = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                input=content,
                timeout=timeout,
                env={
                    "PATH": PATH,
                    "LC_ALL": "C",
                    "DEBIAN_FRONTEND": "noninteractive",
                    "NEEDRESTART_MODE": "l",
                    "NEEDRESTART_SUSPEND": "1",
                },
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise CommandFailed(label, "unavailable or timed out") from None
        if result.returncode not in allowed:
            raise CommandFailed(label, result.returncode)
        if mutate and self.step is not None:
            self.step(label, "DONE")
        return result.stdout.decode("utf-8", errors="replace")

    def json(self, label, *args):
        try:
            return json.loads(self.command(label, *args))
        except ValueError:
            raise Stop(f"{label} did not return valid JSON.") from None

    def ip(self, *args):
        return self.json("ip query", "ip", "-j", "-N", *args)

    def service(self, unit, prop):
        return self.command(
            "systemd query", "systemctl", "show", unit, "-p", prop, "--value"
        ).strip()

    def vici(self, action, *options):
        return self.command("VICI query", "swanctl", action, *options, "--uri", SOCKET)

    def vici_names(self):
        return set(self.vici_connections())

    def vici_connections(self):
        connections = {}
        current = None
        for line in self.vici("--list-conns").splitlines():
            if line and not line[0].isspace():
                match = re.match(r"^(.+?):\s+IKEv[12]\b", line)
                if not match:
                    raise Stop("VICI returned an unrecognized connection entry.")
                current = match.group(1)
                connections[current] = []
            elif line and current is not None:
                connections[current].append(line)
        return connections

    def probe(self):
        if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
        if os.getuid() != 0:
            raise Stop("Run the CLI as root, not as a setuid executable.")
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        fields = dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
        if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID", "").strip('"') != "24.04":
            raise Stop("Only Ubuntu 24.04 is supported.")
        virtual = self.command("VM detection", "systemd-detect-virt", "--vm").strip()
        if not virtual or virtual == "none" or not Path("/run/systemd/system").is_dir():
            raise Stop("A systemd-managed isolated VM is required.")
        try:
            marker = read_file(LAB_MARKER, limit=64, parent_mode=0o700)
        except OSError:
            raise Stop("The root-only isolated VM authorization marker is missing.") from None
        if marker != b"ipsecvpn-lab-v1\n":
            raise Stop("The isolated VM authorization marker is invalid.")
        if any(not shutil.which(name, path=PATH) for name in HOST_TOOLS):
            raise Stop("The required Ubuntu host tools are missing.")
        self.command("XFRM interface support", "modprobe", "-nq", "xfrm_interface")
        self.command("IPv4 XFRM support", "ip", "xfrm", "policy", "list")
        self.json("nftables support", "nft", "-j", "list", "ruleset")
        return {"os": "Ubuntu 24.04", "kernel": platform.release(), "hypervisor": virtual}

    def packages(self):
        installed = self.command(
            "Package inventory",
            "dpkg-query",
            "-W",
            "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n",
        )
        return {
            name: version
            for name, version, state in (line.split("\t") for line in installed.splitlines())
            if state.startswith("ii")
        }

    def package_state(self):
        inventory = self.command(
            "Full dpkg inventory",
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
        )
        return {
            name: {"version": version, "status": state}
            for name, version, state in (line.split("\t") for line in inventory.splitlines())
        }

    def apt_plan(self):
        if self.command("Package audit", "dpkg", "--audit").strip():
            raise Stop("The VM already has an incomplete package transaction.")
        report = self.command(
            "APT simulation",
            "apt-get",
            "-s",
            "--no-install-recommends",
            "--no-upgrade",
            "--no-remove",
            "install",
            *PACKAGES,
        )
        plan = {}
        for line in report.splitlines():
            if line.startswith("Remv "):
                raise Stop("APT would remove an installed package.")
            if line.startswith("Inst "):
                match = re.match(r"Inst ([A-Za-z0-9+:.-]+) \(([^ )]+)", line)
                if not match:
                    raise Stop(
                        "APT would upgrade an installed package or returned an unknown plan."
                    )
                plan[match.group(1)] = match.group(2)
        if any(not plan.get(name, "").startswith("5.9.") for name in PACKAGES):
            raise Stop("Expected Ubuntu strongSwan 5.9.x packages are unavailable.")
        return plan

    def ike_ports(self):
        return self.command(
            "IKE socket probe", "ss", "-H", "-ulnp", "( sport = :500 or sport = :4500 )"
        ).strip()

    def vici_listeners(self):
        listeners = self.command("VICI listener probe", "ss", "-H", "-xlpn")
        return [line for line in listeners.splitlines() if str(VICI_PATH) in line.split()]

    def assert_no_starter(self):
        if self.service("strongswan-starter.service", "ActiveState") not in {"inactive", "failed"}:
            raise Stop("A legacy strongSwan starter unit is active.")

    def assert_no_other_ike(self):
        self.assert_no_starter()
        if self.command("XFRM SA probe", "ip", "xfrm", "state", "list", "nokeys").strip():
            raise Stop("An active kernel IPsec SA exists. Use a dedicated idle VM.")
        if self.command("XFRM SPD probe", "ip", "xfrm", "policy", "list", "nosock").strip():
            raise Stop("An unexpected global XFRM policy exists.")

    def assert_idle_ike(self):
        self.assert_no_other_ike()
        if (
            self.service(UNIT, "ActiveState") != "inactive"
            or self.ike_ports()
            or any(
                path.exists() or path.is_symlink() for path in (VICI_PATH, Path("/run/charon.ctl"))
            )
        ):
            raise Stop("An existing IKE listener or strongSwan service is unowned.")

    def assert_exclusive_ike(self, permitted=()):
        self.assert_no_other_ike()
        self.assert_daemon(permitted)
        if self.vici("--list-sas").strip():
            raise Stop("Active SAs prevent changes that require an idle daemon.")

    def assert_daemon(self, permitted=()):
        self.assert_no_starter()
        if self.service(UNIT, "FragmentPath") not in VENDOR_UNITS:
            raise Stop("The strongSwan unit is not the expected Ubuntu unit.")
        if self.service(UNIT, "DropInPaths") != str(DROPIN):
            raise Stop("The strongSwan unit has unexpected overrides.")
        if "charon-systemd" not in self.service(UNIT, "ExecStart"):
            raise Stop("The active unit does not use charon-systemd.")
        state = self.service(UNIT, "ActiveState")
        pid = self.service(UNIT, "MainPID")
        ports = self.ike_ports().splitlines()
        if state != "active" or not pid.isdecimal() or int(pid) <= 0 or not ports:
            raise Stop("The owned charon-systemd service and IKE sockets are not active.")
        self.assert_private_daemon(pid)
        vici = self.vici_listeners()
        if not vici or any(set(re.findall(r"pid=(\d+),", line)) != {pid} for line in ports + vici):
            raise Stop("The daemon does not exclusively own the IKE and VICI sockets.")
        output = self.vici("--version", "--daemon")
        if not re.search(r"\b5\.9\.\d+\b", output) or "charon-systemd" not in output:
            raise Stop("VICI did not report the expected strongSwan 5.9.x version.")
        if not self.vici_names().issubset(permitted):
            raise Stop("Unowned VICI connections prevent safe changes.")
        return pid

    def assert_private_daemon(self, pid):
        if not pid.isdecimal() or int(pid) <= 0:
            raise Stop("The strongSwan service has no provable process identity.")
        environment = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if f"STRONGSWAN_CONF={PRIVATE_CONF}".encode() not in environment:
            raise Stop("The running strongSwan process does not use the project configuration.")

    def routing(self):
        rules = self.ip("-4", "rule", "show")
        expected = {(0, "255"), (32766, "254"), (32767, "253")}
        if (
            {(row.get("priority"), table_id(row.get("table"))) for row in rules} != expected
            or len(rules) != 3
            or any(
                set(row) - {"priority", "src", "table", "protocol"} or row.get("src") != "all"
                for row in rules
            )
        ):
            raise Stop("IPv4 policy routing differs from the default rule set.")
        routes = self.ip("-4", "route", "show", "table", "all")
        links = self.ip("-details", "link", "show")
        return rules, routes, links

    def check_paths(self, manifest, routes, owned_routes, links, owned_links):
        if not manifest:
            return
        ids = {link.if_id for link in manifest.links}
        names = {link.name for link in manifest.links}
        identities = {link.remote_id.lstrip("@").casefold() for link in manifest.links}
        if len(identities) != len(manifest.links):
            raise Stop("Distinct remote IKE identities are required for per-link keys.")
        for row in links:
            name = row.get("ifname")
            if (name in names or xfrm_id(row) in ids) and name not in owned_links:
                raise Stop("A requested XFRM name or ID is already in use.")
        networks = [IPv4Network(cidr) for cidr in manifest.networks]
        defaults = [row for row in routes if row.get("dst") == "default"]
        if not defaults or any(row.get("dev") in names or row.get("nexthops") for row in defaults):
            raise Stop("The existing IPv4 default path is missing or ambiguous.")
        for row in routes:
            destination = row.get("dst")
            if destination not in {None, "default"} and route_key(row) not in owned_routes:
                network = IPv4Network(destination)
                if any(network.overlaps(cidr) for cidr in networks):
                    raise Stop("An existing route overlaps an authorized remote LAN.")
        established = self.command(
            "TCP management path probe", "ss", "-H", "-nt", "state", "established"
        )
        for line in established.splitlines():
            try:
                peer = IPv4Address(
                    line.split()[-1].rsplit(":", 1)[0].removeprefix("[::ffff:").rstrip("]")
                )
            except ValueError:
                continue
            if any(peer in network for network in networks):
                raise Stop(
                    "An established TCP management or application path overlaps a managed LAN."
                )
        for link in manifest.links:
            if link.wan == "auto":
                raise Stop("outer_path.interface auto is an offline placeholder.")
            addresses = self.ip("-4", "addr", "show", "dev", link.wan)
            if not any(
                addr.get("local") == link.source for row in addresses for addr in row["addr_info"]
            ):
                raise Stop("The IKE source address is not assigned to the specified WAN interface.")
            lookup = self.ip("-4", "route", "get", link.peer, "from", link.source)
            if (
                len(lookup) != 1
                or lookup[0].get("dev") != link.wan
                or (link.gateway is not None and lookup[0].get("gateway") != link.gateway)
                or route_kind(lookup[0]) != "unicast"
                or link.wan in names
                or link.wan in owned_links
            ):
                raise Stop("The existing peer route does not match the specified WAN path.")
        if self.command("Forwarding probe", "sysctl", "-n", "net.ipv4.ip_forward").strip() != "1":
            raise Stop(
                "Preconfigure IPv4 forwarding on the VM before apply; no sysctl was changed."
            )
        for interface in {"all", "default", *(link.wan for link in manifest.links)}:
            rp_filter = Path(f"/proc/sys/net/ipv4/conf/{interface}/rp_filter").read_text().strip()
            if rp_filter not in {"0", "2"}:
                raise Stop("Strict reverse-path filtering must be reviewed before this deployment.")

    def nft(self):
        return self.json("nftables inventory", "nft", "-j", "list", "ruleset")["nftables"]

    def check_firewall(self, objects):
        legacy = Path("/proc/net/ip_tables_names")
        if legacy.exists() and legacy.read_text().strip():
            raise Stop("An IPv4 legacy iptables table prevents proof of safe coexistence.")
        sensitive = set()
        for obj in objects:
            row = obj.get("chain", {})
            if row.get("family") not in {"ip", "inet", "netdev", "bridge"}:
                continue
            hook = row.get("hook")
            if hook is None:
                continue
            if row.get("policy", "accept") != "accept":
                raise Stop("A foreign firewall base chain can override the project's allow rules.")
            sensitive.add((row["family"], row["table"], row["name"]))
        for obj in objects:
            row = obj.get("rule", {})
            key = (row.get("family"), row.get("table"), row.get("chain"))
            if key in sensitive and any(
                not set(expr).issubset({"match", "counter", "accept", "log"})
                for expr in row["expr"]
            ):
                raise Stop("A foreign firewall rule may drop, redirect or rewrite project traffic.")

    def baseline(self, rules, routes, links, foreign_nft, owned_routes, owned_links):
        addresses = self.ip("address", "show")
        ssh = {
            service: self.service(service, "ActiveState")
            for service in ("ssh.service", "ssh.socket")
        }
        ssh["socket"] = self.service("ssh.socket", "Listen")
        ssh["listeners"] = sorted(
            line.split()[3]
            for line in self.command("SSH listener snapshot", "ss", "-H", "-ltnp").splitlines()
            if '("sshd",' in line
        )
        return {
            "rules": fingerprint(rules),
            "default_routes": fingerprint([row for row in routes if row.get("dst") == "default"]),
            "foreign_routes": fingerprint(
                [row for row in routes if route_key(row) not in owned_routes]
            ),
            "foreign_links": fingerprint(
                [
                    {key: row.get(key) for key in ("ifname", "address", "mtu", "linkinfo")}
                    for row in links
                    if row["ifname"] not in owned_links
                ]
            ),
            "addresses": fingerprint(
                [
                    (
                        row["ifname"],
                        sorted(
                            (info["family"], info["local"], info["prefixlen"])
                            for info in row["addr_info"]
                        ),
                    )
                    for row in addresses
                    if row["ifname"] not in owned_links
                ]
            ),
            "foreign_nft": fingerprint(foreign_nft),
            "ssh": fingerprint(ssh),
            "sysctl": fingerprint(
                {
                    key: self.command("sysctl snapshot", "sysctl", "-n", f"net.ipv4.{key}").strip()
                    for key in ("ip_forward", "conf.all.rp_filter", "conf.default.rp_filter")
                }
            ),
        }


def xfrm_id(row):
    info = row.get("linkinfo", {})
    if info.get("info_kind") != "xfrm":
        return None
    return int(str(info["info_data"]["if_id"]), 0)


def route_key(row):
    destination = row.get("dst")
    if destination and destination != "default" and "/" not in destination:
        destination += "/32"
    table = table_id(row.get("table", "254"))
    return (
        destination,
        route_kind(row),
        row.get("dev"),
        str(row.get("metric", 0)),
        str(row.get("protocol")),
        table,
    )


def route_kind(row):
    kind = str(row.get("type", "unicast"))
    # ip -N prints RTN_* values numerically even in JSON.
    return {"1": "unicast", "6": "blackhole"}.get(kind, kind)


def table_id(value):
    text = str(value)
    return {"local": "255", "main": "254", "default": "253"}.get(text, text)


def separate_nft(objects):
    owned, foreign = [], []
    for item in objects:
        kind, row = next(iter(item.items()))
        if kind == "metainfo":
            continue
        target = (
            owned
            if row.get("family") == "ip" and row.get("table", row.get("name")) == TABLE
            else foreign
        )
        target.append(item)
    return owned, foreign


def fingerprint(data):
    def clean(value):
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            return {
                key: ({} if key == "counter" else clean(item))
                for key, item in value.items()
                if key not in {"handle", "expires", "used"}
            }
        return value

    return digest(canonical(clean(data)))
