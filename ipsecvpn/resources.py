"""Apply and verify only declared project network and VICI objects."""

import os
import re
from pathlib import Path

from .host import SOCKET, fingerprint, route_key, separate_nft, xfrm_id
from .renderer import (
    BLACKHOLE_METRIC,
    ROUTE_PROTOCOL,
    TABLE,
    XFRM_METRIC,
    nft_config,
    swanctl_config,
)
from .sa import Snapshot
from .secureio import Stop, atomic_write, make_directory, remove_file, sync_dir, trusted_dir

SWANCTL_DIR = Path("/etc/swanctl")


def route_specs(manifests):
    result = set()
    for manifest in manifests:
        if manifest:
            for link in manifest.links:
                for cidr in link.remote_ts:
                    result.add((cidr, "unicast", link.name, XFRM_METRIC, ROUTE_PROTOCOL, "254"))
                    result.add((cidr, "blackhole", None, BLACKHOLE_METRIC, ROUTE_PROTOCOL, "254"))
    return result


def link_specs(manifests):
    return {
        (link.name, link.if_id) for manifest in manifests if manifest for link in manifest.links
    }


def network_scope(manifests):
    return sorted({cidr for manifest in manifests if manifest for cidr in manifest.networks})


class Resources:
    def __init__(self, host, token, candidates):
        self.host = host
        self.token = token
        self.alias = f"ipsecvpn:{token}"
        self.candidates = tuple(candidates)
        self.routes = route_specs(self.candidates)
        self.links = link_specs(self.candidates)

    @property
    def runtime(self):
        return SWANCTL_DIR / f"ipsecvpn-{self.token}"

    def purge_runtime(self):
        try:
            os.close(trusted_dir(self.runtime, 0o700))
        except FileNotFoundError:
            return
        remove_file(self.runtime / "swanctl.conf")
        self.runtime.rmdir()
        sync_dir(SWANCTL_DIR)

    def network(self):
        rules, routes, links = self.host.routing()
        owned_links = set()
        for row in links:
            name = row["ifname"]
            if row.get("ifalias") == self.alias:
                if (name, xfrm_id(row)) not in self.links:
                    raise Stop("An unregistered interface carries the project ownership tag.")
                owned_links.add(name)
            elif any(name == expected or xfrm_id(row) == if_id for expected, if_id in self.links):
                raise Stop("An XFRM name or ID belongs to an unowned interface.")
        owned_routes = set()
        for row in routes:
            key = route_key(row)
            if key in self.routes:
                if row.get("gateway") or row.get("nexthops") or row.get("prefsrc"):
                    raise Stop("A project-marked route has unexpected routing attributes.")
                if key[2] is not None and key[2] not in owned_links:
                    raise Stop("A project-marked route is attached to an unowned interface.")
                owned_routes.add(key)
            elif key[4] == ROUTE_PROTOCOL:
                raise Stop("An unregistered route uses the project route protocol.")
        owned_nft, foreign_nft = separate_nft(self.host.nft())
        if owned_nft and not any(
            item.get("chain", {}).get("name") == f"owner_{self.token}" for item in owned_nft
        ):
            raise Stop("The private nftables table is not owned by this installation.")
        return rules, routes, links, owned_routes, owned_links, owned_nft, foreign_nft

    def preflight(self, target):
        view = self.network()
        rules, routes, links, owned_routes, owned_links, _, foreign_nft = view
        self.host.check_firewall(foreign_nft)
        self.host.check_paths(target, routes, owned_routes, links, owned_links)
        return self.host.baseline(rules, routes, links, foreign_nft, owned_routes, owned_links)

    def baseline(self):
        rules, routes, links, owned_routes, owned_links, _, foreign_nft = self.network()
        return self.host.baseline(rules, routes, links, foreign_nft, owned_routes, owned_links)

    def nft(self, manifest, transition=False):
        owned, _ = separate_nft(self.host.nft())
        if owned and not any(
            item.get("chain", {}).get("name") == f"owner_{self.token}" for item in owned
        ):
            raise Stop("The nftables table cannot be proven owned.")
        content = f"delete table ip {TABLE}\n" if owned else ""
        if transition:
            content += nft_config(
                None,
                self.token,
                network_scope(self.candidates),
                (name for name, _ in self.links),
                handshake=manifest,
            )
        elif manifest:
            content += nft_config(manifest, self.token)
        if content:
            args = ("nft", "-f", "-")
            self.host.command("nft syntax check", "nft", "-c", "-f", "-", content=content.encode())
            self.host.command("nft atomic update", *args, content=content.encode(), mutate=True)

    def route(self, operation, spec):
        cidr, kind, interface, metric, protocol, _ = spec
        destination = ("blackhole", cidr) if kind == "blackhole" else (cidr, "dev", interface)
        self.host.command(
            f"IPv4 {kind} route {operation}",
            "ip",
            "-4",
            "route",
            operation,
            *destination,
            "table",
            "main",
            "proto",
            protocol,
            "metric",
            metric,
            mutate=True,
        )

    def guard(self, handshake=None):
        self.nft(handshake, transition=True)
        owned_routes = self.network()[3]
        for spec in sorted(spec for spec in self.routes - owned_routes if spec[1] == "blackhole"):
            self.route("add", spec)

    def load(self, manifest, keys):
        self.host.assert_exclusive_ike({name for name, _ in self.links})
        make_directory(self.runtime)
        conf = self.runtime / "swanctl.conf"
        atomic_write(conf, swanctl_config(manifest, keys).encode())
        try:
            self.host.command(
                "VICI load",
                "swanctl",
                "--load-all",
                "--clear",
                "--noprompt",
                "--file",
                str(conf),
                "--uri",
                SOCKET,
                mutate=True,
            )
        finally:
            self.purge_runtime()

    def replace(self, target, keys, *, loader=None, hold=False):
        self.guard()
        self.host.assert_exclusive_ike({name for name, _ in self.links})
        _, _, links, routes, names, _, _ = self.network()
        desired_links = link_specs((target,))
        desired_routes = route_specs((target,))
        for spec in sorted(routes - desired_routes):
            if spec[1] == "unicast":
                self.route("del", spec)
        for row in links:
            name = row["ifname"]
            if name in names and (name, xfrm_id(row)) not in desired_links:
                self.host.command("XFRM delete", "ip", "link", "del", "dev", name, mutate=True)
        for name, if_id in sorted(desired_links):
            if name not in names:
                self.host.command(
                    "XFRM create",
                    "ip",
                    "link",
                    "add",
                    "name",
                    name,
                    "type",
                    "xfrm",
                    "if_id",
                    str(if_id),
                    mutate=True,
                )
                # Linux 6.8's newlink path ignores IFLA_IFALIAS on creation.
                self.host.command(
                    "XFRM mark and activate",
                    "ip",
                    "link",
                    "set",
                    "dev",
                    name,
                    "alias",
                    self.alias,
                    "up",
                    mutate=True,
                )
            else:
                self.host.command("XFRM up", "ip", "link", "set", "dev", name, "up", mutate=True)
        for spec in sorted(desired_routes - self.network()[3]):
            self.route("add", spec)
        (loader or self.load)(target, keys)
        if hold:
            self.nft(target, transition=True)
        else:
            self.finish(target)

    def finish(self, target):
        for spec in sorted(self.network()[3] - route_specs((target,))):
            self.route("del", spec)
        self.nft(target)

    def verify(self, expected, baseline, nft_sha=None, *, live=None):
        if live is not None and (not isinstance(live, Snapshot) or live.manifest != expected):
            raise Stop("The live SA proof does not belong to the expected manifest.")
        _, _, links, routes, names, table, _ = self.network()
        wanted = {name for name, _ in link_specs((expected,))}
        up = {row["ifname"] for row in links if row["ifname"] in names and "UP" in row["flags"]}
        if names != wanted or up != wanted or routes != route_specs((expected,)):
            raise Stop("Observed XFRM interfaces or exact routes differ from the manifest.")
        if bool(table) != bool(expected) or (nft_sha and nft_sha != fingerprint(table)):
            raise Stop("Observed project nftables rules differ from the expected state.")
        connections = self.host.vici_connections()
        if set(connections) != wanted or (live is None and self.host.vici("--list-sas").strip()):
            raise Stop("The daemon did not report exactly the intended VICI connections.")
        for link in expected.links if expected else ():
            listing = "\n".join(connections[link.name])
            if (
                f"  local:  {link.source}" not in connections[link.name]
                or f"  remote: {link.peer}" not in connections[link.name]
                or not re.search(rf"^  {re.escape(link.child)}: TUNNEL\b", listing, re.M)
            ):
                raise Stop("The loaded VICI peer addresses or CHILD differ from the manifest.")
            for direction, selectors in (("local", link.local_ts), ("remote", link.remote_ts)):
                observed = re.findall(rf"^    {direction}:\s+(.+)$", listing, re.M)
                if len(observed) != 1 or set(observed[0].split()) != set(selectors):
                    raise Stop("The loaded VICI selectors differ from the authorized CIDRs.")
        for spec in sorted(routes):
            if spec[1] == "unicast":
                lookup = self.host.ip("-4", "route", "get", spec[0].split("/")[0])
                if len(lookup) != 1 or lookup[0].get("dev") != spec[2]:
                    raise Stop("The kernel did not resolve a protected network through its XFRM.")
        current = self.baseline()
        if current != baseline:
            changed = ", ".join(
                sorted(name for name in current if current[name] != baseline.get(name))
            )
            raise Stop(f"A protected non-project host baseline changed ({changed}).")
        return fingerprint(table) if table else None
