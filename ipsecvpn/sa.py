"""Correlate the full VICI inventory with the IPv4 forwarding SPD and SAD."""

import re
import socket
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from itertools import product

from vici import Session
from vici.exception import (
    CommandException,
    DeserializationException,
    EventUnknownException,
    SessionException,
)

from .host import VICI_PATH
from .renderer import DeploymentManifest
from .secureio import Stop


class SAError(Stop):
    def __init__(self, reason, detail):
        self.reason = reason
        super().__init__(detail)


def unowned(detail):
    return SAError("UNOWNED_SA", detail)


def transition(detail):
    return SAError("SA_TRANSITION", detail)


@contextmanager
def session(pid, path=VICI_PATH):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(8)
            client.connect(str(path))
            peer = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            actual_pid, uid, _ = struct.unpack("3i", peer)
            if (actual_pid, uid) != (int(pid), 0):
                raise SAError("UNOWNED_DAEMON", "The VICI socket peer is not the owned daemon.")
            yield Session(client)
    except CommandException:
        raise SAError("VICI_REJECTED", "The daemon rejected the requested operation.") from None
    except (
        OSError,
        SessionException,
        DeserializationException,
        EventUnknownException,
        struct.error,
    ):
        raise SAError("VICI_UNAVAILABLE", "A local VICI request did not complete.") from None


def number(text, base=10):
    value = int(text, base)
    if value <= 0:
        raise ValueError("Expected a positive identifier.")
    return value


def text(row, key):
    return row[key].decode("ascii")


def cidr(value):
    net = IPv4Network(value)
    if net.prefixlen == 0:
        raise ValueError("Unrestricted selector.")
    return str(net)


def identity(value):
    return value.removeprefix("@").lower()


def proposal(row, expected, *, ike):
    parts = expected.split("-")
    aes = parts.pop(0)
    gcm = aes.endswith("gcm16")
    wanted = {
        "encr-alg": "AES_GCM_16" if gcm else "AES_CBC",
        "encr-keysize": aes.removeprefix("aes").removesuffix("gcm16"),
    }
    if not gcm:
        integrity = parts.pop(0).removeprefix("sha")
        wanted["integ-alg"] = f"HMAC_SHA2_{integrity}_{int(integrity) // 2}"
    elif "integ-alg" in row:
        return False
    if ike:
        wanted["prf-alg"] = "PRF_HMAC_SHA2_" + parts.pop(0).removeprefix("prfsha")
    # The first CHILD in IKE_AUTH may use IKE key material without separate DH.
    if ike or "dh-group" in row:
        group = re.fullmatch(r"(modp|ecp)(\d+)", parts[0])
        wanted["dh-group"] = f"{group[1].upper()}_{group[2]}"
    return all(row.get(key) == value.encode() for key, value in wanted.items())


@dataclass(frozen=True)
class State:
    source: str
    destination: str
    spi: int
    reqid: int
    if_id: int


@dataclass(frozen=True)
class Policy:
    source: str
    destination: str
    direction: str
    outer_source: str
    outer_destination: str
    reqid: int
    if_id: int


@dataclass(frozen=True)
class Child:
    unique_id: int
    inbound: State
    outbound: State
    counts: tuple[int, ...] = field(compare=False)


@dataclass(frozen=True)
class Ike:
    name: str
    unique_id: int
    cookies: tuple[int, int]
    child: Child | None


@dataclass(frozen=True)
class Snapshot:
    ikes: tuple[Ike, ...]
    manifest: DeploymentManifest | None

    def get(self, name):
        return next((ike for ike in self.ikes if ike.name == name), None)

    @property
    def state(self):
        return "OWNED" if self.ikes else "EMPTY"


def parse_ike(name, row, link):
    if (
        row.get("version") != b"2"
        or text(row, "local-host") != link.source
        or text(row, "remote-host") != link.peer
        or identity(text(row, "local-id")) != identity(link.local_id)
        or identity(text(row, "remote-id")) != identity(link.remote_id)
        or not proposal(row, link.ike_proposal, ike=True)
    ):
        raise unowned("IKE identity, endpoint or proposal differs from the active manifest.")
    if row.get("state") != b"ESTABLISHED":
        raise transition("An IKE SA has not reached a stable established state.")
    children = row.get("child-sas", {})
    if len(children) > 1:
        raise transition("Multiple CHILD generations require a stable VICI snapshot.")
    child = None
    if children:
        info = next(iter(children.values()))
        if (
            info.get("name") != link.child.encode()
            or info.get("protocol") != b"ESP"
            or info.get("mode") != b"TUNNEL"
            or number(text(info, "if-id-in"), 16) != link.if_id
            or number(text(info, "if-id-out"), 16) != link.if_id
            or set(cidr(s.decode()) for s in info["local-ts"]) != set(link.local_ts)
            or set(cidr(s.decode()) for s in info["remote-ts"]) != set(link.remote_ts)
            or any(key.startswith(("mark-", "cpi-")) for key in info)
            or not proposal(info, link.esp_proposal, ike=False)
        ):
            raise unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
        if info.get("state") != b"INSTALLED":
            raise transition("A CHILD SA has not reached a stable installed state.")
        reqid = number(text(info, "reqid"))
        child = Child(
            number(text(info, "uniqueid")),
            State(link.peer, link.source, number(text(info, "spi-in"), 16), reqid, link.if_id),
            State(link.source, link.peer, number(text(info, "spi-out"), 16), reqid, link.if_id),
            tuple(int(info[key]) for key in ("bytes-in", "bytes-out", "packets-in", "packets-out")),
        )
    return Ike(
        name,
        number(text(row, "uniqueid")),
        tuple(number(text(row, f"{side}-spi"), 16) for side in ("initiator", "responder")),
        child,
    )


def parse_vici(events, manifest):
    links = {link.name: link for link in manifest.links} if manifest else {}
    result = {}
    for event in events:
        for name, row in event.items():
            if name not in links:
                raise unowned("VICI reported an IKE SA outside the active manifest.")
            if name in result:
                raise transition("Multiple IKE generations require a stable VICI snapshot.")
            result[name] = parse_ike(name, row, links[name])
    return Snapshot(tuple(sorted(result.values(), key=lambda ike: ike.name)), manifest)


def value(tokens, key):
    if tokens.count(key) != 1:
        raise ValueError("Missing or ambiguous XFRM field.")
    return tokens[tokens.index(key) + 1]


def kernel_states(output):
    result = []
    for line in output.splitlines():
        segments = [segment.split() for segment in line.split("\\") if segment.strip()]
        head, body = segments[0], segments[1]
        fields = [token for segment in segments[1:] for token in segment]
        if (
            head[::2] != ["src", "dst"]
            or value(body, "proto") != "esp"
            or value(body, "mode") != "tunnel"
            or {"mark", "output-mark", "output_mask"}.intersection(fields)
        ):
            raise unowned("The kernel reported a non-project XFRM state.")
        result.append(
            State(
                str(IPv4Address(head[1])),
                str(IPv4Address(head[3])),
                number(value(body, "spi"), 0),
                number(value(body, "reqid")),
                number(value(fields, "if_id"), 0),
            )
        )
    return result


def kernel_policies(output):
    result = []
    for line in output.splitlines():
        segments = [segment.split() for segment in line.split("\\") if segment.strip()]
        head = segments[0]
        fields = [token for segment in segments[1:] for token in segment]
        if (
            head[::2] != ["src", "dst"]
            or {"mark", "block", "use", "dev", "sub", "offload"}.intersection(fields)
            or fields.count("tmpl") != 1
        ):
            raise unowned("The kernel reported a non-project XFRM forwarding policy.")
        template = fields[fields.index("tmpl") + 1 :]
        if value(template, "proto") != "esp" or value(template, "mode") != "tunnel":
            raise unowned("A kernel policy does not use the expected ESP tunnel template.")
        spi = number(value(template, "spi"), 0) if "spi" in template else None
        result.append(
            (
                Policy(
                    cidr(head[1]),
                    cidr(head[3]),
                    value(fields, "dir"),
                    str(IPv4Address(value(template, "src"))),
                    str(IPv4Address(value(template, "dst"))),
                    number(value(template, "reqid")),
                    number(value(fields, "if_id"), 0),
                ),
                spi,
            )
        )
    return result


def correlate(snapshot, manifest, states, policies):
    expected_states = set()
    expected_policies = {}
    for link in manifest.links if manifest else ():
        ike = snapshot.get(link.name)
        if not ike or not ike.child:
            continue
        inbound, outbound = ike.child.inbound, ike.child.outbound
        expected_states.update((inbound, outbound))
        for local, remote in product(link.local_ts, link.remote_ts):
            for direction, source, destination, sa in (
                ("out", local, remote, outbound),
                ("in", remote, local, inbound),
                ("fwd", remote, local, inbound),
            ):
                key = Policy(
                    source, destination, direction, sa.source, sa.destination, sa.reqid, sa.if_id
                )
                expected_policies[key] = sa.spi
    if set(states) != expected_states or len(states) != len(expected_states):
        raise unowned("The kernel XFRM state does not map exactly to VICI CHILD SPIs.")
    if (
        {policy for policy, _ in policies} != set(expected_policies)
        or len(policies) != len(expected_policies)
        or any(spi is not None and expected_policies[policy] != spi for policy, spi in policies)
    ):
        raise unowned("The kernel XFRM policy does not map exactly to the authorized selectors.")


def inventory(host, manifest, pid, *, attempts=4, delay=0.2):
    for attempt in range(attempts):
        try:
            with session(pid) as client:
                before = parse_vici(list(client.list_sas()), manifest)
                states = kernel_states(
                    host.command(
                        "XFRM state inventory", "ip", "-o", "xfrm", "state", "list", "nokeys"
                    )
                )
                policies = kernel_policies(
                    host.command(
                        "XFRM policy inventory", "ip", "-o", "xfrm", "policy", "list", "nosock"
                    )
                )
                after = parse_vici(list(client.list_sas()), manifest)
            if before != after:
                raise transition("VICI changed while the kernel inventory was being read.")
            correlate(after, manifest, states, policies)
            return after
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            error = SAError("SA_UNVERIFIED", "SA or policy fields could not be verified.")
        except SAError as exc:
            error = exc
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise error
