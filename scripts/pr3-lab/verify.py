"""Real three-node acceptance, executed only inside the disposable QEMU guest."""

import hashlib
import json
import os
import re
import secrets
import select
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

from topology import (
    HERE,
    HOST,
    PEER_ROOT,
    PROFILE,
    TOPO,
    addr,
    cli,
    command,
    create_profile,
    in_ns,
    install_topology_unit,
    ip,
    peerctl,
    require_lab,
    start_peer,
    write_profile,
)

from ipsecvpn.host import LAB_MARKER, UNIT, Host
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import DeploymentManifest, build_manifest, connection_settings
from ipsecvpn.resources import Resources
from ipsecvpn.sa import (
    SAError,
    correlate,
    inventory,
    kernel_policies,
    kernel_states,
    parse_vici,
    session,
)
from ipsecvpn.secureio import Stop, read_keys, read_record
from ipsecvpn.transaction import ACTIVE, INSTALLED, JOURNAL, Deployment

SUMMARY = Path("/var/tmp/ipsecvpn-pr3-acceptance.jsonl")
BASELINE = HERE / "baseline.json"
PORT = TOPO["traffic_port"]
UPDATE = PROFILE.with_name("pr3-update.yaml")
ENV = {}
HEAD = (HERE / "head-sha").read_text(encoding="ascii").strip()
LAB_CASES = {
    f"{section}{index:02d}"
    for section, count in (("T", 14), ("S", 10), ("N", 6), ("F", 16))
    for index in range(1, count + 1)
}


def emit(cases, expected, observed, *, status="PASS", action="inspect real nodes"):
    for case in cases.split():
        receipt = {
            "case": case,
            "time_utc": datetime.now(UTC).isoformat(),
            "head_sha": HEAD,
            "environment": ENV,
            "action": action,
            "expected": expected,
            "observed": observed,
            "status": status,
            "proof_refs": [SUMMARY.name],
        }
        line = json.dumps(receipt, sort_keys=True)
        if PROFILE.exists():
            encoded = line.encode()
            for key in read_keys(load_profile(PROFILE)).values():
                assert key not in encoded and key.hex().encode() not in encoded
        with SUMMARY.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        print(line, flush=True)


def environment():
    packages = HOST.packages()
    ENV.update(
        HOST.probe(),
        strongswan=packages["charon-systemd"],
        iproute2=packages["iproute2"],
        nft=command("nft", "--version").stdout.strip(),
    )


def recorded_cases():
    lines = SUMMARY.read_text(encoding="utf-8").splitlines() if SUMMARY.exists() else ()
    return [json.loads(line) for line in lines]


def summarize():
    ENV.update(HOST.probe())
    packages = HOST.packages()
    ENV.update(
        strongswan=packages.get("charon-systemd", "not installed"),
        iproute2=packages.get("iproute2", "unknown"),
        nft=command("nft", "--version").stdout.strip(),
    )
    previous = {item["case"] for item in recorded_cases()}
    for case in sorted(LAB_CASES - previous):
        emit(
            case,
            "Execute the case under the PR3 acceptance matrix.",
            "Not reached after an earlier isolated failure or interrupted run.",
            status="SKIP",
            action="collect existing evidence",
        )


def failure_context():
    known = {
        "version",
        "state",
        "uniqueid",
        "local-host",
        "remote-host",
        "local-id",
        "remote-id",
        "encr-alg",
        "encr-keysize",
        "integ-alg",
        "prf-alg",
        "dh-group",
        "name",
        "reqid",
        "if-id-in",
        "if-id-out",
        "protocol",
        "mode",
        "encap",
        "local-ts",
        "remote-ts",
    }

    def safe(row):
        return {
            key: [item.decode("ascii") for item in value]
            if isinstance(value, list)
            else value.decode("ascii")
            for key, value in row.items()
            if key in known
        }

    result = {}
    try:
        pid = HOST.service(UNIT, "MainPID")
        if pid.isdecimal() and int(pid):
            with session(pid) as control:
                result["hub_vici"] = [
                    {
                        "connection": name,
                        **safe(row),
                        "children": [safe(child) for child in row.get("child-sas", {}).values()],
                    }
                    for event in control.list_sas()
                    for name, row in event.items()
                ]
        for kind, option in (("state", "nokeys"), ("policy", "nosock")):
            raw = ip("-o", "xfrm", kind, "list", option).stdout
            # Extract only field pairs with fixed token types. Do not emit a raw SA dump.
            result[f"hub_{kind}_fields"] = [
                re.findall(
                    r"\b(?:src|dst|dir|proto|reqid|mode|if_id|priority) [0-9a-zA-Z./_-]+", row
                )
                for row in raw.splitlines()
            ][:40]
        journal = read_record(JOURNAL)
        if journal:
            result["journal"] = {
                key: journal[key]
                for key in ("id", "action", "phase", "failure", "recovery_failure")
                if key in journal
            }
            result["journal"]["steps"] = [
                [step["label"], step["result"]] for step in journal["steps"]
            ]
    except (Stop, RuntimeError, ValueError, TypeError, KeyError, OSError):
        result["diagnostic"] = "Some local evidence was unavailable."
    return result


def manifest():
    return build_manifest(load_profile(PROFILE))


def baseline_for(model):
    owner = read_record(INSTALLED)["token"]
    return Resources(HOST, owner, (model,)).baseline()


def peer_pid(site):
    return int((PEER_ROOT / site["router"] / "pid").read_text(encoding="ascii"))


def prove_topology():
    pids = {
        "hub": int(HOST.service(UNIT, "MainPID")),
        **{site["router"]: peer_pid(site) for site in TOPO["sites"]},
    }
    namespaces = {node: os.readlink(f"/proc/{pid}/ns/net") for node, pid in pids.items()}
    assert len(set(pids.values())) == len(set(namespaces.values())) == 3
    for site in TOPO["sites"]:
        assert not ip("-4", "route", "show", "default", ns=site["router"]).stdout
        assert (PEER_ROOT / site["router"] / "charon.vici").is_socket()
    assert not ip("-4", "route", "show", "default", "dev", TOPO["wan"]).stdout
    emit(
        "T01",
        "Three isolated IKE nodes, two LAN stacks, no default route on the test WAN.",
        {
            "pids": pids,
            "network_namespaces": namespaces,
            "peer_vici": {s["router"]: s["router"] + "/charon.vici" for s in TOPO["sites"]},
            "lan_nodes": [s["host"] for s in TOPO["sites"]],
            "qemu": "restrict=on with loopback-only SSH management",
        },
    )


def sample_both_ends(model):
    pid = HOST.assert_daemon({link.name for link in model.links})
    live = inventory(HOST, model, pid)
    if len(live.ikes) != 2 or not all(ike.child for ike in live.ikes):
        raise SAError("SA_TRANSITION", "Both complete Hub CHILDs are required for this sample.")
    proofs = []
    for site, link in zip(TOPO["sites"], model.links, strict=True):
        reverse = replace(
            link,
            source=link.peer,
            peer=link.source,
            local_id=link.remote_id,
            remote_id=link.local_id,
            local_ts=link.remote_ts,
            remote_ts=link.local_ts,
        )
        peer = DeploymentManifest(model.event_id, (reverse,))
        with session(peer_pid(site), PEER_ROOT / site["router"] / "charon.vici") as ctl:
            observed = parse_vici(list(ctl.list_sas()), peer)
            states = kernel_states(
                ip("-o", "xfrm", "state", "list", "nokeys", ns=site["router"]).stdout
            )
            policies = kernel_policies(
                ip("-o", "xfrm", "policy", "list", "nosock", ns=site["router"]).stdout
            )
            if observed != parse_vici(list(ctl.list_sas()), peer):
                raise SAError("SA_TRANSITION", "Peer VICI changed during its kernel sample.")
        correlate(observed, peer, states, policies)
        hub_child = live.get(link.name).child
        peer_ike = observed.get(link.name)
        if not peer_ike or not peer_ike.child:
            raise SAError("SA_TRANSITION", "The peer has no stable CHILD in this sample.")
        peer_child = peer_ike.child
        if (hub_child.outbound.spi, hub_child.inbound.spi) != (
            peer_child.inbound.spi,
            peer_child.outbound.spi,
        ):
            raise SAError("SA_TRANSITION", "The two endpoint generations changed between reads.")
        proofs.append(
            {
                "peer_node": site["router"],
                "hub_interface": link.name,
                "peer_interface": "tunnel",
                "ike": "ESTABLISHED",
                "child": "INSTALLED",
                "if_id": link.if_id,
                "hub_reqid": hub_child.inbound.reqid,
                "peer_reqid": peer_child.inbound.reqid,
                "hub_ike_id": live.get(link.name).unique_id,
                "peer_ike_id": peer_ike.unique_id,
                "hub_child_id": hub_child.unique_id,
                "peer_child_id": peer_child.unique_id,
                "local_ts": link.local_ts,
                "remote_ts": link.remote_ts,
                "peer_policy_count": len(policies),
                "opposite_spis_match": True,
            }
        )
    if live != inventory(HOST, model, pid):
        raise SAError("SA_TRANSITION", "Hub VICI changed while the two peers were sampled.")
    return live, proofs


def verify_sas(model, *, phase="initial negotiation"):
    deadline = time.monotonic() + 20
    while True:
        try:
            live, proofs = sample_both_ends(model)
            break
        except SAError as exc:
            if exc.reason not in {"SA_TRANSITION", "UNOWNED_SA"} or time.monotonic() >= deadline:
                raise
            time.sleep(0.35)
    for index, proof in enumerate(proofs, start=2):
        emit(
            f"T0{index}",
            "Both ends installed the same negotiated tunnel.",
            proof,
            action=f"verify both kernel and VICI ends after {phase}",
        )
    emit(
        "T04",
        "Every Hub CHILD maps to both SPIs and all global ESP policies.",
        {
            "interfaces": [link.name for link in model.links],
            "ikes": len(live.ikes),
            "kernel_state_count": 2 * len(live.ikes),
        },
    )
    return live


def start_traffic(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    ready, _, _ = select.select([proc.stdout], [], [], 5)
    if not ready or proc.stdout.readline().strip() != "READY":
        stop_process(proc)
        raise RuntimeError("The LAN receiver did not start.")
    return proc


def stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)


def exchange(
    side,
    protocol,
    source_net,
    destination_net,
    *,
    sport,
    count=3,
    size=96,
    pmtu="default",
    mss=0,
    expected_failure=False,
):
    source = addr(source_net, 11)
    destination = addr(destination_net, 11)
    sender, receiver = TOPO["sites"][side]["host"], TOPO["sites"][1 - side]["host"]
    program = (sys.executable, str(HERE / "traffic.py"))
    server = start_traffic(
        in_ns(receiver, *program, "server", protocol, destination, str(PORT), str(count))
    )
    try:
        nonce = secrets.token_hex(8)
        proc = command(
            *in_ns(
                sender,
                *program,
                "client",
                protocol,
                source,
                str(sport),
                destination,
                str(PORT),
                str(count),
                str(size),
                nonce,
                pmtu,
                str(mss),
            ),
            allowed=(0, 1),
            timeout=12,
        )
        receipt = json.loads(proc.stdout)
        if proc.returncode == 1 and expected_failure is not False:
            assert isinstance(receipt, dict)
            return {
                "sender": sender,
                "receiver": receiver,
                "source": source,
                "destination": destination,
                "bytes": size,
                "nonce": nonce,
                **receipt,
            }
        assert expected_failure is not True
        assert proc.returncode == 0, receipt
        remote = json.loads(server.communicate(timeout=8)[0])
        assert server.returncode == 0 and remote == receipt and len(remote) == count
        assert all(row["source"] == [source, sport] and row["bytes"] == size for row in remote)
        return {
            "sender": sender,
            "receiver": receiver,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "source_port": sport,
            "destination_port": PORT,
            "nonce": nonce,
            "received": count,
            "bytes_each": size,
            "mss": mss,
            "sha256": [row["sha256"] for row in remote],
        }
    finally:
        stop_process(server)


def begin_captures(model, *, wan_only=False):
    points = [
        ("hub", TOPO["wan"], None, "ip"),
        ("wan-switch", "bridge", "wan-switch", "ip"),
    ]
    for link, site in zip(model.links, TOPO["sites"], strict=True) if not wan_only else ():
        points.extend(
            (
                ("hub", link.name, None, "ip"),
                (site["router"], "wan", site["router"], "ip"),
                (site["host"], "eth0", site["host"], "ip"),
            )
        )
    captures = []
    capture_root = PEER_ROOT / "captures"
    capture_root.mkdir(mode=0o700, exist_ok=True)
    try:
        for node, interface, ns, capture_filter in points:
            path = capture_root / f"{node}-{interface}.pcap"
            args = (
                "tcpdump",
                "-nn",
                "-Z",
                "root",
                "--immediate-mode",
                "-U",
                "-i",
                interface,
                "-s",
                "256",
                "-w",
                str(path),
                capture_filter,
            )
            proc = subprocess.Popen(
                in_ns(ns, *args) if ns else args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            captures.append((node, interface, path, proc))
            ready, _, _ = select.select([proc.stderr], [], [], 6)
            if not ready or "listening on" not in proc.stderr.readline():
                raise RuntimeError(f"Capture failed to start at {node}/{interface}.")
    except BaseException:
        for _, _, _, proc in captures:
            stop_process(proc)
        raise
    return captures


def finish_captures(captures, *, markers=()):
    rows = {}
    evidence = {}
    for _, _, _, proc in captures:
        stop_process(proc)
    for node, interface, path, proc in captures:
        if not path.exists():
            continue
        data = path.read_bytes()
        evidence[f"{node}/{interface}"] = {
            "pcap_sha256": hashlib.sha256(data).hexdigest(),
            "captured_bytes": len(data),
            "plaintext_payload_markers": sum(marker.encode() in data for marker in markers),
            "marker_hashes_present": [
                hashlib.sha256(marker.encode()).hexdigest()
                for marker in markers
                if marker.encode() in data
            ],
        }
        lines = command("tcpdump", "-nn", "-tt", "-r", str(path)).stdout.splitlines()
        path.unlink()
        rows[f"{node}/{interface}"] = [
            re.sub(r"spi=0x[0-9a-f]+", "spi=<redacted>", line) for line in lines
        ]
    return rows, evidence


def verify_traffic(model, first):
    def link_stats():
        result = {}
        for link in model.links:
            raw = json.loads(ip("-s", "-j", "link", "show", "dev", link.name).stdout)[0]
            stats = raw.get("stats64") or raw["stats"]
            result[link.name] = [stats[direction]["packets"] for direction in ("rx", "tx")]
        return result

    initial_stats = link_stats()
    baseline = {
        site["site_id"]: (site["rx_packets"], site["tx_packets"]) for site in cli("status")["sites"]
    }
    captures = begin_captures(model)
    all_rows = []
    try:
        for side in (0, 1):
            src, dst = TOPO["sites"][side]["lans"], TOPO["sites"][1 - side]["lans"]
            for proto in ("udp", "tcp"):
                receipt = exchange(
                    side, proto, src[0], dst[0], sport=PORT + 1 + 2 * side + (proto == "tcp")
                )
                all_rows.append(receipt)
            for index in range(1, 4):
                all_rows.append(
                    exchange(
                        side,
                        "udp",
                        src[index // 2],
                        dst[index % 2],
                        sport=PORT + 10 + 4 * side + index,
                    )
                )
        time.sleep(1.2)
    finally:
        observed, captures_proof = finish_captures(
            captures, markers=[row["nonce"] for row in all_rows]
        )
    current = cli("status")
    assert current["status"] == "PASS" and current["data_path"]["status"] == "SKIP", current
    for site in current["sites"]:
        before = baseline[site["site_id"]]
        assert site["rx_packets"] > before[0] and site["tx_packets"] > before[1]
    final_stats = link_stats()
    assert all(
        all(new > old for old, new in zip(initial_stats[name], final_stats[name], strict=True))
        for name in final_stats
    )
    wan = observed[f"hub/{TOPO['wan']}"]
    assert captures_proof[f"hub/{TOPO['wan']}"]["plaintext_payload_markers"] == 0
    assert all(not any(row["source"] in line for row in all_rows) for line in wan)
    wire = observed["wan-switch/bridge"]
    assert captures_proof["wan-switch/bridge"]["plaintext_payload_markers"] == 0
    assert all(not any(row["source"] in line for row in all_rows) for line in wire)
    for link in model.links:
        assert any(link.peer in line and "ESP" in line for line in wan), wan[:5]
    for site in TOPO["sites"]:
        edge = observed[f"{site['router']}/wan"]
        assert any("ESP" in line for line in edge)
        assert all(not any(row["source"] in line for row in all_rows) for line in edge)
    primary = [all_rows[0], all_rows[1], all_rows[5], all_rows[6]]
    if first:
        for case, row in zip(("T05", "T07", "T06", "T08"), primary, strict=True):
            emit(
                case,
                "LAN hosts verify nonce, sequence and original source.",
                {**row, "hub_xfrm_packets": {"before": initial_stats, "after": final_stats}},
            )
        emit("T09", "Every pair in the multi-CIDR matrix reaches the opposite LAN host.", all_rows)
    for row in primary:
        needle = f"{row['source']}.{row['source_port']} > {row['destination']}.{PORT}:"
        for key in [f"hub/{link.name}" for link in model.links] + [
            f"{row['sender']}/eth0",
            f"{row['receiver']}/eth0",
        ]:
            assert any(needle in line for line in observed[key]), (key, needle)
        if row["protocol"] == "tcp":
            path = observed[f"{row['sender']}/eth0"]
            assert any(needle in line and "Flags [S]" in line for line in path)
            assert any(needle in line and "Flags [F" in line for line in path)
    if first:
        emit(
            "T10 T11",
            "LAN and XFRM tuples match. WAN only carries encrypted test traffic.",
            {
                "hub_xfrm_packets": {"before": initial_stats, "after": final_stats},
                "capture_points": {
                    key: {
                        "packets": len(lines),
                        "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
                        "samples": lines[:4],
                        **captures_proof[key],
                    }
                    for key, lines in observed.items()
                },
            },
        )
    return all_rows


def verify_routes(model):
    paths = {}
    for site, link in zip(TOPO["sites"], model.links, strict=True):
        destination = addr(link.local_ts[0], 11)
        site_lookup = ip("-j", "route", "get", destination, ns=site["router"])
        assert json.loads(site_lookup.stdout)[0]["dev"] == "tunnel"
        inner = json.loads(ip("-j", "route", "get", addr(link.remote_ts[0], 11)).stdout)[0]
        outer = json.loads(ip("-j", "route", "get", link.peer, "from", link.source).stdout)[0]
        assert inner["dev"] == link.name and outer["dev"] == TOPO["wan"]
        paths[site["router"]] = {
            "peer_xfrm": "tunnel",
            "hub_xfrm": inner["dev"],
            "hub_peer_route": outer["dev"],
        }
    emit(
        "T12",
        "Reciprocal private routes use XFRM, while outer peers remain on the isolated WAN.",
        paths,
    )


def connect(model):
    for link in model.links:
        report = cli("initiate", "--site", link.site_id, "--confirm")
        assert report["status"] == "PASS", report


def verify_noop(model):
    pid = HOST.assert_daemon({link.name for link in model.links})
    live = inventory(HOST, model, pid)
    recorded = JOURNAL.read_bytes()
    assert cli("doctor")["data_path"]["status"] == "SKIP"
    result = cli("apply", "-c", str(PROFILE), "--confirm")
    assert "NOOP" in result["detail"] and JOURNAL.read_bytes() == recorded
    assert inventory(HOST, model, pid) == live
    row = exchange(
        0, "udp", TOPO["sites"][0]["lans"][0], TOPO["sites"][1]["lans"][0], sport=PORT + 39
    )
    emit(
        "T14",
        "Live same-profile apply preserves IKE/CHILD IDs and journal.",
        {"apply": result["detail"], "payload": row},
        action="doctor; apply --confirm; UDP probe",
    )


def pair(protocol, start, **kwargs):
    return [
        exchange(
            side,
            protocol,
            TOPO["sites"][side]["lans"][0],
            TOPO["sites"][1 - side]["lans"][0],
            sport=PORT + start + side,
            **kwargs,
        )
        for side in (0, 1)
    ]


def stable(model, predicate, seconds=12):
    end = time.monotonic() + seconds
    pid = HOST.assert_daemon({link.name for link in model.links})
    while time.monotonic() < end:
        try:
            observed = inventory(HOST, model, pid)
            if predicate(observed):
                return observed
        except Stop:
            pass
        time.sleep(0.35)
    raise RuntimeError("The isolated Hub did not reach the expected verified SA state.")


def verify_rekeys(model):
    link = model.links[0]
    node = TOPO["sites"][0]
    pid = HOST.assert_daemon({item.name for item in model.links})
    for idx, (case, kind) in enumerate((("S01", "ike"), ("S02", "child"))):
        before = inventory(HOST, model, pid).get(link.name)
        report = cli("rekey", "--site", link.site_id, f"--{kind}", "--confirm")
        after = inventory(HOST, model, pid).get(link.name)
        old = before.unique_id if kind == "ike" else before.child.unique_id
        new = after.unique_id if kind == "ike" else after.child.unique_id
        assert old != new
        verify_sas(model, phase=f"local {kind} rekey")
        emit(
            case,
            "Targeted rekey correlates VICI old/new and retains real bidirectional traffic.",
            {
                "journal": report["journal"],
                "old": old,
                "new": new,
                "flows": pair("udp", 45 + idx * 2),
            },
            action=f"rekey --{kind} --confirm",
        )
    changes = {}
    for kind in ("child", "ike"):
        before = inventory(HOST, model, pid).get(link.name)
        old = before.child.unique_id if kind == "child" else before.unique_id
        peerctl(node, "--rekey", f"--{kind}", link.child if kind == "child" else link.name)

        def changed(snap):
            current = snap.get(link.name)
            return (
                current
                and current.child
                and (current.child.unique_id if kind == "child" else current.unique_id) != old
            )

        current = stable(model, changed).get(link.name)
        verify_sas(model, phase=f"peer {kind} rekey")
        changes[kind] = [old, current.child.unique_id if kind == "child" else current.unique_id]
    emit(
        "S03",
        "The real peer initiates CHILD and IKE rekey.",
        {"peer": node["router"], "hub_generations": changes, "flows": pair("udp", 50)},
        action="peer swanctl --rekey for each SA type",
    )
    for kind in ("child", "ike"):
        old = inventory(HOST, model, pid).get(link.name)
        gate = Barrier(2, timeout=5)

        def trigger(leader):
            socket_path = PEER_ROOT / node["router"] / "charon.vici"
            control = session(pid) if leader else session(peer_pid(node), socket_path)
            with control as client:
                gate.wait()
                start = time.monotonic()
                reply = client.request(
                    "rekey",
                    {
                        kind: link.child if kind == "child" else link.name,
                    },
                )
                assert reply.get("matches") == b"1"
                return start

        with ThreadPoolExecutor(2) as pool:
            sent = tuple(pool.map(trigger, (True, False)))
        original_journal = JOURNAL.read_bytes()
        contender = cli("apply", "-c", str(PROFILE), "--confirm", expect=None)
        if contender["status"] == "PASS":
            assert "NOOP" in contender["detail"]
        else:
            assert contender["decision"] == "STOP"
        assert JOURNAL.read_bytes() == original_journal
        old_id = old.child.unique_id if kind == "child" else old.unique_id

        def advanced(snap):
            item = snap.get(link.name)
            return (
                item
                and item.child
                and (item.child.unique_id if kind == "child" else item.unique_id) != old_id
            )

        stable(model, advanced, seconds=18)
        verify_sas(model, phase=f"simultaneous {kind} rekey")
        assert abs(sent[0] - sent[1]) < 1
        emit(
            "S04",
            "Both real endpoints request rekey within the same bounded window.",
            {
                "kind": kind,
                "request_skew_ms": round(abs(sent[0] - sent[1]) * 1000, 3),
                "flows": pair("udp", 52 if kind == "child" else 54),
            },
        )
        emit(
            "F14",
            "A concurrent same-profile apply either sees stable NOOP or refuses ambiguity.",
            {"kind": kind, "apply": contender["detail"], "journal_unchanged": True},
        )


def capture_fail_closed(model, start):
    captures = begin_captures(model, wan_only=True)
    rows = []
    control = secrets.token_hex(16)
    try:
        rows = pair("udp", start, expected_failure=True, count=1)
        # A public-endpoint test datagram verifies the independent wire tap.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((TOPO["hub"].split("/")[0], 0))
            probe.sendto(control.encode(), (TOPO["sites"][-1]["endpoint"].split("/")[0], PORT))
        time.sleep(0.2)
    finally:
        observed, captures_proof = finish_captures(
            captures, markers=[row["nonce"] for row in rows] + [control]
        )
    point = f"hub/{TOPO['wan']}"
    wan = observed[point]
    hits = [line for line in wan if any(row["source"] in line for row in rows)]
    proof = {
        "unreachable_flows": rows,
        "capture_point": point,
        "wan_packets": len(wan),
        "hub_local_private_headers": hits[:12],
        **captures_proof[point],
        "external_wire": {
            "capture_point": "wan-switch/bridge",
            "packets": len(observed["wan-switch/bridge"]),
            "private_address_headers": [
                line
                for line in observed["wan-switch/bridge"]
                if any(row["source"] in line for row in rows)
            ][:12],
            **captures_proof["wan-switch/bridge"],
        },
    }
    wire = proof["external_wire"]
    control_hash = hashlib.sha256(control.encode()).hexdigest()
    assert control_hash in wire["marker_hashes_present"], "External capture missed its control."
    private_hashes = {hashlib.sha256(row["nonce"].encode()).hexdigest() for row in rows}
    wire["private_payload_markers"] = len(
        private_hashes.intersection(wire["marker_hashes_present"])
    )
    wire["capture_control_verified"] = True
    # The Hub's AF_PACKET view can see a decapsulated skb before the missing-XFRM
    # inbound policy drop. The separate switch sees actual wire frames.
    if wire["private_address_headers"] or wire["private_payload_markers"]:
        emit(
            "WAN_GUARD",
            "WAN capture must contain no private traffic or test payload.",
            proof,
            status="FAIL",
        )
        raise AssertionError("WAN capture includes private addresses or a test payload marker.")
    return {**proof, "wan_private_plaintext": 0}


def verify_mtu(model):
    def stats(node):
        command_args = ("cat", "/proc/net/xfrm_stat")
        if node:
            command_args = in_ns(node, *command_args)
        return {
            name: int(value)
            for name, value in (line.split() for line in command(*command_args).stdout.splitlines())
        }

    node = TOPO["sites"][0]["router"]
    nodes = [None, node, TOPO["sites"][1]["router"]]
    before = {ns or "hub": stats(ns) for ns in nodes}
    small = pair("udp", 60, count=5, size=96, pmtu="df")
    emit(
        "N01",
        "Five small DF UDP payloads received in both directions.",
        {"flows": small, "lost": 0},
    )
    captures = begin_captures(model)
    try:
        bounds = [
            exchange(
                0,
                "udp",
                TOPO["sites"][0]["lans"][0],
                TOPO["sites"][1]["lans"][0],
                sport=PORT + 64 + i,
                count=1,
                size=size,
                pmtu="df",
                expected_failure=None,
            )
            for i, size in enumerate((1200, 1300, 1380, 1420, 1460, 1472))
        ]
        fragments = pair("udp", 72, count=2, size=2048, pmtu="fragment", expected_failure=None)
        qdisc_before = json.loads(
            command(*in_ns(node, "tc", "-j", "qdisc", "show", "dev", "wan")).stdout
        )
        assert all(row["kind"] == "noqueue" for row in qdisc_before)
        command(
            *in_ns(
                node,
                "tc",
                "qdisc",
                "add",
                "dev",
                "wan",
                "root",
                "handle",
                "300:",
                "tbf",
                "rate",
                "1mbit",
                "burst",
                "8kb",
                "latency",
                "200ms",
            )
        )
        try:
            started = time.monotonic()
            streams = pair("tcp", 74, count=2, size=8192, mss=512) + pair(
                "tcp", 76, count=2, size=8192, mss=1024
            )
            shaping = {
                "node": node,
                "interface": "wan",
                "requested_rate": "1mbit",
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "observed_qdisc": json.loads(
                    command(*in_ns(node, "tc", "-s", "-j", "qdisc", "show", "dev", "wan")).stdout
                ),
            }
            assert len(shaping["observed_qdisc"]) == 1
            assert shaping["observed_qdisc"][0]["kind"] == "tbf"
            assert shaping["observed_qdisc"][0]["handle"] == "300:"
        finally:
            command(*in_ns(node, "tc", "qdisc", "del", "dev", "wan", "root", "handle", "300:"))
        qdisc_after = json.loads(
            command(*in_ns(node, "tc", "-j", "qdisc", "show", "dev", "wan")).stdout
        )
        assert qdisc_after == qdisc_before
        shaping["original_qdisc_restored"] = True
    finally:
        observed, _ = finish_captures(captures)
    devices = {
        f"hub/{link.name}": json.loads(ip("-j", "link", "show", "dev", link.name).stdout)[0]["mtu"]
        for link in model.links
    }
    for site in TOPO["sites"]:
        for device in ("wan", "tunnel"):
            key = f"{site['router']}/{device}"
            devices[key] = json.loads(
                ip("-j", "link", "show", "dev", device, ns=site["router"]).stdout
            )[0]["mtu"]
    icmp = {
        key: [line for line in lines if "need to frag" in line.lower()]
        for key, lines in observed.items()
    }
    emit(
        "N02",
        "Real DF size sweep with measured link MTUs.",
        {
            "mtus": devices,
            "sweep": bounds,
            "outer": "UDP encapsulated ESP",
            "path_routes": {
                f"{node or 'hub'}-to-site-{side}": json.loads(
                    ip(
                        "-j",
                        "-4",
                        "route",
                        "get",
                        addr(TOPO["sites"][side]["lans"][0], 11),
                        ns=node,
                    ).stdout
                )
                for node, side in (
                    (None, 0),
                    (None, 1),
                    (TOPO["sites"][0]["router"], 1),
                    (TOPO["sites"][1]["router"], 0),
                    (TOPO["sites"][0]["host"], 1),
                    (TOPO["sites"][1]["host"], 0),
                )
            },
        },
    )
    has_feedback = any(icmp.values()) or any(row.get("errno") == 90 for row in bounds)
    emit(
        "N03",
        "Oversize DF receives ICMP fragmentation-needed or EMSGSIZE.",
        {"icmp": icmp, "results": bounds},
        status="PASS" if has_feedback else "FAIL",
    )
    fragment_evidence = {
        key: [line for line in lines if "ip-proto-17" in line.lower() or "frag" in line.lower()][:8]
        for key, lines in observed.items()
    }
    fragments_ok = all(row.get("received") == 2 for row in fragments) and any(
        fragment_evidence.values()
    )
    emit(
        "N04",
        "Fragmented datagrams are reassembled with verified payloads.",
        {"flows": fragments, "fragments": fragment_evidence},
        status="PASS" if fragments_ok else "FAIL",
    )
    emit(
        "N05",
        "Both TCP directions verify payloads and two MSS settings under a peer WAN rate cap.",
        {"flows": streams, "shaping": shaping},
    )
    after = {ns or "hub": stats(ns) for ns in nodes}
    counters = {
        node: {
            key: value - before[node][key]
            for key, value in fields.items()
            if value != before[node][key]
        }
        for node, fields in after.items()
    }
    emit(
        "N06",
        "Collect actual per-node XFRM counters and XFRM traffic stats without sysctl edits.",
        {"errors": counters, "hub_links": cli("status")["sites"]},
    )


def assert_write_stop(model):
    site = model.links[0].site_id
    recorded = JOURNAL.read_bytes()
    for args in (
        ("apply", "-c", str(PROFILE), "--maintenance", "--confirm"),
        ("initiate", "--site", site, "--confirm"),
        ("rekey", "--site", site, "--child", "--confirm"),
        ("uninstall", "--maintenance", "--confirm"),
    ):
        assert cli(*args, expect=1)["decision"] == "STOP"
    assert JOURNAL.read_bytes() == recorded


def reversed_link(link):
    return replace(
        link,
        source=link.peer,
        peer=link.source,
        local_id=link.remote_id,
        remote_id=link.local_id,
        local_ts=link.remote_ts,
        remote_ts=link.local_ts,
    )


def set_link(client, link, key):
    client.request(
        "load-shared",
        {
            "id": f"ike-{link.name}",
            "type": "IKE",
            "data": key,
            "owners": [link.local_id, link.remote_id],
        },
    )
    client.request("load-conn", {link.name: connection_settings(link)})


def ike_id(client, name):
    matches = [int(event[name]["uniqueid"]) for event in client.list_sas() if name in event]
    if len(matches) > 1:
        raise RuntimeError("Multiple generations in the isolated fault fixture.")
    return matches[0] if matches else None


def remove_fixture_sa(client, name):
    identifier = ike_id(client, name)
    if identifier is not None:
        client.request("terminate", {"ike-id": str(identifier), "force": "yes", "timeout": "2500"})


def verify_bad_negotiation(model):
    link = model.links[0]
    node = TOPO["sites"][0]
    path = PEER_ROOT / node["router"] / "charon.vici"
    reverse = reversed_link(link)
    key = read_keys(load_profile(PROFILE))[link.site_id]
    pid = HOST.assert_daemon({item.name for item in model.links})
    with session(pid) as hub:
        remove_fixture_sa(hub, link.name)
    with session(peer_pid(node), path) as peer:
        remove_fixture_sa(peer, link.name)
    stable(model, lambda snapshot: not snapshot.get(link.name))
    variants = [
        ("F01", "wrong PSK", reverse, os.urandom(32), "IKE_AUTHENTICATION"),
        (
            "F01",
            "wrong IKE ID",
            replace(reverse, local_id="@pr3-incorrect-id"),
            key,
            "IKE_AUTHENTICATION",
        ),
        (
            "F02",
            "wrong ESP proposal",
            replace(reverse, esp_proposal="aes128-sha256-modp2048"),
            key,
            "PROPOSAL_REJECTED",
        ),
        (
            "F02",
            "wrong IKE DH group",
            replace(reverse, ike_proposal="aes256-sha256-prfsha256-modp3072"),
            key,
            "PROPOSAL_REJECTED",
        ),
        (
            "F03",
            "disjoint selectors",
            replace(reverse, local_ts=("10.192.0.0/24",)),
            key,
            "CHILD_SELECTORS",
        ),
    ]
    for case, action, variant, proposed_key, expected_reason in variants:
        with session(peer_pid(node), path) as peer:
            set_link(peer, variant, proposed_key)
        try:
            report = cli("initiate", "--site", link.site_id, "--confirm", expect=1)
            assert report["decision"] == "STOP"
            states = kernel_states(
                HOST.command("Fixture SAD", "ip", "-o", "xfrm", "state", "list", "nokeys")
            )
            assert all(state.if_id != link.if_id for state in states)
            emit(
                case,
                "Negotiation fails without installing a CHILD or exposing credentials.",
                {"decision": "STOP", "reason_code": report.get("reason_code")},
                status="PASS" if report.get("reason_code") == expected_reason else "FAIL",
                action=action,
            )
        finally:
            with session(pid) as hub:
                remove_fixture_sa(hub, link.name)
            with session(peer_pid(node), path) as peer:
                remove_fixture_sa(peer, link.name)
                set_link(peer, reverse, key)
    with session(peer_pid(node), path) as peer:
        set_link(peer, replace(reverse, esp_proposal="aes256-sha256-modp3072"), key)
    try:
        # IKE_AUTH inherits the IKE DH exchange. PFS mismatch is exercised by
        # the subsequent CREATE_CHILD_SA rekey, which must retain the old CHILD.
        cli("initiate", "--site", link.site_id, "--confirm")
        old = inventory(HOST, model, pid).get(link.name)
        refusal = cli("rekey", "--site", link.site_id, "--child", "--confirm", expect=1)
        after = inventory(HOST, model, pid).get(link.name)
        assert refusal["reason_code"] == "SA_TRANSITION" and after == old
        emit(
            "F02",
            "Disjoint PFS groups do not create a downgraded CHILD generation.",
            {
                "decision": refusal["decision"],
                "reason_code": refusal["reason_code"],
                "hub_pfs": link.esp_proposal,
                "peer_pfs": "aes256-sha256-modp3072",
                "old_child_retained": True,
                "flows": pair("udp", 180),
            },
            action="real CHILD rekey with disjoint configured PFS groups",
        )
    finally:
        with session(pid) as hub:
            remove_fixture_sa(hub, link.name)
        with session(peer_pid(node), path) as peer:
            remove_fixture_sa(peer, link.name)
            set_link(peer, reverse, key)
    cli("initiate", "--site", link.site_id, "--confirm")


def verify_foreign_ike(model):
    original = model.links[0]
    foreign = replace(
        original,
        if_id=65213,
        local_id="@pr3-foreign-hub",
        remote_id="@pr3-foreign-site",
        local_ts=("10.193.0.0/24",),
        remote_ts=("10.194.0.0/24",),
    )
    key = os.urandom(32)
    node = TOPO["sites"][0]
    path = PEER_ROOT / node["router"] / "charon.vici"
    pid = HOST.assert_daemon({item.name for item in model.links})
    with session(pid) as hub, session(peer_pid(node), path) as peer:
        set_link(hub, foreign, key)
        set_link(peer, reversed_link(foreign), key)
        try:
            peer.request(
                "initiate", {"ike": foreign.name, "child": foreign.child, "timeout": "5000"}
            )
            identifier = ike_id(hub, foreign.name)
            assert identifier
            assert_write_stop(model)
            assert ike_id(hub, foreign.name) == identifier
            assert cli("status", expect=1)["decision"] == "STOP"
        finally:
            for client in (hub, peer):
                remove_fixture_sa(client, foreign.name)
                client.request("unload-conn", {"name": foreign.name})
                client.request("unload-shared", {"id": f"ike-{foreign.name}"})
    emit(
        "F04",
        "An independently authenticated foreign IKE/CHILD stays intact while writes STOP.",
        {"decision": "STOP", "foreign_if_id": foreign.if_id},
    )


def verify_foreign_policy(model):
    policy = (
        "src",
        "192.0.2.211/32",
        "dst",
        "192.0.2.212/32",
        "dir",
        "out",
        "if_id",
        str(model.links[0].if_id),
    )
    ip("xfrm", "policy", "add", *policy, "action", "block", "priority", "470000")
    try:
        before = ip("-o", "xfrm", "policy", "list", "nosock").stdout
        assert_write_stop(model)
        assert cli("status", expect=1)["decision"] == "STOP"
        assert ip("-o", "xfrm", "policy", "list", "nosock").stdout == before
    finally:
        ip("xfrm", "policy", "delete", *policy)
    emit(
        "F05 F06",
        "Unowned kernel policy using a genuine if_id blocks writes.",
        {"decision": "STOP", "original_policy_retained_until_fixture_cleanup": True},
    )


class RouteFault(Host):
    def __init__(self, kind="route"):
        super().__init__()
        self.kind = kind
        self.triggered = False
        self.nft_writes = 0

    def command(self, label, *args, **kwargs):
        if label == "nft atomic update" and kwargs.get("mutate"):
            self.nft_writes += 1
            if self.kind == "nft" and self.nft_writes == 2:
                self.triggered = True
                return super().command(
                    label, *args, content=b"intentionally invalid fixture input\n", mutate=True
                )
        if (
            self.kind in {"route", "kill"}
            and label == "IPv4 unicast route del"
            and kwargs.get("mutate")
            and not self.triggered
        ):
            self.triggered = True
            if self.kind == "kill":
                super().command(label, *args, **kwargs)
                os.kill(os.getpid(), signal.SIGKILL)
            return super().command(
                label, "setpriv", "--bounding-set=-net_admin", *args, mutate=True
            )
        return super().command(label, *args, **kwargs)


class ViciFault(Deployment):
    def __init__(self):
        super().__init__()
        self.triggered = False

    def step(self, label, result):
        super().step(label, result)
        if label == "VICI scoped load" and result == "STARTED":
            self.triggered = True
            with session(HOST.service(UNIT, "MainPID")) as client:
                client.request("ipsecvpn-unknown-fixture-operation")


def verify_maintenance(model):
    profile = load_profile(PROFILE)
    profile["site_links"][0]["if_id"] += 256
    write_profile(profile, UPDATE)
    blocked = cli("apply", "-c", str(UPDATE), "--confirm", expect=1)
    assert "maintenance" in blocked["detail"]
    emit(
        "F13",
        "Unconfirmed active config change preserves the old business path.",
        {"decision": "STOP", "flows": pair("udp", 80)},
    )
    saved = cli("backup", "--confirm")["backup_id"]
    changed = cli("apply", "-c", str(UPDATE), "--maintenance", "--confirm")
    assert changed["maintenance"]["required_for_changes"]
    emit(
        "S07",
        "Explicit maintenance changes Hub XFRM ID, restores both CHILDs and actual LAN traffic.",
        {"journal": changed["backup_id"], "flows": pair("udp", 84) + pair("tcp", 86)},
    )
    returned = cli("rollback", "--to", saved, "--maintenance", "--confirm")
    assert returned["configuration_restored"] and returned["data_path_restored"]["status"] == "SKIP"
    assert cli("status")["status"] == "PASS"
    for index, kind in enumerate(("route", "nft", "vici", "kill")):
        if kind == "kill":
            child = subprocess.run((sys.executable, __file__, "crash"), check=False, timeout=90)
            assert child.returncode == -signal.SIGKILL
        else:
            faulty = ViciFault() if kind == "vici" else RouteFault(kind)
            operation = faulty if kind == "vici" else Deployment(faulty)
            try:
                operation.dispatch("apply", True, UPDATE, maintenance=True)
            except Stop:
                assert faulty.triggered
            else:
                raise AssertionError("Live maintenance unexpectedly accepted the route fault.")
        journal = read_record(JOURNAL)
        assert journal["phase"] in {"STOP_FOR_MANUAL", "APPLYING"}
        assert not journal.get("configuration_restored")
        proof = capture_fail_closed(model, 140 + 4 * index)
        recovered = cli("rollback", "--to", journal["id"], "--maintenance", "--confirm")
        assert (
            recovered["configuration_restored"]
            and recovered["data_path_restored"]["status"] == "SKIP"
        )
        emit(
            "S08" if kind == "kill" else "S10",
            "Fault stays guarded until explicit maintenance recovery and real traffic proof.",
            {
                "journal": journal["id"],
                "failed_phase": journal["phase"],
                "guard": proof,
                "restored_phase": read_record(JOURNAL)["phase"],
                "flows": pair("udp", 142 + 4 * index),
                "fault": kind,
            },
        )
        if kind == "kill":
            emit("F10", "Interrupted transaction has no WAN private plaintext.", proof)
    assert read_record(ACTIVE)["profile"] == load_profile(PROFILE)


def verify_isolation_failures(model):
    extra = TOPO["sites"][0]["extra_lan"]
    failures = [
        exchange(
            0,
            "udp",
            extra,
            TOPO["sites"][1]["lans"][0],
            sport=PORT + 100,
            count=1,
            expected_failure=True,
        ),
        exchange(
            1,
            "udp",
            TOPO["sites"][1]["lans"][0],
            extra,
            sport=PORT + 101,
            count=1,
            expected_failure=True,
        ),
    ]
    spoofed_net = TOPO["sites"][1]["lans"][1]
    spoofed = f"{addr(spoofed_net, 11)}/32"
    sender = TOPO["sites"][0]["host"]
    ip("addr", "add", spoofed, "dev", "eth0", ns=sender)
    try:
        failures.append(
            exchange(
                0,
                "udp",
                spoofed_net,
                TOPO["sites"][1]["lans"][0],
                sport=PORT + 176,
                count=1,
                expected_failure=True,
            )
        )
    finally:
        ip("addr", "del", spoofed, "dev", "eth0", ns=sender)
    emit("F07", "Declared but unauthorized LAN is refused in both directions.", failures)
    assert all(row["timeout"] or row["errno"] is not None for row in failures)
    emit(
        "F16",
        "Bounded negative probes report failure and their servers are stopped.",
        {"probe_outcomes": failures, "network_cleanup": "disposable guest lifecycle"},
    )
    link = model.links[0]
    install = read_record(INSTALLED)
    resources = Resources(HOST, install["token"], (model,))
    ip("link", "del", "dev", link.name)
    try:
        report = cli("status", expect=1)
        assert report["data_path"]["status"] == "SKIP"
        lookup = ip("-4", "route", "get", addr(link.remote_ts[0], 11), allowed=(2,))
        assert lookup.returncode == 2
        proof = capture_fail_closed(model, 102)
        emit(
            "F08 F09",
            "Missing XFRM leaves the protected route blocked and business unverified.",
            {"diagnostics": report["status"], "business": report["data_path"], **proof},
        )
    finally:
        ip("link", "add", "name", link.name, "type", "xfrm", "if_id", str(link.if_id))
        ip("link", "set", "dev", link.name, "alias", resources.alias, "up")
        for spec in sorted(resources.routes):
            if spec[2] == link.name:
                resources.route("add", spec)
    assert cli("status")["status"] == "PASS"
    command(
        "nft",
        "-f",
        "-",
        input=(
            "table ip pr3_foreign {\n"
            "    chain filter {\n"
            "        type filter hook forward priority 15; policy drop;\n"
            "    }\n"
            "}\n"
        ),
    )
    try:
        outside = command("nft", "list", "table", "ip", "pr3_foreign").stdout
        assert_write_stop(model)
        assert command("nft", "list", "table", "ip", "pr3_foreign").stdout == outside
    finally:
        command("nft", "delete", "table", "ip", "pr3_foreign")
    emit("F11", "An external nft DROP stops active writes and is preserved.", "STOP")
    ip("-4", "route", "add", "blackhole", "default", "metric", "49152")
    try:
        assert_write_stop(model)
    finally:
        ip("-4", "route", "del", "blackhole", "default", "metric", "49152")
    emit("F12", "Recorded route baseline drift stops changes.", "STOP")
    assert (
        cli("rollback", "--to", "0" * 32, "--maintenance", "--confirm", expect=1)["decision"]
        == "STOP"
    )
    profile = load_profile(PROFILE)
    key = Path(profile["site_links"][0]["secret_ref"][5:])
    original = key.read_bytes()
    try:
        key.write_bytes(os.urandom(32).hex().encode() + b"\n")
        assert cli("apply", "-c", str(PROFILE), "--confirm", expect=1)["decision"] == "STOP"
    finally:
        key.write_bytes(original)
    emit("F15", "Invalid backup and unexpected PSK drift block changes.", "STOP")


def verify_plaintext_injection(model):
    site, target = TOPO["sites"]
    destination = addr(target["lans"][0], 11)
    host_route = f"{destination}/32"
    captures = begin_captures(model)
    receipt = None
    ip(
        "route",
        "add",
        host_route,
        "via",
        TOPO["hub"].split("/")[0],
        "dev",
        "wan",
        ns=site["router"],
    )
    try:
        receipt = exchange(
            0,
            "udp",
            site["lans"][0],
            target["lans"][0],
            sport=PORT + 184,
            count=1,
            expected_failure=True,
        )
    finally:
        ip("route", "del", host_route, ns=site["router"])
        observed, proof = finish_captures(captures, markers=[receipt["nonce"]] if receipt else ())
    needle = f"{receipt['source']}.{PORT + 184} > {destination}.{PORT}:"
    assert any(needle in line for line in observed["wan-switch/bridge"])
    assert proof["wan-switch/bridge"]["plaintext_payload_markers"] == 1
    for point in (f"hub/{model.links[1].name}", f"{target['host']}/eth0"):
        assert all(needle not in line for line in observed[point]), point
    emit(
        "F07",
        "An actual plaintext private packet on the outer WAN is refused by the Hub ACL.",
        {
            "injected_flow": receipt,
            "wire": proof["wan-switch/bridge"],
            "forwarded_attack_packets": 0,
            "recovered_flows": pair("udp", 186),
        },
        action="divert one peer host route onto the closed WAN, then restore it",
    )


def verify_child_outage(model):
    link, other = model.links
    pid = HOST.assert_daemon({item.name for item in model.links})
    before = inventory(HOST, model, pid)
    old = before.get(link.name)
    with session(pid) as hub:
        hub.request(
            "terminate", {"child-id": str(old.child.unique_id), "force": "yes", "timeout": "2500"}
        )
    remaining = stable(model, lambda row: row.get(link.name) and not row.get(link.name).child)
    assert remaining.get(link.name).unique_id == old.unique_id
    assert remaining.get(other.name) == before.get(other.name)
    diagnostics = cli("status")
    assert diagnostics["status"] == "SKIP" and diagnostics["data_path"]["status"] == "SKIP"
    guard = capture_fail_closed(model, 188)
    cli("initiate", "--site", link.site_id, "--confirm")
    restored = inventory(HOST, model, pid).get(link.name)
    assert restored.unique_id == old.unique_id and restored.child.unique_id != old.child.unique_id
    emit(
        "F09 S06",
        "Only one CHILD is removed, IKE and the other site survive, then traffic is restored.",
        {
            "ike_retained": old.unique_id,
            "guard": guard,
            "flows": pair("udp", 190) + pair("tcp", 192),
        },
        action="target one verified CHILD ID in the disposable Hub",
    )


def verify_blocked_ike(model):
    link, other = model.links
    site = TOPO["sites"][0]
    pid = HOST.assert_daemon({item.name for item in model.links})
    original = inventory(HOST, model, pid)
    path = PEER_ROOT / site["router"] / "charon.vici"
    with session(pid) as hub, session(peer_pid(site), path) as peer:
        remove_fixture_sa(hub, link.name)
        remove_fixture_sa(peer, link.name)
    stable(model, lambda row: not row.get(link.name))
    blocked = command(
        *in_ns(site["router"], "nft", "-f", "-"),
        input=(
            "table ip pr3_ike_block {\n"
            "    chain input {\n"
            "        type filter hook input priority -10; policy accept;\n"
            f"        ip saddr {link.source} udp dport {{ 500, 4500 }} drop\n"
            "    }\n"
            "}\n"
        ),
        allowed=(0, 1),
    )
    if blocked.returncode:
        emit(
            "IKE_BLOCK_FIXTURE",
            "Load the exact isolated peer port-block rule.",
            {"nft_error": blocked.stderr[:1600]},
            status="FAIL",
        )
        raise RuntimeError("The isolated peer IKE-port fixture could not be installed.")
    try:
        refusal = cli("initiate", "--site", link.site_id, "--confirm", expect=1)
        assert refusal.get("reason_code") == "PEER_UNREACHABLE", refusal
        guard = capture_fail_closed(model, 194)
    finally:
        command(*in_ns(site["router"], "nft", "delete", "table", "ip", "pr3_ike_block"))
        with session(pid) as hub, session(peer_pid(site), path) as peer:
            remove_fixture_sa(hub, link.name)
            remove_fixture_sa(peer, link.name)
    assert inventory(HOST, model, pid).get(other.name) == original.get(other.name)
    cli("initiate", "--site", link.site_id, "--confirm")
    emit(
        "S05 S06",
        "UDP500/4500 block has bounded failed negotiation, guarded data and targeted recovery.",
        {
            "decision": refusal["decision"],
            "reason_code": refusal["reason_code"],
            "guard": guard,
            "other_site_preserved": True,
            "flows": pair("udp", 196) + pair("tcp", 198),
        },
        action="block both IKE ports only in one isolated peer, then remove the exact fixture",
    )


def verify_dpd(model):
    link, other = model.links
    site = TOPO["sites"][0]
    start = time.monotonic()
    ip("link", "set", "wan", "down", ns=site["router"])
    try:
        proof = capture_fail_closed(model, 108)
        remaining = stable(
            model,
            lambda snap: (
                not snap.get(link.name) and snap.get(other.name) and snap.get(other.name).child
            ),
            seconds=190,
        )
        assert remaining.get(other.name).child
    finally:
        ip("link", "set", "wan", "up", ns=site["router"])
    detected = time.monotonic() - start
    report = cli("initiate", "--site", link.site_id, "--confirm")
    emit(
        "S05 S06",
        "One peer loses WAN, DPD removes only its SA, then targeted reconnect restores traffic.",
        {
            "detection_and_isolation_seconds": round(detected, 3),
            "guard": proof,
            "reconnect_journal": report["journal"],
            "flows": pair("udp", 110),
        },
    )


def verify_daemon_restart(model):
    old_pid = HOST.service(UNIT, "MainPID")
    peers = {site["router"]: peer_pid(site) for site in TOPO["sites"]}
    command("systemctl", "restart", UNIT, timeout=90)
    assert all(Path(f"/proc/{pid}").exists() for pid in peers.values()), peers
    stable(
        model, lambda snap: len(snap.ikes) == 2 and all(ike.child for ike in snap.ikes), seconds=90
    )
    assert HOST.service(UNIT, "MainPID") != old_pid
    emit(
        "T13_DAEMON",
        "Restarting the owned daemon restores verified SAs and both business directions.",
        {"flows": pair("udp", 114), "independent_peer_pids_preserved": peers},
        action="systemctl restart strongswan",
    )


def reset_saved_peer_kernel(site, states, policies):
    require_lab()
    node = site["router"]
    current_states = kernel_states(ip("-o", "xfrm", "state", "list", "nokeys", ns=node).stdout)
    current_policies = kernel_policies(ip("-o", "xfrm", "policy", "list", "nosock", ns=node).stdout)
    if (
        set(current_states) != set(states)
        or len(current_states) != len(states)
        or set(current_policies) != set(policies)
        or len(current_policies) != len(policies)
    ):
        raise Stop("Peer crash recovery requires an exact match to its saved owned objects.")
    for policy, _ in policies:
        ip(
            "xfrm",
            "policy",
            "delete",
            "src",
            policy.source,
            "dst",
            policy.destination,
            "dir",
            policy.direction,
            "if_id",
            str(policy.if_id),
            ns=node,
        )
    for state in states:
        # iproute2 6.1 deletes a state by endpoints/protocol/SPI. Its if_id was
        # already checked in the complete saved/current inventory comparison.
        ip(
            "xfrm",
            "state",
            "delete",
            "src",
            state.source,
            "dst",
            state.destination,
            "proto",
            "esp",
            "spi",
            hex(state.spi),
            ns=node,
        )
    assert not ip("xfrm", "state", "list", "nokeys", ns=node).stdout.strip()
    assert not ip("xfrm", "policy", "list", "nosock", ns=node).stdout.strip()


def verify_peer_restart(model):
    node, link = TOPO["sites"][0], model.links[0]
    verify_sas(model, phase="before simulated peer power loss")
    states = kernel_states(ip("-o", "xfrm", "state", "list", "nokeys", ns=node["router"]).stdout)
    policies = kernel_policies(
        ip("-o", "xfrm", "policy", "list", "nosock", ns=node["router"]).stdout
    )
    peer_model = DeploymentManifest(model.event_id, (reversed_link(link),))
    with session(peer_pid(node), PEER_ROOT / node["router"] / "charon.vici") as control:
        correlate(parse_vici(list(control.list_sas()), peer_model), peer_model, states, policies)
    saved_hash = hashlib.sha256(repr((states, policies)).encode()).hexdigest()
    old = peer_pid(node)
    os.kill(old, signal.SIGKILL)
    deadline = time.monotonic() + 12
    while Path(f"/proc/{old}").exists() and time.monotonic() < deadline:
        time.sleep(0.25)
    assert not Path(f"/proc/{old}").exists()
    # A crashed process leaves kernel objects. Model loss of the peer's IPsec
    # kernel state using only its pre-crash, exactly verified ownership snapshot.
    unknown = (
        "src",
        "10.195.0.0/24",
        "dst",
        "10.196.0.0/24",
        "dir",
        "out",
        "if_id",
        str(link.if_id),
    )
    ip(
        "xfrm",
        "policy",
        "add",
        *unknown,
        "action",
        "block",
        "priority",
        "470001",
        ns=node["router"],
    )
    before_state = ip("-o", "xfrm", "state", "list", "nokeys", ns=node["router"]).stdout
    before_policy = ip("-o", "xfrm", "policy", "list", "nosock", ns=node["router"]).stdout
    try:
        try:
            reset_saved_peer_kernel(node, states, policies)
        except Stop:
            assert (
                ip("-o", "xfrm", "state", "list", "nokeys", ns=node["router"]).stdout
                == before_state
            )
            assert (
                ip("-o", "xfrm", "policy", "list", "nosock", ns=node["router"]).stdout
                == before_policy
            )
        else:
            raise AssertionError("Unknown peer kernel object was accepted during crash recovery.")
    finally:
        ip("xfrm", "policy", "delete", *unknown, ns=node["router"])
    reset_saved_peer_kernel(node, states, policies)
    guard = capture_fail_closed(model, 202)
    socket_path = PEER_ROOT / node["router"] / "charon.vici"
    if socket_path.is_socket():
        socket_path.unlink()
    start_peer(node, link, read_keys(load_profile(PROFILE)), model.event_id)
    assert peer_pid(node) != old
    stable(model, lambda snapshot: not snapshot.get(link.name), seconds=190)
    report = cli("initiate", "--site", link.site_id, "--confirm")
    verify_sas(model, phase="peer daemon crash and restart")
    emit(
        "S06",
        "Abruptly killed the peer daemon, restarted its stack and restored both LAN directions.",
        {
            "peer": node["router"],
            "old_pid": old,
            "new_pid": peer_pid(node),
            "saved_kernel_snapshot_sha256": saved_hash,
            "known_kernel_objects_reset": {"states": len(states), "policies": len(policies)},
            "unknown_recovery_object": "STOP with kernel inventory unchanged",
            "guard": guard,
            "journal": report["journal"],
            "flows": pair("udp", 168),
        },
    )


def verify_timed_rekey():
    profile = load_profile(PROFILE)
    # Allow the daemon's old-SA retention and all three real kernel/VICI reads
    # to finish between generations, including on a software-emulated guest.
    profile["security"].update(child_lifetime_seconds=90, ike_lifetime_seconds=120)
    timed_path = PROFILE.with_name("pr3-timed.yaml")
    write_profile(profile, timed_path)
    saved = cli("backup", "--confirm")["backup_id"]
    cli("apply", "-c", str(timed_path), "--maintenance", "--confirm")
    model = build_manifest(profile)
    link = model.links[0]
    pid = HOST.assert_daemon({item.name for item in model.links})
    old = inventory(HOST, model, pid).get(link.name)
    start = time.monotonic()
    before_flows = pair("udp", 172)

    def both_advanced(observed):
        row = observed.get(link.name)
        return (
            row
            and row.child
            and row.unique_id != old.unique_id
            and (row.child.unique_id != old.child.unique_id)
        )

    after = stable(model, both_advanced, seconds=150).get(link.name)
    verify_sas(model, phase="automatic IKE and CHILD timers")
    emit(
        "S01 S02",
        "Configured timers independently replace IKE and CHILD without operator rekey.",
        {
            "old_ike_child": [old.unique_id, old.child.unique_id],
            "new_ike_child": [after.unique_id, after.child.unique_id],
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "configured_seconds": {
                "ike_rekey": link.ike_lifetime,
                "child_lifetime": link.child_lifetime,
            },
            "before_flows": before_flows,
            "after_flows": pair("udp", 174),
        },
        action="observe real VICI and XFRM while daemon timers elapse",
    )
    cli("rollback", "--to", saved, "--maintenance", "--confirm")


def before_reboot():
    displaced = LAB_MARKER.with_suffix(".fixture")
    LAB_MARKER.rename(displaced)
    try:
        refusal = cli("install", "--confirm", expect=1)
        assert refusal["decision"] == "STOP" and "authorization marker" in refusal["detail"]
        assert read_record(INSTALLED) is None
    finally:
        displaced.rename(LAB_MARKER)
    assert cli("install", "--confirm")["status"] == "PASS"
    environment()
    emit(
        "C05",
        "Missing root-only lab authorization prevents install.",
        refusal["detail"],
        action="install --confirm in the disposable guest without marker",
    )
    create_profile()
    install_topology_unit()
    model = manifest()
    prove_topology()
    BASELINE.write_text(json.dumps(baseline_for(model)), encoding="utf-8")
    assert cli("apply", "-c", str(PROFILE), "--confirm")["status"] == "PASS"
    command("systemctl", "start", "ipsecvpn-restore.service")
    connect(model)
    verify_sas(model)
    verify_routes(model)
    verify_traffic(model, first=True)
    verify_noop(model)
    verify_rekeys(model)
    verify_bad_negotiation(model)
    verify_foreign_ike(model)
    verify_foreign_policy(model)
    verify_maintenance(model)
    verify_mtu(model)
    verify_isolation_failures(model)
    verify_plaintext_injection(model)
    verify_child_outage(model)
    verify_blocked_ike(model)
    verify_dpd(model)
    verify_peer_restart(model)
    verify_timed_rekey()
    verify_daemon_restart(model)
    assert baseline_for(model) == json.loads(BASELINE.read_text(encoding="utf-8"))


def after_reboot():
    environment()
    model = manifest()
    units = ("ipsecvpn-guard.service", "ipsecvpn-restore.service", UNIT)
    deadline = time.monotonic() + 90
    while True:
        states = {unit: HOST.service(unit, "ActiveState") for unit in units}
        if all(state == "active" for state in states.values()):
            break
        assert "failed" not in states.values() and time.monotonic() < deadline, states
        time.sleep(1)
    command("systemctl", "is-active", "ipsecvpn-guard.service", "ipsecvpn-restore.service")
    result = cli("status")
    assert result["status"] == "PASS", result
    receipts = verify_traffic(model, first=False)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert baseline_for(model) == baseline
    emit(
        "T13",
        "VM reboot restores guard, routes, owned SAs and real bidirectional LAN traffic.",
        {"baseline": baseline, "flows": receipts},
        action="actual VM reboot; verify new SSH session, restored services and UDP/TCP",
    )
    removed = cli("uninstall", "--maintenance", "--confirm")
    assert not HOST.command("Empty SAD", "ip", "xfrm", "state", "list", "nokeys").strip()
    assert not HOST.command("Empty SPD", "ip", "xfrm", "policy", "list", "nosock").strip()
    assert Resources(HOST, "uninstalled", ()).baseline() == baseline
    emit(
        "S09",
        "Live maintenance uninstall drains only owned SAs and restores the foreign baseline.",
        {"journal": removed["backup_id"], "empty_sad_spd": True, "baseline": baseline},
    )
    cases = recorded_cases()
    if any(item["status"] == "FAIL" for item in cases) or LAB_CASES - {
        item["case"] for item in cases if item["status"] == "PASS"
    }:
        raise RuntimeError("The complete three-node acceptance matrix did not pass.")


if __name__ == "__main__":
    require_lab()
    if sys.argv[1] == "summarize":
        summarize()
        sys.exit(0)
    if sys.argv[1] == "crash":
        Deployment(RouteFault("kill")).dispatch("apply", True, UPDATE, maintenance=True)
        sys.exit(2)
    try:
        {"before-reboot": before_reboot, "after-reboot": after_reboot}[sys.argv[1]]()
    except (RuntimeError, OSError, AssertionError, ValueError, KeyError) as exc:
        emit(
            "LAB",
            "Executed three-node assertions pass.",
            {"failure": str(exc), **failure_context()},
            status="FAIL",
        )
        raise
