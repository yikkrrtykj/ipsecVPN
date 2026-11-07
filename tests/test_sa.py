import json
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from ipsecvpn import cli, diagnostics, live
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest, nft_config
from ipsecvpn.sa import (
    Policy,
    SAError,
    State,
    correlate,
    kernel_policies,
    kernel_states,
    parse_vici,
)


@pytest.fixture
def observed():
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = manifest.links[0]
    child = {
        "name": link.child.encode(),
        "uniqueid": b"11",
        "reqid": b"7",
        "state": b"INSTALLED",
        "protocol": b"ESP",
        "mode": b"TUNNEL",
        "spi-in": b"11223344",
        "spi-out": b"55667788",
        "if-id-in": f"{link.if_id:08x}".encode(),
        "if-id-out": f"{link.if_id:08x}".encode(),
        "local-ts": [net.encode() for net in link.local_ts],
        "remote-ts": [net.encode() for net in link.remote_ts],
        "encr-alg": b"AES_CBC",
        "encr-keysize": b"256",
        "integ-alg": b"HMAC_SHA2_256_128",
        **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), b"0"),
    }
    event = {
        link.name: {
            "version": b"2",
            "uniqueid": b"1",
            "state": b"ESTABLISHED",
            "local-host": link.source.encode(),
            "remote-host": link.peer.encode(),
            "local-id": link.local_id.encode(),
            "remote-id": link.remote_id.encode(),
            "initiator-spi": b"1122334455667788",
            "responder-spi": b"8877665544332211",
            "encr-alg": b"AES_CBC",
            "encr-keysize": b"256",
            "integ-alg": b"HMAC_SHA2_256_128",
            "prf-alg": b"PRF_HMAC_SHA2_256",
            "dh-group": b"MODP_2048",
            "child-sas": {link.child: child},
        }
    }
    states = [
        State(link.peer, link.source, 0x11223344, 7, link.if_id),
        State(link.source, link.peer, 0x55667788, 7, link.if_id),
    ]
    policies = [
        (Policy(source, target, direction, state.source, state.destination, 7, link.if_id), None)
        for local in link.local_ts
        for remote in link.remote_ts
        for source, target, direction, state in (
            (local, remote, "out", states[1]),
            (remote, local, "in", states[0]),
            (remote, local, "fwd", states[0]),
        )
    ]
    return manifest, link, event, child, states, policies


def test_vici_and_kernel_must_agree(observed):
    manifest, _, event, _, states, policies = observed
    snapshot = parse_vici([event], manifest)
    correlate(snapshot, manifest, states, policies)
    with pytest.raises(SAError, match="state does not map"):
        correlate(snapshot, manifest, [*states, replace(states[0], spi=8)], policies)
    with pytest.raises(SAError, match="policy does not map"):
        correlate(snapshot, manifest, states, policies[:-1])
    with pytest.raises(SAError, match="outside the active manifest"):
        parse_vici([{"foreign": next(iter(event.values()))}], manifest)


@pytest.mark.parametrize("field", ("spi", "reqid", "if_id"))
def test_known_connection_cannot_cover_mismatched_kernel_identifiers(observed, field):
    manifest, _, event, _, states, policies = observed
    changed = replace(states[0], **{field: getattr(states[0], field) + 1})
    with pytest.raises(SAError, match="state does not map"):
        correlate(parse_vici([event], manifest), manifest, [changed, states[1]], policies)


@pytest.mark.parametrize("actually_drained", (True, False))
def test_vici_timeout_needs_proof_of_exact_drain(observed, monkeypatch, actually_drained):
    manifest, _, event, _, _, _ = observed
    original = parse_vici([event], manifest)
    after = parse_vici([], manifest) if actually_drained else original
    observations = iter((original, after))
    monkeypatch.setattr(live, "inventory", lambda *_args, **_kwargs: next(observations))
    requests = []

    class Control:
        def request(self, action, data):
            requests.append((action, data["ike-id"]))
            raise SAError("VICI_REJECTED", "Timed out but may have deleted the SA.")

    @contextmanager
    def control(_pid):
        yield Control()

    monkeypatch.setattr(live, "session", control)
    if actually_drained:
        live.drain_links(None, manifest, 17, original)
    else:
        with pytest.raises(SAError, match="did not drain"):
            live.drain_links(None, manifest, 17, original)
    assert requests == [("terminate", str(original.ikes[0].unique_id))]


def test_maintenance_handshake_guard_does_not_allow_data(observed):
    manifest, _, _, _, _, _ = observed
    guard = nft_config(
        None, "test", manifest.networks, [link.name for link in manifest.links], handshake=manifest
    )
    forward, remainder = guard.split("chain output")
    output, inbound = remainder.split("chain input")
    assert "accept" not in forward.split("policy accept;")[1]
    assert "accept" not in output.split("policy accept;")[1]
    assert "udp dport { 500, 4500 } accept" in inbound
    assert all(
        f"ip daddr {net} drop" in forward and f"ip daddr {net} drop" in output
        for net in manifest.networks
    )


def test_matching_name_cannot_authorize_narrowed_child(observed):
    manifest, _, event, child, _, _ = observed
    child["remote-ts"] = [b"10.99.99.0/24"]
    with pytest.raises(SAError, match="CHILD selector"):
        parse_vici([event], manifest)


@pytest.mark.parametrize("command", ("status", "doctor"))
def test_read_only_diagnostics_keep_business_unverified(observed, monkeypatch, capsys, command):
    manifest, _, event, _, _, _ = observed
    snapshot = parse_vici([event], manifest)
    reads = []

    class ReadOnlyHost:
        def probe(self):
            reads.append("host probe")

    def read(path):
        reads.append(path.name)
        return None if path == diagnostics.JOURNAL else {"fixture": True}

    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Linux")
    monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(diagnostics, "Host", ReadOnlyHost)
    monkeypatch.setattr(diagnostics, "read_record", read)
    monkeypatch.setattr(diagnostics, "installed_record", lambda: {"fixture": True})
    monkeypatch.setattr(diagnostics, "owned_resources", lambda *_: (manifest, snapshot, 17))
    assert cli.main([command, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "SKIP" and report["data_path"]["status"] == "SKIP"
    assert [site["child_state"] for site in report["sites"]] == ["INSTALLED", "DOWN"]
    assert len(reads) == 4 and "host probe" in reads
    assert all(site["data_path"]["status"] == "SKIP" for site in report["sites"])


def test_unconfirmed_rekey_overlap_is_not_a_write_snapshot(observed):
    manifest, _, event, _, _, _ = observed
    with pytest.raises(SAError, match="Multiple IKE generations"):
        parse_vici([event, event], manifest)


def test_nokeys_oneline_iproute2_inventory(observed):
    _, _, _, _, states, policies = observed
    assert (
        kernel_states(
            "\n".join(
                f"src {row.source} dst {row.destination} \\ proto esp spi {row.spi:#x} reqid 7"
                f" mode tunnel \\ replay-window 32 \\ if_id {row.if_id:#x} \\"
                for row in states
            )
        )
        == states
    )
    assert (
        kernel_policies(
            "\n".join(
                f"src {row.source} dst {row.destination} \\ dir {row.direction} priority 380160"
                f" ptype main \\ tmpl src {row.outer_source} dst {row.outer_destination}"
                f" \\ proto esp reqid 7 mode tunnel \\ if_id {row.if_id:#x} \\"
                for row, _ in policies
            )
        )
        == policies
    )
