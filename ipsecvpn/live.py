"""Verified protocol operations, separate from disk and network transactions."""

import time
from contextlib import closing

from vici.exception import CommandException

from .renderer import build_manifest, connection_settings
from .resources import Resources
from .sa import SAError, identity, inventory, session
from .secureio import Stop


def assert_baseline(active, baseline):
    if active and active.get("host_baseline", baseline) != baseline:
        raise Stop("The recorded SSH, routing or foreign firewall baseline has changed.")


def owned_resources(host, install, active):
    manifest = build_manifest(active["profile"]) if active else None
    resources = Resources(host, install["token"], (manifest,))
    pid = host.assert_daemon({link.name for link in manifest.links} if manifest else set())
    baseline = resources.preflight(manifest)
    assert_baseline(active, baseline)
    observed = inventory(host, manifest, pid)
    resources.verify(
        manifest, baseline, active.get("nft_sha256") if active else None, live=observed
    )
    return manifest, observed, pid


def initiate_link(host, manifest, pid, link):
    diagnostic = "IKE_NEGOTIATION_UNVERIFIED"
    with session(pid) as client:
        verify_initiate_config(client, manifest)
        try:
            for event in client.initiate(
                {"ike": link.name, "child": link.child, "timeout": "6000", "loglevel": "1"}
            ):
                msg = event.get("msg", b"").lower()
                if b"ts_unacceptable" in msg or b"traffic selectors unacceptable" in msg:
                    diagnostic = "CHILD_SELECTORS"
                elif b"authentication_failed" in msg or b"no shared key" in msg:
                    diagnostic = "IKE_AUTHENTICATION"
                elif b"no_proposal_chosen" in msg or b"no proposal found" in msg:
                    diagnostic = "PROPOSAL_REJECTED"
                elif diagnostic == "IKE_NEGOTIATION_UNVERIFIED" and b"retransmit" in msg:
                    diagnostic = "PEER_UNREACHABLE"
        except CommandException:
            raise SAError(
                diagnostic, "The targeted IKE/CHILD negotiation did not complete."
            ) from None
    observed = inventory(host, manifest, pid).get(link.name)
    if not observed or not observed.child:
        raise SAError("CHILD_NOT_ESTABLISHED", "The target did not install a verified CHILD SA.")
    return observed


def verify_initiate_config(client, manifest):
    links = {item.name: item for item in manifest.links}
    seen = set()
    for event in client.list_conns():
        for name, row in event.items():
            if name in seen or name not in links:
                raise Stop("The daemon has an unowned loaded connection.")
            seen.add(name)
            link = links[name]
            auth = {key for key in row if key.startswith(("local-", "remote-"))}
            if auth != {"local-1", "remote-1"} or row.get("version") != b"IKEv2":
                raise Stop("The loaded authentication profile is not the expected IKEv2 PSK.")
            for direction, expected in (("local", link.local_id), ("remote", link.remote_id)):
                section = row[f"{direction}-1"]
                if section.get("class") != b"pre-shared key" or identity(
                    section.get("id", b"").decode("ascii")
                ) != identity(expected):
                    raise Stop("A loaded IKE identity differs from the active manifest.")
    keys = set(client.get_shared().get("keys", ()))
    if (
        seen != set(links)
        or keys != {f"ike-{name}".encode() for name in links}
        or client.get_keys().get("keys")
    ):
        raise Stop("The loaded credential or connection inventory is not project-exclusive.")


def rekey_ids(event, kind, link):
    item = event.get(link.name, {})
    if kind == "child":
        children = item.get("child-sas", {})
        item = next(iter(children.values()), {}) if len(children) == 1 else {}
    try:
        return int(item["old"]["uniqueid"]), int(item["new"]["uniqueid"])
    except (KeyError, ValueError, TypeError):
        return None


def rekey_link(host, manifest, pid, link, old, kind):
    previous = old.child.unique_id if kind == "child" else old.unique_id
    with (
        session(pid) as watcher,
        closing(watcher.listen([f"{kind}-rekey"], timeout=0.15)) as events,
    ):
        next(events)  # The first iteration registers before the command on the second socket.
        with session(pid) as client:
            reply = client.request("rekey", {f"{kind}-id": str(previous)})
            if reply.get("matches") != b"1":
                raise SAError("SA_TRANSITION", "The verified rekey target changed before dispatch.")
        deadline = time.monotonic() + 7
        for _, event in events:
            relation = rekey_ids(event, kind, link) if event else None
            if relation and relation[0] == previous and relation[1] != previous:
                break
            if time.monotonic() >= deadline:
                raise SAError(
                    "SA_TRANSITION", "The daemon did not confirm the old/new SA relation."
                )
    current = inventory(host, manifest, pid, attempts=10, delay=0.7).get(link.name)
    if not current or not current.child:
        raise SAError("SA_TRANSITION", "No stable CHILD was observed after rekey.")
    observed = current.child.unique_id if kind == "child" else current.unique_id
    if observed != relation[1]:
        raise SAError("SA_TRANSITION", "The new SA did not match the daemon's rekey event.")
    return current


def drain_links(host, manifest, pid, live):
    current = inventory(host, manifest, pid)
    if current != live:
        raise SAError("SA_TRANSITION", "The active SAs changed after the maintenance snapshot.")
    remaining = list(current.ikes)
    for ike in current.ikes:
        try:
            with session(pid) as client:
                reply = client.request(
                    "terminate",
                    {
                        "ike-id": str(ike.unique_id),
                        "force": "yes",
                        "timeout": "2500",
                        "loglevel": "0",
                    },
                )
                if reply.get("matches") != b"1":
                    raise SAError("SA_TRANSITION", "The verified termination target changed.")
        except SAError as exc:
            if exc.reason != "VICI_REJECTED":
                raise
            # 5.9.13 can force local deletion on timeout and still return failure.
            # Verify the exact resulting inventory before issuing the next command.
        remaining.remove(ike)
        observed = inventory(host, manifest, pid, attempts=8, delay=0.55)
        if observed.ikes != tuple(remaining):
            raise SAError("SA_TRANSITION", "The precise set of owned SAs did not drain.")


def configure_scoped(host, pid, candidates, target, keys):
    known = {link.name for model in candidates if model for link in model.links}
    desired = {link.name: link for link in target.links} if target else {}
    host.assert_exclusive_ike(known)
    with session(pid) as client:
        conns = {name.decode("ascii") for name in client.get_conns().get("conns", ())}
        shared = {name.decode("ascii") for name in client.get_shared().get("keys", ())}
        if not conns.issubset(known) or not shared.issubset({f"ike-{name}" for name in known}):
            raise Stop("A non-project connection or shared credential is loaded.")
        if client.get_keys().get("keys"):
            raise Stop("The daemon has an unowned private credential.")
        for name in sorted(conns - desired.keys()):
            client.request("unload-conn", {"name": name})
        for key in sorted(shared - {f"ike-{name}" for name in desired}):
            client.request("unload-shared", {"id": key})
        for name, link in desired.items():
            client.request(
                "load-shared",
                {
                    "id": f"ike-{name}",
                    "type": "IKE",
                    "data": keys[link.site_id],
                    "owners": [link.local_id, link.remote_id],
                },
            )
            client.request("load-conn", {name: connection_settings(link)})
