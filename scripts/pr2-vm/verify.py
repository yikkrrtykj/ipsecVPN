"""Acceptance assertions executed by root inside the disposable Ubuntu guest."""

import copy
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from ipaddress import collapse_addresses, ip_network
from pathlib import Path

import yaml

from ipsecvpn.host import UNIT, VICI_PATH, Host, fingerprint, separate_nft
from ipsecvpn.installer import GUARD, RESTORE, STATE
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest
from ipsecvpn.resources import Resources
from ipsecvpn.secureio import Stop, read_record
from ipsecvpn.transaction import ACTIVE, BACKUPS, INSTALLED, JOURNAL, Deployment, boot, locked

HERE = Path(__file__).parent
PROFILE = Path("/etc/ipsecvpn/profiles/lab.yaml")
UPDATE = PROFILE.with_name("update.yaml")
SUMMARY = Path("/var/tmp/ipsecvpn-acceptance.jsonl")
BASELINE = Path("/var/tmp/ipsecvpn-lab-baseline.json")
CLI = Path(sys.executable).with_name("ipsecvpn")
HOST = Host()
ENV = {}
KEYS = []
UNAUTHORIZED_LAN = "10.77.90.0/24"
FOREIGN_SERVICES = ("nftables.service", "systemd-networkd.service", "systemd-journald.service")
CASE_COMMANDS = {
    "V01": "systemd-detect-virt --vm; modprobe -nq xfrm_interface; ip xfrm policy list",
    "V02": "ipsecvpn install --dry-run --json",
    "V03": "ipsecvpn install --confirm --json; dpkg-query -W; swanctl --list-conns",
    "V04": "ipsecvpn apply -c <profile> --confirm --json; swanctl --list-conns; swanctl --list-sas",
    "V05": "ip -j -d link show",
    "V06": "ip -4 route get <protected-address>",
    "V07": "nft list table ip ipsecvpn",
    "V08": "ipsecvpn apply -c <profile> --dry-run --json",
    "V09": "ipsecvpn apply -c <profile> --confirm --json",
    "V10": "ipsecvpn apply -c <profile> --confirm --json",
    "V11": "ipsecvpn backup --confirm --json; ipsecvpn apply -c <update> --confirm --json",
    "V12": "ipsecvpn rollback --to <id> --confirm --json",
    "V13": "apply with injected nft, ip or swanctl failure; verify RESTORED journal",
    "V14": "apply, SIGKILL after route mutation, ipsecvpn rollback --to <id> --confirm --json",
    "V15": "ipsecvpn apply -c <profile> --confirm --json while holding the deployment lock",
    "V16": "ipsecvpn uninstall --confirm --json; dpkg-query -W; ss -H -ulnp",
    "V17": "systemctl reboot --no-block; cat /proc/sys/kernel/random/boot_id; systemctl is-active",
    "V18": "ipsecvpn rollback --to <corrupt-or-missing-id> --confirm --json",
    "V19": "journalctl --no-pager -u strongswan.service -o cat; scan project state and JSONL",
    "V20": "ip -j -N -4 route show table all; ip -j -N -4 rule show; nft -j list ruleset",
    "F01": "ipsecvpn install --confirm --json with isolated UDP/500 listener",
    "F02": "ip link add <conflict>; ipsecvpn apply -c <profile> --confirm --json",
    "F03": "ip route add blackhole <conflict>; ipsecvpn apply -c <profile> --confirm --json",
    "F04": "ipsecvpn apply -c <wrong-wan-profile> --confirm --json",
    "F05": "nft -f -; ipsecvpn apply -c <profile> --confirm --json",
    "F06": "ipsecvpn render -c <invalid-profile>",
    "F07": "ipsecvpn apply -c <profile> --confirm --json with invalid credential fixture",
    "F08": "ipsecvpn install --confirm --json with foreign swanctl fixture",
    "F09": "ipsecvpn install --confirm via unprivileged user or isolated mount namespace",
    "F10": "systemctl stop strongswan.service; ip link del <xfrm>; ip -4 route get <address>",
    "F11": "setpriv --bounding-set=-net_admin ip -4 route del <owned-route>",
    "F12": "ip route add blackhole <host-route> / ip rule add <policy>; apply preflight",
    "F13": "ipsecvpn render -c <invalid-profile>",
    "F14": "ipsecvpn apply -c <incomplete-backup-profile> --confirm --json",
    "L01": "ipsecvpn install; apply; uninstall; install; apply (each with --confirm)",
    "L02": "apt-get install; systemctl start <missing-unit>; ipsecvpn rollback --to <id>",
    "L03": "dpkg --unpack --no-triggers <deb>; dpkg --audit; ipsecvpn rollback --to <id>",
    "L04": "systemctl start strongswan.service; ipsecvpn install --confirm with foreign fixtures",
}
READ_ONLY_CASES = {"V01", "V02", "V08", "V19", "F04", "F06", "F09", "F13"}


def command(*args, allowed=(0,), data=None):
    proc = subprocess.run(
        args, input=data, text=True, capture_output=True, check=False, timeout=120
    )
    if proc.returncode not in allowed:
        message = proc.stderr.encode()
        safe = not any(key in message or key.hex().encode() in message for key in KEYS)
        detail = proc.stderr.strip()[:400] if safe else "redacted stderr"
        raise RuntimeError(f"{Path(args[0]).name} exit={proc.returncode}: {detail}")
    return proc


def cli(*args, ok=True):
    proc = command(str(CLI), *args, "--json", allowed=(0, 1))
    output = (proc.stdout + proc.stderr).encode()
    assert all(key not in output and key.hex().encode() not in output for key in KEYS)
    report = json.loads(proc.stdout)
    assert proc.returncode == (0 if ok else 1), report.get("detail")
    assert report["status"] == ("PASS" if ok else "FAIL"), report.get("detail")
    if not ok:
        assert report.get("decision") == "STOP", report.get("detail")
    return report


def emit(ids, verdict, expected, observed, audit_command=None):
    with SUMMARY.open("a", encoding="utf-8") as stream:
        for case in ids.split():
            row = {
                "case": case,
                "at": datetime.now(UTC).isoformat(),
                "result": verdict,
                "vm": "ipsecvpn-pr2-lab",
                "versions": ENV,
                "command": audit_command
                or CASE_COMMANDS.get(case, "python scripts/pr2-vm/verify.py <phase>"),
                "expected": expected,
                "observed": observed,
                "evidence": SUMMARY.name,
                "system_touched": case not in READ_ONLY_CASES,
                "driver": "scripts/pr2-vm/verify.py",
            }
            line = json.dumps(row, sort_keys=True)
            encoded = line.encode()
            assert all(key not in encoded and key.hex().encode() not in encoded for key in KEYS)
            stream.write(line + "\n")
            print(line, flush=True)


def profile_write(path, profile):
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    path.chmod(0o600)


def resources(*manifests):
    install = read_record(INSTALLED)
    return Resources(HOST, install["token"] if install else "lab-before-install", manifests)


def current_manifest():
    return build_manifest(read_record(ACTIVE)["profile"])


def foreign_services():
    return {
        unit: {key: HOST.service(unit, key) for key in ("ActiveState", "FragmentPath", "MainPID")}
        for unit in FOREIGN_SERVICES
    }


def verify_forward_acl(manifest):
    def normalized_cidrs(text):
        return tuple(collapse_addresses(ip_network(cidr) for cidr in text))

    nft_text = command("nft", "list", "table", "ip", "ipsecvpn").stdout
    assert "masquerade" not in nft_text and "snat" not in nft_text
    lines = [line.strip() for line in nft_text.splitlines()]
    directions = []
    for source, target in (manifest.links, tuple(reversed(manifest.links))):
        prefix = f'iifname "{source.name}" oifname "{target.name}" ip saddr '
        matches = [line for line in lines if line.startswith(prefix) and line.endswith(" accept")]
        assert len(matches) == 1
        actual_src, actual_dst = (
            matches[0].removeprefix(prefix).removesuffix(" accept").split(" ip daddr ", 1)
        )
        assert normalized_cidrs(
            actual_src.strip("{} ").replace(",", " ").split()
        ) == normalized_cidrs(source.remote_ts)
        assert normalized_cidrs(
            actual_dst.strip("{} ").replace(",", " ").split()
        ) == normalized_cidrs(target.remote_ts)
        assert lines.index(matches[0]) < lines.index(f'iifname "{source.name}" drop')
        assert lines.index(matches[0]) < lines.index(f'oifname "{target.name}" drop')
        directions.append({"from": source.name, "to": target.name, "rule": matches[0]})
    assert UNAUTHORIZED_LAN not in nft_text
    assert not HOST.ip("-4", "route", "show", "exact", UNAUTHORIZED_LAN)
    emit(
        "V07",
        "PASS",
        "Exactly scoped bidirectional ACL with per-interface drops and no NAT or extra LAN route.",
        directions,
    )


def bootstrap_profiles():
    profile = load_profile(HERE / "example.yaml")
    routes = HOST.ip("-4", "route", "show", "default")
    assert routes, "Isolated VM baseline is missing its synthetic default route."
    default = routes[0]
    wan = default["dev"]
    addr = HOST.ip("-4", "addr", "show", "dev", wan)[0]["addr_info"][0]["local"]
    for link in profile["site_links"]:
        link["outer_path"].update(interface=wan, source_ip=addr, gateway=default["gateway"])
        path = Path(link["secret_ref"][5:])
        key = secrets.token_hex(32).encode("ascii")
        KEYS.append(key)
        path.write_bytes(key + b"\n")
        path.chmod(0o600)
    profile["traffic_policy"]["allowed_site_pairs"][0].update(
        a_cidrs=profile["sites"][0]["lan_cidrs"].copy(),
        b_cidrs=profile["sites"][1]["lan_cidrs"].copy(),
    )
    profile["sites"][0]["lan_cidrs"].append(UNAUTHORIZED_LAN)
    profile["backup"] = {"enabled": True, "type": "external_managed"}
    profile_write(PROFILE, profile)
    update = copy.deepcopy(profile)
    update["site_links"][1]["if_id"] += 100
    update["sites"][1]["lan_cidrs"] = ["10.77.12.0/24"]
    update["traffic_policy"]["allowed_site_pairs"][0]["b_cidrs"] = ["10.77.12.0/24"]
    update["sites"][1]["public_endpoint"] = "198.51.100.77"
    profile_write(UPDATE, update)
    return profile


class FaultHost(Host):
    def __init__(self, label, crash=False):
        super().__init__()
        self.label, self.crash, self.fired = label, crash, False

    def command(self, label, *args, **kwargs):
        if kwargs.get("mutate") and label == self.label and not self.fired:
            self.fired = True
            if self.crash:
                super().command(label, *args, **kwargs)
                os.kill(os.getpid(), signal.SIGKILL)
            if label == "IPv4 unicast route del":
                return super().command(
                    label, "setpriv", "--bounding-set=-net_admin", *args, mutate=True
                )
            return super().command(
                label, args[0], "--ipsecvpn-injected-invalid-option", mutate=True
            )
        return super().command(label, *args, **kwargs)


def check_failure(label, manifest, baseline):
    faulty = FaultHost(label)
    try:
        Deployment(faulty).dispatch("apply", True, UPDATE)
    except Stop:
        assert faulty.fired
    else:
        raise AssertionError("Injected failure did not stop the transaction.")
    assert read_record(JOURNAL)["phase"] == "RESTORED"
    resources(manifest).verify(manifest, baseline, read_record(ACTIVE)["nft_sha256"])


class InstallFaultHost(Host):
    def __init__(self, partial):
        super().__init__()
        self.partial = partial

    def command(self, label, *args, **kwargs):
        if self.partial and label == "APT install":
            (deb,) = (HERE / "apt").glob("libstrongswan_*.deb")
            self.step(label, "STARTED")
            super().command(
                "Partial dpkg unpack", "dpkg", "--unpack", "--no-triggers", str(deb), mutate=True
            )
            raise Stop("Injected APT failure after dpkg unpacked the first package.")
        if not self.partial and label == "Start owned daemon":
            return super().command(
                label, "systemctl", "start", "ipsecvpn-missing-test.service", mutate=True
            )
        return super().command(label, *args, **kwargs)


def check_install_failure(partial, baseline, services):
    case = "L03" if partial else "L02"
    before = HOST.package_state()
    try:
        Deployment(InstallFaultHost(partial)).dispatch("install", True)
    except Stop as exc:
        assert "STOP_FOR_MANUAL" in str(exc), str(exc)
    else:
        raise AssertionError("The injected install failure did not stop the transaction.")
    journal = read_record(JOURNAL)
    identifier = journal["id"]
    evidence = journal["install_failure_packages"]
    assert journal["action"] == "install" and journal["phase"] == "STOP_FOR_MANUAL"
    assert journal.get("protected_baseline_unchanged"), journal.get("recovery_failure")
    assert read_record(INSTALLED) is None
    after = HOST.package_state()
    assert before == journal["install"]["before_package_state"]
    delta = evidence["delta"]
    assert delta and set(delta) == {
        name for name in before.keys() | after.keys() if before.get(name) != after.get(name)
    }
    assert evidence["audit_clean"] is not partial and after != before
    assert all(
        row["before"] == before.get(name) and row["after"] == after.get(name)
        for name, row in delta.items()
    )
    added = sorted(after.keys() - before.keys())
    steps = [[step["label"], step["result"]] for step in journal["steps"]]
    if partial:
        assert ["Partial dpkg unpack", "DONE"] in steps and ["APT install", "DONE"] not in steps
        assert added == ["libstrongswan"]
        assert after["libstrongswan"]["status"] == "iU "
        for name in delta.keys() - set(added):
            assert after[name]["status"] in {"it ", "iW "}
            assert after[name]["version"] == before[name]["version"]
    else:
        assert ["APT install", "DONE"] in steps
        assert ["Start owned daemon", "STARTED"] in steps
        assert ["Start owned daemon", "DONE"] not in steps
        assert set(delta) == set(added) == set(journal["install"]["packages"])
        assert all(after[name]["status"] == "ii " for name in delta)
    assert not HOST.ike_ports() and not VICI_PATH.exists()
    assert resources().baseline() == baseline
    assert foreign_services() == services
    assert "Unfinished" in cli("install", "--confirm", ok=False)["detail"]
    blocked = cli("rollback", "--to", identifier, "--confirm", ok=False)
    assert "STOP_FOR_MANUAL" in blocked["detail"] and HOST.package_state() == after

    # This is the operator's explicit lab repair, outside the deployment transaction.
    if partial:
        HOST.command("Lab purge of unpacked package", "dpkg", "--purge", *added)
        if HOST.package_state() != before:
            HOST.command("Lab process pending triggers", "dpkg", "--triggers-only", "--pending")
    else:
        preview = HOST.command("Lab purge preview", "apt-get", "-s", "purge", *added)
        removals = {
            line.split()[1] for line in preview.splitlines() if line.startswith(("Remv ", "Purg "))
        }
        assert removals == set(added) and not any(
            line.startswith("Inst ") for line in preview.splitlines()
        )
        HOST.command("Lab purge of explicitly added packages", "apt-get", "-y", "purge", *added)
    assert HOST.package_state() == before
    cli("rollback", "--to", identifier, "--confirm")
    restored = read_record(JOURNAL)
    assert restored["phase"] == "RESTORED" and restored["package_recovery"]["delta"] == {}
    assert restored["install_failure_packages"] == evidence
    assert resources().baseline() == baseline and foreign_services() == services
    emit(
        case,
        "PASS",
        "Package drift stops recovery; only exact manual repair permits RESTORED.",
        {
            "journal": identifier,
            "phases": [journal["phase"], restored["phase"]],
            "failure": journal["failure"],
            "package_drift": evidence,
            "after_manual_rollback": restored["package_recovery"],
            "protected_baseline": baseline,
            "foreign_service_pids_equal": True,
        },
    )


def negative_cases(profile, manifest, baseline):
    expected = "apply --confirm exits FAIL/STOP without changing project or foreign resources"

    def stopped(case, label, path=PROFILE, match=None):
        result = cli("apply", "-c", str(path), "--confirm", ok=False)
        if match:
            assert match in result["detail"], result["detail"]
        emit(case, "PASS", expected, label)

    link = manifest.links[0]
    command("ip", "link", "add", "name", "labcollision", "type", "xfrm", "if_id", str(link.if_id))
    try:
        stopped("F02", "Existing XFRM ID detected.", match="XFRM")
        assert HOST.ip("link", "show", "dev", "labcollision")
    finally:
        command("ip", "link", "del", "dev", "labcollision")
    command("ip", "link", "add", "name", link.name, "type", "dummy")
    try:
        stopped("F02", "Reserved interface name detected.", match="XFRM")
        assert HOST.ip("link", "show", "dev", link.name)
    finally:
        command("ip", "link", "del", "dev", link.name)
    network = link.remote_ts[0]
    host_route = network.split("/")[0] + "/32"
    for cidr, case in ((network, "F03"), (host_route, "F12")):
        command("ip", "route", "add", "blackhole", cidr, "proto", "static")
        try:
            stopped(case, "Conflicting route retained.", match="overlaps")
        finally:
            command("ip", "route", "del", "blackhole", cidr, "proto", "static")
    command("ip", "rule", "add", "priority", "100", "lookup", "main")
    try:
        stopped("F12", "Unmanaged policy rule rejected.", match="policy routing")
    finally:
        command("ip", "rule", "del", "priority", "100", "lookup", "main")

    draft = PROFILE.with_name("negative.yaml")
    wrong = copy.deepcopy(profile)
    wrong["site_links"][0]["outer_path"]["gateway"] = "192.0.2.253"
    profile_write(draft, wrong)
    stopped("F04", "Peer lookup rejected mismatched gateway.", draft, "WAN path")

    command(
        "nft",
        "-f",
        "-",
        data=(
            "table ip lab_block {\n"
            "    chain forward {\n"
            "        type filter hook forward priority 0; policy drop;\n"
            "    }\n"
            "}\n"
        ),
    )
    try:
        stopped("F05", "Foreign forward DROP was preserved.", match="foreign firewall")
        command("nft", "list", "table", "ip", "lab_block")
    finally:
        command("nft", "delete", "table", "ip", "lab_block")

    secret = Path(profile["site_links"][0]["secret_ref"][5:])
    real = secret.with_suffix(".saved")
    secret.rename(real)
    try:
        stopped("F07", "Missing IKE key rejected.", match="IKE key")
        secret.symlink_to(real)
        stopped("F07", "Symlink rejected.", match="IKE key")
        secret.unlink()
        os.link(real, secret)
        stopped("F07", "Hardlink rejected.", match="protected file")
        secret.unlink()
    finally:
        secret.unlink(missing_ok=True)
        real.rename(secret)
    secret.chmod(0o644)
    try:
        stopped("F07", "Insecure key mode rejected.", match="protected file")
    finally:
        secret.chmod(0o600)
    os.chown(secret, 65534, 65534)
    try:
        stopped("F07", "Non-root key owner rejected.", match="protected file")
    finally:
        os.chown(secret, 0, 0)

    nonroot = command(
        "runuser", "-u", "nobody", "--", str(CLI), "install", "--confirm", allowed=(1,)
    )
    assert "FAIL/STOP" in nonroot.stderr
    emit("F09", "PASS", "Non-root host write exits STOP.", "Exit 1 before work.")
    wrong_release = HERE / "foreign-os-release"
    wrong_release.write_text("ID=ubuntu\nVERSION_ID=22.04\n", encoding="ascii")
    for source, target, expected_error in (
        (wrong_release, Path("/etc/os-release").resolve(), "Only Ubuntu 24.04"),
        (Path("/usr/bin/false"), Path("/usr/sbin/modprobe").resolve(), "XFRM interface support"),
    ):
        rejected = command(
            "unshare",
            "--mount",
            "--propagation",
            "private",
            "sh",
            "-ec",
            'mount --bind "$1" "$2"; exec "$3" install --confirm',
            "isolated-probe",
            str(source),
            str(target),
            str(CLI),
            allowed=(1,),
        )
        assert "FAIL/STOP" in rejected.stderr and expected_error in rejected.stderr
        emit("F09", "PASS", "Reject version or kernel feature mismatch.", expected_error)
    malformed = copy.deepcopy(profile)
    malformed["default_route"] = "192.0.2.1"
    profile_write(draft, malformed)
    assert "Schema violation" in command(str(CLI), "render", "-c", str(draft), allowed=(1,)).stdout
    malformed = copy.deepcopy(profile)
    malformed["site_links"][0]["outer_path"]["interface"] = "eth0;echo invalid"
    profile_write(draft, malformed)
    assert "Schema violation" in command(str(CLI), "render", "-c", str(draft), allowed=(1,)).stdout
    emit(
        "F06 F13",
        "PASS",
        "Reject foreign configuration fields and injected syntax.",
        "Schema rejected both before execution.",
    )
    malformed = copy.deepcopy(profile)
    malformed["site_links"][0]["secret_ref"] = "file:/etc/ipsecvpn/secrets/../lab-authorized"
    profile_write(draft, malformed)
    stopped("F07", "Key path traversal rejected by profile validation.", draft, "Schema violation")
    assert resources().baseline() == baseline


def before_reboot():
    ENV.update(
        HOST.probe(),
        nft=command("nft", "--version").stdout.strip(),
        iproute2=HOST.packages()["iproute2"],
        strongswan="not installed",
    )
    profile = bootstrap_profiles()
    manifest = build_manifest(profile)
    baseline = resources().baseline()
    services = foreign_services()
    assert all(row["ActiveState"] == "active" for row in services.values())
    BASELINE.write_text(json.dumps({"network": baseline, "services": services}), encoding="utf-8")
    emit(
        "V01",
        "PASS",
        "Ubuntu/kernel/VM and nft/XFRM probe succeeds.",
        "Read-only host probes succeeded.",
    )

    foreign = Path("/etc/swanctl")
    foreign.mkdir()
    marker = foreign / "foreign.conf"
    marker.write_text("# isolated fixture\n", encoding="ascii")
    try:
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert marker.read_text(encoding="ascii") == "# isolated fixture\n"
    finally:
        marker.unlink()
        foreign.rmdir()
    emit("F08", "PASS", "Existing swanctl config is preserved.", "STOP with file unchanged.")
    listener = subprocess.Popen(
        (
            sys.executable,
            "-c",
            "import socket,time;s=socket.socket(2,2);s.bind(('0.0.0.0',500));"
            "print('ready',flush=True);time.sleep(30)",
        ),
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert listener.stdout.readline().strip() == "ready"
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert listener.poll() is None
    finally:
        listener.terminate()
        listener.wait(timeout=10)
    emit(
        "F01",
        "PASS",
        "Occupied UDP/500 yields STOP with original owner alive.",
        "Unrelated listener remained.",
    )
    assert not STATE.exists(), "A refused install created persistent deployment state."

    packages = HOST.packages()
    state_before = sorted(path.name for path in STATE.iterdir()) if STATE.exists() else []
    cli("install", "--dry-run")
    assert HOST.packages() == packages and resources().baseline() == baseline
    assert (sorted(path.name for path in STATE.iterdir()) if STATE.exists() else []) == state_before
    emit(
        "V02",
        "PASS",
        "Dry-run preserves packages, files and networking.",
        "Package and state inventories matched.",
    )
    check_install_failure(partial=False, baseline=baseline, services=services)
    check_install_failure(partial=True, baseline=baseline, services=services)
    installed = cli("install", "--confirm")
    ENV["strongswan"] = HOST.packages()["charon-systemd"]
    assert installed["baseline_unchanged"] and HOST.vici_names() == set()
    emit(
        "V03",
        "PASS",
        "Install only planned packages and start owned VICI daemon.",
        installed["packages"],
    )

    negative_cases(profile, manifest, baseline)
    initial = cli("apply", "-c", str(PROFILE), "--dry-run")
    assert len(initial["diff"]["add"]) == 2 and read_record(ACTIVE) is None
    assert resources().baseline() == baseline
    emit("V08", "PASS", "Apply dry-run changes no live resource.", initial["diff"])
    applied = cli("apply", "-c", str(PROFILE), "--confirm")
    assert applied["backup"]["status"] == "SKIP" and applied["backup"]["readiness"] == "INCOMPLETE"
    assert read_record(JOURNAL)["phase"] == "COMMITTED"
    state = read_record(ACTIVE)
    nft = resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    assert not HOST.vici("--list-sas").strip()
    verify_forward_acl(manifest)
    emit(
        "V04 V05 V06 V09 F14",
        "PASS",
        "Two idle VICI connections and XFRM links, exact routes, dual ACL, committed state.",
        {
            "if_ids": [link.if_id for link in manifest.links],
            "nft_sha256": nft,
            "backup": "SKIP/INCOMPLETE",
        },
    )
    journal = (STATE / "journal.json").read_bytes()
    assert "NOOP" in cli("apply", "-c", str(PROFILE), "--confirm")["detail"]
    assert (STATE / "journal.json").read_bytes() == journal and read_record(ACTIVE) == state
    emit(
        "V10",
        "PASS",
        "Identical apply returns NOOP, journal and active hashes unchanged.",
        "Verified.",
    )
    saved = cli("backup", "--confirm")["backup_id"]
    assert cli("apply", "-c", str(UPDATE), "--confirm")["diff"]["add"]
    updated = current_manifest()
    resources(updated).verify(updated, baseline, read_record(ACTIVE)["nft_sha256"])
    cli("rollback", "--to", saved, "--confirm")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V11 V12",
        "PASS",
        "Changed CIDR, Peer and if_id; verified exact rollback.",
        "Updated and original manifests each matched live state.",
    )

    for label in ("nft atomic update", "IPv4 unicast route del", "VICI load"):
        check_failure(label, manifest, baseline)
        emit(
            "V13 F11" if label == "IPv4 unicast route del" else "V13",
            "PASS",
            "Injected real command error, then verified pre-state.",
            label + " → RESTORED",
        )
    with locked():
        assert "LOCKED" in cli("apply", "-c", str(PROFILE), "--confirm", ok=False)["detail"]
    emit(
        "V15",
        "PASS",
        "Concurrent writer cannot acquire lock.",
        "LOCKED, original transaction unaffected.",
    )

    child = subprocess.run((sys.executable, __file__, "crash"), check=False)
    assert child.returncode == -signal.SIGKILL
    interrupted = read_record(JOURNAL)
    assert interrupted["phase"] == "APPLYING"
    assert "Unfinished" in cli("apply", "-c", str(PROFILE), "--confirm", ok=False)["detail"]
    cli("rollback", "--to", interrupted["id"], "--confirm")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V14",
        "PASS",
        "SIGKILL after a real route mutation, then explicit recovery.",
        "APPLYING → STOP → RESTORED.",
    )

    bad = BACKUPS / f"{saved}.json"
    original = bad.read_bytes()
    bad.write_bytes(b"{}")
    try:
        cli("rollback", "--to", saved, "--confirm", ok=False)
        cli("rollback", "--to", "0" * 32, "--confirm", ok=False)
    finally:
        bad.write_bytes(original)
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V18", "PASS", "Corrupt/missing backups block writes.", "Both blocked; pre-state verified."
    )

    command("systemctl", "stop", UNIT)
    for link in manifest.links:
        for cidr in link.remote_ts:
            protected = cidr.split("/")[0]
            assert HOST.ip("-4", "route", "get", protected)[0]["dev"] == link.name
        command("ip", "link", "del", "dev", link.name)
    for cidr in manifest.networks:
        lookup = command("ip", "-4", "route", "get", cidr.split("/")[0], allowed=(2,))
        assert "Invalid argument" in lookup.stderr or "Network is unreachable" in lookup.stderr
        assert "blackhole" in command("ip", "-4", "route", "show", "exact", cidr).stdout
    command("systemctl", "start", UNIT)
    boot("restore")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "F10",
        "PASS",
        "Stopped daemon and deleted XFRM; kernel lookup blocks protected CIDR.",
        "Actual blackhole selected, default WAN not returned.",
    )
    assert foreign_services() == services
    emit(
        "V20",
        "PASS",
        "Preserve baseline across install, apply, update, faults and rollback.",
        {**baseline, "foreign_service_units": sorted(services), "foreign_service_pids_equal": True},
    )
    check_secret_evidence(profile)
    (HERE / "nft-before-reboot.json").write_text(
        json.dumps(separate_nft(HOST.nft())[0]), encoding="utf-8"
    )


def check_secret_evidence(profile):
    paths = [SUMMARY, *STATE.rglob("*.json")]
    secret_values = [
        Path(link["secret_ref"][5:]).read_bytes().strip() for link in profile["site_links"]
    ]
    for path in paths:
        if path.is_file():
            content = path.read_bytes()
            assert all(
                value not in content and value.hex().encode() not in content
                for value in secret_values
            )
    assert not list(Path("/etc/swanctl").glob("ipsecvpn-*/swanctl.conf"))
    daemon = command("journalctl", "--no-pager", "-u", UNIT, "-o", "cat").stdout.encode()
    assert all(
        value not in daemon and value.hex().encode() not in daemon for value in secret_values
    )
    emit(
        "V19",
        "PASS",
        "Scan persisted journal, snapshots and emitted evidence for both test keys.",
        "No raw or hex-encoded IKE key matches.",
    )


def after_reboot():
    packages = HOST.packages()
    ENV.update(
        HOST.probe(),
        nft=command("nft", "--version").stdout.strip(),
        iproute2=packages["iproute2"],
        strongswan=packages["charon-systemd"],
    )
    saved = json.loads(BASELINE.read_text(encoding="utf-8"))
    baseline = saved["network"]
    # is-active with several units succeeds when any one is active. Wait for every
    # automatic oneshot to finish without manually starting or repairing a unit.
    deadline = time.monotonic() + 90
    while True:
        states = {unit: HOST.service(unit, "ActiveState") for unit in (GUARD, RESTORE, UNIT)}
        if all(state == "active" for state in states.values()):
            break
        assert "failed" not in states.values() and time.monotonic() < deadline, states
        time.sleep(1)
    command("systemctl", "is-active", GUARD, RESTORE, UNIT)
    manifest = current_manifest()
    try:
        resources(manifest).verify(manifest, baseline, read_record(ACTIVE)["nft_sha256"])
    except Stop:
        emit(
            "REBOOT_DIAGNOSTIC",
            "FAIL",
            "Project firewall after reboot matches the recorded configuration.",
            {
                "recorded_sha256": read_record(ACTIVE)["nft_sha256"],
                "before_objects": json.loads((HERE / "nft-before-reboot.json").read_text()),
                "after_objects": separate_nft(HOST.nft())[0],
                "boot_units": command(
                    "journalctl",
                    "--no-pager",
                    "-b",
                    "-u",
                    GUARD,
                    "-u",
                    RESTORE,
                    "-n",
                    "30",
                    "-o",
                    "cat",
                ).stdout,
            },
        )
        raise
    services = foreign_services()
    for unit, row in services.items():
        assert all(
            row[key] == saved["services"][unit][key] for key in ("ActiveState", "FragmentPath")
        )
    emit(
        "V17 V20",
        "PASS",
        "Independent reboot, new SSH session and automatic restore.",
        "Boot services active and protected baseline hashes identical.",
    )
    old_owner = read_record(INSTALLED)["token"]
    package_state = HOST.package_state()
    uninstalled = cli("uninstall", "--confirm")
    assert resources().baseline() == baseline
    assert foreign_services() == services
    assert read_record(ACTIVE) is None and HOST.packages()["charon-systemd"]
    assert not HOST.ike_ports()
    emit(
        "V16",
        "PASS",
        "Remove owned network and boot resources, keep shared packages and SSH.",
        "Exact protected baseline and package retention verified.",
    )
    check_reinstall(baseline, services, old_owner, package_state, uninstalled["backup_id"])
    cli("uninstall", "--confirm")
    test_firewall_frontends()


def check_reinstall(baseline, services, old_owner, package_state, uninstall_id):
    before = (STATE / "journal.json").read_bytes()
    assert HOST.package_state() == package_state
    foreign = Path("/etc/swanctl/foreign.conf")
    foreign.write_text("# independently configured strongSwan fixture\n", encoding="ascii")
    try:
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert (
            foreign.read_text(encoding="ascii") == "# independently configured strongSwan fixture\n"
        )
    finally:
        foreign.unlink()
    command("systemctl", "start", UNIT)
    try:
        pid = HOST.service(UNIT, "MainPID")
        assert int(pid) > 0
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert HOST.service(UNIT, "MainPID") == pid and HOST.ike_ports()
    finally:
        command("systemctl", "stop", UNIT)
    if VICI_PATH.exists():
        try:
            assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
            assert VICI_PATH.is_socket()
        finally:
            # The test created this socket by starting the stock daemon.
            assert not HOST.vici_listeners()
            VICI_PATH.unlink()
    assert HOST.package_state() == package_state and (STATE / "journal.json").read_bytes() == before
    assert resources().baseline() == baseline and foreign_services() == services
    emit(
        "L04",
        "PASS",
        "Reinstall stops on genuine foreign config or running daemon.",
        "Both refusals preserved the foreign object, packages, journal and protected baseline.",
    )
    dry = cli("install", "--dry-run")
    assert dry["mode"] == "reinstall" and not dry["packages"]
    assert (STATE / "journal.json").read_bytes() == before and HOST.package_state() == package_state
    install = cli("install", "--confirm")
    assert install["mode"] == "reinstall" and not install["packages"]
    assert read_record(INSTALLED)["token"] != old_owner
    assert read_record(INSTALLED)["retained_from"] == uninstall_id
    assert all(step["label"] != "APT install" for step in read_record(JOURNAL)["steps"])
    applied = cli("apply", "-c", str(PROFILE), "--confirm")
    manifest = current_manifest()
    resources(manifest).verify(manifest, baseline, read_record(ACTIVE)["nft_sha256"])
    assert HOST.package_state() == package_state and foreign_services() == services
    emit(
        "L01",
        "PASS",
        "Install, apply, uninstall, reinstall without APT, apply again.",
        {
            "uninstall_journal": uninstall_id,
            "reinstall_journal": install["journal"],
            "apply_journal": applied["backup_id"],
            "package_state_sha256": fingerprint(package_state),
            "package_delta": {},
            "protected_baseline": baseline,
            "foreign_service_pids_equal": True,
        },
    )


def test_firewall_frontends():
    # These disposable guest rules are fixtures, after the project has been removed.
    command("iptables", "-w", "-I", "FORWARD", "-j", "DROP")
    try:
        assert_foreign_firewall_stops("iptables FORWARD DROP", "iptables -w -I FORWARD -j DROP")
    finally:
        command("iptables", "-w", "-D", "FORWARD", "-j", "DROP")
    command("ufw", "allow", "22/tcp")
    command("ufw", "--force", "enable")
    try:
        assert_foreign_firewall_stops("UFW default routed policy", "ufw --force enable")
    finally:
        command("ufw", "--force", "disable")


def assert_foreign_firewall_stops(label, fixture_command):
    rules = HOST.nft()
    try:
        HOST.check_firewall(rules)
    except Stop:
        pass
    else:
        raise AssertionError("Foreign firewall fixture did not stop preflight.")
    assert fingerprint(rules) == fingerprint(HOST.nft())
    emit(
        "F05",
        "PASS",
        "Foreign frontend policy stops preflight with no rule changes.",
        label,
        audit_command=fixture_command + "; nft -j list ruleset; firewall preflight",
    )


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "crash":
        Deployment(FaultHost("IPv4 blackhole route add", crash=True)).dispatch(
            "apply", True, UPDATE
        )
    else:
        try:
            {"before-reboot": before_reboot, "after-reboot": after_reboot}[action]()
        except (AssertionError, OSError, RuntimeError, ValueError, KeyError, IndexError) as exc:
            emit("VM", "FAIL", "All executed acceptance assertions pass.", str(exc))
            journal = read_record(JOURNAL)
            if journal and journal["action"] != "install" and journal["phase"] != "COMMITTED":
                emit(
                    "TRANSACTION",
                    "FAIL",
                    "Apply or recovery preserves the baseline.",
                    {
                        "phase": journal["phase"],
                        "failure": journal.get("failure"),
                        "recovery_failure": journal.get("recovery_failure"),
                        "steps": [
                            step["label"] + " " + step["result"] for step in journal["steps"]
                        ],
                    },
                )
            if journal and journal["action"] == "install" and journal["phase"] != "COMMITTED":
                emit(
                    "INSTALL",
                    "FAIL",
                    "Install or injected recovery preserves the intended state.",
                    {
                        "phase": journal["phase"],
                        "failure": journal.get("failure"),
                        "recovery_failure": journal.get("recovery_failure"),
                        "package_recovery": journal.get("package_recovery"),
                        "strongswan_state": HOST.service(UNIT, "ActiveState"),
                        "vici_path_present": VICI_PATH.exists(),
                        "steps": journal["steps"],
                    },
                )
                diagnostic = command(
                    "journalctl", "--no-pager", "-u", UNIT, "-n", "18", "-o", "cat"
                )
                raw = diagnostic.stdout.encode()
                if all(key not in raw and key.hex().encode() not in raw for key in KEYS):
                    print(diagnostic.stdout, flush=True)
            raise
