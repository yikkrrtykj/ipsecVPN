#!/usr/bin/env bash
# All privileged network commands in this file run inside the disposable guest.
set -euo pipefail
systemd-detect-virt --vm
# shellcheck disable=SC1091
. /etc/os-release
suite="${1:-pr2}"
case "$suite" in
    pr2) extra_packages=() ;;
    pr3) extra_packages=(tcpdump) ;;
    *) exit 2 ;;
esac
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 || "$(hostname)" != "ipsecvpn-$suite-lab" ]]; then
    printf '%s\n' 'STOP: guest identity or release does not match the disposable lab.' >&2
    exit 1
fi

cp -a /home/ubuntu/lab /opt/ipsecvpn-lab
chown -R root:root /opt/ipsecvpn-lab
chmod 0755 /opt/ipsecvpn-lab /opt/ipsecvpn-lab/apt
if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.disabled
fi
printf 'deb [trusted=yes] file:/opt/ipsecvpn-lab/apt ./\n' > /etc/apt/sources.list.d/lab.list
apt-get -qq update
apt-get -qq install -y --no-install-recommends nftables python3-venv iptables ufw "${extra_packages[@]}"
python3 -m venv /opt/ipsecvpn-lab/venv
/opt/ipsecvpn-lab/venv/bin/python -m pip install --no-index \
    --find-links=/opt/ipsecvpn-lab/wheels ipsecvpn
install -d -m 0700 /etc/ipsecvpn /etc/ipsecvpn/profiles /etc/ipsecvpn/secrets
printf 'ipsecvpn-lab-v1\n' > /etc/ipsecvpn/lab-authorized
chmod 0600 /etc/ipsecvpn/lab-authorized
printf 'net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 2\nnet.ipv4.conf.default.rp_filter = 2\n' \
    > /etc/sysctl.d/90-ipsecvpn-lab-prerequisites.conf
sysctl -q -p /etc/sysctl.d/90-ipsecvpn-lab-prerequisites.conf
cat > /etc/nftables.conf <<'EOF'
table inet lab_existing {
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 22 counter accept
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        counter
    }
}
EOF
systemctl enable --now nftables.service
/opt/ipsecvpn-lab/venv/bin/python /opt/ipsecvpn-lab/verify.py before-reboot
