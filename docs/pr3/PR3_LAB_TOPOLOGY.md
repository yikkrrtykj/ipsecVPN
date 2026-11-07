# PR #3 — 隔离实验拓扑与实际抓包要求

## 1. 实验连接图

```text
LAN-A1 10.43.10.0/24   LAN-A2 10.43.11.0/24
       \                      /
    [site-a router, WAN 198.51.100.21]
                 || IKEv2 / CHILD A
                 || UDP/500,4500 ESP encapsulation
           [isolated WAN switch]
                 ||
    [hub, WAN 198.51.100.10]
       XFRM A (if_id 101)
                 ⇄ IPv4 forwarding + nft ACL, no SNAT
       XFRM B (if_id 102)
                 ||
           [isolated WAN switch]
                 || IKEv2 / CHILD B
    [site-b router, WAN 198.51.100.22]
       /                       \
LAN-B1 10.76.12.0/24   LAN-B2 10.76.13.0/24
```

所有地址为完全隔离实验用文档 / 私有地址，不得复用为生产常量。实验 IP 与 Hub/Site ID 必须来自 fixtures。主机应各有一个真实路由器后的业务测试 host（可以使用独立 network namespaces），避免 Hub 自身发包被错当成完整跨站转发。

## 2. 真实双端的证明

必须提供每个节点自己的 `uname -r`、Ubuntu 发行版与 strongSwan 版本、进程 PID、独立 VICI socket、独立内核路由表、`ip -d link`、`ip xfrm state list nokeys`、`ip xfrm policy list` 和单独的 Packet Capture。不能只有 Hub 的状态。

网络隔离证明：测试 WAN 无公网默认路由，也不允许 runner 向真实互联网发送业务包；root/QEMU/namespace 的资源更改限于一次性 lab。CI 结束无论失败或通过都应销毁实验网络并保留脱敏证据。若仓库原有 QEMU VM 测试脚本与三节点实验需要不同运行权限，单设 workflow，不得悄悄扩大旧 workflow 权限。

## 3. 抓包观察点

| 抓包点 | 必须证明 |
| --- | --- |
| Site A LAN host | 发起/接收业务 UDP/TCP，真实 A 源 IP 和 B 目的 IP |
| Site A WAN | 出口是 UDP4500/ESP 密文而非原始 LAN UDP/TCP |
| Hub WAN | A 和 B 两个不同 Peer 的 IPsec 加密流，外层 peer IP 与 profile 对应 |
| Hub XFRM-A | 解密后的 A→B 内层 IP/源地址正确 |
| Hub XFRM-B | A→B 内层 IP 经过正确的对向路由；反向也验证 |
| Site B WAN | 收到新的 B 隧道 ESP 流 |
| Site B LAN host | 校验源 IP、端口、payload nonce/seq，与源端一致 |

必须用双端**主动发起**的连接证明，而不是一次回包就声称双方向业务通过。每个方向至少提供 UDP echo 和 TCP socket 服务，并有明确有限时长、包速率与大小限制。

## 4. 故障注入规范

- 先生成基线哈希：SSH listener、WAN IPv4 地址、default route、IP rule、foreign nft/iptables、daemon、XFRM/state/policy 及包清单。
- 每个故障先记录连接/SA 状态，再注入，观察数据平面与漏包，最后恢复并重新验证真实业务。
- 不能使用 `ip xfrm state flush`、`nft flush ruleset`、全局 `iptables -F`，也不得停掉主机 SSH；如果为了实验需要模拟外来 SA，使用只在隔离 peer/test 栈创建的明确可清理对象。
- 若黑洞路由和 nft 安全策略因故障被删除，应立即 STOP，不继续人工“试试看”而用默认路由冒险转发。

## 5. 参考的低风险采集命令（仅隔离实验机）

```bash
swanctl --list-sas --uri unix:///run/charon.vici
ip -d link show type xfrm
ip xfrm state list nokeys
ip xfrm policy list
ip -4 route show table all
ip -4 rule show
nft list table ip ipsecvpn
cat /proc/net/xfrm_stat
```

不要将未脱敏 `swanctl` debug、`ip xfrm state` 或 tcpdump 完整 pcap 上传到公开仓库；优先生成字段筛选后的结构化收据和文件摘要。
