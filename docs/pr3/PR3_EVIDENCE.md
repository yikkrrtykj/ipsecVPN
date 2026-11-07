# PR #3 隔离验收记录

基线与 merge-base 为 `1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`，首提交 `41c1583` 收录开发合同。GitHub 仓库现名为 `yikkrrtykj/event-ipsec-hub`，原地址重定向至同一个 PR #3。

## 实际执行环境

独立 Ubuntu 24.04 QEMU 客户机使用 Linux `6.8.0-147-generic`、strongSwan `5.9.13-2ubuntu4.24.04.5`、iproute2 `6.1.0-1ubuntu6.4`、nftables `1.0.9`。Hub、Peer A、Peer B 拥有独立网络栈、daemon 和 VICI socket。两端 LAN host 和 WAN 交换机另有命名空间。管理口为 `restrict=on`、loopback SSH，包与 wheel 从管理端离线送入。原始抓包只存在可销毁客户机，导出 JSONL 包含脱敏包头、负载摘要和 pcap 哈希。

## 可复核运行

下表记录实际执行提交 `840ead5bb443de0af5a66331c3d3f73172632400`。该轮已完成 Hub 服务重启、VM 重启和活动卸载。独立端口阻断、仅 CHILD 下线、外层明文注入、PFS 不匹配、崩溃重启后的双端采样及 N05 限速 TCP 的补充用例在后续提交重新执行。最新整轮结论与 HEAD 在 Draft PR 描述中更新。

| 运行 | 实际结果与证据 |
| --- | --- |
| 离线验证 | PASS。85 项 pytest，保留原 73 项。Ruff、ShellCheck、4 份配置、仓库外 wheel 的 validate/plan/export-peer/render/status/doctor、Gitleaks 均通过。 [运行日志](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42333944846) |
| PR #2 VM 回归 | PASS。V01–V20、F01–F14、L01–L04 共 38 个唯一 case，包含包清单差异、dpkg 异常、APT 后激活失败、人工恢复及外来 strongSwan 拒绝。 [运行日志](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42333944868) · [JSONL 13559765301](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42333944868/artifacts/13559765301) |
| PR #3 三节点 | T01–T14、S01–S10、N01–N06、F01–F16 全部 PASS。包含两个 Peer PID 保留的 Hub daemon 重启、新 SSH 会话确认的实际 VM 重启、重启后双向 UDP/TCP 与活动卸载后的 SAD/SPD 清空、主机基线一致。 [运行日志](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42333944849) · [JSONL 13559233621](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42333944849/artifacts/13559233621) |

## 数据平面与生命周期观察

- 两条独立 IKEv2/CHILD，Hub 有 4 个内核状态和 24 条 ESP 策略，每个 Peer 有 12 条策略。A/B 主动发起 UDP、TCP，四对授权 CIDR 双向覆盖。接收端原源地址、端口、逐包 nonce/序号及 SHA-256 一致。LAN、两个 Hub XFRM、外部 WAN 均有采集，两 XFRM 收发计数增长。
- 本端、对端、同时 IKE/CHILD rekey 均执行。定时用例观察 IKE/CHILD ID 从 `[27,27]` 变为 `[29,31]`，耗时 `41.474s`，未发起操作员 rekey，前后双向负载通过。计时参数仅位于 fixture。
- WAN 中断由 DPD 检出并目标化重连，实测检测及隔离耗时 `166.724s`。单侧 Peer daemon 重启后新 PID 及双向业务通过，另一条隧道独立核对。
- 活 SA 同配置 apply 为 NOOP。维护更新、显式 rollback、真实路由权限/nft 语法/VICI 拒绝、SIGKILL 均保留 journal 和保护规则。人工恢复报告 `CONFIGURATION_RESTORED`，工具未发送端到端探针时 `data_path_restored=SKIP`，实验另行核验双向负载。
- 错 PSK/ID、proposal、TS、真实外来 SA、同 if_id 未登记策略、伪造源 IP、未经授权 LAN、外部 DROP、默认路由变化和损坏备份均执行负面校验。预期拒绝为 case PASS，观察明确 STOP，外来对象与事务日志保留核对。

## MTU 实测

DF UDP payload `1200/1300/1380` 字节收到校验回执，`1420/1460/1472` 字节返回 `EMSGSIZE=90`。JSONL 记录接口 MTU 及 ICMP fragmentation-needed。2048 字节 UDP 分片完成重组和摘要核对。双向 TCP 在 MSS `512/1024` 下完成 8192 字节 payload。三节点 `/proc/net/xfrm_stat` 的错误计数增量为空。产品默认未修改 MTU、MSS 或全局 PMTUD。

## 发现与修复依据

1. 最初维护保护阻断终止回执，VICI 超时而内核已撤除首条 SA。修复只保留原授权 Peer 的握手入口，每次终止后核验精确剩余 SA，再关闭入口变更配置。后续 S07、S08、S10 已实际通过。
2. 删除 XFRM 后 Hub 本机 AF_PACKET 可看到入站解密 skb。新增独立 WAN 交换机抓包，并用文档公网地址间的随机控制报文验证采集有效。F09 线侧没有私网地址或业务 nonce，pcap SHA-256 为 `18c897da54c26e3a463211f870afd5dac1e44fea92900afd5b50f72b9c73e4a0`，Hub 本机观察仍保留。 [strongSwan 抓包语义](https://docs.strongswan.org/docs/5.9/support/faq.html#_capturing_outbound_plaintext_packets_with_tcpdumpwireshark)
3. 旧 VM 回归曾在恢复 oneshot 尚未完成时检查规则。journal 当时只有 restore 的 Starting，观察到保护规则。多 unit 的 `systemctl is-active` 只需其中一个 active 就成功。实验现逐个等待全部 unit active，再执行原有核验，没有人工启动修复动作。
4. Hub restart 曾连带停止实验 topology 服务的 Peer B，Hub 最终呈 A 已建立、B CONNECTING。实验 topology 服务移除对 Hub unit 的 Requires，新增 Hub 重启时对端 PID 持续存活断言。840ead5 的 T13_DAEMON、T13、S09 已通过。历史失败的原始记录继续保留。 [历史失败 JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42332206806/artifacts/13558353867)
5. 补充双端采样发现 Peer 被 SIGKILL 后遗留内核 SA，新进程可以建立新连接但库存仍不完整。实验恢复先保存崩溃前的完整 VICI/内核归属证明，核对遗留库存完全一致后逐条清理该 Peer 的已知对象，模拟断电时的 IPsec 内核状态丢失。混入未知策略的负面用例要求 STOP 且库存不变，之后还需重建 daemon、完整双端核验及真实双向流量。此恢复操作仅属于可销毁 Peer 夹具。

iproute2 6.1 的单条 SA 删除按端点、ESP 协议和 SPI 寻址，`if_id` 在写入前的完整库存比较中核验。 [iproute2 6.1 官方实现](https://github.com/iproute2/iproute2/blob/v6.1.0/ip/xfrm_state.c)

## 继续 SKIP 的范围

现场厂商互操作、实际赛事与跨境公网 SLA、外部备用网关切换、监控告警、其他发行版、IPv6 和 N 站点为 SKIP。没有接触生产服务器或现场设备。PR #3 保持 Draft，等待人工代码审查。
