# 隔离实验中的活动隧道操作

`ipsecvpn status --json` 和 `ipsecvpn doctor --json` 读取本机证据。IKE 已建立、CHILD 已装入、内核路由与 ACL 正常分别检查。默认不发业务探测，`data_path` 为 `SKIP`。归属或基线无法核实时停止写入。

```bash
ipsecvpn initiate --site "$site" --dry-run
ipsecvpn initiate --site "$site" --confirm
ipsecvpn rekey --site "$site" --child --confirm
ipsecvpn rekey --site "$site" --ike --confirm
ipsecvpn apply -c "$profile" --maintenance --dry-run
ipsecvpn apply -c "$profile" --maintenance --confirm
ipsecvpn rollback --to "$snapshot" --maintenance --confirm
ipsecvpn uninstall --maintenance --confirm
```

默认加载配置时保持 `start_action=none`。Hub 发起显式 `initiate`，对端按配置应答。成功后记录该站点和当前 profile 摘要，启动恢复先建立闭锁保护，再对各已登记站点执行一次有界协商。已有有效 CHILD 时 `initiate` 复用现有连接，掉线后可用同一命令目标化重连。协议级定时 rekey 由 daemon 管理。

活动部署的同配置 apply 核对 profile、密钥摘要与实际 SA/网络状态后返回 `NOOP`。变更前用 dry-run 核对两条隧道都可能短时断开、保护前缀和回滚 ID。确认维护操作后，工具先阻断项目业务流量，只保留已授权 Peer 的 IKE 以接收终止回执。每次目标化终止后重新核对 VICI 和内核，确认仅指定 SA 离开，再关闭握手入口并按项目名称装载连接和凭据。允许新配置授权的 Peer 握手之后再尝试重建原有站点。重新开放业务仍须实际验证跨站路径。

中断时检查 journal 与当前保护规则，先修复带外管理、对端、路由或服务边界。若事务要求人工维护恢复，按该事务 ID 执行 `rollback --to "$transaction" --maintenance --confirm`。此操作只在能确认当前对象来自 journal 已知配置时继续。配置及 SA 恢复可报告 `CONFIGURATION_RESTORED`，未运行端到端测试时 `data_path_restored=SKIP`。无法证明归属时保留现场，使用独立控制台核查。

MTU 以实验路径测量为准。用 `ip link`、路由 PMTU、`/proc/net/xfrm_stat`、DF UDP、IPv4 分片、ICMP fragmentation-needed 和有限 TCP 流量逐层排查。默认不修改主机 MTU、MSS 或全局 PMTUD。自动 MTU/MSS 配置和现场建议值为 `SKIP`。
