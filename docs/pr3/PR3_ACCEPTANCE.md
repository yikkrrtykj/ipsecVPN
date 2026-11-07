# PR #3 — 真实 IPsec / 数据平面验收矩阵

> 基线 `1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`。**真实观察、不可用 mock 冒充**。本矩阵由 Codex 实测后逐项填入 JSONL；下列“PASS 条件”不是当前完成状态。

## 1. 证据规范

每个 case 至少输出 `case`、`time_utc`、`head_sha`、`environment`（VM/namespace、Ubuntu/kernel/strongSwan/iproute2/nft 版本）、`action`（脱敏）、`expected`、`observed`、`status`（`PASS|FAIL|SKIP|STOP`）、`proof_refs`（log/pcap 摘要/sa 截图哈希等）。CI 只保留隔离文档公网与 RFC1918 地址；PSK、内核加密密钥及真实业务公网 IP 不能出现在证据。每条二层/三层观察需标明**在哪个节点、哪个接口**采集。

规则：
- `PASS`：实际在隔离实验栈运行，内核、VICI、包计数和测试 host 的真实观察均支持期望。
- `FAIL`：执行后未达标或基线被破坏；必须保留证据且在最终总结解释。
- `SKIP`：明确环境/当前版本不支持或被放在后续 PR；不能把 SKIP 写成 PASS。
- `STOP`：外来 SA、归属不明、密钥风险、会导致明文泄漏、破坏 SSH/默认路由/其它 VPN 时拒绝改变现场。**负面测试里“预期拒绝”可记 PASS，但观察必须明确 STOP**。

## 2. C — 离线与代码回归

| ID | 测试 | PASS 条件 |
| --- | --- | --- |
| C01 | 继承 PR #1/#2 测试 | 原 73 项 pytest 全部通过，扩展测试额外运行 |
| C02 | Ruff、ShellCheck、Schema、Gitleaks | 无 lint/test/security FAIL |
| C03 | 仓库外 wheel 安装 | `validate`、`plan`、`export-peer`、`render`、`status`/`doctor` 在合法条件下行为正确 |
| C04 | 通用赛事 fixtures | 任意站点、VPS、网段、对端厂商、多 CIDR；无固定国家/赛事依赖 |
| C05 | 非 root/非 VM/缺 marker | 写操作 STOP；未弱化 PR #2 安全约束 |
| C06 | 外来/未知 SA 的 fixture | 对任何变更都 STOP，快照不变 |
| C07 | rekey 期间的合理 SA 并存 | 验证所有归属；未知 SPI、reqid、selector、外来 SA 一律 STOP |
| C08 | `status` / `doctor` 不改系统 | 断言无写 API、无网络探针（默认）及秘密输出 |
| C09 | `apply` 同 profile + 活 SA | NOOP，不终止/重载现有 CHILD，保留业务路径 |
| C10 | 影响业务的配置变更 | 没有显式维护确认就 STOP，有确认但无法证明所有权仍 STOP |
| C11 | 故障 JSON | 状态分层准确，未实际发送业务探针时 `data_path=SKIP/UNKNOWN` |
| C12 | rollback 状态 | 区分配置恢复与真实业务恢复，不能虚报 RESTORED/UP |
| C13 | 文档/版本兼容 | 证明使用 Ubuntu 24.04 实际 strongSwan 5.9.x 可用的命令选项 |
| C14 | 旧离线/VM 验收兼容 | C01–C10、V01–V20、F01–F14、L01–L04 旧合同均通过或有解释的等价替代；不能删除用例 |

## 3. T — 三节点真实 IPsec 正向实验

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| T01 | 构造隔离 Hub/A/B 及各自 LAN host | WAN 不可访问互联网；独立 `charon`/内核 SA/policy；测试后可销毁 |
| T02 | A→Hub IKEv2+CHILD | 两端实际 `ESTABLISHED` + `INSTALLED`；身份、提议、TS 和 if_id 精确匹配 |
| T03 | B→Hub IKEv2+CHILD | 两端状态正确；与 A 使用独立 PSK、连接、child、SPI 和 if_id |
| T04 | Hub VICI ↔ 内核 XFRM 一致性 | 存在正确的内核 state/policy、reqid、方向、SPI（不输出密钥） |
| T05 | A LAN host → B LAN host UDP | nonce/seq/源 IP/端口/载荷回执正确，Hub 两 XFRM 计数增长 |
| T06 | B LAN host → A LAN host UDP | 与 T05 反向独立验证，不以回包代替 B 主动发起 |
| T07 | A→B TCP | 三次握手、 payload、双向 FIN/RST/计数可查；源 IP 不变 |
| T08 | B→A TCP | 同 T07，从 B 主动发起 |
| T09 | 多 CIDR 与显式授权矩阵 | A 至少 2 CIDR、B 至少 2 CIDR 交叉通信满足 policy，无 selector narrowing 假成功 |
| T10 | 业务抓包三点对应 | A/B LAN 明文正确；Hub XFRM 可见正确内层包；WAN 只见受保护的 UDP4500/ESP 而非 LAN payload |
| T11 | Hub 无 SNAT | tcpdump/conntrack/nft 等证明业务源地址原样，未产生项目 NAT 规则 |
| T12 | 两站路由回程 | A、Hub、B route get 和转发计数一致，Hub peer 外层路径未进入 XFRM |
| T13 | Hub 服务及 VM 重启 | 先 guard 后路由/SA 恢复，端到端双向重新通过；SSH/默认路由未变 |
| T14 | 活 SA 同配置 apply | 返回 NOOP，IKE/CHILD 连续，业务 nonce 无非预期中断 |

## 4. S — SA/事务生命周期

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| S01 | 本端 IKE rekey | Old/new SA 关系可证明、重新建立后业务继续，旧 SA 合理清除 |
| S02 | 本端 CHILD rekey | 观察两端 VICI 与内核 SPI/reqid，传输恢复/连续有证据 |
| S03 | 对端发起 CHILD/IKE rekey | Hub 不误判外来 SA，正常 rekey 被接受 |
| S04 | 双方同时触发 rekey | 不误删不属于项目的对象、不失控重复 SA；异常可诊断 |
| S05 | DPD / WAN 临时中断与恢复 | 断开检测、重试上限、重新建链，双向数据恢复实测 |
| S06 | 某一侧 peer 掉线 | 另一侧状态准确；无错误的跨站 PASS；私网 payload 不泄漏 |
| S07 | 活 SA 下受控维护更新 | 显式确认、闭锁、受影响连接、备份、真实重建并验证两方向业务 |
| S08 | 活 SA 下更新被强制中断 | 不假报恢复；复原真实数据平面或 STOP_FOR_MANUAL + 保持闭锁 |
| S09 | 活 SA 下卸载 | 仅本项目的 SA/policy 被关闭；项目网络对象可删；其他配置不受影响 |
| S10 | 强制失败（VICI/route/nft） | journal、快照及现场状态相符，不误标 COMMITTED/RESTORED |

## 5. N — MTU、PMTUD 与 UDP/TCP 性能诊断

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| N01 | 小 UDP 包双向 | 序列完整、丢包统计准确 |
| N02 | MTU 增量搜索 | 记录路径、包长、是否 DF、外层封装方式和观察结果 |
| N03 | DF 包超过可传路径 MTU | ICMP type 3/code 4 或合理错误被观察，不能误报成功 |
| N04 | UDP 分片 / 丢失片 | 接收端包与 checksum 验证，失败能解释且不假报 MTU PASS |
| N05 | TCP 不同 MSS 与较大 payload | 带宽受限测试可完成；如有调整仅作用项目流量 |
| N06 | xfrm_stat 与 NIC 计数 | 错误量与现象对应；无滥改全局 sysctl |

## 6. F — 负面安全、归属和防泄漏

| ID | 注入 | PASS 条件 |
| --- | --- | --- |
| F01 | 错 PSK / IKE ID | 连接被拒绝、原因明确、密钥不泄漏 |
| F02 | 错 proposal / PFS | 失败不降级、准确定位协议层 |
| F03 | TS 不一致 / narrowing | 不允许超出明确授权范围，不假报双站完整通 |
| F04 | 第三方/未知 IKE 或 CHILD SA | 所有写操作 STOP，外来对象原样保留 |
| F05 | 未映射内核 XFRM SA/policy | 严格 STOP，禁止 bulk flush / delete |
| F06 | 伪造相同 connection name / 变更 SPI、reqid、if_id | 名称不构成所有权；拒绝危险操作 |
| F07 | unauthorized LAN、额外 VLAN、伪造源 IP | 双向拒绝、未经授权网络不走 Hub 跨站互通 |
| F08 | 只有 SA 在线，但路由/ACL 错误 | `data_path` 不能显示 PASS |
| F09 | 删除 Hub XFRM 或 CHILD | 强制黑洞/fail-closed，WAN 无明文业务 payload |
| F10 | 重启过程、事务部分失败 | WAN 无明文 LAN payload，SSH/默认路由仍正常 |
| F11 | 外来 iptables/UFW/nft DROP/规则影响 | 按原安全策略 STOP，不抢占配置 |
| F12 | 主机 default route 或 peer route 被意外改变 | STOP，不建立递归路由/默认出口泄漏 |
| F13 | 活 SA 下未确认配置更新 | 必须 STOP，旧业务保持原样 |
| F14 | active SA rekey 与操作竞争 | 快照有界重试；归属不明 STOP；不会误杀旧新 SA |
| F15 | 错/损坏的事务、备份或 PSK | 不解锁任何危险操作，保持安全状态 |
| F16 | 测试中止/超时 | 持久证据不写恒真 PASS；可安全清理独立 lab |

## 7. PR #3 必须继续 SKIP 的事项

- 真实山石/其他品牌现场 IKE 互操作，双方公司 ISP WAN、跨境丢包与公网 QoS。
- 腾讯云或其它外部备 Hub 的真实自动切换、双站 Track 联动、手动回切 SLA。
- 实际电竞业务（PUBG/赛事 UDP）全链路效果，直播制作端到端质量。
- Prometheus/Grafana/飞书 Webhook、长期稳定性 SLO、外网 DDOS 安全设计、商业高可用能力。
- Ubuntu 24.04 之外的发行版，任意 N 站点/并行活动 profile、IPv6 VPN。

上述 SKIP 不阻塞完成**Linux 三节点隔离实验**范围的 PR #3，但必须在 PR/README 标明“非生产验收”。

## 8. 汇报格式

```text
PR #3 URL: ... (Draft)
Base: 1bdfdb7fe17a2c959a0859856824eadf8f1ceae6
Merge-base: ...
Head: ...

PASS: Cxx, Txx, Sxx, Nxx, Fxx（附证据）
FAIL: ... / none
SKIP: ...（每项说明范围/原因）
STOP: ... / none unresolved

Topology: independent node proof, actual kernel/charon versions, isolation proof
SA: each IKE/CHILD + kernel if_id/reqid/SPI consistency
UDP/TCP: each direction, source IP unchanged, packet counters, capture samples
MTU/PMTUD: measured result, DF/ICMP/xfrm_stat evidence
Lifecycle: DPD, both rekey directions, restart, controlled update/rollback
Ownership: unknown-SA negative proof
Host guard: default route, SSH, foreign nft baseline unchanged
Secrets: scan result
CI: links and artifact IDs
Statement: no production deployment, no field vendor testing
```
