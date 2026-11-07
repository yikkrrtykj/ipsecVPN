# ipsecVPN — PR #3 真实 IKEv2 与跨 XFRM 数据平面开发手册

> 开发合同版本 PR3.1 · 2026-11-07  
> 仓库：`yikkrrtykj/ipsecVPN`  
> 唯一基线与预期 merge-base：`1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`  
> 仅新建独立 **Draft PR #3**。禁止修改 `main`、自动合并、在生产 VPS 或现场防火墙试运行。

## 0. 目标与边界

本 PR 把 PR #2 的“离线装载两个 CHILD 配置、XFRM 与路由”推进到 **真实的三节点 IPsec**：两个可配置远端站点的各自业务 LAN，经 Linux Hub 上两条独立 IKEv2/CHILD SA 完成双向三层数据交换。传输的原始业务 IP 必须不变；验证多 CIDR、UDP、TCP、MTU/PMTUD、重协商、恢复与异常诊断。

产品始终是**通用赛事工具**：国家、场馆、ISP、VPS、设备品牌、网段、对端公网和 IKE 身份全部由 profile / 实验夹具决定。不得写死上海、土耳其、PUBG、V.PS 或腾讯云。P0 限定：**一个活动赛事 profile，一台自建 Hub，两个远端站点，每站一条主 IPsec，多个授权 IPv4 LAN**。外部备用参数保持可选、只读与 `SKIP`。本 PR **不做** 生产上线、山石真机联调、腾讯云备份切换、监控告警或 Web UI。

**强制验收定义**：`IKE ESTABLISHED` 不等于 `CHILD INSTALLED`；二者都不等于业务转发成功。最终必须证明两个 SA 都在、内核 XFRM 方向/ID/计数正确、两方向 UDP/TCP 真正抵达对端内网主机、源地址未被 SNAT，以及故障状态不会明文泄漏。

## 1. 不得绕过 PR #2 的保护

保留 PR #2 的 Ubuntu 24.04 + `charon-systemd` + `swanctl` + VICI + 专有 XFRM 接口、精确路由与 blackhole、独立 nftables 表、持久事务与 journal、回滚、失败闭锁、root-only lab marker、SSH/默认路由/非项目对象的基线检查。强制继续使用已发布的 wheel 和隔离授权主机机制。不得将实验 marker 改写成任意机器的可用生产开关。

现有两个代码冲突点要 **先审计再修改**：

1. `ipsecvpn/host.py` 的 `assert_no_other_ike()` / `assert_exclusive_ike()` 拒绝任何内核 SA 和 VICI `--list-sas`。PR #3 应允许严格证实的 **本项目活动 SA**，对归属不明的任何 IKE/CHILD 或 kernel XFRM SA/policy 必须 `STOP`。不能直接删除“有 SA 就停”逻辑。
2. `ipsecvpn/resources.py::load()` 当前执行 `swanctl --load-all --clear`。须查明其对已加载配置、凭据、正在运行的 SA、rekey 的语义；禁止在线操作默默清除无关配置或使业务短时无保护。用受限目标加载流程；需要切断旧 CHILD 时应在明确维护模式下执行，并留原状态、诊断和可验证恢复证据。

## 2. 隔离实验拓扑与安全边界

必须构建**独立的 Hub / Site A / Site B 内核网络栈**，优先 3 台可销毁的 Ubuntu 24.04 QEMU VM；可接受 Hub VM + 两个完全隔离的 Linux network namespace，前提是各 peer 有独立的 `charon` 进程、VICI socket、XFRM SA/policy、WAN/LAN 路由和抓包点，并证明不是同一内核 IPsec 状态假冒两端。不能把“对单一进程发起一次 IKE”当成双端测试。

推荐实验拓扑（**仅 RFC5737 文档公网 + RFC1918 内网、无公网出口**）：

```text
Site A LAN host(s)                         Site B LAN host(s)
  10.43.10.11/24                              10.76.12.11/24
  10.43.11.11/24                              10.76.13.11/24
      |                                              |
 Site A router                                   Site B router
 WAN 198.51.100.21                              WAN 198.51.100.22
      \                                           /
       \---------- isolated WAN L2 --------------/
                          |
                Linux Hub 198.51.100.10
              XFRM if_id=101 / if_id=102
            [A CHILD SA]     [B CHILD SA]
             NO SNAT, site-to-site forwarding
```

各 LAN host 的**默认网关是本站点路由器**；对端 CIDR 由站点路由器指向对应 IPsec path。两站必须有各自 IKE ID、独立 256-bit PSK、独立 CHILD 名称与 if_id；Hub 根据现有 profile 推导反向 Traffic Selectors。可为 Site A/B 增加非 XFRM 的策略型路由测试，不能假设现场厂商也支持 XFRM；Linux peer 作为互操作性实验模型，不等于山石实测。

- QEMU/namespace 只能走封闭实验 WAN，禁 Internet 默认出口；runner 仅通过 loopback SSH 转发管理测试虚机，不在 runner 主命名空间修改网卡、iptables/nft、sysctl、路由或 SSH。
- 远端 peer 限制资源、禁止过量发包和长时间压测；测试包只发向隔离实验网段；实验 PSK 不记录原值、十六进制编码或内核 SA key。`ip xfrm state` 日志必须 `nokeys`。
- 对端作为测试夹具，必须提供真实安装、启动、配置、启停和销毁步骤，固定依赖、发行版版本、内核、strongSwan、nftables、iproute2。
- 测试可以扩展现有 `scripts/pr2-vm/`，但不能让 PR #2 的 34 项集成回归退化；如果需要新增实验脚本，使用 `scripts/pr3-lab/` 及其专门 workflow。

## 3. 核心功能 A：真实 IKE/CHILD SA 建立与重协商

1. 先在无 SA 场景保持 PR #2 原有完整校验；Hub 和两 peer 均真实启动 `charon` 并使用独立 root-only PSK。严格使用 IKEv2 和 profile 指定加密套件，不因协商失败自动降级到 IKEv1、DH1、SHA1 或 `0.0.0.0/0` selectors。
2. 真实启动每个 CHILD（可由 `swanctl --initiate --child <project-child>` 目标化触发）；实现明确启动策略，区别：只装载配置、人工 initiate、重启后受控自动恢复。远端离线时必须尽快返回可诊断状态、保留 blackhole、采用有上限重试；不能造成无限密集 IKE 重试。明确控制谁是发起端，避免双方无序重复 initiate。
3. `swanctl --list-sas` 的 IKE/CHILD 项、状态、IKE identities、本地/远端实际地址、各子 SA 的 selector、加密算法、`if_id_in` / `if_id_out`、SPI、reqid、内核 XFRM policies/states 必须关联一致。允许合理的协议 rekey 短暂并存，但不能将旧/新 SPI 绝对值作为永久 ID。
4. 对 IKE、CHILD 分别测试主动 rekey、定时 rekey、对端 rekey、双端同时 rekey 和 DPD 断开。必须记录**本端、对端的状态及业务包序列**；允许可解释短时抖动，不能仅靠短暂无报错宣称无缝。
5. 站点重启、Hub strongSwan 重启、整个 Hub VM 重启与短暂 WAN 中断后：保护规则先启用，再尝试重连，重新建立的 SA 属于项目且跨站业务恢复；不允许失联时退回公网明文。明确 `start_action` / `dpd_action` 的选择以及重试机制的实际行为，不能把它们的名称当成已验证能力。
6. 测试错误 PSK、错误 ID、PFS/DH/ESP proposal 不一致、peer 不在线、selectors 不兼容，诊断需指明层次与可能原因，不能打印 PSK、完整密钥材料或任何 SA key。

## 4. 核心功能 B：活动 SA 所有权与事务

### 4.1 所有权证明（必须组合核验）

以下是**联合证据**，不能凭某一个名称或一条标记就判断可操作：

- root-only 安装事务记录、当前 event/manifest 摘要、项目独占 `charon-systemd` unit、进程实际 `STRONGSWAN_CONF` 和 VICI socket 归属，确保不是别的 daemon；
- VICI 实际 IKE/CHILD 的 connection name、唯一 SA ID、local/remote IKE identity、实际 local/remote address、协商 proposal、双向 selectors、children 数量；
- kernel `ip xfrm state/policy`（只读、**nokeys**）匹配 expected if_id、reqid、外层地址、SPI、模式及策略方向；同一连接 rekey 允许受控的前后 SA 暂时重叠，必须有确证的 VICI rekey 关联；
- XFRM interface 的唯一 if_id 与项目所有权 alias、routes、nft ACL、实际可见收发计数。

凡出现**额外** IKE/CHILD、VICI 缺项、kernel 有无法映射的 SA/policy、SPI/reqid/if_id 不吻合、进程或 socket 归属异常、反向 selector 不一致 → `FAIL/STOP`，保留当前外来对象，禁止修改其 SA/路由；不可“只看项目名称然后删除”。内核状态可能有短暂重协商竞争，使用有界重试与一致性快照，不得因为某次采样不一致就误删 SA。证明不能成立时永远不允许强制接管。

### 4.2 操作分级

- 只读 `status` / `doctor`（默认不发包）可在有已验证项目 SA 时运行，外来状态则报告 `STOP` 或 `UNKNOWN/UNOWNED`，不修改主机。
- `initiate` / `rekey` / 目标化重连需要显式命令、限定一条属于项目的连接、在持久事务锁下操作；允许 IKE daemon 自身正常协议 rekey，不因 SPI 更新就误报不属项目。
- `apply` 未改变任何 profile/secret 时返回 `NOOP`，不能因为有活 SA 就 STOP；无影响的只读操作也不能中断业务。
- **变更 peer 地址、IKE ID、PSK、selectors、if_id、CIDRs、路由/ACL 等影响存量业务的配置，必须通过显式维护窗口模式**（命令参数由 Codex 设计并固定在文档），显示受影响流量、预估中断**类别**（不编造秒数）、备份/回滚点后确认。先 fail-closed，再在严格受控范围内 terminate/reload/reinitiate；无法安全执行时 STOP 而不是热切换伪成功。
- rollback 必须区分 `configuration_restored` 与 `data_path_restored`。只恢复磁盘配置但未重新建立 CHILD 或 UDP/TCP 不通，绝不能报 `RESTORED/UP`。断站时允许 `RECOVERABLE_OFFLINE` / `STOP_FOR_MANUAL`，但留住闭锁保护，提供人工恢复命令。
- uninstall 在有活 SA 时必须明确停止项目 SA 的权限、顺序及业务影响；外来 SA 不可 terminate。异常中断后重启不会尝试把未知 SA 擅自当成项目 SA。

### 4.3 兼容性红线

PR #2 的 `swanctl --load-all --clear`、`assert_exclusive_ike` 和 `resources.verify` 的“只准空 SA”假设都需要在 **证明所有权前提**下重构。不得简单全局放宽；应把无 SA、已验证项目 SA、外来 SA、过渡 rekey SA、无法确认 SA 分成独立状态，逐一测试。

## 5. 核心功能 C：站点 A ↔ Hub ↔ 站点 B 真实数据平面

- 站点 A 内网主机（真实独立 namespace/VM）发起 UDP echo 和 TCP 连接至站点 B 内网主机；必须经过 A→Hub 解密、Hub A-XFRM→B-XFRM 再加密、B→内网；B→A 反向同样验证。
- 以固定源 IP、源端口、payload nonce、序列号做端到端比对；对端收到的源 IP 应与原始 LAN host 一致。Hub 不做 SNAT/MASQUERADE。抓包分别观察 WAN **只见 ESP/UDP4500 密文**、两个 XFRM **可见授权内层流量**、LAN **收发 IP/端口/载荷一致**。不能把 Hub 自身 ping 某个 site 当作跨两条 SA 的转发证据。
- 多 CIDR：至少 A 的两个和 B 的两个授权子网，交叉方向按授权矩阵验证；`lan_cidrs` 中未授权/未参与 selector 的网段以及第三站点/伪造源地址必须拒绝。检查 SA selector narrowing；如果特定 strongSwan 对端只接受一对子网，需要记录兼容限制，明确处理方案（例如受限的多个 CHILD 配置），不能自动退化为任意全流量。
- 路由检查：站点 LAN 内核到达远端 LAN 经隧道；Hub 由正确的 XFRM 接口转入对向；Hub 的 WAN 对 peer 公网走原直连默认路径；黑洞路由仍生效。不存在双方各连同一 Hub 却互相不可达的假阳性。
- 明确 nft 规则只放行 `A allowed CIDR ↔ B allowed CIDR`，而不是只匹配出口接口即全通。执行禁止方向、私网地址仿冒、未经授权 CIDR 和外层明文注入测试。先验证外来 nft/iptables/UFW 基线检查未被削弱。
- 完全不进行公网负载测试；实验 UDP/TCP 使用有限大小、速率和时长，提供成功/失败的按包计数，不写死业务端口。

## 6. 核心功能 D：MTU / PMTUD / 分片

- 同一隔离架构分别测小 UDP 包、接近路径 MTU 的 UDP、DF=1 大包、IPv4 分片、TCP 大流及多个 TCP MSS；区分内层 MTU、外层 UDP 封装 overhead 和 ICMP Fragmentation Needed。
- 记录两端 WAN/XFRM 设备 MTU、路径路由 MTU、`/proc/net/xfrm_stat` 计数（例如 `XfrmOutStateModeError`）、ICMP type3/code4、抓包与端到端 payload 校验。MTU/PMTU 数值必须按真实隔离拓扑测量，不写“1400 保证可用”。
- **先测试 PMTUD 与 ICMP 正常放通**，再考虑可选**项目 XFRM 接口 MTU 与针对授权 XFRM TCP SYN 的 MSS 限制**；不能默认全局修改 net.ipv4.ip_no_pmtu_disc、所有 TCP MSS、现有接口 MTU 或 netplan。
- 如决定实现可配置 MTU/MSS：必须 schema 校验、严格限制目标接口/范围、事务备份/回滚、现有路由/SSH 守恒；否则 PR #3 允许先提供诊断与实测建议，自动 MTU 调整明确 `SKIP/UNSUPPORTED`，不可虚构成功。

## 7. 核心功能 E：`status` 与 `doctor`

建议 CLI（名称可微调，保持简短且向后兼容）：

```text
ipsecvpn status [--json]                   # 实际 VICI+kernel+host/route 实况，只读
ipsecvpn doctor [--json]                   # 只读分层诊断，不扫描内网或发包
ipsecvpn doctor --probe --site <id> ...   # 可选：有界主动实验探针，必须明确授权目标/路径
ipsecvpn initiate --site <id> --dry-run|--confirm
ipsecvpn rekey --site <id> --child|--ike --dry-run|--confirm
ipsecvpn apply ... --maintenance --confirm  # 影响活动 SA 的受控配置变更
```

- `status` JSON 每站包含 `site_id`、`ike_state`、`child_state`、`auth/selector/if_id_verified`、`kernel_sa_policy_verified`、`xfrm_interface`、`tx/rx bytes/packets`、`protected_route`、`egress_guard`、`data_path`（若没发真实探针则必须 `SKIP/UNKNOWN`）、`reason_code`；区分 `PASS` / `FAIL` / `SKIP` / `STOP`，不将 SA 状态直接作为 business UP。
- `doctor` 提供层级原因：OS/service/VICI → IKE handshake / IDs / PSK / proposal → CHILD/selector/PFS → kernel SA/policy/if_id → inner route/ACL → 外层 peer route/NAT-T/UDP4500 → test target/MTU。尽量引用强证据而非凭一条错误日志猜原因；无法判定标注 `UNKNOWN`。
- 默认所有诊断不得发任何新的网络探针、修改 SA、改变路由或重启服务；若开启 `--probe`，只允许 profile 配置及 CLI 确认的具体测试 IP:port、限速/超时/重试，且只能在实验环境执行。
- JSON/文本中禁止输出 PSK、key、ESP authentication/encryption material；原始 `ip xfrm state` 及 debug 日志不可直接写入 CI artifact。日志暴露 SPI 可以酌情使用短期脱敏标识，避免公开关联真实公网。
- 面向以后 PR #4 监控的数据结构应稳定，但 PR #3 不实现 exporter/Grafana/飞书。

## 8. 事务、回滚、启动和故障场景

正常自动 rekey 不应由控制面事务每次阻断；明确区分“同一配置的协议 SA 更新”和“运维命令改变配置”。要求测试：

1. 活 SA 下执行 `status`、`doctor` 和重复 apply；只读或 `NOOP`，不得被旧版空 SA 检查误阻断。
2. 活 SA 下原子变更（受控维护模式）、模拟异常（禁用对端/杀 daemon、路由/nft/VICI 写入失败、SIGKILL）。失败后要么重新建立**已验证原有数据平面**，要么在 fail-closed 状态清楚标为 `STOP_FOR_MANUAL`，不虚报恢复。
3. 出现外来 IKE 或 XFRM state/policy 时：任何部署变更、terminate、卸载都 STOP；只读诊断报告其存在，且原对象、WAN、SSH、nft 与项目状态保持不变。
4. 远端断电、WAN 断开、UDP500/4500 阻断、仅 CHILD down、仅一个站点重连、Hub daemon 重启和 VM 完整重启后，业务链路恢复与否要有**实际端到端探针证据**；反向路径不可单侧成功冒充双向。
5. XFRM 接口消失或 SA 缺失期间，在 Hub WAN 侧抓包：受保护的 LAN payload（明文）为 **零**。尤其检查黑洞选择器、错误更具体路由、临时重路由、已存在连接，以及被错误 routing mark 旁路。
6. 保持 PR #2 L01–L04、V01–V20、F01–F14 的原始回归全部 PASS。若因支持活动 SA 而改变负面测试预期，必须给出严格替代证据，不得删除旧用例绕过。

## 9. 开发分层与变更约束

- 先加入只读 SA snapshot / ownership 模块与测试夹具，再加入目标化 IKE/CHILD 管理和真实三节点 lab，最后开放活 SA 的 `apply` / `rollback`；不要第一步大幅改掉事务系统。
- 保持 profile schema V2.0 向后兼容；需要新可选字段时提供默认/迁移文档和拒绝非法组合。默认禁用影响系统全局的 MTU/MSS 优化。
- 不能在用户未授权时修改真实对端防火墙或云安全组。测试 peer 可自动生成但仅存在隔离 lab；对端配置不应被当作山石可直接导入模板。
- 代码应保持 Python/Shell lint、Wheel 外部安装、Gitleaks 与 CI 全绿；新测试结果必须来自客观外部命令/抓包观察，不写恒真 verdict。
- `README`、架构和 handoff 更新应清楚标注“Linux ↔ Linux 三节点实验互通”与“现场任意厂商设备验证 SKIP”的边界。

## 10. 交付清单

1. 新 `docs/pr3/PR3_DEV_MANUAL.md`（本文件）、`PR3_ACCEPTANCE.md`、`PR3_LAB_TOPOLOGY.md`、`PR3_REVIEW_CHECKLIST.md` 和 `CODEX_PR3_TASK.md`，作为 PR 首批规范提交。
2. `status` / `doctor` / 指定站点 initiate/rekey（若实现）及必要结构化状态/所有权模型；和 PR #2 事务兼容。
3. 三节点隔离实验自动搭建/销毁脚本、真实 Peer 配置、有限 UDP/TCP test helper，输出脱敏机器可读测试记录；GitHub workflow 附 artifacts。
4. PR #3 新增验收项和 PR #1/#2 全量回归；每个测试必须给出 PASS/FAIL/SKIP/STOP + 证据，不能用“本地通过”无记录。
5. 清晰技术限制、维护窗口/故障恢复及未验证项清单。不得修改生产，Draft PR 等待人工审查。

## 11. 官方技术参考（Codex 应查阅相应 5.9 版本）

- strongSwan 5.9 route-based VPN / XFRM：<https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html>
- strongSwan 5.9 swanctl 配置：<https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html>
- strongSwan swanctl `--list-sas` / `--initiate` / `--terminate`：<https://docs.strongswan.org/docs/latest/swanctl/swanctlListSas.html> / <https://docs.strongswan.org/docs/latest/swanctl/swanctlInitiate.html> / <https://docs.strongswan.org/docs/latest/swanctl/swanctlTerminate.html>
- strongSwan rekey：<https://docs.strongswan.org/docs/latest/config/rekeying.html>
- strongSwan 5.9 forwarding / PMTUD / MSS：<https://docs.strongswan.org/docs/5.9/howtos/forwarding.html>
- PR #2 代码基线：<https://github.com/yikkrrtykj/ipsecVPN/tree/1bdfdb7fe17a2c959a0859856824eadf8f1ceae6>

**文档中的算法、命令和行为必须以实验中 Ubuntu 24.04 实际安装的 strongSwan 5.9.x 进行核实；不得把最新版文档新增能力当作 5.9.x 已支持。**
