# CODEX TASK — ipsecVPN PR #3

## 0. 必须遵守

- 仓库 `yikkrrtykj/ipsecVPN`。
- **基线 `1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`，预期 merge-base 同 SHA。** 先 fetch main 校验 head，创建独立开发分支 `codex/pr3-live-ipsec-dataplane`（若已存在，检查再决定，不覆盖）及 Draft PR #3。
- 先将本套 `docs/pr3/PR3_DEV_MANUAL.md`、`docs/pr3/PR3_ACCEPTANCE.md`、`docs/pr3/PR3_LAB_TOPOLOGY.md`、`docs/pr3/PR3_REVIEW_CHECKLIST.md`、`CODEX_PR3_TASK.md` 作为规范纳入分支，再开始实现。
- 阅读 `docs/SPEC.md`、`docs/pr2/PR2_DEV_MANUAL.md`、`docs/network-ownership.md`、`ipsecvpn/{host,renderer,resources,transaction,installer,cli}.py` 和现有全部 VM 验收。**禁止简单删掉所有权/空 SA 检查。**
- 本阶段仅在独立 Ubuntu 24.04 QEMU VM / 严格隔离 network namespaces 测试。禁止生产 IP、生产 PSK、生产 VPS、真实山石、腾讯云或任何公网探测/压测；不自动合并 main。

## 1. 推荐施工顺序（每一步保留可审查提交）

**A. 静态模型与状态只读层**

1. 对当前 PR #2 的 `assert_exclusive_ike()`、`swanctl --load-all --clear`、`resources.verify()`、boot 及 recover 做风险审计，出一份 `docs/pr3/SA_OWNERSHIP_DESIGN.md`，明确无 SA、己方稳定 SA、己方 rekey 过渡 SA、外来 SA、未知 SA 的状态机和拒绝条件。
2. 实现强结构的 VICI + kernel SA/policy snapshot（只读），以及与 event、connection、IKE IDs、peer endpoints、selector、if_id、reqid、SPI、daemon/socket 所有权的联合校验。不得裸输出内核 SA key；对外 `status` / `doctor` JSON 和文本输出脱敏。
3. 将未知/外来 SA 作为负面 fixture，证明任何写操作 STOP；旧的无 SA V/F/L 测试必须保持通过。

**B. 三节点真实隔离网络实验**

4. 构建 Hub + Site A + Site B、至少各两个 LAN CIDR、可关闭的测试 peer、真实 strongSwan IKEv2 服务与独立 IPsec 内核网络栈。禁止用 mocked VICI 或同一网络命名空间的“假对端”代替。
5. 建立两个独立 IKE/CHILD，验证 peer/HUB 双端身份、selectors、XFRM SA、nft、路由。用 TCP 和 UDP 从 A LAN host→B LAN host、B→A 主动发起，抓包和 nonce/seq 证明过两个 SA、不做 SNAT。
6. 增加多 CIDR、未经授权 VLAN、错误 TS/PSK/提议、源地址伪造和数据外泄测试。实验失败不能以改成 `0.0.0.0/0` 或强制绕过规则修复。

**C. 活 SA 的生命周期**

7. 提供目标化 `initiate`、`rekey` 和受控重连的 API/CLI（若命名调整，文档一致），保证只操作验证过的项目 SA。对本端、对端与同时 rekey 的合理重叠状态保持容忍；外来 SA 依然 STOP。
8. 原 profile 的 `apply` 在活动项目 SA 下必须 NOOP，不应误 `STOP` 或重启。任何影响现有业务的 `apply --maintenance`、rollback/uninstall，要先证明所有权、备份、闭锁、受影响范围、明确确认，并对结果区分“配置已还原”与“业务确实恢复”。不满足证明就 fail-closed / STOP_FOR_MANUAL。
9. 测试 DPD、一个 peer down、Hub daemon 重启、Hub VM 完整重启、路由与 nft/VICI 故障、SIGKILL 与人工恢复，保留 SSH/默认路由/其它 VPN 资产基线。

**D. MTU / PMTUD / 诊断与交付**

10. 小包到大包、DF/PMTUD/ICMP type3 code4、分片、TCP MSS 等在三节点隔离网真实执行；记录适用范围，不得把任意固定 MTU 写成默认标准。
11. `status` / `doctor` 默认只读；有源地址/目标/路径约束的有界探针必须用户明确启用，并且只允许实验网络。未测业务只可 `SKIP/UNKNOWN`。
12. 更新 README、部署/故障排查/版本限制说明，保留所有未验证的生产场景为 SKIP。

## 2. 必须通过的回归与新验收

- 所有原有 pytest、Ruff、ShellCheck、4 份配置、wheel-outside-checkout、Gitleaks，以及 PR #2 的 C01–C10、V01–V20、F01–F14、L01–L04（如用例重构需提供同等级完整性证据）。
- `PR3_ACCEPTANCE.md` 中的 C01–C14、T01–T14、S01–S10、N01–N06、F01–F16；每项明确执行状态，不能缺测后统一写 PASS。
- 真正三节点实验：两条站点 IKE SA、对应 CHILD SA、两边 kernel SA/policy、双向 UDP/TCP、Hub XFRM-A↔XFRM-B、多 CIDR、原始 LAN IP 不变、WAN 无业务明文、故障 fail-closed。
- Liveness：活动 SA 下 `status/doctor` 和同配置 apply 是只读/NOOP；本端/对端 IKE+CHILD rekey，DPD/掉线恢复；外来 SA 拒绝变更；维护变更失败不会误报 RESTORED。
- MTU：必须存在真实 DF/ICMP/fragment/xfrm_stat 证据；必要时先发现、再独立设计可选 MSS/MTU，绝不能跨设备全局改动。

## 3. 必须保留为 SKIP 的范围

- 真实 Hillstone/其它品牌防火墙互操作与现场工程配置。
- 真实跨境线路及 PUBG 或其他赛事业务的 SLA、时延、丢包与断流时间。
- 外部腾讯云/其他备 VPN 的路由 Track 与自动切换。
- Prometheus/Grafana/Feishu 告警（PR #4），以及生产部署批准。

## 4. 每轮开发的产出与收尾

在 Draft PR 描述中写入：

```text
PR #3: <URL> (Draft)
base/merge-base: 1bdfdb7fe17a2c959a0859856824eadf8f1ceae6
head: <SHA>
PASS: C..., T..., S..., N..., F...（CI/job/artifact 和脱敏证据）
FAIL: ...
SKIP: ... （逐项原因）
STOP: ... （仍未解除的阻断）
SA ownership model: <path>
VM isolation proof: <path>
Actual 2-way UDP/TCP/XFRM capture proof: <path>
MTU/PMTUD result: <path>
Rekey/DPD/crash-recovery: <path>
SSH/default-route/foreign nft baseline: <path>
Gitleaks: <result>
No production deployment. Draft only; no merge.
```

若关键验收未完成或 FAIL/STOP 存在，不要以超时/缺权限为由跳过且报告已完工；在同一个 Draft PR 如实记录未完成项，结束本轮等待人工审查。**不要自动开始 PR #4。**
