# PR #3 人工审核清单

本文件用于人工审核 Codex 的 **Draft PR**，不属于代码自动合并授权。

- [ ] base 和 merge-base 都是 `1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`；所有修改在 PR #3 分支，无生产部署。
- [ ] 规范文件作为首提交纳入 PR，代码保持泛用站点、网段、地域、厂商参数，不出现当前某场比赛的强制常量。
- [ ] 旧 PR #2 73 pytest、QEMU V/F/L 及安全安装重装恢复用例继续运行；无删除旧断言掩盖回归。
- [ ] 三节点实验是真实独立 IKE/XFRM 双端（各自 charon 进程/网络栈），不是 mock 伪成功；实验外网隔离且可销毁。
- [ ] `assert_exclusive_ike` 改动仍然拒绝外来/未知 SA、kernel state/policy、未验证 IKE daemon/socket；仅属于项目的 SA 获准操作。
- [ ] 不依赖固定 SPI 作为归属；rekey 短暂重叠、双端同时 rekey 的状态切换有实际数据及安全门禁。
- [ ] `swanctl --load-all --clear` 在活 SA 场景已处理或替换，任何可能破坏业务的配置更改都需要维护窗口显式确认。
- [ ] `apply --same-config` 活 SA 必须 NOOP，不产生意外重协商；影响业务变更有备份/恢复或 STOP_FOR_MANUAL。
- [ ] A→B、B→A 均由真正 LAN host 发起 UDP 与 TCP，并在 Hub 两 XFRM 上观察到流量、源 IP 不变且无 SNAT。
- [ ] 两站多 CIDR/selector narrowing 和未经授权 LAN 都验证过；未通过时不显示业务 PASS。
- [ ] 真实抓包 WAN 无受保护 LAN 明文数据；XFRM/SA 缺失时仍 fail-closed，重启和异常期间同样成立。
- [ ] MTU/PMTUD 测试有 DF/ICMP/xfrm_stat 证据；无真实测量不能写“最佳 MTU”；若新增 MSS/MTU 变更严格限制到项目范围和回滚。
- [ ] status/doctor 默认只读，不主动探测、删除 SA、重启 daemon；结果是分层的 PASS/FAIL/SKIP/STOP，而非一个 online 布尔值。
- [ ] 所有秘密、PSK、ESP key 不在代码、日志、JSONL artifact、pcap、stdout/stderr；无原始 `ip xfrm state` 敏感导出。
- [ ] PR #3 里没有自动操作山石、腾讯云或其它外部备 VPN，没有擅自部署到 V.PS。
- [ ] 实验的 PASS/FAIL/SKIP/STOP 逐项附 CI/日志/哈希/准确节点及接口，标注 Linux 实验验证与现场 SKIP 的差别。
- [ ] 最终 PR 保持 Draft，人工审查后再考虑普通 Merge commit。

**特别阻塞条件：** 只要存在未知内核 SA/policy 而更新仍继续、默认路由明文泄漏、只测 Hub 自身/单方向却报告两站互通、在活 SA 更新时不能证实旧业务恢复却报告 RESTORED，立即要求修复并继续保持 Draft。
