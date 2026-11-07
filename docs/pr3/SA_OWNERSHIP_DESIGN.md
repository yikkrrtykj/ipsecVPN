# 活动 SA 的所有权与操作边界

PR #2 的事务只能装载无活动 SA 的配置。原 `assert_exclusive_ike` 检查 daemon 和空 SA，`Resources.verify` 也要求空 SA。保留该入口用于安装、启动恢复和任何装载路径，除非该路径先完成下述归属和事务门禁。strongSwan 5.9.13 的 `--load-all --clear` 会清除 VICI 管理的共享凭据和其它凭据，再从文件重装。活动路径不能把此命令当作单条连接的更新。 [VICI 5.9.13 命令与事件](https://github.com/strongswan/strongswan/blob/5.9.13/src/libcharon/plugins/vici/README.md)

| 状态 | 联合证据 | 操作边界 |
| --- | --- | --- |
| EMPTY | 当前 daemon、全量 VICI、内核 SA 和全局策略表已确认；SA 和策略均空 | 经原有预检装载，按站点发起 |
| OWNED | 安装、活动配置、daemon PID 和 VICI 对端凭证一致；IKE、CHILD 和内核完整匹配；XFRM、路由和 ACL 已验证 | 只读、同配置 NOOP、显式目标化协议操作 |
| TRANSITION | rekey 或其它过渡中 VICI 与内核的稳定快照无法取得 | 短时间重采样；证据收敛后继续，否则 STOP。未关联的旧新对象不作写入授权 |
| UNOWNED | 多出连接、身份、SPI、reqid、if_id、选择器或策略超出项目证明 | 保留对象，任何会改变部署或 SA 的操作 STOP |
| UNKNOWN | 无法查询、解析不完整或策略无法核实 | STOP。记录有证据的层次 |

一次读取先确认发行版 daemon、私有配置环境和独占监听。Unix socket 的 peer PID 与 systemd 主进程绑定。两次 VICI 读数包夹无密钥的内核读取。仅比较身份、协议和 SA 结构，动态包计数不影响一致性。CHILD 的两个 SPI 与方向分别匹配内核，策略逐项比对方向、网段笛卡尔积、外层地址、reqid、if_id 和 ESP tunnel 模板。检查的是作用于转发的全局 SPD，排除仅作用于单个 socket 的本机策略。初始 IKE_AUTH 的 CHILD 复用 IKE 的密钥协商，VICI 此时可能没有单独的 CHILD DH 字段。 [strongSwan 5.9.13 VICI 实现](https://github.com/strongswan/strongswan/blob/5.9.13/src/libcharon/plugins/vici/vici_query.c) · [iproute2 6.1 SPD 枚举](https://github.com/iproute2/iproute2/blob/v6.1.0/ip/xfrm_policy.c)

活 SA 同配置判断同时检查已登记的 PSK 摘要、配置和资源，整个过程只读。目标化 rekey 或停止使用快照内的唯一 ID，避免按可能重用的配置名批量操作。真正维护路径须先写持久快照和 journal，再启用项目闭锁保护，之后方可处理已验证的项目连接。未知的内核对象不会被强制清理。

回滚报告将配置恢复、SA 状态与业务证据分开。现场断开或未发送真实双向探针时，不能标记业务恢复或业务 UP。
