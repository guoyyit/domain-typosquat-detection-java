# 域名仿冒检测与封禁管理服务

基于 Spring Boot 3 / Java 17 实现的域名 typosquatting 检测、判定与处置服务。
判定结果**确定性可复现**，处置状态**可追溯、可在重启后恢复**。

## 一、域名归一化与确定性比对

所有输入域名先经 `DomainNormalizer` 归一化后再参与比对：

- 大小写统一为小写；
- 去除根尾点（`example.com.` → `example.com`）；
- 去除协议前缀（`http://` / `https://`）与端口（`:8080`）；
- 去除路径、查询串、用户信息（`user@`）；
- Unicode 域名经 `IDN.toASCII` 统一转为 punycode ASCII 形式；
- 同形字符判定额外保留一份 Unicode 视觉形式（`normalizeUnicode`），
  因此 Cyrillic/Greek 等同形替换即使在 punycode 下也能被识别。

确定性保证：特征命中集合、排序（按 `FeatureType` 枚举序）与综合分数
只依赖输入与当前配置，不依赖时间、线程调度或字典迭代哈希顺序；
受保护域名取最高分，平分时按受保护域名字典序取较小者，保证稳定。

## 二、仿冒特征与判定语义

针对每个受保护域名的可注册主域（最后两个标签）计算下列特征：

| 特征 | 触发条件（默认配置） | 默认权重 |
| --- | --- | --- |
| `EDIT_DISTANCE` | 主标签 Levenshtein 距离 ≤ `edit-distance-threshold`（默认 2），且非纯插删 | 0.40 |
| `INSERT_DELETE` | 距离 ≤ `insert-delete-threshold`（默认 1）且仅由插入/删除构成 | 0.35 |
| `HOMOGLYPH` | 视觉同形骨架归并后距离 ≤ `homoglyph-threshold`（默认 1），且确含同形字符 | 0.60 |
| `TLD_SWAP` | 主标签相同但顶级域不同 | 0.30 |
| `BRAND_AFFIX` | 主标签（或其同形骨架）包含品牌词且带有额外前缀/后缀 | 0.50 |
| `SUBDOMAIN_DISGUISE` | 品牌标签出现在子域位置（如 `paypal.evil.com`） | 0.45 |

- 综合分数 = 命中特征权重之和（每特征对单一受保护域名至多计一次）。
- 风险等级：`score >= high-score-threshold`（默认 0.80）为 `HIGH`；
  `>= medium-score-threshold`（默认 0.50）为 `MEDIUM`；否则 `LOW`。
- 判定结果 `Verdict` 含每个命中特征的类型、对应受保护域名、权重、贡献分与文字说明。

## 三、受保护域名运行期维护

`ProtectedDomainService` 支持新增 / 修改 / 删除，所有变更：

- 在单个写事务内更新并**原子持久化**，对后续检测立即生效；
- 与并发检测通过 `ReentrantReadWriteLock` 读写锁隔离，互不阻塞读一致性；
- 不影响历史判定：历史 `Verdict` 独立保留，仍可按域名查询。

## 四、批量检测的规模控制

`BatchDetectionService`：

- 单批条目数受 `domguard.max-batch-size` 限制，超限直接拒绝整批；
- 固定大小线程池，并发度受 `domguard.batch-concurrency` 约束（资源上界）；
- 每条目在独立线程执行并受 `domguard.per-item-timeout-millis` 超时控制；
- 单条失败或超时只影响该条（返回 `error`），不影响其余条目；
- 结果 `BatchItemResult` 与输入下标一一对应，并按下标排序返回。

## 五、封禁名单状态转换与可追溯状态链

系统为每个曾被封禁的域名维护一条**只追加、永不覆盖**的封禁状态链
（`StatusTransition`，保存在 `StateData.blockStatusChain`）。
封禁、过期、解封、重新封禁在**全部处置路径**上都可追溯，
过期清理与人工解封均不删除历史。

### 5.1 状态与动作

封禁生命周期状态 `BlockStatus`：

| 状态 | 含义 |
| --- | --- |
| `BLOCKED` | 当前处于生效封禁 |
| `EXPIRED` | 封禁到期被清理，当前不封禁但保留历史 |
| `UNBLOCKED` | 人工解封（含白名单申诉解除），当前不封禁但保留历史 |

状态链动作（`StatusTransition.action`）：

| 动作 | 状态转换 | 操作者 |
| --- | --- | --- |
| `BLOCK` | `null → BLOCKED`（首次封禁，变更前为「从未封禁」） | 调用方 / `system` |
| `REBLOCK` | `EXPIRED` 或 `UNBLOCKED → BLOCKED`（再次命中重新封禁） | 调用方 / `system` |
| `EXPIRE` | `BLOCKED → EXPIRED`（TTL 到期） | `system` |
| `UNBLOCK` | `BLOCKED → UNBLOCKED`（人工解封 / 白名单申诉） | 调用方 |

完整转换规则：

- 首次封禁产生 `BLOCK`；对已过期或已解封域名再次封禁产生 `REBLOCK`，
  历史记录原样保留，链上仅追加新节点；
- `cleanupExpired` 对每个到期条目追加 `EXPIRE` 后再将其移出当前封禁名单，
  「当前是否封禁」与「是否曾被封禁」从此分离；
- 若检测、解封、重新封禁遇到「已到期但尚未清理」的条目，
  会在同一写事务内先补登记 `EXPIRE`（时间取 TTL 到期时刻），杜绝链断裂；
- 人工解封与白名单申诉复用同一路径：单事务内完成惰性过期补链、
  `UNBLOCK` 追加、当前封禁移除与白名单写入；
- 每条 `StatusTransition` 记录 `operator`（操作者）、`timestampMillis`
  （操作时间）、`reason`（操作原因）、`fromStatus`（变更前状态）与
  `toStatus`（变更后状态）；每个动作同时写一条同事务审计记录（`AuditRecord`）。

### 5.2 历史封禁状态的保留语义

- `BlockStatusService.wasEverBlocked(domain)` 完全由状态链推导：
  只要存在任意一条链节点即为 `true`，与当前是否封禁无关；
- 判定结果 `Verdict.previouslyBlocked` 与白名单条目
  `WhitelistEntry.previouslyBlocked` 均改为基于状态链，
  字段语义不变（仍为「是否曾被封禁」），仅修正取值，原有调用方无需迁移；
- 过期清理后或人工解封后再次检测、再次申诉，结果都如实体现「曾被封禁」；
  已过期 / 已解封域名再次命中 `HIGH` 时自动 `REBLOCK`，历史不丢失。

### 5.3 查询接口

- `GET /api/blocklist/status/{domain}`：返回
  `domain`、`everBlocked`、`currentStatus`
  （`BLOCKED` / `EXPIRED` / `UNBLOCKED` / `NEVER_BLOCKED`）与按时间排列的 `chain`；
- `BlocklistService.statusChain(domain)`：编程式查询完整状态链；
- `GET /api/blocklist` 仍只列当前生效封禁（字段语义不变）。

### 5.4 自动处置

检测为 `HIGH` 且开启 `auto-block-enabled`、未在白名单、当前未封禁时，
按 `block-ttl-millis` 自动 `BLOCK` / `REBLOCK`（操作者 `system`）。

## 六、白名单与人工覆盖

`WhitelistService.exempt(domain, operator, reason)`：

- 记录操作者、操作时间、操作理由，以及加入前是否曾被封禁
  （`previouslyBlocked`，由状态链推导），并在同一写事务内解除当前封禁；
- 申诉发生在域名已过期但未清理时，先补 `EXPIRE`；申诉时仍生效则追加 `UNBLOCK`，
  因此申诉与并发过期清理交错也不会丢失历史或断链；
- 白名单内域名不会被自动封禁，`Verdict.whitelisted = true`；
- 解除后若仍命中特征，`Verdict` 同时给出 `previouslyBlocked = true`
  与当前 `score` / `hits`，历史封禁状态与当前风险并存可见；
- `revoke(domain)` 撤销白名单。

## 七、崩溃恢复

- 全部状态（受保护字典、封禁名单、白名单、审计记录、审计序列号、历史判定）
  与**封禁状态链**一起序列化为单个 JSON 快照 `<data-dir>/guard-state.json`；
- 写入采用「写临时文件 + `ATOMIC_MOVE`（失败回退普通替换）」，
  任意写操作要么完整生效、要么沿用旧快照，不会出现部分生效状态；
- 每次封禁 / 过期 / 解封 / 重新封禁的状态变更、审计与快照写入在
  `GuardState` 的**同一个写事务（同一把写锁）**内完成，
  写入中途崩溃不会出现「状态生效但历史 / 审计丢失」；
- 启动时 `GuardState.init()` 加载快照恢复，状态与重启前一致；
- 升级兼容：老版本快照没有 `blockStatusChain` 字段也可正常读取，
  启动时据现存封禁条目与白名单的 `previouslyBlocked` 回填状态链，
  历史封禁状态不因升级丢失；
- 历史判定容量受 `max-history-records` 限制（FIFO 淘汰），保证内存有界。

### 并发语义

- `GuardState` 以 `ReentrantReadWriteLock` 串行化所有写事务；
  过期清理、检测（含自动封禁）、申诉解封、重新封禁并发发生时，
  每个状态变更都是「判定 + 改链 + 审计 + 落盘」的原子单元，
  清理动作不会影响正在进行中的其他处置，状态链始终前后衔接
  （上一条 `toStatus` 等于下一条 `fromStatus`）。

## 八、配置项（前缀 `domguard`）

| 配置键 | 默认值 | 含义 |
| --- | --- | --- |
| `edit-distance-weight` 等 `*-weight` | 见 `application.properties` | 六类特征权重 |
| `edit-distance-threshold` / `insert-delete-threshold` / `homoglyph-threshold` | 2 / 1 / 1 | 特征触发阈值 |
| `high-score-threshold` / `medium-score-threshold` | 0.80 / 0.50 | 风险分级阈值 |
| `max-domain-length` | 253 | 域名长度上界 |
| `max-batch-size` | 100 | 单批条目上限 |
| `batch-concurrency` | 8 | 批量并发线程数 |
| `per-item-timeout-millis` | 5000 | 单条检测超时 |
| `block-ttl-millis` | 604800000（7 天） | 自动/默认封禁时长 |
| `auto-block-enabled` | true | 是否对 HIGH 自动封禁 |
| `max-history-records` | 10000 | 历史判定容量 |
| `data-dir` | `./data` | 快照持久化目录 |

## 九、HTTP 接口（`/api`）

- `POST /detect`、`POST /detect/batch`：单条 / 批量检测；
- `GET|POST /protected`、`POST /protected/{id}`、`DELETE /protected/{id}`：字典维护；
- `GET /blocklist`、`GET /blocklist/status/{domain}`、`POST /blocklist/block`、`/blocklist/unblock`、`/blocklist/cleanup`；
- `GET|POST /whitelist`、`DELETE /whitelist/{domain}`；
- `GET /audit`：审计流水；`GET /history/{domain}`：历史判定。

## 十、自动化测试

- `DomainNormalizerTest`：大小写/尾点/端口/协议归一化、IDN、非法输入；
- `FeatureDetectorTest`：六类特征命中与命中结果稳定排序；
- `GuardServiceIntegrationTest`：判定确定性、字典即时生效与历史保留、
  批量失败隔离与顺序、并发封禁、过期回收与再封禁、白名单历史状态并存；
- `PersistenceRecoveryTest`：快照往返、缺失快照、原子覆盖无残留临时文件；
- `GuardStateRestartTest`：重启后状态一致、无快照冷启动；
- `BlockStatusChainTest`：过期清理后再检测（自动 `REBLOCK`）与再申诉、
  人工解封后再申诉、重复封禁完整状态链（含 `fromStatus` / 操作者 / 原因）；
- `BlockStatusRestartTest`：`BLOCK → EXPIRE → REBLOCK` 链重启后逐字节一致，
  以及老版本快照（无状态链字段）升级回填、历史不丢失、不凭空捏造历史；
- `BlockStatusConcurrencyTest`：过期清理、申诉解封、重新封禁、人工解封
  多线程交错后，每个域名历史封禁状态仍在、状态链前后衔接且不断裂。

## 十一、状态链验证方法

可按以下方式验证历史封禁状态在全部处置路径上可追溯：

1. `POST /api/blocklist/block`（带较短 `ttlMillis`）后调用
   `POST /api/blocklist/cleanup`，再 `GET /api/blocklist/status/{domain}`：
   `everBlocked` 恒为 `true`，`chain` 含 `BLOCK`、`EXPIRE`；
2. 过期后对同一高风险域名 `POST /api/detect`，再次查询状态链：
   末尾追加 `REBLOCK`（`fromStatus = EXPIRED`），此前节点不变；
3. 人工 `/blocklist/unblock` 或 `POST /api/whitelist` 申诉后：
   `Verdict.previouslyBlocked`、`WhitelistEntry.previouslyBlocked`
   与 `everBlocked` 均为 `true`，链上为 `BLOCKED → UNBLOCKED`；
4. 重启服务后重复第 1–3 步查询，`chain` 与重启前完全一致；
5. 检查 `<data-dir>/guard-state.json` 中 `blockStatusChain`：
   写入过程中仅存在 `guard-state.json` 或其 `.tmp` 之一，
   不会出现半截 JSON 或丢失历史。
