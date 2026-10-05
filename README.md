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

## 五、封禁状态链与历史封禁状态

每个域名的封禁处置构成一条**只追加、不修改、不删除**的状态链
（`BlockLifecycle` + `BlockTransition`），与触发它的状态变更在**同一写事务**内
提交并原子持久化，因此链上每条记录的变更前状态恒等于上一条记录的变更后状态
（链式闭合，不会断裂）。

### 状态与转换规则

生命周期状态：`NONE`（从未封禁）→ `ACTIVE`（生效封禁）→ `EXPIRED`（已过期）
/ `UNBLOCKED`（已解封）；`EXPIRED` / `UNBLOCKED` 可再次进入 `ACTIVE`。

| 动作 | 触发 | 变更前状态 → 变更后状态 |
| --- | --- | --- |
| `BLOCK` | 首次封禁（手动或自动处置） | `NONE` → `ACTIVE` |
| `REBLOCK` | 再次封禁（含过期/解封后重新命中高风险） | `ACTIVE`/`EXPIRED`/`UNBLOCKED` → `ACTIVE` |
| `EXPIRE` | `cleanupExpired` 清理到期条目 | `ACTIVE` → `EXPIRED` |
| `UNBLOCK` | 人工解封或白名单申诉解除生效封禁 | `ACTIVE` → `UNBLOCKED` |

每条 `BlockTransition` 记录：操作者（自动处置为 `system`）、操作时间、
操作原因、变更前状态与变更后状态。

补充语义：

- `block(domain, reason, ttlMillis)`：`ttlMillis` 为空表示永久封禁，
  否则 `expiresAt = now + ttl`；已封禁域名在过期或解封前 `isBlocked` 恒为 `true`；
- 到期后 `isBlocked` 返回 `false`；`cleanupExpired` 物理清理过期条目，
  **仅移除当前条目，状态链与「曾被封禁」标记完整保留**；
- 过期或解封后再次检测命中高风险时可重新封禁（`REBLOCK`），
  历史记录不被覆盖或丢失；
- 白名单申诉解除生效封禁时记录 `UNBLOCK`；域名已无封禁条目时申诉只写入
  白名单条目，不重复产生状态链记录；
- 读取侧的派生状态：存储状态为 `ACTIVE` 但条目已到期（尚未清理）时，
  对外呈现为 `EXPIRED`；
- 自动处置：检测为 `HIGH` 且开启 `auto-block-enabled`、未在白名单时，
  按 `block-ttl-millis` 自动封禁（操作者记为 `system`）。

### 历史封禁状态保留语义

「曾被封禁」（`Verdict.previouslyBlocked`、`WhitelistEntry.previouslyBlocked`、
`BlocklistService.wasEverBlocked`）的唯一来源是封禁生命周期，
**不再依赖当前封禁条目是否存在**。因此：

- 过期清理、人工解封、白名单撤销之后，历史封禁状态仍为真；
- 字段语义与取值类型对调用方完全不变，仅取值修正为与真实处置历史一致；
- 状态链通过 `GET /api/blocklist/lifecycle/{domain}` 查询，
  从未封禁的域名返回 `everBlocked=false`、`currentStatus=NONE` 与空链。

## 六、白名单与人工覆盖

`WhitelistService.exempt(domain, operator, reason)`：

- 记录操作者、操作时间、操作理由，以及加入前是否曾被封禁
  （`previouslyBlocked`，取自封禁生命周期，解封/过期后仍为真），
  并解除当前封禁（在状态链上记录 `UNBLOCK`）；
- 白名单内域名不会被自动封禁，`Verdict.whitelisted = true`；
- 解除后若仍命中特征，`Verdict` 同时给出 `previouslyBlocked = true`
  与当前 `score` / `hits`，历史封禁状态与当前风险并存可见；
- `revoke(domain)` 撤销白名单；撤销不影响封禁状态链，
  历史封禁状态依然可追溯。

## 七、崩溃恢复

- 全部状态（受保护字典、封禁名单、**封禁状态链**、白名单、审计记录、
  审计序列号、历史判定）序列化为单个 JSON 快照 `<data-dir>/guard-state.json`；
- 写入采用「写临时文件 + `ATOMIC_MOVE`（失败回退普通替换）」，
  任意写操作要么完整生效、要么沿用旧快照，不会出现部分生效状态；
- 启动时 `GuardState.init()` 加载快照恢复，状态链与历史封禁状态与重启前一致；
- **升级兼容**：旧版本快照缺少状态链字段时，加载阶段按封禁名单与
  白名单中的历史封禁标记自动重建生命周期（已过期条目补记 `EXPIRE`，
  白名单条目补记 `BLOCK`+`UNBLOCK`），已有持久化数据无需迁移即可读取，
  历史封禁状态不因升级丢失；
- 历史判定容量受 `max-history-records` 限制（FIFO 淘汰），保证内存有界。

### 并发一致性

过期清理与检测、申诉、重新封禁并发发生时，全部变更经 `GuardState`
单一写锁串行化，且状态链记录与状态变更同属一个写事务：

- 清理动作只移除已到期条目并追加 `EXPIRE` 记录，
  不影响正在进行中的其他处置，也不会清除历史状态；
- 任意交错顺序下状态链保持链式闭合，历史封禁状态不丢失；
- 申诉的「曾被封禁」判定与白名单写入、解封记录在同一事务内完成，
  不会出现读取到中间状态的申诉结果。

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
- `GET /blocklist`、`POST /blocklist/block`、`/blocklist/unblock`、`/blocklist/cleanup`；
- `GET /blocklist/lifecycle/{domain}`：域名封禁生命周期与完整状态链；
- `GET|POST /whitelist`、`DELETE /whitelist/{domain}`；
- `GET /audit`：审计流水；`GET /history/{domain}`：历史判定。

## 十、自动化测试

- `DomainNormalizerTest`：大小写/尾点/端口/协议归一化、IDN、非法输入；
- `FeatureDetectorTest`：六类特征命中与命中结果稳定排序；
- `GuardServiceIntegrationTest`：判定确定性、字典即时生效与历史保留、
  批量失败隔离与顺序、并发封禁、过期回收与再封禁、白名单历史状态并存；
- `BlockStateChainTest`：过期清理后再检测（历史状态保留并重新封禁）、
  过期清理后再申诉、人工解封后再申诉、重复封禁的完整状态链
  （`BLOCK→UNBLOCK→REBLOCK→EXPIRE→REBLOCK`）、过期清理与申诉/检测并发
  交错时状态链闭合且历史不丢失；
- `BlockLifecycleRestartTest`：状态链与历史判定重启后一致、白名单撤销后
  历史封禁状态仍可追溯、旧版本快照（无状态链字段）升级迁移；
- `PersistenceRecoveryTest`：快照往返、缺失快照、原子覆盖无残留临时文件；
- `GuardStateRestartTest`：重启后状态一致、无快照冷启动。

### 验证方法

1. `mvn test`：全量自动化测试覆盖上述全部场景；
2. 运行期验证：对域名依次执行封禁 →（到期后）`POST /api/blocklist/cleanup`
   → `POST /api/detect` 或 `POST /api/whitelist`，
   再 `GET /api/blocklist/lifecycle/{domain}` 应看到完整状态链，
   且判定/申诉结果中 `previouslyBlocked=true`；
3. 重启验证：重启服务后再次查询状态链接口，结果应与重启前完全一致。
