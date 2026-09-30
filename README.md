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

## 五、封禁名单状态转换

`BlocklistService` 的封禁、解封、过期清理、查询可并发进行（读写锁保护）：

- `block(domain, reason, ttlMillis)`：`ttlMillis` 为空表示永久封禁；
  否则 `expiresAt = now + ttl`；
- 已封禁域名在过期或人工解封前 `isBlocked` 恒为 `true`，不会被放行；
- 到期后 `isBlocked` 返回 `false`；`cleanupExpired` 物理清理过期条目；
- 过期条目被清理后，再次检测命中高风险时可重新封禁（同一条目可复活）；
- 自动处置：检测为 `HIGH` 且开启 `auto-block-enabled`、未在白名单时，
  按 `block-ttl-millis` 自动封禁。

## 六、白名单与人工覆盖

`WhitelistService.exempt(domain, operator, reason)`：

- 记录操作者、操作时间、操作理由，以及加入前是否曾被封禁
  （`previouslyBlocked`），并解除当前封禁；
- 白名单内域名不会被自动封禁，`Verdict.whitelisted = true`；
- 解除后若仍命中特征，`Verdict` 同时给出 `previouslyBlocked = true`
  与当前 `score` / `hits`，历史封禁状态与当前风险并存可见；
- `revoke(domain)` 撤销白名单。

## 七、崩溃恢复

- 全部状态（受保护字典、封禁名单、白名单、审计记录、审计序列号、历史判定）
  序列化为单个 JSON 快照 `<data-dir>/guard-state.json`；
- 写入采用「写临时文件 + `ATOMIC_MOVE`（失败回退普通替换）」，
  任意写操作要么完整生效、要么沿用旧快照，不会出现部分生效状态；
- 启动时 `GuardState.init()` 加载快照恢复，状态与重启前一致；
- 历史判定容量受 `max-history-records` 限制（FIFO 淘汰），保证内存有界。

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
- `GET|POST /whitelist`、`DELETE /whitelist/{domain}`；
- `GET /audit`：审计流水；`GET /history/{domain}`：历史判定。

## 十、自动化测试

- `DomainNormalizerTest`：大小写/尾点/端口/协议归一化、IDN、非法输入；
- `FeatureDetectorTest`：六类特征命中与命中结果稳定排序；
- `GuardServiceIntegrationTest`：判定确定性、字典即时生效与历史保留、
  批量失败隔离与顺序、并发封禁、过期回收与再封禁、白名单历史状态并存；
- `PersistenceRecoveryTest`：快照往返、缺失快照、原子覆盖无残留临时文件；
- `GuardStateRestartTest`：重启后状态一致、无快照冷启动。
