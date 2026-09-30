# 域名仿冒检测与封禁管理服务

基于 Spring Boot 3 / Java 17 的服务，对恶意域名常见的字符替换、拼写变体、
顶级域替换、品牌词拼接与子域伪装进行确定性检测、评分、封禁处置、
白名单申诉、批量隔离与崩溃恢复。

## 构建与运行

```bash
mvn spring-boot:run          # 启动服务（默认端口 8080）
mvn test                     # 运行全部自动化测试
```

状态文件默认写入工作目录下的 `data/state.json`（可用配置项覆盖，
该目录已加入 `.gitignore`）。

## 归一化与确定性

所有域名在参与比对前统一经 `DomainNormalizer` 归一化：

1. 去除首尾空白；
2. 识别并剥离协议（`scheme://`，含无 scheme 的 `//` 形式）、用户信息
   （`user:pass@`）、端口、路径与查询串；
3. 去除全部尾点；
4. 每个标签先经 `IDN.toASCII`（Unicode → Punycode ASCII），再按 Root Locale
   小写化；非法字符（空格等）抛出 `IllegalArgumentException`。

因此 `https://PayPal.COM:443/`、`paypal.com.`、`paypal.com` 归一化结果完全一致；
西里尔/希腊等 Unicode 域名得到稳定的 `xn--` ASCII 形式。检测只依赖
归一化结果 + 当时的受保护集合快照，相同输入必得相同命中特征与分数。

## 判定特征与评分

检测引擎按 `FeatureType` 固定枚举顺序执行六个检测器，命中特征分数求和，
并以 `max-score`（默认 100）封顶：

| 特征 | 触发条件（相对某受保护域名） | 默认权重 |
| --- | --- | --- |
| `EDIT_DISTANCE` | 同顶级域，注册主体 Levenshtein 距离 ∈ [1, `max-distance`]（默认 2） | 40 |
| `INSERT_DELETE` | 同顶级域，仅经 ≤ `max-distance`（默认 2）次插入/删除可达（不允许替换） | 30 |
| `HOMOGLYPH` | 含 `xn--` 标签，且同形字符骨架与受保护主体相同或距离 ≤ 1 | 60 |
| `TLD_SWAP` | 最左标签相同，仅顶级域不同（如 `paypal.org`） | 25 |
| `BRAND_AFFIX` | 最左标签完整包含品牌词且有额外前缀/后缀（如 `login-paypal`、`paypal-secure`） | 70 |
| `SUBDOMAIN_DISGUISE` | 品牌词/受保护主机出现在子域标签，而末两级注册主机不同（如 `paypal.evil.com`） | 75 |

“注册主体/主机”采用确定性近似：最左标签 + 末级标签参与主体比对，
末两级标签（如 `evil.com`）参与子域伪装判定；不依赖外部公共后缀列表。
同形映射表在 `ConfusableMapper` 中固定维护（西里尔、希腊、重音拉丁、全角）。

综合分数 → 判定结论：

- `score >= block-threshold`（默认 70）→ `TYPOSQUATTING`
- `score >= suspicious-threshold`（默认 40）→ `SUSPICIOUS`
- 其余 → `SAFE`

每条判定结果包含：记录 id、原始输入、归一化域名、结论、总分、按固定顺序排列的
命中特征（类型/分数/可复现的命中说明），以及 `whitelisted`、`currentlyBanned`、
`previouslyBanned` 三个状态标记与时间戳。

## 白名单与风险共存

白名单只影响处置，不改变风险结论。误报申诉通过白名单解除时，记录操作者、
时间与理由，并把生效中的封禁置为 `LIFTED`。解除后再次检测若仍命中高风险特征，
结论仍为 `TYPOSQUATTING`，同时 `whitelisted=true`、`currentBanned=false`、
`previouslyBanned=true`，风险与历史封禁状态同时可见。

## 封禁状态转换

```
            ban()                       expiresAt 到期（定时/惰性回收）
   (无记录) ──────▶ ACTIVE ───────────────────────────────────────▶ EXPIRED
                     │  ▲                                             │
        unban()/     │  │ 再次检测命中后 ban()（过期记录保留，          │
        whitelist()  │  └ 产生一条全新 ACTIVE 记录，可重新封禁）        │
                     ▼                                               │
                   LIFTED ◀───────────────────────────────────────────┘
              （人工解封/申诉解除；不可再“放行”，仅作历史标记）
```

- `ACTIVE`：在 `expiresAt` 前拦截（`isAllowed=false`）；封禁幂等，并发重复封禁
  只产生一条 ACTIVE 记录。
- `EXPIRED`：到期自动回收；保留记录用于 `previouslyBanned` 标记；再次命中可重新
  封禁为新的 ACTIVE 记录。
- `LIFTED`：人工解封或白名单解除；同样保留历史。
- 回收由定时任务（间隔可配置）与写路径上的惰性回收双重保证。

## 受保护集合的运行期维护

新增/修改/删除在写锁内提交并立即整体持久化，之后的检测读到的是不可变快照，
字典变更与并发检测互不干扰。已经落盘的历史判定不会被字典变更改写：
删除品牌前判定为 `SUSPICIOUS` 的记录，在删除后仍可按域名/记录 id 查询。

## 批量检测

- 单批条目数受 `batch.max-batch-size`（默认 100）限制，超限返回 HTTP 413；
- 固定大小线程池 + 信号量把并发度约束在 `batch.concurrency`（默认 4）；
- 每条检测受 `batch.timeout-millis`（默认 5000ms）约束，超时记为该条 error；
- 任一条失败/超时只体现在对应下标，其余条目照常判定；结果 `index/input` 与输入
  逐条对齐，顺序不变。

## 持久化与崩溃恢复

品牌字典、封禁名单、白名单与审计（历史判定）聚合为单个 `AppState`：

- 每次变更在写锁内修改内存状态，写入同目录唯一临时文件后 `ATOMIC_MOVE`
  （文件系统不支持时退化为 replace move）替换 `data/state.json`；
- 写入中途崩溃时 move 尚未发生，重启后读到的仍是上一个完整版本，
  不会出现部分生效的状态；
- 状态带单调递增 `version` 与 `updatedAt`，重启后内存状态与重启前一致。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/detect` | 单条检测，body `{"domain":"..."}` |
| POST | `/api/detect/batch` | 批量检测，body `{"domains":["..."]}` |
| GET | `/api/protected` | 列出受保护域名 |
| POST | `/api/protected` | 新增，body `{"domain","brand?"}` |
| PUT | `/api/protected/{id}` | 修改 |
| DELETE | `/api/protected/{id}` | 删除 |
| POST | `/api/bans` | 封禁，body `{"domain","reason?","ttlMillis?"}` |
| DELETE | `/api/bans?domain=...` | 人工解封 |
| GET | `/api/bans` | 封禁记录（含历史状态） |
| POST | `/api/whitelist` | 申诉解除，body `{"domain","operator","reason"}` |
| DELETE | `/api/whitelist?domain=...` | 撤销白名单 |
| GET | `/api/whitelist` | 白名单及审计信息 |
| GET | `/api/history?domain=...` | 历史判定（不带 domain 返回全部） |
| GET | `/api/history/{id}` | 按记录 id 查询历史判定 |

## 配置项（前缀 `typosquat.detection`）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `suspicious-threshold` | 40 | 可疑阈值 |
| `block-threshold` | 70 | 仿冒阈值 |
| `max-score` | 100 | 综合分上限 |
| `edit-distance.enabled` / `.weight` / `.max-distance` | true / 40 / 2 | 编辑距离特征 |
| `insert-delete.enabled` / `.weight` / `.max-distance` | true / 30 / 2 | 插入删除特征 |
| `homoglyph.enabled` / `.weight` | true / 60 | 同形字符特征 |
| `tld-swap.enabled` / `.weight` | true / 25 | 顶级域替换 |
| `brand-affix.enabled` / `.weight` | true / 70 | 品牌前后缀 |
| `subdomain-disguise.enabled` / `.weight` | true / 75 | 子域伪装 |
| `batch.max-batch-size` | 100 | 单批最大条目 |
| `batch.concurrency` | 4 | 批量并发上限 |
| `batch.timeout-millis` | 5000 | 单条超时 |
| `ban.default-ttl-millis` | 86400000 | 默认封禁有效期（1 天） |
| `ban.cleanup-interval-millis` | 60000 | 过期回收周期 |
| `persistence.dir` | data | 状态文件目录 |

## 测试覆盖

- `DomainNormalizerTest`：大小写、尾点、协议/端口/路径剥离、Unicode→ASCII 稳定性；
- `LevenshteinUtilTest` / `ConfusableMapperTest`：距离与同形骨架的确定性；
- `DetectionFeatureTest`：六类特征命中、阈值结论、可复现、分数封顶与说明；
- `BatchDetectionServiceTest`：逐条对齐、单条失败隔离、空批、超批拒绝；
- `EnforcementServiceTest`：封禁/解封、过期回收再封禁、白名单审计、
  并发封禁幂等、并发读写一致性；
- `WhitelistRiskTest`：解除后高风险结论与历史封禁状态并存；
- `PersistenceRecoveryTest`：重启后状态一致、字典变更后历史仍可查询、
  崩溃残留临时文件不破坏已提交状态。
