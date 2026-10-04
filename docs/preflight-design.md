# 上线前预检（Preflight）设计

## 1. 要解决的问题

脱敏策略正式执行前，没人知道：

- 这次会动多少行（范围过滤条件写错 → 全表）
- 被改列在真实数据上变成什么形态（基数坍塌、join 键失效）
- 哪些下游报表/任务会读到被改的列
- 改完才发现"报表全塌了"

预检子系统在**不修改任何数据、不长时间占用源端、不把原始值落盘**的前提下，给出受影响行数、列、下游消费方和风险结论；并且保证**预检结论与真正执行的范围严格一致，执行参数变了必须重新预检**。

## 2. 总体流程

```
policy + dataset + scope(过滤条件) + salt + 预算参数
                │
                ▼
        编译执行范围（列名白名单 + 参数化 SQL）
                │
        ┌───────┴────────┐
        ▼                ▼
 只读探针(ro 连接)   血缘目录(纯元数据)
 COUNT/聚合/抽样      列级消费者边
        │                │
        └───────┬────────┘
                ▼
            风险引擎
   行数 / 列变化 / 基数坍塌 / 下游断裂
                ▼
        票证(ticket, 仅聚合值)
        含分段指纹 + 水位线 + 有效期
                ▼
        执行守卫（逐段比对）
        通过 → 事务内 UPDATE
        实际变更行数 != 预检行数 → 回滚
```

## 3. 输入与执行范围（scope）

执行范围是一棵过滤条件树，与策略定义分离、随每次执行/预检请求传入：

```json
{
  "filters": [
    {"op": "eq", "column": "region", "value": "cn"},
    {"op": "between", "column": "updated_at", "values": ["2026-09-01", "2026-09-30"]}
  ]
}
```

- 支持 `eq/ne/gt/ge/lt/le/in/between`，全部编译成**参数化**谓词（`?` 绑定值），杜绝注入。
- 列名必须命中 dataset 已声明字段，只允许 `[A-Za-z0-9_]`，并通过方言安全引号包裹。
- 预检和执行共用同一个 `compile_scope()`（`maskhub/preflight/scope.py`），从源头保证"看的就是要改的"。

## 4. 真实数据形态：只读探针与聚合画像

代码：`maskhub/preflight/probe.py`、`profiler.py`、`transform.py`

### 4.1 原始值不落盘、不出库

- 探针以 `mode=ro` 打开连接；即使上层逻辑出错，语句也无写权限（测试 `test_probe_is_read_only` 验证）。
- SQL 守卫只允许单条 `SELECT/WITH`：拒绝分号、注释、引号不配对、非查询语句。
- 脱敏变换（redact / hash / partial / tokenize）以 **UDF 注册在数据库进程内**，变换后的表达式直接参与聚合；没有任何 `SELECT 原始列` 取回客户端的路径。
- 票证和日志只记录：行数、非空数、真实变化行数、变换前后 distinct 数、粗粒度长度桶（`null/0-4/4-8/…/64+`）。原始值、脱敏后的具体值都不落盘（测试 `test_ticket_never_contains_raw_values` 扫描票证文件断言）。

### 4.2 分层扫描，不占源端太久

- **行数永远精确且廉价**：一条 `COUNT(*)` 谓词查询拿 scope 行数、表总行数。
- 范围行数 ≤ `scan_budget_rows`（默认 5 万）：单条聚合查询拿全部列画像（一次扫描算完所有列，带超时）。
- 范围行数超预算：列画像切换为**确定性 rowid 等距抽样**，计数仍精确，分布指标标记 `sampled` 并给出 `sample_scale`；风险结论追加 `PROFILE_SAMPLED`。
- `deadline_ms`（默认 3s、上限 30s）通过 SQLite progress handler 中断长查询；超时则保留精确行数、列指标标 `incomplete`（`PROFILE_INCOMPLETE`），不让整个预检失败。

### 4.3 画像指标（每列）

| 指标 | 用途 |
|---|---|
| `non_null_in_scope` | 空值占比 |
| `changed_rows` | 应用规则后**实际发生变化**的行数（已脱敏的旧数据会识别为 no-op：`CHANGE_LOW`） |
| `distinct_before/after`、`distinct_ratio_after` | 基数坍塌（`CARDINALITY_COLLAPSE`，阈值 <0.5） |
| `length_buckets` | 粗粒度真实形态，不泄露值 |

## 5. 下游消费方（列级血缘）

代码：`maskhub/lineage/`

消费者声明"读哪个 dataset 的哪一列、怎么用"：

```json
{
  "identifier": "risk-join", "kind": "model", "owner": "risk",
  "reads": [{"column": "customer.id_card", "usage": "join_key"}]
}
```

用法分级决定同一列脱敏对下游的破坏程度：

| usage | redact | hash/tokenize/partial |
|---|---|---|
| `join_key` | **block**（不可逆，join 必然断） | high（只有所有关联侧同 salt/同算法一起切才不断） |
| `filter` | high | medium |
| `metric`（COUNT DISTINCT/分组） | medium | medium |
| `passthrough` | low | low |

只有读取**被改列**的消费者进入影响面（读未改动列的消费者不出现，测试覆盖 `region-segments` 用例）。

## 6. 风险结论与处理建议

代码：`maskhub/preflight/risk.py`

发现项（finding）带稳定 id（`代码:主体`）、严重级别和可执行建议：

- `SCOPE_EMPTY`：0 行命中（info）
- `BLAST_HIGH/MEDIUM`：范围占全表 ≥50% / ≥10% → 建议维护窗口、先快照、分区灰度
- `CARDINALITY_COLLAPSE`：distinct 坍塌 → 建议保基数规则或协调报表口径
- `DOWNSTREAM_BREAK:<consumer>`：按上表分级，建议 join 协同切换 / 影子列 / 报表回填
- `SENSITIVE_UNCOVERED`：范围内敏感列无规则覆盖（high）
- `CHANGE_LOW`：该列实际几乎不变（规则模式可能没匹配上）
- `PROFILE_SAMPLED/INCOMPLETE`：估计或不完整

汇总为三档：

- **BLOCK**：存在 block 级 finding；执行必须显式携带对每个 block finding id 的 `waivers`（审计记录），否则 409。
- **WARN**：存在 high/medium；可执行，附建议清单。
- **GO**：仅 low/info。

## 7. 预检与执行的一致性保证

代码：`maskhub/preflight/fingerprint.py`、`ticket.py`、`guard.py`、`executor.py`

### 7.1 分段指纹：参数变了必须重新预检

票证不保存可执行参数本身，而是保存每个输入段的 SHA-256：

`policy / rules / dataset / scope / lineage / options(预算+deadline) / salt(只存哈希) / engine(变换算法版本)`

执行时守卫用**当前注册表和请求参数**重新计算并逐段比对，且报错会指出漂移的是哪一段：

- 改过滤条件/范围值 → `scope` 漂移 → 409
- 改 salt（hash/tokenize 的密钥）→ `salt` 漂移 → 409（salt 本身是敏感值，只以哈希进票证）
- 改规则参数、换策略 → `rules`/`policy` 漂移 → 409
- 新增/修改下游消费者 → `lineage` 漂移 → 409
- 调整扫描预算/deadline（决定结论是精确还是抽样）→ `options` 漂移 → 409
- 升级脱敏算法 → `engine` 版本漂移 → 409

### 7.2 数据水位线：源端数据变了票证作废

dataset 可声明 `watermark_column`（如 `updated_at`）。预检时只读探测其 `MAX`，执行前重测；不一致即拒绝：

```
source data changed (watermark '2026-09-01' -> '2026-10-04'); re-run preflight
```

另有 24h（可配 `ttl_seconds`）有效期。

### 7.3 执行时行数复核：最后一道闸

执行器在一个 `BEGIN IMMEDIATE` 事务内用与预检**相同的编译谓词、相同的 UDF 绑定**做 UPDATE，并比对数据库报告的匹配行数与票证精确行数；不一致立即回滚（`ExecutionMismatch`）。基于抽样画像签发的票证禁止执行（无法保证精确行数）。

## 8. 预检本身的安全约束汇总

| 约束 | 实现 |
|---|---|
| 不修改数据 | `mode=ro` 连接 + SQL 单 SELECT 守卫；全流程只有聚合语句 |
| 不占用源端太久 | 精确计数 + 预算内单遍聚合；超预算确定性抽样；deadline 中断；默认 3s |
| 原始值不落盘 | 变换在库内 UDF 完成；票证只存数字和粗桶；salt 只存哈希 |
| 结论与执行一致 | scope 编译共用；8 段指纹；水位线；事务内行数复核 |
| 参数变更强制重检 | 守卫按当前输入重算指纹，逐段比对 |
| 不可绕过 | 执行端点必须持票；block 需显式 waiver；全部动作进审计 journal |

## 9. HTTP 接口

| 方法/路径 | 说明 |
|---|---|
| `POST /consumers` / `GET /consumers` / `POST /consumer/remove` | 血缘消费方维护 |
| `POST /preflight/run` | 入参 `policy, dataset, scope, salt, scan_budget_rows, deadline_ms, ttl_seconds`；返回票证 |
| `GET /preflight/ticket?ticket=` / `GET /preflight/tickets` | 查询票证 |
| `POST /policy/execute` | 入参 `ticket, scope(可省略则回放票证范围), salt, waivers[]`；守卫通过才执行 |

审计动作：`preflight.run`、`policy.execute`（含 policy/dataset/结论/行数/列数/下游数/是否抽样）。

## 10. 扩展到其他源类型

当前落地了 SQLite 适配器（`probe.py` 的 `SqliteProbe` + `executor.py`）。接入 MySQL/Hive/数仓时只需实现同样的两个接口：

- 探针：只读账号、聚合下推、查询超时、抽样谓词（各引擎用自己的采样语法）；优先读从库/只读副本；
- 执行器：事务 UPDATE + affected rows 回读。

预算/抽样/指纹/守卫/风险引擎全部源无关，不需要改动。生产建议：预检路由到只读副本或表快照，水位线从分区元数据取，大表计数优先走分区统计而不是 `COUNT(*)`。

## 11. 测试

`tests/test_preflight.py`（14 例）+ `tests/test_preflight_http.py`（4 例），全部基于临时真实 SQLite 源，覆盖：

精确影响面（行/列/distinct/长度桶）、下游分级、BLOCK+waiver、WARN 放行、执行后南北分区对比、票证无原始值、scope/salt/policy/lineage/水位线五类漂移拒绝、只读连接、SQL 注入拦截、抽样估计票证禁止执行、空范围、预检前后源文件字节不变、HTTP 全链路与审计。
