# CGGMP · Pairwise Echo · IA — 问题清单与 remediation

> **状态**：review-v1 增补（2026-09-13）  
> **范围**：`crypto/tss/ecdsa/cggmp/sign` · `crypto/tss/pairwise` · `types/message` · Scheme A′ IA  
> **关联**：[CGGMP.md](./CGGMP.md) · [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) · [FROST_PAIRWISE_ECHO.md](./FROST_PAIRWISE_ECHO.md)  
> **读者**：安全审计 / MPC 集成 / 运维  
> **目的**：统一 **问题状态语义**、暴露 **IA 可证明归责边界**、给出 **可执行 remediation**

---

## 1. 结论（对外口径）

| 层级 | 承诺 | 说明 |
|------|------|------|
| **P0** | 不坏签 / 不泄钥 | 失败路径 abort；`GetResult` 仅在 `StateDone` |
| **P1** | 防 equivocation | Pairwise Digest + Digest Echo + reveal gate（sign 已落地） |
| **P2** | Identifiable Abort | **工程化归责**：多数恶意路径可 `GetBlamedPeers()`；**非**论文级「唯一可证明归责」 |

**禁止对外表述**：「任意作恶方必被密码学唯一归责」。  
**允许对外表述**：「失败可 abort；常见作恶/不一致广播可指向 suspect peer；已知启发式与 over-blame 见本文 §3–§4」。

**API 口径（PR-D1 / PR-D3 目标）**：

- 集成层 **不得** 将 `GetBlamedPeers()` 的混合集合直接当作法庭级「确证作恶」；
- 目标 API：`GetBlameResult()` 返回 `{ Confirmed, Suspect }`（或 `GetConfirmedPeers()` / `GetSuspectPeers()`）；
- **Confirmed**：DecModQ/ZK 失败、gate 密码学失败、明确 sender blame 等 **密码学路径**；
- **Suspect**：digest 超时、Err2 缺席、mask 多解 cohort、全局 Δ over-blame 等 **运维 hint**；
- 过渡期：`GetBlamedPeers()` = `Confirmed ∪ Suspect`（兼容），文档标注 **deprecated for penalty logic**。

---

## 2. 状态语义（四档）

旧文档单用 ✅ 易与「IA 完备」混淆。本清单统一：

| 状态 | 含义 |
|------|------|
| **已修** | 代码 + 单测闭环；剩余风险仅理论级 |
| **部分** | 已缓解主风险（如 DoS、多数 blame 路径），但 IA soundness / 覆盖未闭合 |
| **待修** | 有明确代码或文档缺口，应排期 |
| **接受风险** | 已知密码学/工程边界；需 sign-off 理由与影响范围 |

---

## 3. 主问题清单

### 3.1 安全审查遗留（F / M 系列）

| ID | 级 | 问题 | 状态 | 说明 |
|----|-----|------|------|------|
| F-01 | 高 | Echo / Pairwise Digest | **部分** | sign ✅；signSix / refresh **待修**（仍弱 Echo） |
| F-02 | 中 | Sign 入口 ped 校验 | **已修** | `ValidateAllPed` |
| F-03 | 中 | DKG Schnorr commitment | **已修** | 不再 `return nil` 静默 |
| M-01 | 中 | Round3 Delta 字符串 DoS | **已修** | `ParseBigIntString`；**≠** IA 精确归责 |
| F-04 | 中 | Err 广播收集 | **已修** | Err1/Err2 状态机 |
| F-05 | 中 | signSix Err2 Type | **已修** | `round_6.go` |
| M-02 | 中 | partialPubKey 校验 | **已修** | Sign 入口 `ValidatePublicKey` |
| F-06 | 低 | msg 进 ssid | **已修** | `ComputeSignSSID` |
| F-07 | 低 | Refresh Echo | **待修** | 无 Pairwise Digest |
| F-08 | 低 | Refresh 集成 | **待修** | 集成层 warm / 材料一致性 |

### 3.2 IA / Pairwise 专项（本审查新增 IA-xx）

| ID | 级 | 问题 | 状态 | 影响 |
|----|-----|------|------|------|
| **IA-01** | 高 | PublicX / mask 枚举 **首个 VerifyModQ 成功即返回** | **部分** | PR-D1：全量枚举 + AmbiguousMaskPolicy + BlameResult；方案 C（唯一性引理）仍待 |
| **IA-02** | 高 | **R1-FS**：`GetE` 非素数 challenge | **接受风险** | 仅证明模板无闭合论证；运行期 gcd 恒成立；非 IA 精度主因 |
| **IA-03** | 中 | Err1 **精确归责**有限（DecModQ 自证；∑δ≠Δ over-blame） | **部分** | IA 卖点被高估 |
| **IA-04** | 中 | Digest **超时 blame**（慢/分区 vs 恶意不发） | **部分** | 可用性 / 误惩罚 |
| **IA-05** | 中 | `gateEdgeDigest` store 缺失 **单边 blame reveal 方** | **部分** | 极端路由下可能错方向 |
| **IA-06** | 中 | Err2 **缺席归责**（`blameAbsentSenders`） | **部分** | 缺席 ≠ 作恶 |
| **IA-07** | 低 | 文档 ✅ 与 IA 能力混用 | **待修** | 审计友好度（本文即 remediation） |
| **IA-08** | 低 | R1 Checklist 未覆盖 w-Weak / 等价类 | **待修** | 见 §6 |

### 3.3 Pairwise Echo（PE-xx，与 IA 正交）

| ID | 级 | 问题 | 状态 |
|----|-----|------|------|
| PE-01 | — | CGGMP sign R1–R3 Digest 双屏障 | **已修** |
| PE-02 | — | FROST sign R1–R2 Digest 双屏障 | **已修** |
| PE-03 | — | DKG / Refresh Pairwise | **待修**（非 P0） |
| PE-04 | — | signSix Pairwise | **待修** |

---

## 4. 分项 remediation

### IA-01 · PublicX / mask 枚举唯一性

**现状**（`sign/err_helpers.go` · `matchDecModQWithBetaCorrection`）：

- 对 `c_j ∈ {0,1}`（≤8 远端 peer → ≤256 mask）枚举；
- **`VerifyModQ` 第一次成功即 `return true`**（early exit）；
- 文档 §4 写「首个匹配即返回」，与实现一致。

**风险**：

- 若存在 **两个 mask** 均使 DecModQ 验证通过，则归责依赖 **枚举顺序**，非可证明唯一；
- §5.2「\|Y\|<8N 唯一 lift」约束的是 **Y 的代表元**，**不推出 c 向量唯一**。

**方案（按优先级）**：

| 方案 | 工作 | 建议 |
|------|------|------|
| **A · 文档** | 在 CGGMP.md / 集成规范标注「mask 多解 = 不精确 blame」 | **立即** |
| **B · 保守实现** | 枚举 **全部** mask（先找第一个再扫完；≥2 即 `MaskAmbiguous`）；0 → **Confirmed** blame sender；**>1 → 不精确 blame**（见下 **默认策略**） | **已落地（PR-D1）** |
| **C · 密码学** | 补引理：在 `MaxIARemotePeers=8` + Paillier 参数下 mask 唯一（或 w.h.p. 唯一） | **P2 研究**；未闭合前不得标「已修」 |

**多 mask 默认策略（PR-D1 必须写死，禁止实现者即兴）**：

| 策略 | Confirmed | Suspect | 运维 | 适用 |
|------|-----------|---------|------|------|
| **`SuspectAllErr`（默认）** | **空集** | **本轮 Err 发送者 − Confirmed** | `AmbiguousMask` 告警 | 生产默认：不作密码学确证，但 cohort 高概率含作恶者 |
| `SuspectNone` | 空集 | 空集 | 同上 + **必须**人工介入 | 保守部署：零误伤 suspect |
| `ConfirmAllErr` | cohort → Confirmed | 空集 | 告警 | **仅** `-tags alice_ia_debug`；生产 `SetAmbiguousMaskPolicy` **强制 remap → SuspectAllErr** |

- Alice：`crypto/tss/blame` · `AmbiguousMaskPolicy`，默认 **`SuspectAllErr`**；
- 生产构建：`ConfirmAllErr` **不可用**（`policy_prod.go`）；调试构建：`-tags alice_ia_debug`；
- **禁止**默认 `ConfirmAllErr` — 与 §1「非唯一可证归责」冲突。

**验收**：

- 单测：`TestGetBlameResultSplitsDisjoint`（Confirmed ∩ Suspect = ∅）；
- 单测：`TestAmbiguousMaskPolicyCohortExcludesConfirmed`（cohort = Err − Confirmed）；
- 单测：`TestAmbiguousMaskPolicyConfirmAllErrRemappedInProd`；
- Benchmark 仍保留 `MatchDecModQMaskEnum8`（最坏 256；实现为先找第一个再扫完，≥2 提前返回 Ambiguous）。

---

### IA-02 · R1-FS Challenge 非素数（Accepted Risk）

**现状**（`crypto/zkproof/paillier` · `GetE`）：

- 代码与 **upstream 一致**：Fiat–Shamir challenge \(e \in [-q/2,q/2]\) **整数**，**非素数**；
- §2.1（memo）：\(e\neq e'\) 时 \(\gcd(e-e',N)=1\) **确定性恒成立**（非 w.h.p.）；**不影响运行期**；
- **唯一弱点**：证明模板未按标准 FS 形式表述 → 标准模型 soundness **无闭合论证**；**无已知攻击**；
- **未改 GetE** — 影响 **整个 alice 库** 的 Paillier ZK，非仅 IA。

**Accepted Risk 记录（需 sign-off）** — 量化 memo：[R1-FS_risk_memo.md](./R1-FS_risk_memo.md)（§0 准确状态表）

| 项 | 内容 |
|----|------|
| **影响** | DecModQ / Mul / Aff 等 FS 证明；**证明模板**使用非素数整数 challenge（与 upstream 一致） |
| **运行期 \(\gcd(e-e',N)\neq 1\)** | Alice 默认参数下 \(e\neq e'\) 时 **概率 = 0**（\(|e-e'|\le q\ll \min(p,p')\)）；\(e=e'\) 归 FS 绑定，非随机 gcd 事件 |
| **通用随机上界（模板）** | 若无 \(\|e\|\le q/2\) 约束，\(\Pr[\gcd\neq 1]=O(2^{-1024})\)（2048-bit \(N=p\cdot p'\) union bound） |
| **实际接受对象** | **证明模板表述缺口（A）** — 最坏后果见 memo **§2.4**；**≠** 运行期弱化；gcd（B）可忽略 |
| **「弱」的精确定义** | 仅指标准模型下 **无闭合 soundness 论证**；代码行为与 upstream 相同；文档比旧注释更紧 |
| **伪造 DecModQ proof** | memo **§2.5**：分支 1 下 gcd 路径不可能；分支 2 无已知构造；**非 IA 归责主因** |
| **IA 归责关联** | R1-FS **不**使恶意方轻易伪造 DecModQ 误导 blame；精度缺口在 **IA-01 / IA-03** |
| **为何不阻塞 sign 发版** | 与 upstream alice 一致；改 GetE 为库级 breaking 变更 |
| **闭合路径** | PR-D4a memo ✅ · PR-D4b prime challenge PoC（独立分支） |

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) + CGGMP.md §5.4 标 **接受风险** |
| P1 | 外部密码学 review 对 memo **§2.4.3** sign-off |
| P2 | PR-D4b：`GetE` prime challenge PoC（不阻塞主线） |

---

### IA-03 · Err1 精确归责能力

**现状**（`sign/err_process.go` · `ProcessErr1Msg`）：

1. **DecModQ 路径**：验证 Err1 广播者 **自洽**（本地密文 ↔ 广播 \(x\)）— **自证/自曝**，**不**直接指认上游 MtA 作恶者；
2. **Mul/Aff ZK 失败**：应在 **Round1/2** 已 blame（正常路径）；
3. **全局 \(\sum\delta \neq \Delta\)**：DecModQ 全通过后，**所有远端 Err1 发送者**入 `errPeers` — **粗粒度 over-blame**。

**与 M-01 区分**：

| 项 | M-01 | IA-03 |
|----|------|-------|
| 问题 | 畸形 Delta → panic DoS | 谁该为 δ 不一致负责 |
| 修复 | 解析 error | **未**精确到单 peer |
| 状态 | **已修** | **部分** |

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | 问题表单独列 IA-03；禁止把 M-01 ✅ 读成 IA 完备 |
| P1 | 文档 + `GetBlamedPeers` 注释：Err1 全局 Δ 失败 = **suspect set**，非法庭证据 |
| P2 | 研究论文 Err1 能否在 DecModQ 全过情况下指认 MtA 作恶者（可能需额外 ZK） |

---

### IA-04 · Digest 超时 blame

**现状**：

- `MsgMain.SetAbortTimeout`（默认 **2 分钟**）作用于 `DigestBarrierHandler`；
- 超时 → `OnDigestTimeout` → blame **未在该轮发出 digest 的 peer**；
- **无法区分**恶意不发 vs 网络慢/分区。

**与 broker 层关系**：

- broker **JWT WS 掉线** → `abortMpcTask`（**秒级**），通常 **先于** 2 分钟；
- 2 分钟主要覆盖 **「仍显示在线但不发 digest」** 或 **无 broker abort 的测试/分区**。

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | 集成文档：digest 超时 blame = **best-effort**；**不得**单独作为经济惩罚唯一依据 |
| P1 | `SetAbortTimeout` 可配置；生产建议 **30s–120s** 按 RTT 调参 |
| P1 | broker 可选：**sign 阶段 protocol idle 超时**（有 WS 但 long time 无 mpc wire） |
| P1 | 超时 blame 写入 **Suspect**（非 Confirmed）；见 §4.7 API |
| P2 | broker `BlamedNodes[]` 携带 suspect/confirmed 标签（INT-04） |

---

### IA-05 · gate store 缺失 blame 方向

**现状**（`crypto/tss/pairwise/gate.go`）：

```text
Store.Get(round, sender, self) 失败 → Blame(sender) → ErrDigestBarrier
```

此处 `sender` = **reveal 消息发送方**。

**设计假设**：

- MsgMain 顺序保证：**Digest 屏障完成后**才进入 Round reveal handler；
- store 缺 entry ⇒ 更常解释为 **reveal 抢跑 / 本地状态不一致**，而非「digest 在网络上丢了但 reveal 合法」。

**剩余风险**：

- 若实现 bug 或乱序导致 digest 未入库却收到 reveal，会 **blame reveal 方**；
- 若 digest 发送方未发、reveal 方也未发，应在 **Digest 超时（IA-04）** blame digest 缺失方。

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | 文档写清 **gate blame 方向性假设**（见上） |
| **P1** | **gate 失败诊断分支**（工程正确性，优先于 reveal 单边 blame）： |
| | 1. `Store.Get` 失败时，查本地是否 **曾收到** 该 `sender` 的 digest（内存 store / 日志 / `DigestBarrier` 收包记录）； |
| | 2. **若曾收到** → 归为 **本地处理路径故障**：**不 blame 任何远端**；`Confirmed`/`Suspect` 均为空；触发 `LocalDigestProcessingFault` 运维告警； |
| | 3. **若未收到** → 维持现有逻辑：**Suspect** blame reveal 方（或结合 IA-04 超时 blame digest 缺失方）； |
| P1 | `OnDigestTimeout` 与 gate 失败 **合并 blame 上下文**（日志带 round / 是否曾收到 digest / 诊断分支结果） |
| P2 | 持久化 digest 收包审计 trail（跨进程 replay 诊断） |

---

### IA-06 · Err2 缺席归责

**现状**（`sign/err_helpers.go` · `blameAbsentSenders`）：

- 未广播 Err2 的 peer 进入 blamed 集合；
- **2 方场景**：攻击者本地验签可通过 → **不发 Err2**；victim 靠 **缺席 + 离线 `ProcessErr2Msg`**；
- **缺席** 可能来自：作恶、网络、实现选择。

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | 文档：缺席 blame = **运维 hint**；精确归责依赖 **ProcessErr2 收到有效 Err2 + ZK** |
| **P1** | `blameAbsentSenders` 产出写入 **Suspect**，**不得**进入 Confirmed（与 IA-04 同级） |
| P1 | 3 方+ 诚实 mesh 测试补全（已有部分 coverage） |
| P2 | Err2 收集超时与 `ErrAbortTimeout` 文档化（CGGMP Err 收集阶段） |

---

### §4.7 · Blame API：Confirmed vs Suspect（IA-04 / IA-06 / §1 闭合）

**现状**：`GetBlameResult()` / `GetConfirmedPeers()` / `GetSuspectPeers()` 已落地（CGGMP sign + FROST）；`GetBlamedPeers()` = Confirmed ∪ Suspect（兼容，**penalty 请用 Confirmed**）。

**类型**（`crypto/tss/blame`）：

```go
type Result struct {
    Confirmed map[string]struct{}
    Suspect   map[string]struct{}
}
```

**onBlame 调用点清单（CGGMP sign）**：

| Kind | 调用点 |
|------|--------|
| **Confirmed** | `blameSender`（R1–R3 ZK/gate/table）；`blamePeer`（δ/σ）；`NewSign` echo `SetOnConflict`；`err1/err2 Finalize` ← ProcessErr Confirmed |
| **Suspect** | `blameMissingDigestSenders` / `OnDigestTimeout` R1–R3；ProcessErr Suspect（缺席、全局 Δ、ambiguous cohort） |

**分类规则（摘要）**：

| 来源 | 集合 |
|------|------|
| DecModQ / Mul / Aff ZK 失败、mask 0 解 sender | **Confirmed** |
| mask 多解 + `SuspectAllErr`（默认） | **Suspect** = 本轮 Err 发送者 − Confirmed |
| 全局 \(\sum\delta\neq\Delta\) | **Suspect**（Err 发送者） |
| Digest 超时（IA-04） | **Suspect** |
| gate 失败（PR-D3 诊断前） | **Confirmed**（reveal 方；诊断留 PR-D3） |
| Err2 缺席（IA-06） | **Suspect** |
| ProcessErr2 有效 Err2 + ZK 指认 | **Confirmed** |

**方案**：

| 优先级 | 动作 |
|--------|------|
| P1 | Alice：`BlameResult` + 分类 — **已落地（PR-D1）** |
| P1 | `mpc.FormatSignErr` / INT-03 输出区分 confirmed vs suspect |
| P2 | INT-04：`BlamedNodes[]` 带 `kind: confirmed|suspect` |

---

### IA-07 / IA-08 · 文档一致性

**方案**：

| 优先级 | 动作 |
|--------|------|
| P0 | 发布本文；[CGGMP.md](./CGGMP.md) §2 改为 **指向本文 §3** 作权威状态表 |
| P0 | 废弃单 ✅ 表示 IA 完备；F-01 改为 **部分** |
| P1 | §6 R1 Checklist 扩展（见下） |

---

## 5. 集成层 remediation（broker / node）

与 Alice 协议内 IA **互补**，不改变密码学 blame 边界：

| ID | 项 | 现状 | 建议 |
|----|-----|------|------|
| INT-01 | Node 掉线 fast-fail | broker `abortMpcTasksForNode` + `mpcTaskAbort` | **已修**；优先于 Alice 2m |
| INT-02 | FROST blame 进 error 文本 | `mpc.FormatSignErr` | **已修**（alg_ed25519） |
| INT-03 | CGGMP blame 进 error 文本 | 未接 | **待修**：`alg_ecdsa/sign.go` 同 FROST |
| INT-04 | blame 上报 broker | 未做 | **P2**：`CliMPCSignResultReq` 增 `BlamedNodes[]` |
| INT-05 | digest 超时 vs broker 超时 | 文档分散 | **P0**：运维手册写 **预期 fail 时间线** |

**预期 fail 时间线（sign，participant 掉线）**：

```text
T+0s     broker WS onClose
T+0~1s   abortMpcTask → 在线 node mpcTaskAbort → abortCancel → RunSign 退出
         （通常远早于 Alice Digest 2m）
T+2m     仅当上层 abort 未生效时，Alice ErrDigestTimeout
T+6/12m  node signTimeout / session 兜底
```

---

## 6. R1 / DecModQ Checklist（扩展）

相对 [CGGMP.md](./CGGMP.md) §5.4，明确 **已修 / 部分 / 接受风险 / 待评估**：

| 项 | 状态 | 备注 |
|----|------|------|
| KS（含 \(w\) 无界） | **接受风险** | ZK **Weak**；不破坏 KS |
| Lift A2（\(k\in[-2,7]\)） | **已修** | 与 `MaxIARemotePeers=8` 联动 |
| \(\|Y\|<8N\) + \(\|z_1\|\) 上界 / Modulo Gap | **已修** | **有效判定界**；不可删 Verify 检查（CGGMP.md §5.2） |
| Err 组合（Scheme A′） | **部分** | 见 IA-01、IA-03、IA-06 |
| Blame 边界文档化 | **部分** | 本文 §4 |
| **PublicX mask 唯一性** | **待修** | IA-01 方案 B/C |
| **R1-FS Challenge 素数** | **接受风险** | IA-02；[R1-FS_risk_memo.md](./R1-FS_risk_memo.md) · PR-D4a |
| **\(Y^*\) 等价类 / Extractor** | **待评估** | 不阻塞当前 IA 工程；审计追问时引用 §5.2 |
| **w 无界 → Weak ZK** | **接受风险** | 与 upstream 一致 |

---

## 7. 实施优先级（建议 PR 切分）

```text
PR-D0   本文 + CGGMP.md §2 交叉引用 + README 索引（无代码）
PR-D1   matchDecModQ 多解检测（IA-01 方案 B）✅
        + AmbiguousMaskPolicy 默认 SuspectAllErr（cohort=Err−Confirmed）
        + ConfirmAllErr 生产 remap；alice_ia_debug 才放行
        + BlameResult Confirmed/Suspect API（§4.7）；Confirmed ∩ Suspect = ∅
        + 枚举：先找第一个再扫完（≥2 → MaskAmbiguous）
PR-D2   alg_ecdsa FormatSignErr（INT-03）+ blame kind 输出
PR-D3   SetAbortTimeout 可配置 + gate 诊断分支 P1（IA-05）+ 集成文档（IA-04）
PR-D4a  R1-FS_risk_memo.md — 量化上界 + 影响范围 + upstream diff（纯文档，可立即合）
PR-D4b  GetE prime challenge PoC（独立分支，不阻塞主线）
PR-D5   signSix / refresh Pairwise（PE-03/04，独立大项）
```

---

## 8. 测试补充清单

| 测试 | 覆盖 | 优先级 |
|------|------|--------|
| `TestMatchDecModQAmbiguousMask` | IA-01 多解 | P1 |
| `TestProcessErr1GlobalDeltaOverBlame` | IA-03 文档化行为 | P0（已有逻辑，补断言文档） |
| `TestDigestTimeoutDoesNotBlameIfAborted` | INT-01 与 IA-04 | P1 |
| `TestProcessErr2AbsentSender` | IA-06 边界 | P1 |
| 3-party Err2 mesh honest | IA-06 | P2 |

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-13 | 初版：四档状态、IA-01~08、集成层 INT-01~05、R1 Checklist 扩展、PR 切分 |
| 2026-09-13 | 审计收口：IA-02 量化 memo、IA-01 默认策略、IA-05 P1 诊断、§4.7 Blame API、PR-D4a/b |
| 2026-09-13 | \|Y\|<8N/\|z1\| 标有效判定界；R1-FS「弱」收窄为模板表述缺口 |
| 2026-09-13 | PR-D1 落地：blame 包、MaskMatchResult、BlameResult、SuspectAllErr cohort、生产 ConfirmAllErr remap |
