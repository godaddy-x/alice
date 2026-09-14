# CGGMP Sign 成功路径 7 阶段改造方案（EQ + 归责）

> **状态**：**落地中**（CoFlight 调度已合入代码 · 可继续 PR-D 文档/版本）  
> **范围**：`crypto/tss/ecdsa/cggmp/sign`（3-round Sign）  
> **关联**：[PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) · [CGGMP.md](./CGGMP.md) · [CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md)  
> **日期**：2026-09-14（评审增补同日；代码落地同日）

---

## 0. 评审结论（一句话）

调度设计成立：**保持当前 EQ 语义 + Scheme A′ 归责，成功路径压到 7 阶段。**  
核心风险：**Finalize 双条件是同飞后 EQ 的唯一防线**（外层硬守卫 + A7/A8 + EchoConflict 不变量）。  
实现确认点：**「唯一 Next 出口」**——CoFlight 阶段推进必须经 barrier；其它路径显式标 **N/A INV**（见 §6.1.1）。可进 PR-A。

---

## 1. 目标

| 项 | 要求 |
|----|------|
| **EQ** | 保持**当前级** Pairwise Digest 双屏障语义（每轮 commit → Echo 冲突检测 → Reveal gate） |
| **归责** | 保留 Scheme A′ Err1/Err2 + DecModQ + `GetBlameResult`（Confirmed / Suspect） |
| **成功路径延迟** | 压到 **7 个网络阶段**（相对原始 4 轮 **+3**；相对当前串行 Digest **约 −4**） |
| **失败路径** | 可维持现状（+1 Err 收集）；成功为主，不优化失败延迟 |

**非目标**：削弱每轮 Digest；改成会末-only transcript（P2）；presign / 离线（P3）；signSix / Refresh / DKG Echo；为 Err 收集再加成功路径 RTT。

---

## 2. 轮次对照

| 方案 | 成功路径阶段数 | vs 原始 | EQ | 归责 |
|------|----------------|---------|-----|------|
| 原始 v1.0.7 | **4** | — | 弱 | 弱 |
| 当前 fork（Digest 串行） | **~11** | +7 | 当前级 | 有 |
| **本方案（Echo‖Reveal 同飞）** | **7** | **+3** | **当前级** | **有** |
| 仅归责、无 Digest | 4 | +0 | 弱 | 有 |
| 会末 transcript（P2） | 5 | +1 | **弱于当前** | 可选 |

### 2.1 成功路径：原始 vs 本方案

```text
原始：  R1 ────────► R2 ────────► R3 ────────► R4(σ)

当前：  D1 → E1 → R1 → D2 → E2 → R2 → D3 → E3 → R3 → R4
        （约 10～11；若 R4 再 Echo(σ) 另计第 8+）

本方案： D1 → (E1 ‖ R1) → D2 → (E2 ‖ R2) → D3 → (E3 ‖ R3) → R4
         │    每轮 2 段   │                  │              │
         └──── 共 6 ─────┘                  └── +1 = 7 ───┘
```

相对原始多付的 **+3** 全部用于 R1/R2/R3 各一轮 Digest 锁定；每轮内部 Echo 与 Reveal 同飞，不再各占独立 barrier。

**7 阶段计数成立的前提**：成功路径 **R4 不再对 σ 做全局 Echo**（验签失败走 Err2）。否则会多出第 8 阶段。见 §4.2、§5.1。

### 2.2 失败路径（不计入「7」）

```text
… → R3 ──δ 坏──► Err1 收集(+1) ──► ProcessErr1 → Failed
… → R4 ──验签坏──► Err2 收集(+1) ──► ProcessErr2 → Failed
```

DecModQ / Scheme A′ **仅出现在 abort**；成功路径 **0** 额外 ZK。

---

## 3. 协议语义（必须保持 =「当前 EQ」）

每轮 \(i \in \{1,2,3\}\) 仍满足：

1. **Digest（Di）**  
   - 广播 pairwise digest 表 + `table_root`  
   - 收齐并校验表；冲突 → Confirmed 归责 digest 作者  

2. **Echo（Ei）**  
   - 对已收 digest 表做 Echo；哈希冲突 → 归责  

3. **Reveal（Ri）**  
   - 明文/密文 + 既有 CGGMP ZK（Ψ / Aff-g / Log* 等）  
   - **Gate**：对照本地 store 中的 digest header；不一致 → blame reveal 发送方  
   - Reveal **本身不 Echo**（与现状一致）

### 3.1 方案成立的基础（不可妥协）

> **同飞只改调度，不改判定顺序的因果。**

本地接受本轮并 `Next` 的前提写死为三条（Finalize **强制**）：

1. 已 Accept 本轮完整 digest 表（无 root / 表项错误）；  
2. **无 Echo 冲突**，且 Echo 收集完成（`echoDone`）；  
3. Ri 内容与对应 digest header 交叉校验通过，且 Reveal 收集完成（`revealDone`）。

只要这三条作为 Finalize 的强制前置条件，Echo ‖ Reveal 同飞就不会弱化 EQ 语义。

因此：**允许「同时发出 Ei 与 Ri」**；**不允许「未满足上述三条就推进下一轮」**。

---

## 4. 调度设计（7 阶段）

### 4.1 阶段表

| # | 阶段名 | 发出 | 本地推进条件 |
|---|--------|------|--------------|
| 1 | `R1Digest` | Di 表 | 收齐合法 R1 digest 表 |
| 2 | `R1CoFlight` | **E1 ‖ R1** | `echoDone ∧ revealDone ∧ ¬echoConflict` → R2Digest |
| 3 | `R2Digest` | D2 | 收齐合法 R2 digest 表 |
| 4 | `R2CoFlight` | **E2 ‖ R2** | 同阶段 2 |
| 5 | `R3Digest` | D3 | 收齐合法 R3 digest 表 |
| 6 | `R3CoFlight` | **E3 ‖ R3** | 同上；再 δ 聚合 OK → R4；失败 → Err1 |
| 7 | `Round4` | σ | 验签 OK → Done；失败 → Err2 |

### 4.2 同飞规则（实现约束）

| 规则 | 说明 |
|------|------|
| **同 barrier 发送** | Digest 表 Accept 完成后，本节点在同一调度点发出 Echo(Ei) 与 Reveal(Ri) |
| **收齐逻辑分离** | Handler 仍可拆分；**仅** CoFlight 外层 `Finalize` 汇合后才 `Next` |
| **早到缓冲** | 对端可能先到 Ri 后到 Ei（或反之）；Ri 可先入 pending；**Echo 完成前不得 Finalize** |
| **冲突优先（不变量）** | `EchoConflict` 一旦置位 → **任何** pending Reveal **不得**参与 Finalize；立即 abort |
| **R4** | 成功路径 **不再** 对 σ 做全局 Echo（验签失败走 Err2）；避免第 8 阶段 |

### 4.3 与「串行 3 段/轮」等价性

| 攻击 / 性质 | 串行 D→E→R | 同飞 E‖R | 是否保持 |
|-------------|------------|----------|----------|
| 对 A/B 发不同 digest | Echo 冲突 | 同 | 是 |
| digest 与 reveal 不一致 | gate | 同 | 是 |
| 跳过 Digest 直接 reveal | 拒 | 拒（未 Accept Di） | 是 |
| 仅延迟 Echo、抢跑下一轮 | 串行天然挡住 | **必须靠 Finalize 双条件** | **外层硬守卫 + A7** |

串行下「Echo 未完成就不能推进」是天然的（Reveal 尚未发送）。同飞后该约束**完全依赖** Finalize 显式检查；漏检则恶意方可以：正常发 Reveal、故意延迟/不发 Echo，诚实方仅见 `revealDone` 就 `Next` → **EQ 被绕过**。

### 4.4 核心实现风险与硬守卫（评审重点）

#### 4.4.1 Finalize 双条件 = 同飞后 EQ 的唯一防线

检查必须在 **CoFlight 状态机最外层**，不得散落在各 round handler 里「碰巧记得检查」。

```go
// CoFlight.Finalize 入口（示意；R1/R2/R3 共用同一守卫）
func (c *coFlightBarrier) Finalize() error {
    if c.echoConflict {
        return ErrEchoConflict // 已走 abort / blame；不得 Next
    }
    if !c.echoDone {
        return ErrEchoNotComplete // 不得因 revealDone 而 Next
    }
    if !c.revealDone {
        return ErrRevealNotComplete
    }
    // 再执行 gate 汇总 / δ 聚合 / Next
    return c.next()
}
```

| 不变量 ID | 陈述 |
|-----------|------|
| **INV-1** | `!echoDone ⇒ Finalize 不得 Next` |
| **INV-2** | `echoConflict ⇒ Finalize 不得使用任何 pending Reveal 推进` |
| **INV-3** | `echoConflict` 置位后，后续到达的 Reveal 只入 discard / 忽略，不清除冲突 |

#### 4.4.2 早到 Reveal × 冲突竞态

禁止竞态：`Reveal 先齐 → Finalize 先跑 → Echo 冲突后到被忽略`。

实现要求：

1. `HandleEchoConflict` / `SetOnConflict`：**同步**置 `echoConflict`，并取消或否决进行中的 Finalize；  
2. Finalize 全程在持有同一 barrier 锁下读取 `echoConflict | echoDone | revealDone`；  
3. 单测覆盖「冲突与 Reveal 齐同时到达」（**A8**）。

---

## 5. 归责（保持现状收益）

| 路径 | 触发 | 机制 | 成功路径成本 |
|------|------|------|--------------|
| Digest / Echo 冲突 | 表或 Echo 哈希不一致 | Confirmed digest 作者 | 0（abort） |
| Reveal vs digest | gate 交叉校验失败 | blame reveal 发送方 | 0 |
| Err1 | \(g·δ ≠ ΣΔ\) 等 | DecModQ 包 + `ProcessErr1` | 0 |
| Err2 | `ecdsa.Verify` 失败 | Scheme A′ 双 DecModQ + `ProcessErr2` | 0 |

文档声明不变：工程级 Confirmed/Suspect；∑δ≠Δ 等仍可能 Suspect 过粗（见 IA_LIMITS **IA-03**）。**不为归责增加成功路径轮次。**

### 5.1 R4 不 Echo 与 Err2 一致性假设

R4 去掉 σ 的全局 Echo：成功路径无问题；σ 被篡改 → 验签失败 → Err2，归责仍走已有 `ProcessErr2Msg` 双 DecModQ。

**Err1/Err2 收集阶段本身不做 Pairwise Digest / Echo**（与现状一致，且不计入成功路径 7）。

| 问题 | 本方案立场 | IA 文档锚点 |
|------|------------|-------------|
| 多方看到不同的 σ | 诚实方验签失败进 Err2；攻击方可能本地验过不发 Err2 | **IA-06** Err2 absence → **Suspect**，非 Confirmed |
| Err2 广播被 equivocate（对谁发/不发） | **不**用 Echo 加固 Err 收集；依赖会话广播尽力送达 + 超时 | **IA-04** 类超时 / **IA-06** absence；工程提示而非铁证 |
| 收到合法 Err2 + ZK 过 | Confirmed 归责路径 | IA_LIMITS §4.7 Blame API |

若未来要求「abort 证据包也抗 pairwise equivocation」，属 **独立增强**（会再 +RTT），**不在本 7 阶段方案范围**。

---

## 6. 代码改造要点

### 6.1 预期触点

| 区域 | 改动 |
|------|------|
| **新建** `coflight_barrier.go`（或等价） | 外层 `echoDone` / `revealDone` / `echoConflict`；**CoFlight→下一轮的唯一推进出口**（见 §6.1.1） |
| `types/message/msg_main.go` | 一般不改框架；了解其两处 handler 切换（Finalize / OnAbortMessage） |
| Sign round 状态机 | Digest Accept 后进入 **CoFlight**，同点发 E‖R |
| `digest_handlers.go` | Echo 只置 `echoDone` / 冲突；**不**单独返回下一轮 handler |
| `round_1/2/3.go` | Reveal 可早到 pending；gate 后置 `revealDone`；**不**单独返回下一轮 handler |
| `message.go` | R4：`GetEchoMessage` 对 σ 为 nil（成功路径无 Echo） |
| Wire Type | **不改** Type 编号（0–8）；另加 **调度版本**（§6.3） |
| 测试 | A1–A8；含外层守卫单测；§6.1.2 grep 清单 |

### 6.1.1 「唯一 Next 出口」——现状确认（代码审计）

Alice **没有**名为 `Next()` 的 API。handler 切换全部由 `types/message.MsgMain` 驱动，路径只有两类：

| # | 框架路径 | 位置 | 行为 | 与 INV 关系 |
|---|----------|------|------|-------------|
| **P1** | `handler.Finalize()` → 非 nil 下一 handler | `msg_main.go` ~213（正常收齐）；~177（abort handler 已收齐时） | **成功路径推进主通道** | CoFlight 阶段的 Finalize **必须**走 `coFlightBarrier`（INV-1/2/3） |
| **P2** | `AbortHandler.OnAbortMessage()` → 下一 handler | `msg_main.go` ~163 | 切入 Err1/Err2 收集等 | **N/A INV**（离开成功 CoFlight，进 abort） |
| **P3** | Digest / Abort **超时** | `popMessage` → `OnDigestTimeout` / `ErrDigestTimeout` / `ErrAbortTimeout` | **返回 error，不切换下一轮** | **N/A INV**（协议失败，非 Next） |

Sign 包内当前由 Finalize **返回下一 handler** 的触点（串行现状，PR-B 将重排）：

- `round1DigestHandler.Finalize` → reveal / 现 round1  
- `round1Handler.Finalize` → `newRound2DigestHandler`  
- `round2DigestHandler` / `round2Handler` / `round3DigestHandler` / `round3Handler` / `round4Handler` 同类  
- `err1Handler` / `err2Handler`.Finalize → 通常 `nil`（结束）+ blame  

**结论（收窄「唯一出口」语义）：**

1. **不要求** 全局所有 handler 切换都进 `coFlightBarrier`（P2/P3 与 R4→Done、Err Finalize 不适用 INV）。  
2. **要求** 凡从 **R1/R2/R3 CoFlight** 进入下一成功阶段（下一 Digest 或 R4）的 Finalize，**有且仅有** barrier 的 `Finalize` 可返回非 nil next。  
3. Digest-only / Reveal-only handler（若仍拆分）**禁止**自行 `return newRound*`；只更新 barrier 标志，由 barrier 统一 `Next`。  
4. `OnAbortMessage` 路径显式注释：`// N/A INV: abort switch, not CoFlight Next`。

### 6.1.2 PR-A grep 级检查（必做）

在 `crypto/tss/ecdsa/cggmp/sign/`（及改动触及的 `types/message`）确认：

```text
# 1) 所有返回下一 handler 的 Finalize / OnAbortMessage
rg "return new(Round|Err)|return newRound|OnAbortMessage" crypto/tss/ecdsa/cggmp/sign/

# 2) 框架层仅两处切换（预期稳定）
rg "currentHandler|OnAbortMessage|Finalize\(" types/message/msg_main.go
```

PR-A checklist：

| 检查项 | 通过标准 |
|--------|----------|
| CoFlight 相关 `return newRound*` | **仅**出现在 `coFlightBarrier.Finalize`（或单一 wrapper） |
| 其它 Finalize 仍 `return newRound*` | 每处旁注 `// N/A INV: <Digest-only\|R4\|Err\|serial-legacy>` |
| `OnAbortMessage` | 旁注 `// N/A INV: abort switch` |
| 超时路径 | 确认 **无** 成功路径 handler 切换（仅 error / blame hook） |

### 6.2 建议实现顺序

1. **PR-A**：`coFlightBarrier` 外层硬守卫 + INV-1/2/3 单测（A7/A8）+ 乱序（A5/A6）+ **§6.1.2 grep 清单**——**行为先对齐串行，再改发送时序**  
2. **PR-B**：R1–R3 切到同飞发送；更新 PAIRWISE 流程图  
3. **PR-C**：去掉成功路径 R4 Echo；mesh E2E / 9-party；断言阶段数 = 7（A1）  
4. **PR-D**：broker / 节点说明 + `SignScheduleVersion` 混部快失败

### 6.3 Broker / 节点注意

- 转发层 **不要** 假设「同轮只有一种 Type 在飞」；CoFlight 阶段会同时出现 DigestEcho + Reveal。  
  若 broker 有「轮次 → 单一 Type」的超时或缓冲策略，必须改掉，并写入 broker 协议说明。  
- 超时：CoFlight 用 **同一** abort timer（或 `max(Echo, Reveal)`），避免一边齐一边挂死。  
- **混部**：**不可**与旧串行调度节点同会话。建议在 wire / session 参数增加调度版本标识（**不必改 Type 编号**），例如：

  ```text
  SignScheduleVersion = "coflight-v1"   // 旧节点 = "serial-v1" 或缺省
  ```

  会话建立时版本不一致 → **立即失败**，避免难以诊断的行为分歧。

---

## 7. 验收标准

| ID | 标准 |
|----|------|
| A1 | 诚实 3-party / 9-party Sign 成功；断言成功路径 **网络阶段 = 7**（或等价 barrier 数） |
| A2 | R2（及 R1/R3）pairwise equivocation → 冲突 abort + Confirmed 作者（与现网测同级） |
| A3 | Reveal 与 digest header 不一致 → blame（现有 cross-check 测仍过） |
| A4 | Mesh Err1 / Err2 E2E 仍过；`GetBlameResult` 行为不退化 |
| A5 | 乱序：先 Reveal 后 Echo、先 Echo 后 Reveal，均能成功或正确 abort |
| A6 | Echo 冲突时即使 Reveal 已到齐 → 仍 abort，不进入下一轮 |
| **A7** | Echo 未完成但 Reveal 已齐 → Finalize **必须**返回错误（如 `ErrEchoNotComplete`），**不得** Next |
| **A8** | Echo 冲突与 Reveal 齐同时到达 → **冲突优先**，abort + Confirmed blame 作者 |

A7 ↔ §4.3「实现必测」/ INV-1；A8 ↔ §4.2「冲突优先」/ INV-2。

---

## 8. 风险与回退

| 风险 | 缓解 |
|------|------|
| Finalize 漏双条件 → EQ 被弱化 | **外层硬守卫**；A7/A8；INV-1/2/3 code review 清单 |
| Reveal 齐后 Finalize 与 Echo 冲突竞态 | 同锁读取；冲突置位否决 Finalize；A8 |
| 消息洪峰（同阶段 Type 翻倍） | 可接受；带宽相对 Paillier ZK 仍小 |
| 集成方状态机写死「E 后才有 R」 | changelog + broker 说明（§6.3） |
| 与旧串行节点混部 | **不可混部**；`SignScheduleVersion` 快失败 |
| Err2 收集无 Echo | **接受**；归入 IA-06 / Suspect；不在本方案加 RTT |

**回退**：feature flag `SignSchedule=serial|coflight`（可选）；默认 coflight 达 A1–A8 后去掉 serial。

---

## 9. 决策摘要

```text
要：当前级 EQ + Scheme A′ 归责 + 成功路径尽量短
做：每轮 Digest 保留；Echo ‖ Reveal 同飞；R4 不再 Echo
得：成功 7 阶段（原始 4 + 3 道 Digest）
弃：会末-only、砍 Digest、为归责/Err 收集加成功轮次
硬：CoFlight 外层 Finalize 守卫 + INV-1/2/3 + A7/A8
```

**进 PR-A 门槛**：外层硬守卫 + A7/A8 测试骨架 + INV 注释/assert + **§6.1.2 Next 路径 grep 清单通过**。

---

## 10. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-09-14 | 初稿：7-RTT CoFlight 改造方案 |
| 2026-09-14 | 评审增补：§0 结论；§3.1 因果基础；§4.4 硬守卫与 INV；§5.1 Err2/IA-06；§6.3 调度版本；A7/A8；可进 PR-A |
| 2026-09-14 | §6.1.1 确认 MsgMain 仅 P1 Finalize / P2 OnAbort / P3 超时；收窄「唯一 Next」；§6.1.2 PR-A grep |
| 2026-09-14 | **代码落地**：`coFlightBarrier` + `MultiCollectHandler`；R1–R3 Echo‖Reveal 同飞；R4 成功路径无 Echo；`SignScheduleVersion=coflight-v1` |
