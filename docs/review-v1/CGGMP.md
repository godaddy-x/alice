# CGGMP 安全审查与 Identifiable Abort（review-v1）

> **范围**：Alice fork · 3 轮 `cggmp/sign` · Scheme A′ IA（失败路径）  
> **不变**：Keygen / Refresh / Sign **成功路径公式**与论文一致  
> **生产**：`wallet-mpc-node` 仍 pin **alice v1.0.7**；本 fork **尚未合入**

---

## 1. 结论

Sign 主路径与论文一致（广播一致前提下）。未发现远程 key-recovery 单点。

**残留**：DecModQ **R1-FS**（FS Challenge 非素数）；Err1 全局 Δ blame 粒度粗（R3）；Refresh / signSix Echo 仍弱。

**Pairwise**：3 轮 Sign 已落地 Round\*Digest commit–reveal（见 `PAIRWISE_ECHO.md`）；破坏性 wire（Type 重编号）。

---

## 2. 问题清单

> **权威状态表**（四档：已修 / 部分 / 待修 / 接受风险）及 remediation 方案见  
> **[CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md)** §3–§7。  
> 下表为概要；**勿将 ✅ 解读为 IA 可证明归责完备**。

| ID | 级 | 问题 | 概要状态 |
|----|-----|------|----------|
| F-01 | 高 | Echo / Pairwise | **部分**（sign 已修；signSix / refresh 待修） |
| F-02 | 中 | Sign ped 校验 | 已修 |
| F-03 | 中 | DKG Schnorr commitment | 已修 |
| M-01 | 中 | Round3 Delta DoS | 已修（**≠** Err1 精确归责） |
| F-04 | 中 | Err 广播收集 | 已修 |
| F-05 | 中 | signSix Err2 Type | 已修 |
| M-02 | 中 | partialPubKey 校验 | 已修 |
| F-06 | 低 | msg 进 ssid | 已修 |
| F-07/F-08 | 低 | Refresh | 待修 |
| IA-01~08 | — | IA / blame 边界 | 见 IA_LIMITS 文档 |

**Sign Echo / Digest（严格）**：

| 轮次 | 全局 Echo | Pairwise |
|------|-----------|----------|
| R1 | `Round1Digest`（K/Γ + psi 表 + `table_root`） | `Round1` reveal；`GetEchoMessage=nil`；gate 验 psi digest |
| R2 | `Round2Digest`（Γ + MtA 表） | `Round2` reveal；gate + Γ 交叉校验 |
| R3 | `Round3Digest`（δ/Δ + ψ 表） | `Round3` reveal；gate + δ/Δ 交叉校验 |
| R4 | Echo(σ) | 无 |

`Start` 必须先 `prepareRound1Digest` 再 `MessageMain.Start`，避免 Finalize 时空 `pendingRound1`。

**问责增强（2026-09-12 审计补齐）**：

| 事件 | 行为 |
|------|------|
| Digest 屏障超时 | `DigestBarrierHandler` + `ErrDigestTimeout`；`OnDigestTimeout` → blame 未发 digest 的对端 |
| `gateEdgeDigest` store 缺失 | blame 发送方 + `ErrDigestBarrier` |
| ZK 验证失败（R1 Psi / R2 AffG·Log* / R3 BigDelta·Psidoublepai） | blame 对应 Round 消息发送方 |
| 多次 blame | `storeBlamedPeers` **并集合并**（sign / signSix） |
| Echo hash 冲突 | `SetOnConflict` → blame digest 作者 |

集成层应调用 `Sign.SetAbortTimeout`（与 `MsgMain` 一致）；详见 `PAIRWISE_ECHO.md` §2。

---

## 3. 集成假设

1. Refresh→Sign 同一套材料  
2. `msg` = digest；`ssid` 绑会话  
3. **≤9 方**：`ValidateIAParticipantCount` 在 `NewSign` 与 `ProcessErr*` 强制  
4. 失败完整重启；E2E 加密  

---

## 4. Scheme A′（Identifiable Abort）

| 构件 | 说明 |
|------|------|
| **DecModQ** | 证 \(Y\equiv x\pmod q\)，\(\|Y\|<8N\)；lift \(k\in[-2,7]\)（`err_paillier.go`） |
| **PublicX** | \(x=(\mathrm{share}+\sum c_j N_j)\bmod q\)；枚举 \(c_j\in\{0,1\}\)，**首个匹配即返回** |
| **Err2 拆分** | 不证 \(K^m C_{\mathrm{inner}}^r\)（\(r\cdot S\gg N\)）；DecModQ(\(C_{\mathrm{inner}},\chi\)) + DecModQ(\(K^m,\sigma-r\chi\)) |
| **规模** | `MaxIARemotePeers=8`；总参与方 ≤9（代码断言） |

**Err1**：\(C_0=H\prod D F^{-1}\) → DecModQ(\(C_0\), PublicX(δ))。

**Err2**：DecModQ(\(C_{\mathrm{inner}}\), PublicX(χ)) + DecModQ(\(K^m\), σ−rχ)；Verify 用本地 \(R\)、Round4 σ。

```text
Round3 ──δ 失败──► Err1 ──ProcessErr1──► Failed
   └──► Round4 ──σ 失败──► Err2 ──ProcessErr2──► Failed
```

**否决**：无界 CRT、假 Enc(δ/σ)、密文 translate。signSix 走 NthRoot（非 DecModQ）。

---

## 5. DecModQ / R1（形式化备忘）

### 5.1 与 Special Decry 差异

| 项 | Special Decry | DecModQ |
|----|---------------|---------|
| FS DST | `SpecialDecryZKDST` | `DecModQZKDST` |
| Range | \(\|\alpha+eY\|\le 2^{L+\varepsilon}\) | **有效判定界**：\(\|Y\|<8N\) + Verify \(\|z_1\|\le\texttt{maxDecModQZ1}\) |
| 绑定 \(x\) | 短整数 | \(x\in[0,q)\)；\(z_1 G = C_{pt}+e\cdot x G\) |

### 5.2 审查结论（摘要）

- **\(w\) 无界**：不破坏 KS；ZK 为 Weak（可接受）。
- **\(Y^*\)**：Extractor 得 \(\mathbb{Z}_{N\cdot q}\) **等价类**；\(\|Y\|<8N\) 唯一确定小代表元。
- **有效判定界（相对论文的工程加强；代码与文档一致）**：
  - **\(\|Y\|<8N\)**（`maxDecModQYOverN=8`）：Prove 入口拒绝过大 \(Y\)；与 Scheme A′ lift \(k\in[-2,7]\)、`MaxIARemotePeers=8` 联动。
  - **\(\|z_1\| \le \texttt{maxDecModQZ1}\)**（≈ \(2^{L+\varepsilon}+(8N-1)(q-1)+2^{64}\)）：`VerifyModQ` **已显式检查**；无此界则恶意方可取 \(Y_{\mathrm{mal}}=Y+K\cdot N\cdot q\) 仍过 EC/Paillier 等式，破坏 \(\|Y\|<8N\) 与 IA 问责。**不可删除**。
  - 上述两界是 **有效 soundness / 问责判定条件**，不是可选优化；删任一即离开当前审查结论。
- **Lift A2**：\(Y_{\max}\lesssim q+8N\approx 8N\) ⇒ \(k\in[-2,7]\)；与 `MaxIARemotePeers` 联动。
- **Modulo Gap**：Prove/Verify 共用**未约减** `z1`；EC 仅在 `ScalarMult` 内 mod \(q\)。
- **R1-FS**（准确状态）：代码与 upstream 一致（整数 challenge）；运行期 \(\gcd(e-e',N)=1\)（\(e\neq e'\)）已 **确定性** 证明恒成立；**唯一「弱」点**是证明模板未按标准 FS 形式表述 → 标准模型下 soundness **无闭合论证**，**不影响运行期行为**，**无已知攻击**。量化 memo：[R1-FS_risk_memo.md](./R1-FS_risk_memo.md)。**未改 GetE**（库级决策）。

### 5.3 Blame 边界

DecModQ = **自证/自曝**（本地密文 ↔ 广播 \(x\)）。指责上游 MtA 作恶者需 Mul/Aff ZK 失败；DecModQ 通过但全局 \(\sum\delta\neq\Delta\) 时当前实现 **粗粒度 blame**（R3）。

### 5.4 R1 Checklist

完整项（含 PublicX 唯一性、w-Weak、接受风险 sign-off）见  
**[CGGMP_IA_LIMITS_AND_REMEDIATION.md §6](./CGGMP_IA_LIMITS_AND_REMEDIATION.md#6-r1--decmodq-checklist扩展)**。

- [x] Lift A2、\(|z_1|\) 上界、Modulo Gap（**已修**）  
- [~] Err 组合 / Blame 边界（**部分** — IA-01/03/06）  
- [~] KS / \(w\) 无界（**接受风险** — Weak ZK）  
- [ ] **R1-FS** Challenge 素数性（**接受风险** — [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) · PR-D4a 已交付 memo）  
- [ ] **PublicX mask 枚举唯一性**（**待修** — IA-01）  

---

## 6. 代码与测试

| 区域 | 路径 |
|------|------|
| DecModQ | `crypto/zkproof/paillier/dec_modq.go` |
| Lift / PublicX / 入口 | `cggmp/err_paillier.go`、`utils.go` |
| Err / Blame | `sign/err_abort.go`、`err_process.go`、`err_helpers.go` |
| Echo / Digest | `sign/message.go`、`digest_handlers.go`、`pairwise_digest.go`、`pairwise_store.go` |
| Digest 超时 | `types/message/abort_handler.go`（`DigestBarrierHandler`）、`msg_main.go`（`ErrDigestTimeout`） |
| 攻击问责单测 | `sign/pairwise_attack_test.go`、`types/message/digest_timeout_test.go` |

```bash
go test ./crypto/zkproof/paillier/ ./crypto/tss/ecdsa/cggmp/ \
  ./crypto/tss/ecdsa/cggmp/sign/ -count=1
go test ./crypto/tss/ecdsa/cggmp/sign/ -bench=MatchDecModQMaskEnum8 -benchmem
```

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-12 | Scheme A′、Echo R2–R4、入口断言、R1 备忘 |
| 2026-09-12 | 外部审查：`|z1|`/Modulo Gap 确认、Blame、R1-FS |
| 2026-09-12 | 三份 CGGMP 文档合并为本文件 |
| 2026-09-12 | Pairwise Digest 严格版落地（R1–R3 屏障 + Err store 绑定） |
| 2026-09-12 | Err H_edge 再哈希、Echo conflict blame、digest DST v3 长度前缀 |
| 2026-09-12 | 审计补齐：digest 超时 blame、ZK 失败 blame、`storeBlamedPeers` 并集、gate 缺表 blame |
| 2026-09-12 | 攻击问责单测（equivocation/echo conflict/Err H_edge）；死代码清理 |
| 2026-09-13 | §5.2：|Y|<8N / |z1| 标为有效判定界；R1-FS 准确状态（模板弱 ≠ 运行期弱） |
