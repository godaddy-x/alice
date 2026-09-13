# FROST Pairwise Echo Digest — 彻底改造设计

> **状态**：已实现（signer v2 wire） · **代码**：`crypto/tss/eddsa/frost/signer/`、`crypto/tss/pairwise/`  
> **前提**：**不考虑旧节点兼容**；全员须同一 fork（破坏性 wire）  
> **对齐参考**：CGGMP [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) · [FROST_SECURITY_REVIEW.md](./FROST_SECURITY_REVIEW.md)  
> **修订**：2026-09-13 初版

---

## 1. 目标与非目标

### 1.1 安全目标（与 CGGMP 一致口径）

| 优先级 | 目标 | 说明 |
|--------|------|------|
| P0 | **不坏签** | 任一轮校验失败 → abort，不产出可通过 `verifySignature` 的签名 |
| P0 | **不泄钥** | 失败路径不输出 share / 可恢复私钥的材料 |
| P1 | **防 equivocation** | 对不同 peer 发送不同 Round1/2 内容可被检测并 abort |
| P2 | **可问责** | `GetBlamedPeers()` 在常见作恶路径给出可归因 peer（允许 over-blame，见 CGGMP Err1 边界） |

### 1.2 非目标

- **不**实现 CGGMP Scheme A′（DecModQ / Err1 / Err2）—— FROST 无 Paillier/MTA
- **不**做 DKG Echo（`crypto/tss/dkg/` 另立项，见 FR-08）
- **不**实现 Reshare（FR-04 仍单独处理）
- **不**保留旧 wire（`Round1=0, Round2=1`）或 feature flag

---

## 2. 现状与差距

### 2.1 当前 FROST Signer

```text
NewSigner → MsgMain(Round1, Round2) → EchoMsgMain（仅 Round1 D/E 全局 Echo）
Start → Broadcast Round1 → Finalize → Broadcast Round2 → verify
```

| 能力 | 现状 | 改造后 |
|------|------|--------|
| Round1 Echo | 全局 hash(D,E) | Digest Echo + reveal gate |
| Round2 保护 | 无 Echo / 无 digest | Digest Echo + reveal gate |
| Commit→Reveal 顺序 | 无 | MsgMain digest 屏障 + 超时 |
| Pairwise 边绑定 | 无 | BLAKE2b v3 `H_edge(sender→recipient)` |
| Echo 冲突问责 | 仅 `ErrDifferentHash` | `SetOnConflict` → blame 作者 |
| 问责 API | `GetBlamedPeer()` 单数、仅 R2 代数失败 | `GetBlamedPeers()` 统一 |
| SSID 绑 session | 无独立 `ComputeSignSSID` | 新增 `ComputeFrostSignSSID` |

Round2 已有 **`zi·G == c·coBk·Y + ri`** 逐人代数校验 + 最终 `verifySignature`（FR-03 已在代码中）。

### 2.2 主要攻击面（改造要覆盖）

| # | 攻击 | 现况 | 改造后 |
|---|------|------|--------|
| A1 | 对不同 peer 广播不同 Round1 (D,E) | 全局 Echo 可部分缓解；无屏障 | R1 Digest + gate |
| A2 | 对不同 peer 不同 digest 表 | 无 digest | Echo 冲突 + `ValidateDigestTable` |
| A3 | Reveal 先于 Digest | 无 gate | MsgMain 缓冲 + `ErrDigestBarrier` |
| A4 | Digest 缺 peer / 错 root | 无 | `ValidateDigestTable` |
| A5 | 中继篡改某条边的 H_edge | 无 pairwise | gate 重算 mismatch → blame sender |
| A6 | Round2 对不同 peer 不同 zi | 无 | R2 Digest + gate |
| A7 | Round2 代数失败 | 本地 `blamedPeer` | 保留 + 写入 `GetBlamedPeers` |
| A8 | 最终验签失败 | 全员 abort，无 blame | 可选 `Type_Err` 广播（见 §5） |

---

## 3. 协议设计

### 3.1 协议流

```text
R1Digest(Echo) ──► Round1(gate) ──► R2Digest(Echo) ──► Round2(gate) ──► verify ──► Done
                      │                              │
                      └── digest 超时 ──► blame ──► Failed
                      └── gate/verify 失败 ──► blame ──► Failed
```

相对 CGGMP：**无 R3/R4/Err1/Err2**；问责在 Round1/2 gate 与 Round2 代数校验完成。

### 3.2 Wire Type（破坏性重编号）

```protobuf
enum Type {
    Round1Digest = 0;
    Round1       = 1;
    Round2Digest = 2;
    Round2       = 3;
    Err          = 4;   // 可选：验签失败等广播（§5.2）
}
```

**旧节点无法互通**；集成方须 bump 协议版本（建议 tag：`frost-sign-v2`）。

### 3.3 Proto 增量

```protobuf
message PeerDigestEntry {
    string peer_id = 1;
    bytes digest = 2;   // 固定 32 字节
}

message Round1DigestMsg {
    ecpointgrouplaw.EcPointMessage D = 1;  // digest 阶段承诺的 D（reveal 交叉校验）
    ecpointgrouplaw.EcPointMessage E = 2;
    repeated PeerDigestEntry to_peer = 3;
    bytes table_root = 4;
}

message Round2DigestMsg {
    repeated PeerDigestEntry to_peer = 1;
    bytes table_root = 2;
}

message BodyErr {
    string blamed_id = 1;
    uint32 reason = 2;   // 枚举：VerifyZi / VerifySig / EchoConflict / ...
}
```

`Round1` / `Round2` body **不变**（仍为 `BodyRound1{D,E}`、`BodyRound2{zi}`）。

### 3.4 SSID（session 绑定）

```go
// crypto/tss/eddsa/frost/ssid.go（或 signer 包内）
func ComputeFrostSignSSID(
    dkgSSID []byte,
    msg []byte,
    pubKey *ecpointgrouplaw.ECPoint,
    threshold uint32,
    peerIDs []string, // 排序后
) []byte
```

输入：`dkgSSID || msg || curve_id || pubkey_encoding || threshold || sorted(peer_ids)`  
输出：BLAKE2b-256（与 CGGMP `ComputeSignSSID` 同风格，**独立 DST**）。

所有 `H_edge` 使用此 `ssid`；防止跨 session 重放 digest。

### 3.5 Pairwise 边哈希

**DST**（与 CGGMP 分离）：

```text
AMIS-Alice-FROST-Sign-Pairwise-Digest-v1
```

**结构**（复用 CGGMP v3 长度前缀）：

```text
H_edge = BLAKE2b-256(
    DST,
    LP(ssid), LP("R1"|"R2"), LP(sender), LP(recipient), LP(payload)
)
```

**Round1 payload**（canonical，与 `computeB` / reveal 一致）：

```go
// 确定性 proto：BMessage { x, encoded(D), encoded(E) }
// x = bk.GetX().Bytes()；encoded 使用 round_1.go 现有 ecpointEncoding
func Round1PairwiseDigest(ssid []byte, sender, recipient string, bkX []byte, D, E *ecpointgrouplaw.ECPoint) ([]byte, error)
```

**Round2 payload**：

```go
// payload = zi bytes（32-byte fixed for Ed25519/Taproot 路径按现有 round_2 约定）
func Round2PairwiseDigest(ssid []byte, sender, recipient string, zi []byte) ([]byte, error)
```

**表校验**：直接复用（抽取后）`ValidateDigestTable` / `tableRoot` / `commitDigestTable`。

### 3.6 Echo 分层（P7 同 CGGMP）

| 消息类型 | `GetEchoMessage` | 说明 |
|----------|------------------|------|
| `Round1Digest` | 克隆 digest 表 + D/E 头 | Echo 屏障 |
| `Round1` | `nil` | reveal 由 gate 保护 |
| `Round2Digest` | 克隆 digest 表 | Echo 屏障 |
| `Round2` | `nil` | reveal 由 gate 保护 |
| `Err` | 克隆 body（若实现 §5.2） | 便于收集 |

Echo 冲突 → `SetOnConflict(authorID)` → `storeBlamedPeers`。

### 3.7 Handler 链与 MsgMain

```go
ms := message.NewMsgMain(selfID, peerNum, listener, r1d,
    Type_Round1Digest,
    Type_Round1,
    Type_Round2Digest,
    Type_Round2,
    // Type_Err,  // 可选
)
ms.SetAbortTimeout(2 * time.Minute)

signer.MessageMain = frost.WrapEchoCollect(ms, pm, collector, onEchoConflict)
// 或抽到 crypto/tss/echo_collect.go，与 cggmp.WrapEchoAbortCollect 同型（无 isErr 时可简化）
```

Handler 切换：

```text
round1DigestHandler → round1Handler → round2DigestHandler → round2Handler → Done
```

**Start 顺序**（与 CGGMP 一致，避免 pending  race）：

1. `newRound1` / 构建 `round1Handler` 状态  
2. `prepareRound1Digest()`：为每个 peer 算 `H_edge(R1)`，生成 **pending Round1**（按 peer 发送同构 body，但 digest 表 per-edge）  
3. `MessageMain.Start()`  
4. `Broadcast(Round1Digest)`  
5. `Finalize(round1Digest)` → 逐 peer `MustSend` pending Round1  

**Round1 Finalize**（现有逻辑保留）：

- 聚合 B、ρ、R、c  
- `buildRound2DigestAndBroadcast()`  
- 切 `round2DigestHandler`（**不在此直接 Broadcast Round2**）

**Round2Digest Finalize** → 发送 pending Round2 → `round2Handler`。

### 3.8 Gate 与交叉校验

#### Round1Digest → Round1

| 步骤 | 行为 |
|------|------|
| Accept digest | `ValidateDigestTable`；存 `digestStore[R1][sender][recipient]` |
| Digest 头 | 存 sender 的 `digestD/digestE`（来自 Round1DigestMsg） |
| Gate Round1 | `H_edge(R1)` 重算 == store；`D/E` 与 digest 头一致；`IsIdentity` / 曲线检查 |
| 超时 | `OnDigestTimeout` → blame 未发 R1Digest 的 peer |

#### Round2Digest → Round2

| 步骤 | 行为 |
|------|------|
| Accept digest | 同上 |
| Gate Round2 | `H_edge(R2, zi)` == store |
| 代数 | 现有 `zi·G` vs `c·coBk·Y + ri` → blame 该 peer |
| 最终 | `verifySignature` → 失败 abort（§5.2 可选 Err） |

### 3.9 Peer 状态扩展

```go
type peer struct {
    // ... existing ...

    // digest store 侧（round1Handler 上集中 store 亦可）
    digestD *ecpointgrouplaw.ECPoint
    digestE *ecpointgrouplaw.ECPoint
}
```

`PairwiseDigestStore` 挂在 `round1` / 顶层 handler（与 CGGMP `round1Handler.digestStore` 同型）。

---

## 4. 代码结构（实现清单）

### 4.1 Phase 0 — 公共 pairwise 包（已完成）

路径：`crypto/tss/pairwise/`

| 文件 | 内容 |
|------|------|
| `digest.go` | `EdgeDigest` / `ValidateTable` / `CommitTable` / DST 参数 |
| `store.go` | `Store`（R1–R3） |
| `gate.go` | `Gatekeeper`（AcceptTable / GateEdgeDigest） |
| `errors.go` | 统一错误类型 |

CGGMP `sign/pairwise_*.go` 与 FROST `signer/pairwise_digest.go` 均为**薄封装**（各自 DST + canonical payload）。

### 4.2 Phase 1 — FROST signer 改造

| 文件 | 动作 |
|------|------|
| `message.proto` | §3.2 wire 重编号 + 新 message |
| `message.go` | `GetEchoMessage` 分层；`IsValid` 扩展 |
| `signer.go` | Handler 链、SSID、`GetBlamedPeers`、`SetAbortTimeout` |
| `round_1.go` | 拆出 gate；`prepareRound1Digest` 入口 |
| `round_1_digest.go` | **新建** `round1DigestHandler` |
| `round_2.go` | gate + blame 写入 `onBlamedPeers` |
| `round_2_digest.go` | **新建** `round2DigestHandler` |
| `digest_handlers.go` | **新建** gate/accept/timeout  glue |
| `pairwise_digest.go` | **新建** FROST Round1/2 payload |
| `abort_collect.go` | **新建**（或复用 `cggmp.AbortMsgCollector` 泛型） |

**删除 / 替换**：

- `signer.go` 中对 Round1 的直接 `GetEchoMessage` 全局 Echo 路径（改为 digest Echo）
- 旧 `Type` 枚举值假设（测试、broker 解码）

### 4.3 Phase 2 — 问责与 Err（可选）

| 项 | 说明 |
|----|------|
| `Type_Err` | Round2 代数失败 / 验签失败时广播 `{blamed_id, reason}` |
| `GetBlamedPeers` | Failed 后返回；Echo 冲突 / gate / 代数失败均写入 |
| Mesh E2E | `TestMeshFrostR1Equivocation`, `TestMeshFrostR2Tamper` |

FROST **不需要** CGGMP 级 `ProcessErr1Msg`；验签失败时全员 abort 即可满足 P0（blame 精度 P2）。

### 4.4 Phase 3 — 集成

| 组件 | 改动 |
|------|------|
| `wallet-mpc-node/mpc/alg_ed25519/` | 消息 type 映射、版本协商（强制 v2） |
| open_gateway 文档 | 索引指向本文 |
| `FROST_SECURITY_REVIEW.md` | FR-01 标记为「见 FROST_PAIRWISE_ECHO.md」 |

---

## 5. 问责模型（FROST 专用）

### 5.1 精确 blame 路径

| 触发 | Blame 对象 | 依据 |
|------|------------|------|
| Digest 表非法 / root 错 | digest 发送方 | `ValidateDigestTable` |
| Echo 冲突 | digest 原作者 | `SetOnConflict` |
| Digest 超时 | 缺 digest 的 peer | `OnDigestTimeout` |
| Gate mismatch | reveal 发送方 | `gateEdgeDigest` |
| R1 D/E 与 digest 头不一致 | Round1 发送方 | 交叉校验 |
| R1 平凡点 / 曲线错 | Round1 发送方 | 现有检查 |
| R2 `zi·G` 失败 | 该 node | 现有 `round_2` |
| R2 gate mismatch | Round2 发送方 | gate |

### 5.2 验签失败（`verifySignature` false）

**P0 行为**：abort，不输出签名。

**P2 可选**：

- 仅本地 `Failed`，blame 空集或全员（与 CGGMP Err1 粗 blame 同哲学——**可接受**）
- 或广播 `Type_Err{reason=VerifySig}` 供审计（不强制指认单人，因可能是聚合问题）

### 5.3 API

```go
func (s *Signer) GetBlamedPeers() (map[string]struct{}, error)
// StateFailed 外返回 ErrBlamedPeersNotReady

func (s *Signer) SetAbortTimeout(d time.Duration)
```

保留 `GetBlamedPeer()` 为 deprecated 别名（返回 map 中任一 id）或删除（破坏性文档中声明）。

---

## 6. 测试计划

### 6.1 覆盖率门禁

| 包 | 目标 |
|----|------|
| `frost/signer` | ≥ **80%**（对齐 CGGMP sign） |
| `crypto/tss/pairwise` | gate/store **100%** |
| `types/message` | 已有 digest/echo 测试继续全绿 |

### 6.2 测试矩阵

| 分类 | 用例 | 文件 |
|------|------|------|
| Digest 原语 | edge 稳定/敏感、表缺 peer、bad root | `pairwise_digest_test.go` |
| R1 gate | barrier、 mismatch、D/E 头不一致 | `digest_handlers_test.go` |
| R2 gate | zi tamper、barrier | 同上 |
| Echo 冲突 | R1/R2 digest 作者 equivocation | `pairwise_attack_test.go` |
| 超时 | `OnDigestTimeout` blame | 复用 `types/message` 模式 |
| 诚实路径 | 2/3/9 方 Ed25519 + Secp256k1 Taproot | 扩展 `signer_test.go` |
| Mesh E2E | outbound tamper PM；2-of-3 | `signer_mesh_abort_test.go` |
| 限额 | 可选：与 CGGMP 同 `MaxSignPeers=9` 或不限 | `signer_limits_test.go` |

### 6.3 命令

```powershell
cd E:\work\github\alice
go test ./crypto/tss/pairwise/ ./crypto/tss/eddsa/frost/signer/ ./types/message/ -count=1 -timeout 300s -coverprofile cover_frost.out
go test ./crypto/tss/eddsa/frost/signer/ -run TestMeshFrost -v
```

---

## 7. 集成与 rollout

### 7.1 版本策略

| 项 | 策略 |
|----|------|
| 兼容 | **无** backward compat |
| 部署 | broker + 全部 node 同版本升级 |
| 配置 | `algorithm=ed25519` 钱包须标记 `frost_sign_v2`（或 bump MPC 协议 version） |
| 回滚 | 整集群回滚；**不可** v1/v2 混签 |

### 7.2 open_gateway / broker 检查项

- [ ] `alg_ed25519` 消息 type 0–3（+4 Err）解码  
- [ ] sign task 启动前 SSID 与 CGGMP 一样绑 `msg` digest  
- [ ] abort 时上报 `GetBlamedPeers`（可选，非 P0）  
- [ ] 集成测：原跳过 FROST 的 L3 用例启用（见 `BROKER_NODE_INTEGRATION_TEST_PLAN.md` FROST 行）

---

## 8. 实施顺序（建议 PR 切分）

```text
PR1  crypto/tss/pairwise 抽取 + CGGMP sign 回归（无行为变化）
PR2  FROST proto + message.go + SSID + round1Digest/R1 gate + 单测
PR3  round2Digest/R2 gate + 诚实路径 E2E + 覆盖率
PR4  GetBlamedPeers + Echo conflict + mesh tamper E2E
PR5  （可选）Type_Err + alg_ed25519 集成 + L3 文档
```

预估：**PR1–PR4 ≈ 4–6 人天**（FROST 仅 2 轮 digest，约为 CGGMP sign 改造的 45% 工作量）。

---

## 9. 与 CGGMP 对照

| 维度 | CGGMP sign | FROST（本设计） |
|------|------------|-----------------|
| Digest 轮次 | R1/R2/R3 | **R1/R2** |
| Digest 头字段 | K/Γ、Γ、δ/Δ | **D/E**（R1）、无（R2） |
| Err 协议 | Err1/Err2 + DecModQ | **无**（或轻量 `Type_Err`） |
| IA 上限 | 9 方（DecModQ lift） | **不强制**（可设同 9 方便运维） |
| 最终验签 | Round4 + Err2 | Round2 finalize 内 `verifySignature` |
| Echo 公共层 | `WrapEchoAbortCollect` | 同型（可无 Err collect） |

---

## 10. 开放问题（实现前确认）

| # | 问题 | 建议默认 |
|---|------|----------|
| Q1 | Secp256k1 Taproot 与 Ed25519 是否共用同一 digest canonicalization？ | **共用** `ecpointEncoding` + `BMessage` |
| Q2 | 9 方上限是否复制 CGGMP？ | **复制**（运维一致）；无密码学硬性要求 |
| Q3 | `GetBlamedPeer()` 是否删除？ | **Deprecated 一版后删除** |
| Q4 | DKG 是否同 PR 改造？ | **否**；Sign 与 DKG 版本独立，但 SSID 依赖 DKG ssid |

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-13 | 初版：彻底改造设计；无旧节点兼容；PR 切分与测试矩阵 |
| 2026-09-13 | 实现 landing：R1/R2 Digest 双屏障、SSID、GetBlamedPeers、pairwise 公共包 |
