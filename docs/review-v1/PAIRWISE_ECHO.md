# Pairwise Echo Digest — 改造 · 实现 · 测试

> **状态**：已实现 · **代码**：`crypto/tss/ecdsa/cggmp/sign` · **同目录**：`CGGMP.md` · `BROKER_NODE_INTEGRATION_TEST_PLAN.md`  
> **最后对齐代码**：2026-09-13 · sign **84.5%** · `types/message` **68.5%**

---

## 1. 改造功能点（相对 v1.0.7 / 初稿）

| # | 功能点 | 改造内容 | 关键文件 |
|---|--------|----------|----------|
| P1 | **R1–R3 Digest 双屏障** | 每轮 Commit（Digest Echo）→ Reveal（pairwise gate）；Reveal 不 Echo | `digest_handlers.go` |
| P2 | **Pairwise 边哈希** | BLAKE2b v3 + 长度前缀；R2 canon 不含 Γ；`table_root` 双承诺 | `crypto/tss/pairwise` · `pairwise_digest.go` |
| P3 | **Digest 表完备性** | 缺/多/重复 peer、错 digest 长、错 root → blame 作者 | `ValidateDigestTable` |
| P4 | **Reveal 交叉校验** | R1 K/Γ；R2 Γ；R3 δ/Δ 与 Digest 头一致后再 ZK | `round_1/2/3.go` |
| P5 | **Digest 屏障 gate** | store 无 entry → `ErrDigestBarrier` blame **reveal 发送方** | `gateEdgeDigest` |
| P6 | **Digest 超时问责** | sign 级 `OnDigestTimeout` → blame **缺 digest 的对端** | `digest_handlers.go` |
| P7 | **Echo 分层** | Digest/R4/Err Echo；Round1/2/3 reveal `GetEchoMessage=nil` | `message.go` |
| P8 | **Echo 冲突问责** | digest 作者对不同 peer 不一致 → blame 作者 | `WrapEchoAbortCollect` |
| P9 | **Err1 可问责 abort** | δ 聚合失败 → 构建 DecModQ 包 → 广播收集 → `ProcessErr1Msg` | `round_3.go` · `err_process.go` |
| P10 | **Err2 可问责 abort** | 验签失败 → Scheme A′ 双 DecModQ → 广播收集 → `ProcessErr2Msg` | `round_4.go` · `err_process.go` |
| P11 | **Err 与 digest 绑定** | Err 中 D/F 须与 store 中 Round2 pairwise digest 一致 | `sessionRound2MatchesDigest` |
| P12 | **GetBlamedPeers 离线回退** | Failed 后无缓存 → `abortCollector` + `ProcessErr*` | `sign.go` |
| P13 | **9 方上限** | `MaxIARemotePeers=8`；`NewSign` / `ProcessErr*` 强制 | `cggmp/utils.go` |
| P14 | **破坏性 wire** | Type 0–8 重编号；无 feature flag | `message.proto` |
| P15 | **Mesh abort E2E** | 全进程 mesh 触发 Err1/Err2（非 AddMessage 注入） | `sign_mesh_abort_test.go` |

**协议流（简）**：

```text
R1Digest(Echo) ──► Round1(gate) ──► R2Digest(Echo) ──► Round2(gate) ──►
R3Digest(Echo) ──► Round3(gate) ──► [δ OK→Round4 | δ fail→Err1] ──► [sig OK→Done | sig fail→Err2]
```

**Wire Type**：`Round1Digest=0 … Round4=6, Err1=7, Err2=8`（全员须同一 fork）。

---

## 2. 实现逻辑分支 × 测试覆盖

> 列 **分支** = 代码中的主要 if/abort 路径；**测试** = 代表性入口（同包还有 `coverage_batch*` / Ginkgo 补充）。

### 2.1 Digest 基础设施

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| 改 payload / peer_id → digest 变 | `edgeDigest`, `Round*PairwiseDigest` | 32B BLAKE2b | `TestEdgeDigestStableAndSensitive`, `TestRound2PairwiseDigestExcludesGamma` |
| 表缺 peer / 重复 / 未知 / digest≠32B | `ValidateDigestTable` | 拒收 + blame 表作者 | `TestValidateDigestTable*`, `TestAcceptDigestTableBlamesIncomplete3Party` |
| `table_root` 与重算不符 | `commitDigestTable` / accept | `ErrDigestTableRoot` | `TestValidateDigestTable` badRoot |
| store 读写 | `crypto/tss/pairwise/store.go` · sign 薄封装 | 按 round/sender/recipient 深拷贝 | `TestPairwiseDigestStoreGetMiss`（间接全 suite） |

### 2.2 Round1 Digest → Round1 Reveal

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| `prepareRound1Digest` 失败 | `Sign.Start` | 不启动 / `ms.Fail()` | `TestSignStartPrepareFailure*` |
| Digest nil body / 非法表 | `round1DigestHandler.HandleMessage` | blame sender | `TestRound1DigestNilBodyBlamesSender`, `TestRound1DigestHandleMessageInvalidTableBlames` |
| Finalize 缺 pending | `round1DigestHandler.Finalize` | error | `TestRound1DigestFinalizeRequiresPending` |
| **Gate**：store 无 entry | `gateEdgeDigest` | blame reveal sender + `ErrDigestBarrier` | `TestGateDigestBarrierBlames` |
| **Gate**：H_edge 不匹配 | `gateEdgeDigest` | blame + `ErrPairwiseDigestMismatch` | `TestGateEdgeDigestMismatchBlames` |
| K/Γ 与 digest 头不一致 | `round1Handler.HandleMessage` | blame | `TestRound1CiphertextCrossCheck*`, `TestRound1GammaCiphertextMismatch*` |
| `Psi.Verify` 失败 | `round1Handler.HandleMessage` | blame | `TestRound1PsiEquivocation*`, `TestRound1InvalidPsiVerify*` |
| Digest 超时 | `OnDigestTimeout` | blame 未发 R1Digest 的 peer | `TestRound1DigestOnDigestTimeoutBlames`, Ginkgo digest timeout |
| R1 Digest Echo 冲突 | `WrapEchoAbortCollect` | blame digest 作者 | `TestEchoConflictRound1DigestBlamesAuthor` |

### 2.3 Round2 Digest → Round2 Reveal

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| build R2 digest 失败 | `buildRound2DigestAndBroadcast` | Finalize error | `TestBuildRound2DigestAndBroadcastError` |
| Digest Γ 非法 / 与 reveal 不一致 | `round2DigestHandler` / `round2Handler` | blame | `TestRound2DigestInvalidGamma*`, `TestRound2GammaCrossCheck*` |
| MtA ZK（Psi/Psihat/Psipai）失败 | `round2Handler.HandleMessage` | blame | `TestRound2InvalidPsi*`, `TestRound2InvalidPsihat*`, `TestRound2InvalidPsipai*` |
| **同 digest 对不同 peer 不同 Round2 body** | gate + store | blame sender | `TestRound2EquivocationBlamesSender`, **`sign_e2e_test.go`**（3 方 mesh tamper） |
| Digest 超时 | `OnDigestTimeout` | blame 缺 R2Digest | `TestRound2DigestOnDigestTimeoutBlames`, Ginkgo |
| R2 Digest Echo 冲突 | Echo layer | blame 作者 | `TestEchoConflictRound2DigestBlamesAuthor` |

### 2.4 Round3 Digest → Round3 Reveal → Err1

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| δ/Δ 与 digest 头不一致 | `round3Handler.HandleMessage` | blame | `TestRound3DeltaCrossCheckBlamesSender` |
| `Psidoublepai` / parse δ 失败 | `round3Handler.HandleMessage` | blame | `TestRound3InvalidPsi*`, `TestRound3InvalidDeltaParse*` |
| **`g·δ ≠ ΣΔ`** | `round3Handler.Finalize` | `enterErr1Phase(ErrInvalidDelta)` | `TestRound3FinalizeEntersErr1PhaseOnBadDelta` |
| `R` 为无穷远点 | `round3Handler.Finalize` | `ErrZeroR`（非 Err1） | `TestRound3FinalizeZeroR` |
| test hook 篡改 peer δ 后重聚合 | `round3BeforeAggregateVerifyTestHook` | 同上 Err1 路径 | **`TestMeshErr1AbortE2E`** |
| 构建 Err1 包失败 | `buildDeltaVerifyFailureMsg` | Finalize error | `TestBuildDeltaVerifyFailureMsgBlamesInvalidPsi`, `TestOnAbortErr1BuildFailure` |
| 远端 Err1 到达 | `onAbortErr1` | publish + 切 `err1Handler` | `TestMsgMainRound3OnAbortErr1ViaPopAny`, `TestOnAbortErr1HandlesRemoteMessage` |
| Err1 收集完成 | `err1Handler.Finalize` | `ProcessErr1Msg` → blame | `TestErr1HandlerFinalizeBlamesBadPeer`, `TestProcessErr1MsgThreeParty*` |
| Digest 超时 | `OnDigestTimeout` | blame 缺 R3Digest | `TestRound3DigestOnDigestTimeoutBlames`, Ginkgo |

### 2.5 Round4 → Err2

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| **`ecdsa.Verify` 失败** | `round4Handler.Finalize` | `enterErr2Phase(ErrIncorrectSig)` | `TestRound4FinalizeEntersErr2PhaseOnBadSig` |
| `s == 0` | `round4Handler.Finalize` | `ErrZeroS` | round4 finalize 单测 |
| Wire tamper σ（mesh） | `outboundTamperPM` | victim Err2 + blame attacker | **`TestMeshErr2AbortE2E`** |
| 构建 Err2 包失败 | `buildSigmaVerifyFailureMsg` | error | `TestBuildSigmaVerifyFailureMsg*`, `TestOnAbortErr2BuildFailure` |
| 远端 Err2 到达 | `onAbortErr2` / `round4 OnAbortMessage` | publish + 切 `err2Handler` | `TestMsgMainRound4OnAbortErr2ViaPopAny`, `TestRound4OnAbortMessageRoutesErr2` |
| Err2 收集 / 缺席 sender | `ProcessErr2Msg` + `blameAbsentSenders` | blame 集合 | `TestProcessErr2MsgThreeParty*`, `err_process_coverage_test.go` |
| Round4 Echo(σ) | `GetEchoMessage` | 全局 σ Echo | Ginkgo `abort_test.go` |

### 2.6 问责 API 与 Echo/收集包装

| 分支 / 条件 | 实现 | 行为 | 测试 |
|-------------|------|------|------|
| 非 `StateFailed` 调 `GetBlamedPeers` | `sign.go` | `ErrBlamedPeersNotReady` | `TestGetBlamedPeersNotReady` |
| 已有 `blamedPeers` 缓存 | `storeBlamedPeers` | 并集合并返回 | `TestGetBlamedPeersReturnsStoredCopy` |
| 无缓存，collector 有 Err | fallback → `ProcessErr*` | 离线分析 | `TestGetBlamedPeersFallback*` |
| Err1/2 广播 | `publishErr1/2` | collector + `cggmp.Broadcast` | `TestPublishErr1RecordsAndBroadcasts`, `TestWrapEchoAbortCollectRecordsErr1` |
| Err 中 D/F 与 store 不一致 | `sessionRound2MatchesDigest` | blame | Ginkgo `sign_test.go`, `TestProcessErr1Msg*` sessionRound2 |
| 参与方 >9 | `ValidateIAParticipantCount` | error | `sign_limits_test.go`, `TestProcessErr*TooManyParticipants` |

### 2.7 诚实路径与规模

| 场景 | 实现 | 测试 |
|------|------|------|
| 2 方 sign | `buildSigns(2)` | Ginkgo `sign_test.go` *should be ok* |
| 3/9 方 E2E | `sign_e2e_test.go` | 3 方 honest + R2 equivocation |
| 10 方拒绝 | `newRound1Handler` | `sign_limits_test.go` |
| 9 方 honest | 全轮 digest + sign | Ginkgo *9-party honest sign* |

### 2.8 Mesh abort E2E（PeerManager 真广播）

| 用例 | 触发 | 断言 | 测试 |
|------|------|------|------|
| **Err1 3 方** | detector hook 篡改 attacker 的 δ；Err1 mesh 传播 | 全员 Failed；detector blame attacker | `TestMeshErr1AbortE2E` |
| **Err2 2 方** | attacker tamper victim 的 Round4 σ | victim Failed + blame；collector 含 Err2 | `TestMeshErr2AbortE2E` |

> Err2 用 2 方：`err2Handler` 需 `peerNum+1` 条 Err2；攻击者本地验签可通过时仅 victim 进入收集，归责靠 `blameAbsentSenders` + 离线 `ProcessErr2Msg`。

---

## 3. 覆盖率与怎么跑

### 3.1 门禁

```powershell
cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ ./types/message/ -count=1 -timeout 600s -coverprofile cover_sign.out
```

| 包 | 当前 | 门禁 |
|----|------|------|
| `sign` | **84.5%** (~106s) | ≥80% |
| `types/message` | **68.5%** | 全绿（MsgMain 基础设施） |
| `digest_handlers` / `pairwise_store` | gate/accept/timeout **100%** | 关键路径 |

### 3.2 常用子集

```powershell
# mesh abort（~12s）
go test ./crypto/tss/ecdsa/cggmp/sign/ -run TestMeshErr -v

# MsgMain digest/Echo/乱序
go test ./types/message/ -count=1 -timeout 120s
```

### 3.3 测试文件索引

| 职责 | 文件 |
|------|------|
| Mesh / 搭建 | `sign_setup_test.go`, `sign_mesh_abort_test.go` |
| Digest 核心 | `pairwise_digest_test.go`, `pairwise_attack_test.go`, `digest_crosscheck_test.go`, `digest_zk_test.go` |
| Handler 单测 | `digest_handlers_coverage_test.go`, `digest_coverage2_test.go` |
| Err / abort | `err_process_coverage_test.go`, `abort_coverage_test.go`, `abort_e2e_coverage_test.go`, `coverage_batch3`–`9` |
| Ginkgo 集成 | `sign_test.go`, `sign_e2e_test.go`, `sign_limits_test.go`, `abort_test.go`, `err_test.go` |
| MsgMain | `types/message/digest_timeout_test.go`, `msg_main_echo_test.go`, `msg_main_order_test.go` |

---

## 4. 已知缺口（边际）

| 缺口 | 原因 |
|------|------|
| `Round1PsiDigest` / `Round3PairwiseDigest` ~75% | marshal 失败难稳定触发 |
| `round_2/3.HandleMessage` 部分 ZK 成功组合 | 需构造特定密码学输入 |
| `round_1 Finalize` MTA 失败分支 | 难无 mock 注入 |
| `signSix` / Refresh Echo | 不在本改造范围 |
| L3 broker abort blame | 诚实路径已验；问责以 L1 + mesh E2E 为主 |

---

## 5. L2/L3 联调（摘要）

| 层级 | 验证什么 | 入口 |
|------|----------|------|
| **L2** broker 进程内 | digest 轮次 1→6、fault、协调层 | `wallet-mpc-broker/mpc/alg_ecdsa/` |
| **L3** broker↔node | 诚实 sign、abnormal、kill node | `BROKER_NODE_INTEGRATION_TEST_PLAN.md` |

B1/B2 成功 ⇒ 全链路 Pairwise Digest + CGGMP sign 可用；abort 问责细节以本文 §2 为准。

---

## 6. 攻击矩阵对照（设计 §8）

| # | 攻击 | §2 覆盖 |
|---|------|---------|
| 1 | R2 对不同 peer 不同 body | 2.3 equivocation + `sign_e2e` |
| 2 | 对不同 peer 不同 digest 表 | 2.1–2.3 Echo 冲突 |
| 3 | reveal 先于 digest | MsgMain 乱序缓冲 + gate barrier blame |
| 4 | digest 表缺 peer | 2.1 ValidateDigestTable |
| 5 | 篡改 `table_root` | 2.1 badRoot |
| 6 | R1 psi / 密文不一致 | 2.2–2.4 交叉校验 |
| 7 | Err 谎报 D/F | 2.6 sessionRound2 + ProcessErr* |
| 8 | 中继改 H_edge | 2.2–2.4 gate mismatch |

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-13 | 合并为单一文档；按「功能点 / 分支 / 测试」对齐代码 |
| 2026-09-13 | mesh E2E、84.5% 复测、删除重复 Ginkgo mesh 用例 |
