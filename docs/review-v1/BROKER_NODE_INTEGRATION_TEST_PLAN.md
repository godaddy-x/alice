# 本地 Alice → Broker / Node 集成测试计划

> **replace**：`wallet-mpc-broker/go.mod`、`wallet-mpc-node/go.mod`  
> ```go
> replace github.com/getamis/alice => ../alice
> ```  
> Alice 改造与 L1 测试：同目录 `PAIRWISE_ECHO.md`

> **范围**：CGGMP ECDSA sign / Pairwise Echo Digest；FROST / Ed25519 非发版阻塞。

| 层级 | 结果 |
|------|------|
| **L1** Alice | sign **84.5%** · mesh Err1/Err2 E2E · 见 `PAIRWISE_ECHO.md` §3 |
| **L2** 进程内 | PASS（fault ~200s）· 本文 §2 阶段 A |
| **L3** broker↔node | B1/B2+/B3 + abnormal PASS · 本文 §2 阶段 B/D |

**L1 门禁**：见 `PAIRWISE_ECHO.md` §3.1。

## Alice 模块 ↔ 联调层级（摘要）

| 模块 | L1 | L2 | L3 |
|------|----|----|-----|
| digest / gate / Echo | `pairwise_*` · `digest_*` | A2 msgType 1→6 | B 成功即全链路 digest |
| Err1/Err2 blame | `TestMeshErr*` + `err_process_*` | — | 诚实路径；问责见 L1 mesh |
| `round_*` / `sign.go` | Ginkgo `sign_test.go` | A2 子集 sign | B1/B2/B3 |

---

## 架构（本方案）

```text
Terminal 1  TestMainServe          → broker :9422 (CLI) + :9522 (node relay)
Terminal 2  TestRunNode0           → node0 ─┐
Terminal 3  TestRunNode1           → node1 ─┼→ WS :9522
Terminal 4  TestRunNode2           → node2 ─┘
Terminal 5  go test -tags stress   → SignTransaction 经 :9422 驱动三节点 CGGMP sign
```

**前提**：`cli_config.yaml` 已配置 `walletMode: 3`、node0–2 `nodeBindings`、对应 tenant `cliBindings`；node 配置在 `wallet-mpc-node/integration/cli_node{0,1,2}.json`，**必须在 `integration/` 目录下启动**（相对路径 `cli_node0.json`）。

---

## 0. 一次性检查

```powershell
cd E:\work\github\wallet-mpc-broker
go list -m github.com/getamis/alice    # => v1.0.7 => ../alice

cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ -count=1 -timeout 600s
```

| 项 | 通过标准 |
|----|----------|
| replace 生效 | `=> ../alice` |
| Alice sign 单测 | 全绿（包覆盖率 **84.5%**） |
| broker 编译 | `go build ./...` 无错（测试辅助须为 `*_test.go`） |

---

## 1. 启动服务（4 个终端，顺序建议）

### 1.1 Broker（先起）

```powershell
cd E:\work\github\wallet-mpc-broker
$env:BROKER_SERVE_TEST = "1"
# 可选：$env:BROKER_CONFIG = "cli_config.yaml"
go test -run ^TestMainServe$ -timeout 0 -v
```

日志应出现：

- `listening on 127.0.0.1:9422`
- `listening on 127.0.0.1:9522`
- `walletMode=3`

### 1.2 Node0 / 1 / 2（各开一个终端）

```powershell
cd E:\work\github\wallet-mpc-node\integration
go test -run ^TestRunNode0$ -timeout 0 -v
# 另开终端：TestRunNode1$、TestRunNode2$
```

| 现象 | 说明 |
|------|------|
| 启动时 `connect refused` | 正常：broker 未就绪；node 会自动重连 |
| `websocket reconnect successful` | 已连上 :9522 |
| broker 日志 `CLIENT_CONNECTED user_id=node0/1/2` | 三节点在线 |

### 1.3 端口探测

```powershell
Test-NetConnection 127.0.0.1 -Port 9422
Test-NetConnection 127.0.0.1 -Port 9522
```

---

## 2. 测试矩阵

### 阶段 A — 进程内（无需 broker/node）

在 **broker 目录**执行：

```powershell
cd E:\work\github\wallet-mpc-broker

# A1 从零 keygen + sign（2-of-2）
go test ./mpc/alg_ecdsa/ -run TestCGGMPKeygenAndSignTwoOfTwo -count=1 -timeout 10m -v

# A2 真实 2-of-3 份额 + warm refresh + sign（覆盖 Pairwise Echo 全轮次）
go test ./mpc/alg_ecdsa/ -run "TestSignSessionSubsetTwoOfThree|TestSignTwiceSameRefreshDifferentMessages|TestRefreshSubsetTwoOfThreeFiltered" -count=1 -timeout 15m -v

# A3 进程内 fault（wire/SSID/缺 peer/blackhole/Filter，无需 broker）
go test ./mpc/alg_ecdsa/ -run "Tampered|Missing|Different|Blackhole|RefreshMissing|SSID|Filter" -count=1 -timeout 15m -v
```

| 用例 | 验证 | 层级 |
|------|------|------|
| `TestCGGMPKeygenAndSignTwoOfTwo` | dkg + **本地 alice sign**（含 digest 轮次 msgType 1→6） | Inbox 模拟 |
| `TestSignSessionSubsetTwoOfThree` | 2-of-3 子集 sign + digest | 真实 integration 份额 |
| `TestSignTwiceSameRefreshDifferentMessages` | 同 refresh 材料连签两笔 | 同上 |
| `TestRefreshSubsetTwoOfThreeFiltered` | 2-of-3 refresh warm | 同上（sign 前置依赖） |
| **A3 fault** | wire 篡改 / 缺 peer / blackhole / SSID / Filter | 快速失败或超时，不挂死 | `sign_fault_test.go`、`filter_test.go` |

node 侧镜像：`wallet-mpc-node/mpc/alg_ecdsa/`（同上命令，换目录）。

### 阶段 B — Broker ↔ 3 Node 联调（**本环境主路径**）

**服务已按 §1 启动后**，在 broker 目录：

```powershell
cd E:\work\github\wallet-mpc-broker

# B1 单笔冒烟（必跑）
$env:BROKER_SIGN_STRESS = "1"
$env:STRESS_WALLET_ID = "1CToiZvPtGoCEmyoEYayB3cozrh3aici1M"   # 2-of-3 ecdsa，node0–2
go test -tags stress -run ^TestBrokerNodeSignPreflight$ -count=1 -timeout 15m -v

# B2 连续 5 笔（同钱包、不同 nonce）
$env:STRESS_ROUNDS = "5"
$env:STRESS_WORKERS = "1"
go test -tags stress -run ^TestBrokerNodeSignStress$ -count=1 -timeout 15m -v

# B2+ 单钱包并发（4 worker × 20 轮 = 80 请求）
$env:STRESS_WORKERS = "4"
$env:STRESS_ROUNDS = "20"
$env:STRESS_MIN_OK_PCT = "95"
go test -tags stress -run ^TestBrokerNodeSignStress$ -count=1 -timeout 20m -v

# B3 多钱包并行（3 钱包）
$env:STRESS_WALLET_IDS = "1CToiZvPtGoCEmyoEYayB3cozrh3aici1M,112uMQcPAJEjX6FaZjVHNPWag4r8zLcy5n,16hyedepYpLGLHdGxnEeBoTefhYaS4dzZx"
$env:STRESS_MIN_WALLETS = "3"
$env:STRESS_WORKERS = "4"
$env:STRESS_ROUNDS = "15"
go test -tags stress -run ^TestBrokerNodeSignStressMultiWallet$ -count=1 -timeout 30m -v
```

| ID | 场景 | 条件 | 期望 | 入口 |
|----|------|------|------|------|
| B1 | 单笔 ETH sign | 3 节点在线；2-of-3 钱包 | `preflight ok`，~3–10s | `TestBrokerNodeSignPreflight` |
| B2 | 同钱包连续 sign | `STRESS_ROUNDS=5`，单 worker | `ok=5 fail=0`，`inFlight=0` | `TestBrokerNodeSignStress` |
| B2+ | 同钱包并发 sign | `STRESS_WORKERS=4 STRESS_ROUNDS=20` | `ok=80 fail=0`（同钱包 MPC 段串行，worker 排队） | 同上 |
| B3 | 多钱包并行 | `STRESS_WALLET_IDS` 3 个 2-of-3；`WORKERS=4 ROUNDS=15` | `ok=60 fail=0` | `TestBrokerNodeSignStressMultiWallet` |
| B3 | CLI Plan2 | broker :9422 | PublicKey / Login 成功 | `api_test.go`（可选） |

**钱包选择**：`keys/{tenant}/*.json` 中须 `keyMode=mpc`、`threshold=2`、`nodeIDs` 含 node0–2。默认压测钱包 ID 可能不存在，用 `STRESS_WALLET_ID` 覆盖。

**tenant / tradeKey**：与 `cli_config.yaml` → `cliBindings` 一致（当前 tenant `e5c689f687e5d291f0c1d0e19ed1d3c0`）。

### 阶段 C — 压测（可选，**仅 ECDSA CGGMP**）

见 `wallet-mpc-broker/docs/MPC_SIGN_STRESS_TEST.md`。

**暂不跑**：`TestBrokerNodeSignStressMixedWallets`（FROST/Ed25519 混合）、`alg_ed25519` 包联调。

### 阶段 D — 异常 / 故障模拟

见 `wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md`：

| 层 | 入口 |
|----|------|
| 进程内 wire/SSID/缺 peer/blackhole/Filter | `mpc/alg_ecdsa/sign_fault_test.go` + `filter_test.go` |
| broker 协调 offline/busy/failover/容量 | `app/mpc_*_test.go` |
| 网络 bad wallet / invalid payload / tradeSign 重放 / kill failover | `sign_abnormal_test.go`（`-tags stress`） |
| 脚本 kill-node / insufficient / all-down | `scripts/run_sign_abnormal_kill_node.ps1` |

---

## 3. 2026-09-13 实测记录（本地 alice replace）

| 步骤 | 结果 |
|------|------|
| `TestMainServe` + `walletMode=3` | 9422/9522 监听 OK |
| `TestRunNode0/1/2` | 三节点重连后 `CLIENT_CONNECTED` |
| `TestCGGMPKeygenAndSignTwoOfTwo` | PASS ~4.2s（msgType 1→6） |
| **A2** `TestSignSessionSubsetTwoOfThree` | PASS ~7s（2-of-3 子集 + digest） |
| **A2** `TestSignTwiceSameRefreshDifferentMessages` | PASS ~5.3s |
| **A2** `TestRefreshSubsetTwoOfThreeFiltered` | PASS ~5s |
| Alice `sign` 包全量单测 | PASS ~106s，**84.5%** |
| **A3** 进程内 fault（broker+node） | PASS ~200s |
| **D** abnormal 网络单测 | PASS（bad wallet / invalid tradeSign / empty payload / replay） |
| **D** `run_sign_abnormal_kill_node.ps1` | PASS（kill-during-sign failover ~5s） |
| `TestBrokerNodeSignPreflight`（`1CToiZ…`） | PASS ~4.6s |
| `TestBrokerNodeSignPreflight`（`112uMQc…`） | PASS ~0.4s（warm 后） |
| `TestBrokerNodeSignStress`（5 轮串行） | PASS 5/5，p50 ~354ms |
| **B2+ 并发** `workers=4 rounds=20` 单钱包 | PASS **80/80**，p50 ~1.5s，~46s 总耗时 |
| **B3 多钱包** 3 钱包 × 4 worker × 15 轮 | PASS **60/60**，p50 ~702ms，~25s 总耗时 |

**结论**：本地 alice（Pairwise Echo Digest）在 2-of-3 broker↔node 链路下，单钱包串行/并发、多钱包并行签名均稳定，`fail=0 panic=0 inFlight=0`。

---

## 4. 故障排查

| 症状 | 处理 |
|------|------|
| node 一直 `connect refused` | 先起 `TestMainServe`，再起 node |
| node 起在错误目录 | 必须在 `wallet-mpc-node/integration` 下跑 `TestRunNode*` |
| `load wallet meta: file not found` | 设置 `STRESS_WALLET_ID` 为现有 2-of-3 钱包 |
| sign 超时 / warm 等待 | 首签可能等 refresh warm（最长 ~120s）；重试 B1 |
| `sign already in progress` | 同 key 并发；降低 `STRESS_WORKERS` 或串行 |
| 改回远程 alice | 注释 `replace`，`go mod tidy` |

---

## 5. 建议执行顺序（**改动代码优先**）

| 顺序 | 内容 | 阻塞 |
|------|------|------|
| 1 | **L1** Alice `sign` + `types/message` 单测 + 覆盖率门禁 | 是 |
| 2 | **L2** 阶段 A1 → A2（进程内 CGGMP sign + digest） | 是 |
| 3 | §1 启动 broker + node0–2 | 联调前 |
| 4 | **L3** 阶段 B1 → B2（ECDSA 2-of-3 诚实 sign） | 是 |
| 5 | 阶段 B3 多钱包 / B2+ 并发 | 否 |
| 6 | 阶段 D abnormal（fault + 网络 + kill 脚本） | 否 |
| — | FROST / 混合压测 | **跳过** |

---

## 6. 相关文档

| 文档 | 说明 |
|------|------|
| PAIRWISE_ECHO.md | Alice 改造 · L1 测试 |
| wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md | 异常矩阵与脚本 |
| wallet-mpc-broker/docs/MPC_SIGN_STRESS_TEST.md | 压测参数 |

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-13 | 初版 replace + 四阶段 |
| 2026-09-13 | **改为 TestMainServe + TestRunNode0/1/2 主路径**；补充 B1/B2 命令与实测记录 |
| 2026-09-13 | 补充 B2+ 并发 / B3 多钱包压测结果（80/80、60/60 全绿） |
| 2026-09-13 | **异常测试**：`sign_fault_test.go` + `sign_abnormal_test.go`；见 `wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md` |
| 2026-09-13 | L1 细节迁至 `PAIRWISE_ECHO.md`；本文保留联调操作 |
