# Local Alice → Broker / Node Integration Test Plan

> **replace**: `wallet-mpc-broker/go.mod`, `wallet-mpc-node/go.mod`  
> ```go
> replace github.com/getamis/alice => ../alice
> ```  
> Alice changes and L1 tests: same directory `PAIRWISE_ECHO.md`

> **Scope**: CGGMP ECDSA sign / Pairwise Echo Digest; FROST / Ed25519 are not release blockers.

| Layer | Result |
|-------|--------|
| **L1** Alice | sign **84.5%** · mesh Err1/Err2 E2E · see `PAIRWISE_ECHO.md` §3 |
| **L2** in-process | PASS (fault ~200s) · this doc §2 stage A |
| **L3** broker↔node | B1/B2+/B3 + abnormal PASS · this doc §2 stages B/D |

**L1 gate**: see `PAIRWISE_ECHO.md` §3.1.

## Alice Modules ↔ Integration Layers (summary)

| Module | L1 | L2 | L3 |
|--------|----|----|-----|
| digest / gate / Echo | `pairwise_*` · `digest_*` | A2 msgType 1→6 | B success implies full-path digest |
| Err1/Err2 blame | `TestMeshErr*` + `err_process_*` | — | honest path; attribution via L1 mesh |
| `round_*` / `sign.go` | Ginkgo `sign_test.go` | A2 subset sign | B1/B2/B3 |

---

## Architecture (this plan)

```text
Terminal 1  TestMainServe          → broker :9422 (CLI) + :9522 (node relay)
Terminal 2  TestRunNode0           → node0 ─┐
Terminal 3  TestRunNode1           → node1 ─┼→ WS :9522
Terminal 4  TestRunNode2           → node2 ─┘
Terminal 5  go test -tags stress   → SignTransaction via :9422 drives 3-node CGGMP sign
```

**Prerequisites**: `cli_config.yaml` configured with `walletMode: 3`, node0–2 `nodeBindings`, and matching tenant `cliBindings`; node configs live in `wallet-mpc-node/integration/cli_node{0,1,2}.json` and **must be started from the `integration/` directory** (relative path `cli_node0.json`).

---

## 0. One-time Checks

```powershell
cd E:\work\github\wallet-mpc-broker
go list -m github.com/getamis/alice    # => v1.0.7 => ../alice

cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ -count=1 -timeout 600s
```

| Item | Pass criteria |
|------|---------------|
| replace active | `=> ../alice` |
| Alice sign unit tests | all green (package coverage **84.5%**) |
| broker build | `go build ./...` clean (test helpers must be `*_test.go`) |

---

## 1. Start Services (4 terminals; suggested order)

### 1.1 Broker (start first)

```powershell
cd E:\work\github\wallet-mpc-broker
$env:BROKER_SERVE_TEST = "1"
# optional: $env:BROKER_CONFIG = "cli_config.yaml"
go test -run ^TestMainServe$ -timeout 0 -v
```

Logs should show:

- `listening on 127.0.0.1:9422`
- `listening on 127.0.0.1:9522`
- `walletMode=3`

### 1.2 Node0 / 1 / 2 (one terminal each)

```powershell
cd E:\work\github\wallet-mpc-node\integration
go test -run ^TestRunNode0$ -timeout 0 -v
# separate terminals: TestRunNode1$, TestRunNode2$
```

| Observation | Notes |
|-------------|-------|
| `connect refused` at startup | Normal: broker not ready yet; node will reconnect automatically |
| `websocket reconnect successful` | Connected to :9522 |
| broker log `CLIENT_CONNECTED user_id=node0/1/2` | All three nodes online |

### 1.3 Port probe

```powershell
Test-NetConnection 127.0.0.1 -Port 9422
Test-NetConnection 127.0.0.1 -Port 9522
```

---

## 2. Test Matrix

### Stage A — In-process (no broker/node needed)

Run from the **broker directory**:

```powershell
cd E:\work\github\wallet-mpc-broker

# A1 keygen + sign from scratch (2-of-2)
go test ./mpc/alg_ecdsa/ -run TestCGGMPKeygenAndSignTwoOfTwo -count=1 -timeout 10m -v

# A2 real 2-of-3 shares + warm refresh + sign (covers full Pairwise Echo rounds)
go test ./mpc/alg_ecdsa/ -run "TestSignSessionSubsetTwoOfThree|TestSignTwiceSameRefreshDifferentMessages|TestRefreshSubsetTwoOfThreeFiltered" -count=1 -timeout 15m -v

# A3 in-process fault (wire/SSID/missing peer/blackhole/Filter; no broker)
go test ./mpc/alg_ecdsa/ -run "Tampered|Missing|Different|Blackhole|RefreshMissing|SSID|Filter" -count=1 -timeout 15m -v
```

| Case | Verifies | Layer |
|------|----------|-------|
| `TestCGGMPKeygenAndSignTwoOfTwo` | dkg + **local alice sign** (incl. digest rounds msgType 1→6) | Inbox simulation |
| `TestSignSessionSubsetTwoOfThree` | 2-of-3 subset sign + digest | real integration shares |
| `TestSignTwiceSameRefreshDifferentMessages` | two consecutive signs with same refresh material | same as above |
| `TestRefreshSubsetTwoOfThreeFiltered` | 2-of-3 refresh warm | same (sign prerequisite) |
| **A3 fault** | wire tamper / missing peer / blackhole / SSID / Filter | fast fail or timeout, no hang | `sign_fault_test.go`, `filter_test.go` |

Node-side mirror: `wallet-mpc-node/mpc/alg_ecdsa/` (same commands, change directory).

### Stage B — Broker ↔ 3 Node Integration (**primary path for this environment**)

**After services are started per §1**, from the broker directory:

```powershell
cd E:\work\github\wallet-mpc-broker

# B1 single-tx smoke (required)
$env:BROKER_SIGN_STRESS = "1"
$env:STRESS_WALLET_ID = "1CToiZvPtGoCEmyoEYayB3cozrh3aici1M"   # 2-of-3 ecdsa, node0–2
go test -tags stress -run ^TestBrokerNodeSignPreflight$ -count=1 -timeout 15m -v

# B2 five consecutive txs (same wallet, different nonces)
$env:STRESS_ROUNDS = "5"
$env:STRESS_WORKERS = "1"
go test -tags stress -run ^TestBrokerNodeSignStress$ -count=1 -timeout 15m -v

# B2+ single-wallet concurrency (4 workers × 20 rounds = 80 requests)
$env:STRESS_WORKERS = "4"
$env:STRESS_ROUNDS = "20"
$env:STRESS_MIN_OK_PCT = "95"
go test -tags stress -run ^TestBrokerNodeSignStress$ -count=1 -timeout 20m -v

# B3 multi-wallet parallel (3 wallets)
$env:STRESS_WALLET_IDS = "1CToiZvPtGoCEmyoEYayB3cozrh3aici1M,112uMQcPAJEjX6FaZjVHNPWag4r8zLcy5n,16hyedepYpLGLHdGxnEeBoTefhYaS4dzZx"
$env:STRESS_MIN_WALLETS = "3"
$env:STRESS_WORKERS = "4"
$env:STRESS_ROUNDS = "15"
go test -tags stress -run ^TestBrokerNodeSignStressMultiWallet$ -count=1 -timeout 30m -v
```

| ID | Scenario | Conditions | Expect | Entry |
|----|----------|------------|--------|-------|
| B1 | single ETH sign | 3 nodes online; 2-of-3 wallet | `preflight ok`, ~3–10s | `TestBrokerNodeSignPreflight` |
| B2 | consecutive signs, same wallet | `STRESS_ROUNDS=5`, single worker | `ok=5 fail=0`, `inFlight=0` | `TestBrokerNodeSignStress` |
| B2+ | concurrent signs, same wallet | `STRESS_WORKERS=4 STRESS_ROUNDS=20` | `ok=80 fail=0` (same-wallet MPC segment is serial; workers queue) | same |
| B3 | multi-wallet parallel | `STRESS_WALLET_IDS` 3× 2-of-3; `WORKERS=4 ROUNDS=15` | `ok=60 fail=0` | `TestBrokerNodeSignStressMultiWallet` |
| B3 | CLI Plan2 | broker :9422 | PublicKey / Login success | `api_test.go` (optional) |

**Wallet selection**: under `keys/{tenant}/*.json`, require `keyMode=mpc`, `threshold=2`, `nodeIDs` containing node0–2. Default stress wallet IDs may not exist; override with `STRESS_WALLET_ID`.

**tenant / tradeKey**: must match `cli_config.yaml` → `cliBindings` (current tenant `e5c689f687e5d291f0c1d0e19ed1d3c0`).

### Stage C — Stress (optional, **ECDSA CGGMP only**)

See `wallet-mpc-broker/docs/MPC_SIGN_STRESS_TEST.md`.

**Do not run for now**: `TestBrokerNodeSignStressMixedWallets` (FROST/Ed25519 mix), `alg_ed25519` package integration.

### Stage D — Abnormal / Fault Simulation

See `wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md`:

| Layer | Entry |
|-------|-------|
| In-process wire/SSID/missing peer/blackhole/Filter | `mpc/alg_ecdsa/sign_fault_test.go` + `filter_test.go` |
| broker coordination offline/busy/failover/capacity | `app/mpc_*_test.go` |
| network bad wallet / invalid payload / tradeSign replay / kill failover | `sign_abnormal_test.go` (`-tags stress`) |
| scripts kill-node / insufficient / all-down | `scripts/run_sign_abnormal_kill_node.ps1` |

---

## 3. 2026-09-13 Measured Results (local alice replace)

| Step | Result |
|------|--------|
| `TestMainServe` + `walletMode=3` | 9422/9522 listening OK |
| `TestRunNode0/1/2` | three nodes `CLIENT_CONNECTED` after reconnect |
| `TestCGGMPKeygenAndSignTwoOfTwo` | PASS ~4.2s (msgType 1→6) |
| **A2** `TestSignSessionSubsetTwoOfThree` | PASS ~7s (2-of-3 subset + digest) |
| **A2** `TestSignTwiceSameRefreshDifferentMessages` | PASS ~5.3s |
| **A2** `TestRefreshSubsetTwoOfThreeFiltered` | PASS ~5s |
| Alice `sign` package full unit tests | PASS ~106s, **84.5%** |
| **A3** in-process fault (broker+node) | PASS ~200s |
| **D** abnormal network unit tests | PASS (bad wallet / invalid tradeSign / empty payload / replay) |
| **D** `run_sign_abnormal_kill_node.ps1` | PASS (kill-during-sign failover ~5s) |
| `TestBrokerNodeSignPreflight` (`1CToiZ…`) | PASS ~4.6s |
| `TestBrokerNodeSignPreflight` (`112uMQc…`) | PASS ~0.4s (after warm) |
| `TestBrokerNodeSignStress` (5 serial rounds) | PASS 5/5, p50 ~354ms |
| **B2+ concurrent** `workers=4 rounds=20` single wallet | PASS **80/80**, p50 ~1.5s, ~46s total |
| **B3 multi-wallet** 3 wallets × 4 workers × 15 rounds | PASS **60/60**, p50 ~702ms, ~25s total |

**Conclusion**: local alice (Pairwise Echo Digest) is stable on the 2-of-3 broker↔node path for single-wallet serial/concurrent and multi-wallet parallel signing, with `fail=0 panic=0 inFlight=0`.

---

## 4. Troubleshooting

| Symptom | Action |
|---------|--------|
| node stuck on `connect refused` | start `TestMainServe` first, then nodes |
| node started in wrong directory | must run `TestRunNode*` under `wallet-mpc-node/integration` |
| `load wallet meta: file not found` | set `STRESS_WALLET_ID` to an existing 2-of-3 wallet |
| sign timeout / warm wait | first sign may wait for refresh warm (up to ~120s); retry B1 |
| `sign already in progress` | same-key concurrency; lower `STRESS_WORKERS` or run serial |
| revert to remote alice | comment out `replace`, `go mod tidy` |

---

## 5. Suggested Execution Order (**code changes first**)

| Order | Content | Blocking |
|-------|---------|----------|
| 1 | **L1** Alice `sign` + `types/message` unit tests + coverage gate | yes |
| 2 | **L2** stage A1 → A2 (in-process CGGMP sign + digest) | yes |
| 3 | §1 start broker + node0–2 | before integration |
| 4 | **L3** stage B1 → B2 (ECDSA 2-of-3 honest sign) | yes |
| 5 | stage B3 multi-wallet / B2+ concurrent | no |
| 6 | stage D abnormal (fault + network + kill script) | no |
| — | FROST / mixed stress | **skip** |

---

## 6. Related Documents

| Document | Notes |
|----------|-------|
| PAIRWISE_ECHO.md | Alice changes · L1 tests |
| wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md | abnormal matrix and scripts |
| wallet-mpc-broker/docs/MPC_SIGN_STRESS_TEST.md | stress parameters |

---

## Revisions

| Date | Notes |
|------|-------|
| 2026-09-13 | Initial replace + four stages |
| 2026-09-13 | **Switched to TestMainServe + TestRunNode0/1/2 primary path**; added B1/B2 commands and measured results |
| 2026-09-13 | Added B2+ concurrent / B3 multi-wallet stress results (80/80, 60/60 all green) |
| 2026-09-13 | **Abnormal tests**: `sign_fault_test.go` + `sign_abnormal_test.go`; see `wallet-mpc-broker/docs/BROKER_NODE_ABNORMAL_TEST.md` |
| 2026-09-13 | L1 detail moved to `PAIRWISE_ECHO.md`; this doc keeps integration ops |
| 2026-09-14 | English edition |
