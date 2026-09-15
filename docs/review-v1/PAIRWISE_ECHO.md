# Pairwise Echo Digest — CGGMP + FROST

> **Status**: Implemented · Shared `crypto/tss/pairwise`  
> **CGGMP**: `crypto/tss/ecdsa/cggmp/sign` · **FROST**: `crypto/tss/eddsa/frost/signer` (frost-sign-v2)  
> **Related**: [CGGMP.md](./CGGMP.md) · [FROST.md](./FROST.md) · [CGGMP_IA.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) (filename retained for history)  
> **Last code alignment**: 2026-09-14 · CGGMP sign Echo three-step main closed loop verified; edge cases see IA_LIMITS §8  
> **Prerequisite**: Breaking wire change; **no** legacy-node compatibility

---

## 0. Shared Model

| Item | Description |
|------|-------------|
| Goals | P0 no broken signatures / no key leakage; P1 prevent pairwise equivocation; P2 engineered blame (see IA docs) |
| Mechanism | Round\*Digest (Echo barrier) → Round\* reveal (`GetEchoMessage=nil`) + **gate** verifies edge digest |
| Primitives | BLAKE2b-256 + length prefix; `ValidateDigestTable` / `table_root`; `crypto/tss/pairwise` |
| Accountability | Digest timeout → Suspect; gate/ZK/Echo conflict → Confirmed (CGGMP/FROST aligned `GetBlameResult`) |

| | CGGMP Sign | FROST Sign |
|--|------------|------------|
| Digest rounds | R1–R3 | R1–R2 |
| Wire | Type 0–8 (incl. Err1/Err2) | Type 0–3 (frost-sign-v2) |
| IA / DecModQ | Scheme A′ Err1/Err2 | No Paillier; algebraic failure + digest blame |
| DST | CGGMP pairwise DST | `AMIS-Alice-FROST-Sign-Pairwise-Digest-v1` |

### 0.1 Equivocation Closed Loop and Boundaries

**Two-layer split**: DecModQ / R1-FS = the **trust base** for Err-path IA (forged ZK cannot freely sling blame); **Echo three-step** = the **direct mechanism** against equivocation.

| Step | Mechanism | 3-round sign |
|------|-----------|--------------|
| Digest exchange | `Round*Digest` + `table_root` + Digest Echo | Yes |
| Inconsistency detection | Echo hash conflict · `ValidateDigestTable` · `gateEdgeDigest` | Yes |
| Attribution | `SetOnConflict` → Confirmed author; gate/table failure → blame sender; timeout → Suspect | Yes |

**Reveal is not Echoed (by design)**: Depends on the **Digest barrier already completing**, and the gate being able to access the corresponding **store entry**. If the store is missing, the current implementation blames the **reveal sender** (`ErrDigestBarrier`); the IA-05 P1 diagnostic branch (“digest was received but not stored” → local fault, do not blame remote) is deferred to **PR-D3**, see [IA_LIMITS · IA-05](./CGGMP_IA_LIMITS_AND_REMEDIATION.md#ia-05--gate-store-miss-blame-direction).

**Test coverage scope**: The three-step closed loop is verified on 3-round sign **honest paths** + **mesh abort E2E**; edge scenarios (gate local diagnosis, Err2 absence attribution, `GetBlameResult` mutual exclusion, etc.) completion is tracked in [IA_LIMITS §8](./CGGMP_IA_LIMITS_AND_REMEDIATION.md#8-additional-test-checklist). **signSix / Refresh** Echo remains weak (do not extrapolate that the whole library is equivocation-hardened).

---

## A. CGGMP Sign

### A.1 Change Feature Points (vs v1.0.7)

| # | Feature | Change | Related files |
|---|---------|--------|---------------|
| P1 | **R1–R3 Digest dual barrier** | Each round Commit (Digest Echo) → Reveal (pairwise gate); Reveal is not Echoed | `digest_handlers.go` |
| P2 | **Pairwise edge hash** | BLAKE2b v3 + length prefix; R2 canon excludes Γ; `table_root` dual commitment | `crypto/tss/pairwise` · `pairwise_digest.go` |
| P3 | **Digest table completeness** | Missing/extra/duplicate peer, wrong digest length, wrong root → blame author | `ValidateDigestTable` |
| P4 | **Reveal cross-check** | R1 K/Γ; R2 Γ; R3 δ/Δ must match Digest header before ZK | `round_1/2/3.go` |
| P5 | **Digest barrier gate** | No store entry → `ErrDigestBarrier` blame **reveal sender** | `gateEdgeDigest` |
| P6 | **Digest timeout accountability** | Sign-level `OnDigestTimeout` → blame **peer missing digest** | `digest_handlers.go` |
| P7 | **Echo layering** | Digest/R4/Err Echo; Round1/2/3 reveal `GetEchoMessage=nil` | `message.go` |
| P8 | **Echo conflict accountability** | Digest author inconsistent across peers → blame author | `WrapEchoAbortCollect` |
| P9 | **Err1 accountable abort** | δ aggregation failure → build DecModQ package → broadcast collect → `ProcessErr1Msg` | `round_3.go` · `err_process.go` |
| P10 | **Err2 accountable abort** | Signature verification failure → Scheme A′ dual DecModQ → broadcast collect → `ProcessErr2Msg` | `round_4.go` · `err_process.go` |
| P11 | **Err bound to digest** | D/F in Err must match Round2 pairwise digest in store | `sessionRound2MatchesDigest` |
| P12 | **Blame API** | `GetBlameResult` (Confirmed/Suspect); `GetBlamedPeers` = union for compatibility | `blame` · `sign.go` |
| P13 | **9-party cap** | `MaxIARemotePeers=8`; enforced by `NewSign` / `ProcessErr*` | `cggmp/utils.go` |
| P14 | **Breaking wire** | Type 0–8 renumbered; no feature flag | `message.proto` |
| P15 | **Mesh abort E2E** | Full-process mesh triggers Err1/Err2 (not AddMessage injection) | `sign_mesh_abort_test.go` |

**Protocol flow (brief)** (success path **7** stages after CoFlight redesign):

```text
R1Digest ‖ Round1 ──► R2Digest ‖ Round2 ──► R3Digest ‖ Round3 ──► Round4(σ, no Echo)
  (Digest still Echo-gated before MsgMain; Reveal co-flighted; Finalize needs echoDone∧revealDone)
```

See [CGGMP_SIGN_7RTT_COFLIGHT_DESIGN.md](./CGGMP_SIGN_7RTT_COFLIGHT_DESIGN.md).

**Wire Type**: `Round1Digest=0 … Round4=6, Err1=7, Err2=8` (all parties must be on the same fork; `Round1Digest.schedule_version` must equal `SignScheduleVersion=coflight-v1`).

---

## 2. Implementation Logic Branches × Test Coverage

> Column **Branch** = main if/abort paths in code; **Test** = representative entry points (same package also has `coverage_batch*` / Ginkgo supplements).

### 2.1 Digest Infrastructure

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| Change payload / peer_id → digest changes | `edgeDigest`, `Round*PairwiseDigest` | 32B BLAKE2b | `TestEdgeDigestStableAndSensitive`, `TestRound2PairwiseDigestExcludesGamma` |
| Table missing peer / duplicate / unknown / digest≠32B | `ValidateDigestTable` | Reject + blame table author | `TestValidateDigestTable*`, `TestAcceptDigestTableBlamesIncomplete3Party` |
| `table_root` mismatches recomputation | `commitDigestTable` / accept | `ErrDigestTableRoot` | `TestValidateDigestTable` badRoot |
| Store read/write | `crypto/tss/pairwise/store.go` · sign thin wrapper | Deep copy by round/sender/recipient | `TestPairwiseDigestStoreGetMiss` (indirect full suite) |

### 2.2 Round1 Digest → Round1 Reveal

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| `prepareRound1Digest` fails | `Sign.Start` | Does not start / `ms.Fail()` | `TestSignStartPrepareFailure*` |
| Digest nil body / illegal table | `round1DigestHandler.HandleMessage` | blame sender | `TestRound1DigestNilBodyBlamesSender`, `TestRound1DigestHandleMessageInvalidTableBlames` |
| Finalize missing pending | `round1DigestHandler.Finalize` | error | `TestRound1DigestFinalizeRequiresPending` |
| **Gate**: no store entry | `gateEdgeDigest` | blame reveal sender + `ErrDigestBarrier` | `TestGateDigestBarrierBlames` |
| **Gate**: H_edge mismatch | `gateEdgeDigest` | blame + `ErrPairwiseDigestMismatch` | `TestGateEdgeDigestMismatchBlames` |
| K/Γ inconsistent with digest header | `round1Handler.HandleMessage` | blame | `TestRound1CiphertextCrossCheck*`, `TestRound1GammaCiphertextMismatch*` |
| `Psi.Verify` fails | `round1Handler.HandleMessage` | blame | `TestRound1PsiEquivocation*`, `TestRound1InvalidPsiVerify*` |
| Digest timeout | `OnDigestTimeout` | blame peer that did not send R1Digest | `TestRound1DigestOnDigestTimeoutBlames`, Ginkgo digest timeout |
| R1 Digest Echo conflict | `WrapEchoAbortCollect` | blame digest author | `TestEchoConflictRound1DigestBlamesAuthor` |

### 2.3 Round2 Digest → Round2 Reveal

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| Build R2 digest fails | `buildRound2DigestAndBroadcast` | Finalize error | `TestBuildRound2DigestAndBroadcastError` |
| Digest Γ illegal / inconsistent with reveal | `round2DigestHandler` / `round2Handler` | blame | `TestRound2DigestInvalidGamma*`, `TestRound2GammaCrossCheck*` |
| MtA ZK (Psi/Psihat/Psipai) fails | `round2Handler.HandleMessage` | blame | `TestRound2InvalidPsi*`, `TestRound2InvalidPsihat*`, `TestRound2InvalidPsipai*` |
| **Same digest, different Round2 body to different peers** | gate + store | blame sender | `TestRound2EquivocationBlamesSender`, **`sign_e2e_test.go`** (3-party mesh tamper) |
| Digest timeout | `OnDigestTimeout` | blame missing R2Digest | `TestRound2DigestOnDigestTimeoutBlames`, Ginkgo |
| R2 Digest Echo conflict | Echo layer | blame author | `TestEchoConflictRound2DigestBlamesAuthor` |

### 2.4 Round3 Digest → Round3 Reveal → Err1

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| δ/Δ inconsistent with digest header | `round3Handler.HandleMessage` | blame | `TestRound3DeltaCrossCheckBlamesSender` |
| `Psidoublepai` / parse δ fails | `round3Handler.HandleMessage` | blame | `TestRound3InvalidPsi*`, `TestRound3InvalidDeltaParse*` |
| **`g·δ ≠ ΣΔ`** | `round3Handler.Finalize` | `enterErr1Phase(ErrInvalidDelta)` | `TestRound3FinalizeEntersErr1PhaseOnBadDelta` |
| `R` is point at infinity | `round3Handler.Finalize` | `ErrZeroR` (not Err1) | `TestRound3FinalizeZeroR` |
| Test hook tampers peer δ then re-aggregates | `round3BeforeAggregateVerifyTestHook` | Same Err1 path | **`TestMeshErr1AbortE2E`** |
| Building Err1 package fails | `buildDeltaVerifyFailureMsg` | Finalize error | `TestBuildDeltaVerifyFailureMsgBlamesInvalidPsi`, `TestOnAbortErr1BuildFailure` |
| Remote Err1 arrives | `onAbortErr1` | publish + switch to `err1Handler` | `TestMsgMainRound3OnAbortErr1ViaPopAny`, `TestOnAbortErr1HandlesRemoteMessage` |
| Err1 collection complete | `err1Handler.Finalize` | `ProcessErr1Msg` → blame | `TestErr1HandlerFinalizeBlamesBadPeer`, `TestProcessErr1MsgThreeParty*` |
| Digest timeout | `OnDigestTimeout` | blame missing R3Digest | `TestRound3DigestOnDigestTimeoutBlames`, Ginkgo |

### 2.5 Round4 → Err2

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| **`ecdsa.Verify` fails** | `round4Handler.Finalize` | `enterErr2Phase(ErrIncorrectSig)` | `TestRound4FinalizeEntersErr2PhaseOnBadSig` |
| `s == 0` | `round4Handler.Finalize` | `ErrZeroS` | round4 finalize unit test |
| Wire tamper σ (mesh) | `outboundTamperPM` | victim Err2 + blame attacker | **`TestMeshErr2AbortE2E`** |
| Building Err2 package fails | `buildSigmaVerifyFailureMsg` | error | `TestBuildSigmaVerifyFailureMsg*`, `TestOnAbortErr2BuildFailure` |
| Remote Err2 arrives | `onAbortErr2` / `round4 OnAbortMessage` | publish + switch to `err2Handler` | `TestMsgMainRound4OnAbortErr2ViaPopAny`, `TestRound4OnAbortMessageRoutesErr2` |
| Err2 collect / absent sender | `ProcessErr2Msg` + `blameAbsentSenders` | blame set | `TestProcessErr2MsgThreeParty*`, `err_process_coverage_test.go` |
| Round4 Echo(σ) | `GetEchoMessage` | Global σ Echo | Ginkgo `abort_test.go` |

### 2.6 Blame API and Echo/Collect Wrappers

| Branch / Condition | Implementation | Behavior | Test |
|--------------------|----------------|----------|------|
| Call `GetBlamedPeers` when not `StateFailed` | `sign.go` | `ErrBlamedPeersNotReady` | `TestGetBlamedPeersNotReady` |
| Cached `blamedPeers` already present | `storeBlamedPeers` | Union-merge and return | `TestGetBlamedPeersReturnsStoredCopy` |
| No cache; collector has Err | fallback → `ProcessErr*` | Offline analysis | `TestGetBlamedPeersFallback*` |
| Err1/2 broadcast | `publishErr1/2` | collector + `cggmp.Broadcast` | `TestPublishErr1RecordsAndBroadcasts`, `TestWrapEchoAbortCollectRecordsErr1` |
| D/F in Err inconsistent with store | `sessionRound2MatchesDigest` | blame | Ginkgo `sign_test.go`, `TestProcessErr1Msg*` sessionRound2 |
| Participants >9 | `ValidateIAParticipantCount` | error | `sign_limits_test.go`, `TestProcessErr*TooManyParticipants` |

### 2.7 Honest Paths and Scale

| Scenario | Implementation | Test |
|----------|----------------|------|
| 2-party sign | `buildSigns(2)` | Ginkgo `sign_test.go` *should be ok* |
| 3/9-party E2E | `sign_e2e_test.go` | 3-party honest + R2 equivocation |
| 10-party rejected | `newRound1Handler` | `sign_limits_test.go` |
| 9-party honest | Full-round digest + sign | Ginkgo *9-party honest sign* |

### 2.8 Mesh Abort E2E (PeerManager Real Broadcast)

| Case | Trigger | Assertion | Test |
|------|---------|-----------|------|
| **Err1 3-party** | Detector hook tampers attacker’s δ; Err1 mesh propagation | All Failed; detector blames attacker | `TestMeshErr1AbortE2E` |
| **Err2 2-party** | Attacker tampers victim’s Round4 σ | Victim Failed + blame; collector contains Err2 | `TestMeshErr2AbortE2E` |

> Err2 uses 2 parties: `err2Handler` needs `peerNum+1` Err2 messages; when the attacker’s local signature verification can pass, only the victim enters collection; attribution relies on `blameAbsentSenders` + offline `ProcessErr2Msg`.

---

## 3. Coverage and How to Run

### 3.1 Gate

```powershell
cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ ./types/message/ -count=1 -timeout 600s -coverprofile cover_sign.out
```

| Package | Current | Gate |
|---------|---------|------|
| `sign` | **84.5%** (~106s) | ≥80% |
| `types/message` | **68.5%** | All green (MsgMain infrastructure) |
| `digest_handlers` / `pairwise_store` | gate/accept/timeout **100%** | Critical paths |

### 3.2 Common Subsets

```powershell
# mesh abort (~12s)
go test ./crypto/tss/ecdsa/cggmp/sign/ -run TestMeshErr -v

# MsgMain digest/Echo/out-of-order
go test ./types/message/ -count=1 -timeout 120s
```

### 3.3 Test File Index

| Responsibility | File |
|----------------|------|
| Mesh / setup | `sign_setup_test.go`, `sign_mesh_abort_test.go` |
| Digest core | `pairwise_digest_test.go`, `pairwise_attack_test.go`, `digest_crosscheck_test.go`, `digest_zk_test.go` |
| Handler unit tests | `digest_handlers_coverage_test.go`, `digest_coverage2_test.go` |
| Err / abort | `err_process_coverage_test.go`, `abort_coverage_test.go`, `abort_e2e_coverage_test.go`, `coverage_batch3`–`9` |
| Ginkgo integration | `sign_test.go`, `sign_e2e_test.go`, `sign_limits_test.go`, `abort_test.go`, `err_test.go` |
| MsgMain | `types/message/digest_timeout_test.go`, `msg_main_echo_test.go`, `msg_main_order_test.go` |

---

## 4. Known Gaps (Marginal)

| Gap | Reason |
|-----|--------|
| `Round1PsiDigest` / `Round3PairwiseDigest` ~75% | Marshal failures hard to trigger stably |
| Partial ZK success combinations in `round_2/3.HandleMessage` | Need specific cryptographic inputs |
| `round_1 Finalize` MTA failure branch | Hard to inject without mocks |
| `signSix` / Refresh Echo | Out of scope for this change |
| L3 broker abort blame | Honest path verified; accountability primarily via L1 + mesh E2E |

---

## 5. L2/L3 Integration (Summary)

| Layer | What is verified | Entry |
|-------|------------------|-------|
| **L2** in-process broker | Digest rounds 1→6, fault, coordination layer | `wallet-mpc-broker/mpc/alg_ecdsa/` |
| **L3** broker↔node | Honest sign, abnormal, kill node | `BROKER_NODE_INTEGRATION_TEST_PLAN.md` |

B1/B2 success ⇒ end-to-end Pairwise Digest + CGGMP sign is usable; abort blame details follow §2 of this document.

---

## 6. Attack Matrix Cross-Check (Design §8)

| # | Attack | §2 Coverage |
|---|--------|-------------|
| 1 | R2 different body to different peers | 2.3 equivocation + `sign_e2e` |
| 2 | Different digest tables to different peers | 2.1–2.3 Echo conflict |
| 3 | Reveal before digest | MsgMain out-of-order buffer + gate barrier blame |
| 4 | Digest table missing peer | 2.1 ValidateDigestTable |
| 5 | Tamper `table_root` | 2.1 badRoot |
| 6 | R1 psi / ciphertext inconsistency | 2.2–2.4 cross-check |
| 7 | Err lies about D/F | 2.6 sessionRound2 + ProcessErr* |
| 8 | Relay alters H_edge | 2.2–2.4 gate mismatch |

---

## B. FROST Sign (frost-sign-v2)

> The former FROST Pairwise dedicated doc has been merged into this document. Open security items: see [FROST.md](./FROST.md).

### B.1 Protocol Flow and Wire

```text
R1Digest(Echo) ──► Round1(gate) ──► R2Digest(Echo) ──► Round2(gate) ──► verify ──► Done
```

| Type | Value |
|------|-------|
| Round1Digest | 0 |
| Round1 | 1 |
| Round2Digest | 2 |
| Round2 | 3 |

- Round1 payload: canonical D/E (+ bk X); Round2 payload: `zi`  
- `ComputeFrostSignSSID` binds session; Start must call `prepareRound1Digest` first  
- **Non-goals**: DKG Echo, Reshare, CGGMP Scheme A′ DecModQ  

### B.2 Gap vs Pre-Change (Closed)

| Capability | Old | Now |
|------------|-----|-----|
| Round1 | Global Echo(D,E) only | Digest + gate |
| Round2 | None | Digest + gate |
| Blame | Singular `GetBlamedPeer` | `GetBlameResult` / Confirmed∪Suspect |
| SSID | Weak | `ComputeFrostSignSSID` |

### B.3 Test Entry Points

```powershell
go test ./crypto/tss/eddsa/frost/signer/ ./crypto/tss/pairwise/ -count=1 -timeout 120s
```

---

## Revisions

| Date | Notes |
|------|-------|
| 2026-09-13 | CGGMP: merged into a single document; mesh E2E, 84.5% |
| 2026-09-14 | **Merged FROST Pairwise**; shared §0; FROST details in §B · open items in FROST.md |
| 2026-09-14 | §0.1: Echo three-step vs DecModQ base; Reveal/gate prerequisites; coverage scope |
| 2026-09-14 | English edition |
