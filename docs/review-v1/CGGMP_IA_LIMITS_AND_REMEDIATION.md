# CGGMP · Pairwise Echo · IA — Issue List and Remediation

> **Status**: review-v1 supplement (2026-09-13)  
> **Scope**: `crypto/tss/ecdsa/cggmp/sign` · `crypto/tss/pairwise` · `types/message` · Scheme A′ IA  
> **Related**: [README.md](./README.md) · [CGGMP.md](./CGGMP.md) · [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) · [FROST.md](./FROST.md) · [R1-FS_risk_memo.md](./R1-FS_risk_memo.md)  

> **Audience**: security audit / MPC integration / operations  
> **Purpose**: unify **issue status semantics**, expose **IA attributable blame boundaries**, provide **actionable remediation**

---

## 1. Conclusions (external messaging)

| Tier | Commitment | Notes |
|------|------------|-------|
| **P0** | No bad signatures / no key leakage | Abort on failure paths; `GetResult` only in `StateDone` |
| **P1** | Anti-equivocation | Pairwise Digest + Digest Echo + reveal gate (landed for sign) |
| **P2** | Identifiable Abort | **Engineering attribution**: most malicious paths can use `GetBlamedPeers()`; **not** paper-grade “uniquely provable attribution” |

**Forbidden external claim**: “Any malicious party is always uniquely attributed by cryptography.”  
**Allowed external claim**: “Failures abort; common malice / inconsistent broadcasts can point to a suspect peer; known heuristics and over-blame are in §3–§4 of this document.”

**API wording (PR-D1 / PR-D3 goals)**:

- Integration layers **must not** treat the mixed set from `GetBlamedPeers()` as courtroom-grade “confirmed malice”;
- Target API: `GetBlameResult()` returns `{ Confirmed, Suspect }` (or `GetConfirmedPeers()` / `GetSuspectPeers()`);
- **Confirmed**: DecModQ/ZK failures, cryptographic gate failures, explicit sender blame, and other **cryptographic paths**;
- **Suspect**: digest timeouts, Err2 absence, multi-solution mask cohorts, global Δ over-blame, and other **ops hints**;
- Transition: `GetBlamedPeers()` = `Confirmed ∪ Suspect` (compatibility); document as **deprecated for penalty logic**.

---

## 2. Status semantics (four tiers)

Older docs used a bare ✅ that was easy to confuse with “IA complete.” This list unifies:

| Status | Meaning |
|--------|---------|
| **Fixed** | Code + unit tests closed; remaining risk is theoretical only |
| **Partial** | Main risk mitigated (e.g. DoS, most blame paths), but IA soundness / coverage not closed |
| **Open** | Clear code or documentation gap; should be scheduled |
| **Accepted risk** | Known cryptographic/engineering boundary; needs sign-off rationale and impact scope |

---

## 3. Primary issue list

### 3.1 Security review leftovers (F / M series)

| ID | Sev | Issue | Status | Notes |
|----|-----|-------|--------|-------|
| F-01 | High | Echo / Pairwise Digest | **Partial** | sign ✅; signSix / refresh **Open** (still weak Echo) |
| F-02 | Med | Sign entry ped validation | **Fixed** | `ValidateAllPed` |
| F-03 | Med | DKG Schnorr commitment | **Fixed** | No longer silent `return nil` |
| M-01 | Med | Round3 Delta string DoS | **Fixed** | `ParseBigIntString`; **≠** precise IA attribution |
| F-04 | Med | Err broadcast collection | **Fixed** | Err1/Err2 state machine |
| F-05 | Med | signSix Err2 Type | **Fixed** | `round_6.go` |
| M-02 | Med | partialPubKey validation | **Fixed** | Sign entry `ValidatePublicKey` |
| F-06 | Low | msg into ssid | **Fixed** | `ComputeSignSSID` |
| F-07 | Low | Refresh Echo | **Open** | No Pairwise Digest |
| F-08 | Low | Refresh integration | **Open** | Integration-layer warm / material consistency |

### 3.2 IA / Pairwise focus (IA-xx newly added in this review)

| ID | Sev | Issue | Status | Impact |
|----|-----|-------|--------|--------|
| **IA-01** | High | PublicX / mask enum **returns on first VerifyModQ success** | **Partial** | PR-D1: full enum + AmbiguousMaskPolicy + BlameResult; Option C (uniqueness lemma) still pending |
| **IA-02** | High | **R1-FS**: `GetE` non-prime challenge | **Accepted risk** | No closed proof-layer argument; runtime gcd always holds; attribution precision see IA-01/03 (memo §2.5.3) |
| **IA-03** | Med | Err1 **precise attribution** is limited (DecModQ self-check; ∑δ≠Δ over-blame) | **Partial** | IA selling points overstated |
| **IA-04** | Med | Digest **timeout blame** (slow/partition vs malicious silence) | **Partial** | Availability / false penalties |
| **IA-05** | Med | `gateEdgeDigest` store miss **unilaterally blames reveal side** | **Partial** | Extreme routing may blame wrong direction |
| **IA-06** | Med | Err2 **absence attribution** (`blameAbsentSenders`) | **Partial** | Absence ≠ malice |
| **IA-07** | Low | Docs ✅ conflated with IA capability | **Open** | Audit friendliness (this doc is the remediation) |
| **IA-08** | Low | R1 Checklist omits w-Weak / equivalence classes | **Open** | See §6 |

### 3.3 Pairwise Echo (PE-xx, orthogonal to IA)

| ID | Sev | Issue | Status |
|----|-----|-------|--------|
| PE-01 | — | CGGMP sign R1–R3 Digest dual barrier | **Fixed** |
| PE-02 | — | FROST sign R1–R2 Digest dual barrier | **Fixed** |
| PE-03 | — | DKG / Refresh Pairwise | **Open** (not P0) |
| PE-04 | — | signSix Pairwise | **Open** |

---

## 4. Per-item remediation

### IA-01 · PublicX / mask enumeration uniqueness

**Current state** (`sign/err_helpers.go` · `matchDecModQWithBetaCorrection`):

- Enumerate `c_j ∈ {0,1}` (≤8 remote peers → ≤256 masks);
- **`VerifyModQ` returns `true` on first success** (early exit);
- Doc §4 says “return on first match,” matching the implementation.

**Risk**:

- If **two masks** both pass DecModQ verification, attribution depends on **enumeration order**, not provable uniqueness;
- §5.2 “\|Y\|<8N unique lift” constrains the **representative of Y**, and **does not imply uniqueness of the c vector**.

**Options (by priority)**:

| Option | Work | Recommendation |
|--------|------|----------------|
| **A · Docs** | Mark in CGGMP.md / integration specs: “multi-solution mask = imprecise blame” | **Immediate** |
| **B · Conservative impl** | Enumerate **all** masks (find first, then finish scan; ≥2 → `MaskAmbiguous`); 0 → **Confirmed** blame sender; **>1 → imprecise blame** (see **default policy** below) | **Landed (PR-D1)** |
| **C · Cryptography** | Prove lemma: under `MaxIARemotePeers=8` + Paillier params, mask is unique (or w.h.p. unique) | **P2 research**; must not mark **Fixed** until closed |

**Multi-mask default policy (PR-D1 must hard-code; no implementer improvisation)**:

| Policy | Confirmed | Suspect | Ops | Fit |
|--------|-----------|---------|-----|-----|
| **`SuspectAllErr` (default)** | **Empty** | **This round’s Err senders − Confirmed** | `AmbiguousMask` alert | Production default: no crypto confirmation, but cohort likely contains the adversary |
| `SuspectNone` | Empty | Empty | Same + **must** escalate manually | Conservative deploy: zero false-suspect damage |
| `ConfirmAllErr` | cohort → Confirmed | Empty | Alert | **Only** `-tags alice_ia_debug`; production `SetAmbiguousMaskPolicy` **force-remaps → SuspectAllErr** |

- Alice: `crypto/tss/blame` · `AmbiguousMaskPolicy`, default **`SuspectAllErr`**;
- Production builds: `ConfirmAllErr` **unavailable** (`policy_prod.go`); debug builds: `-tags alice_ia_debug`;
- **Forbidden** default `ConfirmAllErr` — conflicts with §1 “not uniquely provable attribution.”

**Acceptance**:

- Unit test: `TestGetBlameResultSplitsDisjoint` (Confirmed ∩ Suspect = ∅);
- Unit test: `TestAmbiguousMaskPolicyCohortExcludesConfirmed` (cohort = Err − Confirmed);
- Unit test: `TestAmbiguousMaskPolicyConfirmAllErrRemappedInProd`;
- Benchmark still keeps `MatchDecModQMaskEnum8` (worst-case 256; impl finds first then finishes scan; ≥2 early-returns Ambiguous).

---

### IA-02 · R1-FS Challenge non-prime (Accepted Risk)

**Reading order** (quantified detail in [R1-FS_risk_memo.md](./R1-FS_risk_memo.md)):

```text
Runtime safety     → memo §2.1 (deterministically 0)
Generic upper bound → memo §2.2 (O(2^-1024))
What is accepted   → memo §2.3 (A/B/C)
Worst-case outcome → memo §2.4 (branches 1/2)
Forgery hardness   → memo §2.5 (DCR constraints)
sign-off           → memo §2.4.3 (citable directly)
```

**Current state** (`crypto/zkproof/paillier` · `GetE`):

- Code matches **upstream**: Fiat–Shamir challenge \(e \in [-q/2,q/2]\) is an **integer**, **not prime**;
- memo §2.1: when \(e\neq e'\), \(\gcd(e-e',N)=1\) holds **deterministically** (not w.h.p.); **no runtime impact**;
- **Sole weakness (proof layer)**: proof template not stated in standard FS form → standard-model soundness has **no closed argument**; runtime unaffected; **no known attack**;
- **GetE not changed** — affects **entire alice library** Paillier ZK, not IA alone.

**Accepted Risk record (needs sign-off)** — quantified memo: [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) (§0 accurate status table)

| Item | Content |
|------|---------|
| **Impact** | DecModQ / Mul / Aff and other FS proofs; **proof template** uses non-prime integer challenge (same as upstream) |
| **Runtime \(\gcd(e-e',N)\neq 1\)** | Under Alice default params, when \(e\neq e'\) **probability = 0** (\(|e-e'|\le q\ll \min(p,p')\)); \(e=e'\) is FS binding, not a random gcd event |
| **Generic random upper bound (template)** | Without \(\|e\|\le q/2\) constraint, \(\Pr[\gcd\neq 1]=O(2^{-1024})\) (2048-bit \(N=p\cdot p'\) union bound) |
| **What is actually accepted** | **Proof-template wording gap (A)** — worst-case outcomes in memo **§2.4**; **≠** runtime weakening; gcd (B) is negligible |
| **Precise meaning of “weak”** | Only: **no closed soundness argument** in the standard model (proof layer); code behavior matches upstream; docs tighter than old comments |
| **Forging DecModQ proof hardness** | See memo **§2.5** (branch 1: gcd path impossible; branch 2: no closed argument / no known construction; lower bound under DCR) |
| **Primary cause of IA attribution imprecision** | **Not** R1-FS; see **IA-01 / IA-03** and memo **§2.5.3** |
| **Why not blocking sign release** | Matches upstream alice; changing GetE is a library-wide breaking change |
| **Closure path** | PR-D4a memo ✅ · PR-D4b prime challenge PoC (separate branch) |

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) + CGGMP.md §5.4 mark **Accepted risk** |
| P1 | External crypto review sign-off on memo **§2.4.3** |
| P2 | PR-D4b: `GetE` prime challenge PoC (does not block mainline) |

---

### IA-03 · Err1 precise attribution capability

**Current state** (`sign/err_process.go` · `ProcessErr1Msg`):

1. **DecModQ path**: verifies Err1 broadcaster **self-consistency** (local ciphertext ↔ broadcast \(x\)) — **self-proof / self-exposure**, does **not** directly name the upstream MtA adversary;
2. **Mul/Aff ZK failure**: should already blame in **Round1/2** (happy path);
3. **Global \(\sum\delta \neq \Delta\)**: after all DecModQ pass, **all remote Err1 senders** enter `errPeers` — **coarse over-blame**.

**Distinction from M-01**:

| Item | M-01 | IA-03 |
|------|------|-------|
| Problem | Malformed Delta → panic DoS | Who is responsible for δ inconsistency |
| Fix | Parse error | **Not** narrowed to a single peer |
| Status | **Fixed** | **Partial** |

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | List IA-03 separately in the issue table; forbid reading M-01 ✅ as IA completeness |
| P1 | Docs + `GetBlamedPeers` comments: Err1 global Δ failure = **suspect set**, not courtroom evidence |
| P2 | Research whether paper Err1 can name MtA adversary when all DecModQ pass (may need extra ZK) |

---

### IA-04 · Digest timeout blame

**Current state**:

- `MsgMain.SetAbortTimeout` (default **2 minutes**) applies to `DigestBarrierHandler`;
- Timeout → `OnDigestTimeout` → blame peers that **did not send digest in that round**;
- **Cannot distinguish** malicious silence vs slow network / partition.

**Relation to broker layer**:

- Broker **JWT WS disconnect** → `abortMpcTask` (**second-scale**), usually **before** the 2-minute timeout;
- The 2-minute window mainly covers **“still appears online but never sends digest”** or **tests/partitions without broker abort**.

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | Integration docs: digest timeout blame = **best-effort**; **must not** be the sole basis for economic penalties |
| P1 | `SetAbortTimeout` configurable; production suggestion **30s–120s** tuned by RTT |
| P1 | Optional broker: **sign-phase protocol idle timeout** (WS up but no mpc wire for a long time) |
| P1 | Timeout blame written to **Suspect** (not Confirmed); see §4.7 API |
| P2 | Broker `BlamedNodes[]` carries suspect/confirmed tags (INT-04) |

---

### IA-05 · Gate store miss blame direction

**Current state** (`crypto/tss/pairwise/gate.go`):

```text
Store.Get(round, sender, self) fails → Blame(sender) → ErrDigestBarrier
```

Here `sender` = **reveal message sender**.

**Design assumption**:

- MsgMain ordering guarantees: Round reveal handlers run **only after Digest barrier completes**;
- Missing store entry is more often explained as **reveal racing ahead / local state inconsistency**, not “digest lost on the wire but reveal is legitimate.”

**Residual risk**:

- If an implementation bug or reordering delivers reveal before digest is stored, we **blame the reveal side**;
- If the digest sender never sent and the reveal side also never sent, **Digest timeout (IA-04)** should blame the missing digest side.

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | Document **gate blame directionality assumptions** (above; also [PAIRWISE_ECHO.md §0.1](./PAIRWISE_ECHO.md)) |
| **P1** | **Gate failure diagnostic branch** (engineering correctness, preferred over unilateral reveal blame): |
| | 1. On `Store.Get` failure, check whether local side **ever received** that `sender`’s digest (in-memory store / logs / `DigestBarrier` receive records); |
| | 2. **If received** → classify as **local processing-path fault**: **blame no remote**; both `Confirmed`/`Suspect` empty; raise `LocalDigestProcessingFault` ops alert; |
| | 3. **If not received** → keep current logic: **Suspect** blame reveal side (or combine with IA-04 timeout blame of missing digest side); |
| P1 | Merge `OnDigestTimeout` and gate-failure **blame context** (logs include round / whether digest was ever received / diagnostic branch result) |
| P2 | Persist digest receive audit trail (cross-process replay diagnosis) |

---

### IA-06 · Err2 absence attribution

**Current state** (`sign/err_helpers.go` · `blameAbsentSenders`):

- Peers that did not broadcast Err2 enter the blamed set;
- **2-party scenario**: attacker’s local verify may succeed → **no Err2 sent**; victim relies on **absence + offline `ProcessErr2Msg`**;
- **Absence** may come from: malice, network, or implementation choice.

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | Docs: absence blame = **ops hint**; precise attribution depends on **ProcessErr2 receiving a valid Err2 + ZK** |
| **P1** | `blameAbsentSenders` output goes to **Suspect**, **must not** enter Confirmed (same tier as IA-04) |
| P1 | Complete 3-party+ honest mesh tests (partial coverage already exists) |
| P2 | Document Err2 collection timeout vs `ErrAbortTimeout` (CGGMP Err collection phase) |

---

### §4.7 · Blame API: Confirmed vs Suspect (closes IA-04 / IA-06 / §1)

**Current state**: `GetBlameResult()` / `GetConfirmedPeers()` / `GetSuspectPeers()` landed (CGGMP sign + FROST); `GetBlamedPeers()` = Confirmed ∪ Suspect (compatibility; **use Confirmed for penalties**).

**Types** (`crypto/tss/blame`):

```go
type Result struct {
    Confirmed map[string]struct{}
    Suspect   map[string]struct{}
}
```

**onBlame call-site inventory (CGGMP sign)**:

| Kind | Call sites |
|------|------------|
| **Confirmed** | `blameSender` (R1–R3 ZK/gate/table); `blamePeer` (δ/σ); `NewSign` echo `SetOnConflict`; `err1/err2 Finalize` ← ProcessErr Confirmed |
| **Suspect** | `blameMissingDigestSenders` / `OnDigestTimeout` R1–R3; ProcessErr Suspect (absence, global Δ, ambiguous cohort) |

**Classification rules (summary)**:

| Source | Set |
|--------|-----|
| DecModQ / Mul / Aff ZK failure, mask 0-solution sender | **Confirmed** |
| Multi-solution mask + `SuspectAllErr` (default) | **Suspect** = this round’s Err senders − Confirmed |
| Global \(\sum\delta\neq\Delta\) | **Suspect** (Err senders) |
| Digest timeout (IA-04) | **Suspect** |
| Gate failure (pre PR-D3 diagnostics) | **Confirmed** (reveal side; diagnostics remain PR-D3) |
| Err2 absence (IA-06) | **Suspect** |
| ProcessErr2 valid Err2 + ZK attribution | **Confirmed** |

**Plan**:

| Priority | Action |
|----------|--------|
| P1 | Alice: `BlameResult` + classification — **landed (PR-D1)** |
| P1 | `mpc.FormatSignErr` / INT-03 output distinguishes confirmed vs suspect |
| P2 | INT-04: `BlamedNodes[]` with `kind: confirmed|suspect` |

---

### IA-07 / IA-08 · Documentation consistency

**Plan**:

| Priority | Action |
|----------|--------|
| P0 | Publish this doc; change [CGGMP.md](./CGGMP.md) §2 to **point here §3** as the authoritative status table |
| P0 | Retire bare ✅ as “IA complete”; change F-01 to **Partial** |
| P1 | Extend §6 R1 Checklist (below) |

---

## 5. Integration-layer remediation (broker / node)

Complementary to in-protocol Alice IA; does **not** change cryptographic blame boundaries:

| ID | Item | Current | Recommendation |
|----|------|---------|----------------|
| INT-01 | Node disconnect fast-fail | broker `abortMpcTasksForNode` + `mpcTaskAbort` | **Fixed**; preferred over Alice 2m |
| INT-02 | FROST blame in error text | `mpc.FormatSignErr` | **Fixed** (alg_ed25519) |
| INT-03 | CGGMP blame in error text | Not wired | **Open**: `alg_ecdsa/sign.go` same as FROST |
| INT-04 | Blame report to broker | Not done | **P2**: add `BlamedNodes[]` to `CliMPCSignResultReq` |
| INT-05 | Digest timeout vs broker timeout | Docs scattered | **P0**: ops runbook documents **expected fail timeline** |

**Expected fail timeline (sign, participant disconnect)**:

```text
T+0s     broker WS onClose
T+0~1s   abortMpcTask → online node mpcTaskAbort → abortCancel → RunSign exits
         (usually far earlier than Alice Digest 2m)
T+2m     Alice ErrDigestTimeout only if upper-layer abort did not take effect
T+6/12m  node signTimeout / session fallback
```

---

## 6. R1 / DecModQ Checklist (extended)

Relative to [CGGMP.md](./CGGMP.md) §5.4, explicitly mark **Fixed / Partial / Accepted risk / To evaluate**:

| Item | Status | Notes |
|------|--------|-------|
| KS (incl. unbounded \(w\)) | **Accepted risk** | ZK **Weak**; does not break KS |
| Lift A2 (\(k\in[-2,7]\)) | **Fixed** | Coupled with `MaxIARemotePeers=8` |
| \(\|Y\|<8N\) + \(\|z_1\|\) bound / Modulo Gap | **Fixed** | **Effective decision bound**; do not remove Verify checks (CGGMP.md §5.2) |
| Err composition (Scheme A′) | **Partial** | See IA-01, IA-03, IA-06 |
| Blame boundary documentation | **Partial** | This doc §4 |
| **PublicX mask uniqueness** | **Open** | IA-01 options B/C |
| **R1-FS Challenge prime** | **Accepted risk** | IA-02; [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) · PR-D4a |
| **\(Y^*\) equivalence class / Extractor** | **To evaluate** | Does not block current IA engineering; cite §5.2 when auditors ask |
| **Unbounded \(w\) → Weak ZK** | **Accepted risk** | Matches upstream |

---

## 7. Implementation priority (suggested PR split)

```text
PR-D0   This doc + CGGMP.md §2 cross-refs + README index (no code)
PR-D1   matchDecModQ multi-solution detection (IA-01 option B) ✅
        + AmbiguousMaskPolicy default SuspectAllErr (cohort=Err−Confirmed)
        + ConfirmAllErr production remap; alice_ia_debug only to allow
        + BlameResult Confirmed/Suspect API (§4.7); Confirmed ∩ Suspect = ∅
        + Enum: find first then finish scan (≥2 → MaskAmbiguous)
PR-D2   alg_ecdsa FormatSignErr (INT-03) + blame kind output
PR-D3   SetAbortTimeout configurable + gate diagnostic branch P1 (IA-05) + integration docs (IA-04)
PR-D4a  R1-FS_risk_memo.md — quantified bounds + impact scope + upstream diff (docs only; merge anytime)
PR-D4b  GetE prime challenge PoC (separate branch; does not block mainline)
PR-D5   signSix / refresh Pairwise (PE-03/04; independent large item)
```

---

## 8. Additional test checklist

> **Echo three-step closed loop**: honest path + mesh abort E2E already covered (see [PAIRWISE_ECHO.md §0.1](./PAIRWISE_ECHO.md)). The table below is **edge / IA precision** follow-up tests; do not confuse with “Echo not implemented.”

| Test | Coverage | Priority |
|------|----------|----------|
| `TestMatchDecModQAmbiguousMask` | IA-01 multi-solution | P1 |
| `TestProcessErr1GlobalDeltaOverBlame` | IA-03 documented behavior | P0 (logic exists; add assertion docs) |
| `TestDigestTimeoutDoesNotBlameIfAborted` | INT-01 vs IA-04 | P1 |
| `TestProcessErr2AbsentSender` | IA-06 boundary | P1 |
| 3-party Err2 mesh honest | IA-06 | P2 |
| Gate local diagnostic branch (received digest / not) | IA-05 · PR-D3 | P1 |
| `TestGetBlameResultSplitsDisjoint` | Confirmed ∩ Suspect = ∅; `blameAbsentSenders` mutually exclusive with Confirmed | P1 |

---

## Revisions

| Date | Notes |
|------|-------|
| 2026-09-13 | Initial: four-tier status, IA-01~08, integration INT-01~05, R1 Checklist extension, PR split |
| 2026-09-13 | Audit close-out: IA-02 quantified memo, IA-01 default policy, IA-05 P1 diagnostics, §4.7 Blame API, PR-D4a/b |
| 2026-09-13 | \|Y\|<8N/\|z1\| marked as effective decision bound; R1-FS “weak” narrowed to template wording gap |
| 2026-09-13 | PR-D1 landed: blame package, MaskMatchResult, BlameResult, SuspectAllErr cohort, production ConfirmAllErr remap |
| 2026-09-14 | IA-02 wording close-out: reading order; forgery hardness / primary attribution cause as separate rows; aligned with R1-FS memo |
| 2026-09-14 | §8 + IA-05: Echo closed-loop coverage wording; add gate diagnostic / BlameResult disjointness tests |
| 2026-09-14 | English edition |
