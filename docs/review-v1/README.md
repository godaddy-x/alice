# review-v1 doc index

> Alice fork (`godaddy-x/alice` · `master-pr1`) · **code is authoritative**  
> Scope: **3-round CGGMP sign** + **FROST sign** Pairwise Echo; Scheme A′ IA  
> **Not closed here**: strong Echo for signSix / Refresh / DKG (still weak)

---

## Reading order

| # | Doc | Owns (when reading only this file) |
|---|-----|-------------------------------------|
| 1 | **[PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md)** | How Echo works: 3-step closed loop, Reveal/gate boundaries, test entry points |
| 2 | **[CGGMP.md](./CGGMP.md)** | CGGMP security summary, Scheme A′, **§7** CVE / CGGMP24 gap |
| 3 | **[CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md)** | IA status (4 tiers), remediation, §8 edge-case tests |
| 4 | **[R1-FS_risk_memo.md](./R1-FS_risk_memo.md)** | IA-02 accepted risk (proof-template gap ≠ runtime weakness) |
| 5 | **[FROST.md](./FROST.md)** | FROST open items (Echo = FR-01 closed; detail in PAIRWISE §B) |
| — | [BROKER_NODE_INTEGRATION_TEST_PLAN.md](./BROKER_NODE_INTEGRATION_TEST_PLAN.md) | L2/L3 integration (optional) |
| — | [UPSTREAM_ISSUE_ECHO_IA.md](./UPSTREAM_ISSUE_ECHO_IA.md) | Draft English issue for getamis/alice |

**One-liner layers** (audit shorthand):

- **Echo three steps** = direct defense against pairwise equivocation (3-round sign **landed**)  
- **DecModQ / R1-FS** = trust base for Err-path IA (forged ZK hard to misdirect blame)  
- **IA** = engineering Confirmed/Suspect · **≠** paper “unique cryptographically identifiable abort”

---

## Status snapshot

| Topic | Status |
|-------|--------|
| CGGMP Sign Pairwise Echo | **Implemented** (Digest Echo + gate; Reveal not Echoed) |
| FROST Sign Pairwise Echo | **Implemented** (frost-sign-v2) |
| Scheme A′ Err1/Err2 + `GetBlameResult` | **Implemented** (bounds in IA_LIMITS) |
| CVE-2025-66016 minimal (`gcd(N,w)`) | **Aligned** (CGGMP §7.2; ≠ full CGGMP24) |
| CVE-2025-66017 presign API | **Out of scope** (no such API) |
| IA-05 gate diagnostics / edge tests | **Partial** (PR-D3 / IA_LIMITS §8) |
| signSix · Refresh · DKG Echo | **Weak / open** |

---

## Test entry points

```powershell
cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ -run "TestMeshErr|TestEchoConflict|TestGate" -count=1
go test ./crypto/tss/ecdsa/cggmp/sign/ -timeout 600s -coverprofile cover_sign.out
go test ./crypto/tss/eddsa/frost/signer/ ./crypto/tss/pairwise/ ./crypto/zkproof/paillier/ -count=1
```
