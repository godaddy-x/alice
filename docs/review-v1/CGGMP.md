# CGGMP Security Review and Identifiable Abort (review-v1)

> **Scope**: 3-round `cggmp/sign` · Scheme A′ IA · success-path formulas unchanged  
> **Related**: [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) (Echo) · [CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) (IA authoritative table) · [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) · [README.md](./README.md)  
> **Production**: `wallet-mpc-node` still pins **alice v1.0.7**; this fork is **not yet merged**

---

## 1. Conclusions

The Sign main path matches the paper (under consistent broadcast). No remote key-recovery single point of failure was found.

**Residuals**: DecModQ **R1-FS** (FS Challenge is not prime); Err1 global Δ blame granularity is coarse (R3); Refresh / signSix Echo remain weak.

**Pairwise**: 3-round Sign **Echo three-step is landed** (Digest exchange · conflict detection · attribution; see `PAIRWISE_ECHO.md` §0.1); breaking wire. DecModQ/R1-FS is the trust base for the Err path, **not** a direct mechanism for equivocation.

---

## 2. Issue List

> **Authoritative status table** (four tiers: fixed / partial / pending / accepted risk) and remediation plans are in  
> **[CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md)** §3–§7.  
> The table below is a summary; **do not interpret ✅ as IA-provable attribution completeness**.

| ID | Severity | Issue | Summary status |
|----|----------|-------|----------------|
| F-01 | High | Echo / Pairwise | **Partial** (sign fixed; signSix / refresh pending) |
| F-02 | Medium | Sign ped verification | Fixed |
| F-03 | Medium | DKG Schnorr commitment | Fixed |
| M-01 | Medium | Round3 Delta DoS | Fixed (**≠** Err1 precise attribution) |
| F-04 | Medium | Err broadcast collection | Fixed |
| F-05 | Medium | signSix Err2 Type | Fixed |
| M-02 | Medium | partialPubKey verification | Fixed |
| F-06 | Low | msg into ssid | Fixed |
| F-07/F-08 | Low | Refresh | Pending |
| IA-01~08 | — | IA / blame boundaries | See IA_LIMITS document |

**Sign Echo / Digest (strict)**:

| Round | Global Echo | Pairwise |
|-------|-------------|----------|
| R1 | `Round1Digest` (K/Γ + psi table + `table_root`) | `Round1` reveal; `GetEchoMessage=nil`; gate verifies psi digest |
| R2 | `Round2Digest` (Γ + MtA table) | `Round2` reveal; gate + Γ cross-check |
| R3 | `Round3Digest` (δ/Δ + ψ table) | `Round3` reveal; gate + δ/Δ cross-check |
| R4 | Echo(σ) | None |

`Start` must call `prepareRound1Digest` before `MessageMain.Start` to avoid an empty `pendingRound1` at Finalize time.

**Accountability enhancements (2026-09-12 audit backfill)**:

| Event | Behavior |
|-------|----------|
| Digest barrier timeout | `DigestBarrierHandler` + `ErrDigestTimeout`; `OnDigestTimeout` → blame peers that did not send digest |
| `gateEdgeDigest` store missing | blame sender + `ErrDigestBarrier` |
| ZK verification failure (R1 Psi / R2 AffG·Log* / R3 BigDelta·Psidoublepai) | blame the corresponding Round message sender |
| Multiple blame events | `GetBlameResult`: Confirmed ∪ Suspect; `GetBlamedPeers` = union (compat) |
| Echo hash conflict | `SetOnConflict` → Confirmed digest author |
| PublicX multi-mask | `MaskAmbiguous` → SuspectAllErr (default; see IA_LIMITS) |

**Layering**: DecModQ/R1-FS = Err-path trust base; anti-equivocation = Echo three-step (see `PAIRWISE_ECHO.md` §0.1).  
**Premise for Reveal without Echo**: Digest barrier completed and gate can obtain store; if missing, blame the reveal party (IA-05; diagnostics left to PR-D3).  
**Coverage scope**: Honest path + mesh abort E2E verified; edge tests see IA_LIMITS §8.

Integration layer should call `Sign.SetAbortTimeout`; prefer reading `GetBlameResult()`.

---

## 3. Integration Assumptions

1. Refresh→Sign use the same material set  
2. `msg` = digest; `ssid` binds the session  
3. **≤9 parties**: `ValidateIAParticipantCount` enforced in `NewSign` and `ProcessErr*`  
4. Full restart on failure; E2E encryption  

---

## 4. Scheme A′ (Identifiable Abort)

| Component | Description |
|-----------|-------------|
| **DecModQ** | Prove \(Y\equiv x\pmod q\), \(\|Y\|<8N\); lift \(k\in[-2,7]\) (`err_paillier.go`) |
| **PublicX** | \(x=(\mathrm{share}+\sum c_j N_j)\bmod q\); enumerate \(c_j\in\{0,1\}\). Prove may take the first solution; Err **Verify** rescans for a second success → `MaskAmbiguous` (PR-D1) |
| **Err2 split** | Do not prove \(K^m C_{\mathrm{inner}}^r\) (\(r\cdot S\gg N\)); DecModQ(\(C_{\mathrm{inner}},\chi\)) + DecModQ(\(K^m,\sigma-r\chi\)) |
| **Scale** | `MaxIARemotePeers=8`; total participants ≤9 (code assertion) |

**Err1**: \(C_0=H\prod D F^{-1}\) → DecModQ(\(C_0\), PublicX(δ)).

**Err2**: DecModQ(\(C_{\mathrm{inner}}\), PublicX(χ)) + DecModQ(\(K^m\), σ−rχ); Verify uses local \(R\), Round4 σ.

```text
Round3 ──δ fail──► Err1 ──ProcessErr1──► Failed
   └──► Round4 ──σ fail──► Err2 ──ProcessErr2──► Failed
```

**Rejected**: unbounded CRT, fake Enc(δ/σ), ciphertext translate. signSix uses NthRoot (not DecModQ).

---

## 5. DecModQ / R1 (Formal Memo)

### 5.1 Differences from Special Decry

| Item | Special Decry | DecModQ |
|------|---------------|---------|
| FS DST | `SpecialDecryZKDST` | `DecModQZKDST` |
| Range | \(\|\alpha+eY\|\le 2^{L+\varepsilon}\) | **Effective decision bound**: \(\|Y\|<8N\) + Verify \(\|z_1\|\le\texttt{maxDecModQZ1}\) |
| Binding \(x\) | Short integer | \(x\in[0,q)\); \(z_1 G = C_{pt}+e\cdot x G\) |

### 5.2 Review Conclusions (Summary)

- **Unbounded \(w\)**: Does not break KS; ZK is Weak (acceptable).
- **\(Y^*\)**: Extractor obtains an equivalence class in \(\mathbb{Z}_{N\cdot q}\); \(\|Y\|<8N\) uniquely determines the small representative.
- **Effective decision bounds (engineering strengthening relative to the paper; code and docs consistent)**:
  - **\(\|Y\|<8N\)** (`maxDecModQYOverN=8`): Prove entry rejects oversized \(Y\); linked with Scheme A′ lift \(k\in[-2,7]\), `MaxIARemotePeers=8`.
  - **\(\|z_1\| \le \texttt{maxDecModQZ1}\)** (≈ \(2^{L+\varepsilon}+(8N-1)(q-1)+2^{64}\)): `VerifyModQ` **already checks explicitly**; without this bound a malicious party can take \(Y_{\mathrm{mal}}=Y+K\cdot N\cdot q\) and still pass EC/Paillier equalities, breaking \(\|Y\|<8N\) and IA accountability. **Must not be removed**.
  - The two bounds above are **effective soundness / accountability decision conditions**, not optional optimizations; removing either leaves the current review conclusions.
- **Lift A2**: \(Y_{\max}\lesssim q+8N\approx 8N\) ⇒ \(k\in[-2,7]\); linked with `MaxIARemotePeers`.
- **Modulo Gap**: Prove/Verify share **unreduced** `z1`; EC only mods \(q\) inside `ScalarMult`.
- **R1-FS** (accurate status): Code matches upstream (integer challenge); at runtime \(\gcd(e-e',N)=1\) (when \(e\neq e'\)) is **deterministically** proven always to hold; the **only “weak” point (at the proof level)** is that the proof template is not stated in standard FS form → soundness in the standard model has **no closed argument**; **runtime is unaffected**; **no known attack**. Quantitative memo: [R1-FS_risk_memo.md](./R1-FS_risk_memo.md). **GetE not changed** (library-level decision).

### 5.3 Blame Boundaries

DecModQ = **self-proof / self-exposure** (local ciphertext ↔ broadcast \(x\)). Accusing an upstream MtA adversary requires Mul/Aff ZK failure; when DecModQ passes but global \(\sum\delta\neq\Delta\), the current implementation uses **coarse-grained blame** (R3).

### 5.4 R1 Checklist

Full items (including PublicX uniqueness, w-Weak, accepted-risk sign-off) are in  
**[CGGMP_IA_LIMITS_AND_REMEDIATION.md §6](./CGGMP_IA_LIMITS_AND_REMEDIATION.md#6-r1--decmodq-checklist-extended)**.

- [x] Lift A2, \(|z_1|\) upper bound, Modulo Gap (**fixed**)  
- [~] Err composition / Blame boundaries (**partial** — IA-01/03/06)  
- [~] KS / unbounded \(w\) (**accepted risk** — Weak ZK)  
- [ ] **R1-FS** Challenge primality (**accepted risk** — [R1-FS_risk_memo.md](./R1-FS_risk_memo.md) · PR-D4a delivered memo)  
- [~] **PublicX mask enumeration uniqueness** (**partial** — PR-D1 multi-solution detection; mathematical uniqueness still open — IA-01)  


---

## 6. Code and Tests

| Area | Path |
|------|------|
| DecModQ | `crypto/zkproof/paillier/dec_modq.go` |
| Lift / PublicX / entry | `cggmp/err_paillier.go`, `utils.go` |
| Err / Blame | `sign/err_abort.go`, `err_process.go`, `err_helpers.go` |
| Echo / Digest | `sign/message.go`, `digest_handlers.go`, `pairwise_digest.go`, `pairwise_store.go` |
| Digest timeout | `types/message/abort_handler.go` (`DigestBarrierHandler`), `msg_main.go` (`ErrDigestTimeout`) |
| Attack-attribution unit tests | `sign/pairwise_attack_test.go`, `types/message/digest_timeout_test.go` |

```bash
go test ./crypto/zkproof/paillier/ ./crypto/tss/ecdsa/cggmp/ \
  ./crypto/tss/ecdsa/cggmp/sign/ -count=1
go test ./crypto/tss/ecdsa/cggmp/sign/ -bench=MatchDecModQMaskEnum8 -benchmem
```

---

## 7. CGGMP24 / CVE Cross-Check (nonce · Πmod · presign)

> **Scope**: Paper checklist items relative to Lindell DBDE, CVE-2025-66016/66017, and CGGMP24 revisions.  
> **Code anchors**: `blummodzkproof.go` · `ring_pedersenzkproof.go` · `nosmallfactoezkproof.go` · `refresh/` · `sign/`  
> **Non-goals**: Full migration to Lockness `cggmp24`; this section is a **gap inventory** only.

### 7.1 Lindell DBDE (nonce manipulation)

| Item | Conclusion |
|------|------------|
| Attack model | 2PC Lindell: one party can construct structured \(k_2=b^\ell\) and extract share bits from signature results |
| Alice | Each party samples \(k_i,\gamma_i\) locally via `RandomInt(q)`; Ψ=`EncryptRange`; MtA=`Aff-g` + `Log*` |
| Verdict | **DBDE path does not apply directly** (not a “single party determines final nonce” architecture) |
| Residual | Integration must ensure Ψ/Aff-g **Verify is never skipped**; Ped/`N` must go through Refresh `ModProof`/`FacProof` |

### 7.2 CVE-2025-66016 (Πmod missing check → full key extraction)

#### 7.2.1 Algebraic form of the Lockness minimal patch (cross-checked against source)

Advisory / CHANGELOG only say “missing check”; **the repo diff is authoritative**:

| Evidence | Content |
|----------|---------|
| Compare | [`LFDT-Lockness/paillier-zk` `v0.4.2...v0.4.3`](https://github.com/LFDT-Lockness/paillier-zk/compare/v0.4.2...v0.4.3) |
| Sole `.rs` security change | `src/paillier_blum_modulus.rs` · `interactive::verify` |
| Algebraic form | `fail_if_ne(..., n.gcd(w), 1)` ⇒ **\(\gcd(N,w)=1\)** |
| NI path | `non_interactive::verify` **directly calls** `interactive::verify` → same check |
| **Not** | \(x_i\in\mathbb{Z}_N^\*\), range, \(z^N=y\) equalities, etc. (those already existed in 0.4.2 or belong elsewhere) |

#### 7.2.2 Comparison with Alice

| Check | Alice `PaillierBlumMessage.Verify` | Relation to 0.4.3 |
|-------|-----------------------------------|-------------------|
| \(\gcd(N,w)=1\) | **Present** (`GCD(w,n)==1` → `ErrInvalidInput`) | **= CVE-66016 minimal patch** |
| \(J(w,N)=-1\) | **Present** | **Stronger than** CVE-66016 minimal patch (\(J=-1\) implies \(\gcd(w,N)=1\)); not new in 0.4.3 |
| \(N\) odd composite, non-prime, ≥2048-bit | **Present** | Independent |
| \(z_i^N\equiv y_i\), \(x_i^4\equiv(-1)^a w^b y_i\) | **Present** | Independent |
| \(y_i\) verifier-derived | **Present** (deterministic FS; NI-like) | Independent |
| \(x_i,z_i\in\mathbb{Z}_N^\*\) | **Fixed (added in this fork, G-05)** | **≠** 66016 patch; ZKDocs hardening item |

**Verdict (precision criteria)**:

1. **CVE-66016 Lockness minimal patch (sole addition in `paillier-zk` 0.4.3) = \(\gcd(N,w)=1\)**; Alice **has the equivalent check** → for the “public one-line fix,” **aligned**.  
2. **≠** “CVE ecosystem fully closed”: Lockness still requires migrating to **cggmp24** (“many other security checks”); see §7.4 G-01~G-06.  
3. **≠** “\(x_i\) membership = 66016”: the diff rules out that candidate; G-05 is a separate hardening.

Call sites: only **`cggmp/refresh`** `ModProof` (**not** `dec_modq.go`). Sign trusts externally supplied `paillierKey`/`ped`.

### 7.3 CVE-2025-66017 (presign + raw/HD)

| Item | Alice |
|------|-------|
| Presignature API / HD path late-binding | **None** |
| `NewSign` / `signSix.NewSign` | **`msg` fixed at start**; `ssid` binds msg; fresh \(k\) each session |
| BIP32 | Independent 2PC, **not** spliced with CGGMP \(R\) precomputation |

**Verdict**: Library surface **does not fall into** either CVE-66017 scenario. Integration layer should still: **only sign digests computed by this node** (avoid ops misuse of “hash only, no original message”).

### 7.4 CGGMP24 parameter / structure gaps (not CVEs, but recommended scheduling)

| ID | Severity | CGGMP24 / modern profile | Alice status | Recommendation |
|----|----------|--------------------------|--------------|-----------------|
| **G-01** | Medium | Πmod/Πprm amplified to ~**128** rounds (128-bit) | `MINIMALCHALLENGE=**80**` | Evaluate raising to 128 (breaking / performance) |
| **G-02** | Medium | Paillier **3072**-bit (toward Appendix C.1) | Default **2048** (`safePubKeySize`) | Product security-level decision; not an immediate CVE |
| **G-03** | Medium | Independent **\(N\)** (encryption) and **\(\hat N\)** (Ring-Pedersen) | Refresh: `NewPedersenParameterByPaillier` → **\(N=\hat N\)** | Differs from paper revision; migrating auxiliary modulus needs protocol changes |
| **G-04** | Low | Fig.8 often uses **Πenc-elg** | Sign uses **Πenc + Πlog\*** (classic CGGMP21 split); library has `EncElg` not wired to main path | Revisit whether to switch path after paper revision comparison |
| **G-05** | Low | Πmod \(x_i\) membership | **Fixed (added in this fork)**: `blummodzkproof.go` Verify | Unit tests: `x=0` / not coprime with \(N\) / \(x\ge N\) |
| **G-06** | Info | CGGMP24 has further checks “once omitted on paper, already assumed in proofs” | Full coverage not claimed | Per-figure diff against ePrint 2021/060 **2024 revision** (PR-level) |

### 7.5 Conclusions (one-liners for external use)

- **vs Safeheron Lindell 17**: Stronger IA/attribution (protocol choice); nonce attack surface is **not isomorphic** — this is not “missing a DBDE patch.”  
- **vs CVE-66016**: Confirmed via `paillier-zk` **v0.4.2→v0.4.3** diff that the patch is \(\gcd(N,w)=1\); Alice **has the equivalent check**. Full CGGMP24 **not claimed**.  
- **vs CVE-66017**: No dangerous presign API; guard against integration raw/HD misuse.  
- **Next engineering steps**: G-01/G-02 parameter decisions; G-03/G-06 are protocol upgrades — do not couple to Pairwise/IA releases. **G-05 fixed (added in this fork)**; unit tests in §7.4.

---

## Revisions

| Date | Notes |
|------|-------|
| 2026-09-12 | Scheme A′, Echo R2–R4, entry assertions, R1 memo |
| 2026-09-12 | External review: `|z1|`/Modulo Gap confirmed, Blame, R1-FS |
| 2026-09-12 | Three CGGMP docs merged into this file |
| 2026-09-12 | Pairwise Digest strict edition landed (R1–R3 barrier + Err store binding) |
| 2026-09-12 | Err H_edge rehash, Echo conflict blame, digest DST v3 length prefix |
| 2026-09-12 | Audit backfill: digest timeout blame, ZK failure blame, `storeBlamedPeers` union, gate missing-table blame |
| 2026-09-12 | Attack-attribution unit tests (equivocation/echo conflict/Err H_edge); dead-code cleanup |
| 2026-09-13 | §5.2: |Y|<8N / |z1| marked as effective decision bounds; R1-FS accurate status (template-weak ≠ runtime-weak) |
| 2026-09-14 | PublicX multi-mask / GetBlameResult; doc index consolidated under review-v1/README |
| 2026-09-14 | §7: Lindell DBDE / CVE-66016·66017 / CGGMP24 gaps (G-01~06) |
| 2026-09-14 | G-05: Πmod Verify adds \(x_i,z_i\in\mathbb{Z}_N^\*\) |
| 2026-09-14 | §7.2: Cross-checked paillier-zk v0.4.2→v0.4.3; confirmed 66016 = \(\gcd(N,w)\); decoupled from G-05 |
| 2026-09-14 | §7 doc consistency: G-05 “fixed” in both places; Jacobi “stronger than” gcd; §7.5 next steps drop G-05 patch |
| 2026-09-14 | Echo/DecModQ layering + Reveal gate premise + test coverage scope (aligned with PAIRWISE §0.1) |
| 2026-09-14 | English edition |
