# R1-FS · GetE Non-Prime Challenge — Accepted-Risk Memo

> **Status**: review-v1 · IA-02 closure document (PR-D4a deliverable)  
> **Related**: [CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) §IA-02 · [CGGMP.md](./CGGMP.md) §5.4  
> **Code**: `crypto/zkproof/paillier/affinegroupzkproof.go` · `GetE`  
> **Audience**: security audit / sign-off owners

---

## 0. Accurate Status (one sentence)

| Item | Status |
|------|--------|
| **Code** | Matches upstream alice (**unchanged** — `GetE` integer challenge) |
| **Runtime gcd** | When \(e\neq e'\), \(\gcd(e-e',N)=1\) holds **deterministically always** (§2.1); **does not** affect Verify / abort behavior |
| **Docs vs comments** | This memo / CGGMP.md are **tighter** than code comments (comments previously said w.h.p.; this memo is authoritative) |
| **Only “weak” point (proof level)** | The proof template is **not stated in standard FS form** → soundness under the standard model has **no closed argument**. **Runtime is unaffected** (§2.1); “only” means **at the proof level**, **not** at the runtime level |
| **Does not include** | Runtime weakening, known forgery attacks, or easy bypass of IA attribution (see §2.5) |

**Accepted risk = template wording gap (A)**; **≠** “unsafe at runtime” or “weaker than a standard FS implementation”.

### IA-02 Reading Order

```text
Runtime safety     → §2.1 (deterministic 0)
Generic upper bound → §2.2 (O(2^-1024))
What we accept     → §2.3 (A/B/C)
Worst-case outcome → §2.4 (branch 1/2)
Forgery hardness   → §2.5 (DCR constraints)
sign-off           → §2.4.3 (directly citable)
```

---

## 1. Problem Statement

Alice Paillier ZK (DecModQ / Mul / Aff, etc.) Fiat–Shamir challenges are produced by `GetE`:

- \(e \in \mathbb{Z}\), sampled under \(|e| \le q/2\) (`groupOrder` \(q\) is the elliptic-curve order; under secp256k1, \(q \approx 2^{256}\));
- **Not** a prime-field element, **not** uniform over \(\mathbb{Z}_N^\*\).

Standard FS soundness proofs typically require challenges from a prime-order field; this implementation follows upstream alice’s integer-challenge design.  
**What is accepted as risk is the “proof-template gap”**, not “runtime frequently hitting \(\gcd(e-e',N)\neq 1\)”, and not “the implementation is weaker than standard FS”.

---

## 2. Magnitude Claims (for audit)

### 2.1 **Runtime** Bound under Alice’s Actual Parameters

**Claim**: Under standard Paillier parameters (2048-bit \(N = p\cdot p'\), \(p,p'\) each ~1024-bit primes; `NoSmallFactor`; \(|e|,|e'|\le q/2\)), for **any** \(e \neq e'\):

\[
\Pr\big[\gcd(e-e', N) \neq 1 \mid e \neq e'\big] = 0
\]

**Derivation (parameter inequalities, not asymptotics)**:

1. Let \(\delta = e - e'\). From the `GetE` constraint, \(|\delta| \le q < 2^{256}\).
2. Let \(N = p \cdot p'\), with \(p,p'\) the Paillier prime factors, each \(\approx 2^{1024}\).
3. If \(\gcd(\delta, N) > 1\), there exists a prime \(r \mid \delta\) and \(r \mid N\), hence \(r \in \{p, p'\}\).
4. If \(r \mid \delta\), then \(|\delta| \ge r \ge 2^{1023}\) order of magnitude, contradicting \(|\delta| < 2^{256}\).
5. Therefore when \(e \neq e'\) we must have \(\gcd(\delta, N) = 1\).

**The \(e = e'\) case (FS binding, not random gcd failure)**:

- \(\gcd(0, N) = N \neq 1\), but requiring two independent FS outputs to equal the same \(e\) is equivalent to a **hash collision / replay under identical transcript inputs**;
- Under the RO/FS model, that event’s probability is **negligible** (bound by `HashProtos` + salt retry `maxRetry`; see `GetE` implementation).

**Conclusion (runtime)**: DecModQ and related proofs **do not abort under Alice’s default parameters because a random draw hit \(\gcd(e-e',N)\neq 1\)**; when \(e\neq e'\), the extractor **always** has \(\gcd(e-e',N)=1\) available.

> **Relation to class-A risk (see §2.4)**: §2.1 already proves **deterministically** that the gcd condition always holds under default parameters. The class-A gap is **not** “runtime gcd may fail”, but “whether that condition suffices to close the soundness proof” — the two must be stated separately at sign-off.

### 2.2 Generic Random-Model Bound (template reference; not Alice’s main path)

If the \(|e|\le q/2\) constraint is **not** imposed, and \(\delta\) is instead treated as “independent random on \(\mathbb{Z}\) at the same magnitude as \(N\)” (or \(|\delta|\) can reach \(O(\sqrt{N})\)), then \(\gcd(\delta,N)\neq 1\) iff some prime factor of \(N\) divides \(\delta\):

\[
\Pr[\gcd(\delta, N) \neq 1] \;\lesssim\; \frac{1}{p} + \frac{1}{p'} \;=\; O(2^{-1024})
\]

(for 2048-bit \(N = p\cdot p'\), \(p,p'\sim 1024\) bit.)

**Source**: classical number theory — the probability that a random integer shares a factor with a fixed large prime \(p\) is \(\le 1/p\); union bound over the two prime factors.  
**Relation to Alice**: this bound **neither tightens nor relaxes** §2.1’s **exact 0** conclusion; it is only a **generic magnitude anchor** when auditors ask “how small is ‘extremely small’?”.

### 2.3 What Risk We **Actually Accept**

| Class | Description | Magnitude |
|-------|-------------|-----------|
| **A · Proof gap** | Integer challenge is not over a prime field; **worst-case outcome in §2.4** (not a runtime gcd event) | **Qualitative** — needs sign-off |
| **B · Runtime gcd failure** | §2.1: **0** when \(e\neq e'\); \(e=e'\) folds into FS binding | **Negligible** |
| **C · Library-wide breaking change** | Changing `GetE` affects the whole-library Paillier ZK API | Engineering cost — see PR-D4b |

### 2.4 Worst-Case Outcome of Class-A Gap (sign-off basis)

Sign-off means “**I know the worst case is X, and I accept X**”. This section bounds class A’s **cryptographic** worst case; **runtime** is unaffected by any branch in §2.4 (§2.1 already closed).

#### 2.4.1 First answer three audit must-asks

| Question | Answer |
|----------|--------|
| **Is the worst case soundness failure or extractor failure?** | Worst case means **soundness has no closed argument under the standard model** (possibly with extractor steps that cannot be formalized in the textbook template). **Not** “a known polynomial-time forgery algorithm exists”. |
| **If the extractor fails, is the proof still sound?** | **Case split** (§2.4.2). If the extractor **only** needs \(\gcd(e-e',N)=1\), then §2.1 already shows that condition always holds, so soundness is **not affected by gcd at the algebraic premise**; the gap reduces to “the proof is not written in the standard FS template”. If the extractor **additionally** requires \(e-e'\in\mathbb{Z}_N^\*\) or prime-field structure, then the extractor step **cannot be applied directly** under the standard template, but that **does not equal** having constructed a forgery; soundness under the standard model has **no closed proof**. |
| **If soundness fails, what capability does the attacker need?** | Under the premise that **no concrete attack is known**, the worst-case scenario is: a malicious prover **may**, in the RO/FS model, use the non-standard challenge space to find a forgery path **not covered by existing proofs**. Capability upper bound: a **standard malicious MPC participant** (arbitrary protocol deviation, adaptive choice of Paillier-related messages), **without** assuming CDH/DDH or similar hardness breaks. **This is an upper-bound description**; under **branch 1** that attack path is **ruled out** by §2.1 (gcd forgery is unavailable). |

#### 2.4.2 Two branches (PR-D4b / external review confirms classification)

**Branch 1 — extractor algebraic premise requires \(\gcd(e-e',N)=1\) (when \(e\neq e'\)) and nothing more**

- §2.1 already proves **deterministically**: under Alice’s default parameters this condition **always holds**.
- **Worst-case outcome**: class-A risk **reduces to “the proof template is not stated in standard Fiat–Shamir form”** — i.e. a **wording / documentation gap** relative to audit docs / paper citations, **not** runtime soundness failure, **not** a known exploitable algebraic vulnerability.
- **sign-off meaning**: accept “**documentation-level technical debt** consistent with the upstream / Kudelski review path”; **do not** accept “a known Paillier ZK forgery attack exists”.

**Branch 2 — some extractor **additionally** requires \(e-e'\) to be prime or \(e-e'\in\mathbb{Z}_N^\*\) (or equivalent standard field structure)**

- §2.1 **still holds**: \(\gcd(e-e',N)=1\) is always satisfied at runtime; **runtime behavior is the same as branch 1**.
- **Worst-case outcome**: the corresponding ZK’s **soundness has no closed argument under the standard model** — i.e. one **cannot** give a complete extractor inside the textbook FS framework; **this does not equal** having proved soundness false.
- **Attacker capability upper bound** (**theoretical worst case** if soundness indeed fails): malicious prover + information visible in-protocol; output a **forgery proof that passes Verify** (against the affected Paillier ZK statement). **This is a hypothetical description, not a known attack construction; there is currently no evidence that this scenario is reachable.** The memo end also stresses: this memo / upstream **do not** give a concrete construction of such an attack.
- **sign-off meaning**: accept that “a forgery path **not covered by proofs may exist**, but there is **no known instance**; risk posture matches upstream; PR-D4b / external cryptographic review **confirm whether we fall into this branch**.

**This memo’s position**: we **do not claim** to have determined whether each Alice `GetE` call site is branch 1 or branch 2; §2.1 closes runtime gcd for **both** branches. Branch classification is a PR-D4b deliverable, not a PR-D4a blocker.

#### 2.4.3 Suggested sign-off wording (directly citable)

> **The worst case I accept is**: under the standard model, some Paillier FS proofs **may** lack a closed soundness argument (branch 2); or there is only a proof-template wording gap (branch 1). **I do not accept** the stronger claim that a known polynomial-time forgery attack already exists — there is currently **no** such attack on record.  
> **Runtime**: §2.1 proves \(\gcd(e-e',N)=1\) always holds when \(e\neq e'\); the class-A gap **does not** introduce extra aborts or verify bypasses.  
> **Closure path**: branch 1/2 classification is confirmed by PR-D4b + external review; does not block signing off Pairwise Echo release.  
> **Forgery hardness (DecModQ)**: see §2.5 — no known feasible attack; the main IA precision gaps are not R1-FS.

**Relation of §2.3 to §2.4**: the A/B/C taxonomy in §2.3 remains; **sign-off owners should sign against §2.4.3**, not only the “consistent with Kudelski” line in the §2.3 table.

### 2.5 Hardness of Forging a “Valid Number that Passes DecModQ Verify” (threat model)

This section answers the follow-up after sign-off: **even after accepting the class-A gap, how hard is it in practice for an attacker to forge a DecModQ proof?**  
Conclusion up front: **no known feasible attack under the current threat model**; hardness **depends entirely on §2.4.2 branch classification**; the main gaps for **IA attribution precision** remain IA-01 / IA-03, **not** R1-FS.

#### 2.5.1 Underlying assumptions (branch-independent)

The DecModQ statement is \(Y \equiv x \pmod q\) (\(Y\) is Paillier-ciphertext-related; \(x\) is a broadcast scalar). Paillier semantic security rests on the **Decisional Composite Residuosity (DCR)** assumption: given \(N,g,\omega\), distinguishing the \(N\)-th residue class of \([\omega]_N\) from a general element is believed hard under standard parameters.

More operationally: recovering random plaintext from a Paillier ciphertext, or constructing a ciphertext–proof pair that **fails the statement yet passes Verify**, without the trapdoor, is equivalent to breaking DCR / solving an **\(N\)-th root**-class problem of the same magnitude as **RSA mod \(N\)** — **far harder** than algebraic gcd tricks inside the allowed challenge space.

#### 2.5.2 By branch: can FS challenge structure alone open a forgery path?

| Branch | Hardness of forging a DecModQ proof | Rationale |
|--------|--------------------------------------|-----------|
| **Branch 1** (extractor needs **only** \(\gcd(e-e',N)=1\)) | **Algebraically not exploitable via the gcd path** | To exploit a “bad” challenge pair \((e,e')\) with \(\gcd(e-e',N)>1\), the attacker must find such a pair inside the space allowed by `GetE`; §2.1 **deterministically** rules this out (always 1 when \(e\neq e'\)). At the FS layer the **simple forgery path is blocked**; remaining hardness **falls to Paillier/DCR** |
| **Branch 2** (additional prime-field / \(\mathbb{Z}_N^\*\) structure required) | **No closed argument**; therefore no quantitative “easy/hard” judgment; **no known construction today** | **Primary**: under the standard model, soundness **proof machinery does not cover** (no closed argument) ⇒ **Secondary**: one cannot assert “easy” or “hard”, only uncertainty; **additional fact**: nobody has given a concrete construction. Literature notes that non-standard challenge spaces **may** weaken soundness error (e.g. needing \(O(\log p)\) repetitions), but exploitation requires a **very specific design flaw** — Alice’s implementation has **no** known instance of such a flaw |

#### 2.5.3 Practical judgment (integration / IA view)

To forge a DecModQ “valid number” that passes Verify, an attacker must **simultaneously** achieve:

1. Break Paillier/DCR (or equivalently solve an \(N\)-th-root-class hard problem), **or**
2. Exploit a defect in FS challenge structure to forge a transcript.

Path (2)’s gcd exploitation is ruled out by §2.1; (1) is **orthogonal** to R1-FS and has **no known polynomial-time algorithm**.

**Remaining branch-2 risk** is therefore a **proof-template coverage problem** (“not proven impossible”), **not** a quantified “attacker capability problem” — consistent with §2.4.1’s “not a known forgery algorithm”.

**Implications for IA**:

- R1-FS **does not** let a malicious party **easily** forge DecModQ to bypass Verify and mislead `GetBlamedPeers`;
- The main causes of **imprecise attribution** remain **IA-01** (mask multi-solution heuristics) and **IA-03** (Err1 global Δ over-blame); see [CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) §IA-01 · §IA-03.

#### 2.5.4 One-liner (may be attached to sign-off)

> **Forging a valid DecModQ proof**: under branch 1 the gcd forgery path is **impossible**; under branch 2 there is **no known construction**, and the hardness lower bound remains constrained by Paillier/DCR. R1-FS is not the main precision bottleneck for current IA engineering attribution.

---

## 3. Impact Scope

| Component | Impact |
|-----------|--------|
| `crypto/zkproof/paillier/*` | All `GetE` call sites (DecModQ, Mul, Aff, …) |
| CGGMP sign IA | DecModQ self-proof / Err1 paths depend on FS soundness |
| CGGMP DKG / refresh / signSix | Same-library ZK, not sign-only |
| FROST | Does not go through Paillier `GetE` (**out of** this memo’s scope) |

---

## 4. Diff vs Upstream

| Item | upstream getamis/alice | This fork |
|------|------------------------|-----------|
| `GetE` algorithm | \(e\in[-q/2,q/2]\) integer | **Unchanged** |
| Accepted-risk documentation | Scattered in CGGMP reviews | **This memo + IA-02 four-tier “accepted risk”** |
| Closure path | — | PR-D4a (this memo) ✅ · PR-D4b (prime challenge PoC) |

---

## 5. Follow-ups (PR-D4b; does not block mainline)

- Branch PoC: change `GetE` to a prime challenge (or \(\mathbb{Z}_q^\*\) sampling + compatibility with existing transcripts);
- **Primary goal**: per ZK call site, confirm §2.4.2 **branch 1 vs branch 2** classification (DecModQ / Mul / Aff …);
- Evaluate: whole-library ZK regression, performance, `maxRetry` behavior, interoperability with old proofs;
- **Do not** commit to a PoC timeline in this memo — only define deliverable boundaries.

---

## 6. References (derivation sources)

1. Alice implementation: `crypto/zkproof/paillier/affinegroupzkproof.go` — `GetE` (\(|e|\le q/2\) constraint).
2. CGGMP review notes: [CGGMP.md](./CGGMP.md) §§5.3–5.4 (R1-FS entry).
3. Generic \(\gcd\) probability: probability that random \(\delta\) is divisible by a \(p\)-bit prime \(p\) is \(\le 2^{-p}\) (union bound in §2.2).
4. Standard Fiat–Shamir template: challenges from a prime-order field; class-A worst-case bound in **§2.4**.

---

## Revisions

| Date | Notes |
|------|-------|
| 2026-09-13 | Initial: quantitative bounds §2.1–2.2, sign-off wording §2.3, PR-D4a delivery |
| 2026-09-13 | §2.4 class-A worst-case bound + clarify §2.1 vs class-A boundary; §2.4.3 sign-off citation block |
| 2026-09-13 | §2.5 DecModQ forgery hardness / threat model; decouple IA precision from R1-FS |
| 2026-09-13 | §0 accurate status table: template weak ≠ runtime weak; docs tighter than comments |
| 2026-09-14 | Wording tighten: hypothetical worst ≠ known attack; “only weak” limited to proof layer; §2.5.2 primary/secondary; §0 reading order |
| 2026-09-14 | English edition |
