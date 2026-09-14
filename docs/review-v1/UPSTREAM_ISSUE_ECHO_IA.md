# [Feedback] Pairwise Echo / Identifiable Abort on Sign — reference fork (no merge expected)

## Summary

We would like maintainers to consider two Sign-path topics that are easy to under-specify in practice:

1. **Pairwise Echo / broadcast consistency**  
   Global `EchoMsgMain`-style hashing does not by itself stop **pairwise equivocation** (same author, same round, different payloads to different peers). Hardening usually needs an extra commit–reveal barrier (digest table + reveal gate), similar in spirit to adding a reliability round for the first-round broadcast.

2. **Identifiable Abort (IA)**  
   Failure-path blame is valuable, but it is easy to over-claim. We think upstream (and integrators) benefit from **explicit Confirmed vs Suspect semantics** and a written list of what IA does *not* prove.

We are **not** asking to renegotiate success-path formulas (Keygen / Refresh / Sign main algebra can stay paper-aligned). This is about **consistency of what was broadcast** and **honest documentation of abort accountability**.

## Ask (roadmap — timing entirely yours)

**Why now:** broadcast consistency is a prerequisite for IA to be meaningful in practice. Without it, a malicious peer can equivocate and the failure-path blame may point at the wrong party. This is a documentation/consistency gap, not a success-path algebra issue.

- **Sign (priority)**: consider a **pairwise digest + reveal gate** (or equivalent) so honest parties only advance under a consistent digest view, and digest authors are blamed on Echo conflict.
- **Failure path**: document / expose **Confirmed vs Suspect** (or similar) so penalty logic is not fed a mixed peer set.
- **Later / optional**: DKG, Refresh, signSix can follow the same bar; we suggest **3-round Sign first**.

## What we already validated on a fork (reference only)

Breaking-wire prototype for comparison — **please do not treat this as a merge request**.

| Area | Status on fork |
|------|----------------|
| CGGMP 3-round Sign Pairwise Echo | Digest Echo + table/`table_root` + reveal gate; conflict → blame digest author |
| FROST Sign Pairwise Echo | Same pattern applied to a different protocol family (EdDSA); included only to show the pattern generalizes |
| Scheme A′-style IA | Err1/Err2 + DecModQ; `GetBlameResult` Confirmed/Suspect |
| Strong Echo on Refresh / signSix / DKG | **Not** claimed complete |

- Repo: https://github.com/godaddy-x/alice  
- Branch: `master`  
- Docs index: `docs/review-v1/README.md`  
  - Echo: `PAIRWISE_ECHO.md` (§0.1 closed-loop + boundaries)  
  - IA limits: `CGGMP_IA_LIMITS_AND_REMEDIATION.md`  
  - CGGMP overview / CVE notes: `CGGMP.md`

Happy to discuss design or tests. **No expectation of upstream merge.**

Thanks for considering.
