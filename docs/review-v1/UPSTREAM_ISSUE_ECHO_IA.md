# Upstream Issue Draft — Echo / IA (getamis/alice)

> **Status**: draft for posting to [getamis/alice](https://github.com/getamis/alice)  
> **Language**: English (paste into GitHub)  
> **Intent**: ask maintainers to consider stronger Sign-path Echo + clearer IA limits; fork = **reference only** (not a merge request)

Copy **Suggested title** + **Suggested body** only. Keep **Notes** internal.

---

## Suggested title

```text
[Feedback] Pairwise Echo / Identifiable Abort on Sign — reference fork (no merge expected)
```

## Suggested body

```markdown
## Summary

We would like maintainers to consider two Sign-path topics that are easy to under-specify in practice:

1. **Pairwise Echo / broadcast consistency**  
   Global `EchoMsgMain`-style hashing does not by itself stop **pairwise equivocation** (same author, same round, different payloads to different peers). Hardening usually needs an extra commit–reveal barrier (digest table + reveal gate), similar in spirit to adding a reliability round for the first-round broadcast.

2. **Identifiable Abort (IA)**  
   Failure-path blame is valuable, but it is easy to over-claim. We think upstream (and integrators) benefit from **explicit Confirmed vs Suspect semantics** and a written list of what IA does *not* prove.

We are **not** asking to renegotiate success-path formulas (Keygen / Refresh / Sign main algebra can stay paper-aligned). This is about **consistency of what was broadcast** and **honest documentation of abort accountability**.

## Ask (roadmap — timing entirely yours)

- **Sign (priority)**: consider a **pairwise digest + reveal gate** (or equivalent) so honest parties only advance under a consistent digest view, and digest authors are blamed on Echo conflict.
- **Failure path**: document / expose **Confirmed vs Suspect** (or similar) so penalty logic is not fed a mixed peer set.
- **Later / optional**: DKG, Refresh, signSix can follow the same bar; we suggest **3-round Sign first**.

## What we already validated on a fork (reference only)

Breaking-wire prototype for comparison — **please do not treat this as a merge request**.

| Area | Status on fork |
|------|----------------|
| CGGMP 3-round Sign Pairwise Echo | Digest Echo + table/`table_root` + reveal gate; conflict → blame digest author |
| FROST Sign Pairwise Echo | Same pattern (separate wire version) |
| Scheme A′-style IA | Err1/Err2 + DecModQ; `GetBlameResult` Confirmed/Suspect |
| Strong Echo on Refresh / signSix / DKG | **Not** claimed complete |

- Repo: https://github.com/godaddy-x/alice  
- Branch: `master-pr1`  
- Docs index: `docs/review-v1/README.md`  
  - Echo: `PAIRWISE_ECHO.md` (§0.1 closed-loop + boundaries)  
  - IA limits: `CGGMP_IA_LIMITS_AND_REMEDIATION.md`  
  - CGGMP overview / CVE notes: `CGGMP.md`

Happy to discuss design or tests. **No expectation of upstream merge.**

Thanks for considering.
```

---

## Notes (internal — do not paste)

| Item | Guidance |
|------|----------|
| Tone | Short feedback; fork = comparison only; no merge ask; no formula renegotiation |
| Echo | Three-step loop **closed on 3-round Sign** on the fork; say “validated on fork”, do not claim the whole library |
| IA | Engineering accountability; do **not** claim unique cryptographically identifiable abort |
| Keep out of this issue | Long R1-FS memo, full CGGMP24 gap list, G-01~06 detail (separate thread if needed) |
| CVE | Not required in this issue; audit notes live in `CGGMP.md` §7 |
| Boundaries | Reveal-not-Echo + gate store; IA-05 P1 / §8 edge tests ≠ “Echo not implemented” |
