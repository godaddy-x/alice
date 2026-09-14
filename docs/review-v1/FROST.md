# FROST — security conclusions and open items

> **Scope**: `crypto/tss/eddsa/frost/`, shared `crypto/tss/dkg/`  
> **Pairwise Echo (implemented)**: [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) §B  
> **Related**: [README.md](./README.md) · [CGGMP.md](./CGGMP.md)

---

## 1. Conclusions

No Paillier/MtA-class single-point key recovery. Round2 has `zi·G` algebraic checks; DKG has Feldman + Schnorr + `ValidatePublicKey`.

**FR-01 (no strong Echo) closed**: Sign ships R1/R2 Pairwise Digest (frost-sign-v2).

---

## 2. Issue list (open / closed)

| ID | Sev | Issue | Status |
|----|-----|-------|--------|
| **FR-01** | Med | Sign Echo / equivocation | **Fixed** → [PAIRWISE_ECHO.md](./PAIRWISE_ECHO.md) §B |
| **FR-02** | Med | `NewSigner` does not validate DKG outputs | **Open** P1: `ValidatePublicKey` + `share·G==Y` |
| **FR-03** | Med | Final Ed25519 verify | **Confirm/open** P1: Finalize or app-layer verify |
| **FR-04** | Low | README mentions Reshare; code has none | **Open** P2 |
| **FR-05** | Low | Round1 D/E curve / identity checks | **Open** P3 |
| **FR-06** | Low | No paper-level identifiable abort | **Partial**: digest/algebra blame; no CGGMP Err packets |
| **FR-07** | Info | Signing requires all parties online | Ops awareness |
| **FR-08** | Info | Shared DKG has no Echo | **Open** (not P0) |

---

## 3. Integration notes

1. Sign only with local DKG share / Bks / Ys / pubKey  
2. App layer should Ed25519-verify the final signature (mitigates FR-03)  
3. No Refresh — share rotation needs a separate plan  
4. All parties online together; breaking wire — same fork for everyone  

---

## Revisions

| Date | Note |
|------|------|
| 2026-09-12 | Initial FR-01~08 (was FROST_SECURITY_REVIEW) |
| 2026-09-13 | FR-01 → Pairwise redesign |
| 2026-09-14 | Condensed to this file; Echo body in PAIRWISE_ECHO.md |
| 2026-09-14 | English edition |
