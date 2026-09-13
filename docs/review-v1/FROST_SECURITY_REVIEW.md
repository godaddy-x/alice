# FROST 实现路径安全审查

> **审查**：review-v1（[`./README.md`](./README.md)）  
> **范围**：`crypto/tss/eddsa/frost/`、`crypto/tss/dkg/`（通用 DKG）  
> **读者**：集成方 / MPC 节点实现者 / 安全审计  
> **关联**：[../../crypto/tss/eddsa/frost/README.md](../../crypto/tss/eddsa/frost/README.md)、[CGGMP.md](./CGGMP.md)、**改造设计 [FROST_PAIRWISE_ECHO.md](./FROST_PAIRWISE_ECHO.md)**  
> **修订**：2026-09-13 指向 FROST Pairwise Echo 设计稿

---

## 1. 结论

**无 Paillier/MTA 类 key-recovery 单点漏洞**。Round2 有 `zi·G` 代数校验，通用 DKG 有 Feldman + Schnorr + `ValidatePublicKey`。

主风险：**全程无 Echo**（equivocation）、**Sign 入口不 re-validate DKG 产物**、**运行时无最终签名 verify**、**Reshare 文档有但代码无**。

---

## 2. 问题清单与修复索引

| ID | 级 | 问题 | 位置 | 修复要点 | 优先 |
|----|-----|------|------|----------|------|
| **FR-01** | 中 | ~~Signer 仅 Round1 全局 Echo~~ | `signer/` | **已实现** [FROST_PAIRWISE_ECHO.md](./FROST_PAIRWISE_ECHO.md) R1/R2 Digest + gate | — |
| **FR-02** | 中 | `NewSigner` 不校验 DKG 产物 | `signer/round_1.go` | `ValidatePublicKey` + `share·G==Y` | P1 |
| **FR-03** | 中 | 无 Ed25519/BIP340 最终 verify | `signer/round_2.go` | Finalize 调用 verify | P1 |
| **FR-04** | 低 | README 有 Reshare，代码未实现 | `frost/README.md` | 删文档或实现 refresh | P2 |
| **FR-05** | 低 | Round1 不验 D/E 曲线/identity | `signer/round_1.go` | `HandleMessage` 加强校验 | P3 |
| **FR-06** | 低 | 无 identifiable abort | `signer/round_2.go` | 失败时广播 blame（可选） | P3 |
| **FR-07** | 信息 | 签名须**全员**在线 | `signer/round_1.go` | 集成/运维认知 | — |
| **FR-08** | 信息 | 通用 DKG 亦无 Echo | `crypto/tss/dkg/dkg.go` | 可选 DKG Echo | — |

**与 CGGMP（review-v1）**：F-02/F-05/CVE-2023-33241 **不适用**；CGGMP Echo 为 bug 禁用，FROST 为从未实现。

---

## 3. 修复方案（代码级）

### 3.1 FR-01：Pairwise Echo Digest（P1）

**不再**采用「仅 Round1 全局 Echo」补丁；按 [FROST_PAIRWISE_ECHO.md](./FROST_PAIRWISE_ECHO.md) 彻底改造：R1/R2 Digest 双屏障、pairwise gate、Echo 冲突问责、`GetBlamedPeers`。**无旧 wire 兼容**。

### 3.2 FR-02：Sign 入口校验 DKG 产物（P1）

`newRound1`：`CheckValid` → `ValidatePublicKey` → `share·G == Ys[self]`；仅用本地 DKG 落盘数据。

### 3.3 FR-03：Finalize 最终 verify（P1）

`round_2.go` 在 `p.z = z.Mod(...)` 后调用 `verifySignature(...)`。

### 3.4 FR-04 ~ FR-06（P2/P3）

Reshare 文档/实现、Round1 D/E 校验、identifiable abort（可选）。

---

## 4. 已确认措施

- Round2：`zi·G == c·coBk·Y + ri`；拒绝平凡 R/z
- DKG：Feldman + Schnorr + `ValidatePublicKey`
- `message` 绑入 binding factor / challenge hash
- 测试中有最终 verify；Secp256k1 路径要求 `len(message)==32`

---

## 5. 集成注意事项

1. Sign 仅用本地 DKG 的 share/Bks/Ys/pubKey  
2. Sign 完成后在**应用层**做 Ed25519 最终 verify（补 FR-03）  
3. 无 Refresh — 份额轮换需另规划  
4. 全员须同时在线签名  
5. 外部消息转发不能替代 Echo（仍应修 FR-01）

---

## 6. 参考

- [FROST 论文](https://eprint.iacr.org/2020/852.pdf)
- Kudelski `REPORT_2022.pdf`

---

## 附录 A. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-09-12 | 初版：FR-01~FR-08 问题清单与修复方案 |
| 2026-09-13 | FR-01 改为 FROST_PAIRWISE_ECHO 彻底改造；链至设计稿 |
