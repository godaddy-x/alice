# review-v1 文档索引

> Alice fork（Pairwise Echo Digest + Scheme A′ IA）· 以代码与 `PAIRWISE_ECHO.md` 为准

| 文档 | 内容 |
|------|------|
| **PAIRWISE_ECHO.md** | CGGMP sign · 改造 · 测试（已实现） |
| **FROST_PAIRWISE_ECHO.md** | FROST sign · Pairwise Echo（**已实现** · frost-sign-v2） |
| **CGGMP_IA_LIMITS_AND_REMEDIATION.md** | **IA / Pairwise 问题清单（四档状态）+ remediation 方案** |
| **R1-FS_risk_memo.md** | **IA-02 接受风险 · 量化上界 + sign-off 表述（PR-D4a）** |
| CGGMP.md | 安全审查 · Scheme A′ · DecModQ R1（概要；状态表以 IA_LIMITS 为准） |
| BROKER_NODE_INTEGRATION_TEST_PLAN.md | replace 联调 · L2/L3 · abnormal |
| FROST_SECURITY_REVIEW.md | FROST 现状审查 · FR-01~08 |

```powershell
cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ -run TestMeshErr -v
go test ./crypto/tss/ecdsa/cggmp/sign/ -timeout 600s -coverprofile cover_sign.out
```
