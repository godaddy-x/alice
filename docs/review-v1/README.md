# review-v1 文档索引

> Alice fork（Pairwise Echo Digest + Scheme A′ IA）· 以代码与 `PAIRWISE_ECHO.md` 为准

| 文档 | 内容 |
|------|------|
| **PAIRWISE_ECHO.md** | 改造功能点 · 实现分支 · 测试覆盖 · 跑法 · 缺口 |
| CGGMP.md | 安全审查 · Scheme A′ · DecModQ R1 |
| BROKER_NODE_INTEGRATION_TEST_PLAN.md | replace 联调 · L2/L3 · abnormal |
| FROST_SECURITY_REVIEW.md | FROST（非 CGGMP sign 阻塞项） |

```powershell
cd E:\work\github\alice
go test ./crypto/tss/ecdsa/cggmp/sign/ -run TestMeshErr -v
go test ./crypto/tss/ecdsa/cggmp/sign/ -timeout 600s -coverprofile cover_sign.out
```
