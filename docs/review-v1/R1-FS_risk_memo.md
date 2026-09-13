# R1-FS · GetE 非素数 Challenge — 接受风险 memo

> **状态**：review-v1 · IA-02 闭合文档（PR-D4a 交付物）  
> **关联**：[CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) §IA-02 · [CGGMP.md](./CGGMP.md) §5.4  
> **代码**：`crypto/zkproof/paillier/affinegroupzkproof.go` · `GetE`  
> **读者**：安全审计 / sign-off 负责人

---

## 0. 准确状态（一句话）

| 项 | 状态 |
|----|------|
| **代码** | 与 upstream alice **一致**（`GetE` 整数 challenge，未改） |
| **运行期 gcd** | \(e\neq e'\) 时 \(\gcd(e-e',N)=1\) **确定性恒成立**（§2.1）；**不**影响 Verify / abort 行为 |
| **文档 vs 注释** | 本文 / CGGMP.md 比代码注释 **更紧**（注释曾写 w.h.p.；应以本文为准） |
| **唯一「弱」点** | 证明模板 **未按标准 FS 形式表述** → 标准模型下 soundness **无闭合论证** |
| **不包含** | 运行期弱化、已知伪造攻击、IA 归责可轻易绕过（见 §2.5） |

**接受风险 = 模板表述缺口（A）**；**≠**「运行期不安全」或「比标准 FS 实现更弱」。

---

## 1. 问题陈述

Alice Paillier ZK（DecModQ / Mul / Aff 等）的 Fiat–Shamir challenge 由 `GetE` 生成：

- \(e \in \mathbb{Z}\)，采样约束为 \(|e| \le q/2\)（`groupOrder` \(q\) 为椭圆曲线阶，secp256k1 下 \(q \approx 2^{256}\)）；
- **非**素数域元素，**非** \(\mathbb{Z}_N^\*\) 上均匀随机。

标准 FS soundness 证明通常要求 challenge 取自素数阶域；本实现沿用 upstream alice 的整数 challenge 设计。  
**接受风险的对象是「证明模板缺口」**，而非「运行期频繁触发 \(\gcd(e-e',N)\neq 1\)」，亦非「实现比标准 FS 更弱」。

---

## 2. 量级声明（审计用）

### 2.1 Alice 实际参数下的 **运行期** 上界

**声明**：在标准 Paillier 参数（2048-bit \(N = p\cdot p'\)，\(p,p'\) 各约 1024-bit 素数；`NoSmallFactor`；\(|e|,|e'|\le q/2\)）下，对 **任意** \(e \neq e'\)：

\[
\Pr\big[\gcd(e-e', N) \neq 1 \mid e \neq e'\big] = 0
\]

**推导（参数不等式，非渐近）**：

1. 令 \(\delta = e - e'\)。由 `GetE` 约束，\(|\delta| \le q < 2^{256}\)。
2. 设 \(N = p \cdot p'\)，\(p,p'\) 为 Paillier 素因子，各 \(\approx 2^{1024}\)。
3. 若 \(\gcd(\delta, N) > 1\)，则存在素数 \(r \mid \delta\) 且 \(r \mid N\)，故 \(r \in \{p, p'\}\)。
4. 若 \(r \mid \delta\)，则 \(|\delta| \ge r \ge 2^{1023}\) 量级，与 \(|\delta| < 2^{256}\) 矛盾。
5. 故 \(e \neq e'\) 时必有 \(\gcd(\delta, N) = 1\)。

**\(e = e'\) 情形（FS 绑定，非 gcd 随机失败）**：

- \(\gcd(0, N) = N \neq 1\)，但要求两次独立 FS 输出相同 \(e\)，等价于 **相同 transcript 输入下的 hash 碰撞 / 重放**；
- 在 RO/FS 模型下，该事件概率 **可忽略**（由 `HashProtos` + salt 重试 `maxRetry` 绑定；见 `GetE` 实现）。

**结论（运行期）**：DecModQ 等证明 **不会因「随机抽到 \(\gcd(e-e',N)\neq 1\)」而在 Alice 默认参数下 abort**；extractor 在 \(e\neq e'\) 时 **恒有** \(\gcd(e-e',N)=1\) 可用。

> **与 A 类风险的关系（见 §2.4）**：§2.1 已 **确定性** 证明 gcd 条件在默认参数下恒成立。A 类缺口 **不是**「运行期 gcd 可能失败」，而是「该条件是否足以闭合 soundness 证明」——二者必须在 sign-off 时分开表述。

### 2.2 通用随机模型上界（模板引用，非 Alice 主路径）

若 **不** 施加 \(|e|\le q/2\) 约束，而令 \(\delta\) 在 \(\mathbb{Z}\) 上「与 \(N\) 同量级独立随机」（或 \(|\delta|\) 可达 \(O(\sqrt{N})\)），则 \(\gcd(\delta,N)\neq 1\) 当且仅当 \(\delta\) 被 \(N\) 的某个素因子整除：

\[
\Pr[\gcd(\delta, N) \neq 1] \;\lesssim\; \frac{1}{p} + \frac{1}{p'} \;=\; O(2^{-1024})
\]

（对 2048-bit \(N = p\cdot p'\)，\(p,p'\sim 1024\) bit。）

**来源**：经典数论 — 随机整数与固定大素数 \(p\) 共享因子的概率 \(\le 1/p\)；两素因子并集 union bound。  
**与 Alice 关系**：此上界 **不收紧也不放松** §2.1 的 **精确 0** 结论；仅作审计追问「极低是多少」时的 **通用量级锚点**。

### 2.3 我们 **实际接受** 的风险是什么

| 类别 | 说明 | 量级 |
|------|------|------|
| **A · 证明缺口** | 整数 challenge 非素数域；**最坏后果见 §2.4**（非运行期 gcd 事件） | **定性** — 需 sign-off |
| **B · 运行期 gcd 失败** | §2.1：\(e\neq e'\) 时 **0**；\(e=e'\) 归 FS 绑定 | **可忽略** |
| **C · 库级 breaking 变更** | 改 `GetE` 影响全库 Paillier ZK API | 工程成本 — 见 PR-D4b |

### 2.4 A 类缺口的最坏后果（sign-off 依据）

sign-off 的本质是「**我知道最坏情况是 X，我接受 X**」。本节界定 A 类在 **密码学层面** 的最坏边界；**运行期** 不受 §2.4 中任何分支影响（§2.1 已闭合）。

#### 2.4.1 先回答三个审计必问

| 问题 | 回答 |
|------|------|
| **最坏是 soundness 失效还是 extractor 失效？** | 最坏指 **soundness 在标准模型下无闭合论证**（可能伴随 extractor 步骤在教科书模板中不可形式化）。**不是**「已知存在多项式时间伪造算法」。 |
| **若是 extractor 失效，证明是否仍然 sound？** | **分情形**（§2.4.2）。若 extractor **仅**依赖 \(\gcd(e-e',N)=1\)，则 §2.1 已证该条件恒成立，soundness **在代数前提上不受 gcd 影响**；缺口退化为「证明未按标准 FS 模板书写」。若 extractor **额外**要求 \(e-e'\in\mathbb{Z}_N^\*\) 或素数域结构，则 extractor 步骤在标准模板下 **不可直接套用**，但 **不等于** 已构造出伪造；soundness 在标准模型下 **无闭合证明**。 |
| **若是 soundness 失效，攻击者需要什么能力？** | 在 **尚未发现具体攻击** 的前提下，最坏情景是：攻击者作为 malicious prover，在 RO/FS 模型下 **可能** 利用非标准 challenge 空间找到 **未被现有证明覆盖** 的伪造路径。所需能力上界：**标准 MPC 恶意参与者**（可任意偏离协议、自适应选择 Paillier 相关消息），**不**假设 CDH/DDH 等额外困难问题被突破。 |

#### 2.4.2 两种分支（PR-D4b / 外部 review 确认归属）

**分支 1 — extractor 代数前提 **仅** 要求 \(\gcd(e-e',N)=1\)（\(e\neq e'\)）**

- §2.1 已 **确定性** 证明：Alice 默认参数下该条件 **恒成立**。
- **最坏后果**：A 类风险 **退化为「证明模板未按标准 Fiat–Shamir 形式表述」** — 即审计文档/论文引用的 **表述 gap**，**不是** 运行期 soundness 失效，**不是** 已知可 exploitable 的代数漏洞。
- **sign-off 含义**：接受「与 upstream / Kudelski 审查路径一致的 **文档级技术债**」；**不** 接受「存在已知的 Paillier ZK 伪造攻击」。

**分支 2 — 某 extractor **额外** 要求 \(e-e'\) 为素数或 \(e-e'\in\mathbb{Z}_N^\*\)（或等价的标准域结构）**

- §2.1 **仍成立**：\(\gcd(e-e',N)=1\) 在运行期恒满足；**运行期行为与分支 1 相同**。
- **最坏后果**：对应 ZK 的 **soundness 在标准模型下无闭合论证** — 即 **无法** 在教科书 FS 框架内给出完整 extractor；**不等于** 已证明 soundness 为假。
- **攻击者能力上界**（若 soundness  indeed 不成立时的 **理论最坏**）：malicious prover + 协议内可见信息；产出 **通过 Verify 的伪造 proof**（针对受影响的 Paillier ZK 语句）。**未** 在本 memo 或 upstream 中给出此类攻击的具体构造。
- **sign-off 含义**：接受「**可能存在** 未被证明覆盖的伪造路径，但 **无已知实例**；与 upstream 风险 posture 一致；由 PR-D4b / 外部密码学 review **确认是否落入本分支**。

**本 memo 立场**：**不声称** 已确定 Alice 各 `GetE` 调用点属于分支 1 还是分支 2；§2.1 对两分支 **均** 闭合运行期 gcd。分支归属是 PR-D4b 的交付目标，不是 PR-D4a 的阻塞项。

#### 2.4.3 sign-off 建议表述（可直接引用）

> **我接受的最坏情况是**：在标准模型下，部分 Paillier FS 证明 **可能** 无法给出闭合 soundness 论证（分支 2）；或仅为证明模板表述 gap（分支 1）。**我不接受** 已存在已知的多项式时间伪造攻击这一 stronger 命题 — 当前 **无** 此类攻击记录。  
> **运行期**：§2.1 已证 \(\gcd(e-e',N)=1\) 在 \(e\neq e'\) 时恒成立；**不因 A 类缺口产生额外 abort 或 verify 绕过**。  
> **闭合路径**：分支 1/2 归属由 PR-D4b + 外部 review 确认；不阻塞 sign Pairwise Echo 发版。  
> **伪造难度（DecModQ）**：见 §2.5 — 无已知可行攻击；IA 精度主因不在 R1-FS。

**§2.3 与 §2.4 关系**：§2.3 的 A/B/C 分类保留；**sign-off 负责人应依据 §2.4.3 签字**，而非仅 §2.3 表格中的「与 Kudelski 一致」一句。

### 2.5 伪造「能通过 DecModQ Verify 的有效数」的难度（威胁模型）

本节回答 sign-off 的后续追问：**即便接受 A 类缺口，攻击者伪造 DecModQ proof 的实际难度是多少？**  
结论前置：**当前威胁模型下无已知可行攻击**；难度 **完全取决于 §2.4.2 分支归属**；**IA 归责精度**的主要缺口仍在 IA-01 / IA-03，**不在** R1-FS。

#### 2.5.1 底层依赖（与分支无关）

DecModQ 证明语句 \(Y \equiv x \pmod q\)（\(Y\) 为 Paillier 密文相关量，\(x\) 为广播标量）。Paillier 语义安全性建立在 **合数剩余类 / Decisional Composite Residuosity (DCR)** 假设上：给定 \(N,g,\omega\)，区分 \([\omega]_N\) 的 \(N\) 次剩余类与一般元素在标准参数下被认为困难。

更 operational 的表述：从 Paillier 密文 **反推随机明文** 或构造 **不满足语句却通过 Verify** 的密文—证明对，在缺少 trapdoor 时等价于破坏 DCR / 求解与 **RSA mod \(N\)** 同量级的 **\(N\) 次根** 类问题 — **远高于** 在允许 challenge 空间内做 gcd 代数 trick 的难度。

#### 2.5.2 分分支：FS challenge 结构能否单独打开伪造路径

| 分支 | 伪造 DecModQ proof 的难度 | 理由 |
|------|---------------------------|------|
| **分支 1**（extractor **仅**需 \(\gcd(e-e',N)=1\)） | **代数上不可经 gcd 路径利用** | 要利用「坏」challenge 对 \((e,e')\) 使 \(\gcd(e-e',N)>1\)，攻击者须在 `GetE` 允许空间内找到此类对；§2.1 **确定性** 排除（\(e\neq e'\) 时恒为 1）。FS 层面 **简单伪造路径被堵死**；剩余难度 **归 Paillier/DCR** |
| **分支 2**（额外要求素数域 / \(\mathbb{Z}_N^\*\) 结构） | **无已知构造**；非「容易/困难」二元，而是 **证明工具未覆盖** | 标准模型下无闭合 soundness 论证 ⇒ **理论上可能存在** 未被证明排除的伪造角；**当前无人给出具体构造**。文献中 non-standard challenge 空间 **可能** 削弱 soundness error（需重复 \(O(\log p)\) 次等），但需 **非常具体的设计缺陷** 才可 exploit — Alice 实现 **无** 此类已知缺陷实例 |

#### 2.5.3 实际判断（集成 / IA 视角）

攻击者若要伪造通过 Verify 的 DecModQ「有效数」，需 **同时** 满足：

1. 破坏 Paillier/DCR（或等价求解 \(N\) 次根类难题），**或**
2. 利用 FS challenge 结构缺陷构造伪造 transcript。

其中 (2) 的 gcd 利用路径已被 §2.1 排除；(1) 与 R1-FS **正交**，且 **无已知多项式时间算法**。

**分支 2 剩余风险** 因此是 **证明模板覆盖问题**（「未被证明不可能」），**不是** 已量化的「攻击者能力问题」 — 与 §2.4.1「不是已知存在伪造算法」一致。

**对 IA 的含义**：

- R1-FS **不会** 使 malicious 方 **轻易** 通过伪造 DecModQ 绕过 Verify 并误导 `GetBlamedPeers`；
- **归责不精确** 的主因仍是 **IA-01**（mask 多解启发式）与 **IA-03**（Err1 全局 Δ over-blame），见 [CGGMP_IA_LIMITS_AND_REMEDIATION.md](./CGGMP_IA_LIMITS_AND_REMEDIATION.md) §IA-01 · §IA-03。

#### 2.5.4 一句话（可并入 sign-off 附件）

> **伪造 DecModQ 有效 proof**：分支 1 下 gcd 伪造路径 **不可能**；分支 2 下 **无已知构造**，难度下界仍受 Paillier/DCR 约束。R1-FS 不是当前 IA 工程化归责的主要精度瓶颈。

---

## 3. 影响范围

| 组件 | 影响 |
|------|------|
| `crypto/zkproof/paillier/*` | 所有 `GetE` 调用点（DecModQ, Mul, Aff, …） |
| CGGMP sign IA | DecModQ 自证 / Err1 路径依赖 FS soundness |
| CGGMP DKG / refresh / signSix | 同库 ZK，非 sign-only |
| FROST | 不经过 Paillier `GetE`（**不在** 本 memo 范围） |

---

## 4. 与 upstream 的 diff

| 项 | upstream getamis/alice | 本 fork |
|----|------------------------|---------|
| `GetE` 算法 | \(e\in[-q/2,q/2]\) 整数 | **未改** |
| 接受风险文档 | 分散在 CGGMP 审查 | **本文 + IA-02 四档「接受风险」** |
| 闭合路径 | — | PR-D4a（本文）✅ · PR-D4b（prime challenge PoC） |

---

## 5. 后续（PR-D4b，不阻塞主线）

- 分支 PoC：`GetE` 改为素数 challenge（或 \(\mathbb{Z}_q^\*\) 采样 + 与现有 transcript 兼容）；
- **首要目标**：逐 ZK 调用点确认 §2.4.2 **分支 1 vs 分支 2** 归属（DecModQ / Mul / Aff …）；
- 评估：全库 ZK 回归、性能、`maxRetry` 行为、与旧 proof 互操作；
- **不** 在本 memo 中承诺 PoC 时间表 — 仅定义交付物边界。

---

## 6. 参考文献（推导来源）

1. Alice 实现：`crypto/zkproof/paillier/affinegroupzkproof.go` — `GetE`（\(|e|\le q/2\) 约束）。
2. CGGMP 审查记录：[CGGMP.md](./CGGMP.md) §5.3–5.4（R1-FS 条目）。
3. 通用 \(\gcd\) 概率：随机 \(\delta\) 被 \(p\)-bit 素数 \(p\) 整除的概率 \(\le 2^{-p}\)（union bound 见 §2.2）。
4. Fiat–Shamir 标准模板：challenge 取自素数阶域；A 类最坏后果界定见 **§2.4**。

---

## 修订

| 日期 | 说明 |
|------|------|
| 2026-09-13 | 初版：量化上界 §2.1–2.2、sign-off 表述 §2.3、PR-D4a 交付 |
| 2026-09-13 | §2.4 A 类最坏后果界定 + §2.1 与 A 类边界点破；§2.4.3 sign-off 引用段 |
| 2026-09-13 | §2.5 DecModQ 伪造难度 / 威胁模型；IA 精度与 R1-FS 解耦 |
| 2026-09-13 | §0 准确状态表：模板弱 ≠ 运行期弱；文档比注释更紧 |
