# DelegationCourt — GenLayer 互联网法院生态伙伴演练实验室 (ERC-7710 · x402 · ERC-8004)

[English](./README.md) | **简体中文**

**DelegationCourt** (`delegation-court/1`) 是构建在 **GenLayer** 上的链上**互联网法院生态伙伴演练实验室（Internet Court: Partner Demo Lab）**，将三大 Web3 与智能体商业标准深度融合为一套由多验证者共识裁决的链上争议仲裁与执行流水线：

1. **MetaMask 智能账户委托工具包 (`ERC-7710` / `ERC-7715`) — 链上限制条款执行器 (Caveat Enforcer)**：
   - 委托人（Principal）通过绑定能力边界与预算上限（`allowed_capabilities`、`max_spend_usd_cents`、`erc7710_delegation_hash`）向自主 AI 智能体授予受限权限。
   - 合约提供 `is_erc7710_delegation_active(delegation_hash)` 与 `get_erc7710_delegation(delegation_hash)`。一旦智能体越权调用未授权能力、超支预算或在目录树中隐瞒可执行文件，互联网法院将自动把该委托置为 `REVOKED_BY_COURT`（永久吊销），并拦截该委托哈希下的后续任务注册。
2. **Coinbase `x402` 智能体支付协议 — 拉取式托管与罚没清算 (Pull-Based Escrow)**：
   - 每笔委托任务绑定 `x402_payment_id` 与 `escrow_amount_cents`，并执行确定性预算核验（`actual_spend_usd_cents <= max_spend_usd_cents`）。
   - 根据互联网法院裁决（`UPHELD` 0% 罚没、`PARTIAL_SLASH` 50% 部分罚没、`BLOCKED_AND_REVOKED` 100% 全额罚没并吊销授权），由 `settle_escrow(mandate_id)` 记入 `claimable_balances`，并通过 `withdraw_balance(amount_cents)` 安全提现。
3. **无信任智能体标准 (`ERC-8004`) — 可移植声誉与验证注册表 (Agent Reputation Card)**：
   - `get_erc8004_agent_card(agent_address)` 维护防篡改、重审不重复计数的智能体声誉卡（`adjudicated_count`、`upheld_count`、`partial_slash_count`、`revoked_count`、`trust_score_bps` 及状态评级）。

---

## 链上真实部署与端到端交易证明 (GenLayer Studio-dev `chainId = 61997`)

- **合约地址**：`0xA8E20181AE15aa254339edE75786DaeEd9B48852`
- **部署交易 (`ACCEPTED`)**：`0x542864398980cbec32e59ff8754082622791ce2f8b4d8004028ab7a34215b898`
- **`register_mandate` 交易 (`ACCEPTED`)**：`0xc288eb4ae04560506d832baa44af0981508f39667172bbb59186c86ef4b82376`
- **`lock_mandate_evidence` 交易 (`ACCEPTED`)**：`0x4c2814d4a2f279631346078da37a1a89fbf78244ef967ff94d7d06ff583ae415`
- **`adjudicate_mandate` 交易 (`ACCEPTED`)**：`0xe005103d6a21e3b87d5b7eb366d6d79b04ee67a7cbffe552c191a36e57d31c6d`
- **在线交互工作台 (GitHub Pages)**：https://glieser2.github.io/delegation-court/

---

## 快速验证与测试

```bash
# 1. 运行 Python 智能合约单元测试（11 项核心安全与伙伴协议测试）
python scripts/generate-compact.py
python -m unittest discover -s tests/python -p "test_*.py" -v

# 2. 运行前端 Vitest 与 CLI/MCP 集成测试并构建生产包
pnpm test
pnpm run build
```
