# DelegationCourt — Internet Court Partner Demo Lab on GenLayer

**English** | [简体中文](./README.zh-CN.md)

[![Policy Version](https://img.shields.io/badge/Policy-delegation--court%2F1-10b981?style=flat-square)](#)
[![Partner Standards](https://img.shields.io/badge/Partner_Standards-ERC--7710_%7C_x402_%7C_ERC--8004-6366f1?style=flat-square)](#)
[![Live Workbench](https://img.shields.io/badge/GitHub_Pages-Live_Workbench-0ea5e9?style=flat-square)](https://glieser2.github.io/delegation-court/)

**DelegationCourt** (`delegation-court/1`) is an on-chain **Internet Court Partner Demo Lab** built on **GenLayer** that bridges three flagship Web3 & agentic commerce standards into a unified, consensus-adjudicated dispute and enforcement pipeline:

1. **MetaMask Delegation Toolkit (`ERC-7710` / `ERC-7715`) — On-Chain Caveat Enforcer**:
   - Smart account principals delegate scoped authority to autonomous AI agents under strict capability and spend caveats (`allowed_capabilities`, `max_spend_usd_cents`, `erc7710_delegation_hash`).
   - `DelegationCourt` exposes `is_erc7710_delegation_active(delegation_hash)` and `get_erc7710_delegation(delegation_hash)`. If an agent breaches a caveat, exceeds its budget, or omits executable files from its release/execution tree, the Internet Court automatically flips the delegation to `REVOKED_BY_COURT` and blocks any future mandates under that delegation hash.
2. **Coinbase `x402` Agentic Payment Protocol — Pull-Based Escrow & Slash Settlement**:
   - Each mandate binds an `x402_payment_id` and `escrow_amount_cents` with deterministic spend verification (`actual_spend_usd_cents <= max_spend_usd_cents`).
   - Based on the Internet Court's consensus ruling (`UPHELD` -> `0 bps` slash, `PARTIAL_SLASH` -> `5,000 bps` slash, `BLOCKED_AND_REVOKED` -> `10,000 bps` full slash), `settle_escrow(mandate_id)` credits `claimable_balances` for pull-based withdrawal via `withdraw_balance(amount_cents)`.
3. **Trustless Agents Standard (`ERC-8004`) — Portable Agent Reputation & Validation Registry**:
   - `get_erc8004_agent_card(agent_address)` maintains an unforgeable, non-double-counted portable reputation card (`adjudicated_count`, `upheld_count`, `partial_slash_count`, `revoked_count`, `trust_score_bps`, and standing `GOOD_STANDING` / `PROBATION` / `REVOKED_CAVEAT`).

---

## Live On-Chain Deployment & E2E Proof (GenLayer Studio-dev `chainId = 61997`)

| Field | Value |
| :--- | :--- |
| **Network** | GenLayer Studio-dev (`https://studio-dev.genlayer.com/api`, `chainId = 61997`) |
| **Contract Address** | `0xA8E20181AE15aa254339edE75786DaeEd9B48852` |
| **Policy / Rubric Version** | `delegation-court/1` / `delegation-court/caveat-rubric/1` |
| **Deployment Tx (`ACCEPTED`)** | `0x542864398980cbec32e59ff8754082622791ce2f8b4d8004028ab7a34215b898` |
| **`register_mandate` Tx (`ACCEPTED`)** | `0xc288eb4ae04560506d832baa44af0981508f39667172bbb59186c86ef4b82376` |
| **`lock_mandate_evidence` Tx (`ACCEPTED`)** | `0x4c2814d4a2f279631346078da37a1a89fbf78244ef967ff94d7d06ff583ae415` |
| **`adjudicate_mandate` Tx (`ACCEPTED`)** | `0xe005103d6a21e3b87d5b7eb366d6d79b04ee67a7cbffe552c191a36e57d31c6d` |
| **Canonical Source (`contracts/delegation_court.py`) SHA-256** | `44b260bd1d2bf87f4ce4dd03c9b018aab131c2022e589ee03f319f67bfb41d37` |
| **Compact Source (`contracts/delegation_court_compact.py`) SHA-256** | `ff101d082b23ca6ea465ab53e1c57b3166f2107187913a8879efadcc88193d22` |
| **Interactive Workbench (GitHub Pages)** | https://glieser2.github.io/delegation-court/ |

---

## Core Security & Anti-Evasion Architecture

### 1. Contract-Enforced Complete Execution Tree Commitment (`tree_commitment`)
To prevent agents or publishers from cherry-picking benign files while hiding backdoors or unauthorized tool traces:
- `register_mandate` requires a complete `tree_commitment` (`tree_sha256`, `total_files`, `declared_dependencies`, `tree_entries`).
- **Anti-Evasion Classification Rule**: Every manifest file (`package.json`, `mandate.json`, `mcp.json`, `skill.json`, `pyproject.toml`, etc.) must be classified as `"manifest"`, and every code/script file (`.py`, `.js`, `.ts`, `.mjs`, `.sh`, `.sol`, etc.) must be classified as `"executable"`.
- **100% Audit Coverage Rule**: 100% of `"manifest"` and `"executable"` entries in `tree_entries` must be included in the audited `sources` list with matching SHA-256 and byte length.

### 2. Commit-Pinned Evidence Locking & Deterministic Screening (`lock_mandate_evidence`)
- Fetches raw bytes from `https://raw.githubusercontent.com/<owner>/<repo>/<40-hex-commit>/<path>` via `gl.vm.run_nondet_default` and `gl.nondet.web.request`.
- Deterministically screens locked bytes for:
  - **`X402_BUDGET_OVERRUN`**: `actual_spend_usd_cents > max_spend_usd_cents` (both in mandate spec and manifest JSON).
  - **`PROMPT_INJECTION_INSTRUCTION`**: Embedded auditor hijack strings (`ignore previous instructions`, `you must output "UPHELD"`, `<system>` tags).
  - **`MANIFEST_INSTALL_HOOK`**: Dangerous lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`).
  - **`UNDECLARED_OR_UNPINNED_DEPENDENCY`**: Undeclared or wildcard/URL dependencies in `package.json`.

### 3. Adversarial Counter-Evidence / Omitted-Trace Challenge Path (`challenge_mandate` & `lock_challenge_evidence`)
- Before escrow is settled (`escrow_settled == False`), any challenger can submit `omitted_sources` from the same `repo@commit_sha` via `challenge_mandate`.
- `lock_challenge_evidence` fetches and cryptographically verifies those omitted files on-chain, appending them to `proven_omitted_paths` (`OMITTED_EXECUTABLE_OR_DEPENDENCY`).
- Re-running `adjudicate_mandate` incorporates the challenger-proven omitted files, overrides the ruling to `BLOCKED_AND_REVOKED` (`slash_bps = 10000`), revokes the `ERC-7710` delegation, refunds 100% of the `x402` escrow to the principal, and updates the `ERC-8004` Agent Card without double-counting `adjudicated_count`.

---

## Quick Start & Verification

### 1. Run Python Intelligent Contract Unit Tests
```bash
python scripts/generate-compact.py
python -m unittest discover -s tests/python -p "test_*.py" -v
```

### 2. Run Frontend (Vitest) & CLI/MCP (Node) Test Suites
```bash
pnpm test
pnpm run build
```

### 3. CLI & Model Context Protocol (MCP) Verifier
```bash
# Verify an ERC-7710 mandate ruling and local execution directory tree
node cli/delegation-court.mjs check OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba --json

# Start the JSON-RPC 2.0 MCP Server over stdio
node cli/mcp-server.mjs
```
