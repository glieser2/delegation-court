# Security Architecture & Threat Model — DelegationCourt (`delegation-court/1`)

## 1. Threat Model & Invariants
1. **Unforgeable Principal & Agent Attribution**:
   - `register_mandate` binds `principal_address = str(gl.message.sender_address).lower()` and requires `agent_address != principal_address`.
   - `erc7710_delegation_hash` ownership is pinned on first registration: another principal or agent cannot hijack an existing delegation hash, nor can any mandate be registered under a `REVOKED_BY_COURT` delegation hash.
2. **Complete Execution Tree Commitment (`tree_commitment`)**:
   - Every manifest file (`package.json`, `mandate.json`, `mcp.json`, `skill.json`, etc.) must be classified as `"manifest"`, and every code file (`.py`, `.js`, `.ts`, `.sh`, `.sol`, etc.) as `"executable"`.
   - 100% of `"manifest"` and `"executable"` entries in `tree_entries` must be included in `sources`.
3. **Adversarial Omitted-Trace Challenge & One-Shot Escrow Settlement**:
   - Escrow funds remain locked until `settle_escrow(mandate_id)` is called by the principal or agent after adjudication when no challenge is pending.
   - If challenged prior to escrow settlement via `challenge_mandate` + `lock_challenge_evidence`, Round 2 `adjudicate_mandate` re-computes the verdict over the expanded evidence snapshot and updates `erc8004_agent_cards` by scanning current mandate rulings (eliminating double-counting across rounds).
