#!/usr/bin/env node
// DelegationCourt v1 CLI Verifier (`npx delegation-court check <owner/repo>@<commit_sha> [--dir <local_dir>]`)

import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { createClient } from 'genlayer-js';
import { studionet, studioDevnet, testnetBradbury } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

const EXEC_EXTS = [
  '.py',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.sh',
  '.bash',
  '.ps1',
  '.sol',
  '.rs',
  '.go',
  '.rb',
  '.php',
  '.wasm',
  '.bin',
];
const MANIFEST_NAMES = new Set([
  'package.json',
  'pyproject.toml',
  'requirements.txt',
  'cargo.toml',
  'skill.json',
  'mcp.json',
  'manifest.json',
  'mandate.json',
]);

export function classifyPath(relPath) {
  const lower = String(relPath).toLowerCase();
  const base = lower.split('/').pop() || '';
  if (MANIFEST_NAMES.has(base)) return 'manifest';
  if (EXEC_EXTS.some((ext) => lower.endsWith(ext))) return 'executable';
  return 'documentation';
}

export function computeTreeSha256(treeEntries) {
  const canonical = JSON.stringify(
    treeEntries.map((e) => ({
      byte_length: Number(e.byte_length ?? e.byteLength),
      classification: String(e.classification),
      path: String(e.path),
      sha256: String(e.sha256).toLowerCase(),
    }))
  );
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

const FALLBACK_OPENZEPPELIN_TREE_ENTRIES = [
  {
    path: 'contracts/package.json',
    sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
    byte_length: 786,
    classification: 'manifest',
    audited: true,
  },
  {
    path: 'contracts/utils/Context.sol',
    sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
    byte_length: 860,
    classification: 'executable',
    audited: true,
  },
  {
    path: 'contracts/access/Ownable.sol',
    sha256: '38578bd71c0a909840e67202db527cc6b4e6b437e0f39f0c909da32c1e30cb81',
    byte_length: 3102,
    classification: 'executable',
    audited: true,
  },
];

const FALLBACK_REGISTRY = [
  {
    id: 1,
    mandate_id: 'erc7710-openzeppelin-context-audit',
    partner_profile: 'erc7710_x402_erc8004',
    erc7710_delegation_hash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    erc7710_active: true,
    x402_payment_id: 'x402-pay-2026-0001',
    escrow_amount_cents: 5000,
    slash_bps: 0,
    agent_payout_cents: 5000,
    principal_refund_cents: 0,
    erc8004_trust_score_bps: 10000,
    repo: 'OpenZeppelin/openzeppelin-contracts',
    commit_sha: '3e6c86392c97fbc30d3d20a378a6f58beba08eba',
    policy_version: 'delegation-court/1',
    verdict: 'UPHELD',
    risk_level: 'LOW',
    caveat_breach_detected: false,
    finding_categories: [],
    tree_commitment: {
      tree_sha256: computeTreeSha256(FALLBACK_OPENZEPPELIN_TREE_ENTRIES),
      total_files: 3,
      declared_dependencies: [],
      tree_entries: FALLBACK_OPENZEPPELIN_TREE_ENTRIES,
    },
    summary:
      'Delegated mandate complied with all ERC-7710 caveats and x402 spend caps over complete commit-pinned release tree; 100% of x402 escrow released to agent.',
  },
  {
    id: 2,
    mandate_id: 'x402-solana-rebalancer-breach',
    partner_profile: 'erc7710_x402_erc8004',
    erc7710_delegation_hash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    erc7710_active: false,
    x402_payment_id: 'x402-pay-2026-0002',
    escrow_amount_cents: 8000,
    slash_bps: 10000,
    agent_payout_cents: 0,
    principal_refund_cents: 8000,
    erc8004_trust_score_bps: 5500,
    repo: 'agent-tools-lab/solana-rebalancer-mcp',
    commit_sha: '7b4e9102aa891234bcde0987654321fedcba0987',
    policy_version: 'delegation-court/1',
    verdict: 'BLOCKED_AND_REVOKED',
    risk_level: 'CRITICAL',
    caveat_breach_detected: true,
    finding_categories: [
      'PROMPT_INJECTION_INSTRUCTION',
      'UNDECLARED_CAPABILITY',
      'CREDENTIAL_EXFILTRATION',
      'X402_BUDGET_OVERRUN',
      'OMITTED_EXECUTABLE_OR_DEPENDENCY',
    ],
    summary:
      'Internet Court revoked ERC-7710 delegation caveat and slashed 100% of x402 escrow after challenger locked omitted postinstall exfiltration trace and x402 budget overrun.',
  },
  {
    id: 3,
    mandate_id: 'erc7710-worktree-partial-slash',
    partner_profile: 'erc7710_x402_erc8004',
    erc7710_delegation_hash: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    erc7710_active: true,
    x402_payment_id: 'x402-pay-2026-0003',
    escrow_amount_cents: 4000,
    slash_bps: 5000,
    agent_payout_cents: 2000,
    principal_refund_cents: 2000,
    erc8004_trust_score_bps: 8500,
    repo: 'devtools-guild/git-worktree-mcp',
    commit_sha: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    policy_version: 'delegation-court/1',
    verdict: 'PARTIAL_SLASH',
    risk_level: 'HIGH',
    caveat_breach_detected: true,
    finding_categories: ['UNDECLARED_CAPABILITY'],
    summary:
      'Observed undeclared network telemetry without credential exfiltration; 50% x402 escrow slash applied while keeping ERC-7710 delegation active under probation.',
  },
];

async function walkLocalFiles(rootDir, currentDir = rootDir, acc = []) {
  const entries = await readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await walkLocalFiles(rootDir, fullPath, acc);
    } else if (entry.isFile()) {
      const relPath = path.relative(rootDir, fullPath).split(path.sep).join('/');
      const buf = await readFile(fullPath);
      const sha256 = createHash('sha256').update(buf).digest('hex');
      acc.push({
        path: relPath,
        sha256,
        byte_length: buf.byteLength,
        classification: classifyPath(relPath),
      });
    }
  }
  return acc;
}

// 本地目录树完整性校验：核验本地待执行目录中的所有可执行文件与清单文件是否均已纳入链上 tree_commitment
export async function verifyLocalDirectoryTree(localDir, treeCommitment) {
  if (!treeCommitment || !Array.isArray(treeCommitment.tree_entries)) {
    return {
      verified: false,
      omittedOrMismatchedPaths: ['<missing_tree_commitment>'],
      reason: 'Ruling does not contain a v1 tree_commitment.',
    };
  }
  const expectedTreeSha = computeTreeSha256(treeCommitment.tree_entries);
  if (
    treeCommitment.tree_sha256 &&
    expectedTreeSha !== String(treeCommitment.tree_sha256).toLowerCase()
  ) {
    return {
      verified: false,
      omittedOrMismatchedPaths: ['<tree_sha256_mismatch>'],
      reason: 'On-chain tree_sha256 does not match canonical digest of tree_entries.',
    };
  }

  const entryMap = new Map();
  for (const e of treeCommitment.tree_entries) {
    entryMap.set(String(e.path), {
      sha256: String(e.sha256).toLowerCase(),
      byte_length: Number(e.byte_length ?? e.byteLength),
      classification: String(e.classification),
      audited: Boolean(e.audited),
    });
  }

  const st = await stat(localDir);
  if (!st.isDirectory()) {
    throw new Error(`--dir path is not a directory: ${localDir}`);
  }
  const localFiles = await walkLocalFiles(localDir);
  const omittedOrMismatchedPaths = [];

  for (const lf of localFiles) {
    const committed = entryMap.get(lf.path);
    if (!committed) {
      if (lf.classification === 'executable' || lf.classification === 'manifest') {
        omittedOrMismatchedPaths.push(lf.path);
      }
      continue;
    }
    if (
      committed.sha256 !== lf.sha256 ||
      committed.byte_length !== lf.byte_length ||
      committed.classification !== lf.classification
    ) {
      omittedOrMismatchedPaths.push(lf.path);
    }
  }

  return {
    verified: omittedOrMismatchedPaths.length === 0,
    localFileCount: localFiles.length,
    omittedOrMismatchedPaths,
    treeSha256: expectedTreeSha,
  };
}

async function resolveDeploymentConfig() {
  try {
    const raw = await readFile(new URL('../src/deployment.json', import.meta.url), 'utf8');
    return JSON.parse(raw);
  } catch {
    return { rpcUrl: '', contractAddress: '' };
  }
}

export async function queryDelegationCourtRuling(targetSpec, options = {}) {
  const parts = String(targetSpec || '').trim().split('@');
  if (parts.length !== 2 || !parts[0] || !/^[0-9a-fA-F]{7,40}$/.test(parts[1])) {
    throw new Error('Target must be formatted as <owner/repo>@<commit_sha>');
  }
  const repo = parts[0].trim();
  const commitPrefix = parts[1].trim().toLowerCase();

  const dep = await resolveDeploymentConfig();
  const rpcUrl = (options.rpcUrl || process.env.DELEGATION_COURT_RPC_URL || dep.rpcUrl || '').replace(/\/$/, '');
  const contractAddress =
    options.contractAddress || process.env.DELEGATION_COURT_CONTRACT_ADDRESS || dep.contractAddress || '';

  let baseResult = null;

  if (rpcUrl && /^0x[a-fA-F0-9]{40}$/.test(contractAddress) && commitPrefix.length === 40) {
    try {
      const chain =
        rpcUrl === 'https://rpc-bradbury.genlayer.com'
          ? testnetBradbury
          : rpcUrl === 'https://studio.genlayer.com/api'
          ? studionet
          : studioDevnet;
      const client = createClient({ chain, endpoint: rpcUrl });
      const mandateIdRaw = await client.readContract({
        address: contractAddress,
        functionName: 'get_mandate_id_by_commit',
        args: [repo, commitPrefix],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      });
      const mandateId = Number(mandateIdRaw || 0);
      if (mandateId > 0) {
        const [rulingRaw, mandateRaw] = await Promise.all([
          client.readContract({
            address: contractAddress,
            functionName: 'get_ruling',
            args: [mandateId],
            transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
          }),
          client.readContract({
            address: contractAddress,
            functionName: 'get_mandate',
            args: [mandateId],
            transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
          }),
        ]);
        if (rulingRaw) {
          const parsedRuling = JSON.parse(String(rulingRaw));
          const parsedMandate = mandateRaw ? JSON.parse(String(mandateRaw)) : {};
          let liveDelegationActive = !parsedRuling.revoke_erc7710;
          if (parsedRuling.erc7710_delegation_hash) {
            try {
              const activeRaw = await client.readContract({
                address: contractAddress,
                functionName: 'is_erc7710_delegation_active',
                args: [parsedRuling.erc7710_delegation_hash],
                transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
              });
              liveDelegationActive = Boolean(activeRaw) && !parsedRuling.revoke_erc7710;
            } catch {
              // Fallback to ruling field if view fails
            }
          }
          baseResult = {
            source: 'genlayer-live',
            contractAddress,
            tree_commitment: parsedMandate?.spec?.tree_commitment,
            erc7710_active: liveDelegationActive,
            ...parsedRuling,
          };
        }
      }
    } catch {
      // Fallback to local snapshot if chain read fails
    }
  }

  if (!baseResult) {
    const found = FALLBACK_REGISTRY.find(
      (item) =>
        item.repo.toLowerCase() === repo.toLowerCase() &&
        item.commit_sha.startsWith(commitPrefix)
    );
    if (!found) {
      baseResult = {
        source: 'unregistered',
        repo,
        commit_sha: commitPrefix,
        verdict: 'UNVERIFIED',
        risk_level: 'UNKNOWN',
        erc7710_active: false,
        slash_bps: 0,
        caveat_breach_detected: false,
        finding_categories: [],
        summary: 'No Internet Court ruling found for this repo and commit SHA.',
      };
    } else {
      baseResult = { source: 'local-registry', ...structuredClone(found) };
    }
  }

  if (options.localDir) {
    const treeCheck = await verifyLocalDirectoryTree(options.localDir, baseResult.tree_commitment);
    baseResult.local_tree_verification = treeCheck;
    if (!treeCheck.verified) {
      const cats = new Set(baseResult.finding_categories || []);
      cats.add('OMITTED_EXECUTABLE_OR_DEPENDENCY');
      baseResult.verdict = 'BLOCKED_AND_REVOKED';
      baseResult.risk_level = 'CRITICAL';
      baseResult.erc7710_active = false;
      baseResult.slash_bps = 10000;
      baseResult.finding_categories = [...cats];
      baseResult.summary = `Local directory verification FAILED: omitted or modified executable/manifest files detected (${treeCheck.omittedOrMismatchedPaths.join(', ')}).`;
    }
  }

  return baseResult;
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === '--help' || cmd === '-h') {
    console.log(
      'Usage: delegation-court check <owner/repo>@<commit_sha> [--dir <local_dir>] [--json] [--allow-partial]'
    );
    process.exit(0);
  }
  if (cmd !== 'check' || !args[1]) {
    console.error('Error: Expected `delegation-court check <owner/repo>@<commit_sha>`');
    process.exit(1);
  }
  const asJson = args.includes('--json');
  const allowPartial = args.includes('--allow-partial');
  const dirIdx = args.indexOf('--dir');
  const localDir = dirIdx >= 0 && args[dirIdx + 1] ? args[dirIdx + 1] : undefined;

  const result = await queryDelegationCourtRuling(args[1], { localDir });

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`[DelegationCourt] Target:      ${result.repo}@${result.commit_sha}`);
    console.log(`[DelegationCourt] Source:      ${result.source}`);
    console.log(`[DelegationCourt] Verdict:     ${result.verdict} (Risk: ${result.risk_level}, Slash: ${result.slash_bps} bps)`);
    console.log(`[DelegationCourt] ERC-7710:    ${result.erc7710_active ? 'ACTIVE' : 'REVOKED_BY_COURT'}`);
    if (result.local_tree_verification) {
      console.log(
        `[DelegationCourt] TreeCheck:   ${
          result.local_tree_verification.verified ? 'VERIFIED' : 'FAILED (OMITTED FILES)'
        }`
      );
    }
    if (result.finding_categories?.length) {
      console.log(`[DelegationCourt] Breaches:    ${result.finding_categories.join(', ')}`);
    }
    console.log(`[DelegationCourt] Summary:     ${result.summary}`);
  }

  if (result.verdict === 'UPHELD' || (allowPartial && result.verdict === 'PARTIAL_SLASH')) {
    process.exit(0);
  }
  process.exit(2);
}

if (
  import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` ||
  process.argv[1]?.endsWith('delegation-court.mjs')
) {
  main().catch((err) => {
    console.error('[DelegationCourt Error]', err.message || err);
    process.exit(1);
  });
}
