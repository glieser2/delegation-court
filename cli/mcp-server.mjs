#!/usr/bin/env node
// DelegationCourt MCP Server (JSON-RPC 2.0 over stdio for ERC-7710 Smart Accounts, x402 Gateways & AI Agents)

import readline from 'node:readline';
import { queryDelegationCourtRuling } from './delegation-court.mjs';

const SERVER_INFO = {
  name: 'delegation-court-mcp',
  version: '1.0.0',
};

const TOOLS = [
  {
    name: 'delegation_court_check_ruling',
    description:
      'Query GenLayer DelegationCourt on-chain Internet Court ruling for an ERC-7710 delegated mandate and x402 escrow (<owner/repo>@<commit_sha>), and optionally verify a local directory tree against the contract-enforced tree_commitment before releasing x402 funds or executing delegated actions.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Repository and commit SHA in the format owner/repo@commit_sha',
        },
        local_dir: {
          type: 'string',
          description:
            'Optional local directory path to verify against the on-chain tree_commitment (revokes ERC-7710 caveat if any local executable or manifest file is omitted)',
        },
      },
      required: ['target'],
    },
  },
];

export async function handleJsonRpcMessage(msg) {
  if (!msg || typeof msg !== 'object') return null;
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      },
    };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: { tools: TOOLS },
    };
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    if (toolName === 'delegation_court_check_ruling') {
      try {
        const res = await queryDelegationCourtRuling(toolArgs.target, {
          localDir: toolArgs.local_dir,
        });
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
            isError: res.verdict === 'BLOCKED_AND_REVOKED',
          },
        };
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: String(err.message || err) }],
            isError: true,
          },
        };
      }
    }
    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` },
    };
  }

  if (id !== undefined) {
    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    };
  }
  return null;
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('mcp-server.mjs')) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const parsed = JSON.parse(trimmed);
      const response = await handleJsonRpcMessage(parsed);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    } catch {
      // ignore malformed line
    }
  });
}
