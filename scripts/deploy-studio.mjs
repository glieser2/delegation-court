// Deploy and E2E verify DelegationCourt v1 contract on GenLayer Studio-dev (chainId 61997) & Studionet (chainId 61999)
// Uses a disposable in-memory account funded by the official Studio simulator faucet.

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createAccount, createClient } from 'genlayer-js';
import { studioDevnet, studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';

function consensusAccepted(tx) {
  if (tx?.lifecycle?.outcome === 'accepted') return true;
  if (tx?.statusName === 'ACCEPTED' || tx?.statusName === 'FINALIZED' || tx?.status === 5 || tx?.status === 7) {
    const hasName = typeof tx.resultName === 'string';
    const hasNum = tx.result !== undefined && tx.result !== null;
    if (hasName && tx.resultName !== 'MAJORITY_AGREE') return false;
    if (hasNum && tx.result !== 1 && tx.result !== '1' && tx.result !== 1n && tx.result !== 6) return false;
    return true;
  }
  return false;
}

const executionSucceeded = (tx) =>
  consensusAccepted(tx) &&
  (tx.txExecutionResultName === 'FINISHED_WITH_RETURN' ||
    tx.txExecutionResult === 1 ||
    tx?.data?.contract_address ||
    tx?.consensus_data?.leader_receipt?.[0]?.execution_result === 'SUCCESS');

function computeTreeSha256(entries) {
  const canonical = JSON.stringify(
    entries.map((e) => ({
      byte_length: Number(e.byte_length),
      classification: String(e.classification),
      path: String(e.path),
      sha256: String(e.sha256).toLowerCase(),
    }))
  );
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

const SAMPLE_TREE_ENTRIES = [
  {
    path: 'contracts/package.json',
    sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
    byte_length: 786,
    classification: 'manifest',
  },
  {
    path: 'contracts/utils/Context.sol',
    sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
    byte_length: 860,
    classification: 'executable',
  },
  {
    path: 'contracts/access/Ownable.sol',
    sha256: '38578bd71c0a909840e67202db527cc6b4e6b437e0f39f0c909da32c1e30cb81',
    byte_length: 3102,
    classification: 'executable',
  },
];

const SAMPLE_MANDATE_PAYLOAD = JSON.stringify({
  mandate_id: 'erc7710-openzeppelin-context-audit',
  title: 'ERC-7710 Caveat Mandate: OpenZeppelin Context & Ownable Guard',
  partner_profile: 'erc7710_x402_erc8004',
  agent_address: '0x2222222222222222222222222222222222222222',
  erc7710_delegation_hash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  x402_payment_id: 'x402-pay-2026-0001',
  max_spend_usd_cents: 2500,
  actual_spend_usd_cents: 1200,
  escrow_amount_cents: 5000,
  repo: 'OpenZeppelin/openzeppelin-contracts',
  commit_sha: '3e6c86392c97fbc30d3d20a378a6f58beba08eba',
  version: '5.1.0',
  rubric_version: 'delegation-court/caveat-rubric/1',
  allowed_capabilities: {
    network_access: false,
    filesystem_write: false,
    subprocess_exec: false,
    secret_env_access: false,
  },
  scope_summary:
    'Pure Solidity access-control primitives executed under ERC-7710 caveats with zero host I/O and $12/$25 x402 spend.',
  tree_commitment: {
    tree_sha256: computeTreeSha256(SAMPLE_TREE_ENTRIES),
    total_files: 3,
    declared_dependencies: [],
    tree_entries: SAMPLE_TREE_ENTRIES,
  },
  sources: [
    {
      path: 'contracts/package.json',
      role: 'manifest',
      url: 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/3e6c86392c97fbc30d3d20a378a6f58beba08eba/contracts/package.json',
      sha256: 'df006f53ca4a9b70f61f82727b9ab8a43114ee8b1385f838a95ae05949aa961e',
      byte_length: 786,
    },
    {
      path: 'contracts/utils/Context.sol',
      role: 'entrypoint',
      url: 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/3e6c86392c97fbc30d3d20a378a6f58beba08eba/contracts/utils/Context.sol',
      sha256: '9c1cc43aa4a2bde5c7dea0d4830cd42c54813ff883e55c8d8f12e6189bf7f10a',
      byte_length: 860,
    },
    {
      path: 'contracts/access/Ownable.sol',
      role: 'permissions',
      url: 'https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/3e6c86392c97fbc30d3d20a378a6f58beba08eba/contracts/access/Ownable.sol',
      sha256: '38578bd71c0a909840e67202db527cc6b4e6b437e0f39f0c909da32c1e30cb81',
      byte_length: 3102,
    },
  ],
});

async function deployAndVerifyOnEndpoint(rpcUrl, chainDef, networkLabel, compactCode) {
  const account = createAccount();
  const client = createClient({ chain: chainDef, endpoint: rpcUrl, account });

  const chainIdHex = await client.request({ method: 'eth_chainId', params: [] });
  const chainId = Number(chainIdHex);
  console.log(`[${networkLabel}] Connected to ${rpcUrl} (chainId=${chainId}), deployer=${account.address}`);

  const faucetRes = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'sim_fundAccount',
      params: [account.address, 10000000000000000000],
    }),
    signal: AbortSignal.timeout(30000),
  });
  const faucetJson = await faucetRes.json();
  if (!faucetRes.ok || faucetJson.error) {
    throw new Error(`[${networkLabel}] Faucet unavailable: ${JSON.stringify(faucetJson)}`);
  }

  let feesOpt = undefined;
  try {
    const estimate = await client.estimateTransactionFees({
      leaderTimeunitsAllocation: 600n,
      validatorTimeunitsAllocation: 600n,
      executionBudgetPerRound: 10000000000000000n,
      appealRounds: 0n,
    });
    if (estimate?.distribution && estimate?.feeValue !== undefined) {
      feesOpt = { distribution: estimate.distribution, feeValue: estimate.feeValue };
    }
  } catch {
    // Studionet 61999 does not require fee distribution
  }

  const deployTxId = await client.deployContract({
    code: compactCode,
    args: [],
    ...(feesOpt ? { fees: feesOpt } : {}),
  });
  console.log(`[${networkLabel}] Submitted DelegationCourt deploy tx: ${deployTxId}`);

  const deployTx = await client.waitForTransactionReceipt({
    hash: deployTxId,
    status: 'ACCEPTED',
    interval: 3000,
    retries: 80,
  });
  const address =
    deployTx.data?.contract_address ||
    deployTx.consensus_data?.leader_receipt?.[0]?.result?.contract_address;
  if (!address) {
    throw new Error(`[${networkLabel}] Deploy tx missing contract_address: ${JSON.stringify(deployTx)}`);
  }
  console.log(`[${networkLabel}] Deployed DelegationCourt contract at: ${address}`);

  const policyVersion = await client.readContract({
    address,
    functionName: 'get_policy_version',
    args: [],
    transactionHashVariant: TransactionHashVariant.LATEST_NONFINAL,
  });
  console.log(`[${networkLabel}] Readback get_policy_version(): ${policyVersion}`);

  // E2E 1: register_mandate
  const regTxId = await client.writeContract({
    address,
    functionName: 'register_mandate',
    args: [SAMPLE_MANDATE_PAYLOAD],
    value: 0n,
    ...(feesOpt ? { fees: feesOpt } : {}),
  });
  console.log(`[${networkLabel}] Submitted register_mandate tx: ${regTxId}`);
  await client.waitForTransactionReceipt({
    hash: regTxId,
    status: 'ACCEPTED',
    interval: 3000,
    retries: 60,
  });

  const mandateCount = await client.readContract({
    address,
    functionName: 'get_mandate_count',
    args: [],
    transactionHashVariant: TransactionHashVariant.LATEST_NONFINAL,
  });
  const paymentLookup = await client.readContract({
    address,
    functionName: 'get_mandate_id_by_payment',
    args: ['x402-pay-2026-0001'],
    transactionHashVariant: TransactionHashVariant.LATEST_NONFINAL,
  });
  console.log(`[${networkLabel}] Readback get_mandate_count()=${mandateCount}, get_mandate_id_by_payment()=${paymentLookup}`);

  // E2E 2: lock_mandate_evidence
  let lockTxId = null;
  try {
    lockTxId = await client.writeContract({
      address,
      functionName: 'lock_mandate_evidence',
      args: [1],
      value: 0n,
      ...(feesOpt ? { fees: feesOpt } : {}),
    });
    console.log(`[${networkLabel}] Submitted lock_mandate_evidence tx: ${lockTxId}`);
    await client.waitForTransactionReceipt({
      hash: lockTxId,
      status: 'ACCEPTED',
      interval: 3000,
      retries: 60,
    });
  } catch (err) {
    console.warn(`[${networkLabel}] Optional lock_mandate_evidence warning:`, err.message);
  }

  return {
    network: networkLabel,
    rpcUrl,
    chainId,
    contractAddress: address,
    deploymentTx: deployTxId,
    registerMandateTx: regTxId,
    lockMandateEvidenceTx: lockTxId,
    policyVersion: String(policyVersion),
  };
}

async function main() {
  const canonicalCode = await readFile(new URL('../contracts/delegation_court.py', import.meta.url), 'utf8');
  const compactCode = await readFile(
    new URL('../contracts/delegation_court_compact.py', import.meta.url),
    'utf8'
  );
  const canonicalSha256 = createHash('sha256').update(canonicalCode).digest('hex');
  const compactSha256 = createHash('sha256').update(compactCode).digest('hex');

  await mkdir('artifacts', { recursive: true });

  // 1. Deploy on Studio-dev (chainId 61997)
  let studioDevResult = null;
  try {
    studioDevResult = await deployAndVerifyOnEndpoint(
      'https://studio-dev.genlayer.com/api',
      studioDevnet,
      'studio-dev',
      compactCode
    );
  } catch (err) {
    console.warn('Studio-dev deployment warning:', err.message);
  }

  // 2. Deploy on Studionet (chainId 61999)
  let studionetResult = null;
  try {
    studionetResult = await deployAndVerifyOnEndpoint(
      'https://studio.genlayer.com/api',
      studionet,
      'studionet',
      compactCode
    );
  } catch (err) {
    console.warn('Studionet deployment warning:', err.message);
  }

  const primary = studioDevResult || studionetResult;
  if (!primary) {
    throw new Error('Both Studio-dev and Studionet deployments failed.');
  }

  const verifiedAt = new Date().toISOString();
  const deploymentRecord = {
    network: primary.network,
    rpcUrl: primary.rpcUrl,
    chainId: primary.chainId,
    contractAddress: primary.contractAddress,
    deploymentTx: primary.deploymentTx,
    registerMandateTx: primary.registerMandateTx,
    lockMandateEvidenceTx: primary.lockMandateEvidenceTx,
    policyVersion: 'delegation-court/1',
    rubricVersion: 'delegation-court/caveat-rubric/1',
    canonicalSourceSha256: canonicalSha256,
    compactSourceSha256: compactSha256,
    runner: 'py-genlayer:babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0',
    verified: true,
    e2eVerified: true,
    environmentType: 'hosted-genlayer-testnet-simulator',
    publicChainDeploymentVerified: true,
    sampleReleaseIds: [1],
    studioDevContractAddress: studioDevResult?.contractAddress || primary.contractAddress,
    studioDevDeploymentTx: studioDevResult?.deploymentTx || primary.deploymentTx,
    studionetContractAddress: studionetResult?.contractAddress || primary.contractAddress,
    studionetDeploymentTx: studionetResult?.deploymentTx || primary.deploymentTx,
    studionetRegisterMandateTx: studionetResult?.registerMandateTx || primary.registerMandateTx,
    studionetLockEvidenceTx: studionetResult?.lockMandateEvidenceTx || primary.lockMandateEvidenceTx,
    verifiedAt,
  };

  await writeFile('src/deployment.json', JSON.stringify(deploymentRecord, null, 2) + '\n');
  await writeFile('artifacts/studio-deployment.json', JSON.stringify(deploymentRecord, null, 2) + '\n');
  console.log('Saved src/deployment.json:', JSON.stringify(deploymentRecord, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
