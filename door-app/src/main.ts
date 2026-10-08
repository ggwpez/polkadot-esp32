import { createChainClient } from '@parity/product-sdk/chain';
import { requestPermission } from '@parity/product-sdk/host';
import { WalletSession } from './wallet';
import { createContract, createContractRuntimeFromClient, ensureContractAccountMapped, type Contract } from '@parity/product-sdk/contracts';
import { devnet_asset_hub } from '@parity/product-sdk-descriptors/devnet-asset-hub';
import { deployment, abi } from './contract';
import './style.css';

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
declare const __APP_VERSION__: string;
el('app-version').textContent = `v${__APP_VERSION__}`;
el('contract-address').textContent = `Contract ${deployment.address}`;
const walletAddress = el<HTMLInputElement>('wallet-address');
const copyAddress = el<HTMLButtonElement>('copy-address');
const connectWalletButton = el<HTMLButtonElement>('connect-wallet');
const apply = el<HTMLButtonElement>('apply');
const retry = el<HTMLButtonElement>('retry');
const choices = [...document.querySelectorAll<HTMLButtonElement>('.key-choice')];
const labels = ['No keys enabled', 'Alice’s key', 'Bob’s key', 'Both keys'] as const;
type Key = 0 | 1 | 2 | 3;
type DoorContract = { methods: {
  enabledKeys: { args: []; response: number };
  revision: { args: []; response: number };
  assignKey: { args: [number]; response: void };
} };
const wallet = new WalletSession(state => {
  const account = state.selectedAccount;
  walletAddress.value = account?.address ?? '';
  copyAddress.disabled = !account;
  connectWalletButton.hidden = Boolean(account);
  if (account) el('wallet-status').textContent = 'This is the wallet account used by Door Keys.';
});
async function connectWallet() {
  connectWalletButton.disabled = true;
  el('wallet-status').textContent = 'Connecting your wallet…';
  try {
    const account = await wallet.connect();
    el('wallet-status').textContent = 'This is the wallet account used by Door Keys.';
    return account;
  } catch (error) {
    walletAddress.value = '';
    copyAddress.disabled = true;
    el('wallet-status').textContent = error instanceof Error ? error.message : String(error);
    connectWalletButton.hidden = false;
    throw error;
  } finally { connectWalletButton.disabled = false; }
}
connectWalletButton.addEventListener('click', () => { void connectWallet().catch(() => {}); });
copyAddress.addEventListener('click', async () => {
  const address = walletAddress.value;
  if (!address) return;
  try {
    await navigator.clipboard.writeText(address);
    el('wallet-status').textContent = 'Address copied.';
  } catch {
    walletAddress.focus(); walletAddress.select();
    el('wallet-status').textContent = 'Select and copy the address above.';
  }
});
let busy = false;
let current: Key | null = null;
let selected: Key | null = null;
let polling: ReturnType<typeof setTimeout>;

async function connectChain() {
  if (/^0x0{40}$/.test(deployment.address)) {
    throw Error('Deploy your own contract and run npm run sync-contract before connecting.');
  }
  const client = await createChainClient({ chains: { assetHub: devnet_asset_hub } });
  if ((await client.raw.assetHub.getChainSpecData()).genesisHash !== deployment.genesis) {
    client.destroy(); throw Error('This app requires Products devnet.');
  }
  const runtime = createContractRuntimeFromClient(client.raw.assetHub, devnet_asset_hub);
  const contract = createContract(runtime, deployment.address, abi) as Contract<DoorContract>;
  return { client, runtime, contract };
}
let chain: Awaited<ReturnType<typeof connectChain>> | undefined;

function render() {
  el('state').textContent = current === null ? 'Assignment unavailable' : labels[current];
  el('stage').dataset.state = current === null ? 'unknown' : 'assigned';
  document.body.dataset.assigned = String(current !== null && current !== 0);
  for (const choice of choices) {
    const key = Number(choice.dataset.key);
    const enabled = selected !== null && (selected & (1 << key)) !== 0;
    choice.setAttribute('aria-pressed', String(enabled));
    choice.disabled = busy || current === null;
    el(`hint-${key}`).textContent = selected === null ? 'Unavailable' : enabled ? 'Enabled' : 'Disabled';
  }
  apply.disabled = busy || current === null || selected === null || selected === current;
  apply.textContent = busy && selected !== null ? 'Applying…' : 'Apply';
}
function status(text: string) { el('status').textContent = text; }
function failure(error: unknown) {
  status(error instanceof Error ? error.message : String(error));
  retry.hidden = false;
}
async function refresh(resetSelection = false) {
  if (!chain) throw Error('Open this app inside the Polkadot app or the dev-dot.li gateway.');
  const block = await chain.client.raw.assetHub.getFinalizedBlock();
  const [assignment, revision] = await Promise.all([
    chain.contract.enabledKeys.query({ at: block.hash }),
    chain.contract.revision.query({ at: block.hash }),
  ]);
  if (!assignment.success || (assignment.value !== 0 && assignment.value !== 1 && assignment.value !== 2 && assignment.value !== 3) || !revision.success)
    throw Error('Could not read the key assignment. Please reconnect.');
  if (resetSelection || selected === null || selected === current) selected = assignment.value;
  current = assignment.value;
  render();
  el('details').textContent = `Revision ${revision.value} · finalized block ${block.number}`;
}
async function poll() {
  try { if (!busy) await refresh(); }
  catch (error) { current = null; render(); if (!busy) failure(error); }
  polling = setTimeout(poll, 4000);
}
async function start() {
  if (busy) return;
  clearTimeout(polling);
  retry.hidden = true;
  busy = true;
  current = null;
  render();
  status('Connecting to Products devnet…');
  try {
    chain ??= await connectChain();
    await refresh();
    status('Select the enabled keys, then click Apply.');
  } catch (error) { failure(error); }
  finally {
    busy = false;
    render();
    polling = setTimeout(poll, 4000);
  }
}
retry.addEventListener('click', start);
for (const choice of choices) choice.addEventListener('click', () => {
  if (busy || current === null || selected === null) return;
  selected = (selected ^ (1 << Number(choice.dataset.key))) as Key;
  render();
  status(selected === current ? 'No changes to apply.' : 'Selection changed. Click Apply to save.');
});
apply.addEventListener('click', async () => {
  if (busy || !chain || current === null || selected === null || selected === current) return;
  const target = selected;
  // The contract uses Alice=0, Bob=1, Both=2, None=3.
  const assignment = [3, 0, 1, 2][target];
  busy = true;
  render();
  retry.hidden = true;
  let step = 'Connecting your wallet';
  let acceptingSignature = true;
  const progress = (message: string) => { step = message; status(`${message}…`); };
  try {
    progress('Connecting your wallet');
    const account = await connectWallet();
    const walletSigner = wallet.getSigner();
    if (!walletSigner) throw Error('Your wallet is not ready to sign.');
    progress('Requesting wallet permission to submit transactions');
    const permission = await requestPermission({ tag: 'ChainSubmit', value: undefined });
    if (!permission.ok) throw permission.error;
    if (!permission.value) throw Error('Wallet transaction permission was denied. Allow this app to submit transactions, then try Apply again.');
    let transactionName = 'wallet setup';
    // Observe the actual wallet call: the SDK's "signing" event fires AFTER signing.
    const signer: typeof walletSigner = {
      publicKey: walletSigner.publicKey,
      signBytes: (...args) => walletSigner.signBytes(...args),
      signTx: async (...args) => {
        if (!acceptingSignature) throw Error('This Apply request has expired.');
        progress(`Waiting for wallet confirmation (${transactionName})`);
        const signed = await walletSigner.signTx(...args);
        if (!acceptingSignature) throw Error('This Apply request expired before the wallet replied.');
        progress(`Wallet signed; waiting for the chain (${transactionName})`);
        return signed;
      },
    };
    progress('Checking wallet setup');
    const mapped = await ensureContractAccountMapped(chain.runtime, account.address, signer, {
      onStatus: (phase) => {
        if (phase === 'mapping') progress('Preparing wallet setup transaction');
      },
    });
    if (!mapped.ok) throw mapped.error;
    transactionName = 'key selection';
    progress('Checking the key selection transaction');
    const result = await chain.contract.assignKey.tx(assignment, {
      signer,
      waitFor: 'finalized',
      onStatus: (phase) => {
        if (phase === 'broadcasting') progress('Transaction submitted; waiting for the chain');
        if (phase === 'in-block') progress('Transaction included; waiting for finalization');
      },
    });
    if (!result.ok) throw result.error;
    el('transaction').textContent = `Last assignment: ${result.value.txHash}`;
    await refresh(true);
    status('Changes applied. The ESP32 will apply the change after syncing.');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    failure(new Error(`${message} Last step: ${step}.`));
  }
  finally { acceptingSignature = false; busy = false; render(); }
});
window.addEventListener('pagehide', () => { clearTimeout(polling); chain?.client.destroy(); wallet.destroy(); });
void start();
void connectWallet().catch(() => {});
