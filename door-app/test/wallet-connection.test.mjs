import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SignerManager } from '@parity/product-sdk/wallet';
import { WalletSession, createWalletManager } from '../src/wallet.ts';
const account = { address: 'test-account', publicKey: new Uint8Array(32), name: 'Test', source: 'host' };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const success = { ok: true, value: [account] };
const provider = () => ({ type: 'host', connect: async () => success, disconnect() {}, onStatusChange: () => () => {}, onAccountsChange: () => () => {} });
function fakeManager(reply) {
  let state = { selectedAccount: null }; const listeners = new Set(); const signer = {};
  return {
    destroyed: 0, calls: 0,
    async connect() { this.calls++; const result = await reply; if (result.ok) state = { selectedAccount: result.value[0] }; for (const f of listeners) f(state); return result; },
    getState: () => state, getSigner: () => state.selectedAccount ? signer : null,
    subscribe(f) { listeners.add(f); return () => listeners.delete(f); },
    destroy() { this.destroyed++; listeners.clear(); },
  };
}
test('silent host times out; retry works; late replies cannot replace the account', async () => {
  const first = deferred(), old = fakeManager(first.promise), next = fakeManager(Promise.resolve(success));
  const updates = [], managers = [old, next];
  const wallet = new WalletSession(s => updates.push(s), () => managers.shift(), 15);
  const pending = wallet.connect(); assert.equal(wallet.connect(), pending);
  await assert.rejects(pending, /did not respond in time/);
  assert.equal(old.destroyed, 1); assert.equal(wallet.getSigner(), null);
  assert.equal(await wallet.connect(), account); const signer = wallet.getSigner();
  first.resolve({ ok: true, value: [{ ...account, address: 'expired-account' }] });
  await new Promise(r => setImmediate(r));
  assert.equal(wallet.getSigner(), signer);
  assert.deepEqual(updates.map(s => s.selectedAccount?.address), ['test-account']);
  assert.equal(await wallet.connect(), account); assert.equal(next.calls, 1); wallet.destroy();
});
test('host rejection allows retry', async () => {
  const managers = [fakeManager(Promise.resolve({ ok: false, error: Error('Please sign in') })), fakeManager(Promise.resolve(success))];
  const wallet = new WalletSession(() => {}, () => managers.shift(), 100);
  await assert.rejects(wallet.connect(), /Please sign in/); assert.equal(await wallet.connect(), account); wallet.destroy();
});
test('destroy cancels pending connection', async () => {
  const wallet = new WalletSession(() => {}, () => fakeManager(new Promise(() => {})), 1000);
  const pending = wallet.connect(); wallet.destroy();
  await assert.rejects(pending, /session is closed/); await assert.rejects(wallet.connect(), /session is closed/);
});
test('SDK reproduction: host storage stalls account selection after provider connects', async () => {
  const read = deferred(); let storageRead = false;
  const manager = new SignerManager({ persistence: { getItem() { storageRead = true; return read.promise; }, setItem() {}, removeItem() {} }, createProvider: provider });
  const pending = manager.connect(); await new Promise(r => setImmediate(r));
  assert.equal(storageRead, true); assert.equal(manager.getState().status, 'connecting'); assert.equal(manager.getState().selectedAccount, null);
  read.resolve(null); await pending; assert.equal(manager.getState().selectedAccount, account); manager.destroy();
});
test('production manager selects account without host storage', async () => {
  const manager = createWalletManager(); manager.providerFactory = provider;
  assert.equal((await manager.connect()).ok, true); assert.equal(manager.getState().selectedAccount, account); manager.destroy();
});
