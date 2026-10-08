import { test as base, expect } from '@playwright/test';
import { createTestHostFixture, type TestHost } from '@parity/host-api-test-sdk/playwright';
import { deployment } from '../src/contract';

// Public development key; this test only connects and never signs a transaction.
const test = base.extend<{ testHost: TestHost }>(createTestHostFixture({
  productUrl: 'http://localhost:4173',
  accounts: ['alice'],
  productAccounts: { 'example-door.dot/0': { name: 'Alice', uri: '//Alice' } },
  networks: [{ id: 'products-devnet', name: 'Products devnet', genesisHash: deployment.genesis,
    rpcUrl: 'wss://asset-hub-paseo-rpc.n.dwellir.com', tokenSymbol: 'PAS', tokenDecimals: 10 }],
}));

test('connects the app account and displays its funding address', async ({ testHost }) => {
  const frame = testHost.productFrame();
  await expect(frame.locator('#wallet-address')).not.toHaveValue('', { timeout: 30_000 });
  await expect(frame.locator('#wallet-status')).toHaveText('This is the wallet account used by Door Keys.');
  await expect(frame.locator('#connect-wallet')).toBeHidden();
});
