import { test as base, expect } from '@playwright/test';
import { createTestHostFixture, type TestHost } from '@parity/host-api-test-sdk/playwright';
import { execFileSync } from 'node:child_process';
import { deployment } from '../src/contract';

// Explicit live test. Test host pages contain signing material: no traces/HTML captures.
const key = process.env.DOOR_MNEMONIC;
const test = base.extend<{ testHost: TestHost }>(createTestHostFixture({
  productUrl: 'http://localhost:4173',
  accounts: key ? [{ name: 'Door test', uri: key }] : ['alice'],
  productAccounts: key ? { 'example-door.dot/0': { name: 'Door test', uri: key } } : {},
  networks: [{ id: 'products-devnet', name: 'Products devnet', genesisHash: deployment.genesis,
    rpcUrl: 'wss://asset-hub-paseo-rpc.n.dwellir.com', tokenSymbol: 'PAS', tokenDecimals: 10 }],
}));

function checkPolicy(expected: string) {
  console.log(execFileSync('../.venv/bin/python', ['../door-contract/tools/check_keys.py', expected], { encoding: 'utf8' }));
}

test('selects keys and applies all four combinations', async ({ testHost, page }) => {
  test.skip(!key, 'Set DOOR_MNEMONIC to run the live test.');
  const frame = testHost.productFrame();
  const alice = frame.getByRole('button', { name: 'Alice', exact: true });
  const bob = frame.getByRole('button', { name: 'Bob', exact: true });
  await expect(alice).toBeEnabled({ timeout: 60_000 });
  const original = [await alice.getAttribute('aria-pressed') === 'true', await bob.getAttribute('aria-pressed') === 'true'];
  async function setKeys(a: boolean, b: boolean) {
    for (const [button, enabled] of [[alice, a], [bob, b]] as const) {
      if ((await button.getAttribute('aria-pressed') === 'true') !== enabled) {
        await button.click();
        await expect(button).toBeEnabled();
        await expect(button).toHaveAttribute('aria-pressed', String(enabled), { timeout: 30_000 });
      }
    }
    const apply = frame.getByRole('button', { name: 'Apply', exact: true });
    if (await apply.isEnabled()) {
      await apply.click();
      await expect(frame.locator('#status')).toContainText('Changes applied.', { timeout: 100_000 });
      await expect(alice).toBeEnabled();
      await expect(bob).toBeEnabled();
    }
    checkPolicy(a ? b ? 'Both' : 'Alice' : b ? 'Bob' : 'None');
    await page.waitForTimeout(20_000);
  }
  try {
    for (const [a, b] of [[false, false], [true, false], [true, true], [false, true], [false, false]]) await setKeys(a, b);
  } finally {
    await setKeys(original[0], original[1]);
  }
});

test('shows a reconnect action outside the host', async ({ page }) => {
  await page.goto('http://localhost:4173');
  await expect(page.getByRole('button', { name: 'Reconnect' })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('button', { name: 'Alice', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Bob', exact: true })).toBeDisabled();
});
