import { test, expect } from '@playwright/test';
import config from '../polkadot-app-deploy.config';

test('silent host cannot leave Connect wallet disabled', async ({ page }) => {
  await page.route('**/silent-host', route => route.fulfill({ contentType: 'text/html', body: '<iframe src="/"></iframe>' }));
  await page.goto('http://localhost:4173/silent-host');
  const app = page.frameLocator('iframe');
  await expect(app.locator('#app-version')).toHaveText(`v${config.executables[0].appVersion.join('.')}`);
  await expect(app.locator('#wallet-status')).toHaveText('Connecting your wallet…');
  await expect(app.locator('#wallet-status')).toContainText('did not respond in time', { timeout: 25_000 });
  await expect(app.locator('#connect-wallet')).toBeVisible();
  await expect(app.locator('#connect-wallet')).toBeEnabled();
  await app.locator('#connect-wallet').click();
  await expect(app.locator('#wallet-status')).toHaveText('Connecting your wallet…');
  await expect(app.locator('#wallet-status')).toContainText('did not respond in time', { timeout: 25_000 });
  await expect(app.locator('#connect-wallet')).toBeEnabled();
});
