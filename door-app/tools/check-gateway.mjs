import { chromium } from '@playwright/test';
async function check() {
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  await page.goto('https://door.example.invalid', { waitUntil: 'domcontentloaded', timeout: 60_000 });
  const deadline = Date.now() + 120_000;
  let trusted = false;
  while (Date.now() < deadline) {
    const fallback = page.getByRole('button', { name: 'Use Trusted Provider', exact: true });
    if (!trusted && await fallback.isVisible()) {
      await fallback.click();
      trusted = true;
      console.log('Headless browser shared worker unavailable; using the gateway RPC fallback.');
    }
    for (const frame of page.frames()) {
      if (await frame.locator('#assign').count()) {
        const state = await frame.locator('#state').textContent();
        const status = await frame.locator('#status').textContent();
        if (await frame.getByRole('radio', { name: /Alice/ }).isEnabled()) {
          console.log(JSON.stringify({ url: page.url(), trusted, state, status, details: await frame.locator('#details').textContent() }));
          await page.screenshot({ path: '../.local-backups/door/app-gateway.png' });
          process.exitCode = 0;
          return;
        }
      }
    }
    await page.waitForTimeout(2000);
  }
  console.log('Gateway did not expose a ready key selector. Visible content:');
  for (const frame of page.frames()) {
    console.log((await frame.locator('body').innerText().catch(() => '')).slice(0,2500));
  }
  await page.screenshot({ path: '../.local-backups/door/app-gateway.png' });
  process.exitCode = 1;
} finally { await browser.close(); }
}
await check();
