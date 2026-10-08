import { chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 256, height: 256 } });
  await page.setContent('<style>body{margin:0;background:transparent}</style>' + readFileSync(new URL('../icon.svg', import.meta.url), 'utf8'));
  await page.screenshot({ path: new URL('../icon.png', import.meta.url).pathname, omitBackground: true });
} finally { await browser.close(); }
