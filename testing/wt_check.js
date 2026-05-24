// wt_check.js — drive REAL headless Chrome to verify WebTransport opens.
// Run via the puppeteer image in the server's network namespace so 127.0.0.1:8443
// reaches the Bolt server directly (matches the cert SAN; no Docker NAT).
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--ignore-certificate-errors',
      '--enable-quic',
    ],
  });
  try {
    const page = await browser.newPage();
    page.on('console', (m) => console.log('  [page]', m.text()));
    // A secure context that can use WebTransport. The page itself may load over
    // h1/h2; WebTransport opens its own QUIC connection.
    await page.goto('https://127.0.0.1:8443/', { waitUntil: 'domcontentloaded' })
      .catch((e) => console.log('  goto note:', e.message));
    const result = await page.evaluate(async () => {
      if (typeof WebTransport === 'undefined') return 'NO_WEBTRANSPORT_API';
      try {
        const wt = new WebTransport('https://127.0.0.1:8443/wt');
        await Promise.race([
          wt.ready,
          new Promise((_, rej) => setTimeout(() => rej(new Error('ready timeout')), 8000)),
        ]);
        return 'READY';
      } catch (e) {
        return 'FAIL: ' + (e && e.message ? e.message : String(e));
      }
    });
    console.log('WT_BROWSER_RESULT=' + result);
  } finally {
    await browser.close();
  }
})();
