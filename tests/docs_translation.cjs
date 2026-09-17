// Run: node tests/docs_translation.cjs (requires Playwright + Chromium).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '..');
const pages = fs.readdirSync(path.join(root, 'docs'), { recursive: true })
  .filter(p => p.endsWith('.html')).map(p => '/docs/' + p.replaceAll('\\', '/'));
const code = page => page.locator('pre,code,kbd,samp').evaluateAll(nodes => nodes.map(n => n.textContent));
(async () => {
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    const file = path.join(root, pathname);
    if (!file.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404).end(); return; }
      res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
      res.end(data);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.DOCS_CHROMIUM || undefined, args: ['--no-sandbox', '--disable-gpu'] });
  let requests = 0;
  const errors = [];
  async function setup(context, failure = false) {
    await context.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin === base) return route.continue();
      if (url.hostname !== 'api.translate.zvo.cn') return route.abort();
      requests++;
      if (failure) return route.abort();
      let body = { result: 1, info: 'SUCCESS' };
      if (url.pathname === '/translate.json') {
        const params = new URLSearchParams(request.postData());
        const texts = JSON.parse(decodeURIComponent(params.get('text')));
        assert(!texts.some(t => /db\.put\(|pip install nedb-engine/.test(t)), 'code sent to backend');
        const prefix = params.get('to') === 'spanish' ? 'ES ' : '中文 ';
        body = { ...body, from: params.get('from'), to: params.get('to'), text: texts.map(t => prefix + t) };
      }
      return route.fulfill({ json: body, headers: { 'access-control-allow-origin': '*' } });
    });
    context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  }
  try {
    for (const file of pages) {
      const context = await browser.newContext();
      await setup(context);
      const page = await context.newPage();
      await page.goto(base + file);
      assert.equal(await page.locator('#docs-language').count(), 1, file);
      const original = await code(page);
      const count = requests;
      assert.equal(await page.locator('script[src*="vendor/translate.js"]').count(), 0);
      assert.equal(requests, count);
      for (const language of ['spanish', 'chinese_simplified']) {
        await page.goto(base + file + '?docs-language=' + language);
        await page.waitForSelector('.docs-language[data-state="translated"]', { timeout: 10000 });
        assert.deepEqual(await code(page), original, file + ' ' + language);
        assert.equal(await page.locator('html').getAttribute('lang'), language === 'spanish' ? 'es' : 'zh-Hans');
        assert(await page.locator('body').innerText().then(t => t.includes(language === 'spanish' ? 'ES ' : '中文 ')));
      }
      await page.locator('.docs-language a').click();
      await page.waitForURL(/docs-language=english/);
      assert.deepEqual(await code(page), original);
      await context.close();
      console.log('PASS', file, 'English / Spanish / Chinese / exact code / restore');
    }
    // Failure, storage denial, navigation persistence, and RTL use real client code.
    for (const failure of [false, true]) {
      const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
      await setup(context, failure);
      await context.addInitScript(() => {
        Storage.prototype.getItem = Storage.prototype.setItem = () => { throw new Error('storage denied'); };
      });
      const page = await context.newPage();
      await page.goto(base + '/docs/docs/index.html?docs-language=spanish');
      await page.waitForSelector('.docs-language[data-state="error"]');
      assert(await page.locator('h1').isVisible());
      assert((await page.locator('.sidebar a.item').first().getAttribute('href')).includes('docs-language=spanish'));
      await page.locator('.docs-language a').click();
      await page.waitForURL(/docs-language=english/);
      await context.close();
    }
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await setup(context);
    const page = await context.newPage();
    await page.goto(base + '/docs/docs/index.html?docs-language=arabic');
    await page.waitForSelector('.docs-language[data-state="translated"]');
    assert.equal(await page.locator('html').getAttribute('dir'), 'rtl');
    const box = await page.locator('#docs-language').boundingBox();
    assert(box.x >= 0 && box.x + box.width <= 390, 'mobile selector fits');
    await context.close();
    assert.deepEqual(errors, []);
    console.log(`PASS ${pages.length} pages; error fallback, storage denial, navigation, RTL/mobile`);
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
