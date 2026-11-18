import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ headless: true });
const consoleErrors = [];
const failedCss = [];
async function inspectViewport(width, height, screenshotPath) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', error => consoleErrors.push(error.message));
  page.on('requestfailed', request => { if (request.resourceType() === 'stylesheet') failedCss.push(`${request.url()}: ${request.failure()?.errorText}`); });
  const response = await page.goto('http://127.0.0.1:3000', { waitUntil: 'networkidle' });
  assert.equal(response.status(), 200);
  const styles = await page.evaluate(() => {
    const style = selector => getComputedStyle(document.querySelector(selector));
    const hero = style('h1');
    const wrapper = style('header');
    const container = style('main > section');
    const button = style('form button');
    const grid = document.querySelector('article').parentElement;
    return {
      title: document.title,
      logoWidth: document.querySelector('header > a img')?.getBoundingClientRect().width,
      heroFontSize: hero.fontSize,
      heroWeight: hero.fontWeight,
      headerDisplay: wrapper.display,
      containerPadding: container.paddingLeft,
      buttonBackground: button.backgroundColor,
      buttonPadding: button.padding,
      scannerBottom: document.querySelector('form#scanner').getBoundingClientRect().bottom,
      viewportHeight: window.innerHeight,
      capabilityColumns: getComputedStyle(grid).gridTemplateColumns.split(' ').length,
      cssLoaded: [...document.styleSheets].some(sheet => sheet.href?.includes('/_next/static/css/')),
      width: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });
  assert.equal(styles.title, 'Rugscripts');
  assert.equal(styles.logoWidth, 178);
  assert.equal(styles.headerDisplay, 'flex');
  assert.equal(await page.getByRole('link', { name: 'Follow RUGSCRIPTS on X' }).count(), 1);
  assert.equal(styles.buttonBackground, 'rgb(255, 77, 53)');
  assert.ok(Number.parseFloat(styles.heroFontSize) >= (width > 768 ? 68 : 40));
  assert.equal(styles.cssLoaded, true);
  assert.equal(styles.scrollWidth, width, `horizontal overflow at ${width}px`);
  if (width >= 1280) assert.ok(styles.scannerBottom <= height, `scanner form extends below the fold at ${width}x${height}`);
  assert.equal(styles.capabilityColumns, width >= 1280 ? 4 : width >= 768 ? 2 : 1);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  return { page, styles };
}
try {
  const desktop = await inspectViewport(1440, 768, '/tmp/rugscripts-desktop.png');
  const mobile = await inspectViewport(390, 844, '/tmp/rugscripts-mobile.png');
  await desktop.page.locator('input[type=url]').fill('https://example.com');
  await desktop.page.getByRole('button', { name: 'SCAN WEBSITE' }).click();
  await desktop.page.getByText('Risk breakdown', { exact: true }).waitFor({ timeout: 20000 });
  const result = await desktop.page.locator('[aria-live="polite"]').innerText();
  assert.match(result, /example\.com/);
  await desktop.page.getByText('Analysis engine · static-html-js-v1', { exact: true }).waitFor();
  const xLinks = await desktop.page.locator('a[href^="https://x.com/"]').evaluateAll(links => links.map(link => ({ href: link.href, target: link.target, rel: link.rel })));
  assert.ok(xLinks.length >= 5, 'expected X follow, share, and research links');
  assert.ok(xLinks.every(link => link.target === '_blank' && link.rel.includes('noopener') && link.rel.includes('noreferrer')));
  const share = new URL(xLinks.find(link => link.href.startsWith('https://x.com/intent/post?'))?.href || 'https://invalid.test');
  assert.match(share.searchParams.get('text') || '', /RUGSCRIPTS/);
  assert.doesNotMatch(share.searchParams.get('text') || '', /example\.com/);
  await desktop.page.screenshot({ path: '/tmp/rugscripts-results.png', fullPage: true });
  await mobile.page.locator('input[type=url]').fill('https://example.com');
  await mobile.page.getByRole('button', { name: 'SCAN WEBSITE' }).click();
  await mobile.page.getByText('Risk breakdown', { exact: true }).waitFor({ timeout: 20000 });
  const mobileOverflow = await mobile.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  assert.equal(mobileOverflow, 0, 'results dashboard overflows mobile viewport');
  await mobile.page.screenshot({ path: '/tmp/rugscripts-results-mobile.png', fullPage: true });
  assert.deepEqual(failedCss, []);
  assert.deepEqual(consoleErrors, []);
  console.log(JSON.stringify({ desktop: desktop.styles, mobile: mobile.styles, scannerResultRendered: true, mobileResultsOverflow: mobileOverflow, consoleErrors, failedCss, screenshots: ['/tmp/rugscripts-desktop.png', '/tmp/rugscripts-mobile.png', '/tmp/rugscripts-results.png', '/tmp/rugscripts-results-mobile.png'] }, null, 2));
  await desktop.page.close();
  await mobile.page.close();
} finally {
  await browser.close();
}
