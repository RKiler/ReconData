#!/usr/bin/env node
/*
 * Credential-safe browser check for Perk login redirect candidates.
 *
 * Safety properties:
 * - Reads cookies locally and never writes their values to output.
 * - Blocks every HTTP(S) request whose hostname is not app.perk.com.
 * - Performs navigation only; no form submission or state-changing action.
 * - Uses fresh browser contexts for every test case.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const playwrightRoot = process.env.PERK_PLAYWRIGHT_ROOT;
if (!playwrightRoot) throw new Error('PERK_PLAYWRIGHT_ROOT is required');
const { chromium } = require(path.join(playwrightRoot, 'node_modules', 'playwright-core'));

const TARGET_HOST = 'app.perk.com';
const COOKIE_FILE = '/root/cookies_perk.txt';
const OUTPUT_FILE = '/root/perk_bac_idor_results/evidence/historical_urls_20260721_active/browser_login_results.json';
const CHROME = '/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';

function cookiePairs() {
  const line = fs.readFileSync(COOKIE_FILE, 'utf8')
    .split(/\r?\n/)
    .find((value) => /^Cookie\s*:/i.test(value));
  if (!line) throw new Error('Cookie header not found');
  return line.replace(/^Cookie\s*:\s*/i, '').split(';').map((pair) => {
    const index = pair.indexOf('=');
    if (index < 1) return null;
    return {
      name: pair.slice(0, index).trim(),
      value: pair.slice(index + 1).trim(),
      domain: TARGET_HOST,
      path: '/',
      secure: true,
    };
  }).filter(Boolean);
}

const cases = [
  ['baseline', 'https://app.perk.com/login'],
  ['absolute_external', 'https://app.perk.com/login?coming_from=https%3A%2F%2Fexample.invalid%2Fcodex-open-redirect-check'],
  ['protocol_relative', 'https://app.perk.com/login?coming_from=%2F%2Fexample.invalid%2Fcodex-open-redirect-check'],
  ['sso_return_to', 'https://app.perk.com/sso-login?return_to=https%3A%2F%2Fexample.invalid%2Fcodex-open-redirect-check'],
];

(async () => {
  const browser = await chromium.launch({
    executablePath: CHROME,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const results = [];
  try {
    for (const mode of ['anonymous', 'authenticated_cookies']) {
      for (const [name, url] of cases) {
        const context = await browser.newContext({
          viewport: { width: 1280, height: 720 },
          locale: 'en-US',
          serviceWorkers: 'block',
        });
        if (mode === 'authenticated_cookies') await context.addCookies(cookiePairs());

        const blockedOffHost = [];
        const navigationResponses = [];
        await context.route('**/*', async (route) => {
          const requestUrl = route.request().url();
          try {
            const parsed = new URL(requestUrl);
            if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname !== TARGET_HOST) {
              blockedOffHost.push({
                hostname: parsed.hostname,
                path: parsed.pathname,
                resource_type: route.request().resourceType(),
                navigation: route.request().isNavigationRequest(),
              });
              return route.abort('blockedbyclient');
            }
          } catch (_) {
            return route.abort('blockedbyclient');
          }
          return route.continue();
        });

        const page = await context.newPage();
        page.on('response', (response) => {
          if (response.request().isNavigationRequest()) {
            navigationResponses.push({
              url: response.url().replace(/([?&](?:coming_from|return_to)=)[^&]*/gi, '$1[REDACTED]'),
              status: response.status(),
            });
          }
        });

        let initialStatus = null;
        let error = null;
        try {
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
          initialStatus = response ? response.status() : null;
          if (initialStatus === 202) {
            await page.waitForResponse(
              (candidate) => candidate.request().isNavigationRequest() && candidate.status() !== 202,
              { timeout: 15000 },
            ).catch(() => null);
          }
          await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => null);
        } catch (failure) {
          error = String(failure.message || failure).slice(0, 300);
        }

        const html = await page.content().catch(() => '');
        const finalUrl = page.url();
        const parsedFinal = (() => { try { return new URL(finalUrl); } catch (_) { return null; } })();
        results.push({
          mode,
          case: name,
          requested_path: new URL(url).pathname,
          initial_status: initialStatus,
          final_origin: parsedFinal ? parsedFinal.origin : null,
          final_path: parsedFinal ? parsedFinal.pathname : null,
          final_query_keys: parsedFinal ? [...parsedFinal.searchParams.keys()] : [],
          title: await page.title().catch(() => ''),
          html_length: Buffer.byteLength(html),
          html_sha256: crypto.createHash('sha256').update(html).digest('hex'),
          waf_interstitial: /aws[- ]?waf|challenge\.js|awswaf/i.test(html),
          marker_reflected: /codex-open-redirect-check/i.test(html),
          navigation_responses: navigationResponses,
          blocked_off_host: blockedOffHost,
          error,
        });
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }

  fs.writeFileSync(OUTPUT_FILE, `${JSON.stringify({ generated_at: new Date().toISOString(), results }, null, 2)}\n`, { mode: 0o600 });
  const concise = results.map(({ mode, case: testCase, initial_status, final_origin, final_path, waf_interstitial, marker_reflected, blocked_off_host, error }) => ({
    mode,
    case: testCase,
    initial_status,
    final_origin,
    final_path,
    waf_interstitial,
    marker_reflected,
    off_host_attempts: blocked_off_host.length,
    error,
  }));
  process.stdout.write(`${JSON.stringify(concise, null, 2)}\n`);
})().catch((error) => {
  process.stderr.write(`browser check failed: ${String(error.message || error).slice(0, 500)}\n`);
  process.exitCode = 1;
});
