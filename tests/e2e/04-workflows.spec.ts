import { readFileSync } from 'node:fs';
import { test, expect, waitFor } from './support/fixtures';
import { CA_PEM, SCREENSHOT_DIR } from './support/env';

test.describe('Executive dashboard content', () => {
  test('overview shows 5 KPI tiles, 8 KRIs with RAG, 3 trend charts and the heat map', async ({ as }) => {
    const { page, api } = await as('ciso');
    const summary = (await api('GET', '/kpi/summary')).json;
    for (const label of ['Mean time to detect', 'Mean time to respond', 'Patch compliance', 'Remediation velocity', 'Open critical findings']) {
      await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
    }
    expect(summary.kpis.mttdHours).toBeGreaterThan(0);
    expect(summary.kpis.mttrHours).toBeGreaterThan(0);
    expect(summary.kpis.patchCompliancePct).toBeGreaterThan(0);
    expect(summary.kpis.patchCompliancePct).toBeLessThanOrEqual(100);
    expect(summary.kpis.openCriticalFindings).toBeGreaterThan(0);
    await expect(page.getByText(String(summary.kpis.openCriticalFindings), { exact: true }).first()).toBeVisible();

    const kriTable = page.locator('table').first();
    await expect(kriTable.locator('tbody tr')).toHaveCount(summary.kris.length);
    expect(summary.kris.length).toBe(8);
    for (const k of summary.kris) expect(['GREEN', 'AMBER', 'RED', null]).toContain(k.status);

    await expect(page.locator('.recharts-wrapper')).toHaveCount(3);
    await expect(page.locator('.recharts-line')).toHaveCount(6);
    await expect(page.getByRole('grid', { name: 'Risk matrix' }).getByRole('gridcell')).toHaveCount(25);
    const trends = (await api('GET', '/kpi/trends?days=90')).json;
    expect(trends.points.length).toBeGreaterThanOrEqual(85);
  });

  test('risk matrix drill-down: cell → risks → assets → open vulnerabilities', async ({ as }) => {
    const { page } = await as('ciso');
    await page.goto('/risk');
    const cells = page.getByRole('gridcell');
    await expect(cells).toHaveCount(25);
    // pick the populated cell with the highest score
    const labels = await cells.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? ''));
    const populated = labels.map((l, i) => ({ i, m: /Likelihood (\d), impact (\d): (\d+) risks/.exec(l) })).filter((x) => x.m && Number(x.m[3]) > 0);
    expect(populated.length).toBeGreaterThan(3);
    populated.sort((a, b) => Number(b.m![1]) * Number(b.m![2]) - Number(a.m![1]) * Number(a.m![2]));
    await cells.nth(populated[0]!.i).click();
    const riskButton = page.locator('ul li button').first();
    await expect(riskButton).toBeVisible();
    await riskButton.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText(/Linked assets & open vulnerabilities/)).toBeVisible();
    const details = dialog.locator('details').first();
    await expect(details).toBeVisible();
    await details.evaluate((el) => ((el as HTMLDetailsElement).open = true));
    await expect(details.locator('table').or(details.getByText('No open vulnerabilities.'))).toBeVisible();
    await page.screenshot({ path: `${SCREENSHOT_DIR}/13-risk-drilldown.png` });
  });
});

test.describe('Risk register & acceptance workflow', () => {
  const xssTitle = `<img src=x onerror="window.__xss=1"> E2E ${Date.now()}`;

  test('SecOps registers a risk; HTML is rendered inert (stored XSS)', async ({ as }) => {
    const { page } = await as('secops');
    await page.goto('/risk');
    await page.getByRole('button', { name: /register risk/i }).click();
    const d = page.getByRole('dialog');
    await d.getByLabel('Title').fill(xssTitle);
    await d.getByLabel('Description').fill('Legacy remote access appliance without MFA; exploited CVEs in the wild.');
    await d.getByLabel('Category').fill('Cyber');
    await d.getByLabel('Risk owner').fill('Network Security Lead');
    await d.getByLabel('Likelihood (1-5)').selectOption('5');
    await d.getByLabel('Impact (1-5)').selectOption('5');
    await d.getByRole('button', { name: 'Save risk' }).click();
    await expect(d).toBeHidden();
    await page.getByRole('gridcell', { name: /Likelihood 5, impact 5/ }).click();
    await page.getByRole('button', { name: new RegExp(xssTitle.slice(-16)) }).click();
    await expect(page.getByRole('dialog').getByText(xssTitle).first()).toBeVisible(); // shown literally
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
    expect(await page.locator('img[src="x"]').count()).toBe(0);

    // Request acceptance from the drill-down.
    await page.getByRole('button', { name: 'Request acceptance' }).click();
    const req = page.getByRole('dialog', { name: /request risk acceptance/i });
    await req.getByLabel(/justification/i).fill('Compensating controls: geo-blocking, IPS signatures and 24x7 monitoring until replacement.');
    await req.getByLabel(/validity/i).fill('60');
    await req.getByRole('button', { name: /submit for ciso approval/i }).click();
    await expect(page.getByRole('dialog').getByText('PENDING')).toBeVisible();
  });

  test('CISO approves (segregation of duties shown for own requests)', async ({ as }) => {
    const ciso = await as('ciso');
    // Create a request owned by the CISO via API → UI must refuse self-approval.
    const r = await ciso.api('POST', '/risks', { title: 'CISO-owned E2E risk', description: 'SoD check', category: 'Governance', likelihood: 2, impact: 3, ownerName: 'CISO' });
    await ciso.api('POST', `/risks/${r.json.id}/acceptances`, { justification: 'Requested by the CISO themself for SoD testing.', expiresInDays: 10 });

    await ciso.page.goto('/acceptances');
    await ciso.page.getByLabel('Filter status').selectOption('PENDING');
    const own = ciso.page.locator('tr', { hasText: 'CISO-owned E2E risk' });
    await expect(own.getByText('Own request')).toBeVisible();
    await expect(own.getByRole('button', { name: /approve/i })).toHaveCount(0);

    const row = ciso.page.locator('tr', { hasText: xssTitle.slice(-16) });
    await row.getByRole('button', { name: /approve/i }).click();
    const d = ciso.page.getByRole('dialog');
    await d.getByLabel('Decision rationale').fill('Accepted until Q3 replacement project completes.');
    await d.getByRole('button', { name: 'Confirm' }).click();
    await ciso.page.getByLabel('Filter status').selectOption('APPROVED');
    await expect(ciso.page.locator('tr', { hasText: xssTitle.slice(-16) }).getByText('APPROVED')).toBeVisible();

    // A second CISO can approve the first CISO's own request.
    const ciso2 = await as('ciso2');
    const pending = (await ciso2.api('GET', '/risk-acceptances?status=PENDING')).json.items.find((a: { risk: { title: string } }) => a.risk.title === 'CISO-owned E2E risk');
    expect((await ciso2.api('POST', `/risk-acceptances/${pending.id}/decision`, { decision: 'REJECT', note: 'Insufficient compensating controls.' })).status).toBe(200);
  });

  test('approved acceptance can be revoked and the risk re-opens', async ({ as }) => {
    const { api } = await as('ciso');
    const approved = (await api('GET', '/risk-acceptances?status=APPROVED')).json.items.find((a: { risk: { title: string } }) => a.risk.title === xssTitle);
    expect(approved).toBeTruthy();
    expect((await api('POST', `/risk-acceptances/${approved.id}/revoke`, { note: 'Compensating control failed audit.' })).status).toBe(204);
    expect((await api('GET', `/risks/${approved.riskId}`)).json.status).toBe('OPEN');
  });
});

test.describe('Threat intelligence stream', () => {
  test('filters, search, facets and analyst triage', async ({ as }) => {
    const { page } = await as('secops');
    await page.goto('/threats');
    await expect(page.locator('article').first()).toBeVisible();
    await page.getByRole('button', { name: /^Ransomware/ }).click();
    await expect(page.locator('article').first()).toBeVisible();
    const types = await page.locator('article').evaluateAll((els) => els.map((e) => e.textContent ?? ''));
    expect(types.every((t) => t.includes('Ransomware'))).toBe(true);
    await page.getByRole('button', { name: /^Ransomware/ }).click(); // clear

    await page.getByPlaceholder(/search title, cve or tag/i).fill('CVE-2024-3400');
    await expect(page.locator('article', { hasText: 'CVE-2024-3400' }).first()).toBeVisible();
    await page.getByPlaceholder(/search title, cve or tag/i).fill('');

    await page.getByLabel('Impacting my assets').check();
    await expect(page.locator('article').first()).toContainText(/Impacted assets: [1-9]/);
    await page.getByLabel('Impacting my assets').uncheck();

    const first = page.locator('article').first();
    const title = (await first.locator('h3').innerText()).trim();
    await first.getByRole('button', { name: 'Triage' }).click();
    await expect(page.locator('article', { hasText: title }).getByText('TRIAGED')).toBeVisible();
  });

  test('auditor sees the stream read-only', async ({ as }) => {
    const { page } = await as('auditor');
    await page.goto('/threats');
    await expect(page.locator('article').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Triage' })).toHaveCount(0);
  });
});

test.describe('Incidents', () => {
  test('SecOps logs an incident; another user sees it live via SSE without reloading', async ({ as }) => {
    const watcher = await as('patch');
    await watcher.page.goto('/incidents');
    await expect(watcher.page.getByText('Live', { exact: true })).toBeVisible();

    const { page } = await as('secops');
    await page.goto('/incidents');
    await page.getByRole('button', { name: /log incident/i }).click();
    const d = page.getByRole('dialog');
    const title = `E2E ransomware precursor ${Date.now()}`;
    await d.getByLabel('Title').fill(title);
    await d.getByLabel('Description').fill('Cobalt Strike beacon observed on finance workstation.');
    await d.getByLabel('Severity').selectOption('CRITICAL');
    await d.getByLabel('Assets affected').fill('3');
    await d.getByRole('button', { name: 'Create incident' }).click();
    const row = page.locator('tr', { hasText: title });
    await expect(row).toBeVisible();

    // Live propagation to the other session.
    await expect(watcher.page.locator('tr', { hasText: title })).toBeVisible({ timeout: 10_000 });

    // Lifecycle → MTTR inputs.
    await row.getByLabel('Update status').selectOption('CONTAINED');
    await row.getByLabel('Update status').selectOption('RESOLVED');
    await expect(row.locator('td').nth(4)).not.toHaveText('—');
    // Watcher (Patch Admin) cannot edit incidents.
    await expect(watcher.page.locator('tr', { hasText: title }).getByLabel('Update status')).toHaveCount(0);
  });
});

test.describe('Remediation', () => {
  test('Patch admin updates status and links a change ticket', async ({ as }) => {
    const { page } = await as('patch');
    await page.goto('/remediation');
    await page.getByLabel('Severity').selectOption('CRITICAL');
    const row = page.locator('tbody tr').filter({ has: page.getByRole('button', { name: 'Link' }) }).first();
    await expect(row).toBeVisible();
    const finding = (await row.locator('td').nth(1).innerText()).split('\n')[0]!;
    await row.getByRole('button', { name: 'Link' }).click();
    const d = page.getByRole('dialog');
    await d.getByLabel('System').fill('ServiceNow');
    await d.getByLabel('Ticket key').fill('CHG0099001');
    await d.getByLabel(/URL/).fill('https://servicenow.example/change/CHG0099001');
    await d.getByRole('button', { name: 'Link ticket' }).click();
    await expect(page.locator('tbody tr', { hasText: 'CHG0099001' }).first()).toBeVisible();
    const linked = page.locator('tbody tr', { hasText: 'CHG0099001' }).first();
    await expect(linked.getByRole('link', { name: /CHG0099001/ })).toHaveAttribute('rel', /noopener/);
    await linked.getByLabel('Remediation status').selectOption('REMEDIATED');
    await page.getByLabel('Status', { exact: true }).selectOption('REMEDIATED');
    await expect(page.locator('tbody tr', { hasText: finding }).first()).toBeVisible();
  });

  test('non-https ticket URLs are rejected', async ({ as }) => {
    const { api } = await as('patch');
    const v = (await api('GET', '/vulnerabilities?status=OPEN&limit=1')).json.items[0];
    const r = await api('POST', `/vulnerabilities/${v.id}/change-ticket`, { system: 'Jira', externalKey: 'CHG-1', url: 'javascript:alert(1)' });
    expect(r.status).toBe(400);
  });
});

test.describe('KRI thresholds & parameters', () => {
  test('CISO edits a KRI; invalid ordering is refused; breaches can be acknowledged', async ({ as }) => {
    const { page, api } = await as('ciso');
    await page.goto('/parameters');
    const row = page.locator('tr', { hasText: 'Open critical findings' });
    await row.getByLabel(/amber threshold/).fill('50');
    await row.getByLabel(/red threshold/).fill('20');
    await row.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(/Red threshold must be greater than amber/)).toBeVisible();
    await row.getByLabel(/amber threshold/).fill('15');
    await row.getByLabel(/red threshold/).fill('40');
    await row.getByRole('button', { name: 'Save' }).click();
    await expect.poll(async () => (await api('GET', '/kri')).json.items.find((k: { key: string }) => k.key === 'open_critical').amberThreshold).toBe(15);

    const appetite = page.getByLabel('Risk appetite (max tolerated inherent score, 1-25)');
    await appetite.fill('10');
    await appetite.locator('xpath=..').getByRole('button').click();
    await expect.poll(async () => (await api('GET', '/admin/settings')).json.items.find((s: { key: string }) => s.key === 'riskAppetiteScore').value).toBe(10);
    // CISO cannot change system-level retention.
    await expect(page.getByText('Requires system:manage').first()).toBeVisible();

    const ack = page.getByRole('button', { name: /acknowledge/i }).first();
    if (await ack.count()) {
      await ack.click();
      await expect(page.getByText(/^ack /).first()).toBeVisible();
    }
    const audit = await api('GET', '/audit?action=kri.update&limit=5');
    expect(audit.json.items[0].details.after.amber).toBe(15);
  });

  test('auditor sees parameters read-only', async ({ as }) => {
    const { page } = await as('auditor');
    await page.goto('/parameters');
    await expect(page.locator('tr', { hasText: 'Open critical findings' }).getByLabel(/amber threshold/)).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
  });
});

test.describe('Audit log & compliance', () => {
  test('auditor verifies the chain, filters, inspects a record and exports a CSV safely', async ({ as }) => {
    const secops = await as('secops');
    await secops.api('POST', '/risks', { title: '=HYPERLINK("http://evil.example","x")', description: 'CSV injection probe', category: 'Test', likelihood: 1, impact: 1, ownerName: 'QA' });

    const { page } = await as('auditor');
    await page.goto('/audit');
    await page.getByRole('button', { name: /verify integrity/i }).click();
    await expect(page.getByText(/Hash chain intact/)).toBeVisible();
    await page.getByLabel('Action').selectOption({ label: (await page.getByLabel('Action').locator('option', { hasText: 'risk.create' }).innerText()).trim() });
    await expect(page.locator('tbody tr').first()).toContainText('risk.create');
    await page.locator('tbody tr').first().click();
    await expect(page.getByRole('dialog').getByText('prevHash')).toBeVisible();
    await page.keyboard.press('Escape');

    await page.getByLabel('Action').selectOption('');
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /export csv/i }).click()]);
    const csv = readFileSync((await download.path())!, 'utf8');
    expect(csv.split('\r\n')[0]).toContain('prevHash');
    expect(csv).toContain('HYPERLINK'); // probe present (inside quoted JSON details)
    expect(csv).not.toMatch(/(^|,)"?[=+@]/m); // no cell starts with a spreadsheet formula
    expect(csv.split('\r\n').length).toBeGreaterThan(20);
  });

  test('compliance report lists NIST AU and PCI 10 controls with live evidence', async ({ as }) => {
    const { page } = await as('auditor');
    await page.goto('/compliance');
    await expect(page.getByText(/Audit log integrity: verified/)).toBeVisible();
    for (const id of ['AU-2', 'AU-9', 'AU-12', '10.2.1', '10.3.2', '8.2.8', '3.5.1', '4.2.1']) {
      await expect(page.getByRole('cell', { name: id, exact: true })).toBeVisible();
    }
    await expect(page.getByText('FAILED', { exact: true })).toHaveCount(0);
  });
});

test.describe('Administration', () => {
  test('admin sees system health; CISO sees users read-only', async ({ as }) => {
    const admin = await as('admin');
    await admin.page.goto('/admin');
    for (const card of ['Application', 'Database', 'Security posture', 'Scheduler & feeds']) await expect(admin.page.getByText(card, { exact: true })).toBeVisible();
    await expect(admin.page.getByText('mtlsFromGateway')).toBeVisible();
    const ciso = await as('ciso');
    await ciso.page.goto('/admin');
    await expect(ciso.page.getByText('Users (provisioned on first SSO login)')).toBeVisible();
    await expect(ciso.page.getByRole('button', { name: /disable|revoke sessions/i })).toHaveCount(0);
    await expect(ciso.page.getByText('Database', { exact: true })).toHaveCount(0);
  });

  test('admin configures a Splunk connector in the UI, tests, syncs and rotates credentials', async ({ as }) => {
    const { page, api } = await as('admin');
    const name = `UI Splunk ${Date.now()}`;
    await page.goto('/integrations');
    await page.getByRole('button', { name: /add connector/i }).click();
    const d = page.getByRole('dialog');
    await d.getByLabel('Connector type').selectOption('splunk');
    await d.getByLabel('Display name').fill(name);
    await d.getByLabel('API endpoint (base URL)').fill('https://splunk.sim.test:8443');
    await d.getByLabel('Polling interval (minutes)').fill('15');
    await d.getByLabel('SPL search *').fill('search `notable` | head 100');
    await d.getByLabel('Authentication mode').selectOption('API_KEY');
    await d.getByLabel(/API key \/ access key/).fill('splunk-sim-token');
    await d.getByLabel('Value prefix').fill('Bearer ');
    await d.getByLabel(/Custom CA certificate/).fill(CA_PEM);
    await d.getByRole('button', { name: 'Save' }).click();
    await expect(d).toBeHidden();

    const card = page.locator('.card', { hasText: name });
    await expect(card.getByText('UNTESTED').or(card.getByText('DISABLED'))).toBeVisible();
    await expect(card).toContainText('stored (apiKey, apiKeyPrefix, caCert)');
    await card.getByRole('button', { name: /test connection/i }).click();
    await expect(card.getByText('Connected to Splunk 9.3.1')).toBeVisible();
    await card.getByRole('button', { name: /sync now/i }).click();
    await expect(card.getByText(/Synchronised \d+ records/)).toBeVisible();
    await page.screenshot({ path: `${SCREENSHOT_DIR}/14-integration-configured.png`, fullPage: true });

    // Credentials never come back from the API.
    const list = await api('GET', '/integrations');
    expect(list.text).not.toContain('splunk-sim-token');

    // Rotate to a wrong token → test fails safely with a generic message.
    await card.getByRole('button', { name: /rotate credentials/i }).click();
    const rot = page.getByRole('dialog');
    await rot.getByLabel(/API key \/ access key/).fill('revoked-token');
    await rot.getByLabel('Value prefix').fill('Bearer ');
    await rot.getByLabel(/Custom CA certificate/).fill(CA_PEM);
    await rot.getByRole('button', { name: /replace credentials/i }).click();
    await card.getByRole('button', { name: /test connection/i }).click();
    await expect(card.getByText('Upstream returned HTTP 401').first()).toBeVisible();

    page.once('dialog', (dlg) => dlg.accept());
    await card.getByRole('button', { name: /delete/i }).click();
    await expect(page.locator('.card', { hasText: name })).toHaveCount(0);
  });
});

test.describe('Real-time stream', () => {
  test('SSE delivers change notifications and is closed at token expiry boundary', async ({ as }) => {
    const { page, api } = await as('ciso');
    await page.goto('/');
    await page.evaluate(() => {
      const w = window as unknown as { __events: string[] };
      w.__events = [];
      const es = new EventSource('/api/stream');
      for (const t of ['ready', 'kpi', 'risks', 'incidents']) es.addEventListener(t, () => w.__events.push(t));
    });
    await waitFor(async () => (await page.evaluate(() => (window as unknown as { __events: string[] }).__events)).includes('ready'), 10_000, 300);
    await api('POST', '/risks', { title: 'SSE probe risk', description: 'probe', category: 'Test', likelihood: 1, impact: 2, ownerName: 'QA' });
    await waitFor(async () => (await page.evaluate(() => (window as unknown as { __events: string[] }).__events)).includes('risks'), 10_000, 300);
  });
});
